import curses
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from queue import Empty, Queue
import threading
from typing import Iterable

from .core import Event, TraceIndex


@dataclass
class UiState:
    event_count: int
    selected: int = 0
    errors_only: bool = False
    warnings_only: bool = False
    agent_filter: str | None = None
    event_kind_filter: str | None = None
    search: str | None = None
    trace_filter: str | None = None
    quit: bool = False

    def handle_key(self, key: str, value: str | None = None) -> None:
        if key == "j" and self.event_count:
            self.selected = min(self.selected + 1, self.event_count - 1)
        elif key == "k":
            self.selected = max(self.selected - 1, 0)
        elif key == "e":
            self.errors_only = not self.errors_only
        elif key == "l":
            self.warnings_only = not self.warnings_only
        elif key == "a":
            self.agent_filter = value or None
        elif key == "t":
            self.event_kind_filter = value or None
        elif key == "/":
            self.search = value or None
        elif key == "T":
            self.trace_filter = value or None
        elif key == "q":
            self.quit = True


def start_event_reader(
    events: Iterable[Event],
) -> Queue[Event | Exception | None]:
    updates: Queue[Event | Exception | None] = Queue()

    def read() -> None:
        try:
            for event in events:
                updates.put(event)
        except Exception as error:
            updates.put(error)
        finally:
            updates.put(None)

    threading.Thread(target=read, daemon=True).start()
    return updates


def drain_event_updates(
    index: TraceIndex,
    state: UiState,
    updates: Queue[Event | Exception | None],
) -> tuple[bool, Exception | None]:
    eof = False
    reader_error = None
    while True:
        try:
            update = updates.get_nowait()
        except Empty:
            break
        if isinstance(update, Event):
            index.add(update)
        elif update is None:
            eof = True
        else:
            reader_error = update
    state.event_count = index.event_count
    return eof, reader_error


def render_snapshot(
    index: TraceIndex,
    *,
    width: int,
    selected: int = 0,
    now: str | datetime | None = None,
    state: UiState | None = None,
) -> str:
    indexed_events = index.events
    if isinstance(now, str):
        current = datetime.fromisoformat(now.replace("Z", "+00:00"))
    elif now is not None:
        current = now
    elif indexed_events:
        current = max(event.timestamp for event in indexed_events)
    else:
        current = datetime.fromtimestamp(0, timezone.utc)
    events = list(index.ordered_events())
    warnings = index.warnings(now=current)
    warning_ids = {warning.event_id for warning in warnings}
    if state:
        events = [
            event for event in events
            if (not state.trace_filter or event.trace_id == state.trace_filter)
            and (not state.agent_filter or event.actor["id"] == state.agent_filter)
            and (not state.event_kind_filter or event.kind == state.event_kind_filter)
            and (
                not state.search
                or state.search.casefold() in json.dumps(
                    event.raw, ensure_ascii=False, sort_keys=True
                ).casefold()
            )
            and (
                not state.errors_only
                or event.kind.endswith(".failed")
                or event.operation["status"].lower() in {"error", "errored", "failed"}
            )
            and (not state.warnings_only or event.event_id in warning_ids)
        ]
        selected = state.selected
    filters = ["FILTER"]
    if state:
        filters.extend(
            f"{name}={value}"
            for name, value in (
                ("agent", state.agent_filter),
                ("kind", state.event_kind_filter),
                ("search", state.search),
                ("trace", state.trace_filter),
            )
            if value
        )
        filters.extend((
            f"errors={'on' if state.errors_only else 'off'}",
            f"warnings={'on' if state.warnings_only else 'off'}",
        ))
    lines = [" ".join(filters), "AGENT LANES"]
    latest_by_actor = {event.actor["id"]: event for event in events}
    visible_actors = latest_by_actor.keys()
    for actor_id in dict.fromkeys(
        event.actor["id"]
        for event in indexed_events
        if event.actor["id"] in visible_actors
    ):
        event = latest_by_actor[actor_id]
        elapsed = max(0.0, (current - event.timestamp).total_seconds())
        actor = event.actor
        operation = event.operation
        lane = (
            f"{actor_id} {operation['status']} {operation.get('name', '-')} "
            f"elapsed {elapsed:.1f}s"
        )
        if width >= 80:
            if actor.get("role"):
                lane += f" role {actor['role']}"
            actor_event_ids = {
                candidate.event_id
                for candidate in events
                if candidate.actor["id"] == actor_id
            }
            codes = [
                warning.code
                for warning in warnings
                if warning.event_id in actor_event_ids
            ]
            if codes:
                lane += " warning " + ",".join(codes)
            error = event.raw.get("error", operation.get("error"))
            if error:
                lane += f" error {error}"
        lines.append(lane)
    lines.append("TIMELINE")
    lines.extend(
        f"event {event.event_id} trace {event.trace_id} {event.kind}"
        for event in events
    )
    if events:
        event = events[min(max(selected, 0), len(events) - 1)]
        lines.extend((
            "INSPECTOR",
            f"schema_version: {event.schema_version}",
            f"event_id: {event.event_id}",
            f"trace_id: {event.trace_id}",
            f"span_id: {event.span_id}",
            f"parent_span_id: {event.parent_span_id}",
            f"emitter_id: {event.emitter_id}",
            f"sequence: {event.sequence}",
            f"timestamp: {event.timestamp.isoformat()}",
            f"kind: {event.kind}",
            "actor: " + json.dumps(event.actor, ensure_ascii=False, sort_keys=True),
            "operation: "
            + json.dumps(event.operation, ensure_ascii=False, sort_keys=True),
        ))
        if "payload" in event.raw:
            payload = event.raw["payload"]
            if isinstance(payload, dict):
                payload.pop("_agent_tail", None)
            lines.append(
                "payload: " + json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
            )
    return "\n".join(line[:width] for line in lines)


def run(index: TraceIndex, events: Iterable[Event] | None = None) -> None:
    curses.wrapper(_curses_loop, index, events)


def _curses_loop(screen, index: TraceIndex, events: Iterable[Event] | None) -> None:
    updates = start_event_reader(events) if events is not None else None
    state = UiState(event_count=index.event_count)
    eof = updates is None
    frozen_now = datetime.now().astimezone() if eof else None
    reader_error: Exception | None = None
    screen.timeout(100)

    while not state.quit:
        if updates is not None:
            batch_eof, batch_error = drain_event_updates(index, state, updates)
            if batch_error is not None:
                reader_error = batch_error
            if batch_eof and not eof:
                eof = True
                frozen_now = datetime.now().astimezone()

        height, width = screen.getmaxyx()
        status = "INPUT EOF - final view frozen" if eof else "INPUT LIVE"
        if reader_error:
            status += f" - READER ERROR: {reader_error}"
        text = status + "\n" + render_snapshot(
            index,
            width=max(width - 1, 1),
            now=frozen_now if eof else datetime.now().astimezone(),
            state=state,
        )
        screen.erase()
        for row, line in enumerate(text.splitlines()[:height]):
            try:
                screen.addnstr(row, 0, line, max(width - 1, 1))
            except curses.error:
                pass
        screen.refresh()

        try:
            key = screen.get_wch()
        except curses.error:
            continue
        if not isinstance(key, str):
            continue
        if key in {"a", "t", "/", "T"}:
            prompts = {
                "a": "agent filter: ",
                "t": "event-kind filter: ",
                "/": "search: ",
                "T": "trace: ",
            }
            prompt = prompts[key]
            screen.timeout(-1)
            screen.addnstr(max(height - 1, 0), 0, prompt, max(width - 1, 1))
            value = screen.getstr(
                max(height - 1, 0),
                min(len(prompt), max(width - 1, 0)),
                max(width - len(prompt) - 1, 1),
            ).decode(errors="replace")
            screen.timeout(100)
            state.handle_key(key, value)
        else:
            state.handle_key(key)
