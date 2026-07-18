import curses
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from queue import Empty, Queue
import threading
from typing import Iterable
import unicodedata

from .core import Event, TraceIndex


def _truncate_cells(value: str, max_cells: int) -> str:
    value = "".join(
        " " if character == "\t"
        else "�" if unicodedata.category(character).startswith("C")
        else character
        for character in value
    )
    cells = 0
    end = 0
    for end, character in enumerate(value, 1):
        if (
            unicodedata.category(character).startswith("M")
            or unicodedata.combining(character)
        ):
            width = 0
        else:
            width = 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        if cells + width > max_cells:
            return value[:end - 1]
        cells += width
    return value[:end]


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
    updates: Queue[Event | Exception | None] = Queue(maxsize=1)

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
    metadata_only: bool = False,
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
    warning_ids = {(warning.trace_id, warning.event_id) for warning in warnings}
    warning_actor_ids = {
        (warning.trace_id, warning.actor_id) for warning in warnings
    }
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
            and (
                not state.warnings_only
                or (event.trace_id, event.event_id) in warning_ids
                or (event.trace_id, event.actor["id"]) in warning_actor_ids
            )
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
    lines = [" ".join(filters)]
    policy = index.warning_policy_projection(now=current)
    if policy is not None:
        lines.extend((
            f"WARNING POLICY: {policy['path']} version {policy['version']}",
            "WARNING POLICY CHANGES: restart required",
            f"SUPPRESSED FINDINGS: {policy['suppressed_counts']['total']} "
            f"(LOOP {policy['suppressed_counts']['by_code']['LOOP']}, "
            f"RETRY {policy['suppressed_counts']['by_code']['RETRY']})",
        ))
        lines.extend(
            "EFFECTIVE WARNING RULE: "
            + json.dumps(rule, sort_keys=True, separators=(",", ":"))
            for rule in policy["rules"]
        )
    if metadata_only:
        lines.append("PAYLOAD MODE: metadata-only (payload bodies omitted)")
    presented_warnings = [
        warning for warning in warnings
        if not state
        or (not state.trace_filter or warning.trace_id == state.trace_filter)
        and (not state.agent_filter or warning.actor_id == state.agent_filter)
    ]
    if presented_warnings:
        lines.append("WARNING FINDINGS")
        lines.extend(
            f"WARNING {warning.code} event {warning.event_id} actor "
            f"{warning.actor_id}: {warning.summary} evidence {warning.evidence}"
            for warning in presented_warnings
        )
    lines.append("AGENT LANES")
    latest_by_actor = {
        (event.trace_id, event.actor["id"]): event for event in events
    }
    visible_actors = latest_by_actor.keys()
    actor_states = {}
    for trace_id in dict.fromkeys(event.trace_id for event in events):
        for actor_id, actor_state in index.trace(trace_id).actors.items():
            lane = (trace_id, actor_id)
            if lane in visible_actors:
                actor_states[lane] = actor_state
    visible_traces = {trace_id for trace_id, _ in visible_actors}
    for trace_id, actor_id in dict.fromkeys(
        (event.trace_id, event.actor["id"])
        for event in indexed_events
        if (event.trace_id, event.actor["id"]) in visible_actors
    ):
        lane_key = (trace_id, actor_id)
        event = latest_by_actor[lane_key]
        state_actor = actor_states[lane_key]
        elapsed = max(0.0, (current - state_actor.last_activity).total_seconds())
        actor = event.actor
        operation = event.operation
        lane_name = (
            f"{trace_id} {actor_id}" if len(visible_traces) > 1 else actor_id
        )
        lane = (
            f"{lane_name} {state_actor.status} {state_actor.operation} "
            f"elapsed {elapsed:.1f}s "
            f"{'uncertain' if state_actor.uncertain else 'causal'}"
        )
        if width >= 80:
            if actor.get("role"):
                lane += f" role {actor['role']}"
            codes = [
                warning.code
                for warning in warnings
                if (warning.trace_id, warning.actor_id) == lane_key
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
            metadata = payload.get("_agent_tail") if isinstance(payload, dict) else None
            if isinstance(metadata, dict) and metadata.get("omitted") is True:
                lines.append(
                    "payload: omitted (metadata-only) "
                    + json.dumps(metadata, ensure_ascii=False, sort_keys=True)
                )
                return "\n".join(_truncate_cells(line, width) for line in lines)
            if isinstance(payload, dict):
                payload.pop("_agent_tail", None)
            lines.append(
                "payload: " + json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
            )
    return "\n".join(_truncate_cells(line, width) for line in lines)


def run(
    index: TraceIndex,
    events: Iterable[Event] | None = None,
    *,
    metadata_only: bool = False,
) -> Exception | None:
    return curses.wrapper(_curses_loop, index, events, metadata_only)


def _curses_loop(
    screen,
    index: TraceIndex,
    events: Iterable[Event] | None,
    metadata_only: bool = False,
) -> Exception | None:
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
        content_width = max(width - 1, 1)
        text = _truncate_cells(status, content_width) + "\n" + render_snapshot(
            index,
            width=content_width,
            now=frozen_now if eof else datetime.now().astimezone(),
            state=state,
            metadata_only=metadata_only,
        )
        screen.erase()
        for row, line in enumerate(text.splitlines()[:height]):
            try:
                screen.addstr(row, 0, line)
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

    return reader_error
