from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import sys
import threading
import time
from typing import Callable, Iterable, TextIO
from urllib.parse import parse_qs, unquote, urlparse

from .core import Event, IngestionError, JSONLReader, TraceIndex, sanitize_event


@dataclass(frozen=True)
class ServeConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    open_browser: bool = False
    full_payloads: bool = False
    unsafe_unredacted: bool = False
    remote_access: bool = False
    access_token: str | None = None
    loop_threshold: int = 4
    stall_seconds: float = 30.0
    max_bytes: int = 16 * 1024 * 1024
    max_live_updates: int = 10_000

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_live_updates, int)
            or isinstance(self.max_live_updates, bool)
            or self.max_live_updates <= 0
        ):
            raise ValueError("max_live_updates must be a positive integer")


class RunStore:
    def __init__(
        self,
        index: TraceIndex | None = None,
        errors: Iterable[IngestionError] = (),
        *,
        source_kind: str = "snapshot",
        max_live_updates: int = 10_000,
    ) -> None:
        if (
            not isinstance(max_live_updates, int)
            or isinstance(max_live_updates, bool)
            or max_live_updates <= 0
        ):
            raise ValueError("max_live_updates must be a positive integer")
        self._reader = JSONLReader(retain_events=False)
        self._index = index
        if self._index is None:
            self._index = TraceIndex()
        self._errors = tuple(errors)
        self._findings: list[dict[str, object]] = []
        self._payload_details: dict[tuple[str, str], object] = {}
        self._last_eviction_count = 0
        self._warning_history: dict[tuple[str, str, str], dict[str, object]] = {}
        self._terminal_traces: dict[str, str] = {}
        self._source_status: dict[str, object] = {
            "kind": source_kind,
            "connected": False,
            "state": "idle",
        }
        self._cursor = 0
        self._updates: deque[dict[str, object]] = deque(maxlen=max_live_updates)
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)

    @classmethod
    def from_lines(
        cls,
        lines: Iterable[str],
        *,
        full_payloads: bool = False,
        unsafe_unredacted: bool = False,
        loop_threshold: int = 4,
        stall_seconds: float = 30.0,
        max_bytes: int = 16 * 1024 * 1024,
        max_live_updates: int = 10_000,
    ) -> "RunStore":
        index = TraceIndex(
            loop_threshold=loop_threshold,
            stall_seconds=stall_seconds,
            max_bytes=max_bytes,
        )
        store = cls(
            index,
            source_kind="snapshot",
            max_live_updates=max_live_updates,
        )
        for line in lines:
            store.feed_line(
                line,
                full_payloads=full_payloads,
                unsafe_unredacted=unsafe_unredacted,
            )
        store.set_source_status(connected=False, state="disconnected")
        return store

    @property
    def cursor(self) -> int:
        with self._lock:
            return self._cursor

    def feed_line(
        self,
        line: str,
        *,
        full_payloads: bool = False,
        unsafe_unredacted: bool = False,
    ) -> Event | None:
        with self._condition:
            prior_error_count = len(self._reader.all_errors)
            event = self._reader.feed(line)
            self._sync_ingestion_errors(prior_error_count)
            if event is None:
                return None
            safe = sanitize_event(
                event,
                full_payloads=full_payloads,
                unsafe_unredacted=unsafe_unredacted,
            )
            retained = sanitize_event(
                event,
                full_payloads=True,
                unsafe_unredacted=unsafe_unredacted,
            )
            self._payload_details[(safe.trace_id, safe.event_id)] = _payload_preview(retained)
            prior_terminal_state = self._terminal_traces.get(safe.trace_id)
            self._index.add(safe)
            eviction_count = self._index.eviction_count
            if eviction_count != self._last_eviction_count:
                self._sync_payload_details()
                self._last_eviction_count = eviction_count
            terminal_state = _terminal_state(safe)
            if terminal_state:
                self._terminal_traces[safe.trace_id] = terminal_state
            elif prior_terminal_state:
                self.add_finding(
                    "instrumentation",
                    "LATE_EVENT",
                    f"event arrived after trace was {prior_terminal_state}",
                    event_id=safe.event_id,
                    trace_id=safe.trace_id,
                )
            self._publish("event", self._event_message(safe))
            return safe

    def add_finding(
        self,
        kind: str,
        code: str,
        message: str,
        *,
        line: int | None = None,
        event_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        with self._condition:
            finding = {
                "kind": kind,
                "code": code,
                "message": message,
                "line": line,
                "event_id": event_id,
                "trace_id": trace_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            self._findings.append(finding)
            self._publish("finding", finding)

    def set_source_status(self, *, connected: bool, state: str) -> None:
        with self._condition:
            changed = (
                self._source_status.get("connected") != connected
                or self._source_status.get("state") != state
            )
            self._source_status = {
                **self._source_status,
                "connected": connected,
                "state": state,
            }
            if changed:
                self._publish("source", dict(self._source_status))

    def stream_updates(self, after: int) -> Iterable[dict[str, object]]:
        next_cursor = after + 1
        while True:
            heartbeat = None
            reset = None
            with self._condition:
                oldest = (
                    int(self._updates[0]["cursor"])
                    if self._updates
                    else self._cursor + 1
                )
                if next_cursor < oldest or next_cursor > self._cursor + 1:
                    reset = {
                        "cursor": self._cursor,
                        "type": "reset",
                        "data": {
                            "requested_cursor": next_cursor - 1,
                            "oldest_retained_cursor": oldest,
                            "current_cursor": self._cursor,
                            "reason": "history_gap",
                        },
                    }
                    pending = []
                elif self._cursor < next_cursor:
                    self._condition.wait(timeout=15)
                    if self._cursor < next_cursor:
                        heartbeat = {
                            "cursor": self._cursor,
                            "type": "heartbeat",
                            "data": {},
                        }
                    pending = []
                else:
                    pending = [
                        update for update in self._updates
                        if update["cursor"] >= next_cursor
                    ]
            if reset is not None:
                yield reset
                return
            if heartbeat is not None:
                yield heartbeat
                continue
            for update in pending:
                yield update
                next_cursor = int(update["cursor"]) + 1

    def list_runs(self) -> dict[str, object]:
        with self._lock:
            trace_ids = list(dict.fromkeys(event.trace_id for event in self._index.events))
            runs = [self._summary(trace_id) for trace_id in trace_ids]
            return {
                "api_version": "v1",
                "cursor": self._cursor,
                "runs": runs,
                "source": dict(self._source_status),
                "findings": list(self._findings),
                "ingestion_errors": [
                    finding for finding in self._findings
                    if finding.get("kind") == "ingestion"
                ],
            }

    def run_detail(self, trace_id: str) -> dict[str, object] | None:
        with self._lock:
            trace_ids = {event.trace_id for event in self._index.events}
            if trace_id not in trace_ids:
                return None
            view = self._index.trace(trace_id)
            now = self._warning_now(view.events)
            projection = _relationships(view)
            evidence_map = _event_evidence(view.events)
            started_at = min((event.timestamp for event in view.events), default=None)
            return {
                "api_version": "v1",
                "cursor": self._cursor,
                "run": self._summary(trace_id, projection=projection),
                "duration_seconds": _duration_seconds(view.events),
                "usage": _usage_summary(view.events),
                "events": [
                    self._event_message(
                        event,
                        event.event_id in view.uncertain_event_ids,
                        started_at=started_at,
                    )
                    for event in view.events
                ],
                "actors": [
                    {
                        "id": actor_id,
                        "parent_id": projection["parents"].get(actor_id),
                        "child_ids": projection["children"].get(actor_id, []),
                        "role": _actor_role(view.events, actor_id),
                        "model": _actor_model(view.events, actor_id),
                        "status": actor.status,
                        "operation": actor.operation,
                        "last_activity": actor.last_activity.isoformat(),
                        "last_activity_event_id": actor.last_activity_event_id,
                        "open_span_ids": list(actor.open_span_ids),
                        "uncertain": actor.uncertain,
                        "usage": _usage_summary(
                            event for event in view.events
                            if event.actor["id"] == actor_id
                        ),
                    }
                    for actor_id, actor in view.actors.items()
                ],
                "warnings": self._warnings_for_trace(trace_id, now) + projection["warnings"],
                "links": projection["links"],
                "unresolved_endpoints": projection["unresolved_endpoints"],
                "evidence_map": evidence_map,
                "source": dict(self._source_status),
                "findings": [
                    finding for finding in self._findings
                    if finding.get("trace_id") in {None, trace_id}
                ],
            }

    def _summary(
        self,
        trace_id: str,
        *,
        projection: dict[str, object] | None = None,
    ) -> dict[str, object]:
        view = self._index.trace(trace_id)
        timestamps = [event.timestamp for event in view.events]
        if projection is None:
            projection = _relationships(view)
        runtime_warning_count = sum(
            1 for warning in self._index.warnings(now=max(timestamps, default=_epoch()))
            if warning.trace_id == trace_id
        )
        return {
            "trace_id": trace_id,
            "event_count": len(view.events),
            "actor_count": len(view.actors),
            "started_at": min(timestamps).isoformat() if timestamps else None,
            "ended_at": max(timestamps).isoformat() if timestamps else None,
            "duration_seconds": _duration_seconds(view.events),
            "usage": _usage_summary(view.events),
            "uncertain_event_count": len(view.uncertain_event_ids),
            "warning_count": runtime_warning_count + len(projection["warnings"]),
            "state": self._lifecycle_state(trace_id),
        }

    def event_payload(self, trace_id: str, event_id: str) -> dict[str, object] | None:
        with self._lock:
            for event in self._index.trace(trace_id).events:
                if event.event_id == event_id:
                    return {
                        "api_version": "v1",
                        "trace_id": trace_id,
                        "event_id": event_id,
                        "payload": self._payload_details.get(
                            (trace_id, event_id),
                            _payload_preview(event),
                        ),
                    }
            return None

    def _sync_payload_details(self) -> None:
        retained_keys = set()
        for event in self._index.events:
            key = (event.trace_id, event.event_id)
            retained_keys.add(key)
            payload = event.raw.get("payload")
            if isinstance(payload, dict) and set(payload) == {"_agent_tail"}:
                self._payload_details.pop(key, None)
        for key in set(self._payload_details) - retained_keys:
            self._payload_details.pop(key, None)

    def _warning_now(self, events: Iterable[Event]) -> datetime:
        event_list = list(events)
        if self._source_status.get("connected"):
            return datetime.now(timezone.utc)
        return max((event.timestamp for event in event_list), default=_epoch())

    def _warnings_for_trace(
        self,
        trace_id: str,
        now: datetime,
    ) -> list[dict[str, object]]:
        current_keys = set()
        for warning in self._index.warnings(now=now):
            if warning.trace_id != trace_id:
                continue
            key = (warning.code, warning.event_id, warning.actor_id)
            current_keys.add(key)
            prior = self._warning_history.get(key, {})
            self._warning_history[key] = {
                "category": "runtime",
                "code": warning.code,
                "event_id": warning.event_id,
                "trace_id": warning.trace_id,
                "actor_id": warning.actor_id,
                "summary": warning.summary,
                "evidence": warning.evidence,
                "active": True,
                "detected_at": prior.get("detected_at", now.isoformat()),
                "resolved_at": None,
            }
        for key, record in list(self._warning_history.items()):
            if record.get("trace_id") == trace_id and key not in current_keys and record.get("active"):
                record["active"] = False
                record["resolved_at"] = now.isoformat()
        return [
            record for record in self._warning_history.values()
            if record.get("trace_id") == trace_id
        ]

    def _lifecycle_state(self, trace_id: str) -> str:
        terminal_state = self._terminal_traces.get(trace_id)
        if terminal_state:
            return terminal_state
        if self._source_status.get("connected"):
            return "live"
        return "incomplete"

    def _sync_ingestion_errors(self, prior_count: int) -> None:
        errors = self._reader.all_errors
        for error in errors[prior_count:]:
            message = error.message
            if message.startswith("duplicate event ID"):
                code = "DUPLICATE_EVENT"
            elif message.startswith("invalid JSON"):
                code = "INVALID_JSON"
            else:
                code = "INVALID_EVENT"
            self.add_finding("ingestion", code, message, line=error.line)
        self._errors = tuple(errors)

    def _publish(self, message_type: str, data: dict[str, object]) -> None:
        self._cursor += 1
        self._updates.append({
            "cursor": self._cursor,
            "type": message_type,
            "data": data,
        })
        self._condition.notify_all()

    def _event_message(
        self,
        event: Event,
        uncertain: bool | None = None,
        *,
        started_at: datetime | None = None,
    ) -> dict[str, object]:
        if uncertain is None:
            uncertain = event.event_id in self._index.trace(event.trace_id).uncertain_event_ids
        if started_at is None:
            offset_seconds = 0.0
        else:
            offset_seconds = (event.timestamp - started_at).total_seconds()
        return {
            "event_id": event.event_id,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "parent_span_id": event.parent_span_id,
            "emitter_id": event.emitter_id,
            "sequence": event.sequence,
            "timestamp": event.timestamp.isoformat(),
            "offset_seconds": offset_seconds,
            "kind": event.kind,
            "actor": event.actor,
            "operation": event.operation,
            "relationships": [
                {"type": relationship.type, "event_id": relationship.event_id}
                for relationship in event.relationships
            ],
            "attributes": _attributes(event),
            "usage": _usage_summary((event,)),
            "payload": _payload_preview(event),
            "uncertain": uncertain,
        }


def serve(
    source: TextIO,
    *,
    config: ServeConfig,
    open_url: Callable[[str], object] | None = None,
) -> int:
    store = RunStore(
        TraceIndex(
            loop_threshold=config.loop_threshold,
            stall_seconds=config.stall_seconds,
            max_bytes=config.max_bytes,
        ),
        source_kind="stdin",
        max_live_updates=config.max_live_updates,
    )
    reader = threading.Thread(
        target=_read_stream,
        args=(source, store, config),
        daemon=True,
    )
    reader.start()
    return _serve_store(store, config=config, open_url=open_url)


def serve_file(
    path: Path,
    *,
    config: ServeConfig,
    open_url: Callable[[str], object] | None = None,
) -> int:
    path.open(encoding="utf-8").close()
    store = RunStore(
        TraceIndex(
            loop_threshold=config.loop_threshold,
            stall_seconds=config.stall_seconds,
            max_bytes=config.max_bytes,
        ),
        source_kind="file",
        max_live_updates=config.max_live_updates,
    )
    stop = threading.Event()
    reader = start_file_follower(path, store, config=config, stop=stop)
    try:
        return _serve_store(store, config=config, open_url=open_url)
    finally:
        stop.set()
        reader.join(timeout=1)


def _serve_store(
    store: RunStore,
    *,
    config: ServeConfig,
    open_url: Callable[[str], object] | None = None,
) -> int:
    _validate_remote_access(config)
    if config.remote_access and not config.access_token:
        config = replace(config, access_token=secrets.token_urlsafe(24))
    server = make_server(store, host=config.host, port=config.port)
    server.access_token = config.access_token
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/"
    if config.access_token:
        url += f"?token={config.access_token}"
    print(f"Agent Tail serve mode listening on {url}", flush=True)
    if config.remote_access:
        print(
            "WARNING: remote access is enabled; share the token URL only with trusted clients.",
            flush=True,
        )
    if config.open_browser and open_url is not None:
        open_url(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def start_file_follower(
    path: Path,
    store: RunStore,
    *,
    config: ServeConfig,
    stop: threading.Event | None = None,
    poll_seconds: float = 0.05,
) -> threading.Thread:
    stop = stop or threading.Event()
    thread = threading.Thread(
        target=_follow_file,
        args=(path, store, config, stop, poll_seconds),
        daemon=True,
    )
    thread.start()
    return thread


def _follow_file(
    path: Path,
    store: RunStore,
    config: ServeConfig,
    stop: threading.Event,
    poll_seconds: float,
) -> None:
    store.set_source_status(connected=True, state="reading")
    source = path.open(encoding="utf-8")
    position = 0
    stat = path.stat()
    identity = (stat.st_dev, stat.st_ino)
    try:
        while not stop.is_set():
            line = source.readline()
            if line:
                if not line.endswith("\n"):
                    source.seek(position)
                    store.set_source_status(connected=True, state="caught_up")
                    time.sleep(poll_seconds)
                    continue
                position = source.tell()
                store.feed_line(
                    line,
                    full_payloads=config.full_payloads,
                    unsafe_unredacted=config.unsafe_unredacted,
                )
                store.set_source_status(connected=True, state="reading")
                continue

            store.set_source_status(connected=True, state="caught_up")
            try:
                stat = path.stat()
            except OSError as error:
                store.add_finding("source", "SOURCE_UNAVAILABLE", str(error))
                time.sleep(poll_seconds)
                continue

            current_identity = (stat.st_dev, stat.st_ino)
            if current_identity != identity:
                store.add_finding(
                    "source",
                    "SOURCE_REPLACED",
                    "source file was replaced; replayed events will be deduplicated",
                )
                source.close()
                source = path.open(encoding="utf-8")
                identity = current_identity
                position = 0
                continue
            if stat.st_size < position:
                store.add_finding(
                    "source",
                    "SOURCE_TRUNCATED",
                    "source file was truncated; reading resumed from start",
                )
                source.seek(0)
                position = 0
                continue
            time.sleep(poll_seconds)
    except UnicodeError as error:
        store.add_finding("source", "SOURCE_DECODE_ERROR", str(error))
    finally:
        source.close()
        store.set_source_status(connected=False, state="disconnected")


def _read_stream(
    source: TextIO,
    store: RunStore,
    config: ServeConfig,
) -> None:
    store.set_source_status(connected=True, state="reading")
    try:
        for line in source:
            store.feed_line(
                line,
                full_payloads=config.full_payloads,
                unsafe_unredacted=config.unsafe_unredacted,
            )
    except UnicodeError as error:
        store.add_finding("source", "SOURCE_DECODE_ERROR", str(error))
    finally:
        store.set_source_status(connected=False, state="disconnected")


def make_server(store: RunStore, *, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    class Handler(_Handler):
        run_store = store

    server = _Server((host, port), Handler)
    server.access_token = None
    return server


class _Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address) -> None:
        if isinstance(sys.exception(), ConnectionResetError):
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    run_store: RunStore

    def do_GET(self) -> None:
        if not self._authorized():
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self._send_bytes(_static_index(), "text/html; charset=utf-8")
            return
        if path == "/api/v1/runs":
            self._send_json(self.run_store.list_runs())
            return
        if path == "/api/v1/events":
            after = _cursor_from_path(self.path)
            self._send_sse(after)
            return
        prefix = "/api/v1/runs/"
        if path.startswith(prefix):
            suffix = path.removeprefix(prefix)
            parts = suffix.split("/")
            if len(parts) == 4 and parts[1] == "events" and parts[3] == "payload":
                payload = self.run_store.event_payload(
                    unquote(parts[0]),
                    unquote(parts[2]),
                )
                if payload is None:
                    self._send_json({"error": "event not found"}, HTTPStatus.NOT_FOUND)
                else:
                    self._send_json(payload)
                return
            trace_id = unquote(suffix)
            detail = self.run_store.run_detail(trace_id)
            if detail is None:
                self._send_json({"error": "run not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._send_json(detail)
            return
        self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(
        self,
        body: dict[str, object],
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self._send_bytes(
            json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        token = getattr(self.server, "access_token", None)
        if not token:
            return True
        parsed = urlparse(self.path)
        query_token = parse_qs(parsed.query).get("token", [None])[0]
        auth = self.headers.get("Authorization", "")
        return query_token == token or auth == f"Bearer {token}"

    def _send_sse(self, after: int) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        for update in self.run_store.stream_updates(after):
            body = (
                f"id: {update['cursor']}\n"
                f"event: {update['type']}\n"
                "data: "
                + json.dumps(update["data"], ensure_ascii=False, sort_keys=True)
                + "\n\n"
            ).encode("utf-8")
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionError, OSError):
                break


def _static_index() -> bytes:
    return Path(__file__).with_name("web").joinpath("index.html").read_bytes()


def _payload_preview(event: Event) -> object:
    raw = event.raw
    if "payload" not in raw:
        return None
    payload = raw["payload"]
    if isinstance(payload, dict):
        payload = dict(payload)
        metadata = payload.pop("_agent_tail", None)
        return {"preview": payload, "metadata": metadata}
    return {"preview": payload, "metadata": None}


def _epoch() -> datetime:
    return datetime.fromtimestamp(0, timezone.utc)


def _duration_seconds(events: Iterable[Event]) -> float | None:
    event_list = list(events)
    if not event_list:
        return None
    return (
        max(event.timestamp for event in event_list)
        - min(event.timestamp for event in event_list)
    ).total_seconds()


def _relationships(view) -> dict[str, object]:
    actor_ids = set(view.actors)
    events_by_id = {event.event_id: event for event in view.events}
    introduced_actor_ids: set[str] = set()
    parents: dict[str, str] = {}
    children: dict[str, list[str]] = {}
    links: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []
    unresolved: dict[str, dict[str, object]] = {}

    def add_link(link: dict[str, object]) -> None:
        identity = (
            link.get("type"),
            link.get("source_actor_id"),
            link.get("target_actor_id"),
            link.get("unresolved_target"),
            link.get("event_id"),
        )
        if not any(
            identity == (
                existing.get("type"),
                existing.get("source_actor_id"),
                existing.get("target_actor_id"),
                existing.get("unresolved_target"),
                existing.get("event_id"),
            )
            for existing in links
        ):
            links.append(link)

    for event in view.events:
        actor_id = event.actor["id"]
        introduces_actor = actor_id not in introduced_actor_ids
        parent_actor_id = None
        if event.parent_span_id and event.parent_span_id in view.spans:
            parent_span = view.spans[event.parent_span_id]
            has_causal_start = any(
                events_by_id[event_id].kind.endswith(".started")
                for event_id in parent_span.event_ids
                if event_id in events_by_id
            )
            if has_causal_start and parent_span.actor_id != actor_id:
                parent_actor_id = parent_span.actor_id
        if parent_actor_id:
            if introduces_actor:
                parents[actor_id] = parent_actor_id
                children.setdefault(parent_actor_id, []).append(actor_id)
                add_link({
                    "type": "spawn",
                    "source_actor_id": parent_actor_id,
                    "target_actor_id": actor_id,
                    "event_id": event.event_id,
                })
            else:
                add_link({
                    "type": "causal",
                    "source_actor_id": parent_actor_id,
                    "target_actor_id": actor_id,
                    "event_id": event.event_id,
                })
                if actor_id in parents and parents[actor_id] != parent_actor_id:
                    warnings.append({
                        "category": "projection",
                        "code": "AMBIGUOUS_PARENT",
                        "event_id": event.event_id,
                        "trace_id": event.trace_id,
                        "actor_id": actor_id,
                        "summary": "actor has multiple causal parent candidates",
                        "evidence": f"primary {parents[actor_id]}, later {parent_actor_id}",
                    })

        attributes = _attributes(event)
        target = attributes.get("to")
        if event.kind == "message.sent" and isinstance(target, str):
            link = {
                "type": "message",
                "source_actor_id": actor_id,
                "event_id": event.event_id,
            }
            if target in actor_ids:
                link["target_actor_id"] = target
            else:
                link["unresolved_target"] = target
                unresolved[target] = {
                    "id": target,
                    "introduced_by_event_id": event.event_id,
                }
            add_link(link)

        introduced_actor_ids.add(actor_id)

    return {
        "parents": parents,
        "children": children,
        "links": links,
        "warnings": warnings,
        "unresolved_endpoints": list(unresolved.values()),
    }


def _event_follows(candidate: Event, reference: Event) -> bool:
    if candidate.emitter_id == reference.emitter_id:
        if candidate.sequence == reference.sequence:
            return False
        return candidate.sequence > reference.sequence
    return candidate.timestamp > reference.timestamp


def _evidence_chronology(
    evidence: Event,
    boundary: Event,
    boundary_name: str,
) -> str:
    if _event_follows(evidence, boundary):
        return f"after_{boundary_name}"
    if _event_follows(boundary, evidence):
        return f"before_{boundary_name}"
    return "undetermined"


def _event_evidence(events: Iterable[Event]) -> dict[str, object]:
    event_list = list(events)
    events_by_id = {event.event_id: event for event in event_list}
    corrections_by_change: dict[str, list[dict[str, object]]] = {}
    changes = []
    invalid_changes = []
    links = []
    unresolved = []
    for source in event_list:
        source_links = []
        source_unresolved = []
        decision_events = [
            target
            for relationship in source.relationships
            if relationship.type == "applies"
            and (target := events_by_id.get(relationship.event_id)) is not None
            and target.kind == "change.proposed"
            and target.actor["id"].strip()
            and _event_follows(source, target)
        ] if source.kind == "change.applied" else []
        earliest_decision = None
        for decision_event in decision_events:
            if earliest_decision is None or _event_follows(
                earliest_decision,
                decision_event,
            ):
                earliest_decision = decision_event
        projected_relationships = set()
        for relationship in source.relationships:
            relationship_key = (relationship.type, relationship.event_id)
            if relationship_key in projected_relationships:
                continue
            projected_relationships.add(relationship_key)
            item = {
                "type": relationship.type,
                "source_event_id": source.event_id,
                "target_event_id": relationship.event_id,
                "source_kind": source.kind,
                "source_actor_id": source.actor["id"],
            }
            target = events_by_id.get(relationship.event_id)
            if target is None:
                unresolved.append(item)
                source_unresolved.append(item)
            else:
                resolved = {
                    **item,
                    "target_kind": target.kind,
                    "target_actor_id": target.actor["id"],
                }
                if (
                    source.kind == "change.applied"
                    and relationship.type == "applies"
                    and target.kind == "change.proposed"
                ):
                    resolved["chronology"] = _evidence_chronology(
                        target,
                        source,
                        "change",
                    )
                verification = _verification_result(
                    target,
                    events_by_id,
                    source
                    if source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    else None,
                )
                if verification is not None:
                    if (
                        source.kind == "change.applied"
                        and relationship.type == "verified_by"
                        and target.kind == "verification.finished"
                    ):
                        resolved["chronology"] = _evidence_chronology(
                            target,
                            source,
                            "change",
                        )
                    resolved["verification"] = verification
                requirement = _requirement_detail(target)
                if requirement is not None:
                    if (
                        source.kind == "change.applied"
                        and relationship.type == "motivated_by"
                        and target.kind == "requirement.observed"
                    ):
                        boundary = earliest_decision or source
                        boundary_name = "decision" if earliest_decision else "change"
                        resolved["chronology"] = _evidence_chronology(
                            target,
                            boundary,
                            boundary_name,
                        )
                        if earliest_decision is not None:
                            resolved["decision_event_id"] = earliest_decision.event_id
                    resolved["requirement"] = requirement
                context = _context_read_detail(target)
                if context is not None:
                    if (
                        source.kind == "change.applied"
                        and relationship.type == "informed_by"
                        and target.kind == "context.read"
                    ):
                        boundary = earliest_decision or source
                        boundary_name = "decision" if earliest_decision else "change"
                        resolved["chronology"] = _evidence_chronology(
                            target,
                            boundary,
                            boundary_name,
                        )
                        if earliest_decision is not None:
                            resolved["decision_event_id"] = earliest_decision.event_id
                    resolved["context"] = context
                tool = _tool_call_detail(target)
                if tool is not None:
                    if (
                        source.kind == "change.applied"
                        and relationship.type == "preceded_by"
                        and target.kind.startswith("tool.call.")
                    ):
                        boundary = earliest_decision or source
                        boundary_name = "decision" if earliest_decision else "change"
                        resolved["chronology"] = _evidence_chronology(
                            target,
                            boundary,
                            boundary_name,
                        )
                        if earliest_decision is not None:
                            resolved["decision_event_id"] = earliest_decision.event_id
                    resolved["tool"] = tool
                compaction = _context_compaction_detail(target, events_by_id)
                if compaction is not None:
                    if (
                        source.kind == "change.applied"
                        and relationship.type == "informed_by"
                        and target.kind == "context.compacted"
                    ):
                        boundary = earliest_decision or source
                        boundary_name = "decision" if earliest_decision else "change"
                        resolved["chronology"] = _evidence_chronology(
                            target,
                            boundary,
                            boundary_name,
                        )
                        if earliest_decision is not None:
                            resolved["decision_event_id"] = earliest_decision.event_id
                    resolved["compaction"] = compaction
                correction = _human_correction(source)
                if relationship.type == "corrects" and correction is not None:
                    resolved["correction"] = correction
                if (
                    relationship.type == "corrects"
                    and source.kind == "human.corrected"
                    and target.kind == "change.applied"
                ):
                    resolved["chronology"] = _evidence_chronology(
                        source,
                        target,
                        "change",
                    )
                    if correction is None:
                        resolved["reason"] = "invalid_correction_detail"
                        invalid = {
                            **item,
                            "target_kind": target.kind,
                            "reason": "invalid_correction_detail",
                        }
                        unresolved.append(invalid)
                        source_unresolved.append(invalid)
                    elif _event_follows(target, source):
                        resolved["reason"] = "correction_precedes_change"
                        invalid = {
                            **item,
                            "target_kind": target.kind,
                            "reason": "correction_precedes_change",
                        }
                        unresolved.append(invalid)
                        source_unresolved.append(invalid)
                    elif not _event_follows(source, target):
                        resolved["reason"] = "correction_chronology_undetermined"
                        invalid = {
                            **item,
                            "target_kind": target.kind,
                            "reason": "correction_chronology_undetermined",
                        }
                        unresolved.append(invalid)
                        source_unresolved.append(invalid)
                    corrections_by_change.setdefault(target.event_id, []).append(resolved)
                links.append(resolved)
                source_links.append(resolved)
                if (
                    source.kind == "change.applied"
                    and relationship.type == "motivated_by"
                    and target.kind == "requirement.observed"
                    and _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "requirement_not_preceding_change",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "motivated_by"
                    and target.kind == "requirement.observed"
                    and earliest_decision is not None
                    and _event_follows(target, earliest_decision)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "requirement_follows_decision",
                        "decision_event_id": earliest_decision.event_id,
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "motivated_by"
                    and target.kind == "requirement.observed"
                    and requirement is None
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_requirement_detail",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "motivated_by"
                    and target.kind == "requirement.observed"
                    and not _event_follows(target, earliest_decision or source)
                    and not _event_follows(earliest_decision or source, target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "requirement_chronology_undetermined",
                    }
                    if earliest_decision is not None:
                        invalid["decision_event_id"] = earliest_decision.event_id
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "context_not_preceding_change",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and earliest_decision is not None
                    and _event_follows(target, earliest_decision)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "context_follows_decision",
                        "decision_event_id": earliest_decision.event_id,
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and context is None
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_context_detail",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and _has_invalid_context_line_start(target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_context_line_start",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and _has_invalid_context_line_end(target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_context_line_end",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and _has_invalid_context_symbol(target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_context_symbol",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.read"
                    and not _event_follows(target, earliest_decision or source)
                    and not _event_follows(earliest_decision or source, target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "context_chronology_undetermined",
                    }
                    if earliest_decision is not None:
                        invalid["decision_event_id"] = earliest_decision.event_id
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.compacted"
                    and _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "compaction_not_preceding_change",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.compacted"
                    and earliest_decision is not None
                    and _event_follows(target, earliest_decision)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "compaction_follows_decision",
                        "decision_event_id": earliest_decision.event_id,
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.compacted"
                    and not any(
                        candidate.type == "summarizes"
                        for candidate in target.relationships
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_compaction_detail",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "informed_by"
                    and target.kind == "context.compacted"
                    and not _event_follows(target, earliest_decision or source)
                    and not _event_follows(earliest_decision or source, target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "compaction_chronology_undetermined",
                    }
                    if earliest_decision is not None:
                        invalid["decision_event_id"] = earliest_decision.event_id
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "tool_not_preceding_change",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and earliest_decision is not None
                    and _event_follows(target, earliest_decision)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "tool_follows_decision",
                        "decision_event_id": earliest_decision.event_id,
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and (
                        not isinstance(tool, dict)
                        or "command" not in tool and "result" not in tool
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_tool_detail",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and isinstance(tool, dict)
                    and isinstance(raw_tool := _attributes(target).get("tool"), dict)
                    and "command" in raw_tool
                    and (
                        not isinstance(raw_tool["command"], str)
                        or not raw_tool["command"].strip()
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_tool_command",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and isinstance(tool, dict)
                    and isinstance(raw_tool := _attributes(target).get("tool"), dict)
                    and "result" in raw_tool
                    and (
                        not isinstance(raw_tool["result"], str)
                        or not raw_tool["result"].strip()
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_tool_result",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and isinstance(tool, dict)
                    and not target.operation["status"].strip()
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_tool_operation_status",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and isinstance(tool, dict)
                    and "name" in target.operation
                    and (
                        not isinstance(target.operation["name"], str)
                        or not target.operation["name"].strip()
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_tool_operation_name",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and isinstance(tool, dict)
                    and isinstance(raw_tool := _attributes(target).get("tool"), dict)
                    and "exit_code" in raw_tool
                    and (
                        not isinstance(raw_tool["exit_code"], int)
                        or isinstance(raw_tool["exit_code"], bool)
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_tool_exit_code",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "preceded_by"
                    and target.kind.startswith("tool.call.")
                    and not _event_follows(target, earliest_decision or source)
                    and not _event_follows(earliest_decision or source, target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "tool_chronology_undetermined",
                    }
                    if earliest_decision is not None:
                        invalid["decision_event_id"] = earliest_decision.event_id
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and _event_follows(source, target)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "verification_precedes_change",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and verification is None
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_verification_result",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and isinstance(verification, dict)
                    and isinstance(
                        raw_verification := _attributes(target).get("verification"),
                        dict,
                    )
                    and "exit_code" in raw_verification
                    and (
                        not isinstance(raw_verification["exit_code"], int)
                        or isinstance(raw_verification["exit_code"], bool)
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_verification_exit_code",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and isinstance(verification, dict)
                    and isinstance(
                        raw_verification := _attributes(target).get("verification"),
                        dict,
                    )
                    and not verification.get("unresolved")
                    and "command" in raw_verification
                    and (
                        not isinstance(raw_verification["command"], str)
                        or not raw_verification["command"].strip()
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_verification_command",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and isinstance(verification, dict)
                    and isinstance(
                        raw_verification := _attributes(target).get("verification"),
                        dict,
                    )
                    and "test_origin" in raw_verification
                    and (
                        not isinstance(raw_verification["test_origin"], str)
                        or raw_verification["test_origin"] not in {
                            "pre_existing",
                            "same_agent",
                        }
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_verification_test_origin",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and isinstance(verification, dict)
                    and "exit_code" in verification
                    and (
                        verification["passed"] is True
                        and verification["exit_code"] != 0
                        or verification["passed"] is False
                        and verification["exit_code"] == 0
                    )
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "conflicting_verification_outcome",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and isinstance(verification, dict)
                    and "command" not in verification
                    and not verification.get("unresolved")
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_verification_command",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "verified_by"
                    and target.kind == "verification.finished"
                    and not _event_follows(source, target)
                    and not _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "verification_chronology_undetermined",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "applies"
                    and target.kind == "change.proposed"
                    and _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "proposal_not_preceding_change",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "applies"
                    and target.kind == "change.proposed"
                    and not target.actor["id"].strip()
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "invalid_decision_actor",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and relationship.type == "applies"
                    and target.kind == "change.proposed"
                    and not _event_follows(source, target)
                    and not _event_follows(target, source)
                ):
                    invalid = {
                        **item,
                        "target_kind": target.kind,
                        "reason": "proposal_chronology_undetermined",
                    }
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    source.kind == "change.applied"
                    and (
                        relationship.type == "verified_by"
                        and target.kind != "verification.finished"
                        or relationship.type == "motivated_by"
                        and target.kind != "requirement.observed"
                        or relationship.type == "informed_by"
                        and target.kind not in {"context.read", "context.compacted"}
                        or relationship.type == "preceded_by"
                        and not target.kind.startswith("tool.call.")
                        or relationship.type == "applies"
                        and target.kind != "change.proposed"
                    )
                ):
                    invalid = {**item, "target_kind": target.kind}
                    unresolved.append(invalid)
                    source_unresolved.append(invalid)
                elif (
                    relationship.type == "corrects"
                    and source.kind == "human.corrected"
                    and target.kind != "change.applied"
                ):
                    unresolved.append({**item, "target_kind": target.kind})
        hunk = _change_hunk(source)
        integrity = _change_hunk_integrity(source)
        if hunk is not None:
            change = {
                "event_id": source.event_id,
                "actor_id": source.actor["id"],
                "hunk": hunk,
                "links": source_links,
                "unresolved": source_unresolved,
                "corrections": corrections_by_change.setdefault(source.event_id, []),
                "coverage": _evidence_coverage(
                    source_links,
                    source_unresolved,
                    integrity,
                ),
            }
            if integrity:
                change["integrity"] = integrity
            changes.append(change)
        elif any(
            issue["field"] in {
                "change",
                "path",
                "old_start",
                "old_count",
                "new_start",
                "new_count",
            }
            for issue in integrity
        ):
            invalid_changes.append({
                "event_id": source.event_id,
                "actor_id": source.actor["id"],
                "integrity": integrity,
            })
    return {
        "changes": changes,
        "invalid_changes": invalid_changes,
        "links": links,
        "unresolved": unresolved,
    }


def _evidence_coverage(
    links: list[dict[str, object]],
    unresolved: list[dict[str, object]],
    integrity: list[dict[str, str]],
) -> dict[str, object]:
    present = {
        "requirement": any(
            link.get("type") == "motivated_by"
            and link.get("target_kind") == "requirement.observed"
            and "requirement" in link
            for link in links
        ),
        "context": any(
            (
                link.get("type") == "informed_by"
                and link.get("target_kind") == "context.read"
                and "context" in link
            )
            or (
                link.get("type") == "informed_by"
                and link.get("target_kind") == "context.compacted"
                and isinstance((compaction := link.get("compaction")), dict)
                and isinstance((sources := compaction.get("sources")), list)
                and any(
                    isinstance(source, dict)
                    and source.get("type") == "summarizes"
                    and source.get("kind") == "context.read"
                    and "context" in source
                    for source in sources
                )
            )
            for link in links
        ),
        "tool": any(
            link.get("type") == "preceded_by"
            and isinstance((tool := link.get("tool")), dict)
            and ("command" in tool or "result" in tool)
            for link in links
        ),
        "verification": any(
            link.get("type") == "verified_by"
            and isinstance((verification := link.get("verification")), dict)
            and "command" in verification
            for link in links
        ),
        "decision": any(
            link.get("type") == "applies"
            and link.get("target_kind") == "change.proposed"
            and isinstance(link.get("target_actor_id"), str)
            and bool(link["target_actor_id"].strip())
            for link in links
        ),
    }
    missing = [kind for kind, is_present in present.items() if not is_present]
    unresolved_count = sum(
        link.get("type") in {
            "motivated_by",
            "informed_by",
            "preceded_by",
            "verified_by",
            "applies",
        }
        for link in unresolved
    ) + sum(
        sum(
            isinstance(source, dict) and source.get("type") == "summarizes"
            for source in compaction.get("unresolved", [])
        )
        for link in links
        if link.get("type") == "informed_by"
        and link.get("target_kind") == "context.compacted"
        and isinstance((compaction := link.get("compaction")), dict)
        and isinstance(compaction.get("unresolved"), list)
    ) + sum(
        len(verification.get("unresolved", []))
        for link in links
        if link.get("type") == "verified_by"
        and isinstance((verification := link.get("verification")), dict)
        and isinstance(verification.get("unresolved"), list)
    )
    unknown_test_origin_count = sum(
        "test_origin" not in verification
        for link in links
        if link.get("type") == "verified_by"
        and isinstance((verification := link.get("verification")), dict)
    )
    same_agent_test_count = sum(
        verification.get("test_origin") == "same_agent"
        for link in links
        if link.get("type") == "verified_by"
        and isinstance((verification := link.get("verification")), dict)
    )
    failed_verification_count = sum(
        verification.get("passed") is False
        for link in links
        if link.get("type") == "verified_by"
        and isinstance((verification := link.get("verification")), dict)
    )
    coverage = {
        "status": "incomplete"
        if missing
        or unresolved_count
        or unknown_test_origin_count
        or same_agent_test_count
        or failed_verification_count
        or integrity
        else "complete",
        "missing": missing,
        "unresolved_count": unresolved_count,
    }
    if unknown_test_origin_count:
        coverage["unknown_test_origin_count"] = unknown_test_origin_count
    if same_agent_test_count:
        coverage["same_agent_test_count"] = same_agent_test_count
    if failed_verification_count:
        coverage["failed_verification_count"] = failed_verification_count
    if integrity:
        coverage["integrity_issue_count"] = len(integrity)
    return coverage


def _change_hunk(event: Event) -> dict[str, object] | None:
    if event.kind != "change.applied":
        return None
    change = _attributes(event).get("change")
    if not isinstance(change, dict):
        return None
    path = change.get("path")
    range_keys = ("old_start", "old_count", "new_start", "new_count")
    if not isinstance(path, str) or not path.strip() or any(
        not isinstance(change.get(key), int)
        or isinstance(change.get(key), bool)
        or change[key] < 0
        for key in range_keys
    ) or any(
        change[start_key] == 0 and change[count_key] > 0
        for start_key, count_key in (("old_start", "old_count"), ("new_start", "new_count"))
    ):
        return None
    hunk = {"path": path, **{key: change[key] for key in range_keys}}
    symbol = change.get("symbol")
    if isinstance(symbol, str) and symbol.strip():
        hunk["symbol"] = symbol
    return hunk


def _change_hunk_integrity(event: Event) -> list[dict[str, str]]:
    change = _attributes(event).get("change")
    if event.kind != "change.applied":
        return []
    if not isinstance(change, dict):
        return [{"field": "change", "reason": "invalid_change_detail"}]
    integrity = []
    path = change.get("path")
    if not isinstance(path, str) or not path.strip():
        integrity.append({"field": "path", "reason": "invalid_change_path"})
    old_start = change.get("old_start")
    old_count = change.get("old_count")
    if (
        not isinstance(old_start, int)
        or isinstance(old_start, bool)
        or old_start < 0
        or old_start == 0
        and isinstance(old_count, int)
        and not isinstance(old_count, bool)
        and old_count > 0
    ):
        integrity.append({
            "field": "old_start",
            "reason": "invalid_change_old_start",
        })
    if (
        not isinstance(old_count, int)
        or isinstance(old_count, bool)
        or old_count < 0
    ):
        integrity.append({
            "field": "old_count",
            "reason": "invalid_change_old_count",
        })
    new_start = change.get("new_start")
    new_count = change.get("new_count")
    if (
        not isinstance(new_start, int)
        or isinstance(new_start, bool)
        or new_start < 0
        or new_start == 0
        and isinstance(new_count, int)
        and not isinstance(new_count, bool)
        and new_count > 0
    ):
        integrity.append({
            "field": "new_start",
            "reason": "invalid_change_new_start",
        })
    if (
        not isinstance(new_count, int)
        or isinstance(new_count, bool)
        or new_count < 0
    ):
        integrity.append({
            "field": "new_count",
            "reason": "invalid_change_new_count",
        })
    if "symbol" in change:
        symbol = change["symbol"]
        if not isinstance(symbol, str) or not symbol.strip():
            integrity.append({"field": "symbol", "reason": "invalid_change_symbol"})
    return integrity


def _verification_result(
    event: Event,
    events_by_id: dict[str, Event],
    change_event: Event | None = None,
) -> dict[str, object] | None:
    if event.kind != "verification.finished":
        return None
    verification = _attributes(event).get("verification")
    if not isinstance(verification, dict):
        return None
    command = verification.get("command")
    passed = verification.get("passed")
    if not isinstance(passed, bool):
        return None
    result: dict[str, object] = {"passed": passed}
    if isinstance(command, str) and command.strip():
        result["command"] = command
    exit_code = verification.get("exit_code")
    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        result["exit_code"] = exit_code
    test_origin = verification.get("test_origin")
    if isinstance(test_origin, str) and test_origin in {"pre_existing", "same_agent"}:
        result["test_origin"] = test_origin
    starts = []
    unresolved = []
    projected_relationships = set()
    for relationship in event.relationships:
        if relationship.type != "completes":
            continue
        relationship_key = (relationship.type, relationship.event_id)
        if relationship_key in projected_relationships:
            continue
        projected_relationships.add(relationship_key)
        started = events_by_id.get(relationship.event_id)
        if started is None:
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
            })
            continue
        if started.kind != "verification.started":
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": started.kind,
            })
            continue
        detail: dict[str, object] = {
            "event_id": started.event_id,
            "actor_id": started.actor["id"],
            "chronology": _evidence_chronology(started, event, "finish"),
        }
        if change_event is not None:
            detail["change_chronology"] = _evidence_chronology(
                started,
                change_event,
                "change",
            )
        unresolved_count_before_start = len(unresolved)
        start_after_finish = _event_follows(started, event)
        start_finish_chronology_undetermined = (
            not start_after_finish and not _event_follows(event, started)
        )
        start_before_change = (
            change_event is not None and _event_follows(change_event, started)
        )
        start_change_chronology_undetermined = (
            change_event is not None
            and not start_before_change
            and not _event_follows(started, change_event)
        )
        if start_after_finish:
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": started.kind,
                "reason": "verification_start_after_finish",
            })
        elif start_before_change:
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": started.kind,
                "reason": "verification_start_precedes_change",
            })
        started_verification = _attributes(started).get("verification")
        has_command = False
        if isinstance(started_verification, dict):
            started_command = started_verification.get("command")
            if isinstance(started_command, str) and started_command.strip():
                has_command = True
                detail["command"] = started_command
                result.setdefault("command", started_command)
                if (
                    not start_after_finish
                    and not start_before_change
                    and result["command"] != started_command
                ):
                    unresolved.append({
                        "type": relationship.type,
                        "event_id": relationship.event_id,
                        "target_kind": started.kind,
                        "reason": "conflicting_verification_command",
                    })
        starts.append(detail)
        if (
            not has_command
            and not start_after_finish
            and not start_before_change
        ):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": started.kind,
                "reason": "invalid_verification_command",
            })
        if (
            start_finish_chronology_undetermined
            and len(unresolved) == unresolved_count_before_start
        ):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": started.kind,
                "reason": "verification_start_finish_chronology_undetermined",
            })
        elif (
            start_change_chronology_undetermined
            and len(unresolved) == unresolved_count_before_start
        ):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": started.kind,
                "reason": "verification_start_change_chronology_undetermined",
            })
    if starts:
        result["starts"] = starts
    if unresolved:
        result["unresolved"] = unresolved
    return result


def _requirement_detail(event: Event) -> dict[str, object] | None:
    if event.kind != "requirement.observed":
        return None
    requirement = _attributes(event).get("requirement")
    if not isinstance(requirement, dict):
        return None
    requirement_id = requirement.get("id")
    text = requirement.get("text")
    if not isinstance(requirement_id, str) or not requirement_id.strip():
        return None
    if not isinstance(text, str) or not text.strip():
        return None
    return {"id": requirement_id, "text": text}


def _context_read_detail(event: Event) -> dict[str, object] | None:
    if event.kind != "context.read":
        return None
    context = _attributes(event).get("context")
    if not isinstance(context, dict):
        return None
    path = context.get("path")
    if not isinstance(path, str) or not path.strip():
        return None
    detail: dict[str, object] = {"path": path}
    line_start = context.get("line_start")
    if isinstance(line_start, int) and not isinstance(line_start, bool) and line_start > 0:
        detail["line_start"] = line_start
    line_end = context.get("line_end")
    if (
        isinstance(line_end, int)
        and not isinstance(line_end, bool)
        and line_end > 0
        and ("line_start" not in detail or line_end >= detail["line_start"])
    ):
        detail["line_end"] = line_end
    symbol = context.get("symbol")
    if isinstance(symbol, str) and symbol.strip():
        detail["symbol"] = symbol
    return detail


def _has_invalid_context_line_start(event: Event) -> bool:
    context = _attributes(event).get("context")
    if not isinstance(context, dict) or "line_start" not in context:
        return False
    line_start = context["line_start"]
    return (
        not isinstance(line_start, int)
        or isinstance(line_start, bool)
        or line_start <= 0
    )


def _has_invalid_context_line_end(event: Event) -> bool:
    context = _attributes(event).get("context")
    if not isinstance(context, dict) or "line_end" not in context:
        return False
    line_end = context["line_end"]
    if not isinstance(line_end, int) or isinstance(line_end, bool) or line_end <= 0:
        return True
    line_start = context.get("line_start")
    return (
        isinstance(line_start, int)
        and not isinstance(line_start, bool)
        and line_start > 0
        and line_end < line_start
    )


def _has_invalid_context_symbol(event: Event) -> bool:
    context = _attributes(event).get("context")
    if not isinstance(context, dict) or "symbol" not in context:
        return False
    symbol = context["symbol"]
    return not isinstance(symbol, str) or not symbol.strip()


def _tool_call_detail(event: Event) -> dict[str, object] | None:
    if not event.kind.startswith("tool.call."):
        return None
    operation = event.operation
    detail: dict[str, object] = {}
    status = operation["status"]
    if status.strip():
        detail["status"] = status
    name = operation.get("name")
    if isinstance(name, str) and name.strip():
        detail["name"] = name
    tool = _attributes(event).get("tool")
    if not isinstance(tool, dict):
        return detail
    for key in ("command", "result"):
        value = tool.get(key)
        if isinstance(value, str) and value.strip():
            detail[key] = value
    exit_code = tool.get("exit_code")
    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        detail["exit_code"] = exit_code
    return detail


def _context_compaction_detail(
    event: Event,
    events_by_id: dict[str, Event],
) -> dict[str, object] | None:
    if event.kind != "context.compacted":
        return None
    sources = []
    unresolved = []
    projected_relationships = set()
    for relationship in event.relationships:
        relationship_key = (relationship.type, relationship.event_id)
        if relationship_key in projected_relationships:
            continue
        projected_relationships.add(relationship_key)
        item: dict[str, object] = {
            "type": relationship.type,
            "event_id": relationship.event_id,
        }
        source = events_by_id.get(relationship.event_id)
        if source is None:
            unresolved.append(item)
            continue
        if relationship.type == "summarizes" and source.kind != "context.read":
            item["target_kind"] = source.kind
            unresolved.append(item)
            continue
        item["kind"] = source.kind
        item["actor_id"] = source.actor["id"]
        context = _context_read_detail(source)
        if relationship.type == "summarizes" and context is None:
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": source.kind,
                "reason": "invalid_context_detail",
            })
            continue
        if context is not None:
            item["context"] = context
        if relationship.type == "summarizes":
            item["chronology"] = _evidence_chronology(
                source,
                event,
                "compaction",
            )
        sources.append(item)
        source_chronology = item.get("chronology")
        if relationship.type == "summarizes" and _event_follows(source, event):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": source.kind,
                "reason": "context_not_preceding_compaction",
            })
        elif relationship.type == "summarizes" and source_chronology == "undetermined":
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": source.kind,
                "reason": "context_source_chronology_undetermined",
            })
        elif relationship.type == "summarizes" and _has_invalid_context_line_start(source):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": source.kind,
                "reason": "invalid_context_line_start",
            })
        elif relationship.type == "summarizes" and _has_invalid_context_line_end(source):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": source.kind,
                "reason": "invalid_context_line_end",
            })
        elif relationship.type == "summarizes" and _has_invalid_context_symbol(source):
            unresolved.append({
                "type": relationship.type,
                "event_id": relationship.event_id,
                "target_kind": source.kind,
                "reason": "invalid_context_symbol",
            })
    return {"sources": sources, "unresolved": unresolved}


def _human_correction(event: Event) -> dict[str, object] | None:
    if event.kind != "human.corrected":
        return None
    correction = _attributes(event).get("correction")
    if not isinstance(correction, dict):
        return None
    action = correction.get("action")
    if not isinstance(action, str) or action not in {"modified", "reverted"}:
        return None
    return {"action": action}


def _actor_role(events: Iterable[Event], actor_id: str) -> object:
    for event in events:
        if event.actor["id"] == actor_id and "role" in event.actor:
            return event.actor["role"]
    return None


def _actor_model(events: Iterable[Event], actor_id: str) -> object:
    for event in events:
        if event.actor["id"] != actor_id:
            continue
        actor = event.actor
        if "model" in actor:
            return actor["model"]
        attributes = _attributes(event)
        if "model" in attributes:
            return attributes["model"]
    return None


def _usage_summary(events: Iterable[Event]) -> dict[str, object]:
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cost_usd": 0.0,
    }
    available = {key: False for key in totals}
    for event in events:
        usage = _usage(event)
        for key in totals:
            value = usage.get(key)
            if _number(value):
                totals[key] += value
                available[key] = True
    return {
        key: {"available": available[key], "value": totals[key] if available[key] else None}
        for key in totals
    }


def _usage(event: Event) -> dict[str, object]:
    raw = event.raw
    usage = raw.get("usage")
    if isinstance(usage, dict):
        result = dict(usage)
    else:
        result = {}
    attributes = _attributes(event)
    attribute_usage = attributes.get("usage")
    if isinstance(attribute_usage, dict):
        result.update(attribute_usage)
    for key in ("input_tokens", "output_tokens", "total_tokens", "cost_usd"):
        if key in attributes and key not in result:
            result[key] = attributes[key]
        if key in raw and key not in result:
            result[key] = raw[key]
    return result


def _attributes(event: Event) -> dict[str, object]:
    attributes = event.raw.get("attributes")
    return dict(attributes) if isinstance(attributes, dict) else {}


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _terminal_state(event: Event) -> str | None:
    if event.kind == "trace.completed":
        return "completed"
    if event.kind == "trace.failed":
        return "failed"
    return None


def _cursor_from_path(path: str) -> int:
    values = parse_qs(urlparse(path).query).get("cursor", ["0"])
    try:
        return max(0, int(values[0]))
    except (TypeError, ValueError):
        return 0


def _validate_remote_access(config: ServeConfig) -> None:
    remote_host = config.host not in {"127.0.0.1", "localhost", "::1"}
    if remote_host and not config.remote_access:
        raise ValueError("non-loopback host requires --remote-access")
    if config.remote_access and config.unsafe_unredacted:
        raise ValueError("--unsafe-unredacted cannot be combined with remote access")
