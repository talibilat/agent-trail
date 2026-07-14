from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
    loop_threshold: int = 4
    stall_seconds: float = 30.0
    max_bytes: int = 16 * 1024 * 1024


class RunStore:
    def __init__(
        self,
        index: TraceIndex | None = None,
        errors: Iterable[IngestionError] = (),
        *,
        source_kind: str = "snapshot",
    ) -> None:
        self._reader = JSONLReader(retain_events=False)
        self._index = index
        if self._index is None:
            self._index = TraceIndex()
        self._errors = tuple(errors)
        self._findings: list[dict[str, object]] = []
        self._terminal_traces: dict[str, str] = {}
        self._source_status: dict[str, object] = {
            "kind": source_kind,
            "connected": False,
            "state": "idle",
        }
        self._cursor = 0
        self._updates: list[dict[str, object]] = []
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
    ) -> "RunStore":
        index = TraceIndex(
            loop_threshold=loop_threshold,
            stall_seconds=stall_seconds,
            max_bytes=max_bytes,
        )
        store = cls(index, source_kind="snapshot")
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
            prior_terminal_state = self._terminal_traces.get(safe.trace_id)
            self._index.add(safe)
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
            with self._condition:
                while self._cursor < next_cursor:
                    self._condition.wait(timeout=15)
                    if self._cursor < next_cursor:
                        heartbeat = {
                            "cursor": self._cursor,
                            "type": "heartbeat",
                            "data": {},
                        }
                        break
                if heartbeat is not None:
                    pending = []
                else:
                    pending = [
                        update for update in self._updates
                        if update["cursor"] >= next_cursor
                    ]
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
                "ingestion_errors": list(self._ingestion_findings()),
            }

    def run_detail(self, trace_id: str) -> dict[str, object] | None:
        with self._lock:
            trace_ids = {event.trace_id for event in self._index.events}
            if trace_id not in trace_ids:
                return None
            view = self._index.trace(trace_id)
            now = max((event.timestamp for event in view.events), default=_epoch())
            return {
                "api_version": "v1",
                "cursor": self._cursor,
                "run": self._summary(trace_id),
                "events": [
                    self._event_message(event, event.event_id in view.uncertain_event_ids)
                    for event in view.events
                ],
                "actors": [
                    {
                        "id": actor_id,
                        "status": actor.status,
                        "operation": actor.operation,
                        "last_activity": actor.last_activity.isoformat(),
                        "last_activity_event_id": actor.last_activity_event_id,
                        "open_span_ids": list(actor.open_span_ids),
                        "uncertain": actor.uncertain,
                    }
                    for actor_id, actor in view.actors.items()
                ],
                "warnings": [
                    {
                        "code": warning.code,
                        "event_id": warning.event_id,
                        "trace_id": warning.trace_id,
                        "actor_id": warning.actor_id,
                        "summary": warning.summary,
                        "evidence": warning.evidence,
                    }
                    for warning in self._index.warnings(now=now)
                    if warning.trace_id == trace_id
                ],
                "source": dict(self._source_status),
                "findings": [
                    finding for finding in self._findings
                    if finding.get("trace_id") in {None, trace_id}
                ],
            }

    def _summary(self, trace_id: str) -> dict[str, object]:
        view = self._index.trace(trace_id)
        timestamps = [event.timestamp for event in view.events]
        return {
            "trace_id": trace_id,
            "event_count": len(view.events),
            "actor_count": len(view.actors),
            "started_at": min(timestamps).isoformat() if timestamps else None,
            "ended_at": max(timestamps).isoformat() if timestamps else None,
            "warning_count": sum(
                1 for warning in self._index.warnings(now=max(timestamps, default=_epoch()))
                if warning.trace_id == trace_id
            ),
            "state": self._lifecycle_state(trace_id),
        }

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

    def _ingestion_findings(self) -> Iterable[dict[str, object]]:
        return (
            finding for finding in self._findings
            if finding.get("kind") == "ingestion"
        )

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
    ) -> dict[str, object]:
        if uncertain is None:
            uncertain = event.event_id in self._index.trace(event.trace_id).uncertain_event_ids
        return {
            "event_id": event.event_id,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "parent_span_id": event.parent_span_id,
            "emitter_id": event.emitter_id,
            "sequence": event.sequence,
            "timestamp": event.timestamp.isoformat(),
            "kind": event.kind,
            "actor": event.actor,
            "operation": event.operation,
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
    )
    reader = threading.Thread(
        target=_read_stream,
        args=(source, store, config),
        kwargs={"source_kind": "stdin"},
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
    server = make_server(store, host=config.host, port=config.port)
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/"
    print(f"Agent Tail serve mode listening on {url}", flush=True)
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
    identity = _file_identity(path)
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
    *,
    source_kind: str,
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
        state = "disconnected" if source_kind == "stdin" else "caught_up"
        store.set_source_status(connected=False, state=state)


def _file_identity(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino


def make_server(store: RunStore, *, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    class Handler(_Handler):
        run_store = store

    return _Server((host, port), Handler)


class _Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address) -> None:
        if isinstance(sys.exception(), ConnectionResetError):
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    run_store: RunStore

    def do_GET(self) -> None:
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
            trace_id = unquote(path.removeprefix(prefix))
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
