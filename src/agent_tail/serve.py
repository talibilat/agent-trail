from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from typing import Callable, Iterable, TextIO
from urllib.parse import unquote, urlparse

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
    def __init__(self, index: TraceIndex, errors: Iterable[IngestionError]) -> None:
        self._index = index
        self._errors = tuple(errors)
        self._lock = threading.RLock()

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
        reader = JSONLReader(retain_events=False)
        index = TraceIndex(
            loop_threshold=loop_threshold,
            stall_seconds=stall_seconds,
            max_bytes=max_bytes,
        )
        for line in lines:
            event = reader.feed(line)
            if event is not None:
                index.add(sanitize_event(
                    event,
                    full_payloads=full_payloads,
                    unsafe_unredacted=unsafe_unredacted,
                ))
        return cls(index, reader.all_errors)

    def list_runs(self) -> dict[str, object]:
        with self._lock:
            trace_ids = list(dict.fromkeys(event.trace_id for event in self._index.events))
            runs = [self._summary(trace_id) for trace_id in trace_ids]
            return {
                "api_version": "v1",
                "runs": runs,
                "ingestion_errors": [self._error(error) for error in self._errors],
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
                "run": self._summary(trace_id),
                "events": [
                    {
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
                        "uncertain": event.event_id in view.uncertain_event_ids,
                    }
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
        }

    @staticmethod
    def _error(error: IngestionError) -> dict[str, object]:
        return {"line": error.line, "message": error.message}


def serve(
    source: TextIO,
    *,
    config: ServeConfig,
    open_url: Callable[[str], object] | None = None,
) -> int:
    store = RunStore.from_lines(
        source,
        full_payloads=config.full_payloads,
        unsafe_unredacted=config.unsafe_unredacted,
        loop_threshold=config.loop_threshold,
        stall_seconds=config.stall_seconds,
        max_bytes=config.max_bytes,
    )
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


def make_server(store: RunStore, *, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    class Handler(_Handler):
        run_store = store

    return ThreadingHTTPServer((host, port), Handler)


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
