from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import math
import os
import posixpath
import re
import shlex
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import sys
import threading
import time
from typing import Callable, Iterable, Mapping, TextIO
from urllib.parse import parse_qs, unquote, urlparse

from .core import Event, IngestionError, JSONLReader, TraceIndex, sanitize_event
from .security import security_projection
from .warning_policy import WarningPolicy


@dataclass(frozen=True)
class ServeConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    open_browser: bool = False
    full_payloads: bool = False
    metadata_only: bool = False
    unsafe_unredacted: bool = False
    remote_access: bool = False
    access_token: str | None = None
    loop_threshold: int = 4
    fan_out_threshold: int = 8
    stall_seconds: float = 30.0
    max_bytes: int = 16 * 1024 * 1024
    max_live_updates: int = 10_000
    warning_policy: WarningPolicy | None = None

    def __post_init__(self) -> None:
        if self.full_payloads and self.metadata_only:
            raise ValueError("full_payloads and metadata_only cannot both be enabled")
        if (
            not isinstance(self.max_live_updates, int)
            or isinstance(self.max_live_updates, bool)
            or self.max_live_updates <= 0
        ):
            raise ValueError("max_live_updates must be a positive integer")
        if (
            not isinstance(self.fan_out_threshold, int)
            or isinstance(self.fan_out_threshold, bool)
            or self.fan_out_threshold <= 0
        ):
            raise ValueError("fan_out_threshold must be a positive integer")


class RunStore:
    def __init__(
        self,
        index: TraceIndex | None = None,
        errors: Iterable[IngestionError] = (),
        *,
        source_kind: str = "snapshot",
        metadata_only: bool = False,
        max_live_updates: int = 10_000,
        warning_policy: WarningPolicy | None = None,
    ) -> None:
        if (
            not isinstance(max_live_updates, int)
            or isinstance(max_live_updates, bool)
            or max_live_updates <= 0
        ):
            raise ValueError("max_live_updates must be a positive integer")
        self._reader = JSONLReader(retain_events=False)
        self._metadata_only = metadata_only
        self._index = index
        if self._index is None:
            self._index = TraceIndex(warning_policy=warning_policy)
        self._trace_by_event_id = {
            event.event_id: event.trace_id for event in self._index.events
        }
        self._errors = tuple(errors)
        self._findings: list[dict[str, object]] = []
        for error in self._errors:
            message = error.message
            if message.startswith("duplicate event ID"):
                code = "DUPLICATE_EVENT"
            elif message.startswith("invalid JSON"):
                code = "INVALID_JSON"
            else:
                code = "INVALID_EVENT"
            self._findings.append({
                "kind": "ingestion",
                "code": code,
                "message": message,
                "line": error.line,
                "event_id": None,
                "trace_id": None,
                "detected_at": _epoch().isoformat(),
            })
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
        metadata_only: bool = False,
        unsafe_unredacted: bool = False,
        loop_threshold: int = 4,
        fan_out_threshold: int = 8,
        stall_seconds: float = 30.0,
        max_bytes: int = 16 * 1024 * 1024,
        max_live_updates: int = 10_000,
        warning_policy: WarningPolicy | None = None,
    ) -> "RunStore":
        index = TraceIndex(
            loop_threshold=loop_threshold,
            fan_out_threshold=fan_out_threshold,
            stall_seconds=stall_seconds,
            max_bytes=max_bytes,
            warning_policy=warning_policy,
        )
        store = cls(
            index,
            source_kind="snapshot",
            metadata_only=metadata_only,
            max_live_updates=max_live_updates,
        )
        for line in lines:
            store.feed_line(
                line,
                full_payloads=full_payloads,
                unsafe_unredacted=unsafe_unredacted,
                defer_uncertainty_projection=True,
            )
        store.set_source_status(connected=False, state="disconnected")
        store.finalize_initial_uncertainty()
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
        defer_uncertainty_projection: bool = False,
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
                metadata_only=self._metadata_only,
                unsafe_unredacted=unsafe_unredacted,
            )
            if self._metadata_only:
                self._payload_details[(safe.trace_id, safe.event_id)] = _payload_preview(safe)
            else:
                retained = sanitize_event(
                    event,
                    full_payloads=True,
                    unsafe_unredacted=unsafe_unredacted,
                )
                self._payload_details[(safe.trace_id, safe.event_id)] = _payload_preview(retained)
            prior_terminal_state = self._terminal_traces.get(safe.trace_id)
            self._index.add(safe)
            self._trace_by_event_id[safe.event_id] = safe.trace_id
            eviction_count = self._index.eviction_count
            if eviction_count != self._last_eviction_count:
                self._sync_payload_details(self._index.recent_evictions)
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
            uncertainty = False if defer_uncertainty_projection else None
            self._publish("event", self._event_message(safe, uncertainty))
            return safe

    def finalize_initial_uncertainty(self) -> None:
        with self._condition:
            uncertainty_by_event_id = {}
            trace_ids = dict.fromkeys(event.trace_id for event in self._index.events)
            for trace_id in trace_ids:
                view = self._index.trace(trace_id)
                uncertainty_by_event_id.update(
                    (event.event_id, event.event_id in view.uncertain_event_ids)
                    for event in view.events
                )
            for update in self._updates:
                if update.get("type") != "event":
                    continue
                data = update.get("data")
                if not isinstance(data, dict):
                    continue
                event_id = data.get("event_id")
                if event_id in uncertainty_by_event_id:
                    data["uncertain"] = uncertainty_by_event_id[event_id]

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
            policy = self._index.warning_policy_projection(now=now, trace_id=trace_id)
            projection = _relationships(view)
            context_provenance = _context_provenance(view)
            evidence_map = _event_evidence(view.events)
            security = security_projection(
                view,
                evicted_event_ids=self._index.metadata_evictions(trace_id),
            )
            runtime_warnings = self._warnings_for_trace(
                trace_id, now, security["findings"]
            )
            outcome_cost = _outcome_cost(
                view,
                evidence_map,
                runtime_warnings + projection["warnings"],
                evicted_event_ids=self._index.metadata_evictions(trace_id),
                retained_event_traces=self._trace_by_event_id,
            )
            started_at = min((event.timestamp for event in view.events), default=None)
            return {
                "api_version": "v1",
                "cursor": self._cursor,
                "run": self._summary(
                    trace_id, projection=projection, security=security
                ),
                **({"payload_mode": "metadata-only"} if self._metadata_only else {}),
                "duration_seconds": _duration_seconds(view.events),
                "usage": _usage_summary(view.events),
                "outcome_cost": outcome_cost,
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
                "warnings": runtime_warnings + projection["warnings"],
                "links": projection["links"],
                "unresolved_endpoints": projection["unresolved_endpoints"],
                "evidence_map": evidence_map,
                "context_provenance": context_provenance,
                "security": security,
                "source": dict(self._source_status),
                "findings": [
                    finding for finding in self._findings
                    if finding.get("trace_id") in {None, trace_id}
                ],
                **({"warning_policy": policy} if policy is not None else {}),
            }

    def _summary(
        self,
        trace_id: str,
        *,
        projection: dict[str, object] | None = None,
        security: dict[str, object] | None = None,
    ) -> dict[str, object]:
        view = self._index.trace(trace_id)
        timestamps = [event.timestamp for event in view.events]
        if projection is None:
            projection = _relationships(view)
        if security is None:
            security = security_projection(
                view,
                evicted_event_ids=self._index.metadata_evictions(trace_id),
            )
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
            "warning_count": (
                runtime_warning_count
                + len(projection["warnings"])
                + len(security["findings"])
            ),
            "state": self._lifecycle_state(trace_id),
            **({"payload_mode": "metadata-only"} if self._metadata_only else {}),
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

    def _sync_payload_details(
        self,
        evictions: Iterable[tuple[str, str, str]],
    ) -> None:
        for trace_id, event_id, evicted in evictions:
            self._payload_details.pop((trace_id, event_id), None)
            if evicted == "metadata":
                self._trace_by_event_id.pop(event_id, None)

    def _warning_now(self, events: Iterable[Event]) -> datetime:
        event_list = list(events)
        if self._source_status.get("connected"):
            return datetime.now(timezone.utc)
        return max((event.timestamp for event in event_list), default=_epoch())

    def _warnings_for_trace(
        self,
        trace_id: str,
        now: datetime,
        security_findings: Iterable[dict[str, object]] = (),
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
        for finding in security_findings:
            event_id = str(finding["operation_event_id"])
            actor_id = str(finding["operation_actor_id"])
            key = (str(finding["code"]), event_id, actor_id)
            current_keys.add(key)
            prior = self._warning_history.get(key, {})
            self._warning_history[key] = {
                "category": "security",
                "code": finding["code"],
                "event_id": event_id,
                "trace_id": trace_id,
                "actor_id": actor_id,
                "summary": finding["summary"],
                "evidence": json.dumps(finding, sort_keys=True, separators=(",", ":")),
                "active": True,
                "detected_at": prior.get("detected_at", now.isoformat()),
                "resolved_at": None,
            }
        for key, record in list(self._warning_history.items()):
            if record.get("trace_id") == trace_id and key not in current_keys and record.get("active"):
                record["active"] = False
                record["resolved_at"] = now.isoformat()
        return [
            dict(record) for record in self._warning_history.values()
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
            fan_out_threshold=config.fan_out_threshold,
            stall_seconds=config.stall_seconds,
            max_bytes=config.max_bytes,
            warning_policy=config.warning_policy,
        ),
        source_kind="stdin",
        metadata_only=config.metadata_only,
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
    store = RunStore(
        TraceIndex(
            loop_threshold=config.loop_threshold,
            fan_out_threshold=config.fan_out_threshold,
            stall_seconds=config.stall_seconds,
            max_bytes=config.max_bytes,
            warning_policy=config.warning_policy,
        ),
        source_kind="file",
        metadata_only=config.metadata_only,
        max_live_updates=config.max_live_updates,
    )
    store.set_source_status(connected=True, state="reading")
    initial_position = 0
    with path.open(encoding="utf-8") as source:
        initial_stat = os.fstat(source.fileno())
        initial_identity = (initial_stat.st_dev, initial_stat.st_ino)
        while True:
            position = source.tell()
            line = source.readline()
            if not line:
                initial_position = position
                break
            if not line.endswith("\n"):
                initial_position = position
                break
            initial_position = source.tell()
            store.feed_line(
                line,
                full_payloads=config.full_payloads,
                unsafe_unredacted=config.unsafe_unredacted,
                defer_uncertainty_projection=True,
            )
    store.set_source_status(connected=True, state="caught_up")
    store.finalize_initial_uncertainty()
    stop = threading.Event()
    reader = start_file_follower(
        path,
        store,
        config=config,
        stop=stop,
        initial_position=initial_position,
        initial_identity=initial_identity,
    )
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
    print(f"AgentTrail serve mode listening on {url}", flush=True)
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
    initial_position: int = 0,
    initial_identity: tuple[int, int] | None = None,
) -> threading.Thread:
    stop = stop or threading.Event()
    thread = threading.Thread(
        target=_follow_file,
        args=(
            path,
            store,
            config,
            stop,
            poll_seconds,
            initial_position,
            initial_identity,
        ),
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
    initial_position: int = 0,
    initial_identity: tuple[int, int] | None = None,
) -> None:
    store.set_source_status(connected=True, state="reading")
    source = path.open(encoding="utf-8")
    stat = path.stat()
    identity = (stat.st_dev, stat.st_ino)
    position = initial_position if initial_identity in {None, identity} else 0
    source.seek(position)
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
        if isinstance(metadata, dict) and metadata.get("omitted") is True:
            return {"state": "omitted", "metadata": metadata}
        if not payload and metadata is not None:
            return {"state": "evicted", "metadata": metadata}
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


def _coordination_warnings(
    view,
    warning_factory: Callable[..., object],
    *,
    fan_out_threshold: int,
) -> list[object]:
    events = list(view.events)
    events_by_id = {event.event_id: event for event in events}
    projection = _relationships(view)
    parents = projection["parents"]
    actor_events: dict[str, list[Event]] = {}
    for event in events:
        actor_events.setdefault(str(event.actor["id"]), []).append(event)

    def causal_before(before: Event, after: Event) -> bool:
        if before.emitter_id == after.emitter_id:
            return before.sequence < after.sequence
        return bool(
            view.causal_ancestors[after.event_id] & view.event_bits[before.event_id]
        )

    def lifecycle_before(before: Event, after: Event) -> bool:
        if before.emitter_id == after.emitter_id:
            return before.sequence < after.sequence
        if causal_before(before, after):
            return True
        if causal_before(after, before):
            return False
        return before.timestamp < after.timestamp

    def terminal_event(actor_id: str) -> Event | None:
        activity = actor_events.get(actor_id, [])
        return next(
            (candidate for candidate in reversed(activity) if _terminal_operation(candidate)),
            None,
        )

    def warning(
        code: str,
        event: Event,
        summary: str,
        cited: Iterable[Event],
        warning_actor_id: str | None = None,
        **evidence: object,
    ) -> object:
        cited_events = []
        cited_ids = set()
        for item in cited:
            if item.event_id not in cited_ids:
                cited_events.append(item)
                cited_ids.add(item.event_id)
        evidence["event_ids"] = [item.event_id for item in cited_events]
        evidence["associated_usage"] = _usage_summary(cited_events)
        return warning_factory(
            code,
            event.event_id,
            event.trace_id,
            warning_actor_id or str(event.actor["id"]),
            summary,
            **evidence,
        )

    warnings: list[object] = []

    # Fan-out is measured at child-start boundaries. Cross-emitter timestamps can
    # establish lifecycle interval order, but equal timestamps remain unknown.
    children_by_parent: dict[str, list[str]] = {}
    for child_id, parent_id in parents.items():
        children_by_parent.setdefault(str(parent_id), []).append(str(child_id))
    for parent_id, child_ids in children_by_parent.items():
        intervals = []
        for child_id in child_ids:
            activity = actor_events.get(child_id, [])
            if activity:
                intervals.append((child_id, activity[0], terminal_event(child_id)))
        best: tuple[list[tuple[str, Event, Event | None]], list[str], Event] | None = None
        for _, boundary, _ in intervals:
            open_intervals = []
            unknown_ids = []
            for interval in intervals:
                child_id, start, end = interval
                start_known = start.event_id == boundary.event_id or lifecycle_before(
                    start, boundary
                )
                start_after = lifecycle_before(boundary, start)
                if not start_known:
                    if not start_after:
                        unknown_ids.append(child_id)
                    continue
                if end is None or lifecycle_before(boundary, end):
                    open_intervals.append(interval)
                elif not lifecycle_before(end, boundary):
                    unknown_ids.append(child_id)
            if len(open_intervals) > fan_out_threshold and (
                best is None or len(open_intervals) > len(best[0])
            ):
                best = (open_intervals, unknown_ids, boundary)
        if best is not None:
            open_intervals, unknown_ids, boundary = best
            evidence_events = [start for _, start, _ in open_intervals]
            evidence_events.extend(
                end for _, _, end in open_intervals if end is not None
            )
            warnings.append(warning(
                "HIGH_FAN_OUT",
                boundary,
                f"{parent_id} had {len(open_intervals)} simultaneously open direct children",
                evidence_events,
                warning_actor_id=parent_id,
                parent_actor_id=parent_id,
                threshold=fan_out_threshold,
                concurrent_child_ids=[item[0] for item in open_intervals],
                concurrency_unknown_child_ids=unknown_ids,
            ))

    changes: list[tuple[Event, str, str | None]] = []
    for event in events:
        if event.kind != "change.applied":
            continue
        change = _attributes(event).get("change")
        if not isinstance(change, dict):
            continue
        path, reason = _normalized_repository_path(change.get("path"))
        if path is None or reason is not None:
            continue
        symbol = change.get("symbol")
        changes.append((
            event,
            path,
            symbol.strip() if isinstance(symbol, str) and symbol.strip() else None,
        ))
    changes_by_path: dict[str, list[tuple[Event, str | None]]] = {}
    for event, path, symbol in changes:
        prior_changes = changes_by_path.setdefault(path, [])
        for prior, prior_symbol in prior_changes:
            if prior.actor["id"] == event.actor["id"]:
                continue
            if causal_before(prior, event) or causal_before(event, prior):
                continue
            matching_symbol = (
                symbol if symbol is not None and symbol == prior_symbol else None
            )
            warnings.append(warning(
                "OVERLAPPING_CHANGE",
                event,
                f"distinct actors changed {path} without an established causal order",
                (prior, event),
                path=path,
                actor_ids=[prior.actor["id"], event.actor["id"]],
                matching_symbol=matching_symbol,
                causal_order="unknown",
            ))
            break
        prior_changes.append((event, symbol))

    operation_groups: dict[tuple[str, str, str, str], list[Event]] = {}
    for event in events:
        signature = _redundant_operation_signature(event, events_by_id)
        snapshot = _validated_snapshot(event)
        if signature is None or snapshot is None:
            continue
        operation_type, normalized = signature
        key = (operation_type, normalized, snapshot[0], snapshot[1])
        prior_events = operation_groups.setdefault(key, [])
        prior = next(
            (item for item in prior_events if item.actor["id"] != event.actor["id"]),
            None,
        )
        if prior is not None:
            warnings.append(warning(
                "REDUNDANT_OPERATION",
                event,
                f"different actors repeated an identical {operation_type} on the same repository snapshot",
                (prior, event),
                operation_type=operation_type,
                normalized_signature=normalized,
                repository={"commit": snapshot[0], "worktree_sha256": snapshot[1]},
                actor_ids=[prior.actor["id"], event.actor["id"]],
            ))
        prior_events.append(event)

    for child_id, parent_id in parents.items():
        child_end = terminal_event(str(child_id))
        parent_end = terminal_event(str(parent_id))
        if child_end is not None and _successful_operation(child_end) and parent_end is not None:
            result_before_end = causal_before(child_end, parent_end)
            if result_before_end or child_end.event_id == parent_end.event_id:
                consumed = False
                for source in actor_events.get(str(parent_id), []):
                    if not any(
                        relationship.type == "consumes"
                        and relationship.event_id == child_end.event_id
                        for relationship in source.relationships
                    ):
                        continue
                    if source.event_id == parent_end.event_id or causal_before(source, parent_end):
                        consumed = True
                        break
                if not consumed:
                    warnings.append(warning(
                        "UNCONSUMED_CHILD_RESULT",
                        child_end,
                        f"{parent_id} completed without explicitly consuming {child_id}'s result",
                        (child_end, parent_end),
                        parent_actor_id=parent_id,
                        child_actor_id=child_id,
                        result_event_id=child_end.event_id,
                        parent_terminal_event_id=parent_end.event_id,
                        consumes_relationship="absent",
                    ))

        if parent_end is None:
            continue
        for child_event in actor_events.get(str(child_id), []):
            if causal_before(parent_end, child_event):
                warnings.append(warning(
                    "CHILD_AFTER_PARENT_END",
                    child_event,
                    f"{child_id} produced an event after {parent_id}'s terminal event",
                    (parent_end, child_event),
                    parent_actor_id=parent_id,
                    child_actor_id=child_id,
                    parent_terminal_event_id=parent_end.event_id,
                    ordering="causal",
                ))
    return warnings


def _terminal_operation(event: Event) -> bool:
    return event.operation["status"].strip().lower() in TraceIndex._TERMINAL_STATUSES


def _successful_operation(event: Event) -> bool:
    return event.operation["status"].strip().lower() in {
        "complete", "completed", "done", "succeeded", "success",
    }


def _validated_snapshot(event: Event) -> tuple[str, str] | None:
    diagnostics: list[dict[str, object]] = []
    snapshot = _repository_snapshot(event, diagnostics)
    commit = snapshot["commit"]
    worktree = snapshot["worktree_sha256"]
    if (
        diagnostics
        or commit.get("availability") != "available"
        or worktree.get("availability") != "available"
    ):
        return None
    return str(commit["value"]), str(worktree["value"])


def _redundant_operation_signature(
    event: Event,
    events_by_id: dict[str, Event],
) -> tuple[str, str] | None:
    if event.kind == "context.search":
        search = _attributes(event).get("search")
        if not isinstance(search, dict):
            return None
        query = search.get("query")
        matches = search.get("matches")
        if not isinstance(query, str) or not query.strip() or not isinstance(matches, list):
            return None
        normalized_matches = []
        seen_matches = set()
        for match in matches:
            path, reason = _normalized_repository_path(match)
            if path is None or reason is not None or path in seen_matches:
                return None
            normalized_matches.append(path)
            seen_matches.add(path)
        signature = json.dumps(
            {"query": query.strip(), "matches": sorted(set(normalized_matches))},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return "search", signature
    if event.kind != "verification.finished":
        return None
    raw_verification = _attributes(event).get("verification")
    if not isinstance(raw_verification, dict):
        return None
    supplied_command = raw_verification.get("command")
    if "command" in raw_verification and (
        not isinstance(supplied_command, str) or not supplied_command.strip()
    ):
        return None
    passed = raw_verification.get("passed")
    exit_code = raw_verification.get("exit_code")
    if not isinstance(passed, bool) or (
        "exit_code" in raw_verification
        and (
            not isinstance(exit_code, int)
            or isinstance(exit_code, bool)
            or (passed and exit_code != 0)
            or (not passed and exit_code == 0)
        )
    ):
        return None
    verification = _verification_result(event, events_by_id)
    if not isinstance(verification, dict) or verification.get("unresolved"):
        return None
    command = verification.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    try:
        shlex.split(command)
    except ValueError:
        return None
    return "verification", command.strip()


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


_SHA256 = re.compile(r"[0-9a-f]{64}")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_CONTEXT_PROVENANCE_KINDS = {
    "context.read",
    "context.search",
    "context.compacted",
    "change.applied",
}


def _normalized_repository_path(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, "invalid_repository_path"
    path = value.replace("\\", "/")
    if path.startswith("/") or _WINDOWS_ABSOLUTE_PATH.match(path):
        return None, "absolute_repository_path"
    if ".." in path.split("/"):
        return None, "parent_traversal_repository_path"
    normalized = posixpath.normpath(path)
    if normalized in {"", "."}:
        return None, "invalid_repository_path"
    return normalized, None


def _hash_field(
    container: object,
    field: str,
    diagnostic_prefix: str,
    diagnostics: list[dict[str, object]],
) -> dict[str, object]:
    if not isinstance(container, dict) or field not in container:
        return {"availability": "absent"}
    value = container[field]
    if isinstance(value, str) and _SHA256.fullmatch(value):
        return {"availability": "available", "value": value}
    diagnostics.append({
        "code": f"malformed_{diagnostic_prefix}",
        "field": field,
    })
    return {"availability": "malformed"}


def _repository_snapshot(
    event: Event,
    diagnostics: list[dict[str, object]],
) -> dict[str, object]:
    attributes = _attributes(event)
    repository = attributes.get("repository")
    if repository is not None and not isinstance(repository, dict):
        diagnostics.append({
            "code": "malformed_repository_snapshot",
            "field": "repository",
        })
    commit: dict[str, object] = {"availability": "absent"}
    if isinstance(repository, dict) and "commit" in repository:
        value = repository["commit"]
        if isinstance(value, str) and value.strip():
            commit = {"availability": "available", "value": value}
        else:
            commit = {"availability": "malformed"}
            diagnostics.append({
                "code": "malformed_repository_commit",
                "field": "repository.commit",
            })
    worktree = _hash_field(
        repository,
        "worktree_sha256",
        "repository_worktree_sha256",
        diagnostics,
    )
    return {"commit": commit, "worktree_sha256": worktree}


def _path_detail(
    value: object,
    diagnostics: list[dict[str, object]],
    *,
    field: str,
) -> dict[str, object]:
    detail: dict[str, object] = {}
    if isinstance(value, str):
        detail["raw_path"] = value
    normalized, reason = _normalized_repository_path(value)
    if normalized is not None:
        detail["normalized_path"] = normalized
    else:
        diagnostics.append({"code": reason, "field": field})
    return detail


def _context_provenance(view) -> dict[str, object]:
    event_list = list(view.events)
    entries: list[dict[str, object]] = []
    by_event_id: dict[str, dict[str, object]] = {}
    diagnostics: list[dict[str, object]] = []
    events_by_id = {event.event_id: event for event in event_list}

    for event in event_list:
        if event.kind not in _CONTEXT_PROVENANCE_KINDS:
            continue
        entry_diagnostics: list[dict[str, object]] = []
        entry: dict[str, object] = {
            "event_id": event.event_id,
            "kind": event.kind,
            "actor_id": event.actor["id"],
            "emitter_id": event.emitter_id,
            "sequence": event.sequence,
            "timestamp": event.timestamp.isoformat(),
            "repository": _repository_snapshot(event, entry_diagnostics),
        }
        attributes = _attributes(event)
        if event.kind == "context.read":
            context = attributes.get("context")
            if not isinstance(context, dict):
                entry_diagnostics.append({
                    "code": "malformed_context_read",
                    "field": "context",
                })
                context = {}
            locator = _path_detail(
                context.get("path"), entry_diagnostics, field="context.path"
            )
            for key in ("line_start", "line_end"):
                value = context.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    locator[key] = value
            symbol = context.get("symbol")
            if isinstance(symbol, str) and symbol.strip():
                locator["symbol"] = symbol
            entry["locator"] = locator
            entry["content_sha256"] = _hash_field(
                context,
                "content_sha256",
                "context_content_sha256",
                entry_diagnostics,
            )
            entry["freshness"] = "unknown"
            entry["comparisons"] = []
        elif event.kind == "context.search":
            search = attributes.get("search")
            if not isinstance(search, dict):
                entry_diagnostics.append({
                    "code": "malformed_context_search",
                    "field": "search",
                })
                search = {}
            query = search.get("query")
            if isinstance(query, str) and query.strip():
                entry["query"] = query
            else:
                entry_diagnostics.append({
                    "code": "malformed_search_query",
                    "field": "search.query",
                })
            raw_matches = search.get("matches")
            projected_matches: list[dict[str, object]] = []
            canonical_matches: list[str] = []
            seen_raw: set[str] = set()
            if not isinstance(raw_matches, list):
                entry_diagnostics.append({
                    "code": "malformed_search_matches",
                    "field": "search.matches",
                })
                raw_matches = []
            for position, raw_path in enumerate(raw_matches):
                match_diagnostics: list[dict[str, object]] = []
                match = _path_detail(
                    raw_path,
                    match_diagnostics,
                    field=f"search.matches[{position}]",
                )
                if isinstance(raw_path, str) and raw_path in seen_raw:
                    match_diagnostics.append({
                        "code": "duplicate_search_match",
                        "field": f"search.matches[{position}]",
                    })
                elif isinstance(raw_path, str):
                    seen_raw.add(raw_path)
                    normalized = match.get("normalized_path")
                    if isinstance(normalized, str) and normalized not in canonical_matches:
                        canonical_matches.append(normalized)
                if match_diagnostics:
                    match["diagnostics"] = match_diagnostics
                    entry_diagnostics.extend(match_diagnostics)
                projected_matches.append(match)
            entry["matches"] = projected_matches
            entry["canonical_matches"] = canonical_matches
        elif event.kind == "context.compacted":
            sources = []
            seen_sources = set()
            for relationship in event.relationships:
                if relationship.type != "summarizes" or relationship.event_id in seen_sources:
                    continue
                seen_sources.add(relationship.event_id)
                source = events_by_id.get(relationship.event_id)
                source_detail: dict[str, object] = {"event_id": relationship.event_id}
                if source is None:
                    source_detail["status"] = "missing"
                else:
                    source_detail["kind"] = source.kind
                    source_detail["actor_id"] = source.actor["id"]
                    source_detail["chronology"] = _evidence_chronology(
                        source, event, "compaction"
                    )
                sources.append(source_detail)
            entry["summarizes"] = sources
        else:
            change = attributes.get("change")
            if not isinstance(change, dict):
                change = {}
            entry["locator"] = _path_detail(
                change.get("path"), entry_diagnostics, field="change.path"
            )
            entry["preimage_sha256"] = _hash_field(
                change,
                "preimage_sha256",
                "change_preimage_sha256",
                entry_diagnostics,
            )
            entry["freshness"] = "unknown"
            entry["reads"] = []
        if entry_diagnostics:
            entry["diagnostics"] = entry_diagnostics
            diagnostics.extend({"event_id": event.event_id, **item} for item in entry_diagnostics)
        entries.append(entry)
        by_event_id[event.event_id] = entry

    reads = [entry for entry in entries if entry["kind"] == "context.read"]
    changes = [entry for entry in entries if entry["kind"] == "change.applied"]
    for change_entry in changes:
        change_event = events_by_id[str(change_entry["event_id"])]
        linked_reads = {
            relationship.event_id
            for relationship in change_event.relationships
            if relationship.type == "informed_by"
        }
        linked_compactions = [
            events_by_id.get(relationship.event_id)
            for relationship in change_event.relationships
            if relationship.type == "informed_by"
        ]
        linked_reads.update(
            relationship.event_id
            for compaction in linked_compactions
            if compaction is not None and compaction.kind == "context.compacted"
            for relationship in compaction.relationships
            if relationship.type == "summarizes"
        )
        change_path = change_entry.get("locator", {}).get("normalized_path")
        preimage = change_entry["preimage_sha256"]
        statuses = []
        for read_entry in reads:
            if not isinstance(change_path, str):
                continue
            if read_entry.get("locator", {}).get("normalized_path") != change_path:
                continue
            if (
                read_entry["actor_id"] != change_entry["actor_id"]
                and read_entry["event_id"] not in linked_reads
            ):
                continue
            read_event = events_by_id[str(read_entry["event_id"])]
            chronology = _evidence_chronology(read_event, change_event, "change")
            observed = read_entry["content_sha256"]
            freshness = "unknown"
            if (
                observed.get("availability") == "available"
                and preimage.get("availability") == "available"
            ):
                freshness = (
                    "fresh" if observed["value"] == preimage["value"] else "stale"
                )
            comparison = {
                "read_event_id": read_entry["event_id"],
                "change_event_id": change_entry["event_id"],
                "chronology": chronology,
                "freshness": freshness,
            }
            read_entry["comparisons"].append(comparison)
            change_entry["reads"].append(comparison)
            statuses.append(freshness)
            if freshness == "stale":
                diagnostic = {
                    "code": "stale_context_read",
                    "event_id": read_entry["event_id"],
                    "change_event_id": change_entry["event_id"],
                    "path": change_path,
                }
                diagnostics.append(diagnostic)
                read_entry.setdefault("diagnostics", []).append(diagnostic)
                change_entry.setdefault("diagnostics", []).append(diagnostic)
        if "stale" in statuses:
            change_entry["freshness"] = "stale"
        elif "fresh" in statuses:
            change_entry["freshness"] = "fresh"
        for read_entry in reads:
            read_statuses = [item["freshness"] for item in read_entry["comparisons"]]
            if "stale" in read_statuses:
                read_entry["freshness"] = "stale"
            elif "fresh" in read_statuses:
                read_entry["freshness"] = "fresh"

    snapshot_entries = [
        entry for entry in entries
        if any(
            value.get("availability") == "available"
            for value in entry["repository"].values()
        )
    ]
    def causally_ordered(left_event: Event, right_event: Event) -> bool:
        return bool(
            view.causal_ancestors[right_event.event_id]
            & view.event_bits[left_event.event_id]
            or view.causal_ancestors[left_event.event_id]
            & view.event_bits[right_event.event_id]
        )

    for position, left in enumerate(snapshot_entries):
        for right in snapshot_entries[position + 1:]:
            if left["actor_id"] == right["actor_id"]:
                continue
            left_event = events_by_id[str(left["event_id"])]
            right_event = events_by_id[str(right["event_id"])]
            if (
                causally_ordered(left_event, right_event)
                or _evidence_chronology(left_event, right_event, "event")
                != "undetermined"
            ):
                continue
            differing = [
                field for field in ("commit", "worktree_sha256")
                if left["repository"][field].get("availability") == "available"
                and right["repository"][field].get("availability") == "available"
                and left["repository"][field]["value"] != right["repository"][field]["value"]
            ]
            if not differing:
                continue
            diagnostic = {
                "code": "divergent_repository_snapshot",
                "event_ids": [left["event_id"], right["event_id"]],
                "actor_ids": [left["actor_id"], right["actor_id"]],
                "fields": differing,
            }
            diagnostics.append(diagnostic)
            left.setdefault("diagnostics", []).append(diagnostic)
            right.setdefault("diagnostics", []).append(diagnostic)

    actor_entries: dict[str, list[dict[str, object]]] = {}
    for entry in entries:
        actor_entries.setdefault(str(entry["actor_id"]), []).append(entry)
    actors = [
        {"actor_id": actor_id, "entries": timeline}
        for actor_id, timeline in actor_entries.items()
    ]
    return {
        "actors": actors,
        "diagnostics": diagnostics,
        "by_event_id": by_event_id,
    }


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


def _change_verification_warnings(view, warning_factory) -> list[object]:
    evidence_map = _event_evidence(view.events)
    provenance = _context_provenance(view)
    events_by_id = {event.event_id: event for event in view.events}
    warnings = []
    for change in evidence_map["changes"]:
        change_event_id = str(change["event_id"])
        actor_id = str(change["actor_id"])
        trace_id = events_by_id[change_event_id].trace_id
        verification_links = [
            link for link in change["links"]
            if link.get("type") == "verified_by"
            and isinstance(link.get("verification"), dict)
        ]
        covered = any("command" in link["verification"] for link in verification_links)
        if not covered:
            warnings.append(warning_factory(
                "UNCOVERED_CHANGE",
                change_event_id,
                trace_id,
                actor_id,
                f"change {change_event_id} has no valid linked verification command",
                change_event_id=change_event_id,
                event_ids=[change_event_id],
                hunk=change["hunk"],
                verification_command_count=0,
            ))

        invalid_verification_ids = {
            item.get("target_event_id")
            for item in change["unresolved"]
            if item.get("type") == "verified_by"
            and item.get("reason") in {
                "invalid_verification_result",
                "invalid_verification_exit_code",
                "conflicting_verification_outcome",
                "invalid_verification_test_origin",
            }
        }
        passing = [
            link for link in verification_links
            if link["verification"].get("passed") is True
            and link.get("target_event_id") not in invalid_verification_ids
        ]
        if passing and all(
            link["verification"].get("test_origin") == "same_agent"
            for link in passing
        ):
            verification_ids = [str(link["target_event_id"]) for link in passing]
            warnings.append(warning_factory(
                "SELF_CONFIRMING_TEST",
                change_event_id,
                trace_id,
                actor_id,
                f"every passing verification linked to change {change_event_id} has same-agent provenance",
                change_event_id=change_event_id,
                event_ids=[change_event_id, *verification_ids],
                hunk=change["hunk"],
                passing_verification_event_ids=verification_ids,
                test_origin="same_agent",
            ))

        change_entry = provenance["by_event_id"].get(change_event_id, {})
        linked_read_ids = _informing_read_ids(events_by_id[change_event_id], events_by_id)
        stale_reads = []
        stale_read_ids = set()
        for comparison in change_entry.get("reads", []):
            read_event_id = comparison.get("read_event_id")
            if (
                comparison.get("freshness") != "stale"
                or read_event_id not in linked_read_ids
                or read_event_id in stale_read_ids
            ):
                continue
            read_entry = provenance["by_event_id"].get(read_event_id, {})
            observed = read_entry.get("content_sha256", {})
            preimage = change_entry.get("preimage_sha256", {})
            if (
                observed.get("availability") != "available"
                or preimage.get("availability") != "available"
            ):
                continue
            stale_read_ids.add(read_event_id)
            stale_reads.append({
                "event_id": str(read_event_id),
                "content_sha256": observed["value"],
            })
        if stale_reads:
            path = change_entry.get("locator", {}).get("normalized_path")
            read_event_ids = [read["event_id"] for read in stale_reads]
            warnings.append(warning_factory(
                "STALE_CONTEXT",
                change_event_id,
                trace_id,
                actor_id,
                f"{len(stale_reads)} informing context read{'s' if len(stale_reads) != 1 else ''} have validated hashes that differ from the pre-edit hash for {path}",
                change_event_id=change_event_id,
                event_ids=[change_event_id, *read_event_ids],
                path=path,
                preimage_sha256=preimage["value"],
                stale_read_event_ids=read_event_ids,
                stale_reads=stale_reads,
                hunk=change["hunk"],
            ))
    return warnings


def _informing_read_ids(
    change: Event,
    events_by_id: dict[str, Event],
) -> set[str]:
    read_ids = set()
    for relationship in change.relationships:
        if relationship.type != "informed_by":
            continue
        target = events_by_id.get(relationship.event_id)
        if target is None:
            continue
        if target.kind == "context.read":
            read_ids.add(target.event_id)
        elif target.kind == "context.compacted":
            read_ids.update(
                source.event_id
                for link in target.relationships
                if link.type == "summarizes"
                and (source := events_by_id.get(link.event_id)) is not None
                and source.kind == "context.read"
            )
    return read_ids


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


_USAGE_FIELDS = ("input_tokens", "output_tokens", "total_tokens", "cost_usd")


def _outcome_cost(
    view,
    evidence_map: dict[str, object],
    warnings: Iterable[dict[str, object]],
    *,
    evicted_event_ids: Iterable[str] = (),
    retained_event_traces: Mapping[str, str] | None = None,
) -> dict[str, object]:
    events = list(view.events)
    events_by_id = {event.event_id: event for event in events}
    usage_by_id = {
        event.event_id: _usage_summary((event,)) for event in events
    }
    valid_changes = {
        str(change["event_id"]): change for change in evidence_map["changes"]
    }
    evicted_ids = set(evicted_event_ids)
    retained_traces = retained_event_traces or {
        event.event_id: event.trace_id for event in events
    }
    trace_id = events[0].trace_id if events else ""
    hunk_values = {event_id: _empty_usage_values() for event_id in valid_changes}
    hunk_event_ids = {event_id: [] for event_id in valid_changes}
    attributed_events = []
    pending_events = []
    unattributed_events: dict[str, list[Event]] = {}

    for event in events:
        event_usage = usage_by_id[event.event_id]
        if not any(metric["available"] for metric in event_usage.values()):
            continue
        target_ids = list(dict.fromkeys(
            relationship.event_id
            for relationship in event.relationships
            if relationship.type == "contributes_to"
        ))
        valid_target_ids = [target for target in target_ids if target in valid_changes]
        if valid_target_ids:
            divisor = len(valid_target_ids)
            for target in valid_target_ids:
                _add_usage(hunk_values[target], event_usage, divisor=divisor)
                hunk_event_ids[target].append(event.event_id)
            attributed_events.append(event)
            continue

        missing_ids = [target for target in target_ids if target not in retained_traces]
        pending_ids = [target for target in missing_ids if target not in evicted_ids]
        if pending_ids:
            pending_events.append({
                "event_id": event.event_id,
                "target_event_ids": pending_ids,
                "usage": event_usage,
            })
            continue

        if not target_ids:
            reason = "no_contributes_to"
        elif missing_ids:
            reason = "target_evicted"
        elif any(retained_traces.get(target) != trace_id for target in target_ids):
            reason = "cross_trace_target"
        else:
            reason = "invalid_target"
        unattributed_events.setdefault(reason, []).append(event)

    by_hunk = []
    for event_id, change in valid_changes.items():
        outcome = _observed_hunk_outcome(view, change, events_by_id)
        usage = _usage_projection(hunk_values[event_id])
        by_hunk.append({
            "change_event_id": event_id,
            "actor_id": change["actor_id"],
            "hunk": change["hunk"],
            "observed_outcome": outcome,
            "contributing_event_ids": hunk_event_ids[event_id],
            "usage": usage,
        })

    actor_events: dict[str, list[Event]] = {}
    for event in events:
        actor_events.setdefault(str(event.actor["id"]), []).append(event)
    by_actor = [
        {
            "actor_id": actor_id,
            "usage": _sum_projected_usage(
                usage_by_id[event.event_id] for event in activity
            ),
        }
        for actor_id, activity in actor_events.items()
    ]

    operations: dict[str, list[Event]] = {}
    for event in events:
        name = event.operation.get("name")
        operation = name.strip() if isinstance(name, str) and name.strip() else event.kind
        operations.setdefault(operation, []).append(event)
    by_operation = [
        {
            "operation": operation,
            "usage": _sum_projected_usage(
                usage_by_id[event.event_id] for event in operation_events
            ),
        }
        for operation, operation_events in operations.items()
    ]

    warning_event_ids: dict[str, list[str]] = {}
    for warning in warnings:
        code = warning.get("code")
        if not isinstance(code, str):
            continue
        cited = _warning_event_ids(warning.get("evidence"))
        known = warning_event_ids.setdefault(code, [])
        known.extend(event_id for event_id in cited if event_id not in known)
    by_warning_code = []
    for code, event_ids in warning_event_ids.items():
        by_warning_code.append({
            "warning_code": code,
            "event_ids": event_ids,
            "usage": _sum_projected_usage(
                usage_by_id[event_id]
                for event_id in event_ids
                if event_id in usage_by_id
            ),
        })

    pending_usage = _sum_projected_usage(item["usage"] for item in pending_events)
    unattributed_rows = [
        {
            "reason": reason,
            "event_count": len(reason_events),
            "usage": _sum_projected_usage(
                usage_by_id[event.event_id] for event in reason_events
            ),
        }
        for reason, reason_events in unattributed_events.items()
    ]
    unattributed_usage = _sum_projected_usage(
        item["usage"] for item in unattributed_rows
    )
    return {
        "allocation_rule": "full_to_one_or_equal_split_across_distinct_valid_hunks",
        "warning_association": "non_exclusive_do_not_sum",
        "totals": _sum_projected_usage(usage_by_id.values()),
        "allocation": {
            "attributed": _sum_projected_usage(
                usage_by_id[event.event_id] for event in attributed_events
            ),
            "pending": pending_usage,
            "unattributed": unattributed_usage,
        },
        "by_actor": by_actor,
        "by_operation": by_operation,
        "by_warning_code": by_warning_code,
        "by_hunk": by_hunk,
        "pending": pending_events,
        "unattributed": unattributed_rows,
    }


def _observed_hunk_outcome(
    view,
    change: dict[str, object],
    events_by_id: dict[str, Event],
) -> str:
    corrections = change.get("corrections", [])
    if not corrections:
        return "no_correction_observed"
    change_event = events_by_id[str(change["event_id"])]
    valid = []
    for link in corrections:
        correction_event = events_by_id.get(str(link.get("source_event_id")))
        correction = link.get("correction")
        if (
            correction_event is None
            or not isinstance(correction, dict)
            or correction.get("action") not in {"modified", "reverted"}
            or not _causally_before(view, change_event, correction_event)
        ):
            return "undetermined"
        valid.append((correction_event, str(correction["action"])))
    latest = [
        item for item in valid
        if not any(
            item[0].event_id != other[0].event_id
            and _causally_before(view, item[0], other[0])
            for other in valid
        )
    ]
    return latest[0][1] if len(latest) == 1 else "undetermined"


def _causally_before(view, before: Event, after: Event) -> bool:
    if before.emitter_id == after.emitter_id:
        return before.sequence < after.sequence
    return bool(
        view.causal_ancestors[after.event_id] & view.event_bits[before.event_id]
    )


def _warning_event_ids(evidence: object) -> list[str]:
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (TypeError, ValueError):
            return []
    if not isinstance(evidence, dict) or not isinstance(evidence.get("event_ids"), list):
        return []
    return list(dict.fromkeys(
        event_id for event_id in evidence["event_ids"] if isinstance(event_id, str)
    ))


def _empty_usage_values() -> dict[str, object]:
    return {field: None for field in _USAGE_FIELDS}


def _add_usage(
    totals: dict[str, object],
    usage: dict[str, object],
    *,
    divisor: int = 1,
) -> None:
    for field in _USAGE_FIELDS:
        metric = usage[field]
        if not metric["available"]:
            continue
        value = metric["value"] / divisor if divisor > 1 else metric["value"]
        totals[field] = value if totals[field] is None else totals[field] + value


def _usage_projection(values: dict[str, object]) -> dict[str, object]:
    return {
        field: {"available": values[field] is not None, "value": values[field]}
        for field in _USAGE_FIELDS
    }


def _sum_projected_usage(usages: Iterable[dict[str, object]]) -> dict[str, object]:
    totals = _empty_usage_values()
    for usage in usages:
        _add_usage(totals, usage)
    return _usage_projection(totals)


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
    raw = event._raw
    usage = raw.get("usage")
    if isinstance(usage, dict):
        result = dict(usage)
    else:
        result = {}
    raw_attributes = raw.get("attributes")
    attributes = dict(raw_attributes) if isinstance(raw_attributes, dict) else {}
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
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


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
