from __future__ import annotations

from dataclasses import dataclass
import hashlib
from http import HTTPStatus
import ipaddress
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
from typing import Callable, Iterable
from urllib.parse import parse_qs, quote, urlparse

from .core import IngestionError, TraceIndex
from .serve import RunStore, _Handler, _Server


@dataclass(frozen=True)
class ExportCandidate:
    content: bytes
    format: str
    destination: Path
    digest: str

    @classmethod
    def create(cls, content: str, *, format: str, destination: Path) -> "ExportCandidate":
        encoded = content.encode("utf-8")
        return cls(
            content=encoded,
            format=format,
            destination=Path(destination),
            digest=hashlib.sha256(encoded).hexdigest(),
        )


class ReviewDecision:
    """A one-way, thread-safe review decision exposed for deterministic tests."""

    def __init__(self) -> None:
        self._state = "pending"
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._activated = False
        self._last_seen = 0.0

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def decide(self, state: str) -> bool:
        if state not in {"approved", "cancelled", "expired", "failed"}:
            raise ValueError("invalid review state")
        with self._lock:
            if self._state != "pending":
                return False
            self._state = state
            self._event.set()
            return True

    def touch(self) -> None:
        with self._lock:
            if self._state == "pending":
                self._activated = True
                self._last_seen = time.monotonic()

    def wait(self, timeout: float, *, abandoned_after: float | None = None) -> str:
        deadline = time.monotonic() + timeout
        while self.state == "pending":
            now = time.monotonic()
            with self._lock:
                abandoned = (
                    abandoned_after is not None
                    and self._activated
                    and now - self._last_seen >= abandoned_after
                )
            if abandoned:
                self.decide("cancelled")
                break
            remaining = deadline - now
            if remaining <= 0:
                self.decide("expired")
                break
            self._event.wait(min(remaining, 0.25))
        return self.state


def inventory(
    index: TraceIndex,
    errors: Iterable[IngestionError],
    candidate: ExportCandidate,
    *,
    metadata_only: bool,
) -> dict[str, object]:
    error_list = list(errors)
    store = RunStore(index, error_list, source_kind="review", metadata_only=metadata_only)
    store.set_source_status(connected=False, state="frozen")
    details = [
        detail
        for run in store.list_runs()["runs"]
        if (detail := store.run_detail(str(run["trace_id"]))) is not None
    ]
    attribute_paths: set[str] = set()
    payload_states: dict[str, int] = {}
    original_payload_bytes = 0
    for event in index.events:
        attributes = event.raw.get("attributes")
        _collect_paths(attributes, "attributes", attribute_paths)
        payload = event.raw.get("payload")
        state = _payload_state(payload)
        payload_states[state] = payload_states.get(state, 0) + 1
        if isinstance(payload, dict):
            metadata = payload.get("_agent_tail")
            if isinstance(metadata, dict):
                original_payload_bytes += int(metadata.get("original_bytes", 0) or 0)
    return {
        "state": "pending",
        "candidate_digest": candidate.digest,
        "candidate_bytes": len(candidate.content),
        "target_format": candidate.format,
        "target_path": str(candidate.destination),
        "event_count": index.event_count,
        "actor_count": len({event.actor["id"] for event in index.events}),
        "warning_count": sum(len(detail["warnings"]) for detail in details),
        "ingestion_errors": len(error_list),
        "retained_attribute_paths": sorted(attribute_paths),
        "payload_states": dict(sorted(payload_states.items())),
        "original_payload_bytes": original_payload_bytes,
        "redaction_ruleset": "1",
        "metadata_only": metadata_only,
        **(
            {"warning_policy": index.warning_policy_projection()}
            if index.warning_policy is not None
            else {}
        ),
    }


def review_export(
    index: TraceIndex,
    errors: Iterable[IngestionError],
    candidate: ExportCandidate,
    *,
    metadata_only: bool,
    timeout: float,
    open_browser: bool = False,
    open_url: Callable[[str], object] | None = None,
) -> int:
    decision = ReviewDecision()
    token = secrets.token_urlsafe(32)
    error_list = tuple(errors)
    review_inventory = inventory(
        index, error_list, candidate, metadata_only=metadata_only
    )
    store = RunStore(
        index,
        error_list,
        source_kind="review",
        metadata_only=metadata_only,
    )
    store.set_source_status(connected=False, state="frozen")
    server = make_review_server(
        store,
        review_inventory,
        decision,
        token=token,
    )
    host, port = server.server_address[:2]
    if not ipaddress.ip_address(host).is_loopback:
        server.server_close()
        decision.decide("failed")
        return 2
    url = f"http://{host}:{port}/?review=1&token={quote(token)}"
    print(
        f"Review {candidate.format} export: {candidate.digest} "
        f"({len(candidate.content)} bytes) -> {candidate.destination}",
        flush=True,
    )
    print(f"Review URL: {url}", flush=True)

    def run_server() -> None:
        try:
            server.serve_forever()
        except Exception:
            decision.decide("failed")

    thread = threading.Thread(target=run_server, daemon=True)
    try:
        thread.start()
        if open_browser and open_url is not None:
            open_url(url)
        state = decision.wait(timeout, abandoned_after=2.0)
    except KeyboardInterrupt:
        decision.decide("cancelled")
        state = decision.state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    if state != "approved":
        print(f"Export review {state}; destination unchanged.", flush=True)
        return 2
    try:
        write_bytes_atomic(candidate.destination, candidate.content)
    except (OSError, UnicodeError) as error:
        decision.decide("failed")
        print(f"agent-tail: export write failed: {error}", file=sys.stderr)
        return 2
    print(f"Approved export written: sha256 {candidate.digest}", flush=True)
    return 0


def make_review_server(
    store: RunStore,
    review_inventory: dict[str, object],
    decision: ReviewDecision,
    *,
    token: str,
):
    class Handler(_Handler):
        run_store = store

        def do_GET(self) -> None:
            if not self._authorized_review():
                self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            if urlparse(self.path).path == "/api/v1/review":
                decision.touch()
                self._send_json({**review_inventory, "state": decision.state})
                return
            if urlparse(self.path).path == "/api/v1/review/heartbeat":
                decision.touch()
                self._send_json({"state": decision.state})
                return
            super().do_GET()

        def do_POST(self) -> None:
            if not self._authorized_review():
                self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            path = urlparse(self.path).path
            states = {
                "/api/v1/review/approve": "approved",
                "/api/v1/review/cancel": "cancelled",
            }
            state = states.get(path)
            if state is None:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            if not decision.decide(state):
                self._send_json(
                    {"error": "review token already used"}, HTTPStatus.UNAUTHORIZED
                )
                return
            self._send_json({"state": state})

        def _authorized_review(self) -> bool:
            if decision.state != "pending":
                return False
            parsed = urlparse(self.path)
            supplied = parse_qs(parsed.query).get("token", [None])[0]
            authorization = self.headers.get("Authorization", "")
            return secrets.compare_digest(supplied or "", token) or secrets.compare_digest(
                authorization, f"Bearer {token}"
            )

    server = _Server(("127.0.0.1", 0), Handler)
    server.access_token = token
    return server


def write_bytes_atomic(path: Path, content: bytes) -> None:
    path = Path(path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _collect_paths(value: object, prefix: str, paths: set[str]) -> None:
    if isinstance(value, dict):
        if not value:
            paths.add(prefix)
        for key, item in value.items():
            _collect_paths(item, f"{prefix}.{key}", paths)
    elif isinstance(value, list):
        paths.add(f"{prefix}[]")
        for item in value:
            _collect_paths(item, f"{prefix}[]", paths)
    elif value is not None:
        paths.add(prefix)


def _payload_state(payload: object) -> str:
    if payload is None:
        return "absent"
    if not isinstance(payload, dict):
        return "retained"
    metadata = payload.get("_agent_tail")
    if isinstance(metadata, dict) and metadata.get("omitted") is True:
        return "omitted"
    if set(payload) == {"_agent_tail"}:
        return "evicted"
    if isinstance(metadata, dict) and metadata.get("truncated"):
        return "truncated"
    return "retained"
