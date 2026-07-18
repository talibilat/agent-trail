from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable

from .core import IngestionError, TraceIndex
from .serve import RunStore


_HEAD_MARKER = "<!-- AGENT_TAIL_EXPORT_HEAD -->"
_DATA_MARKER = "<!-- AGENT_TAIL_EXPORT_DATA -->"


def normalize_generation_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("--export-html-generated-at must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("--export-html-generated-at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def render_html(
    index: TraceIndex,
    errors: Iterable[IngestionError],
    *,
    generated_at: str | None = None,
    metadata_only: bool = False,
) -> str:
    store = RunStore(
        index,
        errors,
        source_kind="export",
        metadata_only=metadata_only,
    )
    store.set_source_status(connected=False, state="embedded")
    runs = store.list_runs()
    details: dict[str, object] = {}
    for run in runs["runs"]:
        trace_id = str(run["trace_id"])
        detail = store.run_detail(trace_id)
        if detail is None:
            continue
        details[trace_id] = detail

    metadata = {
        "agent_tail_version": _package_version(),
        "schema_versions": sorted({event.schema_version for event in index.events}),
        "redaction_ruleset": "1",
        "export_mode": (
            "metadata-only sanitized embedded snapshot"
            if metadata_only
            else "sanitized embedded snapshot"
        ),
        "payload_retention": _payload_retention(index),
        "generated_at": generated_at,
        **(
            {"warning_policy": index.warning_policy_projection()}
            if index.warning_policy is not None
            else {}
        ),
    }
    snapshot = {
        "metadata": metadata,
        "runs": runs,
        "details": details,
    }
    encoded = base64.b64encode(
        json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")

    shell = Path(__file__).with_name("web").joinpath("index.html").read_text(
        encoding="utf-8"
    )
    if _HEAD_MARKER not in shell or _DATA_MARKER not in shell:
        raise ValueError("packaged browser shell does not support embedded exports")
    script = shell.split("<script>", 1)[1].split("</script>", 1)[0]
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode(
        "ascii"
    )
    csp = (
        "default-src 'none'; "
        f"script-src 'sha256-{digest}'; "
        "style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; "
        "font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; "
        "child-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; "
        "form-action 'none'"
    )
    head = (
        '<meta http-equiv="Content-Security-Policy" '
        f'content="{csp}">'
    )
    data = f'<div id="agent-tail-export-data" hidden>{encoded}</div>'
    return shell.replace(_HEAD_MARKER, head).replace(_DATA_MARKER, data)


def write_html_atomic(path: Path, content: str) -> None:
    path = Path(path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
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


def _package_version() -> str:
    try:
        return version("agent-tail")
    except PackageNotFoundError:
        return "0.1.0"


def _payload_retention(index: TraceIndex) -> dict[str, int]:
    counts = {"absent": 0, "retained": 0, "truncated": 0, "evicted": 0}
    for event in index.events:
        payload = event.raw.get("payload")
        if payload is None:
            counts["absent"] += 1
            continue
        metadata = payload.get("_agent_tail") if isinstance(payload, dict) else None
        if isinstance(metadata, dict) and metadata.get("omitted") is True:
            counts["omitted"] = counts.get("omitted", 0) + 1
        elif isinstance(payload, dict) and set(payload) == {"_agent_tail"}:
            counts["evicted"] += 1
        elif isinstance(metadata, dict) and metadata.get("truncated"):
            counts["truncated"] += 1
        else:
            counts["retained"] += 1
    return counts
