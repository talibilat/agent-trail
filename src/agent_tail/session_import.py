from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Callable, Mapping

from .core import IngestionError, redact_text
from .session_sources import claude_code, codex, opencode


SOURCES = ("claude-code", "codex", "opencode")


class SessionDocumentError(ValueError):
    """Raised when a coding-agent session cannot be selected or supported."""


@dataclass(frozen=True)
class ParsedSession:
    source: str
    version: str
    session_id: str
    metadata: dict[str, object]
    records: tuple[dict[str, object], ...]
    errors: tuple[IngestionError, ...]


@dataclass(frozen=True)
class SessionImport:
    source: str
    version: str
    events: tuple[dict[str, object], ...]
    errors: tuple[IngestionError, ...]


@dataclass(frozen=True)
class MalformedJSONLine:
    message: str


_PARSERS: dict[str, Callable[[str, int], ParsedSession]] = {
    "claude-code": claude_code.parse,
    "codex": codex.parse,
    "opencode": opencode.parse,
}


def import_session(text: str, *, source: str = "auto", max_errors: int = 100) -> SessionImport:
    if source not in (*SOURCES, "auto"):
        raise SessionDocumentError(f"unsupported source selection: {source}")
    if source == "auto":
        matches = [name for name, module in (
            ("claude-code", claude_code),
            ("codex", codex),
            ("opencode", opencode),
        ) if module.detect(text)]
        if not matches:
            raise SessionDocumentError(
                "unsupported session format: no supported source signature matched; use --source"
            )
        if len(matches) != 1:
            raise SessionDocumentError(
                "ambiguous session format: matched " + ", ".join(matches)
                + "; select one with --source"
            )
        source = matches[0]
    parsed = _PARSERS[source](text, max_errors)
    return SessionImport(
        source,
        parsed.version,
        tuple(_build_events(parsed)),
        parsed.errors,
    )


def canonical_jsonl(result: SessionImport) -> str:
    return "".join(
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for event in result.events
    )


def diagnostic(path: str, message: str) -> IngestionError:
    return IngestionError(None, redact_text(f"{path}: {message}"))


def bounded_errors(
    errors: list[IngestionError], omitted: int, source: str
) -> tuple[IngestionError, ...]:
    if omitted:
        errors.append(IngestionError(
            None, f"{omitted} additional {source} session import errors omitted"
        ))
    return tuple(errors)


def parse_json_lines(text: str) -> list[object]:
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line, parse_constant=_invalid_constant))
        except json.JSONDecodeError as error:
            records.append(MalformedJSONLine(f"invalid JSON: {error.msg}"))
        except ValueError:
            records.append(MalformedJSONLine("invalid JSON: non-standard numeric value"))
    return records


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-standard numeric value {value}")


def _identifier(source: str, namespace: str, *parts: object, length: int) -> str:
    digest = hashlib.sha256(
        "\0".join(("agent-tail-session", source, namespace, *(str(part) for part in parts))).encode()
    ).hexdigest()[:length]
    return f"{source}-{namespace}-{digest}"


def _build_events(session: ParsedSession) -> list[dict[str, object]]:
    sequences: defaultdict[str, int] = defaultdict(int)
    source_keys = [str(record["source_key"]) for record in session.records]
    event_ids = {
        key: _identifier(session.source, "event", session.session_id, key, length=32)
        for key in source_keys
    }
    span_ids = {
        key: _identifier(session.source, "span", session.session_id, key, length=16)
        for key in source_keys
    }
    trace_id = _identifier(session.source, "trace", session.session_id, length=32)
    events = []
    for record in session.records:
        key = str(record["source_key"])
        actor_key = str(record.get("actor_id") or "session")
        emitter_key = str(record.get("emitter_id") or actor_key)
        actor_id = f"{session.source}:{actor_key}"
        emitter_id = f"{session.source}:{emitter_key}"
        sequences[emitter_id] += 1
        relationships = []
        for relationship in record.get("relationships", []):
            target = str(relationship["source_key"])
            if target in event_ids:
                relationships.append({
                    "type": relationship["type"],
                    "event_id": event_ids[target],
                })
        attributes = deepcopy(record.get("attributes", {}))
        attributes[session.source.replace("-", "_")] = {
            "tool": session.source,
            "schema_version": session.version,
            "session_id": session.session_id,
            "session": deepcopy(session.metadata),
            "record": deepcopy(record["raw"]),
        }
        event: dict[str, object] = {
            "schema_version": "1.0",
            "event_id": event_ids[key],
            "trace_id": trace_id,
            "span_id": span_ids[key],
            "emitter_id": emitter_id,
            "sequence": sequences[emitter_id],
            "timestamp": record["timestamp"],
            "kind": record["kind"],
            "actor": {"id": actor_id, **deepcopy(record.get("actor", {}))},
            "operation": {
                "status": record.get("status", "unknown"),
                "name": record.get("name", record["kind"]),
            },
            "attributes": attributes,
        }
        parent = record.get("parent_source_key")
        if parent is not None and str(parent) in span_ids:
            event["parent_span_id"] = span_ids[str(parent)]
        if relationships:
            event["relationships"] = relationships
        events.append(event)
    return events


def valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or len(value) < 11 or value[10] != "T":
        return False
    try:
        from datetime import datetime
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.utcoffset() is not None


def non_blank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def hunk(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or not non_blank(value.get("path")):
        return None
    result = {"path": value["path"]}
    for field in ("old_start", "old_count", "new_start", "new_count"):
        item = value.get(field)
        if not integer(item) or item < 0:
            return None
        result[field] = item
    if (result["old_count"] > 0 and result["old_start"] == 0) or (
        result["new_count"] > 0 and result["new_start"] == 0
    ):
        return None
    if non_blank(value.get("symbol")):
        result["symbol"] = value["symbol"]
    return result


def relationship_list(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    allowed = {
        "motivated_by", "informed_by", "preceded_by", "applies",
        "verified_by", "corrects", "contributes_to",
    }
    return [
        {"type": item["type"], "source_key": item["event_id"]}
        for item in value
        if isinstance(item, Mapping)
        and item.get("type") in allowed
        and non_blank(item.get("event_id"))
    ]
