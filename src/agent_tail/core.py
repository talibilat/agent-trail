from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re
from typing import Iterable, Mapping


_SENSITIVE_KEY = re.compile(
    r"^(?:auth|authorization|cookie|setcookie)"
    r"|(?:token|secret|password|apikey|passwd|credentials?)$",
    re.IGNORECASE,
)
_KEY_SEPARATOR = re.compile(r"[^a-z0-9]+", re.IGNORECASE)
_SECRET_VALUE = re.compile(
    r"(?i:\bBearer\s+[^\s,;\"']+)"
    r"|\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}"
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|\bgh[opusr]_[A-Za-z0-9]{36,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{82,}\b"
    r"|\bglpat-[A-Za-z0-9_-]{20,}\b"
    r"|\bxox[bpar]-[A-Za-z0-9-]{20,}\b"
    r"|\bAIza[A-Za-z0-9_-]{35,}\b"
    r"|(?s:-----BEGIN (?P<pem_label>(?:[A-Z0-9]+ )*PRIVATE KEY)-----.*?"
    r"-----END (?P=pem_label)-----)",
)
_PAYLOAD_PREVIEW_BYTES = 4096


class EventError(ValueError):
    """Raised when an event does not match the canonical envelope."""


@dataclass(frozen=True)
class Event:
    schema_version: str
    event_id: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    emitter_id: str
    sequence: int
    timestamp: datetime
    kind: str
    _raw: dict[str, object] = field(repr=False)

    @property
    def actor(self) -> dict[str, object]:
        return deepcopy(self._raw["actor"])

    @property
    def operation(self) -> dict[str, object]:
        return deepcopy(self._raw["operation"])

    @property
    def raw(self) -> dict[str, object]:
        return deepcopy(self._raw)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Event":
        if not isinstance(data, Mapping):
            raise EventError("event must be an object")

        required_types = {
            "schema_version": str,
            "event_id": str,
            "trace_id": str,
            "span_id": str,
            "emitter_id": str,
            "sequence": int,
            "timestamp": str,
            "kind": str,
            "actor": Mapping,
            "operation": Mapping,
        }
        for field, expected_type in required_types.items():
            if field not in data:
                raise EventError(f"missing required field: {field}")
            value = data[field]
            if not isinstance(value, expected_type) or (
                field == "sequence" and isinstance(value, bool)
            ):
                raise EventError(f"{field} has an incorrect type")

        schema_version = data["schema_version"]
        if re.fullmatch(r"1\.[0-9]+", schema_version) is None:
            raise EventError(f"unsupported schema version: {schema_version}")

        sequence = data["sequence"]
        if sequence < 0:
            raise EventError("sequence must not be negative")

        timestamp_text = data["timestamp"]
        try:
            if len(timestamp_text) < 11 or timestamp_text[10] != "T":
                raise ValueError
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
            if timestamp.utcoffset() is None:
                raise ValueError
        except ValueError as error:
            raise EventError(f"invalid timestamp: {timestamp_text}") from error

        actor = data["actor"]
        if not isinstance(actor.get("id"), str):
            raise EventError("actor.id must be a string")

        operation = data["operation"]
        if not isinstance(operation.get("status"), str):
            raise EventError("operation.status must be a string")

        parent_span_id = data.get("parent_span_id")
        if parent_span_id is not None and not isinstance(parent_span_id, str):
            raise EventError("parent_span_id must be a string")

        snapshot = deepcopy(dict(data))
        return cls(
            schema_version=schema_version,
            event_id=data["event_id"],
            trace_id=data["trace_id"],
            span_id=data["span_id"],
            parent_span_id=parent_span_id,
            emitter_id=data["emitter_id"],
            sequence=sequence,
            timestamp=timestamp,
            kind=data["kind"],
            _raw=snapshot,
        )


@dataclass
class IngestionError:
    line: int
    message: str


@dataclass
class Ingestion:
    events: list[Event]
    errors: list[IngestionError]


def read_jsonl(lines: Iterable[str]) -> Ingestion:
    events = []
    errors = []
    accepted_ids = set()

    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = Event.from_dict(json.loads(line))
        except json.JSONDecodeError as error:
            errors.append(IngestionError(line_number, f"invalid JSON: {error.msg}"))
            continue
        except EventError as error:
            errors.append(IngestionError(line_number, str(error)))
            continue

        if event.event_id in accepted_ids:
            errors.append(IngestionError(line_number, f"duplicate event ID: {event.event_id}"))
            continue
        accepted_ids.add(event.event_id)
        events.append(event)

    return Ingestion(events, errors)


def sanitize_event(
    event: Event,
    *,
    full_payloads: bool = False,
    unsafe_unredacted: bool = False,
) -> Event:
    def redact(value: object) -> object:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]"
                if _SENSITIVE_KEY.search(_KEY_SEPARATOR.sub("", str(key)))
                else redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str):
            return _SECRET_VALUE.sub("[REDACTED]", value)
        return value

    raw = event.raw
    if "attributes" in raw and not unsafe_unredacted:
        raw["attributes"] = redact(raw["attributes"])

    if "payload" in raw:
        payload = raw["payload"]
        original = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        safe_payload = payload if unsafe_unredacted else redact(payload)
        if isinstance(safe_payload, dict):
            safe_payload.pop("_agent_tail", None)
        serialized = json.dumps(
            safe_payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        truncated = not full_payloads and len(original) > _PAYLOAD_PREVIEW_BYTES
        metadata = {
            "original_bytes": len(original),
            "sha256": hashlib.sha256(original).hexdigest(),
            "truncated": truncated,
            "ruleset": "1",
        }
        if truncated:
            raw["payload"] = {
                "preview": serialized[:_PAYLOAD_PREVIEW_BYTES].decode(
                    "utf-8", errors="ignore"
                ),
                "_agent_tail": metadata,
            }
        elif isinstance(safe_payload, dict):
            safe_payload["_agent_tail"] = metadata
            raw["payload"] = safe_payload
        else:
            raw["payload"] = {"value": safe_payload, "_agent_tail": metadata}

    return Event.from_dict(raw)
