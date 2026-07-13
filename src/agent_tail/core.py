from dataclasses import dataclass
from datetime import datetime
import re
from types import MappingProxyType
from typing import Mapping


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
    actor: Mapping[str, object]
    operation: Mapping[str, object]
    raw: Mapping[str, object]

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
        except ValueError as error:
            raise EventError(f"invalid timestamp: {timestamp_text}") from error

        actor = data["actor"]
        if not isinstance(actor.get("id"), str):
            raise EventError("actor.id must be a string")

        operation = data["operation"]
        if not isinstance(operation.get("status"), str):
            raise EventError("operation.status must be a string")
        if "name" in operation and not isinstance(operation["name"], str):
            raise EventError("operation.name must be a string")

        parent_span_id = data.get("parent_span_id")
        if parent_span_id is not None and not isinstance(parent_span_id, str):
            raise EventError("parent_span_id must be a string")

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
            actor=MappingProxyType(dict(actor)),
            operation=MappingProxyType(dict(operation)),
            raw=MappingProxyType(dict(data)),
        )
