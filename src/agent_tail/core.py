from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import heapq
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
_STRUCTURAL_IDENTITY_PATHS = {
    ("event_id",),
    ("trace_id",),
    ("span_id",),
    ("parent_span_id",),
    ("emitter_id",),
    ("actor", "id"),
}


class EventError(ValueError):
    """Raised when an event does not match the canonical envelope."""


def redact_text(value: str) -> str:
    return _SECRET_VALUE.sub("[REDACTED]", value)


def _redact_deterministic(value: str) -> str:
    return _SECRET_VALUE.sub(
        lambda match: "[REDACTED:"
        + hashlib.sha256(match.group().encode("utf-8")).hexdigest()[:12]
        + "]",
        value,
    )


def _redact_identity(value: str) -> str:
    if not _SECRET_VALUE.search(value) and value.startswith(
        ("[REDACTED:", "[LITERAL]")
    ):
        value = "[LITERAL]" + value
    return _redact_deterministic(value)


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
    line: int | None
    message: str


@dataclass
class Ingestion:
    events: list[Event]
    errors: list[IngestionError]


class JSONLReader:
    def __init__(self, *, retain_events: bool = True, max_errors: int = 100) -> None:
        self.events: list[Event] = []
        self.errors: list[IngestionError] = []
        self.accepted_count = 0
        self.omitted_error_count = 0
        self._retain_events = retain_events
        self._max_errors = max_errors
        self._accepted_ids: set[str] = set()
        self._line_number = 0

    @property
    def all_errors(self) -> list[IngestionError]:
        if not self.omitted_error_count:
            return list(self.errors)
        return [
            *self.errors,
            IngestionError(
                None,
                f"{self.omitted_error_count} additional ingestion errors omitted",
            ),
        ]

    def feed(self, line: str) -> Event | None:
        self._line_number += 1
        if not line.strip():
            return None
        try:
            event = Event.from_dict(json.loads(line))
        except json.JSONDecodeError as error:
            self._error(f"invalid JSON: {error.msg}")
            return None
        except EventError as error:
            self._error(str(error))
            return None

        if event.event_id in self._accepted_ids:
            self._error(f"duplicate event ID: {event.event_id}")
            return None
        self._accepted_ids.add(event.event_id)
        self.accepted_count += 1
        if self._retain_events:
            self.events.append(event)
        return event

    def read(self, lines: Iterable[str]) -> Ingestion:
        for line in lines:
            self.feed(line)
        return Ingestion(self.events, self.all_errors)

    def _error(self, message: str) -> None:
        if len(self.errors) < self._max_errors:
            self.errors.append(IngestionError(self._line_number, redact_text(message)))
        else:
            self.omitted_error_count += 1


def read_jsonl(lines: Iterable[str]) -> Ingestion:
    return JSONLReader().read(lines)


def sanitize_event(
    event: Event,
    *,
    full_payloads: bool = False,
    unsafe_unredacted: bool = False,
) -> Event:
    def redact(value: object, path: tuple[str, ...] = ()) -> object:
        if isinstance(value, dict):
            redacted = {}
            for key, item in value.items():
                safe_key = (
                    key
                    if unsafe_unredacted or not isinstance(key, str)
                    else _redact_identity(key)
                )
                redacted[safe_key] = (
                    "[REDACTED]"
                    if not unsafe_unredacted
                    and _SENSITIVE_KEY.search(_KEY_SEPARATOR.sub("", str(key)))
                    else redact(item, (*path, str(key)))
                )
            return redacted
        if isinstance(value, list):
            return [redact(item, path) for item in value]
        if isinstance(value, str):
            if path in _STRUCTURAL_IDENTITY_PATHS:
                return _redact_identity(value)
            return value if unsafe_unredacted else redact_text(value)
        return value

    original_raw = event.raw
    raw = redact(original_raw)

    if "payload" in raw:
        payload = original_raw["payload"]
        original = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        safe_payload = raw["payload"]
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


@dataclass(frozen=True)
class Warning:
    code: str
    event_id: str
    actor_id: str
    summary: str
    evidence: str


@dataclass(frozen=True)
class SpanState:
    parent_span_id: str | None
    actor_id: str
    status: str
    open: bool
    event_ids: tuple[str, ...]


@dataclass(frozen=True)
class ActorState:
    status: str
    operation: object
    last_activity: datetime
    last_activity_event_id: str
    open_span_ids: tuple[str, ...]
    uncertain: bool


@dataclass(frozen=True)
class TraceView:
    events: tuple[Event, ...]
    uncertain_event_ids: frozenset[str]
    actors: Mapping[str, ActorState]
    spans: Mapping[str, SpanState]

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(event.event_id for event in self.events)


class TraceIndex:
    _TERMINAL_STATUSES = {
        "canceled", "cancelled", "complete", "completed", "done", "error",
        "errored", "failed", "stopped", "succeeded", "success",
    }
    _STATE_KEYS = (
        "output_hash", "error_hash", "output_id", "error_id", "file_hash",
        "checkpoint_id", "success", "retry_reason",
    )

    def __init__(
        self,
        *,
        loop_threshold: int = 4,
        stall_seconds: float = 30.0,
        orphan_grace_seconds: float = 5.0,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        for field_name, value, expected_type in (
            ("loop_threshold", loop_threshold, int),
            ("stall_seconds", stall_seconds, (int, float)),
            ("orphan_grace_seconds", orphan_grace_seconds, (int, float)),
            ("max_bytes", max_bytes, int),
        ):
            if isinstance(value, bool) or not isinstance(value, expected_type):
                raise TypeError(f"{field_name} has an incorrect type")
        for field_name, valid in (
            ("loop_threshold", loop_threshold >= 2),
            ("stall_seconds", stall_seconds >= 0),
            ("orphan_grace_seconds", orphan_grace_seconds >= 0),
            ("max_bytes", max_bytes > 0),
        ):
            if not valid:
                raise ValueError(f"{field_name} is outside its valid range")
        self.loop_threshold = loop_threshold
        self.stall_seconds = stall_seconds
        self.orphan_grace_seconds = orphan_grace_seconds
        self.max_bytes = max_bytes
        self._events: list[Event] = []
        self._event_ids: set[str] = set()
        self._sizes: dict[str, int] = {}
        self._eviction_warning: Warning | None = None
        self._eviction_count = 0

    def add(self, event: Event) -> None:
        if event.event_id in self._event_ids:
            raise ValueError(f"duplicate event ID: {event.event_id}")
        self._events.append(event)
        self._event_ids.add(event.event_id)
        self._sizes[event.event_id] = self._event_size(event)
        self._evict()

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def ordered_events(self) -> tuple[Event, ...]:
        return tuple(self._order(self._events)[0])

    def trace(self, trace_id: str) -> TraceView:
        events = [event for event in self._events if event.trace_id == trace_id]
        ordered, uncertain, (_, descendants) = self._order(events)
        spans: dict[str, SpanState] = {}
        actor_events: dict[str, list[Event]] = {}

        for event in ordered:
            actor_id = event.actor["id"]
            actor_events.setdefault(actor_id, []).append(event)
            operation_status = event.operation["status"]
            prior = spans.get(event.span_id)
            is_open = prior.open if prior else False
            if self._closes(event):
                is_open = False
            elif event.kind.endswith(".started") or operation_status.lower() in {
                "running", "waiting",
            }:
                is_open = True
            spans[event.span_id] = SpanState(
                event.parent_span_id,
                actor_id,
                operation_status,
                is_open,
                (*prior.event_ids, event.event_id) if prior else (event.event_id,),
            )

        last_activity = {
            actor_id: max(
                enumerate(activity),
                key=lambda item: (item[1].timestamp, item[0]),
            )[1]
            for actor_id, activity in actor_events.items()
        }
        for event in ordered:
            parent_span_id = event.parent_span_id
            seen = set()
            while parent_span_id in spans and parent_span_id not in seen:
                seen.add(parent_span_id)
                parent = spans[parent_span_id]
                if event.timestamp >= last_activity[parent.actor_id].timestamp:
                    last_activity[parent.actor_id] = event
                parent_span_id = parent.parent_span_id

        actor_bits = {}
        for position, event in enumerate(ordered):
            actor_id = event.actor["id"]
            actor_bits[actor_id] = actor_bits.get(actor_id, 0) | 1 << position

        actors = {}
        for actor_id, activity in actor_events.items():
            maxima = [
                event
                for event in activity
                if not descendants[event.event_id] & actor_bits[actor_id]
            ]
            display = maxima[-1] if maxima else activity[-1]
            open_spans = tuple(
                span_id
                for span_id, span in spans.items()
                if span.actor_id == actor_id and span.open
            )
            if open_spans:
                active = next(
                    event
                    for event in reversed(activity)
                    if event.span_id in open_spans
                )
                status = spans[active.span_id].status
            else:
                active = display
                status = display.operation["status"]
            actors[actor_id] = ActorState(
                status,
                active.operation.get("name", "-"),
                last_activity[actor_id].timestamp,
                last_activity[actor_id].event_id,
                open_spans,
                len(maxima) != 1,
            )

        return TraceView(tuple(ordered), frozenset(uncertain), actors, spans)

    def warnings(self, *, now: str | datetime | None = None) -> tuple[Warning, ...]:
        current = self._parse_now(now)
        warnings = [self._eviction_warning] if self._eviction_warning else []

        for trace_id in dict.fromkeys(event.trace_id for event in self._events):
            view = self.trace(trace_id)
            warnings.extend(self._loop_warnings(view.events))
            warnings.extend(self._retry_warnings(view.events))
            for actor_id, actor in view.actors.items():
                elapsed = (current - actor.last_activity).total_seconds()
                if actor.open_span_ids and elapsed >= self.stall_seconds:
                    event_id = actor.last_activity_event_id
                    warnings.append(self._warning(
                        "STALL", event_id, actor_id,
                        f"{actor_id} has produced no event for {elapsed:.1f} seconds",
                        event_ids=[event_id], seconds=elapsed,
                    ))

            span_ids = set(view.spans)
            for event in view.events:
                if (
                    event.parent_span_id
                    and event.parent_span_id not in span_ids
                    and (current - event.timestamp).total_seconds()
                    >= self.orphan_grace_seconds
                ):
                    warnings.append(self._warning(
                        "ORPHAN", event.event_id, event.actor["id"],
                        f"parent span {event.parent_span_id} is absent",
                        event_ids=[event.event_id], parent_span_id=event.parent_span_id,
                    ))

        return tuple(warnings)

    def _order(
        self, events: list[Event]
    ) -> tuple[
        list[Event],
        set[str],
        tuple[dict[str, int], dict[str, int]],
    ]:
        positions = {event.event_id: position for position, event in enumerate(self._events)}
        by_id = {event.event_id: event for event in events}
        outgoing = {event.event_id: set() for event in events}
        causal_outgoing = {event.event_id: set() for event in events}
        causal_incoming = {event.event_id: set() for event in events}
        incoming = {event.event_id: set() for event in events}
        fallback_uncertain = set()

        def edge(before: str, after: str, *, causal: bool = True) -> None:
            if before != after:
                outgoing[before].add(after)
                incoming[after].add(before)
                if causal:
                    causal_outgoing[before].add(after)
                    causal_incoming[after].add(before)

        emitters: dict[str, list[Event]] = {}
        for event in events:
            emitters.setdefault(event.emitter_id, []).append(event)
        for emitter_events in emitters.values():
            sequence_groups: dict[int, list[Event]] = {}
            for event in emitter_events:
                sequence_groups.setdefault(event.sequence, []).append(event)
            sequences = sorted(sequence_groups)
            for lower, higher in zip(sequences, sequences[1:]):
                for before in sequence_groups[lower]:
                    for after in sequence_groups[higher]:
                        edge(before.event_id, after.event_id)

        spans: dict[tuple[str, str], list[Event]] = {}
        for event in events:
            spans.setdefault((event.trace_id, event.span_id), []).append(event)
        for event in events:
            parent_key = (event.trace_id, event.parent_span_id)
            if parent_key in spans:
                parents = spans[parent_key]
                starts = [parent for parent in parents if parent.kind.endswith(".started")]
                if starts:
                    for parent in starts:
                        edge(parent.event_id, event.event_id)
                else:
                    parent = min(
                        parents,
                        key=lambda candidate: (
                            candidate.timestamp, positions[candidate.event_id]
                        ),
                    )
                    edge(parent.event_id, event.event_id, causal=False)
                    fallback_uncertain.update((parent.event_id, event.event_id))

        ready = [
            (by_id[event_id].timestamp, positions[event_id], event_id)
            for event_id in by_id
            if not incoming[event_id]
        ]
        heapq.heapify(ready)
        ordered = []
        while ready:
            _, _, event_id = heapq.heappop(ready)
            ordered.append(by_id[event_id])
            for child in outgoing[event_id]:
                incoming[child].discard(event_id)
                if not incoming[child]:
                    heapq.heappush(ready, (
                        by_id[child].timestamp,
                        positions[child],
                        child,
                    ))

        remainder = []
        if len(ordered) != len(events):
            included = {event.event_id for event in ordered}
            remainder = [event for event in events if event.event_id not in included]
            remainder.sort(key=lambda event: (event.timestamp, positions[event.event_id]))
            ordered.extend(remainder)

        bit = {
            event.event_id: 1 << position
            for position, event in enumerate(ordered)
        }
        ancestors = {event.event_id: 0 for event in ordered}
        for event in ordered:
            for parent in causal_incoming[event.event_id]:
                ancestors[event.event_id] |= ancestors[parent] | bit[parent]

        descendants = {event.event_id: 0 for event in ordered}
        for event in reversed(ordered):
            for child in causal_outgoing[event.event_id]:
                descendants[event.event_id] |= descendants[child] | bit[child]

        all_events = (1 << len(ordered)) - 1
        uncertain = {
            event.event_id
            for event in ordered
            if (
                ancestors[event.event_id]
                | descendants[event.event_id]
                | bit[event.event_id]
            ) != all_events
        }
        uncertain.update(fallback_uncertain)
        uncertain.update(event.event_id for event in remainder)
        return ordered, uncertain, (ancestors, descendants)

    @staticmethod
    def _reaches(outgoing: Mapping[str, set[str]], start: str, target: str) -> bool:
        pending = list(outgoing[start])
        seen = set()
        while pending:
            node = pending.pop()
            if node == target:
                return True
            if node not in seen:
                seen.add(node)
                pending.extend(outgoing[node])
        return False

    def _loop_warnings(self, events: tuple[Event, ...]) -> list[Warning]:
        warnings = []
        for (_, signature), histories in self._histories(events).items():
            for repeated in histories:
                for start in range(len(repeated) - self.loop_threshold + 1):
                    window = repeated[start:start + self.loop_threshold]
                    states = {self._state(event) for event in window}
                    if len(states) == 1:
                        last = window[-1]
                        warnings.append(self._warning(
                            "LOOP", last.event_id, last.actor["id"],
                            f"repeated equivalent operation {len(window)} times without state change",
                            event_ids=[event.event_id for event in window],
                            signature=signature, state=next(iter(states)),
                        ))
                        break
                else:
                    continue
                break
        return warnings

    def _retry_warnings(self, events: tuple[Event, ...]) -> list[Warning]:
        warnings = []
        streaks: dict[tuple[str, str, str], tuple[str, str, list[Event], bool]] = {}
        for event in events:
            scope = (
                event.emitter_id,
                event.actor["id"],
                self._json(event.operation.get("name")),
            )
            failed = (
                event.kind.endswith(".failed")
                or event.operation["status"].lower() == "failed"
            )
            if not failed:
                streaks.pop(scope, None)
                continue

            signature = self._signature(event, include_kind=False)
            state = self._state(event)
            prior = streaks.get(scope)
            if (
                prior is None
                or prior[0] != signature
                or prior[1] != state
                or event.sequence <= prior[2][-1].sequence
            ):
                repeated = [event]
                warned = False
            else:
                repeated = [*prior[2][-2:], event]
                warned = prior[3]

            if len(repeated) >= 3 and not warned:
                window = repeated[-3:]
                delays = [
                    (after.timestamp - before.timestamp).total_seconds()
                    for before, after in zip(window, window[1:])
                ]
                if delays[1] <= delays[0]:
                    warnings.append(self._warning(
                        "RETRY", event.event_id, event.actor["id"],
                        "repeated an unchanged failing call 3 times without increasing delay",
                        event_ids=[item.event_id for item in window],
                        delays=delays, signature=signature, state=state,
                    ))
                    warned = True
            streaks[scope] = (signature, state, repeated, warned)
        return warnings

    def _histories(
        self, events: tuple[Event, ...], *, include_kind: bool = True
    ) -> dict[tuple[str, str], list[list[Event]]]:
        groups: dict[tuple[str, str], list[list[Event]]] = {}
        for event in events:
            histories = groups.setdefault(
                (
                    event.emitter_id,
                    self._signature(event, include_kind=include_kind),
                ),
                [[]],
            )
            if histories[-1] and event.sequence <= histories[-1][-1].sequence:
                histories.append([])
            histories[-1].append(event)
        return groups

    def _signature(self, event: Event, *, include_kind: bool = True) -> str:
        raw = event.raw
        attributes = raw.get("attributes", {})
        if not isinstance(attributes, Mapping):
            attributes = {}
        arguments = attributes.get("arguments", {})
        if isinstance(arguments, Mapping):
            arguments = dict(arguments)
            volatile = attributes.get("volatile_argument_keys", [])
            if isinstance(volatile, list):
                for key in volatile:
                    if isinstance(key, str):
                        arguments.pop(key, None)
        signature = {
            "actor_id": event.actor["id"],
            "arguments": arguments,
            "operation": event.operation.get("name"),
        }
        if include_kind:
            signature["kind"] = event.kind
        return self._json(signature)

    def _state(self, event: Event) -> str:
        attributes = event.raw.get("attributes", {})
        if not isinstance(attributes, Mapping):
            attributes = {}
        return self._json({key: attributes.get(key) for key in self._STATE_KEYS})

    def _closes(self, event: Event) -> bool:
        return (
            event.kind.endswith((".completed", ".failed"))
            or event.operation["status"].lower() in self._TERMINAL_STATUSES
        )

    def _evict(self) -> None:
        while sum(self._sizes.values()) > self.max_bytes:
            changed = False
            for position, event in enumerate(self._events):
                raw = event.raw
                payload = raw.get("payload")
                if not isinstance(payload, dict) or set(payload) == {"_agent_tail"}:
                    continue
                metadata = payload.get("_agent_tail")
                raw["payload"] = {"_agent_tail": metadata} if metadata else {}
                smaller = Event.from_dict(raw)
                old_size = self._sizes[event.event_id]
                smaller_size = self._event_size(smaller)
                if smaller_size >= old_size:
                    continue
                self._events[position] = smaller
                self._sizes[event.event_id] = smaller_size
                self._record_eviction(
                    event, "payload", old_size - self._sizes[event.event_id]
                )
                changed = True
                break
            if changed:
                continue
            event = self._events.pop(0)
            size = self._sizes.pop(event.event_id)
            self._event_ids.remove(event.event_id)
            self._record_eviction(event, "metadata", size)

    def _record_eviction(self, event: Event, evicted: str, bytes_freed: int) -> None:
        self._eviction_count += 1
        self._eviction_warning = self._warning(
            "EVICT", event.event_id, event.actor["id"],
            f"evicted indexed data {self._eviction_count} times",
            count=self._eviction_count,
            latest={
                "bytes_freed": bytes_freed,
                "event_id": event.event_id,
                "evicted": evicted,
            },
        )

    @classmethod
    def _warning(
        cls,
        code: str,
        event_id: str,
        actor_id: str,
        summary: str,
        **evidence: object,
    ) -> Warning:
        return Warning(code, event_id, actor_id, summary, cls._json(evidence))

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _event_size(cls, event: Event) -> int:
        return len(cls._json(event.raw).encode("utf-8"))

    @staticmethod
    def _parse_now(value: str | datetime | None) -> datetime:
        if isinstance(value, datetime):
            return value
        if value is None:
            return datetime.now().astimezone()
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
