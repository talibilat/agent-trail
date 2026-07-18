from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Mapping

from .core import IngestionError, redact_text


_HEX_ID = re.compile(r"^[0-9a-fA-F]+$")
_MODEL_OPERATIONS = {"chat", "embeddings", "generate_content", "text_completion"}


class OTLPDocumentError(ValueError):
    """Raised when input is not a supported OTLP JSON trace document."""


@dataclass(frozen=True)
class OTLPImport:
    events: tuple[dict[str, object], ...]
    errors: tuple[IngestionError, ...]


class _Importer:
    def __init__(self, *, max_errors: int = 100) -> None:
        self.events: list[dict[str, object]] = []
        self.errors: list[IngestionError] = []
        self.omitted_error_count = 0
        self.max_errors = max_errors
        self.sequences: defaultdict[str, int] = defaultdict(int)
        self.span_keys: set[tuple[str, str]] = set()

    def import_document(self, document: object) -> OTLPImport:
        if not isinstance(document, Mapping) or not isinstance(
            document.get("resourceSpans"), list
        ):
            raise OTLPDocumentError(
                "unsupported format: expected an OTLP JSON trace object with resourceSpans"
            )

        for resource_index, resource_spans in enumerate(document["resourceSpans"]):
            resource_path = f"resourceSpans[{resource_index}]"
            if not isinstance(resource_spans, Mapping):
                self.error(resource_path, "must be an object")
                continue
            scope_spans_list = resource_spans.get("scopeSpans")
            if not isinstance(scope_spans_list, list):
                self.error(resource_path, "scopeSpans must be an array")
                continue
            resource = resource_spans.get("resource", {})
            try:
                resource_attributes = _attributes(resource, f"{resource_path}.resource")
            except ValueError as error:
                self.error(f"{resource_path}.resource", str(error))
                continue

            for scope_index, scope_spans in enumerate(scope_spans_list):
                scope_path = f"{resource_path}.scopeSpans[{scope_index}]"
                if not isinstance(scope_spans, Mapping):
                    self.error(scope_path, "must be an object")
                    continue
                spans = scope_spans.get("spans")
                if not isinstance(spans, list):
                    self.error(scope_path, "spans must be an array")
                    continue
                scope = scope_spans.get("scope", {})
                try:
                    scope_attributes = _attributes(scope, f"{scope_path}.scope")
                except ValueError as error:
                    self.error(f"{scope_path}.scope", str(error))
                    continue

                context = {
                    "resource": resource,
                    "resource_schema_url": resource_spans.get("schemaUrl"),
                    "resource_attributes": resource_attributes,
                    "scope": scope,
                    "scope_schema_url": scope_spans.get("schemaUrl"),
                    "scope_attributes": scope_attributes,
                    "resource_index": resource_index,
                    "scope_index": scope_index,
                }
                for span_index, span in enumerate(spans):
                    self.import_span(
                        span,
                        context,
                        f"{scope_path}.spans[{span_index}]",
                    )

        errors = list(self.errors)
        if self.omitted_error_count:
            errors.append(IngestionError(
                None,
                f"{self.omitted_error_count} additional OTLP import errors omitted",
            ))
        return OTLPImport(tuple(self.events), tuple(errors))

    def import_span(
        self,
        span: object,
        context: dict[str, object],
        path: str,
    ) -> None:
        if not isinstance(span, Mapping):
            self.error(path, "must be an object")
            return
        try:
            trace_id = _identifier(span.get("traceId"), 32, "traceId")
            span_id = _identifier(span.get("spanId"), 16, "spanId")
            parent_span_id = span.get("parentSpanId")
            if parent_span_id in (None, ""):
                parent_span_id = None
            else:
                parent_span_id = _identifier(parent_span_id, 16, "parentSpanId")
            name = span.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("name must be a non-empty string")
            timestamp = _timestamp(span.get("endTimeUnixNano"), "endTimeUnixNano")
            span_attributes = _attributes(span, path)
            links = span.get("links", [])
            if not isinstance(links, list):
                raise ValueError("links must be an array")
            for link_index, link in enumerate(links):
                _validate_link(link, f"links[{link_index}]")
            source_events = span.get("events", [])
            if not isinstance(source_events, list):
                raise ValueError("events must be an array")
        except ValueError as error:
            self.error(path, str(error))
            return

        span_key = (trace_id.lower(), span_id.lower())
        if span_key in self.span_keys:
            self.error(path, "duplicates a traceId and spanId pair")
            return
        self.span_keys.add(span_key)

        emitter_id = _emitter_id(context)
        operation_name = span_attributes.get("gen_ai.operation.name")
        if not isinstance(operation_name, str) or not operation_name:
            operation_name = name
        operation_status = _status(span.get("status"))
        actor_id = _actor_id(context, span_attributes, emitter_id)
        kind = _span_kind(span_attributes, operation_status)
        otel = _otel_context(context, span, include_events=False)
        self.events.append(self.event(
            event_id=_event_id(trace_id, span_id, "span"),
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            emitter_id=emitter_id,
            timestamp=timestamp,
            kind=kind,
            actor_id=actor_id,
            operation_name=operation_name,
            operation_status=operation_status,
            otel=otel,
        ))

        for event_index, source_event in enumerate(source_events):
            event_path = f"{path}.events[{event_index}]"
            try:
                if not isinstance(source_event, Mapping):
                    raise ValueError("must be an object")
                event_name = source_event.get("name")
                if not isinstance(event_name, str) or not event_name:
                    raise ValueError("name must be a non-empty string")
                event_timestamp = _timestamp(
                    source_event.get("timeUnixNano"), "timeUnixNano"
                )
                _attributes(source_event, event_path)
            except ValueError as error:
                self.error(event_path, str(error))
                continue
            self.events.append(self.event(
                event_id=_event_id(trace_id, span_id, f"event:{event_index}"),
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                emitter_id=emitter_id,
                timestamp=event_timestamp,
                kind="otel.span.event",
                actor_id=actor_id,
                operation_name=event_name,
                operation_status="unknown",
                otel={**deepcopy(otel), "event": deepcopy(dict(source_event))},
            ))

    def event(self, **values: object) -> dict[str, object]:
        emitter_id = values["emitter_id"]
        self.sequences[emitter_id] += 1
        return {
            "schema_version": "1.0",
            "event_id": values["event_id"],
            "trace_id": values["trace_id"],
            "span_id": values["span_id"],
            **(
                {"parent_span_id": values["parent_span_id"]}
                if values["parent_span_id"] is not None
                else {}
            ),
            "emitter_id": emitter_id,
            "sequence": self.sequences[emitter_id],
            "timestamp": values["timestamp"],
            "kind": values["kind"],
            "actor": {"id": values["actor_id"]},
            "operation": {
                "status": values["operation_status"],
                "name": values["operation_name"],
            },
            "attributes": {"otel": values["otel"]},
        }

    def error(self, path: str, message: str) -> None:
        if len(self.errors) < self.max_errors:
            self.errors.append(IngestionError(
                None,
                redact_text(f"{path}: {message}"),
            ))
        else:
            self.omitted_error_count += 1


def import_otlp_json(document: object, *, max_errors: int = 100) -> OTLPImport:
    return _Importer(max_errors=max_errors).import_document(document)


def parse_otlp_json(text: str) -> OTLPImport:
    try:
        document = json.loads(
            text,
            parse_constant=lambda value: _invalid_json_constant(value),
        )
    except (json.JSONDecodeError, ValueError) as error:
        message = error.msg if isinstance(error, json.JSONDecodeError) else str(error)
        raise OTLPDocumentError(
            f"unsupported format: input is not valid OTLP JSON ({message})"
        ) from error
    return import_otlp_json(document)


def canonical_jsonl(result: OTLPImport) -> str:
    return "".join(
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
        for event in result.events
    )


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"non-standard numeric value {value}")


def _attributes(container: object, path: str) -> dict[str, object]:
    if not isinstance(container, Mapping):
        raise ValueError("must be an object")
    attributes = container.get("attributes", [])
    if not isinstance(attributes, list):
        raise ValueError("attributes must be an array")
    result = {}
    for index, attribute in enumerate(attributes):
        if not isinstance(attribute, Mapping):
            raise ValueError(f"attributes[{index}] must be an object")
        key = attribute.get("key")
        if not isinstance(key, str) or not key:
            raise ValueError(f"attributes[{index}].key must be a non-empty string")
        if key in result:
            raise ValueError(f"attributes[{index}].key is duplicated")
        try:
            result[key] = _any_value(attribute.get("value"))
        except ValueError as error:
            raise ValueError(f"attributes[{index}].value {error}") from error
    return result


def _any_value(value: object) -> object:
    if not isinstance(value, Mapping):
        raise ValueError("must be an object")
    fields = [
        field for field in (
            "stringValue", "boolValue", "intValue", "doubleValue", "bytesValue",
            "arrayValue", "kvlistValue",
        )
        if field in value
    ]
    if len(fields) != 1:
        raise ValueError("must contain exactly one OTLP AnyValue field")
    field = fields[0]
    item = value[field]
    if field in {"stringValue", "bytesValue"}:
        if not isinstance(item, str):
            raise ValueError(f"{field} must be a string")
        return item
    if field == "boolValue":
        if not isinstance(item, bool):
            raise ValueError("boolValue must be a boolean")
        return item
    if field == "intValue":
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            raise ValueError("intValue must be an integer or decimal string")
        try:
            return int(item)
        except ValueError as error:
            raise ValueError("intValue must be a decimal string") from error
    if field == "doubleValue":
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError("doubleValue must be a number")
        return item
    if not isinstance(item, Mapping) or not isinstance(item.get("values"), list):
        raise ValueError(f"{field}.values must be an array")
    if field == "arrayValue":
        return [_any_value(child) for child in item["values"]]
    pairs = {}
    for index, pair in enumerate(item["values"]):
        if not isinstance(pair, Mapping) or not isinstance(pair.get("key"), str):
            raise ValueError(f"kvlistValue.values[{index}] must be a key/value object")
        pairs[pair["key"]] = _any_value(pair.get("value"))
    return pairs


def _identifier(value: object, length: int, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or _HEX_ID.fullmatch(value) is None
        or set(value) == {"0"}
    ):
        raise ValueError(f"{field} must be a non-zero {length}-digit hexadecimal string")
    return value


def _timestamp(value: object, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be a non-negative integer or decimal string")
    try:
        nanoseconds = int(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a decimal string") from error
    if nanoseconds < 0 or str(value).startswith(("+", "-")):
        raise ValueError(f"{field} must be a non-negative integer or decimal string")
    seconds, fraction = divmod(nanoseconds, 1_000_000_000)
    try:
        base = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError(f"{field} is outside the supported timestamp range") from error
    suffix = f".{fraction:09d}".rstrip("0") if fraction else ""
    return f"{base}{suffix}Z"


def _validate_link(link: object, path: str) -> None:
    if not isinstance(link, Mapping):
        raise ValueError(f"{path} must be an object")
    _identifier(link.get("traceId"), 32, f"{path}.traceId")
    _identifier(link.get("spanId"), 16, f"{path}.spanId")
    _attributes(link, path)


def _scope_identity(scope: object) -> str | None:
    if not isinstance(scope, Mapping):
        return None
    name = scope.get("name")
    if not isinstance(name, str) or not name:
        return None
    version = scope.get("version")
    return f"otel.scope:{name}@{version}" if isinstance(version, str) and version else f"otel.scope:{name}"


def _emitter_id(context: dict[str, object]) -> str:
    instance = context["resource_attributes"].get("service.instance.id")
    if isinstance(instance, str) and instance:
        return instance
    scope = _scope_identity(context["scope"])
    if scope:
        return scope
    digest = hashlib.sha256(
        f"{context['resource_index']}\0{context['scope_index']}".encode()
    ).hexdigest()[:16]
    return f"otel.source:{digest}"


def _actor_id(
    context: dict[str, object],
    span_attributes: dict[str, object],
    emitter_id: str,
) -> str:
    for key in ("gen_ai.agent.id", "gen_ai.agent.name"):
        value = span_attributes.get(key)
        if isinstance(value, str) and value:
            return value
    service = context["resource_attributes"].get("service.name")
    if isinstance(service, str) and service:
        return service
    return _scope_identity(context["scope"]) or emitter_id


def _status(status: object) -> str:
    if not isinstance(status, Mapping):
        return "unknown"
    code = status.get("code")
    if code in ("STATUS_CODE_ERROR", "ERROR", 2, "2"):
        return "error"
    if code in ("STATUS_CODE_OK", "OK", 1, "1"):
        return "success"
    return "unknown"


def _span_kind(attributes: dict[str, object], status: str) -> str:
    operation = attributes.get("gen_ai.operation.name")
    if operation in _MODEL_OPERATIONS:
        return "model.request.finished"
    if operation == "execute_tool":
        return "tool.call.failed" if status == "error" else "tool.call.finished"
    if operation == "invoke_agent":
        return "agent.finished"
    return "otel.span.finished"


def _event_id(trace_id: str, span_id: str, ordinal: str) -> str:
    digest = hashlib.sha256(
        f"otlp-json\0{trace_id.lower()}\0{span_id.lower()}\0{ordinal}".encode()
    ).hexdigest()
    return f"otel-{digest[:32]}"


def _otel_context(
    context: dict[str, object],
    span: Mapping[str, object],
    *,
    include_events: bool,
) -> dict[str, object]:
    source_span = deepcopy(dict(span))
    if not include_events:
        source_span.pop("events", None)
    result = {
        "resource": deepcopy(context["resource"]),
        "scope": deepcopy(context["scope"]),
        "span": source_span,
    }
    if context["resource_schema_url"] is not None:
        result["resource_schema_url"] = deepcopy(context["resource_schema_url"])
    if context["scope_schema_url"] is not None:
        result["scope_schema_url"] = deepcopy(context["scope_schema_url"])
    return result
