# OpenTelemetry OTLP JSON Import

AgentTrail imports completed OpenTelemetry spans from the standard OTLP JSON `resourceSpans`, `scopeSpans`, and `spans` hierarchy.
The importer uses only the Python standard library and does not receive protobuf, OTLP/HTTP, OTLP/gRPC, collector endpoints, Zipkin, Jaeger, or vendor-specific formats.

## Import A File

Convert an OTLP JSON trace to canonical AgentTrail JSONL:

```bash
agent-tail import otel traces.json --output run.jsonl
```

Inspect the generated artifact in the terminal:

```bash
agent-tail run.jsonl
```

Open it in the local browser UI:

```bash
agent-tail serve run.jsonl
```

The generated JSONL is a local source artifact that remains semantically faithful to the telemetry input and can contain credentials, prompts, tool data, and other sensitive values.
Protect it exactly as you protect the original OTLP file.
AgentTrail applies its existing sanitization boundary when the generated JSONL is inspected, exported to Markdown, or served, but the JSONL file itself is intentionally not redacted.

## Standard Streams

Use standard input when the OTLP JSON is produced by another local command:

```bash
otel-producer | agent-tail import otel - --output run.jsonl
```

Use standard output to pipe canonical events directly into the inspector:

```bash
agent-tail import otel traces.json --output - | agent-tail -
```

`INPUT` and `OUTPUT` cannot both be `-` because one process cannot safely use standard input and standard output as both sides of this adapter workflow.

## Mapping

Each valid OTLP span produces one completed canonical event, followed by one `otel.span.event` event for each valid nested span event in source array order.
Canonical output uses sorted compact JSON keys, so reordering object keys in the source does not change output bytes.
Array order remains significant.

Valid OTLP trace IDs, span IDs, parent span IDs, timestamps, status, links, resource identity, instrumentation scope, and source attributes are retained.
The original standard OTLP structures are namespaced under `attributes.otel.resource`, `attributes.otel.scope`, `attributes.otel.span`, and, for nested events, `attributes.otel.event`.
OTLP links remain source metadata under `attributes.otel.span.links` because links do not identify canonical event IDs.

Canonical event IDs are SHA-256-derived from the lowercased OTLP trace ID, span ID, and either the span marker or nested event ordinal.
Importing identical content twice therefore produces byte-identical JSONL.
Sequences are contiguous for each selected emitter in resource, scope, span, and nested-event traversal order, without asserting ordering between emitters.

The emitter selection order is:

- The non-empty `service.instance.id` resource attribute.
- The instrumentation scope name and optional version, formatted as `otel.scope:NAME` or `otel.scope:NAME@VERSION`.
- A deterministic `otel.source:` identifier derived from the source resource and scope positions.

The actor selection order is:

- The non-empty `gen_ai.agent.id` span attribute.
- The non-empty `gen_ai.agent.name` span attribute.
- The non-empty `service.name` resource attribute.
- The instrumentation scope identity.
- The selected emitter identity.

GenAI mapping is deliberately conservative and uses only a recognized `gen_ai.operation.name` value.
`chat`, `text_completion`, `embeddings`, and `generate_content` map to `model.request.finished`.
`execute_tool` maps to `tool.call.finished`, or `tool.call.failed` when OTLP status is error.
`invoke_agent` maps to `agent.finished`.
Every other completed span maps to `otel.span.finished`, and source token usage and model attributes remain unchanged under `attributes.otel` for future projections.
An unset or absent OTLP status maps to canonical status `unknown` rather than inferred success.
The importer never synthesizes change, verification, or evidence relationships from incomplete telemetry.

## Diagnostics And Exit Codes

Malformed resources, scopes, spans, and span events produce path-based diagnostics on standard error without discarding independent valid siblings.
Diagnostics are redacted, omit rejected source values, and are bounded to 100 individual messages plus an omitted-count summary.

- Exit code `0` means at least one canonical event was emitted, even when other records were rejected.
- Exit code `1` means the OTLP JSON document was read but no valid event was emitted.
- Exit code `2` means command validation, decoding, file access, output, invalid JSON, or unsupported source format failed.
