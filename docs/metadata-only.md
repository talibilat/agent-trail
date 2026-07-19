# Metadata-Only Mode

Metadata-only mode lets you inspect, serve, and export a trace without retaining event payload bodies.

The mode preserves canonical event identity, causal relationships, actor and operation metadata, attributes, usage, warnings, and Change Evidence Map data that producers place outside `payload`.

Run a terminal inspection with metadata-only retention by using this command.

```bash
agent-tail run.jsonl --metadata-only
```

Serve the browser interface with metadata-only retention by using this command.

```bash
agent-tail serve run.jsonl --metadata-only
```

Create a metadata-only Markdown report or self-contained HTML report by using one of these commands.

```bash
agent-tail run.jsonl --metadata-only --export report.md
agent-tail run.jsonl --metadata-only --export-html report.html
```

For each present top-level payload, AgentTrail retains only its original compact UTF-8 JSON byte count, SHA-256 digest, an explicit `omitted: true` state, and redaction ruleset version.

The digest and byte count describe the original serialized payload before redaction, and identical input produces identical omission metadata.

Events that never had a payload remain labeled as absent, while metadata-only payloads remain labeled as omitted rather than truncated, retained, or evicted.

Omission happens before `TraceIndex`, warning analysis, `RunStore` payload-detail retention, API and SSE projection, rendering, and export.

The lazy serve endpoint returns the omitted state and omission metadata, but it cannot return a payload preview or body.

`--metadata-only` cannot be combined with `--full-payloads` because those retention requests conflict.

Normal redaction still applies to retained metadata, including attributes, actor data, operation data, paths, commands, evidence text, and source-specific extensions.

Combining `--metadata-only` with `--unsafe-unredacted` leaves payload bodies omitted but disables normal redaction for retained non-structural metadata.

That unsafe combination can expose secrets or private values in retained metadata and should only be used with trusted local input.

Metadata-only output is not anonymous, does not remove all sensitive metadata, and still requires review before sharing.
