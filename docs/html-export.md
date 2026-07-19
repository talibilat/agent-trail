# Self-Contained HTML Export

AgentTrail can export a sanitized, interactive, read-only snapshot that opens directly from one local HTML file.
The report uses the same run summaries, run details, warnings, findings, payload previews, and Change Evidence Map projections as serve mode.
The packaged browser UI provides graph, tree, swimlane, and sequence views together with search, playback, warnings, and event and agent inspectors without a running AgentTrail process.

## Usage

Create a deterministic report with no generation timestamp:

```bash
agent-tail run.jsonl --export-html report.html
```

Create a deterministic report with an explicit generation timestamp:

```bash
agent-tail run.jsonl --export-html report.html \
  --export-html-generated-at 2026-07-18T12:00:00Z
```

The timestamp must be an ISO 8601 value with a timezone and is normalized to UTC.
When the option is omitted, the visible export information panel says that generation time was omitted for deterministic output.
The same sanitized input, options, AgentTrail version, and fixed or omitted timestamp produce byte-identical output.

`--export-html` and the Markdown `--export` option are mutually exclusive.
The HTML generation timestamp option is valid only with `--export-html`.
HTML export preserves the standard exit codes, and a successful write atomically replaces the destination.
If serialization or replacement fails, AgentTrail leaves an existing destination unchanged and removes its temporary artifact.

## Included Data

The export embeds the sanitized run list and complete serve projection for every accepted trace.
It includes warnings, ingestion findings, causal and unresolved relationships, retained payload previews and retention metadata, and valid and invalid Change Evidence Map records.
The visible information panel records the AgentTrail version, canonical event schema versions, redaction ruleset, export mode, payload retention counts, and generation time state.
Exported mode disables live SSE, source connectivity behavior, and lazy payload requests.

The default payload policy truncates large payloads on a UTF-8 boundary and records the original byte count and SHA-256 digest.
`--full-payloads` includes full sanitized accepted payloads and can make the report substantially larger.
`--max-bytes` can evict payload data before export while retaining the corresponding payload state and warning.

## Offline Security

The report contains its CSS, JavaScript, icons, and snapshot data in one file and does not depend on fonts, scripts, images, stylesheets, or APIs from another location.
Embedded snapshot JSON is UTF-8 encoded and then base64 encoded inside a non-script element so closing tags, active markup, Unicode separators, and URL-like strings cannot break into executable HTML.
The application script is authorized by a SHA-256 Content Security Policy hash rather than by allowing arbitrary inline scripts.
The export Content Security Policy blocks network connections, remote assets, objects, frames, child contexts, workers, manifests, forms, and base URL changes.
The UI inserts event-controlled values as escaped text or through `textContent` rather than interpreting them as markup.

Sanitization is deliberately limited and cannot identify every secret, credential, personal detail, or proprietary value.
Structural identifiers are protected even when `--unsafe-unredacted` is used, but accepted non-structural values are not redacted in that mode.
Use `--unsafe-unredacted` only for trusted local investigation and do not treat its output as safe to share.
Review the complete artifact, including every run, warning, inspector, and payload preview, before sharing it.

Opening an exported report does not reconnect it to its original source or enable editing, replaying agents, or server operations.
Browser security behavior can vary, so the report's sanitization and restrictive policy are defense in depth rather than a guarantee that arbitrary sensitive input is safe to disclose.
