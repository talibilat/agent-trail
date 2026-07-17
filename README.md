# Agent Tail

Agent Tail is a local CLI and terminal UI for inspecting canonical multi-agent runtime events without a backend.
Version 1 directly supports the canonical JSONL emitted by this runtime from a file or standard input.

## Install

Agent Tail requires Python 3.11 or newer.

```bash
python -m pip install .
agent-tail --help
```

For development without installation, prefix commands with `PYTHONPATH=src python -m agent_tail`.

## Serve Mode

Launch the local browser flight recorder against a growing JSONL file:

```bash
agent-tail serve run.jsonl
```

Use `--open` to open the printed URL automatically, or choose a loopback port with `--port`.
The server follows regular files after reaching the current EOF and receives new standard-input events until stdin disconnects.

The server binds to `127.0.0.1` by default.
A non-loopback host requires `--remote-access`, prints a prominent warning, and generates a token-protected launch URL.
Remote access cannot be combined with `--unsafe-unredacted`.

Serve mode provides graph, tree, swimlane, sequence, playback, search, inspectors, warning history, and lazy sanitized payload details through the same ingestion and trace-index behavior as the terminal application.
The packaged browser UI has no runtime CDN dependency.

To run the browser E2E suite locally:

```bash
python -m pip install '.[test]'
python -m playwright install chromium firefox webkit
PYTHONPATH=src python -m unittest tests.test_e2e
```

The automated release matrix drives installed stable Chrome plus Playwright Firefox and WebKit.
Stable Safari must allow JavaScript from Apple Events or SafariDriver automation before its full installed-browser journey can be automated; without that local setting, release verification is limited to loading the dashboard in installed Safari and the passing WebKit journey.

## Read Events

Read a JSONL file:

```bash
agent-tail run.jsonl
```

Read newline-delimited events from standard input:

```bash
producer | agent-tail -
```

Each non-empty line is parsed independently, so malformed and duplicate lines are reported without discarding other valid events.
The process succeeds when at least one valid event was accepted.

## Event Envelope

Every event must be a JSON object containing these fields:

- `schema_version`: a supported `1.x` string.
- `event_id`: a unique string within the input.
- `trace_id`: the trace identifier.
- `span_id`: the span identifier.
- `emitter_id`: the process or stream that owns `sequence`.
- `sequence`: a non-negative integer.
- `timestamp`: an ISO 8601 timestamp with a timezone.
- `kind`: the event kind string.
- `actor`: an object with a string `id`.
- `operation`: an object with a string `status` and optional `name`.

`parent_span_id` is optional and links an event to a parent span in the same trace.
`relationships` is an optional array of event references with string `type` and `event_id` fields.
Relationship types are extensible, and referenced events may arrive later in a stream.
Run-detail responses project these references into an `evidence_map` with resolved event links and unresolved references.
Resolved links include source and target kinds and actors so clients can present the smallest relevant evidence chain without joining the event list themselves.
For repository changes, emit a `change.applied` event with a Git hunk locator under `attributes.change`:

```json
{
  "kind": "change.applied",
  "attributes": {
    "change": {
      "path": "src/auth/session.py",
      "old_start": 84,
      "old_count": 18,
      "new_start": 84,
      "new_count": 19,
      "symbol": "reject_expired_session"
    }
  }
}
```

The four range values are non-negative integers and `symbol` is optional.
Valid locators are exposed in event order under `evidence_map.changes`, together with the change event and actor IDs.
Unknown kinds, fields, and supported minor schema versions are retained so the canonical envelope can evolve.

Harnesses other than the v1 runtime need an adapter that emits this envelope.
Adapter-specific data belongs under namespaced `attributes`, not in new top-level fields or core parsing rules.

## Ordering And Warnings

Ordering prefers increasing `sequence` within one `emitter_id`, then causal parent links, wall-clock timestamps, and ingestion order.
Events without enough causal information are marked `uncertain` rather than presented as an exact distributed total order.
Clock skew and late arrivals therefore remain visible without overriding an emitter's sequence.

`LOOP`, `RETRY`, `STALL`, and `ORPHAN` findings are heuristics, not diagnoses.
Loop and retry detection compares canonical operation arguments and selected material-state attributes.
Stall detection checks open spans against `--stall-seconds`, which defaults to 30 seconds.
Orphan detection allows a short parent-arrival grace period.

## Payloads And Redaction

By default, common bearer tokens, credential-shaped values, sensitive keys, and several common token formats are redacted before accepted events enter the index.
This ruleset is deliberately limited and cannot guarantee that every secret or private value is detected.
Review every terminal view and exported report before sharing it.

Payloads larger than the preview limit are truncated on a UTF-8 boundary while recording their original byte count and SHA-256 digest.
Use `--full-payloads` to retain full accepted payloads in the in-memory inspector when the input is trusted.
Use `--unsafe-unredacted` only for trusted local data when accepted non-structural values must remain visible.

Structural identifiers remain protected in unsafe mode because they drive indexing and can appear throughout output.
Rejected-data diagnostics also remain redacted because malformed data never reaches the accepted-event safety boundary.
Neither option makes arbitrary untrusted input safe to disclose.

The index defaults to a 16 MiB memory budget controlled by `--max-bytes`.
When necessary it evicts payloads before event metadata and records an `EVICT` warning.

## Markdown Export

Export a deterministic Markdown report with actor states, ordered timelines, heuristic evidence, payload-retention status, and ingestion errors:

```bash
agent-tail run.jsonl --export report.md
```

Markdown is the only v1 export format.

## Keyboard Controls

The interactive terminal UI provides these controls:

- `j`: select the next event.
- `k`: select the previous event.
- `e`: toggle failed events only.
- `l`: toggle warning events only.
- `a`: set or clear an exact actor filter.
- `t`: set or clear an exact event-kind filter.
- `T`: set or clear an exact trace filter.
- `/`: set or clear a case-insensitive event search.
- `q`: quit.

## Exit Codes

- `0`: at least one valid event was accepted, even if other lines were rejected.
- `1`: input was read successfully but no valid events were accepted.
- `2`: command-line validation, input decoding, file access, configuration, or export failed.

## Deferred Scope

Version 1 defers sockets, public harness adapters, HTML and Mermaid exports, persistence, replay, hosting, fan-out warnings, per-tool policies, and custom keybindings.

Serve mode remains process-local and does not persist run history across restarts.
One actor ID represents one logical agent invocation, and primary parentage uses the first causal cross-actor relationship that introduces the actor.
Run titles fall back to sanitized trace IDs.
Dense graph and tree views use progressive reveal rather than automatic clustering.
The local API is versioned as `v1` but remains experimental for external consumers.
