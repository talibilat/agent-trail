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
- `operation`: an object with a non-blank string `status` and optional `name`.

`parent_span_id` is optional and links an event to a parent span in the same trace.
`relationships` is an optional array of event references with string `type` and `event_id` fields.
Relationship types are extensible, and referenced events may arrive later in a stream.
Run-detail responses project these references into an `evidence_map` with resolved event links and unresolved references.
Identical relationships from the same source event are projected once in first-declaration order, while the raw event retains every producer-supplied relationship.
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

`path` is a non-blank string, the four range values are non-negative integers, each positive count has a positive start, and `symbol` is an optional non-blank string.
Valid locators are exposed in event order under `evidence_map.changes`, together with the change event and actor IDs.
Each change record groups the resolved and unresolved relationships originating from that change under its own `links` and `unresolved` arrays.
It also includes factual `coverage` for requirement, context, tool, verification, and decision evidence, plus an unresolved count for missing targets on those canonical evidence relationships, targets of the wrong event kind, missing compacted-context sources, and missing verification-start events.
Unresolved generic relationships remain inspectable but do not reduce factual evidence coverage.
A context category is present for direct context only when an `informed_by` relationship resolves to a `context.read` event with a validated locator; other links to context reads remain visible but do not identify what informed the applied hunk.
A context locator among a compaction's resolved `summarizes` sources also satisfies the category when the change references that compaction with `informed_by`; unrelated outer or source links and empty compactions do not.
A tool category is present only when a `preceded_by` relationship resolves to a tool call with a non-blank command or result; other links to tool calls remain visible, while operation identity and status alone do not satisfy it.
A verification category is present only when a `verified_by` relationship resolves to a finished verification with a non-blank command, either directly or through a resolved start event; other links to verifications remain visible, and a validated outcome or blank start event alone does not satisfy the category.
A requirement category is present only when a `motivated_by` relationship resolves to a `requirement.observed` event with validated requirement details; other links to requirements remain visible but do not identify the motivation behind the applied hunk.
A decision category is present only when an `applies` relationship resolves to a `change.proposed` event with a non-blank actor ID; other links and anonymous proposals remain visible but do not identify the decision-maker behind the applied hunk.
Coverage is `complete` only when all five core categories are present, every direct, compacted, or verification-lifecycle reference resolves, every verification is known to predate the change, and every verification passed.
Otherwise `missing` identifies absent categories, `unknown_test_origin_count` identifies verifications without valid provenance, `same_agent_test_count` identifies tests written by the implementing agent, and `failed_verification_count` identifies failed results, without assigning a subjective confidence score.
The run-level arrays remain available for all relationships, including those originating from events without valid change locators.
To identify a motivating requirement, emit a `requirement.observed` event with non-blank `attributes.requirement.id` and `attributes.requirement.text` strings, then reference it from the change event with a `motivated_by` relationship.
Resolved links to that event include the validated ID and text under `requirement`, while malformed or blank optional requirement metadata is omitted without hiding the relationship.
The browser event inspector presents the selected hunk path, new-file range, canonical old/new Git hunk header, optional symbol, and applying agent together with requirements linked by `motivated_by`; it does not attribute unrelated requirement links as motivations.
To distinguish the agent that made the change decision from the agent that applied it, reference a `change.proposed` event with a non-blank actor ID from `change.applied` using an `applies` relationship; the browser presents both actors separately on the selected hunk and does not attribute unrelated or anonymous proposals as decisions.
Each unresolved hunk relationship is identified by its relationship type and target event ID, followed by an aggregate unresolved-reference status.
Resolved `motivated_by`, `informed_by`, `preceded_by`, `verified_by`, and `applies` targets of the wrong event kind remain inspectable as generic links and are also identified as invalid evidence targets.
Valid `informed_by` targets are `context.read` and `context.compacted` events.
To identify repository or documentation evidence, emit a `context.read` event with a non-blank `attributes.context.path`, optional positive integer `line_start` and `line_end` fields where `line_end` is not before `line_start` when both are present, and an optional non-blank string `symbol`, then reference it from the change event with an `informed_by` relationship.
Resolved links to that event include the validated locator under `context`; malformed optional locator fields are omitted without hiding the relationship.
The browser event inspector presents each context path, line range, symbol, and reading actor linked by `informed_by` directly on the selected change hunk; it does not attribute unrelated context links as informing evidence.
To expose commands and tool results that preceded a change, reference the relevant `tool.call.*` events from the change event with a `preceded_by` relationship.
Other event kinds linked by `preceded_by` remain inspectable but are reported as invalid evidence targets and keep coverage incomplete.
Resolved links to tool calls include non-blank operation status and optional non-blank operation name under `tool`; blank values are omitted from evidence presentation.
Producers can add non-blank `attributes.tool.command` and `attributes.tool.result` strings and an optional integer `attributes.tool.exit_code`; malformed or blank optional fields are omitted without hiding the relationship or operation details.
The browser event inspector presents each tool operation, command, result, actor, status, and optional exit code linked by `preceded_by` directly on the selected change hunk; it does not attribute unrelated tool links as preceding evidence.
When context is summarized before a decision, emit a `context.compacted` event with `summarizes` relationships to its source `context.read` events, then reference the compaction event from the change with `informed_by`.
Resolved links to that event include `compaction.sources` with each distinct valid source event, its kind, actor, and context-read locator, plus `compaction.unresolved` for each distinct missing source event or source of the wrong event kind.
Wrong-kind `summarizes` targets remain inspectable as generic links, include their actual kind in the nested diagnostic, and keep coverage incomplete.
This preserves the observable compaction boundary without capturing private reasoning or summary contents.
The browser event inspector presents the actor for compactions linked by `informed_by`, plus repository locators with optional symbols, source actors, and missing or wrong-kind source diagnostics linked by `summarizes` directly on the selected change hunk; unrelated outer and source relationships are not attributed as compacted context.
To attach a test result, emit a `verification.finished` event with a boolean `attributes.verification.passed` field and optional integer `exit_code`, then reference it from the change event with a `verified_by` relationship.
For lifecycle attribution, emit the command as non-blank `attributes.verification.command` on a `verification.started` event and reference it from `verification.finished` with a `completes` relationship.
Finished-only events can instead include the command directly for producers that do not emit a separate start event.
Set optional `test_origin` to `pre_existing` when the test predates the change or `same_agent` when the change agent also wrote the test.
Resolved links to the finished event include the validated result under `verification`, including each distinct resolved start event and its actor, so each linked hunk exposes every known test command and outcome directly.
The browser falls back to the command reported by the finished event when resolved start events do not identify a command, while retaining their starter attribution.
An outcome-only finished event remains visible in the API and browser but leaves the verification coverage category missing because no test command is known.
Any failed result linked by `verified_by` contributes to `failed_verification_count` and keeps coverage incomplete even when another linked verification passed; failures linked by unrelated relationship types remain generic evidence and do not affect coverage.
Distinct missing start events and `completes` targets that are not `verification.started` events remain visible under `verification.unresolved` and contribute to incomplete hunk coverage; wrong-kind targets include their actual event kind so consumers can distinguish them from missing events.
The browser event inspector presents each test linked by `verified_by`, showing its starter and command separately from the result reporter, together with the pass or fail outcome, optional exit code, and whether the test predates the change, was written by the same agent, or has unknown provenance; it does not attribute unrelated verification links as tests of the hunk.
It identifies each missing verification start by relationship type and event ID rather than hiding lifecycle gaps behind the aggregate incomplete-coverage status.
Malformed optional verification metadata is omitted without rejecting the event, its relationship, or other valid verification details.
To record a later human change, emit a `human.corrected` event with a `corrects` relationship targeting the original `change.applied` event and set `attributes.correction.action` to `modified` or `reverted`.
Each affected hunk exposes these inbound links in event order under `corrections`, including the human actor and validated action when available.
The browser event inspector highlights each later human modification or reversion, together with the correcting actor, directly on the selected change hunk.
Wrong-kind `corrects` targets remain inspectable as generic links and are also reported as invalid targets in the run-level unresolved diagnostics.
When the correction event is selected, the browser presents the relationship type, target event ID, and actual target kind from that diagnostic without attributing it to a change hunk.
Other inbound relationship types remain available as generic evidence links but are not attributed as human corrections.
Malformed correction metadata is omitted without hiding the correction relationship.
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
