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
A `change.applied` event with missing or non-object `attributes.change` cannot identify a Git hunk, so it is excluded from `evidence_map.changes` but remains traceable under `evidence_map.invalid_changes` with its event ID, actor ID, and an `invalid_change_detail` integrity diagnostic.
A change event with a malformed or blank required path cannot identify a Git hunk, so it is excluded from `evidence_map.changes` but remains traceable under `evidence_map.invalid_changes` with its event ID, actor ID, and an `invalid_change_path` integrity diagnostic.
A malformed, negative, or impossible zero-valued `old_start` is excluded in the same way with an `invalid_change_old_start` diagnostic; zero remains valid when `old_count` is zero.
A malformed or negative `old_count` is excluded in the same way with an `invalid_change_old_count` diagnostic; zero remains valid for an empty old range.
A malformed, negative, or impossible zero-valued `new_start` is excluded in the same way with an `invalid_change_new_start` diagnostic; zero remains valid when `new_count` is zero.
A malformed or negative `new_count` is excluded in the same way with an `invalid_change_new_count` diagnostic; zero remains valid for an empty new range.
A supplied malformed or blank symbol is omitted while the valid hunk remains visible, produces an `invalid_change_symbol` integrity diagnostic, and keeps coverage incomplete; an absent symbol remains valid optional metadata.
Valid locators are exposed in event order under `evidence_map.changes`, together with the change event and actor IDs.
Each change record groups the resolved and unresolved relationships originating from that change under its own `links` and `unresolved` arrays.
It also includes factual `coverage` for requirement, context, tool, verification, and decision evidence, plus an unresolved count for missing targets on those canonical evidence relationships, targets of the wrong event kind, missing compacted-context sources, and missing verification-start events.
Unresolved generic relationships remain inspectable but do not reduce factual evidence coverage.
A context category is present for direct context only when an `informed_by` relationship resolves to a `context.read` event with a validated locator; other links to context reads remain visible but do not identify what informed the applied hunk.
A direct `informed_by` context read ordered after its change remains inspectable but is reported as read after the change and keeps coverage incomplete.
A direct `informed_by` context read ordered after the earliest attributable `change.proposed` decision remains inspectable but is reported as read after that decision and keeps coverage incomplete.
For a direct context read and either boundary event from the same emitter, sequence establishes their order despite equal or skewed timestamps; otherwise timestamps establish order and equal timestamps remain non-contradictory.
Canonical context-read events without a valid non-blank path remain inspectable as generic links but are reported as invalid context details and keep coverage incomplete.
A supplied `line_start` that is not a positive integer is omitted, reported as an invalid context line start, and keeps coverage incomplete while the valid path remains visible.
A supplied `line_end` that is not a positive integer or precedes a valid `line_start` is omitted, reported as an invalid context line end, and keeps coverage incomplete while the rest of the valid locator remains visible.
A supplied `symbol` that is not a non-blank string is omitted, reported as an invalid context symbol, and keeps coverage incomplete while the rest of the valid locator remains visible.
A context locator among a compaction's resolved `summarizes` sources also satisfies the category when the change references that compaction with `informed_by`; unrelated outer or source links do not.
A summarized `context.read` timestamped after its `context.compacted` event remains inspectable but is reported as read after the compaction and keeps coverage incomplete; equal timestamps remain valid because they do not establish contradictory ordering.
An `informed_by` compaction ordered after its change remains inspectable but is reported as compacted after the change and keeps coverage incomplete; ordering uses sequence for events from the same emitter and timestamps across emitters, where equal timestamps do not establish contradictory ordering.
An `informed_by` compaction ordered after the earliest attributable `change.proposed` decision remains inspectable but is reported as compacted after that decision and keeps coverage incomplete.
For a compaction and decision from the same emitter, sequence establishes their order despite equal or skewed timestamps; otherwise equal timestamps remain valid because they do not establish contradictory ordering.
An `informed_by` compaction without any `summarizes` relationship remains visible but is reported as invalid compaction details and keeps coverage incomplete even when other context evidence satisfies the category.
A tool category is present only when a `preceded_by` relationship resolves to a tool call with a non-blank command or result; other links to tool calls remain visible, while operation identity and status alone do not satisfy it.
Canonical tool-call events without a valid non-blank command or result remain inspectable as generic links but are reported as invalid tool details and keep coverage incomplete.
A `preceded_by` tool event ordered after the earliest attributable `change.proposed` decision or its applied change remains inspectable but produces a temporal diagnostic and keeps coverage incomplete.
For a tool and either boundary event from the same emitter, sequence establishes their order despite equal or skewed timestamps; otherwise timestamps establish order and equal timestamps remain non-contradictory.
A verification category is present only when a `verified_by` relationship resolves to a finished verification with a non-blank command, either directly or through a resolved start event; other links to verifications remain visible, and a validated outcome or blank start event alone does not satisfy the category.
A requirement category is present only when a `motivated_by` relationship resolves to a `requirement.observed` event with validated requirement details; other links to requirements remain visible but do not identify the motivation behind the applied hunk.
A `motivated_by` requirement ordered after the earliest attributable `change.proposed` decision or its applied change remains inspectable but produces a temporal diagnostic and keeps coverage incomplete.
For a requirement and either boundary event from the same emitter, sequence establishes their order despite equal or skewed timestamps; otherwise timestamps establish order and equal timestamps remain non-contradictory.
A decision category is present only when an `applies` relationship resolves to a `change.proposed` event with a non-blank actor ID; other links remain visible, while anonymous canonical proposals are reported as invalid decision actors and keep coverage incomplete.
An `applies` proposal ordered after its change remains inspectable but is reported as proposed after the applied change and keeps coverage incomplete; sequence establishes proposal/application order for events from the same emitter despite equal or skewed timestamps, while timestamps establish order across emitters and equal timestamps remain non-contradictory.
Coverage is `complete` only when all five core categories are present, every direct, compacted, or verification-lifecycle reference resolves to valid evidence, every canonical verification identifies a test command, every verification is known to predate the change, and every verification passed.
Otherwise `missing` identifies absent categories, `integrity_issue_count` identifies malformed hunk metadata, `unknown_test_origin_count` identifies verifications without valid provenance, `same_agent_test_count` identifies tests written by the implementing agent, and `failed_verification_count` identifies failed results, without assigning a subjective confidence score.
The run-level arrays remain available for all relationships, including those originating from events without valid change locators.
To identify a motivating requirement, emit a `requirement.observed` event with non-blank `attributes.requirement.id` and `attributes.requirement.text` strings, then reference it from the change event with a `motivated_by` relationship.
Resolved links to that event include the validated ID and text under `requirement`.
Canonical requirement events with malformed or blank details remain inspectable as generic links but are reported as invalid requirement details and keep coverage incomplete.
The browser event inspector presents the selected hunk's `change.applied` event ID, path, new-file range, canonical old/new Git hunk header, optional symbol, hunk-integrity diagnostics, and applying agent together with the event ID, requirement ID, text, and observing actor for requirements linked by `motivated_by`; a zero-count new-file range is explicitly shown as `path:start (0 lines)` rather than as a one-line range, blank applying and observing actors are identified as unknown, requirements observed after the decision or change are warned about, and unrelated requirement links are not attributed as motivations.
When a selected `change.applied` event has invalid required change metadata and therefore no truthful hunk locator, the browser presents its event ID, applying actor, and typed change-integrity diagnostics without fabricating a Change Evidence hunk.
To distinguish the agent that made the change decision from the agent that applied it, reference a `change.proposed` event with a non-blank actor ID from `change.applied` using an `applies` relationship; the browser presents the proposal event ID and both actors separately on the selected hunk, identifies a blank proposing actor as unknown and invalid decision evidence, warns when the proposal follows its application, and does not attribute unrelated proposals as decisions.
Each unresolved hunk relationship is identified by its relationship type and target event ID, followed by an aggregate unresolved-reference status.
Missing canonical relationships are labeled as evidence targets, while missing generic relationships are labeled neutrally and do not imply that they affect evidence completeness.
Resolved `motivated_by`, `informed_by`, `preceded_by`, `verified_by`, and `applies` targets of the wrong event kind remain inspectable as generic links and are also identified as invalid evidence targets with their actual event kind.
Valid `informed_by` targets are `context.read` and `context.compacted` events.
To identify repository or documentation evidence, emit a `context.read` event with a non-blank `attributes.context.path`, optional positive integer `line_start` and `line_end` fields where `line_end` is not before `line_start` when both are present, and an optional non-blank string `symbol`, then reference it from the change event with an `informed_by` relationship.
Resolved links to that event include the validated locator under `context`; malformed optional locator fields are omitted without hiding the relationship and are reported as typed integrity diagnostics for canonical direct or compacted context evidence.
The browser event inspector presents each context event ID, path, line range, symbol, and reading actor linked by `informed_by` directly on the selected change hunk; a blank reading actor is identified as unknown, an end-only range is displayed as `path:?-end`, context read after the hunk is warned about, and unrelated context links are not attributed as informing evidence.
To expose commands and tool results that preceded a change, reference the relevant `tool.call.*` events from the change event with a `preceded_by` relationship.
Other event kinds linked by `preceded_by` remain inspectable but are reported as invalid evidence targets and keep coverage incomplete.
Resolved links to tool calls include non-blank operation status and optional non-blank operation name under `tool`; a blank supplied status or malformed or blank supplied name is omitted, reported as invalid operation metadata, and keeps coverage incomplete.
Producers can add non-blank `attributes.tool.command` and `attributes.tool.result` strings and an optional integer `attributes.tool.exit_code`; malformed or blank optional fields are omitted without hiding the relationship or operation details.
A supplied command or result that is malformed or blank is reported as invalid tool command or result evidence and keeps coverage incomplete, while either field may be absent when the other contains substantive provenance.
A supplied tool exit code that is not an integer is reported as invalid tool execution evidence and keeps coverage incomplete, while an absent exit code remains valid optional metadata.
The browser event inspector presents each tool event ID, operation, command, result, actor, status, and optional exit code linked by `preceded_by` directly on the selected change hunk; a blank running actor is identified as unknown, tools occurring after the decision or change are warned about, and unrelated tool links are not attributed as preceding evidence.
When context is summarized before a decision, emit a `context.compacted` event with at least one `summarizes` relationship to a source `context.read` event, then reference the compaction event from the change with `informed_by`.
Resolved links to that event include `compaction.sources` with each distinct valid source event, its kind, actor, and context-read locator, plus `compaction.unresolved` for each distinct missing source event or source of the wrong event kind.
Canonical summarized context reads without a valid non-blank path remain inspectable through their events but are reported as invalid compacted source details and keep coverage incomplete even when another valid source exists.
A summarized context read with an invalid supplied `line_start` retains its valid path in the compaction source list while producing the same typed line-start diagnostic.
Wrong-kind `summarizes` targets remain inspectable as generic links, include their actual kind in the nested diagnostic, and keep coverage incomplete.
This preserves the observable compaction boundary without capturing private reasoning or summary contents.
The browser event inspector presents the event ID and actor for compactions linked by `informed_by`, or labels the compacting actor unknown when its ID is blank, plus repository locators with optional symbols, source event IDs and actors, and missing, wrong-kind, or late-source diagnostics linked by `summarizes` directly on the selected change hunk; a blank source actor is also identified as unknown, compaction after the decision or hunk is warned about, and unrelated outer and source relationships are not attributed as compacted context.
To attach a test result, emit a `verification.finished` event with a boolean `attributes.verification.passed` field and optional integer `exit_code`, then reference it from the change event with a `verified_by` relationship.
Finished verifications timestamped before the applied change remain visible but are reported as temporal contradictions and keep coverage incomplete; equal timestamps remain valid because they do not establish contradictory ordering.
Canonical finished verifications without a boolean result remain inspectable as generic links but are reported as invalid verification results and keep coverage incomplete.
When `exit_code` is supplied, zero must correspond to `passed: true` and a nonzero value to `passed: false`; conflicting values remain visible but produce a diagnostic and keep coverage incomplete.
A supplied exit code that is not an integer is omitted from the projected result, produces an invalid-exit-code diagnostic, and keeps coverage incomplete.
For lifecycle attribution, emit the command as non-blank `attributes.verification.command` on a `verification.started` event and reference it from `verification.finished` with a `completes` relationship.
Finished-only events can instead include the command directly for producers that do not emit a separate start event.
A supplied finished-event command that is malformed or blank is omitted and reported as invalid verification command evidence even when a valid start supplies the effective command, while an absent finished-event command remains valid for lifecycle-based producers.
Set optional `test_origin` to `pre_existing` when the test predates the change or `same_agent` when the change agent also wrote the test.
A supplied `test_origin` outside those values is omitted, reported as invalid verification test provenance, and keeps coverage incomplete; an absent value remains unknown provenance without being treated as malformed.
Resolved links to the finished event include the validated result under `verification`, including each distinct resolved start event and its actor, so each linked hunk exposes every known test command and outcome directly.
Resolved start events without a non-blank command remain available for actor attribution but are reported as invalid start commands and keep coverage incomplete even when another lifecycle event supplies a valid command.
Resolved start events timestamped after their finished event remain visible but are reported as verification lifecycle contradictions and keep coverage incomplete; equal timestamps remain valid because they do not establish contradictory ordering.
Resolved start events timestamped before the applied change also remain visible but are reported as temporal contradictions because the test lifecycle straddles the change; a start timestamp equal to the change remains valid.
When a resolved start command conflicts with the command on the finished event or another resolved start, both commands remain visible and a conflicting-command lifecycle diagnostic keeps coverage incomplete.
The browser falls back to the command reported by the finished event when resolved start events do not identify a command, while retaining their starter attribution.
An outcome-only finished event remains visible in the API and browser but leaves the verification coverage category missing because no test command is known.
It is also reported as an invalid verification command and keeps coverage incomplete even when another canonical verification supplies the category; a missing or wrong-kind start retains its more specific lifecycle diagnostic until it resolves.
Any failed result linked by `verified_by` contributes to `failed_verification_count` and keeps coverage incomplete even when another linked verification passed; failures linked by unrelated relationship types remain generic evidence and do not affect coverage.
Distinct missing start events, resolved starts without valid commands, and `completes` targets that are not `verification.started` events remain visible under `verification.unresolved` and contribute to incomplete hunk coverage; wrong-kind targets include their actual event kind so consumers can distinguish them from missing events.
The browser event inspector presents each test linked by `verified_by`, showing its finished event ID, each resolved start event ID and its starter and command separately from the result reporter, together with the pass or fail outcome, optional exit code, and whether the test predates the change, was written by the same agent, or has unknown provenance; a blank starter or reporter ID is identified as an unknown actor, and unrelated verification links are not attributed as tests of the hunk.
It identifies each missing verification start by relationship type and event ID rather than hiding lifecycle gaps behind the aggregate incomplete-coverage status.
Other malformed optional verification metadata is omitted without rejecting the event, its relationship, or other valid verification details.
To record a later human change, emit a `human.corrected` event with a `corrects` relationship targeting the original `change.applied` event and set `attributes.correction.action` to `modified` or `reverted`.
Each affected hunk exposes these inbound links in event order under `corrections`, including the human actor and validated action when available.
Corrections timestamped before their target change remain attributed and inspectable but are reported as temporal contradictions; equal timestamps remain valid because they do not establish contradictory ordering.
Canonical corrections without a `modified` or `reverted` action remain visible but are reported as invalid correction details instead of being attributed to either outcome.
The browser event inspector highlights each later human modification or reversion directly on the selected change hunk, showing the correction event ID and naming a non-blank correcting actor or reporting that the correcting actor is unknown.
Wrong-kind `corrects` targets remain inspectable as generic links and are also reported as invalid targets in the run-level unresolved diagnostics.
When the correction event is selected, the browser presents the relationship type, target event ID, and actual target kind from that diagnostic without attributing it to a change hunk.
Other inbound relationship types remain available as generic evidence links but are not attributed as human corrections.
Malformed correction metadata is omitted without hiding the correction relationship or its typed diagnostic.
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
