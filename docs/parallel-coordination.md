# Parallel Coordination Findings

AgentTrail reports factual coordination evidence without inferring semantic conflicts, duplicated intent, stale assumptions, task relevance, avoidable spend, or potential savings.

The five coordination findings use the same shared warning stream as LOOP, RETRY, STALL, ORPHAN, and verification-gap findings.

They therefore appear in terminal output, Markdown exports, HTML exports, export review, the browser warning drawer, graph badges, agent inspectors, and selected-event inspectors.

## Configuration

The positive `--fan-out-threshold` option configures `HIGH_FAN_OUT` for the terminal CLI and `agent-tail serve`.

The default threshold is `8`.

The threshold is observational and does not cancel agents, reject events, or enforce a scheduler policy.

```console
agent-tail run.jsonl --fan-out-threshold 12
agent-tail serve run.jsonl --fan-out-threshold 12
```

## Parent And Lifecycle Contract

Coordination analysis uses the existing primary direct-parent topology derived from the first causal cross-actor parent-span introduction.

A child lifecycle starts at that child actor's first canonical event.

A child or parent has a known terminal event when its latest canonical actor event with a terminal operation status establishes completion.

Same-emitter sequence establishes lifecycle order even when timestamps are equal or skewed.

Causal ancestry also establishes lifecycle order.

Strictly ordered timestamps can establish lifecycle interval boundaries across otherwise independent emitters for fan-out measurement.

Equal timestamps across independent emitters do not establish a lifecycle boundary order.

Children whose relevant start or end order is undetermined are listed as `concurrency_unknown_child_ids` and are not counted as concurrent.

`CHILD_AFTER_PARENT_END` is stricter and never uses wall-clock order across emitters.

It requires same-emitter sequence or a causal ancestry path from the parent terminal event to the child event.

## HIGH_FAN_OUT

`HIGH_FAN_OUT` is emitted when the known number of simultaneously open direct children is strictly greater than the configured threshold.

The finding cites the parent actor, threshold, concurrent child actors, unknown child actors, and lifecycle evidence events.

An open child without a terminal event remains open after its established start.

An undetermined interval is never guessed into the concurrent count.

## OVERLAPPING_CHANGE

`OVERLAPPING_CHANGE` requires two `change.applied` events from distinct actors with the exact same normalized repository-relative path.

Path normalization converts backslashes to slashes, removes safe dot segments, and rejects blank, absolute, and parent-traversal paths.

The finding requires no established causal order in either direction.

Wall-clock order alone does not establish causal order for this finding.

Equal paths do not imply a semantic conflict or overlapping line ranges.

Equal non-blank symbols are included as stronger evidence, while absent or different symbols do not imply symbol-level overlap.

## REDUNDANT_OPERATION

`REDUNDANT_OPERATION` applies only to canonical searches and validated finished verifications performed by distinct actors.

A search signature contains the trimmed non-blank query and the sorted unique normalized match paths.

A verification signature contains the validated effective command with surrounding whitespace removed.

Malformed commands, invalid verification outcomes, unresolved verification lifecycle references, malformed searches, and invalid match paths prevent a finding.

Both events must provide validated non-blank `attributes.repository.commit` values.

Both events must also provide validated lowercase SHA-256 `attributes.repository.worktree_sha256` values.

Both fingerprints must be identical between the events.

A missing or malformed fingerprint prevents a finding rather than producing a guessed repository match.

Different known snapshots prevent a finding even when operation signatures are identical.

## UNCONSUMED_CHILD_RESULT

A child result candidate is the known terminal event of a direct child actor when its operation status is completed or successful.

A parent consumes that result only when one of the direct parent actor's events declares `{"type":"consumes","event_id":"CHILD_RESULT_EVENT_ID"}`.

The relationship must target the exact child result event.

The consuming parent event must be causally established before the parent terminal event or be the parent terminal event itself.

The child result must be causally established before the parent terminal event before absence can produce `UNCONSUMED_CHILD_RESULT`.

An unresolved forward `consumes` target remains unknown and cannot produce an early unconsumed claim because no matching result candidate exists yet.

When the target arrives later, the complete history is reevaluated.

A late-arriving parent consumption event can resolve an active warning when its canonical sequence or causal ancestry places it before parent completion.

Warning history retains the resolved record and its resolution time.

## Usage And Cost

Every coordination finding includes `associated_usage` computed only from its cited canonical events.

Available input tokens, output tokens, total tokens, and cost are summed independently.

An unavailable field remains unavailable when none of the cited events supplies that event-local delta.

Associated usage is factual attribution and is not labeled as waste, savings, or avoidable spend.

## Producer Example

The following parent event explicitly consumes a child result.

```json
{
  "schema_version": "1.0",
  "event_id": "parent-accepts-worker-result",
  "trace_id": "trace-1",
  "span_id": "parent-span",
  "emitter_id": "orchestrator",
  "sequence": 8,
  "timestamp": "2026-07-18T12:00:08Z",
  "kind": "result.accepted",
  "actor": {"id": "orchestrator"},
  "operation": {"status": "running", "name": "integrate"},
  "relationships": [
    {"type": "consumes", "event_id": "worker-completed"}
  ]
}
```

Producers should emit repository snapshots on each canonical search or verification event that may participate in redundancy analysis.

Producers should preserve stable emitter IDs and monotonic per-emitter sequences so equal timestamps and clock skew do not erase known ordering.
