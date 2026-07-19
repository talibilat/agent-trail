# Deterministic Verification Gaps

AgentTrail reports four deterministic verification-gap warnings from canonical retained events without assigning confidence, inferring semantic test relevance, or deciding whether a patch should be accepted.
The warnings use the same Change Evidence Map, context provenance, operation normalization, material-state, and causal-ordering contracts as the rest of the application.

## Warning Rules

`UNCOVERED_CHANGE` identifies a valid `change.applied` hunk for which no linked canonical `verification.finished` event resolves a non-blank command from itself or a valid linked `verification.started` event.
Missing targets, wrong-kind targets, outcome-only events, malformed commands, and unresolved lifecycle references remain available through evidence integrity diagnostics.
A later valid target removes the active warning while warning history retains the resolved observation.

`SELF_CONFIRMING_TEST` identifies a valid hunk when at least one valid passing verification exists and every passing verification has validated `test_origin: "same_agent"` provenance.
Command coverage is independent, so an outcome-only same-agent pass can produce both `SELF_CONFIRMING_TEST` and `UNCOVERED_CHANGE`.
One valid passing verification with `test_origin: "pre_existing"` prevents this warning.
Unknown or malformed provenance does not establish a self-confirming claim.
The warning reports a factual provenance condition and does not claim that the implementation or test is incorrect.

`STALE_CONTEXT` identifies an informing context read whose safe normalized repository path exactly matches the changed path and whose validated `content_sha256` differs from the change's validated `preimage_sha256`.
Direct `informed_by` reads and valid reads explicitly summarized by an informed compaction can participate in this rule.
Each change produces at most one `STALE_CONTEXT` warning, with all stale reads listed once in stable event order beside their validated content hashes and the change's single validated path and preimage hash.
Unlinked reads do not participate even when they were emitted by the change actor.
Missing, malformed, or unsafe paths and hashes remain context provenance diagnostics and do not establish staleness.

`FAILED_BEFORE_COMPLETION` identifies a failed tool call or valid failed verification that is known by same-emitter sequence or a causal path to precede `trace.completed` and has no equivalent successful terminal operation known to occur between them.
Operation equivalence uses the existing canonical operation signature after declared volatile arguments are removed and the existing selected material-state fingerprint.
Timestamp order alone never establishes this warning across emitters, including equal timestamps and apparently later completion timestamps.
Same-emitter sequence remains authoritative when timestamps are equal or clock-skewed.
Malformed verification outcomes do not establish failure claims.

## Evidence And Ordering

Each warning uses the affected event ID as its stable warning identity and serializes evidence as canonical sorted compact JSON.
Hunk warnings include `change_event_id`, all decisive event IDs, the validated hunk locator, and the exact validated values used by the rule.
Failure warnings include the failed event, completion event, normalized operation signature, and material-state fingerprint.
Warning order follows retained trace order and fixed rule order, so an unchanged retained event set produces unchanged warning order and evidence.
Duplicate canonical relationships are projected once and therefore cannot duplicate a warning.

## Live History And Presentation

Serve mode records the first detection time for each warning and retains it with `active: false` and `resolved_at` when late evidence resolves the condition.
Run detail exposes active and resolved records through the existing run-level warning array, and the browser associates hunk warnings with the corresponding Change Evidence Map entry by the affected event ID.
The browser warning drawer shows the warning code, actor, factual reason, deterministic evidence, and resolution state, and selecting a hunk warning navigates to its `change.applied` event.
The Change Evidence inspector shows the same warning and evidence directly beside the affected hunk.
Terminal snapshots and Markdown reports print the warning code, affected event, factual reason, and deterministic evidence.
Self-contained HTML exports and pre-export review use the same frozen run-detail projection and browser presentation.

## Producer Guidance

Producers should link each changed hunk to every canonical verification result with `verified_by` and should preserve the verification lifecycle when the command is emitted at start time.
Producers should set `test_origin` only when they know whether a passing test predates the change or was authored by the implementing agent.
Producers should record complete-file SHA-256 values according to the context provenance byte contract when they want stale-context diagnostics.
Producers should use stable operation names, canonical arguments, and declared volatile argument keys so equivalent recovery can be recognized deterministically.
Per-tool warning policy continues to apply only to `LOOP` and `RETRY` and does not suppress or tune these verification-gap warnings.
