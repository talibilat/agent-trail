# Local Run Comparison

AgentTrail compares two local canonical JSONL runs without a backend, browser, persisted history, repository checkout, network request, or model call.
Each file must retain exactly one trace after canonical line validation and sanitization.

## Command

Run the comparison with two file paths.

```bash
agent-tail compare RUN_A.jsonl RUN_B.jsonl
```

The command writes deterministic Markdown-compatible text to standard output and returns exit code `0` after a valid comparison.
It returns exit code `2` for unreadable input, invalid UTF-8, or an input that does not contain exactly one retained trace.
Malformed lines are isolated by the normal JSONL ingestion rules, so valid events in the same file remain available and malformed records appear under integrity differences.

## Compared Facts

Actor correspondence requires exact sanitized actor IDs, and parent topology uses the canonical causal actor projection.
Context reads compare validated normalized paths, line and symbol locators, digest availability and values, and repository snapshot availability and values.
Context searches compare trimmed queries, validated canonical match paths, and repository snapshot availability and values.
Tool operations reuse the LOOP and RETRY normalized signature, including volatile-argument removal and selected material-state fields, and also retain the canonical operation status.
Warnings compare exact warning codes and actor IDs.
Verification records compare validated commands, pass or fail outcomes, exit codes, test provenance, and command availability.
Usage compares event-local and total input tokens, output tokens, total tokens, and cost while preserving unavailable data separately from numeric zero.
Changes compare safe normalized repository paths and valid Git hunk locators.
Human corrections compare exact actors, `modified` or `reverted` actions, and the semantic target hunk.

Event IDs, span IDs, trace IDs, absolute timestamps, ingestion positions, and redacted payload previews are not semantic comparison fields.
Invalid context, hunk, verification, correction, and ingestion records remain integrity facts rather than being converted into valid semantic facts.

## Causal Divergence

Comparison preserves sequence within each emitter even when timestamps imply the opposite order.
Across emitters, only canonical parent-span causal ancestry establishes before and after.
Independent cross-emitter records remain unordered, so changing their file order or timestamps does not create a false sequential divergence.

The algorithm repeatedly consumes equal semantic records that are currently supported by each run's partial order.
When each run has one distinct supported next record, the report labels that boundary as the earliest supported divergence.
When either boundary contains concurrent or uncertain records, the report prints a stable sorted divergence frontier instead of choosing an event.

## Interpretation

The report includes run summaries, usage and cost totals, added and removed facts, integrity differences, and divergence evidence.
Comparison is not exact replay because AgentTrail does not reconstruct repository, dependency, environment, network, tool, or model state.
Comparison is not a quality judgment, causal explanation, fuzzy actor match, semantic code review, or score of either run.
