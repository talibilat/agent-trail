# Pre-Export Review

AgentTrail can hold a complete Markdown or self-contained HTML export in memory while you inspect its sanitized data before any destination is changed.
The review uses the packaged browser shell, run and event inspectors, warnings, search, payload presentation, and Change Evidence Map projections used by the HTML export and local browser UI.

## Start A Review

Review a Markdown candidate with this command.

```bash
agent-tail run.jsonl --export report.md --review
```

Review a self-contained HTML candidate with this command.

```bash
agent-tail run.jsonl --export-html report.html --review
```

Add `--open` to open the printed local URL in the default browser.
Use `--review-timeout SECONDS` to change the default ten-minute session lifetime.
The `--review` option is invalid without `--export` or `--export-html`, and `--open` is valid only for a review.

## Frozen Candidate

AgentTrail reads the file or standard input once, sanitizes accepted events once, builds one index, and serializes one candidate before starting the review server.
The terminal and review banner show the candidate byte count and SHA-256 digest.
Approval atomically writes those exact frozen bytes without rereading the input, rebuilding the index, or serializing the report again.
The destination remains untouched while review is pending and after cancellation, expiration, interruption, server failure, serialization failure, or write failure.

An approved and successfully written review exits with status `0`.
Cancellation, expiration, interruption, review-server failure, and write failure exit with status `2`.

## Inclusion Inventory

The persistent review banner identifies the target format and path, candidate digest and byte count, event and actor counts, warning and ingestion-error counts, retained attribute paths, payload-state counts, original payload bytes, redaction ruleset, and metadata-only state.
Search and the existing inspectors remain available for reviewing retained paths, commands, test results, requirements, corrections, warnings, ingestion diagnostics, relationships, and payload data that survived the selected policy.
The review is frozen and does not follow a growing source.

With `--metadata-only`, the inventory labels payload bodies as omitted and the inspectors expose only omission state, original byte count, digest, and ruleset metadata.
No review endpoint retains or recovers an omitted payload body.

## Approval And Cancellation

Select `Approve export` only after reviewing the candidate and inclusion inventory.
Select `Cancel` to stop without changing the destination.
Closing the review page requests cancellation, and cancellation remains the default if the page closes without delivering that request, the session expires, or the process is interrupted.

## Local Security Boundary

The temporary server binds to an ephemeral port on `127.0.0.1` only and cannot use serve mode's remote-access configuration.
Every response is marked `Cache-Control: no-store`.
The printed URL contains a generated token, and missing or incorrect tokens cannot read review data or submit a decision.
The first approval or cancellation consumes the review token, so later requests and repeated decisions are rejected.
The server stops after the decision or timeout and does not provide a general mutation API.

Sanitization is intentionally limited and cannot guarantee removal of every secret, personal detail, or proprietary value.
Review mode proves which frozen bytes were approved, but it does not certify that those bytes are safe to publish.
