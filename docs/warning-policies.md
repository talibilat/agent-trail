# Warning Policies

AgentTrail accepts an optional local warning policy through the explicit `--warning-policy PATH` option on standard, export, review, and serve commands.
AgentTrail never searches the repository, current directory, or home directory for a policy.
Serve mode loads the policy once at startup, and policy changes require a server restart.

## Version 1 Schema

The document must be TOML with an integer `version` equal to `1` and an optional array of `tools` tables.
Each tool table requires an exact, non-blank string `name` and at least one configured behavior.
The optional `loop_threshold` is an integer of at least `2`.
The optional `retry_threshold` is an integer of at least `3`, because retry backoff analysis requires two delays.
The optional `suppress` value is an array containing unique `LOOP` or `RETRY` strings.
Unknown versions, top-level keys, tool keys, warning codes, duplicate tool names, duplicate suppression codes, and malformed values are rejected.
The complete policy is validated before AgentTrail opens an event input, consumes standard input, starts a serve reader, or replaces an export destination.

```toml
version = 1

[[tools]]
name = "poll_status"
loop_threshold = 8

[[tools]]
name = "read_expected"
loop_threshold = 12
retry_threshold = 5

[[tools]]
name = "flaky_api"
suppress = ["RETRY"]
```

The `poll_status` rule allows eight equivalent polling calls before a `LOOP` finding is produced.
The `read_expected` rule permits expected repeated reads and raises the unchanged-failure retry threshold without affecting other operations.
The `flaky_api` rule suppresses only `RETRY`, so `LOOP` and every warning for other tools retain their normal behavior.

## Matching And Results

Rules match the canonical event `operation.name` exactly after native ingestion or import adaptation.
Matching is case-sensitive and does not use prefixes, suffixes, actor IDs, repository paths, payload text, or blank operation names.
Events without a matching rule use the command's existing defaults.

Suppression is recorded after detector evidence is produced rather than deleting events or evidence before analysis.
Terminal snapshots, Markdown reports, self-contained HTML exports, export-review inventory, and serve run details expose the loaded path, version, effective thresholds, suppression list, restart requirement, and suppressed counts.
The browser warnings drawer displays the same run-specific policy result while unrelated active warnings retain their original evidence and remain inspectable.

```bash
agent-tail run.jsonl --warning-policy warning-policy.toml
agent-tail run.jsonl --warning-policy warning-policy.toml --export report.md
agent-tail serve run.jsonl --warning-policy warning-policy.toml
```

Policy parse diagnostics do not quote source lines or unrelated file contents, and credential-shaped diagnostic values are redacted.
