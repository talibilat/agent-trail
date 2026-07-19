# Agent Tail

Agent Tail is a local CLI, terminal UI, and browser flight recorder for debugging coding-agent and multi-agent runs without a backend.
It connects causal runtime events to repository context, changes, verification, warnings, security influence, usage, and observed outcomes.

## Quick Start

Agent Tail requires Python 3.11 or newer.

```bash
python -m pip install .
agent-tail serve examples/demo-run.jsonl --open --fan-out-threshold 2
```

For development without installation, replace `agent-tail` with `PYTHONPATH=src python -m agent_tail` in every command.
The comprehensive demo opens a local UI and does not make external network requests.

## Test Everything In The UI

Most product features can be tested from one browser session.
Imports and run comparison start as CLI commands, but every imported canonical JSONL file can then be opened in the same UI.

```bash
agent-tail serve examples/demo-run.jsonl --open --fan-out-threshold 2
```

Use the demo in this order:

1. Switch between **Graph**, **Tree**, **Swimlane**, and **Sequence** to inspect topology, parentage, timing, and handoffs.
2. Open **Warnings** to see loop, uncovered-change, stale-context, self-confirming-test, fan-out, overlapping-change, redundant-operation, unconsumed-result, child-after-parent, and untrusted-to-sensitive findings.
3. Select `implementer`, then select `change.applied`, to inspect the requirement, context, tool, proposal, test, human correction, stale hash, and attributed cost for one hunk.
4. Select `researcher` or either `searcher-*` agent to inspect repository snapshots, content hashes, queries, and matched paths in Context Provenance.
5. Select `security-worker`, then select `http_post`, to inspect the audit-only `web -> network_egress` influence path.
6. Select the run overview to inspect totals, actor and operation usage, hunk allocation, warning associations, and the observed `modified` outcome.
7. Search for `demo-change`, scrub playback backward, and use **Jump to live** to test investigation controls.

The demo payload contains a fake bearer value so the inspector can demonstrate redaction.
Do not use real credentials in examples or shared reports.

## Live Update Demo

Use a temporary copy so the tracked example remains unchanged.

```bash
cp examples/demo-run.jsonl /tmp/agent-tail-demo.jsonl
agent-tail serve /tmp/agent-tail-demo.jsonl --open --fan-out-threshold 2
```

Append a new event from another terminal while the browser is open.

```bash
cat examples/demo-live-event.jsonl >> /tmp/agent-tail-demo.jsonl
```

The request count, timeline, and outcome-cost totals update through SSE without refreshing the page.
If a reconnect cursor falls outside retained live history, the browser reloads the authoritative snapshot automatically.

## Demo Files

The Claude Code, Codex, and OpenCode session files are synthetic, independently authored fixtures that model the pinned formats documented by their import adapters.
They are not copied from user sessions or vendor repositories.

| File | Purpose |
| --- | --- |
| `examples/demo-run.jsonl` | Comprehensive UI demo covering evidence, provenance, warnings, security, coordination, payloads, and cost. |
| `examples/demo-live-event.jsonl` | One append-only event for testing live SSE updates and cost changes. |
| `examples/warning-policy.toml` | Raises the expected `poll_status` loop threshold and suppresses `flaky_api` retries. |
| `examples/otel-traces.json` | Minimal standard OTLP JSON trace for the OpenTelemetry importer. |
| `examples/claude-code-session.jsonl` | Minimal pinned Claude Code session export. |
| `examples/codex-session.jsonl` | Minimal pinned Codex CLI rollout export. |
| `examples/opencode-session.json` | Minimal pinned OpenCode session export. |
| `examples/langgraph-demo.py` | Small LangGraph run captured through `AgentTailCallbackHandler`. |
| `examples/compare-run-a.jsonl` | Successful-style comparison input with repository context and integration tests. |
| `examples/compare-run-b.jsonl` | Divergent comparison input with different context, tests, usage, and cost. |

## Feature Catalog

Each feature below has a two-line summary: what it does and how to run or inspect it.
Detailed contracts and security boundaries are linked from each entry.

### Browser Flight Recorder

Graph, tree, swimlane, and sequence views combine topology, causal uncertainty, playback, search, warning history, and event or agent inspectors.
Run `agent-tail serve examples/demo-run.jsonl --open --fan-out-threshold 2` and switch views from the top navigation.

### Causal Ordering And Uncertainty

Ordering prefers per-emitter sequence and explicit causal ancestry, then uses timestamps and ingestion order only as fallbacks while marking facts that cannot be totally ordered.
Run the comprehensive demo and compare Graph, Swimlane, and Sequence views to see concurrent branches without fabricated certainty.

### Fault-Tolerant Ingestion

Each JSONL line is validated independently, so malformed records and duplicate IDs become redacted findings without discarding valid sibling events.
Run `agent-tail INPUT.jsonl` or pipe a producer into `agent-tail -`, then inspect ingestion findings in the terminal, API, UI, or exports.

### Live Tailing And Bounded History

Serve mode follows growing files or standard input, streams typed SSE updates, and resets stale clients from authoritative snapshots without unbounded replay memory.
Run the [live update demo](#live-update-demo), and read [bounded live history](docs/bounded-live-history.md) for the reset contract.

### Change Evidence Map

Each valid Git hunk can show its requirement, repository context, decision agent, preceding tools, verification lifecycle, test origin, and later human correction.
Open `implementer -> change.applied` in the demo, and read the [event envelope](#canonical-event-envelope) for producer relationships.

### Verification Gap Detector

Deterministic warnings identify uncovered changes, failures before completion, stale context, and tests whose only passing evidence was produced by the same agent.
Open **Warnings** and the demo hunk, then read [verification gaps](docs/verification-gaps.md) for exact rules.

### Context Provenance

Actor timelines expose file hashes, repository commits, dirty-worktree fingerprints, searches, compaction boundaries, stale reads, and divergent snapshots without storing file contents.
Select `researcher` in the demo, then read [context provenance](docs/context-provenance.md) for path and hashing algorithms.

### Parallel-Agent Coordination

Findings cover excessive fan-out, same-path changes without causal order, exact redundant work, unconsumed child results, and child activity after parent completion.
Run the UI with `--fan-out-threshold 2`, open **Warnings**, and read [parallel coordination](docs/parallel-coordination.md).

### Taint Security Audit

Producer-declared trust labels propagate only through explicit `influenced_by` edges to sensitive capabilities, with incomplete instrumentation reported separately from no observed path.
Select `security-worker -> http_post` in the demo, then read [taint security](docs/taint-security.md).

### Outcome Cost Attribution

Event-local tokens and cost are conserved across attributed, pending, and unattributed buckets and can be linked explicitly to valid hunks and observed corrections.
Open the run overview and demo hunk, then read [outcome cost](docs/outcome-cost.md).

### Runtime Warnings

The warning engine detects loops, unchanged retries, stalls, missing parents, verification gaps, coordination problems, security paths, and memory eviction with factual evidence.
Open **Warnings** in the demo or run `agent-tail examples/demo-run.jsonl --fan-out-threshold 2` for a terminal snapshot.

### Per-Tool Warning Policies

A versioned TOML policy can tune or explicitly suppress `LOOP` and `RETRY` for exact canonical operation names while preserving suppression counts and evidence.
Run `agent-tail serve examples/demo-run.jsonl --open --fan-out-threshold 2 --warning-policy examples/warning-policy.toml` and read [warning policies](docs/warning-policies.md).

### Redaction And Payload Retention

Common secret shapes and sensitive keys are redacted before indexing, large payloads are truncated with byte counts and hashes, and the memory budget evicts payloads before metadata.
Inspect `demo-usage`, try `--full-payloads` only with trusted input, and never treat finite redaction rules as a sharing guarantee.

### Metadata-Only Mode

Payload bodies are omitted before indexing while deterministic original byte count, SHA-256, and omission state remain available throughout terminal, API, browser, and exports.
Run `agent-tail serve examples/demo-run.jsonl --open --metadata-only --fan-out-threshold 2` and read [metadata-only mode](docs/metadata-only.md).

### Markdown Export

The deterministic text report includes actor state, timelines, warnings, security audit, outcome-cost tables, payload state, and ingestion findings.
Run `agent-tail examples/demo-run.jsonl --fan-out-threshold 2 --export demo-report.md` and open `demo-report.md`.

### Self-Contained HTML Export

One sanitized offline HTML file embeds the interactive browser UI, all run projections, and a restrictive no-network Content Security Policy.
Run `agent-tail examples/demo-run.jsonl --fan-out-threshold 2 --export-html demo-report.html` and read [HTML export](docs/html-export.md).

### Pre-Export Review

A temporary loopback-only review session freezes the exact Markdown or HTML candidate, shows its disclosure inventory and digest, and writes only after one-shot approval.
Run `agent-tail examples/demo-run.jsonl --export-html /tmp/reviewed-demo.html --review --open` and read [export review](docs/export-review.md).

### OpenTelemetry Import

The dependency-free importer converts standard OTLP JSON resources, scopes, spans, and span events into deterministic canonical JSONL without receiving live OTLP traffic.
Run the command in [Import Demos](#import-demos), then read [OpenTelemetry import](docs/opentelemetry-import.md).

### Coding-Agent Session Imports

Isolated adapters conservatively convert fixture-pinned Claude Code, Codex, and OpenCode exports without scanning global directories or inventing missing evidence.
Run the commands in [Import Demos](#import-demos), then read [coding-agent imports](docs/coding-agent-imports.md).

### LangGraph Adapter

The optional callback handler captures synchronous or asynchronous graph, node, model, tool, failure, and explicit evidence activity as flushed canonical JSONL.
Run the command in [LangGraph Demo](#langgraph-demo), then read [LangGraph adapter](docs/langgraph-adapter.md).

### Local Run Comparison

Comparison reports added and removed semantic facts, usage changes, integrity differences, and the earliest supported divergence or stable concurrent frontier without exact replay claims.
Run `agent-tail compare examples/compare-run-a.jsonl examples/compare-run-b.jsonl` and read [run comparison](docs/run-comparison.md).

### 10,000-Event Performance Envelope

Release gates verify retained and default-budget ingestion, projection, serialization, memory, installed-browser startup, search, view switching, playback, and progressive reveal.
Run `PYTHONPATH=src python -m unittest tests.test_performance -v` and read [performance envelope](docs/performance-envelope.md).

### Terminal UI And Snapshots

TTY output provides an interactive lane view, while redirected output produces a deterministic plain snapshot suitable for scripts and CI artifacts.
Run `agent-tail examples/demo-run.jsonl` in a terminal or redirect it with `agent-tail examples/demo-run.jsonl > snapshot.txt`.

### Local API And SSE

The versioned local API exposes run lists, complete run projections, lazy payload detail, and cursor-based typed SSE updates used by the packaged browser.
Run `agent-tail serve examples/demo-run.jsonl`, then open `/api/v1/runs` or `/api/v1/events?cursor=0` on the printed loopback origin.

### Offline Assets And Guarded Remote Access

The browser ships without runtime CDN dependencies, binds to loopback by default, and requires an explicit tokenized mode before listening on a non-loopback host.
Run locally with `agent-tail serve examples/demo-run.jsonl`, or read [Security And Remote Access](#security-and-remote-access) before using `--remote-access`.

## Import Demos

Convert OTLP JSON and open the result in the UI.

```bash
agent-tail import otel examples/otel-traces.json --output /tmp/otel-demo.jsonl
agent-tail serve /tmp/otel-demo.jsonl --open
```

Convert each supported coding-agent session and open any result in the UI.

```bash
agent-tail import session examples/claude-code-session.jsonl --source auto --output /tmp/claude-demo.jsonl
agent-tail import session examples/codex-session.jsonl --source auto --output /tmp/codex-demo.jsonl
agent-tail import session examples/opencode-session.json --source auto --output /tmp/opencode-demo.jsonl
agent-tail serve /tmp/claude-demo.jsonl --open
```

Generated import artifacts can contain source prompts, commands, and other sensitive telemetry.
Protect imported JSONL like the original source file.

## LangGraph Demo

Install the optional adapter dependency, generate a trace, and open it in the UI.

```bash
python -m pip install '.[langgraph]'
python examples/langgraph-demo.py /tmp/langgraph-demo.jsonl
agent-tail serve /tmp/langgraph-demo.jsonl --open
```

The adapter never infers repository reads, changes, or verification from model text.
Use its explicit evidence helpers when the application can supply those facts.

## Export And Review Demos

Create deterministic Markdown and self-contained HTML reports.

```bash
agent-tail examples/demo-run.jsonl --fan-out-threshold 2 --export /tmp/agent-tail-demo.md
agent-tail examples/demo-run.jsonl --fan-out-threshold 2 --export-html /tmp/agent-tail-demo.html
```

Review the exact frozen HTML bytes before they replace the destination.

```bash
agent-tail examples/demo-run.jsonl --fan-out-threshold 2 --export-html /tmp/agent-tail-reviewed.html --review --open
```

The review command waits until **Approve export**, **Cancel**, timeout, or interruption.
Closing the review page cancels by default and leaves an existing destination unchanged.

## CLI Reference

```text
agent-tail INPUT [options]
agent-tail serve INPUT [options]
agent-tail compare RUN_A.jsonl RUN_B.jsonl
agent-tail import otel INPUT --output OUTPUT
agent-tail import session INPUT --source auto --output OUTPUT
```

Common inspection and export options are `--full-payloads`, `--metadata-only`, `--unsafe-unredacted`, `--loop-threshold`, `--fan-out-threshold`, `--warning-policy`, `--stall-seconds`, and `--max-bytes`.
Serve-only options are `--host`, `--port`, `--open`, `--remote-access`, and `--max-live-updates`.

Run command-specific help for the complete current options.

```bash
agent-tail --help
agent-tail serve --help
agent-tail compare --help
agent-tail import otel --help
agent-tail import session --help
```

## Canonical Event Envelope

Every JSONL line is one object with `schema_version`, `event_id`, `trace_id`, `span_id`, `emitter_id`, `sequence`, zoned `timestamp`, `kind`, `actor.id`, and `operation.status`.
Optional `parent_span_id` and extensible `{type, event_id}` relationships provide causal and evidence links, while adapter-specific data belongs under namespaced `attributes`.

```json
{
  "schema_version": "1.0",
  "event_id": "change-1",
  "trace_id": "trace-1",
  "span_id": "change-span",
  "emitter_id": "worker-1",
  "sequence": 7,
  "timestamp": "2026-07-18T12:00:07Z",
  "kind": "change.applied",
  "actor": {"id": "implementer"},
  "operation": {"status": "completed", "name": "edit"},
  "attributes": {
    "change": {
      "path": "src/auth/session.py",
      "old_start": 84,
      "old_count": 18,
      "new_start": 84,
      "new_count": 19
    }
  },
  "relationships": [
    {"type": "informed_by", "event_id": "context-1"},
    {"type": "verified_by", "event_id": "verification-1"}
  ]
}
```

Unknown supported-minor fields and relationship types are retained, unresolved references can resolve after later events arrive, and uncertain distributed order is shown rather than fabricated.
Use the feature documents in `docs/` for exact validation, hashing, chronology, warning, security, and attribution contracts.

## Local API

Serve mode exposes `GET /api/v1/runs`, `GET /api/v1/runs/{trace_id}`, lazy payload detail, and `GET /api/v1/events?cursor=N` for typed SSE updates.
The API is process-local, versioned as `v1`, and experimental for external consumers.

## Security And Remote Access

The server binds to `127.0.0.1` by default and the packaged browser has no runtime CDN dependency.
Non-loopback binding requires `--remote-access`, prints a warning, and generates a token-protected URL; remote access cannot be combined with `--unsafe-unredacted`.

Sanitization cannot guarantee removal of every secret, source fragment, customer value, path, command, or prompt.
Review every UI, Markdown report, and HTML artifact before sharing it.

## Run The Tests

Install browser-test dependencies and browser engines once.

```bash
python -m pip install '.[test]'
python -m playwright install chromium firefox webkit
```

Run the complete suite, the browser suite, or the 10,000-event release gates.

```bash
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python -m unittest tests.test_e2e
PYTHONPATH=src python -m unittest tests.test_performance -v
```

## Terminal Keys

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

- `0`: at least one valid event was accepted or a requested operation succeeded.
- `1`: input was read successfully but no valid event was accepted.
- `2`: command validation, configuration, input, export, review, or comparison failed.

## Current Boundaries

Agent Tail does not provide hosted storage, exact replay, a general policy-enforcement engine, semantic code review, fuzzy run matching, or automatic repository inspection.
Serve mode remains process-local, run history is not persisted across restarts, and one actor ID represents one logical invocation.

## License

Agent Tail is licensed under the [MIT License](LICENSE).
