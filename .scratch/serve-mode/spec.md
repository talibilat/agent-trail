# Implement AgentTrail Serve Mode With A Live Orchestration Web UI

Status: ready-for-agent

## Problem Statement

AgentTrail currently helps a developer inspect canonical multi-agent runtime events through a local CLI and terminal UI.
That terminal experience is useful for fast local debugging, but it does not provide the richer visual system view shown in the supplied orchestration mock.
A developer running many agents concurrently needs to see the live shape of a run, the causal agent graph, the active and completed agents, cross-agent handoffs, token and cost movement, warnings, and event details without rebuilding the story from interleaved logs.
The current package is explicitly local-first and has no HTTP server, API, browser UI, or persistence beyond one in-memory trace index per process.
The user wants the visual design to become part of the same AgentTrail tool instead of remaining a mockup or becoming a separate hosted product.
The result should preserve the existing CLI and TUI behavior for terminal users while adding an opt-in serve mode for users who want the visual flight-recorder experience.

## Solution

Add an integrated `serve` mode to AgentTrail.
The serve mode reads the same canonical JSONL event envelope that the CLI already accepts, sanitizes and indexes those events through the existing ingestion pipeline, and exposes a local browser UI backed by real data.
The browser UI ports the supplied orchestration design into maintainable frontend code and keeps the same product shape: top bar, run picker, search, warnings button, metrics strip, graph view, tree view, swimlane view, sequence view, inspector panel, warnings drawer, and scrub or playback transport.
The backend projects the current trace index into a run-view JSON shape that the frontend can render directly while leaving visual layout geometry to the client.
The server also provides a streaming channel so newly appended JSONL events update the browser without manual refresh.
Completed and failed runs remain scrub-friendly historical traces, while active runs can be followed live.
Serve mode is local-first by default, binds to loopback by default, uses sanitized data, and does not introduce a database, account, hosted service, or separate package.

## User Stories

1. As a local agent developer, I want to run one command that opens a web view for a JSONL trace, so that I can inspect agent orchestration without setting up a hosted observability product.
2. As a terminal-first AgentTrail user, I want the existing default CLI and TUI behavior to remain unchanged, so that the new visual UI does not break my current workflow.
3. As a developer debugging a live agent run, I want the web UI to update as new JSONL lines are appended, so that I can watch the system progress in real time.
4. As a developer reading a completed trace, I want scrub and playback controls, so that I can move through the run at the moment where the interesting behavior happened.
5. As a developer watching a live run, I want to pause auto-follow by scrubbing backward, so that I can investigate older events while new events continue to buffer.
6. As a developer watching a live run, I want a clear jump-to-live control, so that I can return to the current edge of the run when I finish investigating history.
7. As a developer investigating several traces in one stream, I want a run picker grouped by trace ID, so that I can switch between active and completed runs.
8. As a developer opening a stream with multiple traces, I want the most recently active live run selected automatically, so that the UI starts on the run most likely to matter.
9. As a developer who explicitly selected a run, I want that selection to remain stable, so that activity in another run does not pull me away from my investigation.
10. As a developer, I want each run to show a clear state, so that I can distinguish live, completed, failed, and incomplete traces.
11. As a developer reading from stdin, I want EOF to mean the source disconnected rather than the run succeeded, so that unterminated traces are not falsely marked completed.
12. As a developer following a growing file, I want EOF to mean the reader has caught up, so that the server keeps waiting for more events until shutdown.
13. As a developer, I want trace completion to be based on explicit terminal events, so that runtime semantics come from the event stream rather than from file behavior.
14. As a developer, I want malformed lines to appear as redacted ingestion findings, so that instrumentation problems are visible without hiding otherwise valid events.
15. As a developer, I want duplicate event IDs to be reported, so that bad emitters do not silently corrupt the run view.
16. As a developer, I want file truncation or replacement to be detected, so that I understand when the source stream changed under the server.
17. As a developer, I want deduplication by event ID during file replacement or replay, so that the UI does not double count events.
18. As a developer, I want each agent represented as a node, so that I can quickly see the participating agents in the run.
19. As a developer, I want agent parent and child relationships inferred from cross-actor span ancestry, so that the UI reflects the causal spawn structure of the run.
20. As a developer, I want ambiguous agent parentage surfaced as a warning, so that conflicting instrumentation is visible rather than hidden.
21. As a developer, I want cross-agent messages shown separately from the primary spawn tree, so that communication edges do not corrupt the hierarchy.
22. As a developer, I want unresolved message targets displayed as unresolved endpoints, so that handoffs to missing actors are visible.
23. As a developer, I want the graph view to show the relationship map, so that I can understand the overall orchestration shape.
24. As a developer, I want the tree view to show the spawn hierarchy, so that I can follow which agent caused which downstream work.
25. As a developer, I want the swimlane view to show concurrency over time, so that I can see which agents were active, waiting, done, or failed at the same moment.
26. As a developer, I want the sequence view to show cross-agent handoffs, so that I can follow messages between agents.
27. As a developer, I want a visual inspector for a selected agent, so that I can inspect its role, model, status, timing, token usage, costs, events, and warnings.
28. As a developer, I want a visual inspector for a selected event, so that I can inspect its trace ID, span ID, parent span, emitter, sequence, actor, status, timestamp, operation, usage, attributes, and payload preview.
29. As a developer, I want payload previews sanitized before they reach the browser, so that sensitive data is not exposed by the web UI.
30. As a developer, I want full payload details loaded only when inspecting an event, so that the initial UI is faster and less likely to expose unnecessary data.
31. As a security-conscious user, I want the browser to receive the same redacted data as the TUI, so that serve mode does not weaken the safety boundary.
32. As a developer, I want token and cost metrics to use event-local deltas, so that totals are not double counted.
33. As a developer, I want missing token or cost data displayed as unavailable, so that unknown data is not confused with a true zero.
34. As a developer, I want headline metrics to reflect the run up to the current playback time, so that metrics match the visible moment in the trace.
35. As a developer, I want filters to affect the visual stage without silently redefining top-level run totals, so that metrics remain understandable.
36. As a developer, I want warnings visible in the top bar and drawer, so that loops, retries, stalls, or ingestion problems are not missed.
37. As a developer, I want warning history preserved after a warning resolves, so that transient stalls and retry storms remain part of the debugging story.
38. As a developer, I want stall warnings to appear even when no new event arrives, so that silence can become visible.
39. As a developer, I want warning timestamps to distinguish triggering event time from detection time, so that I can place findings correctly on the timeline.
40. As a developer, I want loop and retry warnings labeled as heuristics, so that I do not mistake them for guaranteed root-cause diagnoses.
41. As a developer, I want uncertain event ordering marked in the UI, so that distributed timing ambiguity is not hidden.
42. As a developer, I want the UI to preserve causal order even when wall-clock timestamps are imperfect, so that the trace stays faithful to the event model.
43. As a developer, I want run duration and playback offsets based on trace-relative time, so that scrub controls are intuitive.
44. As a developer, I want the UI to support search by agents, kinds, traces, and relevant event content, so that I can narrow down a large run quickly.
45. As a developer, I want the warnings drawer to be openable without leaving the current view, so that I can investigate warnings in context.
46. As a developer, I want each view tab to preserve the mock's interaction model, so that switching from the design to the product feels natural.
47. As a developer, I want desktop layouts to be the primary experience, so that the complex orchestration view remains legible.
48. As a developer on a narrow screen, I want core run selection, metrics, warnings, timeline, and inspector access to remain usable, so that the UI does not fully fail outside the ideal mock size.
49. As a developer, I want the UI to work without external internet access, so that local debugging is not blocked by unavailable CDNs.
50. As a package user, I want serve mode to be installed with AgentTrail, so that I do not need a separate package or service.
51. As a developer, I want the browser URL printed in the terminal, so that I can open it manually in any environment.
52. As a developer, I want browser auto-open controlled by a flag, so that CI, remote shells, and headless environments remain predictable.
53. As a security-conscious user, I want serve mode bound to loopback by default, so that trace data is not exposed on the network accidentally.
54. As a security-conscious user, I want remote binding to require explicit acknowledgement, so that exposing local trace data is an intentional act.
55. As a security-conscious user, I want remote access protected by a generated token when enabled, so that trusted-network development has a basic access boundary.
56. As a developer, I want the server API to be versioned from the start, so that future changes do not create accidental compatibility promises.
57. As a frontend developer, I want the initial run snapshot to include a cursor, so that live streaming can continue without losing or duplicating events.
58. As a developer, I want SSE reconnect to re-fetch the authoritative snapshot, so that browser disconnections do not corrupt the UI.
59. As a developer, I want slow browser clients disconnected rather than blocking ingestion, so that one tab cannot stall the trace reader.
60. As a developer, I want source connectivity surfaced separately from run completion, so that I can tell whether the stream ended or the run ended.
61. As a developer, I want a backend-readiness report after implementation, so that I can see which pieces reused existing code and which pieces were newly introduced.
62. As a developer, I want an integration guide after implementation, so that adapter authors know which fields power graph edges, sequence arrows, usage cards, model labels, roles, and warnings.
63. As an adapter author, I want the sequence-view contract documented, so that I can emit `message.sent` events that render as handoff arrows.
64. As an adapter author, I want the usage contract documented, so that token and cost cards populate correctly.
65. As an adapter author, I want the role and model contracts documented, so that agent labels and inspector details populate correctly.
66. As an AgentTrail maintainer, I want serve mode to reuse the existing sanitizer and trace index, so that the web UI does not fork canonical event behavior.
67. As an AgentTrail maintainer, I want a pure run-view projection layer, so that backend aggregation can be tested without HTTP or browser concerns.
68. As an AgentTrail maintainer, I want a small local HTTP server, so that serve mode remains simple and consistent with the local-first promise.
69. As an AgentTrail maintainer, I want the frontend to compute layout geometry, so that the backend exposes domain state rather than pixel positions.
70. As an AgentTrail maintainer, I want browser smoke tests against the real packaged UI, so that visual integration failures are caught before release.
71. As an AgentTrail maintainer, I want the original CLI snapshot and TUI paths verified after serve-mode work, so that backward compatibility is protected.
72. As an AgentTrail maintainer, I want performance limits stated in acceptance criteria, so that the first web UI remains useful on realistic local traces.

## Implementation Decisions

- Add an opt-in `serve` subcommand to the existing AgentTrail command rather than replacing or changing the default TUI invocation.
- The default command with an input path continues to render the existing terminal experience exactly as before.
- Serve mode accepts one JSONL file or stdin in the first release.
- Serve mode may receive events from multiple trace IDs in that single stream.
- Directory inputs, glob inputs, sockets, multiple simultaneous source files, and framework-specific adapters are deferred.
- Regular file input is followed after the reader reaches the current end of file.
- EOF on a regular file means the reader is caught up, not that a run completed.
- EOF on stdin means the source disconnected.
- A run is completed only by an explicit `trace.completed` event.
- A run is failed only by an explicit `trace.failed` event.
- A run with no terminal trace event and no connected source is `incomplete`.
- Late events after a terminal trace event are accepted and displayed.
- Late events after a terminal trace event produce a visible instrumentation warning.
- File truncation and replacement are detected and surfaced as source warnings.
- Replayed events are deduplicated by event ID.
- Malformed lines, duplicate IDs, truncation, replacement, and other source issues are exposed as ingestion or source findings distinct from runtime warnings.
- The existing JSONL reader, sanitizer, and trace index remain the authoritative ingestion, redaction, ordering, state, and warning foundation.
- A pure run-view projection layer aggregates one trace from the trace index into the JSON shape needed by the frontend.
- The run-view projection exposes agents, events, warnings, duration, run metadata, lifecycle state, and relationship links.
- The run-view projection does not compute client pixel coordinates.
- The frontend computes graph, tree, swimlane, and sequence layout geometry.
- One actor ID identifies one logical agent invocation within a trace for the first release.
- The primary agent tree is derived from the earliest causal cross-actor parent-span relationship that introduces an actor.
- Later cross-agent relationships are exposed as links rather than overwriting the primary parent.
- Conflicting parent derivation produces an ambiguity warning rather than silently changing hierarchy.
- Events whose actors have not otherwise appeared create minimal placeholder agents.
- Message targets that have no corresponding actor are displayed as unresolved endpoints.
- Sequence-view handoff arrows are keyed by `kind == "message.sent"` and `attributes.to` naming the destination actor ID.
- Optional message IDs can help pair sent and received messages later, but they are not required for the first release.
- Event offsets for playback use seconds relative to the earliest timestamp in the trace.
- Causal ordering and ordering uncertainty remain preserved from the trace index.
- The UI must mark uncertain ordering rather than presenting distributed event order as exact.
- Live runs stream new events over Server-Sent Events instead of WebSockets.
- SSE uses typed messages for event updates, warning updates, run metadata, and source status.
- SSE messages include a monotonically increasing server cursor.
- Initial run snapshots include a matching cursor so the browser can continue streaming from a known point.
- Browser reconnect re-fetches the authoritative snapshot and reconciles events by event ID.
- The server protects trace-index reads and writes so run snapshots are internally consistent.
- Time-based warnings such as stalls are recomputed periodically and pushed to the browser even when no event arrives.
- Warnings preserve history with active and resolved state where applicable.
- Warning data distinguishes linked event time from detection time.
- Usage fields are treated as event-local deltas.
- Adapters should normally attach final model usage to completion or failure events rather than duplicating cumulative usage across request and response events.
- Missing usage and cost data displays as unavailable rather than zero.
- Top-level metrics reflect the run up to the current playback time.
- Search and filters affect rendered views and local lists without silently redefining headline run totals.
- Completed and failed runs open at their final state with playback paused.
- Live runs auto-follow the current edge until the user scrubs backward or otherwise leaves live-follow mode.
- Playback speed applies to historical playback, not live-follow mode.
- The browser URL should at least encode selected run and selected view.
- Serve mode uses a local standard-library HTTP server in the Python runtime.
- The API is versioned from the start and documented as experimental until exercised by external adapters.
- CORS is disabled by default.
- The server binds to loopback by default.
- Binding to a non-loopback host requires an explicit remote-access flag and a prominent launch warning.
- Remote access uses a generated token in the launch URL for the first release.
- Remote access is incompatible with unsafe unredacted mode unless a stronger explicit override is later designed.
- Sanitization occurs before indexing, run-view projection, and streaming.
- The browser never receives unsanitized event data.
- Payload previews are included in ordinary run snapshots when available.
- Full retained payload detail is fetched lazily through the inspector path rather than eagerly loaded for every event.
- The production package must include the web UI assets.
- The web UI should work offline and should not depend on runtime CDN requests.
- The implementation may use a build step for maintainers if the installed runtime remains one Python package and one command.
- If the no-build approach conflicts with offline operation or maintainability, offline operation and maintainability take priority.
- The visual language, hierarchy, colors, typography, core interactions, and four-view structure from the supplied mock are retained.
- Literal mock coordinates may be adjusted for real data, responsiveness, accessibility, and maintainability.
- Desktop widths are the primary fully interactive experience.
- Narrower screens preserve essential run selection, metrics, warnings, timeline, and inspector access.
- `AgentTrail` remains the product name.
- `Flight recorder` may be used as a descriptive label rather than a separate product identity.
- The web UI should support graph, tree, swimlane, and sequence views in the first release.
- The graph view communicates overall relationships.
- The tree view communicates spawn hierarchy.
- The swimlane view communicates concurrent activity over time.
- The sequence view communicates cross-agent handoffs.
- The server continues ingesting when no browsers are connected.
- Each SSE client has bounded buffering.
- Slow clients are disconnected and recover through snapshot reconciliation rather than blocking ingestion.
- Memory-budget behavior remains visible to the browser through eviction metadata and warnings.
- The browser must not retain unlimited history in a way that defeats the configured server memory budget.
- A backend-readiness report is produced after implementation as a standalone HTML document.
- A UI-backend integration guide is produced after implementation as a standalone HTML document.
- The readiness report describes reused core behavior, newly introduced serve-mode behavior, and known approximations.
- The integration guide documents the serve command, endpoint contracts, streaming behavior, sequence message contract, usage contract, model contract, role contract, and warning behavior.
- Existing Markdown export remains available and unchanged.
- New export UI and self-contained HTML export are separate future work unless explicitly added by a later ticket.

## Testing Decisions

- The primary test seam is the process boundary around the real serve mode.
- The highest-value acceptance test launches the actual AgentTrail command in serve mode against a temporary growing JSONL file.
- The test then exercises the real HTTP API, real SSE stream, and packaged browser UI.
- The test verifies behavior from the user's perspective rather than private implementation details.
- The same seam covers ingestion, sanitization, indexing, run projection, source following, streaming, reconnection, rendering, view switching, warnings, playback, and backward-compatible startup.
- The browser portion should load a real fixture, switch graph, tree, swimlane, and sequence views, open agent and event inspectors, open the warnings drawer, scrub playback, and receive an appended live event.
- A reconnect test should prove that a disconnected browser can re-fetch a snapshot and continue without losing or duplicating events.
- A stall test should prove that warning updates can arrive when no new event is appended.
- A source lifecycle test should prove that regular-file EOF, stdin EOF, terminal trace events, and incomplete traces produce distinct states.
- A sanitization test should prove that sensitive data is redacted before browser snapshots and SSE messages are emitted.
- A backward-compatibility test should prove that the existing non-serve invocation still renders through the original terminal or snapshot path.
- Existing core tests remain the prior art for event validation, redaction, ordering, trace indexing, actor state, warnings, and CLI behavior.
- Focused unit tests are appropriate for the pure run-view projection because it is a new domain seam with deterministic input and output.
- Focused server tests are appropriate for API route contracts, cursor behavior, and source status when browser automation would be unnecessarily heavy.
- Avoid tests that assert exact pixel coordinates or private frontend implementation structure.
- Prefer tests that assert visible labels, counts, selected run behavior, view availability, warning presence, playback state, and inspector content.
- Performance acceptance should include first useful paint within one second for a 10,000-event fixture on a developer machine target.
- Performance acceptance should include usable interaction for at least 100 agents.
- Ingestion targets should preserve the existing ambition of handling 100,000 metadata events without unbounded memory growth.
- Automated browser smoke tests may use development-only dependencies because the runtime package remains local-first and lightweight.
- Manual browser verification is still useful for visual polish, but it is not sufficient as the only release gate.
- Current stable Chrome, Firefox, and Safari should be considered the browser support target.

## Out of Scope

- Hosted dashboards are out of scope.
- User accounts are out of scope.
- A database or cross-restart run history is out of scope.
- Editing, replaying, or correcting agent runs is out of scope.
- Automatically diagnosing root cause is out of scope.
- Automatically executing corrective actions is out of scope.
- Capturing hidden chain-of-thought is out of scope.
- Framework-specific adapters are out of scope for this serve-mode increment.
- Directory inputs, glob inputs, sockets, and multiple simultaneous source files are out of scope for the first serve-mode release.
- WebSocket transport is out of scope because server-to-client push is sufficient.
- Remote hosted sharing is out of scope.
- Cross-origin API access is out of scope by default.
- New export UI is out of scope.
- Self-contained HTML export is out of scope for this increment unless split into a follow-up ticket.
- Persistent user preferences are out of scope.
- Custom keybindings are out of scope.
- Perfect mobile parity with the 1440px desktop mock is out of scope.
- Pixel-perfect literal replication at the expense of real-data usability is out of scope.
- Perfect redaction guarantees are out of scope.
- Exact distributed total ordering is out of scope when the source data lacks enough causal information.
- General-purpose observability features such as evaluations, prompt scoring, production monitoring, and hosted retention are out of scope.

## Further Notes

The supplied serve-mode plan and orchestration mock are treated as the canonical product direction for this spec.
The mock's generated design runtime is not treated as a production dependency.
The production UI should be maintainable, readable, packageable, and local-first.
The exact module and file layout can be chosen during implementation, but the conceptual seams are the CLI entrypoint, ingestion source follower, trace index, run-view projection, local HTTP server, static frontend assets, and browser UI.
The current repository has no root domain glossary or ADRs for this area.
No ADR conflict was found during exploration.
The local issue tracker is configured for this repository and this spec is ready for an implementation agent.
The implementation should create the readiness report and integration guide after the code is built so those documents reflect actual behavior rather than only the plan.
Known approximations from the current plan should be called out in the readiness report, including representative span selection per agent, fallback run titles, process-local run lists, and no cross-restart history.
The adapter contract should be documented clearly because the UI can only show model names, roles, usage, costs, and sequence arrows when producers emit the required fields.
