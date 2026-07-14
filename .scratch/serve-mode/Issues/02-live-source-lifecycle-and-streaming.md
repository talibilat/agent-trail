# 02 - Live Source Lifecycle And Streaming

**What to build:** Turn the foundation from a static viewer into a real live tail.
A user can point serve mode at a growing JSONL file or stdin, see new events arrive without refreshing the browser, and distinguish source connectivity from run completion.
Malformed input, duplicate events, truncation, replacement, terminal trace events, incomplete traces, and late events become visible source or instrumentation findings rather than hidden server behavior.

**Blocked by:** 01 - Serve Mode Foundation And Smokeable Shell.

**Status:** resolved

- [x] Regular file input continues waiting for appended complete JSONL lines after reaching the current end of file.
- [x] Stdin EOF marks the source disconnected without falsely marking unterminated traces as completed.
- [x] Explicit trace terminal events drive live, completed, failed, and incomplete run states.
- [x] New events are delivered to the browser over Server-Sent Events with typed messages and a server cursor.
- [x] Browser reconnect re-fetches the authoritative snapshot and reconciles by event ID without losing or duplicating events.
- [x] Malformed lines, duplicate IDs, source truncation, source replacement, and late events are visible as distinct source or instrumentation findings.
- [x] Automated tests cover growing-file tailing, stdin EOF, terminal run states, duplicate suppression, and SSE reconnect behavior.

## Comments

Implemented in the issue 02 live-source lifecycle change.
Added live file following, stdin disconnect state, explicit trace lifecycle states, source and ingestion findings, typed SSE updates with cursors, browser snapshot refresh on SSE updates/reconnects, and tests for the live-source behaviours.
Verified with the full unittest suite, diff check, and code-review skill.
