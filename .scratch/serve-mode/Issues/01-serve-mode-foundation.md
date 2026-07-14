# 01 - Serve Mode Foundation And Smokeable Shell

**What to build:** Add the first end-to-end serve-mode path.
A user can run Agent Tail in serve mode against one existing JSONL input, receive a printed local URL, open a packaged offline browser shell, and see real sanitized run and event data through a versioned local API.
The existing non-serve CLI and TUI behavior remains unchanged.

**Blocked by:** None - can start immediately.

**Status:** resolved

- [x] A serve-mode command starts a loopback local HTTP server for one JSONL file or stdin.
- [x] The command supports host, port, and explicit browser-open behavior without changing the default terminal invocation.
- [x] The browser shell loads without external network access and displays real run summaries and a basic event timeline from the input.
- [x] The local API is versioned and exposes run listing and run detail responses backed by sanitized indexed events.
- [x] The default non-serve command still follows the existing terminal behavior and test expectations.
- [x] Server startup, input validation, and basic route behavior are covered by automated tests.

## Comments

Implemented in the issue 01 serve-mode foundation change.
Added `agent-tail serve`, a loopback standard-library HTTP server, `/api/v1/runs`, `/api/v1/runs/<trace-id>`, a packaged offline browser shell, and focused server/CLI tests.
Verified with the full unittest suite, package wheel asset inspection, and code-review skill.
