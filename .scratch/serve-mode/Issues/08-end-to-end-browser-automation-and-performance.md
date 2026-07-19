# 08 - End-To-End Browser Automation And Performance Envelope

**What to build:** Establish the approved process-boundary verification seam for serve mode.
A maintainer can run automated tests that launch the real AgentTrail serve command, feed a growing JSONL input, exercise the real API and SSE stream, drive the packaged browser UI, and verify the core user journey without relying on implementation details.

**Blocked by:** 04 - Graph And Tree Views From Real Runs; 05 - Swimlane, Sequence, And Playback Experience; 06 - Inspector, Warnings Drawer, Search, Filters, And Payload Detail; 07 - Security, Packaging, Offline Assets, And Remote Access Guardrails.

**Status:** resolved

- [x] The end-to-end suite launches the real serve command against a temporary growing JSONL input.
- [x] The suite verifies run loading, SSE event append, reconnect recovery, source lifecycle state, and sanitized browser-visible data.
- [x] The suite switches graph, tree, swimlane, and sequence views using the packaged browser UI.
- [x] The suite selects agents and events, opens the warnings drawer, uses search or filters, scrubs playback, and jumps back to live.
- [x] The suite verifies the existing non-serve invocation still follows the original terminal behavior.
- [x] Performance checks cover first useful paint for a large fixture and usable interaction for a large agent count target.
- [x] Tests avoid asserting exact pixel coordinates or private frontend implementation structure.

## Comments

Implemented in the issue 08 end-to-end browser automation and performance change.
Added a Playwright test extra and Chromium-driven process-boundary tests for the packaged UI, live SSE updates, reconnect recovery, source lifecycle, sanitization, all four visual views, inspectors, warnings, search, playback, buffered events, jump-to-live, compatibility, and a 100-agent browser performance envelope.
Verified with the full unittest suite, Playwright E2E suite, diff check, and code-review skill.
