# 07 - Security, Packaging, Offline Assets, And Remote Access Guardrails

**What to build:** Harden serve mode for safe local use and predictable installation.
A user can install AgentTrail, run serve mode offline, avoid accidental network exposure, and intentionally enable remote development access only with explicit warnings and a generated access token.

**Blocked by:** 01 - Serve Mode Foundation And Smokeable Shell.

**Status:** resolved

- [x] The packaged browser UI works without runtime CDN or third-party network requests.
- [x] Sanitization happens before indexing, projection, and streaming so the browser never receives unsanitized event data.
- [x] Loopback binding is the default and cross-origin API access is disabled by default.
- [x] Non-loopback binding requires an explicit remote-access flag and prints a prominent warning.
- [x] Remote access uses a generated token in the launch URL for the first release.
- [x] Unsafe unredacted mode cannot be combined with remote exposure unless a separate explicit override is designed and documented.
- [x] Memory-budget and payload-eviction behavior remains visible to the browser without allowing the browser to retain unlimited server-evicted history.
- [x] Automated tests cover offline asset loading, redaction boundaries, CORS defaults, remote-access guardrails, token checks, and unsafe-mode rejection.

## Comments

Implemented in the issue 07 security, packaging, offline assets, and remote access change.
Added explicit remote-access guardrails, generated token URLs, token-protected API/SSE access, unsafe-mode rejection for remote exposure, CORS-default coverage, offline asset packaging verification, and payload-retention pruning after memory eviction.
Verified with the full unittest suite, wheel packaging inspection, diff check, and code-review skill.
