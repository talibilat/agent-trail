# 03 - Causal Run Projection For Agents, Links, Usage, And Warnings

**What to build:** Enrich the serve-mode data contract so the browser receives a complete run view rather than raw events alone.
A user can see logical agents, primary spawn hierarchy, cross-agent links, lifecycle state, trace-relative timing, usage totals, warning data, and ordering uncertainty derived from the existing trace index.
The projection remains independent of pixel layout so the client owns visual geometry.

**Blocked by:** 01 - Serve Mode Foundation And Smokeable Shell.

**Status:** resolved

- [x] Run detail responses include browser-ready agents, events, warnings, duration, lifecycle state, source state, usage summaries, and relationship links.
- [x] The primary agent tree is derived from causal cross-actor span ancestry while later cross-agent relationships remain separate links.
- [x] Conflicting parent derivation, unresolved message targets, missing usage, and ordering uncertainty are represented explicitly.
- [x] Sequence handoff links use the documented message-sent target contract.
- [x] Usage and cost aggregation treats usage fields as event-local deltas and displays unavailable metrics distinctly from true zero.
- [x] Warning data distinguishes runtime warnings from ingestion and source findings where the UI needs that distinction.
- [x] Deterministic projection tests cover parent derivation, link extraction, warning mapping, usage aggregation, lifecycle state, and uncertainty markers.

## Comments

Implemented in the issue 03 causal run projection change.
Added duration, lifecycle, source, usage, agent metadata, relationship links, unresolved endpoints, projection warnings, and uncertainty markers to run detail responses.
Verified with the full unittest suite, diff check, and code-review skill.
