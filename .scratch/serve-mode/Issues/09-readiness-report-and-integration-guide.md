# 09 - Backend Readiness Report And UI Integration Guide

**What to build:** Publish the human-facing implementation documentation promised by the spec.
A developer can read what was actually built, which existing core behavior was reused, which serve-mode pieces are new, what approximations remain, how to run serve mode, and what adapter fields are required for the visual UI to populate correctly.

**Blocked by:** 02 - Live Source Lifecycle And Streaming; 03 - Causal Run Projection For Agents, Links, Usage, And Warnings; 06 - Inspector, Warnings Drawer, Search, Filters, And Payload Detail; 07 - Security, Packaging, Offline Assets, And Remote Access Guardrails.

**Status:** resolved

- [x] A standalone backend-readiness report explains reused ingestion, sanitization, trace indexing, ordering, warning behavior, and newly added serve-mode behavior.
- [x] The report identifies known approximations such as representative spans, fallback run titles, process-local run lists, and no cross-restart history.
- [x] A standalone integration guide explains how to run serve mode and how the UI attaches to the local API and SSE stream.
- [x] The integration guide documents the contracts for message handoffs, usage and cost deltas, model labels, actor roles, warning behavior, and payload redaction.
- [x] The documents describe actual implemented behavior rather than repeating pre-implementation plans.
- [x] The documents are readable in a browser without external assets.

## Comments

Implemented in the issue 09 readiness report and integration guide change.
Added self-contained browser-readable HTML documentation for backend readiness, reused and new behavior, known approximations, command/API/SSE integration, adapter contracts, warnings, and redaction.
Verified with documentation checks, the full unittest and Playwright suite, diff check, and code-review skill.
