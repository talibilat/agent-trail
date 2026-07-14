# 06 - Inspector, Warnings Drawer, Search, Filters, And Payload Detail

**What to build:** Complete the investigative workflow around selecting agents and events.
A user can search and filter a large run, select an agent or event, inspect detailed sanitized metadata and usage, open warning history, and lazily request retained payload detail only when needed.

**Blocked by:** 02 - Live Source Lifecycle And Streaming; 03 - Causal Run Projection For Agents, Links, Usage, And Warnings.

**Status:** resolved

- [x] Agent inspector panels show role, model, status, timing, usage, cost, related events, and warnings for the selected agent.
- [x] Event inspector panels show trace identity, span identity, emitter, sequence, actor, operation, status, timestamp, attributes, usage, and sanitized payload preview for the selected event.
- [x] Retained full payload detail is fetched lazily for an inspected event and remains sanitized.
- [x] Search and filters narrow visible agents, events, and lists without silently redefining headline run totals.
- [x] The warnings drawer shows active and resolved runtime warnings, source findings, ingestion findings, trigger times, and detection times where available.
- [x] Stall warnings can update in the browser even when no new event arrives.
- [x] Browser-level tests cover agent inspection, event inspection, warning drawer behavior, search, filters, lazy payload detail, and no-event stall updates.

## Comments

Implemented in the issue 06 inspector, warnings, search, filters, and payloads change.
Added lazy retained payload detail, search and actor/kind filters, agent and event inspectors, warnings drawer details, runtime warning history, and heartbeat refresh for no-event warning updates.
Verified with the full unittest suite, diff check, and code-review skill.
