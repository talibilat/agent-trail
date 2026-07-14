# 04 - Graph And Tree Views From Real Runs

**What to build:** Replace the basic browser shell's relationship display with the mock-inspired graph and tree experience powered by real run data.
A user can switch between graph and tree views, inspect the agent hierarchy, pan and zoom around larger runs, focus subtrees, and keep the visual language of the supplied design while accepting responsive corrections for real data.

**Blocked by:** 03 - Causal Run Projection For Agents, Links, Usage, And Warnings.

**Status:** resolved

- [x] The graph view renders real agent nodes and relationship edges from the projected run data.
- [x] The tree view renders the primary spawn hierarchy from the projected run data.
- [x] Agent status, role, model, warning state, usage signals, and selection state are visible where the design calls for them.
- [x] Pan, zoom, reset, and focus interactions work for graph and tree views.
- [x] Large or dense runs remain usable through clustering, progressive reveal, or equivalent safeguards rather than rendering an unbounded unreadable canvas.
- [x] Desktop layouts preserve the supplied visual language and narrower screens preserve essential access instead of fully breaking.
- [x] Browser-level tests verify that real fixture data renders in both views and that selecting an agent updates the visible UI.

## Comments

Implemented in the issue 04 graph and tree views change.
Added graph, tree, and timeline tabs, projected relationship rendering, primary-spawn-only tree edges, selectable agent cards, pan/zoom/reset/focus controls, progressive reveal for dense runs, and packaged-shell smoke coverage.
Verified with the full unittest suite, diff check, and code-review skill.
