# LangGraph Callback Adapter

The direct LangGraph adapter writes callback activity incrementally as canonical AgentTrail JSONL.
It supports LangGraph 1.x and does not add LangGraph to the base AgentTrail installation.

## Install

Install AgentTrail with the optional LangGraph dependency:

```bash
python -m pip install 'agent-tail[langgraph]'
```

The supported dependency range is `langgraph>=1.0.1,<2` on Python 3.11 or newer.
Importing `agent_tail` or `agent_tail.langgraph` without this extra remains safe.
Constructing `AgentTailCallbackHandler` without the extra raises an actionable installation error.

## Capture A Graph

Pass the handler through the standard LangGraph callback configuration:

```python
from langgraph.graph import END, START, StateGraph
from agent_tail import AgentTailCallbackHandler


builder = StateGraph(dict)
builder.add_node("increment", lambda state: {"value": state["value"] + 1})
builder.add_edge(START, "increment")
builder.add_edge("increment", END)
graph = builder.compile()

with AgentTailCallbackHandler("run.jsonl") as callback:
    graph.invoke(
        {"value": 1},
        {"callbacks": [callback]},
    )
```

The same handler supports the asynchronous LangGraph callback path:

```python
with AgentTailCallbackHandler("run.jsonl") as callback:
    result = await graph.ainvoke(
        {"value": 1},
        {"callbacks": [callback]},
    )
```

The default output path is `agent-tail.jsonl`.
An existing path is opened in append mode, and every complete JSONL line is flushed before its callback returns.
A writable text stream can be supplied instead of a path, and caller-owned streams are flushed but are not closed by the handler.

Inspect the growing file in another process:

```bash
agent-tail serve run.jsonl --open
```

## Callback Mapping

Top-level graph runs, graph nodes, and nested graph invocations map from chain callbacks to `agent.started`, `agent.finished`, and `agent.failed`.
LLM and chat-model callbacks map to `model.request.started`, `model.request.finished`, and `model.request.failed`.
Tool callbacks map to `tool.call.started`, `tool.call.finished`, and `tool.call.failed`.
Normalized tool input is stored under `attributes.arguments`, and command and result evidence is stored under `attributes.tool`.
Other standard callback types are retained conservatively as `langgraph.callback.*` events instead of creating new canonical concepts.
Custom `handoff` and `message.sent` callbacks map to `message.sent` only when their data contains non-blank `sender` and `recipient` values, with `from` and `to` accepted as explicit aliases.
The adapter does not infer messages, handoffs, repository reads, changes, requirements, or test results from prompts or model output.

Framework callback names, tags, metadata, checkpoint namespaces, graph nodes, paths, triggers, inputs, outputs, and errors remain under `attributes.langgraph`.
No LangGraph-specific field is added to the canonical top-level envelope, core index, serve API, or browser UI.

Each callback run ID deterministically derives its actor, span, and lifecycle event IDs.
The root callback ancestry deterministically derives one trace ID for the graph invocation.
Child callbacks retain the reported parent run as `parent_span_id`, and the adapter does not invent ordering between concurrent branches.
One locked monotonic sequence belongs to the configured emitter, and the same lock prevents concurrent writes from interleaving JSONL lines.
Completed callback runs are removed immediately, and `max_active_runs` bounds incomplete lifecycle bookkeeping for long-lived handlers.

## Change Evidence Helpers

Evidence is emitted only when application code calls an explicit helper.
Every helper requires a stable caller-selected `evidence_id`, validates the canonical evidence fields it owns, and returns the deterministic canonical event ID.
Use `event_id(run_id, kind, evidence_id)` to calculate a future helper event ID before emitting a change that references it.

```python
from uuid import UUID


run_id = UUID("00000000-0000-0000-0000-000000000001")

context_id = callback.emit_context_read(
    run_id=run_id,
    evidence_id="session-context",
    path="src/auth/session.py",
    line_start=84,
    line_end=102,
    symbol="reject_expired_session",
)

verification_id = callback.event_id(
    run_id,
    "verification.finished",
    "session-tests-finished",
)

change_id = callback.emit_change_applied(
    run_id=run_id,
    evidence_id="session-change",
    path="src/auth/session.py",
    old_start=84,
    old_count=18,
    new_start=84,
    new_count=19,
    symbol="reject_expired_session",
    relationships=[
        {"type": "informed_by", "event_id": context_id},
        {"type": "verified_by", "event_id": verification_id},
    ],
)

verification_start_id = callback.emit_verification_started(
    run_id=run_id,
    evidence_id="session-tests-started",
    command="pytest tests/test_session.py",
    test_origin="pre_existing",
)

callback.emit_verification_finished(
    run_id=run_id,
    evidence_id="session-tests-finished",
    passed=True,
    start_event_id=verification_start_id,
    exit_code=0,
    test_origin="pre_existing",
)
```

Context helpers require a non-blank path and validate optional positive line bounds and symbols.
`emit_context_read` also accepts an explicit complete-file `content_sha256`, repository commit, and worktree digest.
`emit_context_search` accepts an explicit non-blank query, a distinct ordered path list including an empty list, and the same optional repository snapshot fields.
`emit_change_applied` accepts an explicit complete-file `preimage_sha256` and the same optional repository snapshot fields.
These helpers validate caller-supplied values but never inspect a repository, read a file, perform a search, or calculate a digest.
See [Context provenance](context-provenance.md) for the exact byte and dirty-worktree manifest algorithms.
Change helpers require a valid Git hunk range and accept only the canonical `motivated_by`, `informed_by`, `preceded_by`, `verified_by`, and `applies` relationship types.
The caller must supply every relationship type and canonical target event ID explicitly.
Verification helpers require a command on the start or finished event, validate lifecycle linkage, validate boolean outcomes and exit-code agreement, and accept only `pre_existing` or `same_agent` test origins.

Requirements, tool calls, and proposals can be produced by another canonical event source and referenced by ID from `emit_change_applied`.
Helpers do not fabricate those facts when their event IDs are absent.

## Sensitive Telemetry

The generated JSONL is append-only source telemetry and can contain prompts, model output, tool arguments, errors, checkpoint data, credentials, and private application state.
Protect it like the original LangGraph execution data.

AgentTrail sanitizes accepted events before they enter `TraceIndex` in terminal, export, serve API, and browser paths.
The existing sanitizer redacts recognized secret values and sensitive keys, but no ruleset can guarantee detection of every secret.
Review generated artifacts and rendered output before sharing them.
