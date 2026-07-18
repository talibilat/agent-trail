import asyncio
import hashlib
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from uuid import UUID

from agent_tail.core import Event
from agent_tail.langgraph import AgentTailCallbackHandler
from agent_tail.serve import RunStore


LANGGRAPH_AVAILABLE = importlib.util.find_spec("langgraph") is not None
ROOT = Path(__file__).parents[1]


class LangGraphAdapterTests(unittest.TestCase):
    def test_deterministic_parent_parallel_model_tool_and_failure_fixture(self):
        first = self._fixture()
        second = self._fixture()

        self.assertEqual(first, second)
        self.assertEqual(
            hashlib.sha256(first.encode()).hexdigest(),
            "6b2ca9e30119dd188c979055242fde08b7ae3d684aa9ae83998cf80521dfbcd8",
        )
        events = [Event.from_dict(json.loads(line)) for line in first.splitlines()]
        self.assertEqual(
            [event.kind for event in events],
            [
                "agent.started",
                "agent.started",
                "agent.started",
                "model.request.started",
                "model.request.finished",
                "agent.finished",
                "tool.call.started",
                "tool.call.finished",
                "agent.failed",
                "agent.failed",
            ],
        )
        self.assertEqual([event.sequence for event in events], list(range(1, 11)))
        self.assertEqual({event.trace_id for event in events}, {events[0].trace_id})
        self.assertEqual(events[1].parent_span_id, events[0].span_id)
        self.assertEqual(events[2].parent_span_id, events[0].span_id)
        self.assertEqual(events[3].parent_span_id, events[1].span_id)
        self.assertEqual(events[6].parent_span_id, events[2].span_id)
        self.assertEqual(events[8].span_id, events[2].span_id)
        self.assertIn("authorization", events[6].raw["attributes"]["arguments"])

    def test_concurrent_callbacks_write_complete_non_interleaved_lines(self):
        stream = _ConcurrentWriteDetector()
        handler = AgentTailCallbackHandler(
            stream, clock=lambda: "2026-07-18T12:00:00Z"
        )
        root = UUID(int=100)
        handler.on_chain_start({"name": "graph"}, {}, run_id=root)
        barrier = threading.Barrier(9)

        def branch(number):
            run_id = UUID(int=200 + number)
            barrier.wait()
            handler.on_chain_start(
                {"name": f"node-{number}"}, {},
                run_id=run_id, parent_run_id=root,
            )
            handler.on_chain_end({}, run_id=run_id, parent_run_id=root)

        threads = [threading.Thread(target=branch, args=(number,)) for number in range(8)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        handler.on_chain_end({}, run_id=root)

        lines = stream.getvalue().splitlines()
        events = [json.loads(line) for line in lines]
        self.assertFalse(stream.overlapped)
        self.assertEqual(len(events), 18)
        self.assertEqual(
            sorted(event["sequence"] for event in events), list(range(1, 19))
        )

    def test_output_path_appends_and_flushes_each_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "trace.jsonl")
            output.write_text("existing\n", encoding="utf-8")
            handler = AgentTailCallbackHandler(
                output, clock=lambda: "2026-07-18T12:00:00Z"
            )
            handler.on_chain_start({"name": "graph"}, {}, run_id=UUID(int=1))
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 2)
            handler.close()
            self.assertTrue(handler._stream.closed)

    def test_custom_handoff_requires_explicit_sender_and_recipient(self):
        stream = StringIO()
        handler = AgentTailCallbackHandler(
            stream, clock=lambda: "2026-07-18T12:00:00Z"
        )
        run_id = UUID(int=88)
        handler.on_custom_event(
            "handoff",
            {"sender": "planner", "recipient": "worker", "task": "inspect"},
            run_id=run_id,
        )
        handler.on_custom_event(
            "handoff", {"sender": "planner"}, run_id=run_id
        )
        events = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(events[0]["kind"], "message.sent")
        self.assertEqual(events[0]["actor"]["id"], "planner")
        self.assertEqual(events[0]["attributes"]["to"], "worker")
        self.assertEqual(events[1]["kind"], "langgraph.callback.custom")

    def test_lifecycle_state_is_bounded_and_released(self):
        handler = AgentTailCallbackHandler(StringIO(), max_active_runs=2)
        run_ids = [UUID(int=value) for value in range(1, 5)]
        for run_id in run_ids:
            handler.on_chain_start({"name": "node"}, {}, run_id=run_id)
        self.assertEqual(handler.active_run_count, 2)
        for run_id in run_ids:
            handler.on_chain_end({}, run_id=run_id)
        self.assertEqual(handler.active_run_count, 0)

    def test_evidence_helpers_validate_and_project_change_evidence(self):
        stream = StringIO()
        handler = AgentTailCallbackHandler(
            stream, clock=lambda: "2026-07-18T12:00:00Z"
        )
        run_id = UUID(int=301)
        handler.on_chain_start({"name": "coding-graph"}, {}, run_id=run_id)
        context_id = handler.emit_context_read(
            run_id=run_id,
            evidence_id="auth-context",
            path="src/auth.py",
            line_start=10,
            line_end=20,
            symbol="authenticate",
            content_sha256="1" * 64,
            repository_commit="abc123",
            repository_worktree_sha256="2" * 64,
        )
        search_id = handler.emit_context_search(
            run_id=run_id,
            evidence_id="auth-search",
            query="authenticate",
            matches=[],
            repository_commit="abc123",
        )
        verification_id = handler.event_id(
            run_id, "verification.finished", "auth-tests-finished"
        )
        change_id = handler.emit_change_applied(
            run_id=run_id,
            evidence_id="auth-change",
            path="src/auth.py",
            old_start=10,
            old_count=2,
            new_start=10,
            new_count=3,
            preimage_sha256="1" * 64,
            repository_commit="abc123",
            repository_worktree_sha256="2" * 64,
            relationships=[
                {"type": "informed_by", "event_id": context_id},
                {"type": "verified_by", "event_id": verification_id},
            ],
        )
        start_id = handler.emit_verification_started(
            run_id=run_id,
            evidence_id="auth-tests-started",
            command="pytest tests/test_auth.py",
            test_origin="pre_existing",
        )
        self.assertEqual(
            handler.emit_verification_finished(
                run_id=run_id,
                evidence_id="auth-tests-finished",
                passed=True,
                start_event_id=start_id,
                exit_code=0,
                test_origin="pre_existing",
            ),
            verification_id,
        )
        handler.on_chain_end({}, run_id=run_id)

        store = RunStore.from_lines(stream.getvalue().splitlines(True))
        detail = store.run_detail(json.loads(stream.getvalue().splitlines()[0])["trace_id"])
        change = detail["evidence_map"]["changes"][0]
        self.assertEqual(change["event_id"], change_id)
        self.assertEqual(change["hunk"]["path"], "src/auth.py")
        self.assertEqual(
            detail["context_provenance"]["by_event_id"][change_id]["freshness"],
            "fresh",
        )
        self.assertEqual(
            detail["context_provenance"]["by_event_id"][search_id]["canonical_matches"],
            [],
        )
        self.assertEqual(
            {link["target_event_id"] for link in change["links"]},
            {context_id, verification_id},
        )
        verification = next(
            link for link in change["links"] if link["type"] == "verified_by"
        )
        self.assertTrue(verification["verification"]["passed"])
        self.assertEqual(
            verification["verification"]["starts"][0]["event_id"], start_id
        )

        with self.assertRaisesRegex(ValueError, "path must be"):
            handler.emit_context_read(
                run_id=run_id, evidence_id="bad", path=" "
            )
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            handler.emit_context_read(
                run_id=run_id,
                evidence_id="bad-hash",
                path="x.py",
                content_sha256="A" * 64,
            )
        with self.assertRaisesRegex(ValueError, "distinct"):
            handler.emit_context_search(
                run_id=run_id,
                evidence_id="duplicate-search",
                query="x",
                matches=["x.py", "x.py"],
            )
        with self.assertRaisesRegex(ValueError, "not valid"):
            handler.emit_change_applied(
                run_id=run_id,
                evidence_id="bad-change",
                path="x.py",
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=1,
                relationships=[{"type": "corrects", "event_id": change_id}],
            )
        with self.assertRaisesRegex(ValueError, "agree"):
            handler.emit_verification_finished(
                run_id=run_id,
                evidence_id="bad-finish",
                passed=True,
                command="pytest",
                exit_code=1,
            )

    def test_generated_secrets_are_sanitized_at_terminal_and_export_boundaries(self):
        secret = "ghp_" + "a" * 36
        root = UUID(int=401)
        tool = UUID(int=402)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "sensitive.jsonl")
            report = Path(directory, "report.md")
            handler = AgentTailCallbackHandler(source)
            handler.on_chain_start(
                {"name": "secure-graph"},
                {"prompt": f"use {secret}"},
                run_id=root,
                metadata={"authorization": secret, "custom": secret},
            )
            handler.on_tool_start(
                {"name": "lookup"},
                secret,
                run_id=tool,
                parent_run_id=root,
                inputs={"token": secret, "query": secret},
            )
            handler.on_tool_error(
                RuntimeError(f"failed with {secret}"),
                run_id=tool,
                parent_run_id=root,
            )
            handler.on_chain_error(
                RuntimeError(f"graph failed with {secret}"), run_id=root
            )
            handler.close()
            raw = source.read_text(encoding="utf-8")
            self.assertIn(secret, raw)
            self.assertNotIn(str(root), raw)
            terminal = subprocess.run(
                [sys.executable, "-m", "agent_tail", str(source)],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                check=False,
                capture_output=True,
                text=True,
            )
            exported = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    str(source),
                    "--export",
                    str(report),
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(terminal.returncode, 0, terminal.stderr)
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertNotIn(secret, terminal.stdout + terminal.stderr)
            self.assertNotIn(secret, exported.stdout + exported.stderr)
            self.assertNotIn(secret, report.read_text(encoding="utf-8"))

    def test_base_package_imports_and_constructor_error_is_actionable_without_extra(self):
        script = """
import builtins
real_import = builtins.__import__
def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and (name == 'langgraph' or name.startswith('langchain_core')):
        raise ImportError('blocked optional dependency')
    return real_import(name, globals, locals, fromlist, level)
builtins.__import__ = blocked
import agent_tail
from agent_tail.langgraph import AgentTailCallbackHandler
print('imported')
try:
    AgentTailCallbackHandler()
except ImportError as error:
    print(error)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("imported", result.stdout)
        self.assertIn("agent-tail[langgraph]", result.stdout)

    @unittest.skipUnless(LANGGRAPH_AVAILABLE, "LangGraph extra is not installed")
    def test_supported_langgraph_sync_and_async_invocations(self):
        from langgraph.graph import END, START, StateGraph
        from typing_extensions import TypedDict

        class State(TypedDict):
            value: int
            left: int
            right: int

        def left(state):
            return {"left": state["value"] + 1}

        def right(state):
            return {"right": state["value"] + 2}

        builder = StateGraph(State)
        builder.add_node("left", left)
        builder.add_node("right", right)
        builder.add_edge(START, "left")
        builder.add_edge(START, "right")
        builder.add_edge("left", END)
        builder.add_edge("right", END)
        graph = builder.compile()

        sync_stream = StringIO()
        sync_handler = AgentTailCallbackHandler(sync_stream)
        graph.invoke(
            {"value": 1},
            {"callbacks": [sync_handler], "run_id": UUID(int=900)},
        )

        async_stream = StringIO()
        async_handler = AgentTailCallbackHandler(async_stream)

        async def invoke():
            return await graph.ainvoke(
                {"value": 1},
                {"callbacks": [async_handler], "run_id": UUID(int=900)},
            )

        asyncio.run(invoke())
        sync_events = [json.loads(line) for line in sync_stream.getvalue().splitlines()]
        async_events = [json.loads(line) for line in async_stream.getvalue().splitlines()]

        def structure(events):
            by_span = {}
            for event in events:
                by_span.setdefault(event["span_id"], []).append(event)
            return sorted(
                (
                    activity[0]["operation"]["name"],
                    tuple(event["kind"] for event in activity),
                    activity[0].get("parent_span_id") is not None,
                )
                for activity in by_span.values()
            )

        self.assertEqual(structure(sync_events), structure(async_events))
        self.assertEqual(
            structure(sync_events),
            [
                ("LangGraph", ("agent.started", "agent.finished"), False),
                ("left", ("agent.started", "agent.finished"), True),
                ("right", ("agent.started", "agent.finished"), True),
            ],
        )
        self.assertEqual(sync_handler.active_run_count, 0)
        self.assertEqual(async_handler.active_run_count, 0)

    def _fixture(self):
        stream = StringIO()
        handler = AgentTailCallbackHandler(
            stream, clock=lambda: "2026-07-18T12:00:00Z"
        )
        graph = UUID(int=1)
        node_a = UUID(int=2)
        node_b = UUID(int=3)
        model = UUID(int=4)
        tool = UUID(int=5)
        handler.on_chain_start({"name": "parent"}, {"request": "safe"}, run_id=graph)
        handler.on_chain_start(
            {"name": "left"}, {}, run_id=node_a, parent_run_id=graph,
            metadata={"langgraph_node": "left", "langgraph_checkpoint_ns": "left:1"},
        )
        handler.on_chain_start(
            {"name": "right"}, {}, run_id=node_b, parent_run_id=graph,
            metadata={"langgraph_node": "right"},
        )
        handler.on_llm_start(
            {"name": "fake-model"}, ["prompt"],
            run_id=model, parent_run_id=node_a,
        )
        handler.on_llm_end(
            {"generations": [["answer"]]}, run_id=model, parent_run_id=node_a
        )
        handler.on_chain_end({"answer": 1}, run_id=node_a, parent_run_id=graph)
        handler.on_tool_start(
            {"name": "lookup"}, "lookup token",
            run_id=tool, parent_run_id=node_b,
            inputs={"query": "safe", "authorization": "Bearer fixture-secret"},
        )
        handler.on_tool_end(
            {"result": "missing"}, run_id=tool, parent_run_id=node_b
        )
        handler.on_chain_error(
            RuntimeError("node failed"), run_id=node_b, parent_run_id=graph
        )
        handler.on_chain_error(RuntimeError("graph failed"), run_id=graph)
        return stream.getvalue()


class _ConcurrentWriteDetector(StringIO):
    def __init__(self):
        super().__init__()
        self._writing = False
        self.overlapped = False

    def write(self, value):
        if self._writing:
            self.overlapped = True
        self._writing = True
        try:
            return super().write(value)
        finally:
            self._writing = False


if __name__ == "__main__":
    unittest.main()
