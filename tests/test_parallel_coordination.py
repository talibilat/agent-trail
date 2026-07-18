import base64
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import re
import unittest

from agent_tail.core import Event, TraceIndex
from agent_tail.cli import _markdown, parser, serve_parser
from agent_tail.html_export import render_html
from agent_tail.review import ExportCandidate, inventory
from agent_tail.serve import RunStore


def event_data(event_id, *, actor="parent", emitter="parent-emitter", sequence=1,
               timestamp="2026-07-18T12:00:00Z", kind="agent.started",
               status="running", span_id=None, parent_span_id=None,
               attributes=None, relationships=None, usage=None):
    event = {
        "schema_version": "1.0",
        "event_id": event_id,
        "trace_id": "parallel-trace",
        "span_id": span_id or f"span-{event_id}",
        "emitter_id": emitter,
        "sequence": sequence,
        "timestamp": timestamp,
        "kind": kind,
        "actor": {"id": actor},
        "operation": {"status": status, "name": kind},
    }
    if parent_span_id is not None:
        event["parent_span_id"] = parent_span_id
    if attributes is not None:
        event["attributes"] = attributes
    if relationships is not None:
        event["relationships"] = relationships
    if usage is not None:
        event["usage"] = usage
    return event


def warnings(*events, threshold=8):
    index = TraceIndex(fan_out_threshold=threshold)
    for item in events:
        index.add(Event.from_dict(item))
    return index.warnings(now="2026-07-18T13:00:00Z")


def codes(*events, threshold=8):
    return [warning.code for warning in warnings(*events, threshold=threshold)]


def parent_start(**changes):
    return event_data("parent-start", span_id="parent-span", **changes)


def child_start(number, **changes):
    defaults = {
        "actor": f"child-{number}",
        "emitter": f"child-emitter-{number}",
        "sequence": 1,
        "timestamp": f"2026-07-18T12:00:0{number}Z",
        "parent_span_id": "parent-span",
    }
    defaults.update(changes)
    return event_data(f"child-{number}-start", **defaults)


class ParallelCoordinationTests(unittest.TestCase):
    def test_coordination_warning_cache_is_immutable_reused_and_trace_specific(self):
        change = {"change": {"path": "src/shared.py"}}
        index = TraceIndex()
        for item in (
            event_data(
                "change-a", actor="a", emitter="a", kind="change.applied",
                status="completed", attributes=change,
            ),
            event_data(
                "change-b", actor="b", emitter="b", kind="change.applied",
                status="completed", attributes=change,
            ),
        ):
            index.add(Event.from_dict(item))

        first = index._coordination_warnings(index.trace("parallel-trace"))
        second = index._coordination_warnings(index.trace("parallel-trace"))
        other_trace = event_data("other-trace-event")
        other_trace["trace_id"] = "other-trace"
        index.add(Event.from_dict(other_trace))

        self.assertIsInstance(first, tuple)
        self.assertIs(first, second)
        self.assertIs(index._coordination_warning_cache["parallel-trace"], first)
        self.assertNotIn("other-trace", index._coordination_warning_cache)

    def test_coordination_warning_cache_invalidates_for_late_consumes(self):
        index = TraceIndex()
        result = child_start(
            1, emitter="lifecycle", sequence=2,
            kind="agent.completed", status="completed",
        )
        parent_end = event_data(
            "parent-end", emitter="lifecycle", sequence=4,
            kind="agent.completed", status="completed",
        )
        for item in (parent_start(), result, parent_end):
            index.add(Event.from_dict(item))
        self.assertIn("UNCONSUMED_CHILD_RESULT", [item.code for item in index.warnings()])
        cached = index._coordination_warning_cache["parallel-trace"]

        index.add(Event.from_dict(event_data(
            "late-consume", emitter="lifecycle", sequence=3,
            relationships=[{"type": "consumes", "event_id": result["event_id"]}],
        )))

        self.assertNotIn("parallel-trace", index._coordination_warning_cache)
        self.assertNotIn("UNCONSUMED_CHILD_RESULT", [item.code for item in index.warnings()])
        self.assertIsNot(index._coordination_warning_cache["parallel-trace"], cached)

    def test_eviction_clears_coordination_warning_caches_for_all_traces(self):
        index = TraceIndex(max_bytes=1024 * 1024)
        index.add(Event.from_dict(event_data("trace-a")))
        index.warnings()
        cached = index._coordination_warning_cache["parallel-trace"]

        index.max_bytes = index._retained_bytes + 100
        other = event_data("large-other")
        other["trace_id"] = "other-trace"
        other["payload"] = {"text": "x" * 1000}
        index.add(Event.from_dict(other))

        self.assertGreater(index.eviction_count, 0)
        self.assertNotIn("parallel-trace", index._coordination_warning_cache)
        self.assertIsInstance(cached, tuple)

    def test_fan_out_threshold_cli_and_serve_options_are_positive_and_default_to_eight(self):
        self.assertEqual(parser().parse_args(["-"]).fan_out_threshold, 8)
        self.assertEqual(serve_parser().parse_args(["-"]).fan_out_threshold, 8)
        self.assertEqual(
            parser().parse_args(["-", "--fan-out-threshold", "3"]).fan_out_threshold,
            3,
        )
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            serve_parser().parse_args(["-", "--fan-out-threshold", "0"])

    def test_high_fan_out_counts_only_established_open_intervals(self):
        findings = warnings(
            parent_start(),
            child_start(1),
            child_start(2),
            child_start(3),
            threshold=2,
        )
        warning = next(item for item in findings if item.code == "HIGH_FAN_OUT")
        evidence = json.loads(warning.evidence)

        self.assertEqual(evidence["threshold"], 2)
        self.assertEqual(
            evidence["concurrent_child_ids"],
            ["child-1", "child-2", "child-3"],
        )
        self.assertEqual(evidence["concurrency_unknown_child_ids"], [])

    def test_high_fan_out_threshold_is_strict_and_equal_time_is_unknown(self):
        exact = [parent_start(), child_start(1), child_start(2)]
        equal = [
            parent_start(),
            child_start(1, timestamp="2026-07-18T12:00:01Z"),
            child_start(2, timestamp="2026-07-18T12:00:01Z"),
            child_start(3, timestamp="2026-07-18T12:00:01Z"),
        ]

        self.assertNotIn("HIGH_FAN_OUT", codes(*exact, threshold=2))
        self.assertNotIn("HIGH_FAN_OUT", codes(*equal, threshold=2))

    def test_high_fan_out_same_emitter_sequence_overrides_clock_skew(self):
        events = [parent_start()]
        for number, timestamp in ((1, "12:00:03"), (2, "12:00:02"), (3, "12:00:01")):
            events.append(child_start(
                number,
                emitter="scheduler",
                sequence=number,
                timestamp=f"2026-07-18T{timestamp}Z",
            ))

        self.assertIn("HIGH_FAN_OUT", codes(*events, threshold=2))

    def test_overlapping_change_requires_normalized_path_distinct_actors_and_no_order(self):
        first = event_data(
            "change-a", actor="actor-a", emitter="a", kind="change.applied",
            status="completed", attributes={"change": {
                "path": "src/./shared.py", "old_start": 1, "old_count": 1,
                "new_start": 1, "new_count": 1, "symbol": "shared",
            }}, usage={"input_tokens": 3},
        )
        second = event_data(
            "change-b", actor="actor-b", emitter="b", kind="change.applied",
            status="completed", attributes={"change": {
                "path": "src/shared.py", "old_start": 8, "old_count": 1,
                "new_start": 8, "new_count": 1, "symbol": "shared",
            }}, usage={"input_tokens": 5},
        )
        warning = next(item for item in warnings(first, second) if item.code == "OVERLAPPING_CHANGE")
        evidence = json.loads(warning.evidence)

        self.assertEqual(evidence["path"], "src/shared.py")
        self.assertEqual(evidence["matching_symbol"], "shared")
        self.assertEqual(evidence["causal_order"], "unknown")
        self.assertEqual(evidence["associated_usage"]["input_tokens"]["value"], 8)
        self.assertFalse(evidence["associated_usage"]["cost_usd"]["available"])

    def test_overlapping_change_rejects_known_sequence_same_actor_and_invalid_path(self):
        base = {"kind": "change.applied", "status": "completed"}
        change = {"change": {"path": "src/shared.py"}}
        sequential = [
            event_data("a", actor="a", emitter="one", sequence=1, attributes=change, **base),
            event_data("b", actor="b", emitter="one", sequence=2, attributes=change, **base),
        ]
        same_actor = [
            event_data("c", actor="a", emitter="one", attributes=change, **base),
            event_data("d", actor="a", emitter="two", attributes=change, **base),
        ]
        invalid = [
            event_data("e", actor="a", emitter="one", attributes={"change": {}}, **base),
            event_data("f", actor="b", emitter="two", attributes={"change": {}}, **base),
        ]

        for pair in (sequential, same_actor, invalid):
            self.assertNotIn("OVERLAPPING_CHANGE", codes(*pair))

    def test_redundant_search_requires_identical_signature_and_complete_snapshot(self):
        repository = {"commit": "abc123", "worktree_sha256": "a" * 64}
        def search(event_id, actor, emitter, query="needle", snapshot=repository):
            return event_data(
                event_id, actor=actor, emitter=emitter, kind="context.search",
                status="completed", attributes={
                    "search": {"query": query, "matches": ["src/./x.py"]},
                    **({"repository": snapshot} if snapshot is not None else {}),
                },
            )

        warning = next(item for item in warnings(
            search("search-a", "a", "a"),
            search("search-b", "b", "b"),
        ) if item.code == "REDUNDANT_OPERATION")
        evidence = json.loads(warning.evidence)
        self.assertEqual(evidence["operation_type"], "search")
        self.assertIn('"matches":["src/x.py"]', evidence["normalized_signature"])

        self.assertNotIn("REDUNDANT_OPERATION", codes(
            search("missing-a", "a", "a", snapshot=None),
            search("missing-b", "b", "b", snapshot=None),
        ))
        self.assertNotIn("REDUNDANT_OPERATION", codes(
            search("query-a", "a", "a"),
            search("query-b", "b", "b", query="other"),
        ))

    def test_redundant_verification_requires_valid_effective_command_and_same_snapshot(self):
        def verification(event_id, actor, emitter, worktree="a" * 64, command="pytest -q"):
            return event_data(
                event_id, actor=actor, emitter=emitter, kind="verification.finished",
                status="completed", attributes={
                    "verification": {"command": command, "passed": True},
                    "repository": {"commit": "abc123", "worktree_sha256": worktree},
                },
            )

        self.assertIn("REDUNDANT_OPERATION", codes(
            verification("verify-a", "a", "a"),
            verification("verify-b", "b", "b"),
        ))
        self.assertNotIn("REDUNDANT_OPERATION", codes(
            verification("snapshot-a", "a", "a", worktree="a" * 64),
            verification("snapshot-b", "b", "b", worktree="b" * 64),
        ))
        self.assertNotIn("REDUNDANT_OPERATION", codes(
            verification("invalid-a", "a", "a", command="  "),
            verification("invalid-b", "b", "b", command="  "),
        ))

    def test_unconsumed_child_result_requires_known_order_and_explicit_consumes(self):
        result = child_start(
            1, emitter="lifecycle", sequence=2, kind="agent.completed",
            status="completed", timestamp="2026-07-18T12:00:04Z",
        )
        parent_end = event_data(
            "parent-end", actor="parent", emitter="lifecycle", sequence=4,
            kind="agent.completed", status="completed",
        )
        self.assertIn("UNCONSUMED_CHILD_RESULT", codes(parent_start(), result, parent_end))

        consume = event_data(
            "consume", actor="parent", emitter="lifecycle", sequence=3,
            relationships=[{"type": "consumes", "event_id": result["event_id"]}],
        )
        self.assertNotIn(
            "UNCONSUMED_CHILD_RESULT",
            codes(parent_start(), result, consume, parent_end),
        )

        unknown_result = dict(result, emitter_id="child-clock", timestamp="2026-07-18T12:00:00Z")
        unknown_end = dict(parent_end, emitter_id="parent-clock", timestamp="2026-07-18T12:00:00Z")
        self.assertNotIn(
            "UNCONSUMED_CHILD_RESULT",
            codes(parent_start(), unknown_result, unknown_end),
        )

    def test_forward_consumes_and_late_reference_resolve_warning_history(self):
        store = RunStore()
        initial = [
            parent_start(),
            child_start(1, emitter="lifecycle", sequence=2, kind="agent.completed", status="completed"),
            event_data("parent-end", emitter="lifecycle", sequence=4, kind="agent.completed", status="completed"),
        ]
        for item in initial:
            store.feed_line(json.dumps(item) + "\n")
        before = store.run_detail("parallel-trace")["warnings"]
        self.assertTrue(any(item["code"] == "UNCONSUMED_CHILD_RESULT" and item["active"] for item in before))

        store.feed_line(json.dumps(event_data(
            "late-consume", emitter="lifecycle", sequence=3,
            relationships=[{"type": "consumes", "event_id": "child-1-start"}],
        )) + "\n")
        after = store.run_detail("parallel-trace")["warnings"]
        resolved = next(item for item in after if item["code"] == "UNCONSUMED_CHILD_RESULT")
        self.assertFalse(resolved["active"])
        self.assertIsNotNone(resolved["resolved_at"])

        forward = RunStore()
        for item in (parent_start(), event_data(
            "consume-forward", emitter="lifecycle", sequence=3,
            relationships=[{"type": "consumes", "event_id": "result-forward"}],
        ), event_data(
            "parent-forward-end", emitter="lifecycle", sequence=4,
            kind="agent.completed", status="completed",
        )):
            forward.feed_line(json.dumps(item) + "\n")
        self.assertNotIn(
            "UNCONSUMED_CHILD_RESULT",
            [item["code"] for item in forward.run_detail("parallel-trace")["warnings"]],
        )
        forward_result = child_start(
            1, emitter="lifecycle", sequence=2, kind="agent.completed", status="completed",
        )
        forward_result["event_id"] = "result-forward"
        forward.feed_line(json.dumps(forward_result) + "\n")
        self.assertNotIn(
            "UNCONSUMED_CHILD_RESULT",
            [item["code"] for item in forward.run_detail("parallel-trace")["warnings"] if item["active"]],
        )

    def test_child_after_parent_end_requires_causal_order_not_wall_clock(self):
        parent_end = event_data(
            "parent-end", emitter="lifecycle", sequence=3,
            timestamp="2026-07-18T12:00:09Z", kind="agent.completed", status="completed",
        )
        late = child_start(
            1, emitter="lifecycle", sequence=4,
            timestamp="2026-07-18T12:00:01Z",
        )
        self.assertIn("CHILD_AFTER_PARENT_END", codes(parent_start(), parent_end, late))

        independent = child_start(
            1, emitter="independent", sequence=1,
            timestamp="2026-07-18T12:00:10Z",
        )
        self.assertNotIn(
            "CHILD_AFTER_PARENT_END",
            codes(parent_start(), parent_end, independent),
        )

    def test_late_parent_start_resolves_topology_before_coordination_analysis(self):
        child = child_start(
            1, emitter="lifecycle", sequence=2, kind="agent.completed", status="completed",
        )
        parent_end = event_data(
            "parent-end", emitter="lifecycle", sequence=3,
            kind="agent.completed", status="completed",
        )
        index = TraceIndex()
        index.add(Event.from_dict(child))
        index.add(Event.from_dict(parent_end))
        self.assertNotIn("UNCONSUMED_CHILD_RESULT", [item.code for item in index.warnings()])

        index.add(Event.from_dict(parent_start(timestamp="2026-07-18T11:59:59Z")))
        self.assertIn("UNCONSUMED_CHILD_RESULT", [item.code for item in index.warnings()])

    def test_shared_warning_source_reaches_markdown_html_and_review(self):
        change = {"change": {"path": "src/shared.py"}}
        index = TraceIndex()
        for item in (
            event_data(
                "change-a", actor="a", emitter="a", kind="change.applied",
                status="completed", attributes=change,
            ),
            event_data(
                "change-b", actor="b", emitter="b", kind="change.applied",
                status="completed", attributes=change,
            ),
        ):
            index.add(Event.from_dict(item))

        markdown = _markdown(index, [])
        html = render_html(index, [], generated_at="2026-07-18T12:00:00Z")
        encoded = re.search(
            r'<div id="agent-tail-export-data" hidden>([^<]+)</div>', html
        ).group(1)
        snapshot = base64.b64decode(encoded).decode("utf-8")
        candidate = ExportCandidate.create(
            markdown,
            format="Markdown",
            destination=Path("report.md"),
        )
        review_inventory = inventory(index, [], candidate, metadata_only=False)

        self.assertIn("OVERLAPPING_CHANGE", markdown)
        self.assertIn("OVERLAPPING_CHANGE", snapshot)
        self.assertGreaterEqual(review_inventory["warning_count"], 1)


if __name__ == "__main__":
    unittest.main()
