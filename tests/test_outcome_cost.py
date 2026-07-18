import json
import unittest

from agent_tail.cli import _markdown
from agent_tail.core import Event, TraceIndex
from agent_tail.serve import RunStore, _event_evidence, _outcome_cost


HUNK = {
    "path": "src/example.py",
    "old_start": 1,
    "old_count": 1,
    "new_start": 1,
    "new_count": 2,
}


def event_data(event_id, sequence, **changes):
    data = {
        "schema_version": "1.0",
        "event_id": event_id,
        "trace_id": "trace-outcome",
        "span_id": event_id,
        "emitter_id": "worker",
        "sequence": sequence,
        "timestamp": f"2026-07-18T12:00:{sequence:02d}Z",
        "kind": "activity.completed",
        "actor": {"id": "agent-a"},
        "operation": {"status": "completed", "name": "work"},
    }
    data.update(changes)
    return data


def relationship(target):
    return {"type": "contributes_to", "event_id": target}


def store_for(*events, **options):
    return RunStore.from_lines(
        [json.dumps(event) + "\n" for event in events],
        **options,
    )


class OutcomeCostTests(unittest.TestCase):
    def test_fractional_allocation_duplicates_and_mixed_metrics_conserve(self):
        events = [
            event_data("change-a", 1, kind="change.applied", attributes={"change": HUNK}),
            event_data("change-b", 2, kind="change.applied", attributes={
                "change": {**HUNK, "path": "tests/test_example.py"},
            }),
            event_data(
                "one-target", 3,
                actor={"id": "agent-b"},
                operation={"status": "completed", "name": "model"},
                usage={"input_tokens": 9, "cost_usd": 0},
                relationships=[relationship("change-a"), relationship("change-a")],
            ),
            event_data(
                "two-targets", 4,
                usage={"output_tokens": 5, "total_tokens": 7, "cost_usd": 0.3},
                relationships=[
                    relationship("change-a"), relationship("change-b"),
                    relationship("change-b"),
                ],
            ),
            event_data("pending", 5, usage={"output_tokens": 2}, relationships=[relationship("later")]),
            event_data("wrong-kind", 6, usage={"total_tokens": 4}, relationships=[relationship("one-target")]),
            event_data("unlinked", 7, usage={"input_tokens": 1}),
            event_data(
                "zero", 8,
                usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0},
                relationships=[relationship("change-a")],
            ),
            event_data("unknown", 9),
            event_data("malformed", 10, usage={
                "input_tokens": True,
                "output_tokens": "3",
                "total_tokens": float("nan"),
                "cost_usd": float("inf"),
            }),
        ]

        detail = store_for(*events).run_detail("trace-outcome")
        attribution = detail["outcome_cost"]
        hunks = {row["change_event_id"]: row for row in attribution["by_hunk"]}

        self.assertEqual(attribution["totals"], detail["usage"])
        self.assertEqual(attribution["allocation"]["attributed"]["input_tokens"]["value"], 9)
        self.assertEqual(attribution["allocation"]["pending"]["output_tokens"]["value"], 2)
        self.assertEqual(attribution["allocation"]["unattributed"]["input_tokens"]["value"], 1)
        self.assertEqual(attribution["allocation"]["unattributed"]["total_tokens"]["value"], 4)
        self.assertEqual(hunks["change-a"]["usage"]["input_tokens"]["value"], 9)
        self.assertEqual(hunks["change-a"]["usage"]["output_tokens"]["value"], 2.5)
        self.assertEqual(hunks["change-b"]["usage"]["output_tokens"]["value"], 2.5)
        self.assertEqual(hunks["change-a"]["usage"]["total_tokens"]["value"], 3.5)
        self.assertEqual(hunks["change-b"]["usage"]["total_tokens"]["value"], 3.5)
        self.assertEqual(hunks["change-a"]["usage"]["cost_usd"]["value"], 0.15)
        self.assertEqual(hunks["change-b"]["usage"]["cost_usd"]["value"], 0.15)
        self.assertEqual(hunks["change-a"]["contributing_event_ids"], [
            "one-target", "two-targets", "zero",
        ])
        self.assertEqual(attribution["pending"][0]["target_event_ids"], ["later"])
        self.assertEqual(
            {row["reason"] for row in attribution["unattributed"]},
            {"invalid_target", "no_contributes_to"},
        )
        self.assertTrue(hunks["change-a"]["usage"]["cost_usd"]["available"])
        self.assertFalse(hunks["change-b"]["usage"]["input_tokens"]["available"])

        for field in ("input_tokens", "output_tokens", "total_tokens", "cost_usd"):
            total = attribution["totals"][field]
            buckets = [attribution["allocation"][name][field] for name in (
                "attributed", "pending", "unattributed",
            )]
            if total["available"]:
                self.assertAlmostEqual(
                    total["value"],
                    sum(bucket["value"] for bucket in buckets if bucket["available"]),
                )

    def test_forward_reference_resolves_live_without_changing_totals(self):
        store = RunStore()
        store.feed_line(json.dumps(event_data(
            "usage", 1,
            usage={"input_tokens": 12, "cost_usd": 0.4},
            relationships=[relationship("change")],
        )) + "\n")

        before = store.run_detail("trace-outcome")["outcome_cost"]
        store.feed_line(json.dumps(event_data(
            "change", 2,
            kind="change.applied",
            attributes={"change": HUNK},
        )) + "\n")
        after = store.run_detail("trace-outcome")["outcome_cost"]

        self.assertEqual(before["totals"], after["totals"])
        self.assertEqual(before["allocation"]["pending"]["input_tokens"]["value"], 12)
        self.assertEqual(after["allocation"]["attributed"]["input_tokens"]["value"], 12)
        self.assertFalse(after["allocation"]["pending"]["input_tokens"]["available"])

    def test_retained_cross_trace_target_is_unattributed_not_pending(self):
        store = store_for(
            event_data(
                "usage", 1, usage={"input_tokens": 7},
                relationships=[relationship("other-change")],
            ),
            event_data(
                "other-change", 1, trace_id="trace-other",
                kind="change.applied", attributes={"change": HUNK},
            ),
        )

        attribution = store.run_detail("trace-outcome")["outcome_cost"]

        self.assertFalse(attribution["allocation"]["pending"]["input_tokens"]["available"])
        self.assertEqual(attribution["allocation"]["unattributed"]["input_tokens"]["value"], 7)
        self.assertEqual(attribution["unattributed"], [{
            "reason": "cross_trace_target",
            "event_count": 1,
            "usage": {
                "input_tokens": {"available": True, "value": 7},
                "output_tokens": {"available": False, "value": None},
                "total_tokens": {"available": False, "value": None},
                "cost_usd": {"available": False, "value": None},
            },
        }])

    def test_valid_target_wins_over_wrong_kind_cross_trace_and_missing_targets(self):
        usage = {
            "input_tokens": 8,
            "output_tokens": 4,
            "total_tokens": 12,
            "cost_usd": 0.6,
        }
        store = store_for(
            event_data("change", 1, kind="change.applied", attributes={"change": HUNK}),
            event_data("wrong-kind", 2),
            event_data(
                "usage", 3, usage=usage,
                relationships=[
                    relationship("change"),
                    relationship("wrong-kind"),
                    relationship("other-change"),
                    relationship("missing-forward"),
                ],
            ),
            event_data(
                "other-change", 1, trace_id="trace-other",
                kind="change.applied", attributes={"change": HUNK},
            ),
        )

        attribution = store.run_detail("trace-outcome")["outcome_cost"]
        hunk_usage = attribution["by_hunk"][0]["usage"]

        for field, value in usage.items():
            self.assertEqual(attribution["totals"][field]["value"], value)
            self.assertEqual(attribution["allocation"]["attributed"][field]["value"], value)
            self.assertEqual(hunk_usage[field]["value"], value)
            self.assertFalse(attribution["allocation"]["pending"][field]["available"])
            self.assertFalse(attribution["allocation"]["unattributed"][field]["available"])
        self.assertEqual(attribution["by_hunk"][0]["contributing_event_ids"], ["usage"])
        self.assertEqual(attribution["pending"], [])
        self.assertEqual(attribution["unattributed"], [])

    def test_missing_target_remains_pending_when_cross_trace_target_is_also_named(self):
        store = store_for(
            event_data(
                "usage", 1, usage={"input_tokens": 5},
                relationships=[
                    relationship("other-change"),
                    relationship("missing-forward"),
                ],
            ),
            event_data(
                "other-change", 1, trace_id="trace-other",
                kind="change.applied", attributes={"change": HUNK},
            ),
        )

        attribution = store.run_detail("trace-outcome")["outcome_cost"]

        self.assertEqual(attribution["allocation"]["pending"]["input_tokens"]["value"], 5)
        self.assertFalse(attribution["allocation"]["unattributed"]["input_tokens"]["available"])
        self.assertEqual(attribution["pending"][0]["target_event_ids"], ["missing-forward"])

    def test_known_evicted_target_is_unattributed_not_pending(self):
        source = Event.from_dict(event_data(
            "usage", 1,
            usage={"input_tokens": 3},
            relationships=[relationship("evicted-change")],
        ))
        index = TraceIndex()
        index.add(source)
        view = index.trace("trace-outcome")

        attribution = _outcome_cost(
            view,
            _event_evidence(view.events),
            [],
            evicted_event_ids={"evicted-change"},
        )

        self.assertFalse(attribution["allocation"]["pending"]["input_tokens"]["available"])
        self.assertEqual(attribution["allocation"]["unattributed"]["input_tokens"]["value"], 3)
        self.assertEqual(attribution["unattributed"][0]["reason"], "target_evicted")

    def test_correction_outcomes_use_only_causal_or_same_emitter_order(self):
        changes = [
            event_data("modified-change", 1, kind="change.applied", attributes={"change": HUNK}),
            event_data("reverted-change", 4, kind="change.applied", attributes={"change": {**HUNK, "new_start": 4}}),
            event_data("none-change", 8, kind="change.applied", attributes={"change": {**HUNK, "new_start": 8}}),
            event_data("unordered-change", 9, kind="change.applied", attributes={"change": {**HUNK, "new_start": 9}}),
            event_data("contradictory-change", 12, kind="change.applied", attributes={"change": {**HUNK, "new_start": 12}}),
        ]
        corrections = [
            event_data(
                "modified", 2, kind="human.corrected",
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "modified-change"}],
            ),
            event_data(
                "first", 5, kind="human.corrected",
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "reverted-change"}],
            ),
            event_data(
                "final", 6, kind="human.corrected",
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "corrects", "event_id": "reverted-change"}],
            ),
            event_data(
                "unordered-a", 1, emitter_id="human-a",
                timestamp="2026-07-18T13:00:00Z", kind="human.corrected",
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "unordered-change"}],
            ),
            event_data(
                "unordered-b", 1, emitter_id="human-b",
                timestamp="2026-07-18T14:00:00Z", kind="human.corrected",
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "corrects", "event_id": "unordered-change"}],
            ),
            event_data(
                "before", 11, kind="human.corrected",
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "corrects", "event_id": "contradictory-change"}],
            ),
        ]

        rows = {
            row["change_event_id"]: row["observed_outcome"]
            for row in store_for(*changes, *corrections).run_detail("trace-outcome")["outcome_cost"]["by_hunk"]
        }

        self.assertEqual(rows, {
            "modified-change": "modified",
            "reverted-change": "reverted",
            "none-change": "no_correction_observed",
            "unordered-change": "undetermined",
            "contradictory-change": "undetermined",
        })

    def test_causal_ancestry_orders_correction_despite_clock_skew(self):
        events = [
            event_data(
                "change", 1, emitter_id="agent", kind="change.applied",
                timestamp="2026-07-18T14:00:00Z",
                attributes={"change": HUNK},
            ),
            event_data(
                "bridge", 2, emitter_id="agent", kind="agent.started",
                span_id="bridge-span", timestamp="2026-07-18T14:00:01Z",
                operation={"status": "running", "name": "handoff"},
            ),
            event_data(
                "correction", 1, emitter_id="human", kind="human.corrected",
                parent_span_id="bridge-span", timestamp="2026-07-18T13:00:00Z",
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "change"}],
            ),
        ]

        row = store_for(*events).run_detail("trace-outcome")["outcome_cost"]["by_hunk"][0]

        self.assertEqual(row["observed_outcome"], "modified")

    def test_warning_associations_are_non_exclusive_and_do_not_change_totals(self):
        events = []
        for sequence, second in enumerate((0, 3, 5, 6), 1):
            events.append(event_data(
                f"failure-{sequence}", sequence,
                timestamp=f"2026-07-18T12:00:{second:02d}Z",
                kind="tool.call.failed",
                operation={"status": "failed", "name": "retry-work"},
                attributes={"arguments": {"path": "same.py"}},
                usage={"input_tokens": 1},
            ))

        attribution = store_for(*events, loop_threshold=4).run_detail("trace-outcome")["outcome_cost"]
        warning_rows = {row["warning_code"]: row for row in attribution["by_warning_code"]}

        self.assertEqual(attribution["warning_association"], "non_exclusive_do_not_sum")
        self.assertEqual(attribution["totals"]["input_tokens"]["value"], 4)
        self.assertEqual(warning_rows["LOOP"]["usage"]["input_tokens"]["value"], 4)
        self.assertEqual(warning_rows["RETRY"]["usage"]["input_tokens"]["value"], 3)
        self.assertEqual(len(warning_rows["LOOP"]["event_ids"]), 4)

    def test_warning_associations_cover_stall_orphan_verification_and_coordination(self):
        first_hunk = {**HUNK, "path": "src/shared.py"}
        second_hunk = {**first_hunk, "new_start": 8}
        events = [
            event_data(
                "stalled", 1, emitter_id="stalled", kind="tool.call.started",
                timestamp="2026-07-18T12:00:00Z", actor={"id": "stalled-agent"},
                operation={"status": "running", "name": "slow"},
                usage={"input_tokens": 3},
            ),
            event_data(
                "orphan", 1, emitter_id="orphan", parent_span_id="missing-span",
                timestamp="2026-07-18T12:00:01Z", actor={"id": "orphan-agent"},
                usage={"input_tokens": 4},
            ),
            event_data(
                "change-a", 1, emitter_id="change-a", kind="change.applied",
                timestamp="2026-07-18T12:00:02Z", actor={"id": "agent-a"},
                attributes={"change": first_hunk}, usage={"input_tokens": 5},
            ),
            event_data(
                "change-b", 1, emitter_id="change-b", kind="change.applied",
                timestamp="2026-07-18T12:00:02Z", actor={"id": "agent-b"},
                attributes={"change": second_hunk}, usage={"input_tokens": 6},
            ),
            event_data(
                "clock", 1, emitter_id="clock", timestamp="2026-07-18T12:01:00Z",
                actor={"id": "clock"},
            ),
        ]

        attribution = store_for(
            *events, stall_seconds=5,
        ).run_detail("trace-outcome")["outcome_cost"]
        rows = {row["warning_code"]: row for row in attribution["by_warning_code"]}

        for code in ("STALL", "ORPHAN", "UNCOVERED_CHANGE", "OVERLAPPING_CHANGE"):
            self.assertIn(code, rows)
        self.assertEqual(rows["STALL"]["usage"]["input_tokens"]["value"], 3)
        self.assertEqual(rows["ORPHAN"]["usage"]["input_tokens"]["value"], 4)
        self.assertEqual(rows["UNCOVERED_CHANGE"]["usage"]["input_tokens"]["value"], 11)
        self.assertEqual(rows["OVERLAPPING_CHANGE"]["usage"]["input_tokens"]["value"], 11)
        self.assertEqual(attribution["totals"]["input_tokens"]["value"], 18)

    def test_markdown_is_deterministic_and_uses_only_observed_labels(self):
        store = store_for(
            event_data("change", 1, kind="change.applied", attributes={"change": HUNK}),
            event_data(
                "usage", 2, usage={"input_tokens": 2},
                relationships=[relationship("change")],
            ),
        )
        index = store._index

        first = _markdown(index, [])
        second = _markdown(index, [])

        self.assertEqual(first, second)
        self.assertIn("### Outcome cost attribution", first)
        self.assertIn("no&#95;correction&#95;observed", first)
        self.assertIn("Warning associations are non-exclusive and must not be summed.", first)
        for judgment in ("accepted", "merged", "waste", "valuable"):
            self.assertNotIn(judgment, first.lower())


if __name__ == "__main__":
    unittest.main()
