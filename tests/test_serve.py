import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest import mock

from agent_tail import cli
import agent_tail.serve as serve_module
from agent_tail.serve import (
    RunStore,
    ServeConfig,
    make_server,
    serve,
    serve_file,
    start_file_follower,
)


def event_data(**changes):
    data = {
        "schema_version": "1.0",
        "event_id": "evt-1",
        "trace_id": "trace-1",
        "span_id": "span-1",
        "emitter_id": "worker-1",
        "sequence": 1,
        "timestamp": "2026-07-13T11:02:44.912Z",
        "kind": "tool.call.started",
        "actor": {"id": "reviewer-1"},
        "operation": {"status": "running", "name": "read_file"},
    }
    data.update(changes)
    return data


class ServeTests(unittest.TestCase):
    def _initial_uncertainty_lines(self):
        return [
            json.dumps(event_data(
                event_id="causal-1",
                trace_id="trace-causal",
                span_id="causal-span-1",
                emitter_id="causal-emitter",
                sequence=1,
            )) + "\n",
            json.dumps(event_data(
                event_id="causal-2",
                trace_id="trace-causal",
                span_id="causal-span-2",
                emitter_id="causal-emitter",
                sequence=2,
            )) + "\n",
            json.dumps(event_data(
                event_id="uncertain-1",
                trace_id="trace-uncertain",
                span_id="uncertain-span-1",
                emitter_id="uncertain-emitter-1",
                sequence=1,
            )) + "\n",
            json.dumps(event_data(
                event_id="uncertain-2",
                trace_id="trace-uncertain",
                span_id="uncertain-span-2",
                emitter_id="uncertain-emitter-2",
                sequence=1,
            )) + "\n",
        ]

    def _assert_replayed_uncertainty_matches_detail(self, store):
        stream = store.stream_updates(after=0)
        replayed = [next(stream) for _ in range(store.cursor)]
        replayed_uncertainty = {
            update["data"]["event_id"]: update["data"]["uncertain"]
            for update in replayed
            if update["type"] == "event"
        }
        detail_uncertainty = {
            event["event_id"]: event["uncertain"]
            for trace_id in ("trace-causal", "trace-uncertain")
            for event in store.run_detail(trace_id)["events"]
        }

        self.assertEqual(replayed_uncertainty, detail_uncertainty)
        self.assertEqual(replayed_uncertainty["causal-1"], False)
        self.assertEqual(replayed_uncertainty["causal-2"], False)
        self.assertEqual(replayed_uncertainty["uncertain-1"], True)
        self.assertEqual(replayed_uncertainty["uncertain-2"], True)

    def test_from_lines_reconciles_replayed_initial_uncertainty(self):
        store = RunStore.from_lines(self._initial_uncertainty_lines())

        self._assert_replayed_uncertainty_matches_detail(store)

    def test_serve_file_reconciles_replayed_initial_uncertainty(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "initial.jsonl")
            source.write_text(
                "".join(self._initial_uncertainty_lines()), encoding="utf-8"
            )
            captured = []
            with mock.patch.object(
                serve_module,
                "_serve_store",
                side_effect=lambda store, **_: captured.append(store) or 0,
            ):
                result = serve_file(source, config=ServeConfig(port=0))

        self.assertEqual(result, 0)
        self._assert_replayed_uncertainty_matches_detail(captured[0])

    def test_store_lists_and_details_sanitized_runs(self):
        secret = "ghp_" + "a" * 36
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id=secret,
                payload={"token": "Bearer payload-secret", "text": "safe"},
            )) + "\n",
            "not json\n",
        ])

        runs = store.list_runs()
        detail = store.run_detail("trace-1")
        encoded = json.dumps(detail)

        self.assertEqual(runs["api_version"], "v1")
        self.assertEqual(runs["runs"][0]["trace_id"], "trace-1")
        self.assertEqual(runs["ingestion_errors"][0]["line"], 2)
        self.assertEqual(detail["api_version"], "v1")
        self.assertEqual(detail["run"]["event_count"], 1)
        self.assertIn("[REDACTED", detail["events"][0]["event_id"])
        self.assertNotIn(secret, encoded)
        self.assertNotIn("payload-secret", encoded)

    def test_store_exposes_relationships_in_snapshots_and_live_events(self):
        store = RunStore()
        store.feed_line(json.dumps(event_data(relationships=[{
            "type": "motivated_by",
            "event_id": "requirement-1",
        }])) + "\n")

        detail = store.run_detail("trace-1")
        update = next(store.stream_updates(after=0))
        expected = [{"type": "motivated_by", "event_id": "requirement-1"}]

        self.assertEqual(detail["events"][0]["relationships"], expected)
        self.assertEqual(update["type"], "event")
        self.assertEqual(update["data"]["relationships"], expected)

    def test_live_update_journal_bounds_history_and_replays_retained_boundary(self):
        store = RunStore(max_live_updates=3)
        for number in range(1, 5):
            store.add_finding("test", f"FINDING_{number}", f"finding {number}")

        retained = store.stream_updates(after=1)

        self.assertEqual(
            [next(retained)["cursor"] for _ in range(3)],
            [2, 3, 4],
        )
        self.assertEqual(len(store._updates), 3)
        self.assertEqual(store.cursor, 4)

    def test_stale_and_future_cursors_reset_without_advancing_cursor(self):
        store = RunStore(max_live_updates=2)
        for number in range(1, 4):
            store.add_finding("test", f"FINDING_{number}", f"finding {number}")

        for requested in (0, 4):
            with self.subTest(requested=requested):
                update = next(store.stream_updates(after=requested))
                self.assertEqual(update, {
                    "cursor": 3,
                    "type": "reset",
                    "data": {
                        "requested_cursor": requested,
                        "oldest_retained_cursor": 2,
                        "current_cursor": 3,
                        "reason": "history_gap",
                    },
                })
                self.assertEqual(store.cursor, 3)

    def test_live_update_limits_must_be_positive_in_config_and_store(self):
        for value in (0, -1, True, 1.5, "10"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    ServeConfig(max_live_updates=value)
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    RunStore(max_live_updates=value)

    def test_run_evidence_map_resolves_forward_references_and_reports_missing(self):
        store = RunStore()
        store.feed_line(json.dumps(event_data(
            event_id="change-1",
            kind="change.applied",
            relationships=[
                {"type": "motivated_by", "event_id": "requirement-1"},
                {"type": "verified_by", "event_id": "missing-test"},
            ],
        )) + "\n")

        before_target = store.run_detail("trace-1")["evidence_map"]
        store.feed_line(json.dumps(event_data(
            event_id="requirement-1",
            emitter_id="requirements",
            span_id="span-2",
            sequence=2,
            timestamp="2026-07-13T11:01:00Z",
            kind="requirement.observed",
            actor={"id": "user"},
            attributes={"requirement": {
                "id": "R1",
                "text": "Resolve the forward requirement.",
            }},
        )) + "\n")
        after_target = store.run_detail("trace-1")["evidence_map"]

        unresolved_requirement = {
            "type": "motivated_by",
            "source_event_id": "change-1",
            "target_event_id": "requirement-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
        }
        self.assertIn(unresolved_requirement, before_target["unresolved"])
        self.assertEqual(after_target["links"], [{
            **unresolved_requirement,
            "target_kind": "requirement.observed",
            "target_actor_id": "user",
            "chronology": "before_change",
            "requirement": {
                "id": "R1",
                "text": "Resolve the forward requirement.",
            },
        }])
        self.assertEqual(after_target["unresolved"], [{
            **unresolved_requirement,
            "type": "verified_by",
            "target_event_id": "missing-test",
        }])

    def test_evidence_map_deduplicates_identical_relationships(self):
        relationships = [
            {"type": "verified_by", "event_id": "verification-1"},
            {"type": "verified_by", "event_id": "verification-1"},
            {"type": "reviewed_by", "event_id": "missing-review"},
            {"type": "reviewed_by", "event_id": "missing-review"},
        ]
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=relationships,
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-1",
                span_id="span-2",
                sequence=2,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": False,
                    "test_origin": "same_agent",
                }},
            )) + "\n",
        ])

        detail = store.run_detail("trace-1")
        change = detail["evidence_map"]["changes"][0]

        self.assertEqual(detail["events"][0]["relationships"], relationships)
        self.assertEqual(len(change["links"]), 1)
        self.assertEqual(len(change["unresolved"]), 1)
        self.assertEqual(len(detail["evidence_map"]["links"]), 1)
        self.assertEqual(len(detail["evidence_map"]["unresolved"]), 1)
        self.assertEqual(change["coverage"]["same_agent_test_count"], 1)
        self.assertEqual(change["coverage"]["failed_verification_count"], 1)

    def test_run_evidence_map_projects_valid_change_hunks(self):
        valid_hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
            "symbol": "reject_expired_session",
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": valid_hunk},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-2",
                span_id="span-2",
                sequence=2,
                kind="change.applied",
                attributes={"change": {
                    **valid_hunk,
                    "path": "tests/test_session.py",
                    "new_start": 91,
                    "symbol": " \t\n",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-1",
                span_id="span-3",
                sequence=3,
                kind="change.proposed",
                attributes={"change": valid_hunk},
            )) + "\n",
            json.dumps(event_data(
                event_id="invalid-change",
                span_id="span-4",
                sequence=4,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "old_start": True}},
            )) + "\n",
            json.dumps(event_data(
                event_id="blank-path-change",
                span_id="span-5",
                sequence=5,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "path": " \t\n"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="invalid-zero-new-start-change",
                span_id="span-6",
                sequence=6,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "new_start": 0}},
            )) + "\n",
            json.dumps(event_data(
                event_id="invalid-zero-old-start-change",
                span_id="span-7",
                sequence=7,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "old_start": 0}},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"], [
            {
                "event_id": "change-1",
                "actor_id": "reviewer-1",
                "hunk": valid_hunk,
                "links": [],
                "unresolved": [],
                "corrections": [],
                "coverage": {
                    "status": "incomplete",
                    "missing": ["requirement", "context", "tool", "verification", "decision"],
                    "unresolved_count": 0,
                },
            },
            {
                "event_id": "change-2",
                "actor_id": "reviewer-1",
                "hunk": {
                    "path": "tests/test_session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 91,
                    "new_count": 19,
                },
                "links": [],
                "unresolved": [],
                "corrections": [],
                "coverage": {
                    "status": "incomplete",
                    "missing": ["requirement", "context", "tool", "verification", "decision"],
                    "unresolved_count": 0,
                    "integrity_issue_count": 1,
                },
                "integrity": [{
                    "field": "symbol",
                    "reason": "invalid_change_symbol",
                }],
            },
        ])
        self.assertEqual(evidence["links"], [])
        self.assertEqual(evidence["unresolved"], [])
        self.assertEqual(evidence["invalid_changes"], [
            {
                "event_id": "invalid-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "old_start",
                    "reason": "invalid_change_old_start",
                }],
            },
            {
                "event_id": "blank-path-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "path",
                    "reason": "invalid_change_path",
                }],
            },
            {
                "event_id": "invalid-zero-new-start-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "new_start",
                    "reason": "invalid_change_new_start",
                }],
            },
            {
                "event_id": "invalid-zero-old-start-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "old_start",
                    "reason": "invalid_change_old_start",
                }],
            },
        ])

    def test_invalid_change_path_remains_traceable(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="invalid-path-change",
                kind="change.applied",
                actor={"id": "implementer-1"},
                attributes={"change": {
                    "path": ["src/auth/session.py"],
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                    "symbol": "reject_expired_session",
                }},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"], [])
        self.assertEqual(evidence["invalid_changes"], [{
            "event_id": "invalid-path-change",
            "actor_id": "implementer-1",
            "integrity": [{
                "field": "path",
                "reason": "invalid_change_path",
            }],
        }])

    def test_invalid_change_detail_remains_traceable(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="missing-change-detail",
                kind="change.applied",
                actor={"id": "implementer-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="non-object-change-detail",
                span_id="span-2",
                sequence=2,
                kind="change.applied",
                actor={"id": "implementer-2"},
                attributes={"change": ["src/auth/session.py"]},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"], [])
        self.assertEqual(evidence["invalid_changes"], [
            {
                "event_id": "missing-change-detail",
                "actor_id": "implementer-1",
                "integrity": [{
                    "field": "change",
                    "reason": "invalid_change_detail",
                }],
            },
            {
                "event_id": "non-object-change-detail",
                "actor_id": "implementer-2",
                "integrity": [{
                    "field": "change",
                    "reason": "invalid_change_detail",
                }],
            },
        ])

    def test_invalid_change_old_count_remains_traceable(self):
        valid_hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="boolean-old-count-change",
                kind="change.applied",
                attributes={"change": {**valid_hunk, "old_count": True}},
            )) + "\n",
            json.dumps(event_data(
                event_id="negative-old-count-change",
                span_id="span-2",
                sequence=2,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "old_count": -1}},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"], [])
        self.assertEqual(evidence["invalid_changes"], [
            {
                "event_id": "boolean-old-count-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "old_count",
                    "reason": "invalid_change_old_count",
                }],
            },
            {
                "event_id": "negative-old-count-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "old_count",
                    "reason": "invalid_change_old_count",
                }],
            },
        ])

    def test_invalid_change_new_start_remains_traceable(self):
        valid_hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="boolean-new-start-change",
                kind="change.applied",
                attributes={"change": {**valid_hunk, "new_start": True}},
            )) + "\n",
            json.dumps(event_data(
                event_id="zero-new-start-change",
                span_id="span-2",
                sequence=2,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "new_start": 0}},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"], [])
        self.assertEqual(evidence["invalid_changes"], [
            {
                "event_id": "boolean-new-start-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "new_start",
                    "reason": "invalid_change_new_start",
                }],
            },
            {
                "event_id": "zero-new-start-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "new_start",
                    "reason": "invalid_change_new_start",
                }],
            },
        ])

    def test_invalid_change_new_count_remains_traceable(self):
        valid_hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="boolean-new-count-change",
                kind="change.applied",
                attributes={"change": {**valid_hunk, "new_count": True}},
            )) + "\n",
            json.dumps(event_data(
                event_id="negative-new-count-change",
                span_id="span-2",
                sequence=2,
                kind="change.applied",
                attributes={"change": {**valid_hunk, "new_count": -1}},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"], [])
        self.assertEqual(evidence["invalid_changes"], [
            {
                "event_id": "boolean-new-count-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "new_count",
                    "reason": "invalid_change_new_count",
                }],
            },
            {
                "event_id": "negative-new-count-change",
                "actor_id": "reviewer-1",
                "integrity": [{
                    "field": "new_count",
                    "reason": "invalid_change_new_count",
                }],
            },
        ])

    def test_invalid_change_symbol_reduces_complete_coverage(self):
        targets = [
            event_data(
                event_id="requirement-1",
                timestamp="2026-07-13T10:59:00Z",
                kind="requirement.observed",
                attributes={"requirement": {"id": "R3", "text": "Reject expiry."}},
            ),
            event_data(
                event_id="context-1",
                sequence=2,
                timestamp="2026-07-13T10:59:00Z",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            ),
            event_data(
                event_id="tool-1",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --check"}},
            ),
            event_data(
                event_id="verification-1",
                sequence=4,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(
                event_id="proposal-1",
                emitter_id="change-worker",
                sequence=5,
                kind="change.proposed",
            ),
            event_data(
                event_id="change-1",
                emitter_id="change-worker",
                sequence=6,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                    "symbol": ["not-a-symbol"],
                }},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-1"},
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "preceded_by", "event_id": "tool-1"},
                    {"type": "verified_by", "event_id": "verification-1"},
                    {"type": "applies", "event_id": "proposal-1"},
                ],
            ),
        ]
        store = RunStore.from_lines(json.dumps(event) + "\n" for event in targets)

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertNotIn("symbol", change["hunk"])
        self.assertEqual(change["integrity"], [{
            "field": "symbol",
            "reason": "invalid_change_symbol",
        }])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": [],
            "unresolved_count": 0,
            "integrity_issue_count": 1,
        })

    def test_tool_after_change_uses_same_emitter_sequence_ordering(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="tool-after-change",
                emitter_id="worker-2",
                timestamp="2026-07-13T11:03:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --check"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-same-time-after-change",
                span_id="span-same-time-tool",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git status --short"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-clock-skew-after-change",
                span_id="span-skewed-tool",
                sequence=4,
                timestamp="2026-07-13T11:01:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --stat"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-same-time-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-tool",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git status --porcelain"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "preceded_by", "event_id": "tool-after-change"},
                    {
                        "type": "preceded_by",
                        "event_id": "tool-same-time-after-change",
                    },
                    {
                        "type": "preceded_by",
                        "event_id": "tool-clock-skew-after-change",
                    },
                    {
                        "type": "preceded_by",
                        "event_id": "tool-same-time-other-emitter",
                    },
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["tool"]["command"], "git diff --check")
        self.assertEqual(
            [item["target_event_id"] for item in change["unresolved"]],
            [
                "tool-after-change",
                "tool-same-time-after-change",
                "tool-clock-skew-after-change",
                "tool-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            [
                "tool_not_preceding_change",
                "tool_not_preceding_change",
                "tool_not_preceding_change",
                "tool_chronology_undetermined",
            ],
        )
        self.assertNotIn("decision_event_id", change["unresolved"][-1])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "verification", "decision"],
            "unresolved_count": 4,
        })

    def test_equal_same_emitter_sequences_have_undetermined_chronology(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="tool-equal-sequence",
                timestamp="2026-07-13T11:01:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --check"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{
                    "type": "preceded_by",
                    "event_id": "tool-equal-sequence",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["chronology"], "undetermined")
        self.assertEqual(change["unresolved"], [{
            "type": "preceded_by",
            "source_event_id": "change-1",
            "target_event_id": "tool-equal-sequence",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "tool.call.completed",
            "reason": "tool_chronology_undetermined",
        }])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "verification", "decision"],
            "unresolved_count": 1,
        })

    def test_tool_after_decision_is_incomplete_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="proposal-1",
                timestamp="2026-07-13T11:01:00Z",
                kind="change.proposed",
                actor={"id": "planner-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-same-time",
                span_id="span-current-tool",
                sequence=2,
                timestamp="2026-07-13T11:01:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git status --short"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-clock-skew",
                span_id="span-skewed-tool",
                sequence=3,
                timestamp="2026-07-13T11:00:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --stat"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-tool",
                sequence=1,
                timestamp="2026-07-13T11:01:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git status --porcelain"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-after-decision",
                span_id="span-late-tool",
                sequence=4,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --check"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=5,
                timestamp="2026-07-13T11:03:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "applies", "event_id": "proposal-1"},
                    {"type": "preceded_by", "event_id": "tool-same-time"},
                    {"type": "preceded_by", "event_id": "tool-clock-skew"},
                    {"type": "preceded_by", "event_id": "tool-other-emitter"},
                    {"type": "preceded_by", "event_id": "tool-after-decision"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        chronology_by_event = {
            link["target_event_id"]: link["chronology"]
            for link in change["links"]
            if link["target_kind"].startswith("tool.call.")
        }
        self.assertEqual(chronology_by_event, {
            "tool-same-time": "after_decision",
            "tool-clock-skew": "after_decision",
            "tool-other-emitter": "undetermined",
            "tool-after-decision": "after_decision",
        })
        self.assertEqual({
            link["target_event_id"]: link["decision_event_id"]
            for link in change["links"]
            if link["target_kind"].startswith("tool.call.")
        }, {
            "tool-same-time": "proposal-1",
            "tool-clock-skew": "proposal-1",
            "tool-other-emitter": "proposal-1",
            "tool-after-decision": "proposal-1",
        })
        self.assertEqual(change["unresolved"], [
            {
                "type": "preceded_by",
                "source_event_id": "change-1",
                "target_event_id": "tool-same-time",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "tool.call.completed",
                "reason": "tool_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "preceded_by",
                "source_event_id": "change-1",
                "target_event_id": "tool-clock-skew",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "tool.call.completed",
                "reason": "tool_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "preceded_by",
                "source_event_id": "change-1",
                "target_event_id": "tool-other-emitter",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "tool.call.completed",
                "reason": "tool_chronology_undetermined",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "preceded_by",
                "source_event_id": "change-1",
                "target_event_id": "tool-after-decision",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "tool.call.completed",
                "reason": "tool_follows_decision",
                "decision_event_id": "proposal-1",
            },
        ])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "verification"],
            "unresolved_count": 4,
        })

    def test_earliest_decision_uses_same_emitter_sequence_ordering(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="proposal-earliest",
                sequence=1,
                timestamp="2026-07-13T11:03:00Z",
                kind="change.proposed",
                actor={"id": "planner-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-after-earliest",
                span_id="span-tool",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --check"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-later",
                span_id="span-later-proposal",
                sequence=3,
                timestamp="2026-07-13T11:01:00Z",
                kind="change.proposed",
                actor={"id": "planner-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=4,
                timestamp="2026-07-13T11:04:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "applies", "event_id": "proposal-earliest"},
                    {"type": "applies", "event_id": "proposal-later"},
                    {"type": "preceded_by", "event_id": "tool-after-earliest"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["unresolved"], [{
            "type": "preceded_by",
            "source_event_id": "change-1",
            "target_event_id": "tool-after-earliest",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "tool.call.completed",
            "reason": "tool_follows_decision",
            "decision_event_id": "proposal-earliest",
        }])
        self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_requirement_after_change_uses_same_emitter_sequence_ordering(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="requirement-after-change",
                emitter_id="worker-2",
                timestamp="2026-07-13T11:03:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-late",
                    "text": "Requirement recorded after implementation.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-same-time-after-change",
                span_id="span-same-time-requirement",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-equal",
                    "text": "Requirement recorded at the change timestamp.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-clock-skew-after-change",
                span_id="span-skewed-requirement",
                sequence=4,
                timestamp="2026-07-13T11:01:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-skewed",
                    "text": "Requirement recorded after the change by sequence.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-same-time-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-requirement",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-other-emitter",
                    "text": "Requirement recorded at the same timestamp elsewhere.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-after-change"},
                    {
                        "type": "motivated_by",
                        "event_id": "requirement-same-time-after-change",
                    },
                    {
                        "type": "motivated_by",
                        "event_id": "requirement-clock-skew-after-change",
                    },
                    {
                        "type": "motivated_by",
                        "event_id": "requirement-same-time-other-emitter",
                    },
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(
            [link["requirement"]["id"] for link in change["links"]],
            ["R-late", "R-equal", "R-skewed", "R-other-emitter"],
        )
        self.assertEqual(
            {
                link["target_event_id"]: link["chronology"]
                for link in change["links"]
                if link["target_kind"] == "requirement.observed"
            },
            {
                "requirement-after-change": "after_change",
                "requirement-same-time-after-change": "after_change",
                "requirement-clock-skew-after-change": "after_change",
                "requirement-same-time-other-emitter": "undetermined",
            },
        )
        self.assertEqual(
            [item["target_event_id"] for item in change["unresolved"]],
            [
                "requirement-after-change",
                "requirement-same-time-after-change",
                "requirement-clock-skew-after-change",
                "requirement-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            [
                "requirement_not_preceding_change",
                "requirement_not_preceding_change",
                "requirement_not_preceding_change",
                "requirement_chronology_undetermined",
            ],
        )
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["context", "tool", "verification", "decision"],
            "unresolved_count": 4,
        })

    def test_requirement_observed_after_decision_is_incomplete_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="proposal-1",
                timestamp="2026-07-13T11:01:00Z",
                kind="change.proposed",
                actor={"id": "planner-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-same-time",
                span_id="span-current-requirement",
                sequence=2,
                timestamp="2026-07-13T11:01:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-current",
                    "text": "Requirement observed at decision time.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-after-decision",
                span_id="span-late-requirement",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-late",
                    "text": "Requirement observed after the decision.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-clock-skew",
                span_id="span-skewed-requirement",
                sequence=4,
                timestamp="2026-07-13T11:00:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-skewed",
                    "text": "Requirement observed after the decision by sequence.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="requirement-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-requirement",
                sequence=1,
                timestamp="2026-07-13T11:01:00Z",
                kind="requirement.observed",
                attributes={"requirement": {
                    "id": "R-concurrent",
                    "text": "Requirement observed concurrently by another emitter.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=5,
                timestamp="2026-07-13T11:03:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "applies", "event_id": "proposal-1"},
                    {"type": "motivated_by", "event_id": "requirement-same-time"},
                    {"type": "motivated_by", "event_id": "requirement-after-decision"},
                    {"type": "motivated_by", "event_id": "requirement-clock-skew"},
                    {"type": "motivated_by", "event_id": "requirement-other-emitter"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(
            {
                link["target_event_id"]: link["chronology"]
                for link in change["links"]
                if link["target_kind"] == "requirement.observed"
            },
            {
                "requirement-same-time": "after_decision",
                "requirement-after-decision": "after_decision",
                "requirement-clock-skew": "after_decision",
                "requirement-other-emitter": "undetermined",
            },
        )
        self.assertEqual(
            {
                link["target_event_id"]: link["decision_event_id"]
                for link in change["links"]
                if link["target_kind"] == "requirement.observed"
            },
            {
                "requirement-same-time": "proposal-1",
                "requirement-after-decision": "proposal-1",
                "requirement-clock-skew": "proposal-1",
                "requirement-other-emitter": "proposal-1",
            },
        )
        self.assertEqual(change["unresolved"], [
            {
                "type": "motivated_by",
                "source_event_id": "change-1",
                "target_event_id": "requirement-same-time",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "requirement.observed",
                "reason": "requirement_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "motivated_by",
                "source_event_id": "change-1",
                "target_event_id": "requirement-after-decision",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "requirement.observed",
                "reason": "requirement_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "motivated_by",
                "source_event_id": "change-1",
                "target_event_id": "requirement-clock-skew",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "requirement.observed",
                "reason": "requirement_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "motivated_by",
                "source_event_id": "change-1",
                "target_event_id": "requirement-other-emitter",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "requirement.observed",
                "reason": "requirement_chronology_undetermined",
                "decision_event_id": "proposal-1",
            },
        ])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["context", "tool", "verification"],
            "unresolved_count": 4,
        })

    def test_context_read_after_change_uses_same_emitter_sequence_ordering(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-after-change",
                emitter_id="worker-2",
                timestamp="2026-07-13T11:03:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/late-context.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-same-time-after-change",
                span_id="span-same-time-context",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/current-context.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-clock-skew-after-change",
                span_id="span-skewed-context",
                sequence=4,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/skewed-context.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-same-time-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-context",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/concurrent-context.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "informed_by", "event_id": "context-after-change"},
                    {
                        "type": "informed_by",
                        "event_id": "context-same-time-after-change",
                    },
                    {
                        "type": "informed_by",
                        "event_id": "context-clock-skew-after-change",
                    },
                    {
                        "type": "informed_by",
                        "event_id": "context-same-time-other-emitter",
                    },
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(
            [link["context"]["path"] for link in change["links"]],
            [
                "docs/late-context.md",
                "docs/current-context.md",
                "docs/skewed-context.md",
                "docs/concurrent-context.md",
            ],
        )
        self.assertEqual(
            [item["target_event_id"] for item in change["unresolved"]],
            [
                "context-after-change",
                "context-same-time-after-change",
                "context-clock-skew-after-change",
                "context-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            [
                "context_not_preceding_change",
                "context_not_preceding_change",
                "context_not_preceding_change",
                "context_chronology_undetermined",
            ],
        )
        self.assertNotIn("decision_event_id", change["unresolved"][-1])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification", "decision"],
            "unresolved_count": 4,
        })

    def test_context_compacted_after_change_cannot_be_informing_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-1",
                timestamp="2026-07-13T11:01:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/session-lifecycle.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-after-change",
                emitter_id="worker-2",
                span_id="span-late-compaction",
                sequence=2,
                timestamp="2026-07-13T11:03:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-same-time-before-change",
                span_id="span-current-compaction",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-same-time-after-change",
                span_id="span-equal-late-compaction",
                sequence=5,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-clock-skew-after-change",
                span_id="span-skewed-late-compaction",
                sequence=6,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-same-time-other-emitter",
                emitter_id="worker-3",
                span_id="span-concurrent-compaction",
                sequence=7,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                sequence=4,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "informed_by", "event_id": "compaction-after-change"},
                    {
                        "type": "informed_by",
                        "event_id": "compaction-same-time-before-change",
                    },
                    {
                        "type": "informed_by",
                        "event_id": "compaction-same-time-after-change",
                    },
                    {
                        "type": "informed_by",
                        "event_id": "compaction-clock-skew-after-change",
                    },
                    {
                        "type": "informed_by",
                        "event_id": "compaction-same-time-other-emitter",
                    },
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(
            [link["target_event_id"] for link in change["links"]],
            [
                "compaction-after-change",
                "compaction-same-time-before-change",
                "compaction-same-time-after-change",
                "compaction-clock-skew-after-change",
                "compaction-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            [item["target_event_id"] for item in change["unresolved"]],
            [
                "compaction-after-change",
                "compaction-same-time-after-change",
                "compaction-clock-skew-after-change",
                "compaction-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            [
                "compaction_not_preceding_change",
                "compaction_not_preceding_change",
                "compaction_not_preceding_change",
                "compaction_chronology_undetermined",
            ],
        )
        self.assertNotIn("decision_event_id", change["unresolved"][-1])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification", "decision"],
            "unresolved_count": 4,
        })

    def test_context_read_after_decision_is_incomplete_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="proposal-1",
                timestamp="2026-07-13T11:01:00Z",
                kind="change.proposed",
                actor={"id": "planner-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-same-time",
                span_id="span-current-context",
                sequence=2,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/current.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-after-decision",
                span_id="span-late-context",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/late.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-clock-skew",
                span_id="span-skewed-context",
                sequence=4,
                timestamp="2026-07-13T11:00:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/skewed.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-context",
                sequence=1,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/concurrent.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=5,
                timestamp="2026-07-13T11:03:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "applies", "event_id": "proposal-1"},
                    {"type": "informed_by", "event_id": "context-same-time"},
                    {"type": "informed_by", "event_id": "context-after-decision"},
                    {"type": "informed_by", "event_id": "context-clock-skew"},
                    {"type": "informed_by", "event_id": "context-other-emitter"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        chronology_by_event = {
            link["target_event_id"]: link["chronology"]
            for link in change["links"]
            if link["target_kind"] == "context.read"
        }
        self.assertEqual(chronology_by_event, {
            "context-same-time": "after_decision",
            "context-after-decision": "after_decision",
            "context-clock-skew": "after_decision",
            "context-other-emitter": "undetermined",
        })
        self.assertEqual({
            link["target_event_id"]: link["decision_event_id"]
            for link in change["links"]
            if link["target_kind"] == "context.read"
        }, {
            "context-same-time": "proposal-1",
            "context-after-decision": "proposal-1",
            "context-clock-skew": "proposal-1",
            "context-other-emitter": "proposal-1",
        })
        self.assertEqual(change["unresolved"], [
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "context-same-time",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.read",
                "reason": "context_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "context-after-decision",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.read",
                "reason": "context_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "context-clock-skew",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.read",
                "reason": "context_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "context-other-emitter",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.read",
                "reason": "context_chronology_undetermined",
                "decision_event_id": "proposal-1",
            },
        ])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification"],
            "unresolved_count": 4,
        })

    def test_context_compacted_after_decision_is_incomplete_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-1",
                timestamp="2026-07-13T11:00:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/session-lifecycle.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-1",
                span_id="span-proposal",
                sequence=2,
                timestamp="2026-07-13T11:01:00Z",
                kind="change.proposed",
                actor={"id": "planner-1"},
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-same-time",
                span_id="span-current-compaction",
                sequence=3,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-after-decision",
                span_id="span-late-compaction",
                sequence=4,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-clock-skew",
                span_id="span-skewed-compaction",
                sequence=5,
                timestamp="2026-07-13T11:00:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter-compaction",
                sequence=1,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=6,
                timestamp="2026-07-13T11:03:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "applies", "event_id": "proposal-1"},
                    {"type": "informed_by", "event_id": "compaction-same-time"},
                    {"type": "informed_by", "event_id": "compaction-after-decision"},
                    {"type": "informed_by", "event_id": "compaction-clock-skew"},
                    {"type": "informed_by", "event_id": "compaction-other-emitter"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        chronology_by_event = {
            link["target_event_id"]: link["chronology"]
            for link in change["links"]
            if link["target_kind"] == "context.compacted"
        }
        self.assertEqual(chronology_by_event, {
            "compaction-same-time": "after_decision",
            "compaction-after-decision": "after_decision",
            "compaction-clock-skew": "after_decision",
            "compaction-other-emitter": "undetermined",
        })
        self.assertEqual(
            {
                link["target_event_id"]: link["decision_event_id"]
                for link in change["links"]
                if link["target_kind"] == "context.compacted"
            },
            {
                "compaction-same-time": "proposal-1",
                "compaction-after-decision": "proposal-1",
                "compaction-clock-skew": "proposal-1",
                "compaction-other-emitter": "proposal-1",
            },
        )
        self.assertEqual(change["unresolved"], [
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "compaction-same-time",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.compacted",
                "reason": "compaction_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "compaction-after-decision",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.compacted",
                "reason": "compaction_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "compaction-clock-skew",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.compacted",
                "reason": "compaction_follows_decision",
                "decision_event_id": "proposal-1",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "compaction-other-emitter",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.compacted",
                "reason": "compaction_chronology_undetermined",
                "decision_event_id": "proposal-1",
            },
        ])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification"],
            "unresolved_count": 4,
        })

    def test_context_read_after_compaction_cannot_be_summarized_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-before-compaction",
                timestamp="2026-07-13T11:01:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/before.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-same-time",
                span_id="span-current-context",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/current.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-after-compaction",
                span_id="span-late-context",
                sequence=5,
                timestamp="2026-07-13T11:03:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/late.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-clock-skewed-before",
                span_id="span-clock-skewed-before-context",
                sequence=3,
                timestamp="2026-07-13T11:03:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/clock-skewed-before.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-clock-skewed-after",
                span_id="span-clock-skewed-after-context",
                sequence=6,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/clock-skewed-after.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-after-compaction-independent",
                emitter_id="independent-reader",
                timestamp="2026-07-13T11:03:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/independent-late.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="context-same-time-independent",
                emitter_id="current-reader",
                timestamp="2026-07-13T11:02:00Z",
                kind="context.read",
                attributes={"context": {"path": "docs/independent-current.md"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-1",
                span_id="span-compaction",
                sequence=4,
                timestamp="2026-07-13T11:02:00Z",
                kind="context.compacted",
                relationships=[
                    {"type": "summarizes", "event_id": "context-before-compaction"},
                    {"type": "summarizes", "event_id": "context-same-time"},
                    {"type": "summarizes", "event_id": "context-after-compaction"},
                    {"type": "summarizes", "event_id": "context-clock-skewed-before"},
                    {"type": "summarizes", "event_id": "context-clock-skewed-after"},
                    {"type": "summarizes", "event_id": "context-after-compaction-independent"},
                    {"type": "summarizes", "event_id": "context-same-time-independent"},
                ],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=7,
                timestamp="2026-07-13T11:03:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{"type": "informed_by", "event_id": "compaction-1"}],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]
        compaction = change["links"][0]["compaction"]

        self.assertEqual(
            [source["context"]["path"] for source in compaction["sources"]],
            [
                "docs/before.md",
                "docs/current.md",
                "docs/late.md",
                "docs/clock-skewed-before.md",
                "docs/clock-skewed-after.md",
                "docs/independent-late.md",
                "docs/independent-current.md",
            ],
        )
        self.assertEqual(
            {
                source["event_id"]: source["chronology"]
                for source in compaction["sources"]
            },
            {
                "context-before-compaction": "before_compaction",
                "context-same-time": "before_compaction",
                "context-after-compaction": "after_compaction",
                "context-clock-skewed-before": "before_compaction",
                "context-clock-skewed-after": "after_compaction",
                "context-after-compaction-independent": "after_compaction",
                "context-same-time-independent": "undetermined",
            },
        )
        self.assertEqual(compaction["unresolved"], [
            {
                "type": "summarizes",
                "event_id": "context-after-compaction",
                "target_kind": "context.read",
                "reason": "context_not_preceding_compaction",
            },
            {
                "type": "summarizes",
                "event_id": "context-clock-skewed-after",
                "target_kind": "context.read",
                "reason": "context_not_preceding_compaction",
            },
            {
                "type": "summarizes",
                "event_id": "context-after-compaction-independent",
                "target_kind": "context.read",
                "reason": "context_not_preceding_compaction",
            },
            {
                "type": "summarizes",
                "event_id": "context-same-time-independent",
                "target_kind": "context.read",
                "reason": "context_source_chronology_undetermined",
            },
        ])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification", "decision"],
            "unresolved_count": 4,
        })

    def test_proposal_after_change_cannot_be_decision_evidence(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="proposal-after-change",
                emitter_id="independent-planner",
                timestamp="2026-07-13T11:03:00Z",
                kind="change.proposed",
                actor={"id": "late-planner"},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-same-time",
                span_id="span-same-time",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.proposed",
                actor={"id": "current-planner"},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-same-time-after",
                span_id="span-same-time-after",
                sequence=4,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.proposed",
                actor={"id": "sequence-late-planner"},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-clock-skewed-after",
                span_id="span-clock-skewed-after",
                sequence=5,
                timestamp="2026-07-13T11:01:00Z",
                kind="change.proposed",
                actor={"id": "clock-skewed-late-planner"},
            )) + "\n",
            json.dumps(event_data(
                event_id="proposal-same-time-independent",
                emitter_id="another-planner",
                timestamp="2026-07-13T11:02:00Z",
                kind="change.proposed",
                actor={"id": "independent-current-planner"},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[
                    {"type": "applies", "event_id": "proposal-after-change"},
                    {"type": "applies", "event_id": "proposal-same-time"},
                    {"type": "applies", "event_id": "proposal-same-time-after"},
                    {"type": "applies", "event_id": "proposal-clock-skewed-after"},
                    {"type": "applies", "event_id": "proposal-same-time-independent"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(
            [link["target_actor_id"] for link in change["links"]],
            [
                "late-planner",
                "current-planner",
                "sequence-late-planner",
                "clock-skewed-late-planner",
                "independent-current-planner",
            ],
        )
        self.assertEqual(
            {
                link["target_event_id"]: link["chronology"]
                for link in change["links"]
            },
            {
                "proposal-after-change": "after_change",
                "proposal-same-time": "before_change",
                "proposal-same-time-after": "after_change",
                "proposal-clock-skewed-after": "after_change",
                "proposal-same-time-independent": "undetermined",
            },
        )
        self.assertEqual(
            [item["target_event_id"] for item in change["unresolved"]],
            [
                "proposal-after-change",
                "proposal-same-time-after",
                "proposal-clock-skewed-after",
                "proposal-same-time-independent",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            [
                "proposal_not_preceding_change",
                "proposal_not_preceding_change",
                "proposal_not_preceding_change",
                "proposal_chronology_undetermined",
            ],
        )
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification"],
            "unresolved_count": 4,
        })

    def test_change_hunks_group_their_relationship_evidence(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="requirement-1",
                kind="requirement.observed",
                actor={"id": "user"},
                attributes={"requirement": {
                    "id": "R3",
                    "text": "Expired sessions must be rejected.",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-2",
                sequence=2,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-1"},
                    {"type": "verified_by", "event_id": "verification-1"},
                ],
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-3",
                sequence=3,
                kind="context.read",
                relationships=[
                    {"type": "informed_by", "event_id": "missing-document"},
                ],
            )) + "\n",
        ])

        before_verification = store.run_detail("trace-1")["evidence_map"]
        store.feed_line(json.dumps(event_data(
            event_id="verification-1",
            span_id="span-4",
            sequence=4,
            kind="verification.finished",
            attributes={"verification": {
                "command": "pytest tests/test_session.py",
                "passed": True,
                "exit_code": 0,
                "test_origin": "same_agent",
            }},
        )) + "\n")
        after_verification = store.run_detail("trace-1")["evidence_map"]

        motivated_by = {
            "type": "motivated_by",
            "source_event_id": "change-1",
            "target_event_id": "requirement-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "requirement.observed",
            "target_actor_id": "user",
            "chronology": "before_change",
            "requirement": {
                "id": "R3",
                "text": "Expired sessions must be rejected.",
            },
        }
        verified_by_unresolved = {
            "type": "verified_by",
            "source_event_id": "change-1",
            "target_event_id": "verification-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
        }
        self.assertEqual(before_verification["changes"], [{
            "event_id": "change-1",
            "actor_id": "reviewer-1",
            "hunk": hunk,
            "links": [motivated_by],
            "unresolved": [verified_by_unresolved],
            "corrections": [],
            "coverage": {
                "status": "incomplete",
                "missing": ["context", "tool", "verification", "decision"],
                "unresolved_count": 1,
            },
        }])
        self.assertEqual(after_verification["changes"], [{
            "event_id": "change-1",
            "actor_id": "reviewer-1",
            "hunk": hunk,
            "links": [motivated_by, {
                **verified_by_unresolved,
                "target_kind": "verification.finished",
                "target_actor_id": "reviewer-1",
                "chronology": "after_change",
                "verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "exit_code": 0,
                    "test_origin": "same_agent",
                },
            }],
            "unresolved": [],
            "corrections": [],
            "coverage": {
                "status": "incomplete",
                "missing": ["context", "tool", "decision"],
                "unresolved_count": 0,
                "same_agent_test_count": 1,
            },
        }])
        self.assertEqual(
            before_verification["links"],
            before_verification["changes"][0]["links"],
        )
        self.assertIn(
            verified_by_unresolved,
            before_verification["unresolved"],
        )
        self.assertEqual(len(before_verification["unresolved"]), 2)

    def test_evidence_ignores_malformed_optional_verification_results(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-1",
                span_id="span-2",
                sequence=2,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "exit_code": True,
                    "test_origin": "generated",
                }},
            )) + "\n",
        ])

        link = store.run_detail("trace-1")["evidence_map"]["links"][0]

        self.assertEqual(link["verification"], {
            "command": "pytest",
            "passed": True,
        })

    def test_evidence_diagnoses_malformed_supplied_test_origin(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-1",
                span_id="span-2",
                sequence=2,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "exit_code": 0,
                    "test_origin": ["generated"],
                }},
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["verification"], {
            "command": "pytest tests/test_session.py",
            "passed": True,
            "exit_code": 0,
        })
        self.assertEqual(change["unresolved"], [{
            "type": "verified_by",
            "source_event_id": "change-1",
            "target_event_id": "verification-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "verification.finished",
            "reason": "invalid_verification_test_origin",
        }])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "decision"],
            "unresolved_count": 1,
            "unknown_test_origin_count": 1,
        })

    def test_verification_evidence_pairs_finished_with_started_event(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-finished-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-finished-1",
                span_id="span-2",
                sequence=2,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.finished",
                actor={"id": "result-reporter"},
                attributes={"verification": {
                    "passed": True,
                    "exit_code": 0,
                    "test_origin": "pre_existing",
                }},
                relationships=[
                    {
                        "type": "completes",
                        "event_id": "verification-started-1",
                    },
                    {
                        "type": "completes",
                        "event_id": "verification-started-1",
                    },
                    {
                        "type": "completes",
                        "event_id": "not-a-verification-start",
                    },
                    {
                        "type": "completes",
                        "event_id": "verification-started-without-command",
                    },
                ],
            )) + "\n",
            json.dumps(event_data(
                event_id="not-a-verification-start",
                span_id="span-3",
                sequence=3,
                kind="requirement.observed",
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-without-command",
                emitter_id="commandless-start-worker",
                span_id="span-4",
                sequence=4,
                timestamp="2026-07-13T11:02:50Z",
                kind="verification.started",
                actor={"id": "commandless-runner"},
                attributes={"verification": {"command": " \t"}},
            )) + "\n",
        ])

        before_detail = store.run_detail("trace-1")
        before_start = before_detail["evidence_map"]["changes"][0]
        finished_event = next(
            event
            for event in before_detail["events"]
            if event["event_id"] == "verification-finished-1"
        )
        self.assertEqual(len(finished_event["relationships"]), 4)
        self.assertEqual(before_start["links"][0]["verification"], {
            "passed": True,
            "exit_code": 0,
            "test_origin": "pre_existing",
            "starts": [{
                "event_id": "verification-started-without-command",
                "actor_id": "commandless-runner",
                "chronology": "before_finish",
                "change_chronology": "after_change",
            }],
            "unresolved": [
                {
                    "type": "completes",
                    "event_id": "verification-started-1",
                },
                {
                    "type": "completes",
                    "event_id": "not-a-verification-start",
                    "target_kind": "requirement.observed",
                },
                {
                    "type": "completes",
                    "event_id": "verification-started-without-command",
                    "target_kind": "verification.started",
                    "reason": "invalid_verification_command",
                },
            ],
        })
        self.assertEqual(before_start["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 3,
        })

        store.feed_line(json.dumps(event_data(
            event_id="verification-started-1",
            emitter_id="resolved-start-worker",
            span_id="span-3",
            sequence=4,
            timestamp="2026-07-13T11:02:50Z",
            kind="verification.started",
            actor={"id": "test-runner"},
            attributes={"verification": {
                "command": "pytest tests/test_session.py",
            }},
        )) + "\n")

        after_start = store.run_detail("trace-1")["evidence_map"]["changes"][0]
        self.assertEqual(after_start["links"][0]["verification"], {
            "passed": True,
            "command": "pytest tests/test_session.py",
            "exit_code": 0,
            "test_origin": "pre_existing",
            "starts": [{
                "event_id": "verification-started-1",
                "actor_id": "test-runner",
                "chronology": "before_finish",
                "change_chronology": "after_change",
                "command": "pytest tests/test_session.py",
            }, {
                "event_id": "verification-started-without-command",
                "actor_id": "commandless-runner",
                "chronology": "before_finish",
                "change_chronology": "after_change",
            }],
            "unresolved": [
                {
                    "type": "completes",
                    "event_id": "not-a-verification-start",
                    "target_kind": "requirement.observed",
                },
                {
                    "type": "completes",
                    "event_id": "verification-started-without-command",
                    "target_kind": "verification.started",
                    "reason": "invalid_verification_command",
                },
            ],
        })
        self.assertEqual(after_start["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "decision"],
            "unresolved_count": 2,
        })

    def test_outcome_only_verification_remains_visible_but_incomplete(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-finished-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-finished-1",
                span_id="span-2",
                sequence=2,
                kind="verification.finished",
                attributes={"verification": {
                    "passed": False,
                    "exit_code": 1,
                    "test_origin": "pre_existing",
                }},
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["verification"], {
            "passed": False,
            "exit_code": 1,
            "test_origin": "pre_existing",
        })
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 1,
            "failed_verification_count": 1,
        })
        self.assertEqual(change["unresolved"][0]["reason"], "invalid_verification_command")

    def test_conflicting_verification_commands_are_lifecycle_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="verification-started-1",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_a.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-finished-1",
                span_id="span-2",
                sequence=2,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_b.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
                relationships=[{
                    "type": "completes",
                    "event_id": "verification-started-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                emitter_id="change-worker",
                span_id="span-3",
                sequence=3,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-finished-1",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["verification"], {
            "passed": True,
            "command": "pytest tests/test_b.py",
            "test_origin": "pre_existing",
            "starts": [{
                "event_id": "verification-started-1",
                "actor_id": "reviewer-1",
                "chronology": "before_finish",
                "change_chronology": "undetermined",
                "command": "pytest tests/test_a.py",
            }],
            "unresolved": [{
                "type": "completes",
                "event_id": "verification-started-1",
                "target_kind": "verification.started",
                "reason": "conflicting_verification_command",
            }],
        })
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "decision"],
            "unresolved_count": 1,
        })

    def test_verification_start_after_finish_uses_same_emitter_sequence_ordering(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="verification-started-after-finish",
                emitter_id="later-start-worker",
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-same-time",
                emitter_id="same-time-worker",
                span_id="span-same-time",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-before-change",
                emitter_id="before-change-worker",
                span_id="span-before-change",
                sequence=2,
                timestamp="2026-07-13T11:01:00Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-with-change",
                emitter_id="with-change-worker",
                span_id="span-with-change",
                sequence=2,
                timestamp="2026-07-13T11:01:30Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-clock-skew-after-finish",
                span_id="span-clock-skew-after-finish",
                sequence=4,
                timestamp="2026-07-13T11:01:00Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-clock-skew-before-finish",
                span_id="span-clock-skew-before-finish",
                sequence=1,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-clock-skew-after-change",
                emitter_id="change-worker",
                span_id="span-clock-skew-after-change",
                sequence=5,
                timestamp="2026-07-13T11:01:00Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-started-clock-skew-before-change",
                emitter_id="change-worker",
                span_id="span-clock-skew-before-change",
                sequence=3,
                timestamp="2026-07-13T11:01:45Z",
                kind="verification.started",
                attributes={"verification": {"command": "pytest tests/test_session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-finished-1",
                span_id="span-finished",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
                relationships=[
                    {"type": "completes", "event_id": "verification-started-after-finish"},
                    {"type": "completes", "event_id": "verification-started-same-time"},
                    {"type": "completes", "event_id": "verification-started-before-change"},
                    {"type": "completes", "event_id": "verification-started-with-change"},
                    {
                        "type": "completes",
                        "event_id": "verification-started-clock-skew-after-finish",
                    },
                    {
                        "type": "completes",
                        "event_id": "verification-started-clock-skew-before-finish",
                    },
                    {
                        "type": "completes",
                        "event_id": "verification-started-clock-skew-after-change",
                    },
                    {
                        "type": "completes",
                        "event_id": "verification-started-clock-skew-before-change",
                    },
                ],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                emitter_id="change-worker",
                span_id="span-change",
                sequence=4,
                timestamp="2026-07-13T11:01:30Z",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-finished-1",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]
        verification = change["links"][0]["verification"]

        self.assertEqual(
            [start["event_id"] for start in verification["starts"]],
            [
                "verification-started-after-finish",
                "verification-started-same-time",
                "verification-started-before-change",
                "verification-started-with-change",
                "verification-started-clock-skew-after-finish",
                "verification-started-clock-skew-before-finish",
                "verification-started-clock-skew-after-change",
                "verification-started-clock-skew-before-change",
            ],
        )
        self.assertEqual(
            {
                start["event_id"]: start["chronology"]
                for start in verification["starts"]
            },
            {
                "verification-started-after-finish": "after_finish",
                "verification-started-same-time": "undetermined",
                "verification-started-before-change": "before_finish",
                "verification-started-with-change": "before_finish",
                "verification-started-clock-skew-after-finish": "after_finish",
                "verification-started-clock-skew-before-finish": "before_finish",
                "verification-started-clock-skew-after-change": "before_finish",
                "verification-started-clock-skew-before-change": "before_finish",
            },
        )
        self.assertEqual(
            {
                start["event_id"]: start["change_chronology"]
                for start in verification["starts"]
            },
            {
                "verification-started-after-finish": "after_change",
                "verification-started-same-time": "after_change",
                "verification-started-before-change": "before_change",
                "verification-started-with-change": "undetermined",
                "verification-started-clock-skew-after-finish": "before_change",
                "verification-started-clock-skew-before-finish": "after_change",
                "verification-started-clock-skew-after-change": "after_change",
                "verification-started-clock-skew-before-change": "before_change",
            },
        )
        self.assertEqual(verification["unresolved"], [
            {
                "type": "completes",
                "event_id": "verification-started-after-finish",
                "target_kind": "verification.started",
                "reason": "verification_start_after_finish",
            },
            {
                "type": "completes",
                "event_id": "verification-started-same-time",
                "target_kind": "verification.started",
                "reason": "verification_start_finish_chronology_undetermined",
            },
            {
                "type": "completes",
                "event_id": "verification-started-before-change",
                "target_kind": "verification.started",
                "reason": "verification_start_precedes_change",
            },
            {
                "type": "completes",
                "event_id": "verification-started-with-change",
                "target_kind": "verification.started",
                "reason": "verification_start_change_chronology_undetermined",
            },
            {
                "type": "completes",
                "event_id": "verification-started-clock-skew-after-finish",
                "target_kind": "verification.started",
                "reason": "verification_start_after_finish",
            },
            {
                "type": "completes",
                "event_id": "verification-started-clock-skew-before-change",
                "target_kind": "verification.started",
                "reason": "verification_start_precedes_change",
            },
        ])
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "decision"],
            "unresolved_count": 6,
        })

    def test_verification_before_change_uses_same_emitter_sequence_ordering(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="verification-before-change",
                emitter_id="worker-2",
                timestamp="2026-07-13T11:01:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-same-time",
                span_id="span-same-time",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-clock-skew-before-change",
                span_id="span-clock-skew-before",
                sequence=1,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-clock-skew-after-change",
                span_id="span-clock-skew-after",
                sequence=4,
                timestamp="2026-07-13T11:01:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="verification-same-time-other-emitter",
                emitter_id="worker-2",
                span_id="span-other-emitter",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_session.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "verified_by", "event_id": "verification-before-change"},
                    {"type": "verified_by", "event_id": "verification-same-time"},
                    {
                        "type": "verified_by",
                        "event_id": "verification-clock-skew-before-change",
                    },
                    {
                        "type": "verified_by",
                        "event_id": "verification-clock-skew-after-change",
                    },
                    {
                        "type": "verified_by",
                        "event_id": "verification-same-time-other-emitter",
                    },
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(
            [link["target_event_id"] for link in change["links"]],
            [
                "verification-before-change",
                "verification-same-time",
                "verification-clock-skew-before-change",
                "verification-clock-skew-after-change",
                "verification-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            {
                link["target_event_id"]: link["chronology"]
                for link in change["links"]
            },
            {
                "verification-before-change": "before_change",
                "verification-same-time": "before_change",
                "verification-clock-skew-before-change": "before_change",
                "verification-clock-skew-after-change": "after_change",
                "verification-same-time-other-emitter": "undetermined",
            },
        )
        self.assertEqual(
            [item["target_event_id"] for item in change["unresolved"]],
            [
                "verification-before-change",
                "verification-same-time",
                "verification-clock-skew-before-change",
                "verification-same-time-other-emitter",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            [
                "verification_precedes_change",
                "verification_precedes_change",
                "verification_precedes_change",
                "verification_chronology_undetermined",
            ],
        )
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "decision"],
            "unresolved_count": 4,
        })

    def test_conflicting_verification_outcomes_are_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for passed, exit_code in ((True, 1), (False, 0)):
            with self.subTest(passed=passed, exit_code=exit_code):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "verified_by",
                            "event_id": "verification-finished-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="verification-finished-1",
                        span_id="span-2",
                        sequence=2,
                        kind="verification.finished",
                        attributes={"verification": {
                            "command": "pytest tests/test_session.py",
                            "passed": passed,
                            "exit_code": exit_code,
                            "test_origin": "pre_existing",
                        }},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["links"][0]["verification"], {
                    "passed": passed,
                    "command": "pytest tests/test_session.py",
                    "exit_code": exit_code,
                    "test_origin": "pre_existing",
                })
                self.assertEqual(change["unresolved"], [{
                    "type": "verified_by",
                    "source_event_id": "change-1",
                    "target_event_id": "verification-finished-1",
                    "source_kind": "change.applied",
                    "source_actor_id": "reviewer-1",
                    "target_kind": "verification.finished",
                    "reason": "conflicting_verification_outcome",
                }])
                self.assertEqual(change["coverage"]["status"], "incomplete")
                self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_malformed_verification_exit_codes_are_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for exit_code in ("7", True):
            with self.subTest(exit_code=exit_code):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "verified_by",
                            "event_id": "verification-finished-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="verification-finished-1",
                        span_id="span-2",
                        sequence=2,
                        kind="verification.finished",
                        attributes={"verification": {
                            "command": "pytest tests/test_session.py",
                            "passed": True,
                            "exit_code": exit_code,
                            "test_origin": "pre_existing",
                        }},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["links"][0]["verification"], {
                    "passed": True,
                    "command": "pytest tests/test_session.py",
                    "test_origin": "pre_existing",
                })
                self.assertEqual(change["unresolved"], [{
                    "type": "verified_by",
                    "source_event_id": "change-1",
                    "target_event_id": "verification-finished-1",
                    "source_kind": "change.applied",
                    "source_actor_id": "reviewer-1",
                    "target_kind": "verification.finished",
                    "reason": "invalid_verification_exit_code",
                }])
                self.assertEqual(change["coverage"]["status"], "incomplete")
                self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_evidence_ignores_malformed_or_blank_requirement_details(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for requirement_id, text in (("R3", 3), (" \t", "Reject expiry."), ("R3", "\n ")):
            with self.subTest(requirement_id=requirement_id, text=text):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "motivated_by",
                            "event_id": "requirement-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="requirement-1",
                        span_id="span-2",
                        sequence=2,
                        kind="requirement.observed",
                        actor={"id": "user"},
                        attributes={"requirement": {
                            "id": requirement_id,
                            "text": text,
                        }},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]
                link = change["links"][0]

                self.assertNotIn("requirement", link)
                self.assertEqual(link["target_kind"], "requirement.observed")
                self.assertIn("requirement", change["coverage"]["missing"])

    def test_change_hunks_include_context_read_locators(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "informed_by",
                    "event_id": "context-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-2",
                sequence=2,
                kind="context.read",
                attributes={"context": {
                    "path": "docs/session-lifecycle.md",
                    "line_start": 42,
                    "line_end": 51,
                    "symbol": "Session expiration",
                }},
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]
        expected_link = {
            "type": "informed_by",
            "source_event_id": "change-1",
            "target_event_id": "context-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "context.read",
            "target_actor_id": "reviewer-1",
            "chronology": "after_change",
            "context": {
                "path": "docs/session-lifecycle.md",
                "line_start": 42,
                "line_end": 51,
                "symbol": "Session expiration",
            },
        }

        self.assertEqual(evidence["changes"][0]["links"], [expected_link])
        self.assertEqual(evidence["links"], [expected_link])

    def test_evidence_omits_malformed_or_blank_optional_context_read_fields(self):
        for symbol in (17, " \t\n"):
            with self.subTest(symbol=symbol):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        relationships=[{
                            "type": "informed_by",
                            "event_id": "context-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="context-1",
                        span_id="span-2",
                        sequence=2,
                        kind="context.read",
                        attributes={"context": {
                            "path": "src/auth/config.py",
                            "line_start": True,
                            "line_end": -1,
                            "symbol": symbol,
                        }},
                    )) + "\n",
                ])

                link = store.run_detail("trace-1")["evidence_map"]["links"][0]

                self.assertEqual(link["context"], {"path": "src/auth/config.py"})
                self.assertEqual(link["target_kind"], "context.read")

    def test_invalid_context_line_starts_are_direct_and_compacted_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-1",
                kind="context.read",
                attributes={"context": {
                    "path": "docs/session-lifecycle.md",
                    "line_start": True,
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-1",
                span_id="span-2",
                sequence=2,
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-3",
                sequence=3,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "informed_by", "event_id": "compaction-1"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["context"], {
            "path": "docs/session-lifecycle.md",
        })
        self.assertEqual(change["links"][1]["compaction"], {
            "sources": [{
                "type": "summarizes",
                "event_id": "context-1",
                "kind": "context.read",
                "actor_id": "reviewer-1",
                "context": {"path": "docs/session-lifecycle.md"},
                "chronology": "before_compaction",
            }],
            "unresolved": [{
                "type": "summarizes",
                "event_id": "context-1",
                "target_kind": "context.read",
                "reason": "invalid_context_line_start",
            }],
        })
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            ["invalid_context_line_start"],
        )
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification", "decision"],
            "unresolved_count": 2,
        })

    def test_invalid_context_line_ends_are_direct_and_compacted_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-1",
                kind="context.read",
                attributes={"context": {
                    "path": "src/auth/config.py",
                    "line_start": 42,
                    "line_end": 17,
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-1",
                span_id="span-2",
                sequence=2,
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-3",
                sequence=3,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "informed_by", "event_id": "compaction-1"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["context"], {
            "path": "src/auth/config.py",
            "line_start": 42,
        })
        self.assertEqual(change["links"][1]["compaction"], {
            "sources": [{
                "type": "summarizes",
                "event_id": "context-1",
                "kind": "context.read",
                "actor_id": "reviewer-1",
                "context": {
                    "path": "src/auth/config.py",
                    "line_start": 42,
                },
                "chronology": "before_compaction",
            }],
            "unresolved": [{
                "type": "summarizes",
                "event_id": "context-1",
                "target_kind": "context.read",
                "reason": "invalid_context_line_end",
            }],
        })
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            ["invalid_context_line_end"],
        )
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification", "decision"],
            "unresolved_count": 2,
        })

    def test_invalid_context_symbols_are_direct_and_compacted_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-1",
                kind="context.read",
                attributes={"context": {
                    "path": "src/auth/config.py",
                    "symbol": " \t",
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-1",
                span_id="span-2",
                sequence=2,
                kind="context.compacted",
                relationships=[{"type": "summarizes", "event_id": "context-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                span_id="span-3",
                sequence=3,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "informed_by", "event_id": "compaction-1"},
                ],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["context"], {
            "path": "src/auth/config.py",
        })
        self.assertEqual(change["links"][1]["compaction"]["unresolved"], [{
            "type": "summarizes",
            "event_id": "context-1",
            "target_kind": "context.read",
            "reason": "invalid_context_symbol",
        }])
        self.assertEqual(
            [item["reason"] for item in change["unresolved"]],
            ["invalid_context_symbol"],
        )
        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "tool", "verification", "decision"],
            "unresolved_count": 2,
        })

    def test_evidence_preserves_context_line_end_without_line_start(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                relationships=[{
                    "type": "informed_by",
                    "event_id": "context-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-2",
                sequence=2,
                kind="context.read",
                attributes={"context": {
                    "path": "docs/session-lifecycle.md",
                    "line_end": 51,
                }},
            )) + "\n",
        ])

        link = store.run_detail("trace-1")["evidence_map"]["links"][0]

        self.assertEqual(link["context"], {
            "path": "docs/session-lifecycle.md",
            "line_end": 51,
        })
        self.assertEqual(link["target_kind"], "context.read")

    def test_evidence_omits_zero_context_line_coordinates(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                relationships=[{
                    "type": "informed_by",
                    "event_id": "context-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-2",
                sequence=2,
                kind="context.read",
                attributes={"context": {
                    "path": "src/auth/config.py",
                    "line_start": 0,
                    "line_end": 0,
                }},
            )) + "\n",
        ])

        link = store.run_detail("trace-1")["evidence_map"]["links"][0]

        self.assertEqual(link["context"], {"path": "src/auth/config.py"})
        self.assertEqual(link["target_kind"], "context.read")

    def test_evidence_ignores_blank_context_read_paths(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "informed_by",
                    "event_id": "context-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-2",
                sequence=2,
                kind="context.read",
                attributes={"context": {
                    "path": " \t\n",
                    "symbol": "SessionConfig",
                }},
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]
        link = change["links"][0]

        self.assertNotIn("context", link)
        self.assertEqual(link["target_kind"], "context.read")
        self.assertIn("context", change["coverage"]["missing"])

    def test_change_hunks_include_preceding_tool_commands_and_results(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "preceded_by", "event_id": "tool-start-1"},
                    {"type": "preceded_by", "event_id": "tool-finish-1"},
                ],
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-start-1",
                span_id="span-2",
                sequence=2,
                kind="tool.call.started",
                operation={"status": "running", "name": "shell"},
                attributes={"tool": {"command": "git diff -- src/auth/session.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-finish-1",
                span_id="span-3",
                sequence=3,
                kind="tool.call.completed",
                actor={"id": "shell-1"},
                operation={"status": "ok", "name": "shell"},
                attributes={"tool": {
                    "result": "1 file changed, 3 insertions(+)",
                    "exit_code": 0,
                }},
            )) + "\n",
        ])

        links = store.run_detail("trace-1")["evidence_map"]["changes"][0]["links"]

        self.assertEqual(links[0]["tool"], {
            "status": "running",
            "name": "shell",
            "command": "git diff -- src/auth/session.py",
        })
        self.assertEqual(links[1]["target_actor_id"], "shell-1")
        self.assertEqual(links[1]["tool"], {
            "status": "ok",
            "name": "shell",
            "result": "1 file changed, 3 insertions(+)",
            "exit_code": 0,
        })

    def test_evidence_omits_malformed_or_blank_tool_call_fields(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for operation, tool_attributes, expected_tool in (
            (
                {"status": "failed", "name": ["shell"]},
                {"command": 17, "result": "", "exit_code": True},
                {"status": "failed"},
            ),
            (
                {"status": "failed", "name": " \t\n"},
                {"command": " \t", "result": "\n ", "exit_code": True},
                {"status": "failed"},
            ),
            (
                {"status": " \t\n", "name": "shell"},
                {"command": "git diff"},
                {"name": "shell", "command": "git diff"},
            ),
        ):
            with self.subTest(
                operation=operation,
                tool_attributes=tool_attributes,
            ):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "preceded_by",
                            "event_id": "tool-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="tool-1",
                        emitter_id="worker-2",
                        span_id="span-2",
                        sequence=2,
                        kind="tool.call.completed",
                        operation=operation,
                        attributes={"tool": tool_attributes},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(
                    change["links"][0]["tool"],
                    expected_tool,
                )
                if "command" not in expected_tool and "result" not in expected_tool:
                    self.assertIn("tool", change["coverage"]["missing"])

    def test_malformed_tool_operation_names_are_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for name in (["shell"], " \t\n"):
            with self.subTest(name=name):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "preceded_by",
                            "event_id": "tool-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="tool-1",
                        emitter_id="worker-2",
                        span_id="span-2",
                        sequence=2,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": name},
                        attributes={"tool": {"command": "git diff --check"}},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["links"][0]["tool"], {
                    "status": "ok",
                    "command": "git diff --check",
                })
                self.assertEqual(change["unresolved"], [{
                    "type": "preceded_by",
                    "source_event_id": "change-1",
                    "target_event_id": "tool-1",
                    "source_kind": "change.applied",
                    "source_actor_id": "reviewer-1",
                    "target_kind": "tool.call.completed",
                    "reason": "invalid_tool_operation_name",
                }])
                self.assertEqual(change["coverage"]["status"], "incomplete")
                self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_malformed_supplied_tool_commands_are_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for command in (17, " \t\n"):
            with self.subTest(command=command):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "preceded_by",
                            "event_id": "tool-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="tool-1",
                        emitter_id="worker-2",
                        span_id="span-2",
                        sequence=2,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {
                            "command": command,
                            "result": "working tree clean",
                        }},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["links"][0]["tool"], {
                    "status": "ok",
                    "name": "shell",
                    "result": "working tree clean",
                })
                self.assertEqual(change["unresolved"], [{
                    "type": "preceded_by",
                    "source_event_id": "change-1",
                    "target_event_id": "tool-1",
                    "source_kind": "change.applied",
                    "source_actor_id": "reviewer-1",
                    "target_kind": "tool.call.completed",
                    "reason": "invalid_tool_command",
                }])
                self.assertEqual(change["coverage"]["status"], "incomplete")
                self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_malformed_supplied_tool_results_are_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for result in (17, " \t\n"):
            with self.subTest(result=result):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "preceded_by",
                            "event_id": "tool-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="tool-1",
                        emitter_id="worker-2",
                        span_id="span-2",
                        sequence=2,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {
                            "command": "git status --porcelain",
                            "result": result,
                        }},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["links"][0]["tool"], {
                    "status": "ok",
                    "name": "shell",
                    "command": "git status --porcelain",
                })
                self.assertEqual(change["unresolved"], [{
                    "type": "preceded_by",
                    "source_event_id": "change-1",
                    "target_event_id": "tool-1",
                    "source_kind": "change.applied",
                    "source_actor_id": "reviewer-1",
                    "target_kind": "tool.call.completed",
                    "reason": "invalid_tool_result",
                }])
                self.assertEqual(change["coverage"]["status"], "incomplete")
                self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_blank_tool_operation_status_is_a_diagnostic(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "preceded_by",
                    "event_id": "tool-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-1",
                emitter_id="worker-2",
                span_id="span-2",
                sequence=2,
                kind="tool.call.completed",
                operation={"status": " \t\n", "name": "shell"},
                attributes={"tool": {"command": "git diff --check"}},
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["links"][0]["tool"], {
            "name": "shell",
            "command": "git diff --check",
        })
        self.assertEqual(change["unresolved"], [{
            "type": "preceded_by",
            "source_event_id": "change-1",
            "target_event_id": "tool-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "tool.call.completed",
            "reason": "invalid_tool_operation_status",
        }])
        self.assertEqual(change["coverage"]["status"], "incomplete")
        self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_malformed_tool_exit_codes_are_diagnostics(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for exit_code in ("7", True):
            with self.subTest(exit_code=exit_code):
                store = RunStore.from_lines([
                    json.dumps(event_data(
                        event_id="change-1",
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[{
                            "type": "preceded_by",
                            "event_id": "tool-1",
                        }],
                    )) + "\n",
                    json.dumps(event_data(
                        event_id="tool-1",
                        emitter_id="worker-2",
                        span_id="span-2",
                        sequence=2,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {
                            "command": "git diff --check",
                            "exit_code": exit_code,
                        }},
                    )) + "\n",
                ])

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["links"][0]["tool"], {
                    "status": "ok",
                    "name": "shell",
                    "command": "git diff --check",
                })
                self.assertEqual(change["unresolved"], [{
                    "type": "preceded_by",
                    "source_event_id": "change-1",
                    "target_event_id": "tool-1",
                    "source_kind": "change.applied",
                    "source_actor_id": "reviewer-1",
                    "target_kind": "tool.call.completed",
                    "reason": "invalid_tool_exit_code",
                }])
                self.assertEqual(change["coverage"]["status"], "incomplete")
                self.assertEqual(change["coverage"]["unresolved_count"], 1)

    def test_change_hunks_include_context_compaction_sources(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "informed_by",
                    "event_id": "compaction-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-1",
                emitter_id="worker-2",
                span_id="span-2",
                sequence=2,
                kind="context.compacted",
                relationships=[
                    {"type": "summarizes", "event_id": "context-1"},
                    {"type": "summarizes", "event_id": "missing-context"},
                    {"type": "summarizes", "event_id": "tool-1"},
                ],
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-3",
                sequence=3,
                kind="context.read",
                actor={"id": "researcher-1"},
                attributes={"context": {
                    "path": "docs/session-lifecycle.md",
                    "line_start": 42,
                    "line_end": 51,
                }},
            )) + "\n",
            json.dumps(event_data(
                event_id="tool-1",
                span_id="span-4",
                sequence=4,
                kind="tool.call.completed",
            )) + "\n",
        ])

        evidence_map = store.run_detail("trace-1")["evidence_map"]
        link = evidence_map["changes"][0]["links"][0]

        self.assertEqual(link["target_kind"], "context.compacted")
        self.assertEqual(link["compaction"], {
            "sources": [{
                "type": "summarizes",
                "event_id": "context-1",
                "kind": "context.read",
                "actor_id": "researcher-1",
                "context": {
                    "path": "docs/session-lifecycle.md",
                    "line_start": 42,
                    "line_end": 51,
                },
                "chronology": "undetermined",
            }],
            "unresolved": [{
                "type": "summarizes",
                "event_id": "context-1",
                "target_kind": "context.read",
                "reason": "context_source_chronology_undetermined",
            }, {
                "type": "summarizes",
                "event_id": "missing-context",
            }, {
                "type": "summarizes",
                "event_id": "tool-1",
                "target_kind": "tool.call.completed",
            }],
        })
        self.assertIn(
            {
                "type": "summarizes",
                "source_event_id": "compaction-1",
                "source_kind": "context.compacted",
                "source_actor_id": "reviewer-1",
                "target_event_id": "tool-1",
                "target_kind": "tool.call.completed",
                "target_actor_id": "reviewer-1",
                "tool": {"status": "running", "name": "read_file"},
            },
            evidence_map["links"],
        )
        self.assertEqual(
            evidence_map["changes"][0]["coverage"],
            {
                "status": "incomplete",
                "missing": ["requirement", "tool", "verification", "decision"],
                "unresolved_count": 4,
            },
        )

    def test_context_compaction_deduplicates_identical_source_relationships(self):
        relationships = [
            {"type": "summarizes", "event_id": "context-1"},
            {"type": "summarizes", "event_id": "context-1"},
            {"type": "summarizes", "event_id": "missing-context"},
            {"type": "summarizes", "event_id": "missing-context"},
        ]
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[{
                    "type": "informed_by",
                    "event_id": "compaction-1",
                }],
            )) + "\n",
            json.dumps(event_data(
                event_id="compaction-1",
                emitter_id="worker-2",
                span_id="span-2",
                sequence=2,
                kind="context.compacted",
                relationships=relationships,
            )) + "\n",
            json.dumps(event_data(
                event_id="context-1",
                span_id="span-3",
                sequence=3,
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            )) + "\n",
        ])

        detail = store.run_detail("trace-1")
        change = detail["evidence_map"]["changes"][0]
        compaction = change["links"][0]["compaction"]

        self.assertEqual(detail["events"][1]["relationships"], relationships)
        self.assertEqual(len(compaction["sources"]), 1)
        self.assertEqual(len(compaction["unresolved"]), 2)
        self.assertEqual(change["coverage"]["unresolved_count"], 3)

    def test_change_hunk_coverage_reports_complete_core_evidence(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for test_origin, passed, requirement_relationship, context_relationship, tool_relationship, verification_relationship, decision_relationship, include_tool_detail, expected in (
            (None, True, "motivated_by", "informed_by", "preceded_by", "verified_by", "applies", True, {
                "status": "incomplete",
                "missing": [],
                "unresolved_count": 0,
                "unknown_test_origin_count": 1,
            }),
            ("same_agent", True, "motivated_by", "informed_by", "preceded_by", "verified_by", "applies", True, {
                "status": "incomplete",
                "missing": [],
                "unresolved_count": 0,
                "same_agent_test_count": 1,
            }),
            ("pre_existing", True, "motivated_by", "informed_by", "preceded_by", "verified_by", None, True, {
                "status": "incomplete",
                "missing": ["decision"],
                "unresolved_count": 0,
            }),
            ("pre_existing", True, "motivated_by", "informed_by", "preceded_by", "verified_by", "references", True, {
                "status": "incomplete",
                "missing": ["decision"],
                "unresolved_count": 0,
            }),
            ("pre_existing", True, "references", "informed_by", "preceded_by", "verified_by", "applies", True, {
                "status": "incomplete",
                "missing": ["requirement"],
                "unresolved_count": 0,
            }),
            ("pre_existing", True, "motivated_by", "references", "preceded_by", "verified_by", "applies", True, {
                "status": "incomplete",
                "missing": ["context"],
                "unresolved_count": 0,
            }),
            ("pre_existing", True, "motivated_by", "informed_by", "references", "verified_by", "applies", True, {
                "status": "incomplete",
                "missing": ["tool"],
                "unresolved_count": 0,
            }),
            ("pre_existing", False, "motivated_by", "informed_by", "preceded_by", "references", "applies", True, {
                "status": "incomplete",
                "missing": ["verification"],
                "unresolved_count": 0,
            }),
            ("pre_existing", True, "motivated_by", "informed_by", "preceded_by", "verified_by", "applies", False, {
                "status": "incomplete",
                "missing": ["tool"],
                "unresolved_count": 1,
            }),
            ("pre_existing", False, "motivated_by", "informed_by", "preceded_by", "verified_by", "applies", True, {
                "status": "incomplete",
                "missing": [],
                "unresolved_count": 0,
                "failed_verification_count": 1,
            }),
            ("pre_existing", True, "motivated_by", "informed_by", "preceded_by", "verified_by", "applies", True, {
                "status": "complete",
                "missing": [],
                "unresolved_count": 0,
            }),
        ):
            with self.subTest(
                test_origin=test_origin,
                passed=passed,
                requirement_relationship=requirement_relationship,
                context_relationship=context_relationship,
                tool_relationship=tool_relationship,
                verification_relationship=verification_relationship,
                decision_relationship=decision_relationship,
                include_tool_detail=include_tool_detail,
            ):
                verification = {"command": "pytest", "passed": passed}
                if test_origin is not None:
                    verification["test_origin"] = test_origin
                targets = [
                    event_data(
                        event_id="requirement-1",
                        timestamp="2026-07-13T10:59:00Z",
                        kind="requirement.observed",
                        attributes={"requirement": {
                            "id": "R3",
                            "text": "Reject expiry.",
                        }},
                    ),
                    event_data(
                        event_id="context-1",
                        sequence=2,
                        timestamp="2026-07-13T10:59:00Z",
                        kind="context.read",
                        attributes={"context": {"path": "src/auth/config.py"}},
                    ),
                    event_data(
                        event_id="tool-1",
                        sequence=3,
                        timestamp="2026-07-13T11:02:00Z",
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {"command": "pytest"}}
                        if include_tool_detail else None,
                    ),
                    event_data(
                        event_id="verification-1",
                        sequence=4,
                        timestamp="2026-07-13T11:03:00Z",
                        kind="verification.finished",
                        attributes={"verification": verification},
                    ),
                    event_data(
                        event_id="proposal-1",
                        emitter_id="change-worker",
                        sequence=5,
                        kind="change.proposed",
                        actor={"id": "planner-1"},
                    ),
                    event_data(
                        event_id="change-1",
                        emitter_id="change-worker",
                        sequence=6,
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[
                            {"type": requirement_relationship, "event_id": "requirement-1"},
                            {"type": context_relationship, "event_id": "context-1"},
                            {"type": tool_relationship, "event_id": "tool-1"},
                            {"type": verification_relationship, "event_id": "verification-1"},
                            *([{
                                "type": decision_relationship,
                                "event_id": "proposal-1",
                            }] if decision_relationship is not None else []),
                        ],
                    ),
                ]
                store = RunStore.from_lines(
                    json.dumps(event) + "\n" for event in targets
                )

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                self.assertEqual(change["coverage"], expected)
                self.assertTrue(any(
                    link["type"] == requirement_relationship
                    and link["target_event_id"] == "requirement-1"
                    for link in change["links"]
                ))
                self.assertTrue(any(
                    link["type"] == context_relationship
                    and link["target_event_id"] == "context-1"
                    for link in change["links"]
                ))
                self.assertTrue(any(
                    link["type"] == tool_relationship
                    and link["target_event_id"] == "tool-1"
                    for link in change["links"]
                ))
                self.assertTrue(any(
                    link["type"] == verification_relationship
                    and link["target_event_id"] == "verification-1"
                    for link in change["links"]
                ))

    def test_blank_proposal_actor_does_not_satisfy_decision_coverage(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="proposal-1",
                kind="change.proposed",
                actor={"id": " \t"},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                sequence=2,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{"type": "applies", "event_id": "proposal-1"}],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 1,
        })
        self.assertEqual(change["links"][0]["target_actor_id"], " \t")
        self.assertEqual(change["unresolved"], [{
            "type": "applies",
            "source_event_id": "change-1",
            "target_event_id": "proposal-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "change.proposed",
            "reason": "invalid_decision_actor",
        }])

    def test_wrong_kind_decision_target_is_an_unresolved_diagnostic(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="wrong-proposal-1",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                sequence=2,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{
                    "type": "applies",
                    "event_id": "wrong-proposal-1",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 1,
        })
        self.assertEqual(change["unresolved"], [{
            "type": "applies",
            "source_event_id": "change-1",
            "target_event_id": "wrong-proposal-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "context.read",
        }])
        self.assertEqual(change["links"][0]["target_event_id"], "wrong-proposal-1")

    def test_wrong_kind_requirement_target_is_an_unresolved_diagnostic(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="wrong-requirement-1",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                sequence=2,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{
                    "type": "motivated_by",
                    "event_id": "wrong-requirement-1",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 1,
        })
        self.assertEqual(change["unresolved"], [{
            "type": "motivated_by",
            "source_event_id": "change-1",
            "target_event_id": "wrong-requirement-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "context.read",
        }])
        self.assertEqual(change["links"][0]["target_event_id"], "wrong-requirement-1")

    def test_wrong_kind_context_target_is_an_unresolved_diagnostic(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="wrong-context-1",
                kind="tool.call.completed",
                attributes={"tool": {"command": "pytest"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                sequence=2,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{
                    "type": "informed_by",
                    "event_id": "wrong-context-1",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 1,
        })
        self.assertEqual(change["unresolved"], [{
            "type": "informed_by",
            "source_event_id": "change-1",
            "target_event_id": "wrong-context-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "tool.call.completed",
        }])
        self.assertEqual(change["links"][0]["target_event_id"], "wrong-context-1")

    def test_wrong_kind_tool_target_is_an_unresolved_diagnostic(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="wrong-tool-1",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="change-1",
                sequence=2,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/auth/session.py",
                    "old_start": 84,
                    "old_count": 18,
                    "new_start": 84,
                    "new_count": 19,
                }},
                relationships=[{
                    "type": "preceded_by",
                    "event_id": "wrong-tool-1",
                }],
            )) + "\n",
        ])

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": ["requirement", "context", "tool", "verification", "decision"],
            "unresolved_count": 1,
        })
        self.assertEqual(change["unresolved"], [{
            "type": "preceded_by",
            "source_event_id": "change-1",
            "target_event_id": "wrong-tool-1",
            "source_kind": "change.applied",
            "source_actor_id": "reviewer-1",
            "target_kind": "context.read",
        }])
        self.assertEqual(change["links"][0]["target_event_id"], "wrong-tool-1")

    def test_invalid_canonical_evidence_reduces_complete_coverage(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        targets = [
            event_data(
                event_id="requirement-1",
                timestamp="2026-07-13T10:59:00Z",
                kind="requirement.observed",
                attributes={"requirement": {"id": "R3", "text": "Reject expiry."}},
            ),
            event_data(
                event_id="context-1",
                sequence=2,
                timestamp="2026-07-13T10:59:00Z",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            ),
            event_data(
                event_id="tool-1",
                sequence=3,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "pytest"}},
            ),
            event_data(
                event_id="verification-1",
                sequence=4,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(
                event_id="proposal-1",
                emitter_id="change-worker",
                sequence=5,
                kind="change.proposed",
            ),
            event_data(
                event_id="wrong-verification-1",
                sequence=6,
                kind="verification.started",
            ),
            event_data(
                event_id="invalid-verification-1",
                sequence=7,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest tests/test_invalid.py",
                    "passed": "yes",
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(
                event_id="invalid-requirement-1",
                emitter_id="invalid-requirement-worker",
                sequence=8,
                kind="requirement.observed",
                attributes={"requirement": {"id": "R4", "text": " \t"}},
            ),
            event_data(
                event_id="invalid-context-1",
                emitter_id="invalid-context-worker",
                sequence=8,
                kind="context.read",
                attributes={"context": {"path": " \t"}},
            ),
            event_data(
                event_id="invalid-tool-1",
                sequence=4,
                kind="tool.call.completed",
                operation={"status": "ok", "name": "shell"},
                attributes={"tool": {"command": " \t", "result": 42}},
            ),
            event_data(
                event_id="invalid-proposal-1",
                sequence=8,
                kind="change.proposed",
                actor={"id": " \t"},
            ),
            event_data(
                event_id="empty-compaction-1",
                emitter_id="invalid-compaction-worker",
                sequence=8,
                kind="context.compacted",
            ),
            event_data(
                event_id="commandless-verification-1",
                sequence=8,
                kind="verification.finished",
                attributes={"verification": {
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(
                event_id="change-1",
                emitter_id="change-worker",
                sequence=9,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-1"},
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "preceded_by", "event_id": "tool-1"},
                    {"type": "verified_by", "event_id": "verification-1"},
                    {"type": "verified_by", "event_id": "wrong-verification-1"},
                    {"type": "verified_by", "event_id": "invalid-verification-1"},
                    {"type": "motivated_by", "event_id": "invalid-requirement-1"},
                    {"type": "informed_by", "event_id": "invalid-context-1"},
                    {"type": "informed_by", "event_id": "empty-compaction-1"},
                    {"type": "preceded_by", "event_id": "invalid-tool-1"},
                    {
                        "type": "verified_by",
                        "event_id": "commandless-verification-1",
                    },
                    {"type": "applies", "event_id": "proposal-1"},
                    {"type": "applies", "event_id": "invalid-proposal-1"},
                    {"type": "references", "event_id": "missing-note"},
                ],
            ),
        ]
        store = RunStore.from_lines(json.dumps(event) + "\n" for event in targets)

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": [],
            "unresolved_count": 8,
        })
        self.assertEqual(change["unresolved"], [
            {
                "type": "verified_by",
                "source_event_id": "change-1",
                "target_event_id": "wrong-verification-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "verification.started",
            },
            {
                "type": "verified_by",
                "source_event_id": "change-1",
                "target_event_id": "invalid-verification-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "verification.finished",
                "reason": "invalid_verification_result",
            },
            {
                "type": "motivated_by",
                "source_event_id": "change-1",
                "target_event_id": "invalid-requirement-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "requirement.observed",
                "reason": "invalid_requirement_detail",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "invalid-context-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.read",
                "reason": "invalid_context_detail",
            },
            {
                "type": "informed_by",
                "source_event_id": "change-1",
                "target_event_id": "empty-compaction-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "context.compacted",
                "reason": "invalid_compaction_detail",
            },
            {
                "type": "preceded_by",
                "source_event_id": "change-1",
                "target_event_id": "invalid-tool-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "tool.call.completed",
                "reason": "invalid_tool_detail",
            },
            {
                "type": "verified_by",
                "source_event_id": "change-1",
                "target_event_id": "commandless-verification-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "verification.finished",
                "reason": "invalid_verification_command",
            },
            {
                "type": "applies",
                "source_event_id": "change-1",
                "target_event_id": "invalid-proposal-1",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
                "target_kind": "change.proposed",
                "reason": "invalid_decision_actor",
            },
            {
                "type": "references",
                "source_event_id": "change-1",
                "target_event_id": "missing-note",
                "source_kind": "change.applied",
                "source_actor_id": "reviewer-1",
            },
        ])
        self.assertIn(
            "wrong-verification-1",
            [link["target_event_id"] for link in change["links"]],
        )
        self.assertIn(
            "invalid-verification-1",
            [link["target_event_id"] for link in change["links"]],
        )
        self.assertIn(
            "invalid-requirement-1",
            [link["target_event_id"] for link in change["links"]],
        )
        self.assertIn(
            "invalid-context-1",
            [link["target_event_id"] for link in change["links"]],
        )
        self.assertIn(
            "invalid-tool-1",
            [link["target_event_id"] for link in change["links"]],
        )

    def test_blank_verification_commands_do_not_satisfy_verification_coverage(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for finished_command, started_command, invalid_finished in (
            (None, None, False),
            (" \t", None, False),
            (None, "\n ", False),
            (17, "pytest tests/test_session.py", True),
            (" " * 2, "pytest tests/test_session.py", True),
        ):
            with self.subTest(
                finished_command=finished_command,
                started_command=started_command,
            ):
                started_event = event_data(
                    event_id="verification-started-1",
                    sequence=4,
                    timestamp="2026-07-13T11:02:50Z",
                    kind="verification.started",
                )
                if started_command is not None:
                    started_event["attributes"] = {
                        "verification": {"command": started_command},
                    }
                finished_verification = {
                    "passed": True,
                    "test_origin": "pre_existing",
                }
                if finished_command is not None:
                    finished_verification["command"] = finished_command
                events = [
                    event_data(
                        event_id="requirement-1",
                        timestamp="2026-07-13T10:59:00Z",
                        kind="requirement.observed",
                        attributes={"requirement": {
                            "id": "R3",
                            "text": "Reject expiry.",
                        }},
                    ),
                    event_data(
                        event_id="context-1",
                        sequence=2,
                        timestamp="2026-07-13T10:59:00Z",
                        kind="context.read",
                        attributes={"context": {"path": "src/auth/config.py"}},
                    ),
                    event_data(
                        event_id="tool-1",
                        sequence=3,
                        timestamp="2026-07-13T11:02:00Z",
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {"command": "pytest"}},
                    ),
                    started_event,
                    event_data(
                        event_id="verification-finished-1",
                        sequence=5,
                        timestamp="2026-07-13T11:03:00Z",
                        kind="verification.finished",
                        attributes={"verification": finished_verification},
                        relationships=[{
                            "type": "completes",
                            "event_id": "verification-started-1",
                        }],
                    ),
                    event_data(
                        event_id="proposal-1",
                        emitter_id="change-worker",
                        sequence=6,
                        kind="change.proposed",
                    ),
                    event_data(
                        event_id="change-1",
                        emitter_id="change-worker",
                        sequence=7,
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[
                            {"type": "motivated_by", "event_id": "requirement-1"},
                            {"type": "informed_by", "event_id": "context-1"},
                            {"type": "preceded_by", "event_id": "tool-1"},
                            {
                                "type": "verified_by",
                                "event_id": "verification-finished-1",
                            },
                            {"type": "applies", "event_id": "proposal-1"},
                        ],
                    ),
                ]
                store = RunStore.from_lines(
                    json.dumps(event) + "\n" for event in events
                )

                change = store.run_detail("trace-1")["evidence_map"]["changes"][0]

                if invalid_finished:
                    self.assertEqual(change["links"][3]["verification"], {
                        "passed": True,
                        "command": "pytest tests/test_session.py",
                        "test_origin": "pre_existing",
                        "starts": [{
                            "event_id": "verification-started-1",
                            "actor_id": "reviewer-1",
                            "chronology": "before_finish",
                            "change_chronology": "after_change",
                            "command": "pytest tests/test_session.py",
                        }],
                    })
                    self.assertEqual(change["coverage"], {
                        "status": "incomplete",
                        "missing": [],
                        "unresolved_count": 1,
                    })
                    self.assertEqual(
                        change["unresolved"][0]["reason"],
                        "invalid_verification_command",
                    )
                else:
                    self.assertEqual(change["links"][3]["verification"], {
                        "passed": True,
                        "test_origin": "pre_existing",
                        "starts": [{
                            "event_id": "verification-started-1",
                            "actor_id": "reviewer-1",
                            "chronology": "before_finish",
                            "change_chronology": "after_change",
                        }],
                        "unresolved": [{
                            "type": "completes",
                            "event_id": "verification-started-1",
                            "target_kind": "verification.started",
                            "reason": "invalid_verification_command",
                        }],
                    })
                    self.assertEqual(change["coverage"], {
                        "status": "incomplete",
                        "missing": ["verification"],
                        "unresolved_count": 1,
                    })
                    self.assertEqual(change["unresolved"], [])

    def test_only_canonical_compaction_links_satisfy_context_coverage(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        for outer_type, inner_type, expected_status, expected_missing, unresolved_count in (
            ("references", "summarizes", "incomplete", ["context"], 0),
            ("informed_by", "references", "incomplete", ["context"], 1),
            ("informed_by", "summarizes", "complete", [], 0),
        ):
            with self.subTest(outer_type=outer_type, inner_type=inner_type):
                events = [
                    event_data(
                        event_id="requirement-1",
                        timestamp="2026-07-13T10:59:00Z",
                        kind="requirement.observed",
                        attributes={"requirement": {
                            "id": "R3",
                            "text": "Reject expiry.",
                        }},
                    ),
                    event_data(
                        event_id="context-1",
                        sequence=2,
                        timestamp="2026-07-13T11:00:00Z",
                        kind="context.read",
                        attributes={"context": {"path": "src/auth/config.py"}},
                    ),
                    event_data(
                        event_id="compaction-1",
                        sequence=3,
                        timestamp="2026-07-13T11:01:00Z",
                        kind="context.compacted",
                        relationships=[
                            {"type": inner_type, "event_id": "context-1"},
                            {"type": "references", "event_id": "missing-context"},
                        ],
                    ),
                    event_data(
                        event_id="tool-1",
                        sequence=4,
                        timestamp="2026-07-13T11:02:00Z",
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {"command": "pytest"}},
                    ),
                    event_data(
                        event_id="verification-1",
                        sequence=5,
                        timestamp="2026-07-13T11:03:00Z",
                        kind="verification.finished",
                        attributes={"verification": {
                            "command": "pytest",
                            "passed": True,
                            "test_origin": "pre_existing",
                        }},
                    ),
                    event_data(
                        event_id="proposal-1",
                        emitter_id="change-worker",
                        sequence=6,
                        kind="change.proposed",
                    ),
                    event_data(
                        event_id="change-1",
                        emitter_id="change-worker",
                        sequence=7,
                        kind="change.applied",
                        attributes={"change": hunk},
                        relationships=[
                            {"type": "motivated_by", "event_id": "requirement-1"},
                            {"type": outer_type, "event_id": "compaction-1"},
                            {"type": "preceded_by", "event_id": "tool-1"},
                            {"type": "verified_by", "event_id": "verification-1"},
                            {"type": "applies", "event_id": "proposal-1"},
                        ],
                    ),
                ]
                store = RunStore.from_lines(
                    json.dumps(event) + "\n" for event in events
                )

                coverage = store.run_detail("trace-1")["evidence_map"]["changes"][0]["coverage"]

                self.assertEqual(coverage, {
                    "status": expected_status,
                    "missing": expected_missing,
                    "unresolved_count": unresolved_count,
                })

    def test_invalid_compacted_context_detail_reduces_complete_coverage(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        events = [
            event_data(
                event_id="requirement-1",
                timestamp="2026-07-13T10:59:00Z",
                kind="requirement.observed",
                attributes={"requirement": {"id": "R3", "text": "Reject expiry."}},
            ),
            event_data(
                event_id="context-1",
                sequence=2,
                timestamp="2026-07-13T11:00:00Z",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            ),
            event_data(
                event_id="invalid-context-1",
                sequence=3,
                timestamp="2026-07-13T11:00:00Z",
                kind="context.read",
                attributes={"context": {"path": " \t"}},
            ),
            event_data(
                event_id="compaction-1",
                sequence=4,
                timestamp="2026-07-13T11:01:00Z",
                kind="context.compacted",
                relationships=[
                    {"type": "summarizes", "event_id": "context-1"},
                    {"type": "summarizes", "event_id": "invalid-context-1"},
                ],
            ),
            event_data(
                event_id="tool-1",
                sequence=5,
                timestamp="2026-07-13T11:02:00Z",
                kind="tool.call.completed",
                attributes={"tool": {"command": "pytest"}},
            ),
            event_data(
                event_id="verification-1",
                sequence=6,
                timestamp="2026-07-13T11:03:00Z",
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(
                event_id="proposal-1",
                emitter_id="change-worker",
                sequence=7,
                kind="change.proposed",
            ),
            event_data(
                event_id="change-1",
                emitter_id="change-worker",
                sequence=8,
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-1"},
                    {"type": "informed_by", "event_id": "compaction-1"},
                    {"type": "preceded_by", "event_id": "tool-1"},
                    {"type": "verified_by", "event_id": "verification-1"},
                    {"type": "applies", "event_id": "proposal-1"},
                ],
            ),
        ]
        store = RunStore.from_lines(json.dumps(event) + "\n" for event in events)

        change = store.run_detail("trace-1")["evidence_map"]["changes"][0]
        compaction = change["links"][1]["compaction"]

        self.assertEqual(change["coverage"], {
            "status": "incomplete",
            "missing": [],
            "unresolved_count": 1,
        })
        self.assertEqual(
            [source["event_id"] for source in compaction["sources"]],
            ["context-1"],
        )
        self.assertEqual(compaction["unresolved"], [{
            "type": "summarizes",
            "event_id": "invalid-context-1",
            "target_kind": "context.read",
            "reason": "invalid_context_detail",
        }])

    def test_change_hunks_include_later_human_corrections(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-1",
                span_id="span-2",
                sequence=2,
                kind="human.corrected",
                actor={"id": "maintainer-1"},
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-2",
                span_id="span-3",
                sequence=3,
                kind="human.corrected",
                actor={"id": "maintainer-1"},
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-3",
                span_id="span-4",
                sequence=4,
                kind="human.corrected",
                actor={"id": "maintainer-2"},
                attributes={"correction": {"action": ["edited"]}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="unrelated-correction",
                span_id="span-5",
                sequence=5,
                kind="human.corrected",
                actor={"id": "maintainer-unrelated"},
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "references", "event_id": "change-1"}],
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["changes"][0]["corrections"], [
            {
                "type": "corrects",
                "source_event_id": "correction-1",
                "target_event_id": "change-1",
                "source_kind": "human.corrected",
                "source_actor_id": "maintainer-1",
                "target_kind": "change.applied",
                "target_actor_id": "reviewer-1",
                "chronology": "after_change",
                "correction": {"action": "modified"},
            },
            {
                "type": "corrects",
                "source_event_id": "correction-2",
                "target_event_id": "change-1",
                "source_kind": "human.corrected",
                "source_actor_id": "maintainer-1",
                "target_kind": "change.applied",
                "target_actor_id": "reviewer-1",
                "chronology": "after_change",
                "correction": {"action": "reverted"},
            },
            {
                "type": "corrects",
                "source_event_id": "correction-3",
                "target_event_id": "change-1",
                "source_kind": "human.corrected",
                "source_actor_id": "maintainer-2",
                "target_kind": "change.applied",
                "target_actor_id": "reviewer-1",
                "chronology": "after_change",
                "reason": "invalid_correction_detail",
            },
        ])
        self.assertEqual(evidence["unresolved"], [{
            "type": "corrects",
            "source_event_id": "correction-3",
            "target_event_id": "change-1",
            "source_kind": "human.corrected",
            "source_actor_id": "maintainer-2",
            "target_kind": "change.applied",
            "reason": "invalid_correction_detail",
        }])
        self.assertEqual(evidence["links"][0], evidence["changes"][0]["corrections"][0])
        self.assertEqual(evidence["links"][-1], {
            "type": "references",
            "source_event_id": "unrelated-correction",
            "target_event_id": "change-1",
            "source_kind": "human.corrected",
            "source_actor_id": "maintainer-unrelated",
            "target_kind": "change.applied",
            "target_actor_id": "reviewer-1",
        })

    def test_correction_before_change_uses_same_emitter_sequence_ordering(self):
        hunk = {
            "path": "src/auth/session.py",
            "old_start": 84,
            "old_count": 18,
            "new_start": 84,
            "new_count": 19,
        }
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="change-1",
                sequence=2,
                timestamp="2026-07-13T11:02:00Z",
                kind="change.applied",
                attributes={"change": hunk},
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-before-change",
                span_id="span-before",
                sequence=1,
                timestamp="2026-07-13T11:03:00Z",
                kind="human.corrected",
                actor={"id": "early-maintainer"},
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-after-change",
                span_id="span-after",
                sequence=3,
                timestamp="2026-07-13T11:01:00Z",
                kind="human.corrected",
                actor={"id": "later-maintainer"},
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-same-time",
                span_id="span-same-time",
                emitter_id="maintainer-feed",
                timestamp="2026-07-13T11:02:00Z",
                kind="human.corrected",
                actor={"id": "current-maintainer"},
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]
        change = evidence["changes"][0]

        corrections = {
            correction["source_event_id"]: correction
            for correction in change["corrections"]
        }
        self.assertEqual(set(corrections), {
            "correction-before-change",
            "correction-after-change",
            "correction-same-time",
        })
        self.assertEqual(
            corrections["correction-before-change"]["correction"],
            {"action": "modified"},
        )
        self.assertEqual(
            corrections["correction-before-change"]["reason"],
            "correction_precedes_change",
        )
        self.assertEqual(
            corrections["correction-before-change"]["chronology"],
            "before_change",
        )
        self.assertNotIn("reason", corrections["correction-after-change"])
        self.assertEqual(
            corrections["correction-after-change"]["chronology"],
            "after_change",
        )
        self.assertEqual(
            corrections["correction-same-time"]["reason"],
            "correction_chronology_undetermined",
        )
        self.assertEqual(
            corrections["correction-same-time"]["chronology"],
            "undetermined",
        )
        self.assertEqual(evidence["unresolved"], [
            {
                "type": "corrects",
                "source_event_id": "correction-same-time",
                "target_event_id": "change-1",
                "source_kind": "human.corrected",
                "source_actor_id": "current-maintainer",
                "target_kind": "change.applied",
                "reason": "correction_chronology_undetermined",
            },
            {
                "type": "corrects",
                "source_event_id": "correction-before-change",
                "target_event_id": "change-1",
                "source_kind": "human.corrected",
                "source_actor_id": "early-maintainer",
                "target_kind": "change.applied",
                "reason": "correction_precedes_change",
            },
        ])
        self.assertEqual(change["coverage"]["unresolved_count"], 0)

    def test_wrong_kind_human_correction_target_is_an_unresolved_diagnostic(self):
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id="context-1",
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            )) + "\n",
            json.dumps(event_data(
                event_id="correction-1",
                span_id="span-2",
                sequence=2,
                kind="human.corrected",
                actor={"id": "maintainer-1"},
                attributes={"correction": {"action": "reverted"}},
                relationships=[{"type": "corrects", "event_id": "context-1"}],
            )) + "\n",
        ])

        evidence = store.run_detail("trace-1")["evidence_map"]

        self.assertEqual(evidence["unresolved"], [{
            "type": "corrects",
            "source_event_id": "correction-1",
            "target_event_id": "context-1",
            "source_kind": "human.corrected",
            "source_actor_id": "maintainer-1",
            "target_kind": "context.read",
        }])
        self.assertEqual(evidence["links"], [{
            "type": "corrects",
            "source_event_id": "correction-1",
            "target_event_id": "context-1",
            "source_kind": "human.corrected",
            "source_actor_id": "maintainer-1",
            "target_kind": "context.read",
            "target_actor_id": "reviewer-1",
            "context": {"path": "src/auth/config.py"},
            "correction": {"action": "reverted"},
        }])
        self.assertEqual(evidence["changes"], [])

    def test_http_server_serves_offline_shell_and_versioned_api(self):
        store = RunStore.from_lines([
            json.dumps(event_data(trace_id="trace/1", kind="<script>kind</script>")) + "\n"
        ])
        server = make_server(store, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

        html = urlopen(base_url + "/", timeout=2).read().decode("utf-8")
        root_response = urlopen(base_url + "/", timeout=2)
        runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=2).read())
        detail = json.loads(urlopen(base_url + "/api/v1/runs/trace%2F1", timeout=2).read())
        payload = json.loads(urlopen(base_url + "/api/v1/runs/trace%2F1/events/evt-1/payload", timeout=2).read())

        self.assertIn("AgentTrail", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("Access-Control-Allow-Origin", root_response.headers)
        self.assertIn("textContent", html)
        self.assertIn('data-view="graph"', html)
        self.assertIn('data-view="tree"', html)
        self.assertIn('data-view="swimlane"', html)
        self.assertIn('data-view="sequence"', html)
        self.assertIn('data-action="focus"', html)
        self.assertIn('data-action="clear-focus"', html)
        self.assertIn('data-action="reset"', html)
        self.assertIn('visibleLimit', html)
        self.assertIn("stageEl.addEventListener('wheel'", html)
        self.assertIn('id="playback-toggle"', html)
        self.assertIn('id="scrubber"', html)
        self.assertIn('id="speed"', html)
        self.assertIn('id="jump-live"', html)
        self.assertIn('id="search"', html)
        self.assertIn('id="inspector"', html)
        self.assertIn('id="warnings-drawer"', html)
        self.assertIn('Load retained payload', html)
        self.assertIn('cost_usd', html)
        self.assertIn('detected_at', html)
        self.assertIn("stream.addEventListener('heartbeat'", html)
        self.assertIn("stream.addEventListener('reset'", html)
        self.assertIn("await refreshAuthoritative()", html)
        self.assertIn("if (!events) connectEvents()", html)
        self.assertIn('renderWarningsDrawer', html)
        self.assertIn('renderSwimlane', html)
        self.assertIn('renderSequence', html)
        self.assertIn('eventsAtHorizon', html)
        self.assertIn("focusedAgentId", html)
        self.assertIn('buildForest', html)
        self.assertIn('Focus subtree', html)
        self.assertEqual(runs["runs"][0]["trace_id"], "trace/1")
        self.assertEqual(detail["events"][0]["event_id"], "evt-1")
        self.assertEqual(payload["event_id"], "evt-1")

        with self.assertRaises(HTTPError) as raised:
            urlopen(base_url + "/api/v1/runs/missing", timeout=2).read()
        self.assertEqual(raised.exception.code, 404)

    def test_remote_token_protects_api_routes(self):
        store = RunStore.from_lines([json.dumps(event_data()) + "\n"])
        server = make_server(store, host="127.0.0.1", port=0)
        server.access_token = "secret-token"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

        with self.assertRaises(HTTPError) as raised:
            urlopen(base_url + "/api/v1/runs", timeout=2).read()
        authorized = json.loads(
            urlopen(base_url + "/api/v1/runs?token=secret-token", timeout=2).read()
        )

        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(authorized["runs"][0]["trace_id"], "trace-1")

    def test_remote_access_guardrails_reject_unsafe_configurations(self):
        with self.assertRaisesRegex(ValueError, "remote-access"):
            serve(
                io.StringIO(""),
                config=ServeConfig(host="0.0.0.0"),
            )
        with self.assertRaisesRegex(ValueError, "unsafe-unredacted"):
            serve(
                io.StringIO(""),
                config=ServeConfig(remote_access=True, unsafe_unredacted=True),
            )

    def test_growing_file_appends_are_delivered_over_sse_and_reconnect(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            store = RunStore(source_kind="file")
            stop = threading.Event()
            follower = start_file_follower(
                source, store, config=ServeConfig(), stop=stop, poll_seconds=0.01
            )
            self.addCleanup(stop.set)
            self.addCleanup(lambda: follower.join(timeout=1))
            self.assertTrue(_wait_until(lambda: store.list_runs()["runs"]))
            cursor = store.cursor
            server = make_server(store, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

            response = urlopen(base_url + f"/api/v1/events?cursor={cursor}", timeout=2)
            with source.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event_data(
                    event_id="evt-2",
                    span_id="span-2",
                    sequence=2,
                )) + "\n")
            payload = _read_sse_data(response)
            response.close()
            detail = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=2).read())
            response = urlopen(
                base_url + f"/api/v1/events?cursor={detail['cursor']}",
                timeout=2,
            )
            with source.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event_data(
                    event_id="evt-3",
                    span_id="span-3",
                    sequence=3,
                )) + "\n")
            reconnected_payload = _read_sse_data(response)
            response.close()
            reconnected_detail = json.loads(
                urlopen(base_url + "/api/v1/runs/trace-1", timeout=2).read()
            )

        self.assertEqual(payload["event_id"], "evt-2")
        self.assertEqual(reconnected_payload["event_id"], "evt-3")
        self.assertEqual(
            [event["event_id"] for event in detail["events"]],
            ["evt-1", "evt-2"],
        )
        self.assertEqual(
            [event["event_id"] for event in reconnected_detail["events"]],
            ["evt-1", "evt-2", "evt-3"],
        )
        self.assertEqual(
            len({event["event_id"] for event in reconnected_detail["events"]}),
            3,
        )

    def test_http_sse_returns_typed_reset_for_history_gap(self):
        store = RunStore(max_live_updates=2)
        for number in range(1, 4):
            store.add_finding("test", f"FINDING_{number}", f"finding {number}")
        server = make_server(store, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

        response = urlopen(base_url + "/api/v1/events?cursor=0", timeout=2)
        frame = _read_sse_frame(response)
        response.close()

        self.assertEqual(frame["id"], "3")
        self.assertEqual(frame["event"], "reset")
        self.assertEqual(frame["data"], {
            "requested_cursor": 0,
            "oldest_retained_cursor": 2,
            "current_cursor": 3,
            "reason": "history_gap",
        })
        self.assertEqual(store.cursor, 3)

    def test_file_follower_waits_for_complete_jsonl_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            store = RunStore(source_kind="file")
            stop = threading.Event()
            follower = start_file_follower(
                source, store, config=ServeConfig(), stop=stop, poll_seconds=0.01
            )
            self.addCleanup(stop.set)
            self.addCleanup(lambda: follower.join(timeout=1))
            self.assertTrue(_wait_until(lambda: store.list_runs()["runs"]))
            partial = json.dumps(event_data(
                event_id="evt-2",
                span_id="span-2",
                sequence=2,
            ))

            with source.open("a", encoding="utf-8") as handle:
                split_at = partial.index('"span_id"')
                handle.write(partial[:split_at])
                handle.flush()
            time.sleep(0.05)
            self.assertEqual(store.run_detail("trace-1")["run"]["event_count"], 1)

            with source.open("a", encoding="utf-8") as handle:
                handle.write(partial[split_at:] + "\n")
            self.assertTrue(_wait_until(
                lambda: store.run_detail("trace-1")["run"]["event_count"] == 2
            ))
            codes = {finding["code"] for finding in store.list_runs()["findings"]}

        self.assertNotIn("INVALID_JSON", codes)

    def test_stdin_eof_marks_incomplete_without_completing_trace(self):
        store = RunStore(source_kind="stdin")
        serve_module._read_stream(
            io.StringIO(json.dumps(event_data()) + "\n"),
            store,
            ServeConfig(),
        )

        detail = store.run_detail("trace-1")

        self.assertEqual(detail["source"]["state"], "disconnected")
        self.assertFalse(detail["source"]["connected"])
        self.assertEqual(detail["run"]["state"], "incomplete")

    def test_explicit_terminal_events_drive_run_states_and_late_findings(self):
        for kind, state in (("trace.completed", "completed"), ("trace.failed", "failed")):
            with self.subTest(kind=kind):
                store = RunStore(source_kind="stdin")
                store.set_source_status(connected=True, state="reading")
                store.feed_line(json.dumps(event_data()) + "\n")
                store.feed_line(json.dumps(event_data(
                    event_id=f"evt-{state}",
                    span_id=f"span-{state}",
                    sequence=2,
                    kind=kind,
                    operation={"status": state},
                )) + "\n")

                self.assertEqual(store.run_detail("trace-1")["run"]["state"], state)

        store = RunStore(source_kind="stdin")
        store.set_source_status(connected=True, state="reading")
        store.feed_line(json.dumps(event_data(kind="trace.completed")) + "\n")
        store.feed_line(json.dumps(event_data(
            event_id="late",
            span_id="late",
            sequence=2,
        )) + "\n")

        codes = {finding["code"] for finding in store.run_detail("trace-1")["findings"]}
        self.assertIn("LATE_EVENT", codes)

    def test_ingestion_findings_are_visible(self):
        store = RunStore(source_kind="file")
        store.feed_line("not json\n")
        store.feed_line(json.dumps(event_data()) + "\n")
        store.feed_line(json.dumps(event_data()) + "\n")

        codes = {finding["code"] for finding in store.list_runs()["findings"]}

        self.assertIn("INVALID_JSON", codes)
        self.assertIn("DUPLICATE_EVENT", codes)

    def test_lazy_payload_detail_retains_sanitized_full_payload(self):
        store = RunStore.from_lines([
            json.dumps(event_data(payload={"text": "x" * 5000, "token": "Bearer hidden"})) + "\n"
        ])

        detail = store.run_detail("trace-1")
        payload = store.event_payload("trace-1", "evt-1")

        self.assertTrue(detail["events"][0]["payload"]["metadata"]["truncated"])
        self.assertFalse(payload["payload"]["metadata"]["truncated"])
        self.assertIn("x" * 100, payload["payload"]["preview"]["text"])
        self.assertNotIn("hidden", json.dumps(payload))

    def test_metadata_only_precedes_index_store_projection_sse_and_lazy_payload(self):
        sentinel = "payload-only-store-sentinel"
        store = RunStore.from_lines([
            json.dumps(event_data(
                attributes={
                    "change": {
                        "path": "src/retained.py",
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 2,
                    },
                    "note": "Bearer retained-secret",
                },
                kind="change.applied",
                payload={"body": sentinel},
            )) + "\n"
        ], metadata_only=True)

        detail = store.run_detail("trace-1")
        update = next(store.stream_updates(after=0))
        lazy = store.event_payload("trace-1", "evt-1")
        indexed = json.dumps(store._index.events[0].raw)
        combined = json.dumps((detail, update, lazy))

        self.assertNotIn(sentinel, indexed + combined)
        self.assertNotIn("retained-secret", combined)
        self.assertEqual(detail["payload_mode"], "metadata-only")
        self.assertEqual(detail["run"]["payload_mode"], "metadata-only")
        self.assertEqual(detail["events"][0]["payload"]["state"], "omitted")
        self.assertEqual(update["data"]["payload"]["state"], "omitted")
        self.assertEqual(lazy["payload"]["state"], "omitted")
        self.assertNotIn("preview", lazy["payload"])
        self.assertEqual(
            detail["evidence_map"]["changes"][0]["hunk"]["path"],
            "src/retained.py",
        )
        self.assertFalse(any(
            warning["code"] == "EVICT" for warning in detail["warnings"]
        ))

    def test_metadata_only_preserves_complete_change_evidence_attributes(self):
        events = [
            event_data(
                event_id="requirement-1",
                kind="requirement.observed",
                attributes={"requirement": {"id": "R1", "text": "Keep evidence."}},
            ),
            event_data(
                event_id="context-1",
                span_id="span-context",
                sequence=2,
                kind="context.read",
                attributes={"context": {
                    "path": "src/context.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "target",
                }},
            ),
            event_data(
                event_id="tool-1",
                span_id="span-tool",
                sequence=3,
                kind="tool.call.completed",
                attributes={"tool": {
                    "command": "git diff --check",
                    "result": "clean",
                    "exit_code": 0,
                }},
            ),
            event_data(
                event_id="proposal-1",
                span_id="span-proposal",
                sequence=4,
                kind="change.proposed",
            ),
            event_data(
                event_id="change-1",
                span_id="span-change",
                sequence=5,
                kind="change.applied",
                attributes={"change": {
                    "path": "src/change.py",
                    "old_start": 10,
                    "old_count": 1,
                    "new_start": 10,
                    "new_count": 2,
                }},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-1"},
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "preceded_by", "event_id": "tool-1"},
                    {"type": "applies", "event_id": "proposal-1"},
                    {"type": "verified_by", "event_id": "verification-1"},
                ],
            ),
            event_data(
                event_id="verification-1",
                span_id="span-verification",
                sequence=6,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "exit_code": 0,
                    "test_origin": "same_agent",
                }},
            ),
            event_data(
                event_id="correction-1",
                span_id="span-correction",
                sequence=7,
                kind="human.corrected",
                attributes={"correction": {"action": "modified"}},
                relationships=[{"type": "corrects", "event_id": "change-1"}],
            ),
        ]
        for event in events:
            event["payload"] = {"sentinel": f"payload-{event['event_id']}"}
        store = RunStore.from_lines(
            (json.dumps(event) + "\n" for event in events),
            metadata_only=True,
        )

        evidence = store.run_detail("trace-1")["evidence_map"]
        change = evidence["changes"][0]

        self.assertEqual(change["hunk"]["path"], "src/change.py")
        self.assertEqual(
            change["coverage"]["status"],
            "incomplete",
            change["coverage"],
        )
        self.assertEqual(change["coverage"]["missing"], [])
        self.assertEqual(change["coverage"]["same_agent_test_count"], 1)
        self.assertEqual(change["corrections"][0]["correction"]["action"], "modified")
        self.assertEqual(
            next(link["requirement"] for link in change["links"] if "requirement" in link)["id"],
            "R1",
        )
        self.assertEqual(
            next(link["context"] for link in change["links"] if "context" in link)["symbol"],
            "target",
        )
        self.assertEqual(
            next(link["tool"] for link in change["links"] if "tool" in link)["command"],
            "git diff --check",
        )
        self.assertTrue(next(
            link["verification"]["passed"]
            for link in change["links"]
            if "verification" in link
        ))
        self.assertNotIn("payload-", json.dumps(store.run_detail("trace-1")))

    def test_lazy_payload_detail_respects_payload_eviction(self):
        store = RunStore.from_lines([
            json.dumps(event_data(payload={"text": "x" * 5000})) + "\n"
        ], max_bytes=1000)

        payload = store.event_payload("trace-1", "evt-1")
        encoded = json.dumps(payload)

        self.assertNotIn("x" * 100, encoded)
        self.assertIn("metadata", encoded)

    def test_runtime_warning_history_marks_resolved_warnings(self):
        store = RunStore(source_kind="stdin")
        store.set_source_status(connected=True, state="reading")
        store.feed_line(json.dumps(event_data(
            timestamp="2000-01-01T00:00:00Z",
        )) + "\n")

        active = json.loads(json.dumps(store.run_detail("trace-1")["warnings"]))
        store.set_source_status(connected=False, state="disconnected")
        resolved = store.run_detail("trace-1")["warnings"]

        self.assertTrue(any(warning["code"] == "STALL" and warning["active"] for warning in active))
        self.assertTrue(any(warning["code"] == "STALL" and not warning["active"] for warning in resolved))

    def test_file_replacement_and_truncation_are_source_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            replacement = Path(directory, "replacement.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            store = RunStore(source_kind="file")
            stop = threading.Event()
            follower = start_file_follower(
                source, store, config=ServeConfig(), stop=stop, poll_seconds=0.01
            )
            self.addCleanup(stop.set)
            self.addCleanup(lambda: follower.join(timeout=1))
            self.assertTrue(_wait_until(lambda: store.list_runs()["runs"]))

            replacement.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            replacement.replace(source)
            self.assertTrue(_wait_until(
                lambda: any(
                    finding["code"] == "SOURCE_REPLACED"
                    for finding in store.list_runs()["findings"]
                )
            ))
            self.assertTrue(_wait_until(
                lambda: any(
                    finding["code"] == "DUPLICATE_EVENT"
                    for finding in store.list_runs()["findings"]
                )
            ))
            source.write_text("", encoding="utf-8")
            self.assertTrue(_wait_until(
                lambda: any(
                    finding["code"] == "SOURCE_TRUNCATED"
                    for finding in store.list_runs()["findings"]
                )
            ))

    def test_projection_includes_agents_links_usage_and_warnings(self):
        lines = [
            json.dumps(event_data(
                actor={"id": "lead", "role": "planner"},
                span_id="lead-span",
                usage={"input_tokens": 10, "cost_usd": 0.25},
            )) + "\n",
            json.dumps(event_data(
                event_id="child-start",
                actor={"id": "worker", "role": "executor"},
                span_id="worker-span",
                parent_span_id="lead-span",
                sequence=2,
                attributes={"model": "model-a"},
                usage={"output_tokens": 4, "total_tokens": 14},
            )) + "\n",
            json.dumps(event_data(
                event_id="handoff",
                actor={"id": "lead"},
                span_id="lead-msg",
                sequence=3,
                kind="message.sent",
                attributes={"to": "worker"},
            )) + "\n",
            json.dumps(event_data(
                event_id="missing-handoff",
                actor={"id": "worker"},
                span_id="worker-msg",
                sequence=4,
                kind="message.sent",
                attributes={"to": "missing-agent"},
            )) + "\n",
            json.dumps(event_data(
                event_id="other-parent",
                actor={"id": "observer"},
                span_id="observer-span",
                sequence=5,
            )) + "\n",
            json.dumps(event_data(
                event_id="ambiguous",
                actor={"id": "worker"},
                span_id="worker-later",
                parent_span_id="observer-span",
                sequence=6,
            )) + "\n",
            json.dumps(event_data(
                event_id="fallback-parent",
                actor={"id": "fallback"},
                span_id="fallback-root",
                emitter_id="fallback-parent-emitter",
                sequence=1,
                timestamp="2026-07-13T11:03:00Z",
                kind="tool.call.progress",
            )) + "\n",
            json.dumps(event_data(
                event_id="uncertain-child",
                actor={"id": "uncertain-worker"},
                span_id="uncertain-child",
                parent_span_id="fallback-root",
                emitter_id="uncertain-child-emitter",
                sequence=1,
                timestamp="2026-07-13T11:02:00Z",
            )) + "\n",
        ]
        store = RunStore.from_lines(lines)

        detail = store.run_detail("trace-1")
        worker = next(actor for actor in detail["actors"] if actor["id"] == "worker")
        uncertain = next(
            event for event in detail["events"]
            if event["event_id"] == "uncertain-child"
        )
        links = {(link["type"], link.get("source_actor_id"), link.get("target_actor_id"), link.get("unresolved_target")) for link in detail["links"]}
        warning_codes = {warning["code"] for warning in detail["warnings"]}

        self.assertEqual(worker["parent_id"], "lead")
        self.assertEqual(worker["role"], "executor")
        self.assertEqual(worker["model"], "model-a")
        self.assertIn(("spawn", "lead", "worker", None), links)
        self.assertIn(("causal", "observer", "worker", None), links)
        self.assertIn(("message", "lead", "worker", None), links)
        self.assertIn(("message", "worker", None, "missing-agent"), links)
        self.assertNotIn(("spawn", "fallback", "uncertain-worker", None), links)
        self.assertEqual(detail["unresolved_endpoints"][0]["id"], "missing-agent")
        self.assertIn("AMBIGUOUS_PARENT", warning_codes)
        self.assertEqual(detail["run"]["warning_count"], len(detail["warnings"]))
        self.assertEqual(detail["usage"]["input_tokens"], {"available": True, "value": 10})
        self.assertEqual(detail["usage"]["output_tokens"], {"available": True, "value": 4})
        self.assertEqual(detail["usage"]["cost_usd"], {"available": True, "value": 0.25})
        self.assertFalse(detail["events"][2]["usage"]["input_tokens"]["available"])
        self.assertEqual(detail["duration_seconds"], 60.0)
        self.assertTrue(uncertain["uncertain"])

    def test_serve_cli_dispatches_without_changing_default_invocation(self):
        with mock.patch.object(cli, "serve", return_value=0) as serve:
            result = cli.main(["serve", "-", "--host", "127.0.0.1", "--port", "0"])

        self.assertEqual(result, 0)
        serve.assert_called_once()
        self.assertEqual(serve.call_args.kwargs["config"].host, "127.0.0.1")
        self.assertEqual(serve.call_args.kwargs["config"].port, 0)
        self.assertEqual(serve.call_args.kwargs["config"].max_live_updates, 10_000)

        with mock.patch.object(cli, "serve", return_value=0) as configured_serve:
            result = cli.main(["serve", "-", "--max-live-updates", "25"])

        self.assertEqual(result, 0)
        self.assertEqual(
            configured_serve.call_args.kwargs["config"].max_live_updates,
            25,
        )

    def test_serve_prints_generated_token_url_and_honors_browser_open(self):
        class FakeServer:
            server_address = ("127.0.0.1", 43210)

            def serve_forever(self):
                raise KeyboardInterrupt

            def server_close(self):
                pass

        opened = []
        stdout = io.StringIO()
        with (
            mock.patch("agent_tail.serve.make_server", return_value=FakeServer()),
            mock.patch("agent_tail.serve.secrets.token_urlsafe", return_value="test-token"),
            mock.patch("sys.stdout", stdout),
        ):
            result = serve(
                io.StringIO(json.dumps(event_data()) + "\n"),
                config=ServeConfig(
                    port=0,
                    open_browser=True,
                    remote_access=True,
                ),
                open_url=opened.append,
            )

        self.assertEqual(result, 0)
        self.assertIn("http://127.0.0.1:43210/?token=test-token", stdout.getvalue())
        self.assertIn("WARNING: remote access is enabled", stdout.getvalue())
        self.assertEqual(opened, ["http://127.0.0.1:43210/?token=test-token"])

    def test_serve_cli_input_validation_errors_return_two(self):
        with mock.patch.object(cli.sys, "stderr", io.StringIO()):
            result = cli.main(["serve", "does-not-exist.jsonl"])

        self.assertEqual(result, 2)

    def test_serve_cli_max_live_updates_must_be_positive(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_tail",
                "serve",
                "-",
                "--max-live-updates",
                "0",
            ],
            input="",
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("must be a positive integer", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_default_cli_path_still_accepts_file_input(self):
        source = Path(__file__).parent / "fixtures" / "runtime.jsonl"
        stdout = io.StringIO()
        with (
            mock.patch.object(cli.sys.stdout, "isatty", return_value=False),
            mock.patch.object(cli.sys, "stdout", stdout),
            mock.patch.object(cli.sys, "stderr", io.StringIO()),
        ):
            result = cli.main([str(source)])

        self.assertEqual(result, 0)
        self.assertIn("AGENT LANES", stdout.getvalue())

class ContextProvenanceTests(unittest.TestCase):
    def test_forward_and_late_reads_keep_freshness_separate_from_chronology(self):
        digest = "4" * 64
        events = [
            event_data(
                event_id="change-forward", span_id="change", sequence=2,
                timestamp="2026-07-18T12:00:00Z", kind="change.applied",
                attributes={"change": {
                    "path": "src/forward.py", "old_start": 1, "old_count": 1,
                    "new_start": 1, "new_count": 1, "preimage_sha256": digest,
                }},
                relationships=[{"type": "informed_by", "event_id": "read-forward"}],
            ),
            event_data(
                event_id="read-forward", span_id="read", sequence=1,
                timestamp="2026-07-18T12:00:00Z", kind="context.read",
                attributes={"context": {
                    "path": "src/forward.py", "content_sha256": digest,
                }},
            ),
            event_data(
                event_id="read-late", span_id="late", sequence=3,
                timestamp="2026-07-18T11:59:00Z", kind="context.read",
                attributes={"context": {
                    "path": "src/forward.py", "content_sha256": "5" * 64,
                }},
            ),
        ]
        projection = RunStore.from_lines(
            json.dumps(item) + "\n" for item in events
        ).run_detail("trace-1")["context_provenance"]

        self.assertEqual(
            projection["by_event_id"]["read-forward"]["comparisons"],
            [{
                "read_event_id": "read-forward",
                "change_event_id": "change-forward",
                "chronology": "before_change",
                "freshness": "fresh",
            }],
        )
        self.assertEqual(
            projection["by_event_id"]["read-late"]["comparisons"][0],
            {
                "read_event_id": "read-late",
                "change_event_id": "change-forward",
                "chronology": "after_change",
                "freshness": "stale",
            },
        )

    def test_projects_stale_search_compaction_and_clock_skew_without_text(self):
        old_hash = "1" * 64
        current_hash = "2" * 64
        worktree = "3" * 64
        events = [
            event_data(
                event_id="read-1", sequence=1,
                timestamp="2026-07-18T12:04:00Z", kind="context.read",
                attributes={
                    "context": {
                        "path": "src/./main.py", "line_start": 4,
                        "content_sha256": old_hash, "contents": "must not project",
                    },
                    "repository": {"commit": "abc123", "worktree_sha256": worktree},
                },
            ),
            event_data(
                event_id="search-1", span_id="search", sequence=2,
                timestamp="2026-07-18T12:03:00Z", kind="context.search",
                attributes={"search": {
                    "query": "ContextProvenance", "matches": [
                        "src/main.py", "src/main.py", "../secret", "/etc/passwd",
                    ],
                    "summary": "must not project",
                }},
            ),
            event_data(
                event_id="compact-1", span_id="compact", sequence=3,
                timestamp="2026-07-18T12:02:00Z", kind="context.compacted",
                attributes={"summary": "must not project"},
                relationships=[{"type": "summarizes", "event_id": "read-1"}],
            ),
            event_data(
                event_id="change-1", span_id="change", sequence=4,
                timestamp="2026-07-18T12:01:00Z", kind="change.applied",
                attributes={
                    "change": {
                        "path": "src/main.py", "old_start": 1, "old_count": 1,
                        "new_start": 1, "new_count": 1,
                        "preimage_sha256": current_hash,
                    },
                    "repository": {"commit": "abc123", "worktree_sha256": worktree},
                },
                relationships=[{"type": "informed_by", "event_id": "compact-1"}],
            ),
        ]
        detail = RunStore.from_lines(json.dumps(item) + "\n" for item in events).run_detail(
            "trace-1"
        )
        projection = detail["context_provenance"]
        read = projection["by_event_id"]["read-1"]
        search = projection["by_event_id"]["search-1"]
        change = projection["by_event_id"]["change-1"]

        self.assertEqual(read["locator"]["normalized_path"], "src/main.py")
        self.assertEqual(read["freshness"], "stale")
        self.assertEqual(read["comparisons"][0]["chronology"], "before_change")
        self.assertEqual(change["freshness"], "stale")
        self.assertEqual(search["query"], "ContextProvenance")
        self.assertEqual(search["canonical_matches"], ["src/main.py"])
        self.assertEqual(
            [item["code"] for item in search["diagnostics"]],
            [
                "duplicate_search_match", "parent_traversal_repository_path",
                "absolute_repository_path",
            ],
        )
        self.assertNotIn("contents", json.dumps(projection))
        self.assertNotIn("must not project", json.dumps(projection))
        self.assertNotIn("must not project", json.dumps(detail))
        self.assertEqual(detail["evidence_map"]["changes"][0]["event_id"], "change-1")

    def test_missing_malformed_hashes_and_unsafe_paths_remain_unknown(self):
        events = [
            event_data(
                event_id="read-unsafe", kind="context.read",
                attributes={"context": {
                    "path": "../../src/main.py", "content_sha256": "A" * 64,
                }},
            ),
            event_data(
                event_id="change-unsafe", span_id="change", sequence=2,
                kind="change.applied", attributes={"change": {
                    "path": "../../src/main.py", "old_start": 1, "old_count": 1,
                    "new_start": 1, "new_count": 1,
                }},
            ),
            event_data(
                event_id="empty-search", span_id="search", sequence=3,
                kind="context.search",
                attributes={"search": {"query": "nothing", "matches": []}},
            ),
        ]
        projection = RunStore.from_lines(
            json.dumps(item) + "\n" for item in events
        ).run_detail("trace-1")["context_provenance"]
        read = projection["by_event_id"]["read-unsafe"]
        change = projection["by_event_id"]["change-unsafe"]

        self.assertEqual(read["locator"]["raw_path"], "../../src/main.py")
        self.assertNotIn("normalized_path", read["locator"])
        self.assertEqual(read["content_sha256"]["availability"], "malformed")
        self.assertEqual(read["freshness"], "unknown")
        self.assertEqual(change["freshness"], "unknown")
        self.assertEqual(projection["by_event_id"]["empty-search"]["canonical_matches"], [])
        self.assertFalse(any(item["code"] == "stale_context_read" for item in projection["diagnostics"]))

    def test_equal_time_cross_actor_snapshots_diverge_but_ordered_events_do_not(self):
        events = [
            event_data(
                event_id="actor-a", emitter_id="a", actor={"id": "a"},
                timestamp="2026-07-18T12:00:00Z", kind="context.read",
                attributes={
                    "context": {"path": "a.py"},
                    "repository": {"commit": "commit-a", "worktree_sha256": "a" * 64},
                },
            ),
            event_data(
                event_id="actor-b", emitter_id="b", actor={"id": "b"},
                timestamp="2026-07-18T12:00:00Z", kind="context.search",
                attributes={
                    "search": {"query": "x", "matches": []},
                    "repository": {"commit": "commit-b", "worktree_sha256": "b" * 64},
                },
            ),
            event_data(
                event_id="actor-c", emitter_id="a", sequence=2, actor={"id": "c"},
                timestamp="2026-07-18T12:01:00Z", kind="context.read",
                attributes={
                    "context": {"path": "c.py"},
                    "repository": {"commit": "commit-c"},
                },
            ),
        ]
        projection = RunStore.from_lines(
            json.dumps(item) + "\n" for item in events
        ).run_detail("trace-1")["context_provenance"]
        divergent = [
            item for item in projection["diagnostics"]
            if item["code"] == "divergent_repository_snapshot"
        ]

        equal_time = next(
            item for item in divergent
            if item["event_ids"] == ["actor-a", "actor-b"]
        )
        self.assertEqual(equal_time["fields"], ["commit", "worktree_sha256"])
        self.assertFalse(any(
            item["event_ids"] == ["actor-a", "actor-c"] for item in divergent
        ))
        self.assertFalse(any(
            item["event_ids"] == ["actor-b", "actor-c"] for item in divergent
        ))

    def test_explicit_causal_snapshot_order_suppresses_divergence(self):
        events = [
            event_data(
                event_id="context-source", emitter_id="source", sequence=1,
                actor={"id": "source"}, timestamp="2026-07-18T12:00:00Z",
                kind="context.read", attributes={
                    "context": {"path": "source.py"},
                    "repository": {"commit": "commit-source"},
                },
            ),
            event_data(
                event_id="causal-bridge", emitter_id="source", sequence=2,
                span_id="bridge-span", actor={"id": "bridge"},
                timestamp="2026-07-18T12:00:00Z", kind="agent.started",
            ),
            event_data(
                event_id="context-child", emitter_id="child", sequence=1,
                span_id="child-span", parent_span_id="bridge-span",
                actor={"id": "child"}, timestamp="2026-07-18T12:00:00Z",
                kind="context.search", attributes={
                    "search": {"query": "child", "matches": []},
                    "repository": {"commit": "commit-child"},
                },
            ),
        ]
        projection = RunStore.from_lines(
            json.dumps(item) + "\n" for item in events
        ).run_detail("trace-1")["context_provenance"]

        self.assertFalse(any(
            item["code"] == "divergent_repository_snapshot"
            for item in projection["diagnostics"]
        ))


def _wait_until(callback, *, timeout: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if callback():
            return True
        time.sleep(0.01)
    return False


def _read_sse_data(response) -> dict[str, object]:
    for _ in range(50):
        line = response.readline().decode("utf-8")
        if line.startswith("data: "):
            return json.loads(line.removeprefix("data: "))
    raise AssertionError("SSE data frame was not received")


def _read_sse_frame(response) -> dict[str, object]:
    frame = {}
    for _ in range(50):
        line = response.readline().decode("utf-8").rstrip("\n")
        if not line:
            if frame:
                return frame
            continue
        key, value = line.split(": ", 1)
        frame[key] = json.loads(value) if key == "data" else value
    raise AssertionError("SSE frame was not received")


if __name__ == "__main__":
    unittest.main()
