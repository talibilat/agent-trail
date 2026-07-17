import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest import mock

from agent_tail import cli
import agent_tail.serve as serve_module
from agent_tail.serve import RunStore, ServeConfig, make_server, serve, start_file_follower


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
            span_id="span-2",
            sequence=2,
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
                kind="requirement.observed",
                attributes={"requirement": {"id": "R3", "text": "Reject expiry."}},
            ),
            event_data(
                event_id="context-1",
                sequence=2,
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            ),
            event_data(
                event_id="tool-1",
                sequence=3,
                kind="tool.call.completed",
                attributes={"tool": {"command": "git diff --check"}},
            ),
            event_data(
                event_id="verification-1",
                sequence=4,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(event_id="proposal-1", sequence=5, kind="change.proposed"),
            event_data(
                event_id="change-1",
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
                span_id="span-4",
                sequence=4,
                kind="verification.started",
                actor={"id": "commandless-runner"},
                attributes={"verification": {"command": " \t"}},
            )) + "\n",
        ])

        before_detail = store.run_detail("trace-1")
        before_start = before_detail["evidence_map"]["changes"][0]
        self.assertEqual(len(before_detail["events"][1]["relationships"]), 4)
        self.assertEqual(before_start["links"][0]["verification"], {
            "passed": True,
            "exit_code": 0,
            "test_origin": "pre_existing",
            "starts": [{
                "event_id": "verification-started-without-command",
                "actor_id": "commandless-runner",
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
            span_id="span-3",
            sequence=4,
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
                "command": "pytest tests/test_session.py",
            }, {
                "event_id": "verification-started-without-command",
                "actor_id": "commandless-runner",
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
            }],
            "unresolved": [{
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
                "unresolved_count": 2,
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
        self.assertEqual(len(compaction["unresolved"]), 1)
        self.assertEqual(change["coverage"]["unresolved_count"], 1)

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
                        kind="requirement.observed",
                        attributes={"requirement": {
                            "id": "R3",
                            "text": "Reject expiry.",
                        }},
                    ),
                    event_data(
                        event_id="context-1",
                        sequence=2,
                        kind="context.read",
                        attributes={"context": {"path": "src/auth/config.py"}},
                    ),
                    event_data(
                        event_id="tool-1",
                        sequence=3,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {"command": "pytest"}}
                        if include_tool_detail else None,
                    ),
                    event_data(
                        event_id="verification-1",
                        sequence=4,
                        kind="verification.finished",
                        attributes={"verification": verification},
                    ),
                    event_data(
                        event_id="proposal-1",
                        sequence=5,
                        kind="change.proposed",
                        actor={"id": "planner-1"},
                    ),
                    event_data(
                        event_id="change-1",
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
                kind="requirement.observed",
                attributes={"requirement": {"id": "R3", "text": "Reject expiry."}},
            ),
            event_data(
                event_id="context-1",
                sequence=2,
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            ),
            event_data(
                event_id="tool-1",
                sequence=3,
                kind="tool.call.completed",
                attributes={"tool": {"command": "pytest"}},
            ),
            event_data(
                event_id="verification-1",
                sequence=4,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(event_id="proposal-1", sequence=5, kind="change.proposed"),
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
                sequence=8,
                kind="requirement.observed",
                attributes={"requirement": {"id": "R4", "text": " \t"}},
            ),
            event_data(
                event_id="invalid-context-1",
                sequence=8,
                kind="context.read",
                attributes={"context": {"path": " \t"}},
            ),
            event_data(
                event_id="invalid-tool-1",
                sequence=8,
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
                        kind="requirement.observed",
                        attributes={"requirement": {
                            "id": "R3",
                            "text": "Reject expiry.",
                        }},
                    ),
                    event_data(
                        event_id="context-1",
                        sequence=2,
                        kind="context.read",
                        attributes={"context": {"path": "src/auth/config.py"}},
                    ),
                    event_data(
                        event_id="tool-1",
                        sequence=3,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {"command": "pytest"}},
                    ),
                    started_event,
                    event_data(
                        event_id="verification-finished-1",
                        sequence=5,
                        kind="verification.finished",
                        attributes={"verification": finished_verification},
                        relationships=[{
                            "type": "completes",
                            "event_id": "verification-started-1",
                        }],
                    ),
                    event_data(
                        event_id="proposal-1",
                        sequence=6,
                        kind="change.proposed",
                    ),
                    event_data(
                        event_id="change-1",
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
                        kind="requirement.observed",
                        attributes={"requirement": {
                            "id": "R3",
                            "text": "Reject expiry.",
                        }},
                    ),
                    event_data(
                        event_id="context-1",
                        sequence=2,
                        kind="context.read",
                        attributes={"context": {"path": "src/auth/config.py"}},
                    ),
                    event_data(
                        event_id="compaction-1",
                        sequence=3,
                        kind="context.compacted",
                        relationships=[
                            {"type": inner_type, "event_id": "context-1"},
                            {"type": "references", "event_id": "missing-context"},
                        ],
                    ),
                    event_data(
                        event_id="tool-1",
                        sequence=4,
                        kind="tool.call.completed",
                        operation={"status": "ok", "name": "shell"},
                        attributes={"tool": {"command": "pytest"}},
                    ),
                    event_data(
                        event_id="verification-1",
                        sequence=5,
                        kind="verification.finished",
                        attributes={"verification": {
                            "command": "pytest",
                            "passed": True,
                            "test_origin": "pre_existing",
                        }},
                    ),
                    event_data(
                        event_id="proposal-1",
                        sequence=6,
                        kind="change.proposed",
                    ),
                    event_data(
                        event_id="change-1",
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
                kind="requirement.observed",
                attributes={"requirement": {"id": "R3", "text": "Reject expiry."}},
            ),
            event_data(
                event_id="context-1",
                sequence=2,
                kind="context.read",
                attributes={"context": {"path": "src/auth/config.py"}},
            ),
            event_data(
                event_id="invalid-context-1",
                sequence=3,
                kind="context.read",
                attributes={"context": {"path": " \t"}},
            ),
            event_data(
                event_id="compaction-1",
                sequence=4,
                kind="context.compacted",
                relationships=[
                    {"type": "summarizes", "event_id": "context-1"},
                    {"type": "summarizes", "event_id": "invalid-context-1"},
                ],
            ),
            event_data(
                event_id="tool-1",
                sequence=5,
                kind="tool.call.completed",
                attributes={"tool": {"command": "pytest"}},
            ),
            event_data(
                event_id="verification-1",
                sequence=6,
                kind="verification.finished",
                attributes={"verification": {
                    "command": "pytest",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
            event_data(event_id="proposal-1", sequence=7, kind="change.proposed"),
            event_data(
                event_id="change-1",
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

        self.assertIn("Agent Tail", html)
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
        self.assertIn("events.addEventListener('heartbeat'", html)
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


if __name__ == "__main__":
    unittest.main()
