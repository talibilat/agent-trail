import json
import unittest

from agent_tail.serve import RunStore


def event(event_id, sequence, kind, **changes):
    value = {
        "schema_version": "1.0",
        "event_id": event_id,
        "trace_id": "trace-1",
        "span_id": f"span-{event_id}",
        "emitter_id": "worker-1",
        "sequence": sequence,
        "timestamp": f"2026-07-18T12:00:{sequence:02d}Z",
        "kind": kind,
        "actor": {"id": "agent-1"},
        "operation": {"status": "completed", "name": "operation"},
    }
    value.update(changes)
    return value


def change(relationships=(), **detail):
    return event(
        "change-1",
        2,
        "change.applied",
        attributes={"change": {
            "path": "src/session.py",
            "old_start": 8,
            "old_count": 1,
            "new_start": 8,
            "new_count": 2,
            **detail,
        }},
        relationships=list(relationships),
    )


def verification(event_id="verification-1", sequence=3, *, origin="pre_existing"):
    return event(
        event_id,
        sequence,
        "verification.finished",
        attributes={"verification": {
            "command": "pytest tests/test_session.py",
            "passed": True,
            "exit_code": 0,
            "test_origin": origin,
        }},
        operation={"status": "completed", "name": "pytest"},
    )


def store(*events):
    return RunStore.from_lines(json.dumps(item) + "\n" for item in events)


def warnings(run_store, code):
    return [
        item for item in run_store.run_detail("trace-1")["warnings"]
        if item["code"] == code and item.get("active", True)
    ]


class VerificationGapWarningTests(unittest.TestCase):
    def test_uncovered_change_resolves_after_forward_target_arrives(self):
        run_store = RunStore(source_kind="stdin")
        run_store.feed_line(json.dumps(change([{
            "type": "verified_by", "event_id": "verification-1",
        }])) + "\n")

        initial = run_store.run_detail("trace-1")
        run_store.feed_line(json.dumps(verification()) + "\n")
        final = run_store.run_detail("trace-1")

        uncovered = next(item for item in initial["warnings"] if item["code"] == "UNCOVERED_CHANGE")
        self.assertTrue(uncovered["active"])
        history = [item for item in final["warnings"] if item["code"] == "UNCOVERED_CHANGE"]
        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["active"])
        self.assertIsNotNone(history[0]["resolved_at"])

    def test_coverage_uses_canonical_command_and_deduplicates_relationships(self):
        relationship = {"type": "verified_by", "event_id": "verification-1"}
        run_store = store(change([relationship, relationship]), verification())

        self.assertEqual(warnings(run_store, "UNCOVERED_CHANGE"), [])
        links = run_store.run_detail("trace-1")["evidence_map"]["changes"][0]["links"]
        self.assertEqual(len(links), 1)

    def test_wrong_kind_outcome_only_and_malformed_targets_do_not_cover(self):
        cases = (
            event("verification-1", 3, "context.read", attributes={"context": {"path": "x"}}),
            event("verification-1", 3, "verification.finished", attributes={"verification": {"passed": True}}),
            event("verification-1", 3, "verification.finished", attributes={"verification": {"command": 4, "passed": True}}),
        )
        for target in cases:
            with self.subTest(kind=target["kind"], attributes=target["attributes"]):
                run_store = store(change([{
                    "type": "verified_by", "event_id": "verification-1",
                }]), target)
                self.assertEqual(len(warnings(run_store, "UNCOVERED_CHANGE")), 1)
                self.assertTrue(
                    run_store.run_detail("trace-1")["evidence_map"]["changes"][0]["unresolved"]
                )

    def test_self_confirming_requires_every_valid_passing_test_to_be_same_agent(self):
        relationships = [
            {"type": "verified_by", "event_id": "same"},
            {"type": "verified_by", "event_id": "existing"},
        ]
        mixed = store(
            change(relationships),
            verification("same", 3, origin="same_agent"),
            verification("existing", 4, origin="pre_existing"),
        )
        only_same = store(
            change(relationships[:1]),
            verification("same", 3, origin="same_agent"),
        )

        self.assertEqual(warnings(mixed, "SELF_CONFIRMING_TEST"), [])
        warning = warnings(only_same, "SELF_CONFIRMING_TEST")[0]
        self.assertEqual(
            json.loads(warning["evidence"])["passing_verification_event_ids"],
            ["same"],
        )

    def test_malformed_or_unknown_test_origin_does_not_self_confirm(self):
        for origin in (None, "generated"):
            target = verification(origin="same_agent")
            if origin is None:
                del target["attributes"]["verification"]["test_origin"]
            else:
                target["attributes"]["verification"]["test_origin"] = origin
            run_store = store(change([{
                "type": "verified_by", "event_id": "verification-1",
            }]), target)
            self.assertEqual(warnings(run_store, "SELF_CONFIRMING_TEST"), [])

    def test_outcome_only_same_agent_pass_is_self_confirming_but_not_coverage(self):
        target = verification(origin="same_agent")
        del target["attributes"]["verification"]["command"]
        run_store = store(change([{
            "type": "verified_by", "event_id": "verification-1",
        }]), target)

        self.assertEqual(len(warnings(run_store, "UNCOVERED_CHANGE")), 1)
        self.assertEqual(len(warnings(run_store, "SELF_CONFIRMING_TEST")), 1)

    def test_stale_context_requires_linked_equal_normalized_path_and_valid_hashes(self):
        read = event(
            "read-1",
            1,
            "context.read",
            attributes={"context": {
                "path": "src//session.py",
                "content_sha256": "1" * 64,
            }},
        )
        run_store = store(
            read,
            change(
                [{"type": "informed_by", "event_id": "read-1"}],
                preimage_sha256="2" * 64,
            ),
        )

        warning = warnings(run_store, "STALE_CONTEXT")[0]
        evidence = json.loads(warning["evidence"])
        self.assertEqual(evidence["path"], "src/session.py")
        self.assertEqual(evidence["preimage_sha256"], "2" * 64)
        self.assertEqual(evidence["stale_read_event_ids"], ["read-1"])
        self.assertEqual(evidence["stale_reads"], [{
            "event_id": "read-1",
            "content_sha256": "1" * 64,
        }])

        malformed = read.copy()
        malformed["attributes"] = {"context": {
            "path": "src/session.py", "content_sha256": "bad",
        }}
        malformed_store = store(malformed, change(
            [{"type": "informed_by", "event_id": "read-1"}],
            preimage_sha256="2" * 64,
        ))
        self.assertEqual(warnings(malformed_store, "STALE_CONTEXT"), [])
        self.assertIn(
            "malformed_context_content_sha256",
            {item["code"] for item in malformed_store.run_detail("trace-1")["context_provenance"]["diagnostics"]},
        )

    def test_stale_context_aggregates_direct_and_compacted_reads_once(self):
        direct = event("read-direct", 1, "context.read", attributes={"context": {
            "path": "src/session.py", "content_sha256": "1" * 64,
        }})
        compacted = event("read-compacted", 2, "context.read", attributes={"context": {
            "path": "src/session.py", "content_sha256": "3" * 64,
        }})
        compaction = event(
            "compaction-1",
            3,
            "context.compacted",
            relationships=[
                {"type": "summarizes", "event_id": "read-compacted"},
                {"type": "summarizes", "event_id": "read-compacted"},
            ],
        )
        direct_link = {"type": "informed_by", "event_id": "read-direct"}
        compaction_link = {"type": "informed_by", "event_id": "compaction-1"}
        run_store = store(
            direct,
            compacted,
            compaction,
            change(
                [direct_link, direct_link, compaction_link, compaction_link],
                preimage_sha256="2" * 64,
            ),
        )

        stale = warnings(run_store, "STALE_CONTEXT")
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["event_id"], "change-1")
        self.assertEqual(json.loads(stale[0]["evidence"]), {
            "change_event_id": "change-1",
            "event_ids": ["change-1", "read-direct", "read-compacted"],
            "hunk": {
                "new_count": 2,
                "new_start": 8,
                "old_count": 1,
                "old_start": 8,
                "path": "src/session.py",
            },
            "path": "src/session.py",
            "preimage_sha256": "2" * 64,
            "stale_read_event_ids": ["read-direct", "read-compacted"],
            "stale_reads": [
                {"content_sha256": "1" * 64, "event_id": "read-direct"},
                {"content_sha256": "3" * 64, "event_id": "read-compacted"},
            ],
        })

    def test_stale_context_history_updates_and_resolves_without_duplicate_keys(self):
        direct = event("read-direct", 1, "context.read", attributes={"context": {
            "path": "src/session.py", "content_sha256": "1" * 64,
        }})
        compacted = event("read-compacted", 2, "context.read", attributes={"context": {
            "path": "src/session.py", "content_sha256": "3" * 64,
        }})
        run_store = RunStore(source_kind="stdin")
        for item in (
            direct,
            compacted,
            change([
                {"type": "informed_by", "event_id": "read-direct"},
                {"type": "informed_by", "event_id": "read-compacted"},
            ], preimage_sha256="2" * 64),
        ):
            run_store.feed_line(json.dumps(item) + "\n")

        initial = warnings(run_store, "STALE_CONTEXT")
        self.assertEqual(len(initial), 1)
        self.assertEqual(
            json.loads(initial[0]["evidence"])["stale_read_event_ids"],
            ["read-direct", "read-compacted"],
        )

        run_store._index.max_bytes = run_store._index._retained_bytes
        run_store.feed_line(json.dumps(event("later-1", 4, "activity.completed")) + "\n")
        one_retained = warnings(run_store, "STALE_CONTEXT")
        self.assertEqual(len(one_retained), 1)
        self.assertEqual(
            json.loads(one_retained[0]["evidence"])["stale_read_event_ids"],
            ["read-compacted"],
        )
        self.assertEqual(len([
            item for item in run_store._warning_history
            if item[0] == "STALE_CONTEXT"
        ]), 1)

        run_store.feed_line(json.dumps(event("later-2", 5, "activity.completed")) + "\n")
        history = [
            item for item in run_store.run_detail("trace-1")["warnings"]
            if item["code"] == "STALE_CONTEXT"
        ]
        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["active"])

    def test_late_stale_reads_expand_one_history_record_in_stable_order(self):
        direct = event("read-direct", 1, "context.read", attributes={"context": {
            "path": "src/session.py", "content_sha256": "1" * 64,
        }})
        compacted = event("read-compacted", 2, "context.read", attributes={"context": {
            "path": "src/session.py", "content_sha256": "3" * 64,
        }})
        compaction = event(
            "compaction-1",
            3,
            "context.compacted",
            relationships=[{
                "type": "summarizes", "event_id": "read-compacted",
            }],
        )
        run_store = RunStore(source_kind="stdin")
        for item in (
            change([
                {"type": "informed_by", "event_id": "read-direct"},
                {"type": "informed_by", "event_id": "compaction-1"},
            ], preimage_sha256="2" * 64),
            compaction,
        ):
            run_store.feed_line(json.dumps(item) + "\n")
        self.assertEqual(warnings(run_store, "STALE_CONTEXT"), [])

        run_store.feed_line(json.dumps(direct) + "\n")
        first = warnings(run_store, "STALE_CONTEXT")
        self.assertEqual(
            json.loads(first[0]["evidence"])["stale_read_event_ids"],
            ["read-direct"],
        )
        detected_at = first[0]["detected_at"]

        run_store.feed_line(json.dumps(compacted) + "\n")
        expanded = warnings(run_store, "STALE_CONTEXT")
        self.assertEqual(len(expanded), 1)
        self.assertEqual(expanded[0]["detected_at"], detected_at)
        self.assertEqual(
            json.loads(expanded[0]["evidence"])["stale_read_event_ids"],
            ["read-direct", "read-compacted"],
        )
        self.assertEqual(len([
            item for item in run_store._warning_history
            if item[0] == "STALE_CONTEXT"
        ]), 1)

    def test_unlinked_same_agent_read_does_not_trigger_stale_context(self):
        run_store = store(
            event("read-1", 1, "context.read", attributes={"context": {
                "path": "src/session.py", "content_sha256": "1" * 64,
            }}),
            change(preimage_sha256="2" * 64),
        )

        self.assertEqual(warnings(run_store, "STALE_CONTEXT"), [])

    def test_failed_before_completion_uses_sequence_despite_clock_skew(self):
        failure = event(
            "failure",
            1,
            "tool.call.failed",
            timestamp="2026-07-18T13:00:00Z",
            operation={"status": "failed", "name": "shell"},
            attributes={"arguments": {"command": "pytest"}},
        )
        completion = event(
            "completion",
            3,
            "trace.completed",
            timestamp="2026-07-18T12:00:00Z",
            operation={"status": "completed", "name": "trace"},
        )
        run_store = store(failure, completion)

        warning = warnings(run_store, "FAILED_BEFORE_COMPLETION")[0]
        self.assertEqual(
            json.loads(warning["evidence"])["event_ids"],
            ["failure", "completion"],
        )

    def test_equivalent_late_recovery_resolves_failure_history(self):
        failure = event(
            "failure", 1, "tool.call.failed",
            operation={"status": "failed", "name": "shell"},
            attributes={"arguments": {"command": "pytest", "nonce": 1}, "volatile_argument_keys": ["nonce"]},
        )
        completion = event("completion", 3, "trace.completed")
        recovery = event(
            "recovery", 2, "tool.call.completed",
            operation={"status": "completed", "name": "shell"},
            attributes={"arguments": {"nonce": 2, "command": "pytest"}, "volatile_argument_keys": ["nonce"]},
        )
        run_store = RunStore(source_kind="stdin")
        for item in (failure, completion):
            run_store.feed_line(json.dumps(item) + "\n")
        self.assertEqual(len(warnings(run_store, "FAILED_BEFORE_COMPLETION")), 1)

        run_store.feed_line(json.dumps(recovery) + "\n")
        history = [
            item for item in run_store.run_detail("trace-1")["warnings"]
            if item["code"] == "FAILED_BEFORE_COMPLETION"
        ]
        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["active"])

    def test_uncertain_equal_time_cross_emitter_completion_does_not_claim_failure(self):
        failure = event(
            "failure", 1, "tool.call.failed",
            emitter_id="worker-a",
            timestamp="2026-07-18T12:00:00Z",
            operation={"status": "failed", "name": "shell"},
        )
        completion = event(
            "completion", 1, "trace.completed",
            emitter_id="worker-b",
            timestamp="2026-07-18T12:00:00Z",
        )

        self.assertEqual(
            warnings(store(failure, completion), "FAILED_BEFORE_COMPLETION"),
            [],
        )

    def test_malformed_verification_failure_remains_diagnostic_not_warning(self):
        failed = event(
            "verification-1",
            3,
            "verification.finished",
            attributes={"verification": {"passed": False, "exit_code": 0}},
            operation={"status": "failed", "name": "pytest"},
        )
        run_store = store(
            failed,
            change([{"type": "verified_by", "event_id": "verification-1"}]),
            event("completion", 4, "trace.completed"),
        )

        self.assertEqual(warnings(run_store, "FAILED_BEFORE_COMPLETION"), [])
        unresolved = run_store.run_detail("trace-1")["evidence_map"]["changes"][0]["unresolved"]
        self.assertEqual(unresolved[0]["reason"], "conflicting_verification_outcome")


if __name__ == "__main__":
    unittest.main()
