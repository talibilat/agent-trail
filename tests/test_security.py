import json
import unittest

from agent_tail.serve import RunStore


def event_data(event_id, sequence, *, emitter_id="worker", **changes):
    data = {
        "schema_version": "1.0",
        "event_id": event_id,
        "trace_id": "trace-security",
        "span_id": event_id,
        "emitter_id": emitter_id,
        "sequence": sequence,
        "timestamp": f"2026-07-18T12:00:{sequence:02d}Z",
        "kind": "message.received",
        "actor": {"id": emitter_id},
        "operation": {"status": "completed", "name": event_id},
    }
    data.update(changes)
    return data


def security_event(event_id, sequence, *, origin=None, capabilities=None, influenced=(), **changes):
    security = {}
    if origin is not None:
        security["trust_origin"] = origin
    if capabilities is not None:
        security["capabilities"] = capabilities
    return event_data(
        event_id,
        sequence,
        attributes={"security": security},
        relationships=[
            {"type": "influenced_by", "event_id": target}
            for target in influenced
        ],
        **changes,
    )


def project(*events):
    store = RunStore.from_lines(json.dumps(event) + "\n" for event in events)
    return store.run_detail("trace-security")


class SecurityProjectionTests(unittest.TestCase):
    def test_uninstrumented_trace_is_incomplete_without_event_diagnostics(self):
        detail = project(event_data("ordinary", 1, kind="activity.completed"))
        security = detail["security"]

        self.assertEqual(security["findings"], [])
        self.assertEqual(security["paths"], [])
        self.assertEqual(security["integrity"], [])
        self.assertEqual(security["unresolved_edges"], [])
        self.assertEqual(security["coverage"], {
            "status": "incomplete",
            "result": "no_observed_path",
            "sensitive_operation_count": 0,
            "finding_count": 0,
            "integrity_issue_count": 0,
            "unresolved_edge_count": 0,
            "security_metadata_observed": False,
            "reasons": ["SECURITY_INSTRUMENTATION_NOT_OBSERVED"],
        })

    def test_direct_untrusted_to_sensitive_and_trusted_user_only(self):
        untrusted = project(
            security_event("web", 1, origin="web"),
            security_event(
                "send", 2, capabilities=["network_egress"], influenced=["web"],
                kind="tool.call.started",
            ),
        )
        trusted = project(
            security_event("user", 1, origin="user"),
            security_event(
                "write", 2, capabilities=["filesystem_write"], influenced=["user"],
                kind="tool.call.started",
            ),
        )

        self.assertEqual(
            [item["code"] for item in untrusted["security"]["findings"]],
            ["UNTRUSTED_TO_SENSITIVE"],
        )
        self.assertEqual(
            [item["event_id"] for item in untrusted["security"]["paths"][0]["events"]],
            ["web", "send"],
        )
        self.assertEqual(trusted["security"]["findings"], [])
        self.assertEqual(trusted["security"]["coverage"]["result"], "no_observed_path")
        self.assertEqual(trusted["security"]["coverage"]["status"], "complete")
        self.assertEqual(trusted["security"]["coverage"]["reasons"], [])

    def test_transitive_mixed_path_retains_distinct_trust_evidence(self):
        detail = project(
            security_event("third-party", 1, origin="third_party"),
            security_event("user", 2, origin="user"),
            security_event("source", 3, origin="source_code"),
            security_event("secret", 4, origin="secret_derived"),
            security_event("merge", 5, influenced=["third-party", "user", "source", "secret"]),
            security_event(
                "execute", 6, capabilities=["process_execution"], influenced=["merge"],
                kind="tool.call.started",
            ),
        )

        path = detail["security"]["paths"][0]
        evidence = {
            item["trust_origin"]: item["risk"] for item in path["trust_origins"]
        }
        self.assertEqual(
            [item["event_id"] for item in path["events"]],
            ["third-party", "merge", "execute"],
        )
        self.assertEqual(evidence["user"], "trusted")
        self.assertEqual(evidence["source_code"], "source_code")
        self.assertEqual(evidence["secret_derived"], "secret_derived")

    def test_cycles_are_bounded_and_do_not_duplicate_findings(self):
        detail = project(
            security_event("web", 1, origin="web", emitter_id="source"),
            security_event("a", 2, influenced=["web", "b"], emitter_id="a-worker"),
            security_event("b", 3, influenced=["a"], emitter_id="b-worker"),
            security_event(
                "operation", 4, capabilities=["credential_access"], influenced=["b"],
                emitter_id="operation-worker", kind="tool.call.started",
            ),
        )

        self.assertEqual(len(detail["security"]["findings"]), 1)
        self.assertEqual(
            [item["event_id"] for item in detail["security"]["paths"][0]["events"]],
            ["web", "a", "b", "operation"],
        )

    def test_equal_length_paths_tie_break_by_canonical_order_then_event_id(self):
        detail = project(
            security_event("web-b", 2, origin="web", emitter_id="source-b"),
            security_event("web-a", 1, origin="web", emitter_id="source-a"),
            security_event(
                "operation", 3, capabilities=["secret_output"],
                influenced=["web-b", "web-a"], emitter_id="operation-worker",
                kind="tool.call.completed",
            ),
        )

        self.assertEqual(
            detail["security"]["findings"][0]["untrusted_source_event_id"],
            "web-a",
        )

    def test_forward_reference_resolves_only_after_target_arrives(self):
        store = RunStore()
        store.feed_line(json.dumps(security_event(
            "operation", 2, capabilities=["network_egress"], influenced=["web"],
            kind="tool.call.started",
        )) + "\n")

        before = store.run_detail("trace-security")
        store.feed_line(json.dumps(security_event("web", 1, origin="web")) + "\n")
        after = store.run_detail("trace-security")

        self.assertEqual(before["security"]["findings"], [])
        self.assertEqual(before["security"]["coverage"]["status"], "incomplete")
        self.assertEqual(
            before["security"]["unresolved_edges"][0]["code"],
            "UNRESOLVED_INFLUENCE_TARGET",
        )
        self.assertEqual(len(after["security"]["findings"]), 1)
        warning = next(
            item for item in after["warnings"]
            if item["code"] == "UNTRUSTED_TO_SENSITIVE"
        )
        self.assertEqual(warning["category"], "security")
        self.assertTrue(warning["active"])

    def test_invalid_sequence_unknown_labels_and_wrong_types_are_incomplete(self):
        detail = project(
            security_event("future", 3, origin="web"),
            security_event(
                "operation", 2, capabilities=["network_egress", "telepathy", 3],
                influenced=["future"], kind="tool.call.started",
            ),
            security_event("unknown", 4, origin="partner"),
            event_data("wrong-security", 5, attributes={"security": []}),
        )

        codes = {item["code"] for item in detail["security"]["integrity"]}
        self.assertTrue({
            "CONTRADICTORY_INFLUENCE_SEQUENCE",
            "UNKNOWN_CAPABILITY",
            "INVALID_CAPABILITY_TYPE",
            "UNKNOWN_TRUST_ORIGIN",
            "INVALID_SECURITY_TYPE",
        }.issubset(codes))
        self.assertEqual(detail["security"]["findings"], [])
        self.assertEqual(detail["security"]["coverage"]["status"], "incomplete")

    def test_missing_trust_evidence_is_unknown_not_safe(self):
        detail = project(security_event(
            "operation", 1, capabilities=["filesystem_write"],
            kind="tool.call.started",
        ))

        self.assertEqual(detail["security"]["coverage"]["result"], "no_observed_path")
        self.assertEqual(detail["security"]["coverage"]["status"], "incomplete")
        self.assertEqual(
            detail["security"]["integrity"][0]["code"], "MISSING_TRUST_ORIGIN"
        )

    def test_unlabeled_influence_leaf_uses_missing_trust_origin(self):
        detail = project(
            event_data("unlabeled-source", 1, kind="message.received"),
            security_event(
                "operation", 2, capabilities=["credential_access"],
                influenced=["unlabeled-source"], kind="tool.call.started",
            ),
        )

        security = detail["security"]
        self.assertEqual(security["findings"], [])
        self.assertEqual(security["coverage"]["status"], "incomplete")
        self.assertEqual(
            [item["code"] for item in security["integrity"]],
            ["MISSING_TRUST_ORIGIN"],
        )
        self.assertEqual(
            security["integrity"][0]["event_id"], "unlabeled-source"
        )

    def test_evicted_influence_target_is_typed_incomplete_coverage(self):
        store = RunStore.from_lines((
            json.dumps(security_event("web", 1, origin="web")) + "\n",
            json.dumps(security_event(
                "operation", 2, capabilities=["network_egress"], influenced=["web"],
                kind="tool.call.started",
            )) + "\n",
        ), max_bytes=500)

        security = store.run_detail("trace-security")["security"]

        self.assertEqual([event.event_id for event in store._index.events], ["operation"])
        self.assertEqual(security["findings"], [])
        self.assertEqual(security["coverage"]["status"], "incomplete")
        self.assertEqual(
            security["unresolved_edges"][0]["code"], "EVICTED_INFLUENCE_TARGET"
        )


if __name__ == "__main__":
    unittest.main()
