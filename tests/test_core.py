from dataclasses import FrozenInstanceError
from datetime import datetime
import hashlib
import json
import unittest

from agent_tail.core import Event, EventError, read_jsonl, sanitize_event


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
        "future_field": {"preserved": True},
    }
    data.update(changes)
    return data


class EventTests(unittest.TestCase):
    def test_rejects_non_object_envelope(self):
        with self.assertRaisesRegex(EventError, "event"):
            Event.from_dict([])

    def test_exposes_typed_required_fields(self):
        event = Event.from_dict(event_data())

        self.assertEqual(event.schema_version, "1.0")
        self.assertEqual(event.event_id, "evt-1")
        self.assertEqual(event.trace_id, "trace-1")
        self.assertEqual(event.span_id, "span-1")
        self.assertEqual(event.emitter_id, "worker-1")
        self.assertEqual(event.sequence, 1)
        self.assertEqual(
            event.timestamp,
            datetime.fromisoformat("2026-07-13T11:02:44.912+00:00"),
        )
        self.assertEqual(event.kind, "tool.call.started")
        self.assertEqual(event.actor["id"], "reviewer-1")
        self.assertEqual(event.operation["status"], "running")

    def test_preserves_unknown_fields_kinds_and_minor_versions(self):
        event = Event.from_dict(
            event_data(schema_version="1.8", kind="future.kind")
        )

        self.assertEqual(event.raw["future_field"], {"preserved": True})
        self.assertEqual(event.kind, "future.kind")

    def test_accepts_missing_parent_span_id(self):
        self.assertIsNone(Event.from_dict(event_data()).parent_span_id)

    def test_is_immutable(self):
        event = Event.from_dict(event_data())

        with self.assertRaises(FrozenInstanceError):
            event.kind = "changed"

    def test_nested_input_mutation_does_not_change_event(self):
        data = event_data(future_field={"items": ["original"]})
        event = Event.from_dict(data)

        data["future_field"]["items"][0] = "changed"

        self.assertEqual(event.raw["future_field"], {"items": ["original"]})

    def test_nested_raw_mutation_does_not_change_event(self):
        event = Event.from_dict(event_data(future_field={"items": ["original"]}))

        raw = event.raw
        raw["future_field"]["items"][0] = "changed"

        self.assertEqual(event.raw["future_field"], {"items": ["original"]})

    def test_rejects_missing_required_fields(self):
        for field in (
            "schema_version",
            "event_id",
            "trace_id",
            "span_id",
            "emitter_id",
            "sequence",
            "timestamp",
            "kind",
            "actor",
            "operation",
        ):
            with self.subTest(field=field):
                data = event_data()
                del data[field]

                with self.assertRaisesRegex(EventError, field):
                    Event.from_dict(data)

    def test_rejects_incorrect_required_field_types(self):
        invalid_values = {
            "schema_version": 1.0,
            "event_id": 1,
            "trace_id": 1,
            "span_id": 1,
            "emitter_id": 1,
            "sequence": True,
            "timestamp": 1,
            "kind": 1,
            "actor": [],
            "operation": [],
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(EventError, field):
                    Event.from_dict(event_data(**{field: value}))

    def test_rejects_invalid_optional_parent_type(self):
        with self.assertRaisesRegex(EventError, "parent_span_id"):
            Event.from_dict(event_data(parent_span_id=1))

    def test_rejects_invalid_sequence(self):
        with self.assertRaisesRegex(EventError, "sequence"):
            Event.from_dict(event_data(sequence=-1))

    def test_rejects_invalid_timestamp(self):
        for timestamp in ("not-a-date", "2026-02-30T11:02:44Z"):
            with self.subTest(timestamp=timestamp):
                with self.assertRaisesRegex(EventError, "timestamp"):
                    Event.from_dict(event_data(timestamp=timestamp))

    def test_rejects_timezone_naive_timestamp(self):
        with self.assertRaisesRegex(EventError, "timestamp"):
            Event.from_dict(event_data(timestamp="2026-07-13T11:02:44"))

    def test_rejects_invalid_schema_versions(self):
        for version in ("2.0", "0.9", "1", "1.x", "1.2.3"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(EventError, "schema version"):
                    Event.from_dict(event_data(schema_version=version))

    def test_rejects_actor_without_string_id(self):
        for actor in ({}, {"id": 1}):
            with self.subTest(actor=actor):
                with self.assertRaisesRegex(EventError, "actor.id"):
                    Event.from_dict(event_data(actor=actor))

    def test_rejects_operation_without_string_status(self):
        for operation in ({}, {"status": 1}):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(EventError, "operation.status"):
                    Event.from_dict(event_data(operation=operation))

    def test_does_not_validate_optional_operation_name(self):
        event = Event.from_dict(
            event_data(operation={"status": "running", "name": [1]})
        )

        self.assertEqual(event.operation["name"], [1])


class RedactionTests(unittest.TestCase):
    def test_redacts_provider_tokens_with_realistic_lengths(self):
        secrets = [
            *(
                prefix + "a" * 36
                for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")
            ),
            *(prefix + "1" * 24 for prefix in ("xoxb-", "xoxp-", "xoxa-", "xoxr-")),
            "AIza" + "a" * 35,
            "github_pat_" + "a" * 82,
            "glpat-" + "a" * 20,
        ]
        short_lookalikes = [
            "ghp_short",
            "xoxb-short",
            "AIza-short",
            "github_pat_short",
            "glpat-short",
        ]
        event = Event.from_dict(
            event_data(payload={"secrets": secrets, "safe": short_lookalikes})
        )

        payload = sanitize_event(event, full_payloads=True).raw["payload"]

        self.assertEqual(payload["secrets"], ["[REDACTED]"] * len(secrets))
        self.assertEqual(payload["safe"], short_lookalikes)

    def test_redacts_complete_pem_private_key_blocks(self):
        private_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIE" + "A" * 64 + "\n"
            + "-----END RSA PRIVATE KEY-----"
        )
        incomplete = "-----BEGIN PRIVATE KEY-----\nnot-complete"
        event = Event.from_dict(
            event_data(payload={"private_key": private_key, "note": incomplete})
        )

        payload = sanitize_event(event, full_payloads=True).raw["payload"]

        self.assertEqual(payload["private_key"], "[REDACTED]")
        self.assertEqual(payload["note"], incomplete)

    def test_redacts_normalized_sensitive_dictionary_keys(self):
        sensitive = {
            key: f"value-{index}"
            for index, key in enumerate(
                (
                    "AUTH",
                    "AuthToken",
                    "AUTH_TOKEN",
                    "Auth-Token",
                    "Authorization",
                    "Cookie",
                    "Set-Cookie",
                    "CookieJar",
                    "sessionToken",
                    "client_secret",
                    "db-password",
                    "serviceApiKey",
                )
            )
        }
        unrelated = {
            key: "kept"
            for key in (
                "oauth",
                "tokenizer",
                "secretary",
                "passwordPolicy",
                "apiKeyVersion",
            )
        }
        event = Event.from_dict(
            event_data(
                attributes={
                    "nested": sensitive,
                    "unrelated": unrelated,
                }
            )
        )

        attributes = sanitize_event(event).raw["attributes"]

        self.assertEqual(
            attributes["nested"],
            {key: "[REDACTED]" for key in sensitive},
        )
        self.assertEqual(attributes["unrelated"], unrelated)

    def test_redacts_nested_secrets_and_bounds_payloads(self):
        secret = "sk-ant-" + "x" * 40
        event = Event.from_dict(
            event_data(
                attributes={
                    "nested": {"authorization": "Bearer token-value"},
                    "note": f"credential: {secret}",
                },
                payload={
                    "items": [{"cookie": "session=secret"}],
                    "text": secret + "z" * 5000,
                },
            )
        )

        safe = sanitize_event(event)
        encoded = json.dumps(safe.raw)

        self.assertNotIn("token-value", encoded)
        self.assertNotIn("session=secret", encoded)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("z" * 100, encoded)
        self.assertTrue(safe.raw["payload"]["_agent_tail"]["truncated"])
        self.assertEqual(safe.raw["payload"]["_agent_tail"]["ruleset"], "1")
        self.assertEqual(len(safe.raw["payload"]["_agent_tail"]["sha256"]), 64)

    def test_full_and_unsafe_payload_flags_are_explicit(self):
        event = Event.from_dict(
            event_data(payload={"text": "Bearer abc" + "z" * 5000})
        )

        full = sanitize_event(event, full_payloads=True)
        unsafe = sanitize_event(
            event, full_payloads=True, unsafe_unredacted=True
        )

        self.assertFalse(full.raw["payload"]["_agent_tail"]["truncated"])
        self.assertNotIn("Bearer abc", json.dumps(full.raw))
        self.assertIn("Bearer abc", json.dumps(unsafe.raw))

    def test_payload_metadata_describes_original_content(self):
        payload = {"text": "secret", "token": "visible-before-redaction"}
        original = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

        safe = sanitize_event(Event.from_dict(event_data(payload=payload)))
        metadata = safe.raw["payload"]["_agent_tail"]

        self.assertEqual(metadata["original_bytes"], len(original))
        self.assertEqual(metadata["sha256"], hashlib.sha256(original).hexdigest())
        self.assertFalse(metadata["truncated"])

    def test_payload_preview_is_utf8_safe_and_at_most_4096_bytes(self):
        event = Event.from_dict(event_data(payload={"text": "\N{EURO SIGN}" * 2000}))

        safe = sanitize_event(event)
        preview = safe.raw["payload"]["preview"]

        self.assertLessEqual(len(preview.encode("utf-8")), 4096)
        preview.encode("utf-8").decode("utf-8")


class IngestionTests(unittest.TestCase):
    def test_keeps_valid_events_and_reports_bad_lines(self):
        first = json.dumps(event_data())
        duplicate = json.dumps(event_data(kind="future.kind"))
        other_trace = json.dumps(event_data(event_id="evt-2", trace_id="trace-2"))

        result = read_jsonl([first, "not json", duplicate, other_trace])

        self.assertEqual([event.event_id for event in result.events], ["evt-1", "evt-2"])
        self.assertEqual([error.line for error in result.errors], [2, 3])
        self.assertIn("JSON", result.errors[0].message)
        self.assertIn("duplicate", result.errors[1].message)

    def test_reports_invalid_envelope_source_line(self):
        invalid = json.dumps(event_data(actor={}))

        result = read_jsonl(["", "  ", invalid])

        self.assertEqual(result.events, [])
        self.assertEqual(result.errors[0].line, 3)
        self.assertIn("actor.id", result.errors[0].message)

    def test_ignores_blank_lines(self):
        result = read_jsonl(["", "  \t", json.dumps(event_data())])

        self.assertEqual([event.event_id for event in result.events], ["evt-1"])
        self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()
