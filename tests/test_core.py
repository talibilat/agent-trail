from dataclasses import FrozenInstanceError
from datetime import datetime
import hashlib
import json
import threading
import unittest

from agent_tail.core import (
    Event,
    EventError,
    JSONLReader,
    TraceIndex,
    read_jsonl,
    redact_text,
    sanitize_event,
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

    def test_accepts_optional_event_relationships(self):
        event = Event.from_dict(event_data(relationships=[
            {
                "type": "motivated_by",
                "event_id": "requirement-1",
                "future_field": True,
            },
        ]))

        self.assertEqual(len(event.relationships), 1)
        self.assertEqual(event.relationships[0].type, "motivated_by")
        self.assertEqual(event.relationships[0].event_id, "requirement-1")
        self.assertTrue(event.raw["relationships"][0]["future_field"])

    def test_defaults_missing_event_relationships_to_empty(self):
        self.assertEqual(Event.from_dict(event_data()).relationships, ())

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

    def test_rejects_invalid_event_relationships(self):
        invalid_values = (
            ({}, "relationships must be an array"),
            (["event-1"], r"relationships\[0\] must be an object"),
            ([{"event_id": "event-1"}], r"relationships\[0\]\.type"),
            ([{"type": 1, "event_id": "event-1"}], r"relationships\[0\]\.type"),
            ([{"type": "verified_by"}], r"relationships\[0\]\.event_id"),
            ([{"type": "verified_by", "event_id": 1}], r"relationships\[0\]\.event_id"),
        )
        for relationships, message in invalid_values:
            with self.subTest(relationships=relationships):
                with self.assertRaisesRegex(EventError, message):
                    Event.from_dict(event_data(relationships=relationships))

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
    def test_redact_text_redacts_secret_values(self):
        self.assertEqual(
            redact_text("failed near Bearer rejected-secret"),
            "failed near [REDACTED]",
        )

    def test_sanitizes_entire_envelope_and_preserves_structural_identity(self):
        shared_span = "ghp_" + "a" * 36
        actor_id = "Bearer actor-secret"
        first = sanitize_event(Event.from_dict(event_data(
            event_id="ghp_" + "b" * 36,
            trace_id="ghp_" + "c" * 36,
            span_id=shared_span,
            emitter_id="ghp_" + "d" * 36,
            kind="Bearer kind-secret",
            actor={"id": actor_id, "role": "Bearer role-secret"},
            operation={"status": "running", "name": "Bearer operation-secret"},
            future_field={"note": "Bearer future-secret"},
        )))
        second = sanitize_event(Event.from_dict(event_data(
            event_id="ghp_" + "e" * 36,
            span_id="span-child",
            parent_span_id=shared_span,
            actor={"id": actor_id},
        )))

        encoded = json.dumps((first.raw, second.raw))
        for secret in (
            shared_span,
            actor_id,
            "kind-secret",
            "role-secret",
            "operation-secret",
            "future-secret",
        ):
            self.assertNotIn(secret, encoded)
        self.assertRegex(first.event_id, r"^\[REDACTED:[0-9a-f]{12}\]$")
        self.assertNotEqual(first.event_id, second.event_id)
        self.assertEqual(first.span_id, second.parent_span_id)
        self.assertEqual(first.actor["id"], second.actor["id"])
        self.assertEqual(first.operation["name"], "[REDACTED]")

    def test_structural_redactions_cannot_collide_with_literal_prefixes(self):
        secret = "ghp_" + "a" * 36
        placeholder = (
            "[REDACTED:" + hashlib.sha256(secret.encode()).hexdigest()[:12] + "]"
        )

        redacted = sanitize_event(Event.from_dict(event_data(event_id=secret)))
        literal = sanitize_event(Event.from_dict(event_data(event_id=placeholder)))
        prefixed = sanitize_event(Event.from_dict(
            event_data(event_id="[LITERAL]" + placeholder)
        ))
        parent = sanitize_event(Event.from_dict(event_data(
            event_id="parent",
            span_id=placeholder,
            actor={"id": "[LITERAL]actor"},
        )))
        child = sanitize_event(Event.from_dict(event_data(
            event_id="child",
            span_id="child",
            parent_span_id=placeholder,
            actor={"id": "[LITERAL]actor"},
        )))

        self.assertEqual(redacted.event_id, placeholder)
        self.assertEqual(literal.event_id, "[LITERAL]" + placeholder)
        self.assertEqual(prefixed.event_id, "[LITERAL][LITERAL]" + placeholder)
        self.assertEqual(parent.span_id, child.parent_span_id)
        self.assertEqual(parent.span_id, "[LITERAL]" + placeholder)
        self.assertEqual(parent.actor["id"], child.actor["id"])
        self.assertEqual(parent.actor["id"], "[LITERAL][LITERAL]actor")
        self.assertEqual(
            sanitize_event(Event.from_dict(event_data())).event_id,
            "evt-1",
        )

    def test_relationship_event_ids_share_structural_redaction(self):
        secret = "ghp_" + "a" * 36
        target = sanitize_event(Event.from_dict(event_data(event_id=secret)))
        source = sanitize_event(Event.from_dict(event_data(
            event_id="source",
            relationships=[{"type": "verified_by", "event_id": secret}],
        )))

        self.assertEqual(source.relationships[0].event_id, target.event_id)
        self.assertNotIn(secret, json.dumps(source.raw))

    def test_recursively_redacts_secret_dictionary_keys_without_collapsing_them(self):
        extension_secret = "ghp_" + "a" * 36
        payload_secret = "ghp_" + "b" * 36
        extension_key = (
            "[REDACTED:"
            + hashlib.sha256(extension_secret.encode()).hexdigest()[:12]
            + "]"
        )
        payload_key = (
            "[REDACTED:"
            + hashlib.sha256(payload_secret.encode()).hexdigest()[:12]
            + "]"
        )
        event = Event.from_dict(event_data(
            future_field={
                extension_secret: "extension",
                payload_secret: "second",
                "ordinary": "kept",
            },
            payload={payload_secret: "payload"},
        ))

        safe = sanitize_event(event, full_payloads=True).raw
        unsafe = sanitize_event(
            event, full_payloads=True, unsafe_unredacted=True
        ).raw

        self.assertEqual(
            safe["future_field"],
            {
                extension_key: "extension",
                payload_key: "second",
                "ordinary": "kept",
            },
        )
        self.assertEqual(safe["payload"][payload_key], "payload")
        self.assertNotEqual(extension_key, payload_key)
        self.assertIn(extension_secret, unsafe["future_field"])
        self.assertIn(payload_secret, unsafe["payload"])
        self.assertIn("event_id", safe)

    def test_dictionary_key_redaction_cannot_overwrite_literal_placeholder(self):
        secret = "ghp_" + "a" * 36
        placeholder = (
            "[REDACTED:" + hashlib.sha256(secret.encode()).hexdigest()[:12] + "]"
        )
        original = {secret: "generated", placeholder: "literal"}
        event = Event.from_dict(event_data(future_field=original))

        safe = sanitize_event(event).raw["future_field"]
        unsafe = sanitize_event(
            event, unsafe_unredacted=True
        ).raw["future_field"]

        self.assertEqual(len(safe), 2)
        self.assertEqual(safe[placeholder], "generated")
        self.assertEqual(safe["[LITERAL]" + placeholder], "literal")
        self.assertEqual(unsafe, original)

    def test_repeated_literal_dictionary_key_prefixes_remain_distinct(self):
        once = "[LITERAL]ordinary"
        twice = "[LITERAL][LITERAL]ordinary"
        event = Event.from_dict(event_data(
            future_field={once: "once", twice: "twice"}
        ))

        safe = sanitize_event(event).raw["future_field"]

        self.assertEqual(len(safe), 2)
        self.assertEqual(safe["[LITERAL]" + once], "once")
        self.assertEqual(safe["[LITERAL]" + twice], "twice")

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

    def test_metadata_only_omits_deterministic_payload_shapes_exactly(self):
        payloads = [
            "scalar payload sentinel",
            {"nested": {"secret": "object payload sentinel"}},
            [1, "array payload sentinel", None],
            {"unicode": "caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{EURO SIGN}"},
            "",
            {"large": "large payload sentinel" + "x" * 5000},
        ]

        for sequence, payload in enumerate(payloads, 1):
            with self.subTest(sequence=sequence):
                original = json.dumps(
                    payload, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                event = Event.from_dict(event_data(
                    event_id=f"evt-{sequence}",
                    span_id=f"span-{sequence}",
                    sequence=sequence,
                    payload=payload,
                ))

                first = sanitize_event(event, metadata_only=True)
                second = sanitize_event(event, metadata_only=True)

                self.assertEqual(first.raw, second.raw)
                self.assertEqual(first.raw["payload"], {"_agent_tail": {
                    "original_bytes": len(original),
                    "sha256": hashlib.sha256(original).hexdigest(),
                    "omitted": True,
                    "ruleset": "1",
                }})
                self.assertNotIn("preview", json.dumps(first.raw))

    def test_metadata_only_redacts_retained_metadata_unless_unsafe(self):
        event = Event.from_dict(event_data(
            attributes={"note": "Bearer retained-metadata-secret"},
            payload={"text": "payload-only-unique-sentinel"},
        ))

        safe = sanitize_event(event, metadata_only=True)
        unsafe = sanitize_event(
            event,
            metadata_only=True,
            unsafe_unredacted=True,
        )

        self.assertNotIn("retained-metadata-secret", json.dumps(safe.raw))
        self.assertIn("retained-metadata-secret", json.dumps(unsafe.raw))
        self.assertNotIn("payload-only-unique-sentinel", json.dumps(unsafe.raw))

    def test_metadata_only_rejects_full_payload_retention(self):
        with self.assertRaisesRegex(ValueError, "cannot both be enabled"):
            sanitize_event(
                Event.from_dict(event_data(payload="secret")),
                full_payloads=True,
                metadata_only=True,
            )


class IngestionTests(unittest.TestCase):
    def test_streaming_reader_retains_no_events_and_bounds_errors(self):
        reader = JSONLReader(retain_events=False, max_errors=3)
        for sequence in range(1, 2001):
            reader.feed(json.dumps(event_data(
                event_id=f"evt-{sequence}", span_id=f"span-{sequence}",
                sequence=sequence,
            )))
        for _ in range(10):
            reader.feed("not json")

        self.assertEqual(reader.events, [])
        self.assertEqual(reader.accepted_count, 2000)
        self.assertEqual(len(reader.errors), 3)
        self.assertEqual(reader.omitted_error_count, 7)
        self.assertIn("7 additional ingestion errors omitted", reader.all_errors[-1].message)

    def test_redacts_rejected_event_error_messages(self):
        secret = "Bearer rejected-timestamp-secret"
        result = read_jsonl([json.dumps(event_data(timestamp=secret))])

        self.assertEqual(result.events, [])
        self.assertIn("invalid timestamp: [REDACTED]", result.errors[0].message)
        self.assertNotIn(secret, result.errors[0].message)

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


class TraceIndexTests(unittest.TestCase):
    def test_large_topological_order_preserves_sequence(self):
        index = TraceIndex(max_bytes=64 * 1024 * 1024)
        for sequence in range(3000):
            index.add(Event.from_dict(event_data(
                event_id=f"evt-{sequence}", span_id=f"span-{sequence}",
                sequence=sequence,
            )))

        ordered = index.ordered_events()

        self.assertEqual(len(ordered), 3000)
        self.assertEqual(ordered[0].event_id, "evt-0")
        self.assertEqual(ordered[-1].event_id, "evt-2999")

    def test_exposes_immutable_event_count_and_insertion_view(self):
        index = TraceIndex()
        event = Event.from_dict(event_data())
        index.add(event)

        self.assertEqual(index.event_count, 1)
        self.assertEqual(index.events, (event,))
        with self.assertRaises(AttributeError):
            index.events.append(event)

    def test_global_order_preserves_cross_trace_emitter_sequence(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="sequence-1", trace_id="trace-1", span_id="span-1",
            sequence=1, timestamp="2026-07-13T11:05:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="sequence-2", trace_id="trace-2", span_id="span-2",
            sequence=2, timestamp="2026-07-13T11:01:00Z",
        )))

        self.assertEqual(
            tuple(event.event_id for event in index.ordered_events()),
            ("sequence-1", "sequence-2"),
        )

    def test_global_order_preserves_parent_before_child_despite_timestamps(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="parent", span_id="parent", emitter_id="parent-worker",
            timestamp="2026-07-13T11:05:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="parent",
            emitter_id="child-worker", timestamp="2026-07-13T11:01:00Z",
        )))

        self.assertEqual(
            tuple(event.event_id for event in index.ordered_events()),
            ("parent", "child"),
        )

    def test_global_order_does_not_link_identical_span_ids_across_traces(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="other-trace-parent", trace_id="trace-1", span_id="shared",
            emitter_id="parent-worker", timestamp="2026-07-13T11:05:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="local-orphan", trace_id="trace-2", span_id="child",
            parent_span_id="shared", emitter_id="child-worker",
            timestamp="2026-07-13T11:01:00Z",
        )))

        self.assertEqual(
            tuple(event.event_id for event in index.ordered_events()),
            ("local-orphan", "other-trace-parent"),
        )

    def test_rejects_invalid_thresholds(self):
        for field, value in (
            ("loop_threshold", 1),
            ("stall_seconds", -0.1),
            ("orphan_grace_seconds", -0.1),
            ("max_bytes", 0),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    TraceIndex(**{field: value})

    def test_rejects_invalid_threshold_types(self):
        for field, values in (
            ("loop_threshold", (True, 2.0, "4")),
            ("stall_seconds", (False, "1", None)),
            ("orphan_grace_seconds", (True, "1", None)),
            ("max_bytes", (True, 1.5, "1024")),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(TypeError, field):
                        TraceIndex(**{field: value})

    def test_groups_and_orders_events_without_inventing_cross_emitter_order(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="root", sequence=2,
        )))
        index.add(Event.from_dict(event_data(
            event_id="root", span_id="root", sequence=1,
        )))
        index.add(Event.from_dict(event_data(
            event_id="other", span_id="other", emitter_id="worker-2", sequence=1,
        )))

        view = index.trace("trace-1")

        self.assertLess(view.event_ids.index("root"), view.event_ids.index("child"))
        self.assertIn("other", view.uncertain_event_ids)
        self.assertEqual(view.actors["reviewer-1"].status, "running")

    def test_lifecycle_and_child_events_control_actor_activity(self):
        index = TraceIndex(stall_seconds=10)
        index.add(Event.from_dict(event_data(
            event_id="root", span_id="root", timestamp="2026-07-13T11:02:44Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="root", sequence=2,
            timestamp="2026-07-13T11:03:25Z", kind="tool.call.completed",
            actor={"id": "tool-1"},
            operation={"status": "completed", "name": "read_file"},
        )))

        view = index.trace("trace-1")

        self.assertTrue(view.spans["root"].open)
        self.assertFalse(view.spans["child"].open)
        self.assertNotIn(
            "STALL",
            {warning.code for warning in index.warnings(now="2026-07-13T11:03:30Z")},
        )
        stall = next(
            warning
            for warning in index.warnings(now="2026-07-13T11:03:40Z")
            if warning.code == "STALL" and warning.actor_id == "reviewer-1"
        )
        self.assertEqual(stall.event_id, "child")
        self.assertEqual(stall.trace_id, "trace-1")

    def test_waiting_is_open_and_terminal_status_closes_span(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="waiting", operation={"status": "waiting", "name": "read_file"},
        )))
        self.assertTrue(index.trace("trace-1").spans["span-1"].open)

        index.add(Event.from_dict(event_data(
            event_id="done", sequence=2, kind="future.kind",
            operation={"status": "cancelled", "name": "read_file"},
        )))

        self.assertFalse(index.trace("trace-1").spans["span-1"].open)

    def test_child_follows_all_explicit_parent_starts_across_emitters(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="start-a", span_id="root", emitter_id="worker-a", sequence=50,
            timestamp="2026-07-13T11:05:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="start-b", span_id="root", emitter_id="worker-b", sequence=1,
            timestamp="2026-07-13T11:04:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="root",
            emitter_id="worker-c", sequence=1,
            timestamp="2026-07-13T11:02:00Z",
        )))

        event_ids = index.trace("trace-1").event_ids

        self.assertLess(event_ids.index("start-a"), event_ids.index("child"))
        self.assertLess(event_ids.index("start-b"), event_ids.index("child"))

    def test_parent_fallback_uses_wall_clock_and_is_uncertain(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="late", span_id="root", emitter_id="worker-a", sequence=1,
            timestamp="2026-07-13T11:03:00Z", kind="tool.call.progress",
        )))
        index.add(Event.from_dict(event_data(
            event_id="early", span_id="root", emitter_id="worker-b", sequence=99,
            timestamp="2026-07-13T11:01:00Z", kind="tool.call.progress",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="root",
            emitter_id="worker-c", sequence=1,
            timestamp="2026-07-13T11:02:00Z",
        )))

        view = index.trace("trace-1")

        self.assertLess(view.event_ids.index("early"), view.event_ids.index("child"))
        self.assertLess(view.event_ids.index("child"), view.event_ids.index("late"))
        self.assertIn("child", view.uncertain_event_ids)

    def test_duplicate_sequences_order_buckets_and_remain_uncertain(self):
        index = TraceIndex()
        for event_id, sequence, timestamp in (
            ("low-a", 1, "2026-07-13T11:05:00Z"),
            ("low-b", 1, "2026-07-13T11:04:00Z"),
            ("high-a", 2, "2026-07-13T11:01:00Z"),
            ("high-b", 2, "2026-07-13T11:02:00Z"),
        ):
            index.add(Event.from_dict(event_data(
                event_id=event_id, span_id=event_id, sequence=sequence,
                timestamp=timestamp,
            )))

        view = index.trace("trace-1")

        self.assertLess(
            max(view.event_ids.index("low-a"), view.event_ids.index("low-b")),
            min(view.event_ids.index("high-a"), view.event_ids.index("high-b")),
        )
        self.assertTrue(
            {"low-a", "low-b", "high-a", "high-b"}
            .issubset(view.uncertain_event_ids)
        )

    def test_actor_state_is_uncertain_for_incomparable_latest_emitters(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="running", span_id="running", emitter_id="worker-a",
            sequence=1, timestamp="2026-07-13T11:02:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="completed", span_id="completed", emitter_id="worker-b",
            sequence=1, timestamp="2026-07-13T11:01:00Z",
            kind="tool.call.completed",
            operation={"status": "completed", "name": "read_file"},
        )))

        actor = index.trace("trace-1").actors["reviewer-1"]

        self.assertTrue(actor.uncertain)

    def test_staggered_ready_events_keep_full_causal_uncertainty(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="independent", span_id="independent", emitter_id="worker-b",
            sequence=1, timestamp="2026-07-13T11:00:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="chain-start", span_id="chain-start", emitter_id="worker-a",
            sequence=1, timestamp="2026-07-13T11:01:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="chain-end", span_id="chain-end", emitter_id="worker-a",
            sequence=2, timestamp="2026-07-13T11:02:00Z",
        )))

        view = index.trace("trace-1")

        self.assertEqual(
            view.event_ids,
            ("independent", "chain-start", "chain-end"),
        )
        self.assertEqual(
            view.uncertain_event_ids,
            {"independent", "chain-start", "chain-end"},
        )
        self.assertTrue(view.actors["reviewer-1"].uncertain)

    def test_actor_state_does_not_treat_parent_fallback_as_causal(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="parent", span_id="parent", emitter_id="worker-a",
            sequence=1, timestamp="2026-07-13T11:01:00Z",
            kind="tool.call.progress",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="parent",
            emitter_id="worker-b", sequence=1,
            timestamp="2026-07-13T11:02:00Z",
        )))

        actor = index.trace("trace-1").actors["reviewer-1"]

        self.assertTrue(actor.uncertain)

    def test_actor_state_is_uncertain_for_equal_sequence_maxima(self):
        index = TraceIndex()
        for event_id, status in (("completed", "completed"), ("failed", "failed")):
            index.add(Event.from_dict(event_data(
                event_id=event_id, span_id=event_id, sequence=1,
                timestamp="2026-07-13T11:02:00Z", kind=f"tool.call.{status}",
                operation={"status": status, "name": "read_file"},
            )))

        actor = index.trace("trace-1").actors["reviewer-1"]

        self.assertTrue(actor.uncertain)
        self.assertEqual(actor.status, "failed")
        self.assertEqual(actor.last_activity_event_id, "failed")


class WarningTests(unittest.TestCase):
    def test_empty_payload_does_not_stall_eviction(self):
        index = TraceIndex(max_bytes=1)
        errors = []

        def add_event():
            try:
                index.add(Event.from_dict(event_data(payload={})))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=add_event, daemon=True)

        thread.start()
        thread.join(0.5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_detects_loop_retry_stall_and_orphan_with_exact_evidence(self):
        index = TraceIndex(loop_threshold=4, stall_seconds=10, orphan_grace_seconds=0)
        for sequence in range(1, 5):
            index.add(Event.from_dict(event_data(
                event_id=f"loop-{sequence}", span_id=f"loop-{sequence}", sequence=sequence,
                attributes={"arguments": {"path": "same.py"}},
            )))
        for sequence in range(5, 8):
            index.add(Event.from_dict(event_data(
                event_id=f"retry-{sequence}", span_id=f"retry-{sequence}", sequence=sequence,
                kind="tool.call.failed", operation={"status": "failed", "name": "read_file"},
                attributes={"arguments": {"path": "same.py"}},
            )))
        index.add(Event.from_dict(event_data(
            event_id="orphan", span_id="orphan", parent_span_id="missing", sequence=8,
        )))

        warnings = index.warnings(now="2026-07-13T11:03:30Z")
        codes = {warning.code for warning in warnings}

        self.assertTrue({"LOOP", "RETRY", "STALL", "ORPHAN"}.issubset(codes))
        self.assertEqual({warning.trace_id for warning in warnings}, {"trace-1"})
        retry = next(warning for warning in warnings if warning.code == "RETRY")
        self.assertEqual(
            json.loads(retry.evidence)["event_ids"],
            ["retry-5", "retry-6", "retry-7"],
        )
        with self.assertRaises(FrozenInstanceError):
            retry.code = "changed"

    def test_output_state_change_prevents_loop_warning(self):
        for state_key in (
            "output_hash", "file_hash", "checkpoint_id", "success", "retry_reason",
        ):
            with self.subTest(state_key=state_key):
                index = TraceIndex(loop_threshold=4)
                for sequence in range(1, 5):
                    index.add(Event.from_dict(event_data(
                        event_id=f"evt-{sequence}", span_id=f"span-{sequence}",
                        sequence=sequence,
                        attributes={
                            "arguments": {"path": "same.py"},
                            state_key: sequence,
                        },
                    )))

                self.assertNotIn("LOOP", {warning.code for warning in index.warnings()})

    def test_signature_is_canonical_and_excludes_declared_volatile_arguments(self):
        index = TraceIndex(loop_threshold=4)
        for sequence in range(1, 5):
            arguments = (
                {"path": "same.py", "line": 3, "request_id": sequence}
                if sequence % 2
                else {"request_id": sequence, "line": 3, "path": "same.py"}
            )
            index.add(Event.from_dict(event_data(
                event_id=f"evt-{sequence}", span_id=f"span-{sequence}", sequence=sequence,
                attributes={
                    "arguments": arguments,
                    "volatile_argument_keys": ["request_id"],
                },
            )))

        self.assertIn("LOOP", {warning.code for warning in index.warnings()})

    def test_loop_and_retry_do_not_combine_emitters(self):
        loop_index = TraceIndex(loop_threshold=2)
        for sequence, emitter_id in enumerate(("worker-1", "worker-2"), 1):
            loop_index.add(Event.from_dict(event_data(
                event_id=f"loop-{sequence}", span_id=f"loop-{sequence}",
                emitter_id=emitter_id, sequence=1,
                attributes={"arguments": {"path": "same.py"}},
            )))
        retry_index = TraceIndex()
        for sequence, emitter_id in enumerate(
            ("worker-1", "worker-2", "worker-3"), 1
        ):
            retry_index.add(Event.from_dict(event_data(
                event_id=f"retry-{sequence}", span_id=f"retry-{sequence}",
                emitter_id=emitter_id, sequence=1, kind="tool.call.failed",
                operation={"status": "failed", "name": "read_file"},
                attributes={"arguments": {"path": "same.py"}},
            )))

        self.assertNotIn("LOOP", {w.code for w in loop_index.warnings()})
        self.assertNotIn("RETRY", {w.code for w in retry_index.warnings()})

    def test_loop_and_retry_reset_at_equal_sequences(self):
        loop_index = TraceIndex(loop_threshold=4)
        for event_id, sequence in enumerate((1, 2, 2, 3), 1):
            loop_index.add(Event.from_dict(event_data(
                event_id=f"loop-{event_id}", span_id=f"loop-{event_id}",
                sequence=sequence,
                attributes={"arguments": {"path": "same.py"}},
            )))
        retry_index = TraceIndex()
        for event_id, sequence in enumerate((1, 1, 2), 1):
            retry_index.add(Event.from_dict(event_data(
                event_id=f"retry-{event_id}", span_id=f"retry-{event_id}",
                sequence=sequence, kind="tool.call.failed",
                operation={"status": "failed", "name": "read_file"},
                attributes={"arguments": {"path": "same.py"}},
            )))

        self.assertNotIn("LOOP", {w.code for w in loop_index.warnings()})
        self.assertNotIn("RETRY", {w.code for w in retry_index.warnings()})

    def test_increasing_retry_delay_prevents_retry_warning(self):
        index = TraceIndex()
        for sequence, second in enumerate((0, 1, 3), 1):
            index.add(Event.from_dict(event_data(
                event_id=f"retry-{sequence}", span_id=f"retry-{sequence}", sequence=sequence,
                timestamp=f"2026-07-13T11:02:{second:02d}Z", kind="tool.call.failed",
                operation={"status": "failed", "name": "read_file"},
                attributes={"arguments": {"path": "same.py"}},
            )))

        self.assertNotIn("RETRY", {warning.code for warning in index.warnings()})

    def test_success_resets_consecutive_retry_failures(self):
        index = TraceIndex()
        statuses = ("failed", "completed", "failed", "failed")
        for sequence, status in enumerate(statuses, 1):
            index.add(Event.from_dict(event_data(
                event_id=f"retry-{sequence}", span_id=f"retry-{sequence}",
                sequence=sequence, kind=f"tool.call.{status}",
                operation={"status": status, "name": "read_file"},
                attributes=(
                    {"arguments": {"path": "same.py"}}
                    if status == "failed"
                    else {}
                ),
            )))

        self.assertNotIn("RETRY", {warning.code for warning in index.warnings()})

        index.add(Event.from_dict(event_data(
            event_id="retry-5", span_id="retry-5", sequence=5,
            kind="tool.call.failed",
            operation={"status": "failed", "name": "read_file"},
            attributes={"arguments": {"path": "same.py"}},
        )))

        retry = next(warning for warning in index.warnings() if warning.code == "RETRY")
        self.assertEqual(
            json.loads(retry.evidence)["event_ids"],
            ["retry-3", "retry-4", "retry-5"],
        )

    def test_changed_material_failure_state_prevents_retry_warning(self):
        for state_key in (
            "output_hash", "error_hash", "output_id", "error_id", "retry_reason",
        ):
            with self.subTest(state_key=state_key):
                index = TraceIndex()
                for sequence in range(1, 4):
                    index.add(Event.from_dict(event_data(
                        event_id=f"retry-{sequence}", span_id=f"retry-{sequence}",
                        sequence=sequence, kind="tool.call.failed",
                        operation={"status": "failed", "name": "read_file"},
                        attributes={
                            "arguments": {"path": "same.py"},
                            state_key: sequence,
                        },
                    )))

                self.assertNotIn(
                    "RETRY", {warning.code for warning in index.warnings()}
                )

    def test_evicts_payload_data_before_event_metadata(self):
        event = sanitize_event(Event.from_dict(event_data(payload={"text": "x" * 500})))
        full_size = len(json.dumps(event.raw, separators=(",", ":")).encode())
        metadata_only = event.raw
        metadata_only["payload"] = {
            "_agent_tail": metadata_only["payload"]["_agent_tail"]
        }
        metadata_size = len(json.dumps(metadata_only, separators=(",", ":")).encode())
        index = TraceIndex(max_bytes=(full_size + metadata_size) // 2)

        index.add(event)

        view = index.trace("trace-1")
        self.assertEqual(view.event_ids, ("evt-1",))
        self.assertEqual(set(view.events[0].raw["payload"]), {"_agent_tail"})
        eviction = next(warning for warning in index.warnings() if warning.code == "EVICT")
        self.assertEqual(eviction.trace_id, "trace-1")
        self.assertEqual(json.loads(eviction.evidence)["latest"]["evicted"], "payload")

        tiny = TraceIndex(max_bytes=1)
        tiny.add(event)
        self.assertEqual(tiny.trace("trace-1").event_ids, ())
        warnings = [warning for warning in tiny.warnings() if warning.code == "EVICT"]
        self.assertEqual(len(warnings), 1)
        evidence = json.loads(warnings[0].evidence)
        self.assertEqual(evidence["count"], 2)
        self.assertEqual(evidence["latest"]["evicted"], "metadata")

    def test_eviction_warning_is_one_bounded_aggregate(self):
        index = TraceIndex(max_bytes=1)
        for sequence in range(1, 4):
            index.add(sanitize_event(Event.from_dict(event_data(
                event_id=f"evt-{sequence}", span_id=f"span-{sequence}",
                sequence=sequence, payload={"text": "x" * 100},
            ))))

        warnings = [warning for warning in index.warnings() if warning.code == "EVICT"]
        evidence = json.loads(warnings[0].evidence)

        self.assertEqual(len(warnings), 1)
        self.assertEqual(evidence["count"], 6)
        self.assertEqual(evidence["latest"]["event_id"], "evt-3")
        self.assertEqual(evidence["latest"]["evicted"], "metadata")

    def test_omitted_payload_is_not_treated_as_retained_or_payload_evicted(self):
        event = sanitize_event(
            Event.from_dict(event_data(payload={"text": "x" * 5000})),
            metadata_only=True,
        )
        event_size = len(json.dumps(
            event.raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"))
        index = TraceIndex(max_bytes=event_size)

        index.add(event)

        self.assertEqual(index.event_count, 1)
        self.assertEqual(index.eviction_count, 0)
        self.assertEqual(index.events[0].raw["payload"]["_agent_tail"]["omitted"], True)


if __name__ == "__main__":
    unittest.main()
