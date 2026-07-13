from dataclasses import FrozenInstanceError
from datetime import datetime
import unittest

from agent_tail.core import Event, EventError


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
        with self.assertRaises(TypeError):
            event.raw["kind"] = "changed"

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

    def test_rejects_incorrect_operation_name_type(self):
        with self.assertRaisesRegex(EventError, "operation.name"):
            Event.from_dict(event_data(operation={"status": "running", "name": 1}))


if __name__ == "__main__":
    unittest.main()
