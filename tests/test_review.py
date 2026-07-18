import hashlib
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from agent_tail.core import Event, IngestionError, TraceIndex, sanitize_event
from agent_tail import cli
import agent_tail.review as review_module
from agent_tail.review import (
    ExportCandidate,
    ReviewDecision,
    inventory,
    make_review_server,
    write_bytes_atomic,
)
from agent_tail.serve import RunStore


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


class ReviewTests(unittest.TestCase):
    def test_candidate_digest_and_state_machine_are_deterministic(self):
        candidate = ExportCandidate.create(
            "exact\nbytes\n", format="Markdown", destination=Path("report.md")
        )
        decision = ReviewDecision()

        self.assertEqual(
            candidate.digest,
            hashlib.sha256(b"exact\nbytes\n").hexdigest(),
        )
        self.assertEqual(decision.state, "pending")
        self.assertTrue(decision.decide("approved"))
        self.assertFalse(decision.decide("cancelled"))
        self.assertEqual(decision.wait(0), "approved")

    def test_inventory_reports_disclosure_and_metadata_only_omission(self):
        payload = {"secret": "payload-only-sentinel"}
        event = sanitize_event(
            Event.from_dict(event_data(
                attributes={"context": {"path": "src/main.py"}},
                payload=payload,
            )),
            metadata_only=True,
        )
        index = TraceIndex()
        index.add(event)
        candidate = ExportCandidate.create(
            "report", format="Markdown", destination=Path("report.md")
        )

        result = inventory(
            index,
            (IngestionError(2, "invalid JSON"),),
            candidate,
            metadata_only=True,
        )

        self.assertTrue(result["metadata_only"])
        self.assertEqual(result["payload_states"], {"omitted": 1})
        self.assertEqual(result["retained_attribute_paths"], ["attributes.context.path"])
        self.assertEqual(result["ingestion_errors"], 1)
        self.assertNotIn("payload-only-sentinel", json.dumps(result))

    def test_review_server_is_loopback_no_store_and_rejects_bad_or_reused_token(self):
        store = RunStore.from_lines([json.dumps(event_data()) + "\n"])
        decision = ReviewDecision()
        server = make_review_server(
            store,
            {"candidate_digest": "abc"},
            decision,
            token="correct-token",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://{server.server_address[0]}:{server.server_address[1]}"
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        self.assertEqual(server.server_address[0], "127.0.0.1")
        for suffix in ("", "?token=wrong"):
            with self.subTest(suffix=suffix), self.assertRaises(HTTPError) as caught:
                urlopen(base + "/api/v1/review" + suffix, timeout=2)
            self.assertEqual(caught.exception.code, 401)

        response = urlopen(base + "/api/v1/review?token=correct-token", timeout=2)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        approve = Request(
            base + "/api/v1/review/approve?token=correct-token", method="POST"
        )
        self.assertEqual(urlopen(approve, timeout=2).status, 200)
        with self.assertRaises(HTTPError) as reused:
            urlopen(approve, timeout=2)
        self.assertEqual(reused.exception.code, 401)

    def test_stdin_is_consumed_once_and_exact_frozen_markdown_is_written(self):
        sentinel = "safe-stdin-value"
        line = json.dumps(event_data(actor={"id": sentinel})) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "report.md")
            destination.write_bytes(b"existing")
            process = _start_review(
                "-", "--export", destination, input_text=line
            )
            summary, url = _review_url(process)
            self.assertEqual(destination.read_bytes(), b"existing")
            review = _json(url, replace_path="/api/v1/review")
            digest = review["candidate_digest"]
            _post(url, "/api/v1/review/approve")
            stdout, stderr = process.communicate(timeout=5)

            self.assertEqual(process.returncode, 0, summary + stdout + stderr)
            self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), digest)
            self.assertIn(sentinel, destination.read_text(encoding="utf-8"))

    def test_cancel_timeout_and_interrupt_preserve_existing_destination(self):
        line = json.dumps(event_data()) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("cancel", "timeout", "interrupt"):
                with self.subTest(mode=mode):
                    destination = Path(directory, f"{mode}.md")
                    destination.write_bytes(b"existing")
                    timeout = "0.15" if mode == "timeout" else "10"
                    process = _start_review(
                        "-", "--export", destination,
                        "--review-timeout", timeout,
                        input_text=line,
                    )
                    _, url = _review_url(process)
                    if mode == "cancel":
                        _post(url, "/api/v1/review/cancel")
                    elif mode == "interrupt":
                        process.send_signal(signal.SIGINT)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 2, stdout + stderr)
                    self.assertEqual(destination.read_bytes(), b"existing")

    def test_metadata_only_review_has_no_payload_recovery_endpoint(self):
        sentinel = "payload-body-must-not-escape"
        line = json.dumps(event_data(payload={"text": sentinel})) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "report.html")
            process = _start_review(
                "-", "--metadata-only", "--export-html", destination,
                input_text=line,
            )
            summary, url = _review_url(process)
            review = _json(url, replace_path="/api/v1/review")
            detail = _json(url, replace_path="/api/v1/runs/trace-1")
            payload = _json(
                url,
                replace_path="/api/v1/runs/trace-1/events/evt-1/payload",
            )
            _post(url, "/api/v1/review/cancel")
            stdout, stderr = process.communicate(timeout=5)

            exposed = summary + stdout + stderr + json.dumps((review, detail, payload))
            self.assertNotIn(sentinel, exposed)
            self.assertTrue(review["metadata_only"])
            self.assertEqual(payload["payload"]["state"], "omitted")
            self.assertNotIn("preview", payload["payload"])

    def test_atomic_byte_write_failure_keeps_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_parent = Path(directory, "missing", "report.md")
            with self.assertRaises(OSError):
                write_bytes_atomic(missing_parent, b"replacement")
            self.assertFalse(missing_parent.exists())

    def test_serialization_and_approved_write_failures_preserve_destination(self):
        line = json.dumps(event_data()) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "report.html")
            destination.write_bytes(b"existing")
            with (
                mock.patch.object(cli.sys, "stdin", io.StringIO(line)),
                mock.patch.object(cli, "render_html", side_effect=ValueError("serialize failed")),
            ):
                self.assertEqual(
                    cli.main(["-", "--export-html", str(destination), "--review"]),
                    2,
                )
            self.assertEqual(destination.read_bytes(), b"existing")

            index = TraceIndex()
            index.add(sanitize_event(Event.from_dict(event_data())))
            candidate = ExportCandidate.create(
                "candidate", format="HTML", destination=destination
            )

            class FakeServer:
                server_address = ("127.0.0.1", 12345)

                def serve_forever(self):
                    decision.decide("approved")

                def shutdown(self):
                    return None

                def server_close(self):
                    return None

            decision = None

            def fake_server(store, review_inventory, supplied_decision, *, token):
                nonlocal decision
                decision = supplied_decision
                return FakeServer()

            with (
                mock.patch.object(review_module, "make_review_server", fake_server),
                mock.patch.object(
                    review_module,
                    "write_bytes_atomic",
                    side_effect=OSError("replace failed"),
                ),
            ):
                result = review_module.review_export(
                    index,
                    (),
                    candidate,
                    metadata_only=False,
                    timeout=1,
                )
            self.assertEqual(result, 2)
            self.assertEqual(destination.read_bytes(), b"existing")


def _start_review(*arguments, input_text):
    process = subprocess.Popen(
        [sys.executable, "-m", "agent_tail", *map(str, arguments), "--review"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    process.stdin.write(input_text)
    process.stdin.close()
    process.stdin = None
    return process


def _review_url(process):
    summary = process.stdout.readline()
    line = process.stdout.readline()
    if not line.startswith("Review URL: "):
        raise AssertionError(summary + line + process.stderr.read())
    return summary, line.removeprefix("Review URL: ").strip()


def _with_path(url, path):
    parsed = urlparse(url)
    token = parse_qs(parsed.query)["token"][0]
    return f"{parsed.scheme}://{parsed.netloc}{path}?token={token}"


def _json(url, *, replace_path=None):
    target = _with_path(url, replace_path) if replace_path else url
    return json.loads(urlopen(target, timeout=3).read())


def _post(url, path):
    return urlopen(Request(_with_path(url, path), method="POST"), timeout=3).read()


if __name__ == "__main__":
    unittest.main()
