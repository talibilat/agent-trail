import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import URLError
from urllib.request import urlopen

from agent_tail.otel import OTLPDocumentError, canonical_jsonl, import_otlp_json, parse_otlp_json


FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*arguments, input=None):
    return subprocess.run(
        [sys.executable, "-m", "agent_tail", *map(str, arguments)],
        input=input,
        check=False,
        capture_output=True,
        text=True,
    )


def reverse_object_keys(value):
    if isinstance(value, dict):
        return {
            key: reverse_object_keys(item)
            for key, item in reversed(tuple(value.items()))
        }
    if isinstance(value, list):
        return [reverse_object_keys(item) for item in value]
    return value


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class OpenTelemetryImportTests(unittest.TestCase):
    def test_deterministic_fixture_matches_exact_canonical_jsonl(self):
        source = (FIXTURES / "otel-traces.json").read_text(encoding="utf-8")
        expected = (FIXTURES / "otel-traces.expected.jsonl").read_text(
            encoding="utf-8"
        )

        imported = parse_otlp_json(source)

        self.assertEqual(imported.errors, ())
        self.assertEqual(canonical_jsonl(imported), expected)
        self.assertEqual(canonical_jsonl(parse_otlp_json(source)), expected)

    def test_object_key_order_does_not_change_output(self):
        document = json.loads(
            (FIXTURES / "otel-traces.json").read_text(encoding="utf-8")
        )

        original = canonical_jsonl(import_otlp_json(document))
        reordered = canonical_jsonl(import_otlp_json(reverse_object_keys(document)))

        self.assertEqual(reordered, original)

    def test_partial_success_reports_paths_without_source_values(self):
        source = (FIXTURES / "otel-malformed.json").read_text(encoding="utf-8")

        imported = parse_otlp_json(source)
        diagnostics = "\n".join(error.message for error in imported.errors)

        self.assertEqual(len(imported.events), 3)
        self.assertIn("spans[1]", diagnostics)
        self.assertIn("events[0]", diagnostics)
        self.assertNotIn("diagnostic-secret", diagnostics)
        self.assertNotIn("event-secret", diagnostics)
        self.assertEqual(
            [event["kind"] for event in imported.events],
            ["otel.span.finished", "otel.span.finished", "otel.span.event"],
        )

    def test_diagnostics_are_bounded(self):
        invalid_spans = [{} for _ in range(105)]
        document = {
            "resourceSpans": [{
                "scopeSpans": [{"scope": {}, "spans": invalid_spans}],
            }],
        }

        imported = import_otlp_json(document, max_errors=2)

        self.assertEqual(len(imported.errors), 3)
        self.assertEqual(
            imported.errors[-1].message,
            "103 additional OTLP import errors omitted",
        )

    def test_non_otlp_and_invalid_json_are_unsupported_formats(self):
        for source in ("not protobuf or json", "{}", "[]"):
            with self.subTest(source=source):
                with self.assertRaisesRegex(OTLPDocumentError, "unsupported format"):
                    parse_otlp_json(source)

    def test_process_imports_file_exactly_and_markdown_reads_result(self):
        source = FIXTURES / "otel-traces.json"
        expected = (FIXTURES / "otel-traces.expected.jsonl").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "imported.jsonl")
            report = Path(directory, "report.md")

            imported = run_cli("import", "otel", source, "--output", output)
            exported = run_cli(output, "--export", report)

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertIn("planner-7", report.read_text(encoding="utf-8"))

    def test_standard_stream_constraints_and_exit_codes(self):
        source = (FIXTURES / "otel-traces.json").read_text(encoding="utf-8")
        malformed = (FIXTURES / "otel-malformed.json").read_text(encoding="utf-8")
        expected = (FIXTURES / "otel-traces.expected.jsonl").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "stdin.jsonl")
            from_stdin = run_cli(
                "import", "otel", "-", "--output", output, input=source
            )

            self.assertEqual(from_stdin.returncode, 0, from_stdin.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

        to_stdout = run_cli(
            "import", "otel", FIXTURES / "otel-traces.json", "--output", "-"
        )
        both_streams = run_cli(
            "import", "otel", "-", "--output", "-", input=source
        )
        partial = run_cli(
            "import", "otel", "-", "--output", Path(tempfile.gettempdir(), "ignored-otel.jsonl"),
            input=malformed,
        )
        no_valid = json.dumps({
            "resourceSpans": [{"scopeSpans": [{"spans": [{}]}]}],
        })
        rejected = run_cli(
            "import", "otel", "-", "--output", Path(tempfile.gettempdir(), "empty-otel.jsonl"),
            input=no_valid,
        )
        unsupported = run_cli(
            "import", "otel", "-", "--output", Path(tempfile.gettempdir(), "bad-otel.jsonl"),
            input="protobuf bytes",
        )

        self.assertEqual(to_stdout.returncode, 0)
        self.assertEqual(to_stdout.stdout, expected)
        self.assertEqual(both_streams.returncode, 2)
        self.assertIn("cannot both be standard streams", both_streams.stderr)
        self.assertEqual(partial.returncode, 0)
        self.assertIn("spans[1]", partial.stderr)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(unsupported.returncode, 2)
        self.assertIn("unsupported format", unsupported.stderr)

    def test_imported_file_is_sanitized_when_served_across_processes(self):
        secret = "ghp_" + "a" * 36
        document = {
            "resourceSpans": [{
                "resource": {"attributes": [{
                    "key": "service.name",
                    "value": {"stringValue": "secure-service"},
                }, {
                    "key": "authorization",
                    "value": {"stringValue": secret},
                }]},
                "scopeSpans": [{
                    "scope": {"name": "security.fixture"},
                    "spans": [{
                        "traceId": "55555555555555555555555555555555",
                        "spanId": "1212121212121212",
                        "name": "secret span",
                        "endTimeUnixNano": "1783940564000000000",
                        "attributes": [{
                            "key": "custom.value",
                            "value": {"stringValue": secret},
                        }],
                        "events": [{
                            "name": f"event {secret}",
                            "timeUnixNano": "1783940563000000000",
                            "attributes": [],
                        }],
                    }],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "source.json")
            output = Path(directory, "imported.jsonl")
            source.write_text(json.dumps(document), encoding="utf-8")
            imported = run_cli("import", "otel", source, "--output", output)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertIn(secret, output.read_text(encoding="utf-8"))

            port = free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(output),
                    "--port", str(port),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.addCleanup(
                lambda: process.kill() if process.poll() is None else None
            )
            detail = None
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urlopen(
                        f"http://127.0.0.1:{port}/api/v1/runs/55555555555555555555555555555555",
                        timeout=0.5,
                    ) as response:
                        detail = json.load(io.TextIOWrapper(response, encoding="utf-8"))
                    break
                except (URLError, TimeoutError):
                    time.sleep(0.05)
            self.assertIsNotNone(detail)
            encoded = json.dumps(detail)
            self.assertNotIn(secret, encoded)
            self.assertIn("[REDACTED]", encoded)
            self.assertEqual(detail["run"]["event_count"], 2)
            self.assertEqual(detail["actors"][0]["id"], "secure-service")
            process.terminate()
            process.wait(timeout=3)

    def test_process_import_then_serve_preserves_parentage_and_source_details(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "imported.jsonl")
            imported = run_cli(
                "import", "otel", FIXTURES / "otel-traces.json", "--output", output
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            port = free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(output),
                    "--port", str(port),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.addCleanup(
                lambda: process.kill() if process.poll() is None else None
            )
            detail = None
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urlopen(
                        f"http://127.0.0.1:{port}/api/v1/runs/11111111111111111111111111111111",
                        timeout=0.5,
                    ) as response:
                        detail = json.load(io.TextIOWrapper(response, encoding="utf-8"))
                    break
                except (URLError, TimeoutError):
                    time.sleep(0.05)
            self.assertIsNotNone(detail)
            self.assertEqual(
                {actor["id"] for actor in detail["actors"]},
                {"planner-7", "planner-service"},
            )
            model = next(
                event for event in detail["events"]
                if event["kind"] == "model.request.finished"
            )
            self.assertEqual(model["parent_span_id"], "aaaaaaaaaaaaaaaa")
            self.assertEqual(
                model["attributes"]["otel"]["span"]["links"][0]["spanId"],
                "dddddddddddddddd",
            )
            self.assertIn("gen_ai.request.model", json.dumps(model["attributes"]))
            process.terminate()
            process.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
