import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tail import cli


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


def run_cli(*arguments, input=None):
    return subprocess.run(
        [sys.executable, "-m", "agent_tail", *map(str, arguments)],
        input=input,
        check=False,
        capture_output=True,
        text=True,
    )


class CliTests(unittest.TestCase):
    def test_markdown_text_neutralizes_hostile_markup_and_controls(self):
        hostile = (
            "<img src=x> ![alt](javascript:boom) [link](https://evil) "
            "`tick` # heading\n- item | pipe \\ slash\x01"
        )

        safe = cli._markdown_text(hostile)

        for active in ("<img", "![", "](javascript:", "](https:", "`", "|", "\\", "\n", "\x01"):
            with self.subTest(active=active):
                self.assertNotIn(active, safe)
        self.assertIn("&lt;img src=x&gt;", safe)
        self.assertFalse(cli._markdown_text("# heading").startswith("#"))
        self.assertFalse(cli._markdown_text("- item").startswith("-"))
        self.assertFalse(cli._markdown_text("1. item").startswith("1."))

    def test_export_escapes_hostile_trace_actor_and_ingestion_error(self):
        hostile = "<img src=x> ![alt](javascript:boom) [link](https://evil) `tick`"
        lines = (
            json.dumps(event_data(trace_id=hostile, actor={"id": hostile})),
            json.dumps(event_data(event_id="bad", timestamp=hostile)),
        )
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.md")
            result = run_cli(
                "-", "--export", report_path, input="\n".join(lines) + "\n"
            )
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("<img", report)
        self.assertNotIn("![", report)
        self.assertNotIn("](javascript:", report)
        self.assertNotIn("](https:", report)
        self.assertIn("&lt;img src=x&gt;", report)

    def test_live_reader_failure_returns_two_after_view_closes(self):
        error = RuntimeError("Bearer reader-secret\ninternal detail")
        stdin = io.StringIO(json.dumps(event_data()) + "\n")
        stderr = io.StringIO()
        with (
            mock.patch.object(cli.sys, "stdin", stdin),
            mock.patch.object(cli.sys, "stderr", stderr),
            mock.patch.object(cli.sys.stdout, "isatty", return_value=True),
            mock.patch.object(cli, "run", return_value=error),
        ):
            result = cli.main(["-"])

        self.assertEqual(result, 2)
        self.assertEqual(stderr.getvalue(), "agent-tail: reader failed: [REDACTED]\n")

    def test_realistic_multi_agent_fixture_exports_expected_warnings_safely(self):
        fixture = Path(__file__).parent / "fixtures" / "runtime.jsonl"
        secret = "ghp_fixturesecretfixturesecretfixturesecret1"
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.md")

            result = run_cli(fixture, "--export", report_path)
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0)
        for evidence in (
            "agent-01",
            "agent-30",
            "LOOP",
            "RETRY",
            "STALL",
            "ORPHAN",
            "[REDACTED]",
            "truncated",
        ):
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, report)
        self.assertNotIn(secret, report)
        self.assertEqual(
            hashlib.sha256(report.encode()).hexdigest(),
            "e88cfab80643e2a678337b9088d02a8c2daabc9651404c69a80f3f1c60ffa5b2",
        )

    def test_help_names_file_and_stdin_inputs_without_internal_options(self):
        result = run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("JSONL file or - for standard input", result.stdout)
        self.assertIn("--max-bytes", result.stdout)
        self.assertNotIn("snapshot-stream", result.stdout)

    def test_html_export_options_are_documented_mutually_exclusive_and_scoped(self):
        help_result = run_cli("--help")
        exclusive = run_cli(
            "-", "--export", "report.md", "--export-html", "report.html", input=""
        )
        timestamp_only = run_cli(
            "-", "--export-html-generated-at", "2026-07-18T12:00:00Z", input=""
        )

        self.assertIn("--export-html PATH", help_result.stdout)
        self.assertIn("--export-html-generated-at TIMESTAMP", help_result.stdout)
        self.assertEqual(exclusive.returncode, 2)
        self.assertIn("not allowed with argument", exclusive.stderr)
        self.assertEqual(timestamp_only.returncode, 2)
        self.assertIn("requires --export-html", timestamp_only.stderr)

    def test_metadata_only_conflicts_with_full_payloads_in_cli_and_serve(self):
        normal = run_cli("-", "--metadata-only", "--full-payloads", input="")
        served = run_cli(
            "serve", "-", "--metadata-only", "--full-payloads", input=""
        )

        for result in (normal, served):
            self.assertEqual(result.returncode, 2)
            self.assertIn(
                "--metadata-only cannot be combined with --full-payloads",
                result.stderr,
            )

    def test_metadata_only_file_and_stdin_cover_terminal_markdown_and_html(self):
        sentinel = "payload-only-process-sentinel"
        payload = {"text": sentinel, "unicode": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"}
        original = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        line = json.dumps(event_data(
            attributes={"note": "retained metadata"},
            payload=payload,
        ), ensure_ascii=False) + "\n"
        digest = hashlib.sha256(original).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            markdown_file = Path(directory, "file.md")
            markdown_stdin = Path(directory, "stdin.md")
            html_file = Path(directory, "file.html")
            html_stdin = Path(directory, "stdin.html")
            source.write_text(line, encoding="utf-8")

            terminal_file = run_cli(source, "--metadata-only")
            terminal_stdin = run_cli("-", "--metadata-only", input=line)
            markdown_file_result = run_cli(
                source, "--metadata-only", "--export", markdown_file
            )
            markdown_stdin_result = run_cli(
                "-", "--metadata-only", "--export", markdown_stdin, input=line
            )
            html_file_result = run_cli(
                source, "--metadata-only", "--export-html", html_file
            )
            html_stdin_result = run_cli(
                "-", "--metadata-only", "--export-html", html_stdin, input=line
            )
            markdown_text = markdown_file.read_text(encoding="utf-8")
            html_bytes = html_file.read_bytes()
            self.assertEqual(markdown_file.read_bytes(), markdown_stdin.read_bytes())
            self.assertEqual(html_file.read_bytes(), html_stdin.read_bytes())

        for result in (
            terminal_file,
            terminal_stdin,
            markdown_file_result,
            markdown_stdin_result,
            html_file_result,
            html_stdin_result,
        ):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(sentinel, result.stdout + result.stderr)
        self.assertEqual(terminal_file.stdout, terminal_stdin.stdout)
        self.assertIn("PAYLOAD MODE: metadata-only", terminal_file.stdout)
        self.assertIn("payload: omitted (metadata-only)", terminal_file.stdout)
        self.assertIn("Payload mode: `metadata-only`", markdown_text)
        self.assertIn("omitted (metadata-only)", markdown_text)
        self.assertNotIn(sentinel.encode(), html_bytes)
        self.assertNotIn(sentinel, markdown_text)
        self.assertIn(digest[:20], terminal_file.stdout)

    def test_file_and_stdin_export_the_same_redacted_report(self):
        line = json.dumps(event_data(
            attributes={"authorization": "Bearer attribute-secret"},
            payload={"token": "Bearer payload-secret"},
        )) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            file_report = Path(directory, "file.md")
            stdin_report = Path(directory, "stdin.md")
            source.write_text(line, encoding="utf-8")

            from_file = run_cli(source, "--export", file_report)
            from_stdin = run_cli("-", "--export", stdin_report, input=line)

            self.assertEqual((from_file.returncode, from_stdin.returncode), (0, 0))
            self.assertEqual(file_report.read_bytes(), stdin_report.read_bytes())
            report = file_report.read_text(encoding="utf-8")
            self.assertIn("trace-1", report)
            self.assertNotIn("attribute-secret", report)
            self.assertNotIn("payload-secret", report)

    def test_structural_redaction_and_literal_placeholder_remain_distinct(self):
        secret = "ghp_" + "a" * 36
        placeholder = (
            "[REDACTED:" + hashlib.sha256(secret.encode()).hexdigest()[:12] + "]"
        )
        input_text = "\n".join((
            json.dumps(event_data(event_id=secret)),
            json.dumps(event_data(
                event_id=placeholder,
                span_id="span-2",
                sequence=2,
            )),
        )) + "\n"

        result = run_cli("-", input=input_text)

        self.assertEqual(result.returncode, 0)
        self.assertIn(f"event {placeholder} ", result.stdout)
        self.assertIn(f"event [LITERAL]{placeholder} ", result.stdout)
        self.assertNotIn("duplicate event ID", result.stderr)

    def test_export_does_not_expose_token_shaped_extension_or_payload_keys(self):
        extension_secret = "ghp_" + "a" * 36
        payload_secret = "ghp_" + "b" * 36
        extension_placeholder = (
            "[REDACTED:"
            + hashlib.sha256(extension_secret.encode()).hexdigest()[:12]
            + "]"
        )
        lines = [
            json.dumps(event_data(
                event_id=f"evt-{sequence}",
                span_id=f"span-{sequence}",
                sequence=sequence,
                attributes={"arguments": {extension_secret: "extension"}},
                payload={payload_secret: "payload"},
            ))
            for sequence in range(1, 5)
        ]
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.md")
            result = run_cli(
                "-", "--export", report_path, input="\n".join(lines) + "\n"
            )
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn(extension_secret, report)
        self.assertNotIn(payload_secret, report)
        self.assertIn(extension_placeholder, report)

    def test_stdin_events_are_sanitized_and_visible_before_eof(self):
        secret = "ghp_" + "a" * 36
        process = subprocess.Popen(
            [sys.executable, "-m", "agent_tail", "-", "--snapshot-stream"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)

        process.stdin.write(json.dumps(event_data(
            event_id=secret,
            actor={"id": "Bearer actor-secret"},
        )) + "\n")
        process.stdin.flush()

        snapshot = process.stdout.readline()
        self.assertNotIn(secret, snapshot)
        self.assertNotIn("actor-secret", snapshot)
        self.assertRegex(snapshot, r"\[REDACTED:[0-9a-f]{12}\]")
        self.assertIsNone(process.poll())

        process.stdin.close()
        self.assertEqual(process.wait(timeout=2), 0)
        process.stdout.close()
        process.stderr.close()

    def test_command_line_and_file_errors_return_two(self):
        missing_argument = run_cli()
        missing_file = run_cli("does-not-exist.jsonl")

        self.assertEqual(missing_argument.returncode, 2)
        self.assertEqual(missing_file.returncode, 2)
        self.assertIn("does-not-exist.jsonl", missing_file.stderr)

    def test_semantic_and_non_utf8_file_errors_return_two_without_tracebacks(self):
        semantic = run_cli("-", "--loop-threshold", "1", input="")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "invalid.jsonl")
            source.write_bytes(b"\xff\n")
            non_utf8 = run_cli(source)

        for result in (semantic, non_utf8):
            with self.subTest(stderr=result.stderr):
                self.assertEqual(result.returncode, 2)
                self.assertIn("agent-tail:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_max_bytes_forces_payload_eviction_into_markdown_evidence(self):
        line = json.dumps(event_data(payload={"text": "x" * 5000})) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.md")
            result = run_cli(
                "-", "--export", report_path, "--max-bytes", "1000", input=line
            )
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0)
        self.assertIn("EVICT", report)
        self.assertIn("| evicted |", report)

    def test_max_bytes_must_be_positive(self):
        result = run_cli("-", "--max-bytes", "0", input="")

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_acceptance_controls_exit_status_even_with_invalid_lines(self):
        invalid_only = run_cli("-", input="not json\n")
        mixed = run_cli(
            "-",
            input="not json\n" + json.dumps(event_data()) + "\n" + "{}\n",
        )

        self.assertEqual(invalid_only.returncode, 1)
        self.assertEqual(mixed.returncode, 0)
        self.assertIn("line 1: invalid JSON", mixed.stderr)
        self.assertIn("line 3: missing required field", mixed.stderr)

    def test_rejected_errors_stay_redacted_in_unsafe_mode_and_export(self):
        secret = "Bearer rejected-timestamp-secret"
        line = json.dumps(event_data(timestamp=secret)) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.md")
            result = run_cli(
                "-", "--unsafe-unredacted", "--export", report_path, input=line
            )
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 1)
        self.assertNotIn(secret, result.stderr)
        self.assertNotIn(secret, report)
        self.assertIn("invalid timestamp: [REDACTED]", result.stderr)
        self.assertIn("invalid timestamp: [REDACTED]", report)

    def test_markdown_contains_complete_deterministic_evidence(self):
        lines = []
        for sequence in range(1, 5):
            lines.append(json.dumps(event_data(
                event_id=f"evt-{sequence}",
                span_id=f"span-{sequence}",
                sequence=sequence,
                attributes={"arguments": {"path": "same.py"}},
                payload={"token": "Bearer hidden-value", "text": "x" * 5000},
            )))
        lines.extend(("not json", json.dumps(event_data(
            event_id="other",
            span_id="other",
            emitter_id="worker-2",
            actor={"id": "writer-1"},
        ))))

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.md")
            result = run_cli(
                "-", "--export", report_path, "--loop-threshold", "4",
                input="\n".join(lines) + "\n",
            )
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0)
        for evidence in (
            "Redaction ruleset: `1`",
            "## Trace `trace-1`",
            "### Actor states",
            "reviewer-1",
            "writer-1",
            "### Ordered timeline",
            "uncertain",
            "## Warnings",
            "LOOP",
            "Evidence:",
            "## Ingestion errors",
            "Line 5",
            "Payload retention",
            "truncated",
        ):
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, report)
        self.assertNotIn("hidden-value", report)


if __name__ == "__main__":
    unittest.main()
