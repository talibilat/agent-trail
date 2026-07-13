import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


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
    def test_help_names_file_and_stdin_inputs_without_internal_options(self):
        result = run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("JSONL file or - for standard input", result.stdout)
        self.assertNotIn("snapshot-stream", result.stdout)

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

    def test_stdin_events_are_sanitized_and_visible_before_eof(self):
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
            payload={"token": "Bearer secret-value"},
        )) + "\n")
        process.stdin.flush()

        snapshot = process.stdout.readline()
        self.assertIn("reviewer-1", snapshot)
        self.assertNotIn("secret-value", snapshot)
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
