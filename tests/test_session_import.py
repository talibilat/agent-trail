import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tail.serve import RunStore
from agent_tail.session_import import (
    SessionDocumentError,
    canonical_jsonl,
    import_session,
)


FIXTURES = Path(__file__).parent / "fixtures" / "sessions"
SOURCES = ("claude-code", "codex", "opencode")


def source_path(source, scenario):
    extension = "json" if source == "opencode" else "jsonl"
    return FIXTURES / f"{source}-{scenario}.{extension}"


def run_cli(*arguments, input=None):
    return subprocess.run(
        [sys.executable, "-m", "agent_tail", *map(str, arguments)],
        input=input,
        check=False,
        capture_output=True,
        text=True,
    )


class SessionImportTests(unittest.TestCase):
    def test_minimal_fixtures_match_exact_canonical_jsonl_and_auto_detect(self):
        for source in SOURCES:
            with self.subTest(source=source):
                text = source_path(source, "minimal").read_text(encoding="utf-8")
                expected = (FIXTURES / f"{source}-minimal.expected.jsonl").read_text(
                    encoding="utf-8"
                )

                first = import_session(text)
                second = import_session(text, source=source)

                self.assertEqual(first.source, source)
                self.assertEqual(first.version, "1")
                self.assertEqual(first.errors, ())
                self.assertEqual(canonical_jsonl(first), expected)
                self.assertEqual(canonical_jsonl(second), expected)

    def test_multi_agent_fixtures_preserve_lifecycle_evidence_and_sequences(self):
        for source in SOURCES:
            with self.subTest(source=source):
                imported = import_session(
                    source_path(source, "multi").read_text(encoding="utf-8")
                )
                kinds = [event["kind"] for event in imported.events]
                change = next(event for event in imported.events if event["kind"] == "change.applied")
                verification = next(
                    event for event in imported.events
                    if event["kind"] == "verification.finished"
                )

                self.assertIn("agent.started", kinds)
                self.assertIn("context.read", kinds)
                self.assertIn("tool.call.started", kinds)
                self.assertIn("verification.started", kinds)
                self.assertEqual(
                    [relationship["type"] for relationship in change["relationships"]],
                    ["informed_by", "preceded_by", "verified_by"],
                )
                self.assertEqual(verification["relationships"][0]["type"], "completes")
                self.assertTrue(any("parent_span_id" in event for event in imported.events))
                by_emitter = {}
                for event in imported.events:
                    by_emitter.setdefault(event["emitter_id"], []).append(event["sequence"])
                self.assertTrue(all(values == list(range(1, len(values) + 1)) for values in by_emitter.values()))

    def test_malformed_siblings_continue_and_invalid_hunks_are_not_changes(self):
        secrets = (
            "output-secret",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccc",
        )
        for source, secret in zip(SOURCES, secrets):
            with self.subTest(source=source):
                imported = import_session(
                    source_path(source, "malformed").read_text(encoding="utf-8")
                )
                output = canonical_jsonl(imported)

                self.assertTrue(imported.events)
                self.assertTrue(imported.errors)
                self.assertNotIn("change.applied", [event["kind"] for event in imported.events])
                self.assertIn("tool.call.", output)
                self.assertNotIn(secret, "\n".join(error.message for error in imported.errors))
                store = RunStore.from_lines(output.splitlines(True))
                trace_id = store.list_runs()["runs"][0]["trace_id"]
                self.assertEqual(store.run_detail(trace_id)["evidence_map"]["changes"], [])

    def test_invalid_json_line_does_not_discard_independent_claude_records(self):
        source = source_path("claude-code", "minimal").read_text(encoding="utf-8")
        lines = source.splitlines()
        lines.insert(1, "{not valid Bearer diagnostic-secret")

        imported = import_session("\n".join(lines), source="claude-code")

        self.assertEqual(len(imported.events), 2)
        self.assertEqual(len(imported.errors), 1)
        self.assertIn("record[1]: invalid JSON", imported.errors[0].message)
        self.assertNotIn("diagnostic-secret", imported.errors[0].message)

    def test_auto_detection_ambiguity_and_unsupported_versions_are_actionable(self):
        ambiguous = (FIXTURES / "ambiguous.jsonl").read_text(encoding="utf-8")
        with self.assertRaisesRegex(SessionDocumentError, "ambiguous.*--source"):
            import_session(ambiguous)

        for source in SOURCES:
            with self.subTest(source=source):
                text = source_path(source, "unsupported").read_text(encoding="utf-8")
                with self.assertRaisesRegex(SessionDocumentError, "unsupported.*supported: 1") as raised:
                    import_session(text, source=source)
                self.assertNotIn("ghp_", str(raised.exception))

    def test_process_rejects_ambiguous_and_unsupported_fixtures_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "unused.jsonl")
            ambiguous = run_cli(
                "import", "session", FIXTURES / "ambiguous.jsonl", "--output", output
            )
            self.assertEqual(ambiguous.returncode, 2)
            self.assertIn("ambiguous", ambiguous.stderr)
            self.assertIn("--source", ambiguous.stderr)

            for source in SOURCES:
                with self.subTest(source=source):
                    unsupported = run_cli(
                        "import", "session", source_path(source, "unsupported"),
                        "--source", source, "--output", output,
                    )
                    self.assertEqual(unsupported.returncode, 2)
                    self.assertIn("supported: 1", unsupported.stderr)
                    self.assertNotIn("ghp_", unsupported.stderr)

    def test_diagnostics_are_bounded_and_never_include_rejected_values(self):
        init = source_path("claude-code", "minimal").read_text(encoding="utf-8").splitlines()[0]
        bad = [json.dumps({
            "type": "unknown",
            "uuid": f"Bearer secret-{index}",
            "sessionId": "claude-min",
            "timestamp": "2026-07-18T10:00:00Z",
        }) for index in range(5)]

        imported = import_session("\n".join((init, *bad)), source="claude-code", max_errors=2)

        self.assertEqual(len(imported.errors), 3)
        self.assertEqual(
            imported.errors[-1].message,
            "3 additional claude-code session import errors omitted",
        )
        self.assertNotIn("secret", "\n".join(error.message for error in imported.errors))

    def test_import_has_no_network_home_or_global_directory_access(self):
        source = source_path("codex", "minimal").read_text(encoding="utf-8")
        with (
            mock.patch("pathlib.Path.home", side_effect=AssertionError("home accessed")),
            mock.patch("socket.create_connection", side_effect=AssertionError("network accessed")),
        ):
            imported = import_session(source)
        self.assertEqual(imported.source, "codex")

    def test_process_boundary_imports_every_source_and_existing_cli_reads_it(self):
        with tempfile.TemporaryDirectory() as directory:
            for source in SOURCES:
                with self.subTest(source=source):
                    output = Path(directory, f"{source}.jsonl")
                    first = run_cli(
                        "import", "session", source_path(source, "multi"),
                        "--source", source, "--output", output,
                    )
                    first_bytes = output.read_bytes()
                    second = run_cli(
                        "import", "session", source_path(source, "multi"),
                        "--source", "auto", "--output", output,
                    )
                    opened = run_cli(output)

                    self.assertEqual(first.returncode, 0, first.stderr)
                    self.assertEqual(second.returncode, 0, second.stderr)
                    self.assertEqual(output.read_bytes(), first_bytes)
                    self.assertEqual(opened.returncode, 0, opened.stderr)
                    self.assertIn("change", opened.stdout)

    def test_hostile_values_are_sanitized_in_api_and_markdown(self):
        source = FIXTURES / "claude-code-hostile.jsonl"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "hostile.jsonl")
            report = Path(directory, "hostile.md")
            imported = run_cli("import", "session", source, "--output", output)
            exported = run_cli(output, "--export", report)
            store = RunStore.from_lines(output.read_text(encoding="utf-8").splitlines(True))
            detail = store.run_detail(store.list_runs()["runs"][0]["trace_id"])

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(exported.returncode, 0, exported.stderr)
            artifact = output.read_text(encoding="utf-8")
            encoded_detail = json.dumps(detail)
            markdown = report.read_text(encoding="utf-8")
            self.assertIn("ghp_", artifact)
            self.assertIn("message-injected", artifact)
            self.assertIn("command-injected", artifact)
            self.assertIn("path-injected", artifact)
            self.assertIn("error-injected", artifact)
            self.assertIn("unknown-key-injected", artifact)
            self.assertNotIn("ghp_", encoded_detail)
            self.assertNotIn("ghp_", markdown)
            self.assertIn("[REDACTED]", encoded_detail)
            self.assertNotIn("<img", markdown)


if __name__ == "__main__":
    unittest.main()
