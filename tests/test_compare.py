import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import venv

from agent_tail.compare import compare_paths
from tests.performance_fixture import write_fixture


FIXTURE = Path(__file__).parent / "fixtures" / "compare-run.jsonl"
TIME_LIMIT_SECONDS = 10.0
RSS_LIMIT_BYTES = 512 * 1024 * 1024


def read_events(path=FIXTURE):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_events(path, events, malformed=()):
    path.write_text(
        "\n".join([*(json.dumps(event, sort_keys=True) for event in events), *malformed]) + "\n",
        encoding="utf-8",
    )


def run_cli(*arguments):
    return subprocess.run(
        [sys.executable, "-m", "agent_tail", *map(str, arguments)],
        check=False,
        capture_output=True,
        text=True,
    )


def tool_event(
    event_id,
    actor_id,
    emitter_id,
    operation_name,
    *,
    kind="tool.call.completed",
    span_id=None,
    parent_span_id=None,
    timestamp="2026-07-18T10:00:00Z",
):
    event = {
        "schema_version": "1.0",
        "event_id": event_id,
        "trace_id": "compare-trace",
        "span_id": span_id or event_id,
        "emitter_id": emitter_id,
        "sequence": 1,
        "timestamp": timestamp,
        "kind": kind,
        "actor": {"id": actor_id},
        "operation": {"status": "running" if kind.endswith(".started") else "completed", "name": operation_name},
        "attributes": {"arguments": {}},
    }
    if parent_span_id is not None:
        event["parent_span_id"] = parent_span_id
    return event


class ComparisonTests(unittest.TestCase):
    def test_ids_timestamps_spans_and_ingestion_positions_are_ignored(self):
        events = read_events()
        event_ids = {event["event_id"]: f"replacement-{index}" for index, event in enumerate(events)}
        span_ids = {event["span_id"]: f"replacement-span-{index}" for index, event in enumerate(events)}
        transformed = []
        for index, original in enumerate(events):
            event = json.loads(json.dumps(original))
            event["event_id"] = event_ids[original["event_id"]]
            event["trace_id"] = "replacement-trace"
            event["span_id"] = span_ids[original["span_id"]]
            if original.get("parent_span_id"):
                event["parent_span_id"] = span_ids[original["parent_span_id"]]
            event["timestamp"] = f"2030-01-01T00:00:{index:02d}Z"
            for relationship in event.get("relationships", []):
                relationship["event_id"] = event_ids[relationship["event_id"]]
            transformed.append(event)
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory, "other.jsonl")
            write_events(other, transformed, malformed=("",))
            report = compare_paths(FIXTURE, other)

        self.assertIn("No semantic divergence was found.", report)
        self.assertIn("## Added Facts\n\nNone.", report)
        self.assertIn("## Removed Facts\n\nNone.", report)

    def test_all_fact_categories_and_changed_totals_are_reported(self):
        events = read_events()
        changed = json.loads(json.dumps(events))
        changed[1]["actor"]["id"] = "other-worker"
        changed[2]["attributes"]["context"]["path"] = "src/other.py"
        changed[3]["attributes"]["search"]["query"] = "OtherIndex"
        changed[4]["attributes"]["arguments"]["path"] = "src/other.py"
        changed[4]["usage"] = {"input_tokens": 11, "output_tokens": 0, "total_tokens": 11}
        changed[5]["attributes"]["change"]["new_count"] = 3
        changed[7]["attributes"]["verification"] = {
            "passed": False, "exit_code": 1, "test_origin": "pre_existing"
        }
        changed[8]["attributes"]["correction"]["action"] = "modified"
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory, "changed.jsonl")
            write_events(other, changed)
            report = compare_paths(FIXTURE, other)

        for category in (
            "actor:", "read:", "search:", "operation:", "warning:",
            "verification:", "usage:", "change:", "correction:",
        ):
            with self.subTest(category=category):
                self.assertIn(category, report)
        self.assertIn("divergence", report.lower())
        self.assertIn("unavailable", report)
        self.assertIn("reverted", report)

    def test_independent_cross_emitter_reorder_has_no_false_divergence(self):
        events = read_events()[:2]
        for index, name in enumerate(("alpha", "beta"), 1):
            events.append({
                "schema_version": "1.0", "event_id": f"independent-{index}",
                "trace_id": "compare-trace", "span_id": f"independent-span-{index}",
                "emitter_id": f"independent-emitter-{index}", "sequence": 1,
                "timestamp": f"2026-07-18T10:00:0{index + 2}Z",
                "kind": "tool.call.completed", "actor": {"id": f"actor-{index}"},
                "operation": {"status": "completed", "name": name},
                "attributes": {"arguments": {"value": index}},
            })
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.jsonl")
            right = Path(directory, "right.jsonl")
            write_events(left, events)
            write_events(right, [*events[:2], events[3], events[2]])
            report = compare_paths(left, right)
        self.assertIn("No semantic divergence was found.", report)

    def test_same_emitter_sequence_diverges_despite_opposite_timestamps(self):
        events = read_events()[:2]
        calls = []
        for sequence, name, timestamp in ((2, "alpha", "10:10:00"), (3, "beta", "09:00:00")):
            calls.append({
                "schema_version": "1.0", "event_id": name, "trace_id": "compare-trace",
                "span_id": name, "emitter_id": "worker-emitter", "sequence": sequence,
                "timestamp": f"2026-07-18T{timestamp}Z", "kind": "tool.call.completed",
                "actor": {"id": "worker"},
                "operation": {"status": "completed", "name": name},
                "attributes": {"arguments": {}},
            })
        reversed_calls = json.loads(json.dumps(calls))
        reversed_calls[0]["sequence"], reversed_calls[1]["sequence"] = 3, 2
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.jsonl")
            right = Path(directory, "right.jsonl")
            write_events(left, [*events, *calls])
            write_events(right, [*events, *reversed_calls])
            report = compare_paths(left, right)
        self.assertIn("Earliest supported divergence", report)
        self.assertIn("alpha", report)
        self.assertIn("beta", report)

    def test_multiple_independent_unmatched_records_form_stable_sorted_frontier(self):
        left_events = [
            tool_event("left-zeta", "worker-z", "emitter-z", "zeta"),
            tool_event("left-alpha", "worker-a", "emitter-a", "alpha"),
        ]
        right_events = [
            tool_event("right-gamma", "worker-z", "emitter-z", "gamma"),
            tool_event("right-beta", "worker-a", "emitter-a", "beta"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.jsonl")
            right = Path(directory, "right.jsonl")
            write_events(left, left_events)
            write_events(right, right_events)
            first = compare_paths(left, right)
            second = compare_paths(left, right)

        divergence = first.split("## Divergence Evidence\n\n", 1)[1]
        self.assertEqual(first, second)
        self.assertIn("Stable divergence frontier:", divergence)
        self.assertNotIn("Earliest supported divergence:", divergence)
        self.assertEqual(divergence.count("- Run A:"), 2)
        self.assertEqual(divergence.count("- Run B:"), 2)
        self.assertLess(divergence.index('"operation":"alpha"'), divergence.index('"operation":"zeta"'))
        self.assertLess(divergence.index('"operation":"beta"'), divergence.index('"operation":"gamma"'))

    def test_explicit_parent_span_ancestry_supports_earliest_divergence(self):
        left_events = [
            tool_event(
                "left-parent", "parent", "parent-emitter", "parent-left",
                kind="tool.call.started", span_id="parent-span",
                timestamp="2026-07-18T11:00:00Z",
            ),
            tool_event(
                "left-child", "child", "child-emitter", "child-left",
                parent_span_id="parent-span", timestamp="2026-07-18T09:00:00Z",
            ),
        ]
        right_events = [
            tool_event(
                "right-parent", "parent", "parent-emitter", "parent-right",
                kind="tool.call.started", span_id="parent-span-replaced",
                timestamp="2026-07-18T11:00:00Z",
            ),
            tool_event(
                "right-child", "child", "child-emitter", "child-right",
                parent_span_id="parent-span-replaced", timestamp="2026-07-18T09:00:00Z",
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.jsonl")
            right = Path(directory, "right.jsonl")
            write_events(left, left_events)
            write_events(right, right_events)
            report = compare_paths(left, right)

        divergence = report.split("## Divergence Evidence\n\n", 1)[1]
        self.assertIn("Earliest supported divergence:", divergence)
        self.assertNotIn("Stable divergence frontier:", divergence)
        self.assertIn("parent-left", divergence)
        self.assertIn("parent-right", divergence)
        self.assertNotIn("child-left", divergence)
        self.assertNotIn("child-right", divergence)

    def test_malformed_lines_and_sanitization_are_isolated_and_byte_stable(self):
        secret = "ghp_" + "a" * 36
        events = read_events()
        events[4]["attributes"]["arguments"]["token"] = secret
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.jsonl")
            right = Path(directory, "right.jsonl")
            write_events(left, events, malformed=("not json",))
            write_events(right, events)
            first = run_cli("compare", left, right)
            second = run_cli("compare", left, right)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertNotIn(secret, first.stdout + first.stderr)
        self.assertIn("ingestion:invalid&#95;json", first.stdout)
        self.assertIn("Run B removed", first.stdout)

    def test_exactly_one_trace_and_file_errors_return_two(self):
        events = read_events()
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory, "empty.jsonl")
            empty.write_text("not json\n", encoding="utf-8")
            multiple = Path(directory, "multiple.jsonl")
            events[1]["trace_id"] = "second-trace"
            write_events(multiple, events)
            for result in (
                run_cli("compare", empty, FIXTURE),
                run_cli("compare", multiple, FIXTURE),
                run_cli("compare", "missing.jsonl", FIXTURE),
            ):
                self.assertEqual(result.returncode, 2)
                self.assertIn("agent-tail compare:", result.stderr)

    def test_installed_console_script_exit_codes_and_sanitization(self):
        secret = "ghp_" + "b" * 36
        events = read_events()
        events[4]["attributes"]["arguments"]["authorization"] = secret
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / "bin" / "python"
            script = environment / "bin" / "agent-tail"
            installed = subprocess.run(
                [python, "-m", "pip", "install", "--no-deps", "."],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            left = root / "left.jsonl"
            right = root / "right.jsonl"
            invalid = root / "invalid.jsonl"
            write_events(left, events)
            write_events(right, events)
            invalid.write_text("not json\n", encoding="utf-8")
            compared = subprocess.run(
                [script, "compare", left, right],
                check=False,
                capture_output=True,
                text=True,
            )
            rejected = subprocess.run(
                [script, "compare", invalid, right],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertEqual(rejected.returncode, 2)
        self.assertNotIn(secret, compared.stdout + compared.stderr)
        self.assertIn("No semantic divergence was found.", compared.stdout)
        self.assertIn("expected exactly one retained trace", rejected.stderr)

    def test_10000_event_comparison_stays_inside_existing_time_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.jsonl")
            right = Path(directory, "right.jsonl")
            write_fixture(left)
            write_fixture(right)
            worker = Path(__file__).with_name("comparison_performance_worker.py")
            result = subprocess.run(
                [sys.executable, str(worker), str(left), str(right)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        measured = json.loads(result.stdout)
        print("10,000-event comparison: " + json.dumps(measured, sort_keys=True))
        self.assertLess(measured["total_seconds"], TIME_LIMIT_SECONDS)
        self.assertLess(measured["peak_rss_bytes"], RSS_LIMIT_BYTES)
        self.assertGreater(measured["output_bytes"], 0)
        self.assertRegex(measured["output_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
