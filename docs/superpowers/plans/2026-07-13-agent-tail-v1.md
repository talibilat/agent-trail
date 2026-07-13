# Agent Tail v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local Python CLI/TUI that ingests canonical agent events from JSONL files or standard input, exposes a causal timeline, flags common execution problems, and exports a redacted Markdown report.

**Architecture:** Keep the first release in three modules. `core.py` owns the canonical event boundary, redaction, indexing, and warning heuristics; `ui.py` renders snapshots and the interactive terminal; `cli.py` owns arguments, input selection, and export. The runtime emits the canonical envelope directly, while future harness support remains outside the core as thin producers of the same JSON objects.

**Tech Stack:** Python 3.11+, standard-library `json`, `argparse`, `dataclasses`, `datetime`, `hashlib`, `re`, `curses`, `unittest`, and `tomllib`-compatible packaging through `pyproject.toml`.

---

### Task 1: Package And CLI Skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `src/agent_tail/__init__.py`
- Create: `src/agent_tail/__main__.py`
- Create: `src/agent_tail/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing CLI help test**

```python
import subprocess
import sys
import unittest


class CliTests(unittest.TestCase):
    def test_help_names_file_and_stdin_inputs(self):
        result = subprocess.run(
            [sys.executable, "-m", "agent_tail", "--help"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("JSONL file or - for standard input", result.stdout)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_cli.CliTests.test_help_names_file_and_stdin_inputs -v`

Expected: FAIL because `agent_tail` does not exist.

- [ ] **Step 3: Add minimal packaging and argument parsing**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "agent-tail"
version = "0.1.0"
description = "Local causal timeline for agent runs"
requires-python = ">=3.11"

[project.scripts]
agent-tail = "agent_tail.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

```python
# src/agent_tail/__init__.py
"""Agent Tail."""
```

```python
# src/agent_tail/__main__.py
from .cli import main

raise SystemExit(main())
```

```python
# src/agent_tail/cli.py
import argparse


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail")
    result.add_argument("input", help="JSONL file or - for standard input")
    result.add_argument("--export", metavar="PATH")
    result.add_argument("--full-payloads", action="store_true")
    result.add_argument("--unsafe-unredacted", action="store_true")
    result.add_argument("--loop-threshold", type=int, default=4)
    result.add_argument("--stall-seconds", type=float, default=30.0)
    return result


def main(argv: list[str] | None = None) -> int:
    parser().parse_args(argv)
    return 0
```

- [ ] **Step 4: Run the test and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_cli -v`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add pyproject.toml src/agent_tail tests/test_cli.py && git commit -m "feat: add agent-tail CLI"`

### Task 2: Canonical Event Validation

**Files:**
- Create: `src/agent_tail/core.py`
- Test: `tests/test_core.py`

- [ ] **Step 1: Write failing tests for valid, extensible, and invalid envelopes**

```python
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
    def test_preserves_unknown_fields_and_minor_versions(self):
        event = Event.from_dict(event_data(schema_version="1.8"))

        self.assertEqual(event.raw["future_field"], {"preserved": True})

    def test_rejects_missing_required_fields(self):
        data = event_data()
        del data["trace_id"]

        with self.assertRaisesRegex(EventError, "trace_id"):
            Event.from_dict(data)

    def test_rejects_unsupported_major_version(self):
        with self.assertRaisesRegex(EventError, "schema version"):
            Event.from_dict(event_data(schema_version="2.0"))
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_core.EventTests -v`

Expected: FAIL because `agent_tail.core` does not exist.

- [ ] **Step 3: Implement the canonical envelope boundary**

Create an immutable `Event` dataclass with typed accessors for the required fields and a `raw` mapping containing all input fields.
`Event.from_dict` must reject missing or incorrectly typed required values, invalid ISO-8601 timestamps, negative sequences, actor objects without string IDs, operation objects without string statuses, and schema versions whose major component is not `1`.
It must accept unknown event kinds, unknown fields, missing parent IDs, and any `1.x` schema version.

- [ ] **Step 4: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_core.EventTests -v`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add src/agent_tail/core.py tests/test_core.py && git commit -m "feat: validate canonical events"`

### Task 3: Resilient JSONL Ingestion

**Files:**
- Modify: `src/agent_tail/core.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing ingestion tests**

```python
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
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_core.IngestionTests -v`

Expected: FAIL because `read_jsonl` does not exist.

- [ ] **Step 3: Implement one-pass ingestion**

Add an `Ingestion` dataclass containing `events` and `errors` lists.
Implement `read_jsonl(lines: Iterable[str]) -> Ingestion` with `json.loads`, `Event.from_dict`, and a set of accepted event IDs.
Ignore blank lines, preserve the first duplicate, and include the source line number in every error.

- [ ] **Step 4: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_core.IngestionTests -v`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add src/agent_tail/core.py tests/test_core.py && git commit -m "feat: ingest resilient JSONL streams"`

### Task 4: Payload Bounding And Redaction

**Files:**
- Modify: `src/agent_tail/core.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing redaction tests**

```python
class RedactionTests(unittest.TestCase):
    def test_redacts_nested_secrets_and_bounds_payloads(self):
        secret = "sk-ant-" + "x" * 40
        event = Event.from_dict(event_data(
            attributes={"authorization": "Bearer token-value"},
            payload={"cookie": "session=secret", "text": secret + "z" * 5000},
        ))

        safe = sanitize_event(event)
        encoded = json.dumps(safe.raw)

        self.assertNotIn("token-value", encoded)
        self.assertNotIn(secret, encoded)
        self.assertTrue(safe.raw["payload"]["_agent_tail"]["truncated"])
        self.assertEqual(safe.raw["payload"]["_agent_tail"]["ruleset"], "1")
        self.assertEqual(len(safe.raw["payload"]["_agent_tail"]["sha256"]), 64)

    def test_full_and_unsafe_payload_flags_are_explicit(self):
        event = Event.from_dict(event_data(payload={"text": "Bearer abc" + "z" * 5000}))

        full = sanitize_event(event, full_payloads=True)
        unsafe = sanitize_event(event, full_payloads=True, unsafe_unredacted=True)

        self.assertFalse(full.raw["payload"]["_agent_tail"]["truncated"])
        self.assertNotIn("Bearer abc", json.dumps(full.raw))
        self.assertIn("Bearer abc", json.dumps(unsafe.raw))
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_core.RedactionTests -v`

Expected: FAIL because `sanitize_event` does not exist.

- [ ] **Step 3: Implement recursive sanitization**

Use compiled regular expressions and recursive traversal of dictionaries, lists, and strings.
Replace secrets with `[REDACTED]` before indexing or searching.
Bound serialized payload previews by UTF-8 bytes without emitting invalid Unicode and attach `_agent_tail` metadata containing byte count, content hash, truncation state, and redaction ruleset `1`.

- [ ] **Step 4: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_core.RedactionTests -v`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add src/agent_tail/core.py tests/test_core.py && git commit -m "feat: redact and bound event payloads"`

### Task 5: Trace Index And Warning Heuristics

**Files:**
- Modify: `src/agent_tail/core.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing trace-index tests**

```python
class TraceIndexTests(unittest.TestCase):
    def test_groups_and_orders_events_without_inventing_cross_emitter_order(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(event_id="child", span_id="child", parent_span_id="root", sequence=2)))
        index.add(Event.from_dict(event_data(event_id="root", span_id="root", sequence=1)))
        index.add(Event.from_dict(event_data(
            event_id="other", span_id="other", emitter_id="worker-2", sequence=1,
        )))

        view = index.trace("trace-1")

        self.assertLess(view.event_ids.index("root"), view.event_ids.index("child"))
        self.assertIn("other", view.uncertain_event_ids)
        self.assertEqual(view.actors["reviewer-1"].status, "running")
```

- [ ] **Step 2: Write failing warning tests**

```python
class WarningTests(unittest.TestCase):
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

        codes = {warning.code for warning in index.warnings(now="2026-07-13T11:03:30Z")}

        self.assertTrue({"LOOP", "RETRY", "STALL", "ORPHAN"}.issubset(codes))

    def test_output_change_prevents_loop_warning(self):
        index = TraceIndex(loop_threshold=4)
        for sequence in range(1, 5):
            index.add(Event.from_dict(event_data(
                event_id=f"evt-{sequence}", span_id=f"span-{sequence}", sequence=sequence,
                attributes={"arguments": {"path": "same.py"}, "output_hash": str(sequence)},
            )))

        self.assertNotIn("LOOP", {warning.code for warning in index.warnings()})
```

- [ ] **Step 3: Run the tests and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_core.TraceIndexTests tests.test_core.WarningTests -v`

Expected: FAIL because `TraceIndex` does not exist.

- [ ] **Step 4: Implement the smallest in-memory index**

Store events in trace dictionaries, span dictionaries, actor dictionaries, and insertion-order lists.
Create operation signatures from kind, actor ID, operation name, and canonical JSON arguments after removing adapter-declared volatile argument keys.
Return warnings as immutable records containing code, event ID, actor ID, summary, and exact evidence.
Accept loop, stall, and orphan thresholds as constructor arguments rather than introducing configuration files.
Evict payload previews before metadata when an approximate configurable memory ceiling is reached and add an eviction warning.

- [ ] **Step 5: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_core.TraceIndexTests tests.test_core.WarningTests -v`

Expected: PASS.

- [ ] **Step 6: Commit**

Run: `git add src/agent_tail/core.py tests/test_core.py && git commit -m "feat: index traces and detect execution warnings"`

### Task 6: Terminal Snapshot And Interactive Inspector

**Files:**
- Create: `src/agent_tail/ui.py`
- Create: `tests/test_ui.py`

- [ ] **Step 1: Write failing snapshot tests**

```python
class SnapshotTests(unittest.TestCase):
    def test_snapshot_keeps_essential_text_at_narrow_width(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data()))

        output = render_snapshot(index, width=50, selected=0, now="2026-07-13T11:02:45Z")

        self.assertIn("trace-1", output)
        self.assertIn("reviewer-1", output)
        self.assertIn("running", output)
        self.assertIn("read_file", output)
        self.assertIn("tool.call.started", output)
        self.assertNotIn("\x1b[", output)
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_ui -v`

Expected: FAIL because `agent_tail.ui` does not exist.

- [ ] **Step 3: Implement deterministic text rendering**

Implement a pure `render_snapshot` function that computes rows without terminal I/O.
Keep actor, state, operation, and elapsed columns at narrow widths, then add role, warning, and error columns as space permits.
Render selected event fields and sanitized payload text below the timeline.

- [ ] **Step 4: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_ui -v`

Expected: PASS.

- [ ] **Step 5: Write failing keyboard-state tests**

```python
class UiStateTests(unittest.TestCase):
    def test_keyboard_commands_update_plain_state(self):
        state = UiState(event_count=3)

        state.handle_key("j")
        state.handle_key("e")
        state.handle_key("l")
        state.handle_key("q")

        self.assertEqual(state.selected, 1)
        self.assertTrue(state.errors_only)
        self.assertTrue(state.warnings_only)
        self.assertTrue(state.quit)
```

- [ ] **Step 6: Implement the curses shell**

Add `UiState` for selection and filters, then a small `run(index, events=None)` wrapper using standard-library `curses.wrapper`.
When `events` is supplied, consume available sanitized events incrementally on a reader thread and wake the curses loop through a queue so standard-input traces redraw before EOF.
Use text labels in every state, honor `NO_COLOR`, freeze the final view after EOF, and redraw from `render_snapshot`.

- [ ] **Step 7: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_ui -v`

Expected: PASS.

- [ ] **Step 8: Commit**

Run: `git add src/agent_tail/ui.py tests/test_ui.py && git commit -m "feat: add terminal timeline and inspector"`

### Task 7: Markdown Export And End-To-End CLI

**Files:**
- Modify: `src/agent_tail/core.py`
- Modify: `src/agent_tail/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing export and integration tests**

```python
    def test_file_and_stdin_export_the_same_redacted_report(self):
        line = json.dumps(event_data(payload={"token": "Bearer secret-value"})) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            file_report = Path(directory, "file.md")
            stdin_report = Path(directory, "stdin.md")
            source.write_text(line, encoding="utf-8")

            from_file = subprocess.run(
                [sys.executable, "-m", "agent_tail", str(source), "--export", str(file_report)],
                check=False, capture_output=True, text=True,
            )
            from_stdin = subprocess.run(
                [sys.executable, "-m", "agent_tail", "-", "--export", str(stdin_report)],
                input=line, check=False, capture_output=True, text=True,
            )

            self.assertEqual((from_file.returncode, from_stdin.returncode), (0, 0))
            self.assertEqual(file_report.read_text(), stdin_report.read_text())
            self.assertIn("trace-1", file_report.read_text())
            self.assertNotIn("secret-value", file_report.read_text())

    def test_stdin_events_are_visible_before_eof(self):
        process = subprocess.Popen(
            [sys.executable, "-m", "agent_tail", "-", "--snapshot-stream"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )
        process.stdin.write(json.dumps(event_data()) + "\n")
        process.stdin.flush()

        self.assertIn("reviewer-1", process.stdout.readline())

        process.stdin.close()
        self.assertEqual(process.wait(timeout=2), 0)
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `PYTHONPATH=src python -m unittest tests.test_cli -v`

Expected: FAIL because the CLI does not ingest or export.

- [ ] **Step 3: Connect the CLI**

Open UTF-8 files directly.
For `-`, pass a line iterator to the UI so it sanitizes, indexes, and redraws after each accepted event without waiting for EOF.
Pass each event through sanitization before adding it to `TraceIndex`.
Write Markdown when `--export` is present; otherwise use the interactive UI on a TTY and print a static snapshot on a non-TTY.
Use the internal `--snapshot-stream` acceptance mode to emit one flushed snapshot marker per accepted standard-input event without curses; keep it undocumented because it exists only to test incremental behavior through the real CLI boundary.
Return exit code `0` when at least one event was accepted, `1` when none were accepted, and `2` for command-line or file errors.

- [ ] **Step 4: Run the tests and verify GREEN**

Run: `PYTHONPATH=src python -m unittest tests.test_cli -v`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add src/agent_tail/core.py src/agent_tail/cli.py tests/test_cli.py && git commit -m "feat: connect ingestion UI and Markdown export"`

### Task 8: Realistic Trace And Acceptance Checks

**Files:**
- Create: `tests/fixtures/runtime.jsonl`
- Create: `README.md`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Create a representative 30-agent fixture**

Use a short checked-in JSONL fixture containing 30 `agent.started` events followed by explicit loop, retry, stall, orphan, malformed, duplicate, unknown-kind, clock-skew, late-arrival, secret, and oversized-payload examples.
Every valid line uses the Task 2 envelope and unique actor IDs `agent-01` through `agent-30`.

- [ ] **Step 2: Run the acceptance commands**

Run: `PYTHONPATH=src python -m agent_tail tests/fixtures/runtime.jsonl --export /tmp/agent-tail-report.md`

Expected: exit code `0`; the report contains `agent-01`, `agent-30`, `LOOP`, `RETRY`, `STALL`, `ORPHAN`, and `[REDACTED]`, while the fixture's literal secret is absent.

- [ ] **Step 3: Document the direct runtime envelope**

Write `README.md` with installation, JSONL file and standard-input examples, the required envelope fields, ordering and uncertainty rules, redaction limitations, unsafe flags, Markdown export, keyboard controls, exit codes, and the future adapter rule that harness-specific fields remain namespaced attributes.

- [ ] **Step 4: Run the complete verification suite**

Run: `PYTHONPATH=src python -m unittest discover -s tests -v`

Expected: all tests PASS with no warnings or tracebacks.

Run: `python -m compileall -q src tests`

Expected: exit code `0` with no output.

Run: `PYTHONPATH=src python -m agent_tail tests/fixtures/runtime.jsonl --export /tmp/agent-tail-report.md`

Expected: exit code `0`, a report is created, and no fixture secret appears in it.

- [ ] **Step 5: Commit**

Run: `git add README.md tests && git commit -m "test: validate realistic multi-agent traces"`

## Deferred Until Evidence Requires It

- Unix sockets and named pipes beyond ordinary standard-input piping.
- Public Claude Code, OpenCode, Codex, LangGraph, and OTLP adapters.
- HTML and Mermaid exports.
- Graph pane, graph animation, persistence, replay, hosted services, and configuration files.
- Fan-out pressure warnings and per-tool warning policies.
- Custom keybindings and framework-specific concepts in the canonical core.

## Self-Review

- The plan covers the 36 accepted decisions through a direct runtime envelope, resilient input, bounded redacted payloads, deterministic ordering, uncertainty, four warning heuristics, terminal navigation, Markdown export, and realistic acceptance coverage.
- Deliberately deferred features match the accepted v1 boundary and have no speculative scaffolding.
- Module names and APIs remain consistent across tasks: `Event`, `read_jsonl`, `sanitize_event`, `TraceIndex`, `render_snapshot`, `UiState`, and `main`.
- The plan contains no generated changelog work, hosted infrastructure, database, adapter framework, or new runtime dependency.
