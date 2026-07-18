import hashlib
from queue import Empty, Queue
import threading
import unittest
from unittest import mock
import unicodedata

from agent_tail.core import Event, TraceIndex, sanitize_event
from agent_tail.ui import (
    UiState,
    _curses_loop,
    _truncate_cells,
    drain_event_updates,
    render_snapshot,
    run,
    start_event_reader,
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
    }
    data.update(changes)
    return data


class SnapshotTests(unittest.TestCase):
    def test_cell_truncation_handles_cjk_emoji_combining_and_controls(self):
        self.assertEqual(_truncate_cells("ab界c", 4), "ab界")
        self.assertEqual(_truncate_cells("a🙂b", 3), "a🙂")
        self.assertEqual(_truncate_cells("e\N{COMBINING ACUTE ACCENT}x", 1), "é")
        self.assertEqual(_truncate_cells("e\N{COMBINING ACUTE ACCENT}x", 0), "")
        self.assertEqual(_truncate_cells("a\x00b", 3), "a�b")
        self.assertEqual(
            _truncate_cells("\t\x1b\n\r\N{RIGHT-TO-LEFT OVERRIDE}\ud800", 6),
            " �����",
        )
        output = _truncate_cells("safe\x00\x1b\n\N{RIGHT-TO-LEFT OVERRIDE}", 20)
        self.assertFalse(any(
            unicodedata.category(character).startswith("C")
            for character in output
        ))

    def test_snapshot_keeps_essential_text_at_narrow_width(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data()))

        output = render_snapshot(
            index, width=50, selected=0, now="2026-07-13T11:02:45Z"
        )

        self.assertIn("trace-1", output)
        self.assertIn("reviewer-1", output)
        self.assertIn("running", output)
        self.assertIn("read_file", output)
        self.assertIn("elapsed 0.1s", output)
        self.assertIn("tool.call.started", output)
        self.assertNotIn("\x1b[", output)

    def test_snapshot_has_stable_actor_lanes_and_one_timeline_row_per_event(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="actor-a-late", span_id="actor-a-late", sequence=2,
            timestamp="2026-07-13T11:02:46Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="actor-b", span_id="actor-b", emitter_id="worker-2",
            actor={"id": "writer-1"}, timestamp="2026-07-13T11:02:45Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="actor-a-early", span_id="actor-a-early", sequence=1,
            timestamp="2026-07-13T11:02:44Z",
        )))

        output = render_snapshot(index, width=120, now="2026-07-13T11:02:47Z")
        lanes = output.split("AGENT LANES\n", 1)[1].split("\nTIMELINE", 1)[0]
        timeline = output.split("TIMELINE\n", 1)[1].split("\nINSPECTOR", 1)[0]

        self.assertEqual(lanes.count("reviewer-1"), 1)
        self.assertEqual(lanes.count("writer-1"), 1)
        self.assertLess(lanes.index("reviewer-1"), lanes.index("writer-1"))
        self.assertEqual(timeline.count("event "), 3)

    def test_timeline_uses_global_sequence_order_across_interleaved_traces(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="first", trace_id="trace-1", span_id="first", sequence=1,
            timestamp="2026-07-13T11:05:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="second", trace_id="trace-2", span_id="second", sequence=2,
            timestamp="2026-07-13T11:01:00Z",
        )))

        timeline = render_snapshot(
            index, width=120, now="2026-07-13T11:06:00Z"
        ).split("TIMELINE\n", 1)[1].split("\nINSPECTOR", 1)[0]

        self.assertLess(timeline.index("event first"), timeline.index("event second"))

    def test_omitted_render_time_is_derived_from_indexed_events(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data()))

        first = render_snapshot(index, width=80)
        second = render_snapshot(index, width=80)

        self.assertEqual(first, second)
        self.assertIn("elapsed 0.0s", first)

    def test_selected_inspector_shows_canonical_fields_and_sanitized_payload(self):
        index = TraceIndex()
        event = Event.from_dict(event_data(
            parent_span_id="parent-1",
            payload={"token": "Bearer secret-value", "answer": 42},
        ))
        index.add(sanitize_event(event, full_payloads=True))

        output = render_snapshot(index, width=120, selected=0)

        for value in (
            "schema_version: 1.0",
            "event_id: evt-1",
            "trace_id: trace-1",
            "span_id: span-1",
            "parent_span_id: parent-1",
            "emitter_id: worker-1",
            "sequence: 1",
            "timestamp: 2026-07-13T11:02:44.912000+00:00",
            "kind: tool.call.started",
            'payload: {"answer":42,"token":"[REDACTED]"',
        ):
            with self.subTest(value=value):
                self.assertIn(value, output)
        self.assertNotIn("secret-value", output)

    def test_payload_rendering_does_not_mutate_indexed_event(self):
        index = TraceIndex()
        index.add(sanitize_event(Event.from_dict(event_data(
            payload={"answer": 42},
        ))))
        before = index.events[0].raw

        render_snapshot(index, width=120)

        self.assertEqual(index.events[0].raw, before)
        self.assertIn("_agent_tail", index.events[0].raw["payload"])

    def test_metadata_only_snapshot_labels_omitted_payload(self):
        index = TraceIndex()
        index.add(sanitize_event(
            Event.from_dict(event_data(payload={"text": "hidden sentinel"})),
            metadata_only=True,
        ))

        output = render_snapshot(index, width=200, metadata_only=True)

        self.assertIn("PAYLOAD MODE: metadata-only", output)
        self.assertIn("payload: omitted (metadata-only)", output)
        self.assertIn('"omitted": true', output)
        self.assertNotIn("hidden sentinel", output)

    def test_snapshot_applies_plain_state_filters(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data()))
        index.add(Event.from_dict(event_data(
            event_id="evt-2",
            trace_id="trace-2",
            span_id="span-2",
            emitter_id="worker-2",
            kind="model.response.completed",
            actor={"id": "writer-1"},
            operation={"status": "completed", "name": "write_file"},
            payload={"text": "needle"},
        )))
        state = UiState(event_count=2)
        state.handle_key("a", "writer-1")
        state.handle_key("t", "model.response.completed")
        state.handle_key("/", "needle")
        state.handle_key("T", "trace-2")

        output = render_snapshot(index, width=100, state=state)

        self.assertIn("FILTER agent=writer-1", output)
        self.assertIn("kind=model.response.completed", output)
        self.assertIn("search=needle", output)
        self.assertIn("trace=trace-2", output)
        self.assertIn("writer-1", output)
        self.assertNotIn("reviewer-1", output)

    def test_search_uses_redacted_extension_and_payload_keys(self):
        extension_secret = "ghp_" + "a" * 36
        payload_secret = "ghp_" + "b" * 36
        index = TraceIndex()
        index.add(sanitize_event(Event.from_dict(event_data(
            future_field={extension_secret: "extension"},
            payload={payload_secret: "payload"},
        )), full_payloads=True))

        for secret in (extension_secret, payload_secret):
            state = UiState(event_count=1, search=secret)
            raw_search = render_snapshot(index, width=160, state=state)
            placeholder = (
                "[REDACTED:"
                + hashlib.sha256(secret.encode()).hexdigest()[:12]
                + "]"
            )
            state.search = placeholder
            redacted_search = render_snapshot(index, width=160, state=state)

            self.assertNotIn("event evt-1", raw_search)
            self.assertIn("event evt-1", redacted_search)

    def test_run_is_the_public_curses_boundary(self):
        self.assertTrue(callable(run))

    def test_wide_snapshot_adds_role_warning_and_error_text(self):
        index = TraceIndex(stall_seconds=0)
        index.add(Event.from_dict(event_data(
            actor={"id": "reviewer-1", "role": "reviewer"},
            error="TimeoutError",
        )))

        output = render_snapshot(
            index, width=160, now="2026-07-13T11:02:45Z"
        )

        self.assertIn("role reviewer", output)
        self.assertIn("warning STALL", output)
        self.assertIn("error TimeoutError", output)

    def test_parent_lane_uses_propagated_child_activity_and_actor_warning(self):
        index = TraceIndex(stall_seconds=10)
        index.add(Event.from_dict(event_data(
            event_id="root", span_id="root", timestamp="2026-07-13T11:02:44Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="root", sequence=2,
            timestamp="2026-07-13T11:03:25Z", kind="tool.call.completed",
            actor={"id": "tool-1"},
            operation={"status": "completed", "name": "shell"},
        )))

        output = render_snapshot(
            index, width=160, now="2026-07-13T11:03:40Z"
        )
        parent_lane = next(
            line for line in output.splitlines() if line.startswith("reviewer-1 ")
        )

        self.assertIn("running read_file", parent_lane)
        self.assertIn("elapsed 15.0s", parent_lane)
        self.assertIn("warning STALL", parent_lane)

    def test_warning_only_mode_keeps_propagated_stall_parent_lane(self):
        index = TraceIndex(stall_seconds=10)
        index.add(Event.from_dict(event_data(
            event_id="root", span_id="root", timestamp="2026-07-13T11:02:44Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="child", span_id="child", parent_span_id="root", sequence=2,
            timestamp="2026-07-13T11:03:25Z", kind="tool.call.completed",
            actor={"id": "tool-1"},
            operation={"status": "completed", "name": "shell"},
        )))

        output = render_snapshot(
            index,
            width=160,
            now="2026-07-13T11:03:40Z",
            state=UiState(event_count=2, warnings_only=True),
        )

        self.assertIn("reviewer-1 running read_file", output)
        self.assertIn("warning STALL", output)
        self.assertIn("event root ", output)
        self.assertIn("event child ", output)

    def test_trace_filtered_warning_mode_does_not_leak_same_actor_warning(self):
        index = TraceIndex(stall_seconds=10)
        index.add(Event.from_dict(event_data(
            event_id="trace-1-open", trace_id="trace-1", span_id="trace-1-open",
            emitter_id="worker-1", actor={"id": "shared"},
            timestamp="2026-07-13T11:00:00Z",
        )))
        index.add(Event.from_dict(event_data(
            event_id="trace-2-done", trace_id="trace-2", span_id="trace-2-done",
            emitter_id="worker-2", actor={"id": "shared"},
            timestamp="2026-07-13T11:03:00Z", kind="tool.call.completed",
            operation={"status": "completed", "name": "read_file"},
        )))

        output = render_snapshot(
            index,
            width=160,
            now="2026-07-13T11:03:40Z",
            state=UiState(
                event_count=2,
                trace_filter="trace-2",
                warnings_only=True,
            ),
        )

        self.assertNotIn("warning STALL", output)
        self.assertNotIn("event trace-1-open", output)
        self.assertNotIn("event trace-2-done", output)

    def test_same_actor_in_multiple_visible_traces_has_distinct_lanes(self):
        index = TraceIndex()
        for trace_id, emitter_id in (("trace-1", "worker-1"), ("trace-2", "worker-2")):
            index.add(Event.from_dict(event_data(
                event_id=f"{trace_id}-event", trace_id=trace_id,
                span_id=f"{trace_id}-span", emitter_id=emitter_id,
                actor={"id": "shared"},
            )))

        lanes = render_snapshot(index, width=160).split(
            "AGENT LANES\n", 1
        )[1].split("\nTIMELINE", 1)[0]

        self.assertEqual(lanes.count("shared"), 2)
        self.assertIn("trace-1", lanes)
        self.assertIn("trace-2", lanes)

    def test_lane_displays_actor_state_uncertainty(self):
        index = TraceIndex()
        for event_id, emitter, status in (
            ("running", "worker-a", "running"),
            ("failed", "worker-b", "failed"),
        ):
            index.add(Event.from_dict(event_data(
                event_id=event_id, span_id=event_id, emitter_id=emitter,
                operation={"status": status, "name": "read_file"},
            )))

        lane = next(
            line for line in render_snapshot(index, width=120).splitlines()
            if line.startswith("reviewer-1 ")
        )

        self.assertIn("uncertain", lane)

    def test_lane_pairs_open_span_status_with_its_operation(self):
        index = TraceIndex()
        index.add(Event.from_dict(event_data(
            event_id="read", span_id="read", sequence=1,
            operation={"status": "running", "name": "read_file"},
        )))
        index.add(Event.from_dict(event_data(
            event_id="write", span_id="write", sequence=2,
            kind="tool.call.completed",
            operation={"status": "completed", "name": "write_file"},
        )))

        lane = next(
            line for line in render_snapshot(index, width=120).splitlines()
            if line.startswith("reviewer-1 ")
        )

        self.assertIn("running read_file", lane)
        self.assertNotIn("running write_file", lane)


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

    def test_selection_clamps_and_filter_actions_are_explicit_fields(self):
        state = UiState(event_count=2)

        state.handle_key("k")
        state.handle_key("j")
        state.handle_key("j")
        state.handle_key("a", "reviewer-1")
        state.handle_key("t", "tool.call.started")
        state.handle_key("/", "read_file")
        state.handle_key("T", "trace-1")

        self.assertEqual(state.selected, 1)
        self.assertEqual(state.agent_filter, "reviewer-1")
        self.assertEqual(state.event_kind_filter, "tool.call.started")
        self.assertEqual(state.search, "read_file")
        self.assertEqual(state.trace_filter, "trace-1")


class EventReaderTests(unittest.TestCase):
    def test_curses_loop_sanitizes_and_bounds_reader_error_status(self):
        error = RuntimeError("bad\n\t\x1b\N{RIGHT-TO-LEFT OVERRIDE}\x00end")
        updates = Queue()
        updates.put(error)
        updates.put(None)

        class Screen:
            def __init__(self):
                self.lines = []

            def timeout(self, _value):
                pass

            def getmaxyx(self):
                return (20, 80)

            def erase(self):
                pass

            def addstr(self, row, _column, text):
                self.lines.append((row, text))

            def refresh(self):
                pass

            def get_wch(self):
                return "q"

        screen = Screen()
        with mock.patch(
            "agent_tail.ui.start_event_reader", return_value=updates
        ):
            _curses_loop(screen, TraceIndex(), ())

        status = screen.lines[0][1]
        self.assertIn("READER ERROR", status)
        self.assertIn("end", status)
        self.assertFalse(any(
            unicodedata.category(character).startswith("C")
            for _, line in screen.lines
            for character in line
        ))
        for _, line in screen.lines:
            cells = sum(
                0 if unicodedata.category(character).startswith("M")
                else 2 if unicodedata.east_asian_width(character) in {"W", "F"}
                else 1
                for character in line
            )
            self.assertLessEqual(cells, 79)

    def test_curses_loop_returns_reader_failure_after_quit(self):
        error = RuntimeError("reader failed")
        updates = Queue()
        updates.put(error)
        updates.put(None)

        class Screen:
            def timeout(self, _value):
                pass

            def getmaxyx(self):
                return (20, 80)

            def erase(self):
                pass

            def addnstr(self, *_args):
                pass

            def addstr(self, *_args):
                pass

            def refresh(self):
                pass

            def get_wch(self):
                return "q"

        with mock.patch(
            "agent_tail.ui.start_event_reader", return_value=updates
        ):
            result = _curses_loop(Screen(), TraceIndex(), ())

        self.assertIs(result, error)

    def test_drain_processes_all_current_events_eof_and_error(self):
        index = TraceIndex()
        state = UiState(event_count=0)
        updates = Queue()
        first = Event.from_dict(event_data())
        second = Event.from_dict(event_data(
            event_id="evt-2", span_id="span-2", sequence=2,
        ))
        error = RuntimeError("reader failed")
        for update in (first, second, error, None):
            updates.put(update)

        eof, reader_error = drain_event_updates(index, state, updates)

        self.assertTrue(eof)
        self.assertIs(reader_error, error)
        self.assertEqual(index.events, (first, second))
        self.assertEqual(state.event_count, 2)
        self.assertTrue(updates.empty())

    def test_reader_queues_an_event_before_iterable_eof(self):
        release = threading.Event()
        event = Event.from_dict(event_data())

        def events():
            yield event
            release.wait(0.5)

        updates = start_event_reader(events())

        self.assertEqual(updates.maxsize, 1)
        self.assertIs(updates.get(timeout=0.5), event)
        with self.assertRaises(Empty):
            updates.get_nowait()
        release.set()
        self.assertIsNone(updates.get(timeout=0.5))

    def test_reader_reports_failure_then_eof_without_deadlock(self):
        error = RuntimeError("reader failed")

        def events():
            raise error
            yield

        updates = start_event_reader(events())

        self.assertIs(updates.get(timeout=0.5), error)
        self.assertIsNone(updates.get(timeout=0.5))


if __name__ == "__main__":
    unittest.main()
