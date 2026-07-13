from queue import Empty, Queue
import threading
import unittest

from agent_tail.core import Event, TraceIndex, sanitize_event
from agent_tail.ui import (
    UiState,
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
