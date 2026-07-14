import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest import mock

from agent_tail import cli
import agent_tail.serve as serve_module
from agent_tail.serve import RunStore, ServeConfig, make_server, serve, start_file_follower


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


class ServeTests(unittest.TestCase):
    def test_store_lists_and_details_sanitized_runs(self):
        secret = "ghp_" + "a" * 36
        store = RunStore.from_lines([
            json.dumps(event_data(
                event_id=secret,
                payload={"token": "Bearer payload-secret", "text": "safe"},
            )) + "\n",
            "not json\n",
        ])

        runs = store.list_runs()
        detail = store.run_detail("trace-1")
        encoded = json.dumps(detail)

        self.assertEqual(runs["api_version"], "v1")
        self.assertEqual(runs["runs"][0]["trace_id"], "trace-1")
        self.assertEqual(runs["ingestion_errors"][0]["line"], 2)
        self.assertEqual(detail["api_version"], "v1")
        self.assertEqual(detail["run"]["event_count"], 1)
        self.assertIn("[REDACTED", detail["events"][0]["event_id"])
        self.assertNotIn(secret, encoded)
        self.assertNotIn("payload-secret", encoded)

    def test_http_server_serves_offline_shell_and_versioned_api(self):
        store = RunStore.from_lines([
            json.dumps(event_data(trace_id="trace/1", kind="<script>kind</script>")) + "\n"
        ])
        server = make_server(store, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

        html = urlopen(base_url + "/", timeout=2).read().decode("utf-8")
        runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=2).read())
        detail = json.loads(urlopen(base_url + "/api/v1/runs/trace%2F1", timeout=2).read())

        self.assertIn("Agent Tail", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assertIn("textContent", html)
        self.assertIn("finding.kind", html)
        self.assertEqual(runs["runs"][0]["trace_id"], "trace/1")
        self.assertEqual(detail["events"][0]["event_id"], "evt-1")

        with self.assertRaises(HTTPError) as raised:
            urlopen(base_url + "/api/v1/runs/missing", timeout=2).read()
        self.assertEqual(raised.exception.code, 404)

    def test_growing_file_appends_are_delivered_over_sse_and_reconnect(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            store = RunStore(source_kind="file")
            stop = threading.Event()
            follower = start_file_follower(
                source, store, config=ServeConfig(), stop=stop, poll_seconds=0.01
            )
            self.addCleanup(stop.set)
            self.addCleanup(lambda: follower.join(timeout=1))
            self.assertTrue(_wait_until(lambda: store.list_runs()["runs"]))
            cursor = store.cursor
            server = make_server(store, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

            response = urlopen(base_url + f"/api/v1/events?cursor={cursor}", timeout=2)
            with source.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event_data(
                    event_id="evt-2",
                    span_id="span-2",
                    sequence=2,
                )) + "\n")
            payload = _read_sse_data(response)
            response.close()
            detail = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=2).read())
            response = urlopen(
                base_url + f"/api/v1/events?cursor={detail['cursor']}",
                timeout=2,
            )
            with source.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event_data(
                    event_id="evt-3",
                    span_id="span-3",
                    sequence=3,
                )) + "\n")
            reconnected_payload = _read_sse_data(response)
            response.close()
            reconnected_detail = json.loads(
                urlopen(base_url + "/api/v1/runs/trace-1", timeout=2).read()
            )

        self.assertEqual(payload["event_id"], "evt-2")
        self.assertEqual(reconnected_payload["event_id"], "evt-3")
        self.assertEqual(
            [event["event_id"] for event in detail["events"]],
            ["evt-1", "evt-2"],
        )
        self.assertEqual(
            [event["event_id"] for event in reconnected_detail["events"]],
            ["evt-1", "evt-2", "evt-3"],
        )
        self.assertEqual(
            len({event["event_id"] for event in reconnected_detail["events"]}),
            3,
        )

    def test_file_follower_waits_for_complete_jsonl_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            store = RunStore(source_kind="file")
            stop = threading.Event()
            follower = start_file_follower(
                source, store, config=ServeConfig(), stop=stop, poll_seconds=0.01
            )
            self.addCleanup(stop.set)
            self.addCleanup(lambda: follower.join(timeout=1))
            self.assertTrue(_wait_until(lambda: store.list_runs()["runs"]))
            partial = json.dumps(event_data(
                event_id="evt-2",
                span_id="span-2",
                sequence=2,
            ))

            with source.open("a", encoding="utf-8") as handle:
                split_at = partial.index('"span_id"')
                handle.write(partial[:split_at])
                handle.flush()
            time.sleep(0.05)
            self.assertEqual(store.run_detail("trace-1")["run"]["event_count"], 1)

            with source.open("a", encoding="utf-8") as handle:
                handle.write(partial[split_at:] + "\n")
            self.assertTrue(_wait_until(
                lambda: store.run_detail("trace-1")["run"]["event_count"] == 2
            ))
            codes = {finding["code"] for finding in store.list_runs()["findings"]}

        self.assertNotIn("INVALID_JSON", codes)

    def test_stdin_eof_marks_incomplete_without_completing_trace(self):
        store = RunStore(source_kind="stdin")
        serve_module._read_stream(
            io.StringIO(json.dumps(event_data()) + "\n"),
            store,
            ServeConfig(),
            source_kind="stdin",
        )

        detail = store.run_detail("trace-1")

        self.assertEqual(detail["source"]["state"], "disconnected")
        self.assertFalse(detail["source"]["connected"])
        self.assertEqual(detail["run"]["state"], "incomplete")

    def test_explicit_terminal_events_drive_run_states_and_late_findings(self):
        for kind, state in (("trace.completed", "completed"), ("trace.failed", "failed")):
            with self.subTest(kind=kind):
                store = RunStore(source_kind="stdin")
                store.set_source_status(connected=True, state="reading")
                store.feed_line(json.dumps(event_data()) + "\n")
                store.feed_line(json.dumps(event_data(
                    event_id=f"evt-{state}",
                    span_id=f"span-{state}",
                    sequence=2,
                    kind=kind,
                    operation={"status": state},
                )) + "\n")

                self.assertEqual(store.run_detail("trace-1")["run"]["state"], state)

        store = RunStore(source_kind="stdin")
        store.set_source_status(connected=True, state="reading")
        store.feed_line(json.dumps(event_data(kind="trace.completed")) + "\n")
        store.feed_line(json.dumps(event_data(
            event_id="late",
            span_id="late",
            sequence=2,
        )) + "\n")

        codes = {finding["code"] for finding in store.run_detail("trace-1")["findings"]}
        self.assertIn("LATE_EVENT", codes)

    def test_ingestion_findings_are_visible(self):
        store = RunStore(source_kind="file")
        store.feed_line("not json\n")
        store.feed_line(json.dumps(event_data()) + "\n")
        store.feed_line(json.dumps(event_data()) + "\n")

        codes = {finding["code"] for finding in store.list_runs()["findings"]}

        self.assertIn("INVALID_JSON", codes)
        self.assertIn("DUPLICATE_EVENT", codes)

    def test_file_replacement_and_truncation_are_source_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            replacement = Path(directory, "replacement.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            store = RunStore(source_kind="file")
            stop = threading.Event()
            follower = start_file_follower(
                source, store, config=ServeConfig(), stop=stop, poll_seconds=0.01
            )
            self.addCleanup(stop.set)
            self.addCleanup(lambda: follower.join(timeout=1))
            self.assertTrue(_wait_until(lambda: store.list_runs()["runs"]))

            replacement.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            replacement.replace(source)
            self.assertTrue(_wait_until(
                lambda: any(
                    finding["code"] == "SOURCE_REPLACED"
                    for finding in store.list_runs()["findings"]
                )
            ))
            self.assertTrue(_wait_until(
                lambda: any(
                    finding["code"] == "DUPLICATE_EVENT"
                    for finding in store.list_runs()["findings"]
                )
            ))
            source.write_text("", encoding="utf-8")
            self.assertTrue(_wait_until(
                lambda: any(
                    finding["code"] == "SOURCE_TRUNCATED"
                    for finding in store.list_runs()["findings"]
                )
            ))

    def test_serve_cli_dispatches_without_changing_default_invocation(self):
        with mock.patch.object(cli, "serve", return_value=0) as serve:
            result = cli.main(["serve", "-", "--host", "127.0.0.1", "--port", "0"])

        self.assertEqual(result, 0)
        serve.assert_called_once()
        self.assertEqual(serve.call_args.kwargs["config"].host, "127.0.0.1")
        self.assertEqual(serve.call_args.kwargs["config"].port, 0)

    def test_serve_prints_url_and_honors_explicit_browser_open(self):
        class FakeServer:
            server_address = ("127.0.0.1", 43210)

            def serve_forever(self):
                raise KeyboardInterrupt

            def server_close(self):
                pass

        opened = []
        stdout = io.StringIO()
        with (
            mock.patch("agent_tail.serve.make_server", return_value=FakeServer()),
            mock.patch("sys.stdout", stdout),
        ):
            result = serve(
                io.StringIO(json.dumps(event_data()) + "\n"),
                config=ServeConfig(port=0, open_browser=True),
                open_url=opened.append,
            )

        self.assertEqual(result, 0)
        self.assertIn("http://127.0.0.1:43210/", stdout.getvalue())
        self.assertEqual(opened, ["http://127.0.0.1:43210/"])

    def test_serve_cli_input_validation_errors_return_two(self):
        with mock.patch.object(cli.sys, "stderr", io.StringIO()):
            result = cli.main(["serve", "does-not-exist.jsonl"])

        self.assertEqual(result, 2)

    def test_default_cli_path_still_accepts_file_input(self):
        source = Path(__file__).parent / "fixtures" / "runtime.jsonl"
        stdout = io.StringIO()
        with (
            mock.patch.object(cli.sys.stdout, "isatty", return_value=False),
            mock.patch.object(cli.sys, "stdout", stdout),
            mock.patch.object(cli.sys, "stderr", io.StringIO()),
        ):
            result = cli.main([str(source)])

        self.assertEqual(result, 0)
        self.assertIn("AGENT LANES", stdout.getvalue())


def _wait_until(callback, *, timeout: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if callback():
            return True
        time.sleep(0.01)
    return False


def _read_sse_data(response) -> dict[str, object]:
    for _ in range(50):
        line = response.readline().decode("utf-8")
        if line.startswith("data: "):
            return json.loads(line.removeprefix("data: "))
    raise AssertionError("SSE data frame was not received")


if __name__ == "__main__":
    unittest.main()
