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
        root_response = urlopen(base_url + "/", timeout=2)
        runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=2).read())
        detail = json.loads(urlopen(base_url + "/api/v1/runs/trace%2F1", timeout=2).read())
        payload = json.loads(urlopen(base_url + "/api/v1/runs/trace%2F1/events/evt-1/payload", timeout=2).read())

        self.assertIn("Agent Tail", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("Access-Control-Allow-Origin", root_response.headers)
        self.assertIn("textContent", html)
        self.assertIn('data-view="graph"', html)
        self.assertIn('data-view="tree"', html)
        self.assertIn('data-view="swimlane"', html)
        self.assertIn('data-view="sequence"', html)
        self.assertIn('data-action="focus"', html)
        self.assertIn('data-action="clear-focus"', html)
        self.assertIn('data-action="reset"', html)
        self.assertIn('visibleLimit', html)
        self.assertIn("stageEl.addEventListener('wheel'", html)
        self.assertIn('id="playback-toggle"', html)
        self.assertIn('id="scrubber"', html)
        self.assertIn('id="speed"', html)
        self.assertIn('id="jump-live"', html)
        self.assertIn('id="search"', html)
        self.assertIn('id="inspector"', html)
        self.assertIn('id="warnings-drawer"', html)
        self.assertIn('Load retained payload', html)
        self.assertIn('cost_usd', html)
        self.assertIn('detected_at', html)
        self.assertIn("events.addEventListener('heartbeat'", html)
        self.assertIn('renderWarningsDrawer', html)
        self.assertIn('renderSwimlane', html)
        self.assertIn('renderSequence', html)
        self.assertIn('eventsAtHorizon', html)
        self.assertIn("focusedAgentId", html)
        self.assertIn('buildForest', html)
        self.assertIn('Focus subtree', html)
        self.assertEqual(runs["runs"][0]["trace_id"], "trace/1")
        self.assertEqual(detail["events"][0]["event_id"], "evt-1")
        self.assertEqual(payload["event_id"], "evt-1")

        with self.assertRaises(HTTPError) as raised:
            urlopen(base_url + "/api/v1/runs/missing", timeout=2).read()
        self.assertEqual(raised.exception.code, 404)

    def test_remote_token_protects_api_routes(self):
        store = RunStore.from_lines([json.dumps(event_data()) + "\n"])
        server = make_server(store, host="127.0.0.1", port=0)
        server.access_token = "secret-token"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"

        with self.assertRaises(HTTPError) as raised:
            urlopen(base_url + "/api/v1/runs", timeout=2).read()
        authorized = json.loads(
            urlopen(base_url + "/api/v1/runs?token=secret-token", timeout=2).read()
        )

        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(authorized["runs"][0]["trace_id"], "trace-1")

    def test_remote_access_guardrails_reject_unsafe_configurations(self):
        with self.assertRaisesRegex(ValueError, "remote-access"):
            serve(
                io.StringIO(""),
                config=ServeConfig(host="0.0.0.0"),
            )
        with self.assertRaisesRegex(ValueError, "unsafe-unredacted"):
            serve(
                io.StringIO(""),
                config=ServeConfig(remote_access=True, unsafe_unredacted=True),
            )

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

    def test_lazy_payload_detail_retains_sanitized_full_payload(self):
        store = RunStore.from_lines([
            json.dumps(event_data(payload={"text": "x" * 5000, "token": "Bearer hidden"})) + "\n"
        ])

        detail = store.run_detail("trace-1")
        payload = store.event_payload("trace-1", "evt-1")

        self.assertTrue(detail["events"][0]["payload"]["metadata"]["truncated"])
        self.assertFalse(payload["payload"]["metadata"]["truncated"])
        self.assertIn("x" * 100, payload["payload"]["preview"]["text"])
        self.assertNotIn("hidden", json.dumps(payload))

    def test_lazy_payload_detail_respects_payload_eviction(self):
        store = RunStore.from_lines([
            json.dumps(event_data(payload={"text": "x" * 5000})) + "\n"
        ], max_bytes=1000)

        payload = store.event_payload("trace-1", "evt-1")
        encoded = json.dumps(payload)

        self.assertNotIn("x" * 100, encoded)
        self.assertIn("metadata", encoded)

    def test_runtime_warning_history_marks_resolved_warnings(self):
        store = RunStore(source_kind="stdin")
        store.set_source_status(connected=True, state="reading")
        store.feed_line(json.dumps(event_data(
            timestamp="2000-01-01T00:00:00Z",
        )) + "\n")

        active = json.loads(json.dumps(store.run_detail("trace-1")["warnings"]))
        store.set_source_status(connected=False, state="disconnected")
        resolved = store.run_detail("trace-1")["warnings"]

        self.assertTrue(any(warning["code"] == "STALL" and warning["active"] for warning in active))
        self.assertTrue(any(warning["code"] == "STALL" and not warning["active"] for warning in resolved))

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

    def test_projection_includes_agents_links_usage_and_warnings(self):
        lines = [
            json.dumps(event_data(
                actor={"id": "lead", "role": "planner"},
                span_id="lead-span",
                usage={"input_tokens": 10, "cost_usd": 0.25},
            )) + "\n",
            json.dumps(event_data(
                event_id="child-start",
                actor={"id": "worker", "role": "executor"},
                span_id="worker-span",
                parent_span_id="lead-span",
                sequence=2,
                attributes={"model": "model-a"},
                usage={"output_tokens": 4, "total_tokens": 14},
            )) + "\n",
            json.dumps(event_data(
                event_id="handoff",
                actor={"id": "lead"},
                span_id="lead-msg",
                sequence=3,
                kind="message.sent",
                attributes={"to": "worker"},
            )) + "\n",
            json.dumps(event_data(
                event_id="missing-handoff",
                actor={"id": "worker"},
                span_id="worker-msg",
                sequence=4,
                kind="message.sent",
                attributes={"to": "missing-agent"},
            )) + "\n",
            json.dumps(event_data(
                event_id="other-parent",
                actor={"id": "observer"},
                span_id="observer-span",
                sequence=5,
            )) + "\n",
            json.dumps(event_data(
                event_id="ambiguous",
                actor={"id": "worker"},
                span_id="worker-later",
                parent_span_id="observer-span",
                sequence=6,
            )) + "\n",
            json.dumps(event_data(
                event_id="fallback-parent",
                actor={"id": "fallback"},
                span_id="fallback-root",
                emitter_id="fallback-parent-emitter",
                sequence=1,
                timestamp="2026-07-13T11:03:00Z",
                kind="tool.call.progress",
            )) + "\n",
            json.dumps(event_data(
                event_id="uncertain-child",
                actor={"id": "uncertain-worker"},
                span_id="uncertain-child",
                parent_span_id="fallback-root",
                emitter_id="uncertain-child-emitter",
                sequence=1,
                timestamp="2026-07-13T11:02:00Z",
            )) + "\n",
        ]
        store = RunStore.from_lines(lines)

        detail = store.run_detail("trace-1")
        worker = next(actor for actor in detail["actors"] if actor["id"] == "worker")
        uncertain = next(
            event for event in detail["events"]
            if event["event_id"] == "uncertain-child"
        )
        links = {(link["type"], link.get("source_actor_id"), link.get("target_actor_id"), link.get("unresolved_target")) for link in detail["links"]}
        warning_codes = {warning["code"] for warning in detail["warnings"]}

        self.assertEqual(worker["parent_id"], "lead")
        self.assertEqual(worker["role"], "executor")
        self.assertEqual(worker["model"], "model-a")
        self.assertIn(("spawn", "lead", "worker", None), links)
        self.assertIn(("causal", "observer", "worker", None), links)
        self.assertIn(("message", "lead", "worker", None), links)
        self.assertIn(("message", "worker", None, "missing-agent"), links)
        self.assertNotIn(("spawn", "fallback", "uncertain-worker", None), links)
        self.assertEqual(detail["unresolved_endpoints"][0]["id"], "missing-agent")
        self.assertIn("AMBIGUOUS_PARENT", warning_codes)
        self.assertEqual(detail["run"]["warning_count"], len(detail["warnings"]))
        self.assertEqual(detail["usage"]["input_tokens"], {"available": True, "value": 10})
        self.assertEqual(detail["usage"]["output_tokens"], {"available": True, "value": 4})
        self.assertEqual(detail["usage"]["cost_usd"], {"available": True, "value": 0.25})
        self.assertFalse(detail["events"][2]["usage"]["input_tokens"]["available"])
        self.assertEqual(detail["duration_seconds"], 60.0)
        self.assertTrue(uncertain["uncertain"])

    def test_serve_cli_dispatches_without_changing_default_invocation(self):
        with mock.patch.object(cli, "serve", return_value=0) as serve:
            result = cli.main(["serve", "-", "--host", "127.0.0.1", "--port", "0"])

        self.assertEqual(result, 0)
        serve.assert_called_once()
        self.assertEqual(serve.call_args.kwargs["config"].host, "127.0.0.1")
        self.assertEqual(serve.call_args.kwargs["config"].port, 0)

    def test_serve_prints_generated_token_url_and_honors_browser_open(self):
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
            mock.patch("agent_tail.serve.secrets.token_urlsafe", return_value="test-token"),
            mock.patch("sys.stdout", stdout),
        ):
            result = serve(
                io.StringIO(json.dumps(event_data()) + "\n"),
                config=ServeConfig(
                    port=0,
                    open_browser=True,
                    remote_access=True,
                ),
                open_url=opened.append,
            )

        self.assertEqual(result, 0)
        self.assertIn("http://127.0.0.1:43210/?token=test-token", stdout.getvalue())
        self.assertIn("WARNING: remote access is enabled", stdout.getvalue())
        self.assertEqual(opened, ["http://127.0.0.1:43210/?token=test-token"])

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
