import io
import json
from pathlib import Path
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest import mock

from agent_tail import cli
from agent_tail.serve import RunStore, ServeConfig, make_server, serve


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
        self.assertEqual(runs["runs"][0]["trace_id"], "trace/1")
        self.assertEqual(detail["events"][0]["event_id"], "evt-1")

        with self.assertRaises(HTTPError) as raised:
            urlopen(base_url + "/api/v1/runs/missing", timeout=2).read()
        self.assertEqual(raised.exception.code, 404)

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
        ):
            result = cli.main([str(source)])

        self.assertEqual(result, 0)
        self.assertIn("AGENT LANES", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
