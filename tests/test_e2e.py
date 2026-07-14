import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

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
        "actor": {"id": "reviewer-1", "role": "planner"},
        "operation": {"status": "running", "name": "read_file"},
    }
    data.update(changes)
    return data


class ServeEndToEndTests(unittest.TestCase):
    def test_real_serve_command_ui_api_sse_reconnect_and_sanitization(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data(
                payload={"token": "Bearer hidden-secret", "text": "visible"},
            )) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"

            runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=3).read())
            detail = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read())

            self.assertEqual(runs["runs"][0]["state"], "live")
            self.assertEqual(detail["events"][0]["event_id"], "evt-1")
            self.assertNotIn("hidden-secret", json.dumps(detail))
            self.assertEqual(detail["source"]["state"], "caught_up")

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                expect(page.get_by_text("Agent Tail", exact=True)).to_be_visible()
                expect(page.locator(".agent-card")).to_have_count(1)
                self.assertNotIn("hidden-secret", page.content())

                for view in ("Tree", "Swimlane", "Sequence", "Graph"):
                    page.get_by_role("button", name=view, exact=True).click()
                    expect(page.locator("#stage")).to_be_visible()

                page.locator(".agent-card").first.click()
                expect(page.get_by_text("Agent inspector", exact=True)).to_be_visible()
                page.get_by_role("button", name="Timeline", exact=True).click()
                page.locator(".event").first.click()
                expect(page.get_by_text("Event inspector", exact=True)).to_be_visible()
                page.get_by_role("button", name="Load retained payload").click()
                expect(page.locator("#inspector pre")).to_contain_text("visible")
                self.assertNotIn("hidden-secret", page.locator("#inspector").inner_text())

                page.get_by_role("button", name="Warnings", exact=True).click()
                expect(page.locator("#warnings-drawer")).to_be_visible()
                page.locator("#search").fill("evt-1")
                expect(page.locator(".event")).to_have_count(1)
                page.locator("#search").fill("")

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="evt-2",
                        span_id="span-2",
                        sequence=2,
                        actor={"id": "worker-1", "role": "executor"},
                        parent_span_id="span-1",
                        kind="message.sent",
                        attributes={"to": "reviewer-1"},
                    )) + "\n")
                expect(page.locator(".event")).to_have_count(2)
                page.get_by_role("button", name="Sequence", exact=True).click()
                expect(page.locator(".sequence-row")).to_contain_text("worker-1")

                page.locator("#scrubber").evaluate("element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }")
                expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
                context.set_offline(True)
                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="buffered",
                        span_id="span-3",
                        sequence=3,
                        actor={"id": "worker-2"},
                    )) + "\n")
                context.set_offline(False)
                page.wait_for_timeout(1500)
                page.get_by_role("button", name="Jump to live").click()
                page.get_by_role("button", name="Timeline", exact=True).click()
                expect(page.get_by_text("buffered", exact=True)).to_be_visible()

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="done",
                        span_id="span-1",
                        sequence=4,
                        kind="trace.completed",
                        operation={"status": "completed"},
                    )) + "\n")
                expect(page.get_by_text("completed", exact=True).first).to_be_visible()
                browser.close()

            final = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read())

        self.assertEqual(
            [event["event_id"] for event in final["events"]],
            ["evt-1", "evt-2", "buffered", "done"],
        )
        self.assertEqual(final["run"]["state"], "completed")

    def test_non_serve_invocation_still_renders_terminal_snapshot(self):
        line = json.dumps(event_data()) + "\n"
        result = subprocess.run(
            [sys.executable, "-m", "agent_tail", "-"],
            input=line,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("AGENT LANES", result.stdout)
        self.assertIn("event evt-1", result.stdout)

    def test_large_projection_performance_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "large.jsonl")
            lines = []
            for sequence in range(500):
                actor_id = f"agent-{sequence % 100:03d}"
                lines.append(json.dumps(event_data(
                    event_id=f"evt-{sequence}",
                    span_id=f"span-{sequence}",
                    actor={"id": actor_id},
                    sequence=sequence,
                    timestamp=f"2026-07-13T11:{sequence // 60 % 60:02d}:{sequence % 60:02d}Z",
                )) + "\n")
            source.write_text("".join(lines), encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                started = time.perf_counter()
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator(".agent-card")).to_have_count(80, timeout=10_000)
                first_useful_paint = time.perf_counter() - started
                page.get_by_role("button", name="Show more").click()
                expect(page.locator(".agent-card")).to_have_count(100)
                page.get_by_role("button", name="Tree", exact=True).click()
                expect(page.locator(".agent-card")).to_have_count(100)
                browser.close()

        self.assertLess(first_useful_paint, 10.0)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()


def _wait_for_server_line(process: subprocess.Popen[str]) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        line = process.stdout.readline()
        if "Agent Tail serve mode listening" in line:
            return
        if process.poll() is not None:
            raise AssertionError(process.stderr.read())
    raise AssertionError("serve command did not start")


def _read_sse_data(response) -> dict[str, object]:
    for _ in range(50):
        line = response.readline().decode("utf-8")
        if line.startswith("data: "):
            return json.loads(line.removeprefix("data: "))
    raise AssertionError("SSE data frame was not received")


if __name__ == "__main__":
    unittest.main()
