import json
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import venv
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

from tests.performance_fixture import (
    HIGH_BUDGET_BYTES,
    LATE_EVENT_ID,
    TRACE_ID,
    write_fixture,
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
        "actor": {"id": "reviewer-1", "role": "planner"},
        "operation": {"status": "running", "name": "read_file"},
    }
    data.update(changes)
    return data


class ServeEndToEndTests(unittest.TestCase):
    def test_live_outcome_cost_resolves_forward_hunk_and_correction(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "outcome-cost.jsonl")
            source.write_text(json.dumps(event_data(
                event_id="usage-1",
                usage={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12, "cost_usd": 0.5},
                relationships=[{"type": "contributes_to", "event_id": "change-1"}],
            )) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(source),
                    "--port", str(port),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                page.wait_for_function(
                    "currentDetail.outcome_cost.allocation.pending.cost_usd.value === 0.5"
                )
                initial_total = page.evaluate("currentDetail.outcome_cost.totals.cost_usd.value")
                expect(page.locator(".outcome-cost").first).to_contain_text("pending")

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="change-1",
                        span_id="change-1",
                        sequence=2,
                        kind="change.applied",
                        attributes={"change": {
                            "path": "src/live.py",
                            "old_start": 3,
                            "old_count": 1,
                            "new_start": 3,
                            "new_count": 2,
                        }},
                    )) + "\n")

                page.wait_for_function(
                    "currentDetail.outcome_cost.allocation.attributed.cost_usd.value === 0.5"
                )
                page.locator(".node-wrap").filter(has_text="reviewer-1").click()
                page.locator(".event-row").filter(has_text="change.applied").click()
                inspector = page.locator("#inspector")
                expect(inspector).to_contain_text("observed outcome no_correction_observed")
                expect(inspector).to_contain_text("src/live.py:3-4")
                expect(inspector).to_contain_text("0.5000")

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="correction-1",
                        span_id="correction-1",
                        sequence=3,
                        kind="human.corrected",
                        actor={"id": "human"},
                        attributes={"correction": {"action": "modified"}},
                        relationships=[{"type": "corrects", "event_id": "change-1"}],
                    )) + "\n")

                page.wait_for_function(
                    "currentDetail.outcome_cost.by_hunk[0].observed_outcome === 'modified'"
                )
                expect(inspector).to_contain_text("observed outcome modified")
                self.assertEqual(
                    page.evaluate("currentDetail.outcome_cost.totals.cost_usd.value"),
                    initial_total,
                )
                browser.close()

    def test_growing_file_resolves_forward_security_influence_in_inspector(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "security.jsonl")
            source.write_text(json.dumps(event_data(
                event_id="sensitive-operation",
                sequence=2,
                kind="tool.call.started",
                operation={"status": "running", "name": "http_post"},
                attributes={"security": {"capabilities": ["network_egress"]}},
                relationships=[{"type": "influenced_by", "event_id": "web-input"}],
            )) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(source),
                    "--port", str(port),
                ],
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
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                page.locator(".node-wrap").filter(has_text="reviewer-1").click()
                page.locator(".event-row").filter(has_text="http_post").click()
                audit = page.locator(".security-audit")
                expect(audit).to_contain_text("UNRESOLVED_INFLUENCE_TARGET")
                expect(audit).not_to_contain_text("UNTRUSTED_TO_SENSITIVE")

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="web-input",
                        span_id="web-input",
                        emitter_id="web-source",
                        sequence=1,
                        timestamp="2026-07-13T11:02:43.912Z",
                        kind="message.received",
                        actor={"id": "web-source"},
                        operation={"status": "completed", "name": "receive"},
                        attributes={"security": {"trust_origin": "web"}},
                    )) + "\n")

                page.wait_for_function("currentDetail.security.findings.length === 1")
                expect(audit).to_contain_text("UNTRUSTED_TO_SENSITIVE")
                expect(audit).to_contain_text("network_egress")
                expect(audit).to_contain_text("web-input=web (untrusted)")
                expect(audit).to_contain_text("web-input [web] → sensitive-operation [unlabeled]")
                browser.close()

    def test_parallel_coordination_fixture_surfaces_shared_warnings_everywhere(self):
        fixture = Path(__file__).parent / "fixtures" / "parallel-coordination.jsonl"
        port = _free_port()
        process = subprocess.Popen(
            [
                sys.executable, "-m", "agent_tail", "serve", str(fixture),
                "--port", str(port), "--fan-out-threshold", "2",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.addCleanup(_stop_process, process)
        _wait_for_server_line(process)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")

            expect(page.locator(".node-warn").filter(has_text="HIGH_FAN_OUT")).to_have_count(1)
            expect(page.locator(".node-warn").filter(has_text="OVERLAPPING_CHANGE")).to_have_count(1)
            page.get_by_role("button", name="Warnings", exact=True).click()
            drawer = page.locator("#warnings-drawer")
            expect(drawer).to_contain_text("HIGH_FAN_OUT")
            expect(drawer).to_contain_text("OVERLAPPING_CHANGE")
            expect(drawer).to_contain_text('"path":"src/shared.py"')
            expect(drawer).to_contain_text('"causal_order":"unknown"')
            drawer.locator(".warn-card").filter(has_text="OVERLAPPING_CHANGE").click()
            inspector = page.locator("#inspector")
            expect(inspector).to_contain_text("OVERLAPPING_CHANGE")
            expect(inspector).to_contain_text("uncertain")
            expect(inspector).to_contain_text("yes")
            browser.close()

    def test_growing_file_warning_resolves_and_navigates_to_change_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "verification-gaps.jsonl")
            source.write_text(json.dumps(event_data(
                event_id="change-1",
                kind="change.applied",
                attributes={"change": {
                    "path": "src/session.py",
                    "old_start": 8,
                    "old_count": 1,
                    "new_start": 8,
                    "new_count": 2,
                }},
                relationships=[{
                    "type": "verified_by",
                    "event_id": "verification-1",
                }],
            )) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(source),
                    "--port", str(port),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                page.get_by_role("button", name="Warnings", exact=True).click()
                drawer = page.locator("#warnings-drawer")
                expect(drawer).to_contain_text("UNCOVERED_CHANGE")
                expect(drawer).to_contain_text('"change_event_id":"change-1"')
                drawer.locator(".warn-card").filter(has_text="UNCOVERED_CHANGE").click()
                expect(page.locator(".change-evidence")).to_contain_text("src/session.py:8-9")
                expect(page.locator(".change-evidence")).to_contain_text("deterministic")

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="verification-1",
                        span_id="verification-span",
                        sequence=2,
                        kind="verification.finished",
                        operation={"status": "completed", "name": "pytest"},
                        attributes={"verification": {
                            "command": "pytest tests/test_session.py",
                            "passed": True,
                            "exit_code": 0,
                            "test_origin": "pre_existing",
                        }},
                    )) + "\n")

                page.wait_for_function("currentDetail.warnings.some((warning) => warning.code === 'UNCOVERED_CHANGE' && warning.active === false)")
                page.get_by_role("button", name="Warnings", exact=True).click()
                expect(drawer).to_contain_text("resolved")
                drawer.locator(".warn-card").filter(has_text="UNCOVERED_CHANGE").click()
                expect(page.locator(".change-evidence")).to_contain_text("resolved")
                browser.close()

    def test_growing_file_updates_context_provenance_from_unknown_to_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "context-provenance.jsonl")
            source.write_text("".join((
                json.dumps(event_data(
                    event_id="read-1",
                    kind="context.read",
                    attributes={"context": {
                        "path": "src/session.py",
                        "line_start": 8,
                        "content_sha256": "1" * 64,
                    }, "repository": {"commit": "abc123"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-unknown",
                    span_id="change-unknown",
                    sequence=2,
                    kind="change.applied",
                    attributes={"change": {
                        "path": "src/session.py",
                        "old_start": 8,
                        "old_count": 1,
                        "new_start": 8,
                        "new_count": 1,
                    }, "repository": {"commit": "abc123"}},
                    relationships=[{"type": "informed_by", "event_id": "read-1"}],
                )) + "\n",
            )), encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(source),
                    "--port", str(port),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                page.locator(".node-wrap").filter(has_text="reviewer-1").click()
                page.locator(".event-row").filter(has_text="change.applied").click()
                provenance = page.locator(".context-provenance")
                expect(provenance).to_contain_text("preimage sha256 absent · freshness unknown")
                expect(provenance).to_contain_text("snapshot commit abc123")

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="change-stale",
                        span_id="change-stale",
                        sequence=3,
                        timestamp="2026-07-13T11:03:44.912Z",
                        kind="change.applied",
                        attributes={"change": {
                            "path": "src/session.py",
                            "old_start": 8,
                            "old_count": 1,
                            "new_start": 8,
                            "new_count": 2,
                            "preimage_sha256": "2" * 64,
                        }, "repository": {
                            "commit": "abc123", "worktree_sha256": "3" * 64,
                        }},
                        relationships=[{"type": "informed_by", "event_id": "read-1"}],
                    )) + "\n")

                page.locator(".back-btn").click()
                expect(page.locator(".event-row").filter(has_text="change.applied")).to_have_count(2)
                page.locator(".event-row").filter(has_text="change.applied").first.click()
                expect(page.locator(".change-evidence")).to_contain_text("src/session.py:8-9")
                expect(page.locator(".context-provenance")).to_contain_text(
                    "preimage sha256 " + "2" * 64 + " · freshness stale"
                )
                expect(page.locator(".context-provenance")).to_contain_text(
                    "stale read for change change-stale"
                )
                self.assertNotIn("why", page.locator(".context-provenance").inner_text().lower())
                browser.close()

    def test_metadata_only_serve_omits_payload_from_api_sse_lazy_and_browser(self):
        initial_sentinel = "payload-only-browser-sentinel"
        live_sentinel = "payload-only-sse-sentinel"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "metadata-only.jsonl")
            source.write_text(json.dumps(event_data(
                payload={"text": initial_sentinel},
            )) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    "serve",
                    str(source),
                    "--metadata-only",
                    "--port",
                    str(port),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"
            detail = _wait_for_event(base_url, "evt-1")
            lazy_text = urlopen(
                base_url + "/api/v1/runs/trace-1/events/evt-1/payload",
                timeout=3,
            ).read().decode()
            cursor = detail["cursor"]
            response = urlopen(
                base_url + f"/api/v1/events?cursor={cursor}", timeout=3
            )
            with source.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event_data(
                    event_id="evt-2",
                    span_id="span-2",
                    sequence=2,
                    payload={"text": live_sentinel},
                )) + "\n")
            update = _read_sse_data(response)
            response.close()

            self.assertEqual(detail["payload_mode"], "metadata-only")
            self.assertEqual(detail["events"][0]["payload"]["state"], "omitted")
            self.assertNotIn(initial_sentinel, json.dumps(detail) + lazy_text)
            self.assertNotIn(live_sentinel, json.dumps(update))
            self.assertEqual(update["payload"]["state"], "omitted")
            self.assertNotIn("preview", lazy_text)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                expect(page.locator("#inspector")).to_contain_text(
                    "metadata-only · payload bodies omitted"
                )
                page.locator(".node-wrap").filter(has_text="reviewer-1").click()
                page.locator(".event-row").first.click()
                expect(page.locator("#inspector")).to_contain_text(
                    "payload omitted (metadata-only)"
                )
                expect(page.locator(".io-load-btn")).to_have_count(0)
                self.assertNotIn(initial_sentinel, page.content())
                browser.close()

    def test_coding_agent_hostile_fixture_is_sanitized_at_browser_boundary(self):
        fixture = Path(__file__).parent / "fixtures" / "sessions" / "claude-code-hostile.jsonl"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "hostile.jsonl")
            imported = subprocess.run(
                [
                    sys.executable, "-m", "agent_tail", "import", "session",
                    str(fixture), "--output", str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertIn("ghp_", output.read_text(encoding="utf-8"))

            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(output), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"
            runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=3).read())
            detail_text = urlopen(
                base_url + f"/api/v1/runs/{runs['runs'][0]['trace_id']}", timeout=3
            ).read().decode()
            self.assertNotIn("ghp_", detail_text)
            self.assertIn("[REDACTED", detail_text)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                self.assertNotIn("ghp_", page.content())
                expect(page.locator("#message-injected")).to_have_count(0)
                expect(page.locator("#command-injected")).to_have_count(0)
                expect(page.locator("#path-injected")).to_have_count(0)
                expect(page.locator("#error-injected")).to_have_count(0)
                expect(page.locator("#unknown-key-injected")).to_have_count(0)
                browser.close()

    def test_coding_agent_import_process_to_generic_browser_inspectors(self):
        fixture = Path(__file__).parent / "fixtures" / "sessions" / "claude-code-multi.jsonl"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "imported.jsonl")
            imported = subprocess.run(
                [
                    sys.executable, "-m", "agent_tail", "import", "session",
                    str(fixture), "--source", "auto", "--output", str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)

            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(output), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"
            runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=3).read())
            detail = json.loads(urlopen(
                base_url + f"/api/v1/runs/{runs['runs'][0]['trace_id']}", timeout=3
            ).read())
            self.assertEqual(len(detail["evidence_map"]["changes"]), 1)
            self.assertEqual(
                {event["kind"] for event in detail["events"]},
                {
                    "agent.started", "agent.finished", "context.read",
                    "tool.call.started", "change.applied",
                    "verification.started", "verification.finished",
                },
            )

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                expect(page.locator(".node-wrap").filter(has_text="claude-code:worker-1")).to_be_visible()
                expect(page.locator(".node-wrap").filter(has_text="claude-code:tester")).to_be_visible()
                page.locator(".node-wrap").filter(has_text="claude-code:worker-1").click()
                expect(page.locator("#inspector")).to_contain_text("context.read")
                expect(page.locator("#inspector")).to_contain_text("tool.call")
                page.evaluate("""() => {
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('change.applied')).click();
                }""")
                evidence = page.locator(".change-evidence")
                expect(evidence).to_contain_text("src/parser.py:4-6")
                expect(evidence).to_contain_text("pytest tests/test_parser.py")
                expect(evidence).to_contain_text("PASS")
                browser.close()

    def test_langgraph_adapter_process_to_browser_change_and_failure_journey(self):
        if importlib.util.find_spec("langgraph") is None:
            self.skipTest("LangGraph extra is not installed")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "langgraph.jsonl")
            producer = """
import sys
from uuid import UUID
from agent_tail import AgentTailCallbackHandler
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

output = sys.argv[1]
root = UUID(int=700)
class State(TypedDict):
    value: int

def failing_node(state):
    context_id = callback.emit_context_read(
        run_id=root,
        evidence_id="browser-context",
        path="src/browser.py",
        line_start=5,
        line_end=8,
    )
    verification_id = callback.event_id(
        root, "verification.finished", "browser-verification-finished"
    )
    callback.emit_change_applied(
        run_id=root,
        evidence_id="browser-change",
        path="src/browser.py",
        old_start=5,
        old_count=2,
        new_start=5,
        new_count=3,
        relationships=[
            {"type": "informed_by", "event_id": context_id},
            {"type": "verified_by", "event_id": verification_id},
        ],
    )
    start_id = callback.emit_verification_started(
        run_id=root,
        evidence_id="browser-verification-started",
        command="pytest tests/test_browser.py",
        test_origin="pre_existing",
    )
    callback.emit_verification_finished(
        run_id=root,
        evidence_id="browser-verification-finished",
        passed=True,
        start_event_id=start_id,
        exit_code=0,
        test_origin="pre_existing",
    )
    raise RuntimeError("Bearer browser-boundary-secret")

builder = StateGraph(State)
builder.add_node("failing-node", failing_node)
builder.add_edge(START, "failing-node")
builder.add_edge("failing-node", END)
graph = builder.compile()
with AgentTailCallbackHandler(output) as callback:
    try:
        graph.invoke(
            {"value": 1},
            {"callbacks": [callback], "run_id": root},
        )
    except RuntimeError:
        pass
"""
            produced = subprocess.run(
                [sys.executable, "-c", producer, str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(produced.returncode, 0, produced.stderr)
            self.assertIn("browser-boundary-secret", source.read_text(encoding="utf-8"))

            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    "serve",
                    str(source),
                    "--port",
                    str(port),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"
            runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=3).read())
            trace_id = runs["runs"][0]["trace_id"]
            detail = json.loads(
                urlopen(base_url + f"/api/v1/runs/{trace_id}", timeout=3).read()
            )
            self.assertNotIn("browser-boundary-secret", json.dumps(detail))
            self.assertIn("[REDACTED]", json.dumps(detail))
            self.assertEqual(len(detail["evidence_map"]["changes"]), 1)
            failed_event = next(
                event
                for event in detail["events"]
                if event["kind"] == "agent.failed"
                and event["operation"]["name"] == "failing-node"
            )
            change_event = next(
                event for event in detail["events"]
                if event["kind"] == "change.applied"
            )
            self.assertEqual(
                next(
                    actor["status"]
                    for actor in detail["actors"]
                    if actor["id"] == failed_event["actor"]["id"]
                ),
                "failed",
            )

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                expect(page.locator(".node-wrap")).to_have_count(2)
                self.assertNotIn("browser-boundary-secret", page.content())
                page.locator(".node-wrap").filter(
                    has_text=failed_event["actor"]["id"]
                ).click()
                expect(page.locator("#inspector")).to_contain_text("error")
                page.locator(".node-wrap").filter(
                    has_text=change_event["actor"]["id"]
                ).click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('change.applied')).click();
                }""")
                evidence = page.locator(".change-evidence")
                expect(evidence).to_contain_text("CHANGE EVIDENCE")
                expect(evidence).to_contain_text("src/browser.py:5-7")
                expect(evidence).to_contain_text("pytest tests/test_browser.py")
                browser.close()

    def test_change_inspector_shows_evidence_and_human_corrections_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "change-evidence.jsonl")
            source.write_text("".join((
                json.dumps(event_data(
                    event_id="requirement-1",
                    kind="requirement.observed",
                    actor={"id": "user"},
                    attributes={"requirement": {
                        "id": "R3",
                        "text": "Expired sessions must be rejected. <img id=evidence-injected src=x>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="requirement-unknown-actor",
                    span_id="span-requirement-unknown-actor",
                    kind="requirement.observed",
                    actor={"id": " \t"},
                    attributes={"requirement": {
                        "id": "R4",
                        "text": "Requirement with an unknown observer.",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="requirement-after-change",
                    emitter_id="requirements",
                    span_id="span-requirement-after-change",
                    timestamp="2026-07-13T11:03:00Z",
                    kind="requirement.observed",
                    actor={"id": "late-observer"},
                    attributes={"requirement": {
                        "id": "R-late",
                        "text": "Requirement observed after implementation.",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-1",
                    span_id="span-2",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "researcher-1"},
                    attributes={"context": {
                        "path": "docs/session-lifecycle.md<img id=context-injected>",
                        "line_start": 42,
                        "line_end": 47,
                        "symbol": "Session expiry<img id=context-symbol-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-end-only",
                    span_id="span-context-end-only",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "researcher-2"},
                    attributes={"context": {
                        "path": "docs/session-retention.md",
                        "line_end": 51,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-unknown-actor",
                    span_id="span-context-unknown-actor",
                    sequence=2,
                    timestamp="2026-07-13T11:02:44.911Z",
                    kind="context.read",
                    actor={"id": " \t"},
                    attributes={"context": {
                        "path": "docs/anonymous-research.md",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-after-change",
                    span_id="span-context-after-change",
                    sequence=10,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="context.read",
                    actor={"id": "late-researcher"},
                    attributes={"context": {
                        "path": "docs/post-implementation.md",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-after-compaction",
                    span_id="span-context-after-compaction",
                    sequence=8,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="context.read",
                    actor={"id": "late-source-researcher"},
                    attributes={"context": {
                        "path": "docs/read-after-summary.md",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-invalid-line-start",
                    span_id="span-context-invalid-line-start",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "invalid-line-researcher"},
                    attributes={"context": {
                        "path": "docs/invalid-line.md",
                        "line_start": "<img id=invalid-context-line-start-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-invalid-line-end",
                    span_id="span-context-invalid-line-end",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "invalid-line-end-researcher"},
                    attributes={"context": {
                        "path": "docs/invalid-line-end.md",
                        "line_start": 42,
                        "line_end": "<img id=invalid-context-line-end-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-invalid-symbol",
                    span_id="span-context-invalid-symbol",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "invalid-symbol-researcher"},
                    attributes={"context": {
                        "path": "docs/invalid-symbol.md",
                        "symbol": ["<img id=invalid-context-symbol-injected>"],
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-1",
                    span_id="span-3",
                    sequence=3,
                    kind="verification.started",
                    actor={"id": "test-runner-1<img id=verification-starter-injected>"},
                    attributes={"verification": {}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-conflict",
                    span_id="span-verification-started-conflict",
                    sequence=3,
                    kind="verification.started",
                    actor={"id": "conflicting-test-runner"},
                    attributes={"verification": {
                        "command": "pytest tests/test_other_session.py<img id=verification-conflict-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-after-finish",
                    emitter_id="late-test-worker",
                    span_id="span-verification-started-after-finish",
                    sequence=3,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="verification.started",
                    actor={"id": "late-test-runner"},
                    attributes={"verification": {
                        "command": "pytest tests/test_session.py<img id=verification-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-before-change",
                    emitter_id="premature-test-worker",
                    span_id="span-verification-started-before-change",
                    sequence=3,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="verification.started",
                    actor={"id": "premature-test-runner"},
                    attributes={"verification": {
                        "command": "pytest tests/test_session.py<img id=verification-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-1",
                    span_id="span-verification-finished",
                    sequence=4,
                    kind="verification.finished",
                    actor={"id": "result-reporter-1"},
                    attributes={"verification": {
                        "command": "pytest tests/test_session.py<img id=verification-injected>",
                        "passed": True,
                        "exit_code": 0,
                        "test_origin": "same_agent",
                    }},
                    relationships=[
                        {
                            "type": "completes",
                            "event_id": "verification-started-1",
                        },
                        {
                            "type": "completes",
                            "event_id": "verification-started-conflict",
                        },
                        {
                            "type": "completes",
                            "event_id": "verification-started-after-finish",
                        },
                        {
                            "type": "completes",
                            "event_id": "verification-started-before-change",
                        },
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-2",
                    span_id="span-verification-missing",
                    sequence=5,
                    kind="verification.finished",
                    actor={"id": "result-reporter-2"},
                    attributes={"verification": {"passed": False}},
                    relationships=[
                        {
                            "type": "completes",
                            "event_id": "missing-start<img id=verification-missing-injected>",
                        },
                        {
                            "type": "completes",
                            "event_id": "context-1",
                        },
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-before-change",
                    span_id="span-verification-before-change",
                    sequence=5,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="verification.finished",
                    actor={"id": "early-result-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_too_early.py",
                        "passed": True,
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-1",
                    span_id="span-compaction",
                    sequence=6,
                    kind="context.compacted",
                    actor={"id": "summarizer-1"},
                    relationships=[
                        {"type": "summarizes", "event_id": "context-1"},
                        {"type": "summarizes", "event_id": "context-end-only"},
                        {"type": "summarizes", "event_id": "context-invalid-line-start"},
                        {"type": "summarizes", "event_id": "context-invalid-line-end"},
                        {"type": "summarizes", "event_id": "context-invalid-symbol"},
                        {"type": "summarizes", "event_id": "context-after-compaction"},
                        {"type": "summarizes", "event_id": "context-invalid-detail<img id=invalid-context-injected>"},
                        {"type": "summarizes", "event_id": "missing-context<img id=compaction-missing-injected>"},
                        {"type": "summarizes", "event_id": "tool-1"},
                        {"type": "references", "event_id": "unrelated-context"},
                        {"type": "references", "event_id": "irrelevant-missing-context"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-unknown-actor",
                    span_id="span-compaction-unknown-actor",
                    emitter_id="unknown-compaction-worker",
                    sequence=1,
                    timestamp="2026-07-13T11:02:44.911Z",
                    kind="context.compacted",
                    actor={"id": " \t"},
                    relationships=[
                        {"type": "summarizes", "event_id": "context-unknown-actor"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="empty-compaction<img id=invalid-compaction-injected>",
                    span_id="span-empty-compaction",
                    sequence=6,
                    kind="context.compacted",
                    actor={"id": "empty-summarizer"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-after-change",
                    span_id="span-compaction-after-change",
                    sequence=10,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="context.compacted",
                    actor={"id": "late-summarizer"},
                    relationships=[
                        {"type": "summarizes", "event_id": "context-1"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-1",
                    span_id="span-4",
                    sequence=7,
                    kind="tool.call.completed",
                    actor={"id": "shell-1"},
                    operation={"status": " \t", "name": "shell"},
                    attributes={"tool": {
                        "command": "git diff -- src/auth/session.py<img id=tool-command-injected>",
                        "result": "1 file changed<img id=tool-result-injected>",
                        "exit_code": 0,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-unknown-actor",
                    span_id="span-tool-unknown-actor",
                    emitter_id="unknown-tool-worker",
                    sequence=1,
                    timestamp="2026-07-13T11:02:44.911Z",
                    kind="tool.call.completed",
                    actor={"id": " \t"},
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "git status --short",
                        "result": "clean",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-detail<img id=invalid-tool-injected>",
                    span_id="span-tool-invalid-detail",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {"command": " \t", "result": 42}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-exit-code",
                    span_id="span-tool-invalid-exit-code",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "git diff --check",
                        "exit_code": "<img id=invalid-tool-exit-code-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-operation-name",
                    span_id="span-tool-invalid-operation-name",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={
                        "status": "ok",
                        "name": ["<img id=invalid-tool-operation-name-injected>"],
                    },
                    attributes={"tool": {"command": "git status --porcelain"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-command",
                    span_id="span-tool-invalid-command",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": " \t",
                        "result": "working tree clean",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-result",
                    span_id="span-tool-invalid-result",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "git status --ignored",
                        "result": ["<img id=invalid-tool-result-injected>"],
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-after-change",
                    span_id="span-tool-after-change",
                    sequence=10,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {"command": "git diff --stat"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="proposal-1",
                    span_id="span-proposal",
                    sequence=100,
                    timestamp="2026-07-13T11:02:44.911Z",
                    kind="change.proposed",
                    actor={"id": "planner-1<img id=proposal-injected>"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="anonymous-proposal",
                    span_id="span-anonymous-proposal",
                    emitter_id="change-worker",
                    sequence=8,
                    kind="change.proposed",
                    actor={"id": " \t"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="proposal-after-change",
                    span_id="span-proposal-after-change",
                    sequence=10,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="change.proposed",
                    actor={"id": "late-planner"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-1",
                    span_id="span-5",
                    emitter_id="change-worker",
                    sequence=9,
                    kind="change.applied",
                    actor={"id": "implementer-1"},
                    attributes={"change": {
                        "path": "src/auth/session.py",
                        "old_start": 84,
                        "old_count": 18,
                        "new_start": 84,
                        "new_count": 19,
                        "symbol": "reject_expired_session<img id=hunk-symbol-injected>",
                    }},
                    relationships=[
                        {"type": "applies", "event_id": "proposal-1"},
                        {"type": "applies", "event_id": "anonymous-proposal"},
                        {"type": "applies", "event_id": "proposal-after-change"},
                        {"type": "references", "event_id": "unrelated-proposal"},
                        {"type": "motivated_by", "event_id": "requirement-1"},
                        {"type": "motivated_by", "event_id": "requirement-unknown-actor"},
                        {"type": "motivated_by", "event_id": "requirement-after-change"},
                        {"type": "motivated_by", "event_id": "requirement-invalid-detail"},
                        {"type": "references", "event_id": "unrelated-requirement"},
                        {"type": "informed_by", "event_id": "context-1"},
                        {"type": "informed_by", "event_id": "context-end-only"},
                        {"type": "informed_by", "event_id": "context-unknown-actor"},
                        {"type": "informed_by", "event_id": "context-after-change"},
                        {"type": "informed_by", "event_id": "context-invalid-line-start"},
                        {"type": "informed_by", "event_id": "context-invalid-line-end"},
                        {"type": "informed_by", "event_id": "context-invalid-symbol"},
                        {"type": "informed_by", "event_id": "context-invalid-detail<img id=invalid-context-injected>"},
                        {"type": "references", "event_id": "unrelated-context"},
                        {"type": "informed_by", "event_id": "compaction-1"},
                        {"type": "informed_by", "event_id": "compaction-unknown-actor"},
                        {"type": "informed_by", "event_id": "empty-compaction<img id=invalid-compaction-injected>"},
                        {"type": "informed_by", "event_id": "compaction-after-change"},
                        {"type": "preceded_by", "event_id": "tool-1"},
                        {"type": "preceded_by", "event_id": "tool-unknown-actor"},
                        {"type": "preceded_by", "event_id": "tool-invalid-detail<img id=invalid-tool-injected>"},
                        {"type": "preceded_by", "event_id": "tool-invalid-exit-code"},
                        {"type": "preceded_by", "event_id": "tool-invalid-operation-name"},
                        {"type": "preceded_by", "event_id": "tool-invalid-command"},
                        {"type": "preceded_by", "event_id": "tool-invalid-result"},
                        {"type": "preceded_by", "event_id": "tool-after-change"},
                        {"type": "references", "event_id": "unrelated-tool"},
                        {"type": "verified_by", "event_id": "verification-1"},
                        {"type": "verified_by", "event_id": "verification-1"},
                        {"type": "verified_by", "event_id": "verification-2"},
                        {"type": "verified_by", "event_id": "verification-before-change"},
                        {"type": "verified_by", "event_id": "verification-outcome-only"},
                        {"type": "verified_by", "event_id": "verification-unknown-actors"},
                        {"type": "verified_by", "event_id": "verification-invalid-result"},
                        {"type": "verified_by", "event_id": "verification-conflicting-outcome"},
                        {"type": "verified_by", "event_id": "verification-invalid-exit-code"},
                        {"type": "verified_by", "event_id": "verification-invalid-test-origin"},
                        {"type": "verified_by", "event_id": "context-1"},
                        {"type": "references", "event_id": "unrelated-verification"},
                        {"type": "reviewed_by", "event_id": "missing-review<img id=evidence-missing-injected>"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-1",
                    span_id="span-6",
                    sequence=10,
                    kind="human.corrected",
                    actor={"id": "maintainer-1<img id=correction-injected>"},
                    attributes={"correction": {"action": "modified"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-2",
                    span_id="span-7",
                    sequence=11,
                    kind="human.corrected",
                    actor={"id": "maintainer-2"},
                    attributes={"correction": {"action": "reverted"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-unknown-actor",
                    span_id="span-correction-unknown-actor",
                    emitter_id="unknown-correction-worker",
                    sequence=1,
                    kind="human.corrected",
                    actor={"id": " \t"},
                    attributes={"correction": {"action": "modified"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-invalid-detail",
                    span_id="span-correction-invalid-detail",
                    emitter_id="invalid-correction-detail-worker",
                    sequence=1,
                    kind="human.corrected",
                    actor={"id": "maintainer-invalid-detail"},
                    attributes={"correction": {"action": "edited"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-before-change",
                    span_id="span-correction-before-change",
                    emitter_id="early-correction-worker",
                    sequence=1,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="human.corrected",
                    actor={"id": "early-maintainer"},
                    attributes={"correction": {"action": "modified"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-undetermined",
                    span_id="span-correction-undetermined",
                    emitter_id="concurrent-correction-worker",
                    timestamp="2026-07-13T11:02:44.912Z",
                    kind="human.corrected",
                    actor={"id": "concurrent-maintainer"},
                    attributes={"correction": {"action": "modified"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-proposal",
                    span_id="span-unrelated-proposal",
                    sequence=12,
                    kind="change.proposed",
                    actor={"id": "unrelated-planner<img id=unrelated-proposal-injected>"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-requirement",
                    span_id="span-unrelated-requirement",
                    sequence=13,
                    kind="requirement.observed",
                    actor={"id": "unrelated-user"},
                    attributes={"requirement": {
                        "id": "R-unrelated",
                        "text": "Unrelated requirement <img id=unrelated-requirement-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-context",
                    span_id="span-unrelated-context",
                    sequence=14,
                    kind="context.read",
                    actor={"id": "unrelated-researcher"},
                    attributes={"context": {
                        "path": "docs/unrelated.md<img id=unrelated-context-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-tool",
                    span_id="span-unrelated-tool",
                    sequence=15,
                    kind="tool.call.completed",
                    actor={"id": "unrelated-shell"},
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "rm unrelated.tmp<img id=unrelated-tool-injected>",
                        "result": "unrelated result",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-verification",
                    span_id="span-unrelated-verification",
                    sequence=16,
                    kind="verification.finished",
                    actor={"id": "unrelated-reporter<img id=unrelated-verification-reporter-injected>"},
                    attributes={"verification": {
                        "command": "pytest unrelated_test.py<img id=unrelated-verification-injected>",
                        "passed": False,
                    }},
                    relationships=[{
                        "type": "completes",
                        "event_id": "unrelated-missing-start",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-correction",
                    span_id="span-unrelated-correction",
                    sequence=17,
                    kind="human.corrected",
                    actor={"id": "unrelated-maintainer<img id=unrelated-correction-injected>"},
                    attributes={"correction": {"action": "reverted"}},
                    relationships=[{"type": "references", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-outcome-only",
                    span_id="span-verification-outcome-only",
                    sequence=18,
                    kind="verification.finished",
                    actor={"id": "outcome-only-reporter"},
                    attributes={"verification": {
                        "passed": False,
                        "exit_code": 2,
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="invalid-correction",
                    span_id="span-invalid-correction",
                    sequence=19,
                    kind="human.corrected",
                    actor={"id": "invalid-maintainer"},
                    relationships=[{
                        "type": "corrects",
                        "event_id": "context-1<img id=invalid-correction-target-injected>",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-1<img id=invalid-correction-target-injected>",
                    span_id="span-invalid-correction-target",
                    sequence=20,
                    kind="context.read",
                    actor={"id": "invalid-correction-target"},
                    attributes={"context": {"path": "docs/not-a-change.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-unknown-actor",
                    span_id="span-verification-started-unknown-actor",
                    sequence=21,
                    kind="verification.started",
                    actor={"id": " \t"},
                    attributes={"verification": {
                        "command": "pytest tests/test_anonymous_verifier.py",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-unknown-actors",
                    span_id="span-verification-unknown-actors",
                    sequence=22,
                    kind="verification.finished",
                    actor={"id": " \t"},
                    attributes={"verification": {
                        "passed": True,
                        "test_origin": "pre_existing",
                    }},
                    relationships=[{
                        "type": "completes",
                        "event_id": "verification-started-unknown-actor",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="anonymous-change",
                    span_id="span-anonymous-change",
                    emitter_id="anonymous-change-worker",
                    sequence=1,
                    kind="change.applied",
                    actor={"id": " \t"},
                    attributes={"change": {
                        "path": "src/anonymous.py",
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 1,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="deletion-change",
                    span_id="span-deletion-change",
                    emitter_id="deletion-change-worker",
                    sequence=1,
                    kind="change.applied",
                    actor={"id": "deletion-implementer"},
                    attributes={"change": {
                        "path": "src/obsolete.py",
                        "old_start": 12,
                        "old_count": 3,
                        "new_start": 11,
                        "new_count": 0,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-invalid-result",
                    span_id="span-verification-invalid-result",
                    sequence=23,
                    kind="verification.finished",
                    actor={"id": "invalid-result-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_invalid_result.py",
                        "passed": "yes",
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="requirement-invalid-detail",
                    span_id="span-requirement-invalid-detail",
                    emitter_id="invalid-requirement-worker",
                    sequence=24,
                    timestamp="2026-07-13T11:02:44.911Z",
                    kind="requirement.observed",
                    attributes={"requirement": {
                        "id": "R-BAD<img id=invalid-requirement-injected>",
                        "text": " \t",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-invalid-detail<img id=invalid-context-injected>",
                    span_id="span-context-invalid-detail",
                    emitter_id="invalid-context-worker",
                    sequence=25,
                    timestamp="2026-07-13T11:02:44.911Z",
                    kind="context.read",
                    attributes={"context": {"path": " \t"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-conflicting-outcome",
                    span_id="span-verification-conflicting-outcome",
                    sequence=26,
                    kind="verification.finished",
                    actor={"id": "conflicting-outcome-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_conflicting_outcome.py",
                        "passed": True,
                        "exit_code": 7,
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-invalid-exit-code",
                    span_id="span-verification-invalid-exit-code",
                    sequence=27,
                    kind="verification.finished",
                    actor={"id": "invalid-exit-code-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_invalid_exit_code.py",
                        "passed": True,
                        "exit_code": "<img id=invalid-exit-code-injected>",
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-invalid-test-origin",
                    span_id="span-verification-invalid-test-origin",
                    sequence=28,
                    kind="verification.finished",
                    actor={"id": "invalid-test-origin-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_invalid_test_origin.py",
                        "passed": True,
                        "exit_code": 0,
                        "test_origin": "generated<img id=invalid-test-origin-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-invalid-symbol",
                    span_id="span-change-invalid-symbol",
                    sequence=29,
                    kind="change.applied",
                    actor={"id": "implementer-1"},
                    attributes={"change": {
                        "path": "src/auth/invalid-symbol.py",
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 1,
                        "symbol": ["<img id=invalid-change-symbol-injected>"],
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-invalid-detail",
                    span_id="span-change-invalid-detail",
                    emitter_id="invalid-change-worker",
                    sequence=1,
                    kind="change.applied",
                    actor={"id": "invalid-change-producer<img id=invalid-change-actor-injected>"},
                )) + "\n",
            )), encoding="utf-8")
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
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator(".node-wrap").filter(has_text="implementer-1")).to_be_visible()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('implementer-1')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('span-5')).click();
                }""")

                evidence = page.locator(".change-evidence")
                expect(evidence).to_contain_text("CHANGE EVIDENCE")
                expect(evidence).to_contain_text("src/auth/session.py:84-102")
                expect(evidence).to_contain_text("@@ -84,18 +84,19 @@")
                expect(evidence).to_contain_text("symbol reject_expired_session")
                expect(evidence).to_contain_text("implementer-1")
                expect(evidence).to_contain_text("event change-1")
                expect(evidence).to_contain_text("Change proposed")
                expect(evidence.locator(".proposal-card")).to_have_count(3)
                named_proposal = evidence.locator(".proposal-card").filter(
                    has_text="proposed by planner-1"
                )
                expect(named_proposal).to_contain_text("event proposal-1")
                anonymous_proposal = evidence.locator(".proposal-card").filter(
                    has_text="proposing actor unknown"
                )
                expect(anonymous_proposal).to_have_count(1)
                expect(anonymous_proposal).to_contain_text("event anonymous-proposal")
                expect(anonymous_proposal).not_to_contain_text("proposed by")
                invalid_decision = evidence.locator(".unresolved-evidence").filter(
                    has_text="anonymous-proposal"
                )
                expect(invalid_decision).to_contain_text("Invalid decision actor · applies")
                expect(invalid_decision).to_contain_text("change.proposed")
                late_proposal = evidence.locator(".proposal-card").filter(
                    has_text="proposed by late-planner"
                )
                expect(late_proposal).to_contain_text("event proposal-after-change")
                late_proposal_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="proposal-after-change"
                )
                expect(late_proposal_diagnostic).to_contain_text(
                    "Change proposed after application · applies"
                )
                expect(late_proposal_diagnostic).to_contain_text("change.proposed")
                expect(evidence).not_to_contain_text("unrelated-planner")
                requirement = evidence.locator(".requirement-card").filter(has_text="R3")
                expect(requirement).to_contain_text("event requirement-1")
                expect(requirement).to_contain_text("observed by user")
                expect(requirement).to_contain_text("Expired sessions must be rejected.")
                anonymous_requirement = evidence.locator(".requirement-card").filter(has_text="R4")
                expect(anonymous_requirement).to_contain_text("event requirement-unknown-actor")
                expect(anonymous_requirement).to_contain_text("observing actor unknown")
                expect(anonymous_requirement).not_to_contain_text("observed by")
                late_requirement = evidence.locator(".requirement-card").filter(has_text="R-late")
                expect(late_requirement).to_contain_text("Requirement observed after implementation.")
                late_requirement_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="requirement-after-change"
                )
                expect(late_requirement_diagnostic).to_contain_text(
                    "Requirement observed after change · motivated_by"
                )
                expect(late_requirement_diagnostic).to_contain_text("requirement.observed")
                expect(evidence).not_to_contain_text("R-unrelated")
                expect(evidence).not_to_contain_text("Unrelated requirement")
                direct_context = evidence.locator(".context-card").filter(has_text="docs/session-lifecycle.md")
                expect(direct_context).to_contain_text("event context-1")
                expect(direct_context).to_contain_text(":42-47")
                expect(direct_context).to_contain_text("researcher-1")
                expect(direct_context).to_contain_text("Session expiry")
                end_only_context = evidence.locator(".context-card").filter(has_text="docs/session-retention.md")
                expect(end_only_context.locator(".path")).to_have_text("docs/session-retention.md:?-51")
                expect(end_only_context).to_contain_text("researcher-2")
                unknown_context_actor = evidence.locator(".context-card").filter(has_text="docs/anonymous-research.md")
                expect(unknown_context_actor).to_contain_text("reading actor unknown")
                expect(unknown_context_actor).not_to_contain_text("read by")
                late_context = evidence.locator(".context-card").filter(has_text="docs/post-implementation.md")
                expect(late_context).to_contain_text("event context-after-change")
                expect(late_context).to_contain_text("read by late-researcher")
                late_context_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-after-change"
                )
                expect(late_context_diagnostic).to_contain_text(
                    "Context read after change · informed_by"
                )
                expect(late_context_diagnostic).to_contain_text("context.read")
                expect(evidence).not_to_contain_text("docs/unrelated.md")
                expect(evidence).not_to_contain_text("unrelated-researcher")
                expect(evidence).to_contain_text("Context compacted before decision")
                expect(evidence).to_contain_text("compacted by summarizer-1")
                compaction = evidence.locator(".compaction-card").filter(has_text="summarizer-1")
                expect(compaction).to_contain_text("event compaction-1")
                expect(compaction).to_contain_text("source from researcher-1")
                expect(compaction).to_contain_text("event context-1")
                expect(compaction).to_contain_text("Session expiry")
                expect(compaction.locator(".source").filter(has_text="docs/session-retention.md")).to_have_text("docs/session-retention.md:?-51")
                expect(compaction).to_contain_text("source from researcher-2")
                expect(compaction).to_contain_text("event context-end-only")
                expect(compaction).to_contain_text("docs/read-after-summary.md")
                expect(compaction).to_contain_text("source from late-source-researcher")
                expect(compaction).to_contain_text(
                    "Context read after compaction · context-after-compaction · context.read"
                )
                expect(evidence).to_contain_text("Missing summarizes source")
                expect(evidence).to_contain_text("missing-context")
                expect(compaction).to_contain_text("Invalid summarizes source target · tool-1 · tool.call.completed")
                expect(compaction).not_to_contain_text("source from shell-1")
                expect(evidence).not_to_contain_text("irrelevant-missing-context")
                expect(evidence).to_contain_text("7 compacted sources unresolved")
                unknown_compaction_actor = evidence.locator(".compaction-card").filter(has_text="docs/anonymous-research.md")
                expect(unknown_compaction_actor).to_contain_text("compacting actor unknown")
                expect(unknown_compaction_actor).not_to_contain_text("compacted by")
                expect(unknown_compaction_actor).to_contain_text("source actor unknown")
                expect(unknown_compaction_actor).not_to_contain_text("source from")
                late_compaction = evidence.locator(".compaction-card").filter(has_text="late-summarizer")
                expect(late_compaction).to_contain_text("Context compacted after change")
                expect(late_compaction).to_contain_text("event compaction-after-change")
                late_compaction_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="compaction-after-change"
                )
                expect(late_compaction_diagnostic).to_contain_text(
                    "Context compacted after change · informed_by"
                )
                expect(late_compaction_diagnostic).to_contain_text("context.compacted")
                tool = evidence.locator(".tool-card").filter(has_text="git diff -- src/auth/session.py")
                expect(tool).to_contain_text("Tool · shell")
                expect(tool).to_contain_text("1 file changed")
                expect(tool).to_contain_text("event tool-1 · run by shell-1 · exit 0")
                unknown_tool_actor = evidence.locator(".tool-card").filter(has_text="git status --short")
                expect(unknown_tool_actor).to_contain_text("running actor unknown · ok")
                expect(unknown_tool_actor).not_to_contain_text("run by")
                expect(evidence).not_to_contain_text("undefined")
                expect(evidence).not_to_contain_text("rm unrelated.tmp")
                expect(evidence).not_to_contain_text("unrelated result")
                expect(evidence).not_to_contain_text("unrelated-shell")
                expect(evidence).to_contain_text("PASS")
                expect(evidence).to_contain_text("pytest tests/test_session.py")
                expect(evidence).to_contain_text("started by test-runner-1")
                expect(evidence).to_contain_text("result reported by result-reporter-1")
                expect(evidence).to_contain_text("Invalid completes start command · verification-started-1 · verification.started")
                expect(evidence).to_contain_text("Conflicting completes start command · verification-started-conflict · verification.started")
                expect(evidence).to_contain_text("Verification start occurred after finish · verification-started-after-finish · verification.started")
                expect(evidence).to_contain_text("Verification started before change · verification-started-before-change · verification.started")
                early_verification = evidence.locator(".verification-card").filter(has_text="early-result-reporter")
                expect(early_verification).to_contain_text("pytest tests/test_too_early.py")
                early_verification_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-before-change"
                )
                expect(early_verification_diagnostic).to_contain_text(
                    "Verification finished before change · verified_by"
                )
                expect(early_verification_diagnostic).to_contain_text("verification.finished")
                expect(evidence).to_contain_text("Verification command · pytest tests/test_session.py")
                verification = evidence.locator(".verification-card").filter(has_text="result-reporter-1")
                expect(verification).to_have_count(1)
                expect(verification).to_contain_text("event verification-started-1 · started by test-runner-1")
                expect(verification).to_contain_text("event verification-1 · result reported by result-reporter-1")
                expect(evidence).to_contain_text("exit 0")
                expect(evidence).to_contain_text("implementation and test written by the same agent")
                expect(evidence).to_contain_text("FAIL")
                expect(evidence).to_contain_text("result reported by result-reporter-2")
                expect(evidence).to_contain_text("Missing completes start")
                expect(evidence).to_contain_text("missing-start")
                expect(evidence).to_contain_text("Invalid completes start target · context-1 · context.read")
                expect(evidence).to_contain_text("Test provenance unknown")
                outcome_only = evidence.locator(".verification-card").filter(has_text="outcome-only-reporter")
                expect(outcome_only).to_contain_text("FAIL")
                expect(outcome_only).to_contain_text("exit 2")
                expect(outcome_only).to_contain_text("Test existed before this change")
                unknown_verification_actors = evidence.locator(".verification-card").filter(has_text="test_anonymous_verifier.py")
                expect(unknown_verification_actors).to_contain_text(
                    "event verification-started-unknown-actor · starting actor unknown"
                )
                expect(unknown_verification_actors).to_contain_text("reporting actor unknown")
                expect(unknown_verification_actors).not_to_contain_text("started by")
                expect(unknown_verification_actors).not_to_contain_text("result reported by")
                expect(evidence).not_to_contain_text("undefined")
                expect(evidence).not_to_contain_text("pytest unrelated_test.py")
                expect(evidence).not_to_contain_text("unrelated-reporter")
                expect(evidence).not_to_contain_text("unrelated-missing-start")
                modified_correction = evidence.locator(".correction-card").filter(has_text="maintainer-1")
                expect(modified_correction).to_contain_text("Human modified this change")
                expect(modified_correction).to_contain_text("event correction-1 · corrected by maintainer-1")
                reverted_correction = evidence.locator(".correction-card").filter(has_text="maintainer-2")
                expect(reverted_correction).to_contain_text("Human reverted this change")
                expect(reverted_correction).to_contain_text("event correction-2 · corrected by maintainer-2")
                unknown_correction = evidence.locator(".correction-card").filter(has_text="correcting actor unknown")
                expect(unknown_correction).to_contain_text("Human modified this change")
                expect(unknown_correction).to_contain_text("event correction-unknown-actor")
                expect(unknown_correction).not_to_contain_text("corrected by")
                invalid_correction = evidence.locator(".correction-card").filter(has_text="maintainer-invalid-detail")
                expect(invalid_correction).to_contain_text("Human correction action invalid")
                expect(invalid_correction).to_contain_text("event correction-invalid-detail")
                expect(invalid_correction).not_to_contain_text("Human modified this change")
                expect(invalid_correction).not_to_contain_text("Human reverted this change")
                early_correction = evidence.locator(".correction-card").filter(has_text="early-maintainer")
                expect(early_correction).to_contain_text("Human modified this change")
                expect(early_correction).to_contain_text("Correction occurred before change")
                expect(early_correction).to_contain_text("event correction-before-change")
                undetermined_correction = evidence.locator(".correction-card").filter(
                    has_text="concurrent-maintainer"
                )
                expect(undetermined_correction).to_contain_text("Human modified this change")
                expect(undetermined_correction).to_contain_text(
                    "correction chronology undetermined"
                )
                expect(evidence).not_to_contain_text("unrelated-maintainer")
                generic_diagnostic = evidence.locator(".unresolved-evidence").filter(has_text="reviewed_by")
                expect(generic_diagnostic).to_contain_text("Missing relationship target · reviewed_by")
                expect(generic_diagnostic).not_to_contain_text("Missing evidence")
                expect(generic_diagnostic).to_contain_text("missing-review")
                invalid_evidence = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-1 · context.read"
                )
                expect(invalid_evidence).to_contain_text("Invalid evidence target · verified_by")
                expect(invalid_evidence).to_contain_text("context-1 · context.read")
                malformed_result = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-invalid-result"
                )
                expect(malformed_result).to_contain_text("Invalid verification result · verified_by")
                expect(malformed_result).to_contain_text("verification.finished")
                expect(evidence).not_to_contain_text("invalid-result-reporter")
                commandless_result = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-outcome-only"
                )
                expect(commandless_result).to_contain_text("Invalid verification command · verified_by")
                expect(commandless_result).to_contain_text("verification.finished")
                conflicting_outcome = evidence.locator(".verification-card").filter(
                    has_text="conflicting-outcome-reporter"
                )
                expect(conflicting_outcome).to_contain_text("PASS")
                expect(conflicting_outcome).to_contain_text("exit 7")
                conflicting_outcome_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-conflicting-outcome"
                )
                expect(conflicting_outcome_diagnostic).to_contain_text(
                    "Conflicting verification outcome · verified_by"
                )
                expect(conflicting_outcome_diagnostic).to_contain_text("verification.finished")
                invalid_exit_code = evidence.locator(".verification-card").filter(
                    has_text="invalid-exit-code-reporter"
                )
                expect(invalid_exit_code).to_contain_text("pytest tests/test_invalid_exit_code.py")
                expect(invalid_exit_code).to_contain_text("PASS")
                invalid_exit_code_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-invalid-exit-code"
                )
                expect(invalid_exit_code_diagnostic).to_contain_text(
                    "Invalid verification exit code · verified_by"
                )
                expect(invalid_exit_code_diagnostic).to_contain_text("verification.finished")
                expect(page.locator("#invalid-exit-code-injected")).to_have_count(0)
                invalid_test_origin = evidence.locator(".verification-card").filter(
                    has_text="invalid-test-origin-reporter"
                )
                expect(invalid_test_origin).to_contain_text("pytest tests/test_invalid_test_origin.py")
                expect(invalid_test_origin).to_contain_text("Test provenance unknown")
                invalid_test_origin_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-invalid-test-origin"
                )
                expect(invalid_test_origin_diagnostic).to_contain_text(
                    "Invalid verification test provenance · verified_by"
                )
                expect(invalid_test_origin_diagnostic).to_contain_text("verification.finished")
                expect(page.locator("#invalid-test-origin-injected")).to_have_count(0)
                malformed_requirement = evidence.locator(".unresolved-evidence").filter(
                    has_text="requirement-invalid-detail"
                )
                expect(malformed_requirement).to_contain_text("Invalid requirement details · motivated_by")
                expect(malformed_requirement).to_contain_text("requirement.observed")
                expect(evidence).not_to_contain_text("Requirement R-BAD")
                malformed_context = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-invalid-detail"
                )
                expect(malformed_context).to_contain_text("Invalid context details · informed_by")
                expect(malformed_context).to_contain_text("context.read")
                invalid_context_line_start = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-invalid-line-start"
                )
                expect(invalid_context_line_start).to_contain_text(
                    "Invalid context line start · informed_by"
                )
                expect(invalid_context_line_start).to_contain_text("context.read")
                expect(evidence).to_contain_text("docs/invalid-line.md")
                invalid_context_line_end = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-invalid-line-end"
                )
                expect(invalid_context_line_end).to_contain_text(
                    "Invalid context line end · informed_by"
                )
                expect(invalid_context_line_end).to_contain_text("context.read")
                expect(evidence).to_contain_text("docs/invalid-line-end.md:42")
                expect(page.locator("#invalid-context-line-end-injected")).to_have_count(0)
                invalid_context_symbol = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-invalid-symbol"
                )
                expect(invalid_context_symbol).to_contain_text(
                    "Invalid context symbol · informed_by"
                )
                expect(invalid_context_symbol).to_contain_text("context.read")
                expect(evidence).to_contain_text("docs/invalid-symbol.md")
                expect(page.locator("#invalid-context-symbol-injected")).to_have_count(0)
                invalid_compacted_line_start = evidence.locator(".compaction-card").filter(
                    has_text="Context compacted before decision"
                ).locator(".incomplete").filter(has_text="context-invalid-line-start")
                expect(invalid_compacted_line_start).to_contain_text(
                    "Invalid summarizes source line start"
                )
                expect(invalid_compacted_line_start).to_contain_text("context.read")
                invalid_compacted_line_end = evidence.locator(".compaction-card").filter(
                    has_text="Context compacted before decision"
                ).locator(".incomplete").filter(has_text="context-invalid-line-end")
                expect(invalid_compacted_line_end).to_contain_text(
                    "Invalid summarizes source line end"
                )
                expect(invalid_compacted_line_end).to_contain_text("context.read")
                invalid_compacted_symbol = evidence.locator(".compaction-card").filter(
                    has_text="Context compacted before decision"
                ).locator(".incomplete").filter(has_text="context-invalid-symbol")
                expect(invalid_compacted_symbol).to_contain_text(
                    "Invalid summarizes source symbol"
                )
                expect(invalid_compacted_symbol).to_contain_text("context.read")
                malformed_compacted_context = evidence.locator(".compaction-card").filter(
                    has_text="Context compacted before decision"
                ).locator(".incomplete").filter(has_text="context-invalid-detail")
                expect(malformed_compacted_context).to_contain_text("Invalid summarizes source details")
                expect(malformed_compacted_context).to_contain_text("context.read")
                empty_compaction = evidence.locator(".unresolved-evidence").filter(
                    has_text="empty-compaction"
                )
                expect(empty_compaction).to_contain_text("Invalid compaction details · informed_by")
                expect(empty_compaction).to_contain_text("context.compacted")
                malformed_tool = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-detail"
                )
                expect(malformed_tool).to_contain_text("Invalid tool details · preceded_by")
                expect(malformed_tool).to_contain_text("tool.call.completed")
                malformed_tool_status = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-1"
                )
                expect(malformed_tool_status).to_contain_text(
                    "Invalid tool operation status · preceded_by"
                )
                expect(malformed_tool_status).to_contain_text("tool.call.completed")
                malformed_tool_exit_code = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-exit-code"
                )
                expect(malformed_tool_exit_code).to_contain_text("Invalid tool exit code · preceded_by")
                expect(malformed_tool_exit_code).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("git diff --check")
                expect(page.locator("#invalid-tool-exit-code-injected")).to_have_count(0)
                malformed_tool_operation_name = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-operation-name"
                )
                expect(malformed_tool_operation_name).to_contain_text(
                    "Invalid tool operation name · preceded_by"
                )
                expect(malformed_tool_operation_name).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("git status --porcelain")
                expect(page.locator("#invalid-tool-operation-name-injected")).to_have_count(0)
                malformed_tool_command = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-command"
                )
                expect(malformed_tool_command).to_contain_text(
                    "Invalid tool command · preceded_by"
                )
                expect(malformed_tool_command).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("working tree clean")
                malformed_tool_result = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-result"
                )
                expect(malformed_tool_result).to_contain_text(
                    "Invalid tool result · preceded_by"
                )
                expect(malformed_tool_result).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("git status --ignored")
                later_tool = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-after-change"
                )
                expect(later_tool).to_contain_text("Tool occurred after change · preceded_by")
                expect(later_tool).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("git diff --stat")
                expect(evidence).to_contain_text("Evidence incomplete · 0 missing categories · 45 unresolved references · 0 change integrity issues · 2 tests with unknown provenance · 1 same-agent test · 2 failed verifications")
                expect(page.locator("#evidence-injected")).to_have_count(0)
                expect(page.locator("#hunk-symbol-injected")).to_have_count(0)
                expect(page.locator("#context-injected")).to_have_count(0)
                expect(page.locator("#context-symbol-injected")).to_have_count(0)
                expect(page.locator("#unrelated-context-injected")).to_have_count(0)
                expect(page.locator("#tool-command-injected")).to_have_count(0)
                expect(page.locator("#tool-result-injected")).to_have_count(0)
                expect(page.locator("#unrelated-tool-injected")).to_have_count(0)
                expect(page.locator("#verification-injected")).to_have_count(0)
                expect(page.locator("#verification-starter-injected")).to_have_count(0)
                expect(page.locator("#verification-conflict-injected")).to_have_count(0)
                expect(page.locator("#verification-missing-injected")).to_have_count(0)
                expect(page.locator("#invalid-requirement-injected")).to_have_count(0)
                expect(page.locator("#invalid-context-injected")).to_have_count(0)
                expect(page.locator("#invalid-context-line-start-injected")).to_have_count(0)
                expect(page.locator("#invalid-compaction-injected")).to_have_count(0)
                expect(page.locator("#invalid-tool-injected")).to_have_count(0)
                expect(page.locator("#invalid-tool-result-injected")).to_have_count(0)
                expect(page.locator("#unrelated-verification-injected")).to_have_count(0)
                expect(page.locator("#unrelated-verification-reporter-injected")).to_have_count(0)
                expect(page.locator("#correction-injected")).to_have_count(0)
                expect(page.locator("#unrelated-correction-injected")).to_have_count(0)
                expect(page.locator("#proposal-injected")).to_have_count(0)
                expect(page.locator("#unrelated-proposal-injected")).to_have_count(0)
                expect(page.locator("#compaction-missing-injected")).to_have_count(0)
                expect(page.locator("#evidence-missing-injected")).to_have_count(0)
                page.locator(".back-btn").click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('implementer-1')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('span-change-invalid-symbol')).click();
                }""")
                invalid_symbol_evidence = page.locator(".change-evidence")
                expect(invalid_symbol_evidence).to_contain_text("src/auth/invalid-symbol.py:1-1")
                expect(invalid_symbol_evidence).to_contain_text("Invalid change symbol")
                expect(invalid_symbol_evidence).to_contain_text("1 change integrity issue")
                expect(page.locator("#invalid-change-symbol-injected")).to_have_count(0)
                page.locator(".back-btn").click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('invalid-change-producer')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('span-change-invalid-detail')).click();
                }""")
                invalid_change = page.locator(".invalid-change")
                expect(invalid_change).to_contain_text("CHANGE INTEGRITY")
                expect(invalid_change).to_contain_text("event change-invalid-detail")
                expect(invalid_change).to_contain_text("applied by invalid-change-producer")
                expect(invalid_change).to_contain_text("Invalid change details")
                expect(page.locator(".change-evidence")).to_have_count(0)
                expect(page.locator("#invalid-change-actor-injected")).to_have_count(0)
                page.locator(".back-btn").click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => !node.querySelector('.node-label .id').textContent.trim()).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('change.applied')).click();
                }""")
                anonymous_evidence = page.locator(".change-evidence")
                expect(anonymous_evidence).to_contain_text("src/anonymous.py:1-1")
                expect(anonymous_evidence).to_contain_text("applying actor unknown")
                expect(anonymous_evidence).to_contain_text("event anonymous-change")
                expect(anonymous_evidence).not_to_contain_text("applied by")
                page.locator(".back-btn").click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('deletion-implementer')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('change.applied')).click();
                }""")
                deletion_evidence = page.locator(".change-evidence")
                expect(deletion_evidence.locator(".hunk")).to_have_text("src/obsolete.py:11 (0 lines)")
                expect(deletion_evidence).to_contain_text("@@ -12,3 +11,0 @@")
                expect(deletion_evidence).not_to_contain_text("src/obsolete.py:11-11")
                page.locator(".back-btn").click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('invalid-maintainer')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('human.corrected')).click();
                }""")
                diagnostics = page.locator(".relationship-diagnostics")
                expect(diagnostics).to_contain_text("RELATIONSHIP DIAGNOSTICS")
                expect(diagnostics).to_contain_text("Invalid relationship target · corrects")
                expect(diagnostics).to_contain_text("context-1")
                expect(diagnostics).to_contain_text("context.read")
                expect(page.locator("#invalid-correction-target-injected")).to_have_count(0)
                browser.close()

    def test_context_after_decision_is_visible_as_incomplete_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "compaction-after-decision.jsonl")
            source.write_text("".join((
                json.dumps(event_data(
                    event_id="context-1",
                    timestamp="2026-07-13T11:00:00Z",
                    kind="context.read",
                    actor={"id": "researcher-1"},
                    attributes={"context": {"path": "docs/decision.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="proposal-1",
                    span_id="span-proposal",
                    sequence=2,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="change.proposed",
                    actor={"id": "planner-1"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="proposal-undetermined",
                    emitter_id="concurrent-planner-worker",
                    span_id="span-concurrent-proposal",
                    sequence=1,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="change.proposed",
                    actor={"id": "concurrent-planner"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-same-time",
                    span_id="span-current-context",
                    sequence=3,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="context.read",
                    actor={"id": "current-researcher"},
                    attributes={"context": {"path": "docs/current.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-after-decision",
                    span_id="span-late-context",
                    sequence=4,
                    timestamp="2026-07-13T11:02:00Z",
                    kind="context.read",
                    actor={"id": "late-researcher"},
                    attributes={"context": {"path": "docs/late.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-undetermined",
                    emitter_id="context-worker",
                    span_id="span-undetermined-context",
                    sequence=1,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="context.read",
                    actor={"id": "concurrent-researcher"},
                    attributes={"context": {"path": "docs/concurrent.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-source-undetermined",
                    emitter_id="concurrent-source-worker",
                    span_id="span-concurrent-source",
                    sequence=1,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="context.read",
                    actor={"id": "concurrent-source-reader"},
                    attributes={"context": {"path": "docs/concurrent-source.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="requirement-after-decision",
                    span_id="span-late-requirement",
                    sequence=5,
                    timestamp="2026-07-13T11:02:00Z",
                    kind="requirement.observed",
                    actor={"id": "late-observer"},
                    attributes={"requirement": {
                        "id": "R-late",
                        "text": "Requirement observed after the decision.",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="requirement-undetermined",
                    emitter_id="requirement-worker",
                    span_id="span-undetermined-requirement",
                    sequence=1,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="requirement.observed",
                    actor={"id": "concurrent-observer"},
                    attributes={"requirement": {
                        "id": "R-concurrent",
                        "text": "Requirement observed concurrently with the decision.",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-after-decision",
                    span_id="span-late-tool",
                    sequence=6,
                    timestamp="2026-07-13T11:02:00Z",
                    kind="tool.call.completed",
                    actor={"id": "late-runner"},
                    attributes={"tool": {"command": "git diff --check"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-undetermined",
                    emitter_id="concurrent-tool-worker",
                    span_id="span-concurrent-tool",
                    sequence=1,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="tool.call.completed",
                    actor={"id": "concurrent-runner"},
                    attributes={"tool": {"command": "git status --short"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-before-decision",
                    emitter_id="early-compaction-worker",
                    span_id="span-early-compaction",
                    sequence=5,
                    timestamp="2026-07-13T11:01:00Z",
                    kind="context.compacted",
                    actor={"id": "early-summarizer"},
                    relationships=[
                        {"type": "summarizes", "event_id": "context-1"},
                        {
                            "type": "summarizes",
                            "event_id": "compaction-source-undetermined",
                        },
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-after-decision",
                    span_id="span-late-compaction",
                    sequence=6,
                    timestamp="2026-07-13T11:02:00Z",
                    kind="context.compacted",
                    actor={"id": "late-summarizer"},
                    relationships=[{"type": "summarizes", "event_id": "context-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-start-undetermined",
                    emitter_id="verification-start-worker",
                    span_id="span-concurrent-verification-start",
                    sequence=1,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="verification.started",
                    actor={"id": "concurrent-test-starter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_decision.py",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-undetermined",
                    emitter_id="verification-worker",
                    span_id="span-concurrent-verification",
                    sequence=1,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="verification.finished",
                    actor={"id": "concurrent-verifier"},
                    attributes={"verification": {
                        "command": "pytest tests/test_decision.py",
                        "passed": True,
                        "test_origin": "pre_existing",
                    }},
                    relationships=[{
                        "type": "completes",
                        "event_id": "verification-start-undetermined",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-1",
                    span_id="span-change",
                    sequence=7,
                    timestamp="2026-07-13T11:03:00Z",
                    kind="change.applied",
                    actor={"id": "implementer-1"},
                    attributes={"change": {
                        "path": "src/decision.py",
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 2,
                    }},
                    relationships=[
                        {"type": "applies", "event_id": "proposal-1"},
                        {"type": "applies", "event_id": "proposal-undetermined"},
                        {"type": "motivated_by", "event_id": "requirement-after-decision"},
                        {"type": "motivated_by", "event_id": "requirement-undetermined"},
                        {"type": "informed_by", "event_id": "context-same-time"},
                        {"type": "informed_by", "event_id": "context-after-decision"},
                        {"type": "informed_by", "event_id": "context-undetermined"},
                        {"type": "informed_by", "event_id": "compaction-before-decision"},
                        {"type": "informed_by", "event_id": "compaction-after-decision"},
                        {"type": "preceded_by", "event_id": "tool-after-decision"},
                        {"type": "preceded_by", "event_id": "tool-undetermined"},
                        {"type": "verified_by", "event_id": "verification-undetermined"},
                    ],
                )) + "\n",
            )), encoding="utf-8")
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
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator(".node-wrap").filter(has_text="implementer-1")).to_be_visible()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('implementer-1')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('span-change')).click();
                }""")

                evidence = page.locator(".change-evidence")
                undetermined_proposal = evidence.locator(".proposal-card").filter(
                    has_text="concurrent-planner"
                )
                expect(undetermined_proposal).to_contain_text("proposal chronology undetermined")
                undetermined_proposal_diagnostic = evidence.locator(
                    ".unresolved-evidence"
                ).filter(has_text="proposal-undetermined")
                expect(undetermined_proposal_diagnostic).to_contain_text(
                    "Proposal chronology undetermined · applies"
                )
                expect(undetermined_proposal_diagnostic).to_contain_text("change.proposed")
                early = evidence.locator(".compaction-card").filter(has_text="early-summarizer")
                late = evidence.locator(".compaction-card").filter(has_text="late-summarizer")
                expect(early).to_contain_text("Compaction chronology undetermined")
                expect(early).to_contain_text("decision event proposal-1")
                expect(early).to_contain_text("docs/concurrent-source.md")
                expect(early).to_contain_text("concurrent-source-reader")
                expect(early).to_contain_text("source chronology undetermined")
                expect(early).to_contain_text(
                    "Context source chronology undetermined · compaction-source-undetermined"
                )
                undetermined_compaction_diagnostic = evidence.locator(
                    ".unresolved-evidence"
                ).filter(has_text="compaction-before-decision")
                expect(undetermined_compaction_diagnostic).to_contain_text(
                    "Compaction chronology undetermined · informed_by"
                )
                expect(undetermined_compaction_diagnostic).to_contain_text(
                    "decision event proposal-1"
                )
                expect(late).to_contain_text("Context compacted after decision")
                expect(late).to_contain_text("decision event proposal-1")
                expect(evidence.locator(".context-card").filter(has_text="docs/current.md")).to_be_visible()
                expect(evidence.locator(".context-card").filter(has_text="docs/late.md")).to_be_visible()
                undetermined_context = evidence.locator(".context-card").filter(
                    has_text="docs/concurrent.md"
                )
                expect(undetermined_context).to_contain_text("context chronology undetermined")
                expect(undetermined_context).to_contain_text("decision event proposal-1")
                expect(undetermined_context).to_contain_text("concurrent-researcher")
                undetermined_context_diagnostic = evidence.locator(
                    ".unresolved-evidence"
                ).filter(has_text="context-undetermined")
                expect(undetermined_context_diagnostic).to_contain_text(
                    "Context chronology undetermined · informed_by"
                )
                expect(undetermined_context_diagnostic).to_contain_text(
                    "decision event proposal-1"
                )
                current_context_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-same-time"
                )
                expect(current_context_diagnostic).to_contain_text(
                    "Context read after decision · informed_by"
                )
                expect(current_context_diagnostic).to_contain_text("context.read")
                expect(current_context_diagnostic).to_contain_text("decision event proposal-1")
                late_context_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-after-decision"
                )
                expect(late_context_diagnostic).to_contain_text("Context read after decision · informed_by")
                expect(late_context_diagnostic).to_contain_text("context.read")
                expect(late_context_diagnostic).to_contain_text("decision event proposal-1")
                late_requirement = evidence.locator(".requirement-card").filter(has_text="R-late")
                expect(late_requirement).to_contain_text("Requirement observed after the decision.")
                expect(late_requirement).to_contain_text("decision event proposal-1")
                undetermined_requirement = evidence.locator(".requirement-card").filter(
                    has_text="R-concurrent"
                )
                expect(undetermined_requirement).to_contain_text("concurrent-observer")
                expect(undetermined_requirement).to_contain_text("decision event proposal-1")
                expect(undetermined_requirement).to_contain_text(
                    "requirement chronology undetermined"
                )
                undetermined_requirement_diagnostic = evidence.locator(
                    ".unresolved-evidence"
                ).filter(has_text="requirement-undetermined")
                expect(undetermined_requirement_diagnostic).to_contain_text(
                    "Requirement chronology undetermined · motivated_by"
                )
                expect(undetermined_requirement_diagnostic).to_contain_text(
                    "decision event proposal-1"
                )
                late_requirement_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="requirement-after-decision"
                )
                expect(late_requirement_diagnostic).to_contain_text(
                    "Requirement observed after decision · motivated_by"
                )
                expect(late_requirement_diagnostic).to_contain_text("requirement.observed")
                expect(late_requirement_diagnostic).to_contain_text("decision event proposal-1")
                late_tool = evidence.locator(".tool-card").filter(has_text="git diff --check")
                expect(late_tool).to_contain_text("late-runner")
                expect(late_tool).to_contain_text("decision event proposal-1")
                undetermined_tool = evidence.locator(".tool-card").filter(
                    has_text="git status --short"
                )
                expect(undetermined_tool).to_contain_text("concurrent-runner")
                expect(undetermined_tool).to_contain_text("decision event proposal-1")
                expect(undetermined_tool).to_contain_text("tool chronology undetermined")
                undetermined_tool_diagnostic = evidence.locator(
                    ".unresolved-evidence"
                ).filter(has_text="tool-undetermined")
                expect(undetermined_tool_diagnostic).to_contain_text(
                    "Tool chronology undetermined · preceded_by"
                )
                expect(undetermined_tool_diagnostic).to_contain_text(
                    "decision event proposal-1"
                )
                undetermined_verification = evidence.locator(".verification-card").filter(
                    has_text="pytest tests/test_decision.py"
                )
                expect(undetermined_verification).to_contain_text("concurrent-verifier")
                expect(undetermined_verification).to_contain_text("concurrent-test-starter")
                expect(undetermined_verification).to_contain_text(
                    "start chronology undetermined"
                )
                expect(undetermined_verification).to_contain_text(
                    "start/change chronology undetermined"
                )
                expect(undetermined_verification).to_contain_text(
                    "verification chronology undetermined"
                )
                expect(undetermined_verification).to_contain_text(
                    "Verification start/finish chronology undetermined · verification-start-undetermined · verification.started"
                )
                undetermined_verification_diagnostic = evidence.locator(
                    ".unresolved-evidence"
                ).filter(has_text="verification-undetermined")
                expect(undetermined_verification_diagnostic).to_contain_text(
                    "Verification chronology undetermined · verified_by"
                )
                expect(undetermined_verification_diagnostic).to_contain_text(
                    "verification.finished"
                )
                late_tool_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-after-decision"
                )
                expect(late_tool_diagnostic).to_contain_text(
                    "Tool occurred after decision · preceded_by"
                )
                expect(late_tool_diagnostic).to_contain_text("tool.call.completed")
                expect(late_tool_diagnostic).to_contain_text("decision event proposal-1")
                diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="compaction-after-decision"
                )
                expect(diagnostic).to_contain_text("Context compacted after decision · informed_by")
                expect(diagnostic).to_contain_text("context.compacted")
                expect(diagnostic).to_contain_text("decision event proposal-1")
                expect(evidence).to_contain_text("13 unresolved references")
                browser.close()

    def test_no_proposal_chronology_ambiguity_is_visible_as_incomplete_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "no-proposal-chronology.jsonl")
            source.write_text("".join((
                json.dumps(event_data(
                    event_id="requirement-undetermined",
                    emitter_id="requirement-worker",
                    timestamp="2026-07-13T11:01:00Z",
                    kind="requirement.observed",
                    actor={"id": "concurrent-observer"},
                    attributes={"requirement": {
                        "id": "R-concurrent",
                        "text": "Concurrent requirement without a proposal.",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-undetermined",
                    emitter_id="context-worker",
                    timestamp="2026-07-13T11:01:00Z",
                    kind="context.read",
                    actor={"id": "concurrent-reader"},
                    attributes={"context": {"path": "docs/concurrent.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-source",
                    emitter_id="source-worker",
                    timestamp="2026-07-13T11:00:00Z",
                    kind="context.read",
                    actor={"id": "source-reader"},
                    attributes={"context": {"path": "docs/source.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-undetermined",
                    emitter_id="compaction-worker",
                    timestamp="2026-07-13T11:01:00Z",
                    kind="context.compacted",
                    actor={"id": "concurrent-summarizer"},
                    relationships=[{"type": "summarizes", "event_id": "compaction-source"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-undetermined",
                    emitter_id="tool-worker",
                    timestamp="2026-07-13T11:01:00Z",
                    kind="tool.call.completed",
                    actor={"id": "concurrent-runner"},
                    attributes={"tool": {"command": "git diff --check"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-1",
                    emitter_id="change-worker",
                    span_id="span-change",
                    timestamp="2026-07-13T11:01:00Z",
                    kind="change.applied",
                    actor={"id": "implementer-1"},
                    attributes={"change": {
                        "path": "src/concurrent.py",
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 2,
                    }},
                    relationships=[
                        {"type": "motivated_by", "event_id": "requirement-undetermined"},
                        {"type": "informed_by", "event_id": "context-undetermined"},
                        {"type": "informed_by", "event_id": "compaction-undetermined"},
                        {"type": "preceded_by", "event_id": "tool-undetermined"},
                    ],
                )) + "\n",
            )), encoding="utf-8")
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
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator(".node-wrap").filter(has_text="implementer-1")).to_be_visible()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('implementer-1')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('span-change')).click();
                }""")

                evidence = page.locator(".change-evidence")
                expected_diagnostics = (
                    ("requirement-undetermined", "Requirement chronology undetermined · motivated_by"),
                    ("context-undetermined", "Context chronology undetermined · informed_by"),
                    ("compaction-undetermined", "Compaction chronology undetermined · informed_by"),
                    ("tool-undetermined", "Tool chronology undetermined · preceded_by"),
                )
                for event_id, message in expected_diagnostics:
                    diagnostic = evidence.locator(".unresolved-evidence").filter(has_text=event_id)
                    expect(diagnostic).to_contain_text(message)
                    expect(diagnostic).not_to_contain_text("decision event")
                expect(evidence).to_contain_text("4 unresolved references")
                expect(evidence).not_to_contain_text("decision event")
                browser.close()

    def test_multi_trace_run_picker_stays_within_top_bar(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "multi-trace.jsonl")
            source.write_text("".join((
                json.dumps(event_data()) + "\n",
                json.dumps(event_data(
                    event_id="trace-2-event",
                    trace_id="trace-2",
                    span_id="trace-2-span",
                )) + "\n",
            )), encoding="utf-8")
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
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator("#run-picker-btn")).to_have_count(1)
                self.assertEqual(round(page.locator("header.topbar").bounding_box()["height"]), 52)
                page.locator("#run-picker-btn").click()
                expect(page.locator(".run-menu")).to_be_visible()
                expect(page.locator(".run-menu button.run-row")).to_have_count(2)
                page.locator(".run-menu button.run-row").filter(has_text="trace-2").click()
                expect(page.locator("#run-picker-btn")).to_contain_text("trace-2")
                page.set_viewport_size({"width": 390, "height": 844})
                expect(page.locator("#run-picker-btn")).to_be_visible()
                expect(page.locator(".top-search")).to_be_hidden()
                page.locator("#scrubber").evaluate(
                    "element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }"
                )
                expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
                page.get_by_role("button", name="Jump to live").click()
                browser.close()

    def test_browser_reset_preserves_selection_and_reconnects_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "reset.jsonl")
            source.write_text("".join((
                json.dumps(event_data()) + "\n",
                json.dumps(event_data(
                    event_id="trace-2-event",
                    trace_id="trace-2",
                    span_id="trace-2-span",
                )) + "\n",
            )), encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    "serve",
                    str(source),
                    "--port",
                    str(port),
                    "--max-live-updates",
                    "2",
                ],
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
                event_stream_urls = []
                page.on(
                    "request",
                    lambda request: event_stream_urls.append(request.url)
                    if "/api/v1/events?cursor=" in request.url
                    else None,
                )
                page.goto(
                    f"http://127.0.0.1:{port}",
                    wait_until="domcontentloaded",
                )
                page.locator("#run-picker-btn").click()
                page.locator(".run-menu button.run-row").filter(
                    has_text="trace-2"
                ).click()
                expect(page.locator("#run-picker-btn")).to_contain_text("trace-2")

                page.evaluate("() => { cursor = 999; connectEvents(); }")
                page.wait_for_function("cursor < 999 && events !== null")

                expect(page.locator("#run-picker-btn")).to_contain_text("trace-2")
                self.assertEqual(
                    sum("cursor=999" in url for url in event_stream_urls),
                    1,
                )
                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="trace-2-live",
                        trace_id="trace-2",
                        span_id="trace-2-live-span",
                        sequence=2,
                    )) + "\n")
                page.wait_for_function(
                    "currentDetail.events.some((event) => event.event_id === 'trace-2-live')"
                )
                self.assertEqual(
                    page.evaluate(
                        "currentDetail.events.map((event) => event.event_id)"
                    ),
                    ["trace-2-event", "trace-2-live"],
                )
                expect(page.locator("#run-picker-btn")).to_contain_text("trace-2")
                browser.close()

    def test_warning_policy_is_visible_and_preserves_unrelated_warning_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "policy-run.jsonl")
            policy = Path(directory, "policy.toml")
            policy.write_text(
                "version = 1\n[[tools]]\nname = 'flaky_api'\nsuppress = ['RETRY']\n",
                encoding="utf-8",
            )
            events = []
            for sequence in range(1, 4):
                for name in ("flaky_api", "unrelated_api"):
                    events.append(event_data(
                        event_id=f"{name}-{sequence}",
                        span_id=f"{name}-{sequence}",
                        emitter_id=f"emitter-{name}",
                        sequence=sequence,
                        timestamp=f"2026-07-13T11:02:{sequence:02d}Z",
                        kind="tool.call.failed",
                        actor={"id": f"actor-{name}"},
                        operation={"status": "failed", "name": name},
                        attributes={"arguments": {"url": "same"}},
                    ))
            source.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "serve", str(source),
                    "--port", str(port), "--warning-policy", str(policy),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"
            detail = json.loads(
                urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read()
            )

            self.assertEqual(detail["warning_policy"]["path"], str(policy))
            self.assertEqual(detail["warning_policy"]["version"], 1)
            self.assertEqual(detail["warning_policy"]["suppressed_counts"]["total"], 1)
            retry = next(warning for warning in detail["warnings"] if warning["code"] == "RETRY")
            self.assertEqual(
                json.loads(retry["evidence"])["event_ids"],
                ["unrelated_api-1", "unrelated_api-2", "unrelated_api-3"],
            )

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                page.get_by_role("button", name="Warnings", exact=True).click()
                drawer = page.locator("#warnings-drawer")
                expect(drawer).to_contain_text(str(policy))
                expect(drawer).to_contain_text("version 1")
                expect(drawer).to_contain_text("Suppressed 1")
                expect(drawer).to_contain_text("RETRY")
                expect(drawer).to_contain_text("actor-unrelated_api")
                browser.close()

    def test_primary_journey_in_chrome_firefox_and_webkit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "cross-browser.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
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

            with sync_playwright() as playwright:
                browsers = (
                    ("chrome", playwright.chromium, {"channel": "chrome"}),
                    ("firefox", playwright.firefox, {}),
                    ("webkit", playwright.webkit, {}),
                )
                for index, (browser_name, browser_type, options) in enumerate(browsers, 2):
                    with self.subTest(browser=browser_name):
                        browser = browser_type.launch(headless=True, **options)
                        page = browser.new_page()
                        page.goto(base_url, wait_until="domcontentloaded")
                        expect(page.locator(".brand-name")).to_contain_text("AGENT")
                        expect(page.locator(".node-wrap")).to_have_count(1)
                        for view in ("Tree", "Swimlane", "Sequence", "Graph"):
                            page.get_by_role("button", name=view, exact=True).click()
                            expect(page.locator(".stage-content")).to_be_visible()
                        agent_node = page.locator(".node-wrap").first
                        agent_node.click()
                        if "Focus subtree" not in page.locator("#inspector").inner_text():
                            # A live refresh can replace the node between WebKit pointer events.
                            agent_node.click()
                        expect(page.locator("#inspector")).to_contain_text("Focus subtree")
                        page.get_by_role("button", name="Warnings", exact=True).click()
                        expect(page.locator("#warnings-drawer")).to_be_visible()
                        page.get_by_role("button", name="Close warnings").click()
                        page.get_by_role("button", name="Swimlane", exact=True).click()
                        page.locator("#search").fill("reviewer")
                        expect(page.locator(".lane-row")).to_have_count(1)
                        page.locator("#search").fill("")
                        page.locator("#scrubber").evaluate(
                            "element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }"
                        )
                        expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
                        page.get_by_role("button", name="Jump to live").click()
                        requests_metric = page.locator(".metric").filter(has_text="REQUESTS")
                        requests_before = int(requests_metric.locator(".value").inner_text())
                        live_event_id = f"{browser_name}-live"
                        with source.open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(event_data(
                                event_id=live_event_id,
                                span_id=f"span-{browser_name}",
                                sequence=index,
                            )) + "\n")
                        expect(requests_metric).to_contain_text(str(requests_before + 1))
                        browser.close()

            final = _wait_for_event(base_url, "webkit-live")

        self.assertIn("chrome-live", [event["event_id"] for event in final["events"]])
        self.assertIn("firefox-live", [event["event_id"] for event in final["events"]])
        self.assertIn("webkit-live", [event["event_id"] for event in final["events"]])

    def test_real_serve_command_ui_api_sse_reconnect_and_sanitization(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data(
                payload={"token": "Bearer hidden-secret", "text": "visible"},
                operation={
                    "status": "running",
                    "name": "read_file",
                    "duration_ms": '<img id="injected" src=x onerror=alert(1)>',
                },
                usage={"input_tokens": 12},
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
                expect(page.locator(".brand-name")).to_contain_text("AGENT")
                expect(page.locator(".node-wrap")).to_have_count(1)
                self.assertNotIn("hidden-secret", page.content())

                for view in ("Tree", "Swimlane", "Sequence", "Graph"):
                    page.get_by_role("button", name=view, exact=True).click()
                    expect(page.locator(".stage-content")).to_be_visible()

                page.locator(".node-wrap").first.click()
                expect(page.locator("#inspector")).to_contain_text("EVENT TIMELINE")
                page.locator(".event-row").first.click()
                expect(page.locator("#inspector")).to_contain_text("Event Inspector")
                expect(page.locator("#inspector")).to_contain_text("read_file")
                expect(page.locator("#injected")).to_have_count(0)
                page.get_by_role("button", name="Load retained payload").click()
                expect(page.locator("#inspector pre")).to_contain_text("visible")
                self.assertNotIn("hidden-secret", page.locator("#inspector").inner_text())

                page.get_by_role("button", name="Warnings", exact=True).click()
                expect(page.locator("#warnings-drawer")).to_be_visible()
                page.get_by_role("button", name="Close warnings").click()
                page.get_by_role("button", name="Swimlane", exact=True).click()
                page.locator("#search").fill("evt-1")
                expect(page.locator(".lane-row")).to_have_count(1)
                page.locator("#search").fill("")
                expect(page.locator(".lane-row")).to_have_count(1)

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
                expect(page.locator(".lane-row")).to_have_count(2)
                page.get_by_role("button", name="Sequence", exact=True).click()
                expect(page.locator("#sequence")).to_contain_text("worker-1")
                expect(page.locator("#sequence")).to_contain_text("delegate")

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
                page.get_by_role("button", name="Graph", exact=True).click()
                expect(page.locator(".node-wrap")).to_have_count(3)

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="done",
                        span_id="span-1",
                        sequence=4,
                        kind="trace.completed",
                        operation={"status": "completed"},
                    )) + "\n")
                expect(page.locator("#run-picker-btn")).to_contain_text("completed")
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
        project_root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as directory, sync_playwright() as playwright:
            temporary = Path(directory)
            source = temporary / "performance-10k.jsonl"
            write_fixture(source)
            environment = temporary / "installed"
            venv.EnvBuilder(with_pip=True).create(environment)
            installed_python = environment / "bin" / "python"
            installed_command = environment / "bin" / "agent-tail"
            installation = subprocess.run(
                [str(installed_python), "-m", "pip", "install", "--no-deps", str(project_root)],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(installation.returncode, 0, installation.stderr)

            browser = playwright.chromium.launch(headless=True)
            port = _free_port()
            started = time.perf_counter()
            process = subprocess.Popen(
                [
                    str(installed_command),
                    "serve",
                    str(source),
                    "--port",
                    str(port),
                    "--max-bytes",
                    str(HIGH_BUDGET_BYTES),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=temporary,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"
            deadline = started + 10.0
            while time.perf_counter() < deadline:
                runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=2).read())
                if runs["runs"] and runs["runs"][0]["event_count"] == 10_000:
                    break
                time.sleep(0.05)
            else:
                self.fail("installed serve command did not ingest 10,000 events in 10 seconds")

            page = browser.new_page(viewport={"width": 700, "height": 900})
            page.goto(base_url, wait_until="domcontentloaded")
            expect(page.locator(".node-wrap")).to_have_count(40, timeout=10_000)
            first_useful_view_seconds = time.perf_counter() - started
            self.assertLess(first_useful_view_seconds, 10.0)

            reveal_started = time.perf_counter()
            page.locator('[data-action="show-more"]').click()
            expect(page.locator(".node-wrap")).to_have_count(80)
            progressive_reveal_seconds = time.perf_counter() - reveal_started

            search_started = time.perf_counter()
            page.set_viewport_size({"width": 1280, "height": 900})
            page.get_by_role("button", name="Swimlane", exact=True).click()
            page.locator("#search").fill(LATE_EVENT_ID)
            expect(page.locator(".lane-row")).to_have_count(1)
            page.locator(".lane-row").click()
            page.locator(".event-row").first.click()
            expect(page.locator("#inspector")).to_contain_text(LATE_EVENT_ID)
            late_search_and_inspector_seconds = time.perf_counter() - search_started

            switch_started = time.perf_counter()
            page.locator("#search").fill("")
            page.get_by_role("button", name="Tree", exact=True).click()
            expect(page.locator(".node-wrap")).to_have_count(80)
            view_switch_seconds = time.perf_counter() - switch_started

            playback_started = time.perf_counter()
            page.locator("#scrubber").evaluate(
                "element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }"
            )
            expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
            page.locator("#scrubber").evaluate(
                "element => { element.value = '1000'; element.dispatchEvent(new Event('input', { bubbles: true })); }"
            )
            expect(page.locator(".node-wrap")).to_have_count(80)
            playback_to_end_seconds = time.perf_counter() - playback_started

            for measured in (
                progressive_reveal_seconds,
                late_search_and_inspector_seconds,
                view_switch_seconds,
                playback_to_end_seconds,
            ):
                self.assertLess(measured, 10.0)
            self.assertEqual(TRACE_ID, runs["runs"][0]["trace_id"])
            print("browser performance envelope: " + json.dumps({
                "first_useful_view_seconds": first_useful_view_seconds,
                "late_search_and_inspector_seconds": late_search_and_inspector_seconds,
                "playback_to_end_seconds": playback_to_end_seconds,
                "progressive_reveal_seconds": progressive_reveal_seconds,
                "view_switch_seconds": view_switch_seconds,
            }, sort_keys=True))
            browser.close()

    def test_otlp_import_opens_with_parentage_and_source_attributes(self):
        fixture = Path(__file__).parent / "fixtures" / "otel-traces.json"
        with tempfile.TemporaryDirectory() as directory:
            imported = Path(directory, "imported.jsonl")
            import_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    "import",
                    "otel",
                    str(fixture),
                    "--output",
                    str(imported),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(import_result.returncode, 0, import_result.stderr)
            port = _free_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    "serve",
                    str(imported),
                    "--port",
                    str(port),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page()
                page.goto(
                    f"http://127.0.0.1:{port}", wait_until="domcontentloaded"
                )
                expect(
                    page.locator(".node-wrap").filter(has_text="planner-7")
                ).to_be_visible()
                expect(
                    page.locator(".node-wrap").filter(has_text="planner-service")
                ).to_be_visible()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('planner-service')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('bbbbbbbbbbbbbbbb')).click();
                }""")

                inspector = page.locator("#inspector")
                expect(inspector).to_contain_text("model.request.finished")
                expect(inspector).to_contain_text("parent_span")
                expect(inspector).to_contain_text("aaaaaaaaaaaaaaaa")
                expect(inspector).to_contain_text("gen_ai.request.model")
                expect(inspector).to_contain_text("gpt-4.1")
                expect(inspector).to_contain_text("dddddddddddddddd")
                browser.close()


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
        if "AgentTrail serve mode listening" in line:
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


def _wait_for_event(base_url: str, event_id: str) -> dict[str, object]:
    deadline = time.time() + 3
    while time.time() < deadline:
        detail = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read())
        if any(event["event_id"] == event_id for event in detail["events"]):
            return detail
        time.sleep(0.05)
    raise AssertionError(f"event did not arrive: {event_id}")


if __name__ == "__main__":
    unittest.main()
