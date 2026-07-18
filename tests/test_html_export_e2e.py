import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from playwright.sync_api import expect, sync_playwright


def event_data(sequence, **changes):
    data = {
        "schema_version": "1.0",
        "event_id": f"evt-{sequence}",
        "trace_id": "trace-export",
        "span_id": f"span-{sequence}",
        "emitter_id": "fixture",
        "sequence": sequence,
        "timestamp": f"2026-07-13T11:02:{sequence:02d}Z",
        "kind": "tool.call.started",
        "actor": {"id": "implementer"},
        "operation": {"status": "running", "name": "read_file"},
    }
    data.update(changes)
    return data


class HtmlExportEndToEndTests(unittest.TestCase):
    def test_metadata_only_report_exposes_mode_and_omission_offline(self):
        sentinel = "payload-only-offline-sentinel"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "fixture.jsonl")
            report = Path(directory, "report.html")
            source.write_text(json.dumps(event_data(
                1, payload={"text": sentinel}
            )) + "\n", encoding="utf-8")
            exported = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    str(source),
                    "--metadata-only",
                    "--export-html",
                    str(report),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertNotIn(sentinel.encode(), report.read_bytes())
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(report.as_uri(), wait_until="load")
                expect(page.locator("#export-info")).to_contain_text(
                    "metadata-only sanitized embedded snapshot"
                )
                expect(page.locator("#export-info")).to_contain_text("omitted 1")
                page.locator(".node-wrap").filter(has_text="implementer").click()
                page.locator(".event-row").click()
                expect(page.locator("#inspector")).to_contain_text(
                    "payload omitted (metadata-only)"
                )
                expect(page.locator(".io-load-btn")).to_have_count(0)
                self.assertNotIn(sentinel, page.content())
                browser.close()

    def test_file_report_is_complete_hostile_safe_and_offline(self):
        secret = "ghp_" + "a" * 36
        hostile = '<img id="export-injected" src="https://evil.invalid/pixel">'
        hunk = {
            "path": f"src/main.py{hostile}",
            "old_start": 1,
            "old_count": 1,
            "new_start": 1,
            "new_count": 2,
            "symbol": "apply_change",
        }
        events = [
            event_data(
                1,
                event_id="requirement-1",
                kind="requirement.observed",
                actor={"id": "user"},
                attributes={"requirement": {"id": "R1", "text": f"Keep exports offline. {hostile}"}},
            ),
            event_data(
                2,
                event_id="context-1",
                kind="context.read",
                actor={"id": "researcher"},
                attributes={"context": {"path": "docs/security.md", "line_start": 4, "line_end": 8}},
            ),
            event_data(
                3,
                event_id="change-1",
                kind="change.applied",
                attributes={"change": hunk},
                relationships=[
                    {"type": "motivated_by", "event_id": "requirement-1"},
                    {"type": "informed_by", "event_id": "context-1"},
                    {"type": "verified_by", "event_id": "verification-1"},
                    {"type": "reviewed_by", "event_id": "missing-review"},
                ],
                payload={"token": secret, "output": "x" * 5000},
            ),
            event_data(
                4,
                event_id="verification-1",
                kind="verification.finished",
                actor={"id": "tester"},
                operation={"status": "completed", "name": "pytest"},
                attributes={"verification": {
                    "command": "pytest tests/test_export.py",
                    "passed": True,
                    "test_origin": "pre_existing",
                }},
            ),
        ]
        for sequence in range(5, 9):
            events.append(event_data(
                sequence,
                operation={"status": "running", "name": "repeat_read"},
                attributes={"arguments": {"path": "same.py"}},
            ))

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "fixture.jsonl")
            report = Path(directory, "report.html")
            source.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
            exported = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_tail",
                    str(source),
                    "--export-html",
                    str(report),
                    "--export-html-generated-at",
                    "2026-07-18T12:00:00Z",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(exported.returncode, 0, exported.stderr)
            artifact = report.read_text(encoding="utf-8")
            self.assertNotIn(secret, artifact)
            self.assertNotIn("evil.invalid", artifact)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                requests = []
                page.on("request", lambda request: requests.append(request.url))
                page.add_init_script("""
                    window.__networkCalls = [];
                    const OriginalWebSocket = window.WebSocket;
                    window.WebSocket = function(...args) { window.__networkCalls.push(['websocket', ...args]); return new OriginalWebSocket(...args); };
                    const OriginalEventSource = window.EventSource;
                    window.EventSource = function(...args) { window.__networkCalls.push(['eventsource', ...args]); return new OriginalEventSource(...args); };
                    const originalFetch = window.fetch;
                    window.fetch = function(...args) { window.__networkCalls.push(['fetch', String(args[0])]); return originalFetch(...args); };
                    const originalBeacon = navigator.sendBeacon.bind(navigator);
                    navigator.sendBeacon = function(...args) { window.__networkCalls.push(['beacon', String(args[0])]); return originalBeacon(...args); };
                """)
                page.goto(report.as_uri(), wait_until="load")
                expect(page.locator("#export-info")).to_contain_text("sanitized embedded snapshot")
                expect(page.locator("#export-info")).to_contain_text("2026-07-18T12:00:00Z")
                expect(page.locator("#jump-live")).to_be_hidden()
                expect(page.locator(".node-wrap")).to_have_count(4)

                for view, selector in (
                    ("Graph", ".node-wrap"),
                    ("Tree", ".node-wrap"),
                    ("Swimlane", ".lane-row"),
                    ("Sequence", ".seq-col-head"),
                ):
                    page.get_by_role("button", name=view, exact=True).click()
                    expect(page.locator(selector).first).to_be_visible()

                search = page.locator("#search")
                search.fill("tester")
                expect(page.locator(".seq-col-head").filter(has_text="tester")).to_be_visible()
                search.fill("")

                page.locator("#scrubber").fill("0")
                expect(page.locator("#playback-mode")).to_have_text("paused")
                page.locator("#playback-toggle").click()
                expect(page.locator("#playback-mode")).to_contain_text("replay")
                page.locator("#playback-toggle").click()
                page.locator("#scrubber").fill("1000")

                page.locator("#warning-button").click()
                expect(page.locator("#warnings-drawer")).to_contain_text("LOOP")
                page.get_by_role("button", name="Close warnings").click()

                page.get_by_role("button", name="Graph", exact=True).click()
                page.locator(".node-wrap").filter(has_text="implementer").click()
                page.locator(".event-row").filter(has_text="change.applied").click()
                expect(page.locator(".change-evidence")).to_contain_text("CHANGE EVIDENCE")
                expect(page.locator(".change-evidence")).to_contain_text("pytest tests/test_export.py")
                expect(page.locator(".change-evidence")).to_contain_text("missing-review")
                expect(page.locator("#inspector")).to_contain_text("payload truncated")
                expect(page.locator(".io-load-btn")).to_have_count(0)

                self.assertEqual(page.locator("#export-injected").count(), 0)
                self.assertNotIn(secret, page.content())
                self.assertEqual(page.evaluate("window.__networkCalls"), [])
                self.assertFalse(any(url.startswith(("http:", "https:", "ws:", "wss:")) for url in requests))
                browser.close()


if __name__ == "__main__":
    unittest.main()
