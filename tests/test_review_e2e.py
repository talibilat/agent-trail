import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
        "actor": {"id": "reviewer-1"},
        "operation": {"status": "running", "name": "read_file"},
    }
    data.update(changes)
    return data


class ReviewEndToEndTests(unittest.TestCase):
    def test_closing_review_page_cancels_and_preserves_destination(self):
        source_text = json.dumps(event_data()) + "\n"
        with tempfile.TemporaryDirectory() as directory, sync_playwright() as playwright:
            destination = Path(directory, "cancelled.md")
            destination.write_bytes(b"existing")
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "agent_tail", "-", "--export",
                    str(destination), "--review", "--review-timeout", "10",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(
                lambda: process.kill() if process.poll() is None else None
            )
            process.stdin.write(source_text)
            process.stdin.close()
            process.stdin = None
            process.stdout.readline()
            url = process.stdout.readline().removeprefix("Review URL: ").strip()

            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded")
            expect(page.locator("#review-banner")).to_be_visible()
            page.close()
            stdout, stderr = process.communicate(timeout=5)
            browser.close()

            self.assertEqual(process.returncode, 2, stdout + stderr)
            self.assertEqual(destination.read_bytes(), b"existing")

    def test_markdown_and_html_review_use_inspectors_inventory_and_frozen_digest(self):
        secret = "ghp_" + "a" * 36
        safe_value = "review-visible-safe-value"
        source_text = json.dumps(event_data(
            attributes={"tool": {"command": "pytest tests/test_review.py"}},
            payload={"authorization": f"Bearer {secret}", "result": safe_value},
        )) + "\n"

        with tempfile.TemporaryDirectory() as directory, sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            for option, name in (("--export", "report.md"), ("--export-html", "report.html")):
                with self.subTest(option=option):
                    destination = Path(directory, name)
                    destination.write_bytes(b"existing")
                    process = subprocess.Popen(
                        [
                            sys.executable, "-m", "agent_tail", "-", option,
                            str(destination), "--review", "--review-timeout", "15",
                        ],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                    )
                    self.addCleanup(
                        lambda process=process: process.kill()
                        if process.poll() is None else None
                    )
                    process.stdin.write(source_text)
                    process.stdin.close()
                    process.stdin = None
                    summary = process.stdout.readline()
                    url_line = process.stdout.readline()
                    self.assertTrue(url_line.startswith("Review URL: "), summary + url_line)
                    url = url_line.removeprefix("Review URL: ").strip()
                    digest = summary.split(": ", 1)[1].split(" ", 1)[0]

                    page = browser.new_page()
                    page.goto(url, wait_until="domcontentloaded")
                    expect(page.locator("#review-banner")).to_be_visible()
                    expect(page.locator("#review-banner")).to_contain_text(digest)
                    expect(page.locator("#review-banner")).to_contain_text(
                        "attributes.tool.command"
                    )
                    expect(page.locator("#review-banner")).to_contain_text("retained 1")
                    page.locator(".node-wrap").filter(has_text="reviewer-1").click()
                    page.locator(".event-row").first.click()
                    expect(page.locator("#inspector")).to_contain_text(safe_value)
                    self.assertNotIn(secret, page.content())
                    self.assertEqual(destination.read_bytes(), b"existing")
                    page.locator("#review-approve").click(no_wait_after=True)
                    stdout, stderr = process.communicate(timeout=5)
                    page.close()

                    self.assertEqual(process.returncode, 0, stdout + stderr)
                    self.assertEqual(
                        hashlib.sha256(destination.read_bytes()).hexdigest(), digest
                    )
                    self.assertNotIn(secret.encode(), destination.read_bytes())

                    if option == "--export-html":
                        offline = browser.new_page()
                        offline.goto(destination.as_uri(), wait_until="domcontentloaded")
                        expect(offline.locator(".node-wrap")).to_contain_text("reviewer-1")
                        self.assertNotIn(secret, offline.content())
                        offline.close()
            browser.close()


if __name__ == "__main__":
    unittest.main()
