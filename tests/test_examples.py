from pathlib import Path
import runpy
import tempfile
import threading
import unittest
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

from agent_tail.compare import compare_paths
from agent_tail.otel import parse_otlp_json
from agent_tail.serve import RunStore, make_server
from agent_tail.session_import import import_session
from agent_tail.warning_policy import load_warning_policy


ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples"


class ExampleTests(unittest.TestCase):
    def test_comprehensive_demo_opens_in_the_packaged_browser_ui(self):
        store = RunStore.from_lines(
            (EXAMPLES / "demo-run.jsonl").read_text(encoding="utf-8").splitlines(True),
            fan_out_threshold=2,
        )
        server = make_server(store, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.goto(
                f"http://127.0.0.1:{server.server_address[1]}",
                wait_until="domcontentloaded",
            )

            expect(page.locator(".node-wrap").filter(has_text="implementer")).to_be_visible()
            page.locator(".node-wrap").filter(has_text="implementer").click()
            page.locator(".event-row").filter(has_text="change.applied").click()
            expect(page.locator(".change-evidence")).to_contain_text(
                "src/auth/session.py:84-102"
            )
            expect(page.locator("#inspector")).to_contain_text(
                "observed outcome modified"
            )

            page.locator(".node-wrap").filter(has_text="security-worker").click()
            page.locator(".event-row").filter(has_text="http_post").click()
            expect(page.locator(".security-audit")).to_contain_text(
                "UNTRUSTED_TO_SENSITIVE"
            )
            expect(page.locator(".security-audit")).to_contain_text("network_egress")
            browser.close()

    def test_comprehensive_ui_demo_exercises_documented_projections(self):
        store = RunStore.from_lines(
            (EXAMPLES / "demo-run.jsonl").read_text(encoding="utf-8").splitlines(True),
            fan_out_threshold=2,
        )

        detail = store.run_detail("demo-trace")
        warning_codes = {
            warning["code"] for warning in detail["warnings"]
            if warning.get("active", True)
        }
        change = next(
            item for item in detail["evidence_map"]["changes"]
            if item["event_id"] == "demo-change"
        )
        hunk_cost = next(
            item for item in detail["outcome_cost"]["by_hunk"]
            if item["change_event_id"] == "demo-change"
        )

        self.assertTrue({
            "LOOP",
            "SELF_CONFIRMING_TEST",
            "STALE_CONTEXT",
            "HIGH_FAN_OUT",
            "OVERLAPPING_CHANGE",
            "REDUNDANT_OPERATION",
            "UNCONSUMED_CHILD_RESULT",
            "CHILD_AFTER_PARENT_END",
        }.issubset(warning_codes))
        self.assertEqual(change["hunk"]["path"], "src/auth/session.py")
        self.assertEqual(
            detail["context_provenance"]["by_event_id"]["demo-change"]["freshness"],
            "stale",
        )
        self.assertEqual(
            detail["security"]["findings"][0]["code"],
            "UNTRUSTED_TO_SENSITIVE",
        )
        self.assertEqual(hunk_cost["observed_outcome"], "modified")
        self.assertEqual(hunk_cost["usage"]["cost_usd"]["value"], 0.04)

    def test_warning_policy_changes_the_demo_loop_threshold(self):
        policy = load_warning_policy(EXAMPLES / "warning-policy.toml")
        store = RunStore.from_lines(
            (EXAMPLES / "demo-run.jsonl").read_text(encoding="utf-8").splitlines(True),
            fan_out_threshold=2,
            warning_policy=policy,
        )

        codes = {
            warning["code"] for warning in store.run_detail("demo-trace")["warnings"]
            if warning.get("active", True)
        }

        self.assertNotIn("LOOP", codes)
        self.assertIn("HIGH_FAN_OUT", codes)

    def test_import_examples_match_their_selected_sources(self):
        imported_otel = parse_otlp_json(
            (EXAMPLES / "otel-traces.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(imported_otel.events), 2)
        self.assertEqual(imported_otel.errors, ())

        for filename, source in (
            ("claude-code-session.jsonl", "claude-code"),
            ("codex-session.jsonl", "codex"),
            ("opencode-session.json", "opencode"),
        ):
            with self.subTest(source=source):
                imported = import_session(
                    (EXAMPLES / filename).read_text(encoding="utf-8")
                )
                self.assertEqual(imported.source, source)
                self.assertTrue(imported.events)
                self.assertEqual(imported.errors, ())

    def test_comparison_examples_have_a_supported_divergence(self):
        report = compare_paths(
            EXAMPLES / "compare-run-a.jsonl",
            EXAMPLES / "compare-run-b.jsonl",
        )

        self.assertIn("Earliest supported divergence", report)
        self.assertIn("src/cache.py", report)
        self.assertIn("src/summary.txt", report)

    def test_readme_references_every_curated_example(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        example_files = sorted(
            path.name for path in EXAMPLES.iterdir() if path.is_file()
        )

        for filename in example_files:
            with self.subTest(filename=filename):
                self.assertIn(f"examples/{filename}", readme)

        compile(
            (EXAMPLES / "langgraph-demo.py").read_text(encoding="utf-8"),
            "examples/langgraph-demo.py",
            "exec",
        )

    def test_langgraph_demo_has_no_import_time_file_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unexpected.jsonl"
            with patch("sys.argv", ["langgraph-demo.py", str(output)]):
                runpy.run_path(
                    str(EXAMPLES / "langgraph-demo.py"),
                    run_name="agent_tail_example_import",
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
