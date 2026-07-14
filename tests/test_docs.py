from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class ServeDocumentationTests(unittest.TestCase):
    def test_backend_readiness_report_is_standalone_and_complete(self):
        html = (ROOT / "docs" / "backend-readiness.html").read_text(encoding="utf-8")

        for text in (
            "Reused core behavior",
            "New serve-mode behavior",
            "Representative span per actor",
            "Fallback run titles",
            "Process-local run list",
            "No cross-restart history",
            "TraceIndex",
            "sanitize_event",
        ):
            with self.subTest(text=text):
                self.assertIn(text, html)
        self.assertIn("<!doctype html>", html.lower())
        self.assertNotIn("<script src=", html)
        self.assertNotIn("<link rel=", html)

    def test_integration_guide_documents_implemented_contracts(self):
        html = (ROOT / "docs" / "ui-backend-integration.html").read_text(
            encoding="utf-8"
        )

        for text in (
            "agent-tail serve",
            "/api/v1/runs",
            "/api/v1/events?cursor=N",
            "message.sent",
            "attributes.to",
            "input_tokens",
            "cost_usd",
            "actor.role",
            "actor.model",
            "AMBIGUOUS_PARENT",
            "Payload and redaction boundary",
        ):
            with self.subTest(text=text):
                self.assertIn(text, html)
        self.assertIn("<!doctype html>", html.lower())
        self.assertNotIn("<script src=", html)
        self.assertNotIn("<link rel=", html)


if __name__ == "__main__":
    unittest.main()
