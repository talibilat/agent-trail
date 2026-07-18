import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.performance_fixture import (
    DEFAULT_BUDGET_BYTES,
    HIGH_BUDGET_BYTES,
    expected_totals,
    write_fixture,
)


TIME_LIMIT_SECONDS = 10.0
RSS_LIMIT_BYTES = 512 * 1024 * 1024


class PerformanceEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.source = Path(cls.temporary_directory.name, "performance-10k.jsonl")
        write_fixture(cls.source)

    @classmethod
    def tearDownClass(cls):
        cls.temporary_directory.cleanup()

    def measure(self, max_bytes: int) -> dict[str, object]:
        worker = Path(__file__).with_name("performance_worker.py")
        result = subprocess.run(
            [sys.executable, str(worker), str(self.source), str(max_bytes)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_generator_is_byte_stable(self):
        second = Path(self.temporary_directory.name, "performance-10k-second.jsonl")
        write_fixture(second)

        self.assertEqual(self.source.read_bytes(), second.read_bytes())
        self.assertEqual(expected_totals()["event_count"], 10_000)
        self.assertEqual(expected_totals()["actor_count"], 100)

    def test_retained_process_boundary_envelope(self):
        measured = self.measure(HIGH_BUDGET_BYTES)
        expected = expected_totals()
        print("retained performance envelope: " + json.dumps(measured, sort_keys=True))

        self.assertLess(measured["timings"]["total_seconds"], TIME_LIMIT_SECONDS)
        self.assertLess(measured["peak_rss_bytes"], RSS_LIMIT_BYTES)
        self.assertEqual(measured["retained_event_count"], expected["event_count"])
        self.assertEqual(measured["retained_unique_event_count"], expected["event_count"])
        self.assertEqual(measured["actor_count"], expected["actor_count"])
        self.assertEqual(measured["run_list_event_count"], expected["event_count"])
        for field in ("input_tokens", "output_tokens", "total_tokens"):
            self.assertTrue(measured["usage"][field]["available"])
            self.assertEqual(measured["usage"][field]["value"], expected[field])
        self.assertGreater(measured["uncertain_event_count"], 0)
        self.assertIn("ORPHAN", measured["warning_codes"])
        self.assertEqual(measured["change_count"], expected["change_count"])
        self.assertEqual(
            measured["resolved_evidence_link_count"],
            expected["resolved_evidence_link_count"],
        )

    def test_default_budget_eviction_remains_responsive_and_truthful(self):
        measured = self.measure(DEFAULT_BUDGET_BYTES)
        print("default-budget performance envelope: " + json.dumps(measured, sort_keys=True))

        self.assertLess(measured["timings"]["total_seconds"], TIME_LIMIT_SECONDS)
        self.assertLess(measured["peak_rss_bytes"], RSS_LIMIT_BYTES)
        self.assertGreater(measured["retained_event_count"], 0)
        self.assertLessEqual(measured["retained_event_count"], 10_000)
        self.assertEqual(
            measured["retained_event_count"], measured["retained_unique_event_count"]
        )
        self.assertGreater(
            measured["evicted_metadata_count"] + measured["evicted_payload_count"], 0
        )
        self.assertIn("EVICT", measured["warning_codes"])
        self.assertTrue(measured["payload_detail_safe"])


if __name__ == "__main__":
    unittest.main()
