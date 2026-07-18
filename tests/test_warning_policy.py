import json
from pathlib import Path
import tempfile
import unittest

from agent_tail.core import Event, TraceIndex
from agent_tail.serve import RunStore
from agent_tail.warning_policy import WarningPolicyError, load_warning_policy


FIXTURE = Path(__file__).parent / "fixtures" / "warning-policy.toml"


def event_data(sequence, name, *, failed=False, event_id=None, payload=None):
    status = "failed" if failed else "running"
    return {
        "schema_version": "1.0",
        "event_id": event_id or f"{name}-{sequence}",
        "trace_id": "trace-1",
        "span_id": event_id or f"{name}-{sequence}",
        "emitter_id": f"emitter-{name}",
        "sequence": sequence,
        "timestamp": f"2026-07-13T11:02:{sequence:02d}Z",
        "kind": f"tool.call.{'failed' if failed else 'started'}",
        "actor": {"id": f"actor-{name}"},
        "operation": {"status": status, "name": name},
        "attributes": {"arguments": {"path": "same"}},
        **({"payload": payload} if payload is not None else {}),
    }


class WarningPolicyTests(unittest.TestCase):
    def test_fixture_applies_per_tool_thresholds_and_visible_suppression(self):
        policy = load_warning_policy(FIXTURE)
        index = TraceIndex(warning_policy=policy)
        for sequence in range(1, 5):
            index.add(Event.from_dict(event_data(sequence, "poll_status")))
        for sequence in range(1, 4):
            index.add(Event.from_dict(event_data(sequence, "read_expected", failed=True)))
            index.add(Event.from_dict(event_data(sequence, "flaky_api", failed=True)))
            index.add(Event.from_dict(event_data(sequence, "unrelated", failed=True)))

        analysis = index.warning_analysis(now="2026-07-13T11:02:10Z")
        active = {(warning.code, warning.actor_id) for warning in analysis.warnings}

        self.assertNotIn(("LOOP", "actor-poll_status"), active)
        self.assertNotIn(("RETRY", "actor-read_expected"), active)
        self.assertNotIn(("RETRY", "actor-flaky_api"), active)
        self.assertIn(("RETRY", "actor-unrelated"), active)
        self.assertEqual(
            [(warning.code, warning.actor_id) for warning in analysis.suppressed],
            [("RETRY", "actor-flaky_api")],
        )
        projection = index.warning_policy_projection(now="2026-07-13T11:02:10Z")
        self.assertEqual(projection["version"], 1)
        self.assertEqual(projection["suppressed_counts"]["total"], 1)
        self.assertTrue(projection["restart_required"])

    def test_matching_is_exact_nonblank_and_ignores_payload_text(self):
        policy = load_warning_policy(FIXTURE)
        for position, name in enumerate(
            ("POLL_STATUS", "poll", "poll_status_suffix", "", None),
            1,
        ):
            with self.subTest(name=name):
                index = TraceIndex(warning_policy=policy)
                for sequence in range(1, 5):
                    data = event_data(
                        sequence,
                        "other",
                        event_id=f"{position}-{sequence}",
                        payload={"operation": {"name": "poll_status"}},
                    )
                    data["operation"]["name"] = name
                    index.add(Event.from_dict(data))
                self.assertIn("LOOP", {warning.code for warning in index.warnings()})

    def test_policy_and_default_results_are_deterministic(self):
        lines = [json.dumps(event_data(sequence, "flaky_api", failed=True)) + "\n" for sequence in range(1, 4)]
        first = RunStore.from_lines(lines, warning_policy=load_warning_policy(FIXTURE))
        second = RunStore.from_lines(lines, warning_policy=load_warning_policy(FIXTURE))
        self.assertEqual(first.run_detail("trace-1"), second.run_detail("trace-1"))

        default = TraceIndex()
        explicit_defaults = TraceIndex(loop_threshold=4, retry_threshold=3)
        for sequence in range(1, 5):
            event = Event.from_dict(event_data(sequence, "flaky_api", failed=True))
            default.add(event)
            explicit_defaults.add(event)
        self.assertEqual(default.warnings(), explicit_defaults.warnings())

    def test_rejects_complete_malformed_policy_surface(self):
        invalid = (
            "version = 2\n",
            "version = '1'\n",
            "version = 1\nunknown = true\n",
            "version = 1\ntools = 'bad'\n",
            "version = 1\n[[tools]]\nname = 1\nsuppress = ['LOOP']\n",
            "version = 1\n[[tools]]\nname = '   '\nsuppress = ['LOOP']\n",
            "version = 1\n[[tools]]\nname = 'x'\nloop_threshold = true\n",
            "version = 1\n[[tools]]\nname = 'x'\nretry_threshold = 2\n",
            "version = 1\n[[tools]]\nname = 'x'\nsuppress = ['STALL']\n",
            "version = 1\n[[tools]]\nname = 'x'\nsuppress = 'LOOP'\n",
            "version = 1\n[[tools]]\nname = 'x'\nsuppress = ['LOOP', 'LOOP']\n",
            "version = 1\n[[tools]]\nname = 'x'\nsuppress = ['LOOP']\n[[tools]]\nname = 'x'\nretry_threshold = 3\n",
            "version = 1\n[[tools]]\nname = 'x'\nextra = 1\n",
            "version = 1\n[[tools]]\nname = 'x'\n",
            "version = 1\n[[tools]\nname = 'secret file body'\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "policy.toml")
            for content in invalid:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises(WarningPolicyError):
                        load_warning_policy(path)


if __name__ == "__main__":
    unittest.main()
