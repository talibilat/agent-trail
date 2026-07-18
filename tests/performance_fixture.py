from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Iterator


EVENT_COUNT = 10_000
ACTOR_COUNT = 100
TRACE_ID = "performance-envelope-10k"
LATE_EVENT_ID = "perf-event-09999"
HIGH_BUDGET_BYTES = 64 * 1024 * 1024
DEFAULT_BUDGET_BYTES = 16 * 1024 * 1024


def expected_totals() -> dict[str, int]:
    full_input_cycles, input_remainder = divmod(EVENT_COUNT, 7)
    full_output_cycles, output_remainder = divmod(EVENT_COUNT, 5)
    input_tokens = full_input_cycles * sum(range(1, 8)) + sum(
        range(1, input_remainder + 1)
    )
    output_tokens = full_output_cycles * sum(range(5)) + sum(
        range(output_remainder)
    )
    return {
        "event_count": EVENT_COUNT,
        "actor_count": ACTOR_COUNT,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "change_count": 1,
        "resolved_evidence_link_count": 6,
    }


def events() -> Iterator[dict[str, object]]:
    base = datetime(2026, 7, 13, 11, 0, tzinfo=timezone.utc)
    for index in range(EVENT_COUNT):
        actor_number = index % ACTOR_COUNT
        actor_id = f"actor-{actor_number:03d}"
        local_sequence = index // ACTOR_COUNT
        timestamp_offset = index if index < 8 else 8 + (index - 8) // 2
        event = {
            "schema_version": "1.0",
            "event_id": f"perf-event-{index:05d}",
            "trace_id": TRACE_ID,
            "span_id": "root-span" if index == 0 else f"span-{index:05d}",
            "emitter_id": f"emitter-{actor_number:03d}",
            "sequence": local_sequence,
            "timestamp": (base + timedelta(seconds=timestamp_offset)).isoformat().replace(
                "+00:00", "Z"
            ),
            "kind": "activity.completed",
            "actor": {
                "id": actor_id,
                "role": "orchestrator" if index == 0 else "worker",
            },
            "operation": {
                "status": "completed",
                "name": f"activity-{local_sequence % 17:02d}",
            },
            "usage": {
                "input_tokens": index % 7 + 1,
                "output_tokens": index % 5,
                "total_tokens": index % 7 + 1 + index % 5,
            },
            "payload": {
                "result": f"deterministic-result-{index:05d}-" + "x" * 1200,
            },
        }
        if index == 0:
            event["kind"] = "agent.started"
            event["operation"] = {"status": "running", "name": "orchestrate"}
        elif actor_number != 0 and local_sequence == 0:
            event["parent_span_id"] = "root-span"
            event["kind"] = "agent.started"
            event["operation"] = {"status": "running", "name": "delegated-work"}
        elif local_sequence % 10 == 4:
            event["kind"] = "tool.call.completed"
            event["operation"] = {"status": "completed", "name": "shell"}
            event["attributes"] = {
                "tool": {
                    "command": f"check-component-{actor_number:03d}",
                    "result": "ok",
                    "exit_code": 0,
                }
            }

        if index == 1:
            event["kind"] = "requirement.observed"
            event["attributes"] = {
                "requirement": {
                    "id": "PERF-10K",
                    "text": "Keep a realistic 10,000-event run interactive.",
                }
            }
        elif index == 2:
            event["kind"] = "context.read"
            event["attributes"] = {
                "context": {"path": "src/agent_tail/serve.py", "line_start": 291}
            }
        elif index == 3:
            event["kind"] = "tool.call.completed"
            event["operation"] = {"status": "completed", "name": "profile"}
            event["attributes"] = {
                "tool": {"command": "python -m cProfile performance", "result": "captured"}
            }
        elif index == 4:
            event["kind"] = "change.proposed"
            event["actor"] = {"id": actor_id, "role": "planner"}
        elif index == 5:
            event["kind"] = "change.applied"
            event["attributes"] = {
                "change": {
                    "path": "src/agent_tail/core.py",
                    "old_start": 868,
                    "old_count": 3,
                    "new_start": 868,
                    "new_count": 4,
                    "symbol": "TraceIndex._evict",
                }
            }
            event["relationships"] = [
                {"type": "motivated_by", "event_id": "perf-event-00001"},
                {"type": "informed_by", "event_id": "perf-event-00002"},
                {"type": "preceded_by", "event_id": "perf-event-00003"},
                {"type": "applies", "event_id": "perf-event-00004"},
                {"type": "verified_by", "event_id": "perf-event-00007"},
            ]
        elif index == 6:
            event["kind"] = "verification.started"
            event["attributes"] = {
                "verification": {
                    "command": "python -m unittest tests.test_performance",
                    "test_origin": "pre_existing",
                }
            }
        elif index == 7:
            event["kind"] = "verification.finished"
            event["attributes"] = {
                "verification": {
                    "passed": True,
                    "exit_code": 0,
                    "test_origin": "pre_existing",
                }
            }
            event["relationships"] = [
                {"type": "completes", "event_id": "perf-event-00006"}
            ]
        elif index == 199:
            event["parent_span_id"] = "missing-performance-parent"

        yield event


def write_fixture(path: Path) -> None:
    with path.open("w", encoding="utf-8") as destination:
        for event in events():
            destination.write(
                json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )
