from __future__ import annotations

import json
from pathlib import Path
import resource
import sys
import time

from agent_tail.serve import RunStore

from performance_fixture import TRACE_ID


def elapsed(started: float) -> float:
    return time.perf_counter() - started


def peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def main() -> None:
    source = Path(sys.argv[1])
    max_bytes = int(sys.argv[2])
    total_started = time.perf_counter()

    started = time.perf_counter()
    with source.open(encoding="utf-8") as lines:
        store = RunStore.from_lines(lines, max_bytes=max_bytes)
    ingestion_seconds = elapsed(started)

    started = time.perf_counter()
    runs = store.list_runs()
    run_list_seconds = elapsed(started)

    started = time.perf_counter()
    detail = store.run_detail(TRACE_ID)
    run_detail_seconds = elapsed(started)
    if detail is None:
        raise RuntimeError("performance trace was fully evicted")

    started = time.perf_counter()
    serialized = json.dumps(detail, ensure_ascii=False, sort_keys=True)
    serialization_seconds = elapsed(started)

    retained_ids = {event["event_id"] for event in detail["events"]}
    evicted_ids = [
        f"perf-event-{index:05d}"
        for index in range(10_000)
        if f"perf-event-{index:05d}" not in retained_ids
    ]
    evicted_payload_ids = [
        event["event_id"]
        for event in detail["events"]
        if isinstance(event.get("payload"), dict)
        and event["payload"].get("state") == "evicted"
    ]
    payload_detail_safe = all(
        store.event_payload(TRACE_ID, event_id)["payload"].get("state") == "evicted"
        for event_id in evicted_payload_ids[:10]
    ) and all(
        store.event_payload(TRACE_ID, event_id) is None for event_id in evicted_ids[:10]
    )
    warning_codes = sorted({warning["code"] for warning in detail["warnings"]})
    evidence = detail["evidence_map"]
    result = {
        "timings": {
            "ingestion_seconds": ingestion_seconds,
            "run_list_seconds": run_list_seconds,
            "run_detail_seconds": run_detail_seconds,
            "serialization_seconds": serialization_seconds,
            "total_seconds": elapsed(total_started),
        },
        "peak_rss_bytes": peak_rss_bytes(),
        "serialized_bytes": len(serialized.encode("utf-8")),
        "retained_event_count": len(detail["events"]),
        "retained_unique_event_count": len(retained_ids),
        "actor_count": detail["run"]["actor_count"],
        "usage": detail["usage"],
        "uncertain_event_count": detail["run"]["uncertain_event_count"],
        "warning_codes": warning_codes,
        "change_count": len(evidence["changes"]),
        "resolved_evidence_link_count": len(evidence["links"]),
        "evicted_metadata_count": len(evicted_ids),
        "evicted_payload_count": len(evicted_payload_ids),
        "payload_detail_safe": payload_detail_safe,
        "run_list_event_count": runs["runs"][0]["event_count"],
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
