from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import html
import json
from pathlib import Path
import re
from typing import Iterable, Mapping
import unicodedata

from .core import Event, IngestionError, JSONLReader, TraceIndex, sanitize_event
from .serve import (
    _context_provenance,
    _event_evidence,
    _human_correction,
    _normalized_repository_path,
    _relationships,
    _usage_summary,
    _verification_result,
)


_USAGE_FIELDS = ("input_tokens", "output_tokens", "total_tokens", "cost_usd")


@dataclass(frozen=True)
class SemanticRecord:
    key: str
    summary: str
    event_id: str | None


@dataclass
class ComparedRun:
    index: TraceIndex
    trace_id: str
    records: list[SemanticRecord]
    predecessors: list[set[int]]
    integrity: Counter[str]
    usage: dict[str, object]
    actor_count: int
    warning_count: int
    change_count: int
    accepted_count: int


def load_run(path: Path) -> ComparedRun:
    reader = JSONLReader(retain_events=False)
    index = TraceIndex(max_bytes=1 << 63)
    with path.open(encoding="utf-8") as source:
        for line in source:
            event = reader.feed(line)
            if event is not None:
                index.add(sanitize_event(event))
    trace_ids = sorted({event.trace_id for event in index.events})
    if len(trace_ids) != 1:
        raise ValueError(
            f"{path}: expected exactly one retained trace, found {len(trace_ids)}"
        )
    return _semantic_run(index, trace_ids[0], reader.all_errors, reader.accepted_count)


def compare_paths(path_a: Path, path_b: Path) -> str:
    return render_comparison(load_run(path_a), load_run(path_b))


def _semantic_run(
    index: TraceIndex,
    trace_id: str,
    errors: Iterable[IngestionError],
    accepted_count: int,
) -> ComparedRun:
    view = index.trace(trace_id)
    events = list(view.events)
    events_by_id = {event.event_id: event for event in events}
    projection = _relationships(view)
    provenance = _context_provenance(view)
    evidence = _event_evidence(events)
    now = max(event.timestamp for event in events)
    warnings = [warning for warning in index.warnings(now=now) if warning.trace_id == trace_id]
    records: list[SemanticRecord] = []
    integrity: Counter[str] = Counter()

    def add(category: str, detail: object, event_id: str | None = None) -> None:
        normalized = _json(detail)
        records.append(SemanticRecord(
            f"{category}:{normalized}",
            f"{category}: {normalized}",
            event_id,
        ))

    first_actor_event: dict[str, str] = {}
    for event in events:
        first_actor_event.setdefault(str(event.actor["id"]), event.event_id)
    for actor_id in sorted(view.actors):
        add(
            "actor",
            {"id": actor_id, "parent_id": projection["parents"].get(actor_id)},
            first_actor_event[actor_id],
        )

    provenance_by_id = provenance["by_event_id"]
    for event in events:
        entry = provenance_by_id.get(event.event_id)
        if event.kind == "context.read" and isinstance(entry, dict):
            locator = entry.get("locator", {})
            if (
                isinstance(locator, dict)
                and isinstance(locator.get("normalized_path"), str)
                and not entry.get("diagnostics")
            ):
                add("read", {
                    "actor_id": event.actor["id"],
                    "locator": _without(locator, "raw_path"),
                    "content_sha256": entry.get("content_sha256"),
                    "repository": entry.get("repository"),
                }, event.event_id)
        elif event.kind == "context.search" and isinstance(entry, dict):
            if isinstance(entry.get("query"), str) and not entry.get("diagnostics"):
                add("search", {
                    "actor_id": event.actor["id"],
                    "query": entry["query"].strip(),
                    "matches": entry.get("canonical_matches", []),
                    "repository": entry.get("repository"),
                }, event.event_id)

        if event.kind.startswith("tool.call."):
            add("operation", {
                "signature": json.loads(index._signature(event)),
                "state": json.loads(index._state(event)),
                "status": event.operation["status"],
            }, event.event_id)

        if event.kind == "verification.finished":
            result = _verification_result(event, events_by_id)
            if result is not None:
                add("verification", {
                    "actor_id": event.actor["id"],
                    **_without(result, "starts", "unresolved"),
                    "command_available": isinstance(result.get("command"), str),
                }, event.event_id)
                for unresolved in result.get("unresolved", []):
                    integrity[_integrity_key("verification", unresolved)] += 1
            else:
                integrity["verification:invalid_verification_result"] += 1

        event_usage = _usage_summary((event,))
        if any(event_usage[field]["available"] for field in _USAGE_FIELDS):
            add("usage", {
                "actor_id": event.actor["id"],
                **event_usage,
            }, event.event_id)

    change_by_event_id = {}
    for change in evidence["changes"]:
        event_id = str(change["event_id"])
        hunk = dict(change["hunk"])
        path, reason = _normalized_repository_path(hunk.get("path"))
        if path is None or reason is not None:
            integrity[f"change:{reason or 'invalid_repository_path'}"] += 1
            continue
        hunk["path"] = path
        detail = {"actor_id": change["actor_id"], "hunk": hunk}
        change_by_event_id[event_id] = detail
        add("change", detail, event_id)
    for invalid in evidence["invalid_changes"]:
        for item in invalid.get("integrity", []):
            integrity[_integrity_key("change", item)] += 1

    for event in events:
        correction = _human_correction(event)
        if correction is None:
            if event.kind == "human.corrected":
                integrity["correction:invalid_correction_detail"] += 1
            continue
        targets = [
            change_by_event_id.get(relationship.event_id)
            for relationship in event.relationships
            if relationship.type == "corrects"
        ]
        valid_targets = [target for target in targets if target is not None]
        if valid_targets:
            for target in valid_targets:
                add("correction", {
                    "actor_id": event.actor["id"],
                    "action": correction["action"],
                    "change": target,
                }, event.event_id)
        else:
            integrity["correction:invalid_correction_target"] += 1

    for warning in warnings:
        add("warning", {"actor_id": warning.actor_id, "code": warning.code}, warning.event_id)
    for warning in projection["warnings"]:
        add("warning", {
            "actor_id": warning.get("actor_id"),
            "code": warning.get("code"),
        }, warning.get("event_id"))

    for error in errors:
        integrity[_ingestion_key(error.message)] += 1
    for diagnostic in provenance["diagnostics"]:
        integrity[_integrity_key("context", diagnostic)] += 1
    for unresolved in evidence["unresolved"]:
        if unresolved.get("reason"):
            integrity[_integrity_key("evidence", unresolved)] += 1

    event_record_indices: dict[str, list[int]] = {}
    for position, record in enumerate(records):
        if record.event_id is not None:
            event_record_indices.setdefault(record.event_id, []).append(position)
    predecessors = [set() for _ in records]
    incoming: dict[str, set[str]] = {event.event_id: set() for event in events}
    emitters: dict[str, dict[int, list[Event]]] = {}
    for event in events:
        emitters.setdefault(event.emitter_id, {}).setdefault(event.sequence, []).append(event)
    for sequence_groups in emitters.values():
        sequences = sorted(sequence_groups)
        for lower, higher in zip(sequences, sequences[1:]):
            for after in sequence_groups[higher]:
                incoming[after.event_id].update(
                    before.event_id for before in sequence_groups[lower]
                )
    spans: dict[str, list[Event]] = {}
    for event in events:
        spans.setdefault(event.span_id, []).append(event)
    for event in events:
        starts = [
            parent for parent in spans.get(event.parent_span_id or "", ())
            if parent.kind.endswith(".started")
        ]
        incoming[event.event_id].update(parent.event_id for parent in starts)

    semantic_frontier: dict[str, set[int]] = {}
    for event in events:
        prior = set().union(
            *(semantic_frontier.get(event_id, set()) for event_id in incoming[event.event_id])
        )
        positions = event_record_indices.get(event.event_id, [])
        for position in positions:
            predecessors[position].update(prior)
        semantic_frontier[event.event_id] = set(positions) if positions else prior

    return ComparedRun(
        index=index,
        trace_id=trace_id,
        records=records,
        predecessors=predecessors,
        integrity=integrity,
        usage=_usage_summary(events),
        actor_count=len(view.actors),
        warning_count=len(warnings) + len(projection["warnings"]),
        change_count=len(evidence["changes"]),
        accepted_count=accepted_count,
    )


def render_comparison(run_a: ComparedRun, run_b: ComparedRun) -> str:
    facts_a = Counter(record.key for record in run_a.records)
    facts_b = Counter(record.key for record in run_b.records)
    removed = facts_a - facts_b
    added = facts_b - facts_a
    divergence = _divergence(run_a, run_b)
    lines = [
        "# AgentTrail Run Comparison",
        "",
        "Comparison is factual and local; it is not exact replay or a quality judgment.",
        "",
        "## Run Summaries",
        "",
        "| Run | Events | Actors | Semantic facts | Warnings | Valid changes | Integrity findings |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        _summary_row("A", run_a),
        _summary_row("B", run_b),
        "",
        "## Changed Totals",
        "",
        "| Total | Run A | Run B |",
        "| --- | ---: | ---: |",
    ]
    for label, value_a, value_b in (
        ("events", run_a.accepted_count, run_b.accepted_count),
        ("actors", run_a.actor_count, run_b.actor_count),
        ("semantic facts", len(run_a.records), len(run_b.records)),
        ("warnings", run_a.warning_count, run_b.warning_count),
        ("valid changes", run_a.change_count, run_b.change_count),
        ("integrity findings", sum(run_a.integrity.values()), sum(run_b.integrity.values())),
    ):
        lines.append(f"| {label} | {value_a} | {value_b} |")
    for field in _USAGE_FIELDS:
        lines.append(
            f"| {_markdown(field)} | {_usage_text(run_a.usage[field])} | "
            f"{_usage_text(run_b.usage[field])} |"
        )
    lines.extend(("", "## Added Facts", ""))
    lines.extend(_counter_lines(added) or ["None."])
    lines.extend(("", "## Removed Facts", ""))
    lines.extend(_counter_lines(removed) or ["None."])
    lines.extend(("", "## Integrity Differences", ""))
    integrity_removed = run_a.integrity - run_b.integrity
    integrity_added = run_b.integrity - run_a.integrity
    if not integrity_added and not integrity_removed:
        lines.append("None.")
    else:
        lines.extend(
            f"- Run B added `{count} x {_markdown(key)}`"
            for key, count in sorted(integrity_added.items())
        )
        lines.extend(
            f"- Run B removed `{count} x {_markdown(key)}`"
            for key, count in sorted(integrity_removed.items())
        )
    lines.extend(("", "## Divergence Evidence", ""))
    lines.extend(divergence)
    lines.append("")
    return "\n".join(lines)


def _divergence(run_a: ComparedRun, run_b: ComparedRun) -> list[str]:
    remaining_a = set(range(len(run_a.records)))
    remaining_b = set(range(len(run_b.records)))
    while remaining_a or remaining_b:
        ready_a = _ready(remaining_a, run_a.predecessors)
        ready_b = _ready(remaining_b, run_b.predecessors)
        by_key_a = _positions_by_key(ready_a, run_a.records)
        by_key_b = _positions_by_key(ready_b, run_b.records)
        matched = False
        for key in sorted(by_key_a.keys() & by_key_b.keys()):
            count = min(len(by_key_a[key]), len(by_key_b[key]))
            remaining_a.difference_update(by_key_a[key][:count])
            remaining_b.difference_update(by_key_b[key][:count])
            matched = matched or count > 0
        if matched:
            continue
        if not ready_a and not ready_b:
            return ["No semantic divergence was found."]
        summaries_a = sorted(run_a.records[position].summary for position in ready_a)
        summaries_b = sorted(run_b.records[position].summary for position in ready_b)
        if len(summaries_a) == len(summaries_b) == 1:
            return [
                "Earliest supported divergence:",
                f"- Run A: `{_markdown(summaries_a[0])}`",
                f"- Run B: `{_markdown(summaries_b[0])}`",
            ]
        return [
            "Stable divergence frontier:",
            *[f"- Run A: `{_markdown(summary)}`" for summary in summaries_a],
            *[f"- Run B: `{_markdown(summary)}`" for summary in summaries_b],
        ]
    return ["No semantic divergence was found."]


def _ready(remaining: set[int], predecessors: list[set[int]]) -> list[int]:
    return sorted(position for position in remaining if not predecessors[position] & remaining)


def _positions_by_key(
    positions: Iterable[int], records: list[SemanticRecord]
) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for position in positions:
        result.setdefault(records[position].key, []).append(position)
    return result


def _summary_row(label: str, run: ComparedRun) -> str:
    return (
        f"| {label} | {run.accepted_count} | {run.actor_count} | {len(run.records)} | "
        f"{run.warning_count} | {run.change_count} | {sum(run.integrity.values())} |"
    )


def _counter_lines(counter: Counter[str]) -> list[str]:
    return [
        f"- `{count} x {_markdown(key)}`"
        for key, count in sorted(counter.items())
    ]


def _usage_text(field: object) -> str:
    if not isinstance(field, dict) or not field.get("available"):
        return "unavailable"
    return _markdown(field.get("value"))


def _without(value: Mapping[str, object], *keys: str) -> dict[str, object]:
    return {key: item for key, item in value.items() if key not in keys}


def _integrity_key(category: str, detail: object) -> str:
    if not isinstance(detail, Mapping):
        return f"{category}:malformed"
    reason = detail.get("reason") or detail.get("code") or "malformed"
    field = detail.get("field")
    return f"{category}:{reason}" + (f":{field}" if field is not None else "")


def _ingestion_key(message: str) -> str:
    if message.startswith("invalid JSON"):
        return "ingestion:invalid_json"
    if message.startswith("duplicate event ID"):
        return "ingestion:duplicate_event_id"
    return "ingestion:invalid_event:" + message


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _markdown(value: object) -> str:
    if not isinstance(value, str):
        value = _json(value)
    value = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    value = html.escape(value, quote=False).translate(str.maketrans({
        "\\": "&#92;", "|": "&#124;", "`": "&#96;", "*": "&#42;",
        "_": "&#95;", "#": "&#35;", "!": "&#33;", ">": "&#62;",
        "~": "&#126;",
    }))
    value = re.sub(r"](?=\s*\()", "&#93;", value)
    return value
