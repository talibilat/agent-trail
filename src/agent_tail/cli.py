import argparse
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import sys
from typing import Iterable, TextIO
import unicodedata

from .core import IngestionError, JSONLReader, TraceIndex, redact_text, sanitize_event
from .ui import render_snapshot, run


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail")
    result.add_argument("input", help="JSONL file or - for standard input")
    result.add_argument("--export", metavar="PATH")
    result.add_argument("--full-payloads", action="store_true")
    result.add_argument("--unsafe-unredacted", action="store_true")
    result.add_argument("--loop-threshold", type=int, default=4)
    result.add_argument("--stall-seconds", type=float, default=30.0)
    result.add_argument("--max-bytes", type=_positive_int, default=16 * 1024 * 1024)
    result.add_argument(
        "--snapshot-stream", action="store_true", help=argparse.SUPPRESS
    )
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.snapshot_stream and arguments.input != "-":
        parser().error("--snapshot-stream requires standard input")

    source: TextIO
    close_source = False
    if arguments.input == "-":
        source = sys.stdin
    else:
        try:
            source = open(arguments.input, encoding="utf-8")
            close_source = True
        except OSError as error:
            print(f"agent-tail: {arguments.input}: {error.strerror}", file=sys.stderr)
            return 2

    reader = JSONLReader(retain_events=False)

    def events():
        for line in source:
            event = reader.feed(line)
            if event is not None:
                yield sanitize_event(
                    event,
                    full_payloads=arguments.full_payloads,
                    unsafe_unredacted=arguments.unsafe_unredacted,
                )

    try:
        reader_error = None
        index = TraceIndex(
            loop_threshold=arguments.loop_threshold,
            stall_seconds=arguments.stall_seconds,
            max_bytes=arguments.max_bytes,
        )
        if arguments.snapshot_stream:
            for event in events():
                index.add(event)
                print(
                    f"SNAPSHOT {index.event_count} {event.actor['id']} {event.event_id}",
                    flush=True,
                )
        elif arguments.export:
            for event in events():
                index.add(event)
            Path(arguments.export).write_text(
                _markdown(index, reader.all_errors), encoding="utf-8"
            )
        elif sys.stdout.isatty():
            if arguments.input == "-":
                reader_error = run(index, events())
            else:
                for event in events():
                    index.add(event)
                run(index)
        else:
            for event in events():
                index.add(event)
            print(render_snapshot(index, width=120))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"agent-tail: {error}", file=sys.stderr)
        return 2
    finally:
        if close_source:
            source.close()

    if reader_error is not None:
        message = redact_text(str(reader_error).splitlines()[0])
        print(f"agent-tail: reader failed: {message}", file=sys.stderr)
        return 2
    _print_errors(reader.all_errors)
    return 0 if reader.accepted_count else 1


def _print_errors(errors: Iterable[IngestionError]) -> None:
    for error in errors:
        prefix = f"line {error.line}: " if error.line is not None else ""
        print(prefix + error.message, file=sys.stderr)


def _markdown(index: TraceIndex, errors: Iterable[IngestionError]) -> str:
    events = index.events
    now = max(
        (event.timestamp for event in events),
        default=datetime.fromtimestamp(0, timezone.utc),
    )
    warnings = index.warnings(now=now)
    lines = [
        "# Agent Tail Trace Report",
        "",
        "Redaction ruleset: `1`",
        "",
    ]

    for trace_id in dict.fromkeys(event.trace_id for event in events):
        view = index.trace(trace_id)
        trace_events = view.events
        lines.extend((
            f"## Trace `{_markdown_text(trace_id)}`",
            "",
            f"- Events: {len(trace_events)}",
            f"- Started: `{min(event.timestamp for event in trace_events).isoformat()}`",
            f"- Ended: `{max(event.timestamp for event in trace_events).isoformat()}`",
            "- Emitters: " + ", ".join(
                f"`{_markdown_text(emitter)}`"
                for emitter in dict.fromkeys(event.emitter_id for event in trace_events)
            ),
            "- Schema versions: " + ", ".join(
                f"`{_markdown_text(version)}`"
                for version in dict.fromkeys(event.schema_version for event in trace_events)
            ),
            "",
            "### Actor states",
            "",
            "| Actor | Status | Last event | Open spans | Uncertainty |",
            "| --- | --- | --- | --- | --- |",
        ))
        for actor_id, actor in view.actors.items():
            lines.append(
                f"| {_markdown_text(actor_id)} | {_markdown_text(actor.status)} | "
                f"{_markdown_text(actor.last_activity_event_id)} | "
                f"{_markdown_text(', '.join(actor.open_span_ids) or 'none')} | "
                f"{'uncertain' if actor.uncertain else 'causal'} |"
            )

        lines.extend((
            "",
            "### Ordered timeline",
            "",
            "| Event | Time | Actor | Kind | Span | Order | Payload retention |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ))
        for event in trace_events:
            lines.append(
                f"| {_markdown_text(event.event_id)} | `{event.timestamp.isoformat()}` | "
                f"{_markdown_text(event.actor['id'])} | {_markdown_text(event.kind)} | "
                f"{_markdown_text(event.span_id)} | "
                f"{'uncertain' if event.event_id in view.uncertain_event_ids else 'causal'} | "
                f"{_payload_retention(event.raw.get('payload'))} |"
            )
        lines.append("")

    lines.extend(("## Warnings", ""))
    if warnings:
        for warning in warnings:
            lines.extend((
                f"### {warning.code}: {_markdown_text(warning.summary)}",
                "",
                f"- Event: `{_markdown_text(warning.event_id)}`",
                f"- Actor: `{_markdown_text(warning.actor_id)}`",
                f"- Evidence: `{_markdown_text(warning.evidence)}`",
                "",
            ))
    else:
        lines.extend(("None.", ""))

    lines.extend(("## Ingestion errors", ""))
    error_list = list(errors)
    if error_list:
        lines.extend(
            (f"- Line {error.line}: " if error.line is not None else "- ")
            + _markdown_text(error.message)
            for error in error_list
        )
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def _payload_retention(payload: object) -> str:
    if payload is None:
        return "none"
    if not isinstance(payload, dict):
        return "retained"
    metadata = payload.get("_agent_tail")
    if set(payload) == {"_agent_tail"}:
        return "evicted"
    if isinstance(metadata, dict) and metadata.get("truncated"):
        return "truncated"
    return "retained"


def _markdown_text(value: object) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    value = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    value = html.escape(value, quote=False)
    value = value.translate(str.maketrans({
        "\\": "&#92;",
        "|": "&#124;",
        "`": "&#96;",
        "*": "&#42;",
        "_": "&#95;",
        "#": "&#35;",
        "!": "&#33;",
        ">": "&#62;",
        "~": "&#126;",
    }))
    value = re.sub(r"](?=\s*\()", "&#93;", value)
    value = re.sub(
        r"^(\s*)([-+])(?=\s)",
        lambda match: match.group(1) + f"&#{ord(match.group(2))};",
        value,
    )
    return re.sub(r"^(\s*\d+)\.(?=\s)", r"\1&#46;", value)
