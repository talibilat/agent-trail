import argparse
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import sys
from typing import Iterable, TextIO
import unicodedata
import webbrowser

from .core import IngestionError, JSONLReader, TraceIndex, redact_text, sanitize_event
from .compare import compare_paths
from .html_export import normalize_generation_time, render_html, write_html_atomic
from .otel import OTLPDocumentError, canonical_jsonl as otel_jsonl, parse_otlp_json
from .review import ExportCandidate, review_export, write_bytes_atomic
from .security import security_projection
from .session_import import (
    SOURCES,
    SessionDocumentError,
    canonical_jsonl as session_jsonl,
    import_session,
)
from .serve import RunStore, ServeConfig, serve, serve_file
from .ui import render_snapshot, run
from .warning_policy import WarningPolicyError, load_warning_policy


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail")
    result.add_argument("input", help="JSONL file or - for standard input")
    exports = result.add_mutually_exclusive_group()
    exports.add_argument("--export", metavar="PATH")
    exports.add_argument("--export-html", metavar="PATH")
    result.add_argument("--export-html-generated-at", metavar="TIMESTAMP")
    result.add_argument("--review", action="store_true")
    result.add_argument("--open", action="store_true", dest="open_browser")
    result.add_argument("--review-timeout", type=float, default=600.0, metavar="SECONDS")
    result.add_argument("--full-payloads", action="store_true")
    result.add_argument("--metadata-only", action="store_true")
    result.add_argument("--unsafe-unredacted", action="store_true")
    result.add_argument("--loop-threshold", type=int, default=4)
    result.add_argument("--fan-out-threshold", type=_positive_int, default=8)
    result.add_argument("--warning-policy", metavar="PATH")
    result.add_argument("--stall-seconds", type=float, default=30.0)
    result.add_argument("--max-bytes", type=_positive_int, default=16 * 1024 * 1024)
    result.add_argument(
        "--snapshot-stream", action="store_true", help=argparse.SUPPRESS
    )
    return result


def serve_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail serve")
    result.add_argument("input", help="JSONL file or - for standard input")
    result.add_argument("--host", default="127.0.0.1")
    result.add_argument("--port", type=int, default=8765)
    result.add_argument("--open", action="store_true", dest="open_browser")
    result.add_argument("--remote-access", action="store_true")
    result.add_argument("--full-payloads", action="store_true")
    result.add_argument("--metadata-only", action="store_true")
    result.add_argument("--unsafe-unredacted", action="store_true")
    result.add_argument("--loop-threshold", type=int, default=4)
    result.add_argument("--fan-out-threshold", type=_positive_int, default=8)
    result.add_argument("--warning-policy", metavar="PATH")
    result.add_argument("--stall-seconds", type=float, default=30.0)
    result.add_argument("--max-bytes", type=_positive_int, default=16 * 1024 * 1024)
    result.add_argument("--max-live-updates", type=_positive_int, default=10_000)
    return result


def otel_import_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail import otel")
    result.add_argument("input", metavar="INPUT", help="OTLP JSON file or - for standard input")
    result.add_argument(
        "--output", required=True, metavar="OUTPUT", help="canonical JSONL file or - for standard output"
    )
    return result


def session_import_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail import session")
    result.add_argument("input", metavar="INPUT", help="session JSON or JSONL file or - for standard input")
    result.add_argument(
        "--source", choices=("auto", *SOURCES), default="auto",
        help="source format (default: auto)",
    )
    result.add_argument(
        "--output", required=True, metavar="OUTPUT",
        help="canonical JSONL file or - for standard output",
    )
    return result


def compare_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail compare")
    result.add_argument("run_a", metavar="RUN_A.jsonl")
    result.add_argument("run_b", metavar="RUN_B.jsonl")
    return result


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["serve"]:
        return _serve_main(argv[1:])
    if argv[:1] == ["compare"]:
        return _compare_main(argv[1:])
    if argv[:2] == ["import", "otel"]:
        return _otel_import_main(argv[2:])
    if argv[:2] == ["import", "session"]:
        return _session_import_main(argv[2:])

    argument_parser = parser()
    arguments = argument_parser.parse_args(argv)
    if arguments.snapshot_stream and arguments.input != "-":
        argument_parser.error("--snapshot-stream requires standard input")
    if arguments.export_html_generated_at and not arguments.export_html:
        argument_parser.error("--export-html-generated-at requires --export-html")
    if arguments.review and not (arguments.export or arguments.export_html):
        argument_parser.error("--review requires --export or --export-html")
    if arguments.open_browser and not arguments.review:
        argument_parser.error("--open requires --review")
    if arguments.review_timeout <= 0:
        argument_parser.error("--review-timeout must be positive")
    if arguments.metadata_only and arguments.full_payloads:
        argument_parser.error("--metadata-only cannot be combined with --full-payloads")
    try:
        generated_at = (
            normalize_generation_time(arguments.export_html_generated_at)
            if arguments.export_html_generated_at
            else None
        )
    except ValueError as error:
        argument_parser.error(str(error))

    try:
        warning_policy = (
            load_warning_policy(arguments.warning_policy)
            if arguments.warning_policy
            else None
        )
    except WarningPolicyError as error:
        print(
            f"agent-tail: warning policy {redact_text(arguments.warning_policy)}: "
            f"{redact_text(str(error))}",
            file=sys.stderr,
        )
        return 2

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
                    metadata_only=arguments.metadata_only,
                    unsafe_unredacted=arguments.unsafe_unredacted,
                )

    try:
        reader_error = None
        index = TraceIndex(
            loop_threshold=arguments.loop_threshold,
            fan_out_threshold=arguments.fan_out_threshold,
            stall_seconds=arguments.stall_seconds,
            max_bytes=arguments.max_bytes,
            warning_policy=warning_policy,
        )
        if arguments.snapshot_stream:
            for event in events():
                index.add(event)
                print(
                    f"SNAPSHOT {index.event_count} {event.actor['id']} {event.event_id}",
                    flush=True,
                )
        elif arguments.export or arguments.export_html:
            for event in events():
                index.add(event)
            if arguments.export:
                destination = Path(arguments.export)
                content = _markdown(
                    index,
                    reader.all_errors,
                    metadata_only=arguments.metadata_only,
                )
                export_format = "Markdown"
            else:
                destination = Path(arguments.export_html)
                content = render_html(
                    index,
                    reader.all_errors,
                    generated_at=generated_at,
                    metadata_only=arguments.metadata_only,
                )
                export_format = "HTML"
            if arguments.review:
                candidate = ExportCandidate.create(
                    content,
                    format=export_format,
                    destination=destination,
                )
                return review_export(
                    index,
                    reader.all_errors,
                    candidate,
                    metadata_only=arguments.metadata_only,
                    timeout=arguments.review_timeout,
                    open_browser=arguments.open_browser,
                    open_url=webbrowser.open,
                )
            if arguments.export:
                write_bytes_atomic(destination, content.encode("utf-8"))
            else:
                write_html_atomic(destination, content)
        elif sys.stdout.isatty():
            if arguments.input == "-":
                reader_error = run(
                    index,
                    events(),
                    metadata_only=arguments.metadata_only,
                )
            else:
                for event in events():
                    index.add(event)
                run(index, metadata_only=arguments.metadata_only)
        else:
            for event in events():
                index.add(event)
            print(render_snapshot(
                index,
                width=120,
                metadata_only=arguments.metadata_only,
            ))
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


def _otel_import_main(argv: list[str]) -> int:
    argument_parser = otel_import_parser()
    arguments = argument_parser.parse_args(argv)
    if arguments.input == "-" and arguments.output == "-":
        argument_parser.error("INPUT and OUTPUT cannot both be standard streams")

    try:
        if arguments.input == "-":
            source = sys.stdin.read()
        else:
            source = Path(arguments.input).read_text(encoding="utf-8")
        imported = parse_otlp_json(source)
        output = otel_jsonl(imported)
        if arguments.output == "-":
            sys.stdout.write(output)
        else:
            Path(arguments.output).write_text(output, encoding="utf-8")
    except (OSError, UnicodeError, OTLPDocumentError) as error:
        print(f"agent-tail: {redact_text(str(error))}", file=sys.stderr)
        return 2

    _print_errors(imported.errors)
    return 0 if imported.events else 1


def _compare_main(argv: list[str]) -> int:
    arguments = compare_parser().parse_args(argv)
    try:
        sys.stdout.write(compare_paths(Path(arguments.run_a), Path(arguments.run_b)))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"agent-tail compare: {redact_text(str(error))}", file=sys.stderr)
        return 2
    return 0


def _session_import_main(argv: list[str]) -> int:
    argument_parser = session_import_parser()
    arguments = argument_parser.parse_args(argv)
    if arguments.input == "-" and arguments.output == "-":
        argument_parser.error("INPUT and OUTPUT cannot both be standard streams")

    try:
        source_text = (
            sys.stdin.read()
            if arguments.input == "-"
            else Path(arguments.input).read_text(encoding="utf-8")
        )
        imported = import_session(source_text, source=arguments.source)
        output = session_jsonl(imported)
        if arguments.output == "-":
            sys.stdout.write(output)
        else:
            Path(arguments.output).write_text(output, encoding="utf-8")
    except (OSError, UnicodeError, SessionDocumentError) as error:
        print(f"agent-tail: {redact_text(str(error))}", file=sys.stderr)
        return 2

    _print_errors(imported.errors)
    return 0 if imported.events else 1


def _serve_main(argv: list[str]) -> int:
    argument_parser = serve_parser()
    arguments = argument_parser.parse_args(argv)
    if arguments.port < 0 or arguments.port > 65535:
        argument_parser.error("--port must be between 0 and 65535")
    if arguments.metadata_only and arguments.full_payloads:
        argument_parser.error("--metadata-only cannot be combined with --full-payloads")

    try:
        warning_policy = (
            load_warning_policy(arguments.warning_policy)
            if arguments.warning_policy
            else None
        )
    except WarningPolicyError as error:
        print(
            f"agent-tail: warning policy {redact_text(arguments.warning_policy)}: "
            f"{redact_text(str(error))}",
            file=sys.stderr,
        )
        return 2

    config = ServeConfig(
        host=arguments.host,
        port=arguments.port,
        open_browser=arguments.open_browser,
        full_payloads=arguments.full_payloads,
        metadata_only=arguments.metadata_only,
        unsafe_unredacted=arguments.unsafe_unredacted,
        remote_access=arguments.remote_access,
        loop_threshold=arguments.loop_threshold,
        fan_out_threshold=arguments.fan_out_threshold,
        stall_seconds=arguments.stall_seconds,
        max_bytes=arguments.max_bytes,
        max_live_updates=arguments.max_live_updates,
        warning_policy=warning_policy,
    )
    try:
        if arguments.input == "-":
            return serve(sys.stdin, config=config, open_url=webbrowser.open)
        return serve_file(Path(arguments.input), config=config, open_url=webbrowser.open)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"agent-tail: {error}", file=sys.stderr)
        return 2


def _print_errors(errors: Iterable[IngestionError]) -> None:
    for error in errors:
        prefix = f"line {error.line}: " if error.line is not None else ""
        print(prefix + error.message, file=sys.stderr)


def _markdown(
    index: TraceIndex,
    errors: Iterable[IngestionError],
    *,
    metadata_only: bool = False,
) -> str:
    events = index.events
    error_list = list(errors)
    now = max(
        (event.timestamp for event in events),
        default=datetime.fromtimestamp(0, timezone.utc),
    )
    warnings = index.warnings(now=now)
    detail_store = RunStore(
        index,
        error_list,
        source_kind="export",
        metadata_only=metadata_only,
    )
    detail_store.set_source_status(connected=False, state="frozen")
    lines = [
        "# AgentTrail Trace Report",
        "",
        "Redaction ruleset: `1`",
    ]
    if metadata_only:
        lines.append("Payload mode: `metadata-only` (payload bodies omitted)")
    policy = index.warning_policy_projection(now=now)
    if policy is not None:
        lines.extend((
            f"Warning policy: `{_markdown_text(policy['path'])}` (version {policy['version']})",
            "Warning policy changes require a restart.",
            "Suppressed findings: "
            f"{policy['suppressed_counts']['total']} "
            f"(LOOP {policy['suppressed_counts']['by_code']['LOOP']}, "
            f"RETRY {policy['suppressed_counts']['by_code']['RETRY']})",
            "Effective warning rules: `"
            + _markdown_text(json.dumps(policy["rules"], sort_keys=True, separators=(",", ":")))
            + "`",
        ))
    lines.append("")

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

        detail = detail_store.run_detail(trace_id)
        if detail is not None:
            lines.extend(_markdown_outcome_cost(detail["outcome_cost"]))

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

    lines.extend(("## Security audit", ""))
    for trace_id in dict.fromkeys(event.trace_id for event in events):
        security = security_projection(
            index.trace(trace_id),
            evicted_event_ids=index.metadata_evictions(trace_id),
        )
        coverage = security["coverage"]
        lines.extend((
            f"### Trace `{_markdown_text(trace_id)}`",
            "",
            f"- Coverage: `{coverage['status']}`",
            f"- Result: `{coverage['result']}`",
            f"- Sensitive operations: {coverage['sensitive_operation_count']}",
            f"- Integrity issues: {coverage['integrity_issue_count']}",
            f"- Unresolved influence edges: {coverage['unresolved_edge_count']}",
            "- Coverage reasons: " + (
                ", ".join(
                    f"`{_markdown_text(reason)}`"
                    for reason in coverage["reasons"]
                )
                or "none"
            ),
            "",
        ))
        for finding in security["findings"]:
            path = next(
                item for item in security["paths"]
                if item["id"] == finding["path_id"]
            )
            event_path = " -> ".join(
                _markdown_text(item["event_id"]) for item in path["events"]
            )
            trust = ", ".join(
                f"{_markdown_text(item['event_id'])}="
                f"{_markdown_text(item['trust_origin'])} ({_markdown_text(item['risk'])})"
                for item in path["trust_origins"]
            ) or "none"
            lines.extend((
                f"#### {finding['code']}: {_markdown_text(finding['summary'])}",
                "",
                f"- Operation: `{_markdown_text(finding['operation_event_id'])}`",
                "- Capabilities: " + ", ".join(
                    f"`{_markdown_text(item)}`" for item in finding["capabilities"]
                ),
                f"- Influence path: `{event_path}`",
                f"- Trust evidence: {trust}",
                "",
            ))
        if security["integrity"]:
            lines.append("Integrity diagnostics:")
            lines.extend(
                "- `" + _markdown_text(json.dumps(
                    item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )) + "`"
                for item in security["integrity"]
            )
            lines.append("")

    lines.extend(("## Ingestion errors", ""))
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


def _markdown_outcome_cost(attribution: dict[str, object]) -> list[str]:
    lines = [
        "",
        "### Outcome cost attribution",
        "",
        "Usage is allocated in full to one valid hunk or equally across distinct valid hunks.",
        "Warning associations are non-exclusive and must not be summed.",
        "",
    ]

    def table(title: str, key: str, rows: Iterable[dict[str, object]]) -> None:
        lines.extend((
            f"#### {title}",
            "",
            f"| {key} | Input tokens | Output tokens | Total tokens | Cost USD |",
            "| --- | ---: | ---: | ---: | ---: |",
        ))
        for row in rows:
            usage = row["usage"]
            values = [
                _markdown_usage_value(usage[field])
                for field in ("input_tokens", "output_tokens", "total_tokens", "cost_usd")
            ]
            lines.append(
                f"| {_markdown_text(str(row[key]))} | " + " | ".join(values) + " |"
            )
        lines.append("")

    allocation = attribution["allocation"]
    table("Allocation", "bucket", [
        {"bucket": bucket, "usage": allocation[bucket]}
        for bucket in ("attributed", "pending", "unattributed")
    ])
    table("By actor", "actor_id", attribution["by_actor"])
    table("By operation", "operation", attribution["by_operation"])
    table("By warning code (non-exclusive)", "warning_code", attribution["by_warning_code"])
    table("By valid hunk", "hunk", [
        {
            "hunk": f"{row['change_event_id']} {row['hunk']['path']} "
            f"{row['observed_outcome']}",
            "usage": row["usage"],
        }
        for row in attribution["by_hunk"]
    ])
    return lines


def _markdown_usage_value(metric: dict[str, object]) -> str:
    if not metric["available"]:
        return "unavailable"
    return _markdown_text(str(metric["value"]))


def _payload_retention(payload: object) -> str:
    if payload is None:
        return "none"
    if not isinstance(payload, dict):
        return "retained"
    metadata = payload.get("_agent_tail")
    if isinstance(metadata, dict) and metadata.get("omitted") is True:
        return "omitted (metadata-only)"
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
