from copy import deepcopy
from typing import Mapping


def detect(text: str) -> bool:
    from ..session_import import parse_json_lines
    records = parse_json_lines(text)
    return bool(records) and any(
        isinstance(record, Mapping)
        and record.get("type") == "system"
        and record.get("subtype") == "init"
        and isinstance(record.get("sessionId"), str)
        for record in records
    )


def parse(text: str, max_errors: int):
    from ..session_import import (
        ParsedSession, SessionDocumentError, bounded_errors, diagnostic,
        non_blank, parse_json_lines,
    )
    source = parse_json_lines(text)
    init = next((record for record in source if isinstance(record, Mapping)
                 and record.get("type") == "system" and record.get("subtype") == "init"), None)
    if init is None:
        raise SessionDocumentError("unsupported claude-code format: missing system init record")
    version = init.get("session_format_version")
    if version != "1":
        raise SessionDocumentError(
            "unsupported claude-code session format version; supported: 1"
        )
    session_id = init.get("sessionId")
    if not non_blank(session_id):
        raise SessionDocumentError("malformed claude-code init record: sessionId is required")
    records, errors, omitted = [], [], 0
    for index, raw in enumerate(source):
        path = f"record[{index}]"
        try:
            record = _record(raw, index, session_id)
        except ValueError as error:
            if len(errors) < max_errors:
                errors.append(diagnostic(path, str(error)))
            else:
                omitted += 1
            continue
        if record is not None:
            records.append(record)
    return ParsedSession("claude-code", version, session_id, deepcopy(dict(init)), tuple(records), bounded_errors(errors, omitted, "claude-code"))


def _record(raw: object, index: int, session_id: str) -> dict[str, object] | None:
    from ..session_import import MalformedJSONLine, hunk, integer, non_blank, relationship_list, valid_timestamp
    if isinstance(raw, MalformedJSONLine):
        raise ValueError(raw.message)
    if not isinstance(raw, Mapping):
        raise ValueError("must be an object")
    if raw.get("type") == "system" and raw.get("subtype") == "init":
        return None
    if raw.get("sessionId") != session_id:
        raise ValueError("sessionId must match the init record")
    source_key = raw.get("uuid")
    if not non_blank(source_key):
        raise ValueError("uuid must be a non-blank string")
    timestamp = raw.get("timestamp")
    if not valid_timestamp(timestamp):
        raise ValueError("timestamp must be an ISO 8601 value with a timezone")
    record_type = raw.get("type")
    actor_id = raw.get("agentId") if non_blank(raw.get("agentId")) else record_type
    parent = raw.get("parentUuid") if non_blank(raw.get("parentUuid")) else None
    base = {"source_key": source_key, "timestamp": timestamp, "actor_id": actor_id,
            "emitter_id": actor_id, "parent_source_key": parent, "raw": deepcopy(dict(raw))}
    if record_type in {"user", "assistant"}:
        message = raw.get("message")
        if not isinstance(message, Mapping) or message.get("role") != record_type:
            raise ValueError("message role must match record type")
        base.update(kind="message.sent", status="success", name=record_type,
                    actor={"role": record_type}, attributes={"message": {"role": record_type, "content": deepcopy(message.get("content"))}})
        usage = message.get("usage")
        if isinstance(usage, Mapping):
            for source_name, target in (("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")):
                if integer(usage.get(source_name)) and usage[source_name] >= 0:
                    base["attributes"][target] = usage[source_name]
        return base
    if record_type == "tool_use":
        name = raw.get("name")
        if not non_blank(name):
            raise ValueError("tool name must be a non-blank string")
        attributes = {"arguments": deepcopy(raw.get("input"))}
        if non_blank(raw.get("command")):
            attributes["tool"] = {"command": raw["command"]}
        return {**base, "kind": "tool.call.started", "status": "running", "name": name, "attributes": attributes}
    if record_type == "tool_result":
        name = raw.get("name") if non_blank(raw.get("name")) else "tool"
        failed = raw.get("is_error") is True
        tool = {}
        if isinstance(raw.get("content"), str):
            tool["result"] = raw["content"]
        if integer(raw.get("exit_code")):
            tool["exit_code"] = raw["exit_code"]
        kind = "tool.call.failed" if failed else "tool.call.finished"
        return {**base, "kind": kind, "status": "failed" if failed else "success", "name": name, "attributes": {"tool": tool}}
    if record_type == "context_read" and non_blank(raw.get("path")):
        context = {"path": raw["path"]}
        for field in ("line_start", "line_end"):
            if integer(raw.get(field)) and raw[field] > 0:
                context[field] = raw[field]
        if non_blank(raw.get("symbol")):
            context["symbol"] = raw["symbol"]
        return {**base, "kind": "context.read", "status": "success", "name": "read", "attributes": {"context": context}}
    if record_type == "change":
        locator = hunk(raw.get("hunk"))
        if locator is None:
            return {**base, "kind": "tool.call.finished", "status": "success", "name": "edit", "attributes": {"arguments": deepcopy(raw.get("hunk"))}}
        return {**base, "kind": "change.applied", "status": "success", "name": "edit", "attributes": {"change": locator}, "relationships": relationship_list(raw.get("relationships"))}
    if record_type in {"verification_started", "verification_finished"}:
        return _verification(base, raw, record_type)
    if record_type in {"agent_start", "agent_stop"}:
        started = record_type == "agent_start"
        return {**base, "kind": "agent.started" if started else "agent.finished", "status": "running" if started else "success", "name": "agent", "attributes": {}}
    raise ValueError("type is not supported by the pinned format")


def _verification(base, raw, record_type):
    from ..session_import import integer, non_blank
    verification = {}
    if non_blank(raw.get("command")):
        verification["command"] = raw["command"]
    if record_type == "verification_started":
        if "command" not in verification:
            raise ValueError("verification start command must be non-blank")
        return {**base, "kind": "verification.started", "status": "running", "name": "test", "attributes": {"verification": verification}}
    if not isinstance(raw.get("passed"), bool):
        raise ValueError("verification result passed must be a boolean")
    verification["passed"] = raw["passed"]
    if integer(raw.get("exit_code")):
        verification["exit_code"] = raw["exit_code"]
    relationships = []
    if non_blank(raw.get("startUuid")):
        relationships.append({"type": "completes", "source_key": raw["startUuid"]})
    return {**base, "kind": "verification.finished", "status": "success" if raw["passed"] else "failed", "name": "test", "attributes": {"verification": verification}, "relationships": relationships}
