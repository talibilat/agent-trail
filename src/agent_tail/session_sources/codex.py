from copy import deepcopy
from typing import Mapping


def detect(text: str) -> bool:
    from ..session_import import parse_json_lines
    records = parse_json_lines(text)
    return bool(records) and isinstance(records[0], Mapping) and records[0].get("type") == "session_meta" and isinstance(records[0].get("payload"), Mapping)


def parse(text: str, max_errors: int):
    from ..session_import import ParsedSession, SessionDocumentError, bounded_errors, diagnostic, non_blank, parse_json_lines
    source = parse_json_lines(text)
    if source is None or not source or not isinstance(source[0], Mapping) or source[0].get("type") != "session_meta":
        raise SessionDocumentError("unsupported codex format: expected rollout JSONL beginning with session_meta")
    metadata = source[0].get("payload")
    if not isinstance(metadata, Mapping):
        raise SessionDocumentError("malformed codex session_meta: payload is required")
    version = metadata.get("format_version")
    if version != "1":
        raise SessionDocumentError("unsupported codex rollout format version; supported: 1")
    session_id = metadata.get("id")
    if not non_blank(session_id):
        raise SessionDocumentError("malformed codex session_meta: payload.id is required")
    records, errors, omitted = [], [], 0
    for index, raw in enumerate(source[1:], 1):
        try:
            record = _record(raw, index)
        except ValueError as error:
            if len(errors) < max_errors:
                errors.append(diagnostic(f"record[{index}]", str(error)))
            else:
                omitted += 1
            continue
        if record is not None:
            records.append(record)
    return ParsedSession("codex", version, session_id, deepcopy(dict(metadata)), tuple(records), bounded_errors(errors, omitted, "codex"))


def _record(raw: object, index: int) -> dict[str, object] | None:
    from ..session_import import MalformedJSONLine, hunk, integer, non_blank, relationship_list, valid_timestamp
    if isinstance(raw, MalformedJSONLine):
        raise ValueError(raw.message)
    if not isinstance(raw, Mapping) or not isinstance(raw.get("payload"), Mapping):
        raise ValueError("must contain an object payload")
    payload = raw["payload"]
    timestamp = raw.get("timestamp")
    if not valid_timestamp(timestamp):
        raise ValueError("timestamp must be an ISO 8601 value with a timezone")
    source_key = payload.get("id") if non_blank(payload.get("id")) else f"ordinal:{index}"
    actor_id = payload.get("agent_id") if non_blank(payload.get("agent_id")) else "codex"
    base = {"source_key": source_key, "timestamp": timestamp, "actor_id": actor_id, "emitter_id": actor_id,
            "parent_source_key": payload.get("parent_id") if non_blank(payload.get("parent_id")) else None,
            "raw": deepcopy(dict(raw))}
    record_type = raw.get("type")
    item_type = payload.get("type")
    if record_type == "response_item" and item_type == "message":
        role = payload.get("role")
        if role not in {"user", "assistant"}:
            raise ValueError("message role must be user or assistant")
        return {**base, "kind": "message.sent", "status": "success", "name": role, "actor": {"role": role}, "attributes": {"message": {"role": role, "content": deepcopy(payload.get("content"))}}}
    if record_type == "response_item" and item_type == "function_call":
        name = payload.get("name")
        if not non_blank(name):
            raise ValueError("function call name must be non-blank")
        tool = {"command": payload["command"]} if non_blank(payload.get("command")) else {}
        return {**base, "kind": "tool.call.started", "status": "running", "name": name, "attributes": {"arguments": deepcopy(payload.get("arguments")), "tool": tool}}
    if record_type == "response_item" and item_type == "function_call_output":
        failed = payload.get("success") is False
        tool = {}
        if isinstance(payload.get("output"), str):
            tool["result"] = payload["output"]
        if integer(payload.get("exit_code")):
            tool["exit_code"] = payload["exit_code"]
        return {**base, "kind": "tool.call.failed" if failed else "tool.call.finished", "status": "failed" if failed else "success", "name": payload.get("name", "tool"), "attributes": {"tool": tool}}
    if record_type == "event_msg" and item_type == "token_count":
        usage = payload.get("usage")
        if not isinstance(usage, Mapping):
            raise ValueError("token_count usage must be an object")
        attributes = {}
        for source_name, target in (("input_tokens", "input_tokens"), ("output_tokens", "output_tokens"), ("total_tokens", "total_tokens")):
            if integer(usage.get(source_name)) and usage[source_name] >= 0:
                attributes[target] = usage[source_name]
        return {**base, "kind": "model.request.finished", "status": "success", "name": "model", "attributes": attributes}
    if record_type == "event_msg" and item_type == "context_read" and non_blank(payload.get("path")):
        context = {"path": payload["path"]}
        return {**base, "kind": "context.read", "status": "success", "name": "read", "attributes": {"context": context}}
    if record_type == "event_msg" and item_type == "change":
        locator = hunk(payload.get("hunk"))
        if locator is None:
            return {**base, "kind": "tool.call.finished", "status": "success", "name": "edit", "attributes": {"arguments": deepcopy(payload.get("hunk"))}}
        return {**base, "kind": "change.applied", "status": "success", "name": "edit", "attributes": {"change": locator}, "relationships": relationship_list(payload.get("relationships"))}
    if record_type == "event_msg" and item_type in {"verification_started", "verification_finished"}:
        from .claude_code import _verification
        converted = dict(payload)
        converted["startUuid"] = payload.get("start_id")
        return _verification(base, converted, item_type)
    if record_type == "event_msg" and item_type in {"agent_start", "agent_stop"}:
        started = item_type == "agent_start"
        return {**base, "kind": "agent.started" if started else "agent.finished", "status": "running" if started else "success", "name": "agent", "attributes": {}}
    raise ValueError("record type is not supported by the pinned format")
