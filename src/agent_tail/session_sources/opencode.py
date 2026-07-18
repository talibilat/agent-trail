from copy import deepcopy
import json
from typing import Mapping


def _document(text: str) -> object:
    try:
        return json.loads(text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, ValueError):
        return None


def detect(text: str) -> bool:
    document = _document(text)
    return isinstance(document, Mapping) and isinstance(document.get("info"), Mapping) and isinstance(document.get("messages"), list) and "providerID" in document["info"]


def parse(text: str, max_errors: int):
    from ..session_import import ParsedSession, SessionDocumentError, bounded_errors, diagnostic, non_blank
    document = _document(text)
    if not isinstance(document, Mapping) or not isinstance(document.get("info"), Mapping) or not isinstance(document.get("messages"), list):
        raise SessionDocumentError("unsupported opencode format: expected a JSON session export")
    version = document.get("schema_version")
    if version != "1":
        raise SessionDocumentError("unsupported opencode export schema version; supported: 1")
    session_id = document["info"].get("id")
    if not non_blank(session_id):
        raise SessionDocumentError("malformed opencode export: info.id is required")
    records, errors, omitted = [], [], 0
    for message_index, message in enumerate(document["messages"]):
        if not isinstance(message, Mapping) or not isinstance(message.get("info"), Mapping) or not isinstance(message.get("parts"), list):
            if len(errors) < max_errors:
                errors.append(diagnostic(f"messages[{message_index}]", "must contain info and parts"))
            else:
                omitted += 1
            continue
        for part_index, part in enumerate(message["parts"]):
            try:
                records.append(_part(message["info"], part, message_index, part_index))
            except ValueError as error:
                if len(errors) < max_errors:
                    errors.append(diagnostic(f"messages[{message_index}].parts[{part_index}]", str(error)))
                else:
                    omitted += 1
    metadata = {"schema_version": version, "info": deepcopy(dict(document["info"]))}
    return ParsedSession("opencode", version, session_id, metadata, tuple(records), bounded_errors(errors, omitted, "opencode"))


def _part(info: Mapping[str, object], part: object, message_index: int, part_index: int) -> dict[str, object]:
    from ..session_import import hunk, integer, non_blank, relationship_list, valid_timestamp
    if not isinstance(part, Mapping):
        raise ValueError("must be an object")
    message_id = info.get("id")
    role = info.get("role")
    if not non_blank(message_id) or role not in {"user", "assistant"}:
        raise ValueError("message info requires an id and supported role")
    timestamp = part.get("timestamp", info.get("time"))
    if not valid_timestamp(timestamp):
        raise ValueError("timestamp must be an ISO 8601 value with a timezone")
    part_id = part.get("id") if non_blank(part.get("id")) else f"{message_id}:part:{part_index}"
    actor_id = info.get("agent") if non_blank(info.get("agent")) else role
    base = {"source_key": part_id, "timestamp": timestamp, "actor_id": actor_id, "emitter_id": actor_id,
            "parent_source_key": info.get("parentID") if non_blank(info.get("parentID")) else None,
            "raw": {"message": deepcopy(dict(info)), "part": deepcopy(dict(part))}}
    part_type = part.get("type")
    if part_type == "text":
        return {**base, "kind": "message.sent", "status": "success", "name": role, "actor": {"role": role}, "attributes": {"message": {"role": role, "content": part.get("text")}}}
    if part_type == "tool":
        state = part.get("state")
        if not isinstance(state, Mapping) or not non_blank(part.get("tool")):
            raise ValueError("tool part requires a tool name and state")
        status = state.get("status")
        if status == "running":
            tool = {"command": state["command"]} if non_blank(state.get("command")) else {}
            return {**base, "kind": "tool.call.started", "status": "running", "name": part["tool"], "attributes": {"arguments": deepcopy(state.get("input")), "tool": tool}}
        if status in {"completed", "error"}:
            failed = status == "error"
            tool = {}
            if isinstance(state.get("output"), str):
                tool["result"] = state["output"]
            if integer(state.get("exit_code")):
                tool["exit_code"] = state["exit_code"]
            return {**base, "kind": "tool.call.failed" if failed else "tool.call.finished", "status": "failed" if failed else "success", "name": part["tool"], "attributes": {"tool": tool}}
        raise ValueError("tool state status is unsupported")
    if part_type == "context" and non_blank(part.get("path")):
        return {**base, "kind": "context.read", "status": "success", "name": "read", "attributes": {"context": {"path": part["path"]}}}
    if part_type == "patch":
        locator = hunk(part.get("hunk"))
        if locator is None:
            return {**base, "kind": "tool.call.finished", "status": "success", "name": "patch", "attributes": {"arguments": deepcopy(part.get("hunk"))}}
        return {**base, "kind": "change.applied", "status": "success", "name": "patch", "attributes": {"change": locator}, "relationships": relationship_list(part.get("relationships"))}
    if part_type in {"verification_started", "verification_finished"}:
        from .claude_code import _verification
        converted = dict(part)
        converted["startUuid"] = part.get("startID")
        return _verification(base, converted, part_type)
    if part_type == "step-start":
        usage = part.get("usage")
        attributes = {}
        if isinstance(usage, Mapping):
            for name in ("input_tokens", "output_tokens", "total_tokens"):
                if integer(usage.get(name)) and usage[name] >= 0:
                    attributes[name] = usage[name]
        return {**base, "kind": "model.request.finished", "status": "success", "name": "model", "attributes": attributes}
    if part_type in {"agent_start", "agent_stop"}:
        started = part_type == "agent_start"
        return {**base, "kind": "agent.started" if started else "agent.finished", "status": "running" if started else "success", "name": "agent", "attributes": {}}
    raise ValueError("part type is not supported by the pinned format")
