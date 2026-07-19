from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
from typing import Any, Callable, Mapping, TextIO

try:
    import langgraph as _langgraph  # noqa: F401
    from langchain_core.callbacks import BaseCallbackHandler as _CallbackBase
except ImportError as _import_error:
    _LANGGRAPH_IMPORT_ERROR: ImportError | None = _import_error

    class _CallbackBase:  # type: ignore[no-redef]
        pass
else:
    _LANGGRAPH_IMPORT_ERROR = None


_CHANGE_RELATIONSHIPS = {
    "applies",
    "informed_by",
    "motivated_by",
    "preceded_by",
    "verified_by",
}
_TEST_ORIGINS = {"pre_existing", "same_agent"}


@dataclass(frozen=True)
class _Run:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    actor_id: str
    name: str


class AgentTailCallbackHandler(_CallbackBase):
    """Write LangGraph callback activity as canonical AgentTrail JSONL."""

    run_inline = True
    raise_error = True

    def __init__(
        self,
        output: str | Path | TextIO = "agent-tail.jsonl",
        *,
        emitter_id: str = "langgraph",
        max_active_runs: int = 10_000,
        clock: Callable[[], datetime | str] | None = None,
    ) -> None:
        if _LANGGRAPH_IMPORT_ERROR is not None:
            raise ImportError(
                "LangGraph support requires the optional dependency; "
                "install it with `python -m pip install 'agent-tail[langgraph]'`."
            ) from _LANGGRAPH_IMPORT_ERROR
        if not isinstance(emitter_id, str) or not emitter_id.strip():
            raise ValueError("emitter_id must be a non-blank string")
        if (
            isinstance(max_active_runs, bool)
            or not isinstance(max_active_runs, int)
            or max_active_runs <= 0
        ):
            raise ValueError("max_active_runs must be a positive integer")

        self._lock = threading.RLock()
        self._runs: OrderedDict[str, _Run] = OrderedDict()
        self._sequence = 0
        self._generic_ordinal = 0
        self._max_active_runs = max_active_runs
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._emitter_id = emitter_id.strip()
        self._owns_stream = isinstance(output, (str, Path))
        self._stream = (
            Path(output).open("a", encoding="utf-8")
            if self._owns_stream
            else output
        )
        if not hasattr(self._stream, "write") or not hasattr(self._stream, "flush"):
            raise TypeError("output must be a path or writable text stream")

    def __enter__(self) -> AgentTailCallbackHandler:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def active_run_count(self) -> int:
        with self._lock:
            return len(self._runs)

    def close(self) -> None:
        with self._lock:
            self._stream.flush()
            if self._owns_stream and not self._stream.closed:
                self._stream.close()

    def event_id(self, run_id: object, kind: str, evidence_id: str) -> str:
        """Return the canonical ID used by an evidence helper."""
        run_key = _run_key(run_id)
        _non_blank("kind", kind)
        _non_blank("evidence_id", evidence_id)
        return _identifier("event", run_key, kind, evidence_id, length=32)

    def on_chain_start(
        self,
        serialized: Mapping[str, object] | None,
        inputs: object,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        tags: list[str] | None = None,
        metadata: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        name = _callback_name(serialized, kwargs)
        run = self._start_run(run_id, parent_run_id, name)
        self._emit_lifecycle(
            run_id,
            run,
            "agent.started",
            "running",
            langgraph=_framework_details(
                "chain", name, tags, metadata,
                graph=name if parent_run_id is None else None,
                inputs=inputs,
                **kwargs,
            ),
        )

    def on_chain_end(
        self,
        outputs: object,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: object,
    ) -> None:
        run = self._finish_run(run_id, parent_run_id)
        self._emit_lifecycle(
            run_id,
            run,
            "agent.finished",
            "success",
            langgraph=_framework_details(
                "chain", run.name, None, None, outputs=outputs, **kwargs
            ),
        )

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: object,
    ) -> None:
        run = self._finish_run(run_id, parent_run_id)
        self._emit_lifecycle(
            run_id,
            run,
            "agent.failed",
            "failed",
            langgraph=_framework_details(
                "chain", run.name, None, None, error=str(error), **kwargs
            ),
        )

    def on_llm_start(
        self,
        serialized: Mapping[str, object] | None,
        prompts: object,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        tags: list[str] | None = None,
        metadata: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        self._start_operation(
            "model.request.started",
            "llm",
            serialized,
            prompts,
            run_id,
            parent_run_id,
            tags,
            metadata,
            kwargs,
        )

    def on_chat_model_start(
        self,
        serialized: Mapping[str, object] | None,
        messages: object,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        tags: list[str] | None = None,
        metadata: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        self._start_operation(
            "model.request.started",
            "chat_model",
            serialized,
            messages,
            run_id,
            parent_run_id,
            tags,
            metadata,
            kwargs,
        )

    def on_llm_end(
        self,
        response: object,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: object,
    ) -> None:
        self._finish_operation(
            "model.request.finished", "success", "llm", response,
            run_id, parent_run_id, kwargs,
        )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: object,
    ) -> None:
        self._finish_operation(
            "model.request.failed", "failed", "llm", str(error),
            run_id, parent_run_id, kwargs,
        )

    def on_tool_start(
        self,
        serialized: Mapping[str, object] | None,
        input_str: str,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        tags: list[str] | None = None,
        metadata: Mapping[str, object] | None = None,
        inputs: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        name = _callback_name(serialized, kwargs)
        run = self._start_run(run_id, parent_run_id, name)
        arguments: object = inputs if inputs is not None else input_str
        self._emit_lifecycle(
            run_id,
            run,
            "tool.call.started",
            "running",
            attributes={
                "arguments": _json_safe(arguments),
                "tool": {"command": input_str},
            },
            langgraph=_framework_details(
                "tool", name, tags, metadata, input=input_str,
                inputs=inputs, **kwargs
            ),
        )

    def on_tool_end(
        self,
        output: object,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: object,
    ) -> None:
        run = self._finish_run(run_id, parent_run_id)
        self._emit_lifecycle(
            run_id,
            run,
            "tool.call.finished",
            "success",
            attributes={"tool": {"result": _text_value(output)}},
            langgraph=_framework_details(
                "tool", run.name, None, None, output=output, **kwargs
            ),
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: object,
    ) -> None:
        run = self._finish_run(run_id, parent_run_id)
        self._emit_lifecycle(
            run_id,
            run,
            "tool.call.failed",
            "failed",
            langgraph=_framework_details(
                "tool", run.name, None, None, error=str(error), **kwargs
            ),
        )

    def on_retriever_start(
        self, serialized: Mapping[str, object] | None, query: str, *,
        run_id: object, parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_start(
            "retriever.started", serialized, query, run_id, parent_run_id, kwargs
        )

    def on_retriever_end(
        self, documents: object, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_end(
            "retriever.finished", "success", documents,
            run_id, parent_run_id, kwargs,
        )

    def on_retriever_error(
        self, error: BaseException, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_end(
            "retriever.failed", "failed", str(error),
            run_id, parent_run_id, kwargs,
        )

    def on_custom_event(
        self, name: str, data: object, *, run_id: object,
        tags: list[str] | None = None,
        metadata: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        run = self._run_for(run_id, None, name)
        if name in {"handoff", "message.sent"} and isinstance(data, Mapping):
            sender = data.get("sender", data.get("from"))
            recipient = data.get("recipient", data.get("to"))
            if (
                isinstance(sender, str)
                and sender.strip()
                and isinstance(recipient, str)
                and recipient.strip()
            ):
                message_run = _Run(
                    run.trace_id,
                    run.span_id,
                    run.parent_span_id,
                    sender,
                    name,
                )
                self._emit(
                    message_run,
                    "message.sent",
                    "success",
                    name,
                    event_id=self._next_generic_id(run_id, "message.sent"),
                    attributes={
                        "to": recipient,
                        "langgraph": _framework_details(
                            "custom", name, tags, metadata, data=data, **kwargs
                        ),
                    },
                )
                return
        self._emit(
            run,
            "langgraph.callback.custom",
            "unknown",
            name,
            event_id=self._next_generic_id(run_id, "custom"),
            attributes={"langgraph": _framework_details(
                "custom", name, tags, metadata, data=data, **kwargs
            )},
        )

    def on_llm_new_token(
        self, token: str, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_event("llm_new_token", token, run_id, parent_run_id, kwargs)

    def on_retry(
        self, retry_state: object, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_event("retry", retry_state, run_id, parent_run_id, kwargs)

    def on_text(
        self, text: str, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_event("text", text, run_id, parent_run_id, kwargs)

    def on_agent_action(
        self, action: object, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_event("agent_action", action, run_id, parent_run_id, kwargs)

    def on_agent_finish(
        self, finish: object, *, run_id: object,
        parent_run_id: object | None = None, **kwargs: object,
    ) -> None:
        self._generic_event("agent_finish", finish, run_id, parent_run_id, kwargs)

    def emit_context_read(
        self,
        *,
        run_id: object,
        evidence_id: str,
        path: str,
        line_start: int | None = None,
        line_end: int | None = None,
        symbol: str | None = None,
        content_sha256: str | None = None,
        repository_commit: str | None = None,
        repository_worktree_sha256: str | None = None,
        actor_id: str | None = None,
    ) -> str:
        context: dict[str, object] = {"path": _non_blank("path", path)}
        if line_start is not None:
            context["line_start"] = _positive_int("line_start", line_start)
        if line_end is not None:
            context["line_end"] = _positive_int("line_end", line_end)
        if line_start is not None and line_end is not None and line_end < line_start:
            raise ValueError("line_end must not precede line_start")
        if symbol is not None:
            context["symbol"] = _non_blank("symbol", symbol)
        if content_sha256 is not None:
            context["content_sha256"] = _sha256("content_sha256", content_sha256)
        attributes: dict[str, object] = {"context": context}
        repository = _repository(repository_commit, repository_worktree_sha256)
        if repository:
            attributes["repository"] = repository
        return self._emit_evidence(
            run_id, evidence_id, "context.read", "success", actor_id,
            attributes, [],
        )

    def emit_context_search(
        self,
        *,
        run_id: object,
        evidence_id: str,
        query: str,
        matches: list[str],
        repository_commit: str | None = None,
        repository_worktree_sha256: str | None = None,
        actor_id: str | None = None,
    ) -> str:
        if not isinstance(matches, list):
            raise TypeError("matches must be an array")
        canonical_matches = [_non_blank("match", match) for match in matches]
        if len(set(canonical_matches)) != len(canonical_matches):
            raise ValueError("matches must be distinct")
        attributes: dict[str, object] = {
            "search": {
                "query": _non_blank("query", query),
                "matches": canonical_matches,
            }
        }
        repository = _repository(repository_commit, repository_worktree_sha256)
        if repository:
            attributes["repository"] = repository
        return self._emit_evidence(
            run_id, evidence_id, "context.search", "success", actor_id,
            attributes, [],
        )

    def emit_change_applied(
        self,
        *,
        run_id: object,
        evidence_id: str,
        path: str,
        old_start: int,
        old_count: int,
        new_start: int,
        new_count: int,
        symbol: str | None = None,
        preimage_sha256: str | None = None,
        repository_commit: str | None = None,
        repository_worktree_sha256: str | None = None,
        relationships: list[Mapping[str, str]] | None = None,
        actor_id: str | None = None,
    ) -> str:
        change = {
            "path": _non_blank("path", path),
            "old_start": _range_start("old_start", old_start, old_count),
            "old_count": _non_negative_int("old_count", old_count),
            "new_start": _range_start("new_start", new_start, new_count),
            "new_count": _non_negative_int("new_count", new_count),
        }
        if symbol is not None:
            change["symbol"] = _non_blank("symbol", symbol)
        if preimage_sha256 is not None:
            change["preimage_sha256"] = _sha256("preimage_sha256", preimage_sha256)
        attributes: dict[str, object] = {"change": change}
        repository = _repository(repository_commit, repository_worktree_sha256)
        if repository:
            attributes["repository"] = repository
        links = _relationships(relationships, allowed=_CHANGE_RELATIONSHIPS)
        return self._emit_evidence(
            run_id, evidence_id, "change.applied", "success", actor_id,
            attributes, links,
        )

    def emit_verification_started(
        self,
        *,
        run_id: object,
        evidence_id: str,
        command: str,
        test_origin: str | None = None,
        actor_id: str | None = None,
    ) -> str:
        verification: dict[str, object] = {
            "command": _non_blank("command", command),
        }
        if test_origin is not None:
            verification["test_origin"] = _test_origin(test_origin)
        return self._emit_evidence(
            run_id, evidence_id, "verification.started", "running", actor_id,
            {"verification": verification}, [],
        )

    def emit_verification_finished(
        self,
        *,
        run_id: object,
        evidence_id: str,
        passed: bool,
        start_event_id: str | None = None,
        command: str | None = None,
        exit_code: int | None = None,
        test_origin: str | None = None,
        actor_id: str | None = None,
    ) -> str:
        if not isinstance(passed, bool):
            raise TypeError("passed must be a boolean")
        if start_event_id is None and command is None:
            raise ValueError("command is required when start_event_id is absent")
        verification: dict[str, object] = {"passed": passed}
        if command is not None:
            verification["command"] = _non_blank("command", command)
        if exit_code is not None:
            if isinstance(exit_code, bool) or not isinstance(exit_code, int):
                raise TypeError("exit_code must be an integer")
            if (exit_code == 0) != passed:
                raise ValueError("exit_code must agree with passed")
            verification["exit_code"] = exit_code
        if test_origin is not None:
            verification["test_origin"] = _test_origin(test_origin)
        links = []
        if start_event_id is not None:
            links = [{
                "type": "completes",
                "event_id": _non_blank("start_event_id", start_event_id),
            }]
        return self._emit_evidence(
            run_id, evidence_id, "verification.finished",
            "success" if passed else "failed", actor_id,
            {"verification": verification}, links,
        )

    def _start_operation(
        self, kind: str, callback: str,
        serialized: Mapping[str, object] | None, value: object,
        run_id: object, parent_run_id: object | None,
        tags: list[str] | None, metadata: Mapping[str, object] | None,
        kwargs: Mapping[str, object],
    ) -> None:
        name = _callback_name(serialized, kwargs)
        run = self._start_run(run_id, parent_run_id, name)
        self._emit_lifecycle(
            run_id, run, kind, "running",
            langgraph=_framework_details(
                callback, name, tags, metadata, input=value, **kwargs
            ),
        )

    def _finish_operation(
        self, kind: str, status: str, callback: str, value: object,
        run_id: object, parent_run_id: object | None,
        kwargs: Mapping[str, object],
    ) -> None:
        run = self._finish_run(run_id, parent_run_id)
        field = "error" if status == "failed" else "output"
        self._emit_lifecycle(
            run_id, run, kind, status,
            langgraph=_framework_details(
                callback, run.name, None, None, **{field: value}, **kwargs
            ),
        )

    def _generic_start(
        self, callback: str, serialized: Mapping[str, object] | None,
        value: object, run_id: object, parent_run_id: object | None,
        kwargs: Mapping[str, object],
    ) -> None:
        name = _callback_name(serialized, kwargs)
        run = self._start_run(run_id, parent_run_id, name)
        self._emit_lifecycle(
            run_id, run, f"langgraph.callback.{callback}", "running",
            langgraph=_framework_details(
                callback, name, None, None, input=value, **kwargs
            ),
        )

    def _generic_end(
        self, callback: str, status: str, value: object,
        run_id: object, parent_run_id: object | None,
        kwargs: Mapping[str, object],
    ) -> None:
        run = self._finish_run(run_id, parent_run_id)
        self._emit_lifecycle(
            run_id, run, f"langgraph.callback.{callback}", status,
            langgraph=_framework_details(
                callback, run.name, None, None, value=value, **kwargs
            ),
        )

    def _generic_event(
        self, callback: str, value: object, run_id: object,
        parent_run_id: object | None, kwargs: Mapping[str, object],
    ) -> None:
        run = self._run_for(run_id, parent_run_id, callback)
        self._emit(
            run,
            f"langgraph.callback.{callback}",
            "unknown",
            callback,
            event_id=self._next_generic_id(run_id, callback),
            attributes={"langgraph": _framework_details(
                callback, run.name, None, None, value=value, **kwargs
            )},
        )

    def _start_run(
        self, run_id: object, parent_run_id: object | None, name: str
    ) -> _Run:
        run = self._derive_run(run_id, parent_run_id, name)
        with self._lock:
            key = _run_key(run_id)
            self._runs[key] = run
            self._runs.move_to_end(key)
            while len(self._runs) > self._max_active_runs:
                self._runs.popitem(last=False)
        return run

    def _run_for(
        self, run_id: object, parent_run_id: object | None, name: str
    ) -> _Run:
        key = _run_key(run_id)
        with self._lock:
            run = self._runs.get(key)
        return run or self._derive_run(run_id, parent_run_id, name)

    def _finish_run(
        self, run_id: object, parent_run_id: object | None
    ) -> _Run:
        key = _run_key(run_id)
        with self._lock:
            run = self._runs.pop(key, None)
        return run or self._derive_run(run_id, parent_run_id, "unknown")

    def _derive_run(
        self, run_id: object, parent_run_id: object | None, name: str
    ) -> _Run:
        key = _run_key(run_id)
        parent_key = _run_key(parent_run_id) if parent_run_id is not None else None
        with self._lock:
            parent = self._runs.get(parent_key) if parent_key else None
        trace_id = (
            parent.trace_id
            if parent is not None
            else _identifier("trace", parent_key or key, length=32)
        )
        return _Run(
            trace_id=trace_id,
            span_id=_identifier("span", key, length=16),
            parent_span_id=(
                parent.span_id
                if parent is not None
                else _identifier("span", parent_key, length=16)
                if parent_key
                else None
            ),
            actor_id=_identifier("actor", key, length=16),
            name=name,
        )

    def _emit_lifecycle(
        self, run_id: object, run: _Run, kind: str, status: str, *,
        attributes: Mapping[str, object] | None = None,
        langgraph: Mapping[str, object] | None = None,
    ) -> str:
        merged = dict(attributes or {})
        if langgraph is not None:
            merged["langgraph"] = langgraph
        event_id = _identifier("event", _run_key(run_id), kind, length=32)
        self._emit(run, kind, status, run.name, event_id=event_id, attributes=merged)
        return event_id

    def _emit_evidence(
        self, run_id: object, evidence_id: str, kind: str, status: str,
        actor_id: str | None, attributes: Mapping[str, object],
        relationships: list[dict[str, str]],
    ) -> str:
        run = self._run_for(run_id, None, "evidence")
        event_id = self.event_id(run_id, kind, evidence_id)
        evidence_run = _Run(
            run.trace_id,
            _identifier("evidence-span", _run_key(run_id), evidence_id, length=16),
            run.span_id,
            _non_blank("actor_id", actor_id) if actor_id is not None else run.actor_id,
            kind,
        )
        self._emit(
            evidence_run, kind, status, kind, event_id=event_id,
            attributes=attributes, relationships=relationships,
        )
        return event_id

    def _next_generic_id(self, run_id: object, callback: str) -> str:
        with self._lock:
            self._generic_ordinal += 1
            ordinal = self._generic_ordinal
        return _identifier(
            "event", _run_key(run_id), callback, str(ordinal), length=32
        )

    def _emit(
        self, run: _Run, kind: str, status: str, name: str, *,
        event_id: str, attributes: Mapping[str, object] | None = None,
        relationships: list[dict[str, str]] | None = None,
    ) -> None:
        with self._lock:
            self._sequence += 1
            event: dict[str, object] = {
                "schema_version": "1.0",
                "event_id": event_id,
                "trace_id": run.trace_id,
                "span_id": run.span_id,
                "emitter_id": self._emitter_id,
                "sequence": self._sequence,
                "timestamp": _timestamp(self._clock()),
                "kind": kind,
                "actor": {"id": run.actor_id},
                "operation": {"status": status, "name": name},
            }
            if run.parent_span_id is not None:
                event["parent_span_id"] = run.parent_span_id
            if relationships:
                event["relationships"] = deepcopy(relationships)
            if attributes:
                event["attributes"] = _json_safe(attributes)
            line = json.dumps(
                event, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ) + "\n"
            self._stream.write(line)
            self._stream.flush()


def _identifier(namespace: str, *parts: str, length: int) -> str:
    digest = hashlib.sha256(
        "\0".join(("agent-tail-langgraph", namespace, *parts)).encode("utf-8")
    ).hexdigest()[:length]
    return f"langgraph-{namespace}-{digest}"


def _run_key(run_id: object) -> str:
    value = str(run_id)
    if not value.strip():
        raise ValueError("run_id must not be blank")
    return value


def _callback_name(
    serialized: Mapping[str, object] | None, kwargs: Mapping[str, object]
) -> str:
    name = kwargs.get("name")
    if isinstance(name, str) and name.strip():
        return name
    if isinstance(serialized, Mapping):
        source_name = serialized.get("name")
        if isinstance(source_name, str) and source_name.strip():
            return source_name
        source_id = serialized.get("id")
        if isinstance(source_id, list) and source_id:
            return str(source_id[-1])
    return "unknown"


def _framework_details(
    callback_type: str,
    operation_name: str,
    callback_tags: list[str] | None,
    callback_metadata: Mapping[str, object] | None,
    **values: object,
) -> dict[str, object]:
    details: dict[str, object] = {
        "callback": callback_type,
        "name": operation_name,
    }
    if callback_tags:
        details["tags"] = callback_tags
    if callback_metadata:
        details["metadata"] = callback_metadata
        for source, target in (
            ("langgraph_node", "node"),
            ("langgraph_step", "step"),
            ("langgraph_checkpoint_ns", "checkpoint_namespace"),
            ("checkpoint_ns", "checkpoint_namespace"),
            ("langgraph_triggers", "triggers"),
            ("langgraph_path", "path"),
        ):
            if source in callback_metadata:
                details[target] = callback_metadata[source]
    for key, value in values.items():
        if value is not None and key not in {
            "metadata", "name", "parent_run_id", "run_id", "tags",
        }:
            details[key] = value
    return _json_safe(details)


def _json_safe(value: object) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _json_safe(model_dump(mode="json"))
        except (TypeError, ValueError):
            pass
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _text_value(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        _json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("clock must return an ISO 8601 timestamp") from error
        if parsed.utcoffset() is None:
            raise ValueError("clock timestamp must include a timezone")
        return value
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime or timestamp")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _non_blank(field: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-blank string")
    return value


def _sha256(field: str, value: object) -> str:
    digest = _non_blank(field, value)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 string")
    return digest


def _repository(
    commit: str | None,
    worktree_sha256: str | None,
) -> dict[str, str]:
    repository = {}
    if commit is not None:
        repository["commit"] = _non_blank("repository_commit", commit)
    if worktree_sha256 is not None:
        repository["worktree_sha256"] = _sha256(
            "repository_worktree_sha256", worktree_sha256
        )
    return repository


def _positive_int(field: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def _non_negative_int(field: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if value < 0:
        raise ValueError(f"{field} must not be negative")
    return value


def _range_start(field: str, start: object, count: object) -> int:
    valid_start = _non_negative_int(field, start)
    valid_count = _non_negative_int(field.replace("start", "count"), count)
    if valid_count > 0 and valid_start == 0:
        raise ValueError(f"{field} must be positive when its count is positive")
    return valid_start


def _test_origin(value: object) -> str:
    origin = _non_blank("test_origin", value)
    if origin not in _TEST_ORIGINS:
        raise ValueError("test_origin must be pre_existing or same_agent")
    return origin


def _relationships(
    values: list[Mapping[str, str]] | None, *, allowed: set[str]
) -> list[dict[str, str]]:
    result = []
    for index, relationship in enumerate(values or []):
        if not isinstance(relationship, Mapping):
            raise TypeError(f"relationships[{index}] must be an object")
        relationship_type = _non_blank(
            f"relationships[{index}].type", relationship.get("type")
        )
        if relationship_type not in allowed:
            raise ValueError(
                f"relationships[{index}].type is not valid for this evidence"
            )
        event_id = _non_blank(
            f"relationships[{index}].event_id", relationship.get("event_id")
        )
        result.append({"type": relationship_type, "event_id": event_id})
    return result


__all__ = ["AgentTailCallbackHandler"]
