from __future__ import annotations

from collections import deque
from typing import Iterable, Mapping

from .core import Event, TraceView


TRUST_ORIGINS = (
    "user",
    "repository",
    "source_code",
    "third_party",
    "web",
    "build_output",
    "package_metadata",
    "mcp",
    "secret_derived",
)
UNTRUSTED_ORIGINS = frozenset({
    "third_party", "web", "build_output", "package_metadata", "mcp",
})
SENSITIVE_CAPABILITIES = (
    "network_egress",
    "credential_access",
    "filesystem_write",
    "process_execution",
    "secret_output",
)


def security_projection(
    view: TraceView,
    *,
    evicted_event_ids: Iterable[str] = (),
) -> dict[str, object]:
    """Project producer-declared trust and influence without inspecting payloads."""
    events = list(view.events)
    if not any(
        event.has_security
        or any(relationship.type == "influenced_by" for relationship in event.relationships)
        for event in events
    ):
        return {
            "audit_only": True,
            "findings": [],
            "paths": [],
            "coverage": {
                "status": "incomplete",
                "result": "no_observed_path",
                "sensitive_operation_count": 0,
                "finding_count": 0,
                "integrity_issue_count": 0,
                "unresolved_edge_count": 0,
                "security_metadata_observed": False,
                "reasons": ["SECURITY_INSTRUMENTATION_NOT_OBSERVED"],
            },
            "integrity": [],
            "unresolved_edges": [],
        }
    by_id = {event.event_id: event for event in events}
    order = {event.event_id: position for position, event in enumerate(events)}
    evicted = set(evicted_event_ids)
    integrity: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []
    origins: dict[str, str] = {}
    capabilities: dict[str, list[str]] = {}
    outgoing: dict[str, list[str]] = {event.event_id: [] for event in events}
    incoming: dict[str, list[str]] = {event.event_id: [] for event in events}

    for event in events:
        security_value = event.security
        security = security_value if isinstance(security_value, Mapping) else None
        if event.has_security and security is None:
            integrity.append(_diagnostic(
                "INVALID_SECURITY_TYPE", event, field="attributes.security"
            ))
        if security is not None:
            if "trust_origin" in security:
                value = security["trust_origin"]
                if not isinstance(value, str):
                    integrity.append(_diagnostic(
                        "INVALID_TRUST_ORIGIN_TYPE", event,
                        field="attributes.security.trust_origin",
                    ))
                elif value not in TRUST_ORIGINS:
                    integrity.append(_diagnostic(
                        "UNKNOWN_TRUST_ORIGIN", event,
                        field="attributes.security.trust_origin", value=value,
                    ))
                else:
                    origins[event.event_id] = value
            if "capabilities" in security:
                value = security["capabilities"]
                if not isinstance(value, list):
                    integrity.append(_diagnostic(
                        "INVALID_CAPABILITIES_TYPE", event,
                        field="attributes.security.capabilities",
                    ))
                else:
                    valid: list[str] = []
                    seen = set()
                    if not value:
                        integrity.append(_diagnostic(
                            "EMPTY_CAPABILITIES", event,
                            field="attributes.security.capabilities",
                        ))
                    for item in value:
                        if not isinstance(item, str):
                            integrity.append(_diagnostic(
                                "INVALID_CAPABILITY_TYPE", event,
                                field="attributes.security.capabilities",
                            ))
                        elif item not in SENSITIVE_CAPABILITIES:
                            integrity.append(_diagnostic(
                                "UNKNOWN_CAPABILITY", event,
                                field="attributes.security.capabilities", value=item,
                            ))
                        elif item not in seen:
                            valid.append(item)
                            seen.add(item)
                    if valid:
                        capabilities[event.event_id] = valid

        seen_edges = set()
        for relationship in event.relationships:
            if relationship.type != "influenced_by" or relationship.event_id in seen_edges:
                continue
            seen_edges.add(relationship.event_id)
            target = by_id.get(relationship.event_id)
            edge = {
                "type": "influenced_by",
                "source_event_id": event.event_id,
                "target_event_id": relationship.event_id,
            }
            if target is None:
                reason = (
                    "EVICTED_INFLUENCE_TARGET"
                    if relationship.event_id in evicted
                    else "UNRESOLVED_INFLUENCE_TARGET"
                )
                diagnostic = {**edge, "code": reason}
                unresolved.append(diagnostic)
                integrity.append(diagnostic)
                continue
            if (
                target.emitter_id == event.emitter_id
                and target.sequence >= event.sequence
            ):
                integrity.append({
                    **edge,
                    "code": "CONTRADICTORY_INFLUENCE_SEQUENCE",
                    "source_sequence": event.sequence,
                    "target_sequence": target.sequence,
                    "emitter_id": event.emitter_id,
                })
                continue
            outgoing[target.event_id].append(event.event_id)
            incoming[event.event_id].append(target.event_id)

    def event_key(event_id: str) -> tuple[int, str]:
        return order[event_id], event_id

    for neighbors in outgoing.values():
        neighbors.sort(key=event_key)
    for neighbors in incoming.values():
        neighbors.sort(key=event_key)

    shortest = _shortest_parents(
        outgoing,
        sorted(
            (event_id for event_id, label in origins.items() if label in UNTRUSTED_ORIGINS),
            key=event_key,
        ),
    )
    nearest_by_label = {
        label: _shortest_parents(
            outgoing,
            sorted(
                (event_id for event_id, value in origins.items() if value == label),
                key=event_key,
            ),
        )
        for label in TRUST_ORIGINS
    }

    paths: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    missing_diagnostics: list[dict[str, object]] = []
    for operation_id in sorted(capabilities, key=event_key):
        operation = by_id[operation_id]
        path_ids = _path_to(operation_id, shortest)
        evidence = []
        for label in TRUST_ORIGINS:
            label_path = _path_to(operation_id, nearest_by_label[label])
            if label_path:
                evidence.append({
                    "event_id": label_path[0],
                    "trust_origin": label,
                    "risk": _risk(label),
                })
        if path_ids:
            path_id = f"security-path-{len(paths) + 1}"
            path = {
                "id": path_id,
                "operation_event_id": operation_id,
                "events": [
                    {
                        "event_id": event_id,
                        "kind": by_id[event_id].kind,
                        "actor_id": by_id[event_id].actor["id"],
                        "trust_origins": (
                            [origins[event_id]] if event_id in origins else []
                        ),
                    }
                    for event_id in path_ids
                ],
                "trust_origins": evidence,
            }
            paths.append(path)
            findings.append({
                "code": "UNTRUSTED_TO_SENSITIVE",
                "operation_event_id": operation_id,
                "operation_actor_id": operation.actor["id"],
                "capabilities": capabilities[operation_id],
                "untrusted_source_event_id": path_ids[0],
                "untrusted_origin": origins[path_ids[0]],
                "path_id": path_id,
                "summary": (
                    f"untrusted {origins[path_ids[0]]} influence reaches "
                    f"sensitive operation {operation_id}"
                ),
            })

        reachable = _reachable_roots(operation_id, incoming)
        missing = [event_id for event_id in reachable if event_id not in origins]
        for event_id in sorted(missing, key=event_key):
            missing_diagnostics.append({
                "code": "MISSING_TRUST_ORIGIN",
                "event_id": event_id,
                "operation_event_id": operation_id,
                "field": "attributes.security.trust_origin",
            })

    integrity.extend(missing_diagnostics)
    security_metadata_seen = bool(origins or capabilities or integrity)
    incomplete = bool(integrity) or bool(capabilities and missing_diagnostics)
    coverage = {
        "status": "incomplete" if incomplete else "complete",
        "result": "finding" if findings else "no_observed_path",
        "sensitive_operation_count": len(capabilities),
        "finding_count": len(findings),
        "integrity_issue_count": len(integrity),
        "unresolved_edge_count": len(unresolved),
        "security_metadata_observed": security_metadata_seen,
        "reasons": list(dict.fromkeys(item["code"] for item in integrity)),
    }
    return {
        "audit_only": True,
        "findings": findings,
        "paths": paths,
        "coverage": coverage,
        "integrity": integrity,
        "unresolved_edges": unresolved,
    }


def _diagnostic(code: str, event: Event, **details: object) -> dict[str, object]:
    return {"code": code, "event_id": event.event_id, **details}


def _risk(label: str) -> str:
    if label in UNTRUSTED_ORIGINS:
        return "untrusted"
    if label == "user":
        return "trusted"
    if label == "repository":
        return "repository_controlled"
    return label


def _shortest_parents(
    outgoing: Mapping[str, list[str]],
    sources: list[str],
) -> dict[str, str | None]:
    parents: dict[str, str | None] = {source: None for source in sources}
    queue = deque(sources)
    while queue:
        current = queue.popleft()
        for child in outgoing[current]:
            if child in parents:
                continue
            parents[child] = current
            queue.append(child)
    return parents


def _path_to(
    event_id: str,
    parents: Mapping[str, str | None],
) -> list[str] | None:
    if event_id not in parents:
        return None
    path = []
    current: str | None = event_id
    while current is not None:
        path.append(current)
        current = parents[current]
    path.reverse()
    return path


def _reachable_roots(
    operation_id: str,
    incoming: Mapping[str, list[str]],
) -> set[str]:
    roots = set()
    visited = set()
    queue = deque([operation_id])
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        parents = incoming[current]
        if not parents:
            roots.add(current)
        else:
            queue.extend(parents)
    return roots
