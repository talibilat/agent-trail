# Audit-Only Taint Security

AgentTrail reports producer-declared influence paths from untrusted sources to sensitive operations without inspecting payload content or enforcing policy.

## Contract

Set `attributes.security.trust_origin` on a source event to exactly one of `user`, `repository`, `source_code`, `third_party`, `web`, `build_output`, `package_metadata`, `mcp`, or `secret_derived`.
The `user` label is trusted, `repository` is repository-controlled, and `third_party`, `web`, `build_output`, `package_metadata`, and `mcp` are untrusted for this audit.
The `source_code` and `secret_derived` labels remain distinct risk evidence and are not collapsed into trusted or untrusted categories.
Set `attributes.security.capabilities` on a sensitive operation to a non-empty array containing `network_egress`, `credential_access`, `filesystem_write`, `process_execution`, or `secret_output`.
An event declares observed direct influence with an `influenced_by` relationship whose `event_id` identifies the influencing event.

```json
{
  "event_id": "tool-2",
  "kind": "tool.call.started",
  "attributes": {
    "security": {
      "capabilities": ["network_egress"]
    }
  },
  "relationships": [
    {"type": "influenced_by", "event_id": "web-input-1"}
  ]
}
```

## Propagation

Taint flows only from a resolved relationship target to the event that declares `influenced_by`.
The audit does not infer labels from payloads, redaction, operation names, event kinds, source code, or keywords.
Cross-emitter timestamps do not invalidate an explicit influence claim.
A same-emitter edge is contradictory when its target sequence is equal to or greater than the declaring event sequence, so that edge is diagnosed and excluded.
Cycles are bounded by visited event IDs.
Each finding uses the fewest-edge untrusted path, with ties resolved by canonical event order and then event ID.
The path includes event-by-event labels, while additional reachable trust labels remain visible as evidence.

## Coverage

`UNTRUSTED_TO_SENSITIVE` means a validated untrusted origin reaches an event with at least one validated sensitive capability.
A path containing only a validated `user` origin does not produce this finding.
Unknown labels, malformed metadata, unresolved references, contradictory sequence, missing trust evidence, and evicted targets produce typed integrity diagnostics and incomplete coverage.
When no security metadata or `influenced_by` relationship is observed, coverage is incomplete with the coverage-level reason `SECURITY_INSTRUMENTATION_NOT_OBSERVED`, while event integrity diagnostics remain empty.
An `influenced_by` target with neither `trust_origin` nor an upstream `influenced_by` edge is an unlabeled influence leaf, so it produces the existing `MISSING_TRUST_ORIGIN` event diagnostic rather than a wrong-kind diagnostic.
The `no_observed_path` result is separate from coverage status, so incomplete evidence is never presented as a safe result.
The run-detail API exposes the shared projection under `security` with `findings`, `paths`, `coverage`, `integrity`, and `unresolved_edges`.
The browser inspector, Markdown export, self-contained HTML export, and export review use this sanitized projection.

## Boundaries

This feature is local and audit-only.
It does not block an operation, request permission, contact a policy service, or claim to prevent prompt injection.
It does not judge whether producer labels are complete or honest.
Redaction does not create a `secret_derived` claim, and payload eviction does not prove that an event was safe.
