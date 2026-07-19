# Outcome Cost Attribution

AgentTrail attributes observed event-local usage to explicit change evidence without judging whether work was accepted, merged, valuable, or wasteful.

## Producer Contract

A usage-bearing event contributes to a change only when it has a `contributes_to` relationship whose `event_id` identifies a valid `change.applied` hunk in the same retained trace.
The target may arrive later, so unresolved targets remain pending until a matching event is observed.
An evicted target is reported as unattributed because the retained evidence can no longer validate its hunk.
Unknown relationship types and unknown event kinds remain preserved under the extensible event envelope.

```json
{
  "event_id": "model-7",
  "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150, "cost_usd": 0.004},
  "relationships": [
    {"type": "contributes_to", "event_id": "change-2"}
  ]
}
```

## Allocation

One distinct valid target receives the event's full available usage delta.
Multiple distinct valid targets receive equal shares of every available metric.
Duplicate identical links have no effect.
Invalid and wrong-kind targets do not receive usage.
A missing target remains pending when no valid target is available, while an event with no valid or pending target is unattributed.
When an event names at least one valid target, all available usage is split only across its distinct valid targets.
Input tokens, output tokens, total tokens, and `cost_usd` are conserved independently.
A missing metric remains unavailable, while numeric zero remains available and is allocated normally.
Malformed, boolean, and non-finite values remain unavailable.

Actor and operation tables assign each event-local delta exactly once.
Hunk tables show attributed usage, contributing event IDs, and the fixed allocation rule.
Warning-code tables use the warning's deterministic evidence event IDs.
Warning associations are non-exclusive views and must never be added across warning codes or added back to run totals.

## Observed Outcomes

Valid hunk outcomes are limited to `reverted`, `modified`, `no_correction_observed`, and `undetermined`.
AgentTrail derives these labels only from `human.corrected` events with `corrects` relationships and validated `attributes.correction.action` values.
A correction follows another event only when same-emitter sequence or causal ancestry establishes that order.
Wall-clock timestamps never select the final correction.
The unique causally latest valid correction determines `modified` or `reverted`.
Malformed, contradictory, or unordered corrections produce `undetermined`.
A hunk without an observed correction is labeled `no_correction_observed`, which does not imply acceptance, retention, merging, or success.

## Surfaces

Run detail exposes the deterministic projection under `outcome_cost` with totals, allocation buckets, actor rows, operation rows, warning-code rows, valid-hunk rows, pending events, and unattributed events.
The browser run overview presents allocation, hunk, and non-exclusive warning tables.
The selected hunk inspector presents attributed usage and the observed outcome.
Markdown export emits the same tables in retained event order, while HTML export and export review inherit the run-detail projection and packaged browser presentation.
