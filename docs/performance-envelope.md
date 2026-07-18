# 10,000-Event Performance Envelope

The release gate uses a deterministic generated canonical JSONL run instead of checking in a large static fixture.
The generator emits exactly 10,000 events from 100 actors with parent-child activity, equal-time cross-emitter uncertainty, tool calls, event-local usage deltas, one complete change-evidence chain, and verification evidence.
It does not use random values or wall-clock timestamps.
Expected actor, event, usage, change, and relationship totals are calculated independently from the emitted event objects.

## Process Gate

The retained variant uses a 64 MiB index budget and requires all 10,000 unique event IDs to survive ingestion.
Its measured subprocess boundary includes file ingestion, run-list projection, run-detail projection, JSON serialization, and release assertions.
The complete retained subprocess must finish in less than 10 seconds and peak resident memory must remain below 512 MiB on the project CI target.
The response must contain 100 actors, exact independently calculated usage totals, causal uncertainty, an ORPHAN warning, one change, and all six resolved evidence links.

The default-budget variant uses the product default of 16 MiB.
It must finish in less than 10 seconds, remain below 512 MiB peak resident memory, retain unique event IDs, expose `EVICT` whenever fixture data is evicted, and never return payload detail for evicted payload or metadata.
Payload eviction is expected for the current fixture, while metadata eviction is permitted and asserted truthfully if fixture sizing changes.

Run both process variants with this command from the repository root.

```bash
PYTHONPATH=src python -m unittest tests.test_performance -v
```

The tests print ingestion, run-list, run-detail, serialization, total subprocess time, serialized bytes, retained counts, eviction counts, and peak RSS.

## Browser Gate

The Chromium gate creates an isolated virtual environment, installs the current project into it, and launches that environment's `agent-tail` console script without a source-tree `PYTHONPATH`.
Timing begins immediately before the installed serve command starts and ends when Chromium displays the first interactive 40-actor graph after all 10,000 events have crossed the file and HTTP boundaries.
The first useful view must appear in less than 10 seconds.
Late-event search and inspector selection, graph-to-tree switching, playback scrubbing to the end, and each progressive-reveal step must also complete in less than 10 seconds.
The narrow initial viewport proves that graph rendering is capped at 40 actors, one reveal step increases the cap to 80 actors, and the run's full 100 actors are not rendered initially.

Install the test extra and Chromium once, then run the browser gate from the repository root.

```bash
python -m pip install '.[test]'
python -m playwright install chromium
PYTHONPATH=src python -m unittest tests.test_e2e.ServeEndToEndTests.test_large_projection_performance_envelope -v
```

The browser test prints exact first-view, late-search and inspector, view-switch, playback, and progressive-reveal timings.

## Interpretation

These thresholds define the supported 10,000-event envelope and do not promise the same bounds for larger traces.
The gates retain canonical ordering, causal uncertainty, warning detection, payload redaction, and Change Evidence Map validation.
Serve-mode reconnect history remains independently bounded by `--max-live-updates`, as described in [Bounded live history](bounded-live-history.md).
