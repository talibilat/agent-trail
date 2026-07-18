# Bounded Live History

Serve mode keeps a bounded in-memory journal for Server-Sent Event reconnects.
The default journal limit is 10,000 updates.
Set a different positive limit with `agent-tail serve INPUT --max-live-updates N`.

Every published update receives a monotonically increasing cursor.
Removing an old update from the journal does not reuse its cursor or change the current cursor.
Run-list and run-detail snapshots expose the current cursor so clients can continue from authoritative state.

A reconnect to `/api/v1/events?cursor=N` receives retained updates after `N` when the complete range is still available.
The existing `event`, `finding`, `source`, and `heartbeat` message types are unchanged.

The server sends one `reset` message when the requested cursor is older than retained history or newer than the current cursor.
The reset message uses the current cursor as its SSE ID without incrementing the cursor.
Its JSON data contains `requested_cursor`, `oldest_retained_cursor`, `current_cursor`, and `reason`.
The reason is `history_gap`.
The server then closes that event stream.

After a reset, a client should fetch `/api/v1/runs`, replace its run-list projection, and fetch the selected run detail again if a run is selected.
The client should then reconnect from the authoritative current cursor.
Replacing snapshot state before reconnecting avoids duplicated updates while preserving a selected run that still exists.

The journal limit bounds reconnect metadata, not the `TraceIndex` event and payload budget.
Use `--max-bytes` separately to control indexed trace memory.
Serve-mode history remains process-local and is not restored after restart.
