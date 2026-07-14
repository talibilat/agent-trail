# 05 - Swimlane, Sequence, And Playback Experience

**What to build:** Add the time-oriented investigation views and playback controls.
A user can inspect concurrent agent activity in a swimlane, follow cross-agent handoffs in a sequence view, scrub a completed run, replay historical time, and pause live-follow during an active run without losing incoming events.

**Blocked by:** 02 - Live Source Lifecycle And Streaming; 03 - Causal Run Projection For Agents, Links, Usage, And Warnings.

**Status:** resolved

- [x] The swimlane view shows real agent activity, status changes, and event timing across the run.
- [x] The sequence view shows real cross-agent handoff arrows from the message contract and unresolved endpoints when targets are missing.
- [x] Completed and failed runs open at their final state with playback paused.
- [x] Scrubbing changes the visible event horizon and updates metrics and visible activity to match that time.
- [x] Live runs auto-follow the current edge until the user scrubs backward or disables live-follow.
- [x] Incoming live events continue buffering while the user investigates historical time, and jump-to-live returns to the current edge.
- [x] Playback speed applies to historical playback and does not distort live-follow behavior.
- [x] Browser-level tests cover view switching, scrub behavior, live-follow pause, buffered incoming events, and jump-to-live.

## Comments

Implemented in the issue 05 swimlane, sequence, and playback change.
Added swimlane and sequence views, playback scrubber, play/pause, speed control, live-follow pause, jump-to-live, horizon-filtered metrics/activity, and packaged-shell smoke coverage for the controls.
Verified with the full unittest suite, diff check, and code-review skill.
