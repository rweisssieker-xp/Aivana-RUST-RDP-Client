# Mission and detached-session independent review

Reviewed 2026-09-11 against Tasks 2 and 4 in `docs/superpowers/plans/2026-09-11-mission-control.md`. Static review of current mission modules, session windows, and their app hooks; no implementation edits, live remote tests, or authentication. Line references identify the pre-format source reviewed.

## Findings

### P1: Persist running intent before exposing a remote job to execution

Locations: `src/app/mission_panel.rs:101-104`, `src/app/mission_panel.rs:30-32`.

The mission begins and its command is enqueued before `save_missions` runs. Saving only writes an error to the status string and does not return failure to the caller or cancel the queued command. If DPAPI, disk writes or replacement of the existing store fails, the next operations poll still executes the command. Restart then loads the older Pending/Interrupted state without a durable record that the command ran, allowing an arbitrary mutating SSH command to be repeated as an apparently unstarted step. Persist the running intent successfully before enqueue, surface persistence failure persistently, and recover safely if enqueue subsequently fails. Also avoid overwriting save errors with unconditional creation/import success messages.

### P2: Queued cancellation leaves every mission blocked

Location: `src/app/mission_panel.rs:35-54`; producer behavior in `src/operations.rs:305-307`.

Start a long ordinary Operations job, enqueue a mission step behind it, then cancel that queued mission job in Operations. `JobQueue::poll` sets its status to Cancelled without a `JobResult`. `poll_missions` handles only jobs with a result or IDs no longer present, so this terminal job leaves `missions.remote` populated and its outcome Running indefinitely. All mission start controls stay disabled until the operator manually pauses the mission or removes the job. Worker-disconnection failures without results take the same path. Handle every terminal status, record an explicit interrupted/failed state, clear the association and persist the transition.

### P2: Frozen mission targets do not bind the effective SSH identity/port

Locations: `src/mission.rs:20-21`, `src/app/mission_panel.rs:94-99`.

Target matching freezes UUID, host and profile port, but not protocol or username. Dispatch reads the mutable username and chooses the actual SSH port using the current profile protocol, while the mission UI displays the saved target port. A mission created for SSH on port 2222 still passes target matching after the profile protocol changes with host/port unchanged, but then dispatches SSH to port 22. Even without an edit, selecting an RDP profile for an SSH step shows the RDP port while using 22. Username changes also alter the execution identity after review. Store/review the effective operation endpoint and identity, reject incompatible profiles or explicitly display and bind the derived SSH endpoint, and invalidate execution after relevant profile drift.

### P2: Old sessions are relabelled as evidence for an edited endpoint

Location: `src/app/mission_panel.rs:79-85`.

The profile is matched against the mission target, but session lookup subsequently matches only `profile_id`. Connect profile P to host A, edit P to host B, then create and observe a mission for B while A's session remains in the list. The observation copies A's frame hash, errors and timeline into an `Evidence` whose target is B, alongside a fresh TCP check of B. This mixes two hosts into one apparently source-bound observation and can support an incorrect manual pass. Match session evidence against the endpoint captured when that session connected; omit or clearly separate stale session context when the endpoint cannot be established.

### P2: Import validation admits evidence rejected by normal recording

Location: `src/mission.rs:189-191`.

Imported outcome references are validated against evidence UUID and profile UUID only. Evidence with a different host/port, or an empty facts-and-notes payload, is accepted for a Passed/Review outcome. Passed outcomes also need no verification note. A handoff containing such a Passed pilot can be resumed and used to authorize rollout, although the equivalent call to `Mission::record`/`verify` would reject its evidence. Apply the same endpoint, nonempty-evidence and verification invariants during load/import. Reject structurally inconsistent prerequisite completion as appropriate rather than treating JSON status fields as sufficient proof.

### P2: Reimported evidence IDs collide in the cross-mission comparison

Locations: `src/mission.rs:175-179`, `src/app/mission_panel.rs:225-227`.

Import generates a new mission UUID but retains every evidence UUID and outcome reference. Importing a report twice therefore creates duplicate IDs across the book. The comparison UI stores only evidence UUID and resolves with the first matching entry across all missions. Selecting an evidence entry from a later import can silently display/compare the earlier one; this produces wrong results when a handoff has updated evidence values. Remap evidence UUIDs and their outcome references on import, or use `(mission_id, evidence_id)` throughout selection and lookup. The current behavior does not meet collision-safe handoff requirements.

## Re-review of the two operations fixes

- The Windows capture readers now use `PeekNamedPipe`, read only available bytes, observe a stop flag and are joined before returning. With each worker owning its sole read handle, descendants retaining write handles no longer leave blocked capture workers behind. The inherited-pipe regression is present in the source. This addresses the earlier Windows capture-thread finding; the non-Windows blocking-read fallback does not provide the same guarantee, but the supplied operations execute Windows tools.
- The panel now explicitly says cancellation stops local transport, remote actions may continue, and the remote result is unknown after cancellation/timeout. This addresses the earlier disclosure finding. The queue remains sequential only at the local transport level, as disclosed.

## Detached windows and other checks

No additional concrete focus/clipboard blocker was established in the reviewed paths. Detached focused sessions become selected, changing session aborts autopilot and releases other inputs, the main canvas skips detached sessions, blurred/nonconnected detached canvases are disabled, closing detached windows releases inputs, and clipboard ownership is exclusive in the engine. Saved layouts operate on existing sessions and do not initiate connections. Native focus timing and viewport behavior still need interactive acceptance; this static review does not claim they were exercised.

Normal mission recording checks endpoint association; normal manual verification requires evidence and a note; beginning later steps checks previous completion; rollout requires the pilot; pause/restart mark Running outcomes Interrupted. Corrupt encrypted mission-store load is surfaced and does not silently overwrite the store. The findings above concern paths that bypass or weaken these otherwise useful protections.

Recording-module implementation and inventory-worker changes are outside this review. No test suite was run in this read-only pass.
