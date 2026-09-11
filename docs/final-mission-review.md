# Final scoped Mission Control review

Reviewed 2026-09-11. Scope: the six prior mission findings, three recording/integration findings, teaching module and manual-input integration, and detached-session ownership. Static inspection only; no implementation edits, authentication, live remote input, or test execution. References identify the pre-format source reviewed.

## Remaining findings

### P2: Modified navigation is replayed as a different action

Location: `src/teaching.rs:163-180`.

The recorder treats a modifier press as `TextRequired` but does not track whether it remains held. A subsequent navigation key is therefore captured as ordinary `Navigation`. For example, Shift-down, Tab-down, Tab-up, Shift-up produces a text placeholder followed by plain Tab. Replay moves focus forward rather than backward. Ctrl+Enter and other modified navigation combinations can similarly acquire a different effect. Track modifier/chord state and either retain a deliberately supported chord or represent the whole unsupported chord as a manual placeholder. Do not retain the unmodified navigation fragment. A direct Teacher test with Shift+Tab is sufficient to expose this without remote execution.

### P2: Real demonstrated double-clicks become two unrelated single clicks

Locations: `src/teaching.rs:182-202`, `src/app.rs:2696`, `src/app/teaching_panel.rs:227-242`.

The remote canvas forwards mouse input as raw PointerButton pairs. Each same-position press/release is recorded immediately as a single Click. Although Teacher supports an already-formed DoubleClick action, the manual canvas does not supply that variant. A real double-click thus becomes two single-click steps. Replay requires a separate human confirmation between steps, so their double-click timing is lost and the demonstrated action (such as opening an item) is not reproduced. Recognize paired clicks with appropriate timing/button/position metadata, allow an explicit reviewed double-click conversion, or mark the demonstrated action unsupported rather than offering a misleading equivalent.

### P2: Saving a teaching procedure can destroy the previous saved procedure

Location: `src/teaching.rs:246`.

Teaching has exactly one persisted procedure and replaces it using `std::fs::write`. That truncates the previous file before the replacement finishes. A partial write/full disk or interruption leaves no readable old procedure even though save reports failure. Use the existing `security::atomic_write` helper, preserving the previous file until the new protected bytes have been written successfully. This is consistent with the newly corrected credential persistence path.

## Re-review of earlier findings

All nine earlier main findings are addressed in the inspected paths:

- Mission running intent is saved successfully before remote enqueue; failed persistence prevents dispatch.
- Terminal jobs without results are synthesized into an explicit result, clearing the pending mission association and allowing review rather than leaving every mission blocked.
- Targets bind protocol, username, domain and route as well as profile/host/port; SSH steps reject non-SSH profiles.
- Session-source snapshots are captured on connection, and mission session evidence requires a matching snapshot.
- Load/import reject mismatched or empty evidence and Passed outcomes without verification notes.
- Import remaps evidence UUIDs and all outcome references.
- Vault completion compares a captured profile snapshot, update time and credential reference before applying the result.
- Vault saves under a fresh credential reference before linking the profile. Profile failure leaves the old credential intact. Credential-store save restores its in-memory state if atomic persistence fails.
- Recording polling distinguishes receiver disconnection and reclaims the active recorder slot when finalization did not produce a successful terminal update.

A smaller persistence-disclosure issue remains: mission creation and JSON import still assign unconditional success text after `save_missions()` returns false. This no longer permits unpersisted remote execution, but the UI can wrongly imply the new mission/import survived a restart. Retain the save error and label the in-memory result unsaved.

## Teaching integration and focus checks

- Only manual-canvas sends enter the bounded observation queue; replay and autopilot use ordinary `send_input`. Text and Hotkey contents are replaced with empty markers before entering that queue. Teacher ignores unrelated sessions and clears incomplete key/button pairs on stop.
- The app drains observations into Teacher, validates connection and frame dimensions, and enables capture only while recording. Replay is one explicitly approved step at a time, checks dimensions/policy, releases held inputs, clears transient text and requires manual outcome confirmation.
- Changing selected session, disconnecting or resizing resets replay. Editing the procedure invalidates replay state. No automatic successful business result is inferred from sending an input.
- Detached focused sessions are selected, other inputs are released, and the main canvas avoids rendering the same detached session. Clipboard ownership remains exclusive in the engine; closing a detached viewport releases its input state. No additional definite ownership or clipboard-concurrency blocker was established by static inspection.

Native focus transitions and input timing still need interactive acceptance. Tests being added by the root worker were not run or represented as passing by this review. Recording event text is now included in frame notes; events occurring without a changed captured frame remain outside that frame-based index.
