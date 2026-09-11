# Demonstration to reusable procedure

The native Teaching view records manual remote-desktop actions for the session explicitly selected at Start. The recorder is bounded to 200 steps; dimensions changing or connection loss stop capture. It does not record screenshots, clipboard paths/content, pointer motion, resize or verification actions. Drag gestures are omitted.

TypeText, ordinary physical keys and hotkeys become opaque input placeholders. Text contents and printable key codes never enter the serialized procedure. Consecutive placeholders coalesce. This deliberately cannot reconstruct arbitrary key chords: users must review placeholders and replace them with an appropriate newly entered text or delete them. Navigation keys require a matching press/release before becoming an atomic navigation tap. Pointer buttons require matching press/release at the same position before becoming a click. Partial gestures are discarded at stop.

Users review, reorder, remove and edit click/scroll coordinates; a success criterion and recovery note are required. Save uses Windows DPAPI and one local `teaching.dpapi` slot; the UI explicitly states that saving replaces the previous slot. Non-Windows persistence fails closed. Loading is size-bounded and validates the closed Step schema, allowed navigation keys, coordinates, lengths and step count. Neither typed text nor execution history is persisted. Notes are user-provided and should not contain credentials.

Replay requires a connected selected session, identical framebuffer dimensions and a fresh approval for exactly one step. Approval is bound to the selected session; switching targets invalidates it. Text placeholders require a new ephemeral masked text entry, cleared after attempting the step. Existing policy blocks denied text/actions. Navigation key presses are paired with releases in that step; engine release_inputs is also called after every execution attempt and on abort. There is no timer or automatic continuation. A successful enqueue is labeled sent, never verified: the user must inspect the desktop and explicitly confirm the effect before advancing. Disconnect or dimension changes reset playback. Same dimensions do not establish identical layout; visual review remains mandatory.

The bounded in-memory history distinguishes sent/aborted from manually confirmed effects. It is not machine verification, learning, semantic target recognition or a runbook migration. Existing runbook code is unchanged.

Unit coverage: target session isolation, action count bound, plaintext and clipboard omission, dimension mismatch capture/replay rejection, matched navigation releases and rejection of arbitrary scan codes. Native input observation integration belongs to the app/engine: only manual canvas input is observed, never replay or autopilot input.

Modifier-held navigation is retained as one opaque placeholder, never simplified into a different plain navigation action. Matching consecutive pointer-button pairs within 350 ms coalesce into a double-click; differing or late pairs remain separate steps. Saving atomically replaces the previous encrypted procedure.

Validation: `cargo test teaching::tests --no-default-features` passed all seven tests on Windows, including Shift+Tab and paired double-click regression coverage. No live remote actions were executed during development.
