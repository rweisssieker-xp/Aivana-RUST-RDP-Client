# Recording and integration independent review

Reviewed 2026-09-11: `src/recording.rs`, `src/app/recordings_panel.rs`, `src/integrations.rs`, `src/app/integrations_panel.rs`, with credential-store and polling hooks inspected where necessary. Scope follows Tasks 3 and 4 of the Mission Control plan. Static review only; no implementation edits, remote authentication, real vault retrieval or test execution. Line numbers refer to the source at review time.

## Findings

### P1: Bind an in-flight vault request to the reviewed profile contents

Locations: `src/app/integrations_panel.rs:16`, `src/app/integrations_panel.rs:52-56`, `src/app/integrations_panel.rs:217`.

The pending request retains only a profile UUID. On completion the handler looks up that UUID and applies the login/password to its current contents, including taking the current domain. Other views remain available while the vault worker runs for up to 45 seconds. Editing the target's host, port, protocol, domain or credential association during that interval therefore assigns the returned secret to an endpoint/identity different from the one reviewed. Checking that the UUID still exists only protects deletion. Snapshot the relevant target fields at dispatch and compare before storing; reject stale results and require a fresh explicit assignment rather than silently applying them to the edited profile.

### P2: Failed profile persistence still replaces an existing credential

Locations: `src/app/integrations_panel.rs:56-68`; credential-store behavior at `src/security.rs:149-173`.

`credentials.save` reuses and overwrites `profile.credential_id` before the updated profile list is persisted. If profile persistence then fails, the old profile is retained but still references the credential ID that was just replaced. This leaves its stored username/domain and credential contents inconsistent and loses the previous credential despite the incomplete operation. The failure message about an unsaved profile link is especially misleading for an existing credential because that old link already points at the replacement. Store the new secret under a fresh credential ID, persist the updated profile link, and only retire the previous credential after success (or provide an equivalent rollback/transaction). A failure must leave the existing profile and its referenced secret usable together.

### P2: Recording finalization failure permanently occupies the recorder slot

Locations: `src/recording.rs:53-56`, `src/app/recordings_panel.rs:24-27`.

If the final protected index write fails, the worker sends only an error and exits. The poller handles that error by setting `stopping=true`, but clears `active` only after receiving an `Ok` recording with `finished=true`. Its `while let Ok(...)` loop silently ignores receiver disconnection. The application consequently stays at “Aufzeichnung wird abgeschlossen …”, disables Stop, and cannot start another recording until restart. A persistent disk/permission failure after any frame causes the same path; a worker panic also leaves the slot occupied. Distinguish Empty from Disconnected and release the active slot with an explicit failed/interrupted result, retaining the last valid archive metadata and failure message. Do not require successful disk finalization to reclaim worker state.

## Verified behavior and limits

- Recording start is explicit and bound to a session UUID. Capture ignores other sessions, samples changed hashes at most once per second, uses a two-frame bounded input queue, and enforces 600 frames plus a 128 MiB encoded-PNG budget. Stop removes the sender; even a full queue drains and then terminates the worker. The stated byte quota measures PNG payload, not all DPAPI/index filesystem overhead.
- Masks are validated and applied before PNG encoding and encryption. Frame dimensions/byte lengths are checked. Index writes use temporary files and replacement. Archive frame paths must exactly match the generated numeric filename; export uses create-new semantics and is explicitly unencrypted.
- Playback actually decrypts and decodes saved frames and supports a frame slider. Search actually matches recording titles and saved frame notes. It does not currently index session/timeline events, expose matching frame hits or perform timed video playback. The UI accurately describes keyframes rather than video/audio. The plan's “searchable event index” should not be claimed as delivered beyond these manual frame notes unless event capture is added.
- Inventory parsing has byte/row bounds, ignores imported IDs/passwords/credential references, generates new profile identities, validates hosts/metadata and skips duplicate endpoint conflicts. Selected candidates are rechecked against current profiles before writing; in-memory profiles change only after successful profile persistence. AD rejects oversized/truncated responses and presents prerequisites/failure rather than manufactured data.
- Bitwarden receives a validated UUID and no password/token in command arguments. The inherited session is declared as a prerequisite. Secret stdout travels through a private result channel, diagnostics do not echo vault content, stderr is discarded, and the output buffer is cleared after parsing. Windows pipe peeking avoids a detached blocking output reader. Successful receipt is followed by DPAPI storage, subject to the two findings above.
- The vault process loop has time and output limits. Its cleanup uses `child.kill()` followed by `child.wait()` without a separate cleanup deadline, so the normal 45-second timeout is not a hard guarantee if process termination itself fails. This is a residual bounded-cleanup limitation, not a reproduced hang.
- Archive loading and PNG decoding occur on the UI thread; aggregate archive work can grow across up to 1000 recordings. One malformed/unreadable index currently fails the entire catalog refresh. No large-archive or slow-filesystem responsiveness acceptance was performed.

Focused follow-up tests should cover profile edits during a delayed vault result, a profile-save failure while replacing existing credentials, and recording-worker disconnection/final-index failure. None requires a live server or a real vault secret.
