# Remote operations implementation — 2026-09-11

## Integration API

- `crate::operations` owns endpoint validation, typed requests, command construction and serial `JobQueue`.
- `app::operations_panel::OperationsState::default()` has no I/O. Parent adds `operations` field.
- Call `AivanaApp::poll_operations()` every frame, and `operations_view(ui)` for the German administration panel.
- Each request generates an immutable command preview. Changing the target or request invalidates the review checkbox. Only the explicit enqueue button authorizes execution.
- Jobs contain source host, submission/completion timestamps, immutable command specification, lifecycle state and bounded stdout/stderr. Maximum 32 retained jobs; completed jobs can be removed.

## Implemented transports

- OpenSSH SSH commands: `BatchMode=yes`, `StrictHostKeyChecking=yes`, connection timeout and keepalive. Existing key/agent authentication; no password arguments, credential-store access or authentication retries. Arbitrary commands are explicitly labelled as target-shell commands.
- Windows PowerShell WinRM: script delivered on stdin, current Windows identity with Negotiate. Typed system inventory, services, first 500 processes and last 100 System events in 24 hours. Output is actual JSON from the remote command, retained verbatim within limits. Service Start/Stop/Restart accepts a restricted service name and waits up to 30 seconds for the requested state before reporting it.
- OpenSSH SFTP batch stdin: directory listing, upload and download, with quoted validated paths and an absolute local path. Transfers enter the same serial queue. Optional explicit `-a` resumes an existing partial destination; the UI discloses that its existing bytes must exactly match the unchanged source prefix and that SFTP does not verify prefix integrity. Optional `-R` transfers directories recursively. Both options appear in the reviewed command preview and invalidate previous approval when changed. No automatic retry is performed. No wildcard, newline or batch-command injection in paths. Existing files may be overwritten only through the reviewed transfer action, with this behavior displayed before enqueueing.
- Native two-pane transfer view: explicit background local directory reads retain at most 500 entries and allow selecting absolute file/directory paths. The remote pane shows only stdout from the last successful exact List command for the current host, username, port and remote path, with target/path/completion timestamp and truncation disclosure. It does not parse unreliable textual names into remote actions. Failed jobs and stderr never become a directory listing. Remote target paths remain explicit editable inputs.

## Job execution and limitations

- Background threads keep process execution off the UI thread. Processes are hidden on Windows.
- Cancellation and 120-second job timeout stop the local process. Windows first attempts `taskkill /T /F` with a bounded two-second helper lifetime, then kills the direct child. This is best-effort local process-tree cleanup, not a guarantee that an already-started remote operation is undone. Each pipe capture stores at most 128 KiB and continues draining excess data.
- Exit and pipe cleanup have bounded waits. On Windows, capture workers use `PeekNamedPipe` and read only bytes already available. After a bounded drain interval the worker stop flag ends polling and the runner joins both readers, closing their handles even when descendants retain stdout/stderr. Incomplete streams are labelled. The non-Windows fallback does not provide this Windows-specific cancellation guarantee.
- `Completed` means process exit code zero, not independently proven business success. Service actions additionally query the requested state; users should inspect returned evidence. Truncated output is labelled and must not be assumed to be valid complete JSON.
- The queue and outputs are in memory, not a durable transfer manager. There is no transfer percentage, automatic retry, file checksum verification, remote rename/delete, HTTPS/custom-port WinRM configuration, or password-based remote execution. A cancelled transfer may leave a partial file. Resuming is an explicit reviewed action with a source-prefix integrity assumption; it is not independently verified recovery. Starting another job is always deliberate. Local directory reads are explicit, one at a time, on a worker; an inaccessible network-mounted local directory may depend on OS filesystem timeout.
- Missing local transport tools surface as actual spawn failures. Live server acceptance and authentication remain untested by design.

## Verification

Eight standalone module tests passed using the installed Rust toolchain (`rustc --edition 2024 --test src/operations.rs`), in approximately one second:

1. Endpoint and SFTP injection-sensitive input rejection.
2. Strict noninteractive SSH option construction.
3. Typed service action validation and returned state verification script.
4. Absolute local paths and quoted SFTP transfer construction (observed failing before implementation, then passing).
5. Real local stub-process queue lifecycle, actual stdout, nonzero exit and cancellation before launch.
6. Real local stub-process timeout, running cancellation, and output caps for both stdout and stderr.
7. A local parent exits while its spawned child retains inherited output handles for eight seconds. The runner returns in under four seconds after joining both readers; the remaining local stub is explicitly terminated. This regression passed with the nonblocking pipe reader implementation.
8. Resume/recursive upload and download combinations, invalid transfer paths, and rejection of remote listings from different hosts, users, ports, paths, queued or failed jobs.

An additional app-module regression creates 501 local fixture files and checks the 500-entry bound plus selectable absolute paths. `cargo test --quiet transfer_tests` passed (one test, 0.26 seconds), and `cargo check --quiet` passed with existing unrelated dead-code warnings. Full Cargo-suite execution is owned by root integration.

Only local PowerShell stubs were executed; no network connections, authentication attempts, service modifications or remote file transfers were performed. Parent integration owns the full Cargo build and UI validation.
