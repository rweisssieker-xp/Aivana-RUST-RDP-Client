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
- OpenSSH SFTP batch stdin: directory listing, upload and download, with quoted validated paths and an absolute local path. Transfers enter the same serial queue. No wildcard, newline or batch-command injection in paths. Existing files may be overwritten only through the reviewed transfer action, with this behavior displayed before enqueueing.

## Job execution and limitations

- Background threads keep process execution off the UI thread. Processes are hidden on Windows.
- Cancellation and 120-second job timeout stop the local process. Windows first attempts `taskkill /T /F` with a bounded two-second helper lifetime, then kills the direct child. This is best-effort local process-tree cleanup, not a guarantee that an already-started remote operation is undone. Each pipe capture stores at most 128 KiB and continues draining excess data.
- Exit and pipe cleanup have bounded waits. On Windows, capture workers use `PeekNamedPipe` and read only bytes already available. After a bounded drain interval the worker stop flag ends polling and the runner joins both readers, closing their handles even when descendants retain stdout/stderr. Incomplete streams are labelled. The non-Windows fallback does not provide this Windows-specific cancellation guarantee.
- `Completed` means process exit code zero, not independently proven business success. Service actions additionally query the requested state; users should inspect returned evidence. Truncated output is labelled and must not be assumed to be valid complete JSON.
- The queue and outputs are in memory, not a durable transfer manager. There is no transfer percentage, automatic retry, resumable transfer, file checksum verification, HTTPS/custom-port WinRM configuration, or password-based remote execution. A cancelled transfer may leave a partial file. Starting another job is always deliberate.
- Missing local transport tools surface as actual spawn failures. Live server acceptance and authentication remain untested by design.

## Verification

Seven standalone module tests passed using the installed Rust toolchain (`rustc --edition 2024 --test src/operations.rs`), in approximately one second:

1. Endpoint and SFTP injection-sensitive input rejection.
2. Strict noninteractive SSH option construction.
3. Typed service action validation and returned state verification script.
4. Absolute local paths and quoted SFTP transfer construction (observed failing before implementation, then passing).
5. Real local stub-process queue lifecycle, actual stdout, nonzero exit and cancellation before launch.
6. Real local stub-process timeout, running cancellation, and output caps for both stdout and stderr.
7. A local parent exits while its spawned child retains inherited output handles for eight seconds. The runner returns in under four seconds after joining both readers; the remaining local stub is explicitly terminated. This regression passed with the nonblocking pipe reader implementation.

Only local PowerShell stubs were executed; no network connections, authentication attempts, service modifications or remote file transfers were performed. Parent integration owns the full Cargo build and UI validation.
