# Remote operations independent review

Reviewed 2026-09-11 against Task 1 of `docs/superpowers/plans/2026-09-11-mission-control.md`. Scope: full current `src/operations.rs` and `src/app/operations_panel.rs`. Static review only; no remote authentication, execution, or file transfers. Implementation files were not changed by this review.

## Findings

### P2: Pipe timeout does not bound the lifetime of capture workers

Location: `src/operations.rs:459-465`, with worker creation in `capture` at lines 336-354.

Each output stream has a detached thread blocked in `Read::read`. The 500 ms receive timeouts only stop the runner from waiting for those threads; they do not cancel the reads or close their handles. If a child/descendant retains an inherited output handle after the direct process exits (for example a configured SSH helper), the job becomes terminal and the queue can start another job while both capture threads remain alive. Clearing completed jobs does not reclaim these workers, so repeated executions bypass the nominal 32-job resource bound. Normal successful process exit also skips tree termination entirely.

Use owned process-tree lifetime management and cancellable pipe reads/explicit reader shutdown, then verify that descendants retaining pipes cannot leave workers behind. A local regression should cover a process that exits after starting a descendant with inherited output handles; the existing sleeping-process timeout test does not exercise this case.

### P2: Cancellation needs an explicit remote-outcome-unknown state or disclosure

Location: `src/operations.rs:426-434`; user-facing cancellation at `src/app/operations_panel.rs:205-206`.

Cancelling or timing out terminates the local SSH/PowerShell/SFTP process and immediately records `Cancelled`/`TimedOut`. This does not establish that a command or service transition already accepted by the remote host has stopped, nor that it was rolled back. The queue then advances to the next job. For example, cancellation during a service restart can leave the restart in progress while the next queued administrative action starts. The panel explains partial files and process-code completion, but does not explain this remote execution uncertainty for cancellation.

Show a clear German warning/result that local transport was stopped and the remote outcome is unknown and must be checked before retrying. Do not represent transport cancellation as proof of a cancelled remote change. If sequentiality is intended to cover remote actions, hold subsequent queued actions until the operator explicitly resumes after inspection.

## Checks without findings

- Endpoint and service-name allowlists prevent injection into the generated PowerShell expressions. SSH options and destination are separate arguments. The custom SSH command is intentionally a remote shell program and is identified as such in the panel.
- Strict host-key checks and batch authentication are requested. No password is constructed into arguments or scripts.
- SFTP input rejects line breaks, double quotes, control characters and wildcard syntax; paths are quoted and local transfer paths must be absolute. Overwrite and partial-file semantics are disclosed before review. No delete or implicit retry command is generated.
- Review is invalidated when the built command preview changes, and enqueue receives the spec from that same render. Editing the destination, operation or relevant inputs cannot retain approval for a different built command.
- Completion is explicitly described as process code zero, not verified business success. Typed service actions also wait for and query the requested service state.
- Output collection is bounded per channel; retained jobs are bounded. Queued cancellation, local timeout, nonzero exit and ordinary output limits have dedicated tests in the source. These tests were inspected, not executed as part of this review.
- Hidden Windows process creation, timestamps and actual captured stdout/stderr are present. Missing executables surface as failures.

## Coverage limits

No live acceptance was attempted. Host configuration, WinRM policy, authentication, SFTP server path behavior and remote cancellation behavior remain dependent on the deployed environment. Root app integration and mission semantics are outside this two-file review.
