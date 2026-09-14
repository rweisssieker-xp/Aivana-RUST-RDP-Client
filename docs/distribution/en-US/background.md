# Optional recovery checks while logged out

The application scheduler normally uses an interactive Windows token. For checks while logged out, explicitly register a password-logon task under the **same Windows account** that created Relayne's DPAPI data. PowerShell 7 and Windows Task Scheduler are required. No task is installed automatically.

First save the intended scoped background approvals in Relayne. The worker retains existing authorization checks, expiration (maximum 168 hours), bounded attempts and clone-only unattended mutation rules. Task registration does not extend approvals or authorize production changes. Select a trusted, stable local `relayne.exe` path; moving or replacing that executable changes what the task runs. For production, verify it with the production package tools first and restrict write access to its directory.

```powershell
./scripts/background/Register-LoggedOutRecovery.ps1 -Executable 'C:\approved\Relayne\relayne.exe' -EnableLoggedOutOperation -ConfirmScopedApprovals
```

The credential prompt requires the exact current `DOMAIN\user` identity and its Windows password. A Windows Hello PIN is not the account password. The password passes to Task Scheduler through its in-process COM API; it is never placed on a command line, in task XML, in an environment variable or in a script-created file/log. Windows stores the task credential for future logons. The native temporary password buffer is zeroed; the managed interop string is released for garbage collection and cannot be guaranteed immediately zeroed. Use a trusted local session without diagnostic capture of process memory.

Windows must permit **Log on as a batch job**. Domain policy, account restrictions, password changes, unavailable user profiles or missing DPAPI keys may prevent execution. The script never changes those policies, switches to SYSTEM, elevates the worker or claims that registration guarantees execution. Relayne's server/network credentials are separate from the Windows task credential. Cross-account or cross-machine data copies do not migrate DPAPI credentials automatically.

The task invokes `--recovery-worker-once` every five minutes at least privilege, ignores overlapping instances and has a two-hour execution limit. It shares the application scheduler's per-data-directory task name. An existing task is preserved unless you explicitly add `-ReplaceExistingTask`; this can replace the application's interactive task. Reinstalling scheduling from the application can conversely restore interactive-only operation. Neither registration nor removal starts or stops an existing worker directly.

```powershell
./scripts/background/Get-LoggedOutRecovery.ps1
./scripts/background/Remove-LoggedOutRecovery.ps1 -ConfirmRemoval
```

Inspect Windows task results and Relayne notices after registration, including a real logged-out test in your own authorized environment. Removal only removes scheduling; revoke approvals in Relayne as well if the authorization should end. User data and credentials are retained.

`Test-Background.ps1` uses mocked identity, credentials and Task Scheduler. It registers no real task and requests no real password. Logged-out execution and domain policy require separate Windows environment acceptance testing.
