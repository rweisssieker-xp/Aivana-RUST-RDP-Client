# Production delivery and recovery

Production delivery is separate from `New-DevPackage.ps1` and its explicit unsigned-development installer. Development hashes detect damage; they do not establish publisher authenticity. These production tools require PowerShell 7 on Windows, a trusted Authenticode code-signing certificate, signed executables, and an independently configured publisher certificate thumbprint. Do not accept a thumbprint supplied by the download manifest or release website as the trust configuration.

The authorized release operator signs both executables in the build/signing system, then runs:

```powershell
./scripts/distribution/New-ProductionPackage.ps1 -BuildDirectory ./target/release -OutputDirectory ./release-production -Version 0.1.0 -PublisherThumbprint $ApprovedPublisherThumbprint -TimestampServer $ApprovedHttpsTimestampService
```

The publisher certificate with its private key must already be available in `Cert:\CurrentUser\My`. The script creates no keys and never signs the executables itself. The output contains two signed executables and an Authenticode-signed `manifest.ps1` data envelope. Consumers parse that file as data and never execute it. Publish these three files unchanged to a version-specific HTTPS directory using the organization's release process.

Install from a local verified package or an approved HTTPS release directory:

```powershell
./scripts/distribution/Update-Production.ps1 -PackageDirectory ./release-production -PublisherThumbprint $ApprovedPublisherThumbprint
./scripts/distribution/Update-Production.ps1 -ReleaseUrl $ApprovedVersionSpecificHttpsUrl -PublisherThumbprint $ApprovedPublisherThumbprint
```

Downloads reject redirects, credentials, queries, fragments, non-HTTPS URLs and non-200 responses. They have a five-minute timeout per file, a 64 KiB manifest cap and a 512 MiB executable cap. Manifest properties, version syntax, exact filenames, sizes, hashes, signature trust and certificate pin must pass. Installers verify both before copying and after staging. Version directories are immutable; new releases must increase the selected version; identical verified versions are a no-op. A same-volume rename exposes the completed directory, then an atomic `current.txt` replacement selects it. The delivery lock serializes install/rollback. A pointer-switch failure leaves the previous selection intact and may leave an unselected verified version; inspect it before recovery. Failed stages and downloads remain for inspection and are never automatically executed or deleted.

The production root defaults to `%LOCALAPPDATA%\Relayne\production`, distinct from development installs. `current.txt` selects a directory under `versions`; these tools do not install a service or shortcut. Close Relayne before changing the selected version. Use `Start-Production.ps1 -PublisherThumbprint $ApprovedPublisherThumbprint` as the trusted shortcut target (through PowerShell 7); it reads the selection and re-verifies the manifest and binaries before starting. Local account administrators and processes running as the installing user remain within the trust boundary; protect the script distribution and root with normal Windows ACLs.

## Optional automatic updates

Automatic scheduling is opt-in and separate from installing a version. Before registration, distribute the bootstrap scripts through a trusted process and Authenticode-sign `Update-Production.ps1`, `Production.Common.ps1` and `Package.Common.ps1` with the configured publisher certificate. Keep these scripts in a stable local directory with appropriate Windows permissions. Registration rejects unsigned scripts and certificate mismatches, so unsigned development scripts cannot enable production scheduling.

```powershell
./scripts/distribution/Register-UpdateTask.ps1 -ReleaseUrl $ApprovedHttpsReleaseDirectory -PublisherThumbprint $ApprovedPublisherThumbprint -EnableAutomaticUpdates
./scripts/distribution/Get-UpdateTask.ps1
./scripts/distribution/Remove-UpdateTask.ps1 -ConfirmRemoval
```

The task runs at logon and every six hours while the same user is signed in, using least privilege and no stored password. It invokes a fixed PowerShell 7 executable with `-File` and process-scoped `AllSigned`; no execution-policy bypass or global policy change is used. The publisher must already be trusted for noninteractive execution, and organizational policy may still block execution. Parameters are individually quoted, and the URL cannot contain credentials or queries. Explicitly add `-ReplaceExistingTask` to replace an existing schedule. Removing the schedule does not stop an already-running update.

The configured HTTPS directory supplies the current signed release manifest and executables. Same-version content is re-verified and becomes a no-op; different content under the same version is rejected. Older versions are never installed automatically. New versions are staged and selected without replacing binaries already running; the verified launcher uses the selected version on its next invocation. These scripts perform no data migration, so data compatibility remains release-specific and must be established before a release enters the automatic channel. Protect and retain backups according to the recovery procedure below.

Publisher certificate rotation, bootstrap relocation, channel changes and PowerShell installation changes require explicit review and re-registration. Signing keys, trusted-publisher configuration, HTTPS channel operation and real scheduled-task acceptance remain external prerequisites. `Test-UpdateTask.ps1` mocks signatures and Task Scheduler and registers no real task.

## Backup and rollback

Before updating, close every Relayne process and create a separately protected backup of the actual user data directory and any separately configured recording directories. The default persistent data location is `%APPDATA%\Aivana\RustRdpClient`; confirm the application configuration and any custom paths. Preserve the old version and record which version produced the backup. Verify backup readability, completeness and the restore procedure before relying on it. Configuration may contain secrets; restrict backup permissions. A backup of binaries is not a backup of user data.

No delivery script migrates, restores, deletes, or overwrites user data. Binary rollback is explicit and requires the operator to establish data compatibility:

```powershell
./scripts/distribution/Rollback-Production.ps1 -Version 0.1.0 -PublisherThumbprint $ApprovedPublisherThumbprint -AcknowledgeDataCompatibility
```

Rollback re-verifies the retained package and atomically changes only the selection. It retains newer binaries, data, and backups. If the older version cannot read the current data, close the application, preserve the current data in a new backup, and separately restore a verified compatible backup before launching it. Do not overwrite the only current-data copy. There is no automatic data rollback or backup-retention cleanup.

## Restore into a new inspection directory

```powershell
./scripts/distribution/Restore-ProductionData.ps1 -BackupDirectory 'C:\protected\backup' -Destination 'C:\protected\restore-for-review' -AcknowledgeSameWindowsAccount
```

The destination must not exist and its parent must already exist. The command never overwrites the active application directory or an existing backup. It requires the backup's Windows SID to match the current account, rejects links/junctions, absolute or traversing paths, duplicate inventory entries, unexpected or missing files, and mismatched sizes or hashes. Limits are 4 MiB of inventory, 10,000 files/directories, 512 MiB per file and 8 GiB of file contents. Contents are staged under a fresh private ACL, re-verified after copying and moved into the new destination. Failed copying removes only the verified task-owned staging directory; if its safety checks fail, staging is retained for inspection.

Inventory hashes establish consistency with the unsigned local backup, not publisher authenticity. Restoring bytes does not prove DPAPI decryptability, application schema compatibility or successful migration. Inspect the new directory and run version-specific acceptance with the original Windows account and keys before any operator-controlled switch. Close Relayne, preserve the current data separately, and follow the accepted version's data-location procedure; this script never switches the live data directory or modifies binaries.

Fixture validation completed in this workspace: **27 production checks, 17 update-scheduling checks and 20 restore checks**. Restore tests cover valid nested/empty files, private ACLs, traversal and account rejection, extra/missing/tampered files, junctions, simulated copy corruption, staging cleanup and original-data retention. These tests use temporary fixtures only and establish no live customer-data restoration result.

## Release prerequisites and validation

Certificate issuance, secure private-key access, trusted timestamp service, independently distributed certificate pin, release HTTPS hosting, signing CI and release approval are external prerequisites. Certificate renewal requires an explicit trusted pin update. These scripts do not establish commercial readiness or attest to a live published channel. Test production signing and Windows trust/revocation behavior in the release environment before shipping.

Run `pwsh -NoProfile -File scripts/distribution/Test-Production.ps1` for isolated fixture tests. Signature results are mocked there; no fixture is a real publisher-signed artifact, and no network/signing operation is performed.

Create a private local backup with `Backup-ProductionData.ps1 -Destination <new-directory> -ConfirmApplicationClosed`. The script rejects links, copies data after removing inherited destination permissions, verifies copied hashes against the source, and records an unsigned integrity inventory. The inventory is not publisher-authenticated. DPAPI-protected credentials require the original Windows account and its keys; a cross-account or cross-machine copy is not a usable credential migration. No automatic restoration is provided.
