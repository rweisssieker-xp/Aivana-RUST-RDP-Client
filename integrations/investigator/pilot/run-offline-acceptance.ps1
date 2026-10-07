[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Executable,

    [string] $OutputDirectory = (Join-Path $env:TEMP ("relayne-investigator-acceptance-" + [guid]::NewGuid().ToString('N')))
)

$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
$root = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $root) { throw "Output directory already exists; refusing to overwrite: $root" }
$null = New-Item -ItemType Directory -Path $root

function Invoke-InvestigatorCli([string[]] $Arguments) {
    & $exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Investigator CLI failed ($LASTEXITCODE): $($Arguments -join ' ')" }
}

function Get-Sha256([string] $Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

try {
    $replay = Join-Path $root 'replay'
    Invoke-InvestigatorCli @('replay', $replay)
    $database = Join-Path $replay 'replay.sqlite'
    $report = Join-Path $replay 'report.json'
    if (!(Test-Path -LiteralPath $database -PathType Leaf) -or !(Test-Path -LiteralPath $report -PathType Leaf)) {
        throw 'Synthetic replay did not create its documented database and report.'
    }

    $backup = Join-Path $root 'backup'
    $backupTimer = [Diagnostics.Stopwatch]::StartNew()
    Invoke-InvestigatorCli @('backup', $database, $backup)
    $backupTimer.Stop()

    $verifyOutput = & $exe 'verify-backup' $backup
    if ($LASTEXITCODE -ne 0) { throw "verify-backup failed ($LASTEXITCODE)" }
    $verified = ($verifyOutput -join "`n") | ConvertFrom-Json
    if ($verified.validation.sqlite_integrity -ne 'ok' -or $verified.validation.audit_chain -ne 'verified') {
        throw 'Backup verification did not report SQLite integrity and audit-chain success.'
    }

    $restoredDb = Join-Path $root 'restored.sqlite'
    $restoreTimer = [Diagnostics.Stopwatch]::StartNew()
    $restoreOutput = & $exe 'restore' $backup $restoredDb
    if ($LASTEXITCODE -ne 0) { throw "restore failed ($LASTEXITCODE)" }
    $restoreTimer.Stop()
    $restored = ($restoreOutput -join "`n") | ConvertFrom-Json
    if (!(Test-Path -LiteralPath $restoredDb -PathType Leaf)) { throw 'Restore did not create the new database.' }

    $artifacts = @($report, (Join-Path $backup 'manifest.json'), (Join-Path $backup 'investigator.sqlite'), $restoredDb)
    $receipt = [ordered]@{
        format = 'relayne-offline-acceptance-v1'
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        mode = 'offline_synthetic'
        source_database = [ordered]@{ sha256 = Get-Sha256 $database; bytes = (Get-Item -LiteralPath $database).Length }
        backup_elapsed_ms = $backupTimer.ElapsedMilliseconds
        restore_elapsed_ms = $restoreTimer.ElapsedMilliseconds
        verification = $verified
        restore_result = $restored
        artifacts = @($artifacts | ForEach-Object {
            $relativeUri = ([Uri]($root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar)).MakeRelativeUri([Uri]$_)
            [ordered]@{ path = [Uri]::UnescapeDataString($relativeUri.ToString()).Replace('/', [IO.Path]::DirectorySeparatorChar); sha256 = Get-Sha256 $_; bytes = (Get-Item -LiteralPath $_).Length }
        })
        limitations = @('Synthetic reference scenario only; no provider, tenant, network, credential or external write was used.', 'Elapsed values measure this local run and are not production RTO/RPO evidence.', 'Artifact hashes establish local byte identity, not independent provenance or production approval.')
    }
    $receiptPath = Join-Path $root 'acceptance-receipt.json'
    $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $receiptPath -Encoding utf8
    Write-Output "Offline acceptance passed. Receipt: $receiptPath"
    Write-Output "Backup ms: $($backupTimer.ElapsedMilliseconds); restore ms: $($restoreTimer.ElapsedMilliseconds)"
    Write-Output 'Synthetic only: do not submit this receipt as live pilot evidence.'
}
catch {
    Write-Error "Offline acceptance failed. Partial artifacts retained at '$root'. $($_.Exception.Message)"
    exit 1
}
