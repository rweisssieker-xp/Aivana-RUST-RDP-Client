#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$BackupDirectory,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][switch]$AcknowledgeSameWindowsAccount
)
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
if (!$AcknowledgeSameWindowsAccount) { throw 'Explicit same-account acknowledgement is required. DPAPI keys and version compatibility are separate prerequisites.' }
$source=Assert-PlainPath $BackupDirectory
$destinationPath=Assert-PlainPath $Destination
if (Test-Path -LiteralPath $destinationPath) { throw 'Restore destination must be a new directory; existing data is never overwritten.' }
if ($destinationPath.StartsWith($source.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Restore destination must be outside the backup.' }
$parent=Assert-PlainPath (Split-Path -Parent $destinationPath)
if (!(Test-Path -LiteralPath $parent -PathType Container)) { throw 'Restore destination parent must already exist.' }
$inventoryPath=Assert-PlainPath (Join-Path $source 'backup.json')
if ((Get-Item -LiteralPath $inventoryPath).Length -gt 4194304) { throw 'Backup inventory exceeds 4 MiB.' }
$raw=[IO.File]::ReadAllText($inventoryPath)
$document=[System.Text.Json.JsonDocument]::Parse($raw)
try { Assert-JsonUniqueKeys $document.RootElement } finally { $document.Dispose() }
$inventory=ConvertFrom-Json -InputObject $raw -AsHashtable
Assert-ManifestKeys $inventory @('schema','created_utc','windows_sid','authenticity','files')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
if ($inventory.schema -cne 'relayne-user-backup-v1' -or $inventory.authenticity -cne 'unsigned-local-integrity-only' -or $inventory.windows_sid -cne $sid.Value -or ($inventory.created_utc -isnot [string] -and $inventory.created_utc -isnot [DateTime])) { throw 'Backup identity, account SID, or schema is invalid. Cross-account restoration is not supported.' }
if ($inventory.files -isnot [array] -or $inventory.files.Count -gt 10000) { throw 'Backup file count exceeds 10,000 or has an invalid format.' }
$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$total=0L
foreach ($entry in $inventory.files) {
    Assert-ManifestKeys $entry @('path','sha256','size')
    if ($entry.path -isnot [string] -or !$entry.path -or $entry.path.Length -gt 1024 -or [IO.Path]::IsPathRooted($entry.path) -or $entry.path -match '[\x00-\x1f:*?"<>|]') { throw 'Invalid backup relative path.' }
    foreach ($part in ($entry.path -split '[\\/]')) {
        if (!$part -or $part -in @('.','..') -or $part.EndsWith(' ') -or $part.EndsWith('.') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'Unsafe backup path component.' }
    }
    $entry.path=$entry.path.Replace('/','\')
    if (!$names.Add($entry.path) -or $entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or ($entry.size -isnot [long] -and $entry.size -isnot [int]) -or $entry.size -lt 0 -or $entry.size -gt 536870912) { throw 'Invalid or duplicate backup file entry.' }
    $total+=$entry.size
    if ($total -gt 8589934592) { throw 'Restore exceeds the 8 GiB total limit.' }
    $file=Assert-PlainPath (Join-Path $source ('data/'+$entry.path))
    if (!(Test-Path -LiteralPath $file -PathType Leaf) -or (Get-Item -LiteralPath $file).Length -ne $entry.size -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $entry.sha256) { throw 'Backup file is missing or differs from its inventory.' }
}
# Walk manually so directory junctions are rejected before traversal.
$queue=[Collections.Generic.Queue[string]]::new(); $queue.Enqueue($source)
$seen=0; $directories=0
while ($queue.Count) {
    foreach ($item in Get-ChildItem -LiteralPath $queue.Dequeue() -Force) {
        $path=Assert-PlainPath $item.FullName
        if ($item.PSIsContainer) { $directories++; if ($directories -gt 10000) { throw 'Backup directory limit exceeded.' }; $queue.Enqueue($path); continue }
        if ($path -ieq $inventoryPath) { continue }
        $relative=[IO.Path]::GetRelativePath($source,$path)
        if (!$relative.StartsWith('data\',[StringComparison]::OrdinalIgnoreCase) -or !$names.Contains($relative.Substring(5))) { throw 'Backup contains a file absent from its inventory.' }
        $seen++
    }
}
if ($seen -ne $inventory.files.Count) { throw 'Backup file inventory is incomplete.' }
$stage=Assert-PlainPath (Join-Path $parent ('.relayne-restore-'+[guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $acl=[Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $stage -AclObject $acl
    foreach ($entry in $inventory.files) {
        $target=Assert-PlainPath (Join-Path $stage $entry.path)
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        $file=Assert-PlainPath (Join-Path $source ('data/'+$entry.path))
        Copy-Item -LiteralPath $file -Destination (Assert-PlainPath $target)
        if ((Get-Item -LiteralPath $target).Length -ne $entry.size -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $entry.sha256) { throw 'Copied restore file failed verification.' }
    }
    [IO.Directory]::Move((Assert-PlainPath $stage),(Assert-PlainPath $destinationPath))
    Write-Output "Restored verified backup content into new private directory: $destinationPath. No active data was replaced. Verify DPAPI access and version-specific compatibility before switching data directories."
} finally {
    if (Test-Path -LiteralPath $stage) {
        $checked=Assert-PlainPath $stage
        if ((Split-Path -Parent $checked) -ine $parent -or (Split-Path -Leaf $checked) -cnotmatch '^\.relayne-restore-[a-f0-9]{32}$') { throw 'Unsafe staging cleanup path; staging data retained.' }
        $queue=[Collections.Generic.Queue[string]]::new(); $queue.Enqueue($checked)
        while ($queue.Count) { foreach ($item in Get-ChildItem -LiteralPath $queue.Dequeue() -Force) { $null=Assert-PlainPath $item.FullName; if($item.PSIsContainer){$queue.Enqueue($item.FullName)} } }
        Remove-Item -LiteralPath $checked -Recurse -Force
    }
}
