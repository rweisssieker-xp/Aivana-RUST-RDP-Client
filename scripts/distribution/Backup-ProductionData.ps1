#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][switch]$ConfirmApplicationClosed,
    [string]$DataDirectory = (Join-Path $env:APPDATA 'Aivana\RustRdpClient')
)
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
if (!$ConfirmApplicationClosed) { throw 'Close all Relayne processes before creating a consistent backup.' }
$source = Assert-PlainPath $DataDirectory
$destinationPath = Assert-PlainPath $Destination
if (!(Test-Path -LiteralPath $source -PathType Container)) { throw 'Data directory does not exist.' }
if ($destinationPath.StartsWith($source.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $destinationPath)) { throw 'Backup must be a new directory outside the source.' }
# Reject links before recursive traversal, including directory junctions.
$queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($source)
$files = [Collections.Generic.List[string]]::new()
while ($queue.Count) {
    foreach ($item in Get-ChildItem -LiteralPath $queue.Dequeue() -Force) {
        $plain = Assert-PlainPath $item.FullName
        if ($item.PSIsContainer) { $queue.Enqueue($plain) } else { $files.Add($plain) }
    }
}
New-Item -ItemType Directory -Path $destinationPath | Out-Null
# Private per-user backup: remove inherited ACLs before copying secrets.
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $destinationPath -AclObject $acl
$null = Assert-PlainPath $destinationPath
$entries = foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($source, $file)
    $target = Assert-PlainPath (Join-Path $destinationPath ('data/' + $relative))
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath (Assert-PlainPath $file) -Destination (Assert-PlainPath $target)
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if ($hash -ne (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash) { throw 'Source changed during backup; retain this incomplete backup only for inspection.' }
    @{path=$relative;sha256=$hash;size=(Get-Item -LiteralPath $target).Length}
}
@{schema='relayne-user-backup-v1';created_utc=[DateTime]::UtcNow.ToString('o');windows_sid=$sid.Value;authenticity='unsigned-local-integrity-only';files=@($entries)} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destinationPath 'backup.json') -Encoding utf8
Write-Output "Backup created at $destinationPath. Inventory hashes provide integrity only. DPAPI credentials require the original Windows account and keys. No data was restored."
