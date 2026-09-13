Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-Text([string]$Key, [string]$Language) {
    $catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'messages.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    return $catalog.$Language.$Key
}
function Assert-PlainPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\')) { throw 'UNC paths are not supported.' }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse points are not supported.' }
        }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $full
}
function Get-PackageFiles([string]$Root) {
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point in package.' }
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
            else { $item }
        }
    }
}
function Read-VerifiedPackage([string]$Root) {
    $rootPath = Assert-PlainPath $Root
    $manifestPath = Join-Path $rootPath 'manifest.json'
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 65536) { throw 'Manifest too large.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.schema -ne 'relayne-dev-package-v1' -or $manifest.product -ne 'Relayne' -or
        $manifest.channel -ne 'development' -or $manifest.sale_ready -ne $false -or
        $manifest.version -notmatch '^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$') { throw 'Invalid manifest identity.' }
    $expected = @('relayne.exe','relayne_team.exe','Install-Relayne.ps1','Uninstall-Relayne.ps1',
        'Test-Package.ps1','Package.Common.ps1','messages.json',
        'docs/en-US/guide.md','docs/de/guide.md','docs/fr/guide.md','docs/it/guide.md')
    if (@($manifest.files).Count -ne $expected.Count) { throw 'Invalid file count.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $manifest.files) {
        if ($entry.path -cnotin $expected -or !$seen.Add([string]$entry.path) -or
            $entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid file entry.' }
        $path = Assert-PlainPath (Join-Path $rootPath $entry.path)
        $file = Get-Item -LiteralPath $path
        if ($file.PSIsContainer -or $file.Length -ne $entry.bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Integrity mismatch.' }
    }
    $actual = @(Get-PackageFiles $rootPath)
    if ($actual.Count -ne ($expected.Count + 1)) { throw 'Unexpected package files.' }
    foreach ($file in $actual) {
        $relative = $file.FullName.Substring($rootPath.TrimEnd('\').Length + 1).Replace('\','/')
        if ($relative -ne 'manifest.json' -and $relative -cnotin $expected) { throw 'Unexpected package path.' }
    }
    return $manifest
}
