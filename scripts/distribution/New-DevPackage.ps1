param([Parameter(Mandatory)][string]$BuildDirectory,[Parameter(Mandatory)][string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$output = Assert-PlainPath $OutputDirectory
if (Test-Path -LiteralPath $output) { throw 'Output directory must not already exist.' }
$build = Assert-PlainPath $BuildDirectory
foreach ($binary in @('relayne.exe','relayne_team.exe')) {
    if (!(Test-Path -LiteralPath (Join-Path $build $binary) -PathType Leaf)) { throw "Missing binary: $binary" }
}
$cargo = Get-Content -LiteralPath (Join-Path $repo 'Cargo.toml') -Raw
$version = [regex]::Match($cargo,'(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if ($version -notmatch '^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$') { throw 'Invalid package version.' }
New-Item -ItemType Directory -Path $output | Out-Null
foreach ($binary in @('relayne.exe','relayne_team.exe')) {
    Copy-Item -LiteralPath (Join-Path $build $binary) -Destination (Join-Path $output $binary)
}
foreach ($script in @('Install-Relayne.ps1','Uninstall-Relayne.ps1','Test-Package.ps1','Package.Common.ps1','messages.json')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination (Join-Path $output $script)
}
foreach ($language in @('en-US','de','fr','it')) {
    $doc = Join-Path $output ('docs/' + $language)
    New-Item -ItemType Directory -Path $doc -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo ('docs/distribution/' + $language + '/guide.md')) -Destination (Join-Path $doc 'guide.md')
}
$files = @(Get-PackageFiles $output | Sort-Object FullName | ForEach-Object {
    @{path=$_.FullName.Substring($output.TrimEnd('\').Length+1).Replace('\','/'); bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
$revision = (& git -C $repo rev-parse HEAD | Out-String).Trim()
$dirty = ![string]::IsNullOrWhiteSpace((& git -C $repo status --porcelain | Out-String))
@{schema='relayne-dev-package-v1';product='Relayne';version=$version;channel='development';sale_ready=$false;
    source_revision=$revision;source_dirty=$dirty;binary_source_binding_verified=$false;
    languages=@('en-US','de','fr','it');created_utc=[DateTime]::UtcNow.ToString('o');files=$files
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding UTF8
$null = Read-VerifiedPackage $output
Write-Output $output
