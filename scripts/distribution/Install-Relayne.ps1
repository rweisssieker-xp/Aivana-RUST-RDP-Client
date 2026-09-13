param([ValidateSet('en-US','de','fr','it')][string]$Language='en-US',[switch]$AllowUnsignedDev)
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
if (!$AllowUnsignedDev) { throw (Get-Text 'unsigned' $Language) }
try { $manifest = Read-VerifiedPackage $PSScriptRoot } catch { throw (Get-Text 'invalid' $Language) }
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw (Get-Text 'invalid' $Language) }
$base = Assert-PlainPath (Join-Path $env:LOCALAPPDATA 'Relayne\versions')
$destination = Assert-PlainPath (Join-Path $base $manifest.version)
if (Test-Path -LiteralPath $destination) { throw (Get-Text 'exists' $Language) }
$stage = Assert-PlainPath (Join-Path $base ('.staging-' + [guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
# No existing version is changed, even if copying or verification fails.
foreach ($entry in $manifest.files) {
    $target = Join-Path $stage $entry.path
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $entry.path) -Destination $target
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Destination (Join-Path $stage 'manifest.json')
$null = Read-VerifiedPackage $stage
# Verify both final paths immediately before moving; no recursive computed move across shells.
$stage = Assert-PlainPath $stage
$destination = Assert-PlainPath $destination
if (!(Split-Path -Parent $stage).Equals($base,[StringComparison]::OrdinalIgnoreCase) -or
    !(Split-Path -Parent $destination).Equals($base,[StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $destination)) { throw (Get-Text 'invalid' $Language) }
Move-Item -LiteralPath $stage -Destination $destination
Write-Output (Get-Text 'installed' $Language)
Write-Output ((Join-Path $destination 'relayne.exe') + ' --language ' + $Language)
