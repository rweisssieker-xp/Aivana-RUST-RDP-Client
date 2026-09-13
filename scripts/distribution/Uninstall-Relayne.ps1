param([Parameter(Mandatory)][string]$Version,[ValidateSet('en-US','de','fr','it')][string]$Language='en-US')
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
if ($Version -notmatch '^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$' -or [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw (Get-Text 'invalid' $Language)
}
$base = Assert-PlainPath (Join-Path $env:LOCALAPPDATA 'Relayne\versions')
$destination = Assert-PlainPath (Join-Path $base $Version)
if (!(Split-Path -Parent $destination).Equals($base,[StringComparison]::OrdinalIgnoreCase)) { throw (Get-Text 'invalid' $Language) }
try { $manifest=Read-VerifiedPackage $destination } catch { throw (Get-Text 'invalid' $Language) }
if ($manifest.version -ne $Version) { throw (Get-Text 'invalid' $Language) }
# Reject added/changed files instead of deleting unrecognized content.
$destination = Assert-PlainPath $destination
if (!(Split-Path -Parent $destination).Equals($base,[StringComparison]::OrdinalIgnoreCase)) { throw (Get-Text 'invalid' $Language) }
Remove-Item -LiteralPath $destination -Recurse
Write-Output (Get-Text 'removed' $Language)
