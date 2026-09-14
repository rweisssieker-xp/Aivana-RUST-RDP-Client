#requires -Version 7.0
param(
    [Parameter(Mandatory)][ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version,
    [Parameter(Mandatory)][string]$PublisherThumbprint,
    [Parameter(Mandatory)][switch]$AcknowledgeDataCompatibility,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Relayne\production')
)
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
if (!$AcknowledgeDataCompatibility) { throw 'Confirm the older binary can safely read the current data, or restore a separately verified compatible backup first.' }
$root = Assert-PlainPath $InstallRoot
$lock = [IO.File]::Open((Assert-PlainPath (Join-Path $root 'delivery.lock')), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $package = Assert-PlainPath (Join-Path $root "versions/$Version")
    $manifest = Read-ProductionPackage $package $PublisherThumbprint
    if ($manifest.version -cne $Version) { throw 'Retained version identity mismatch.' }
    Set-ProductionCurrent $root $Version
    Write-Output "Selected retained version $Version. User data and all retained versions were left intact."
} finally { $lock.Dispose() }
