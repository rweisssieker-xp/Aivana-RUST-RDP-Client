#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$PublisherThumbprint,
    [ValidateSet('relayne.exe','relayne_team.exe')][string]$Executable = 'relayne.exe',
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Relayne\production')
)
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
$root = Assert-PlainPath $InstallRoot
$version = [IO.File]::ReadAllText((Assert-PlainPath (Join-Path $root 'current.txt')))
if ($version -cnotmatch '^\d{1,5}\.\d{1,5}\.\d{1,5}$') { throw 'Invalid current version selection.' }
$directory = Assert-PlainPath (Join-Path $root "versions/$version")
$manifest = Read-ProductionPackage $directory $PublisherThumbprint
if ($manifest.version -cne $version) { throw 'Selected version identity mismatch.' }
Start-Process -FilePath (Join-Path $directory $Executable) -WorkingDirectory $directory -WindowStyle Hidden
