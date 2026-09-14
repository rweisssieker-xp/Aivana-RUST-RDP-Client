#requires -Version 7.0
[CmdletBinding(DefaultParameterSetName='Local')]
param(
    [Parameter(Mandatory,ParameterSetName='Local')][string]$PackageDirectory,
    [Parameter(Mandatory,ParameterSetName='Download')][uri]$ReleaseUrl,
    [Parameter(Mandatory)][string]$PublisherThumbprint,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Relayne\production')
)
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
if ($PSCmdlet.ParameterSetName -eq 'Download') {
    if (!$ReleaseUrl.AbsoluteUri.EndsWith('/')) { throw 'Release URL must end with a slash.' }
    $root = Assert-PlainPath $InstallRoot
    $download = Assert-PlainPath (Join-Path $root ('downloads/' + [guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $download -Force | Out-Null
    Receive-BoundedHttpsFile ([uri]::new($ReleaseUrl, 'manifest.ps1')) (Join-Path $download 'manifest.ps1') 65536
    $manifest = Read-ProductionManifest (Join-Path $download 'manifest.ps1') $PublisherThumbprint
    foreach ($file in $manifest.files) { Receive-BoundedHttpsFile ([uri]::new($ReleaseUrl, $file.path)) (Join-Path $download $file.path) $file.size }
    $PackageDirectory = $download
}
Install-ProductionPackage $PackageDirectory $InstallRoot $PublisherThumbprint
