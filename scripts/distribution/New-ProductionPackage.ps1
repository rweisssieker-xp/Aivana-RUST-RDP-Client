#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$BuildDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version,
    [Parameter(Mandatory)][string]$PublisherThumbprint,
    [Parameter(Mandatory)][uri]$TimestampServer
)
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
if (!$TimestampServer.IsAbsoluteUri -or $TimestampServer.Scheme -ne 'https') { throw 'An HTTPS timestamp service is required.' }
$build = Assert-PlainPath $BuildDirectory
$output = Assert-PlainPath $OutputDirectory
if (Test-Path -LiteralPath $output) { throw 'Output directory must not exist.' }
if ($PublisherThumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'Invalid publisher certificate thumbprint.' }
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$PublisherThumbprint"
if (!$certificate.HasPrivateKey) { throw 'The configured publisher certificate needs its private key.' }
# Executables must already be signed by the authorized build/signing system.
foreach ($name in @('relayne.exe','relayne_team.exe')) { Assert-PublisherSignature (Join-Path $build $name) $PublisherThumbprint }
New-Item -ItemType Directory -Path $output | Out-Null
$files = foreach ($name in @('relayne.exe','relayne_team.exe')) {
    $path = Join-Path $output $name
    Copy-Item -LiteralPath (Join-Path $build $name) -Destination $path
    @{ path=$name; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; size=(Get-Item -LiteralPath $path).Length }
}
$json = @{schema='relayne-production-v1';product='Relayne';channel='production';version=$Version;files=@($files)} | ConvertTo-Json -Depth 5
$manifestPath = Join-Path $output 'manifest.ps1'
[IO.File]::WriteAllText($manifestPath, "# Relayne production manifest v1`r`n<#`r`n$json`r`n#>`r`n", [Text.UTF8Encoding]::new($true))
$result = Set-AuthenticodeSignature -LiteralPath $manifestPath -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer.AbsoluteUri
if ($result.Status -ne 'Valid') { throw 'Manifest signing failed; do not publish this directory.' }
$null = Read-ProductionPackage $output $PublisherThumbprint
Write-Output "Verified production package: $output"
