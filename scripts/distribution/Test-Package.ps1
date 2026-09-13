param([string]$PackageRoot = $PSScriptRoot, [ValidateSet('en-US','de','fr','it')][string]$Language='en-US')
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
try {
    $manifest = Read-VerifiedPackage $PackageRoot
    Write-Output (Get-Text 'verified' $Language)
    Write-Output ($manifest | ConvertTo-Json -Depth 5)
} catch { throw (Get-Text 'invalid' $Language) }
