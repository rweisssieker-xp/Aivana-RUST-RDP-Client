Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$root=Join-Path ([IO.Path]::GetTempPath()) ('relayne-distribution-test-' + [guid]::NewGuid().ToString('N'))
$build=Join-Path $root 'build'
New-Item -ItemType Directory -Path $build -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $build 'relayne.exe'),'MZ-development-test-only')
[IO.File]::WriteAllText((Join-Path $build 'relayne_team.exe'),'MZ-team-test-only')
[IO.File]::WriteAllText((Join-Path $build 'private.env'),'never distribute')
$package=Join-Path $root 'package'
& (Join-Path $PSScriptRoot 'New-DevPackage.ps1') -BuildDirectory $build -OutputDirectory $package | Out-Null
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
function Expect-Rejection([scriptblock]$Action) {
    $rejected=$false
    try { & $Action | Out-Null } catch { $rejected=$true }
    if (!$rejected) { throw 'Expected rejection did not occur.' }
}
$manifest=Read-VerifiedPackage $package
if ($manifest.files.Count -ne 11 -or (Test-Path -LiteralPath (Join-Path $package 'private.env'))) { throw 'Allowlist failure.' }
$original=$env:LOCALAPPDATA
$env:LOCALAPPDATA=Join-Path $root 'user'
try {
    Expect-Rejection { & (Join-Path $package 'Install-Relayne.ps1') }
    $base=Join-Path $env:LOCALAPPDATA 'Relayne'
    if (Test-Path -LiteralPath $base) { throw 'Unsigned rejection wrote installation data.' }
    & (Join-Path $package 'Install-Relayne.ps1') -AllowUnsignedDev -Language fr | Out-Null
    $installed=Join-Path $base ('versions/' + $manifest.version)
    $null=Read-VerifiedPackage $installed
    Expect-Rejection { & (Join-Path $package 'Install-Relayne.ps1') -AllowUnsignedDev }
    $profile=Join-Path $base 'retained-profile.json'
    [IO.File]::WriteAllText($profile,'preserve me')
    Expect-Rejection { & (Join-Path $package 'Uninstall-Relayne.ps1') -Version '../escape' }
    & (Join-Path $package 'Uninstall-Relayne.ps1') -Version $manifest.version -Language it | Out-Null
    if ((Test-Path -LiteralPath $installed) -or !(Test-Path -LiteralPath $profile)) { throw 'Uninstall boundary failure.' }
    $exe=Join-Path $package 'relayne.exe'
    [IO.File]::AppendAllText($exe,'tampered')
    Expect-Rejection { Read-VerifiedPackage $package }
    Expect-Rejection { & (Join-Path $package 'Install-Relayne.ps1') -AllowUnsignedDev }
    if (Test-Path -LiteralPath $installed) { throw 'Tampered package installed.' }
    [IO.File]::WriteAllText($exe,'MZ-development-test-only')
    $manifestText=Get-Content -LiteralPath (Join-Path $package 'manifest.json') -Raw
    $malicious=$manifestText | ConvertFrom-Json
    $malicious.files[0].path='../escape'
    $malicious | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding UTF8
    Expect-Rejection { Read-VerifiedPackage $package }
    [IO.File]::WriteAllText((Join-Path $package 'manifest.json'),$manifestText)
    $junctionPackage=Join-Path $root 'junction-package'
    & (Join-Path $PSScriptRoot 'New-DevPackage.ps1') -BuildDirectory $build -OutputDirectory $junctionPackage | Out-Null
    $outside=Join-Path $root 'outside'
    New-Item -ItemType Directory -Path $outside | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $junctionPackage 'external') -Target $outside | Out-Null
    Expect-Rejection { Read-VerifiedPackage $junctionPackage }
    [IO.File]::WriteAllText((Join-Path $package 'extra.env'),'unexpected')
    Expect-Rejection { Read-VerifiedPackage $package }
    foreach ($language in @('en-US','de','fr','it')) {
        foreach ($key in @('verified','invalid','unsigned','exists','installed','removed')) {
            if ([string]::IsNullOrWhiteSpace((Get-Text $key $language))) { throw 'Translation missing.' }
        }
    }
    Write-Output 'PASS: allowlist, unsigned refusal, isolated install, duplicate refusal, uninstall containment/data retention, tamper rejection, traversal rejection, junction rejection, extra-file rejection, four-language messages.'
    Write-Output ('Disposable test artifacts: ' + $root)
} finally { $env:LOCALAPPDATA=$original }
