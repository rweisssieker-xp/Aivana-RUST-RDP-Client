#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
$script:pin = 'A' * 40
$signatureStatus = 'Valid'
$signerPin = $script:pin
$rejectExecutableSignature = $false
# Override only the OS signature provider; all manifest, hash, staging and pointer code is real.
function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    $status = $signatureStatus
    if ($rejectExecutableSignature -and $LiteralPath.EndsWith('.exe')) { $status = 'HashMismatch' }
    [pscustomobject]@{Status=$status;SignerCertificate=[pscustomobject]@{Thumbprint=$signerPin}}
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('relayne-production-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$script:passed = 0
function Assert-Test([bool]$Condition, [string]$Name) {
    if (!$Condition) { throw "FAIL: $Name" }; $script:passed++; Write-Output "PASS: $Name"
}
function Assert-Rejected([scriptblock]$Action, [string]$Name) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-Test $rejected $Name
}
function Write-Fixture([string]$Directory, [string]$Version = '1.0.0') {
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $entries = foreach ($name in @('relayne.exe','relayne_team.exe')) {
        $path = Join-Path $Directory $name
        [IO.File]::WriteAllText($path, "fixture $name $Version")
        @{path=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;size=(Get-Item -LiteralPath $path).Length}
    }
    $manifest = @{schema='relayne-production-v1';product='Relayne';channel='production';version=$Version;files=@($entries)}
    Write-Manifest $Directory $manifest
    return $manifest
}
function Write-Manifest([string]$Directory, $Manifest) {
    $json = $Manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $Directory 'manifest.ps1'), "# Relayne production manifest v1`n<#`n$json`n#>`n# SIG # Begin signature block`n# fixture only`n# SIG # End signature block`n")
}
try {
    $package = Join-Path $testRoot 'package'
    $root = Join-Path $testRoot 'installed'
    $manifest = Write-Fixture $package
    Assert-Test ((Read-ProductionPackage $package $script:pin).version -eq '1.0.0') 'Valid fixture accepted'
    $manifest.files[0].path = '../outside.exe'; Write-Manifest $package $manifest
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Traversal rejected'
    $manifest = Write-Fixture $package
    $manifest.extra = 'unknown'; Write-Manifest $package $manifest
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Unknown property rejected'
    $manifest = Write-Fixture $package
    $manifest.files[0].size = '12'; Write-Manifest $package $manifest
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'String file size rejected'
    $manifest = Write-Fixture $package
    $manifest.files[0].size = 536870913; Write-Manifest $package $manifest
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Oversized executable rejected'
    $manifest = Write-Fixture $package
    $path = Join-Path $package 'manifest.ps1'
    $raw = [IO.File]::ReadAllText($path).Replace('"schema":', '"schema":"duplicate","schema":')
    [IO.File]::WriteAllText($path,$raw)
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Duplicate JSON property rejected'
    $manifest = Write-Fixture $package
    [IO.File]::AppendAllText((Join-Path $package 'relayne.exe'), 'tamper')
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Tampered executable rejected'
    $manifest = Write-Fixture $package
    $signatureStatus = 'NotSigned'
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Unsigned publisher rejected'
    $signatureStatus = 'Valid'; $signerPin = 'B' * 40
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Different trusted publisher rejected'
    $signerPin = $script:pin
    $rejectExecutableSignature = $true
    Assert-Rejected { Read-ProductionPackage $package $script:pin } 'Executable signature failure rejected despite valid manifest and hashes'
    $rejectExecutableSignature = $false
    Assert-Rejected { Receive-BoundedHttpsFile ([uri]'http://example.invalid/file') (Join-Path $testRoot 'download') 10 } 'HTTP rejected before network access'
    $null = Install-ProductionPackage $package $root $script:pin
    $data = Join-Path $root 'user-data'; [IO.File]::WriteAllText($data, 'retain me')
    $manifest = Write-Fixture $package '2.0.0'
    $null = Install-ProductionPackage $package $root $script:pin
    Assert-Test ([IO.File]::ReadAllText((Join-Path $root 'current.txt')) -eq '2.0.0') 'Atomic update selected new version'
    $repeatOutput = Install-ProductionPackage $package $root $script:pin | Out-String
    Assert-Test ($repeatOutput.Contains('already installed and verified') -and [IO.File]::ReadAllText((Join-Path $root 'current.txt')) -eq '2.0.0') 'Same version update is a verified no-op'
    $collisionPackage=Join-Path $testRoot 'collision-package'
    $collisionManifest=Write-Fixture $collisionPackage '2.0.0'
    $collisionFile=Join-Path $collisionPackage 'relayne.exe'
    [IO.File]::AppendAllText($collisionFile,'different authenticated release content')
    $collisionManifest.files[0].sha256=(Get-FileHash -LiteralPath $collisionFile -Algorithm SHA256).Hash
    $collisionManifest.files[0].size=(Get-Item -LiteralPath $collisionFile).Length
    Write-Manifest $collisionPackage $collisionManifest
    Assert-Rejected { Install-ProductionPackage $collisionPackage $root $script:pin } 'Same version with different authenticated content is rejected'
    $lowerPackage=Join-Path $testRoot 'older-package'
    $null=Write-Fixture $lowerPackage '1.0.0'
    Assert-Rejected { Install-ProductionPackage $lowerPackage $root $script:pin } 'Automatic update cannot downgrade the selected version'
    # Run rollback in-process so the isolated OS signature mock applies.
    $null = & (Join-Path $PSScriptRoot 'Rollback-Production.ps1') -Version '1.0.0' -PublisherThumbprint $script:pin -InstallRoot $root -AcknowledgeDataCompatibility
    Assert-Test ([IO.File]::ReadAllText((Join-Path $root 'current.txt')) -eq '1.0.0') 'Explicit rollback selected retained verified version'
    Assert-Test ((Test-Path -LiteralPath (Join-Path $root 'versions/2.0.0/relayne.exe')) -and [IO.File]::ReadAllText($data) -eq 'retain me') 'Rollback retained newer binaries and current data'
    Assert-Rejected { & (Join-Path $PSScriptRoot 'Rollback-Production.ps1') -Version '2.0.0' -PublisherThumbprint $script:pin -InstallRoot $root -AcknowledgeDataCompatibility:$false } 'Rollback requires data compatibility acknowledgement'
    [IO.File]::AppendAllText((Join-Path $root 'versions/2.0.0/relayne.exe'), 'tamper')
    Assert-Rejected { & (Join-Path $PSScriptRoot 'Rollback-Production.ps1') -Version '2.0.0' -PublisherThumbprint $script:pin -InstallRoot $root -AcknowledgeDataCompatibility } 'Rollback re-verifies retained binaries'
    Assert-Test ([IO.File]::ReadAllText((Join-Path $root 'current.txt')) -eq '1.0.0') 'Failed rollback preserved current selection'
    $backup = Join-Path $testRoot 'backup'
    $null = & (Join-Path $PSScriptRoot 'Backup-ProductionData.ps1') -DataDirectory $package -Destination $backup -ConfirmApplicationClosed
    $inventory = Get-Content -LiteralPath (Join-Path $backup 'backup.json') -Raw | ConvertFrom-Json
    Assert-Test ($inventory.files.Count -eq 3 -and $inventory.authenticity -eq 'unsigned-local-integrity-only') 'Backup records integrity inventory without claiming authenticity'
    Assert-Test ((Get-FileHash -LiteralPath (Join-Path $backup 'data/relayne.exe')).Hash -eq (Get-FileHash -LiteralPath (Join-Path $package 'relayne.exe')).Hash) 'Backup content matches source'
    Assert-Rejected { & (Join-Path $PSScriptRoot 'Backup-ProductionData.ps1') -DataDirectory $package -Destination $backup -ConfirmApplicationClosed } 'Existing backup cannot be overwritten'
    $backupAcl = Get-Acl -LiteralPath $backup
    Assert-Test ($backupAcl.AreAccessRulesProtected -and @($backupAcl.Access | Where-Object IsInherited).Count -eq 0) 'Backup disables inherited access rules'
    $junction = Join-Path $testRoot 'linked-package'
    New-Item -ItemType Junction -Path $junction -Target $package | Out-Null
    try {
        Assert-Rejected { Read-ProductionPackage $junction $script:pin } 'Package directory junction rejected'
        Assert-Rejected { & (Join-Path $PSScriptRoot 'Backup-ProductionData.ps1') -DataDirectory $junction -Destination (Join-Path $testRoot 'linked-backup') -ConfirmApplicationClosed } 'Backup source junction rejected'
        Assert-Rejected { Receive-BoundedHttpsFile ([uri]'https://example.invalid/file') (Join-Path $junction 'download') 10 } 'Download destination junction rejected before network access'
    } finally { Remove-Item -LiteralPath $junction -Force }
    Write-Output "$script:passed production fixture checks passed. Signatures were mocked; no network operations performed."
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (!$resolved.StartsWith($temporaryRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notlike 'relayne-production-test-*') { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
