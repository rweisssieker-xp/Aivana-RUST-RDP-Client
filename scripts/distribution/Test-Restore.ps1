#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('relayne-restore-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$passed=0
function Assert-Test([bool]$Condition,[string]$Name) { if(!$Condition){throw "FAIL: $Name"}; $script:passed++; Write-Output "PASS: $Name" }
function Assert-Rejected([scriptblock]$Action,[string]$Name) { $rejected=$false; try{ & $Action | Out-Null }catch{$rejected=$true}; Assert-Test $rejected $Name }
try {
    $source=Join-Path $testRoot 'source'; New-Item -ItemType Directory -Path (Join-Path $source 'nested') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $source 'nested/settings.json'),'fixture settings')
    [IO.File]::WriteAllBytes((Join-Path $source 'empty.bin'),[byte[]]@())
    $backup=Join-Path $testRoot 'backup'
    $null=& (Join-Path $PSScriptRoot 'Backup-ProductionData.ps1') -DataDirectory $source -Destination $backup -ConfirmApplicationClosed
    $manifestPath=Join-Path $backup 'backup.json'; $original=[IO.File]::ReadAllText($manifestPath)
    $restoreScript=Join-Path $PSScriptRoot 'Restore-ProductionData.ps1'; $destination=Join-Path $testRoot 'restored'
    $null=& $restoreScript -BackupDirectory $backup -Destination $destination -AcknowledgeSameWindowsAccount
    Assert-Test ([IO.File]::ReadAllText((Join-Path $destination 'nested/settings.json')) -ceq 'fixture settings' -and (Get-Item -LiteralPath (Join-Path $destination 'empty.bin')).Length -eq 0) 'Restore preserves exact nested and empty-file contents'
    Assert-Test ((Get-Acl -LiteralPath $destination).AreAccessRulesProtected) 'Restored directory has private ACL inheritance protection'
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $destination -AcknowledgeSameWindowsAccount } 'Existing destination cannot be overwritten'
    $candidate=Join-Path $testRoot 'candidate'
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount:$false } 'Same-account acknowledgement is required'
    foreach ($badPath in @('../outside','C:\outside','nested/../escape','nested:stream','nested/CON.txt')) {
        $manifest=$original | ConvertFrom-Json -AsHashtable; $manifest.files[0].path=$badPath
        [IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 6))
        Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } "Unsafe relative path rejected: $badPath"
    }
    $manifest=$original|ConvertFrom-Json -AsHashtable; $manifest.windows_sid='S-1-5-18'; [IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 6))
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Different account SID rejected'
    $manifest=$original|ConvertFrom-Json -AsHashtable; $manifest.files[0].size=536870913; [IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 6))
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Oversized file rejected'
    $manifest=$original|ConvertFrom-Json -AsHashtable; $manifest.files[1]=$manifest.files[0]; [IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 6))
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Duplicate inventory path rejected'
    [IO.File]::WriteAllText($manifestPath,$original)
    $extra=Join-Path $backup 'data/extra.txt'; [IO.File]::WriteAllText($extra,'extra')
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Unlisted source file rejected'
    Remove-Item -LiteralPath $extra
    $nested=Join-Path $backup 'data/nested/settings.json'; [IO.File]::WriteAllText($nested,'tampered')
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Tampered source content rejected'
    [IO.File]::WriteAllText($nested,'fixture settings')
    $missing=Join-Path $backup 'data/empty.bin'; Remove-Item -LiteralPath $missing
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Missing source file rejected'
    [IO.File]::WriteAllBytes($missing,[byte[]]@())
    $junction=Join-Path $testRoot 'linked-backup'; New-Item -ItemType Junction -Path $junction -Target $backup | Out-Null
    try {
        Assert-Rejected { & $restoreScript -BackupDirectory $junction -Destination $candidate -AcknowledgeSameWindowsAccount } 'Backup junction rejected'
        Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination (Join-Path $junction 'new-destination') -AcknowledgeSameWindowsAccount } 'Destination parent junction rejected'
    } finally { Remove-Item -LiteralPath $junction -Force }
    function Copy-Item {
        param([string]$LiteralPath,[string]$Destination)
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
        [IO.File]::AppendAllText($Destination,'simulated corruption')
    }
    Assert-Rejected { & $restoreScript -BackupDirectory $backup -Destination $candidate -AcknowledgeSameWindowsAccount } 'Copy verification failure blocks publication'
    Remove-Item Function:\Copy-Item
    Assert-Test (!(Test-Path -LiteralPath $candidate) -and @(Get-ChildItem -LiteralPath $testRoot -Directory -Force | Where-Object Name -like '.relayne-restore-*').Count -eq 0) 'Failed staging is cleaned without publishing a destination'
    Assert-Test ([IO.File]::ReadAllText($nested) -ceq 'fixture settings' -and [IO.File]::ReadAllText((Join-Path $source 'nested/settings.json')) -ceq 'fixture settings') 'Original source and backup remain unchanged'
    Write-Output "$passed isolated restore fixture checks passed. No real user data was restored or replaced."
} finally {
    if(Test-Path Function:\Copy-Item){Remove-Item Function:\Copy-Item}
    $resolved=[IO.Path]::GetFullPath($testRoot); $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(!$resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notlike 'relayne-restore-test-*'){throw 'Unsafe test cleanup path.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
