#requires -Version 7.0
. (Join-Path $PSScriptRoot 'Acceptance.Common.ps1')
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('relayne-acceptance-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
function Get-LocalAcceptanceCapabilities {
    @{windows=$true;rdp_control_registered=$true;winrm_service_installed=$true;hyperv_management_service_installed=$true;openssh_command_available=$true;note='Mocked installed tools'}
}
$passed=0
function Assert-Test([bool]$Condition,[string]$Name) {
    if (!$Condition) { throw "FAIL: $Name" }; $script:passed++; Write-Output "PASS: $Name"
}
try {
    [IO.File]::WriteAllText((Join-Path $testRoot 'relayne.exe'),'fixture only')
    $report=New-LocalAcceptanceReport $testRoot $true
    Assert-Test (!$report.sale_ready -and !$report.live_acceptance_complete) 'Installed tools cannot establish sale readiness'
    Assert-Test (@($report.live_scenarios | Where-Object status -ne 'NOT RUN').Count -eq 0 -and $report.live_scenarios.Count -eq 9) 'All nine live scenarios remain NOT RUN'
    Assert-Test ($report.report_kind -ceq 'fixture-local-readiness') 'Fixture report explicitly separated'
    Assert-Test ($report.binaries[0].sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $testRoot 'relayne.exe') -Algorithm SHA256).Hash) 'Exact binary hash recorded'
    Assert-Test (!$report.binaries[1].present -and $null -eq $report.binaries[1].sha256) 'Missing binary remains absent'
    $report=New-LocalAcceptanceReport $testRoot $false
    Assert-Test ($report.report_kind -ceq 'local-readiness' -and !$report.sale_ready -and @($report.live_scenarios | Where-Object status -ne 'NOT RUN').Count -eq 0) 'Non-fixture local report still cannot promote live results'
    Assert-Test ($report.host_scope.kind -ceq 'local-machine-only' -and $report.host_scope.computer_name -ceq [Environment]::MachineName) 'Evidence scope is this local host only'
    Write-Output "$passed acceptance fixture checks passed. No remote operations or executable launches occurred."
} finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if (!$resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notlike 'relayne-acceptance-test-*') { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
