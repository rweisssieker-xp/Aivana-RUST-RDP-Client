#requires -Version 7.0
param([Parameter(Mandatory)][switch]$ConfirmRemoval)
. (Join-Path $PSScriptRoot 'Background.Common.ps1')
if (!$ConfirmRemoval) { throw 'Explicit task removal confirmation is required.' }
try {
    $service = Connect-BackgroundScheduler
    $service.GetFolder('\').DeleteTask((Get-BackgroundTaskName), 0)
} catch { throw 'Unable to remove this account recovery task. It may be absent or Windows may deny access.' }
Write-Output 'Removed scheduled task. Existing workers may finish; app approvals and data remain. Revoke background approvals in Relayne to stop authorization as well.'
