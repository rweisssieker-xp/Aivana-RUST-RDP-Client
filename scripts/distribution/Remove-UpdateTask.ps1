#requires -Version 7.0
param([Parameter(Mandatory)][switch]$ConfirmRemoval)
. (Join-Path $PSScriptRoot 'UpdateTask.Common.ps1')
if (!$ConfirmRemoval) { throw 'Explicit update task removal confirmation is required.' }
try { $service=Connect-UpdateTaskScheduler; $service.GetFolder('\').DeleteTask((Get-UpdateTaskName),0) }
catch { throw 'Unable to remove the update task. It may be absent or Windows may deny access.' }
Write-Output 'Removed automatic update scheduling. An update already running may finish; installed versions and user data remain.'
