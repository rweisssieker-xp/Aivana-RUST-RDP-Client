#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][switch]$EnableLoggedOutOperation,
    [Parameter(Mandatory)][switch]$ConfirmScopedApprovals,
    [switch]$ReplaceExistingTask
)
. (Join-Path $PSScriptRoot 'Background.Common.ps1')
if (!$EnableLoggedOutOperation -or !$ConfirmScopedApprovals) { throw 'Explicit logged-out opt-in and confirmation of saved scoped approvals are required.' }
Register-BackgroundTask $Executable ([bool]$ReplaceExistingTask)
