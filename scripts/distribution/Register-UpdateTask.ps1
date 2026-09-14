#requires -Version 7.0
param(
    [Parameter(Mandatory)][uri]$ReleaseUrl,
    [Parameter(Mandatory)][string]$PublisherThumbprint,
    [Parameter(Mandatory)][switch]$EnableAutomaticUpdates,
    [string]$InstallRoot=(Join-Path $env:LOCALAPPDATA 'Relayne\production'),
    [switch]$ReplaceExistingTask
)
. (Join-Path $PSScriptRoot 'UpdateTask.Common.ps1')
if (!$EnableAutomaticUpdates) { throw 'Explicit automatic update opt-in is required.' }
Register-ProductionUpdateTask $ReleaseUrl $PublisherThumbprint $InstallRoot ([bool]$ReplaceExistingTask)
