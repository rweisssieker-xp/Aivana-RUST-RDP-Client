#requires -Version 7.0
. (Join-Path $PSScriptRoot 'UpdateTask.Common.ps1')
try {
    $service=Connect-UpdateTaskScheduler
    $task=$service.GetFolder('\').GetTask((Get-UpdateTaskName))
    [pscustomobject]@{Name=$task.Name;Enabled=$task.Enabled;State=$task.State;LastRunTime=$task.LastRunTime;LastTaskResult=$task.LastTaskResult;NextRunTime=$task.NextRunTime;User=$task.Definition.Principal.UserId;LogonType=$task.Definition.Principal.LogonType;Command=$task.Definition.Actions.Item(1).Path;Arguments=$task.Definition.Actions.Item(1).Arguments}
} catch { throw 'Unable to inspect the update task. It may be absent or Windows may deny access.' }
