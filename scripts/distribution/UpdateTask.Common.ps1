#requires -Version 7.0
. (Join-Path $PSScriptRoot 'Production.Common.ps1')
function Get-UpdateTaskIdentity {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20')) { throw 'Use the intended Windows user account, not a service account.' }
    [pscustomobject]@{Name=$identity.Name;Sid=$identity.User.Value}
}
function Get-UpdateTaskName {
    $identity=Get-UpdateTaskIdentity
    return 'RelayneProductionUpdate-'+$identity.Sid
}
function Connect-UpdateTaskScheduler {
    $service=New-Object -ComObject 'Schedule.Service'; $service.Connect(); return $service
}
function ConvertTo-TaskArgument([string]$Value) {
    if ($Value -match '[\x00-\x1f"]') { throw 'Task arguments must not contain quotes or control characters.' }
    # Windows argv quoting: quoted trailing backslashes must be doubled before the closing quote.
    return '"'+[regex]::Replace($Value,'(\\+)$','$1$1')+'"'
}
function New-UpdateTaskDefinition([uri]$ReleaseUrl,[string]$PublisherThumbprint,[string]$InstallRoot) {
    if (!$ReleaseUrl.IsAbsoluteUri -or $ReleaseUrl.Scheme -cne 'https' -or $ReleaseUrl.UserInfo -or $ReleaseUrl.Query -or $ReleaseUrl.Fragment -or !$ReleaseUrl.AbsoluteUri.EndsWith('/')) { throw 'Use an absolute HTTPS release-directory URL without credentials, query, or fragment, ending in a slash.' }
    $root=Assert-PlainPath $InstallRoot
    $scriptPath=Assert-PlainPath (Join-Path $PSScriptRoot 'Update-Production.ps1')
    foreach ($name in @('Update-Production.ps1','Production.Common.ps1','Package.Common.ps1')) {
        Assert-PublisherSignature (Assert-PlainPath (Join-Path $PSScriptRoot $name)) $PublisherThumbprint
    }
    $hostPath=Assert-PlainPath (Join-Path $PSHOME 'pwsh.exe')
    if (!(Test-Path -LiteralPath $hostPath -PathType Leaf)) { throw 'PowerShell 7 executable is unavailable.' }
    $identity=Get-UpdateTaskIdentity
    $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','AllSigned','-File',$scriptPath,'-ReleaseUrl',$ReleaseUrl.AbsoluteUri,'-PublisherThumbprint',$PublisherThumbprint,'-InstallRoot',$root)
    $argv=($arguments | ForEach-Object { ConvertTo-TaskArgument $_ }) -join ' '
    $escape={param($value) [Security.SecurityElement]::Escape($value)}
    $start=[DateTime]::UtcNow.AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Relayne verified production updates, every six hours while this user is signed in.</Description></RegistrationInfo>
<Triggers><TimeTrigger><Repetition><Interval>PT6H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>$start</StartBoundary><Enabled>true</Enabled></TimeTrigger><LogonTrigger><Enabled>true</Enabled><UserId>$(& $escape $identity.Name)</UserId></LogonTrigger></Triggers>
<Principals><Principal id="Author"><UserId>$(& $escape $identity.Name)</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT30M</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
<Actions Context="Author"><Exec><Command>$(& $escape $hostPath)</Command><Arguments>$(& $escape $argv)</Arguments><WorkingDirectory>$(& $escape $PSScriptRoot)</WorkingDirectory></Exec></Actions>
</Task>
"@
}
function Register-ProductionUpdateTask([uri]$ReleaseUrl,[string]$PublisherThumbprint,[string]$InstallRoot,[bool]$ReplaceExisting) {
    $xml=New-UpdateTaskDefinition $ReleaseUrl $PublisherThumbprint $InstallRoot
    $identity=Get-UpdateTaskIdentity
    $service=Connect-UpdateTaskScheduler
    $flags=if($ReplaceExisting){6}else{2}
    try { $null=$service.GetFolder('\').RegisterTask((Get-UpdateTaskName),$xml,$flags,$identity.Name,$null,3,$null) }
    catch { throw 'Windows rejected update task registration. Check policy, permissions, or an existing task.' }
    Write-Output 'Registered verified production updates at logon and every six hours while signed in. No update was launched by this command.'
}
