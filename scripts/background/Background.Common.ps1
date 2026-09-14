#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-BackgroundIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    [pscustomobject]@{Name=$identity.Name;Sid=$identity.User.Value}
}
function Get-BackgroundTaskName {
    $dataFile = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Aivana\RustRdpClient\relayne-background.dpapi'
    $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($dataFile))
    return 'RelayneRecoveryMonitor-' + [Convert]::ToHexString($hash).ToLowerInvariant()
}
function Connect-BackgroundScheduler {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    return $service
}
function Read-BackgroundCredential([string]$UserName) {
    Get-Credential -UserName $UserName -Message 'Authorize Windows batch logon for this same account. Relayne server credentials are separate.'
}
function Resolve-BackgroundExecutable([string]$Executable) {
    if (![IO.Path]::IsPathFullyQualified($Executable) -or $Executable.StartsWith('\\') -or $Executable -match '[\x00-\x1f"]') { throw 'Use an absolute local executable path without control characters or quotes.' }
    $full = [IO.Path]::GetFullPath($Executable)
    if ([IO.Path]::GetFileName($full) -ine 'relayne.exe' -or !(Test-Path -LiteralPath $full -PathType Leaf)) { throw 'Select an existing relayne.exe.' }
    $current = $full
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Executable paths through links or junctions are not supported.' }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) { break }; $current = $parent
    }
    return $full
}
function New-BackgroundTaskXml([string]$Executable, [string]$Identity) {
    $exe = [Security.SecurityElement]::Escape($Executable)
    $user = [Security.SecurityElement]::Escape($Identity)
    $start = [DateTime]::UtcNow.AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Relayne approved recovery checks under the original Windows account, including while logged out.</Description></RegistrationInfo>
<Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>$start</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
<Principals><Principal id="Author"><UserId>$user</UserId><LogonType>Password</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
<Actions Context="Author"><Exec><Command>$exe</Command><Arguments>--recovery-worker-once</Arguments><WorkingDirectory>$([Security.SecurityElement]::Escape((Split-Path -Parent $Executable)))</WorkingDirectory></Exec></Actions>
</Task>
"@
}
function Register-BackgroundTask([string]$Executable, [bool]$ReplaceExisting) {
    $path = Resolve-BackgroundExecutable $Executable
    $identity = Get-BackgroundIdentity
    if ($identity.Sid -in @('S-1-5-18','S-1-5-19','S-1-5-20') -or $identity.Name -notmatch '^[^\\]+\\[^\\]+$') { throw 'Use the original named Windows user account, not SYSTEM or a service account.' }
    $credential = Read-BackgroundCredential $identity.Name
    if (!$credential -or $credential.UserName -ine $identity.Name) { throw 'Credential identity must exactly match the current DOMAIN\user account.' }
    $xml = New-BackgroundTaskXml $path $identity.Name
    $secretPointer = [IntPtr]::Zero; $password = $null
    try {
        $service = Connect-BackgroundScheduler
        $folder = $service.GetFolder('\')
        $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
        $flags = if ($ReplaceExisting) { 6 } else { 2 } # TASK_CREATE_OR_UPDATE / TASK_CREATE
        # Task Scheduler COM API receives the password in process memory, never a command line or XML.
        $null = $folder.RegisterTask((Get-BackgroundTaskName), $xml, $flags, $identity.Name, $password, 1, $null)
    } catch {
        # Do not echo COM/provider exceptions: they may include sensitive invocation details.
        throw 'Windows rejected task registration. Check batch-logon policy, account password, permissions, and whether this task already exists. No successful registration is claimed.'
    } finally {
        if ($secretPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer) }
        $password = $null; $credential = $null
    }
    Write-Output 'Registered same-account password-logon recovery task. Windows stores the task credential. Execution still requires valid scoped Relayne approvals, DPAPI access and Windows batch-logon permission.'
}
