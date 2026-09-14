#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Background.Common.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('relayne-background-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$exe = Join-Path $testRoot 'relayne.exe'; [IO.File]::WriteAllText($exe, 'fixture, not executable')
$state = @{Account='EXAMPLE\operator';Sid='S-1-5-21-111-222-333-1001';CredentialAccount='EXAMPLE\operator';Denied=$false;Calls=0;PasswordSeen=$false;Xml='';Flags=0}
$fixtureSecret = 'fixture-sensitive-string-never-print'
function Get-BackgroundIdentity { [pscustomobject]@{Name=$state.Account;Sid=$state.Sid} }
function Read-BackgroundCredential([string]$UserName) {
    [pscredential]::new($state.CredentialAccount, (ConvertTo-SecureString -String $fixtureSecret -AsPlainText -Force))
}
$folder = [pscustomobject]@{}
$folder | Add-Member ScriptMethod RegisterTask {
    param($Name,$Xml,$Flags,$User,$Password,$Logon,$Descriptor)
    $state.Calls++; $state.PasswordSeen = $Password -ceq $fixtureSecret
    $state.Xml=$Xml; $state.Flags=$Flags
    if ($state.Denied) { throw "Mock denial with sensitive provider detail: $Password" }
    return [pscustomobject]@{Name=$Name}
}
$service = [pscustomobject]@{}
$service | Add-Member ScriptMethod GetFolder { param($Path) return $folder }
function Connect-BackgroundScheduler { return $service }
$passed=0
function Assert-Test([bool]$Condition,[string]$Label) {
    if (!$Condition) { throw "FAIL: $Label" }; $script:passed++; Write-Output "PASS: $Label"
}
function Assert-Rejected([scriptblock]$Action,[string]$Label) {
    $rejected=$false
    try { & $Action | Out-Null } catch { $rejected=$true; if ($_.ToString().Contains($fixtureSecret)) { throw 'Sensitive value leaked by failure output.' } }
    Assert-Test $rejected $Label
}
try {
    $output = Register-BackgroundTask $exe $false | Out-String
    Assert-Test ($state.Calls -eq 1 -and $state.PasswordSeen) 'Credential passed only to mocked scheduler API'
    Assert-Test (!$output.Contains($fixtureSecret) -and !$state.Xml.Contains($fixtureSecret)) 'Credential absent from output and task XML'
    [xml]$xml=$state.Xml
    $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable); $ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    Assert-Test ($xml.SelectSingleNode('//t:Command',$ns).InnerText -ceq $exe -and $xml.SelectSingleNode('//t:Arguments',$ns).InnerText -ceq '--recovery-worker-once') 'Exact executable and worker command registered'
    Assert-Test ($xml.SelectSingleNode('//t:UserId',$ns).InnerText -ceq $state.Account -and $xml.SelectSingleNode('//t:LogonType',$ns).InnerText -ceq 'Password') 'Same Windows account uses password logon'
    Assert-Test ($xml.SelectSingleNode('//t:RunLevel',$ns).InnerText -ceq 'LeastPrivilege' -and $state.Flags -eq 2) 'Least privilege and create-only default'
    $null=Register-BackgroundTask $exe $true
    Assert-Test ($state.Flags -eq 6) 'Explicit replacement uses create-or-update'
    $state.CredentialAccount='EXAMPLE\other'
    $before=$state.Calls
    Assert-Rejected { Register-BackgroundTask $exe $false } 'Different credential account rejected'
    Assert-Test ($state.Calls -eq $before) 'Identity mismatch never reaches scheduler'
    $state.CredentialAccount=$state.Account
    $state.Sid='S-1-5-18'
    Assert-Rejected { Register-BackgroundTask $exe $false } 'SYSTEM identity rejected'
    $state.Sid='S-1-5-21-111-222-333-1001'
    Assert-Rejected { Register-BackgroundTask '.\relayne.exe' $false } 'Relative executable path rejected'
    Assert-Rejected { Register-BackgroundTask '\\server\share\relayne.exe' $false } 'UNC executable path rejected'
    Assert-Rejected { Register-BackgroundTask ($exe + '" --other') $false } 'Command injection path rejected'
    Assert-Rejected { Register-BackgroundTask (Join-Path $testRoot 'missing.exe') $false } 'Missing or wrong executable rejected'
    $state.Denied=$true
    Assert-Rejected { Register-BackgroundTask $exe $false } 'Policy denial reported without provider secret detail'
    Assert-Test (@(Get-ChildItem -LiteralPath $testRoot -Force).Count -eq 1) 'No credential or task XML files created'
    Assert-Rejected { & (Join-Path $PSScriptRoot 'Register-LoggedOutRecovery.ps1') -Executable $exe -EnableLoggedOutOperation:$false -ConfirmScopedApprovals } 'Explicit logged-out opt-in is required before credential prompt'
    Assert-Rejected { & (Join-Path $PSScriptRoot 'Register-LoggedOutRecovery.ps1') -Executable $exe -EnableLoggedOutOperation -ConfirmScopedApprovals:$false } 'Saved scoped approvals acknowledgement is required'
    Assert-Rejected { & (Join-Path $PSScriptRoot 'Remove-LoggedOutRecovery.ps1') -ConfirmRemoval:$false } 'Explicit removal confirmation is required before scheduler access'
    Write-Output "$passed background fixture checks passed. No real task, credential prompt, or executable launch occurred."
} finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if (!$resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notlike 'relayne-background-test-*') { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
