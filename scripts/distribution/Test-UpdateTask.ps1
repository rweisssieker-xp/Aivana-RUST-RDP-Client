#requires -Version 7.0
. (Join-Path $PSScriptRoot 'UpdateTask.Common.ps1')
$state=@{Signatures=0;InvalidSignature=$false;Calls=0;Xml='';Flags=0;Denied=$false}
function Get-UpdateTaskIdentity { [pscustomobject]@{Name='EXAMPLE\operator';Sid='S-1-5-21-111-222-333-1001'} }
function Assert-PublisherSignature([string]$Path,[string]$PublisherThumbprint) {
    $state.Signatures++
    if ($state.InvalidSignature -or $PublisherThumbprint -cne ('A'*40)) { throw 'Mock signature verification failed.' }
}
$folder=[pscustomobject]@{}
$folder | Add-Member ScriptMethod RegisterTask {
    param($Name,$Xml,$Flags,$User,$Password,$Logon,$Descriptor)
    $state.Calls++; $state.Xml=$Xml; $state.Flags=$Flags
    if ($Password -or $Logon -ne 3 -or $User -cne 'EXAMPLE\operator') { throw 'Unexpected credential or identity.' }
    if ($state.Denied) { throw 'Mock policy denied.' }
}
$service=[pscustomobject]@{}
$service | Add-Member ScriptMethod GetFolder { param($Path) return $folder }
function Connect-UpdateTaskScheduler { return $service }
$passed=0
function Assert-Test([bool]$Condition,[string]$Name) { if (!$Condition) { throw "FAIL: $Name" }; $script:passed++; Write-Output "PASS: $Name" }
function Assert-Rejected([scriptblock]$Action,[string]$Name) { $rejected=$false; try { & $Action | Out-Null } catch { $rejected=$true }; Assert-Test $rejected $Name }
$root=Join-Path ([IO.Path]::GetTempPath()) 'Relayne Test Install'
$pin='A'*40
$url=[uri]'https://example.invalid/releases/stable/'
$null=Register-ProductionUpdateTask $url $pin $root $false
Assert-Test ($state.Calls -eq 1 -and $state.Signatures -eq 3 -and $state.Flags -eq 2) 'Registration verifies all bootstrap scripts and defaults to create-only'
[xml]$xml=$state.Xml
$ns=[Xml.XmlNamespaceManager]::new($xml.NameTable); $ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
$arguments=$xml.SelectSingleNode('//t:Arguments',$ns).InnerText
Assert-Test ($arguments.Contains('"-File"') -and !$arguments.Contains('-Command') -and $arguments.Contains('"AllSigned"') -and !$arguments.Contains('Bypass')) 'Task uses fixed script with AllSigned and no command interpolation'
Assert-Test ($arguments.Contains((ConvertTo-TaskArgument $root)) -and $arguments.Contains((ConvertTo-TaskArgument $url.AbsoluteUri)) -and $arguments.Contains($pin)) 'Space-containing paths, release URL and pin are separate quoted arguments'
Assert-Test ($xml.SelectSingleNode('//t:UserId',$ns).InnerText -eq 'EXAMPLE\operator' -and $xml.SelectSingleNode('//t:RunLevel',$ns).InnerText -eq 'LeastPrivilege' -and $xml.SelectSingleNode('//t:LogonType',$ns).InnerText -eq 'InteractiveToken') 'Task uses current user without elevation or stored password'
Assert-Test ($xml.SelectSingleNode('//t:Interval',$ns).InnerText -eq 'PT6H' -and $null -ne $xml.SelectSingleNode('//t:LogonTrigger',$ns)) 'Schedule covers logon and six-hour checks'
Assert-Test ((ConvertTo-TaskArgument 'C:\Folder\') -ceq '"C:\Folder\\"') 'Windows quoting doubles a trailing backslash'
Assert-Rejected { ConvertTo-TaskArgument 'bad" -Command attack' } 'Embedded quote injection rejected'
Assert-Rejected { ConvertTo-TaskArgument "bad`nargument" } 'Control-character argument rejected'
Assert-Rejected { New-UpdateTaskDefinition ([uri]'http://example.invalid/') $pin $root } 'Non-HTTPS channel rejected'
Assert-Rejected { New-UpdateTaskDefinition ([uri]'https://user:secret@example.invalid/') $pin $root } 'Credential-bearing URL rejected'
Assert-Rejected { New-UpdateTaskDefinition ([uri]'https://example.invalid/?channel=x') $pin $root } 'Query-bearing URL rejected'
$state.InvalidSignature=$true; $before=$state.Calls
Assert-Rejected { Register-ProductionUpdateTask $url $pin $root $false } 'Unsigned or mismatched bootstrap is rejected'
Assert-Test ($state.Calls -eq $before) 'Signature rejection occurs before scheduler mutation'
$state.InvalidSignature=$false
$null=Register-ProductionUpdateTask $url $pin $root $true
Assert-Test ($state.Flags -eq 6) 'Existing task replacement requires explicit selection'
$state.Denied=$true
Assert-Rejected { Register-ProductionUpdateTask $url $pin $root $false } 'Windows policy rejection is surfaced'
Assert-Rejected { & (Join-Path $PSScriptRoot 'Register-UpdateTask.ps1') -ReleaseUrl $url -PublisherThumbprint $pin -InstallRoot $root -EnableAutomaticUpdates:$false } 'Explicit scheduling opt-in is required'
Assert-Rejected { & (Join-Path $PSScriptRoot 'Remove-UpdateTask.ps1') -ConfirmRemoval:$false } 'Explicit removal confirmation is required'
Write-Output "$passed update scheduling fixture checks passed. No tasks, network requests, or executable launches occurred."
