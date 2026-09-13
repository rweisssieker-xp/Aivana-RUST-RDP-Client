$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$j=$p.lab
$r=$p.request
$proof=[ordered]@{request_hash=[string]$p.hash;baseline=$false;changed=$false;fault_observed=$false;repaired=$false;returned=$false;checkpoint_removed=$false;untouched=$false;baseline_mode='';stage='baseline'}
$checkpointAttempted=$false

function Owned-VM {
    $vm=Get-VM -Id ([guid]$j.vm_id)
    if($vm.Name -cne $j.name -or $vm.Notes -cne $j.id -or [string]$vm.State -ne 'Running'){throw 'Clone identity/state'}
    $nics=@($vm|Get-VMNetworkAdapter)
    if($nics.Count -ne 1 -or [string]$nics[0].SwitchId -ne $j.switch_id){throw 'Clone adapter'}
    $switch=Get-VMSwitch -Id ([guid]$j.switch_id)
    if($switch.Name -cne $j.name -or [string]$switch.SwitchType -ne 'Private'){throw 'Clone isolation'}
    $foreign=@(Get-VM|Get-VMNetworkAdapter|Where-Object{[string]$_.SwitchId -eq $j.switch_id -and [string]$_.VMId -ne $j.vm_id})
    if($foreign.Count){throw 'Shared clone network'}
    $drives=@($vm|Get-VMHardDiskDrive)
    if($drives.Count -ne 1){throw 'Clone disk count'}
    $path=[string]$drives[0].Path
    $root=[IO.Path]::GetFullPath([string]$j.directory).TrimEnd('\')+'\'
    $ancestor=[IO.DirectoryInfo]$j.directory
    while($ancestor){if($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse directory'};$ancestor=$ancestor.Parent}
    $found=$false
    for($depth=0;$depth -lt 32;$depth++){
        if(![IO.Path]::GetFullPath($path).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'Foreign clone disk'}
        if((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse disk'}
        $disk=Get-VHD -Path $path
        if($path -ieq (Join-Path $j.directory 'child.vhdx')){if($disk.ParentPath -ine $j.template){throw 'Template changed'};$found=$true;break}
        $path=[string]$disk.ParentPath
        if(!$path){throw 'Missing clone parent'}
    }
    if(!$found){throw 'Clone chain limit'}
    return $vm
}

$guest={
    param($service,$health,$mode,$target,$original)
    $ErrorActionPreference='Stop'
    Add-Type -AssemblyName System.ServiceProcess
    function Healthy {
        $uri=[uri]$health.url
        if($uri.Scheme -notin @('http','https') -or $uri.Host -notin @('localhost','127.0.0.1','[::1]','::1') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'Loopback required'}
        $req=[Net.HttpWebRequest]::Create($uri)
        $req.Method='GET';$req.AllowAutoRedirect=$false;$req.Proxy=$null;$req.UseDefaultCredentials=$false;$req.Credentials=$null
        $req.Timeout=5000;$req.ReadWriteTimeout=5000;$req.MaximumResponseHeadersLength=16
        $response=$null
        try {
            try{$response=$req.GetResponse()}catch [Net.WebException]{if(!$_.Exception.Response){return $false};$response=$_.Exception.Response}
            $stream=$response.GetResponseStream();$buffer=New-Object byte[] 65537;$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
            while($count -lt $buffer.Length){
                $remaining=5000-[int]$clock.ElapsedMilliseconds
                if($remaining -le 0){$req.Abort();return $false}
                $pending=$stream.ReadAsync($buffer,$count,$buffer.Length-$count)
                if(!$pending.Wait($remaining)){$req.Abort();return $false}
                if($pending.Result -eq 0){break};$count+=$pending.Result
            }
            if($count -gt 65536){return $false}
            $body=[Text.Encoding]::UTF8.GetString($buffer,0,$count)
            return ([int]$response.StatusCode -eq [int]$health.expected_status -and (!$health.body_marker -or $body.Contains([string]$health.body_marker)))
        } finally {if($response){$response.Dispose()}}
    }
    function State {
        $svc=Get-Service -Name $service
        $info=Get-CimInstance -ClassName Win32_Service -Filter "Name='$service'"
        if(!$info -or $info.StartMode -notin @('Auto','Manual')){throw 'Unsupported startup mode'}
        $delayed=(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$service) -Name DelayedAutoStart -ErrorAction SilentlyContinue).DelayedAutoStart
        if($delayed -eq 1){throw 'Delayed auto start unsupported'}
        return [pscustomobject]@{svc=$svc;startup=[string]$info.StartMode}
    }
    $state=State;$s=$state.svc
    if(@($s.DependentServices|Where-Object Status -eq Running).Count -or @($s.ServicesDependedOn|Where-Object Status -ne Running).Count){throw 'Dependency guard'}
    switch($mode){
        'baseline' {
            if([string]$s.Status -ne 'Running' -or !(Healthy)){throw 'Unhealthy baseline'}
            $desired=if($target -eq 'Automatic'){'Auto'}else{'Manual'}
            if($state.startup -eq $desired){throw 'No configuration change'}
        }
        'change' {
            if([string]$s.Status -ne 'Running'){throw 'Baseline drift'}
            Set-Service -Name $service -StartupType $target
            $state=State
            $desired=if($target -eq 'Automatic'){'Auto'}else{'Manual'}
            if($state.startup -ne $desired -or [string]$state.svc.Status -ne 'Running' -or !(Healthy)){throw 'Change failed'}
        }
        'fault' {
            if([string]$s.Status -ne 'Running'){throw 'Fault baseline drift'}
            $s|Stop-Service -ErrorAction Stop
            $s.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(15));$s.Refresh()
            if([string]$s.Status -ne 'Stopped' -or (Healthy)){throw 'Fault not reproduced'}
            $s.Refresh();if([string]$s.Status -ne 'Stopped'){throw 'Fault did not persist'}
        }
        'repair' {
            if([string]$s.Status -ne 'Stopped'){throw 'Fault state changed'}
            $s|Start-Service -ErrorAction Stop
            $s.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(15));$s.Refresh()
            if([string]$s.Status -ne 'Running' -or !(Healthy)){throw 'Repair not verified'}
        }
        'return' {
            if($state.startup -ne $original -or [string]$s.Status -ne 'Running' -or !(Healthy)){throw 'Return not verified'}
        }
        default {throw 'Unknown phase'}
    }
    [pscustomobject]@{startup=$state.startup;ok=$true}
}

function Guest-Step($mode,$original){
    $null=Owned-VM
    $result=Invoke-Command -VMId ([guid]$j.vm_id) -Credential $credential -ScriptBlock $guest -ArgumentList $r.spec.service,$r.spec.health,$mode,$r.spec.startup,$original
    if(!$result.ok){throw 'Guest result missing'}
    return $result
}
function Snapshot {
    $vm=Owned-VM
    $all=@($vm|Get-VMSnapshot)
    $owned=@($all|Where-Object Name -CEQ ([string]$p.checkpoint))
    if($all.Count -ne 1 -or $owned.Count -ne 1){throw 'Exact trial checkpoint required'}
    return $owned[0]
}
function Return-Clone($original){
    $snapshot=Snapshot
    $snapshot|Restore-VMSnapshot -Confirm:$false
    $null=Owned-VM
    # PowerShell Direct can take a short time to reconnect after checkpoint restore.
    $verified=$false
    for($attempt=0;$attempt -lt 5;$attempt++){
        try{$null=Guest-Step 'return' $original;$verified=$true;break}catch{Start-Sleep -Milliseconds 500}
    }
    if(!$verified){throw 'Return verification failed'}
    $proof.returned=$true
    $snapshot=Snapshot
    $snapshot|Remove-VMSnapshot -Confirm:$false
    $vm=Owned-VM
    if(@($vm|Get-VMSnapshot).Count){throw 'Checkpoint removal not complete'}
    $proof.checkpoint_removed=$true
}

try {
    if($r.vm_id -cne $j.vm_id -or $r.lab_id -cne $j.id -or $p.checkpoint -cne ('Relayne-Trial-'+$r.id)){throw 'Request binding'}
    $secure=ConvertTo-SecureString ([string]$p.password) -AsPlainText -Force
    $credential=[Management.Automation.PSCredential]::new([string]$p.user,$secure)
    $baselinePath=Join-Path $j.directory ('receipts\change-trials\'+$r.id+'.baseline.dpapi')
    $vm=Owned-VM
    if($p.recover){
        $proof.stage='return';$checkpointAttempted=$true
        Add-Type -AssemblyName System.Security
        $item=Get-Item -LiteralPath $baselinePath
        if($item.Length -gt 4096 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid baseline file'}
        $meta=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($baselinePath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))|ConvertFrom-Json
        if($meta.hash -cne $p.hash -or $meta.mode -notin @('Auto','Manual')){throw 'Invalid baseline binding'}
        $proof.baseline_mode=[string]$meta.mode
        Return-Clone $meta.mode
    } else {
        if([string]$vm.CheckpointType -ne 'Standard'){throw 'Standard checkpoint with memory required'}
        if(@($vm|Get-VMSnapshot).Count){throw 'Existing checkpoints unsupported'}
        $baseline=Guest-Step 'baseline' ''
        $proof.baseline=$true;$proof.baseline_mode=$baseline.startup
        Add-Type -AssemblyName System.Security
        $bytes=[Text.Encoding]::UTF8.GetBytes((@{hash=[string]$p.hash;mode=[string]$baseline.startup}|ConvertTo-Json -Compress))
        $bytes=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $file=[IO.File]::Open($baselinePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        $proof.stage='checkpoint';$checkpointAttempted=$true
        $vm=Owned-VM
        $vm|Checkpoint-VM -SnapshotName ([string]$p.checkpoint)
        $null=Snapshot
        try {
            $proof.stage='change';$null=Guest-Step 'change' ''; $proof.changed=$true
            $proof.stage='fault';$null=Guest-Step 'fault' ''; $proof.fault_observed=$true
            $proof.stage='repair';$null=Guest-Step 'repair' ''; $proof.repaired=$true
        } finally {
            Return-Clone $baseline.startup
        }
        $proof.stage='complete'
    }
} catch {
    # Persist only a bounded stage, never raw guest errors, credentials or response bodies.
    if(!$checkpointAttempted){$proof.untouched=$true;$proof.stage='baseline'}
}
$proof|ConvertTo-Json -Compress
