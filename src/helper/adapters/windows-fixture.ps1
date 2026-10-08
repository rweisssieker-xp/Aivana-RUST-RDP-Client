function New-PSSessionOption { [CmdletBinding()] param($OpenTimeout,$OperationTimeout) return @{} }
function Invoke-Command {
    [CmdletBinding()]
    param($ConnectionUri,$Authentication,$SessionOption,$ScriptBlock,$ArgumentList)
    if ($ConnectionUri -ne 'http://fixture.invalid:5985/wsman' -or $Authentication -ne 'Negotiate') { throw 'wrong fixture context' }
    if ($script:denyFixture) { throw [System.UnauthorizedAccessException]::new('fixture denied') }
    & $ScriptBlock @ArgumentList
}
function Get-CimInstance {
    [CmdletBinding()]
    param($ClassName,$Filter)
    switch ($ClassName) {
        'Win32_PerfRawData_PerfOS_Processor' {
            $script:cpuFixture++
            return [pscustomobject]@{PercentProcessorTime=($script:cpuFixture * 10);Timestamp_Sys100NS=($script:cpuFixture * 100)}
        }
        'Win32_OperatingSystem' { return [pscustomobject]@{TotalVisibleMemorySize=100;FreePhysicalMemory=40;NumberOfProcesses=1;Version='10.0.1';CSName='fixture-host';LastBootUpTime=(Get-Date).AddHours(-1)} }
        'Win32_PerfRawData_PerfOS_Memory' { return [pscustomobject]@{CommittedBytes=20;CommitLimit=100} }
        'Win32_LogicalDisk' { return [pscustomobject]@{Size=100;FreeSpace=40} }
        'Win32_PerfRawData_Tcpip_TCPv4' {
            $script:tcpFixture++
            return [pscustomobject]@{ConnectionsEstablished=2;SegmentsRetransmittedPersec=($script:tcpFixture * 2)}
        }
    }
}
function Get-NetAdapterStatistics { [CmdletBinding()] param($Name)
    $script:ifaceFixture++
    return [pscustomobject]@{ReceivedBytes=($script:ifaceFixture * 100);SentBytes=($script:ifaceFixture * 200);ReceivedPacketErrors=1;OutboundPacketErrors=2;ReceivedDiscardedPackets=3;OutboundDiscardedPackets=4}
}
function Get-Process { [CmdletBinding()] param()
    return [pscustomobject]@{ProcessName='secret-process';WorkingSet64=4096;CPU=4}
}
function Get-Service { [CmdletBinding()] param($Name)
    return [pscustomobject]@{Status='Running';ServicesDependedOn=@([pscustomobject]@{Name='secret-dependency'})}
}
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable,$MaxEvents)
    return [pscustomobject]@{Id=42;Level=2;ProviderName='secret-provider';TimeCreated=(Get-Date)}
}
function Get-NetTCPConnection { [CmdletBinding()] param($State)
    return [pscustomobject]@{State='Listen'}
}
function Start-Sleep { [CmdletBinding()] param($Milliseconds) }
