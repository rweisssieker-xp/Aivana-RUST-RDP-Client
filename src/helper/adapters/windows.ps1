$ErrorActionPreference = 'Stop'
$uri = 'http://__HOST__:__PORT__/wsman'
if (__PORT__ -eq 5986) { $uri = 'https://__HOST__:__PORT__/wsman' }
$service = '__SERVICE__'
$mount = '__MOUNT__'
$interface = '__INTERFACE__'
try {
    $result = Invoke-Command -ConnectionUri $uri -Authentication Negotiate -SessionOption (New-PSSessionOption -OpenTimeout 5000 -OperationTimeout 10000) -ScriptBlock {
        param($service, $mount, $interface)
        function CpuSample {
            try {
                $c = Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
                return @([double]$c.PercentProcessorTime, [double]$c.Timestamp_Sys100NS)
            } catch { return @() }
        }
        function InterfaceSample($name) {
            if (-not $name) { return @() }
            try {
                $c = Get-NetAdapterStatistics -Name $name -ErrorAction Stop
                return @([double]$c.ReceivedBytes, [double]$c.SentBytes)
            } catch { return @() }
        }
        function TcpSample {
            try {
                $c = Get-CimInstance Win32_PerfRawData_Tcpip_TCPv4 -ErrorAction Stop
                if ($null -ne $c.ConnectionsEstablished -and $null -ne $c.SegmentsRetransmittedPersec) {
                    return @([double]$c.ConnectionsEstablished, [double]$c.SegmentsRetransmittedPersec)
                }
            } catch { }
            return @()
        }
        $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $cpuBefore = CpuSample
        $interfaceBefore = InterfaceSample $interface
        $tcpBefore = TcpSample
        $memory = @(); $commit = @(); $disk = @()
        $processCount = $null; $osVersion = $null; $osName = $null; $uptimeSeconds = $null
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $memory = @([double]($os.TotalVisibleMemorySize - $os.FreePhysicalMemory), [double]$os.TotalVisibleMemorySize)
            $processCount = [double]$os.NumberOfProcesses
            $osVersion = [string]$os.Version
            $osName = [string]$os.CSName
            $uptimeSeconds = [double]([DateTime]::UtcNow - $os.LastBootUpTime.ToUniversalTime()).TotalSeconds
        } catch { }
        try {
            $c = Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction Stop
            $commit = @([double]$c.CommittedBytes, [double]$c.CommitLimit)
        } catch { }
        if ($mount) {
            try {
                $volume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$mount'" -ErrorAction Stop
                if ($null -ne $volume.Size -and $volume.Size -gt 0) {
                    $disk = @([double]($volume.Size - $volume.FreeSpace), [double]$volume.Size)
                }
            } catch { }
        }
        $processes = $null
        try {
            $processes = @(Get-Process -ErrorAction Stop | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object {
                @{ name = [string]$_.ProcessName; memory_bytes = [double]$_.WorkingSet64; cpu_seconds = if ($null -ne $_.CPU) { [double]$_.CPU } else { $null } }
            })
        } catch { }
        $serviceState = $null; $dependencies = $null; $dependenciesTruncated = $false
        if ($service) {
            try {
                $svc = Get-Service -Name $service -ErrorAction Stop
                $serviceState = [string]$svc.Status
                $selectedDependencies = @($svc.ServicesDependedOn | Select-Object -First 17)
                $dependenciesTruncated = $selectedDependencies.Count -gt 16
                $dependencies = @($selectedDependencies | Select-Object -First 16 | ForEach-Object { [string]$_.Name })
            } catch { }
        }
        $events = $null; $errorCount = $null; $errorTruncated = $false; $eventsMetadataTruncated = $false
        try {
            $recent = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 101 -ErrorAction Stop)
            $errorTruncated = $recent.Count -gt 100
            $eventsMetadataTruncated = $recent.Count -gt 20
            $errorCount = [double][Math]::Min($recent.Count, 100)
            $events = @($recent | Select-Object -First 20 | ForEach-Object {
                @{ id = [int]$_.Id; level = [int]$_.Level; provider = ([string]$_.ProviderName).Substring(0, [Math]::Min(80, ([string]$_.ProviderName).Length)); at_ms = ([DateTimeOffset]$_.TimeCreated.ToUniversalTime()).ToUnixTimeMilliseconds() }
            })
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @(); $errorCount = 0 }
        }
        $interfaceExtra = $null
        if ($interface) {
            try {
                $stat = Get-NetAdapterStatistics -Name $interface -ErrorAction Stop
                $fields = @('ReceivedPacketErrors','OutboundPacketErrors','ReceivedDiscardedPackets','OutboundDiscardedPackets')
                if (@($fields | Where-Object { $null -eq $stat.PSObject.Properties[$_].Value }).Count -eq 0) {
                    $interfaceExtra = @($fields | ForEach-Object { [double]$stat.PSObject.Properties[$_].Value })
                }
            } catch { }
        }
        $listeningTcp = $null
        try { $listeningTcp = [double]@(Get-NetTCPConnection -State Listen -ErrorAction Stop).Count } catch { }
        Start-Sleep -Milliseconds 250
        $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        @{ schema = 1; start_ms = $start; end_ms = $end; cpu_before = $cpuBefore; cpu_after = (CpuSample);
           interface_before = $interfaceBefore; interface_after = (InterfaceSample $interface);
           memory = $memory; commit = $commit; disk = $disk; error_count = $errorCount;
           events_truncated = $errorTruncated; events_metadata_truncated = $eventsMetadataTruncated; process_count = $processCount; service_state = $serviceState;
           os_version = $osVersion; os_name = $osName; uptime_seconds = $uptimeSeconds; load_one = $null;
           processes = $processes; service_dependencies = $dependencies; service_dependencies_truncated = $dependenciesTruncated; events = $events;
           interface_extra = $interfaceExtra; tcp_before = $tcpBefore; tcp_after = (TcpSample);
           listening_tcp = $listeningTcp }
    } -ArgumentList $service,$mount,$interface -ErrorAction Stop
} catch {
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.ErrorCode -eq -2147024891) {
        '{"collector_status":"denied"}'
        exit 0
    }
    throw
}
if ($result -isnot [System.Collections.IDictionary] -and $result -isnot [pscustomobject]) { throw 'Invalid collector result' }
$fields = @('schema','start_ms','end_ms','cpu_before','cpu_after','interface_before','interface_after','memory','commit','disk','error_count','events_truncated','events_metadata_truncated','process_count','service_state','os_version','os_name','uptime_seconds','load_one','processes','service_dependencies','service_dependencies_truncated','events','interface_extra','tcp_before','tcp_after','listening_tcp')
$closed = [ordered]@{}
foreach ($field in $fields) {
    if ($result -is [System.Collections.IDictionary]) { $closed[$field] = $result[$field] }
    else { $closed[$field] = $result.$field }
}
$closed | ConvertTo-Json -Compress -Depth 6
