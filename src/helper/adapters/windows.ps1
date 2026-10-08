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
            $counter = Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
            return @([double]$counter.PercentProcessorTime, [double]$counter.Timestamp_Sys100NS)
        } catch { return @() }
    }
    function InterfaceSample($name) {
        if (-not $name) { return @() }
        try {
            $counter = Get-NetAdapterStatistics -Name $name -ErrorAction Stop
            return @([double]$counter.ReceivedBytes, [double]$counter.SentBytes)
        } catch { return @() }
    }
    $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $cpuBefore = CpuSample
    $interfaceBefore = InterfaceSample $interface
    $memory = @()
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $memory = @([double]($os.TotalVisibleMemorySize - $os.FreePhysicalMemory), [double]$os.TotalVisibleMemorySize)
        $processCount = [double]$os.NumberOfProcesses
    } catch { $processCount = $null }
    $disk = @()
    $commit = @()
    try {
        $commitCounter = Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction Stop
        $commit = @([double]$commitCounter.CommittedBytes, [double]$commitCounter.CommitLimit)
    } catch { }
    $errorCount = $null
    $errorTruncated = $false
    try {
        $errors = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 101 -ErrorAction Stop)
        if ($errors.Count -le 100) { $errorCount = [double]$errors.Count } else { $errorTruncated = $true }
    } catch { }
    if ($mount) {
        try {
            $volume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$mount'" -ErrorAction Stop
            if ($volume) { $disk = @([double]($volume.Size - $volume.FreeSpace), [double]$volume.Size) }
        } catch { }
    }
    $serviceState = $null
    if ($service) {
        try { $serviceState = (Get-Service -Name $service -ErrorAction Stop).Status.ToString() } catch { }
    }
    Start-Sleep -Milliseconds 250
    $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $cpuAfter = CpuSample
    $interfaceAfter = InterfaceSample $interface
    [pscustomobject]@{ schema = 1; start_ms = $start; end_ms = $end;
        cpu_before = $cpuBefore; cpu_after = $cpuAfter;
        interface_before = $interfaceBefore; interface_after = $interfaceAfter;
        memory = $memory; commit = $commit; disk = $disk; error_count = $errorCount; events_truncated = $errorTruncated;
        process_count = $processCount; service_state = $serviceState }
} -ArgumentList $service,$mount,$interface -ErrorAction Stop
} catch {
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.ErrorCode -eq -2147024891) {
        '{"collector_status":"denied"}'
        exit 0
    }
    throw
}
$result | Select-Object schema,start_ms,end_ms,cpu_before,cpu_after,interface_before,interface_after,memory,commit,disk,error_count,events_truncated,process_count,service_state | ConvertTo-Json -Compress -Depth 4
