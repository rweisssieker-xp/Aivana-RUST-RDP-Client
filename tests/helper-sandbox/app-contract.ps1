Set-StrictMode -Version Latest
$script:AppContractDir = $PSScriptRoot

function Get-AppRoot { 'C:\RelayneHelperAcceptance' }
function Get-AppSpecs {
    @(
        [pscustomobject]@{ kind='api'; port=58080 },
        [pscustomobject]@{ kind='portal-a'; port=58081 },
        [pscustomobject]@{ kind='portal-b'; port=58082 }
    )
}
function Get-AppExecutable { Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe' }
function Get-AppScript { Join-Path $script:AppContractDir 'app-service.ps1' }
function Get-AppConfig([string]$kind) { Join-Path (Get-AppRoot) "app-fixture\$kind.json" }
function Test-AppGuest {
    try {
        $account = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($account.Name.Split('\')[-1] -ine 'WDAGUtilityAccount') { return $false }
        $system = Get-CimInstance Win32_ComputerSystem
        return "$($system.Manufacturer) $($system.Model)" -match '(?i)Microsoft Corporation.*Virtual Machine|Windows Sandbox'
    } catch { return $false }
}
function Assert-AppGuest { if (-not (Test-AppGuest)) { throw 'App fixture requires Windows Sandbox guest identity.' } }
function Get-AppCommandLine([string]$script, [string]$config) {
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $script + '" -ConfigPath "' + $config + '"'
}
function Test-AppProcess($process, $entry, [string]$script) {
    if (-not $process) { return $false }
    $expectedConfig = Get-AppConfig ([string]$entry.kind)
    if ($process.ExecutablePath -ine (Get-AppExecutable) -or
        $entry.config -ine $expectedConfig -or
        (($process.CommandLine.TrimEnd() -ine ('"' + (Get-AppExecutable) + '" ' + (Get-AppCommandLine $script $expectedConfig))) -and
         ($process.CommandLine.TrimEnd() -ine ((Get-AppExecutable) + ' ' + (Get-AppCommandLine $script $expectedConfig))))) { return $false }
    $created = $process.CreationDate.ToUniversalTime().ToString('o')
    return $created -ceq $entry.created_utc
}
function Assert-AppManifest($manifest) {
    $root = Get-AppRoot
    $script = Get-AppScript
    $rootItem = Get-Item -LiteralPath $root -Force
    $configDir = Get-Item -LiteralPath (Join-Path $root 'app-fixture') -Force
    if ($rootItem.FullName -ine $root -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $configDir.FullName -ine (Join-Path $root 'app-fixture') -or ($configDir.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Fixture root/config directory identity changed.'
    }
    if ($manifest.fixture -cne 'guest-local' -or $manifest.root -cne $root -or
        $manifest.script -ine $script -or @($manifest.processes).Count -ne 3 -or
        $manifest.service_sha256 -cne (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash -or
        $manifest.query_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $script:AppContractDir 'app-query.sql') -Algorithm SHA256).Hash) {
        throw 'Fixture manifest source/root contract changed.'
    }
    $specs = @(Get-AppSpecs)
    for ($i = 0; $i -lt 3; $i++) {
        $entry = $manifest.processes[$i]
        if ($entry.kind -cne $specs[$i].kind -or $entry.port -ne $specs[$i].port -or
            $entry.config -ine (Get-AppConfig $specs[$i].kind)) { throw "Fixture process entry $i changed." }
        $configItem = Get-Item -LiteralPath $entry.config -Force
        if (
            ($configItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $entry.config_sha256 -cne (Get-FileHash -LiteralPath $entry.config -Algorithm SHA256).Hash -or
            $entry.pid -le 0 -or -not $entry.created_utc) { throw "Fixture process entry $i changed." }
    }
    if ($manifest.run_id -notmatch '^[a-f0-9]{32}$') { throw 'Fixture run identifier changed.' }
}
function Assert-AppProcesses($manifest) {
    foreach ($entry in $manifest.processes) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.pid)" -ErrorAction SilentlyContinue
        if (-not (Test-AppProcess $process $entry $manifest.script)) { throw "Fixture process $($entry.kind) is missing or changed." }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort $entry.port -ErrorAction Stop)
        if ($listeners.Count -ne 1 -or $listeners[0].OwningProcess -ne $entry.pid) {
            throw "Fixture listener $($entry.kind) is not owned by its recorded process."
        }
    }
}
