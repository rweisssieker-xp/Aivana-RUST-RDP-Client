[CmdletBinding()]
param([switch]$ValidateOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SandboxGuest {
    try {
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1] -ine 'WDAGUtilityAccount') { return $false }
        $system = Get-CimInstance Win32_ComputerSystem
        return "$($system.Manufacturer) $($system.Model)" -match '(?i)Microsoft Corporation.*Virtual Machine|Windows Sandbox'
    } catch { return $false }
}

function Assert-ExactRoot {
    $root = 'C:\RelayneHelperAcceptance'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Prepared guest fixture root is missing.' }
    $item = Get-Item -LiteralPath $root -Force
    if ($item.FullName -ine $root -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guest root identity failed.' }
    foreach ($path in @('credentials.txt','root.crt','pgsql\bin\psql.exe','evidence')) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $path))) { throw "Missing prepared guest input: $path" }
    }
    $credential = Join-Path $root 'credentials.txt'
    $acl = Get-Acl -LiteralPath $credential
    $allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18')
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin $allowed) { throw 'Guest credential file grants access outside the fixture account and SYSTEM.' }
    }
    return $root
}

function Assert-PortsFree {
    foreach ($port in @(58080,58081,58082)) {
        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'), $port)
        try { $probe.Start() } catch { throw "Fixture app port $port is occupied." } finally { $probe.Stop() }
    }
}

$eligible = Test-SandboxGuest
if (-not $eligible -and -not $ValidateOnly) { throw 'App fixture start requires Windows Sandbox guest identity.' }
$result = [ordered]@{ GuestEligible = $eligible; Root = 'C:\RelayneHelperAcceptance'; Database = 'relayne_helper_acceptance'; PgPort = 55433; ApiPort = 58080; PortalAPort = 58081; PortalBPort = 58082 }
if ($ValidateOnly) { [pscustomobject]$result; return }
$root = Assert-ExactRoot
$manifestPath = Join-Path $root 'app-fixture\processes.json'
if (Test-Path -LiteralPath $manifestPath) { throw 'App fixture already has a process manifest; use stop-app.ps1 first.' }
Assert-PortsFree
$configDir = Join-Path $root 'app-fixture'
if (Test-Path -LiteralPath $configDir) { throw 'Existing app fixture config requires inspection before a fresh start.' }
New-Item -ItemType Directory -Path $configDir | Out-Null
$powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$service = Join-Path $PSScriptRoot 'app-service.ps1'
$query = Join-Path $PSScriptRoot 'app-query.sql'
$items = @()
try {
    foreach ($spec in @(@{ kind='api'; port=58080 }, @{ kind='portal-a'; port=58081 }, @{ kind='portal-b'; port=58082 })) {
        $configPath = Join-Path $configDir "$($spec.kind).json"
        [ordered]@{ kind=$spec.kind; host='127.0.0.1'; port=$spec.port; root=$root; database='relayne_helper_acceptance'; pgPort=55433; api='http://127.0.0.1:58080' } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath $configPath -Encoding ASCII
        $process = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $service + '"'),'-ConfigPath',('"' + $configPath + '"')) -PassThru -WindowStyle Hidden
        $items += [ordered]@{ kind=$spec.kind; port=$spec.port; pid=$process.Id; config=$configPath; started_utc=[DateTime]::UtcNow.ToString('o') }
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        Start-Sleep -Milliseconds 250
        try {
            $api = Invoke-RestMethod -Uri 'http://127.0.0.1:58080/orders?customer_id=424242&limit=3' -TimeoutSec 3
            $a = Invoke-RestMethod -Uri 'http://127.0.0.1:58081/check' -TimeoutSec 3
            $b = Invoke-RestMethod -Uri 'http://127.0.0.1:58082/check' -TimeoutSec 3
            if (@($api.orders).Count -eq 3 -and $api.orders[0].order_id -eq 60001 -and $a.status -eq 'verified' -and $b.status -eq 'verified') { $ready = $true; break }
        } catch { }
    }
    if (-not $ready) { throw 'API and both portal data checks did not become ready.' }
    $manifest = [ordered]@{ fixture='guest-local'; root=$root; script=$service; query_sha256=(Get-FileHash -LiteralPath $query -Algorithm SHA256).Hash; service_sha256=(Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash; processes=$items }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding ASCII
    [pscustomobject]@{ Ready=$true; Api='http://127.0.0.1:58080/orders?customer_id=424242&limit=3'; PortalA='http://127.0.0.1:58081/check'; PortalB='http://127.0.0.1:58082/check'; Manifest=$manifestPath; Evidence=(Join-Path $root 'evidence') }
} catch {
    foreach ($item in $items) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($item.pid)" -ErrorAction SilentlyContinue
        if ($process -and $process.ExecutablePath -ieq $powershell -and $process.CommandLine.Contains($service) -and $process.CommandLine.Contains($item.config)) {
            Stop-Process -Id $item.pid -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
