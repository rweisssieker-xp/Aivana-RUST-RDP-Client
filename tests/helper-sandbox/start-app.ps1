[CmdletBinding()]
param([switch]$ValidateOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'app-contract.ps1')

function Assert-ExactRoot {
    $root = Get-AppRoot
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

function Clear-OwnedConfigAfterStop([string]$directory) {
    if (-not (Test-Path -LiteralPath $directory)) { return }
    $dir = Get-Item -LiteralPath $directory -Force
    if (-not $dir.PSIsContainer -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $dir.FullName -ine (Join-Path (Get-AppRoot) 'app-fixture')) { throw 'Existing app config path is not the owned directory.' }
    $allowed = @('api.json','portal-a.json','portal-b.json')
    foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force)) {
        if ($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $child.Name -cnotin $allowed) { throw 'Existing app config contains unowned content.' }
    }
    $script = Get-AppScript
    $exe = Get-AppExecutable
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'")) {
        if ($process.ExecutablePath -ine $exe) { continue }
        foreach ($spec in Get-AppSpecs) {
            $config = Get-AppConfig $spec.kind
            $expected = Get-AppCommandLine $script $config
            if ($process.CommandLine -and $process.CommandLine.Contains($script) -and $process.CommandLine.Contains($config)) {
                throw 'Owned app process is still running; refusing config recovery.'
            }
        }
    }
    foreach ($name in $allowed) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    Remove-Item -LiteralPath $directory
}

$eligible = Test-AppGuest
if (-not $eligible -and -not $ValidateOnly) { throw 'App fixture start requires Windows Sandbox guest identity.' }
$result = [ordered]@{ GuestEligible = $eligible; Root = 'C:\RelayneHelperAcceptance'; Database = 'relayne_helper_acceptance'; PgPort = 55433; ApiPort = 58080; PortalAPort = 58081; PortalBPort = 58082 }
if ($ValidateOnly) { [pscustomobject]$result; return }
$root = Assert-ExactRoot
$manifestPath = Join-Path $root 'app-fixture\processes.json'
if (Test-Path -LiteralPath $manifestPath) { throw 'App fixture already has a process manifest; use stop-app.ps1 first.' }
Assert-PortsFree
$configDir = Join-Path $root 'app-fixture'
Clear-OwnedConfigAfterStop $configDir
New-Item -ItemType Directory -Path $configDir | Out-Null
$powershell = Get-AppExecutable
$service = Get-AppScript
$query = Join-Path $PSScriptRoot 'app-query.sql'
$items = @()
$runId = [guid]::NewGuid().ToString('N')
try {
    foreach ($spec in Get-AppSpecs) {
        $configPath = Get-AppConfig $spec.kind
        [ordered]@{ kind=$spec.kind; host='127.0.0.1'; port=$spec.port; root=$root; database='relayne_helper_acceptance'; pgPort=55433; api='http://127.0.0.1:58080'; run_id=$runId } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath $configPath -Encoding ASCII
        $process = Start-Process -FilePath $powershell -ArgumentList (Get-AppCommandLine $service $configPath) -PassThru -WindowStyle Hidden
        $native = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)"
        if (-not $native) { throw 'Launched fixture process exited before identity capture.' }
        $items += [pscustomobject]@{ kind=$spec.kind; port=$spec.port; pid=$process.Id; config=$configPath; config_sha256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash; created_utc=$native.CreationDate.ToUniversalTime().ToString('o') }
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
    $manifest = [ordered]@{ fixture='guest-local'; root=$root; run_id=$runId; script=$service; query_sha256=(Get-FileHash -LiteralPath $query -Algorithm SHA256).Hash; service_sha256=(Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash; processes=$items }
    Assert-AppManifest ([pscustomobject]$manifest)
    Assert-AppProcesses ([pscustomobject]$manifest)
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding ASCII
    [pscustomobject]@{ Ready=$true; Api='http://127.0.0.1:58080/orders?customer_id=424242&limit=3'; PortalA='http://127.0.0.1:58081/check'; PortalB='http://127.0.0.1:58082/check'; Manifest=$manifestPath; Evidence=(Join-Path $root 'evidence') }
} catch {
    $cleanupSafe = $true
    foreach ($item in $items) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($item.pid)" -ErrorAction SilentlyContinue
        if ($process -and (Test-AppProcess $process $item $service)) {
            Stop-Process -Id $item.pid -Force -ErrorAction SilentlyContinue
        } elseif ($process) { $cleanupSafe = $false }
    }
    if ($cleanupSafe) {
        foreach ($item in $items) { if (Get-Process -Id $item.pid -ErrorAction SilentlyContinue) { $cleanupSafe = $false } }
    }
    if ($cleanupSafe -and -not (Test-Path -LiteralPath $manifestPath)) {
        Clear-OwnedConfigAfterStop $configDir
    }
    throw
}
