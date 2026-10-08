[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = 'C:\RelayneHelperAcceptance'
$manifestPath = Join-Path $root 'app-fixture\processes.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Exact running fixture manifest missing.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$system = Get-CimInstance Win32_ComputerSystem
if ($identity.Name.Split('\')[-1] -ine 'WDAGUtilityAccount' -or
    "$($system.Manufacturer) $($system.Model)" -notmatch '(?i)Microsoft Corporation.*Virtual Machine|Windows Sandbox') {
    throw 'App fixture verification requires Windows Sandbox guest identity.'
}

function Assert-Rows($data) {
    if ($data.database -cne 'relayne_helper_acceptance' -or $data.role -cne 'relayne_fixture_reader' -or
        $data.customer_id -ne 424242 -or @($data.orders).Count -ne 3) { throw 'Unexpected fixture result identity or length.' }
    for ($i = 0; $i -lt 3; $i++) {
        $row = $data.orders[$i]
        if ($row.order_id -ne (60001 + $i) -or $row.customer_id -ne 424242 -or
            $row.status -cne 'pending' -or [decimal]$row.amount -ne [decimal]99.99) { throw 'Unexpected synthetic order content.' }
    }
}

$receipts = @()
$apiUrl = 'http://127.0.0.1:58080/orders?customer_id=424242&limit=3'
$clock = [Diagnostics.Stopwatch]::StartNew()
$direct = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing -TimeoutSec 6
$clock.Stop()
Assert-Rows ($direct.Content | ConvertFrom-Json)
$receipts += [ordered]@{ target='api'; origin='none'; status=[int]$direct.StatusCode; elapsed_ms=$clock.Elapsed.TotalMilliseconds; customer_id=424242; order_ids=@(60001,60002,60003); row_status='pending'; amount=99.99 }
foreach ($port in @(58081,58082)) {
    $origin = "http://127.0.0.1:$port"
    $clock.Restart()
    $api = Invoke-WebRequest -Uri $apiUrl -Headers @{ Origin=$origin } -UseBasicParsing -TimeoutSec 6
    $clock.Stop()
    Assert-Rows ($api.Content | ConvertFrom-Json)
    if ($api.Headers['Access-Control-Allow-Origin'] -cne $origin) { throw "CORS did not authorize exactly $origin." }
    $receipts += [ordered]@{ target='api-cors'; origin=$origin; status=[int]$api.StatusCode; elapsed_ms=$clock.Elapsed.TotalMilliseconds; customer_id=424242; order_ids=@(60001,60002,60003); row_status='pending'; amount=99.99 }
    $clock.Restart()
    $portal = Invoke-WebRequest -Uri "$origin/check" -UseBasicParsing -TimeoutSec 6
    $clock.Stop()
    $check = $portal.Content | ConvertFrom-Json
    if ($check.status -cne 'verified' -or $check.origin -cne $origin -or
        (@($check.order_ids) -join ',') -cne '60001,60002,60003') { throw "Portal $origin failed shared database check." }
    $receipts += [ordered]@{ target='portal'; origin=$origin; status=[int]$portal.StatusCode; elapsed_ms=$clock.Elapsed.TotalMilliseconds; customer_id=424242; order_ids=@($check.order_ids); row_status='pending'; amount=99.99 }
    $page = Invoke-WebRequest -Uri "$origin/" -UseBasicParsing -TimeoutSec 6
    if ($page.Content -notmatch 'Order 60001: pending; 99.99') { throw "Portal $origin did not render checked API content." }
}
$denied = $false
try { Invoke-WebRequest -Uri $apiUrl -Headers @{ Origin='http://127.0.0.1:58083' } -UseBasicParsing -TimeoutSec 6 | Out-Null }
catch { $denied = $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 403 }
if (-not $denied) { throw 'Unreviewed origin was not denied.' }
$result = [ordered]@{ fixture='guest-local'; verified_utc=[DateTime]::UtcNow.ToString('o'); database='relayne_helper_acceptance'; checks=$receipts; denied_origin='http://127.0.0.1:58083'; denied_status=403; product_acceptance=$false }
$path = Join-Path $root 'evidence\app-verification.json'
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
[pscustomobject]@{ Passed=$true; Receipt=$path; Checks=$receipts.Count; ProductAcceptance=$false }
