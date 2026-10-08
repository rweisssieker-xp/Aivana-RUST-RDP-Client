[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'app-contract.ps1')

Assert-AppGuest
$root = Get-AppRoot
$manifestPath = Join-Path $root 'app-fixture\processes.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Exact running fixture manifest missing.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-AppManifest $manifest
Assert-AppProcesses $manifest

function Assert-Rows($data) {
    if ($data.database -cne 'relayne_helper_acceptance' -or $data.role -cne 'relayne_fixture_reader' -or
        $data.customer_id -ne 424242 -or @($data.orders).Count -ne 3) { throw 'Unexpected fixture result identity or length.' }
    for ($i = 0; $i -lt 3; $i++) {
        $row = $data.orders[$i]
        if ($row.order_id -ne (60001 + $i) -or $row.customer_id -ne 424242 -or
            $row.status -cne 'pending' -or [decimal]$row.amount -ne [decimal]99.99) { throw 'Unexpected synthetic order content.' }
    }
}

function Assert-FreshReceipt($manifest, [string]$kind, [string]$probe, [string]$route, [string]$origin, [int]$status) {
    $path = Join-Path (Get-AppRoot) "evidence\app-$($manifest.run_id)-$kind.jsonl"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $kind receipt file." }
    $file = Get-Item -LiteralPath $path -Force
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 1048576) { throw 'Receipt path or byte budget changed.' }
    $lines = @(Get-Content -LiteralPath $path)
    if ($lines.Count -gt 512) { throw 'Receipt record budget changed.' }
    $matches = @()
    foreach ($line in $lines) {
        if ([Text.Encoding]::UTF8.GetByteCount($line) -gt 4096) { throw 'Oversized receipt record.' }
        $record = $line | ConvertFrom-Json
        if ($record.probe -ceq $probe) { $matches += $record }
    }
    if ($matches.Count -ne 1) { throw "No unique fresh $kind receipt for challenge." }
    $result = $matches[0]
    if ($result.fixture -cne 'guest-local' -or $result.run_id -cne $manifest.run_id -or
        $result.service -cne $kind -or $result.route -cne $route -or
        $result.origin -cne $origin -or $result.status -ne $status -or
        $result.elapsed_ms -lt 0 -or $result.elapsed_ms -gt 10000) { throw "Invalid $kind challenge receipt." }
    if ($status -eq 200) {
        if (-not $result.db_backed -or (@($result.observed_order_ids) -join ',') -cne '60001,60002,60003' -or
            @($result.observed_rows).Count -ne 3) { throw "Missing $kind database-backed content receipt." }
        for ($i = 0; $i -lt 3; $i++) {
            $row = $result.observed_rows[$i]
            if ($row.order_id -ne (60001 + $i) -or $row.customer_id -ne 424242 -or
                $row.status -cne 'pending' -or [decimal]$row.amount -ne [decimal]99.99) { throw "Wrong $kind receipt row content." }
        }
    } elseif ($result.db_backed) { throw "Failed $kind request falsely marked database-backed." }
}

$receipts = @()
$apiUrl = 'http://127.0.0.1:58080/orders?customer_id=424242&limit=3'
$probe = [guid]::NewGuid().ToString('N')
$clock = [Diagnostics.Stopwatch]::StartNew()
$direct = Invoke-WebRequest -Uri $apiUrl -Headers @{ 'X-Relayne-Probe'=$probe } -UseBasicParsing -TimeoutSec 6
$clock.Stop()
Assert-Rows ($direct.Content | ConvertFrom-Json)
Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' '' 200
$receipts += [ordered]@{ target='api'; origin='none'; status=[int]$direct.StatusCode; elapsed_ms=$clock.Elapsed.TotalMilliseconds; customer_id=424242; order_ids=@(60001,60002,60003); row_status='pending'; amount=99.99; challenge=$probe }

foreach ($port in @(58081,58082)) {
    $origin = "http://127.0.0.1:$port"
    $kind = if ($port -eq 58081) { 'portal-a' } else { 'portal-b' }
    $probe = [guid]::NewGuid().ToString('N')
    $clock.Restart()
    $api = Invoke-WebRequest -Uri $apiUrl -Headers @{ Origin=$origin; 'X-Relayne-Probe'=$probe } -UseBasicParsing -TimeoutSec 6
    $clock.Stop()
    Assert-Rows ($api.Content | ConvertFrom-Json)
    if ($api.Headers['Access-Control-Allow-Origin'] -cne $origin) { throw "CORS did not authorize exactly $origin." }
    Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' $origin 200
    $receipts += [ordered]@{ target='api-cors'; origin=$origin; status=[int]$api.StatusCode; elapsed_ms=$clock.Elapsed.TotalMilliseconds; customer_id=424242; order_ids=@(60001,60002,60003); row_status='pending'; amount=99.99; challenge=$probe }

    $probe = [guid]::NewGuid().ToString('N')
    $clock.Restart()
    $portal = Invoke-WebRequest -Uri "$origin/check" -Headers @{ 'X-Relayne-Probe'=$probe } -UseBasicParsing -TimeoutSec 6
    $clock.Stop()
    $check = $portal.Content | ConvertFrom-Json
    if ($check.status -cne 'verified' -or $check.origin -cne $origin -or
        (@($check.order_ids) -join ',') -cne '60001,60002,60003') { throw "Portal $origin failed shared database check." }
    Assert-FreshReceipt $manifest $kind $probe '/check' $origin 200
    Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' $origin 200
    $receipts += [ordered]@{ target='portal'; origin=$origin; status=[int]$portal.StatusCode; elapsed_ms=$clock.Elapsed.TotalMilliseconds; customer_id=424242; order_ids=@($check.order_ids); row_status='pending'; amount=99.99; challenge=$probe }

    $probe = [guid]::NewGuid().ToString('N')
    $page = Invoke-WebRequest -Uri "$origin/" -Headers @{ 'X-Relayne-Probe'=$probe } -UseBasicParsing -TimeoutSec 6
    if ($page.Content -notmatch 'Order 60001: pending; 99.99') { throw "Portal $origin did not render checked API content." }
    Assert-FreshReceipt $manifest $kind $probe '/' $origin 200
    Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' $origin 200
}
$denied = $false
$probe = [guid]::NewGuid().ToString('N')
try { Invoke-WebRequest -Uri $apiUrl -Headers @{ Origin='http://127.0.0.1:58083'; 'X-Relayne-Probe'=$probe } -UseBasicParsing -TimeoutSec 6 | Out-Null }
catch { $denied = $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 403 }
if (-not $denied) { throw 'Unreviewed origin was not denied.' }
Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' 'http://127.0.0.1:58083' 403
Assert-AppManifest $manifest
Assert-AppProcesses $manifest
$result = [ordered]@{ fixture='guest-local'; run_id=$manifest.run_id; verified_utc=[DateTime]::UtcNow.ToString('o'); database='relayne_helper_acceptance'; checks=$receipts; denied_origin='http://127.0.0.1:58083'; denied_status=403; product_acceptance=$false }
$path = Join-Path $root "evidence\app-$($manifest.run_id)-verification.json"
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
[pscustomobject]@{ Passed=$true; Receipt=$path; Checks=$receipts.Count; ProductAcceptance=$false }
