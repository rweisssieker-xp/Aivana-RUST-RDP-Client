[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ConfigPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This file is executed only by start-app.ps1 in the disposable guest. Each
# process receives its own non-secret config and writes its own bounded receipt.
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$root = 'C:\RelayneHelperAcceptance'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $computer = Get-CimInstance Win32_ComputerSystem
    $guest = $identity.Name.Split('\')[-1] -ieq 'WDAGUtilityAccount' -and
        "$($computer.Manufacturer) $($computer.Model)" -match '(?i)Microsoft Corporation.*Virtual Machine|Windows Sandbox'
} catch { $guest = $false }
if (-not $guest) { throw 'App service requires Windows Sandbox guest identity.' }
if ($config.root -cne $root -or $config.database -cne 'relayne_helper_acceptance' -or
    $config.pgPort -ne 55433 -or $config.host -cne '127.0.0.1' -or
    $config.kind -cnotin @('api', 'portal-a', 'portal-b')) { throw 'Invalid fixture app contract.' }
$ports = @{ api = 58080; 'portal-a' = 58081; 'portal-b' = 58082 }
if ($config.port -ne $ports[$config.kind]) { throw 'Invalid fixture app port.' }
if ([IO.Path]::GetFullPath($ConfigPath) -ine (Join-Path $root "app-fixture\$($config.kind).json")) { throw 'Invalid fixture config path.' }
if ($config.run_id -notmatch '^[a-f0-9]{32}$') { throw 'Invalid fixture run identifier.' }
$queryPath = Join-Path $PSScriptRoot 'app-query.sql'
$receiptPath = Join-Path $root "evidence\app-$($config.run_id)-$($config.kind).jsonl"
if (Test-Path -LiteralPath $receiptPath) { throw 'Per-run receipt already exists.' }
$receiptCount = 0
$receiptBytes = 0
$credentialPath = Join-Path $root 'credentials.txt'
$caPath = Join-Path $root 'root.crt'
$psqlPath = Join-Path $root 'pgsql\bin\psql.exe'

function Assert-ExpectedRows($value) {
    if ($value.database -cne 'relayne_helper_acceptance' -or
        $value.role -cne 'relayne_fixture_reader' -or
        $value.customer_id -ne 424242 -or @($value.orders).Count -ne 3) { return $false }
    for ($i = 0; $i -lt 3; $i++) {
        $row = $value.orders[$i]
        if ($row.order_id -ne (60001 + $i) -or $row.customer_id -ne 424242 -or
            $row.status -cne 'pending' -or [decimal]$row.amount -ne [decimal]99.99) { return $false }
    }
    return $true
}

function Invoke-DatabaseQuery {
    $readerLine = @(Get-Content -LiteralPath $credentialPath | Where-Object { $_ -clike 'reader=*' })
    if ($readerLine.Count -ne 1) { throw 'Missing guest reader credential.' }
    $secret = $readerLine[0].Substring(7)
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $psqlPath
        $start.Arguments = '-X -q -A -t -v ON_ERROR_STOP=1 -v customer_id=424242 -v row_limit=3 -f "' + $queryPath + '"'
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.CreateNoWindow = $true
        $start.EnvironmentVariables['PGPASSWORD'] = $secret
        $start.EnvironmentVariables['PGUSER'] = 'relayne_fixture_reader'
        $start.EnvironmentVariables['PGHOST'] = '127.0.0.1'
        $start.EnvironmentVariables['PGPORT'] = '55433'
        $start.EnvironmentVariables['PGDATABASE'] = 'relayne_helper_acceptance'
        $start.EnvironmentVariables['PGSSLMODE'] = 'verify-full'
        $start.EnvironmentVariables['PGSSLROOTCERT'] = $caPath
        $process = [Diagnostics.Process]::Start($start)
        try {
            if (-not $process.WaitForExit(5000)) { $process.Kill(); throw 'Bounded database query timed out.' }
            $output = $process.StandardOutput.ReadToEnd().Trim()
            [void]$process.StandardError.ReadToEnd() # Never export SQL or credential diagnostics.
            if ($process.ExitCode -ne 0) { throw 'Bounded database query failed.' }
            $value = $output | ConvertFrom-Json
            if (-not (Assert-ExpectedRows $value)) { throw 'Database rows differ from the reviewed synthetic seed.' }
            return $value
        } finally { $process.Dispose() }
    } finally { $secret = $null; $readerLine = $null }
}

function Invoke-ApiFromPortal([string]$origin, [string]$probe) {
    $request = [Net.HttpWebRequest][Net.WebRequest]::Create('http://127.0.0.1:58080/orders?customer_id=424242&limit=3')
    $request.Method = 'GET'
    $request.Timeout = 5000
    $request.Headers.Add('Origin', $origin)
    if ($probe) { $request.Headers.Add('X-Relayne-Probe', $probe) }
    $response = [Net.HttpWebResponse]$request.GetResponse()
    try {
        if ([int]$response.StatusCode -ne 200 -or $response.Headers['Access-Control-Allow-Origin'] -cne $origin) {
            throw 'API status or exact CORS origin failed.'
        }
        $stream = [IO.StreamReader]::new($response.GetResponseStream())
        try { $value = $stream.ReadToEnd() | ConvertFrom-Json } finally { $stream.Dispose() }
        if (-not (Assert-ExpectedRows $value)) { throw 'Portal received unexpected database rows.' }
        return $value
    } finally { $response.Dispose() }
}

function Write-Response($client, [int]$status, [string]$body, [string]$contentType, [string]$cors) {
    $stream = $client.GetStream()
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $reason = if ($status -eq 200) { 'OK' } elseif ($status -eq 400) { 'Bad Request' } elseif ($status -eq 403) { 'Forbidden' } elseif ($status -eq 404) { 'Not Found' } else { 'Service Unavailable' }
    $headers = "HTTP/1.1 $status $reason`r`nContent-Type: $contentType; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`nCache-Control: no-store`r`n"
    if ($cors) { $headers += "Access-Control-Allow-Origin: $cors`r`nVary: Origin`r`n" }
    $head = [Text.Encoding]::ASCII.GetBytes($headers + "`r`n")
    $stream.Write($head, 0, $head.Length)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

function Read-BoundedRequest($client) {
    $stream = $client.GetStream()
    $bytes = [Collections.Generic.List[byte]]::new()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($bytes.Count -lt 4096) {
        $remaining = 5000 - [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0) { throw 'HTTP header deadline exceeded.' }
        $stream.ReadTimeout = $remaining
        $value = $stream.ReadByte()
        if ($value -lt 0 -or $value -gt 127) { throw 'Invalid HTTP header byte.' }
        $bytes.Add([byte]$value)
        $n = $bytes.Count
        if ($n -ge 4 -and $bytes[$n-4] -eq 13 -and $bytes[$n-3] -eq 10 -and
            $bytes[$n-2] -eq 13 -and $bytes[$n-1] -eq 10) { break }
    }
    if ($bytes.Count -ge 4096 -and -not ($bytes[$bytes.Count-4] -eq 13 -and $bytes[$bytes.Count-3] -eq 10 -and
        $bytes[$bytes.Count-2] -eq 13 -and $bytes[$bytes.Count-1] -eq 10)) { throw 'HTTP header exceeds 4096 bytes.' }
    $lines = [Text.Encoding]::ASCII.GetString($bytes.ToArray()).Split(@("`r`n"), [StringSplitOptions]::None)
    if ($lines.Count -gt 34 -or $lines[0] -notmatch '^GET ([^ ]{1,128}) HTTP/1\.[01]$') { throw 'Invalid or oversized request line/header count.' }
    $route = $Matches[1]; $origin = ''; $probe = ''; $originCount = 0; $probeCount = 0
    for ($i = 1; $i -lt $lines.Count - 2; $i++) {
        if ($lines[$i] -notmatch '^([A-Za-z0-9-]+):[ \t]*([^\r\n]*)$') { throw 'Malformed HTTP header.' }
        $name = $Matches[1]; $value = $Matches[2].Trim()
        if ($name -ieq 'Origin') { $originCount++; $origin = $value }
        if ($name -ieq 'X-Relayne-Probe') { $probeCount++; $probe = $value }
    }
    if ($originCount -gt 1 -or ($originCount -eq 1 -and -not $origin) -or
        $probeCount -gt 1 -or ($probeCount -eq 1 -and $probe -notmatch '^[a-f0-9]{32}$')) {
        throw 'Ambiguous or malformed Origin/probe header.'
    }
    return [pscustomobject]@{ route=$route; origin=$origin; probe=$probe }
}

function Write-BoundedReceipt($receipt) {
    $line = ($receipt | ConvertTo-Json -Depth 6 -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($line)
    if ($script:receiptCount -ge 512 -or $script:receiptBytes + $bytes.Length -gt 1048576 -or $bytes.Length -gt 4096) {
        throw 'App receipt budget exhausted; refusing unrecorded response.'
    }
    $file = [IO.FileStream]::new($receiptPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    $script:receiptCount++
    $script:receiptBytes += $bytes.Length
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'), [int]$config.port)
$listener.Start()
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $client.ReceiveTimeout = 5000
            $client.SendTimeout = 5000
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $status = 400; $body = '{"error":"invalid request"}'; $type = 'application/json'; $cors = ''; $observed = @(); $observedRows = @(); $receiptOrigin = ''; $route = 'invalid'; $probe = ''
            try {
                $request = Read-BoundedRequest $client
                $route = $request.route; $origin = $request.origin; $probe = $request.probe; $receiptOrigin = $origin
                $status = 404; $body = '{"error":"unknown route"}'
                if ($config.kind -ceq 'api') {
                    if ($origin -and $origin -cnotin @('http://127.0.0.1:58081', 'http://127.0.0.1:58082')) {
                        $status = 403; $body = '{"error":"origin denied"}'
                    } elseif ($route -ceq '/orders?customer_id=424242&limit=3') {
                        if ($origin) { $cors = $origin }
                        $data = Invoke-DatabaseQuery
                        $observed = @($data.orders | ForEach-Object { $_.order_id })
                        $observedRows = @($data.orders | Select-Object order_id,customer_id,status,amount)
                        $body = $data | ConvertTo-Json -Depth 8 -Compress
                        $status = 200
                    }
                } elseif ($route -ceq '/check' -or $route -ceq '/') {
                    $portalOrigin = "http://127.0.0.1:$($config.port)"
                    $receiptOrigin = $portalOrigin
                    $data = Invoke-ApiFromPortal $portalOrigin $probe
                    $observed = @($data.orders | ForEach-Object { $_.order_id })
                    $observedRows = @($data.orders | Select-Object order_id,customer_id,status,amount)
                    if ($route -ceq '/check') {
                        $body = [ordered]@{ portal = $config.kind; origin = $portalOrigin; api = 'http://127.0.0.1:58080'; database = $data.database; order_ids = $observed; status = 'verified' } | ConvertTo-Json -Compress
                    } else {
                        $type = 'text/html'
                        $rows = @($data.orders | ForEach-Object {
                            '<li>Order ' + [Net.WebUtility]::HtmlEncode([string]$_.order_id) + ': ' +
                            [Net.WebUtility]::HtmlEncode([string]$_.status) + '; ' +
                            [Net.WebUtility]::HtmlEncode([string]$_.amount) + '</li>'
                        }) -join ''
                        $body = '<!doctype html><meta charset="utf-8"><title>Relayne fixture ' + $config.kind + '</title><h1>' + $config.kind + '</h1><p>Customer ' +
                            [Net.WebUtility]::HtmlEncode([string]$data.customer_id) + '</p><ul>' + $rows + '</ul>'
                    }
                    $status = 200
                }
            } catch {
                if ($route -ne 'invalid') { $status = 503; $body = '{"error":"fixture data unavailable"}'; $type = 'application/json' }
            }
            $clock.Stop()
            $receipt = [ordered]@{ at_utc = [DateTime]::UtcNow.ToString('o'); fixture = 'guest-local'; run_id = $config.run_id; service = $config.kind; origin = $receiptOrigin; route = $route; probe = $probe; status = $status; elapsed_ms = $clock.Elapsed.TotalMilliseconds; expected_order_ids = @(60001,60002,60003); observed_order_ids = $observed; observed_rows = $observedRows; db_backed = ($status -eq 200) }
            Write-BoundedReceipt $receipt
            Write-Response $client $status $body $type $cors
        } finally { $client.Dispose() }
    }
} finally { $listener.Stop() }
