[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-That([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
function Assert-Throws([scriptblock]$work, [string]$message) {
    $failed = $false
    try { & $work | Out-Null } catch { $failed = $true }
    Assert-That $failed $message
}
function Import-TestFunction([string]$filename, [string]$functionName) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $filename), [ref]$tokens, [ref]$errors)
    Assert-That ($errors.Count -eq 0) "$filename parser errors: $($errors -join '; ')"
    $found = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true))
    Assert-That ($found.Count -eq 1) "Missing unique $functionName in $filename."
    $definition = [regex]::Replace($found[0].Extent.Text, '^function\s+' + [regex]::Escape($functionName), "function global:$functionName")
    . ([scriptblock]::Create($definition))
}
foreach ($name in @('app-contract.ps1','app-service.ps1','start-app.ps1','stop-app.ps1','verify-app.ps1')) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$errors)
    Assert-That ($errors.Count -eq 0) "$name parser errors: $($errors -join '; ')"
}
$valid = & (Join-Path $PSScriptRoot 'start-app.ps1') -ValidateOnly
Assert-That ($valid.Root -ceq 'C:\RelayneHelperAcceptance' -and $valid.Database -ceq 'relayne_helper_acceptance') 'Dedicated root/database contract changed.'
Assert-That ($valid.PgPort -eq 55433 -and $valid.ApiPort -eq 58080 -and $valid.PortalAPort -eq 58081 -and $valid.PortalBPort -eq 58082) 'Dedicated port contract changed.'
if ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1] -ine 'WDAGUtilityAccount') {
    Assert-That (-not $valid.GuestEligible) 'Host must not appear guest eligible.'
    Assert-Throws { & (Join-Path $PSScriptRoot 'start-app.ps1') } 'Host start did not fail closed.'
    Assert-Throws { & (Join-Path $PSScriptRoot 'verify-app.ps1') } 'Host verifier did not fail closed.'
}

. (Join-Path $PSScriptRoot 'app-contract.ps1')
Import-TestFunction 'app-service.ps1' 'Assert-ExpectedRows'
$rows = @(1..3 | ForEach-Object { [pscustomobject]@{ order_id=(60000 + $_); customer_id=424242; status='pending'; amount=99.99 } })
$good = [pscustomobject]@{ database='relayne_helper_acceptance'; role='relayne_fixture_reader'; customer_id=424242; orders=$rows }
Assert-That (Assert-ExpectedRows $good) 'Reviewed rows rejected.'
$bad = [pscustomobject]@{ database='relayne_helper_acceptance'; role='relayne_fixture_reader'; customer_id=424242; orders=@($rows[0], $rows[1]) }
Assert-That (-not (Assert-ExpectedRows $bad)) 'Missing row passed.'
$rows[2].status = 'fulfilled'
Assert-That (-not (Assert-ExpectedRows $good)) 'Changed row passed.'

Import-TestFunction 'app-service.ps1' 'Read-BoundedRequest'
function Test-Header([string]$inputText) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $sender = [Net.Sockets.TcpClient]::new()
        try {
            $sender.Connect([Net.IPAddress]::Loopback, $port)
            $receiver = $listener.AcceptTcpClient()
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes($inputText)
                $sender.GetStream().Write($bytes, 0, $bytes.Length)
                return Read-BoundedRequest $receiver
            } finally { $receiver.Dispose() }
        } finally { $sender.Dispose() }
    } finally { $listener.Stop() }
}
$probe = 'a' * 32
$request = Test-Header "GET /check HTTP/1.1`r`nHost: 127.0.0.1`r`nOrigin: http://127.0.0.1:58081`r`nX-Relayne-Probe: $probe`r`n`r`n"
Assert-That ($request.route -ceq '/check' -and $request.origin -ceq 'http://127.0.0.1:58081' -and $request.probe -ceq $probe) 'Valid bounded request rejected.'
Assert-Throws { Test-Header "GET /check HTTP/1.1`r`nOrigin: http://127.0.0.1:58081`r`nOrigin: http://127.0.0.1:58082`r`n`r`n" } 'Duplicate Origin was accepted.'
Assert-Throws { Test-Header "GET /check HTTP/1.1`r`nOrigin:`r`n`r`n" } 'Empty Origin was accepted.'
Assert-Throws { Test-Header ("GET /check HTTP/1.1`r`nX-Pad: " + ('a' * 4100) + "`r`n`r`n") } 'Oversized HTTP header was accepted.'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('relayne-app-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $script:receiptPath = Join-Path $testRoot 'receipt.jsonl'
    $script:receiptCount = 0; $script:receiptBytes = 0
    Import-TestFunction 'app-service.ps1' 'Write-BoundedReceipt'
    Write-BoundedReceipt ([ordered]@{ probe=$probe; status=200 })
    Assert-That ($script:receiptCount -eq 1 -and (Test-Path -LiteralPath $receiptPath)) 'Receipt was not persisted.'
    $script:receiptCount = 512
    Assert-Throws { Write-BoundedReceipt ([ordered]@{ probe=$probe; status=200 }) } 'Record budget was not enforced.'
    $script:receiptCount = 1; $script:receiptBytes = 1048575
    Assert-Throws { Write-BoundedReceipt ([ordered]@{ probe=$probe; status=200 }) } 'Byte budget was not enforced.'
    Assert-That (@(Get-Content -LiteralPath $receiptPath).Count -eq 1) 'Rejected writes changed receipt file.'
    $script:receiptPath = Join-Path $testRoot 'missing\receipt.jsonl'
    $script:receiptBytes = 0
    Assert-Throws { Write-BoundedReceipt ([ordered]@{ probe=$probe; status=200 }) } 'Receipt I/O failure was hidden.'
    Assert-That ($script:receiptCount -eq 1) 'Receipt count advanced after I/O failure.'

    # Exercise the exact stale-config recovery path with owned and foreign files.
    function Get-AppRoot { $testRoot }
    $configDir = Join-Path $testRoot 'app-fixture'
    New-Item -ItemType Directory -Path $configDir | Out-Null
    foreach ($name in @('api.json','portal-a.json','portal-b.json')) { [IO.File]::WriteAllText((Join-Path $configDir $name), '{}') }
    Import-TestFunction 'start-app.ps1' 'Clear-OwnedConfigAfterStop'
    Clear-OwnedConfigAfterStop $configDir
    Assert-That (-not (Test-Path -LiteralPath $configDir)) 'Owned config could not be reused after stop.'
    New-Item -ItemType Directory -Path $configDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $configDir 'api.json'), '{}')
    $activeCommand = '"' + (Get-AppExecutable) + '" ' + (Get-AppCommandLine (Get-AppScript) (Get-AppConfig 'api'))
    function script:Get-CimInstance { [pscustomobject]@{ ExecutablePath=(Get-AppExecutable); CommandLine=$activeCommand } }
    try { Assert-Throws { Clear-OwnedConfigAfterStop $configDir } 'Active owned process was ignored during recovery.' }
    finally { Remove-Item Function:Get-CimInstance }
    Assert-That (Test-Path -LiteralPath (Join-Path $configDir 'api.json')) 'Active process config was removed.'
    Clear-OwnedConfigAfterStop $configDir
    New-Item -ItemType Directory -Path $configDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $configDir 'foreign.txt'), 'preserve')
    Assert-Throws { Clear-OwnedConfigAfterStop $configDir } 'Foreign config content was removed.'
    Assert-That (Test-Path -LiteralPath (Join-Path $configDir 'foreign.txt')) 'Foreign content was not preserved.'

    # A matching body without the fresh challenge receipt must never verify.
    New-Item -ItemType Directory -Path (Join-Path $testRoot 'evidence') | Out-Null
    Import-TestFunction 'verify-app.ps1' 'Assert-FreshReceipt'
    $runId = 'b' * 32; $manifest = [pscustomobject]@{ run_id=$runId }
    Assert-Throws { Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' '' 200 } 'Missing service receipt passed verification.'
    $path = Join-Path $testRoot "evidence\app-$runId-api.jsonl"
    $receipt = [ordered]@{ fixture='guest-local'; run_id=$runId; service='api'; origin=''; route='/orders?customer_id=424242&limit=3'; probe='c'*32; status=200; elapsed_ms=1; observed_order_ids=@(60001,60002,60003); observed_rows=@($rows); db_backed=$true }
    [IO.File]::WriteAllText($path, ($receipt | ConvertTo-Json -Depth 6 -Compress) + "`n")
    Assert-Throws { Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' '' 200 } 'Stale challenge receipt passed verification.'
    $receipt.probe = $probe
    $rows[2].status = 'pending'
    [IO.File]::WriteAllText($path, ($receipt | ConvertTo-Json -Depth 6 -Compress) + "`n")
    Assert-FreshReceipt $manifest 'api' $probe '/orders?customer_id=424242&limit=3' '' 200

    $entry = [pscustomobject]@{ kind='api'; config=(Get-AppConfig 'api'); created_utc=[DateTime]::UtcNow.ToString('o') }
    $fakeProcess = [pscustomobject]@{ ExecutablePath=(Get-AppExecutable); CommandLine=('"' + (Get-AppExecutable) + '" ' + (Get-AppCommandLine (Get-AppScript) $entry.config)); CreationDate=[DateTime]::Parse($entry.created_utc) }
    Assert-That (Test-AppProcess $fakeProcess $entry (Get-AppScript)) 'Exact owned process failed identity check.'
    $fakeProcess.CommandLine += ' -Extra'
    Assert-That (-not (Test-AppProcess $fakeProcess $entry (Get-AppScript))) 'Process with extra arguments passed identity check.'

    # Confirm the exact command-line rule against an actual harmless PS5 child.
    $childScript = Join-Path $testRoot 'idle.ps1'
    [IO.File]::WriteAllText($childScript, 'Start-Sleep -Seconds 10')
    $childConfig = Get-AppConfig 'api'
    $child = Start-Process -FilePath (Get-AppExecutable) -ArgumentList (Get-AppCommandLine $childScript $childConfig) -PassThru -WindowStyle Hidden
    $childEntry = $null
    try {
        $native = Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)"
        Assert-That ([bool]$native) 'Test child exited before command-line capture.'
        $childEntry = [pscustomobject]@{ kind='api'; config=$childConfig; created_utc=$native.CreationDate.ToUniversalTime().ToString('o') }
        Assert-That (Test-AppProcess $native $childEntry $childScript) 'Real PS5 launch did not match the exact command-line identity.'
    } finally {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)" -ErrorAction SilentlyContinue
        if ($current -and $childEntry -and $current.CreationDate.ToUniversalTime().ToString('o') -ceq $childEntry.created_utc) {
            Stop-Process -Id $child.Id -Force
        }
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $temporary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($temporary, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($resolved) -like 'relayne-app-test-*')) { throw 'Test cleanup target escaped the named temp directory.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
$sql = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'app-query.sql') -Raw
Assert-That ($sql.Contains(":'customer_id'::integer") -and $sql.Contains(":'row_limit'::integer") -and $sql.Contains('LIMIT')) 'Typed bounded SQL changed.'
Write-Output 'PASS: PowerShell parsing, guest refusal, synthetic rows, bounded/ambiguous HTTP input, receipt budgets, guarded restart, fresh challenge, and exact process identity.'
