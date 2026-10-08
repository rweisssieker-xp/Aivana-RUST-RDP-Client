[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-That([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
foreach ($name in @('start-app.ps1','stop-app.ps1','app-service.ps1','verify-app.ps1')) {
    $path = Join-Path $PSScriptRoot $name
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-That ($errors.Count -eq 0) "$name parser errors: $($errors -join '; ')"
}
$start = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'start-app.ps1') -Raw
$stop = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'stop-app.ps1') -Raw
$service = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'app-service.ps1') -Raw
$sql = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'app-query.sql') -Raw
$serviceAst = [Management.Automation.Language.Parser]::ParseInput($service, [ref]$null, [ref]$null)
$rowAssertion = @($serviceAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-ExpectedRows' }, $true))
Assert-That ($rowAssertion.Count -eq 1) 'Expected row assertion function missing.'
. ([scriptblock]::Create($rowAssertion[0].Extent.Text))
$rows = @(1..3 | ForEach-Object { [pscustomobject]@{ order_id=(60000 + $_); customer_id=424242; status='pending'; amount=99.99 } })
$good = [pscustomobject]@{ database='relayne_helper_acceptance'; role='relayne_fixture_reader'; customer_id=424242; orders=$rows }
Assert-That (Assert-ExpectedRows $good) 'Reviewed synthetic rows were rejected.'
$bad = [pscustomobject]@{ database='relayne_helper_acceptance'; role='relayne_fixture_reader'; customer_id=424242; orders=@($rows[0], $rows[1]) }
Assert-That (-not (Assert-ExpectedRows $bad)) 'Missing third row passed verification.'
$rows[2].status = 'fulfilled'
Assert-That (-not (Assert-ExpectedRows $good)) 'Changed database content passed verification.'

$valid = & (Join-Path $PSScriptRoot 'start-app.ps1') -ValidateOnly
Assert-That ($valid.Root -ceq 'C:\RelayneHelperAcceptance' -and $valid.Database -ceq 'relayne_helper_acceptance') 'Dedicated root/database contract changed.'
Assert-That ($valid.PgPort -eq 55433 -and $valid.ApiPort -eq 58080 -and $valid.PortalAPort -eq 58081 -and $valid.PortalBPort -eq 58082) 'Dedicated port contract changed.'
if ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1] -ine 'WDAGUtilityAccount') {
    Assert-That (-not $valid.GuestEligible) 'Host must not appear guest eligible.'
    $denied = $false
    try { & (Join-Path $PSScriptRoot 'start-app.ps1') | Out-Null } catch { $denied = $_.Exception.Message -match 'Windows Sandbox guest identity' }
    Assert-That $denied 'Host execution did not fail closed.'
}
Assert-That ($start.Contains('Assert-PortsFree') -and $start.Contains('query_sha256') -and $start.Contains('service_sha256')) 'Startup guard or source hash missing.'
Assert-That ($stop.Contains('CommandLine.Contains($manifest.script)') -and $stop.Contains('CommandLine.Contains($entry.config)')) 'Teardown process identity guard missing.'
Assert-That ($service.Contains('PGSSLMODE') -and $service.Contains('verify-full') -and $service.Contains('PGSSLROOTCERT')) 'Verified TLS settings missing.'
Assert-That ($service.Contains('Access-Control-Allow-Origin') -and $service.Contains('http://127.0.0.1:58081') -and $service.Contains('http://127.0.0.1:58082')) 'Exact CORS origins missing.'
Assert-That ($service.Contains('Invoke-DatabaseQuery') -and $service.Contains('Invoke-ApiFromPortal')) 'Database or API-backed portal path missing.'
Assert-That ($sql.Contains(":'customer_id'::integer") -and $sql.Contains(":'row_limit'::integer") -and $sql.Contains('LIMIT')) 'Bounded typed query missing.'
Assert-That (-not $sql.Contains('pg_sleep') -and -not $sql.Contains('SELECT *')) 'Query may be unbounded.'
Write-Output 'PASS: app scripts parse; host start refused; dedicated target, exact CORS, verified TLS, typed bounded query, and exact process teardown guards present.'
