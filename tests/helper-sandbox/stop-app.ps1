[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'app-contract.ps1')

$root = Get-AppRoot
$manifestPath = Join-Path $root 'app-fixture\processes.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Exact app fixture manifest is missing.' }
Assert-AppGuest
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-AppManifest $manifest
$children = @(Get-ChildItem -LiteralPath (Join-Path $root 'app-fixture') -Force | ForEach-Object { $_.Name } | Sort-Object)
if (($children -join ',') -cne 'api.json,portal-a.json,portal-b.json,processes.json') {
    throw 'Unowned app config content prevents teardown.'
}
$toStop = @()
foreach ($entry in $manifest.processes) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.pid)" -ErrorAction SilentlyContinue
    if (-not $process) { continue }
    if (-not (Test-AppProcess $process $entry $manifest.script)) {
        throw "PID $($entry.pid) no longer matches the fixture process; refusing teardown."
    }
    $toStop += $entry.pid
}
foreach ($entry in $manifest.processes) {
    if ($entry.pid -notin $toStop) { continue }
    $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.pid)" -ErrorAction SilentlyContinue
    if (-not (Test-AppProcess $current $entry $manifest.script)) { throw "Fixture PID $($entry.pid) changed before stop." }
    Stop-Process -Id $entry.pid -Force
}
foreach ($entry in $manifest.processes) {
    if (Get-Process -Id $entry.pid -ErrorAction SilentlyContinue) { throw "Fixture PID $($entry.pid) did not stop." }
}
foreach ($entry in $manifest.processes) {
    $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'), [int]$entry.port)
    try { $probe.Start() } catch { throw "Port $($entry.port) remains occupied; preserving fixture config." } finally { $probe.Stop() }
}
Remove-Item -LiteralPath $manifestPath
foreach ($entry in $manifest.processes) { Remove-Item -LiteralPath $entry.config }
Remove-Item -LiteralPath (Join-Path $root 'app-fixture')
[pscustomobject]@{ Stopped = @($toStop); PreservedDatabase='relayne_helper_acceptance'; PreservedReference='C:\RelayneSqlLab'; PreservedEvidence=(Join-Path $root 'evidence') }
