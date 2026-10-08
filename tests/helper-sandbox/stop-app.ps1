[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = 'C:\RelayneHelperAcceptance'
$manifestPath = Join-Path $root 'app-fixture\processes.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Exact app fixture manifest is missing.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$system = Get-CimInstance Win32_ComputerSystem
if ($identity.Name.Split('\')[-1] -ine 'WDAGUtilityAccount' -or
    "$($system.Manufacturer) $($system.Model)" -notmatch '(?i)Microsoft Corporation.*Virtual Machine|Windows Sandbox') {
    throw 'App fixture stop requires Windows Sandbox guest identity.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.fixture -cne 'guest-local' -or $manifest.root -cne $root -or
    @($manifest.processes).Count -ne 3 -or
    (@($manifest.processes | ForEach-Object { $_.port }) -join ',') -cne '58080,58081,58082') {
    throw 'App fixture manifest contract changed.'
}
$powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$toStop = @()
foreach ($entry in $manifest.processes) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.pid)" -ErrorAction SilentlyContinue
    if (-not $process) { continue }
    if ($process.ExecutablePath -ine $powershell -or
        -not $process.CommandLine.Contains($manifest.script) -or
        -not $process.CommandLine.Contains($entry.config)) {
        throw "PID $($entry.pid) no longer matches the fixture process; refusing teardown."
    }
    $toStop += $entry.pid
}
foreach ($pidValue in $toStop) { Stop-Process -Id $pidValue -Force }
foreach ($entry in $manifest.processes) {
    if (Get-Process -Id $entry.pid -ErrorAction SilentlyContinue) { throw "Fixture PID $($entry.pid) did not stop." }
}
Remove-Item -LiteralPath $manifestPath
[pscustomobject]@{ Stopped = @($toStop); PreservedDatabase='relayne_helper_acceptance'; PreservedReference='C:\RelayneSqlLab'; PreservedEvidence=(Join-Path $root 'evidence') }
