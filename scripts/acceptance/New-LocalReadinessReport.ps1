#requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$BinaryDirectory,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$Fixture
)
. (Join-Path $PSScriptRoot 'Acceptance.Common.ps1')
$output=[IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $output) { throw 'Report output must be a new file; existing evidence is never overwritten.' }
$report=New-LocalAcceptanceReport $BinaryDirectory ([bool]$Fixture)
$json=$report | ConvertTo-Json -Depth 8
$stream=[IO.File]::Open($output,'CreateNew','Write','None')
try {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream.Write($bytes,0,$bytes.Length)
} finally { $stream.Dispose() }
Write-Output "Local readiness report created: $output. All live scenarios are NOT RUN; this report does not establish sale readiness."
