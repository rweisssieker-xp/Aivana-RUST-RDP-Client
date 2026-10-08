[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$bootstrap = Join-Path $PSScriptRoot 'bootstrap.ps1'
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($bootstrap, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "Bootstrap PowerShell parser errors: $($parseErrors -join '; ')" }

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$fixtureDir = Join-Path ([IO.Path]::GetTempPath()) ("relayne-bootstrap-validation-" + [guid]::NewGuid().ToString('N'))
try {
    $runtime = Join-Path $fixtureDir 'runtime'
    foreach ($dir in @('bin', 'lib', 'share')) {
        New-Item -ItemType Directory -Path (Join-Path $runtime $dir) -Force | Out-Null
    }
    foreach ($tool in @('initdb.exe', 'pg_ctl.exe', 'psql.exe', 'createdb.exe')) {
        [IO.File]::WriteAllText((Join-Path $runtime "bin/$tool"), '')
    }
    foreach ($name in @('server.crt', 'server.key', 'root.crt')) {
        [IO.File]::WriteAllText((Join-Path $fixtureDir $name), '')
    }
    $args = @{
        RuntimeSource = $runtime
        TlsCertificate = (Join-Path $fixtureDir 'server.crt')
        TlsPrivateKey = (Join-Path $fixtureDir 'server.key')
        TlsCaCertificate = (Join-Path $fixtureDir 'root.crt')
        ValidateOnly = $true
    }
    $before = @(Get-ChildItem -LiteralPath $fixtureDir -Recurse | Select-Object -ExpandProperty FullName)
    $valid = . $bootstrap @args
    Assert-That ($valid.Valid) "Expected valid prerequisites: $($valid.Errors -join '; ')"
    Assert-That ($valid.Port -eq 55433 -and $valid.Database -eq 'relayne_helper_acceptance' -and $valid.Schema -eq 'fixture') 'Canonical database contract changed.'
    if ($env:USERNAME -ine 'WDAGUtilityAccount') {
        Assert-That (-not $valid.GuestEligible) 'Host validation must report guest eligibility false.'
        $originalUserName = $env:USERNAME
        try {
            $env:USERNAME = 'WDAGUtilityAccount'
            $spoofed = & $bootstrap @args
            Assert-That (-not $spoofed.GuestEligible) 'Caller-controlled USERNAME must not establish guest identity.'
        } finally { $env:USERNAME = $originalUserName }
    }
    $after = @(Get-ChildItem -LiteralPath $fixtureDir -Recurse | Select-Object -ExpandProperty FullName)
    Assert-That ((@($before) -join '|') -ceq (@($after) -join '|')) 'ValidateOnly changed fixture inputs.'

    # Validation and real execution consume the same ordered setup plan and
    # state checks. Exercise them with marker files, without invoking initdb.
    Assert-That (($valid.ClusterSetupSteps -join '|') -ceq 'InitializeCluster|InstallTls') 'Cluster setup must initialize before installing TLS files.'
    $probe = Join-Path $fixtureDir 'setup-probe'
    New-Item -ItemType Directory -Path $probe | Out-Null
    Assert-ClusterSetupState 'InitializeCluster' $probe
    $caught = $false
    try { Assert-ClusterSetupState 'InstallTls' $probe } catch { $caught = $_.Exception.Message -match 'after initdb' }
    Assert-That $caught 'TLS installation was allowed before initdb output.'
    [IO.File]::WriteAllText((Join-Path $probe 'server.crt'), '')
    $caught = $false
    try { Assert-ClusterSetupState 'InitializeCluster' $probe } catch { $caught = $_.Exception.Message -match 'empty data directory' }
    Assert-That $caught 'initdb was allowed on a directory containing TLS files.'
    Remove-Item -LiteralPath (Join-Path $probe 'server.crt')
    [IO.File]::WriteAllText((Join-Path $probe 'PG_VERSION'), '18')
    Assert-ClusterSetupState 'InstallTls' $probe
    [IO.File]::WriteAllText((Join-Path $probe 'server.key'), '')
    $caught = $false
    try { Assert-ClusterSetupState 'InstallTls' $probe } catch { $caught = $_.Exception.Message -match 'Refusing to overwrite' }
    Assert-That $caught 'Existing TLS key was accepted for overwrite.'

    # Invoke the same writers used by the live provision/grant path. Check bytes,
    # including non-ASCII UTF-8, because Windows PowerShell 5.1 otherwise adds BOM.
    $provisionProbe = Join-Path $fixtureDir 'provision.sql'
    $grantProbe = Join-Path $fixtureDir 'grant.sql'
    Write-ProvisionSql $provisionProbe 'owner-é' 'reader-test'
    Write-GrantSql $grantProbe
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    foreach ($sqlPath in @($provisionProbe, $grantProbe)) {
        $bytes = [IO.File]::ReadAllBytes($sqlPath)
        Assert-That ($bytes.Length -gt 3) 'Generated SQL was empty.'
        Assert-That (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) 'Generated SQL contains a UTF-8 BOM.'
        [void]$strictUtf8.GetString($bytes)
    }
    Assert-That ($strictUtf8.GetString([IO.File]::ReadAllBytes($provisionProbe)).Contains('owner-é')) 'Provision SQL lost UTF-8 content.'
    Assert-That ($strictUtf8.GetString([IO.File]::ReadAllBytes($grantProbe)).Contains('GRANT SELECT ON ALL TABLES IN SCHEMA fixture')) 'Grant SQL writer produced wrong content.'

    $stderrProbe = Join-Path $fixtureDir 'native.stderr.log'
    $nativeFailure = ''
    try {
        Invoke-Native $env:ComSpec @('/d', '/c', 'echo SECRET_PROBE 1>&2 & exit /b 7') $stderrProbe
    } catch { $nativeFailure = $_.Exception.Message }
    Assert-That ($nativeFailure -match 'cmd.exe failed with exit code 7') 'Native failure status was not captured.'
    Assert-That ($nativeFailure -match [regex]::Escape($stderrProbe)) 'Native failure omitted diagnostic location.'
    Assert-That (-not $nativeFailure.Contains('SECRET_PROBE')) 'Raw native stderr leaked into failure status.'
    Assert-That ((Get-Content -LiteralPath $stderrProbe -Raw).Contains('SECRET_PROBE')) 'Native stderr was not retained in its diagnostic file.'

    $changed = $args.Clone(); $changed.Port = 55432
    $badPort = & $bootstrap @changed
    Assert-That (-not $badPort.Valid -and ($badPort.Errors -match 'Port must be 55433').Count -eq 1) 'Reference port guard failed.'
    $changed = $args.Clone(); $changed.Database = 'postgres'
    $badDatabase = & $bootstrap @changed
    Assert-That (-not $badDatabase.Valid -and ($badDatabase.Errors -match 'Database must be').Count -eq 1) 'Database guard failed.'
    $changed = $args.Clone(); $changed.Schema = 'public'
    $badSchema = & $bootstrap @changed
    Assert-That (-not $badSchema.Valid -and ($badSchema.Errors -match 'Schema must be').Count -eq 1) 'Schema guard failed.'
    $changed = $args.Clone(); $changed.Root = 'C:\RelayneSqlLab'
    $badRoot = & $bootstrap @changed
    Assert-That (-not $badRoot.Valid -and ($badRoot.Errors -match 'Root must be').Count -eq 1) 'Root guard failed.'
    $changed = $args.Clone(); $changed.RuntimeSource = Join-Path $fixtureDir 'missing'
    $badRuntime = & $bootstrap @changed
    Assert-That (-not $badRuntime.Valid -and $badRuntime.Errors.Count -ge 4) 'Runtime path guard failed.'
    $changed = $args.Clone(); $changed.TlsCaCertificate = Join-Path $fixtureDir 'missing-ca.crt'
    $badCa = & $bootstrap @changed
    Assert-That (-not $badCa.Valid -and ($badCa.Errors -match 'TLS CA certificate').Count -eq 1) 'TLS CA guard failed.'
    $changed = $args.Clone(); $changed.TlsPrivateKey = 'C:\RelayneHelperAcceptance\server.key'
    $insideRoot = & $bootstrap @changed
    Assert-That (-not $insideRoot.Valid -and ($insideRoot.Errors -match 'Inputs must live outside').Count -eq 1) 'Input path isolation guard failed.'
    if (-not $valid.GuestEligible) {
        $hostRejected = $false
        $executeArgs = $args.Clone()
        [void]$executeArgs.Remove('ValidateOnly')
        try { & $bootstrap @executeArgs | Out-Null } catch { $hostRejected = $_.Exception.Message -match 'requires Windows Sandbox' }
        Assert-That $hostRejected 'Host execution was not rejected.'
    }
    Write-Output 'PASS: parser, validation-only side effects, guest refusal, path/port/database/schema/TLS guards, cluster order, BOMless SQL, native stderr containment.'
} finally {
    Remove-Item -LiteralPath $fixtureDir -Recurse -Force -ErrorAction SilentlyContinue
}
