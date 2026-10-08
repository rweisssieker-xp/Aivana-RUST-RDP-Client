<#[
.SYNOPSIS
Creates the disposable PostgreSQL fixture inside Windows Sandbox only.
.DESCRIPTION
Validation mode reads prerequisites and returns a result object without creating files,
opening database connections, or starting processes. The execution path refuses an
existing root and requires both WDAGUtilityAccount and virtual-machine CIM evidence.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RuntimeSource,
    [Parameter(Mandatory = $true)][string]$TlsCertificate,
    [Parameter(Mandatory = $true)][string]$TlsPrivateKey,
    [Parameter(Mandatory = $true)][string]$TlsCaCertificate,
    [string]$Root = 'C:\RelayneHelperAcceptance',
    [int]$Port = 55433,
    [string]$Database = 'relayne_helper_acceptance',
    [string]$Schema = 'fixture',
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SandboxGuest {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $false }
    try {
        $account = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($account.Name.Split('\')[-1] -ine 'WDAGUtilityAccount') { return $false }
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $identity = "$($computer.Manufacturer) $($computer.Model)"
        return $identity -match '(?i)Microsoft Corporation.*Virtual Machine|Windows Sandbox'
    } catch { return $false }
}

function Get-ClusterSetupPlan {
    @('InitializeCluster', 'InstallTls')
}

function Assert-ClusterSetupState([string]$Step, [string]$DataDirectory) {
    switch ($Step) {
        'InitializeCluster' {
            if (-not (Test-Path -LiteralPath $DataDirectory -PathType Container)) { throw 'Cluster data directory is missing.' }
            if (Get-ChildItem -LiteralPath $DataDirectory -Force | Select-Object -First 1) {
                throw 'initdb requires an empty data directory.'
            }
        }
        'InstallTls' {
            if (-not (Test-Path -LiteralPath (Join-Path $DataDirectory 'PG_VERSION') -PathType Leaf)) {
                throw 'TLS files can be installed only after initdb creates PG_VERSION.'
            }
            foreach ($name in @('server.crt', 'server.key')) {
                if (Test-Path -LiteralPath (Join-Path $DataDirectory $name)) { throw "Refusing to overwrite $name." }
            }
        }
        default { throw "Unknown cluster setup step: $Step" }
    }
}

function Get-Validation {
    $errors = [System.Collections.Generic.List[string]]::new()
    $expectedRoot = 'C:\RelayneHelperAcceptance'
    if ($Root -ine $expectedRoot) { $errors.Add("Root must be $expectedRoot.") }
    if ($Port -ne 55433) { $errors.Add('Port must be 55433.') }
    if ($Database -cne 'relayne_helper_acceptance') { $errors.Add('Database must be relayne_helper_acceptance.') }
    if ($Schema -cne 'fixture') { $errors.Add('Schema must be fixture.') }
    if (Test-Path -LiteralPath $expectedRoot) { $errors.Add('Guest root already exists; refusing to overwrite it.') }
    foreach ($item in @(
        @{ Name = 'runtime bin'; Path = (Join-Path $RuntimeSource 'bin'); Type = 'Container' },
        @{ Name = 'runtime lib'; Path = (Join-Path $RuntimeSource 'lib'); Type = 'Container' },
        @{ Name = 'runtime share'; Path = (Join-Path $RuntimeSource 'share'); Type = 'Container' },
        @{ Name = 'initdb'; Path = (Join-Path $RuntimeSource 'bin/initdb.exe'); Type = 'Leaf' },
        @{ Name = 'pg_ctl'; Path = (Join-Path $RuntimeSource 'bin/pg_ctl.exe'); Type = 'Leaf' },
        @{ Name = 'psql'; Path = (Join-Path $RuntimeSource 'bin/psql.exe'); Type = 'Leaf' },
        @{ Name = 'createdb'; Path = (Join-Path $RuntimeSource 'bin/createdb.exe'); Type = 'Leaf' },
        @{ Name = 'TLS certificate'; Path = $TlsCertificate; Type = 'Leaf' },
        @{ Name = 'TLS private key'; Path = $TlsPrivateKey; Type = 'Leaf' },
        @{ Name = 'TLS CA certificate'; Path = $TlsCaCertificate; Type = 'Leaf' }
    )) {
        if (-not (Test-Path -LiteralPath $item.Path -PathType $item.Type)) { $errors.Add("Missing $($item.Name): $($item.Path)") }
    }
    $seed = Join-Path $PSScriptRoot 'seed.sql'
    if (-not (Test-Path -LiteralPath $seed -PathType Leaf)) { $errors.Add("Missing fixture seed: $seed") }
    foreach ($source in @($RuntimeSource, $TlsCertificate, $TlsPrivateKey, $TlsCaCertificate)) {
        if (-not [IO.Path]::IsPathRooted($source)) {
            $errors.Add("Input path must be absolute: $source")
            continue
        }
        try {
            $absolute = [IO.Path]::GetFullPath($source).TrimEnd('\')
            if ($absolute -ieq $expectedRoot -or $absolute.StartsWith("$expectedRoot\", [StringComparison]::OrdinalIgnoreCase)) {
                $errors.Add('Inputs must live outside the new guest root.')
            }
        } catch { $errors.Add("Invalid input path: $source") }
    }
    [pscustomobject]@{
        Valid = $errors.Count -eq 0
        GuestEligible = [bool](Test-SandboxGuest)
        Root = $expectedRoot
        Port = 55433
        Database = 'relayne_helper_acceptance'
        Schema = 'fixture'
        ClusterSetupSteps = @(Get-ClusterSetupPlan)
        Errors = @($errors)
    }
}

function New-Secret {
    $bytes = [byte[]]::new(36)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($Executable)) failed with exit code $LASTEXITCODE." }
}

$validation = Get-Validation
if ($ValidateOnly) { Write-Output $validation; return }
if (-not $validation.GuestEligible) { throw 'Bootstrap requires Windows Sandbox: WDAGUtilityAccount and Windows virtual-machine identity.' }
if (-not $validation.Valid) { throw ($validation.Errors -join ' ') }

$rootPath = $validation.Root
$pgPath = Join-Path $rootPath 'pgsql'
$binPath = Join-Path $pgPath 'bin'
$dataPath = Join-Path $pgPath 'data'
$logsPath = Join-Path $pgPath 'logs'
$secretPath = Join-Path $rootPath 'credentials.txt'
$adminPassword = New-Secret
$ownerPassword = New-Secret
$readerPassword = New-Secret

# The new root is a one-shot fixture. Never remove it on failure: an operator can
# inspect the partial guest state, then discard the entire Sandbox instance.
New-Item -ItemType Directory -Path $rootPath -ErrorAction Stop | Out-Null
# Files holding passwords are guest-local and limited to the Sandbox account.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity.User, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath $rootPath -AclObject $acl
foreach ($dir in @($pgPath, $dataPath, $logsPath, (Join-Path $rootPath 'app-data'), (Join-Path $rootPath 'evidence'))) {
    New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
}
foreach ($part in @('bin', 'lib', 'share')) {
    Copy-Item -LiteralPath (Join-Path $RuntimeSource $part) -Destination $pgPath -Recurse -ErrorAction Stop
}
Copy-Item -LiteralPath $TlsCaCertificate -Destination (Join-Path $rootPath 'root.crt') -ErrorAction Stop
foreach ($step in Get-ClusterSetupPlan) {
    Assert-ClusterSetupState $step $dataPath
    switch ($step) {
        'InitializeCluster' {
            $passwordFile = Join-Path $rootPath 'initdb-password.txt'
            [IO.File]::WriteAllText($passwordFile, "$adminPassword`n", [Text.Encoding]::ASCII)
            try {
                Invoke-Native (Join-Path $binPath 'initdb.exe') @('-D', $dataPath, '-U', 'relayne_fixture_admin', '--encoding=UTF8', '--auth-host=scram-sha-256', '--auth-local=scram-sha-256', "--pwfile=$passwordFile")
            } finally {
                Remove-Item -LiteralPath $passwordFile -ErrorAction SilentlyContinue
            }
        }
        'InstallTls' {
            Copy-Item -LiteralPath $TlsCertificate -Destination (Join-Path $dataPath 'server.crt') -ErrorAction Stop
            Copy-Item -LiteralPath $TlsPrivateKey -Destination (Join-Path $dataPath 'server.key') -ErrorAction Stop
        }
    }
}

Add-Content -LiteralPath (Join-Path $dataPath 'postgresql.conf') -Value @"

# Disposable Relayne Helper acceptance cluster; guest loopback only.
port = 55433
listen_addresses = '127.0.0.1'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
password_encryption = 'scram-sha-256'
log_min_duration_statement = 250
logging_collector = on
log_directory = '../logs'
"@
Set-Content -LiteralPath (Join-Path $dataPath 'pg_hba.conf') -Encoding ascii -Value @'
local all all scram-sha-256
hostssl all all 127.0.0.1/32 scram-sha-256
hostssl all all ::1/128 reject
hostnossl all all 0.0.0.0/0 reject
hostnossl all all ::/0 reject
'@

Invoke-Native (Join-Path $binPath 'pg_ctl.exe') @('-D', $dataPath, '-l', (Join-Path $logsPath 'startup.log'), '-w', 'start')
$env:PGPASSWORD = $adminPassword
$env:PGUSER = 'relayne_fixture_admin'
$env:PGHOST = '127.0.0.1'
$env:PGPORT = '55433'
$env:PGSSLMODE = 'verify-full'
$env:PGSSLROOTCERT = Join-Path $rootPath 'root.crt'
# The supplied certificate must cover 127.0.0.1; no trust-mode fallback is used.
try {
    $provisionFile = Join-Path $rootPath 'provision.sql'
    $sql = @"
CREATE ROLE relayne_fixture_owner LOGIN PASSWORD '$ownerPassword';
CREATE ROLE relayne_fixture_reader LOGIN PASSWORD '$readerPassword';
CREATE DATABASE relayne_helper_acceptance OWNER relayne_fixture_owner;
"@
    [IO.File]::WriteAllText($provisionFile, $sql, [Text.Encoding]::UTF8)
    Invoke-Native (Join-Path $binPath 'psql.exe') @('-X', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres', '-f', $provisionFile)
    Remove-Item -LiteralPath $provisionFile
    $env:PGPASSWORD = $ownerPassword
    Invoke-Native (Join-Path $binPath 'psql.exe') @('-X', '-v', 'ON_ERROR_STOP=1', '-U', 'relayne_fixture_owner', '-d', $Database, '-f', (Join-Path $PSScriptRoot 'seed.sql'))
    $env:PGPASSWORD = $adminPassword
    $grantFile = Join-Path $rootPath 'grant.sql'
    [IO.File]::WriteAllText($grantFile, @'
GRANT CONNECT ON DATABASE relayne_helper_acceptance TO relayne_fixture_reader;
GRANT USAGE ON SCHEMA fixture TO relayne_fixture_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA fixture TO relayne_fixture_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE relayne_fixture_owner IN SCHEMA fixture GRANT SELECT ON TABLES TO relayne_fixture_reader;
'@, [Text.Encoding]::UTF8)
    Invoke-Native (Join-Path $binPath 'psql.exe') @('-X', '-v', 'ON_ERROR_STOP=1', '-d', $Database, '-f', $grantFile)
    Remove-Item -LiteralPath $grantFile
    [IO.File]::WriteAllText($secretPath, "admin=$adminPassword`nowner=$ownerPassword`nreader=$readerPassword`n", [Text.Encoding]::ASCII)
} finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:PGUSER -ErrorAction SilentlyContinue
    Remove-Item Env:PGHOST -ErrorAction SilentlyContinue
    Remove-Item Env:PGPORT -ErrorAction SilentlyContinue
    Remove-Item Env:PGSSLMODE -ErrorAction SilentlyContinue
    Remove-Item Env:PGSSLROOTCERT -ErrorAction SilentlyContinue
}
Write-Output "Guest fixture ready at $rootPath. Credentials: $secretPath"
