[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $ConfigPath).Path
$config = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
$references = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

function Add-EnvReference([string] $Name, [switch] $Required) {
    if ([string]::IsNullOrWhiteSpace($Name)) {
        if ($Required) { throw 'An enabled component is missing its environment variable reference name.' }
        return
    }
    if ($Name.Length -gt 128 -or $Name -cnotmatch '^[A-Z0-9_]+$') {
        throw "Invalid environment variable reference name in configuration: $Name"
    }
    [void] $references.Add($Name)
}

foreach ($user in @($config.users)) {
    Add-EnvReference ([string] $user.token_env) -Required
}

if ($config.sources.enabled) {
    Add-EnvReference ([string] $config.sources.secret_env) -Required
}

Add-EnvReference ([string] $config.operations.notification_webhook_env)
Add-EnvReference ([string] $config.operations.notification_backup_webhook_env)

if ($config.collectors.enabled) {
    foreach ($name in @('entra_token', 'defender_process')) {
        $source = $config.collectors.$name
        if ($source.enabled) { Add-EnvReference ([string] $source.secret_env) -Required }
    }

    foreach ($name in @('log_analytics_storage', 'log_analytics_network')) {
        $source = $config.collectors.$name
        if ($source.enabled) { Add-EnvReference ([string] $source.secret_env) -Required }
    }

    foreach ($instance in @($config.collectors.instances)) {
        switch ([string] $instance.source) {
            { $_ -in @('entra_token', 'defender_process') } {
                if ($instance.cloud.enabled) { Add-EnvReference ([string] $instance.cloud.secret_env) -Required }
            }
            { $_ -in @('log_analytics_storage', 'log_analytics_network') } {
                if ($instance.analytics.enabled) { Add-EnvReference ([string] $instance.analytics.secret_env) -Required }
            }
        }
    }
}

if ($config.response.enabled) {
    Add-EnvReference ([string] $config.response.graph_secret_env) -Required
}

if ($references.Count -eq 0) {
    Write-Output 'No environment variable references configured.'
    exit 1
}

foreach ($name in ($references | Sort-Object)) {
    Write-Output "$name : configured reference (value not inspected)"
}
Write-Output 'Reference names passed syntax validation. This checklist does not inspect environment values, credential validity, permissions, or source connectivity.'
