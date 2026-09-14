#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-LocalAcceptanceCapabilities {
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
    $rdpControl = $false; $winrm = $false; $hyperv = $false
    if ($isWindowsHost) {
        $rdpControl = Test-Path -LiteralPath 'Registry::HKEY_CLASSES_ROOT\MsRdpClient11NotSafeForScripting'
        $winrm = $null -ne (Get-Service -Name WinRM -ErrorAction SilentlyContinue)
        $hyperv = $null -ne (Get-Service -Name vmms -ErrorAction SilentlyContinue)
    }
    [ordered]@{
        windows=$isWindowsHost
        rdp_control_registered=[bool]$rdpControl
        winrm_service_installed=[bool]$winrm
        hyperv_management_service_installed=[bool]$hyperv
        openssh_command_available=[bool](Get-Command ssh.exe -ErrorAction SilentlyContinue)
        note='Local presence only. No component was activated, no service was started, and no remote host was contacted.'
    }
}
function New-LocalAcceptanceReport([string]$BinaryDirectory, [bool]$Fixture) {
    $directory = [IO.Path]::GetFullPath($BinaryDirectory)
    $binaries = foreach ($name in @('relayne.exe','relayne_team.exe')) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item=Get-Item -LiteralPath $path
            $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($path)
            [ordered]@{name=$name;present=$true;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;file_version=$version.FileVersion;product_version=$version.ProductVersion;size=$item.Length}
        } else { [ordered]@{name=$name;present=$false;sha256=$null;file_version=$null;product_version=$null;size=$null} }
    }
    $scenarios = foreach ($name in @('RDP direct connection','RD Gateway','MFA and conditional access','RemoteApp','WinRM execution','Hyper-V recovery clone','Multiple monitors','Jira ticket delivery','Stripe billing and entitlement')) {
        [ordered]@{scenario=$name;status='NOT RUN';evidence=$null;reason='Requires separately authorized live scenario evidence for this exact build and environment.'}
    }
    [ordered]@{
        schema='relayne-local-readiness-v1'
        generated_utc=[DateTime]::UtcNow.ToString('o')
        report_kind=$(if ($Fixture) {'fixture-local-readiness'} else {'local-readiness'})
        sale_ready=$false
        live_acceptance_complete=$false
        host_scope=[ordered]@{kind='local-machine-only';computer_name=[Environment]::MachineName;os=[Runtime.InteropServices.RuntimeInformation]::OSDescription;os_architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();process_architecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()}
        binaries=@($binaries)
        capabilities=(Get-LocalAcceptanceCapabilities)
        live_scenarios=@($scenarios)
        limitations=@('File version metadata is descriptive and may be missing; SHA-256 identifies exact file content.','Local tool presence is not protocol, policy, credential, license or connectivity validation.','No imported evidence can promote a scenario to PASS in this report.','Publisher authenticity must be checked separately using production package verification.')
    }
}
