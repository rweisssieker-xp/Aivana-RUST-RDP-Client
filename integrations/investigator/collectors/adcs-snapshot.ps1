# Bundled read-only ADSI and CA policy inventory. Rust supplies validated LDAP and CA
# hosts plus an exact CA name. No script text, filter, command, or URL comes from RPC.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$server = $env:AIVANA_ADCS_LDAP_SERVER
if ($server -notmatch '^[A-Za-z0-9.-]{1,253}$') { throw 'Invalid LDAP server' }
$caHost = $env:AIVANA_ADCS_CA_HOST
if ($caHost -notmatch '^[A-Za-z0-9.-]{1,253}$') { throw 'Invalid CA host' }
$configuredCa = $env:AIVANA_ADCS_CA_NAME
if ($configuredCa -and ($configuredCa.Length -gt 128 -or $configuredCa -notmatch '^[A-Za-z0-9 _.-]+$')) { throw 'Invalid CA name' }
$auth = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::Signing -bor [System.DirectoryServices.AuthenticationTypes]::Sealing
$root = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$server/RootDSE", $null, $null, $auth)
try { $config = [string]$root.Properties['configurationNamingContext'].Value }
finally { $root.Dispose() }
if ([string]::IsNullOrWhiteSpace($config)) { throw 'Configuration naming context missing' }
$base = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$server/CN=Public Key Services,CN=Services,$config", $null, $null, $auth)
try {

function Search-Objects([string]$filter, [string[]]$properties, [bool]$includeDacl) {
    $search = New-Object System.DirectoryServices.DirectorySearcher($base)
    try {
        $search.Filter = $filter
        $search.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $search.PageSize = 100
        $search.SizeLimit = 100
        $search.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        if ($includeDacl) { $search.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl }
        foreach ($property in $properties) { [void]$search.PropertiesToLoad.Add($property) }
        $results = $null
        $results = $search.FindAll()
        try {
            # Exactly 100 may mean the provider silently truncated a larger result set.
            # Reject before per-CA filtering, which could otherwise hide the limit.
            if ($results.Count -ge 100) { throw 'AD CS LDAP result limit reached; inventory incomplete' }
            $items = @($results)
        } finally { if ($null -ne $results) { $results.Dispose() } }
        return $items
    } finally { $search.Dispose() }
}
function First($item, [string]$key) {
    if ($item.Properties.Contains($key) -and $item.Properties[$key].Count -gt 0) {
        return $item.Properties[$key][0]
    }
    return $null
}
function Integer($item, [string]$key) {
    $value = First $item $key
    if ($null -eq $value) { return $null }
    return [int64]$value
}
function Low-PrivilegeEnroll($security) {
    # Enroll extended right. Explicit denies for these principals suppress a positive result.
    $enroll = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $sids = @('S-1-1-0','S-1-5-11')
    $allow = $false; $deny = $false
    $rules = $security.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($sids -notcontains $rule.IdentityReference.Value) { continue }
        $rights = $rule.ActiveDirectoryRights
        $isEnroll = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0 -and ($rule.ObjectType -eq $enroll -or $rule.ObjectType -eq [Guid]::Empty)) -or (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0)
        if (-not $isEnroll) { continue }
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) { $deny = $true }
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) { $allow = $true }
    }
    if ($allow -and -not $deny) { return $true }
    # Domain-specific low privilege groups were not expanded; never claim exclusion.
    return $null
}

$templates = Search-Objects '(objectClass=pKICertificateTemplate)' @('cn','distinguishedName','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature','pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','ntSecurityDescriptor') $true
$cas = Search-Objects '(objectClass=pKIEnrollmentService)' @('cn','distinguishedName','certificateTemplates','dNSHostName') $false
$out = New-Object System.Collections.ArrayList
foreach ($ca in $cas) {
    $caDn = [string](First $ca 'distinguishedname')
    $caName = [string](First $ca 'cn')
    $publishedHost = [string](First $ca 'dnshostname')
    if ($publishedHost -ine $caHost -or ($configuredCa -and $caName -cne $configuredCa)) { continue }
    if ([string]::IsNullOrWhiteSpace($caDn) -or [string]::IsNullOrWhiteSpace($caName)) { continue }
        # Fixed native Remote Registry read on the approved CA host. CertSrv.h defines
        # REQDISP_PENDING=0, ISSUE=1, DENY=2, USEREQUESTATTRIBUTE=3,
        # PENDINGFIRST=0x100. Only exact 0, 1, and 0x101 are normalized.
        $requiresApproval = $null
        $policyStatus = 'unavailable'
        $rawDisposition = $null
        $activeModule = $null
        if ($configuredCa) {
            try {
                $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $caHost)
                try {
                    $modules = $hklm.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$configuredCa\PolicyModules", $false)
                    if ($null -ne $modules) {
                        try {
                            $active = $modules.GetValue('Active', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                            if ($active -is [string]) { $activeModule = $active }
                            if ($active -is [string] -and $active -ieq 'CertificateAuthority_MicrosoftDefault.Policy') {
                                $key = $modules.OpenSubKey('CertificateAuthority_MicrosoftDefault.Policy', $false)
                                if ($null -ne $key) {
                                    try {
                                        $raw = $key.GetValue('RequestDisposition', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                        if ($raw -is [int]) { $rawDisposition = $raw }
                                        if ($raw -is [int] -and $raw -eq 1) { $requiresApproval = $false; $policyStatus = 'native_registry' }
                                        elseif ($raw -is [int] -and ($raw -eq 0 -or $raw -eq 257)) { $requiresApproval = $true; $policyStatus = 'native_registry' }
                                        else { $policyStatus = 'unsupported_policy_value' }
                                    } finally { $key.Close() }
                                }
                            } else { $policyStatus = 'custom_or_unknown_policy_module' }
                        } finally { $modules.Close() }
                    }
                } finally { $hklm.Close() }
            } catch { $policyStatus = 'unavailable' }
        }
    $published = @($ca.Properties['certificatetemplates'])
    foreach ($template in $templates) {
        $name = [string](First $template 'cn')
        $dn = [string](First $template 'distinguishedname')
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($dn) -or $published -notcontains $name) { continue }
        $nameFlags = Integer $template 'mspki-certificate-name-flag'
        $enrollmentFlags = Integer $template 'mspki-enrollment-flag'
        $signatures = Integer $template 'mspki-ra-signature'
        $oids = @($template.Properties['pkiextendedkeyusage']) + @($template.Properties['mspki-certificate-application-policy'])
        $lowPrivilegeEnroll = $null
        $aclStatus = 'unavailable'
        try {
            $aclBytes = [byte[]](First $template 'ntsecuritydescriptor')
            if ($aclBytes.Length -eq 0) { throw 'Template DACL unavailable' }
            $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $security.SetSecurityDescriptorBinaryForm($aclBytes)
            $lowPrivilegeEnroll = Low-PrivilegeEnroll $security
            $aclStatus = 'bounded_principals_only'
        } catch { $aclStatus = 'unavailable' }
        $baseId = "$caDn|$dn"
        [void]$out.Add(@{ kind='certificate_template'; native_id="$baseId|template"; ca=$caDn; template=$dn; ca_name=$caName; ca_dns_host=$publishedHost; template_name=$name; enrollee_supplies_subject= $(if ($null -ne $nameFlags) { ($nameFlags -band 1) -ne 0 } else { $null }); client_authentication= $(if ($oids.Count -gt 0) { $oids -contains '1.3.6.1.5.5.7.3.2' } else { $null }); manager_approval_required= $(if ($null -ne $enrollmentFlags) { ($enrollmentFlags -band 2) -ne 0 } else { $null }); authorized_signatures_required=$signatures })
        [void]$out.Add(@{ kind='template_acl'; native_id="$baseId|acl"; ca=$caDn; template=$dn; ca_name=$caName; ca_dns_host=$publishedHost; low_privileged_enroll=$lowPrivilegeEnroll; acl_status=$aclStatus; acl_scope='Everyone and Authenticated Users only; domain-specific groups are not assessed' })
        [void]$out.Add(@{ kind='ca_settings'; native_id="$baseId|ca"; ca=$caDn; template=$dn; ca_name=$caName; ca_dns_host=$publishedHost; active_policy_module=$activeModule; request_disposition=$rawDisposition; issuance_requires_approval=$requiresApproval; ca_policy_status=$policyStatus })
    }
}
ConvertTo-Json -InputObject @($out.ToArray()) -Depth 6 -Compress
} finally { $base.Dispose() }
