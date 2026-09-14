#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Package.Common.ps1')

function Assert-PublisherSignature([string]$Path, [string]$PublisherThumbprint) {
    if ($PublisherThumbprint -cnotmatch '^[A-Fa-f0-9]{40}$') { throw 'Configure a publisher certificate SHA-1 thumbprint (40 hexadecimal characters).' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ine $PublisherThumbprint) {
        throw "Publisher signature verification failed: $Path"
    }
}

function Assert-JsonUniqueKeys($Element) {
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (!$names.Add($property.Name)) { throw 'Duplicate manifest property.' }
            Assert-JsonUniqueKeys $property.Value
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) { Assert-JsonUniqueKeys $item }
    }
}

function Assert-ManifestKeys($Object, [string[]]$Expected) {
    if ($Object -isnot [Collections.IDictionary] -or $Object.Count -ne $Expected.Count) { throw 'Invalid manifest properties.' }
    foreach ($key in $Object.Keys) { if ($key -cnotin $Expected) { throw 'Unknown manifest property.' } }
}

function Read-ProductionManifest([string]$Path, [string]$PublisherThumbprint) {
    $Path = Assert-PlainPath $Path
    if ((Get-Item -LiteralPath $Path).Length -gt 65536) { throw 'Manifest exceeds 64 KiB.' }
    Assert-PublisherSignature $Path $PublisherThumbprint
    # This signed PowerShell file is a data envelope. NEVER execute or dot-source it.
    $raw = [IO.File]::ReadAllText($Path)
    $match = [regex]::Match($raw, '(?s)\A# Relayne production manifest v1\r?\n<#\r?\n(?<json>.*?)\r?\n#>\r?\n(?:\r?\n)*(?<signature># SIG # Begin signature block\r?\n(?:#[^\r\n]*\r?\n)*# SIG # End signature block\r?\n?)\z')
    if (!$match.Success) { throw 'Invalid signed manifest envelope.' }
    $document = [System.Text.Json.JsonDocument]::Parse($match.Groups['json'].Value)
    try { Assert-JsonUniqueKeys $document.RootElement } finally { $document.Dispose() }
    $manifest = ConvertFrom-Json -InputObject $match.Groups['json'].Value -AsHashtable
    Assert-ManifestKeys $manifest @('schema','product','channel','version','files')
    if ($manifest.schema -cne 'relayne-production-v1' -or $manifest.product -cne 'Relayne' -or $manifest.channel -cne 'production' -or
        $manifest.version -isnot [string] -or $manifest.version -cnotmatch '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$') { throw 'Invalid production manifest identity or version.' }
    if ($manifest.files -isnot [array] -or $manifest.files.Count -ne 2) { throw 'Exactly two production executables are required.' }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($file in $manifest.files) {
        Assert-ManifestKeys $file @('path','sha256','size')
        if ($file.path -cnotin @('relayne.exe','relayne_team.exe') -or !$names.Add($file.path) -or
            $file.sha256 -isnot [string] -or $file.sha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
            $file.size -isnot [long] -and $file.size -isnot [int]) { throw 'Invalid manifest file entry.' }
        if ($file.size -le 0 -or $file.size -gt 536870912) { throw 'Invalid executable size (maximum 512 MiB).' }
    }
    return $manifest
}

function Read-ProductionPackage([string]$Directory, [string]$PublisherThumbprint) {
    $Directory = Assert-PlainPath $Directory
    $manifest = Read-ProductionManifest (Join-Path $Directory 'manifest.ps1') $PublisherThumbprint
    $items = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($items.Count -ne 3) { throw 'Unexpected package contents.' }
    foreach ($file in $manifest.files) {
        $path = Assert-PlainPath (Join-Path $Directory $file.path)
        if ((Get-Item -LiteralPath $path).Length -ne $file.size -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $file.sha256) { throw 'Package content hash or size mismatch.' }
        Assert-PublisherSignature $path $PublisherThumbprint
    }
    return $manifest
}

function Receive-BoundedHttpsFile([uri]$Uri, [string]$Destination, [long]$MaximumBytes) {
    if (!$Uri.IsAbsoluteUri -or $Uri.Scheme -cne 'https' -or $Uri.UserInfo -or $Uri.Fragment -or $Uri.Query) { throw 'An absolute HTTPS URL without credentials, query, or fragment is required.' }
    $Destination = Assert-PlainPath $Destination
    if ($MaximumBytes -le 0 -or $MaximumBytes -gt 536870912) { throw 'Invalid download size limit.' }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromMinutes(5))
    $response = $null; $source = $null; $target = $null
    try {
        $response = $client.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $timeout.Token).GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ne 200) { throw 'Download requires HTTP 200; redirects are rejected.' }
        if ($response.Content.Headers.ContentLength -gt $MaximumBytes) { throw 'Download exceeds size limit.' }
        $source = $response.Content.ReadAsStreamAsync($timeout.Token).GetAwaiter().GetResult()
        $target = [IO.File]::Open((Assert-PlainPath $Destination), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = [byte[]]::new(65536); $total = 0L
        while (($count = $source.ReadAsync($buffer, 0, $buffer.Length, $timeout.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $count
            if ($total -gt $MaximumBytes) { throw 'Download exceeds size limit.' }
            $target.Write($buffer, 0, $count)
        }
        $target.Flush($true)
    } finally {
        if ($target) { $target.Dispose() }; if ($source) { $source.Dispose() }; if ($response) { $response.Dispose() }
        $timeout.Dispose(); $client.Dispose(); $handler.Dispose()
    }
}

function Set-ProductionCurrent([string]$Root, [string]$Version) {
    $pointer = Assert-PlainPath (Join-Path $Root 'current.txt')
    $temporary = Assert-PlainPath (Join-Path $Root ('.current-' + [guid]::NewGuid().ToString('N')))
    [IO.File]::WriteAllText($temporary, $Version, [Text.UTF8Encoding]::new($false))
    try {
        if (Test-Path -LiteralPath $pointer) {
            $backup = Assert-PlainPath (Join-Path $Root ('.previous-selection-' + [guid]::NewGuid().ToString('N')))
            [IO.File]::Replace($temporary, $pointer, $backup)
        }
        else { [IO.File]::Move($temporary, $pointer) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
}

function Install-ProductionPackage([string]$PackageDirectory, [string]$Root, [string]$PublisherThumbprint) {
    $Root = Assert-PlainPath $Root
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $lockPath = Assert-PlainPath (Join-Path $Root 'delivery.lock')
    $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        $manifest = Read-ProductionPackage $PackageDirectory $PublisherThumbprint
        $pointer = Assert-PlainPath (Join-Path $Root 'current.txt')
        if (Test-Path -LiteralPath $pointer) {
            $current = [IO.File]::ReadAllText($pointer)
            if ($current -notmatch '^\d{1,5}\.\d{1,5}\.\d{1,5}$' -or [version]$manifest.version -lt [version]$current) { throw 'Updates must not downgrade the current version; use explicit rollback for older versions.' }
            if ([version]$manifest.version -eq [version]$current) {
                $installed = Read-ProductionPackage (Join-Path $Root "versions/$current") $PublisherThumbprint
                if ($installed.version -cne $current) { throw 'Installed version identity mismatch.' }
                foreach ($file in $manifest.files) {
                    $existing = @($installed.files | Where-Object path -CEQ $file.path)
                    if ($existing.Count -ne 1 -or $existing[0].sha256 -ine $file.sha256 -or $existing[0].size -ne $file.size) { throw 'Same version has different contents; publishing requires a new version.' }
                }
                Write-Output "Production version $current is already installed and verified. No changes made."
                return
            }
        }
        $versions = Assert-PlainPath (Join-Path $Root 'versions')
        New-Item -ItemType Directory -Path $versions -Force | Out-Null
        $destination = Assert-PlainPath (Join-Path $versions $manifest.version)
        if (Test-Path -LiteralPath $destination) { throw 'Version already exists; retained versions are never overwritten.' }
        $stage = Assert-PlainPath (Join-Path $versions ('.staging-' + [guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $stage | Out-Null
        foreach ($name in @('manifest.ps1','relayne.exe','relayne_team.exe')) { Copy-Item -LiteralPath (Join-Path $PackageDirectory $name) -Destination (Join-Path $stage $name) }
        $null = Read-ProductionPackage $stage $PublisherThumbprint
        # Same-volume directory rename, followed by atomic pointer replacement. Data is never modified.
        [IO.Directory]::Move((Assert-PlainPath $stage), (Assert-PlainPath $destination))
        Set-ProductionCurrent $Root $manifest.version
        Write-Output "Installed production version $($manifest.version). Previous versions and user data were retained."
    } finally { $lock.Dispose() }
}
