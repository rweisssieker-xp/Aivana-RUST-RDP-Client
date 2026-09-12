//! Bounded, encrypted before/after snapshots. No arbitrary command execution UI.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use uuid::Uuid;

pub const CONTENT_LIMIT: usize = 1024 * 1024;
const ENTRY_LIMIT: usize = 128;
const JOURNAL_LIMIT: u64 = 10 * 1024 * 1024;
const JOURNAL_TOTAL_LIMIT: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryKind {
    #[default]
    String,
    ExpandString,
    DWord,
    QWord,
    MultiString,
    Binary,
}
impl RegistryKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::String => "REG_SZ",
            Self::ExpandString => "REG_EXPAND_SZ",
            Self::DWord => "REG_DWORD",
            Self::QWord => "REG_QWORD",
            Self::MultiString => "REG_MULTI_SZ",
            Self::Binary => "REG_BINARY",
        }
    }
    fn validate(self, bytes: &[u8]) -> Result<()> {
        let value = std::str::from_utf8(bytes).context("Registry input requires UTF-8")?;
        match self {
            Self::String | Self::ExpandString => {
                ensure!(!bytes.contains(&0), "Text must not contain NUL")
            }
            Self::DWord => {
                ensure!(
                    value.parse::<u32>().is_ok(),
                    "REG_DWORD requires unsigned decimal u32"
                );
            }
            Self::QWord => {
                ensure!(
                    value.parse::<u64>().is_ok(),
                    "REG_QWORD requires unsigned decimal u64"
                );
            }
            Self::MultiString => {
                let strings: Vec<String> = serde_json::from_str(value)
                    .context("REG_MULTI_SZ requires a JSON string array")?;
                ensure!(
                    strings.iter().all(|s| !s.contains('\0')),
                    "Strings must not contain NUL"
                );
            }
            Self::Binary => {
                STANDARD
                    .decode(value)
                    .context("REG_BINARY requires Base64")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Empty means the current local Windows identity; otherwise WinRM Negotiate.
    pub host: String,
    pub path: String,
    pub registry: bool,
    pub value_name: String,
    #[serde(default)]
    pub registry_kind: RegistryKind,
    /// Explicit owner/group/DACL SDDL change; SACL is deliberately excluded.
    #[serde(default)]
    pub permissions: bool,
}
impl Target {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !(self.registry && self.permissions),
            "Registry ACL changes are unsupported"
        );
        if !self.host.is_empty() {
            crate::operations::Endpoint::new(&self.host, "", 5985).map_err(anyhow::Error::msg)?;
        }
        ensure!(
            self.path.len() <= 2048 && !self.path.chars().any(char::is_control),
            "Invalid path"
        );
        if self.registry {
            ensure!(
                self.path.starts_with("HKCU:\\") || self.path.starts_with("HKLM:\\"),
                "Use HKCU:\\ or HKLM:\\ registry path"
            );
            ensure!(
                self.value_name.len() <= 256 && !self.value_name.chars().any(char::is_control),
                "Invalid registry value name"
            );
        } else {
            let bytes = self.path.as_bytes();
            ensure!(
                bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && bytes[2] == b'\\',
                "Use an absolute Windows drive path"
            );
            ensure!(
                !self.path[2..].contains(':')
                    && !self.path.contains('*')
                    && !self.path.contains('?')
                    && !self.path.contains('/')
                    && self.path[3..].split('\\').all(|part| !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.ends_with('.')
                        && !part.ends_with(' ')),
                "Alternate streams and wildcard paths are unsupported"
            );
        }
        Ok(())
    }
    pub fn label(&self) -> String {
        format!(
            "{} · {}{}",
            if self.host.is_empty() {
                "Local Windows"
            } else {
                &self.host
            },
            self.path,
            if self.registry {
                format!(" · {} [{}]", self.registry_kind.label(), self.value_name)
            } else if self.permissions {
                " · owner/group/DACL SDDL".into()
            } else {
                String::new()
            }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Prepared,
    Applied,
    RestorePending,
    Restored,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    #[serde(default)]
    pub profile_id: Option<Uuid>,
    #[serde(default)]
    pub endpoint_key: Option<String>,
    pub target: Target,
    pub at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub applied_at: Option<DateTime<Utc>>,
    pub phase: Phase,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    #[serde(default)]
    pub file_context: Option<FileContext>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContext {
    pub file_sddl: String,
    pub parent_sddl: String,
    pub parent_path: String,
}
impl Entry {
    pub fn comparison(&self) -> String {
        format!(
            "Before: {} bytes · SHA-256 {}\nAfter: {} bytes · SHA-256 {}",
            self.before.len(),
            fingerprint(&self.before),
            self.after.len(),
            fingerprint(&self.after)
        )
    }
}
pub fn fingerprint(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub trait Backend {
    fn read(&mut self, target: &Target) -> Result<Vec<u8>>;
    /// Must compare the exact current bytes before replacing.
    fn replace(&mut self, target: &Target, expected: &[u8], replacement: &[u8]) -> Result<Vec<u8>>;
    fn file_context(&mut self, _target: &Target) -> Result<Option<FileContext>> {
        Ok(None)
    }
    fn is_missing(&mut self, _target: &Target) -> Result<bool> {
        Ok(false)
    }
    fn restore_deleted(
        &mut self,
        _target: &Target,
        _bytes: &[u8],
        _context: &FileContext,
    ) -> Result<Vec<u8>> {
        bail!("Deleted file restoration unsupported")
    }
}
pub fn normalize_replacement(target: &Target, bytes: &[u8]) -> Result<Vec<u8>> {
    if target.permissions {
        return Ok(
            normalize_sddl(std::str::from_utf8(bytes).context("SDDL requires UTF-8")?)?
                .into_bytes(),
        );
    }
    if !target.registry {
        return Ok(bytes.to_vec());
    }
    target.registry_kind.validate(bytes)?;
    let text = std::str::from_utf8(bytes)?;
    Ok(match target.registry_kind {
        RegistryKind::MultiString => {
            serde_json::to_vec(&serde_json::from_str::<Vec<String>>(text)?)?
        }
        RegistryKind::DWord => text.parse::<u32>()?.to_string().into_bytes(),
        RegistryKind::QWord => text.parse::<u64>()?.to_string().into_bytes(),
        RegistryKind::Binary => STANDARD.encode(STANDARD.decode(text)?).into_bytes(),
        _ => bytes.to_vec(),
    })
}
fn normalize_sddl(s: &str) -> Result<String> {
    // Windows rewrites AI/AR control flags and reorders equivalent consecutive
    // allow/deny ACEs. Preserve deny-vs-allow and explicit-vs-inherited ordering;
    // sort only commutative runs. Protected DACLs retain rules as explicit ACEs.
    ensure!(!s.contains("S:"), "SACL is unsupported");
    let start = s.find("D:").context("DACL required")? + 2;
    let end = s[start..].find('(').map_or(s.len(), |i| start + i);
    let flags = s[start..end].replace("AI", "").replace("AR", "");
    let protected = flags.contains('P');
    let mut result = format!("{}{}", &s[..start], flags);
    let mut group: Vec<String> = vec![];
    let mut previous = String::new();
    let mut tail = &s[end..];
    while !tail.is_empty() {
        ensure!(tail.starts_with('('), "Invalid DACL ACE");
        let close = tail.find(')').context("Invalid DACL ACE")?;
        let mut fields: Vec<String> = tail[1..close].split(';').map(str::to_owned).collect();
        ensure!(
            fields.len() == 6 && matches!(fields[0].as_str(), "A" | "D"),
            "Only standard allow/deny DACL ACEs are supported"
        );
        if protected {
            fields[1] = fields[1].replace("ID", "");
        }
        let key = format!("{}:{}", fields[0], fields[1].contains("ID"));
        if !previous.is_empty() && key != previous {
            group.sort();
            result.push_str(&group.concat());
            group.clear();
        }
        previous = key;
        group.push(format!("({})", fields.join(";")));
        tail = &tail[close + 1..];
    }
    group.sort();
    result.push_str(&group.concat());
    Ok(result)
}
pub fn prepare(backend: &mut impl Backend, target: Target, after: Vec<u8>) -> Result<Entry> {
    target.validate()?;
    let after = normalize_replacement(&target, &after)?;
    ensure!(after.len() <= CONTENT_LIMIT, "Replacement exceeds 1 MiB");
    if target.registry {
        target.registry_kind.validate(&after)?;
    }
    let before = backend.read(&target)?;
    ensure!(before.len() <= CONTENT_LIMIT, "Snapshot exceeds 1 MiB");
    let file_context = backend.file_context(&target)?;
    ensure!(before != after, "No content change");
    let now = Utc::now();
    Ok(Entry {
        id: Uuid::new_v4(),
        profile_id: None,
        endpoint_key: None,
        target,
        at: now,
        updated_at: now,
        applied_at: None,
        phase: Phase::Prepared,
        before,
        after,
        file_context,
    })
}
pub fn apply(root: &Path, backend: &mut impl Backend, mut entry: Entry) -> Result<Entry> {
    ensure!(
        entry.phase == Phase::Prepared,
        "Only prepared changes may be applied"
    );
    ensure!(
        backend.read(&entry.target)? == entry.before,
        "Conflict: target changed since review"
    );
    if entry.file_context.is_some() {
        ensure!(
            backend.file_context(&entry.target)? == entry.file_context,
            "Conflict: file or parent permissions changed since review"
        );
    }
    persist(root, &entry).context("Journal unavailable; no mutation attempted")?;
    let observed = backend.replace(&entry.target, &entry.before, &entry.after)
        .context("Apply not confirmed; encrypted prepared entry retained. Reload journal and inspect target before retrying")?;
    ensure!(
        observed == entry.after,
        "Post-change verification failed; prepared journal retained"
    );
    entry.phase = Phase::Applied;
    entry.updated_at = Utc::now();
    entry.applied_at = Some(entry.updated_at);
    persist(root, &entry).context(
        "Change applied but journal finalization failed; prepared recovery entry remains",
    )?;
    Ok(entry)
}
pub fn restore(root: &Path, backend: &mut impl Backend, mut entry: Entry) -> Result<Entry> {
    ensure!(entry.phase != Phase::Restored, "Already restored");
    if !entry.target.registry && !entry.target.permissions && backend.is_missing(&entry.target)? {
        let context = entry
            .file_context
            .as_ref()
            .context("Old journal has no file ACL/parent snapshot; deleted restore refused")?;
        entry.phase = Phase::RestorePending;
        entry.updated_at = Utc::now();
        persist(root, &entry).context("Restore journal unavailable; no mutation attempted")?;
        ensure!(
            backend.restore_deleted(&entry.target, &entry.before, context)? == entry.before,
            "Deleted file restore verification failed; recovery journal retained"
        );
        entry.phase = Phase::Restored;
        entry.updated_at = Utc::now();
        persist(root, &entry)?;
        return Ok(entry);
    }
    let current = backend.read(&entry.target)?;
    if current == entry.before {
        // Resolves an interrupted restoration or an apply that never reached the target.
        entry.phase = Phase::Restored;
        entry.updated_at = Utc::now();
        persist(root, &entry)?;
        return Ok(entry);
    }
    ensure!(
        current == entry.after,
        "Conflict: target differs from recorded after state; restore refused"
    );
    entry.phase = Phase::RestorePending;
    entry.updated_at = Utc::now();
    persist(root, &entry).context("Restore journal unavailable; no mutation attempted")?;
    let observed = backend
        .replace(&entry.target, &entry.after, &entry.before)
        .context("Restore not confirmed; recovery journal retained")?;
    ensure!(
        observed == entry.before,
        "Restore verification failed; recovery journal retained"
    );
    entry.phase = Phase::Restored;
    entry.updated_at = Utc::now();
    persist(root, &entry)?;
    Ok(entry)
}

fn persist(root: &Path, entry: &Entry) -> Result<()> {
    ensure!(
        cfg!(windows) || cfg!(test),
        "Persistent change history requires Windows DPAPI"
    );
    entry.target.validate()?;
    ensure!(
        entry.before.len() <= CONTENT_LIMIT && entry.after.len() <= CONTENT_LIMIT,
        "Entry too large"
    );
    std::fs::create_dir_all(root)?;
    let path = root.join(format!("{}.dpapi", entry.id));
    if !path.exists() {
        ensure!(
            std::fs::read_dir(root)?.take(ENTRY_LIMIT + 1).count() < ENTRY_LIMIT,
            "Journal full (128 entries); retain encrypted journal offline before starting a new one"
        );
    }
    let clear = serde_json::to_vec(entry)?;
    let encrypted = crate::security::protect_secret(&clear)?;
    ensure!(
        encrypted.len() as u64 <= JOURNAL_LIMIT,
        "Encrypted entry exceeds 10 MiB"
    );
    let mut total = encrypted.len() as u64;
    for item in std::fs::read_dir(root)? {
        let item = item?;
        if item.path() != path {
            total = total
                .checked_add(item.metadata()?.len())
                .context("Journal size overflow")?;
        }
    }
    ensure!(
        total <= JOURNAL_TOTAL_LIMIT,
        "Encrypted journal exceeds 128 MiB; archive entries before further mutation"
    );
    crate::security::atomic_write(&path, &encrypted)
}
pub fn load(root: &Path) -> Result<Vec<Entry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut total = 0u64;
    for item in std::fs::read_dir(root)?.take(ENTRY_LIMIT + 1) {
        ensure!(entries.len() < ENTRY_LIMIT, "Journal exceeds 128 entries");
        let item = item?;
        ensure!(
            item.file_type()?.is_file(),
            "Unexpected journal directory entry"
        );
        let path = item.path();
        total = total
            .checked_add(item.metadata()?.len())
            .context("Journal size overflow")?;
        ensure!(
            total <= JOURNAL_TOTAL_LIMIT,
            "Encrypted journal exceeds 128 MiB"
        );
        // Interrupted atomic writes are never committed entries.
        if path.extension().is_some_and(|x| x == "tmp") {
            continue;
        }
        ensure!(
            path.extension().is_some_and(|x| x == "dpapi"),
            "Unexpected journal file"
        );
        ensure!(
            item.metadata()?.len() <= JOURNAL_LIMIT,
            "Journal entry exceeds bound"
        );
        use std::io::Read;
        let mut encrypted = Vec::new();
        std::fs::File::open(&path)?
            .take(JOURNAL_LIMIT + 1)
            .read_to_end(&mut encrypted)?;
        ensure!(
            encrypted.len() as u64 <= JOURNAL_LIMIT,
            "Journal entry exceeds bound"
        );
        let clear = crate::security::unprotect_secret(&encrypted)?;
        let entry: Entry = serde_json::from_slice(&clear)?;
        entry.target.validate()?;
        ensure!(
            entry.before.len() <= CONTENT_LIMIT && entry.after.len() <= CONTENT_LIMIT,
            "Oversized snapshot"
        );
        ensure!(
            path.file_stem().and_then(|s| s.to_str()) == Some(entry.id.to_string().as_str()),
            "Journal ID mismatch"
        );
        entries.push(entry);
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.at));
    Ok(entries)
}
pub fn journal_directory() -> Result<std::path::PathBuf> {
    crate::security::app_data_file("change-history")
}

pub struct WindowsBackend;
impl Backend for WindowsBackend {
    fn read(&mut self, target: &Target) -> Result<Vec<u8>> {
        normalize_replacement(target, &execute(build_spec(target, None)?)?)
    }
    fn replace(&mut self, target: &Target, expected: &[u8], replacement: &[u8]) -> Result<Vec<u8>> {
        let expected = normalize_replacement(target, expected)?;
        let replacement = normalize_replacement(target, replacement)?;
        normalize_replacement(
            target,
            &execute(build_spec(target, Some((&expected, &replacement)))?)?,
        )
    }
    fn file_context(&mut self, target: &Target) -> Result<Option<FileContext>> {
        if target.registry || target.permissions {
            return Ok(None);
        }
        let body = format!(
            "$p={}; {}; $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop; Check-Path $item; $context=[ordered]@{{file_sddl=(Get-Sddl $p);parent_sddl=(Get-Sddl $item.Directory.FullName);parent_path=$item.Directory.FullName}}; $bytes=[Text.Encoding]::UTF8.GetBytes(($context | ConvertTo-Json -Compress)); [pscustomobject]@{{data=[Convert]::ToBase64String($bytes)}}",
            encoded_text(&target.path),
            FILE_SECURITY
        );
        Ok(Some(serde_json::from_slice(&execute(wrap_script(
            target, &body,
        )?)?)?))
    }
    fn is_missing(&mut self, target: &Target) -> Result<bool> {
        let body = format!(
            "$p={}; $exists=Test-Path -LiteralPath $p -ErrorAction Stop; [pscustomobject]@{{data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$exists))}}",
            encoded_text(&target.path)
        );
        Ok(execute(wrap_script(target, &body)?)? == b"False")
    }
    fn restore_deleted(
        &mut self,
        target: &Target,
        bytes: &[u8],
        context: &FileContext,
    ) -> Result<Vec<u8>> {
        ensure!(
            !target.registry && !target.permissions && bytes.len() <= CONTENT_LIMIT,
            "Invalid deleted file recovery"
        );
        let body = format!(
            r#"$p={}; {}; $parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($p)) -Force -ErrorAction Stop; Check-Path $parent;
if($parent.FullName -cne {} -or (Get-Sddl $parent.FullName) -cne {}){{throw 'Parent path or security changed'}};
if(Test-Path -LiteralPath $p){{throw 'Target already exists'}};
$security=New-Object Security.AccessControl.FileSecurity; $security.SetSecurityDescriptorSddlForm({},[Security.AccessControl.AccessControlSections]'Access,Owner,Group');
$bytes=[Convert]::FromBase64String('{}');
$f=New-Object IO.FileStream($p,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security);
try{{$f.Write($bytes,0,$bytes.Length);$f.Flush($true);$f.Position=0;$observed=New-Object byte[] $bytes.Length;$offset=0;while($offset -lt $observed.Length){{$read=$f.Read($observed,$offset,$observed.Length-$offset);if($read -eq 0){{throw 'Short recovery verification read'}};$offset+=$read}}}}finally{{$f.Dispose()}};
if((Get-Sddl $p) -cne {}){{throw 'Restored permissions verification failed'}};
if([Convert]::ToBase64String($observed) -cne [Convert]::ToBase64String($bytes)){{throw 'Restore bytes differ'}};
[pscustomobject]@{{data=[Convert]::ToBase64String($observed)}}"#,
            encoded_text(&target.path),
            FILE_SECURITY,
            encoded_text(&context.parent_path),
            encoded_text(&context.parent_sddl),
            encoded_text(&context.file_sddl),
            STANDARD.encode(bytes),
            encoded_text(&context.file_sddl)
        );
        execute(wrap_script(target, &body)?)
    }
}
const FILE_SECURITY: &str = r#"function Check-Path($node) { while($null -ne $node){if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse paths unsupported'}; if($node -is [IO.FileInfo]){$node=$node.Directory}else{$node=$node.Parent}} }; function Normalize-Sddl($s) { if($s.Contains('S:')){throw 'SACL unsupported'}; $m=[regex]::Match($s,'D:([^()]*)'); if(!$m.Success){throw 'DACL required'}; $flags=$m.Groups[1].Value.Replace('AI','').Replace('AR',''); $result=$s.Substring(0,$m.Index+2)+$flags; $tail=$s.Substring($m.Index+$m.Length); $group=New-Object 'Collections.Generic.List[string]'; $previous=''; while($tail.Length -gt 0){if(!$tail.StartsWith('(')){throw 'Invalid ACE'}; $close=$tail.IndexOf(')'); if($close -lt 0){throw 'Invalid ACE'}; $fields=$tail.Substring(1,$close-1).Split(';'); if($fields.Length -ne 6 -or $fields[0] -notin @('A','D')){throw 'Only standard allow/deny ACEs supported'}; if($flags.Contains('P')){$fields[1]=$fields[1].Replace('ID','')}; $key=$fields[0]+':'+$fields[1].Contains('ID'); if($previous -ne '' -and $key -cne $previous){$group.Sort([StringComparer]::Ordinal); $result+=($group -join '');$group.Clear()}; $previous=$key;$group.Add('('+($fields -join ';')+')');$tail=$tail.Substring($close+1)}; $group.Sort([StringComparer]::Ordinal);$result+=($group -join '');$result }; function Get-Sddl($path) { Normalize-Sddl ((Get-Acl -LiteralPath $path -ErrorAction Stop).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner,Group')) }"#;
fn encoded_text(value: &str) -> String {
    format!(
        "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'))",
        STANDARD.encode(value.as_bytes())
    )
}
fn build_spec(
    target: &Target,
    replacement: Option<(&[u8], &[u8])>,
) -> Result<crate::operations::CommandSpec> {
    target.validate()?;
    let mut body = format!(
        "$p={}; $limit={CONTENT_LIMIT}; ",
        encoded_text(&target.path)
    );
    if let Some((before, after)) = replacement {
        ensure!(
            before.len() <= CONTENT_LIMIT && after.len() <= CONTENT_LIMIT,
            "Payload exceeds 1 MiB"
        );
        if target.registry {
            target.registry_kind.validate(after)?;
        }
        body.push_str(&format!(
            "$expected='{}'; $replacement=[Convert]::FromBase64String('{}'); ",
            STANDARD.encode(before),
            STANDARD.encode(after)
        ));
    }
    if target.registry {
        if replacement.is_some() && target.registry_kind == RegistryKind::MultiString {
            body.push_str("$a=[string[]](ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($expected)))); if($null -eq $a){$a=[string[]]@()}; $expected=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $a -Compress))); $a=[string[]](ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($replacement))); if($null -eq $a){$a=[string[]]@()}; $replacement=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $a -Compress)); ");
        }
        body.push_str(&format!("$n={}; ", encoded_text(&target.value_name)));
        body.push_str(&format!("$hive=if($p.StartsWith('HKCU:')){{[Microsoft.Win32.Registry]::CurrentUser}}else{{[Microsoft.Win32.Registry]::LocalMachine}}; $key=$hive.OpenSubKey($p.Substring(6),${}); if($null -eq $key){{throw 'Existing registry key required'}}; ", if replacement.is_some() { "true" } else { "false" }));
        body.push_str(&format!(
            "$kind=[Microsoft.Win32.RegistryValueKind]::{:?}; ",
            target.registry_kind
        ));
        body.push_str(r#"function Read-Value { if($key.GetValueKind($n) -ne $kind){throw 'Registry kind differs from reviewed type'}; $v=$key.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $s=switch($kind.ToString()) { 'DWord' { [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$v),0).ToString([Globalization.CultureInfo]::InvariantCulture) } 'QWord' { [BitConverter]::ToUInt64([BitConverter]::GetBytes([long]$v),0).ToString([Globalization.CultureInfo]::InvariantCulture) } 'MultiString' { ConvertTo-Json -InputObject @($v) -Compress } 'Binary' { [Convert]::ToBase64String([byte[]]$v) } default { [string]$v } }; ,([Text.Encoding]::UTF8.GetBytes([string]$s)) }; try { $bytes=[byte[]](Read-Value); if($bytes.Length -gt $limit){throw 'Snapshot exceeds limit'}; "#);
        if replacement.is_some() {
            body.push_str(r#"if([Convert]::ToBase64String($bytes) -cne $expected){throw 'Target conflict; mutation refused'}; $s=[Text.Encoding]::UTF8.GetString($replacement); $v=switch($kind.ToString()) { 'DWord' { [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]::Parse($s)),0) } 'QWord' { [BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]::Parse($s)),0) } 'MultiString' { $parsed=[string[]](ConvertFrom-Json -InputObject $s); if($null -eq $parsed){$parsed=[string[]]@()}; ,$parsed } 'Binary' { ,([Convert]::FromBase64String($s)) } default { $s } }; $key.SetValue($n,$v,$kind); $key.Flush(); $bytes=[byte[]](Read-Value); if([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($replacement)){throw 'Verification failed'}; "#);
        }
        body.push_str(
            "[pscustomobject]@{data=[Convert]::ToBase64String($bytes)} } finally { $key.Close() }",
        );
    } else if target.permissions {
        body.push_str(FILE_SECURITY);
        body.push_str("; $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop; if($item.PSIsContainer){throw 'File ACL target required'}; Check-Path $item; $sddl=Get-Sddl $p; $bytes=[Text.Encoding]::UTF8.GetBytes($sddl); ");
        if replacement.is_some() {
            body.push_str("if([Convert]::ToBase64String($bytes) -cne $expected){throw 'ACL conflict; mutation refused'}; $s=[Text.Encoding]::UTF8.GetString($replacement); $acl=New-Object Security.AccessControl.FileSecurity; $acl.SetSecurityDescriptorSddlForm($s,[Security.AccessControl.AccessControlSections]'Access,Owner,Group'); if((Normalize-Sddl ($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner,Group'))) -cne $s){throw 'Use canonical owner/group/DACL SDDL; SACL unsupported'}; $oldAcl=Get-Acl -LiteralPath $p -ErrorAction Stop; if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $oldAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -or $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value -cne $oldAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value){throw 'Owner and group changes require unsupported privilege escalation'}; $probe=New-Object IO.FileStream($p,[IO.FileMode]::Open,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None); $probe.Dispose(); [IO.File]::SetAccessControl($p,$acl); $bytes=[Text.Encoding]::UTF8.GetBytes((Get-Sddl $p)); if([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($replacement)){throw 'ACL verification failed'}; ");
        }
        body.push_str("[pscustomobject]@{data=[Convert]::ToBase64String($bytes)}");
    } else {
        // Reject reparse points along the full path; opened stream holds an exclusive lock.
        body.push_str("$item=Get-Item -LiteralPath $p -Force -ErrorAction Stop; if($item.PSIsContainer){throw 'Expected existing file'}; $node=$item; while($null -ne $node){if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse paths unsupported'}; if($node -is [IO.FileInfo]){$node=$node.Directory}else{$node=$node.Parent}}; ");
        body.push_str(&format!("$f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::{},[IO.FileShare]::None); try {{ if($f.Length -gt $limit){{throw 'Snapshot exceeds limit'}}; $bytes=New-Object byte[] ([int]$f.Length); $offset=0; while($offset -lt $bytes.Length){{$read=$f.Read($bytes,$offset,$bytes.Length-$offset); if($read -eq 0){{throw 'Short read'}}; $offset+=$read}}; ", if replacement.is_some() { "ReadWrite" } else { "Read" }));
        if replacement.is_some() {
            body.push_str("if([Convert]::ToBase64String($bytes) -cne $expected){throw 'Target conflict; mutation refused'}; $f.Position=0; $f.Write($replacement,0,$replacement.Length); $f.SetLength($replacement.Length); $f.Flush($true); $f.Position=0; $bytes=New-Object byte[] ([int]$f.Length); $offset=0; while($offset -lt $bytes.Length){$read=$f.Read($bytes,$offset,$bytes.Length-$offset); if($read -eq 0){throw 'Short verification read'}; $offset+=$read}; if([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($replacement)){throw 'Verification failed'}; ");
        }
        body.push_str(
            "[pscustomobject]@{data=[Convert]::ToBase64String($bytes)} } finally { $f.Dispose() }",
        );
    }
    wrap_script(target, &body)
}
fn wrap_script(target: &Target, body: &str) -> Result<crate::operations::CommandSpec> {
    target.validate()?;
    let mut spec = crate::operations::CommandSpec {
        program: "powershell.exe".into(),
        args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"]
            .map(str::to_owned)
            .to_vec(),
        stdin: String::new(),
        source: "Encrypted change history".into(),
    };
    if target.host.is_empty() {
        spec.stdin = format!(
            "$ErrorActionPreference='Stop'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\ntry {{ & {{ {body} }} | ConvertTo-Json -Compress; exit 0 }} catch {{ [Console]::Error.WriteLine('Change operation failed; inspect target before retry.'); exit 1 }}\n"
        );
        #[cfg(test)]
        {
            spec.stdin = spec.stdin.replace("[Console]::Error.WriteLine('Change operation failed; inspect target before retry.');", "[Console]::Error.WriteLine($_.Exception.Message);");
        }
    } else {
        let endpoint =
            crate::operations::Endpoint::new(&target.host, "", 5985).map_err(anyhow::Error::msg)?;
        crate::operations::winrm(&mut spec, &endpoint, &body);
    }
    Ok(spec)
}
fn execute(spec: crate::operations::CommandSpec) -> Result<Vec<u8>> {
    ensure!(
        cfg!(windows),
        "Change history execution requires Windows PowerShell"
    );
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    // The command line stays constant: megabyte payloads travel only over stdin.
    let mut command = Command::new(&spec.program);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& ([scriptblock]::Create([Console]::In.ReadToEnd()))",
        ])
        .env_remove("PSModulePath") // Rebuild Windows PowerShell's module paths; do not inherit incompatible PowerShell 7 modules.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().context("Could not start change worker")?;
    let mut input = child.stdin.take().context("Worker stdin missing")?;
    let writer = std::thread::spawn(move || input.write_all(spec.stdin.as_bytes()));
    fn drain(mut stream: impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut block = [0; 8192];
        loop {
            let n = stream.read(&mut block)?;
            if n == 0 {
                break;
            }
            let keep = n.min((limit + 1).saturating_sub(result.len()));
            result.extend_from_slice(&block[..keep]);
        }
        Ok(result)
    }
    let stdout = child.stdout.take().context("Worker stdout missing")?;
    let stderr = child.stderr.take().context("Worker stderr missing")?;
    const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
    let output = std::thread::spawn(move || drain(stdout, OUTPUT_LIMIT));
    let errors = std::thread::spawn(move || drain(stderr, 16 * 1024));
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let written = writer
        .join()
        .map_err(|_| anyhow::anyhow!("Input worker failed"))?;
    let bytes = output
        .join()
        .map_err(|_| anyhow::anyhow!("Output worker failed"))??;
    let diagnostic = errors.join(); // Never surface raw stderr in production.
    if !status.is_some_and(|s| s.success()) || written.is_err() || bytes.len() > OUTPUT_LIMIT {
        #[cfg(test)]
        if let Ok(Ok(stderr)) = &diagnostic {
            eprintln!(
                "Synthetic fixture worker stderr: {}",
                String::from_utf8_lossy(stderr)
            );
        }
        #[cfg(not(test))]
        let _ = diagnostic;
        // Never propagate transport stderr containing paths, values or command payloads into logs.
        bail!(
            "Change operation not confirmed (transport failure, target conflict, unsupported target or permission denied); inspect target and reload encrypted journal"
        );
    }
    #[derive(Deserialize)]
    struct Snapshot {
        data: String,
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).context("Invalid snapshot response")?;
    ensure!(
        snapshot.data.len() <= (CONTENT_LIMIT.div_ceil(3) * 4),
        "Snapshot response exceeds limit"
    );
    let bytes = STANDARD.decode(snapshot.data)?;
    ensure!(bytes.len() <= CONTENT_LIMIT, "Snapshot exceeds limit");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Memory(Vec<u8>, usize);
    impl Backend for Memory {
        fn read(&mut self, _: &Target) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
        fn replace(&mut self, _: &Target, expected: &[u8], replacement: &[u8]) -> Result<Vec<u8>> {
            ensure!(self.0 == expected, "conflict");
            self.1 += 1;
            self.0 = replacement.to_vec();
            Ok(self.0.clone())
        }
    }
    fn target() -> Target {
        Target {
            host: String::new(),
            path: "C:\\test.txt".into(),
            value_name: String::new(),
            registry: false,
            registry_kind: RegistryKind::String,
            permissions: false,
        }
    }
    #[test]
    fn rejects_drift_before_apply_and_restore() {
        let root = std::env::temp_dir().join(format!("history-test-{}", Uuid::new_v4()));
        let mut memory = Memory(b"before".to_vec(), 0);
        let prepared = prepare(&mut memory, target(), b"after".to_vec()).unwrap();
        memory.0 = b"outside".to_vec();
        assert!(apply(&root, &mut memory, prepared.clone()).is_err());
        assert_eq!(memory.1, 0);
        memory.0 = b"before".to_vec();
        let entry = apply(&root, &mut memory, prepared).unwrap();
        memory.0 = b"outside".to_vec();
        assert!(restore(&root, &mut memory, entry.clone()).is_err());
        assert_eq!(memory.1, 1);
        memory.0 = b"after".to_vec();
        let restored = restore(&root, &mut memory, entry).unwrap();
        assert_eq!(restored.phase, Phase::Restored);
        assert_eq!(memory.0, b"before");
        for entry in std::fs::read_dir(&root).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn failed_journal_prevents_mutation() {
        let path = std::env::temp_dir().join(format!("history-file-{}", Uuid::new_v4()));
        std::fs::write(&path, b"not a directory").unwrap();
        let mut memory = Memory(b"before".to_vec(), 0);
        let prepared = prepare(&mut memory, target(), b"after".to_vec()).unwrap();
        assert!(apply(&path, &mut memory, prepared).is_err());
        assert_eq!(memory.1, 0);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn encrypted_journal_roundtrips_and_omits_content() {
        let root = std::env::temp_dir().join(format!("history-encrypted-{}", Uuid::new_v4()));
        let mut memory = Memory(b"sensitive before".to_vec(), 0);
        let entry = prepare(&mut memory, target(), b"sensitive after".to_vec()).unwrap();
        persist(&root, &entry).unwrap();
        let bytes = std::fs::read(root.join(format!("{}.dpapi", entry.id))).unwrap();
        assert!(!bytes.windows(9).any(|v| v == b"sensitive"));
        assert_eq!(load(&root).unwrap()[0].before, b"sensitive before");
        std::fs::remove_file(root.join(format!("{}.dpapi", entry.id))).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn prepared_entry_recovers_an_unconfirmed_mutation() {
        let root = std::env::temp_dir().join(format!("history-recovery-{}", Uuid::new_v4()));
        let mut memory = Memory(b"before".to_vec(), 0);
        let entry = prepare(&mut memory, target(), b"after".to_vec()).unwrap();
        persist(&root, &entry).unwrap();
        memory.0 = b"after".to_vec();
        let loaded = load(&root).unwrap().remove(0);
        assert_eq!(loaded.phase, Phase::Prepared);
        let restored = restore(&root, &mut memory, loaded).unwrap();
        assert_eq!(restored.phase, Phase::Restored);
        assert_eq!(memory.0, b"before");
        assert_eq!(memory.1, 1);
        std::fs::remove_file(root.join(format!("{}.dpapi", entry.id))).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn limits_and_script_literal_encoding() {
        let mut memory = Memory(vec![0; CONTENT_LIMIT + 1], 0);
        assert!(prepare(&mut memory, target(), vec![]).is_err());
        let mut bad = target();
        bad.host = "host'; throw 'injected".into();
        assert!(bad.validate().is_err());
        let script = build_spec(&target(), Some((b"old", b"';exit 9;#"))).unwrap();
        assert!(!script.stdin.contains("';exit 9;#"));
        assert!(script.stdin.contains("FileShare]::None"));
        assert!(script.stdin.contains("conflict"));
    }
    #[test]
    fn typed_registry_inputs_are_bounded_and_canonical() {
        let mut t = target();
        t.registry = true;
        t.path = "HKCU:\\Software\\RelayneTest".into();
        t.registry_kind = RegistryKind::DWord;
        assert_eq!(
            normalize_replacement(&t, b"4294967295").unwrap(),
            b"4294967295"
        );
        assert!(normalize_replacement(&t, b"4294967296").is_err());
        t.registry_kind = RegistryKind::QWord;
        assert_eq!(
            normalize_replacement(&t, b"18446744073709551615").unwrap(),
            b"18446744073709551615"
        );
        t.registry_kind = RegistryKind::MultiString;
        assert_eq!(
            normalize_replacement(&t, br#"[ "a", "b" ]"#).unwrap(),
            br#"["a","b"]"#
        );
        assert!(normalize_replacement(&t, br#"["\u0000"]"#).is_err());
        t.registry_kind = RegistryKind::Binary;
        assert!(normalize_replacement(&t, b"not base64!").is_err());
    }
    #[test]
    fn sddl_normalization_preserves_deny_allow_order_and_effective_inheritance() {
        assert_eq!(
            normalize_sddl("O:SYG:SYD:PAI(A;ID;FR;;;SY)(A;ID;FA;;;BA)").unwrap(),
            "O:SYG:SYD:P(A;;FA;;;BA)(A;;FR;;;SY)"
        );
        assert_ne!(
            normalize_sddl("O:SYG:SYD:(A;;FA;;;SY)(D;;FR;;;SY)").unwrap(),
            normalize_sddl("O:SYG:SYD:(D;;FR;;;SY)(A;;FA;;;SY)").unwrap()
        );
        assert!(normalize_sddl("O:SYG:SYD:(XA;;FA;;;SY)").is_err());
    }
    #[test]
    #[cfg(windows)]
    fn windows_registry_six_kinds_roundtrip_in_unique_hkcu_key() {
        let key = format!("Software\\RelayneHistoryTest-{}", Uuid::new_v4());
        let mut t = target();
        t.registry = true;
        t.path = format!("HKCU:\\{key}");
        t.value_name = "Value".into();
        let mut backend = WindowsBackend;
        let result = (|| -> Result<()> {
            for (kind, initial, before, after) in [
                (RegistryKind::String, "'before'", "before", "after"),
                (
                    RegistryKind::ExpandString,
                    "'%TEMP%'",
                    "%TEMP%",
                    "%USERPROFILE%",
                ),
                (RegistryKind::DWord, "[int]-1", "4294967295", "2147483648"),
                (
                    RegistryKind::QWord,
                    "[long]-1",
                    "18446744073709551615",
                    "9223372036854775808",
                ),
                (
                    RegistryKind::MultiString,
                    "[string[]]@('a','b')",
                    "[\"a\",\"b\"]",
                    "[\"c\",\"d's\",\"\"]",
                ),
                (
                    RegistryKind::Binary,
                    "[byte[]]@(0,255,1)",
                    "AP8B",
                    "AgMABA==",
                ),
                (RegistryKind::MultiString, "[string[]]@()", "[]", "[\"\"]"),
            ] {
                t.registry_kind = kind;
                let setup = format!(
                    "$k=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey({}); try{{$k.SetValue('Value',{},[Microsoft.Win32.RegistryValueKind]::{:?})}}finally{{$k.Close()}}; [pscustomobject]@{{data=''}}",
                    encoded_text(&key),
                    initial,
                    kind
                );
                execute(wrap_script(&t, &setup)?)?;
                ensure!(
                    backend.read(&t)? == before.as_bytes(),
                    "Registry read differs for {:?}",
                    kind
                );
                ensure!(
                    backend.replace(&t, b"wrong", after.as_bytes()).is_err(),
                    "Registry drift accepted"
                );
                ensure!(
                    backend
                        .replace(&t, before.as_bytes(), after.as_bytes())
                        .with_context(|| format!("Registry {kind:?} apply"))?
                        == after.as_bytes(),
                    "Registry apply differs"
                );
                ensure!(
                    backend
                        .replace(&t, after.as_bytes(), before.as_bytes())
                        .with_context(|| format!("Registry {kind:?} restore"))?
                        == before.as_bytes(),
                    "Registry restore differs"
                );
            }
            Ok(())
        })();
        let cleanup = format!(
            "[Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey({},$false); [pscustomobject]@{{data=''}}",
            encoded_text(&key)
        );
        let cleaned = execute(wrap_script(&t, &cleanup).unwrap());
        result.unwrap();
        cleaned.unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn windows_megabyte_deleted_file_and_acl_roundtrip() {
        let dir = std::env::temp_dir().join(format!("relayne-history-large-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("config.bin");
        let journal = dir.join("journal");
        let before = vec![0xa5; CONTENT_LIMIT];
        let after = vec![0x5a; CONTENT_LIMIT];
        std::fs::write(&path, &before).unwrap();
        let mut t = target();
        t.path = path.to_string_lossy().into_owned();
        let result = (|| -> Result<()> {
            let mut backend = WindowsBackend;
            let entry = prepare(&mut backend, t.clone(), after.clone())?;
            let context = entry.file_context.clone().context("Missing file context")?;
            let applied = apply(&journal, &mut backend, entry)?;
            ensure!(std::fs::read(&path)? == after, "Large apply differs");
            std::fs::remove_file(&path)?;
            restore(&journal, &mut backend, applied)?;
            ensure!(std::fs::read(&path)? == before, "Deleted restore differs");
            ensure!(
                backend
                    .file_context(&t)?
                    .context("Missing context")?
                    .file_sddl
                    == context.file_sddl,
                "Deleted restore ACL differs"
            );
            t.permissions = true;
            let original = backend.read(&t)?;
            let script = format!(
                "$p={}; $acl=Get-Acl -LiteralPath $p -ErrorAction Stop; $acl.SetAccessRuleProtection($true,$true); $bytes=[Text.Encoding]::UTF8.GetBytes($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner,Group')); [pscustomobject]@{{data=[Convert]::ToBase64String($bytes)}}",
                encoded_text(&t.path)
            );
            let protected = execute(wrap_script(&t, &script)?)?;
            ensure!(
                original != protected,
                "ACL fixture did not change inheritance"
            );
            backend.replace(&t, &original, &protected)?;
            ensure!(
                backend.replace(&t, &original, &protected).is_err(),
                "ACL drift accepted"
            );
            backend.replace(&t, &protected, &original)?;
            ensure!(backend.read(&t)? == original, "ACL restore differs");
            Ok(())
        })();
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        if journal.exists() {
            for e in std::fs::read_dir(&journal).unwrap() {
                std::fs::remove_file(e.unwrap().path()).unwrap();
            }
            std::fs::remove_dir(&journal).unwrap();
        }
        std::fs::remove_dir(&dir).unwrap();
        result.unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn windows_file_backend_reads_writes_and_refuses_drift_in_temporary_file() {
        let path = std::env::temp_dir().join(format!("relayne-history-{}.txt", Uuid::new_v4()));
        let root = std::env::temp_dir().join(format!("relayne-history-journal-{}", Uuid::new_v4()));
        std::fs::write(&path, b"before\r\n").unwrap();
        let target = Target {
            path: path.to_string_lossy().into_owned(),
            ..target()
        };
        let mut backend = WindowsBackend;
        let result = (|| -> Result<()> {
            let prepared = prepare(&mut backend, target.clone(), b"after".to_vec())?;
            ensure!(prepared.before == b"before\r\n", "read differs");
            let entry = apply(&root, &mut backend, prepared)?;
            ensure!(
                backend
                    .replace(&target, b"before\r\n", b"should not write")
                    .is_err(),
                "drift accepted"
            );
            ensure!(
                std::fs::read(&path)? == b"after",
                "drift write changed file"
            );
            std::fs::write(&path, b"outside")?;
            ensure!(
                restore(&root, &mut backend, entry.clone()).is_err(),
                "restore accepted drift"
            );
            ensure!(std::fs::read(&path)? == b"outside", "restore changed drift");
            std::fs::write(&path, b"after")?;
            ensure!(
                restore(&root, &mut backend, entry)?.phase == Phase::Restored,
                "restore not verified"
            );
            ensure!(std::fs::read(&path)? == b"before\r\n", "restore differs");
            Ok(())
        })();
        std::fs::remove_file(path).unwrap();
        if root.exists() {
            for entry in std::fs::read_dir(&root).unwrap() {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
            std::fs::remove_dir(root).unwrap();
        }
        result.unwrap();
    }
}
