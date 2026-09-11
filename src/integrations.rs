//! Explicit inventory imports and private, bounded Bitwarden credential retrieval.
use crate::{
    models::{ConnectionProfile, Protocol, SecretCredential},
    operations::{CommandSpec, Endpoint},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::Read,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub const INVENTORY_LIMIT: usize = 2 * 1024 * 1024;
const ROW_LIMIT: usize = 2000;

#[derive(Deserialize)]
struct InventoryRow {
    name: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    group: String,
}

/// Only the allowlisted connection metadata is deserialized. IDs, credentials,
/// passwords and arbitrary extra fields can never restore an imported secret.
pub fn parse_inventory(text: &str, csv: bool) -> Result<Vec<ConnectionProfile>, String> {
    if text.len() > INVENTORY_LIMIT {
        return Err("Inventar überschreitet 2 MiB.".into());
    }
    let rows: Vec<InventoryRow> = if csv {
        let mut reader = csv::Reader::from_reader(text.as_bytes());
        reader
            .deserialize()
            .take(ROW_LIMIT + 1)
            .collect::<Result<_, _>>()
            .map_err(|_| "CSV ungültig; Spalten name,host erforderlich.".to_string())?
    } else {
        serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|_| "JSON ungültig; Array mit name und host erforderlich.".to_string())?
    };
    if rows.len() > ROW_LIMIT {
        return Err("Maximal 2000 Inventareinträge pro Import.".into());
    }
    rows.into_iter()
        .enumerate()
        .map(|(index, row)| {
            let protocol = match row.protocol.to_ascii_lowercase().as_str() {
                "" | "rdp" => Protocol::Rdp,
                "ssh" => Protocol::Ssh,
                "vnc" => Protocol::Vnc,
                _ => return Err(format!("Zeile {}: unbekanntes Protokoll.", index + 1)),
            };
            let host = row.host.trim().trim_end_matches('.').to_ascii_lowercase();
            let port = row.port.unwrap_or(protocol.default_port());
            Endpoint::new(&host, "", port)
                .map_err(|_| format!("Zeile {}: ungültiger Host/Port.", index + 1))?;
            for value in [&row.name, &row.username, &row.domain, &row.group] {
                if value.len() > 256 || value.chars().any(char::is_control) {
                    return Err(format!(
                        "Zeile {}: Metadaten zu lang oder mit Steuerzeichen.",
                        index + 1
                    ));
                }
            }
            if row.name.trim().is_empty() {
                return Err(format!("Zeile {}: Name fehlt.", index + 1));
            }
            let mut profile = ConnectionProfile::sample(row.name.trim(), &host, &row.group, false);
            profile.username = row.username;
            profile.domain = row.domain;
            profile.port = port;
            profile.protocol = protocol;
            profile.tags = vec!["inventory".into()];
            Ok(profile)
        })
        .collect()
}

fn identity(profile: &ConnectionProfile) -> String {
    // Conservative endpoint identity prevents silent overwrite for another login.
    format!(
        "{}:{}:{}",
        profile.protocol.label(),
        profile
            .host
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        profile.port
    )
}

pub struct InventoryReview {
    pub candidates: Vec<ConnectionProfile>,
    pub conflicts: usize,
}
pub fn review_inventory(
    rows: Vec<ConnectionProfile>,
    existing: &[ConnectionProfile],
) -> InventoryReview {
    let mut seen: HashSet<String> = existing.iter().map(identity).collect();
    let mut candidates = Vec::new();
    let mut conflicts = 0;
    for row in rows {
        if seen.insert(identity(&row)) {
            candidates.push(row);
        } else {
            conflicts += 1;
        }
    }
    InventoryReview {
        candidates,
        conflicts,
    }
}

pub fn ad_inventory_command() -> CommandSpec {
    CommandSpec {
        program: "powershell.exe".into(),
        args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); Import-Module ActiveDirectory -ErrorAction Stop; $computers=@(Get-ADComputer -Filter * -Properties DNSHostName -ResultSetSize 501); if($computers.Count -gt 500){throw 'Mehr als 500 Computer; bitte gefiltertes Inventar als JSON/CSV importieren.'}; $rows=@($computers | Where-Object {$_.DNSHostName} | ForEach-Object { [pscustomobject]@{name=$_.Name;host=$_.DNSHostName;group='Active Directory';protocol='rdp'} }); ConvertTo-Json -InputObject $rows -Compress"].into_iter().map(str::to_string).collect(),
        stdin: String::new(), source: "Active Directory / aktuelle Windows-Identität".into(),
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct GroupRule {
    pub name: String,
    pub host_contains: String,
    pub tag: String,
}
impl GroupRule {
    pub fn matches(&self, profile: &ConnectionProfile) -> bool {
        profile
            .host
            .to_ascii_lowercase()
            .contains(&self.host_contains.to_ascii_lowercase())
            && (self.tag.is_empty()
                || profile
                    .tags
                    .iter()
                    .any(|tag| tag.eq_ignore_ascii_case(&self.tag)))
    }
}

pub fn bitwarden_command(item_id: &str) -> Result<Command, String> {
    let id = uuid::Uuid::parse_str(item_id)
        .map_err(|_| "Bitwarden-Eintrag benötigt eine gültige UUID.".to_string())?;
    let mut command = Command::new("bw.exe");
    command.args(["get", "item", &id.to_string(), "--nointeraction"]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    Ok(command)
}

#[derive(Deserialize)]
struct VaultItem {
    login: Option<VaultLogin>,
}
#[derive(Deserialize)]
struct VaultLogin {
    username: Option<String>,
    password: Option<String>,
}
fn parse_login(bytes: &[u8]) -> Result<SecretCredential, String> {
    let item: VaultItem =
        serde_json::from_slice(bytes).map_err(|_| "Vault-Antwort ist ungültig.".to_string())?;
    let login = item.login.ok_or("Vault-Eintrag ist kein Login.")?;
    let username = login
        .username
        .filter(|s| !s.is_empty())
        .ok_or("Vault-Login hat keinen Benutzernamen.")?;
    let password = login
        .password
        .filter(|s| !s.is_empty())
        .ok_or("Vault-Login hat kein Passwort.")?;
    Ok(SecretCredential {
        username,
        password,
        domain: String::new(),
    })
}

/// This private channel is never a JobQueue result, Debug value or UI log.
pub struct VaultRequest {
    receiver: mpsc::Receiver<Result<SecretCredential, String>>,
    cancel: Arc<AtomicBool>,
}
impl VaultRequest {
    pub fn start(item: &str) -> Result<Self, String> {
        let command = bitwarden_command(item)?;
        let (tx, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        thread::spawn(move || {
            let _ = tx.send(fetch_login(command, signal));
        });
        Ok(Self { receiver, cancel })
    }
    pub fn poll(&self) -> Option<Result<SecretCredential, String>> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(_) => Some(Err("Vault-Worker beendet.".into())),
        }
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl Drop for VaultRequest {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(not(windows))]
fn fetch_login(_command: Command, _cancel: Arc<AtomicBool>) -> Result<SecretCredential, String> {
    Err("Diese Vault-Integration benötigt Windows und DPAPI.".into())
}

#[cfg(windows)]
fn fetch_login(mut command: Command, cancel: Arc<AtomicBool>) -> Result<SecretCredential, String> {
    if std::env::var_os("BW_SESSION").is_none_or(|value| value.is_empty()) {
        return Err("BW_SESSION fehlt. Bitwarden extern entsperren und Aivana mit geerbter Sitzung starten.".into());
    }
    let mut child = command.spawn().map_err(|_| {
        "bw.exe konnte nicht gestartet werden. Offizielle Bitwarden CLI im PATH erforderlich."
            .to_string()
    })?;
    let mut reader = child.stdout.take().ok_or("Vault-Ausgabekanal fehlt.")?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let started = Instant::now();
    let result = loop {
        if cancel.load(Ordering::Relaxed)
            || started.elapsed() > Duration::from_secs(45)
            || bytes.len() > 262144
        {
            let _ = child.kill();
            let _ = child.wait();
            break Err("Vault-Abruf abgebrochen, Zeitlimit oder Größenlimit erreicht.".into());
        }
        // The sole pipe owner reads only bytes known to be available. No blocking
        // reader thread survives cancellation even if a descendant holds stdout.
        let available = match pipe_available(&reader) {
            Ok(count) => count,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Vault-Ausgabe nicht verfügbar.".into());
            }
        };
        if available > 0 {
            let amount = (available as usize).min(buffer.len());
            match reader.read(&mut buffer[..amount]) {
                Ok(n) if n > 0 => bytes.extend_from_slice(&buffer[..n]),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("Vault-Ausgabe unvollständig.".into());
                }
            }
            continue;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    break Err("Vault-Abruf fehlgeschlagen. Sitzung, Eintrag-ID und Berechtigung extern prüfen.".into());
                }
                // Recheck after process exit so its final write cannot be lost.
                if pipe_available(&reader).unwrap_or(0) > 0 {
                    continue;
                }
                break parse_login(&bytes);
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Vault-Prozessstatus nicht verfügbar.".into());
            }
        }
    };
    bytes.fill(0);
    buffer.fill(0);
    result
}

#[cfg(windows)]
fn pipe_available(reader: &std::process::ChildStdout) -> std::io::Result<u32> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn PeekNamedPipe(
            handle: *mut std::ffi::c_void,
            buffer: *mut std::ffi::c_void,
            size: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
    }
    let mut available = 0;
    // ChildStdout owns a valid anonymous pipe handle; peeking never consumes data.
    let success = unsafe {
        PeekNamedPipe(
            reader.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if success != 0 {
        return Ok(available);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(109) {
        Ok(0)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_never_restores_password_or_identity() {
        let rows = parse_inventory(r#"[{"name":"x","host":"HOST.","password":"secret","credential_id":"malicious","id":"bad"}]"#, false).unwrap();
        assert!(rows[0].password.is_empty());
        assert!(rows[0].credential_id.is_none());
        assert_eq!(rows[0].host, "host");
    }
    #[test]
    fn duplicates_and_login_conflicts_are_skipped() {
        let rows = parse_inventory(r#"[{"name":"a","host":"HOST","username":"a"},{"name":"b","host":"host.","username":"b"}]"#, false).unwrap();
        let review = review_inventory(rows.clone(), &[]);
        assert_eq!(review.candidates.len(), 1);
        assert_eq!(review.conflicts, 1);
        assert_eq!(review_inventory(rows.clone(), &rows[..1]).conflicts, 2);
    }
    #[test]
    fn hostile_hosts_and_vault_ids_are_rejected() {
        assert!(parse_inventory(r#"[{"name":"x","host":"x;whoami"}]"#, false).is_err());
        assert!(bitwarden_command("--session SECRET").is_err());
        let command = bitwarden_command("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(command.get_args().count(), 4);
        assert!(
            ad_inventory_command()
                .args
                .iter()
                .any(|a| a == "-NonInteractive")
        );
    }
    #[test]
    fn csv_and_rules_work() {
        let rows = parse_inventory(
            "name,host,protocol,port,password\nserver,dev.example,ssh,22,ignored\n",
            true,
        )
        .unwrap();
        assert_eq!(rows[0].protocol, Protocol::Ssh);
        assert!(rows[0].password.is_empty());
        assert!(
            GroupRule {
                name: "Dev".into(),
                host_contains: "DEV".into(),
                tag: "inventory".into()
            }
            .matches(&rows[0])
        );
    }
    #[test]
    fn invalid_vault_output_never_echoes_secrets() {
        assert!(
            !parse_login(b"TOP_SECRET")
                .unwrap_err()
                .contains("TOP_SECRET")
        );
        assert!(parse_login(br#"{"login":{"username":"u","password":"p"}}"#).is_ok());
    }
}
