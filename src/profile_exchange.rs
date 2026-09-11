//! Portable connection profiles. Secrets and local credential/workspace identities
//! never cross the exchange boundary; imports receive fresh identities.
use crate::models::{ConnectionProfile, Protocol};
use crate::rd_gateway::validate_host;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde_json::{Value, json};
use std::{collections::HashMap, path::Path};
use uuid::Uuid;

pub fn import_profiles(path: &Path) -> Result<Vec<ConnectionProfile>> {
    let bytes = std::fs::read(path).context("Profildatei konnte nicht gelesen werden")?;
    import_bytes(extension(path)?, &bytes)
}
pub fn export_profiles(path: &Path, profiles: &[ConnectionProfile]) -> Result<()> {
    let bytes = export_bytes(extension(path)?, profiles)?;
    std::fs::write(path, bytes).context("Profildatei konnte nicht geschrieben werden")
}
fn extension(path: &Path) -> Result<&str> {
    path.extension()
        .and_then(|v| v.to_str())
        .context("Dateiendung .rdp, .csv oder .json erforderlich")
}

pub fn import_bytes(format: &str, bytes: &[u8]) -> Result<Vec<ConnectionProfile>> {
    if bytes.len() > 16 * 1024 * 1024 {
        bail!("Profildatei überschreitet 16 MiB");
    }
    let text = decode_text(bytes)?;
    let mut profiles = match format.to_ascii_lowercase().as_str() {
        "rdp" => vec![parse_rdp(&text)?],
        "csv" => parse_csv(&text)?,
        "json" => parse_json(&text)?,
        _ => bail!("Dateiformat muss .rdp, .csv oder .json sein"),
    };
    if profiles.is_empty() {
        bail!("Datei enthält keine Profile");
    }
    for profile in &mut profiles {
        validate_profile(profile)?;
        sanitize(profile);
    }
    Ok(profiles)
}
pub fn export_bytes(format: &str, profiles: &[ConnectionProfile]) -> Result<Vec<u8>> {
    if profiles.is_empty() {
        bail!("Keine Profile ausgewählt");
    }
    for profile in profiles {
        validate_profile(profile)?;
    }
    match format.to_ascii_lowercase().as_str() {
        "json" => Ok(serde_json::to_vec_pretty(
            &json!({"version": 1, "profiles": profiles.iter().map(portable_value).collect::<Result<Vec<_>>>()?}),
        )?),
        "csv" => export_csv(profiles),
        "rdp" => {
            if profiles.len() != 1 {
                bail!(
                    "Eine .rdp-Datei kann nur ein Profil enthalten; für mehrere Profile CSV/JSON verwenden"
                );
            }
            Ok(export_rdp(&profiles[0])?.into_bytes())
        }
        _ => bail!("Dateiformat muss .rdp, .csv oder .json sein"),
    }
}
fn sanitize(profile: &mut ConnectionProfile) {
    profile.id = Uuid::new_v4();
    profile.workspace_id = None;
    profile.credential_id = None;
    profile.password.clear();
    profile.options.gateway.credential_id = None;
    profile.options.gateway.password.clear();
    profile.created_at = Utc::now();
    profile.updated_at = profile.created_at;
}
fn validate_profile(profile: &ConnectionProfile) -> Result<()> {
    validate_host(&profile.host)?;
    if profile.port == 0 {
        bail!("Port muss zwischen 1 und 65535 liegen");
    }
    if profile.name.trim().is_empty() {
        bail!("Profilname fehlt");
    }
    if profile.options.gateway.enabled {
        validate_host(&profile.options.gateway.host)?;
        if profile.options.gateway.port == 0 {
            bail!("Gateway-Port darf nicht 0 sein");
        }
    }
    Ok(())
}
fn portable_value(profile: &ConnectionProfile) -> Result<Value> {
    let mut value = serde_json::to_value(profile)?;
    let obj = value.as_object_mut().unwrap();
    for key in [
        "id",
        "workspace_id",
        "credential_id",
        "password",
        "created_at",
        "updated_at",
    ] {
        obj.remove(key);
    }
    if let Some(gateway) = obj
        .get_mut("options")
        .and_then(|v| v.get_mut("gateway"))
        .and_then(Value::as_object_mut)
    {
        gateway.remove("credential_id");
        gateway.remove("password");
    }
    Ok(value)
}
fn from_value(mut value: Value) -> Result<ConnectionProfile> {
    let object = value
        .as_object_mut()
        .context("Profil muss ein JSON-Objekt sein")?;
    for key in [
        "password",
        "credential_id",
        "workspace_id",
        "id",
        "created_at",
        "updated_at",
    ] {
        object.remove(key);
    }
    let host = object
        .get("host")
        .and_then(Value::as_str)
        .context("Profil benötigt host")?;
    validate_host(host)?;
    let mut base =
        serde_json::to_value(ConnectionProfile::sample(host, host, "Importiert", false))?;
    base.as_object_mut().unwrap().extend(object.clone());
    Ok(serde_json::from_value(base).context("Ungültige Profilfelder")?)
}
fn parse_json(text: &str) -> Result<Vec<ConnectionProfile>> {
    let value: Value = serde_json::from_str(text).context("Ungültige JSON-Datei")?;
    let values = match value {
        Value::Array(items) => items,
        Value::Object(mut obj) if obj.contains_key("profiles") => {
            if let Some(version) = obj.get("version") {
                if version.as_u64() != Some(1) {
                    bail!("Unbekannte Profilformat-Version");
                }
            }
            obj.remove("profiles")
                .unwrap()
                .as_array()
                .context("profiles muss ein Array sein")?
                .clone()
        }
        Value::Object(_) => vec![value],
        _ => bail!("JSON muss Profile enthalten"),
    };
    values.into_iter().map(from_value).collect()
}
fn decode_text(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        if bytes.len() % 2 != 0 {
            bail!("Unvollständige UTF-16-Datei");
        }
        let little = bytes[0] == 0xff;
        let units: Vec<_> = bytes[2..]
            .chunks_exact(2)
            .map(|b| {
                if little {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
            .collect();
        Ok(String::from_utf16(&units).context("Ungültiges UTF-16")?)
    } else {
        Ok(
            std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
                .context("Datei muss UTF-8 oder UTF-16 mit BOM verwenden")?
                .to_owned(),
        )
    }
}
fn parse_endpoint(value: &str, default_port: u16) -> Result<(String, u16)> {
    let (host, port) = if value.starts_with('[') {
        let end = value.find(']').context("IPv6-Klammer fehlt")?;
        let tail = &value[end + 1..];
        let port = if tail.is_empty() {
            default_port
        } else {
            tail.strip_prefix(':')
                .context("Ungültiger Host/Port")?
                .parse::<u16>()
                .context("Ungültiger Port")?
        };
        (value[1..end].to_owned(), port)
    } else if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':').unwrap();
        (
            host.to_owned(),
            port.parse::<u16>().context("Ungültiger Port")?,
        )
    } else {
        (value.to_owned(), default_port)
    };
    validate_host(&host)?;
    if port == 0 {
        bail!("Port darf nicht 0 sein");
    }
    Ok((host, port))
}
fn parse_rdp(text: &str) -> Result<ConnectionProfile> {
    let mut settings = HashMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, ':');
        let key = parts.next().unwrap().trim().to_ascii_lowercase();
        let kind = parts.next().context("Ungültige .rdp-Zeile")?;
        let value = parts.next().context("Ungültige .rdp-Zeile")?;
        if !["s", "i", "b"].contains(&kind) {
            bail!("Ungültiger .rdp-Feldtyp");
        }
        settings.insert(key, value.to_owned());
    }
    let address = settings
        .get("full address")
        .context(".rdp benötigt full address")?;
    let (host, port) = parse_endpoint(address, 3389)?;
    let mut p = ConnectionProfile::sample(&host, &host, "Importiert", false);
    p.port = port;
    if let Some(value) = settings.get("server port") {
        p.port = value.parse().context("Ungültiger server port")?;
    }
    if let Some(value) = settings.get("username") {
        p.username = value.clone();
    }
    if let Some(value) = settings.get("domain") {
        p.domain = value.clone();
    }
    if let Some(value) = settings.get("desktopwidth") {
        p.options.width = value.parse().context("Ungültige Desktopbreite")?;
    }
    if let Some(value) = settings.get("desktopheight") {
        p.options.height = value.parse().context("Ungültige Desktophöhe")?;
    }
    if let Some(value) = settings.get("redirectclipboard") {
        p.options.clipboard = parse_flag(value)?;
    }
    if let Some(value) = settings.get("audiocapturemode") {
        p.options.microphone = parse_flag(value)?;
    }
    if let Some(value) = settings.get("audiomode") {
        p.options.audio_playback = match value.as_str() {
            "0" => true,
            "1" | "2" => false,
            _ => bail!("Ungültiger Audiomodus"),
        };
    }
    if let Some(value) = settings.get("dynamic resolution") {
        p.options.dynamic_resolution = parse_flag(value)?;
    }
    if let Some(value) = settings.get("gatewayhostname").filter(|v| !v.is_empty()) {
        let (host, port) = parse_endpoint(value, 443)?;
        p.options.gateway.host = host;
        p.options.gateway.port = port;
        p.options.gateway.enabled = true;
    }
    if let Some(value) = settings.get("gatewayusagemethod") {
        p.options.gateway.enabled = match value.as_str() {
            "0" | "4" => false,
            "1" | "2" | "3" => true,
            _ => bail!("Ungültige Gateway-Verwendung"),
        };
    }
    Ok(p)
}
fn parse_flag(value: &str) -> Result<bool> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => bail!("Ungültiger Wahrheitswert"),
    }
}
fn export_rdp(p: &ConnectionProfile) -> Result<String> {
    if p.protocol != Protocol::Rdp {
        bail!(".rdp unterstützt nur RDP-Profile");
    }
    for value in [&p.username, &p.domain] {
        if value.contains(['\r', '\n']) {
            bail!(".rdp-Felder dürfen keine Zeilenumbrüche enthalten");
        }
    }
    let host = if p.host.contains(':') {
        format!("[{}]", p.host)
    } else {
        p.host.clone()
    };
    let mut out = format!(
        "full address:s:{host}:{}\r\nusername:s:{}\r\ndomain:s:{}\r\ndesktopwidth:i:{}\r\ndesktopheight:i:{}\r\nredirectclipboard:i:{}\r\naudiomode:i:{}\r\naudiocapturemode:i:{}\r\ndynamic resolution:i:{}\r\n",
        p.port,
        p.username,
        p.domain,
        p.options.width,
        p.options.height,
        p.options.clipboard as u8,
        if p.options.audio_playback { 0 } else { 2 },
        p.options.microphone as u8,
        p.options.dynamic_resolution as u8
    );
    let gw = &p.options.gateway;
    if !gw.host.is_empty() {
        validate_host(&gw.host)?;
        let host = if gw.host.contains(':') {
            format!("[{}]", gw.host)
        } else {
            gw.host.clone()
        };
        out.push_str(&format!(
            "gatewayhostname:s:{host}:{}\r\ngatewayusagemethod:i:{}\r\n",
            gw.port, gw.enabled as u8
        ));
    }
    Ok(out)
}
fn parse_csv(text: &str) -> Result<Vec<ConnectionProfile>> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::Headers)
        .from_reader(text.as_bytes());
    let headers = reader.headers()?.clone();
    let headers: Vec<_> = headers.iter().map(|s| s.to_ascii_lowercase()).collect();
    if !headers.iter().any(|h| h == "host") {
        bail!("CSV benötigt die Spalte host");
    }
    let mut out = Vec::new();
    for row in reader.records() {
        let row = row.context("Ungültige CSV-Zeile")?;
        let mut obj = serde_json::Map::new();
        for (key, value) in headers.iter().zip(row.iter()) {
            if value.is_empty() {
                continue;
            }
            let value = match key.as_str() {
                "port" => json!(value.parse::<u16>().context("Ungültiger CSV-Port")?),
                "favorite" => json!(parse_flag(value)?),
                "tags" => {
                    if value.starts_with('[') {
                        serde_json::from_str(value).context("Ungültige Tags")?
                    } else {
                        json!(value.split(';').map(str::to_owned).collect::<Vec<_>>())
                    }
                }
                "options" => serde_json::from_str(value).context("Ungültige CSV-Optionen")?,
                "protocol" => json!(match value.to_ascii_lowercase().as_str() {
                    "rdp" => "Rdp",
                    "ssh" => "Ssh",
                    "vnc" => "Vnc",
                    _ => bail!("Unbekanntes Protokoll"),
                }),
                "name" | "host" | "username" | "domain" | "group" => json!(value),
                _ => continue,
            };
            obj.insert(key.clone(), value);
        }
        out.push(from_value(Value::Object(obj))?);
    }
    Ok(out)
}
fn export_csv(profiles: &[ConnectionProfile]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    let keys = [
        "name", "host", "port", "username", "domain", "protocol", "group", "tags", "favorite",
        "options",
    ];
    writer.write_record(keys)?;
    for p in profiles {
        let value = portable_value(p)?;
        writer.write_record(keys.iter().map(|key| match &value[key] {
            Value::String(s) => s.clone(),
            v => v.to_string(),
        }))?;
    }
    Ok(writer.into_inner()?)
}
pub fn duplicate_profile(profile: &ConnectionProfile) -> ConnectionProfile {
    let mut duplicate = profile.clone();
    sanitize(&mut duplicate);
    duplicate.name = format!("{} – Kopie", profile.name);
    duplicate
}
#[derive(Default)]
pub struct BatchProfileEdit {
    pub group: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub port: Option<u16>,
    pub options: Option<crate::connection_options::ProfileOptions>,
}
pub fn apply_batch_edit(
    profiles: &mut [ConnectionProfile],
    selected: &[Uuid],
    edit: &BatchProfileEdit,
) -> Result<usize> {
    let mut updates = Vec::new();
    for (index, p) in profiles
        .iter()
        .enumerate()
        .filter(|(_, p)| selected.contains(&p.id))
    {
        let mut p = p.clone();
        if let Some(v) = &edit.group {
            p.group = v.clone();
        }
        if let Some(v) = &edit.tags {
            p.tags = v.clone();
        }
        if let Some(v) = edit.favorite {
            p.favorite = v;
        }
        if let Some(v) = &edit.username {
            p.username = v.clone();
        }
        if let Some(v) = &edit.domain {
            p.domain = v.clone();
        }
        if let Some(v) = edit.port {
            p.port = v;
        }
        if let Some(v) = &edit.options {
            p.options = v.clone();
        }
        validate_profile(&p)?;
        p.updated_at = Utc::now();
        updates.push((index, p));
    }
    let count = updates.len();
    for (index, p) in updates {
        profiles[index] = p;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rdp_utf8_utf16_and_no_secrets() {
        let text = "full address:s:server.example:3390\r\nusername:s:Öps\r\npassword 51:b:deadbeef\r\nredirectclipboard:i:0\r\n";
        let mut utf16 = vec![0xff, 0xfe];
        for u in text.encode_utf16() {
            utf16.extend(u.to_le_bytes());
        }
        for bytes in [text.as_bytes(), utf16.as_slice()] {
            let p = import_bytes("rdp", bytes).unwrap().remove(0);
            assert_eq!(p.host, "server.example");
            assert_eq!(p.port, 3390);
            assert_eq!(p.username, "Öps");
            assert!(p.password.is_empty());
            assert!(!p.options.clipboard);
        }
    }
    #[test]
    fn csv_quoting_and_json_preserve_options_without_credentials() {
        let mut p = ConnectionProfile::sample("A, \"B\"\nC", "host", "Ops", true);
        p.password = "secret-placeholder".into();
        p.credential_id = Some(Uuid::new_v4());
        p.options.clipboard = false;
        for format in ["csv", "json"] {
            let bytes = export_bytes(format, &[p.clone()]).unwrap();
            let text = String::from_utf8(bytes.clone()).unwrap();
            assert!(!text.contains("secret-placeholder"));
            assert!(!text.contains("credential_id"));
            let q = import_bytes(format, &bytes).unwrap().remove(0);
            assert_eq!(q.name, p.name);
            assert!(!q.options.clipboard);
            assert_ne!(p.id, q.id);
            assert!(q.credential_id.is_none());
        }
    }
    #[test]
    fn old_json_defaults_and_password_discard() {
        let p = import_bytes(
            "json",
            br#"[{"host":"host","name":"old","password":"never-import"}]"#,
        )
        .unwrap()
        .remove(0);
        assert_eq!(p.port, 3389);
        assert!(p.password.is_empty());
        assert!(p.credential_id.is_none());
    }
    #[test]
    fn rejects_bad_hosts_ports_and_partial_batch() {
        for text in [
            "full address:s:https://host",
            "full address:s:host:0",
            "full address:s:host:65536",
            "full address:s:bad host",
        ] {
            assert!(import_bytes("rdp", text.as_bytes()).is_err());
        }
        let mut p = vec![ConnectionProfile::sample("A", "host", "old", false)];
        let id = p[0].id;
        assert!(
            apply_batch_edit(
                &mut p,
                &[id],
                &BatchProfileEdit {
                    group: Some("new".into()),
                    port: Some(0),
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert_eq!(p[0].group, "old");
    }
    #[test]
    fn duplicate_clears_identity_and_secrets() {
        let mut p = ConnectionProfile::sample("A", "host", "Ops", false);
        p.password = "test".into();
        p.credential_id = Some(Uuid::new_v4());
        let q = duplicate_profile(&p);
        assert_ne!(p.id, q.id);
        assert!(q.password.is_empty());
        assert!(q.credential_id.is_none());
    }
}
