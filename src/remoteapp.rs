//! Real RemoteApp launch through the Windows RDP client. No secrets are exported.
use crate::models::ConnectionProfile;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteAppOptions {
    pub program: String,
    pub name: String,
    pub arguments: String,
    pub working_directory: String,
}
fn value(value: &str) -> anyhow::Result<&str> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        anyhow::bail!("RemoteApp-Wert enthält Steuerzeichen oder ist zu lang");
    }
    Ok(value)
}
pub fn rdp_document(profile: &ConnectionProfile, app: &RemoteAppOptions) -> anyhow::Result<String> {
    crate::rd_gateway::validate_host(&profile.host)?;
    if profile.port == 0 || app.program.trim().is_empty() {
        anyhow::bail!("RemoteApp-Programm und gültiger Zielport erforderlich");
    }
    let host = if profile.host.contains(':') {
        format!("[{}]", profile.host)
    } else {
        profile.host.clone()
    };
    let mut text = format!(
        "full address:s:{host}:{}\r\nprompt for credentials:i:1\r\nauthentication level:i:1\r\nenablecredsspsupport:i:1\r\nremoteapplicationmode:i:1\r\nremoteapplicationprogram:s:{}\r\nremoteapplicationname:s:{}\r\nremoteapplicationcmdline:s:{}\r\nshell working directory:s:{}\r\ndisableconnectionsharing:i:1\r\nredirectclipboard:i:0\r\nredirectprinters:i:0\r\ndrivestoredirect:s:\r\n",
        profile.port,
        value(&app.program)?,
        value(&app.name)?,
        value(&app.arguments)?,
        value(&app.working_directory)?
    );
    if !profile.username.is_empty() {
        text.push_str(&format!("username:s:{}\r\n", value(&profile.username)?));
    }
    if !profile.domain.is_empty() {
        text.push_str(&format!("domain:s:{}\r\n", value(&profile.domain)?));
    }
    let gateway = &profile.options.gateway;
    if gateway.enabled {
        crate::rd_gateway::validate_gateway(gateway, profile.port)?;
        text.push_str(&format!("gatewayhostname:s:{}:{}\r\ngatewayusagemethod:i:1\r\ngatewayprofileusagemethod:i:1\r\npromptcredentialonce:i:0\r\n", gateway.host, gateway.port));
    }
    Ok(text)
}
#[cfg(windows)]
pub fn launch(profile: &ConnectionProfile, app: &RemoteAppOptions) -> anyhow::Result<()> {
    use std::{io::Write, os::windows::process::CommandExt};
    let document = rdp_document(profile, app)?;
    let directory =
        std::env::temp_dir().join(format!("relayne-remoteapp-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let result = (|| -> anyhow::Result<()> {
        let user = std::env::var("USERNAME")?;
        let domain = std::env::var("USERDOMAIN")?;
        let account = format!("{domain}\\{user}:(OI)(CI)F");
        let secured = std::process::Command::new("icacls.exe")
            .arg(&directory)
            .args(["/inheritance:r", "/grant:r", &account])
            .creation_flags(0x08000000)
            .output()?;
        if !secured.status.success() {
            anyhow::bail!("RemoteApp-Temporärverzeichnis konnte nicht geschützt werden");
        }
        let file_path = directory.join("launch.rdp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)?;
        // Windows RDP files use BOM-prefixed UTF-16LE for international names.
        file.write_all(&[0xff, 0xfe])?;
        for code in document.encode_utf16() {
            file.write_all(&code.to_le_bytes())?;
        }
        file.sync_all()?;
        drop(file);
        let mut child = std::process::Command::new("mstsc.exe")
            .arg(&file_path)
            .spawn()?;
        let cleanup_dir = directory.clone();
        std::thread::spawn(move || {
            let _ = child.wait();
            // mstsc can delegate to an existing instance; allow it time to read the file.
            std::thread::sleep(std::time::Duration::from_secs(60));
            let _ = std::fs::remove_file(cleanup_dir.join("launch.rdp"));
            let _ = std::fs::remove_dir(cleanup_dir);
        });
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(directory.join("launch.rdp"));
        let _ = std::fs::remove_dir(&directory);
    }
    result
}
#[cfg(not(windows))]
pub fn launch(_: &ConnectionProfile, _: &RemoteAppOptions) -> anyhow::Result<()> {
    anyhow::bail!("RemoteApp benötigt den Windows-RDP-Client");
}
#[cfg(test)]
mod tests {
    #[test]
    fn native_remoteapp_document_contains_no_secrets() {
        let mut profile =
            crate::models::ConnectionProfile::sample("test", "server.example", "test", false);
        profile.password = "MUST_NOT_EXPORT".into();
        let app = super::RemoteAppOptions {
            program: "||calc".into(),
            ..Default::default()
        };
        let document = super::rdp_document(&profile, &app).unwrap();
        assert!(document.contains("remoteapplicationprogram:s:||calc"));
        assert!(document.contains("prompt for credentials:i:1"));
        assert!(!document.contains("MUST_NOT_EXPORT"));
    }
    #[test]
    fn values_reject_rdp_setting_injection() {
        assert!(super::value("||Calculator").is_ok());
        assert!(super::value("calc\r\nredirectclipboard:i:1").is_err());
        assert!(super::value("bad\0").is_err());
    }
}
