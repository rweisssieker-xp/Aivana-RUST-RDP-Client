use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{ConnectionProfile, CredentialRef, SecretCredential};

pub trait CredentialStore {
    fn save(
        &mut self,
        profile: &mut ConnectionProfile,
        secret: SecretCredential,
    ) -> Result<CredentialRef>;
    fn get(&self, credential_id: Uuid) -> Result<Option<SecretCredential>>;
    fn delete(&mut self, credential_id: Uuid) -> Result<()>;
    fn has_credential(&self, credential_id: Uuid) -> bool;
    #[allow(dead_code)]
    fn credential_ref_for_profile(&self, profile_id: Uuid) -> Option<CredentialRef>;
    fn test(&self, credential_id: Uuid) -> Result<CredentialHealth>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialHealth {
    Available,
    Missing,
    EmptyPassword,
    DecryptionFailed,
}

#[cfg(test)]
#[derive(Default)]
pub struct LocalCredentialStore {
    refs: HashMap<Uuid, CredentialRef>,
    secrets: HashMap<Uuid, SecretCredential>,
}

#[cfg(test)]
impl CredentialStore for LocalCredentialStore {
    fn save(
        &mut self,
        profile: &mut ConnectionProfile,
        secret: SecretCredential,
    ) -> Result<CredentialRef> {
        let now = Utc::now();
        let id = profile.credential_id.unwrap_or_else(Uuid::new_v4);
        let credential_ref = CredentialRef {
            id,
            profile_id: profile.id,
            username: secret.username.clone(),
            label: format!("{}@{}", secret.username, profile.host),
            created_at: self.refs.get(&id).map(|r| r.created_at).unwrap_or(now),
            updated_at: now,
        };

        profile.credential_id = Some(id);
        profile.password.clear();
        self.refs.insert(id, credential_ref.clone());
        self.secrets.insert(id, secret);
        Ok(credential_ref)
    }

    fn get(&self, credential_id: Uuid) -> Result<Option<SecretCredential>> {
        Ok(self.secrets.get(&credential_id).cloned())
    }

    fn delete(&mut self, credential_id: Uuid) -> Result<()> {
        self.refs
            .remove(&credential_id)
            .context("credential ref missing")?;
        self.secrets.remove(&credential_id);
        Ok(())
    }

    fn has_credential(&self, credential_id: Uuid) -> bool {
        self.secrets.contains_key(&credential_id)
    }

    fn credential_ref_for_profile(&self, profile_id: Uuid) -> Option<CredentialRef> {
        self.refs
            .values()
            .find(|r| r.profile_id == profile_id)
            .cloned()
    }

    fn test(&self, credential_id: Uuid) -> Result<CredentialHealth> {
        match self.secrets.get(&credential_id) {
            None => Ok(CredentialHealth::Missing),
            Some(secret) if secret.password.is_empty() => Ok(CredentialHealth::EmptyPassword),
            Some(_) => Ok(CredentialHealth::Available),
        }
    }
}

pub struct PersistentCredentialStore {
    path: PathBuf,
    refs: HashMap<Uuid, CredentialRef>,
    records: HashMap<Uuid, ProtectedCredentialRecord>,
}

impl PersistentCredentialStore {
    pub fn new() -> Result<Self> {
        Self::at(app_data_file("credentials.json")?)
    }

    pub fn at(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create credential store directory")?;
        }

        if !path.exists() {
            return Ok(Self {
                path,
                refs: HashMap::new(),
                records: HashMap::new(),
            });
        }

        let json = fs::read_to_string(&path).context("read credential store")?;
        let persisted: PersistedCredentialStore =
            serde_json::from_str(&json).context("parse credential store")?;
        Ok(Self {
            path,
            refs: persisted.refs.into_iter().map(|r| (r.id, r)).collect(),
            records: persisted.records.into_iter().map(|r| (r.id, r)).collect(),
        })
    }

    fn persist(&self) -> Result<()> {
        let persisted = PersistedCredentialStore {
            refs: self.refs.values().cloned().collect(),
            records: self.records.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&persisted).context("serialize credentials")?;
        fs::write(&self.path, json).context("write credential store")
    }
}

impl CredentialStore for PersistentCredentialStore {
    fn save(
        &mut self,
        profile: &mut ConnectionProfile,
        secret: SecretCredential,
    ) -> Result<CredentialRef> {
        let now = Utc::now();
        let id = profile.credential_id.unwrap_or_else(Uuid::new_v4);
        let credential_ref = CredentialRef {
            id,
            profile_id: profile.id,
            username: secret.username.clone(),
            label: format!("{}@{}", secret.username, profile.host),
            created_at: self.refs.get(&id).map(|r| r.created_at).unwrap_or(now),
            updated_at: now,
        };
        let clear = serde_json::to_vec(&secret).context("serialize secret")?;
        let protected = protect_secret(&clear).context("protect credential")?;

        profile.credential_id = Some(id);
        profile.password.clear();
        self.refs.insert(id, credential_ref.clone());
        self.records.insert(
            id,
            ProtectedCredentialRecord {
                id,
                protected_hex: hex_encode(&protected),
                updated_at: now,
            },
        );
        self.persist()?;
        Ok(credential_ref)
    }

    fn get(&self, credential_id: Uuid) -> Result<Option<SecretCredential>> {
        let Some(record) = self.records.get(&credential_id) else {
            return Ok(None);
        };
        let protected = hex_decode(&record.protected_hex).context("decode protected credential")?;
        let clear = unprotect_secret(&protected).context("unprotect credential")?;
        let secret = serde_json::from_slice(&clear).context("parse secret")?;
        Ok(Some(secret))
    }

    fn delete(&mut self, credential_id: Uuid) -> Result<()> {
        self.refs
            .remove(&credential_id)
            .context("credential ref missing")?;
        self.records.remove(&credential_id);
        self.persist()
    }

    fn has_credential(&self, credential_id: Uuid) -> bool {
        self.records.contains_key(&credential_id)
    }

    fn credential_ref_for_profile(&self, profile_id: Uuid) -> Option<CredentialRef> {
        self.refs
            .values()
            .find(|r| r.profile_id == profile_id)
            .cloned()
    }

    fn test(&self, credential_id: Uuid) -> Result<CredentialHealth> {
        match self.get(credential_id) {
            Ok(None) => Ok(CredentialHealth::Missing),
            Ok(Some(secret)) if secret.password.is_empty() => Ok(CredentialHealth::EmptyPassword),
            Ok(Some(_)) => Ok(CredentialHealth::Available),
            Err(_) => Ok(CredentialHealth::DecryptionFailed),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedCredentialStore {
    refs: Vec<CredentialRef>,
    records: Vec<ProtectedCredentialRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProtectedCredentialRecord {
    id: Uuid,
    protected_hex: String,
    updated_at: DateTime<Utc>,
}

pub fn redact_secret_text(input: &str) -> String {
    let mut redacted = String::with_capacity(input.len());
    let mut token = String::new();
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !token.is_empty() {
                redacted.push_str(&redact_secret_token(&token));
                token.clear();
            }
            redacted.push(ch);
        } else {
            token.push(ch);
        }
    }
    if !token.is_empty() {
        redacted.push_str(&redact_secret_token(&token));
    }
    redacted
}

fn redact_secret_token(token: &str) -> String {
    let lower = token.to_lowercase();
    for marker in ["password=", "pwd=", "token=", "secret="] {
        if let Some(index) = lower.find(marker) {
            let original_marker = &token[index..index + marker.len()];
            return format!("{}{}[REDACTED]", &token[..index], original_marker);
        }
    }
    token.to_owned()
}

pub fn app_data_file(file: &str) -> Result<PathBuf> {
    #[cfg(test)]
    let base_dir = {
        static TEST_APP_DATA_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        TEST_APP_DATA_DIR
            .get_or_init(|| {
                let started = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_nanos())
                    .unwrap_or_default();
                std::env::temp_dir().join("Aivana").join(format!(
                    "RustRdpClientTests-{}-{started}",
                    std::process::id()
                ))
            })
            .clone()
    };

    #[cfg(not(test))]
    let base_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Aivana")
        .join("RustRdpClient");
    fs::create_dir_all(&base_dir).context("create app data directory")?;
    Ok(base_dir.join(file))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("invalid hex length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("invalid hex byte"))
        .collect()
}

#[cfg(windows)]
pub(crate) fn protect_secret(clear: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: clear.len() as u32,
        pbData: clear.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(anyhow!("CryptProtectData failed"));
    }

    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(protected)
}

#[cfg(windows)]
pub(crate) fn unprotect_secret(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(anyhow!("CryptUnprotectData failed"));
    }

    let clear =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(clear)
}

#[cfg(not(windows))]
pub(crate) fn protect_secret(clear: &[u8]) -> Result<Vec<u8>> {
    Ok(clear.iter().map(|b| b ^ 0xa5).collect())
}

#[cfg(not(windows))]
pub(crate) fn unprotect_secret(protected: &[u8]) -> Result<Vec<u8>> {
    Ok(protected.iter().map(|b| b ^ 0xa5).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ProfileStore;

    #[test]
    fn credential_save_clears_profile_password() {
        let mut store = LocalCredentialStore::default();
        let mut profile = ConnectionProfile::sample("Test", "host", "Default", false);
        profile.password = "secret".to_owned();

        let saved = store
            .save(
                &mut profile,
                SecretCredential {
                    username: "admin".to_owned(),
                    password: "secret".to_owned(),
                    domain: String::new(),
                },
            )
            .unwrap();

        assert_eq!(profile.credential_id, Some(saved.id));
        assert!(profile.password.is_empty());
        assert!(store.has_credential(saved.id));
        assert_eq!(store.test(saved.id).unwrap(), CredentialHealth::Available);
    }

    #[test]
    fn persistent_store_roundtrips_protected_secret() {
        let path = std::env::temp_dir().join(format!("aivana-credentials-{}.json", Uuid::new_v4()));
        let mut store = PersistentCredentialStore::at(path.clone()).unwrap();
        let mut profile = ConnectionProfile::sample("Test", "host", "Default", false);
        let saved = store
            .save(
                &mut profile,
                SecretCredential {
                    username: "admin".to_owned(),
                    password: "secret".to_owned(),
                    domain: "corp".to_owned(),
                },
            )
            .unwrap();

        let reloaded = PersistentCredentialStore::at(path.clone()).unwrap();
        let secret = reloaded.get(saved.id).unwrap().unwrap();
        assert_eq!(secret.password, "secret");
        let json = fs::read_to_string(&path).unwrap();
        assert!(!json.contains("secret"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn redaction_masks_common_secret_markers() {
        assert_eq!(
            redact_secret_text("password=hunter2 token=abc"),
            "password=[REDACTED] token=[REDACTED]"
        );
        assert_eq!(
            redact_secret_text("error=password=hunter2 detail=token=abc"),
            "error=password=[REDACTED] detail=token=[REDACTED]"
        );
        assert_eq!(
            redact_secret_text("line1 password=hunter2\nline2 token=abc"),
            "line1 password=[REDACTED]\nline2 token=[REDACTED]"
        );
        assert_eq!(
            redact_secret_text("AIVANA_RDP_TEST_PASSWORD=hunter2"),
            "AIVANA_RDP_TEST_PASSWORD=[REDACTED]"
        );
    }

    #[test]
    #[ignore = "requires AIVANA_RDP_TEST_HOST, AIVANA_RDP_TEST_USER and AIVANA_RDP_TEST_PASSWORD"]
    fn manual_save_credential_for_profile() {
        let host = std::env::var("AIVANA_RDP_TEST_HOST").expect("AIVANA_RDP_TEST_HOST");
        let username = std::env::var("AIVANA_RDP_TEST_USER").expect("AIVANA_RDP_TEST_USER");
        let password = std::env::var("AIVANA_RDP_TEST_PASSWORD").expect("AIVANA_RDP_TEST_PASSWORD");
        let domain = std::env::var("AIVANA_RDP_TEST_DOMAIN").unwrap_or_default();

        let profile_store = ProfileStore::new().expect("profile store");
        let mut profiles = profile_store.load().expect("load profiles");
        let profile = profiles
            .iter_mut()
            .find(|profile| profile.host.eq_ignore_ascii_case(&host))
            .expect("matching profile");

        let mut credential_store = PersistentCredentialStore::new().expect("credential store");
        let saved = credential_store
            .save(
                profile,
                SecretCredential {
                    username,
                    password,
                    domain,
                },
            )
            .expect("save credential");
        profile_store.save(&profiles).expect("save profiles");

        assert!(credential_store.has_credential(saved.id));
        assert!(profiles.iter().all(|profile| profile.password.is_empty()));
        println!(
            "saved credential metadata for host {host}; credential_id={}",
            saved.id
        );
    }
}
