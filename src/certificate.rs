use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::models::{CertificateIdentity, CertificateTrustStatus};
use crate::security::app_data_file;

pub struct CertificateTrustStore {
    path: Option<PathBuf>,
    identities: HashMap<String, CertificateIdentity>,
}

impl Default for CertificateTrustStore {
    fn default() -> Self {
        Self {
            path: None,
            identities: HashMap::new(),
        }
    }
}

impl CertificateTrustStore {
    pub fn new() -> Result<Self> {
        Self::at(app_data_file("certificates.json")?)
    }

    pub fn at(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create certificate store directory")?;
        }
        if !path.exists() {
            return Ok(Self {
                path: Some(path),
                identities: HashMap::new(),
            });
        }

        let json = fs::read_to_string(&path).context("read certificate trust store")?;
        let persisted: PersistedCertificateTrustStore =
            serde_json::from_str(&json).context("parse certificate trust store")?;
        let had_synthetic_fingerprints = persisted
            .identities
            .iter()
            .any(|identity| identity.fingerprint.starts_with("aivana-local-"));
        let store = Self {
            path: Some(path),
            identities: persisted
                .identities
                .into_iter()
                .filter(|identity| !identity.fingerprint.starts_with("aivana-local-"))
                .map(|identity| (key(&identity.host, identity.port), identity))
                .collect(),
        };
        if had_synthetic_fingerprints {
            let _ = store.persist();
        }
        Ok(store)
    }

    pub fn classify(&self, host: &str, port: u16, fingerprint: &str) -> CertificateTrustStatus {
        let key = key(host, port);
        match self.identities.get(&key) {
            None => CertificateTrustStatus::Unknown,
            Some(identity) if identity.status == CertificateTrustStatus::Rejected => {
                CertificateTrustStatus::Rejected
            }
            Some(identity) if identity.fingerprint == fingerprint => identity.status,
            Some(_) => CertificateTrustStatus::Changed,
        }
    }

    pub fn trust(&mut self, host: &str, port: u16, fingerprint: &str) -> CertificateIdentity {
        self.upsert(host, port, fingerprint, CertificateTrustStatus::Trusted)
    }

    pub fn reject(&mut self, host: &str, port: u16, fingerprint: &str) -> CertificateIdentity {
        self.upsert(host, port, fingerprint, CertificateTrustStatus::Rejected)
    }

    pub fn explain_risk(&self, status: CertificateTrustStatus) -> String {
        match status {
            CertificateTrustStatus::Unknown => {
                "Unknown certificate: expected for new hosts; investigate for existing hosts."
                    .to_owned()
            }
            CertificateTrustStatus::Trusted => "The certificate is locally trusted.".to_owned(),
            CertificateTrustStatus::Rejected => {
                "The certificate was rejected; the connection should remain blocked.".to_owned()
            }
            CertificateTrustStatus::Changed => {
                "The certificate changed; this may indicate a reinstall or a man-in-the-middle risk.".to_owned()
            }
        }
    }

    fn upsert(
        &mut self,
        host: &str,
        port: u16,
        fingerprint: &str,
        status: CertificateTrustStatus,
    ) -> CertificateIdentity {
        let now = Utc::now();
        let key = key(host, port);
        let first_seen_at = self
            .identities
            .get(&key)
            .map(|identity| identity.first_seen_at)
            .unwrap_or(now);
        let identity = CertificateIdentity {
            host: host.to_owned(),
            port,
            fingerprint: fingerprint.to_owned(),
            first_seen_at,
            last_seen_at: now,
            status,
        };
        self.identities.insert(key, identity.clone());
        let _ = self.persist();
        identity
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let persisted = PersistedCertificateTrustStore {
            identities: self.identities.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&persisted).context("serialize cert store")?;
        fs::write(path, json).context("write certificate trust store")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedCertificateTrustStore {
    identities: Vec<CertificateIdentity>,
}

fn key(host: &str, port: u16) -> String {
    format!("{}:{}", host.to_lowercase(), port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changed_certificate() {
        let mut store = CertificateTrustStore::default();
        store.trust("host", 3389, "one");
        assert_eq!(
            store.classify("host", 3389, "two"),
            CertificateTrustStatus::Changed
        );
    }

    #[test]
    fn persistent_certificate_store_roundtrips() {
        let path = std::env::temp_dir().join(format!("aivana-certs-{}.json", uuid::Uuid::new_v4()));
        let mut store = CertificateTrustStore::at(path.clone()).unwrap();
        store.trust("host", 3389, "one");
        let reloaded = CertificateTrustStore::at(path.clone()).unwrap();
        assert_eq!(
            reloaded.classify("host", 3389, "one"),
            CertificateTrustStatus::Trusted
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persistent_store_removes_synthetic_fingerprints() {
        let path = std::env::temp_dir().join(format!("aivana-certs-{}.json", uuid::Uuid::new_v4()));
        fs::write(
            &path,
            r#"{
  "identities": [
    {
      "host": "legacy",
      "port": 3389,
      "fingerprint": "aivana-local-deadbeef",
      "first_seen_at": "2026-01-01T00:00:00Z",
      "last_seen_at": "2026-01-01T00:00:00Z",
      "status": "Trusted"
    }
  ]
}"#,
        )
        .unwrap();

        let store = CertificateTrustStore::at(path.clone()).unwrap();
        assert_eq!(
            store.classify("legacy", 3389, "aivana-local-deadbeef"),
            CertificateTrustStatus::Unknown
        );
        let json = fs::read_to_string(&path).unwrap();
        assert!(!json.contains("aivana-local"));
        let _ = fs::remove_file(path);
    }
}
