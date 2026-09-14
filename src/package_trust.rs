//! Ed25519 publisher signatures. A valid signature is trusted only after explicit key enrollment.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

const LIMIT: usize = 512 * 1024;
const DOMAIN: &[u8] = b"Relayne signed repair package v1\0";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPackage {
    pub schema: u32,
    pub public_key: String,
    pub package: String,
    pub signature: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    pub publishers: BTreeMap<String, String>,
}
fn decoded_key(key: &str) -> Result<Vec<u8>> {
    let b = STANDARD.decode(key.trim())?;
    ensure!(b.len() == 32, "An Ed25519 key must contain 32 bytes");
    Ok(b)
}
pub fn fingerprint(key: &str) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(decoded_key(key)?)))
}
fn message(package: &str) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(package.as_bytes());
    m
}
fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut b = vec![];
    std::fs::File::open(path)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut b)?;
    ensure!(b.len() <= LIMIT, "File too large");
    Ok(b)
}
pub fn create_key() -> Result<String> {
    let path = crate::security::app_data_file("publisher-key.dpapi")?;
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("Key generation failed"))?;
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref())
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;
    let encrypted = crate::security::protect_secret(key.as_ref())?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("The signing key already exists or cannot be saved")?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    Ok(STANDARD.encode(pair.public_key().as_ref()))
}
fn local_key() -> Result<Ed25519KeyPair> {
    let bytes = crate::security::unprotect_secret(&bounded_read(
        &crate::security::app_data_file("publisher-key.dpapi")?,
    )?)?;
    Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| anyhow::anyhow!("Cannot read the signing key"))
}
pub fn public_key() -> Result<String> {
    Ok(STANDARD.encode(local_key()?.public_key().as_ref()))
}
pub fn sign(package: &crate::workflow::Package) -> Result<String> {
    sign_with(package, &local_key()?)
}
fn sign_with(package: &crate::workflow::Package, key: &Ed25519KeyPair) -> Result<String> {
    let package = package.export().map_err(anyhow::Error::msg)?;
    let bundle = SignedPackage {
        schema: 1,
        public_key: STANDARD.encode(key.public_key().as_ref()),
        signature: STANDARD.encode(key.sign(&message(&package)).as_ref()),
        package,
    };
    let text = serde_json::to_string_pretty(&bundle)?;
    ensure!(text.len() <= LIMIT, "Signed package too large");
    Ok(text)
}
impl TrustStore {
    pub fn load() -> Result<Self> {
        let p = crate::security::app_data_file("publisher-trust.dpapi")?;
        if !p.exists() {
            return Ok(Self::default());
        }
        let s: Self =
            serde_json::from_slice(&crate::security::unprotect_secret(&bounded_read(&p)?)?)?;
        ensure!(s.publishers.len() <= 128, "Too many publishers");
        for (k, v) in &s.publishers {
            ensure!(*k == fingerprint(v)?, "The trust store is corrupted");
        }
        Ok(s)
    }
    pub fn save(&self) -> Result<()> {
        ensure!(self.publishers.len() <= 128, "At most 128 publishers are allowed");
        crate::security::atomic_write(
            &crate::security::app_data_file("publisher-trust.dpapi")?,
            &crate::security::protect_secret(&serde_json::to_vec(self)?)?,
        )
    }
    pub fn enroll(&mut self, key: &str) -> Result<String> {
        let id = fingerprint(key)?;
        ensure!(
            self.publishers.contains_key(&id) || self.publishers.len() < 128,
            "Publisher limit reached"
        );
        self.publishers
            .insert(id.clone(), STANDARD.encode(decoded_key(key)?));
        Ok(id)
    }
    pub fn verify(&self, text: &str) -> Result<crate::workflow::Package> {
        ensure!(text.len() <= LIMIT, "Package exceeds 512 KiB");
        let b: SignedPackage = serde_json::from_str(text)?;
        ensure!(b.schema == 1, "Unknown signature schema");
        let key = decoded_key(&b.public_key)?;
        let id = fingerprint(&b.public_key)?;
        ensure!(
            self.publishers
                .get(&id)
                .is_some_and(|v| v == &STANDARD.encode(&key)),
            "The publisher is not explicitly trusted or its trust was revoked"
        );
        let sig = STANDARD.decode(&b.signature)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, &key)
            .verify(&message(&b.package), &sig)
            .map_err(|_| anyhow::anyhow!("Invalid publisher signature"))?;
        crate::workflow::Package::import(&b.package).map_err(anyhow::Error::msg)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn dpapi_key_and_revocable_trust_roundtrip() {
        let key = create_key().unwrap();
        assert_eq!(public_key().unwrap(), key);
        assert!(create_key().is_err());
        let package =
            crate::workflow::Package::new(crate::workflow::example(), "local fixture".into())
                .unwrap();
        let text = sign(&package).unwrap();
        let mut trust = TrustStore::load().unwrap();
        let id = trust.enroll(&key).unwrap();
        trust.save().unwrap();
        assert!(TrustStore::load().unwrap().verify(&text).is_ok());
        trust.publishers.remove(&id);
        trust.save().unwrap();
        assert!(TrustStore::load().unwrap().verify(&text).is_err());
        assert!(SignedPackage::deserialize(&mut serde_json::Deserializer::from_str(&text)).is_ok());
    }
    #[test]
    fn signature_requires_enrolled_key_and_rejects_tamper_revocation() {
        let pkcs = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs.as_ref()).unwrap();
        let p =
            crate::workflow::Package::new(crate::workflow::example(), "fixture".into()).unwrap();
        let text = sign_with(&p, &key).unwrap();
        let mut trust = TrustStore::default();
        assert!(trust.verify(&text).is_err());
        let id = trust
            .enroll(&STANDARD.encode(key.public_key().as_ref()))
            .unwrap();
        assert!(trust.verify(&text).is_ok());
        let mut bundle: SignedPackage = serde_json::from_str(&text).unwrap();
        bundle.package = bundle.package.replace("fixture", "tampered");
        assert!(
            trust
                .verify(&serde_json::to_string(&bundle).unwrap())
                .is_err()
        );
        trust.publishers.remove(&id);
        assert!(trust.verify(&text).is_err());
    }
}
