//! Protected, purpose-bound helper secrets; every use reloads the current vault.
use super::{
    evidence::is_digest,
    scope::{CredentialPurpose, CredentialScope},
};
use crate::{
    models::{ScopedCredentialRef, SecretCredential},
    security::{atomic_write, protect_secret, unprotect_secret},
};
use anyhow::{Result, ensure};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MAX_VAULT_BYTES: usize = 4 * 1024 * 1024;

pub struct ResolvedSecret {
    secret: SecretCredential,
}
impl ResolvedSecret {
    pub fn username(&self) -> &str {
        &self.secret.username
    }
    pub fn password(&self) -> &str {
        &self.secret.password
    }
    pub fn domain(&self) -> &str {
        &self.secret.domain
    }
}

pub trait SecretResolver: Send + Sync {
    fn resolve(
        &self,
        scope: &CredentialScope,
        purpose: CredentialPurpose,
    ) -> Result<ResolvedSecret>;
}

pub struct PersistentSecretResolver {
    path: PathBuf,
}
impl PersistentSecretResolver {
    pub fn new() -> Result<Self> {
        Ok(Self {
            path: crate::security::app_data_file("credentials.scoped.dpapi")?,
        })
    }
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vault {
    schema: u16,
    #[serde(default)]
    refs: Vec<ScopedCredentialRef>,
    #[serde(default)]
    records: Vec<ProtectedRecord>,
    #[serde(default)]
    pending: Vec<Uuid>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedRecord {
    id: Uuid,
    bytes: Vec<u8>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            schema: 1,
            refs: Vec::new(),
            records: Vec::new(),
            pending: Vec::new(),
        }
    }
}

fn lock(path: &Path) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}

fn load(path: &Path) -> Result<Vault> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vault::default()),
        Err(_) => anyhow::bail!("Scoped vault unavailable"),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_VAULT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_VAULT_BYTES,
        "Scoped vault capacity reached"
    );
    let clear =
        unprotect_secret(&bytes).map_err(|_| anyhow::anyhow!("Scoped vault unavailable"))?;
    ensure!(
        clear.len() <= MAX_VAULT_BYTES,
        "Scoped vault capacity reached"
    );
    let vault: Vault =
        serde_json::from_slice(&clear).map_err(|_| anyhow::anyhow!("Scoped vault invalid"))?;
    ensure!(
        vault.schema == 1 && vault.refs.len() <= 1024,
        "Scoped vault invalid"
    );
    for reference in &vault.refs {
        ensure!(
            is_digest(&reference.scope_digest)
                && reference.generation > 0
                && !reference.id.is_nil()
                && !reference.principal.is_empty()
                && vault
                    .refs
                    .iter()
                    .filter(|other| other.id == reference.id)
                    .count()
                    == 1
                && vault
                    .records
                    .iter()
                    .filter(|record| record.id == reference.id)
                    .count()
                    == usize::from(!reference.revoked),
            "Scoped vault invalid"
        );
        if !reference.revoked && !vault.pending.contains(&reference.id) {
            ensure!(
                vault
                    .refs
                    .iter()
                    .filter(|other| !other.revoked
                        && !vault.pending.contains(&other.id)
                        && other.scope_digest == reference.scope_digest
                        && other.purpose == reference.purpose)
                    .count()
                    == 1,
                "Scoped vault invalid"
            );
        }
    }
    ensure!(
        vault.pending.iter().all(|id| {
            vault.pending.iter().filter(|other| *other == id).count() == 1
                && vault
                    .refs
                    .iter()
                    .any(|reference| reference.id == *id && !reference.revoked)
        }),
        "Scoped vault invalid"
    );
    ensure!(
        vault.records.iter().all(|record| vault
            .refs
            .iter()
            .filter(|reference| reference.id == record.id && !reference.revoked)
            .count()
            == 1),
        "Scoped vault invalid"
    );
    Ok(vault)
}

fn save(path: &Path, vault: &Vault) -> Result<()> {
    ensure!(vault.refs.len() <= 1024, "Scoped vault capacity reached");
    let clear = serde_json::to_vec(vault)?;
    ensure!(
        clear.len() <= MAX_VAULT_BYTES,
        "Scoped vault capacity reached"
    );
    let protected =
        protect_secret(&clear).map_err(|_| anyhow::anyhow!("Scoped vault protection failed"))?;
    ensure!(
        protected.len() <= MAX_VAULT_BYTES,
        "Scoped vault capacity reached"
    );
    atomic_write(path, &protected).map_err(|_| anyhow::anyhow!("Scoped vault write failed"))
}

pub(crate) fn save_scoped_at(
    path: &Path,
    scope_digest: &str,
    purpose: CredentialPurpose,
    secret: SecretCredential,
) -> Result<ScopedCredentialRef> {
    ensure!(
        is_digest(scope_digest)
            && !secret.username.trim().is_empty()
            && secret.username.len() <= 512
            && !secret.username.chars().any(char::is_control),
        "Invalid credential scope/principal"
    );
    let _guard = lock(path)?;
    let mut vault = load(path)?;
    let generation = vault
        .refs
        .iter()
        .filter(|r| r.scope_digest == scope_digest && r.purpose == purpose)
        .map(|r| r.generation)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Credential generation exhausted"))?;
    let retired: Vec<_> = vault
        .refs
        .iter()
        .filter(|r| r.scope_digest == scope_digest && r.purpose == purpose)
        .map(|r| r.id)
        .collect();
    for reference in &mut vault.refs {
        if retired.contains(&reference.id) {
            reference.revoked = true;
        }
    }
    vault.records.retain(|r| !retired.contains(&r.id));
    vault.pending.retain(|id| !retired.contains(id));
    let reference = ScopedCredentialRef {
        id: Uuid::new_v4(),
        scope_digest: scope_digest.to_owned(),
        purpose,
        generation,
        principal: secret.username.clone(),
        context: scope_digest.to_owned(),
        created_at: Utc::now(),
        revoked: false,
    };
    let protected = protect_secret(&serde_json::to_vec(&secret)?)
        .map_err(|_| anyhow::anyhow!("Credential protection failed"))?;
    vault.records.push(ProtectedRecord {
        id: reference.id,
        bytes: protected,
    });
    vault.refs.push(reference.clone());
    save(path, &vault)?;
    Ok(reference)
}

pub(crate) fn prepare_scoped_at(
    path: &Path,
    scope_digest: &str,
    purpose: CredentialPurpose,
    expected_current: Option<Uuid>,
    secret: SecretCredential,
) -> Result<ScopedCredentialRef> {
    ensure!(
        is_digest(scope_digest)
            && !secret.username.trim().is_empty()
            && secret.username.len() <= 512
            && !secret.username.chars().any(char::is_control),
        "Invalid credential scope/principal"
    );
    let _guard = lock(path)?;
    let mut vault = load(path)?;
    let current = vault.refs.iter().find(|reference| {
        !reference.revoked
            && !vault.pending.contains(&reference.id)
            && reference.scope_digest == scope_digest
            && reference.purpose == purpose
    });
    ensure!(
        current.map(|reference| reference.id) == expected_current,
        "Credential authority changed"
    );
    let generation = vault
        .refs
        .iter()
        .filter(|r| r.scope_digest == scope_digest && r.purpose == purpose)
        .map(|r| r.generation)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Credential generation exhausted"))?;
    let reference = ScopedCredentialRef {
        id: Uuid::new_v4(),
        scope_digest: scope_digest.to_owned(),
        purpose,
        generation,
        principal: secret.username.clone(),
        context: scope_digest.to_owned(),
        created_at: Utc::now(),
        revoked: false,
    };
    let protected = protect_secret(&serde_json::to_vec(&secret)?)
        .map_err(|_| anyhow::anyhow!("Credential protection failed"))?;
    vault.records.push(ProtectedRecord {
        id: reference.id,
        bytes: protected,
    });
    vault.pending.push(reference.id);
    vault.refs.push(reference.clone());
    save(path, &vault)?;
    Ok(reference)
}

pub(crate) fn commit_scoped_at(path: &Path, new_id: Uuid, previous_id: Option<Uuid>) -> Result<()> {
    let _guard = lock(path)?;
    let mut vault = load(path)?;
    let new = vault
        .refs
        .iter()
        .find(|r| r.id == new_id && !r.revoked)
        .filter(|r| vault.pending.contains(&r.id))
        .ok_or_else(|| anyhow::anyhow!("Prepared credential missing"))?
        .clone();
    let current = vault.refs.iter().find(|r| {
        !r.revoked
            && !vault.pending.contains(&r.id)
            && r.scope_digest == new.scope_digest
            && r.purpose == new.purpose
    });
    ensure!(
        current.map(|r| r.id) == previous_id,
        "Credential authority changed"
    );
    if let Some(old) = current {
        ensure!(
            old.generation < new.generation,
            "Credential generation changed"
        );
    }
    for reference in &mut vault.refs {
        if Some(reference.id) == previous_id {
            reference.revoked = true;
        }
    }
    vault.records.retain(|r| Some(r.id) != previous_id);
    vault.pending.retain(|id| *id != new_id);
    save(path, &vault)
}

pub(crate) fn abort_scoped_at(path: &Path, id: Uuid) -> Result<()> {
    let _guard = lock(path)?;
    let mut vault = load(path)?;
    ensure!(vault.pending.contains(&id), "Prepared credential missing");
    vault.pending.retain(|candidate| *candidate != id);
    for reference in &mut vault.refs {
        if reference.id == id {
            reference.revoked = true;
        }
    }
    vault.records.retain(|record| record.id != id);
    save(path, &vault)
}

pub(crate) fn revoke_scoped_at(path: &Path, id: Uuid) -> Result<()> {
    let _guard = lock(path)?;
    let mut vault = load(path)?;
    ensure!(
        vault.refs.iter().any(|r| r.id == id),
        "Credential reference missing"
    );
    for reference in &mut vault.refs {
        if reference.id == id {
            reference.revoked = true;
        }
    }
    vault.records.retain(|r| r.id != id);
    vault.pending.retain(|candidate| *candidate != id);
    save(path, &vault)
}

impl SecretResolver for PersistentSecretResolver {
    fn resolve(
        &self,
        scope: &CredentialScope,
        purpose: CredentialPurpose,
    ) -> Result<ResolvedSecret> {
        ensure!(
            scope.purpose == purpose && is_digest(&scope.context_digest),
            "Credential scope mismatch"
        );
        let _guard = lock(&self.path)?;
        let vault = load(&self.path)?;
        let reference = vault
            .refs
            .iter()
            .find(|r| r.id == scope.reference)
            .ok_or_else(|| anyhow::anyhow!("Credential unavailable or revoked"))?;
        ensure!(
            !reference.revoked
                && reference.purpose == purpose
                && reference.scope_digest == scope.context_digest
                && reference.generation == scope.generation
                && reference.principal == scope.principal
                && reference.context == scope.context,
            "Credential scope mismatch"
        );
        let record = vault
            .records
            .iter()
            .find(|r| r.id == reference.id)
            .ok_or_else(|| anyhow::anyhow!("Credential unavailable or revoked"))?;
        let clear = unprotect_secret(&record.bytes)
            .map_err(|_| anyhow::anyhow!("Credential unavailable"))?;
        let secret: SecretCredential = serde_json::from_slice(&clear)
            .map_err(|_| anyhow::anyhow!("Credential unavailable"))?;
        ensure!(
            secret.username == reference.principal,
            "Credential principal changed"
        );
        Ok(ResolvedSecret { secret })
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
