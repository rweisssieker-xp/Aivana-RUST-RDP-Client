//! Bounded protected case persistence with optimistic concurrency.
use super::case::{CaseEdit, HelperCase, ProblemIntake, TicketReference};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
use uuid::Uuid;

const STORE_SCHEMA: u16 = 1;
pub const MAX_CASES: usize = 128;
pub const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperStore {
    schema: u16,
    pub cases: Vec<HelperCase>,
    #[serde(skip)]
    source_digest: Option<[u8; 32]>,
}

impl Default for HelperStore {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA,
            cases: vec![],
            source_digest: None,
        }
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_STORE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_STORE_BYTES,
        "Helper store capacity reached; archive or export cases"
    );
    Ok(Some(bytes))
}

fn lock(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}

impl HelperStore {
    pub fn path() -> Result<std::path::PathBuf> {
        crate::security::app_data_file("relayne-helper-cases.dpapi")
    }
    pub fn load(path: &Path) -> Result<Self> {
        let Some(bytes) = read_bounded(path)? else {
            return Ok(Self::default());
        };
        let raw = crate::security::unprotect_secret(&bytes)?;
        ensure!(
            raw.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached; archive or export cases"
        );
        let mut store: Self = serde_json::from_slice(&raw)?;
        store.validate()?;
        store.source_digest = Some(digest(&bytes));
        Ok(store)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == STORE_SCHEMA,
            "Unsupported helper store schema"
        );
        ensure!(
            self.cases.len() <= MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let mut ids = std::collections::BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            ensure!(ids.insert(case.id), "Duplicate helper case ID");
        }
        Ok(())
    }
    pub fn create(&mut self, intake: ProblemIntake) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::new(intake)?;
        let id = case.id;
        self.cases.push(case);
        Ok(id)
    }
    pub fn adopt_incident(&mut self, source: crate::incident::Source) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::from_incident(source)?;
        let id = case.id;
        self.cases.push(case);
        Ok(id)
    }
    pub fn adopt_ticket(
        &mut self,
        reference: TicketReference,
        title: &str,
        description: &str,
    ) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::from_ticket(reference, title, description)?;
        let id = case.id;
        self.cases.push(case);
        Ok(id)
    }
    pub fn revise(&mut self, id: Uuid, expected_revision: u64, edit: CaseEdit) -> Result<u64> {
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id == id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        case.revise(expected_revision, edit)
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.validate()?;
        let raw = serde_json::to_vec(self)?;
        ensure!(
            raw.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached; archive or export cases"
        );
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = lock(path)?;
        let current = read_bounded(path)?.as_deref().map(digest);
        ensure!(
            current == self.source_digest,
            "Helper store changed concurrently; reload"
        );
        let protected = crate::security::protect_secret(&raw)?;
        ensure!(
            protected.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached; archive or export cases"
        );
        crate::security::atomic_write(path, &protected)?;
        self.source_digest = Some(digest(&protected));
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
