//! Bounded protected case persistence with optimistic concurrency.
use super::case::{CaseEdit, HelperCase, ProblemIntake, TicketReference};
use super::evidence::{EvidenceBinding, EvidenceEnvelope, EvidenceHold, Origin, PendingCapture};
use super::manifest::CapabilityId;
use super::scope::CredentialPurpose;
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
    cases: Vec<HelperCase>,
    #[serde(default)]
    pending_captures: Vec<PendingCapture>,
    #[serde(skip)]
    source_digest: Option<[u8; 32]>,
    // Deserializing a value is not the same as loading it under the store's CAS discipline.
    #[serde(skip)]
    opened: bool,
}

impl Default for HelperStore {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA,
            cases: vec![],
            pending_captures: vec![],
            source_digest: None,
            opened: true,
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
    pub fn cases(&self) -> &[HelperCase] {
        &self.cases
    }
    pub fn case(&self, id: Uuid) -> Option<&HelperCase> {
        self.cases.iter().find(|case| case.id() == id)
    }
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
        store.opened = true;
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
        ensure!(
            self.pending_captures.len() <= 128,
            "Pending capture capacity reached"
        );
        for pending in &self.pending_captures {
            pending.binding.validate()?;
            ensure!(
                pending.capability_version > 0,
                "Invalid pending capture version"
            );
            ensure!(
                self.case(pending.binding.case_id).is_some(),
                "Orphan pending capture"
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            ensure!(ids.insert(case.id()), "Duplicate helper case ID");
        }
        Ok(())
    }
    pub fn create(&mut self, intake: ProblemIntake) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::new(intake)?;
        let id = case.id();
        self.cases.push(case);
        Ok(id)
    }
    pub fn adopt_incident(&mut self, source: crate::incident::Source) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::from_incident(source)?;
        let id = case.id();
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
        let id = case.id();
        self.cases.push(case);
        Ok(id)
    }
    pub fn revise(&mut self, id: Uuid, expected_revision: u64, edit: CaseEdit) -> Result<u64> {
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id() == id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        case.revise(expected_revision, edit)
    }
    /// Called by the worker after a real request has been accepted. UI/import paths cannot
    /// create a live observation by simply supplying a self-consistent envelope.
    pub(crate) fn register_pending_capture(
        &mut self,
        case_id: Uuid,
        request_id: Uuid,
        scope_sha256: &str,
        run_id: Option<Uuid>,
        capability_id: CapabilityId,
        capability_version: u16,
    ) -> Result<EvidenceBinding> {
        ensure!(
            self.opened && self.pending_captures.len() < 128,
            "Pending capture unavailable/full"
        );
        ensure!(
            capability_version > 0 && !request_id.is_nil(),
            "Invalid capture request"
        );
        ensure!(
            !self
                .pending_captures
                .iter()
                .any(|p| p.binding.request_id == request_id),
            "Duplicate capture request"
        );
        let case = self
            .case(case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        let scope = case
            .scopes()
            .iter()
            .find(|s| s.digest().ok().as_deref() == Some(scope_sha256))
            .ok_or_else(|| anyhow::anyhow!("Capture scope is not reviewed in case"))?;
        ensure!(
            scope
                .credential()
                .is_none_or(|c| c.purpose != CredentialPurpose::ControlledChange),
            "Controlled-change credential cannot authorize diagnostic capture"
        );
        let binding = EvidenceBinding {
            case_id,
            case_revision: case.revision(),
            request_id,
            scope_sha256: scope.digest()?,
            credential_scope_sha256: scope.credential_scope_digest()?,
            run_id,
        };
        binding.validate()?;
        self.pending_captures.push(PendingCapture {
            binding: binding.clone(),
            capability_id,
            capability_version,
            registered_at: chrono::Utc::now(),
        });
        Ok(binding)
    }
    pub fn attach_evidence(&mut self, case_id: Uuid, envelope: EvidenceEnvelope) -> Result<()> {
        ensure!(
            self.opened,
            "Load or create a helper store before attaching evidence"
        );
        envelope.validate_shape()?;
        let case = self
            .case(case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        ensure!(
            envelope.binding.case_id == case_id
                && envelope.binding.case_revision == case.revision(),
            "Stale or wrong case evidence"
        );
        let scope = case
            .scopes()
            .iter()
            .find(|s| s.digest().ok().as_deref() == Some(&envelope.binding.scope_sha256))
            .ok_or_else(|| anyhow::anyhow!("Evidence scope not reviewed in case"))?;
        let authoritative = EvidenceBinding {
            case_id,
            case_revision: case.revision(),
            request_id: envelope.binding.request_id,
            scope_sha256: scope.digest()?,
            credential_scope_sha256: scope.credential_scope_digest()?,
            run_id: envelope.binding.run_id,
        };
        envelope.validate_ingest(&authoritative)?;
        if envelope.origin == Origin::Live {
            let pending = self
                .pending_captures
                .iter()
                .find(|p| p.binding.request_id == envelope.binding.request_id)
                .ok_or_else(|| anyhow::anyhow!("No trusted pending live capture"))?;
            envelope.validate_ingest(&pending.binding)?;
            ensure!(
                pending.capability_id == envelope.capability_id
                    && pending.capability_version == envelope.capability_version,
                "Capture capability/version mismatch"
            );
            ensure!(
                envelope.retrieved_at >= pending.registered_at - chrono::Duration::seconds(30),
                "Response predates capture request"
            );
        }
        ensure!(
            !case.evidence().iter().any(|e| e.id == envelope.id
                || (e.binding.request_id == envelope.binding.request_id
                    && e.origin == Origin::Live)),
            "Duplicate evidence/request"
        );
        let mut next = self.clone();
        next.cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .unwrap()
            .append_evidence(envelope.clone())?;
        if envelope.origin == Origin::Live {
            next.pending_captures
                .retain(|p| p.binding.request_id != envelope.binding.request_id);
        }
        next.validate()?;
        ensure!(
            serde_json::to_vec(&next)?.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached"
        );
        *self = next;
        Ok(())
    }
    pub(crate) fn set_evidence_hold(&mut self, case_id: Uuid, hold: EvidenceHold) -> Result<()> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        next.cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?
            .set_evidence_hold(hold)?;
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub(crate) fn clear_evidence_hold(&mut self, case_id: Uuid, run_id: Uuid) -> Result<()> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        next.cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?
            .clear_evidence_hold(run_id)?;
        next.validate()?;
        *self = next;
        Ok(())
    }
    /// Deliberate metadata retention maintenance, never called implicitly at capacity/save.
    pub fn prune_expired_evidence_metadata(
        &mut self,
        case_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        let removed = next
            .cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?
            .prune_expired_evidence_metadata(now)?;
        next.validate()?;
        *self = next;
        Ok(removed)
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        ensure!(self.opened, "Load or create a helper store before saving");
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
