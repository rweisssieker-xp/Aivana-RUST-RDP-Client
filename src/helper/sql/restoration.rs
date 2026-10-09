//! Durable ownership of the original production effect and one-shot recovery.
//! A staging index identity is never accepted here.

use crate::helper::{
    approval::DispatchPermit,
    journal::{ActionJournal, IntentRecord, IntentState},
    scope::BoundScope,
    sql::changes::{NativeActionProof, NativeActionState, NativePreflight},
    store::HelperStore,
};
use crate::helper_action::{SqlAction, digest, valid_digest};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RECEIPT_SCHEMA: u16 = 1;
const MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedProductionIndex {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) definition_sha256: String,
    pub(crate) marker_sha256: String,
    pub(crate) marker: String,
}

pub(crate) struct ObservedIndex<'a> {
    pub(crate) id: u64,
    pub(crate) name: &'a str,
    pub(crate) definition: &'a str,
    pub(crate) valid: bool,
    pub(crate) marker: Option<&'a str>,
}

pub(crate) fn verify_original_index(
    receipt: &ProductionReceipt,
    physical_sha256: &str,
    database_id: u64,
    object_id: u64,
    guard_sha256: &str,
    observed: &[ObservedIndex<'_>],
) -> Result<()> {
    let original = receipt
        .index
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Statistics have no index restoration"))?;
    ensure!(
        physical_sha256 == receipt.physical_sha256
            && database_id == receipt.database_id
            && object_id == receipt.object_id
            && guard_sha256 == receipt.restoration_guard_sha256,
        "Original production database, table, grants, or configuration changed"
    );
    let matching = observed
        .iter()
        .filter(|candidate| candidate.id == original.id || candidate.name == original.name)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "Created index missing, duplicated, or replaced"
    );
    let index = matching[0];
    ensure!(
        index.id == original.id
            && index.name == original.name
            && index.valid
            && index.marker == Some(original.marker.as_str())
            && digest(
                b"relayne-helper-created-index-definition-v1",
                &index.definition
            )? == original.definition_sha256
            && digest(b"relayne-helper-created-index-marker-v1", &original.marker)?
                == original.marker_sha256,
        "Original run ownership, index identity, or definition changed"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionReceipt {
    schema: u16,
    run_id: Uuid,
    case_id: Uuid,
    approval_id: Uuid,
    consume_id: Uuid,
    binding_fingerprint: String,
    rehearsal_sha256: String,
    scope: BoundScope,
    physical_sha256: String,
    database_id: u64,
    object_id: u64,
    restoration_guard_sha256: String,
    action: SqlAction,
    before_sha256: String,
    after_sha256: String,
    index: Option<OwnedProductionIndex>,
    created_at: DateTime<Utc>,
    content_sha256: String,
}

impl ProductionReceipt {
    pub(crate) fn from_native(
        permit: &DispatchPermit,
        rehearsal_sha256: &str,
        scope: BoundScope,
        before: &NativePreflight,
        proof: &NativeActionProof,
    ) -> Result<Self> {
        ensure!(
            proof.state() == NativeActionState::Verified,
            "Production effect not verified"
        );
        let identity = proof.identity();
        ensure!(
            identity.run_id() == permit.binding().run_id
                && identity.case_id() == permit.binding().case_id
                && identity.approval_id() == permit.receipt().approval_id
                && identity.consume_id() == permit.receipt().consume_id
                && identity.binding_fingerprint() == permit.binding().fingerprint()?
                && before.before_sha256() == proof.before_sha256()
                && before.before_sha256() == permit.binding().before_sha256
                && scope.digest()? == permit.binding().scope_sha256
                && before.credential_scope_sha256() == permit.binding().credential_scope_sha256,
            "Production native proof differs approved run"
        );
        let index = match &permit.binding().action {
            SqlAction::PostgresCreateIndex { index, .. }
            | SqlAction::SqlServerCreateIndex { index, .. } => {
                let marker = proof
                    .ownership_marker()
                    .ok_or_else(|| anyhow::anyhow!("Run marker missing"))?;
                Some(OwnedProductionIndex {
                    id: proof
                        .created_index_id()
                        .ok_or_else(|| anyhow::anyhow!("Index identity missing"))?,
                    name: index.clone(),
                    definition_sha256: proof
                        .created_index_definition_sha256()
                        .ok_or_else(|| anyhow::anyhow!("Index definition missing"))?
                        .to_owned(),
                    marker_sha256: proof
                        .ownership_marker_sha256()
                        .ok_or_else(|| anyhow::anyhow!("Marker proof missing"))?
                        .to_owned(),
                    marker: marker.to_owned(),
                })
            }
            _ => {
                ensure!(
                    proof.created_index_id().is_none() && proof.ownership_marker().is_none(),
                    "Statistics action has unexpected index proof"
                );
                None
            }
        };
        let mut receipt = Self {
            schema: RECEIPT_SCHEMA,
            run_id: identity.run_id(),
            case_id: identity.case_id(),
            approval_id: identity.approval_id(),
            consume_id: identity.consume_id(),
            binding_fingerprint: identity.binding_fingerprint().to_owned(),
            rehearsal_sha256: rehearsal_sha256.to_owned(),
            scope,
            physical_sha256: before.physical_digest()?,
            database_id: before.database_id(),
            object_id: before.object_id(),
            restoration_guard_sha256: before.restoration_guard_digest()?,
            action: permit.binding().action.clone(),
            before_sha256: proof.before_sha256().to_owned(),
            after_sha256: proof
                .after_sha256()
                .ok_or_else(|| anyhow::anyhow!("After-state missing"))?
                .to_owned(),
            index,
            created_at: Utc::now(),
            content_sha256: String::new(),
        };
        receipt.content_sha256 = receipt.fingerprint()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn fingerprint(&self) -> Result<String> {
        let mut content = self.clone();
        content.content_sha256.clear();
        digest(b"relayne-helper-production-receipt-v1", &content)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == RECEIPT_SCHEMA
                && self.run_id != Uuid::nil()
                && self.case_id != Uuid::nil()
                && self.approval_id != Uuid::nil()
                && self.consume_id != Uuid::nil()
                && self.database_id > 0
                && self.object_id > 0
                && self.created_at <= Utc::now()
                && self.scope.digest()? == self.action.object().scope_sha256
                && self.content_sha256 == self.fingerprint()?,
            "Invalid protected production receipt"
        );
        for value in [
            &self.binding_fingerprint,
            &self.rehearsal_sha256,
            &self.physical_sha256,
            &self.restoration_guard_sha256,
            &self.before_sha256,
            &self.after_sha256,
        ] {
            ensure!(valid_digest(value), "Invalid production receipt digest");
        }
        if let Some(index) = &self.index {
            let action_index = match &self.action {
                SqlAction::PostgresCreateIndex { index, .. }
                | SqlAction::SqlServerCreateIndex { index, .. } => index,
                _ => anyhow::bail!("Statistics action has unexpected index proof"),
            };
            ensure!(
                !self.action.is_statistics()
                    && index.id > 0
                    && index.name == *action_index
                    && valid_digest(&index.definition_sha256)
                    && valid_digest(&index.marker_sha256)
                    && index.marker.starts_with("Relayne.CreatedByRunV1:")
                    && digest(b"relayne-helper-created-index-marker-v1", &index.marker)?
                        == index.marker_sha256,
                "Production index ownership incomplete"
            );
        } else {
            ensure!(self.action.is_statistics(), "Created index proof missing");
        }
        Ok(())
    }

    pub(crate) fn validate_native_proof(
        &self,
        proof: &NativeActionProof,
        intent: &IntentRecord,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            load_production_receipt(self.run_id)?.content_sha256 == self.content_sha256,
            "Protected production receipt differs"
        );
        let identity = proof.identity();
        ensure!(
            proof.state() == NativeActionState::Verified
                && self.run_id == identity.run_id()
                && self.case_id == identity.case_id()
                && self.approval_id == identity.approval_id()
                && self.consume_id == identity.consume_id()
                && self.binding_fingerprint == identity.binding_fingerprint()
                && self.binding_fingerprint == intent.binding_fingerprint
                && self.action.object().scope_sha256 == identity.scope_sha256()
                && digest(b"relayne-helper-sql-action-v1", &self.action)?
                    == identity.action_sha256()
                && self.before_sha256 == proof.before_sha256()
                && proof.after_sha256() == Some(self.after_sha256.as_str())
                && self.index.as_ref().map(|index| index.id) == proof.created_index_id()
                && self
                    .index
                    .as_ref()
                    .map(|index| index.definition_sha256.as_str())
                    == proof.created_index_definition_sha256()
                && self
                    .index
                    .as_ref()
                    .map(|index| index.marker_sha256.as_str())
                    == proof.ownership_marker_sha256(),
            "Production receipt does not match sealed native outcome"
        );
        Ok(())
    }

    pub(crate) fn save(&self) -> Result<()> {
        self.validate()?;
        let path = receipt_path(self.run_id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = lock(&path)?;
        ensure!(
            !path.exists(),
            "Immutable production receipt already exists"
        );
        let clear = serde_json::to_vec(self)?;
        ensure!(clear.len() <= MAX_BYTES, "Production receipt exceeds bound");
        let protected = crate::security::protect_secret(&clear)?;
        ensure!(
            protected.len() <= MAX_BYTES,
            "Protected production receipt exceeds bound"
        );
        crate::security::atomic_write(&path, &protected)
    }

    pub fn run_id(&self) -> Uuid {
        self.run_id
    }
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
    pub(crate) fn scope(&self) -> &BoundScope {
        &self.scope
    }
    pub(crate) fn action(&self) -> &SqlAction {
        &self.action
    }
    pub(crate) fn physical_sha256(&self) -> &str {
        &self.physical_sha256
    }
    pub(crate) fn database_id(&self) -> u64 {
        self.database_id
    }
    pub(crate) fn object_id(&self) -> u64 {
        self.object_id
    }
    pub(crate) fn guard_sha256(&self) -> &str {
        &self.restoration_guard_sha256
    }
    pub(crate) fn index(&self) -> Option<&OwnedProductionIndex> {
        self.index.as_ref()
    }
}

fn receipt_path(run_id: Uuid) -> Result<PathBuf> {
    ensure!(run_id != Uuid::nil(), "Production run ID missing");
    crate::security::app_data_file(&format!("relayne-helper-production-{run_id}.dpapi"))
}

fn lock(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}

pub fn load_production_receipt(run_id: Uuid) -> Result<ProductionReceipt> {
    let path = receipt_path(run_id)?;
    let _guard = lock(&path)?;
    let mut file = std::fs::File::open(path)?;
    let mut protected = Vec::new();
    file.by_ref()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut protected)?;
    ensure!(
        protected.len() <= MAX_BYTES,
        "Protected production receipt exceeds bound"
    );
    let clear = crate::security::unprotect_secret(&protected)?;
    ensure!(clear.len() <= MAX_BYTES, "Production receipt exceeds bound");
    let receipt: ProductionReceipt = serde_json::from_slice(&clear)?;
    receipt.validate()?;
    ensure!(
        receipt.run_id == run_id,
        "Production receipt run differs path"
    );
    Ok(receipt)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorationOutcome {
    Restored,
    NeedsIntervention,
    NotRestorable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestorationRecord {
    schema: u16,
    run_id: Uuid,
    production_receipt_sha256: String,
    prepared_at: DateTime<Utc>,
    outcome: Option<RestorationOutcome>,
    content_sha256: String,
}

impl RestorationRecord {
    fn new(receipt: &ProductionReceipt) -> Result<Self> {
        let mut record = Self {
            schema: 1,
            run_id: receipt.run_id(),
            production_receipt_sha256: receipt.content_sha256().to_owned(),
            prepared_at: Utc::now(),
            outcome: None,
            content_sha256: String::new(),
        };
        record.content_sha256 = record.fingerprint()?;
        Ok(record)
    }

    fn fingerprint(&self) -> Result<String> {
        let mut record = self.clone();
        record.content_sha256.clear();
        digest(b"relayne-helper-restoration-record-v1", &record)
    }

    fn validate_for(&self, receipt: &ProductionReceipt) -> Result<()> {
        ensure!(
            self.schema == 1
                && self.run_id == receipt.run_id()
                && self.production_receipt_sha256 == receipt.content_sha256()
                && self.prepared_at <= Utc::now()
                && self.content_sha256 == self.fingerprint()?,
            "Restoration record is not bound to original production effect"
        );
        Ok(())
    }

    fn finish(&mut self, outcome: RestorationOutcome) -> Result<()> {
        ensure!(self.outcome.is_none(), "Restoration was already attempted");
        self.outcome = Some(outcome);
        self.content_sha256 = self.fingerprint()?;
        Ok(())
    }
}

fn restoration_path(run_id: Uuid) -> Result<PathBuf> {
    ensure!(run_id != Uuid::nil(), "Restoration run missing");
    crate::security::app_data_file(&format!("relayne-helper-restoration-{run_id}.dpapi"))
}

fn read_restoration(path: &Path, receipt: &ProductionReceipt) -> Result<Option<RestorationRecord>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut protected = Vec::new();
    file.by_ref()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut protected)?;
    ensure!(
        protected.len() <= MAX_BYTES,
        "Protected restoration record exceeds bound"
    );
    let clear = crate::security::unprotect_secret(&protected)?;
    ensure!(clear.len() <= MAX_BYTES, "Restoration record exceeds bound");
    let record: RestorationRecord = serde_json::from_slice(&clear)?;
    record.validate_for(receipt)?;
    Ok(Some(record))
}

fn write_restoration(
    path: &Path,
    record: &RestorationRecord,
    receipt: &ProductionReceipt,
) -> Result<()> {
    record.validate_for(receipt)?;
    let clear = serde_json::to_vec(record)?;
    ensure!(clear.len() <= MAX_BYTES, "Restoration record exceeds bound");
    let protected = crate::security::protect_secret(&clear)?;
    ensure!(
        protected.len() <= MAX_BYTES,
        "Protected restoration record exceeds bound"
    );
    crate::security::atomic_write(path, &protected)
}

pub(crate) fn require_terminal_restoration(
    receipt: &ProductionReceipt,
    outcome: RestorationOutcome,
) -> Result<()> {
    let record = read_restoration(&restoration_path(receipt.run_id())?, receipt)?
        .ok_or_else(|| anyhow::anyhow!("Protected restoration outcome missing"))?;
    ensure!(
        record.outcome == Some(outcome),
        "Protected restoration outcome differs journal"
    );
    Ok(())
}

pub async fn restore_index(
    run_id: Uuid,
    journal: &mut ActionJournal,
    cancel: CancellationToken,
) -> Result<RestorationOutcome> {
    let journal_path = journal.storage_path().to_path_buf();
    let receipt = load_production_receipt(run_id)?;
    let path = restoration_path(run_id)?;
    let case_path = HelperStore::path()?;
    let existing = HelperStore::inspect_locked(&case_path, |_store| {
        // One short OS lock covers the actual protected record and journal
        // claim under the same CASE gate as later target dispatch.
        let _guard = lock(&path)?;
        *journal = ActionJournal::load(&journal_path)?;
        let original = journal
            .intents()
            .iter()
            .find(|intent| intent.run_id == run_id)
            .ok_or_else(|| anyhow::anyhow!("Original production action missing"))?;
        ensure!(
            original.state == IntentState::Verified
                && original.case_id == receipt.case_id
                && original.approval_id == receipt.approval_id
                && original.consume_id == receipt.consume_id
                && original.binding_fingerprint == receipt.binding_fingerprint
                && original.native_receipt_sha256.as_deref() == Some(receipt.content_sha256()),
            "Restoration has no exact verified production action"
        );
        if let Some(previous) = read_restoration(&path, &receipt)? {
            if let Some(outcome) = previous.outcome {
                journal.record_restoration_outcome(&receipt, outcome)?;
                return Ok(Some(outcome));
            }
            // In-flight or crashed attempt. Neither state permits another SQL
            // dispatch; pending journal authority blocks later targets.
            return Ok(Some(RestorationOutcome::NeedsIntervention));
        }
        if original.restoration_pending {
            return Ok(Some(RestorationOutcome::NeedsIntervention));
        }
        ensure!(
            original.restoration_outcome.is_none(),
            "Restoration already terminal"
        );
        journal.record_restoration_intent(&receipt)?;
        #[cfg(test)]
        if RESTORATION_TEST_FAULT
            .compare_exchange(
                1,
                0,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            anyhow::bail!("Injected fault after durable restoration journal claim");
        }
        let record = RestorationRecord::new(&receipt)?;
        write_restoration(&path, &record, &receipt)?;
        #[cfg(test)]
        if RESTORATION_TEST_FAULT
            .compare_exchange(
                2,
                0,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            anyhow::bail!("Injected fault after protected restoration record claim");
        }
        Ok(None)
    })?;
    if let Some(outcome) = existing {
        return Ok(outcome);
    }
    let outcome = if receipt.index().is_none() {
        RestorationOutcome::NotRestorable
    } else {
        super::changes::restore_exact_production_index(&receipt, cancel).await
    };
    HelperStore::inspect_locked(&case_path, |_store| {
        let _guard = lock(&path)?;
        *journal = ActionJournal::load(&journal_path)?;
        let mut record = read_restoration(&path, &receipt)?.ok_or_else(|| {
            anyhow::anyhow!("Durable restoration intent missing after native attempt")
        })?;
        record.finish(outcome)?;
        write_restoration(&path, &record, &receipt)?;
        journal.record_restoration_outcome(&receipt, outcome)
    })?;
    Ok(outcome)
}

#[cfg(test)]
static RESTORATION_TEST_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
fn arm_restoration_test_fault(phase: u8) {
    RESTORATION_TEST_FAULT.store(phase, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
#[path = "restoration_tests.rs"]
mod tests;
