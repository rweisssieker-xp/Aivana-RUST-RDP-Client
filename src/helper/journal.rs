//! Protected local authority journal. Ambiguous launches remain unresolved until
//! independently observed; reopening a journal never replays an intent.
use super::approval::DispatchPermit;
use crate::helper_approval::{ActionOutcomeAckV2, ActionOutcomeEventV2, ActionOutcomeV2};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const SCHEMA: u16 = 1;
const MAX_BYTES: usize = 8 * 1024 * 1024;
pub type IntentId = Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentState {
    Prepared,
    DispatchStarted,
    Verified,
    Failed,
    NeedsIntervention,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentRecord {
    pub id: IntentId,
    pub case_id: Uuid,
    pub approval_id: Uuid,
    pub consume_id: Uuid,
    pub run_id: Uuid,
    pub binding_fingerprint: String,
    pub state: IntentState,
    pub prepared_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub outcome_event: Option<ActionOutcomeEventV2>,
    pub outcome_acknowledged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRecord {
    pub case_id: Uuid,
    pub case_revision: u64,
    pub review_sha256: String,
    pub withdrawn: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionJournal {
    schema: u16,
    intents: Vec<IntentRecord>,
    reviews: Vec<ReviewRecord>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    source_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    PreparedNoEffect,
    AwaitingObservation,
    Verified,
    Failed,
    NeedsIntervention,
    OutcomeUnknown,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BYTES, "Action journal exceeds capacity");
    Ok(Some(bytes))
}
fn lock(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}
impl ActionJournal {
    pub fn path() -> Result<PathBuf> {
        crate::security::app_data_file("relayne-helper-action-journal.dpapi")
    }
    pub fn load(path: &Path) -> Result<Self> {
        let Some(bytes) = read(path)? else {
            return Ok(Self {
                schema: SCHEMA,
                intents: Vec::new(),
                reviews: Vec::new(),
                path: path.to_path_buf(),
                source_digest: None,
            });
        };
        let clear = crate::security::unprotect_secret(&bytes)?;
        ensure!(clear.len() <= MAX_BYTES, "Action journal exceeds capacity");
        let mut journal: Self = serde_json::from_slice(&clear)?;
        ensure!(
            journal.schema == SCHEMA,
            "Unsupported action journal schema"
        );
        journal.path = path.to_path_buf();
        journal.source_digest = Some(digest(&bytes));
        journal.validate()?;
        Ok(journal)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.intents.len() <= 10_000 && self.reviews.len() <= 1_000,
            "Action journal capacity/schema invalid"
        );
        let mut ids = std::collections::HashSet::new();
        let mut consumes = std::collections::HashSet::new();
        for item in &self.intents {
            ensure!(
                ids.insert(item.id)
                    && consumes.insert(item.consume_id)
                    && item.id != Uuid::nil()
                && item.case_id != Uuid::nil()
                && item.approval_id != Uuid::nil()
                    && item.run_id != Uuid::nil()
                    && crate::helper_action::valid_digest(&item.binding_fingerprint),
                "Invalid/duplicate action intent"
            );
            if let Some(event) = &item.outcome_event {
                ensure!(
                    event.approval_id == item.approval_id
                        && event.consume_id == item.consume_id
                        && event.run_id == item.run_id
                        && event.fingerprint == item.binding_fingerprint,
                    "Invalid outcome event binding"
                );
            }
            ensure!(
                !item.outcome_acknowledged || item.outcome_event.is_some(),
                "Outcome acknowledgement without event"
            );
        }
        for review in &self.reviews {
            ensure!(
                review.case_id != Uuid::nil()
                    && review.case_revision > 0
                    && crate::helper_action::valid_digest(&review.review_sha256),
                "Invalid local review"
            );
        }
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        self.validate()?;
        let raw = serde_json::to_vec(self)?;
        ensure!(raw.len() <= MAX_BYTES, "Action journal exceeds capacity");
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = lock(&self.path)?;
        ensure!(
            read(&self.path)?.as_deref().map(digest) == self.source_digest,
            "Action journal changed concurrently; reload"
        );
        let protected = crate::security::protect_secret(&raw)?;
        ensure!(
            protected.len() <= MAX_BYTES,
            "Action journal exceeds capacity"
        );
        crate::security::atomic_write(&self.path, &protected)?;
        self.source_digest = Some(digest(&protected));
        Ok(())
    }
    pub fn intents(&self) -> &[IntentRecord] {
        &self.intents
    }
    pub fn review(&self, case_id: Uuid) -> Option<&ReviewRecord> {
        self.reviews.iter().rev().find(|r| r.case_id == case_id)
    }
    /// Caller must hold the case-store coordination lock and check the current case.
    pub(crate) fn record_review_locked(
        &mut self,
        case_id: Uuid,
        case_revision: u64,
        review_sha256: String,
    ) -> Result<()> {
        ensure!(
            case_revision > 0 && crate::helper_action::valid_digest(&review_sha256),
            "Invalid review binding"
        );
        self.reviews.retain(|r| r.case_id != case_id);
        self.reviews.push(ReviewRecord {
            case_id,
            case_revision,
            review_sha256,
            withdrawn: false,
        });
        self.save()
    }
    pub(crate) fn withdraw_review_locked(&mut self, case_id: Uuid) -> Result<()> {
        if let Some(review) = self.reviews.iter_mut().find(|r| r.case_id == case_id) {
            if !review.withdrawn {
                review.withdrawn = true;
                self.save()?;
            }
        }
        Ok(())
    }
    /// Durable before the caller may enqueue/contact a target. Failure returns no id.
    pub fn record_intent(&mut self, permit: DispatchPermit) -> Result<IntentId> {
        ensure!(
            self.intents.len() < 10_000,
            "Action journal capacity reached"
        );
        ensure!(
            !self
                .intents
                .iter()
                .any(|i| i.consume_id == permit.receipt().consume_id
                    || i.run_id == permit.binding().run_id),
            "Action already journaled"
        );
        let now = Utc::now();
        permit.binding().validate(now)?;
        let id = Uuid::new_v4();
        self.intents.push(IntentRecord {
            id,
            case_id: permit.binding().case_id,
            approval_id: permit.receipt().approval_id,
            consume_id: permit.receipt().consume_id,
            run_id: permit.binding().run_id,
            binding_fingerprint: permit.receipt().fingerprint.clone(),
            state: IntentState::Prepared,
            prepared_at: now,
            updated_at: now,
            outcome_event: None,
            outcome_acknowledged: false,
        });
        self.save()?;
        Ok(id)
    }
    pub(crate) fn mark_dispatch_started(&mut self, id: IntentId) -> Result<()> {
        let item = self
            .intents
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| anyhow::anyhow!("Intent missing"))?;
        ensure!(
            item.state == IntentState::Prepared,
            "Intent already launched or unresolved"
        );
        item.state = IntentState::DispatchStarted;
        item.updated_at = Utc::now();
        self.save()
    }
    pub fn reconcile(
        &mut self,
        run_id: Uuid,
        observed: Option<IntentState>,
    ) -> Result<Reconciliation> {
        let resulting = {
            let item = self
                .intents
                .iter_mut()
                .find(|i| i.run_id == run_id)
                .ok_or_else(|| anyhow::anyhow!("Run intent missing"))?;
            if let Some(state) = observed {
                ensure!(
                    matches!(
                        state,
                        IntentState::Verified
                            | IntentState::Failed
                            | IntentState::NeedsIntervention
                            | IntentState::OutcomeUnknown
                    ),
                    "Observation must be terminal"
                );
                ensure!(
                    matches!(
                        item.state,
                        IntentState::DispatchStarted | IntentState::OutcomeUnknown
                    ),
                    "Cannot reconcile an unlaunched run"
                );
                item.state = state;
                item.updated_at = Utc::now();
            }
            item.state
        };
        if observed.is_some() {
            self.save()?;
        }
        Ok(match resulting {
            IntentState::Prepared => Reconciliation::PreparedNoEffect,
            IntentState::DispatchStarted => Reconciliation::AwaitingObservation,
            IntentState::Verified => Reconciliation::Verified,
            IntentState::Failed => Reconciliation::Failed,
            IntentState::NeedsIntervention => Reconciliation::NeedsIntervention,
            IntentState::OutcomeUnknown => Reconciliation::OutcomeUnknown,
        })
    }
    pub fn queue_outcome(
        &mut self,
        id: IntentId,
        outcome: ActionOutcomeV2,
    ) -> Result<ActionOutcomeEventV2> {
        let item = self
            .intents
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| anyhow::anyhow!("Intent missing"))?;
        let expected = match item.state {
            IntentState::Verified => ActionOutcomeV2::Verified,
            IntentState::Failed => ActionOutcomeV2::Failed,
            IntentState::NeedsIntervention => ActionOutcomeV2::NeedsIntervention,
            IntentState::OutcomeUnknown => ActionOutcomeV2::OutcomeUnknown,
            _ => anyhow::bail!("Run outcome unresolved"),
        };
        ensure!(outcome == expected, "Outcome differs from observed state");
        if let Some(event) = &item.outcome_event {
            return Ok(event.clone());
        }
        let event = ActionOutcomeEventV2 {
            event_id: Uuid::new_v4(),
            approval_id: item.approval_id,
            consume_id: item.consume_id,
            run_id: item.run_id,
            fingerprint: item.binding_fingerprint.clone(),
            outcome,
            occurred_at: Utc::now(),
        };
        item.outcome_event = Some(event.clone());
        item.updated_at = Utc::now();
        self.save()?;
        Ok(event)
    }
    pub fn acknowledge_outcome(&mut self, ack: &ActionOutcomeAckV2) -> Result<()> {
        ensure!(ack.accepted, "Team did not accept outcome");
        let item = self
            .intents
            .iter_mut()
            .find(|i| {
                i.outcome_event
                    .as_ref()
                    .is_some_and(|e| e.event_id == ack.event_id)
            })
            .ok_or_else(|| anyhow::anyhow!("Outcome event missing"))?;
        item.outcome_acknowledged = true;
        item.updated_at = Utc::now();
        self.save()
    }
    pub fn pending_outcomes(&self) -> impl Iterator<Item = &ActionOutcomeEventV2> {
        self.intents
            .iter()
            .filter(|i| !i.outcome_acknowledged)
            .filter_map(|i| i.outcome_event.as_ref())
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
