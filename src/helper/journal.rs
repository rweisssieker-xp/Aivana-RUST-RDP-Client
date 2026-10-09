//! Protected local authority journal. Ambiguous launches remain unresolved until
//! independently observed; reopening a journal never replays an intent.
use super::approval::DispatchPermit;
use super::sql::changes::{NativeActionProof, NativeActionState};
use super::sql::rehearsal::SqlRehearsalReceipt;
use super::sql::restoration::{ProductionReceipt, RestorationOutcome};
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
    #[serde(default)]
    pub outcome_note: Option<String>,
    pub outcome_acknowledged: bool,
    #[serde(default)]
    pub outcome_corrections: Vec<OutcomeDelivery>,
    #[serde(default)]
    pub native_receipt_sha256: Option<String>,
    #[serde(default)]
    pub native_after_sha256: Option<String>,
    #[serde(default)]
    pub restoration_outcome: Option<RestorationOutcome>,
    #[serde(default)]
    pub restoration_pending: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeDelivery {
    pub event: ActionOutcomeEventV2,
    #[serde(default)]
    pub operator_note: Option<String>,
    pub acknowledged: bool,
}

fn operator_note_matches(event: &ActionOutcomeEventV2, note: Option<&str>) -> Result<bool> {
    match note {
        Some(note) => Ok(note.trim().len() >= 3
            && note.len() <= 256
            && !note.chars().any(char::is_control)
            && event.operator_reference_sha256.as_deref()
                == Some(
                    crate::helper_approval::operator_reference_digest(
                        event.event_id,
                        event.approval_id,
                        event.run_id,
                        note,
                    )?
                    .as_str(),
                )),
        None => Ok(event.operator_reference_sha256.is_none()),
    }
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
    #[cfg(test)]
    pub(crate) fn test_seed_verified_production(
        &mut self,
        run_id: Uuid,
        case_id: Uuid,
        approval_id: Uuid,
        consume_id: Uuid,
        binding_fingerprint: String,
        production_receipt_sha256: String,
        after_sha256: String,
    ) -> Result<()> {
        let now = Utc::now();
        self.intents.push(IntentRecord {
            id: Uuid::new_v4(),
            case_id,
            approval_id,
            consume_id,
            run_id,
            binding_fingerprint,
            state: IntentState::Verified,
            prepared_at: now,
            updated_at: now,
            outcome_event: None,
            outcome_note: None,
            outcome_acknowledged: false,
            outcome_corrections: Vec::new(),
            native_receipt_sha256: Some(production_receipt_sha256),
            native_after_sha256: Some(after_sha256),
            restoration_outcome: None,
            restoration_pending: false,
        });
        self.save()
    }
    pub(crate) fn storage_path(&self) -> &Path {
        &self.path
    }
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
            ensure!(
                item.native_receipt_sha256
                    .as_deref()
                    .is_none_or(crate::helper_action::valid_digest)
                    && item
                        .native_after_sha256
                        .as_deref()
                        .is_none_or(crate::helper_action::valid_digest),
                "Invalid native SQL outcome reference"
            );
            ensure!(
                !(item.restoration_pending && item.restoration_outcome.is_some())
                    && (!(item.restoration_pending || item.restoration_outcome.is_some())
                        || (item.state == IntentState::Verified
                            && item.native_receipt_sha256.is_some())),
                "Restoration state is not bound to verified native effect"
            );
            if let Some(event) = &item.outcome_event {
                ensure!(
                    event.approval_id == item.approval_id
                        && event.consume_id == item.consume_id
                        && event.run_id == item.run_id
                        && event.fingerprint == item.binding_fingerprint
                        && event.sequence == 1
                        && event.previous_event_id.is_none(),
                    "Invalid outcome event binding"
                );
                ensure!(
                    operator_note_matches(event, item.outcome_note.as_deref())?,
                    "Invalid protected operator note binding"
                );
            }
            let mut previous = item.outcome_event.as_ref();
            for correction in &item.outcome_corrections {
                let event = &correction.event;
                ensure!(
                    previous.is_some_and(|prior| event.sequence == prior.sequence + 1
                        && event.previous_event_id == Some(prior.event_id)
                        && matches!(
                            prior.outcome,
                            ActionOutcomeV2::OutcomeUnknown | ActionOutcomeV2::NeedsIntervention
                        ))
                        && event.approval_id == item.approval_id
                        && event.consume_id == item.consume_id
                        && event.run_id == item.run_id
                        && event.fingerprint == item.binding_fingerprint,
                    "Invalid outcome correction chain"
                );
                ensure!(
                    operator_note_matches(event, correction.operator_note.as_deref())?,
                    "Invalid protected correction note binding"
                );
                previous = Some(event);
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

    /// Reload the protected journal at the last boundary before native contact.
    /// Its binding fingerprint covers the reviewed action, scope and before-state.
    pub(crate) fn require_durable_started(
        path: &Path,
        id: IntentId,
        permit: &DispatchPermit,
    ) -> Result<Self> {
        let now = Utc::now();
        permit.binding().validate(now)?;
        let fingerprint = permit.binding().fingerprint()?;
        ensure!(
            permit.receipt().fingerprint == fingerprint
                && permit.receipt().organization_sha256 == permit.binding().organization_sha256
                && permit.receipt().approval_id != Uuid::nil()
                && permit.receipt().consume_id != Uuid::nil(),
            "Consumed approval does not bind the native action"
        );
        let journal = Self::load(path)?;
        let matches = journal
            .intents
            .iter()
            .filter(|intent| intent.id == id)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "Durable native intent missing or duplicate"
        );
        let intent = matches[0];
        ensure!(
            intent.state == IntentState::DispatchStarted
                && intent.case_id == permit.binding().case_id
                && intent.run_id == permit.binding().run_id
                && intent.approval_id == permit.receipt().approval_id
                && intent.consume_id == permit.receipt().consume_id
                && intent.binding_fingerprint == fingerprint
                && intent.outcome_event.is_none()
                && intent.native_receipt_sha256.is_none()
                && intent.native_after_sha256.is_none(),
            "Durable native intent differs from consumed dispatch"
        );
        Ok(journal)
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
        ensure!(
            permit.receipt().fingerprint == permit.binding().fingerprint()?
                && permit.receipt().organization_sha256 == permit.binding().organization_sha256,
            "Consumed approval binding differs from native intent"
        );
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
            outcome_note: None,
            outcome_acknowledged: false,
            outcome_corrections: Vec::new(),
            native_receipt_sha256: None,
            native_after_sha256: None,
            restoration_outcome: None,
            restoration_pending: false,
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
        ensure!(
            observed.is_none(),
            "Use an atomic outcome report for terminal transitions"
        );
        self.reconcile_inner(run_id, None, false)
    }
    fn reconcile_inner(
        &mut self,
        run_id: Uuid,
        observed: Option<IntentState>,
        persist: bool,
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
                        IntentState::DispatchStarted
                            | IntentState::OutcomeUnknown
                            | IntentState::NeedsIntervention
                    ),
                    "Cannot reconcile an unlaunched run"
                );
                if matches!(
                    item.state,
                    IntentState::OutcomeUnknown | IntentState::NeedsIntervention
                ) {
                    ensure!(
                        matches!(
                            state,
                            IntentState::Verified
                                | IntentState::Failed
                                | IntentState::NeedsIntervention
                        ) && state != item.state,
                        "Invalid outcome correction"
                    );
                    ensure!(
                        item.outcome_corrections
                            .last()
                            .map(|d| d.acknowledged)
                            .unwrap_or(item.outcome_acknowledged),
                        "Report and acknowledge previous outcome before correction"
                    );
                }
                item.state = state;
                item.updated_at = Utc::now();
            }
            item.state
        };
        if observed.is_some() && persist {
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
        self.queue_outcome_inner(id, outcome, None, true)
    }
    fn queue_outcome_inner(
        &mut self,
        id: IntentId,
        outcome: ActionOutcomeV2,
        operator_reference: Option<&str>,
        persist: bool,
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
        let previous = item
            .outcome_corrections
            .last()
            .map(|d| (&d.event, d.acknowledged))
            .or_else(|| {
                item.outcome_event
                    .as_ref()
                    .map(|e| (e, item.outcome_acknowledged))
            });
        if let Some((event, acknowledged)) = previous {
            if event.outcome == outcome {
                return Ok(event.clone());
            }
            ensure!(
                acknowledged,
                "Previous outcome delivery must be acknowledged before correction"
            );
            ensure!(
                matches!(
                    event.outcome,
                    ActionOutcomeV2::OutcomeUnknown | ActionOutcomeV2::NeedsIntervention
                ) && matches!(
                    outcome,
                    ActionOutcomeV2::Verified
                        | ActionOutcomeV2::Failed
                        | ActionOutcomeV2::NeedsIntervention
                ),
                "Invalid outcome correction"
            );
        }
        let event_id = Uuid::new_v4();
        let reference_sha256 = operator_reference
            .map(|note| {
                crate::helper_approval::operator_reference_digest(
                    event_id,
                    item.approval_id,
                    item.run_id,
                    note,
                )
            })
            .transpose()?;
        let event = ActionOutcomeEventV2 {
            event_id,
            sequence: previous.map_or(1, |(e, _)| e.sequence + 1),
            previous_event_id: previous.map(|(e, _)| e.event_id),
            approval_id: item.approval_id,
            consume_id: item.consume_id,
            run_id: item.run_id,
            fingerprint: item.binding_fingerprint.clone(),
            outcome,
            operator_reference_sha256: reference_sha256,
            occurred_at: Utc::now(),
        };
        if item.outcome_event.is_some() {
            item.outcome_corrections.push(OutcomeDelivery {
                event: event.clone(),
                operator_note: operator_reference.map(str::to_owned),
                acknowledged: false,
            });
        } else {
            item.outcome_event = Some(event.clone());
            item.outcome_note = operator_reference.map(str::to_owned);
        }
        item.updated_at = Utc::now();
        if persist {
            self.save()?;
        }
        Ok(event)
    }
    /// One protected write publishes both the observed state and its exact
    /// report event. A failed save leaves the caller's journal unchanged.
    pub fn observe_and_queue_outcome(
        &mut self,
        id: IntentId,
        state: IntentState,
        outcome: ActionOutcomeV2,
        operator_reference: &str,
    ) -> Result<ActionOutcomeEventV2> {
        ensure!(
            operator_reference.trim().len() >= 3
                && operator_reference.len() <= 256
                && !operator_reference.chars().any(char::is_control),
            "Operator reference must be 3–256 printable characters"
        );
        ensure!(
            matches!(
                outcome,
                ActionOutcomeV2::OutcomeUnknown | ActionOutcomeV2::NeedsIntervention
            ),
            "Operator reports cannot assert protected SQL verification"
        );
        let run_id = self
            .intents
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| anyhow::anyhow!("Run intent missing"))?
            .run_id;
        let mut next = self.clone();
        next.reconcile_inner(run_id, Some(state), false)?;
        let event = next.queue_outcome_inner(id, outcome, Some(operator_reference), false)?;
        next.save()?;
        *self = next;
        Ok(event)
    }

    /// Sealed executor result: state and exact team event are one protected
    /// journal write. A receipt reference is required for native success.
    pub(crate) fn record_native_outcome(
        &mut self,
        id: IntentId,
        proof: &NativeActionProof,
        receipt: Option<&SqlRehearsalReceipt>,
    ) -> Result<ActionOutcomeEventV2> {
        let mut next = self.clone();
        let item = next
            .intents
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| anyhow::anyhow!("Native action intent missing"))?;
        let identity = proof.identity();
        ensure!(
            item.state == IntentState::DispatchStarted
                && item.run_id == identity.run_id()
                && item.case_id == identity.case_id()
                && item.approval_id == identity.approval_id()
                && item.consume_id == identity.consume_id()
                && item.binding_fingerprint == identity.binding_fingerprint(),
            "Native action does not match the exact durable started intent"
        );
        ensure!(
            receipt.is_none() || proof.state() == NativeActionState::Verified,
            "Nonverified action cannot attach a success receipt"
        );
        if let Some(receipt) = receipt {
            receipt.validate_native_proof(proof, item)?;
        }
        let receipt_sha256 = receipt.map(SqlRehearsalReceipt::content_sha256);
        let (state, outcome) = match (proof.state(), receipt_sha256) {
            (NativeActionState::Verified, Some(_)) => {
                (IntentState::Verified, ActionOutcomeV2::Verified)
            }
            (NativeActionState::Verified, _) => (
                IntentState::NeedsIntervention,
                ActionOutcomeV2::NeedsIntervention,
            ),
            (NativeActionState::Failed, _) => (IntentState::Failed, ActionOutcomeV2::Failed),
            (NativeActionState::OutcomeUnknown, _) => {
                (IntentState::OutcomeUnknown, ActionOutcomeV2::OutcomeUnknown)
            }
            (NativeActionState::NeedsIntervention, _) => (
                IntentState::NeedsIntervention,
                ActionOutcomeV2::NeedsIntervention,
            ),
        };
        next.reconcile_inner(proof.run_id(), Some(state), false)?;
        let item = next
            .intents
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| anyhow::anyhow!("Native action intent missing"))?;
        item.native_receipt_sha256 = receipt_sha256.map(str::to_owned);
        item.native_after_sha256 = proof.after_sha256().map(str::to_owned);
        let event = next.queue_outcome_inner(id, outcome, None, false)?;
        next.save()?;
        *self = next;
        Ok(event)
    }

    /// A production Verified event can only be derived from the separately
    /// protected original-target receipt and the same sealed native proof.
    pub(crate) fn record_production_outcome(
        &mut self,
        id: IntentId,
        proof: &NativeActionProof,
        receipt: &ProductionReceipt,
    ) -> Result<ActionOutcomeEventV2> {
        let item = self
            .intents
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow::anyhow!("Production intent missing"))?;
        let identity = proof.identity();
        ensure!(
            item.state == IntentState::DispatchStarted
                && item.run_id == identity.run_id()
                && item.case_id == identity.case_id()
                && item.approval_id == identity.approval_id()
                && item.consume_id == identity.consume_id()
                && item.binding_fingerprint == identity.binding_fingerprint()
                && proof.state() == NativeActionState::Verified,
            "Production native outcome differs durable started intent"
        );
        receipt.validate_native_proof(proof, item)?;
        let mut next = self.clone();
        next.reconcile_inner(proof.run_id(), Some(IntentState::Verified), false)?;
        let item = next
            .intents
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow::anyhow!("Production intent missing"))?;
        item.native_receipt_sha256 = Some(receipt.content_sha256().to_owned());
        item.native_after_sha256 = proof.after_sha256().map(str::to_owned);
        let event = next.queue_outcome_inner(id, ActionOutcomeV2::Verified, None, false)?;
        next.save()?;
        *self = next;
        Ok(event)
    }

    pub(crate) fn record_restoration_outcome(
        &mut self,
        receipt: &ProductionReceipt,
        outcome: RestorationOutcome,
    ) -> Result<()> {
        receipt.validate()?;
        super::sql::restoration::require_terminal_restoration(receipt, outcome)?;
        ensure!(
            super::sql::restoration::load_production_receipt(receipt.run_id())?.content_sha256()
                == receipt.content_sha256(),
            "Original production receipt changed"
        );
        let mut next = self.clone();
        let item = next
            .intents
            .iter_mut()
            .find(|item| item.run_id == receipt.run_id())
            .ok_or_else(|| anyhow::anyhow!("Original production intent missing"))?;
        ensure!(
            item.state == IntentState::Verified
                && item.native_receipt_sha256.as_deref() == Some(receipt.content_sha256()),
            "Restoration does not match verified original production action"
        );
        if let Some(existing) = item.restoration_outcome {
            ensure!(existing == outcome, "Restoration outcome already recorded");
            return Ok(());
        }
        item.restoration_outcome = Some(outcome);
        item.restoration_pending = false;
        item.updated_at = Utc::now();
        next.save()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn record_restoration_intent(&mut self, receipt: &ProductionReceipt) -> Result<()> {
        receipt.validate()?;
        ensure!(
            super::sql::restoration::load_production_receipt(receipt.run_id())?.content_sha256()
                == receipt.content_sha256(),
            "Original production receipt changed"
        );
        let mut next = self.clone();
        let item = next
            .intents
            .iter_mut()
            .find(|item| item.run_id == receipt.run_id())
            .ok_or_else(|| anyhow::anyhow!("Original production intent missing"))?;
        ensure!(
            item.state == IntentState::Verified
                && item.native_receipt_sha256.as_deref() == Some(receipt.content_sha256())
                && item.restoration_outcome.is_none()
                && !item.restoration_pending,
            "Original run already restored or restoration pending"
        );
        item.restoration_pending = true;
        item.updated_at = Utc::now();
        next.save()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn has_open_intervention(&self, case_id: Uuid, current_run: Uuid) -> bool {
        self.intents.iter().any(|item| {
            item.case_id == case_id
                && (matches!(
                    item.state,
                    IntentState::NeedsIntervention | IntentState::OutcomeUnknown
                ) || (item.run_id != current_run
                    && matches!(
                        item.state,
                        IntentState::Prepared | IntentState::DispatchStarted
                    ))
                    || item.restoration_pending
                    || item.restoration_outcome == Some(RestorationOutcome::NeedsIntervention))
        })
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
                    || i.outcome_corrections
                        .iter()
                        .any(|d| d.event.event_id == ack.event_id)
            })
            .ok_or_else(|| anyhow::anyhow!("Outcome event missing"))?;
        if item
            .outcome_event
            .as_ref()
            .is_some_and(|e| e.event_id == ack.event_id)
        {
            item.outcome_acknowledged = true;
        } else if let Some(delivery) = item
            .outcome_corrections
            .iter_mut()
            .find(|d| d.event.event_id == ack.event_id)
        {
            delivery.acknowledged = true;
        }
        item.updated_at = Utc::now();
        self.save()
    }
    pub fn pending_outcomes(&self) -> impl Iterator<Item = &ActionOutcomeEventV2> {
        self.intents.iter().flat_map(|i| {
            i.outcome_event
                .iter()
                .filter(move |_| !i.outcome_acknowledged)
                .chain(
                    i.outcome_corrections
                        .iter()
                        .filter_map(|d| (!d.acknowledged).then_some(&d.event)),
                )
        })
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
pub(crate) mod tests;
