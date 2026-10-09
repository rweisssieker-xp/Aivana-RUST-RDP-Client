//! Last local authority check. Remote consent is necessary but never sufficient.
use super::credentials::{PersistentSecretResolver, SecretResolver};
use super::evidence::Eligibility;
use super::scope::CredentialPurpose;
use super::{
    case::HelperCase,
    catalog::{CatalogAction, HelperProposal},
    journal::{ActionJournal, IntentId},
    store::HelperStore,
};
use crate::helper_action::{digest, valid_digest};
use crate::helper_approval::{ActionBindingV2, ActionProof, ConsumeReceiptV2, RunKind};
use anyhow::{Result, ensure};
use chrono::Utc;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

/// Immutable observations from local collectors. A launcher must re-observe live
/// remote metadata/credential/proof before calling the case-store gate below.
pub(crate) struct DispatchObservation {
    metadata_sha256: String,
    before_sha256: String,
    credential_scope_sha256: String,
    observed_at: chrono::DateTime<Utc>,
}
/// Reserved for the native SQL collector in Task 14. No public constructor is
/// available, so stored evidence or a caller-filled DTO cannot authorize launch.
pub struct NativeDispatchProof {
    observation: DispatchObservation,
    physical_sha256: String,
    native: super::sql::changes::NativePreflight,
}
impl NativeDispatchProof {
    /// Only the closed native collector can create this proof.
    pub async fn collect(
        case: &HelperCase,
        proposal: &HelperProposal,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Self> {
        let CatalogAction::Sql { action, metadata } = &proposal.action else {
            anyhow::bail!("Only SQL actions have a native preflight")
        };
        let scope = case
            .scopes()
            .iter()
            .find(|s| s.digest().ok().as_deref() == Some(metadata.object.scope_sha256.as_str()))
            .ok_or_else(|| anyhow::anyhow!("Reviewed SQL change scope missing"))?;
        let native =
            super::sql::changes::collect_native_preflight(action, scope, metadata, cancel).await?;
        let physical_sha256 = native.physical_digest()?;
        Ok(Self {
            observation: DispatchObservation {
                metadata_sha256: native.metadata_sha256().to_owned(),
                before_sha256: native.before_sha256().to_owned(),
                credential_scope_sha256: native.credential_scope_sha256().to_owned(),
                observed_at: native.observed_at(),
            },
            physical_sha256,
            native,
        })
    }
    pub fn physical_sha256(&self) -> &str {
        &self.physical_sha256
    }
    pub(crate) fn native(&self) -> &super::sql::changes::NativePreflight {
        &self.native
    }
    pub(crate) fn observation(&self) -> &DispatchObservation {
        &self.observation
    }
    pub(crate) fn into_native(self) -> super::sql::changes::NativePreflight {
        self.native
    }
}

/// Prepares metadata for a staged consent request from the current reviewed case.
/// This is not a dispatch readiness verdict: privilege and isolated rehearsal are
/// still outstanding until the real SQL executor verifies them.
pub fn staged_request_binding(
    case: &HelperCase,
    proposal: &HelperProposal,
    organization_sha256: String,
    native: &NativeDispatchProof,
    mapping: &super::sql::rehearsal::SqlTrialMapping,
) -> Result<ActionBindingV2> {
    let now = Utc::now();
    ensure!(
        valid_digest(&organization_sha256),
        "Unreviewed team organization identity"
    );
    ensure!(
        proposal.case_id == case.id() && proposal.case_revision == case.revision(),
        "Stale proposal"
    );
    let CatalogAction::Sql { action, metadata } = &proposal.action else {
        anyhow::bail!("Service recipes use existing service authority")
    };
    action.validate(metadata)?;
    let scope = case
        .scopes()
        .iter()
        .find(|s| s.digest().ok().as_deref() == Some(metadata.object.scope_sha256.as_str()))
        .ok_or_else(|| anyhow::anyhow!("SQL scope missing"))?;
    ensure!(
        scope
            .credential()
            .is_some_and(|c| c.purpose == CredentialPurpose::ControlledChange),
        "Controlled-change credential scope missing"
    );
    let resource = scope.resource_digest()?;
    let _evidence = case
        .evidence()
        .iter()
        .find(|e| {
            e.content_sha256 == metadata.source_evidence_sha256
                && case.scopes().iter().any(|read| {
                    read.credential()
                        .is_some_and(|credential| credential.purpose == CredentialPurpose::Read)
                        && read.resource_digest().ok().as_deref() == Some(resource.as_str())
                        && read.digest().ok().as_deref() == Some(e.binding.scope_sha256.as_str())
                        && read.credential_scope_digest().ok().as_deref()
                            == Some(e.binding.credential_scope_sha256.as_str())
                })
                && e.eligibility(now, chrono::Duration::seconds(119)) == Eligibility::Eligible
        })
        .ok_or_else(|| anyhow::anyhow!("Fresh live SQL before-state evidence missing"))?;
    ensure!(
        case.plan()
            .is_some_and(|p| digest(b"relayne-helper-reviewed-plan-v1", p)
                .ok()
                .as_deref()
                == Some(proposal.plan_sha256.as_str())),
        "Reviewed plan changed"
    );
    let review_sha256 = proposal.review_digest()?;
    let metadata_sha256 = digest(b"relayne-helper-sql-metadata-v2", metadata)?;
    let credential_scope_sha256 = scope.credential_scope_digest()?;
    mapping.validate()?;
    ensure!(
        mapping.case_id == case.id()
            && mapping.case_revision == case.revision()
            && mapping.production_scope_sha256 == scope.digest()?
            && mapping.production_physical_sha256 == native.physical_sha256()
            && mapping.action_sha256 == digest(b"relayne-helper-sql-action-v1", action)?,
        "Reviewed staging mapping differs live production action"
    );
    ensure!(
        native.observation.metadata_sha256 == metadata_sha256
            && native.observation.credential_scope_sha256 == credential_scope_sha256
            && valid_digest(&native.observation.before_sha256)
            && native.observation.observed_at <= now
            && now.signed_duration_since(native.observation.observed_at)
                < chrono::Duration::seconds(120),
        "Fresh native SQL preflight differs reviewed action"
    );
    let binding = ActionBindingV2 {
        version: 2,
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        run_id: Uuid::new_v4(),
        run_kind: RunKind::Rehearsal,
        organization_sha256,
        scope_sha256: scope.digest()?,
        credential_scope_sha256: credential_scope_sha256.clone(),
        action_version: proposal.action_version,
        action: action.clone(),
        metadata_sha256: metadata_sha256.clone(),
        before_sha256: native.observation.before_sha256.clone(),
        plan_sha256: proposal.plan_sha256.clone(),
        verification_sha256: digest(
            b"relayne-helper-reviewed-verification-v2",
            &proposal.verification,
        )?,
        proof: ActionProof::StagingReviewProof {
            review_id: Uuid::new_v4(),
            review_sha256,
            mapping_sha256: mapping.fingerprint()?,
            staging_scope_sha256: mapping.staging_scope_sha256.clone(),
            staging_physical_sha256: mapping.staging_physical_sha256.clone(),
            expires_at: now + chrono::Duration::minutes(5),
        },
        restoration: proposal.restoration.clone(),
        statistics_limit_acknowledged: proposal.statistics_limit_acknowledged,
        captured_at: now,
        expires_at: now + chrono::Duration::minutes(3),
    };
    binding.validate(now)?;
    Ok(binding)
}

pub fn production_request_binding(
    case: &HelperCase,
    proposal: &HelperProposal,
    organization_sha256: String,
    native: &NativeDispatchProof,
    rehearsal: &super::sql::rehearsal::SqlRehearsalReceipt,
    journal: &ActionJournal,
) -> Result<ActionBindingV2> {
    let now = Utc::now();
    ensure!(
        valid_digest(&organization_sha256),
        "Unreviewed team organization identity"
    );
    ensure!(
        proposal.case_id == case.id() && proposal.case_revision == case.revision(),
        "Stale production proposal"
    );
    let CatalogAction::Sql { action, metadata } = &proposal.action else {
        anyhow::bail!("Only typed SQL actions can be promoted")
    };
    action.validate(metadata)?;
    let scope = case
        .scopes()
        .iter()
        .find(|scope| scope.digest().ok().as_deref() == Some(metadata.object.scope_sha256.as_str()))
        .ok_or_else(|| anyhow::anyhow!("Production scope missing"))?;
    ensure!(
        scope
            .credential()
            .is_some_and(|credential| credential.purpose == CredentialPurpose::ControlledChange)
            && native.physical_sha256() == rehearsal.production_physical_sha256(),
        "Production scope or physical database differs rehearsal"
    );
    let expires_at = std::cmp::min(now + chrono::Duration::minutes(3), rehearsal.expires_at());
    let binding = ActionBindingV2 {
        version: 2,
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        run_id: Uuid::new_v4(),
        run_kind: RunKind::Production,
        organization_sha256,
        scope_sha256: scope.digest()?,
        credential_scope_sha256: scope.credential_scope_digest()?,
        action_version: proposal.action_version,
        action: action.clone(),
        metadata_sha256: digest(b"relayne-helper-sql-metadata-v2", metadata)?,
        before_sha256: native.observation.before_sha256.clone(),
        plan_sha256: proposal.plan_sha256.clone(),
        verification_sha256: digest(
            b"relayne-helper-reviewed-verification-v2",
            &proposal.verification,
        )?,
        proof: ActionProof::SqlRehearsalReceipt {
            receipt_id: rehearsal.receipt_id(),
            receipt_sha256: rehearsal.content_sha256().to_owned(),
            expires_at,
        },
        restoration: proposal.restoration.clone(),
        statistics_limit_acknowledged: proposal.statistics_limit_acknowledged,
        captured_at: now,
        expires_at,
    };
    binding.validate(now)?;
    let current = DispatchContext {
        case,
        proposal,
        journal,
        observation: &native.observation,
    };
    super::sql::promotion::check_sql_promotion(case, proposal, rehearsal, &binding, &current, now)?;
    Ok(binding)
}

pub struct DispatchContext<'a> {
    pub(crate) case: &'a HelperCase,
    pub(crate) proposal: &'a HelperProposal,
    pub(crate) journal: &'a ActionJournal,
    pub(crate) observation: &'a DispatchObservation,
}
/// Only this authority module can mint a permit. It cannot be cloned,
/// serialized or constructed from a provider/imported value.
pub struct DispatchPermit {
    binding: ActionBindingV2,
    receipt: ConsumeReceiptV2,
}
impl DispatchPermit {
    pub fn binding(&self) -> &ActionBindingV2 {
        &self.binding
    }
    pub fn receipt(&self) -> &ConsumeReceiptV2 {
        &self.receipt
    }
    #[cfg(test)]
    pub(crate) fn test_only(binding: ActionBindingV2, receipt: ConsumeReceiptV2) -> Self {
        Self { binding, receipt }
    }
}
fn gate_states() -> &'static Mutex<std::collections::HashMap<Uuid, (u64, bool)>> {
    static STATES: OnceLock<Mutex<std::collections::HashMap<Uuid, (u64, bool)>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}
fn state(case_id: Uuid) -> Result<(u64, bool)> {
    Ok(*gate_states()
        .lock()
        .map_err(|_| anyhow::anyhow!("Dispatch gate poisoned"))?
        .get(&case_id)
        .unwrap_or(&(0, false)))
}
fn is_blocked(case_id: Uuid) -> Result<bool> {
    Ok(state(case_id)?.1)
}
fn scope_resource(case: &HelperCase, scope_sha256: &str) -> Option<String> {
    case.scopes()
        .iter()
        .find(|scope| scope.digest().ok().as_deref() == Some(scope_sha256))
        .and_then(|scope| scope.resource_digest().ok())
}
fn block(case_id: Uuid) -> Result<()> {
    let mut states = gate_states()
        .lock()
        .map_err(|_| anyhow::anyhow!("Dispatch gate poisoned"))?;
    let entry = states.entry(case_id).or_insert((0, false));
    entry.0 = entry.0.wrapping_add(1);
    entry.1 = true;
    Ok(())
}
fn clear_if_unchanged(case_id: Uuid, generation: u64) -> Result<()> {
    let mut states = gate_states()
        .lock()
        .map_err(|_| anyhow::anyhow!("Dispatch gate poisoned"))?;
    let entry = states.entry(case_id).or_insert((0, false));
    if entry.0 == generation {
        entry.1 = false;
    }
    Ok(())
}

pub fn authorize_dispatch(
    binding: &ActionBindingV2,
    receipt: &crate::team_client::VerifiedConsumeV2,
    current: &DispatchContext<'_>,
) -> Result<DispatchPermit> {
    let now = Utc::now();
    binding.validate(now)?;
    ensure!(
        !is_blocked(binding.case_id)?,
        "Case edit or review withdrawal suspended action authority"
    );
    ensure!(
        !current
            .journal
            .has_open_intervention(binding.case_id, binding.run_id),
        "Case has unresolved native or restoration outcome"
    );
    ensure!(
        receipt.receipt().approval_id != Uuid::nil()
            && receipt.receipt().consume_id != Uuid::nil()
            && receipt.receipt().fingerprint == binding.fingerprint()?
            && receipt.receipt().organization_sha256 == binding.organization_sha256,
        "Consumed action approval differs from binding"
    );
    ensure!(
        current.case.id() == binding.case_id
            && current.case.revision() == binding.case_revision
            && current.case.evidence_revision() == binding.evidence_revision,
        "Case or evidence changed after approval"
    );
    ensure!(
        current.proposal.case_id == binding.case_id
            && current.proposal.case_revision == binding.case_revision,
        "Proposal changed after approval"
    );
    let reviewed = current
        .journal
        .review(binding.case_id)
        .ok_or_else(|| anyhow::anyhow!("Local review missing"))?;
    ensure!(
        !reviewed.withdrawn
            && reviewed.case_revision == binding.case_revision
            && reviewed.review_sha256 == current.proposal.review_digest()?,
        "Local review withdrawn or changed"
    );
    ensure!(
        current
            .case
            .plan()
            .is_some_and(|p| digest(b"relayne-helper-reviewed-plan-v1", p)
                .ok()
                .as_deref()
                == Some(binding.plan_sha256.as_str())),
        "Current plan differs from approved plan"
    );
    ensure!(
        current.proposal.plan_sha256 == binding.plan_sha256
            && digest(
                b"relayne-helper-reviewed-verification-v2",
                &current.proposal.verification
            )? == binding.verification_sha256,
        "Verification criteria changed"
    );
    ensure!(
        current.proposal.restoration == binding.restoration
            && current.proposal.statistics_limit_acknowledged
                == binding.statistics_limit_acknowledged,
        "Restoration review changed"
    );
    let CatalogAction::Sql { action, metadata } = &current.proposal.action else {
        anyhow::bail!("Only typed SQL action uses v2 authority")
    };
    action.validate(metadata)?;
    let resource = scope_resource(current.case, &binding.scope_sha256)
        .ok_or_else(|| anyhow::anyhow!("Current change resource missing"))?;
    ensure!(
        current
            .case
            .evidence()
            .iter()
            .any(|e| e.content_sha256 == metadata.source_evidence_sha256
                && current.case.scopes().iter().any(|read| {
                    read.credential()
                        .is_some_and(|credential| credential.purpose == CredentialPurpose::Read)
                        && read.resource_digest().ok().as_deref() == Some(resource.as_str())
                        && read.digest().ok().as_deref() == Some(e.binding.scope_sha256.as_str())
                        && read.credential_scope_digest().ok().as_deref()
                            == Some(e.binding.credential_scope_sha256.as_str())
                })
                && e.eligibility(now, chrono::Duration::seconds(119)) == Eligibility::Eligible),
        "Live metadata source changed or became stale"
    );
    ensure!(
        action == &binding.action && current.proposal.action_version == binding.action_version,
        "Approved action differs from current proposal"
    );
    ensure!(
        digest(b"relayne-helper-sql-metadata-v2", metadata)? == binding.metadata_sha256
            && current.observation.metadata_sha256 == binding.metadata_sha256,
        "SQL metadata changed"
    );
    ensure!(
        current.observation.before_sha256 == binding.before_sha256
            && valid_digest(&binding.before_sha256),
        "Before-state observation changed"
    );
    ensure!(
        current.observation.observed_at <= now
            && now.signed_duration_since(current.observation.observed_at)
                < chrono::Duration::seconds(120),
        "Last-moment observation stale"
    );
    ensure!(
        current.observation.credential_scope_sha256 == binding.credential_scope_sha256,
        "Credential identity changed"
    );
    let scope = current
        .case
        .scopes()
        .iter()
        .find(|scope| {
            scope.digest().ok().as_deref() == Some(binding.scope_sha256.as_str())
                && scope.credential_scope_digest().ok().as_deref()
                    == Some(binding.credential_scope_sha256.as_str())
        })
        .ok_or_else(|| anyhow::anyhow!("Reviewed case scope or credential changed"))?;
    let credential = scope
        .credential()
        .ok_or_else(|| anyhow::anyhow!("Controlled-change credential missing"))?;
    ensure!(
        credential.purpose == CredentialPurpose::ControlledChange,
        "Wrong credential purpose"
    );
    // Lock order is case store -> credential vault, matching scoped-rotation commit.
    // The resolver reloads active generation/revocation each time; no secret is stored here.
    let _resolved = PersistentSecretResolver::new()?
        .resolve(credential, CredentialPurpose::ControlledChange)?;
    match (&binding.run_kind, &binding.proof) {
        (RunKind::Rehearsal, ActionProof::StagingReviewProof { review_sha256, .. }) => ensure!(
            review_sha256 == &reviewed.review_sha256,
            "Staging review proof changed"
        ),
        (RunKind::Production, ActionProof::SqlRehearsalReceipt { receipt_id, .. }) => {
            let rehearsal = super::sql::rehearsal::load_protected_rehearsal_by_id(*receipt_id)?;
            super::sql::promotion::check_sql_promotion(
                current.case,
                current.proposal,
                &rehearsal,
                binding,
                current,
                now,
            )?;
        }
        _ => anyhow::bail!("Proof type mismatch"),
    }
    Ok(DispatchPermit {
        binding: binding.clone(),
        receipt: receipt.receipt().clone(),
    })
}

fn require_production_physical(
    binding: &ActionBindingV2,
    observation: &NativeDispatchProof,
) -> Result<()> {
    if let ActionProof::SqlRehearsalReceipt { receipt_id, .. } = &binding.proof {
        let receipt = super::sql::rehearsal::load_protected_rehearsal_by_id(*receipt_id)?;
        ensure!(
            observation.physical_sha256() == receipt.production_physical_sha256(),
            "Physical production database changed after rehearsal"
        );
    }
    Ok(())
}

/// Review and withdrawal both use the same case lock as saves/dispatch.
pub fn record_local_review(
    case_path: &Path,
    journal_path: &Path,
    reviewed_case: &HelperCase,
    proposal: &HelperProposal,
) -> Result<()> {
    let generation = state(proposal.case_id)?.0;
    HelperStore::inspect_locked(case_path, |store| {
        let case = store
            .case(proposal.case_id)
            .ok_or_else(|| anyhow::anyhow!("Case missing"))?;
        ensure!(
            case.revision() == proposal.case_revision
                && case.evidence_revision() == reviewed_case.evidence_revision()
                && digest(b"relayne-helper-case-review-v2", case)?
                    == digest(b"relayne-helper-case-review-v2", reviewed_case)?,
            "Stale or unsaved case review"
        );
        super::catalog::with_current_proposal(case, proposal, || {
            let review_sha256 = proposal.review_digest()?;
            let mut journal = ActionJournal::load(journal_path)?;
            journal.record_review_locked(case.id(), case.revision(), review_sha256)
        })
    })?;
    clear_if_unchanged(proposal.case_id, generation)
}
pub fn withdraw_local_review(case_path: &Path, journal_path: &Path, case_id: Uuid) -> Result<()> {
    // Admission is revoked before any filesystem operation. A failed withdrawal
    // keeps this process fail-closed; only a new durable review clears it.
    block(case_id)?;
    HelperStore::inspect_locked(case_path, |_store| {
        let mut journal = ActionJournal::load(journal_path)?;
        journal.withdraw_review_locked(case_id)
    })
}

/// Called only after remote consume and fresh local observation. This routine
/// publishes durable intent under the same OS gate used by case edits. It performs
/// no remote I/O. A failed journal save returns without an intent ID or launch.
pub fn authorize_and_record_intent(
    case_path: &Path,
    journal_path: &Path,
    proposal: &HelperProposal,
    binding: &ActionBindingV2,
    receipt: &crate::team_client::VerifiedConsumeV2,
    observation: &NativeDispatchProof,
) -> Result<IntentId> {
    HelperStore::inspect_locked(case_path, |store| {
        let case = store
            .case(binding.case_id)
            .ok_or_else(|| anyhow::anyhow!("Case missing"))?;
        super::catalog::with_current_proposal(case, proposal, || {
            let mut journal = ActionJournal::load(journal_path)?;
            let current = DispatchContext {
                case,
                proposal,
                journal: &journal,
                observation: &observation.observation,
            };
            let permit = authorize_dispatch(binding, receipt, &current)?;
            require_production_physical(binding, observation)?;
            journal.record_intent(permit)
        })
    })
}

/// The launch side of the gate. Revalidates after the durable Prepared intent,
/// persists DispatchStarted, then releases the case lock and yields one permit.
/// The caller may contact the target only after this returns successfully.
pub fn authorize_and_start_dispatch(
    case_path: &Path,
    journal_path: &Path,
    intent_id: IntentId,
    proposal: &HelperProposal,
    binding: &ActionBindingV2,
    receipt: &crate::team_client::VerifiedConsumeV2,
    observation: &NativeDispatchProof,
) -> Result<DispatchPermit> {
    HelperStore::inspect_locked(case_path, |store| {
        let case = store
            .case(binding.case_id)
            .ok_or_else(|| anyhow::anyhow!("Case missing"))?;
        super::catalog::with_current_proposal(case, proposal, || {
            let mut journal = ActionJournal::load(journal_path)?;
            let intent = journal
                .intents()
                .iter()
                .find(|i| i.id == intent_id)
                .ok_or_else(|| anyhow::anyhow!("Prepared intent missing"))?;
            ensure!(
                intent.state == super::journal::IntentState::Prepared
                    && intent.approval_id == receipt.receipt().approval_id
                    && intent.consume_id == receipt.receipt().consume_id
                    && intent.run_id == binding.run_id
                    && intent.binding_fingerprint == receipt.receipt().fingerprint,
                "Intent already launched or binding changed"
            );
            let current = DispatchContext {
                case,
                proposal,
                journal: &journal,
                observation: &observation.observation,
            };
            let permit = authorize_dispatch(binding, receipt, &current)?;
            require_production_physical(binding, observation)?;
            journal.mark_dispatch_started(intent_id)?;
            Ok(permit)
        })
    })
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
