//! Promotion requires a protected native rehearsal and the ordinary v2
//! consumed approval. A receipt is evidence, never an executable capability.

use crate::helper::{
    approval::{DispatchContext, DispatchPermit, NativeDispatchProof},
    case::HelperCase,
    catalog::{CatalogAction, HelperProposal},
    journal::{ActionJournal, IntentId},
    scope::BoundScope,
    sql::{
        changes::{
            self, NativeActionIdentity, NativeActionProof, NativeActionState, NativePreflight,
        },
        rehearsal::SqlRehearsalReceipt,
        restoration::ProductionReceipt,
    },
};
use crate::helper_action::VerifiedSqlMetadata;
use crate::helper_approval::{ActionBindingV2, ActionOutcomeEventV2, ActionProof, RunKind};
use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub fn check_sql_promotion(
    case: &HelperCase,
    proposal: &HelperProposal,
    receipt: &SqlRehearsalReceipt,
    binding: &ActionBindingV2,
    current: &DispatchContext<'_>,
    now: DateTime<Utc>,
) -> Result<()> {
    ensure!(
        current.case.id() == case.id()
            && current.case.revision() == case.revision()
            && current.case.evidence_revision() == case.evidence_revision()
            && current.proposal == proposal,
        "Promotion current context changed"
    );
    let ActionProof::SqlRehearsalReceipt {
        receipt_id,
        receipt_sha256,
        expires_at,
    } = &binding.proof
    else {
        anyhow::bail!("Actual SQL rehearsal receipt proof required")
    };
    ensure!(
        binding.run_kind == RunKind::Production
            && *receipt_id == receipt.receipt_id()
            && receipt_sha256 == receipt.content_sha256()
            && *expires_at <= receipt.expires_at(),
        "Production approval references another rehearsal"
    );
    receipt.validate_for_production(case, proposal, binding, current.journal, now)
}

/// Opaque, immutable production launch. Only a protected DispatchStarted
/// journal entry plus current case/proposal/native proof can construct it.
pub struct ProductionLaunch {
    permit: DispatchPermit,
    intent_id: IntentId,
    journal_path: PathBuf,
    scope: BoundScope,
    metadata: VerifiedSqlMetadata,
    before: NativePreflight,
    physical_sha256: String,
    rehearsal_sha256: String,
}

impl ProductionLaunch {
    pub(crate) fn from_authorized(
        case: &HelperCase,
        proposal: &HelperProposal,
        rehearsal: &SqlRehearsalReceipt,
        native: NativeDispatchProof,
        permit: DispatchPermit,
        intent_id: IntentId,
        journal_path: &Path,
    ) -> Result<Self> {
        ActionJournal::require_durable_started(journal_path, intent_id, &permit)?;
        let binding = permit.binding();
        let journal = ActionJournal::load(journal_path)?;
        let current = DispatchContext {
            case,
            proposal,
            journal: &journal,
            observation: native.observation(),
        };
        check_sql_promotion(case, proposal, rehearsal, binding, &current, Utc::now())?;
        ensure!(
            native.physical_sha256() == rehearsal.production_physical_sha256(),
            "Launched production physical database differs rehearsal"
        );
        let CatalogAction::Sql { action, metadata } = &proposal.action else {
            anyhow::bail!("Launched production action must be typed SQL")
        };
        ensure!(
            action == &binding.action,
            "Launched production action changed"
        );
        let scope = case
            .scopes()
            .iter()
            .find(|scope| scope.digest().ok().as_deref() == Some(binding.scope_sha256.as_str()))
            .ok_or_else(|| anyhow::anyhow!("Launched production scope missing"))?
            .clone();
        changes::prepare_sql_change(action, &scope, metadata)?;
        Ok(Self {
            permit,
            intent_id,
            journal_path: journal_path.to_path_buf(),
            scope,
            metadata: metadata.clone(),
            before: native.into_native(),
            physical_sha256: rehearsal.production_physical_sha256().to_owned(),
            rehearsal_sha256: rehearsal.content_sha256().to_owned(),
        })
    }

    pub fn run_id(&self) -> Uuid {
        self.permit.binding().run_id
    }
}

pub struct ProductionOutcome {
    pub event: ActionOutcomeEventV2,
    pub receipt: Option<ProductionReceipt>,
}

/// One native attempt only. A failure after DispatchStarted is terminal or
/// ambiguous; the returned journal event may be delivered again without SQL.
pub async fn apply_sql_production(
    launch: ProductionLaunch,
    journal: &mut ActionJournal,
    cancel: CancellationToken,
) -> Result<ProductionOutcome> {
    ActionJournal::require_durable_started(&launch.journal_path, launch.intent_id, &launch.permit)?;
    *journal = ActionJournal::load(&launch.journal_path)?;
    let identity = NativeActionIdentity::from_permit(&launch.permit)?;
    let before_sha256 = launch.before.before_sha256().to_owned();
    let proof = match changes::execute_sql_production(
        &launch.permit,
        launch.intent_id,
        &launch.journal_path,
        &launch.scope,
        &launch.metadata,
        &launch.before,
        &launch.physical_sha256,
        cancel,
    )
    .await
    {
        Ok(proof) => proof,
        Err(_) => NativeActionProof::uncertain(identity, before_sha256),
    };
    *journal = ActionJournal::load(&launch.journal_path)?;
    if proof.state() != NativeActionState::Verified {
        let event = journal.record_native_outcome(launch.intent_id, &proof, None)?;
        return Ok(ProductionOutcome {
            event,
            receipt: None,
        });
    }
    let receipt = ProductionReceipt::from_native(
        &launch.permit,
        &launch.rehearsal_sha256,
        launch.scope,
        &launch.before,
        &proof,
    )
    .and_then(|receipt| {
        receipt.save()?;
        Ok(receipt)
    });
    match receipt {
        Ok(receipt) => {
            let event = journal.record_production_outcome(launch.intent_id, &proof, &receipt)?;
            Ok(ProductionOutcome {
                event,
                receipt: Some(receipt),
            })
        }
        Err(_) => {
            let mut intervention = proof;
            intervention.needs_intervention();
            let event = journal.record_native_outcome(launch.intent_id, &intervention, None)?;
            Ok(ProductionOutcome {
                event,
                receipt: None,
            })
        }
    }
}

#[cfg(test)]
#[path = "promotion_tests.rs"]
mod tests;
