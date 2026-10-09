//! Reviewed isolated staging and protected, actual native rehearsal receipts.
use super::{
    benchmark::{self, ReviewedWorkload, SamplingPolicy},
    changes::{self, NativeActionState},
    templates::{self, ReviewedSelectTemplate},
};
use crate::helper::{
    approval::{DispatchPermit, NativeDispatchProof},
    case::HelperCase,
    catalog::{CatalogAction, HelperProposal},
    evidence::is_digest,
    journal::{ActionJournal, IntentId, IntentState},
    scope::{BoundScope, CredentialPurpose, DatabaseEngine},
};
use crate::helper_action::{RequiredCheck, digest};
use crate::helper_approval::{ActionProof, RunKind};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RECEIPT_SCHEMA: u16 = 1;
const MAX_RECEIPT_BYTES: usize = 128 * 1024;

/// Only review() can construct a mapping; the digest is part of the v2
/// staging proof before remote approval.
#[derive(Clone)]
pub struct SqlTrialMapping {
    pub(crate) case_id: Uuid,
    pub(crate) case_revision: u64,
    pub(crate) production_scope_sha256: String,
    pub(crate) production_physical_sha256: String,
    pub(crate) production_before_sha256: String,
    pub(crate) staging_scope_sha256: String,
    pub(crate) staging_read_scope_sha256: String,
    pub(crate) staging_physical_sha256: String,
    pub(crate) staging_before_sha256: String,
    pub(crate) action_sha256: String,
    verification_sha256: String,
    template: ReviewedSelectTemplate,
    production_template_sha256: String,
    staging_template_sha256: String,
    synthetic_data_sha256: String,
    reviewed_limits: String,
    reviewed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct MappingFingerprint<'a> {
    version: u16,
    case_id: Uuid,
    case_revision: u64,
    production_scope_sha256: &'a str,
    production_physical_sha256: &'a str,
    production_before_sha256: &'a str,
    staging_scope_sha256: &'a str,
    staging_read_scope_sha256: &'a str,
    staging_physical_sha256: &'a str,
    staging_before_sha256: &'a str,
    action_sha256: &'a str,
    verification_sha256: &'a str,
    template: ReviewedSelectTemplate,
    production_template_sha256: &'a str,
    staging_template_sha256: &'a str,
    synthetic_data_sha256: &'a str,
    reviewed_limits: &'a str,
}

impl SqlTrialMapping {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.case_id != Uuid::nil()
                && self.case_revision > 0
                && [
                    &self.production_scope_sha256,
                    &self.production_physical_sha256,
                    &self.production_before_sha256,
                    &self.staging_scope_sha256,
                    &self.staging_read_scope_sha256,
                    &self.staging_physical_sha256,
                    &self.staging_before_sha256,
                    &self.action_sha256,
                    &self.verification_sha256,
                    &self.production_template_sha256,
                    &self.staging_template_sha256,
                    &self.synthetic_data_sha256,
                ]
                .iter()
                .all(|d| is_digest(d))
                && self.production_scope_sha256 != self.staging_scope_sha256
                && self.production_physical_sha256 != self.staging_physical_sha256
                && self.reviewed_limits.len() >= 8
                && self.reviewed_limits.len() <= 512
                && !self.reviewed_limits.chars().any(char::is_control)
                && self.reviewed_at <= Utc::now()
                && self.expires_at > Utc::now()
                && self.expires_at <= self.reviewed_at + Duration::minutes(5),
            "Invalid or expired isolated SQL trial mapping"
        );
        Ok(())
    }
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        digest(
            b"relayne-helper-reviewed-sql-trial-mapping-v1",
            &MappingFingerprint {
                version: templates::REHEARSAL_TEMPLATE_MAPPING_VERSION,
                case_id: self.case_id,
                case_revision: self.case_revision,
                production_scope_sha256: &self.production_scope_sha256,
                production_physical_sha256: &self.production_physical_sha256,
                production_before_sha256: &self.production_before_sha256,
                staging_scope_sha256: &self.staging_scope_sha256,
                staging_read_scope_sha256: &self.staging_read_scope_sha256,
                staging_physical_sha256: &self.staging_physical_sha256,
                staging_before_sha256: &self.staging_before_sha256,
                action_sha256: &self.action_sha256,
                verification_sha256: &self.verification_sha256,
                template: self.template,
                production_template_sha256: &self.production_template_sha256,
                staging_template_sha256: &self.staging_template_sha256,
                synthetic_data_sha256: &self.synthetic_data_sha256,
                reviewed_limits: &self.reviewed_limits,
            },
        )
    }
    pub fn staging_scope_sha256(&self) -> &str {
        &self.staging_scope_sha256
    }
    pub fn staging_physical_sha256(&self) -> &str {
        &self.staging_physical_sha256
    }

    pub async fn review(
        case: &HelperCase,
        proposal: &HelperProposal,
        production: &NativeDispatchProof,
        staging_scope_sha256: &str,
        reviewed_limits: &str,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let CatalogAction::Sql { action, metadata } = &proposal.action else {
            anyhow::bail!("Only SQL action can be rehearsed")
        };
        ensure!(
            proposal.case_id == case.id() && proposal.case_revision == case.revision(),
            "Trial case/proposal changed"
        );
        let production_change = scope(case, &metadata.object.scope_sha256)?;
        let staging_change = scope(case, staging_scope_sha256)?;
        let production_read = matching_read(case, production_change)?;
        let staging_read = matching_read(case, staging_change)?;
        let template = reviewed_template(proposal, production_read)?;
        let production_statement = template.reviewed_statement(production_read)?;
        let staging_statement = template.reviewed_statement(staging_read)?;
        ensure!(
            matches!(staging_change, BoundScope::Database { engine: DatabaseEngine::Postgres, port: 55434, database, .. }
            if database == templates::REHEARSAL_DATABASE),
            "Only versioned isolated guest rehearsal fixture is reviewed"
        );
        let trial = changes::collect_trial_target(
            production.native(),
            action,
            metadata,
            staging_change,
            cancel.clone(),
        )
        .await?;
        let production_data =
            benchmark::fixture_data_digest(production_read, template, cancel.clone()).await?;
        let staging_data = benchmark::fixture_data_digest(staging_read, template, cancel).await?;
        ensure!(
            production_data == staging_data,
            "Full bounded synthetic dataset differs between target and staging"
        );
        let now = Utc::now();
        let mapping = Self {
            case_id: case.id(),
            case_revision: case.revision(),
            production_scope_sha256: metadata.object.scope_sha256.clone(),
            production_physical_sha256: production.physical_sha256().to_owned(),
            production_before_sha256: production.native().before_sha256().to_owned(),
            staging_scope_sha256: staging_scope_sha256.to_owned(),
            staging_read_scope_sha256: staging_read.digest()?,
            staging_physical_sha256: trial.preflight.physical_digest()?,
            staging_before_sha256: trial.preflight.before_sha256().to_owned(),
            action_sha256: digest(b"relayne-helper-sql-action-v1", action)?,
            verification_sha256: digest(
                b"relayne-helper-reviewed-verification-v2",
                &proposal.verification,
            )?,
            template,
            production_template_sha256: production_statement.fingerprint,
            staging_template_sha256: staging_statement.fingerprint,
            synthetic_data_sha256: staging_data,
            reviewed_limits: reviewed_limits.to_owned(),
            reviewed_at: now,
            expires_at: now + Duration::minutes(5),
        };
        mapping.validate()?;
        Ok(mapping)
    }
}

fn scope<'a>(case: &'a HelperCase, sha: &str) -> Result<&'a BoundScope> {
    case.scopes()
        .iter()
        .find(|s| s.digest().ok().as_deref() == Some(sha))
        .ok_or_else(|| anyhow::anyhow!("Current SQL scope missing"))
}

fn matching_read<'a>(case: &'a HelperCase, change: &BoundScope) -> Result<&'a BoundScope> {
    let resource = change.resource_digest()?;
    case.scopes()
        .iter()
        .find(|s| {
            s.resource_digest().ok().as_deref() == Some(resource.as_str())
                && s.credential()
                    .is_some_and(|c| c.purpose == CredentialPurpose::Read)
        })
        .ok_or_else(|| anyhow::anyhow!("Matching scoped read credential missing"))
}

fn reviewed_template(
    proposal: &HelperProposal,
    read: &BoundScope,
) -> Result<ReviewedSelectTemplate> {
    let mut selected = None;
    for check in &proposal.verification.checks {
        if let RequiredCheck::Performance {
            workload_sha256, ..
        } = check
        {
            let template = ReviewedSelectTemplate::from_fingerprint(read, workload_sha256)
                .ok_or_else(|| {
                    anyhow::anyhow!("Performance workload is not a fixed reviewed template")
                })?;
            template.reviewed_statement(read)?;
            ensure!(
                selected.replace(template).is_none(),
                "Multiple rehearsal workloads unsupported"
            );
        }
    }
    selected.context("Reviewed performance workload missing")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlRehearsalReceipt {
    schema: u16,
    receipt_id: Uuid,
    run_id: Uuid,
    approval_id: Uuid,
    consume_id: Uuid,
    case_id: Uuid,
    case_revision: u64,
    mapping_sha256: String,
    production_scope_sha256: String,
    production_physical_sha256: String,
    staging_scope_sha256: String,
    staging_physical_sha256: String,
    action_sha256: String,
    verification_sha256: String,
    before_sha256: String,
    after_sha256: String,
    synthetic_data_sha256: String,
    workload_result_sha256: String,
    workload_before_median_ms: f64,
    workload_after_median_ms: f64,
    complete_native_compatibility: bool,
    created_index_id: Option<u64>,
    created_index_definition_sha256: Option<String>,
    ownership_marker_sha256: Option<String>,
    statistics_nonrestorable: bool,
    reviewed_limits: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    content_sha256: String,
}

impl SqlRehearsalReceipt {
    fn fingerprint(&self) -> Result<String> {
        let mut content = self.clone();
        content.content_sha256.clear();
        digest(b"relayne-helper-sql-rehearsal-receipt-v1", &content)
    }
    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.schema == RECEIPT_SCHEMA
                && self.receipt_id != Uuid::nil()
                && self.run_id != Uuid::nil()
                && self.approval_id != Uuid::nil()
                && self.consume_id != Uuid::nil()
                && self.case_id != Uuid::nil()
                && self.case_revision > 0
                && self.created_at <= now
                && self.expires_at > now
                && self.expires_at <= self.created_at + Duration::hours(1)
                && self.complete_native_compatibility
                && self.workload_before_median_ms.is_finite()
                && self.workload_after_median_ms.is_finite()
                && self.workload_before_median_ms > 0.0
                && self.workload_after_median_ms > 0.0
                && self.content_sha256 == self.fingerprint()?,
            "Invalid, stale or tampered SQL rehearsal receipt"
        );
        for digest in [
            &self.mapping_sha256,
            &self.production_scope_sha256,
            &self.production_physical_sha256,
            &self.staging_scope_sha256,
            &self.staging_physical_sha256,
            &self.action_sha256,
            &self.verification_sha256,
            &self.before_sha256,
            &self.after_sha256,
            &self.synthetic_data_sha256,
            &self.workload_result_sha256,
        ] {
            ensure!(is_digest(digest), "Invalid receipt digest");
        }
        ensure!(
            self.production_scope_sha256 != self.staging_scope_sha256
                && self.production_physical_sha256 != self.staging_physical_sha256
                && (if self.statistics_nonrestorable {
                    self.created_index_id.is_none()
                        && self.created_index_definition_sha256.is_none()
                        && self.ownership_marker_sha256.is_none()
                } else {
                    self.created_index_id.is_some_and(|id| id > 0)
                        && self
                            .created_index_definition_sha256
                            .as_deref()
                            .is_some_and(is_digest)
                        && self
                            .ownership_marker_sha256
                            .as_deref()
                            .is_some_and(is_digest)
                }),
            "Rehearsal action ownership or isolation incomplete"
        );
        Ok(())
    }
    pub fn validate_for(&self, mapping: &SqlTrialMapping, proposal: &HelperProposal) -> Result<()> {
        self.validate(Utc::now())?;
        mapping.validate()?;
        let CatalogAction::Sql { action, .. } = &proposal.action else {
            anyhow::bail!("SQL proposal required for rehearsal receipt")
        };
        ensure!(
            self.case_id == mapping.case_id
                && self.case_revision == mapping.case_revision
                && self.mapping_sha256 == mapping.fingerprint()?
                && self.production_scope_sha256 == mapping.production_scope_sha256
                && self.production_physical_sha256 == mapping.production_physical_sha256
                && self.staging_scope_sha256 == mapping.staging_scope_sha256
                && self.staging_physical_sha256 == mapping.staging_physical_sha256
                && self.action_sha256 == digest(b"relayne-helper-sql-action-v1", action)?
                && self.verification_sha256
                    == digest(
                        b"relayne-helper-reviewed-verification-v2",
                        &proposal.verification
                    )?,
            "SQL rehearsal receipt belongs to another reviewed action or target"
        );
        Ok(())
    }
    pub fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
    pub fn run_id(&self) -> Uuid {
        self.run_id
    }
    pub fn path(&self) -> Result<PathBuf> {
        crate::security::app_data_file(&format!(
            "relayne-helper-sql-rehearsal-{}.dpapi",
            self.run_id
        ))
    }
    fn save(&self) -> Result<PathBuf> {
        self.validate(Utc::now())?;
        let path = self.path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = lock(&path)?;
        ensure!(
            !path.exists(),
            "Immutable SQL rehearsal receipt already exists"
        );
        let clear = serde_json::to_vec(self)?;
        ensure!(
            clear.len() <= MAX_RECEIPT_BYTES,
            "SQL rehearsal receipt exceeds bound"
        );
        let protected = crate::security::protect_secret(&clear)?;
        ensure!(
            protected.len() <= MAX_RECEIPT_BYTES,
            "Protected SQL receipt exceeds bound"
        );
        crate::security::atomic_write(&path, &protected)?;
        Ok(path)
    }
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

pub fn load_sql_rehearsal(path: &Path) -> Result<SqlRehearsalReceipt> {
    let _guard = lock(path)?;
    let mut file = std::fs::File::open(path)?;
    let mut protected = Vec::new();
    file.by_ref()
        .take(MAX_RECEIPT_BYTES as u64 + 1)
        .read_to_end(&mut protected)?;
    ensure!(
        protected.len() <= MAX_RECEIPT_BYTES,
        "Protected receipt exceeds bound"
    );
    let clear = crate::security::unprotect_secret(&protected)?;
    ensure!(clear.len() <= MAX_RECEIPT_BYTES, "Receipt exceeds bound");
    let receipt: SqlRehearsalReceipt = serde_json::from_slice(&clear)?;
    receipt.validate(Utc::now())?;
    ensure!(receipt.path()? == path, "Receipt path/run identity differs");
    Ok(receipt)
}

pub async fn run_sql_rehearsal(
    mapping: &SqlTrialMapping,
    permit: DispatchPermit,
    intent_id: IntentId,
    case: &HelperCase,
    proposal: &HelperProposal,
    journal_path: &Path,
    cancel: CancellationToken,
) -> Result<SqlRehearsalReceipt> {
    let run_id = permit.binding().run_id;
    let before_sha256 = permit.binding().before_sha256.clone();
    let result = run_sql_rehearsal_inner(
        mapping,
        permit,
        intent_id,
        case,
        proposal,
        journal_path,
        cancel,
    )
    .await;
    if result.is_err() {
        // A durable dispatch can precede any native preflight. Close every
        // remaining started intent conservatively, including early failures.
        let mut journal = ActionJournal::load(journal_path)?;
        if journal.intents().iter().any(|intent| {
            intent.id == intent_id
                && intent.run_id == run_id
                && intent.state == IntentState::DispatchStarted
        }) {
            let uncertain = changes::NativeActionProof::uncertain(run_id, before_sha256);
            journal.record_native_outcome(intent_id, &uncertain, None)?;
        }
    }
    result
}

#[cfg(test)]
#[path = "rehearsal_tests.rs"]
mod tests;

async fn run_sql_rehearsal_inner(
    mapping: &SqlTrialMapping,
    permit: DispatchPermit,
    intent_id: IntentId,
    case: &HelperCase,
    proposal: &HelperProposal,
    journal_path: &Path,
    cancel: CancellationToken,
) -> Result<SqlRehearsalReceipt> {
    mapping.validate()?;
    ensure!(
        permit.binding().run_kind == RunKind::Rehearsal
            && permit.binding().case_id == case.id()
            && permit.binding().case_revision == case.revision()
            && permit.binding().before_sha256 == mapping.production_before_sha256
            && permit.binding().action.object().scope_sha256 == mapping.production_scope_sha256
            && matches!(&permit.binding().proof,
            ActionProof::StagingReviewProof { mapping_sha256, staging_scope_sha256, staging_physical_sha256, .. }
                if mapping_sha256 == &mapping.fingerprint()?
                    && staging_scope_sha256 == &mapping.staging_scope_sha256
                    && staging_physical_sha256 == &mapping.staging_physical_sha256),
        "Permit does not authorize exact reviewed staging mapping"
    );
    let CatalogAction::Sql { action, metadata } = &proposal.action else {
        anyhow::bail!("Reviewed SQL action missing")
    };
    ensure!(
        action == &permit.binding().action
            && digest(b"relayne-helper-sql-action-v1", action)? == mapping.action_sha256
            && digest(
                b"relayne-helper-reviewed-verification-v2",
                &proposal.verification
            )? == mapping.verification_sha256,
        "Action or checks changed since staging review"
    );
    let production = NativeDispatchProof::collect(case, proposal, cancel.clone()).await?;
    ensure!(
        production.physical_sha256() == mapping.production_physical_sha256
            && production.native().before_sha256() == mapping.production_before_sha256,
        "Production native preflight changed"
    );
    let production_change = scope(case, &mapping.production_scope_sha256)?;
    let production_read = matching_read(case, production_change)?;
    ensure!(
        benchmark::fixture_data_digest(production_read, mapping.template, cancel.clone()).await?
            == mapping.synthetic_data_sha256,
        "Production synthetic data changed since staging review"
    );
    let stage_change = scope(case, &mapping.staging_scope_sha256)?;
    let stage_read = scope(case, &mapping.staging_read_scope_sha256)?;
    ensure!(
        matching_read(case, stage_change)?.digest()? == stage_read.digest()?,
        "Staging read credential changed"
    );
    let trial = changes::collect_trial_target(
        production.native(),
        action,
        metadata,
        stage_change,
        cancel.clone(),
    )
    .await?;
    ensure!(
        trial.preflight.physical_digest()? == mapping.staging_physical_sha256
            && trial.preflight.before_sha256() == mapping.staging_before_sha256,
        "Staging native before-state changed"
    );
    let source = case
        .evidence()
        .iter()
        .find(|e| e.content_sha256 == metadata.source_evidence_sha256)
        .context("Reviewed live SQL evidence missing")?;
    ensure!(
        source.capability_id == crate::helper::manifest::CapabilityId::SqlRead
            && source.binding.case_id == case.id()
            && source.binding.case_revision == case.revision()
            && source.binding.scope_sha256 == production_read.digest()?
            && source.binding.credential_scope_sha256
                == production_read.credential_scope_digest()?
            && source.eligibility(Utc::now(), Duration::minutes(5))
                == crate::helper::evidence::Eligibility::Eligible
            && benchmark::metadata_matches(&source.sql_observations, mapping.template),
        "Reviewed live SQL source no longer covers exact workload object"
    );
    let workload = ReviewedWorkload {
        scope: stage_read.clone(),
        template: mapping.template,
        case_id: case.id(),
        case_revision: case.revision(),
        review_evidence_id: source.id,
        review_content_sha256: source.content_sha256.clone(),
        reviewed_at: mapping.reviewed_at,
    };
    let policy = SamplingPolicy::default();
    let before = benchmark::run_sandbox_workload(&workload, &policy, cancel.clone()).await?;
    ensure!(
        before.compatibility.is_complete()
            && benchmark::fixture_data_digest(stage_read, mapping.template, cancel.clone()).await?
                == mapping.synthetic_data_sha256,
        "Native baseline or staged data coverage incomplete"
    );
    let run_id = permit.binding().run_id;
    let proof =
        match changes::execute_sql_change(permit, intent_id, stage_change, &trial, cancel.clone())
            .await
        {
            Ok(proof) => proof,
            Err(error) => {
                let uncertain = changes::NativeActionProof::uncertain(
                    run_id,
                    trial.preflight.before_sha256().to_owned(),
                );
                let mut journal = ActionJournal::load(journal_path)?;
                journal.record_native_outcome(intent_id, &uncertain, None)?;
                return Err(error.context(
                    "Native dispatch outcome uncertain; reconcile before another action",
                ));
            }
        };
    if proof.state != NativeActionState::Verified {
        let mut journal = ActionJournal::load(journal_path)?;
        journal.record_native_outcome(intent_id, &proof, None)?;
        anyhow::bail!(
            "Native SQL action failed or outcome is uncertain; reconcile run before another action"
        );
    }
    // Once native SQL has committed, every later error must durably close the
    // dispatch as needing intervention. The consumed permit is never retried.
    let completed: Result<SqlRehearsalReceipt> = async {
        let after = benchmark::run_sandbox_workload(&workload, &policy, cancel.clone()).await?;
        ensure!(
            after.compatibility.is_complete()
                && before.result_sha256 == after.result_sha256
                && after.warmups >= 3
                && after.milliseconds.len() >= 15
                && benchmark::fixture_data_digest(stage_read, mapping.template, cancel).await?
                    == mapping.synthetic_data_sha256,
            "Staged workload/result/coverage incomplete after action"
        );
        let now = Utc::now();
        let mut receipt = SqlRehearsalReceipt {
            schema: RECEIPT_SCHEMA,
            receipt_id: Uuid::new_v4(),
            run_id: proof.run_id(),
            approval_id: Uuid::nil(),
            consume_id: Uuid::nil(),
            case_id: case.id(),
            case_revision: case.revision(),
            mapping_sha256: mapping.fingerprint()?,
            production_scope_sha256: mapping.production_scope_sha256.clone(),
            production_physical_sha256: mapping.production_physical_sha256.clone(),
            staging_scope_sha256: mapping.staging_scope_sha256.clone(),
            staging_physical_sha256: mapping.staging_physical_sha256.clone(),
            action_sha256: mapping.action_sha256.clone(),
            verification_sha256: mapping.verification_sha256.clone(),
            before_sha256: proof.before_sha256.clone(),
            after_sha256: proof
                .after_sha256
                .clone()
                .context("Native SQL committed readback missing")?,
            synthetic_data_sha256: mapping.synthetic_data_sha256.clone(),
            workload_result_sha256: after.result_sha256,
            workload_before_median_ms: before.median_ms,
            workload_after_median_ms: after.median_ms,
            complete_native_compatibility: true,
            created_index_id: proof.created_index_id,
            created_index_definition_sha256: proof.created_index_definition_sha256.clone(),
            ownership_marker_sha256: proof.ownership_marker_sha256.clone(),
            statistics_nonrestorable: action.is_statistics(),
            reviewed_limits: mapping.reviewed_limits.clone(),
            created_at: now,
            expires_at: now + Duration::hours(1),
            content_sha256: String::new(),
        };
        // The permit is consumed by the native executor. Recover exact IDs
        // from the durable intent, never from UI text.
        let mut journal = ActionJournal::load(journal_path)?;
        let intent = journal
            .intents()
            .iter()
            .find(|i| i.id == intent_id && i.run_id == receipt.run_id)
            .context("Durable native intent missing")?;
        receipt.approval_id = intent.approval_id;
        receipt.consume_id = intent.consume_id;
        receipt.content_sha256 = receipt.fingerprint()?;
        receipt.save()?;
        journal.record_native_outcome(intent_id, &proof, Some(receipt.content_sha256()))?;
        Ok(receipt)
    }
    .await;
    match completed {
        Ok(receipt) => Ok(receipt),
        Err(error) => {
            let mut intervention = proof;
            intervention.needs_intervention();
            let recovery = ActionJournal::load(journal_path).and_then(|mut journal| {
                journal
                    .record_native_outcome(intent_id, &intervention, None)
                    .map(|_| ())
            });
            if let Err(journal_error) = recovery {
                return Err(error.context(format!(
                    "SQL committed; durable intervention record failed: {journal_error}"
                )));
            }
            Err(error.context("SQL committed; durable outcome needs intervention"))
        }
    }
}
