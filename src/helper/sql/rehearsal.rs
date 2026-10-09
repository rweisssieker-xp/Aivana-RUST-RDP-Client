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
    journal::{ActionJournal, IntentId, IntentRecord, IntentState},
    scope::{BoundScope, CredentialPurpose, DatabaseEngine},
};
use crate::helper_action::{
    CriterionComparator, CriterionRequirement, RequiredCheck, VerificationSpec, digest,
};
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

const RECEIPT_SCHEMA: u16 = 2;
const MAX_RECEIPT_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlCheckObservation {
    RowCount {
        rows: u64,
    },
    Performance {
        median_ms: f64,
        p95_ms: f64,
        warmups: u8,
        samples: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlCheckOutcome {
    check: RequiredCheck,
    criterion: CriterionRequirement,
    observation: SqlCheckObservation,
    passed: bool,
}

impl SqlCheckOutcome {
    fn observed_criterion_value(&self) -> Result<f64> {
        match (
            &self.check,
            &self.observation,
            self.criterion.measure.as_str(),
        ) {
            (
                RequiredCheck::SqlFunctional { .. },
                SqlCheckObservation::RowCount { rows },
                "SQL row count",
            ) => {
                ensure!(*rows <= 100_000, "SQL row count exceeds fixture bound");
                Ok(*rows as f64)
            }
            (
                RequiredCheck::Performance { .. },
                SqlCheckObservation::Performance { median_ms, .. },
                "Median latency",
            ) => Ok(*median_ms),
            (
                RequiredCheck::Performance { .. },
                SqlCheckObservation::Performance { p95_ms, .. },
                "P95 latency",
            ) => Ok(*p95_ms),
            _ => anyhow::bail!("SQL check observation does not prove criterion"),
        }
    }

    fn validate(&self) -> Result<()> {
        self.check.validate()?;
        self.criterion.validate()?;
        ensure!(
            self.check.implies_criterion(&self.criterion),
            "SQL criterion differs from check"
        );
        let check_passed = match (&self.check, &self.observation) {
            (
                RequiredCheck::SqlFunctional {
                    expected_row_count, ..
                },
                SqlCheckObservation::RowCount { rows },
            ) => rows == expected_row_count,
            (
                RequiredCheck::Performance {
                    maximum_median_ms,
                    maximum_p95_ms,
                    minimum_warmups,
                    minimum_samples,
                    ..
                },
                SqlCheckObservation::Performance {
                    median_ms,
                    p95_ms,
                    warmups,
                    samples,
                },
            ) => {
                median_ms.is_finite()
                    && p95_ms.is_finite()
                    && *median_ms > 0.0
                    && *p95_ms >= *median_ms
                    && *median_ms <= *maximum_median_ms as f64
                    && *p95_ms <= *maximum_p95_ms as f64
                    && warmups >= minimum_warmups
                    && samples >= minimum_samples
                    && *samples <= 64
            }
            _ => false,
        };
        let observed = self.observed_criterion_value()?;
        ensure!(
            observed.is_finite(),
            "SQL criterion observation is not finite"
        );
        let threshold = f64::from_bits(self.criterion.threshold_bits);
        let criterion_passed = match self.criterion.comparator {
            CriterionComparator::AtMost => observed <= threshold,
            CriterionComparator::AtLeast => observed >= threshold,
            CriterionComparator::Equal => observed == threshold,
        };
        ensure!(
            self.passed && check_passed && criterion_passed,
            "Required SQL check or paired criterion failed"
        );
        Ok(())
    }
}

fn evaluate_required_checks(
    spec: &VerificationSpec,
    production_scope_sha256: &str,
    object_id: u64,
    workload_sha256: &str,
    data: &benchmark::FixtureDataObservation,
    samples: &benchmark::WorkloadSamples,
) -> Result<Vec<SqlCheckOutcome>> {
    spec.validate()?;
    ensure!(
        samples.compatibility.is_complete(),
        "Native SQL compatibility incomplete"
    );
    let mut outcomes = Vec::with_capacity(spec.checks.len());
    for (check, criterion) in spec.checks.iter().zip(&spec.criteria) {
        let observation = match check {
            RequiredCheck::SqlFunctional {
                scope_sha256,
                object_id: check_object,
                ..
            } if scope_sha256 == production_scope_sha256 && *check_object == object_id => {
                SqlCheckObservation::RowCount {
                    rows: data.row_count,
                }
            }
            RequiredCheck::Performance {
                scope_sha256,
                object_id: check_object,
                workload_sha256: check_workload,
                ..
            } if scope_sha256 == production_scope_sha256
                && *check_object == object_id
                && check_workload == workload_sha256 =>
            {
                SqlCheckObservation::Performance {
                    median_ms: samples.median_ms,
                    p95_ms: samples.p95_ms,
                    warmups: samples.warmups,
                    samples: u8::try_from(samples.milliseconds.len())
                        .context("SQL sample count exceeds bound")?,
                }
            }
            _ => anyhow::bail!("Required SQL check is outside reviewed object or workload"),
        };
        let outcome = SqlCheckOutcome {
            check: check.clone(),
            criterion: criterion.clone(),
            observation,
            passed: true,
        };
        outcome.validate()?;
        outcomes.push(outcome);
    }
    ensure!(
        outcomes.len() == spec.checks.len(),
        "Required SQL checks incomplete"
    );
    Ok(outcomes)
}

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
    fn validate_content(&self) -> Result<()> {
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
                && self.expires_at <= self.reviewed_at + Duration::minutes(5),
            "Invalid isolated SQL trial mapping content"
        );
        Ok(())
    }
    fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate_content()?;
        ensure!(
            self.reviewed_at <= now && self.expires_at > now,
            "Expired isolated SQL trial mapping"
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_at(Utc::now())
    }

    pub fn fingerprint(&self) -> Result<String> {
        self.validate_content()?;
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
            matches!(staging_change, BoundScope::Database { target, engine: DatabaseEngine::Postgres, port: 55434, database, .. }
                if target.host == "127.0.0.1" && database == templates::REHEARSAL_DATABASE)
                || matches!(staging_change, BoundScope::Database { target, engine: DatabaseEngine::SqlServer, port, database, .. }
                    if target.host == "127.0.0.1"
                        && *port == templates::TDS_REHEARSAL_PORT
                        && database == templates::REHEARSAL_DATABASE),
            "Only versioned isolated SQL rehearsal fixtures are reviewed"
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlRehearsalReceipt {
    schema: u16,
    receipt_id: Uuid,
    run_id: Uuid,
    approval_id: Uuid,
    consume_id: Uuid,
    binding_fingerprint: String,
    case_id: Uuid,
    case_revision: u64,
    mapping_sha256: String,
    production_scope_sha256: String,
    production_physical_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    production_before_sha256: Option<String>,
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
    check_outcomes: Vec<SqlCheckOutcome>,
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
    pub(crate) fn production_physical_sha256(&self) -> &str {
        &self.production_physical_sha256
    }

    pub(crate) fn validate_for_production(
        &self,
        case: &HelperCase,
        proposal: &HelperProposal,
        binding: &crate::helper_approval::ActionBindingV2,
        journal: &ActionJournal,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate(now)?;
        ensure!(
            load_sql_rehearsal(&self.path()?)? == *self,
            "Protected SQL rehearsal receipt differs"
        );
        let staged = journal.intents().iter().find(|intent| {
            intent.run_id == self.run_id
                && intent.case_id == self.case_id
                && intent.approval_id == self.approval_id
                && intent.consume_id == self.consume_id
                && intent.binding_fingerprint == self.binding_fingerprint
                && intent.state == IntentState::Verified
                && intent.native_receipt_sha256.as_deref() == Some(self.content_sha256.as_str())
        });
        ensure!(
            staged.is_some(),
            "Protected rehearsal is not a verified native journal outcome"
        );
        self.validate_production_coverage(case.id(), case.revision(), proposal, binding)?;
        Ok(())
    }
    fn validate_production_coverage(
        &self,
        case_id: Uuid,
        case_revision: u64,
        proposal: &HelperProposal,
        binding: &crate::helper_approval::ActionBindingV2,
    ) -> Result<()> {
        let CatalogAction::Sql { action, .. } = &proposal.action else {
            anyhow::bail!("Current proposal is not typed SQL action")
        };
        ensure!(
            self.case_id == case_id
                && self.case_revision == case_revision
                && binding.case_id == case_id
                && binding.case_revision == case_revision
                && self.production_scope_sha256 == binding.scope_sha256
                && self.action_sha256 == digest(b"relayne-helper-sql-action-v1", action)?
                && binding.action == *action
                && self.verification_sha256
                    == digest(
                        b"relayne-helper-reviewed-verification-v2",
                        &proposal.verification
                    )?
                && binding.verification_sha256 == self.verification_sha256
                && self.production_before_sha256.as_deref() == Some(binding.before_sha256.as_str())
                && self.staging_scope_sha256 != self.production_scope_sha256
                && self.staging_physical_sha256 != self.production_physical_sha256
                && self.complete_native_compatibility
                && self.check_outcomes.iter().all(|outcome| outcome.passed)
                && self.check_outcomes.len() == proposal.verification.checks.len()
                && self
                    .check_outcomes
                    .iter()
                    .zip(
                        proposal
                            .verification
                            .checks
                            .iter()
                            .zip(&proposal.verification.criteria)
                    )
                    .all(|(outcome, (check, criterion))| {
                        &outcome.check == check && &outcome.criterion == criterion
                    })
                && self.statistics_nonrestorable == action.is_statistics()
                && (!action.is_statistics()
                    || (proposal.statistics_limit_acknowledged
                        && binding.statistics_limit_acknowledged)),
            "Rehearsal receipt does not cover current production action and checks"
        );
        Ok(())
    }

    /// Terminal verification uses the actual protected receipt, not a caller
    /// supplied digest. Every identity and native after-state must be exact.
    pub(crate) fn validate_native_proof(
        &self,
        proof: &changes::NativeActionProof,
        intent: &IntentRecord,
    ) -> Result<()> {
        self.validate(Utc::now())?;
        let stored = load_sql_rehearsal(&self.path()?)?;
        ensure!(
            stored == *self,
            "Protected SQL receipt differs from native outcome"
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
                && self.production_scope_sha256 == identity.scope_sha256()
                && self.action_sha256 == identity.action_sha256()
                && self.before_sha256 == proof.before_sha256()
                && proof.after_sha256() == Some(self.after_sha256.as_str())
                && self.created_index_id == proof.created_index_id()
                && self.created_index_definition_sha256.as_deref()
                    == proof.created_index_definition_sha256()
                && self.ownership_marker_sha256.as_deref() == proof.ownership_marker_sha256(),
            "Protected SQL receipt is not the native terminal proof"
        );
        Ok(())
    }

    fn fingerprint(&self) -> Result<String> {
        let mut content = self.clone();
        content.content_sha256.clear();
        digest(b"relayne-helper-sql-rehearsal-receipt-v2", &content)
    }
    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.production_before_sha256
                .as_deref()
                .is_none_or(is_digest),
            "Invalid production before-state in rehearsal receipt"
        );
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
                && !self.check_outcomes.is_empty()
                && self.check_outcomes.len() <= 16
                && self
                    .check_outcomes
                    .iter()
                    .all(|check| check.validate().is_ok())
                && self.content_sha256 == self.fingerprint()?,
            "Invalid, stale or tampered SQL rehearsal receipt"
        );
        for digest in [
            &self.mapping_sha256,
            &self.binding_fingerprint,
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
        mapping.validate_content()?;
        let CatalogAction::Sql { action, .. } = &proposal.action else {
            anyhow::bail!("SQL proposal required for rehearsal receipt")
        };
        ensure!(
            self.check_outcomes.len() == proposal.verification.checks.len()
                && self
                    .check_outcomes
                    .iter()
                    .zip(
                        proposal
                            .verification
                            .checks
                            .iter()
                            .zip(&proposal.verification.criteria)
                    )
                    .all(|(outcome, (check, criterion))| {
                        &outcome.check == check && &outcome.criterion == criterion
                    }),
            "Protected SQL receipt omits or changes required checks"
        );
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
    pub(crate) fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
    pub fn run_id(&self) -> Uuid {
        self.run_id
    }
    #[cfg(test)]
    pub(crate) fn guest_production_before_sha256(&self) -> Option<&str> {
        self.production_before_sha256.as_deref()
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

/// Resolve a team binding's opaque receipt ID only through protected local
/// files. The earlier staging format names files by run ID, not receipt ID.
pub(crate) fn load_protected_rehearsal_by_id(id: Uuid) -> Result<SqlRehearsalReceipt> {
    ensure!(id != Uuid::nil(), "Rehearsal receipt ID missing");
    let directory = crate::security::app_data_file("relayne-helper-sql-rehearsal-index.dpapi")?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Protected receipt directory missing"))?
        .to_path_buf();
    let mut seen = 0usize;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("relayne-helper-sql-rehearsal-") || !name.ends_with(".dpapi") {
            continue;
        }
        seen += 1;
        ensure!(seen <= 10_000, "Protected receipt search bound exceeded");
        let Ok(receipt) = load_sql_rehearsal(&entry.path()) else {
            // Historical expired or unreadable receipts carry no authority.
            continue;
        };
        if receipt.receipt_id == id {
            return Ok(receipt);
        }
    }
    anyhow::bail!("Protected SQL rehearsal receipt missing")
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
    // Verify the protected started intent before any native connection.
    ActionJournal::require_durable_started(journal_path, intent_id, &permit)?;
    let native_identity = changes::NativeActionIdentity::from_permit(&permit)?;
    let run_id = native_identity.run_id();
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
            let uncertain = changes::NativeActionProof::uncertain(native_identity, before_sha256);
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
    let admitted_mapping_sha256 = mapping.fingerprint()?;
    ensure!(
        permit.binding().run_kind == RunKind::Rehearsal
            && permit.binding().case_id == case.id()
            && permit.binding().case_revision == case.revision()
            && permit.binding().before_sha256 == mapping.production_before_sha256
            && permit.binding().action.object().scope_sha256 == mapping.production_scope_sha256
            && matches!(&permit.binding().proof,
            ActionProof::StagingReviewProof { mapping_sha256, staging_scope_sha256, staging_physical_sha256, .. }
            if mapping_sha256 == &admitted_mapping_sha256
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
    let source_matches = match action.object().engine {
        crate::helper_action::SqlEngine::Postgres => {
            benchmark::metadata_matches(&source.sql_observations, mapping.template)
        }
        crate::helper_action::SqlEngine::SqlServer => {
            benchmark::sql_server_metadata_matches(&source.sql_observations, mapping.template)
        }
    };
    ensure!(
        source.capability_id == crate::helper::manifest::CapabilityId::SqlRead
            && source.binding.case_id == case.id()
            && source.binding.case_revision == case.revision()
            && source.binding.scope_sha256 == production_read.digest()?
            && source.binding.credential_scope_sha256
                == production_read.credential_scope_digest()?
            && source.eligibility(Utc::now(), Duration::minutes(5))
                == crate::helper::evidence::Eligibility::Eligible
            && source_matches,
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
    // A review may expire while bounded read-only preflight and sampling run.
    // Refuse native dispatch unless the same mapping is still fresh here.
    mapping.validate()?;
    let postcommit_workload = benchmark::admit_postcommit_workload(&workload)?;
    let native_identity = changes::NativeActionIdentity::from_permit(&permit)?;
    let proof = match changes::execute_sql_change(
        permit,
        intent_id,
        journal_path,
        stage_change,
        &trial,
        cancel.clone(),
    )
    .await
    {
        Ok(proof) => proof,
        Err(error) => {
            let uncertain = changes::NativeActionProof::uncertain(
                native_identity,
                trial.preflight.before_sha256().to_owned(),
            );
            let mut journal = ActionJournal::load(journal_path)?;
            journal.record_native_outcome(intent_id, &uncertain, None)?;
            return Err(
                error.context("Native dispatch outcome uncertain; reconcile before another action")
            );
        }
    };
    if proof.state() != NativeActionState::Verified {
        let mut journal = ActionJournal::load(journal_path)?;
        journal.record_native_outcome(intent_id, &proof, None)?;
        anyhow::bail!(
            "Native SQL action failed or outcome is uncertain; reconcile run before another action"
        );
    }
    // Once native SQL has committed, every later error must durably close the
    // dispatch as needing intervention. The consumed permit is never retried.
    let completed: Result<SqlRehearsalReceipt> = async {
        let after = benchmark::run_admitted_postcommit_workload(
            &postcommit_workload,
            &policy,
            cancel.clone(),
        )
        .await
        .context("PostcommitWorkload")?;
        let after_data = benchmark::fixture_data_observation(stage_read, mapping.template, cancel)
            .await
            .context("PostcommitData")?;
        ensure!(
            after.compatibility.is_complete()
                && before.result_sha256 == after.result_sha256
                && after.warmups >= 3
                && after.milliseconds.len() >= 15
                && after_data.sha256 == mapping.synthetic_data_sha256,
            "PostcommitComparison: staged workload/result/coverage incomplete after action"
        );
        let check_outcomes = evaluate_required_checks(
            &proposal.verification,
            &production_read.digest()?,
            metadata.object.object_id,
            &mapping.template.fingerprint(production_read)?,
            &after_data,
            &after,
        )
        .context("PostcommitRequiredChecks")?;
        let now = Utc::now();
        let mut receipt = SqlRehearsalReceipt {
            schema: RECEIPT_SCHEMA,
            receipt_id: Uuid::new_v4(),
            run_id: proof.run_id(),
            approval_id: proof.identity().approval_id(),
            consume_id: proof.identity().consume_id(),
            binding_fingerprint: proof.identity().binding_fingerprint().to_owned(),
            case_id: case.id(),
            case_revision: case.revision(),
            mapping_sha256: admitted_mapping_sha256,
            production_scope_sha256: mapping.production_scope_sha256.clone(),
            production_physical_sha256: mapping.production_physical_sha256.clone(),
            production_before_sha256: Some(mapping.production_before_sha256.clone()),
            staging_scope_sha256: mapping.staging_scope_sha256.clone(),
            staging_physical_sha256: mapping.staging_physical_sha256.clone(),
            action_sha256: mapping.action_sha256.clone(),
            verification_sha256: mapping.verification_sha256.clone(),
            before_sha256: proof.before_sha256().to_owned(),
            after_sha256: proof
                .after_sha256()
                .context("Native SQL committed readback missing")?
                .to_owned(),
            synthetic_data_sha256: mapping.synthetic_data_sha256.clone(),
            workload_result_sha256: after.result_sha256,
            workload_before_median_ms: before.median_ms,
            workload_after_median_ms: after.median_ms,
            check_outcomes,
            complete_native_compatibility: true,
            created_index_id: proof.created_index_id(),
            created_index_definition_sha256: proof
                .created_index_definition_sha256()
                .map(str::to_owned),
            ownership_marker_sha256: proof.ownership_marker_sha256().map(str::to_owned),
            statistics_nonrestorable: action.is_statistics(),
            reviewed_limits: mapping.reviewed_limits.clone(),
            created_at: now,
            expires_at: now + Duration::hours(1),
            content_sha256: String::new(),
        };
        let mut journal = ActionJournal::load(journal_path).context("PostcommitJournalRecord")?;
        receipt.content_sha256 = receipt
            .fingerprint()
            .context("PostcommitReceiptIntegrity")?;
        receipt.save().context("PostcommitReceiptIntegrity")?;
        journal
            .record_native_outcome(intent_id, &proof, Some(&receipt))
            .context("PostcommitJournalRecord")?;
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
