//! Production verification is independent of rehearsal and of action dispatch.
//! A receipt records what was observed, including missing coverage, and never
//! turns an inconclusive check into a successful repair.

use super::sql::benchmark::{
    capture_typed_compatibility, run_functional_row_count, run_sandbox_workload, ReviewedWorkload,
    SamplingPolicy, TypedCompatibilitySnapshot,
};
use super::{
    case::{CaseResolution, Comparator, HelperCase},
    evidence::is_digest,
    journal::{ActionJournal, IntentState},
    scope::BoundScope,
    sql::benchmark::summary,
};
use crate::helper_action::{CriterionComparator, RequiredCheck, SqlAction, VerificationSpec};
use crate::helper_approval::{ActionApprovalStateV2, ActionApprovalV2, RunKind};
use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const POLICY_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RunReference {
    GenericProduction {
        run_id: Uuid,
        binding_sha256: String,
        production_receipt_sha256: Option<String>,
    },
    ExistingService {
        run_id: Uuid,
        target_index: usize,
        execution_plan_sha256: String,
    },
}

impl RunReference {
    pub fn run_id(&self) -> Uuid {
        match self {
            Self::GenericProduction { run_id, .. } | Self::ExistingService { run_id, .. } => {
                *run_id
            }
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.run_id().is_nil(), "Missing production run");
        match self {
            Self::GenericProduction {
                binding_sha256,
                production_receipt_sha256,
                ..
            } => ensure!(
                is_digest(binding_sha256)
                    && production_receipt_sha256.as_deref().is_none_or(is_digest),
                "Invalid production binding"
            ),
            Self::ExistingService {
                execution_plan_sha256,
                ..
            } => ensure!(
                is_digest(execution_plan_sha256),
                "Invalid service plan binding"
            ),
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VerificationPlan {
    pub case_id: Uuid,
    pub case_revision: u64,
    pub evidence_revision: u64,
    pub run: RunReference,
    pub verification: VerificationSpec,
    pub approved_verification_sha256: String,
    pub http_scopes: Vec<BoundScope>,
    pub sql_targets: Vec<SqlFunctionalTarget>,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SqlFunctionalTarget {
    pub scope_sha256: String,
    pub object_id: u64,
    pub workload: ReviewedWorkload,
}

impl VerificationPlan {
    pub fn content_sha256(&self) -> Result<String> {
        let sql_targets: Vec<_> = self
            .sql_targets
            .iter()
            .map(|target| {
                Ok::<_, anyhow::Error>((
                    &target.scope_sha256,
                    target.object_id,
                    target.workload.identity_sha256()?,
                ))
            })
            .collect::<Result<_>>()?;
        crate::helper_action::digest(
            b"relayne-helper-verification-plan-v1",
            &(
                self.case_id,
                self.case_revision,
                self.evidence_revision,
                &self.run,
                &self.verification,
                &self.approved_verification_sha256,
                &self.http_scopes,
                sql_targets,
                self.captured_at,
            ),
        )
    }
    pub fn validate(&self, case: &HelperCase) -> Result<()> {
        ensure!(
            self.case_id == case.id()
                && self.case_revision == case.revision()
                && self.evidence_revision == case.evidence_revision(),
            "Stale verification plan"
        );
        self.run.validate()?;
        self.verification.validate()?;
        ensure!(
            crate::helper_action::digest(
                b"relayne-helper-reviewed-verification-v2",
                &self.verification
            )? == self.approved_verification_sha256,
            "Approved verification digest mismatch"
        );
        ensure!(
            self.captured_at <= Utc::now() + chrono::Duration::seconds(30),
            "Invalid verification capture time"
        );
        let reviewed: Vec<_> = case
            .intake()
            .success_criteria
            .iter()
            .filter(|criterion| criterion.reviewed)
            .collect();
        ensure!(
            reviewed.len() == self.verification.criteria.len(),
            "Verification criteria differ reviewed case"
        );
        for requirement in &self.verification.criteria {
            ensure!(
                reviewed
                    .iter()
                    .filter(|criterion| criterion.measure == requirement.measure
                        && criterion.unit == requirement.unit
                        && criterion.window == requirement.window
                        && criterion.threshold.to_bits() == requirement.threshold_bits
                        && requirement.comparator
                            == match criterion.comparator {
                                Comparator::AtMost => CriterionComparator::AtMost,
                                Comparator::AtLeast => CriterionComparator::AtLeast,
                                Comparator::Equal => CriterionComparator::Equal,
                            })
                    .count()
                    == 1,
                "Verification criterion changed"
            );
        }
        let mut seen = std::collections::HashSet::new();
        for check in &self.verification.checks {
            check.validate()?;
            let encoded = serde_json::to_vec(check)?;
            ensure!(seen.insert(encoded), "Duplicate verification check");
            if let RequiredCheck::HttpFunctional { scope_sha256, .. } = check {
                ensure!(
                    self.http_scopes
                        .iter()
                        .any(|scope| matches!(scope, BoundScope::Http { .. })
                            && scope.digest().ok().as_deref() == Some(scope_sha256)),
                    "Missing reviewed HTTP target"
                );
            }
            if let RequiredCheck::SqlFunctional {
                scope_sha256,
                object_id,
                ..
            } = check
            {
                ensure!(
                    self.sql_targets
                        .iter()
                        .filter(|target| target.scope_sha256 == *scope_sha256
                            && target.object_id == *object_id
                            && target.workload.scope_digest().ok().as_deref() == Some(scope_sha256)
                            && target.workload.case_binding() == (case.id(), case.revision()))
                        .count()
                        == 1,
                    "Missing reviewed native SQL functional target"
                );
            }
        }
        for scope in &self.http_scopes {
            ensure!(
                matches!(scope, BoundScope::Http { .. })
                    && case
                        .scopes()
                        .iter()
                        .any(|saved| saved.digest().ok() == scope.digest().ok()),
                "Unreviewed HTTP target"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    Failed,
    Unknown,
    Incomplete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalCheckReceipt {
    pub check: RequiredCheck,
    pub outcome: CheckOutcome,
    pub observed_http_status: Option<u16>,
    pub observed_row_count: Option<u64>,
    pub observed_body_sha256: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalReceipt {
    pub case_id: Uuid,
    pub case_revision: u64,
    pub evidence_revision: u64,
    pub verification_plan_sha256: String,
    pub run: RunReference,
    pub captured_at: DateTime<Utc>,
    pub verification: VerificationSpec,
    pub approved_verification_sha256: String,
    pub checks: Vec<FunctionalCheckReceipt>,
}

impl FunctionalReceipt {
    pub fn content_sha256(&self) -> Result<String> {
        self.validate()?;
        crate::helper_action::digest(b"relayne-helper-functional-receipt-v1", self)
    }
    pub fn id(&self) -> Result<Uuid> {
        receipt_id(&self.content_sha256()?)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            is_digest(&self.verification_plan_sha256),
            "Verification plan identity invalid"
        );
        self.run.validate()?;
        self.verification.validate()?;
        ensure!(
            crate::helper_action::digest(
                b"relayne-helper-reviewed-verification-v2",
                &self.verification
            )? == self.approved_verification_sha256,
            "Receipt verification digest mismatch"
        );
        ensure!(
            !self.case_id.is_nil()
                && self.case_revision > 0
                && self.checks.len() == self.verification.checks.len(),
            "Invalid functional receipt"
        );
        let mut seen = std::collections::HashSet::new();
        for (item, expected) in self.checks.iter().zip(&self.verification.checks) {
            ensure!(
                item.observed_at.is_none_or(|at| at <= self.captured_at),
                "Check observation postdates receipt"
            );
            item.check.validate()?;
            ensure!(
                &item.check == expected,
                "Receipt check differs reviewed specification"
            );
            ensure!(
                seen.insert(serde_json::to_vec(&item.check)?),
                "Duplicate result"
            );
            ensure!(
                item.observed_http_status
                    .is_none_or(|v| (100..=599).contains(&v))
                    && item.observed_body_sha256.as_deref().is_none_or(is_digest),
                "Invalid HTTP observation"
            );
            ensure!(
                item.outcome != CheckOutcome::Passed || item.observed_at.is_some(),
                "Passing check lacks observation"
            );
            if let RequiredCheck::HttpFunctional {
                expected_status,
                body_sha256,
                ..
            } = &item.check
            {
                if item.outcome == CheckOutcome::Passed {
                    ensure!(
                        item.observed_http_status == Some(*expected_status)
                            && body_sha256
                                .as_ref()
                                .is_none_or(|v| item.observed_body_sha256.as_ref() == Some(v)),
                        "HTTP proof contradicts check"
                    );
                }
            }
            if let RequiredCheck::SqlFunctional {
                expected_row_count, ..
            } = &item.check
            {
                if item.outcome == CheckOutcome::Passed {
                    ensure!(
                        item.observed_row_count == Some(*expected_row_count),
                        "SQL row count contradicts check"
                    );
                }
            }
        }
        Ok(())
    }
    pub fn all_passed(&self) -> bool {
        self.validate().is_ok()
            && self.checks.iter().any(|c| c.check.functional())
            && self
                .checks
                .iter()
                .filter(|c| c.check.functional())
                .all(|c| c.outcome == CheckOutcome::Passed)
    }
}

/// Performs the reviewed HTTP GETs. A SQL check needs a separate native
/// production observation and is recorded incomplete until supplied.
pub async fn run_checks(
    plan: &VerificationPlan,
    run: &RunReference,
    cancel: CancellationToken,
) -> Result<FunctionalReceipt> {
    ensure!(&plan.run == run, "Verification run mismatch");
    run.validate()?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut checks = Vec::with_capacity(plan.verification.checks.len());
    for check in &plan.verification.checks {
        let mut result = FunctionalCheckReceipt {
            check: check.clone(),
            outcome: CheckOutcome::Incomplete,
            observed_http_status: None,
            observed_row_count: None,
            observed_body_sha256: None,
            observed_at: None,
        };
        if let RequiredCheck::HttpFunctional {
            scope_sha256,
            expected_status,
            body_sha256,
            ..
        } = check
        {
            if let Some(BoundScope::Http {
                target,
                port,
                tls,
                path,
            }) = plan
                .http_scopes
                .iter()
                .find(|s| s.digest().ok().as_deref() == Some(scope_sha256))
            {
                if target.route.is_empty() {
                    let url = super::scope::reviewed_http_url(target, *port, *tls, path)?;
                    let response = tokio::select! { _ = cancel.cancelled() => None, value = client.get(url).send() => value.ok() };
                    if let Some(mut response) = response {
                        result.observed_http_status = Some(response.status().as_u16());
                        let mut hash = Sha256::new();
                        let mut length = 0usize;
                        let mut complete = true;
                        loop {
                            let chunk = tokio::select! { _ = cancel.cancelled() => Err(()), value = response.chunk() => value.map_err(|_| ()) };
                            let chunk = match chunk {
                                Ok(Some(chunk)) => chunk,
                                Ok(None) => break,
                                Err(()) => {
                                    complete = false;
                                    break;
                                }
                            };
                            length = length.saturating_add(chunk.len());
                            if length > 64 * 1024 {
                                complete = false;
                                break;
                            }
                            hash.update(&chunk);
                        }
                        result.observed_at = Some(Utc::now());
                        if complete && !cancel.is_cancelled() {
                            result.observed_body_sha256 = Some(format!("{:x}", hash.finalize()));
                            result.outcome = if result.observed_http_status
                                == Some(*expected_status)
                                && body_sha256
                                    .as_ref()
                                    .is_none_or(|v| result.observed_body_sha256.as_ref() == Some(v))
                            {
                                CheckOutcome::Passed
                            } else {
                                CheckOutcome::Failed
                            };
                        } else {
                            result.outcome = CheckOutcome::Incomplete;
                        }
                    } else {
                        result.outcome = CheckOutcome::Unknown;
                    }
                }
            }
        }
        if let RequiredCheck::SqlFunctional {
            scope_sha256,
            object_id,
            expected_row_count,
            ..
        } = check
        {
            if let Some(target) = plan.sql_targets.iter().find(|target| {
                target.scope_sha256 == *scope_sha256 && target.object_id == *object_id
            }) {
                match run_functional_row_count(&target.workload, cancel.clone()).await {
                    Ok(count) => {
                        result.observed_row_count = Some(count);
                        result.observed_at = Some(Utc::now());
                        result.outcome = if count == *expected_row_count {
                            CheckOutcome::Passed
                        } else {
                            CheckOutcome::Failed
                        };
                    }
                    Err(_) => result.outcome = CheckOutcome::Unknown,
                }
            }
        }
        checks.push(result);
    }
    let receipt = FunctionalReceipt {
        case_id: plan.case_id,
        case_revision: plan.case_revision,
        evidence_revision: plan.evidence_revision,
        verification_plan_sha256: plan.content_sha256()?,
        run: run.clone(),
        captured_at: Utc::now(),
        verification: plan.verification.clone(),
        approved_verification_sha256: plan.approved_verification_sha256.clone(),
        checks,
    };
    receipt.validate()?;
    Ok(receipt)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceReceipt {
    pub policy_version: u16,
    pub case_id: Uuid,
    pub case_revision: u64,
    pub evidence_revision: u64,
    pub run: RunReference,
    pub phase: PerformancePhase,
    pub captured_at: DateTime<Utc>,
    pub scope_sha256: String,
    pub workload_sha256: String,
    pub result_sha256: String,
    pub host_sha256: String,
    pub engine_sha256: String,
    pub build_sha256: String,
    pub dataset_sha256: String,
    pub session_sha256: String,
    pub live_metadata_sha256: String,
    pub typed_context: TypedCompatibilitySnapshot,
    pub approved_action: Option<SqlAction>,
    pub approved_index_definition_sha256: Option<String>,
    pub approved_index_marker_sha256: Option<String>,
    pub approved_change_sha256: Option<String>,
    pub warmups: u8,
    pub samples_ms: Vec<f64>,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub mad_ms: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformancePhase {
    BeforeProduction,
    AfterProduction,
}

impl PerformanceReceipt {
    pub fn content_sha256(&self) -> Result<String> {
        self.validate()?;
        crate::helper_action::digest(b"relayne-helper-performance-receipt-v1", self)
    }
    pub fn id(&self) -> Result<Uuid> {
        receipt_id(&self.content_sha256()?)
    }
    pub fn validate(&self) -> Result<()> {
        self.run.validate()?;
        ensure!(
            self.policy_version == POLICY_VERSION
                && !self.case_id.is_nil()
                && self.case_revision > 0
                && self.warmups >= 3,
            "Invalid sampling policy"
        );
        for value in [
            &self.scope_sha256,
            &self.workload_sha256,
            &self.result_sha256,
            &self.host_sha256,
            &self.engine_sha256,
            &self.build_sha256,
            &self.dataset_sha256,
            &self.session_sha256,
            &self.live_metadata_sha256,
        ] {
            ensure!(is_digest(value), "Invalid performance context");
        }
        ensure!(
            self.approved_change_sha256.as_deref().is_none_or(is_digest),
            "Invalid approved delta"
        );
        let (median, p95, mad) = summary(&self.samples_ms)?;
        ensure!(
            self.median_ms.to_bits() == median.to_bits()
                && self.p95_ms.to_bits() == p95.to_bits()
                && self.mad_ms.to_bits() == mad.to_bits(),
            "Performance summary differs raw samples"
        );
        ensure!(
            matches!(
                (self.phase, self.approved_change_sha256.is_some()),
                (PerformancePhase::BeforeProduction, false)
                    | (PerformancePhase::AfterProduction, true)
            ),
            "Invalid performance phase delta"
        );
        self.typed_context.validate()?;
        ensure!(
            self.approved_index_definition_sha256
                .as_deref()
                .is_none_or(is_digest)
                && self
                    .approved_index_marker_sha256
                    .as_deref()
                    .is_none_or(is_digest),
            "Approved index proof invalid"
        );
        ensure!(
            self.typed_context.data_sha256 == self.dataset_sha256,
            "Native typed coverage differs sample context"
        );
        ensure!(
            match self.approved_action.as_ref() {
                Some(SqlAction::PostgresCreateIndex { .. } | SqlAction::PostgresAnalyze { .. }) =>
                    self.typed_context.engine
                        == super::sql::benchmark::CompatibilityEngine::Postgres,
                Some(
                    SqlAction::SqlServerCreateIndex { .. }
                    | SqlAction::SqlServerUpdateStatistics { .. },
                ) =>
                    self.typed_context.engine
                        == super::sql::benchmark::CompatibilityEngine::SqlServer,
                None => true,
            },
            "Native typed engine differs approved action"
        );
        match (&self.run, self.phase) {
            (
                RunReference::GenericProduction {
                    production_receipt_sha256: None,
                    ..
                },
                PerformancePhase::BeforeProduction,
            ) if self.approved_action.is_none() => {}
            (
                RunReference::GenericProduction {
                    production_receipt_sha256: Some(receipt),
                    ..
                },
                PerformancePhase::AfterProduction,
            ) if self.approved_change_sha256.as_ref() == Some(receipt)
                && self
                    .approved_action
                    .as_ref()
                    .is_some_and(|action| action.object().scope_sha256 == self.scope_sha256) => {}
            _ => anyhow::bail!("Performance sample is not bound to exact production phase"),
        }
        match (&self.approved_action, self.phase) {
            (None, PerformancePhase::BeforeProduction) => ensure!(
                self.approved_index_definition_sha256.is_none()
                    && self.approved_index_marker_sha256.is_none(),
                "Baseline cannot carry action proof"
            ),
            (
                Some(
                    SqlAction::PostgresCreateIndex { .. } | SqlAction::SqlServerCreateIndex { .. },
                ),
                PerformancePhase::AfterProduction,
            ) => ensure!(
                self.approved_index_definition_sha256.is_some()
                    && self.approved_index_marker_sha256.is_some(),
                "Created index proof incomplete"
            ),
            (
                Some(
                    SqlAction::PostgresAnalyze { .. } | SqlAction::SqlServerUpdateStatistics { .. },
                ),
                PerformancePhase::AfterProduction,
            ) => ensure!(
                self.approved_index_definition_sha256.is_none()
                    && self.approved_index_marker_sha256.is_none(),
                "Statistics receipt cannot claim owned index"
            ),
            _ => anyhow::bail!("Performance action phase mismatch"),
        }
        Ok(())
    }
}

fn receipt_id(hash: &str) -> Result<Uuid> {
    ensure!(is_digest(hash), "Receipt hash invalid");
    let mut id = [0u8; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)?;
    }
    Ok(Uuid::from_bytes(id))
}

/// Samples the reviewed fixed SELECT against the exact native production
/// target. Admission and final state are read from the durable journal on
/// both sides of measurement, so a concurrent launch cannot turn a late
/// baseline into a pre-effect baseline.
pub async fn capture_production_performance(
    case: &HelperCase,
    run: &RunReference,
    phase: PerformancePhase,
    workload: &ReviewedWorkload,
    approval: Option<&ActionApprovalV2>,
    cancel: CancellationToken,
) -> Result<PerformanceReceipt> {
    let journal_path = ActionJournal::path()?;
    let before_journal = ActionJournal::load(&journal_path)?;
    if phase == PerformancePhase::BeforeProduction {
        check_baseline_approval(
            approval.ok_or_else(|| anyhow::anyhow!("Production approval required for baseline"))?,
            case,
            run,
        )?;
        ensure!(
            !before_journal
                .intents()
                .iter()
                .any(|intent| intent.run_id == run.run_id()),
            "Baseline must precede dispatch intent"
        );
    } else {
        check_capture_admission(&before_journal, case, run, phase)?;
    }
    let policy = SamplingPolicy::default();
    let typed_before = capture_typed_compatibility(workload, cancel.clone()).await?;
    let samples = run_sandbox_workload(workload, &policy, cancel.clone()).await?;
    let typed_after = capture_typed_compatibility(workload, cancel).await?;
    ensure!(
        typed_before == typed_after,
        "Native context drifted during sampling"
    );
    let after_journal = ActionJournal::load(&journal_path)?;
    if phase == PerformancePhase::BeforeProduction {
        ensure!(
            !after_journal
                .intents()
                .iter()
                .any(|intent| intent.run_id == run.run_id()),
            "Action launched during baseline sampling"
        );
    } else {
        check_capture_admission(&after_journal, case, run, phase)?;
    }
    ensure!(
        samples.case_id == case.id()
            && samples.case_revision == case.revision()
            && case
                .scopes()
                .iter()
                .any(|scope| scope.digest().ok().as_deref() == Some(samples.scope_sha256.as_str())),
        "Production workload differs case"
    );
    ensure!(
        samples.policy_version == POLICY_VERSION
            && samples.warmups >= 3
            && samples.milliseconds.len() >= 15
            && samples.compatibility.is_complete(),
        "Native sampling coverage incomplete"
    );
    let engine_sha256 = format!(
        "{:x}",
        Sha256::digest(format!("{:?}", samples.compatibility.engine()).as_bytes())
    );
    let build_sha256 = format!("{:x}", Sha256::digest(env!("CARGO_PKG_VERSION").as_bytes()));
    let host_sha256 = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}:{}",
                samples.environment_fingerprint, samples.scope_sha256
            )
            .as_bytes()
        )
    );
    let (approved_action, approved_index_definition_sha256, approved_index_marker_sha256) = if phase
        == PerformancePhase::AfterProduction
    {
        let production = super::sql::restoration::load_production_receipt(run.run_id())?;
        ensure!(
            matches!(run, RunReference::GenericProduction { production_receipt_sha256: Some(hash), .. } if hash == production.content_sha256()),
            "Production receipt changed"
        );
        let index = production.index();
        (
            Some(production.action().clone()),
            index.map(|value| value.definition_sha256.clone()),
            index.map(|value| value.marker_sha256.clone()),
        )
    } else {
        (None, None, None)
    };
    let receipt = PerformanceReceipt {
        policy_version: POLICY_VERSION,
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        run: run.clone(),
        phase,
        captured_at: Utc::now(),
        scope_sha256: samples.scope_sha256,
        workload_sha256: samples.workload_fingerprint,
        result_sha256: samples.result_sha256.clone(),
        host_sha256,
        engine_sha256,
        build_sha256,
        dataset_sha256: typed_before.data_sha256.clone(),
        session_sha256: samples.environment_fingerprint,
        live_metadata_sha256: samples.live_metadata_sha256,
        typed_context: typed_before,
        approved_action,
        approved_index_definition_sha256,
        approved_index_marker_sha256,
        approved_change_sha256: match run {
            RunReference::GenericProduction {
                production_receipt_sha256,
                ..
            } => production_receipt_sha256.clone(),
            _ => None,
        },
        warmups: samples.warmups,
        samples_ms: samples.milliseconds,
        median_ms: samples.median_ms,
        p95_ms: samples.p95_ms,
        mad_ms: samples.mad_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn check_baseline_approval(
    approval: &ActionApprovalV2,
    case: &HelperCase,
    run: &RunReference,
) -> Result<()> {
    let RunReference::GenericProduction {
        run_id,
        binding_sha256,
        production_receipt_sha256: None,
    } = run
    else {
        anyhow::bail!("Baseline needs exact future production run")
    };
    approval.binding.validate(Utc::now())?;
    ensure!(
        approval.state == ActionApprovalStateV2::Approved
            && approval.binding.run_kind == RunKind::Production
            && approval.binding.case_id == case.id()
            && approval.binding.case_revision == case.revision()
            && approval.binding.evidence_revision == case.evidence_revision()
            && approval.binding.run_id == *run_id
            && approval.binding.fingerprint()? == *binding_sha256
            && approval.fingerprint == *binding_sha256,
        "Production approval differs baseline launch"
    );
    Ok(())
}

fn check_capture_admission(
    journal: &ActionJournal,
    case: &HelperCase,
    run: &RunReference,
    phase: PerformancePhase,
) -> Result<()> {
    let RunReference::GenericProduction {
        run_id,
        binding_sha256,
        production_receipt_sha256,
    } = run
    else {
        anyhow::bail!("Native SQL samples require generic production run")
    };
    let intent = journal
        .intents()
        .iter()
        .find(|intent| intent.run_id == *run_id && intent.case_id == case.id())
        .ok_or_else(|| anyhow::anyhow!("Exact production intent absent"))?;
    ensure!(
        intent.binding_fingerprint == *binding_sha256,
        "Performance binding differs launched action"
    );
    match phase {
        PerformancePhase::BeforeProduction => ensure!(
            intent.state == IntentState::Prepared && production_receipt_sha256.is_none(),
            "Pre-effect baseline must precede dispatch"
        ),
        PerformancePhase::AfterProduction => ensure!(
            intent.state == IntentState::Verified
                && production_receipt_sha256.as_deref()
                    == intent.production_receipt_sha256.as_deref()
                && production_receipt_sha256.is_some(),
            "Post-effect sample needs verified production receipt"
        ),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Improvement,
    Regression,
    Inconclusive,
}

#[derive(Clone, Copy, Debug)]
pub struct ComparisonPolicy {
    pub maximum_median_ms: f64,
    pub maximum_p95_ms: f64,
}

pub fn compare_performance(
    before: &PerformanceReceipt,
    after: &PerformanceReceipt,
    policy: &ComparisonPolicy,
) -> Comparison {
    if before.validate().is_err()
        || after.validate().is_err()
        || before.phase != PerformancePhase::BeforeProduction
        || after.phase != PerformancePhase::AfterProduction
        || before.case_id != after.case_id
        || before.case_revision != after.case_revision
        || before.run.run_id() != after.run.run_id()
        || before.captured_at >= after.captured_at
        || !policy.maximum_median_ms.is_finite()
        || !policy.maximum_p95_ms.is_finite()
        || policy.maximum_median_ms <= 0.0
        || policy.maximum_p95_ms <= 0.0
    {
        return Comparison::Inconclusive;
    }
    match (&before.run, &after.run) {
        (
            RunReference::GenericProduction {
                binding_sha256: b,
                production_receipt_sha256: None,
                ..
            },
            RunReference::GenericProduction {
                binding_sha256: a,
                production_receipt_sha256: Some(_),
                ..
            },
        ) if a == b => {}
        _ => return Comparison::Inconclusive,
    }
    if before.scope_sha256 != after.scope_sha256
        || before.workload_sha256 != after.workload_sha256
        || before.result_sha256 != after.result_sha256
        || before.host_sha256 != after.host_sha256
        || before.engine_sha256 != after.engine_sha256
        || before.build_sha256 != after.build_sha256
        || before.dataset_sha256 != after.dataset_sha256
        || before.session_sha256 != after.session_sha256
        || after.approved_change_sha256.is_none()
        || !approved_typed_delta(before, after)
    {
        return Comparison::Inconclusive;
    }
    if after.median_ms > policy.maximum_median_ms || after.p95_ms > policy.maximum_p95_ms {
        return Comparison::Regression;
    }
    let before_width = (before.median_ms * 0.1).max(3.0 * before.mad_ms);
    let after_width = (after.median_ms * 0.1).max(3.0 * after.mad_ms);
    if after.median_ms + after_width < before.median_ms - before_width {
        Comparison::Improvement
    } else if before.median_ms + before_width < after.median_ms - after_width {
        Comparison::Regression
    } else {
        Comparison::Inconclusive
    }
}

fn approved_typed_delta(before: &PerformanceReceipt, after: &PerformanceReceipt) -> bool {
    use super::sql::benchmark::CompatibilityEngine;
    let old = &before.typed_context;
    let new = &after.typed_context;
    if old.validate().is_err()
        || new.validate().is_err()
        || old.engine != new.engine
        || old.schema_sha256 != new.schema_sha256
        || old.settings != new.settings
        || old.data_sha256 != new.data_sha256
    {
        return false;
    }
    match after.approved_action.as_ref() {
        Some(SqlAction::PostgresCreateIndex { index, columns, .. })
            if old.engine == CompatibilityEngine::Postgres =>
        {
            approved_index_addition(old, new, after, index, columns)
        }
        Some(SqlAction::SqlServerCreateIndex { index, columns, .. })
            if old.engine == CompatibilityEngine::SqlServer =>
        {
            approved_index_addition(old, new, after, index, columns)
        }
        Some(SqlAction::PostgresAnalyze { .. }) if old.engine == CompatibilityEngine::Postgres => {
            // A statistics hash change cannot identify the exact approved mutation.
            false
        }
        Some(SqlAction::SqlServerUpdateStatistics { .. })
            if old.engine == CompatibilityEngine::SqlServer =>
        {
            false
        }
        _ => false,
    }
}

fn approved_index_addition(
    old: &TypedCompatibilitySnapshot,
    new: &TypedCompatibilitySnapshot,
    receipt: &PerformanceReceipt,
    name: &str,
    columns: &[crate::helper_action::PlainIndexColumn],
) -> bool {
    if new.indexes.len() != old.indexes.len() + 1
        || old.indexes.iter().any(|item| item.name == name)
    {
        return false;
    }
    let Some(added) = new.indexes.iter().find(|item| item.name == name) else {
        return false;
    };
    let statistics_match = if old.engine == super::sql::benchmark::CompatibilityEngine::Postgres {
        old.statistics == new.statistics && old.statistics_sha256 == new.statistics_sha256
    } else {
        new.statistics.len() == old.statistics.len() + 1
            && new
                .statistics
                .iter()
                .any(|(stat_name, _)| stat_name == name)
            && old
                .statistics
                .iter()
                .all(|existing| new.statistics.contains(existing))
    };
    statistics_match
        && added.plain_nonunique_btree
        && added.columns == columns
        && Some(&added.definition_sha256) == receipt.approved_index_definition_sha256.as_ref()
        && added.marker_sha256.as_ref() == receipt.approved_index_marker_sha256.as_ref()
        && old
            .indexes
            .iter()
            .all(|existing| new.indexes.iter().any(|current| current == existing))
}

pub fn resolve_case(
    case: &HelperCase,
    journal: &ActionJournal,
    functional: &FunctionalReceipt,
    performance: Option<(&PerformanceReceipt, &PerformanceReceipt, &ComparisonPolicy)>,
) -> Result<CaseResolution> {
    functional.validate()?;
    ensure!(
        functional.case_id == case.id()
            && functional.case_revision == case.revision()
            && functional.evidence_revision == case.evidence_revision(),
        "Functional receipt belongs to another case revision"
    );
    let reviewed: Vec<_> = case
        .intake()
        .success_criteria
        .iter()
        .filter(|criterion| criterion.reviewed)
        .collect();
    ensure!(
        reviewed.len() == functional.verification.criteria.len(),
        "Required criteria missing"
    );
    for requirement in &functional.verification.criteria {
        ensure!(
            reviewed
                .iter()
                .filter(|criterion| criterion.measure == requirement.measure
                    && criterion.unit == requirement.unit
                    && criterion.window == requirement.window
                    && criterion.threshold.to_bits() == requirement.threshold_bits
                    && requirement.comparator
                        == match criterion.comparator {
                            Comparator::AtMost => CriterionComparator::AtMost,
                            Comparator::AtLeast => CriterionComparator::AtLeast,
                            Comparator::Equal => CriterionComparator::Equal,
                        })
                .count()
                == 1,
            "Required criterion differs current case"
        );
    }
    let RunReference::GenericProduction {
        run_id,
        binding_sha256,
        production_receipt_sha256,
    } = &functional.run
    else {
        anyhow::bail!("Service run requires verified execution evidence")
    };
    let intent = journal
        .intents()
        .iter()
        .find(|i| i.run_id == *run_id && i.case_id == case.id())
        .ok_or_else(|| anyhow::anyhow!("No matching production intent"))?;
    ensure!(
        intent.binding_fingerprint == *binding_sha256
            && intent.verification_sha256.as_deref()
                == Some(functional.approved_verification_sha256.as_str())
            && intent.production_receipt_sha256.as_deref() == production_receipt_sha256.as_deref()
            && production_receipt_sha256.is_some()
            && intent.state == IntentState::Verified,
        "Production action not verified"
    );
    let effect_at = intent
        .outcome_event
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Verified production event missing"))?
        .occurred_at;
    ensure!(
        functional.captured_at >= effect_at,
        "Functional receipt predates production effect"
    );
    ensure!(
        functional
            .checks
            .iter()
            .filter(|check| check.check.functional())
            .all(|check| check.observed_at.is_some_and(|at| at >= effect_at)),
        "Functional observation predates production effect"
    );
    ensure!(
        functional.all_passed(),
        "Required functional checks did not pass"
    );
    if let Some(check) = functional
        .checks
        .iter()
        .filter_map(|result| match &result.check {
            RequiredCheck::Performance {
                maximum_median_ms,
                maximum_p95_ms,
                ..
            } => Some((*maximum_median_ms, *maximum_p95_ms)),
            _ => None,
        })
        .reduce(|left, right| (left.0.min(right.0), left.1.min(right.1)))
    {
        let (before, after, policy) =
            performance.ok_or_else(|| anyhow::anyhow!("Required performance proof missing"))?;
        ensure!(
            before.evidence_revision <= after.evidence_revision
                && after.evidence_revision == case.evidence_revision()
                && before.captured_at < effect_at
                && after.captured_at >= effect_at,
            "Performance receipts do not bracket the exact production effect"
        );
        ensure!(
            policy.maximum_median_ms <= check.0 as f64 && policy.maximum_p95_ms <= check.1 as f64,
            "Performance policy weakens reviewed threshold"
        );
        for required in &functional.verification.checks {
            if let RequiredCheck::Performance {
                scope_sha256,
                workload_sha256,
                minimum_warmups,
                minimum_samples,
                ..
            } = required
            {
                ensure!(
                    before.scope_sha256 == *scope_sha256
                        && after.scope_sha256 == *scope_sha256
                        && before.workload_sha256 == *workload_sha256
                        && after.workload_sha256 == *workload_sha256
                        && before.warmups >= *minimum_warmups
                        && after.warmups >= *minimum_warmups
                        && before.samples_ms.len() >= usize::from(*minimum_samples)
                        && after.samples_ms.len() >= usize::from(*minimum_samples),
                    "Performance proof differs reviewed workload or sampling policy"
                );
            }
        }
        ensure!(
            compare_performance(before, after, policy) == Comparison::Improvement
                && after.run == functional.run,
            "Performance proof inconclusive or regressed"
        );
    }
    Ok(CaseResolution::VerifiedRelayneRepair)
}

pub fn resolve_service_case(
    case: &HelperCase,
    service_journal: &crate::execution::Journal,
    functional: &FunctionalReceipt,
    performance: Option<(&PerformanceReceipt, &PerformanceReceipt, &ComparisonPolicy)>,
) -> Result<CaseResolution> {
    functional.validate()?;
    ensure!(
        functional.case_id == case.id()
            && functional.case_revision == case.revision()
            && functional.evidence_revision == case.evidence_revision(),
        "Service verification case changed"
    );
    let reviewed: Vec<_> = case
        .intake()
        .success_criteria
        .iter()
        .filter(|criterion| criterion.reviewed)
        .collect();
    ensure!(
        reviewed.len() == functional.verification.criteria.len(),
        "Service criteria missing"
    );
    for requirement in &functional.verification.criteria {
        ensure!(
            reviewed
                .iter()
                .filter(|criterion| criterion.measure == requirement.measure
                    && criterion.unit == requirement.unit
                    && criterion.window == requirement.window
                    && criterion.threshold.to_bits() == requirement.threshold_bits
                    && requirement.comparator
                        == match criterion.comparator {
                            Comparator::AtMost => CriterionComparator::AtMost,
                            Comparator::AtLeast => CriterionComparator::AtLeast,
                            Comparator::Equal => CriterionComparator::Equal,
                        })
                .count()
                == 1,
            "Service criteria changed"
        );
    }
    let RunReference::ExistingService {
        run_id,
        target_index,
        execution_plan_sha256,
    } = &functional.run
    else {
        anyhow::bail!("Not a service run")
    };
    let run = service_journal
        .runs
        .iter()
        .find(|run| run.id == *run_id)
        .ok_or_else(|| anyhow::anyhow!("Service run missing"))?;
    let effect_at = run
        .finished
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Service run unfinished"))?;
    ensure!(
        functional.captured_at >= effect_at
            && functional
                .checks
                .iter()
                .filter(|check| check.check.functional())
                .all(|check| check.observed_at.is_some_and(|at| at >= effect_at)),
        "Service functional observation predates verified run"
    );
    let evidence = run
        .verified_target_evidence(*target_index)
        .ok_or_else(|| anyhow::anyhow!("Service run lacks evidenced effect"))?;
    let handoff = run
        .helper_handoff
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Service helper handoff absent"))?;
    let target_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&evidence.target)?)
    );
    ensure!(
        handoff.case_id == case.id()
            && handoff.case_revision == case.revision()
            && handoff.plan_sha256 == *execution_plan_sha256
            && handoff.plan_sha256 == evidence.plan_sha256
            && handoff.target_index == *target_index
            && handoff.target_sha256 == target_sha256,
        "Service handoff differs exact run/plan/target"
    );
    ensure!(
        case.scopes().iter().any(|scope| match scope {
            BoundScope::Windows { target, .. }
            | BoundScope::WindowsWinRm { target, .. }
            | BoundScope::Linux { target, .. } =>
                serde_json::to_vec(target).ok() == serde_json::to_vec(&evidence.target).ok(),
            _ => false,
        }),
        "Service target no longer in reviewed case"
    );
    ensure!(
        functional.all_passed(),
        "Service functional checks incomplete"
    );
    if functional
        .verification
        .checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::Performance { .. }))
    {
        let _ = performance;
        anyhow::bail!(
            "Service performance has no native pre/post producer or compatible comparator"
        );
    }
    Ok(CaseResolution::VerifiedRelayneRepair)
}

pub(crate) fn resolution_proof_sha256(
    case: &HelperCase,
    intent: &super::journal::IntentRecord,
    production: &super::sql::restoration::ProductionReceipt,
    functional: &FunctionalReceipt,
    before: Option<&PerformanceReceipt>,
    after: Option<&PerformanceReceipt>,
    links: &super::case::ResolutionProofLinks,
    evidence_content: &[(Uuid, &str)],
) -> Result<String> {
    let action_sha256 =
        crate::helper_action::digest(b"relayne-helper-resolution-action-v1", production.action())?;
    crate::helper_action::digest(
        b"relayne-helper-resolution-proof-v1",
        &serde_json::json!({
            "case_id": case.id(), "case_revision": case.revision(),
            "evidence_revision": case.evidence_revision(),
            "intent_id": intent.id, "run_id": intent.run_id, "approval_id": intent.approval_id,
            "consume_id": intent.consume_id, "binding_sha256": intent.binding_fingerprint,
            "verification_sha256": intent.verification_sha256,
            "native_receipt_sha256": intent.native_receipt_sha256,
            "native_after_sha256": intent.native_after_sha256,
            "production_receipt_sha256": production.content_sha256(),
            "action_sha256": action_sha256,
            "functional_receipt_sha256": functional.content_sha256()?,
            "verification_plan_sha256": functional.verification_plan_sha256,
            "baseline_receipt_sha256": before.map(PerformanceReceipt::content_sha256).transpose()?,
            "after_receipt_sha256": after.map(PerformanceReceipt::content_sha256).transpose()?,
            "evidence_refs": evidence_content,
            "proof_links": links,
        }),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptStore {
    schema: u16,
    functional: Vec<FunctionalReceipt>,
    performance: Vec<PerformanceReceipt>,
    #[serde(skip)]
    source_sha256: Option<String>,
    #[serde(skip)]
    path: PathBuf,
}

impl ReceiptStore {
    /// Re-evaluates a closed case from exact protected receipt membership and
    /// the current durable journal, including every persisted proof link.
    pub(crate) fn verify_resolution_from_store(
        &self,
        case: &HelperCase,
        journal: &ActionJournal,
    ) -> Result<()> {
        self.validate()?;
        let review = case
            .resolution_review()
            .ok_or_else(|| anyhow::anyhow!("Resolution review missing"))?;
        let links = review
            .proof_links
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Resolution receipt links missing"))?;
        links.validate()?;
        let prior = case.before_resolution_snapshot()?;
        let intent = journal
            .intents()
            .iter()
            .find(|item| {
                item.id == links.intent_id
                    && item.run_id == links.run_id
                    && item.case_id == case.id()
            })
            .ok_or_else(|| anyhow::anyhow!("Resolution intent missing"))?;
        let production = super::sql::restoration::load_production_receipt(links.run_id)?;
        ensure!(
            intent.production_receipt_sha256.as_deref()
                == Some(links.production_receipt_sha256.as_str())
                && production.content_sha256() == links.production_receipt_sha256,
            "Resolution production receipt differs journal"
        );
        let functional = self
            .functional
            .iter()
            .find(|item| {
                item.id().ok() == Some(links.functional_receipt_id)
                    && item.content_sha256().ok().as_deref()
                        == Some(links.functional_receipt_sha256.as_str())
            })
            .ok_or_else(|| {
                anyhow::anyhow!("Resolution functional receipt absent from protected store")
            })?;
        check_run_reference(&functional.run, functional.case_id, journal, true)?;
        check_signed_verification(functional, journal)?;
        let before = match (&links.baseline_receipt_id, &links.baseline_receipt_sha256) {
            (Some(id), Some(hash)) => Some(
                self.performance
                    .iter()
                    .find(|item| {
                        item.id().ok() == Some(*id)
                            && item.content_sha256().ok().as_deref() == Some(hash.as_str())
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!("Resolution baseline receipt absent from protected store")
                    })?,
            ),
            (None, None) => None,
            _ => anyhow::bail!("Resolution baseline links incomplete"),
        };
        let after = match (&links.after_receipt_id, &links.after_receipt_sha256) {
            (Some(id), Some(hash)) => Some(
                self.performance
                    .iter()
                    .find(|item| {
                        item.id().ok() == Some(*id)
                            && item.content_sha256().ok().as_deref() == Some(hash.as_str())
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!("Resolution after receipt absent from protected store")
                    })?,
            ),
            (None, None) => None,
            _ => anyhow::bail!("Resolution after links incomplete"),
        };
        if let Some(before) = before {
            check_run_reference(&before.run, before.case_id, journal, false)?;
        }
        if let Some(after) = after {
            check_run_reference(&after.run, after.case_id, journal, true)?;
            check_approved_action(after)?;
        }
        let thresholds = functional
            .verification
            .checks
            .iter()
            .filter_map(|check| match check {
                RequiredCheck::Performance {
                    maximum_median_ms,
                    maximum_p95_ms,
                    ..
                } => Some((*maximum_median_ms, *maximum_p95_ms)),
                _ => None,
            })
            .reduce(|left, right| (left.0.min(right.0), left.1.min(right.1)));
        let policy = thresholds.map(|(median, p95)| ComparisonPolicy {
            maximum_median_ms: median as f64,
            maximum_p95_ms: p95 as f64,
        });
        let performance = match (before, after, policy.as_ref()) {
            (Some(before), Some(after), Some(policy)) => Some((before, after, policy)),
            (None, None, None) => None,
            _ => anyhow::bail!("Resolution performance references differ reviewed checks"),
        };
        ensure!(
            resolve_case(&prior, journal, functional, performance)?
                == CaseResolution::VerifiedRelayneRepair,
            "Resolution checks no longer qualify"
        );
        let evidence_content: Vec<_> = review
            .evidence_refs
            .iter()
            .map(|id| {
                prior
                    .evidence()
                    .iter()
                    .find(|item| item.id == *id)
                    .map(|item| (*id, item.content_sha256.as_str()))
                    .ok_or_else(|| anyhow::anyhow!("Resolution evidence reference missing"))
            })
            .collect::<Result<_>>()?;
        ensure!(!evidence_content.is_empty(), "Resolution evidence missing");
        ensure!(
            review.proof_sha256.as_deref()
                == Some(
                    resolution_proof_sha256(
                        &prior,
                        intent,
                        &production,
                        functional,
                        before,
                        after,
                        links,
                        &evidence_content,
                    )?
                    .as_str()
                ),
            "Resolution proof digest differs persisted evidence"
        );
        Ok(())
    }
    pub fn path() -> Result<PathBuf> {
        crate::security::app_data_file("relayne-helper-verification.dpapi")
    }
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::File::open(path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                bytes
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    schema: 1,
                    functional: Vec::new(),
                    performance: Vec::new(),
                    source_sha256: None,
                    path: path.to_path_buf(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "Verification store capacity exceeded"
        );
        let raw = crate::security::unprotect_secret(&bytes)?;
        ensure!(
            raw.len() <= 8 * 1024 * 1024,
            "Verification store capacity exceeded"
        );
        let mut store: Self = serde_json::from_slice(&raw)?;
        store.validate()?;
        store.source_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
        store.path = path.to_path_buf();
        Ok(store)
    }
    /// Historical receipts remain immutable; eligibility is rechecked from
    /// the current durable journal every time they are used after reload.
    pub fn load_checked(path: &Path, journal: &ActionJournal) -> Result<Self> {
        let store = Self::load(path)?;
        for item in &store.functional {
            check_run_reference(&item.run, item.case_id, journal, true)?;
            check_signed_verification(item, journal)?;
        }
        for item in &store.performance {
            if item.phase == PerformancePhase::AfterProduction
                || journal
                    .intents()
                    .iter()
                    .any(|intent| intent.run_id == item.run.run_id())
            {
                check_run_reference(
                    &item.run,
                    item.case_id,
                    journal,
                    item.phase == PerformancePhase::AfterProduction,
                )?;
                if item.phase == PerformancePhase::AfterProduction {
                    check_approved_action(item)?;
                }
            }
        }
        Ok(store)
    }
    pub fn functional(&self) -> &[FunctionalReceipt] {
        &self.functional
    }
    pub fn performance(&self) -> &[PerformanceReceipt] {
        &self.performance
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1 && self.functional.len() + self.performance.len() <= 1024,
            "Unsupported verification store or capacity"
        );
        for item in &self.functional {
            item.validate()?;
        }
        for item in &self.performance {
            item.validate()?;
        }
        Ok(())
    }
    pub fn append_functional(
        &mut self,
        journal: &ActionJournal,
        receipt: FunctionalReceipt,
    ) -> Result<()> {
        receipt.validate()?;
        check_run_reference(&receipt.run, receipt.case_id, journal, true)?;
        check_signed_verification(&receipt, journal)?;
        ensure!(
            !self.functional.iter().any(|r| r.case_id == receipt.case_id
                && r.run == receipt.run
                && r.captured_at == receipt.captured_at),
            "Functional receipt already exists"
        );
        self.functional.push(receipt);
        self.save()
    }
    pub fn append_baseline(
        &mut self,
        approval: &ActionApprovalV2,
        case: &HelperCase,
        receipt: PerformanceReceipt,
    ) -> Result<()> {
        receipt.validate()?;
        ensure!(
            receipt.phase == PerformancePhase::BeforeProduction,
            "Baseline phase required"
        );
        check_baseline_approval(approval, case, &receipt.run)?;
        ensure!(
            !self.performance.iter().any(|r| r.case_id == receipt.case_id
                && r.run.run_id() == receipt.run.run_id()
                && r.phase == PerformancePhase::BeforeProduction),
            "Baseline already captured for this run"
        );
        self.performance.push(receipt);
        self.save()
    }
    pub fn append_performance(
        &mut self,
        journal: &ActionJournal,
        receipt: PerformanceReceipt,
    ) -> Result<()> {
        receipt.validate()?;
        ensure!(
            receipt.phase == PerformancePhase::AfterProduction,
            "Use approved pre-dispatch baseline capture"
        );
        check_run_reference(
            &receipt.run,
            receipt.case_id,
            journal,
            receipt.phase == PerformancePhase::AfterProduction,
        )?;
        check_approved_action(&receipt)?;
        ensure!(
            !self.performance.iter().any(|r| r.case_id == receipt.case_id
                && r.run == receipt.run
                && r.phase == receipt.phase
                && r.captured_at == receipt.captured_at),
            "Performance receipt already exists"
        );
        self.performance.push(receipt);
        self.save()
    }
    fn save(&mut self) -> Result<()> {
        self.validate()?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _lock = receipt_lock(&self.path)?;
        let disk = match std::fs::File::open(&self.path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= 8 * 1024 * 1024,
                    "Verification store capacity exceeded"
                );
                Some(bytes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            disk.as_deref().map(|v| format!("{:x}", Sha256::digest(v))) == self.source_sha256,
            "Verification receipts changed concurrently; reload"
        );
        let raw = serde_json::to_vec(self)?;
        ensure!(
            raw.len() <= 8 * 1024 * 1024,
            "Verification store capacity exceeded"
        );
        let protected = crate::security::protect_secret(&raw)?;
        ensure!(
            protected.len() <= 8 * 1024 * 1024,
            "Verification store capacity exceeded"
        );
        crate::security::atomic_write(&self.path, &protected)?;
        self.source_sha256 = Some(format!("{:x}", Sha256::digest(&protected)));
        Ok(())
    }
}

fn check_run_reference(
    run: &RunReference,
    case_id: Uuid,
    journal: &ActionJournal,
    requires_production: bool,
) -> Result<()> {
    if let RunReference::GenericProduction {
        run_id,
        binding_sha256,
        production_receipt_sha256,
    } = run
    {
        let intent = journal
            .intents()
            .iter()
            .find(|intent| intent.run_id == *run_id && intent.case_id == case_id)
            .ok_or_else(|| anyhow::anyhow!("Verification run absent from journal"))?;
        ensure!(
            intent.binding_fingerprint == *binding_sha256,
            "Verification binding differs journal"
        );
        if requires_production {
            ensure!(
                intent.state == IntentState::Verified
                    && production_receipt_sha256.as_deref()
                        == intent.production_receipt_sha256.as_deref()
                    && production_receipt_sha256.is_some(),
                "Production receipt differs journal"
            );
        } else {
            ensure!(
                production_receipt_sha256.is_none(),
                "Baseline references production receipt"
            );
        }
    }
    Ok(())
}

fn check_signed_verification(receipt: &FunctionalReceipt, journal: &ActionJournal) -> Result<()> {
    if let RunReference::GenericProduction { run_id, .. } = &receipt.run {
        let intent = journal
            .intents()
            .iter()
            .find(|intent| intent.run_id == *run_id && intent.case_id == receipt.case_id)
            .ok_or_else(|| anyhow::anyhow!("Verification intent missing"))?;
        ensure!(
            intent.verification_sha256.as_deref()
                == Some(receipt.approved_verification_sha256.as_str()),
            "Receipt checks differ approved production binding"
        );
    }
    Ok(())
}

fn check_approved_action(receipt: &PerformanceReceipt) -> Result<()> {
    let production = super::sql::restoration::load_production_receipt(receipt.run.run_id())?;
    let index = production.index();
    ensure!(
        receipt.approved_change_sha256.as_deref() == Some(production.content_sha256())
            && receipt.approved_action.as_ref() == Some(production.action())
            && receipt.approved_index_definition_sha256.as_deref()
                == index.map(|value| value.definition_sha256.as_str())
            && receipt.approved_index_marker_sha256.as_deref()
                == index.map(|value| value.marker_sha256.as_str()),
        "Performance delta differs immutable production action"
    );
    Ok(())
}

fn receipt_lock(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
