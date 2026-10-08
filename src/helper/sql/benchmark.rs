//! Explicit, reviewed sandbox workload execution and conservative comparison.
use super::templates::{ReviewedSelectTemplate, TemplateBind, connect_fixture};
use crate::helper::{
    case::HelperCase, evidence::Eligibility, manifest::CapabilityId, scope::BoundScope,
    sql::types::SqlObservation,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const POLICY_VERSION: u16 = 1;
#[derive(Clone, Copy, Debug)]
pub struct SamplingPolicy {
    pub warmups: u8,
    pub samples: u8,
    pub deadline_secs: u8,
}
impl Default for SamplingPolicy {
    fn default() -> Self {
        Self {
            warmups: 3,
            samples: 15,
            deadline_secs: 30,
        }
    }
}
impl SamplingPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.warmups == 3
                && (15..=30).contains(&self.samples)
                && (1..=30).contains(&self.deadline_secs),
            "unsupported sampling policy"
        );
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct ReviewedWorkload {
    scope: BoundScope,
    template: ReviewedSelectTemplate,
    case_id: Uuid,
    case_revision: u64,
    review_evidence_id: Uuid,
    review_content_sha256: String,
    reviewed_at: chrono::DateTime<chrono::Utc>,
}
impl ReviewedWorkload {
    pub(crate) fn from_validated_request(
        request: &crate::helper::capability::ProbeRequest,
        template: ReviewedSelectTemplate,
        review_evidence_id: Uuid,
        review_content_sha256: String,
    ) -> Self {
        Self {
            scope: request.scope.clone(),
            template,
            case_id: request.binding.case_id,
            case_revision: request.binding.case_revision,
            review_evidence_id,
            review_content_sha256,
            reviewed_at: request.requested_at,
        }
    }
    pub(crate) fn review_content_sha256(&self) -> &str {
        &self.review_content_sha256
    }
    /// A UI action may create this only from a fresh live SQL-read capture for the exact case scope.
    pub fn review(
        case: &HelperCase,
        scope: &BoundScope,
        template: ReviewedSelectTemplate,
        evidence_id: Uuid,
    ) -> Result<Self> {
        template.reviewed_statement(scope)?;
        let digest = scope.digest()?;
        ensure!(
            case.scopes()
                .iter()
                .any(|s| s.digest().ok() == Some(digest.clone())),
            "scope not in reviewed case"
        );
        let evidence = case
            .evidence()
            .iter()
            .find(|e| e.id == evidence_id)
            .ok_or_else(|| anyhow::anyhow!("review evidence missing"))?;
        ensure!(
            evidence.capability_id == CapabilityId::SqlRead
                && evidence.binding.case_id == case.id()
                && evidence.binding.case_revision == case.revision()
                && evidence.binding.scope_sha256 == digest
                && evidence.eligibility(chrono::Utc::now(), chrono::Duration::minutes(5))
                    == Eligibility::Eligible,
            "fresh live SQL-read review evidence required"
        );
        ensure!(
            metadata_matches(&evidence.sql_observations, template),
            "reviewed live object/column identity missing"
        );
        Ok(Self {
            scope: scope.clone(),
            template,
            case_id: case.id(),
            case_revision: case.revision(),
            review_evidence_id: evidence_id,
            review_content_sha256: evidence.content_sha256.clone(),
            reviewed_at: chrono::Utc::now(),
        })
    }
    pub fn fingerprint(&self) -> Result<String> {
        self.template.fingerprint(&self.scope)
    }
}

pub(super) fn metadata_matches(
    observations: &[SqlObservation],
    template: ReviewedSelectTemplate,
) -> bool {
    let expected: &[&str] = match template {
        ReviewedSelectTemplate::OrderSort => &["event_id", "group_id", "payload"],
        _ => &[
            "order_id",
            "customer_id",
            "status",
            "amount",
            "created_at",
            "detail",
        ],
    };
    let objects: Vec<_> = observations
        .iter()
        .filter_map(|o| match o {
            SqlObservation::PostgresObject {
                schema,
                name,
                object_id,
                column_count,
            } if schema == "fixture"
                && name == template.object()
                && *object_id > 0
                && *column_count == expected.len() as u32 =>
            {
                Some(*object_id)
            }
            _ => None,
        })
        .collect();
    if objects.len() != 1 {
        return false;
    }
    let mut columns: Vec<_> = observations
        .iter()
        .filter_map(|o| match o {
            SqlObservation::PostgresColumn {
                object_id,
                column_id,
                name,
                plain,
            } if *object_id == objects[0] && *column_id > 0 && *plain => {
                Some((*column_id, name.as_str()))
            }
            _ => None,
        })
        .collect();
    columns.sort_by_key(|(id, _)| *id);
    columns.len() == expected.len()
        && columns
            .iter()
            .zip(expected)
            .all(|((_, actual), wanted)| actual == wanted)
        && columns.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

#[derive(Clone, Debug)]
pub struct WorkloadSamples {
    pub policy_version: u16,
    pub case_id: Uuid,
    pub case_revision: u64,
    pub review_evidence_id: Uuid,
    pub review_content_sha256: String,
    pub scope_sha256: String,
    pub workload_fingerprint: String,
    pub result_sha256: String,
    pub environment_fingerprint: String,
    pub live_metadata_sha256: String,
    pub warmups: u8,
    pub milliseconds: Vec<f64>,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub mad_ms: f64,
    /// An intended schema/index/session-setting change must be supplied by a future approved action receipt.
    pub approved_change_sha256: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Improvement,
    Regression,
    Inconclusive,
}
impl WorkloadSamples {
    pub fn can_prove_repair(&self) -> bool {
        false
    }
}
pub(crate) fn summary(values: &[f64]) -> Result<(f64, f64, f64)> {
    ensure!(
        values.len() >= 15
            && values.len() <= 30
            && values.iter().all(|v| v.is_finite() && *v > 0.0),
        "invalid repeated samples"
    );
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median = (sorted[(sorted.len() - 1) / 2] + sorted[sorted.len() / 2]) / 2.0;
    let p95_index = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    let p95 = sorted[p95_index];
    let mut deviations: Vec<f64> = sorted.iter().map(|v| (v - median).abs()).collect();
    deviations.sort_by(f64::total_cmp);
    let mad = (deviations[(deviations.len() - 1) / 2] + deviations[deviations.len() / 2]) / 2.0;
    Ok((median, p95, mad))
}
pub fn compare(
    before: &WorkloadSamples,
    after: &WorkloadSamples,
    approved_change_sha256: &str,
) -> Comparison {
    use crate::helper::evidence::is_digest;
    if !is_digest(approved_change_sha256)
        || before.policy_version != POLICY_VERSION
        || after.policy_version != POLICY_VERSION
        || before.warmups < 3
        || after.warmups < 3
        || before.milliseconds.len() < 15
        || after.milliseconds.len() < 15
        || before.case_id != after.case_id
        || before.scope_sha256 != after.scope_sha256
        || before.workload_fingerprint != after.workload_fingerprint
        || before.result_sha256 != after.result_sha256
        || before.environment_fingerprint != after.environment_fingerprint
        || before.live_metadata_sha256 != after.live_metadata_sha256
        || before.approved_change_sha256.is_some()
        || after.approved_change_sha256.as_deref() != Some(approved_change_sha256)
        || summary(&before.milliseconds).is_err()
        || summary(&after.milliseconds).is_err()
    {
        return Comparison::Inconclusive;
    }
    let Ok((before_median, _, before_mad)) = summary(&before.milliseconds) else {
        return Comparison::Inconclusive;
    };
    let Ok((after_median, _, after_mad)) = summary(&after.milliseconds) else {
        return Comparison::Inconclusive;
    };
    let width_before = (before_median * 0.1).max(3.0 * before_mad);
    let width_after = (after_median * 0.1).max(3.0 * after_mad);
    if after_median + width_after < before_median - width_before {
        Comparison::Improvement
    } else if before_median + width_before < after_median - width_after {
        Comparison::Regression
    } else {
        Comparison::Inconclusive
    }
}

pub async fn run_sandbox_workload(
    request: &ReviewedWorkload,
    policy: &SamplingPolicy,
    cancel: CancellationToken,
) -> Result<WorkloadSamples> {
    policy.validate()?;
    ensure!(!cancel.is_cancelled(), "workload canceled");
    ensure!(
        chrono::Utc::now().signed_duration_since(request.reviewed_at)
            < chrono::Duration::minutes(5),
        "workload review expired"
    );
    let statement = request.template.reviewed_statement(&request.scope)?;
    let session = connect_fixture(&request.scope, request.template, &cancel).await?;
    let run = async {
        session.client.batch_execute("BEGIN READ ONLY; SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '1000ms'").await?;
        let mut samples = Vec::with_capacity(policy.samples as usize);
        let mut result_digest: Option<String> = None;
        for i in 0..usize::from(policy.warmups + policy.samples) {
            if cancel.is_cancelled() {
                anyhow::bail!("workload canceled");
            }
            let start = Instant::now();
            let rows = match statement.bind {
                TemplateBind::None => session.client.query(statement.sql, &[]).await?,
                TemplateBind::Integer(n) => session.client.query(statement.sql, &[&n]).await?,
                TemplateBind::Status(s) => {
                    session.client.query(statement.sql, &[&s.as_str()]).await?
                }
            };
            ensure!(rows.len() <= 100, "workload result exceeds fixed row limit");
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            let mut hash = Sha256::new();
            hash.update(b"relayne-workload-result-v1\0");
            hash.update((rows.len() as u32).to_be_bytes());
            for row in &rows {
                let id: i64 = row.try_get(0)?;
                hash.update(id.to_be_bytes());
            }
            let current = format!("{:x}", hash.finalize());
            if let Some(expected) = &result_digest {
                ensure!(
                    expected == &current,
                    "workload results changed across samples"
                );
            } else {
                result_digest = Some(current);
            }
            if i >= usize::from(policy.warmups) {
                ensure!(
                    elapsed.is_finite() && elapsed > 0.0,
                    "invalid workload clock sample"
                );
                samples.push(elapsed);
            }
        }
        let (median_ms, p95_ms, mad_ms) = summary(&samples)?;
        let mut environment = Sha256::new();
        environment.update(b"relayne-pg-disposable-fixture-v1\0");
        environment.update(request.scope.resource_digest()?.as_bytes());
        environment.update(session.server_version.to_be_bytes());
        environment.update(session.work_mem.as_bytes());
        environment.update(env!("CARGO_PKG_VERSION").as_bytes());
        environment.update(if cfg!(debug_assertions) {
            &b"debug"[..]
        } else {
            &b"release"[..]
        });
        Ok(WorkloadSamples {
            policy_version: POLICY_VERSION,
            case_id: request.case_id,
            case_revision: request.case_revision,
            review_evidence_id: request.review_evidence_id,
            review_content_sha256: request.review_content_sha256.clone(),
            scope_sha256: request.scope.digest()?,
            workload_fingerprint: statement.fingerprint,
            result_sha256: result_digest
                .ok_or_else(|| anyhow::anyhow!("missing workload result"))?,
            environment_fingerprint: format!("{:x}", environment.finalize()),
            live_metadata_sha256: session.metadata_sha256.clone(),
            warmups: policy.warmups,
            milliseconds: samples,
            median_ms,
            p95_ms,
            mad_ms,
            approved_change_sha256: None,
        })
    };
    let outcome = tokio::select! {
        _ = cancel.cancelled() => Err(anyhow::anyhow!("workload canceled")),
        result = tokio::time::timeout(Duration::from_secs(u64::from(policy.deadline_secs)), run) => result.map_err(|_| anyhow::anyhow!("workload deadline exceeded"))?,
    };
    if outcome.is_err() {
        session.cancel_query().await;
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        session.client.batch_execute("ROLLBACK"),
    )
    .await;
    outcome
}
