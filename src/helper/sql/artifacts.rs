//! Bounded, redacted SQL projections kept with protected case evidence.

use super::{
    benchmark::WorkloadSamples,
    plans::{PlanImportFormat, PlanNode, PlanReport},
};
use crate::helper::evidence::is_digest;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_STORED_OPERATORS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlArtifact {
    Plan(PlanArtifact),
    Workload(WorkloadArtifact),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanArtifact {
    pub format: SqlPlanFormat,
    pub source_sha256: String,
    pub metadata_sha256: Option<String>,
    pub template_sha256: String,
    pub operator_count: u16,
    pub operators_truncated: bool,
    pub operators: Vec<PlanOperator>,
    pub has_spill_evidence: bool,
    pub has_temp_io: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlPlanFormat {
    PostgresJson,
    PsqlAlignedExplainJson,
    SqlServerShowplanXml,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanOperator {
    pub depth: u8,
    pub name: String,
    pub estimated_rows: Option<f64>,
    pub estimated_cost: Option<f64>,
    pub actual_rows: Option<f64>,
    pub spill: bool,
    pub temp_io: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadArtifact {
    pub policy_version: u16,
    pub review_evidence_id: Uuid,
    pub review_content_sha256: String,
    pub workload_sha256: String,
    pub result_sha256: String,
    pub environment_sha256: String,
    pub metadata_sha256: String,
    pub warmups: u8,
    pub milliseconds: Vec<f64>,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub mad_ms: f64,
}

impl PlanArtifact {
    pub fn from_report(report: &PlanReport, template_sha256: String) -> Result<Self> {
        let mut operators = Vec::new();
        fn visit(node: &PlanNode, depth: u8, output: &mut Vec<PlanOperator>) {
            if output.len() >= MAX_STORED_OPERATORS {
                return;
            }
            output.push(PlanOperator {
                depth,
                name: node.operator.to_owned(),
                estimated_rows: node.estimated_rows,
                estimated_cost: node.estimated_cost,
                actual_rows: node.actual_rows,
                spill: node.spill.is_some(),
                temp_io: node.temp_io,
            });
            for child in &node.children {
                visit(child, depth.saturating_add(1), output);
            }
        }
        for root in &report.roots {
            visit(root, 0, &mut operators);
        }
        let artifact = Self {
            format: match report.format {
                PlanImportFormat::PostgresJson => SqlPlanFormat::PostgresJson,
                PlanImportFormat::PsqlAlignedExplainJson => SqlPlanFormat::PsqlAlignedExplainJson,
                PlanImportFormat::SqlServerShowplanXml => SqlPlanFormat::SqlServerShowplanXml,
            },
            source_sha256: report.source_sha256.clone(),
            metadata_sha256: report.live_metadata_sha256().map(str::to_owned),
            template_sha256,
            operator_count: report.operators().try_into()?,
            operators_truncated: report.operators() > operators.len(),
            operators,
            has_spill_evidence: report.has_spill_evidence,
            has_temp_io: report.has_temp_io,
        };
        artifact.validate()?;
        Ok(artifact)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            is_digest(&self.source_sha256)
                && is_digest(&self.template_sha256)
                && self.metadata_sha256.as_deref().is_none_or(is_digest),
            "invalid plan digest"
        );
        ensure!(
            self.operator_count > 0
                && !self.operators.is_empty()
                && self.operators.len() <= MAX_STORED_OPERATORS
                && self.operators.len() <= usize::from(self.operator_count)
                && self.operators_truncated
                    == (self.operators.len() < usize::from(self.operator_count)),
            "invalid plan coverage"
        );
        for operator in &self.operators {
            ensure!(
                operator.depth <= 64
                    && operator.name.len() <= 64
                    && operator
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'_'),
                "invalid operator name"
            );
            ensure!(
                [
                    operator.estimated_rows,
                    operator.estimated_cost,
                    operator.actual_rows
                ]
                .into_iter()
                .flatten()
                .all(|v| v.is_finite() && v >= 0.0),
                "invalid operator value"
            );
        }
        Ok(())
    }
}

impl WorkloadArtifact {
    pub fn from_samples(samples: &WorkloadSamples) -> Result<Self> {
        let artifact = Self {
            policy_version: samples.policy_version,
            review_evidence_id: samples.review_evidence_id,
            review_content_sha256: samples.review_content_sha256.clone(),
            workload_sha256: samples.workload_fingerprint.clone(),
            result_sha256: samples.result_sha256.clone(),
            environment_sha256: samples.environment_fingerprint.clone(),
            metadata_sha256: samples.live_metadata_sha256.clone(),
            warmups: samples.warmups,
            milliseconds: samples.milliseconds.clone(),
            median_ms: samples.median_ms,
            p95_ms: samples.p95_ms,
            mad_ms: samples.mad_ms,
        };
        artifact.validate()?;
        Ok(artifact)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.policy_version == 1
                && self.warmups == 3
                && (15..=30).contains(&self.milliseconds.len())
                && !self.review_evidence_id.is_nil(),
            "invalid workload policy"
        );
        ensure!(
            [
                &self.review_content_sha256,
                &self.workload_sha256,
                &self.result_sha256,
                &self.environment_sha256,
                &self.metadata_sha256
            ]
            .into_iter()
            .all(|v| is_digest(v)),
            "invalid workload digest"
        );
        ensure!(
            self.milliseconds
                .iter()
                .chain([&self.median_ms, &self.p95_ms, &self.mad_ms])
                .all(|v| v.is_finite() && *v >= 0.0),
            "invalid workload timing"
        );
        let (median, p95, mad) = super::benchmark::summary(&self.milliseconds)?;
        ensure!(
            self.median_ms == median && self.p95_ms == p95 && self.mad_ms == mad,
            "workload summary differs from samples"
        );
        Ok(())
    }
}

impl SqlArtifact {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Plan(plan) => plan.validate(),
            Self::Workload(workload) => workload.validate(),
        }
    }
}
