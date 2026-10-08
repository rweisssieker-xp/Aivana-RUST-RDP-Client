//! Closed, native database readers. Engines share the normalized observation vocabulary.

pub mod artifacts;
pub mod benchmark;
pub mod plans;
pub mod postgres;
pub mod sql_server;
pub mod templates;
pub mod types;

#[cfg(test)]
mod plan_tests;

use super::{
    capability::{ProbeAdapter, ProbeFuture, ProbeRequest},
    credentials::SecretResolver,
    scope::{BoundScope, DatabaseEngine},
};
use tokio_util::sync::CancellationToken;

/// Registry entry for the SQL-read capability. Task 7 adds the TDS branch here.
pub struct SqlReadAdapter;

pub struct SqlPlanAdapter;
pub struct SqlWorkloadAdapter;

impl ProbeAdapter for SqlPlanAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            use super::{
                capability::ProbeOutput,
                evidence::{Coverage, EvidenceStatus, NormalizedRecord, Observation, RecordKind},
                manifest::ProbeParams,
            };
            use artifacts::{PlanArtifact, SqlArtifact};
            let ProbeParams::SqlPlan { query_digest } = &request.params else {
                anyhow::bail!("SQL plan request mismatch")
            };
            let template =
                templates::ReviewedSelectTemplate::from_fingerprint(&request.scope, query_digest)
                    .ok_or_else(|| anyhow::anyhow!("Unregistered plan template"))?;
            let report = plans::estimated_plan(&request.scope, &template, cancel).await?;
            let artifact = PlanArtifact::from_report(&report, query_digest.clone())?;
            let now = chrono::Utc::now();
            Ok(ProbeOutput {
                status: EvidenceStatus::Complete,
                coverage: Coverage {
                    observed: 1,
                    expected: 1,
                    truncated: false,
                },
                records: vec![NormalizedRecord {
                    kind: RecordKind::SqlPlan,
                    observation: Observation::Unknown,
                    subject_sha256: query_digest.clone(),
                }],
                metrics: vec![],
                sql_observations: vec![],
                sql_artifacts: vec![SqlArtifact::Plan(artifact)],
                evidence_refs: vec![],
                source_id: format!("pg-plan-v1:{query_digest}").into_bytes(),
                source_observed_at: now,
                parser_version: 1,
            })
        })
    }
}

impl ProbeAdapter for SqlWorkloadAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            use super::{
                capability::ProbeOutput,
                evidence::{Coverage, EvidenceStatus, NormalizedRecord, Observation, RecordKind},
                manifest::ProbeParams,
            };
            use artifacts::{SqlArtifact, WorkloadArtifact};
            let ProbeParams::SqlWorkload {
                workload_digest,
                review_evidence_id,
                review_content_sha256,
            } = &request.params
            else {
                anyhow::bail!("SQL workload request mismatch")
            };
            let template = templates::ReviewedSelectTemplate::from_fingerprint(
                &request.scope,
                workload_digest,
            )
            .ok_or_else(|| anyhow::anyhow!("Unregistered workload template"))?;
            let reviewed = benchmark::ReviewedWorkload::from_validated_request(
                request,
                template,
                *review_evidence_id,
                review_content_sha256.clone(),
            );
            let samples = benchmark::run_sandbox_workload(
                &reviewed,
                &benchmark::SamplingPolicy::default(),
                cancel,
            )
            .await?;
            let artifact = WorkloadArtifact::from_samples(&samples)?;
            let now = chrono::Utc::now();
            Ok(ProbeOutput {
                status: EvidenceStatus::Complete,
                coverage: Coverage {
                    observed: 1,
                    expected: 1,
                    truncated: false,
                },
                records: vec![NormalizedRecord {
                    kind: RecordKind::SqlWorkload,
                    observation: Observation::Unknown,
                    subject_sha256: workload_digest.clone(),
                }],
                metrics: vec![],
                sql_observations: vec![],
                sql_artifacts: vec![SqlArtifact::Workload(artifact)],
                evidence_refs: vec![*review_evidence_id],
                source_id: format!("pg-workload-v1:{workload_digest}").into_bytes(),
                source_observed_at: now,
                parser_version: 1,
            })
        })
    }
}

impl ProbeAdapter for SqlReadAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        match &request.scope {
            BoundScope::Database {
                engine: DatabaseEngine::Postgres,
                ..
            } => postgres::PostgresAdapter.collect(request, secrets, cancel),
            BoundScope::Database {
                engine: DatabaseEngine::SqlServer,
                ..
            } => sql_server::SqlServerAdapter.collect(request, secrets, cancel),
            _ => Box::pin(async { anyhow::bail!("SQL engine has no native reader") }),
        }
    }
}
