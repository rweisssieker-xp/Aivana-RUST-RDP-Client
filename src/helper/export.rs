//! Deterministic, bounded, metadata-only case reports.
use super::{
    evidence::{Eligibility, EvidenceEnvelope, RetentionState},
    store::HelperStore,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use uuid::Uuid;

pub const MAX_EXPORT_BYTES: usize = 5 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Markdown,
}

pub struct CaseExport {
    pub format: ExportFormat,
    pub body: String,
    pub included_envelopes: usize,
    pub omitted_envelopes: usize,
    pub truncated: bool,
}

#[derive(Serialize)]
struct Report<'a> {
    schema: u16,
    case_id: Uuid,
    context_revision: u64,
    evidence_revision: u64,
    generated_at: DateTime<Utc>,
    total_envelopes: usize,
    included_envelopes: usize,
    omitted_envelopes: usize,
    truncated: bool,
    evidence: &'a [EvidenceLine],
}

#[derive(Serialize)]
struct EvidenceLine {
    id: Uuid,
    origin: &'static str,
    status: &'static str,
    eligibility: &'static str,
    retention: &'static str,
    capability: &'static str,
    capability_version: u16,
    parser_version: u16,
    case_revision: u64,
    request_id: Uuid,
    run_id: Option<Uuid>,
    scope_sha256: String,
    credential_scope_sha256: String,
    source_sha256: String,
    source_observed_at: DateTime<Utc>,
    retrieved_at: DateTime<Utc>,
    coverage_observed: u32,
    coverage_expected: u32,
    coverage_truncated: bool,
    record_count: usize,
    metric_count: usize,
    evidence_ref_count: usize,
    content_sha256: String,
}

fn label<T: std::fmt::Debug>(value: T) -> &'static str {
    // Closed enums only. No user/provider text enters a report label.
    match format!("{value:?}").as_str() {
        "Live" => "live",
        "ImportedUnverified" => "imported_unverified",
        "SimulationFixture" => "simulation_fixture",
        "Complete" => "complete",
        "Partial" => "partial",
        "Denied" => "denied",
        "Unavailable" => "unavailable",
        "Truncated" => "truncated",
        "Canceled" => "canceled",
        "Failed" => "failed",
        "Eligible" => "eligible",
        "Imported" => "imported",
        "Simulation" => "simulation",
        "ClockUncertain" => "clock_uncertain",
        "Future" => "future",
        "Stale" => "stale",
        "Incomplete" => "incomplete",
        "WithinWindow" => "within_window",
        "ExpiredHeld" => "expired_held",
        "ExpiredReferenced" => "expired_referenced",
        "ExpiredUnheld" => "expired_unheld",
        "NetworkReachability" => "network_reachability",
        "SystemResources" => "system_resources",
        "ServiceStatus" => "service_status",
        "SqlRead" => "sql_read",
        "SqlPlan" => "sql_plan",
        "SqlWorkloadBaseline" => "sql_workload_baseline",
        "SqlWorkloadRehearsal" => "sql_workload_rehearsal",
        "ContainerStatus" => "container_status",
        "CloudInstanceStatus" => "cloud_instance_status",
        _ => "unknown",
    }
}

fn line(
    e: &EvidenceEnvelope,
    now: DateTime<Utc>,
    current_revision: u64,
    retention: RetentionState,
) -> EvidenceLine {
    let eligibility = if e.binding.case_revision != current_revision {
        Eligibility::Stale
    } else {
        e.eligibility(now, Duration::minutes(5))
    };
    EvidenceLine {
        id: e.id,
        origin: label(e.origin),
        status: label(e.status),
        eligibility: label(eligibility),
        retention: label(retention),
        capability: label(e.capability_id),
        capability_version: e.capability_version,
        parser_version: e.parser_version,
        case_revision: e.binding.case_revision,
        request_id: e.binding.request_id,
        run_id: e.binding.run_id,
        scope_sha256: e.binding.scope_sha256.clone(),
        credential_scope_sha256: e.binding.credential_scope_sha256.clone(),
        source_sha256: e.source_id.clone(),
        source_observed_at: e.source_observed_at,
        retrieved_at: e.retrieved_at,
        coverage_observed: e.coverage.observed,
        coverage_expected: e.coverage.expected,
        coverage_truncated: e.coverage.truncated,
        record_count: e.records.len(),
        metric_count: e.metrics.len(),
        evidence_ref_count: e.evidence_refs.len(),
        content_sha256: e.content_sha256.clone(),
    }
}

pub fn export_case(
    store: &HelperStore,
    id: Uuid,
    format: ExportFormat,
    now: DateTime<Utc>,
) -> Result<CaseExport> {
    store.validate()?;
    let case = store
        .case(id)
        .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
    let lines: Vec<_> = case
        .evidence()
        .iter()
        .map(|e| {
            line(
                e,
                now,
                case.revision(),
                case.evidence_retention(e.id, now).unwrap(),
            )
        })
        .collect();
    let mut included = lines.len();
    loop {
        let report = Report {
            schema: 1,
            case_id: id,
            context_revision: case.revision(),
            evidence_revision: case.evidence_revision(),
            generated_at: now,
            total_envelopes: lines.len(),
            included_envelopes: included,
            omitted_envelopes: lines.len() - included,
            truncated: included < lines.len(),
            evidence: &lines[..included],
        };
        let body = match format {
            ExportFormat::Json => serde_json::to_string_pretty(&report)?,
            ExportFormat::Markdown => markdown(&report),
        };
        if body.len() <= MAX_EXPORT_BYTES {
            return Ok(CaseExport {
                format,
                body,
                included_envelopes: included,
                omitted_envelopes: lines.len() - included,
                truncated: included < lines.len(),
            });
        }
        ensure!(
            included > 0,
            "Even the coverage header exceeds export capacity"
        );
        included -= 1;
    }
}

fn markdown(report: &Report<'_>) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Helper evidence report\n\nCase: `{}` · context revision {} · evidence revision {}\nGenerated: {}\nCoverage: {} of {} envelopes; omitted {}; truncated: {}\n",
        report.case_id,
        report.context_revision,
        report.evidence_revision,
        report.generated_at,
        report.included_envelopes,
        report.total_envelopes,
        report.omitted_envelopes,
        report.truncated
    );
    for e in report.evidence {
        let _ = writeln!(
            out,
            "## {}\n\n{} v{} (parser {}); origin {}; status {}; eligibility {}; retention {}.\nSource SHA-256: `{}`; observed {}; retrieved {}.\nRequest `{}`; run `{:?}`; case revision {}.\nScope `{}`; credential scope `{}`.\nCoverage {}/{} (truncated {}); records {}; metrics {}; references {}; content `{}`.\n",
            e.id,
            e.capability,
            e.capability_version,
            e.parser_version,
            e.origin,
            e.status,
            e.eligibility,
            e.retention,
            e.source_sha256,
            e.source_observed_at,
            e.retrieved_at,
            e.request_id,
            e.run_id,
            e.case_revision,
            e.scope_sha256,
            e.credential_scope_sha256,
            e.coverage_observed,
            e.coverage_expected,
            e.coverage_truncated,
            e.record_count,
            e.metric_count,
            e.evidence_ref_count,
            e.content_sha256
        );
    }
    out
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
