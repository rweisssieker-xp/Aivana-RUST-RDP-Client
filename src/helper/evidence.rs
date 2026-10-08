//! Normalized evidence and its exact collection provenance.
use super::manifest::CapabilityId;
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const EVIDENCE_SCHEMA: u16 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;
pub const MAX_RECORDS: usize = 100;
pub const MAX_METRICS: usize = 64;
pub const MAX_EVIDENCE_REFS: usize = 16;
pub const MAX_ENVELOPES_PER_CASE: usize = 1000;
/// Future plan artifacts use this shorter window; Task 4 owns their stored form.
pub const PLAN_ARTIFACT_RETENTION_DAYS: i64 = 90;
/// Normalized evidence is redacted metadata, retained for the metadata window.
pub const METADATA_RETENTION_DAYS: i64 = 365;
pub const MAX_FRESHNESS_SECS: i64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    pub case_id: Uuid,
    pub case_revision: u64,
    pub request_id: Uuid,
    pub scope_sha256: String,
    pub credential_scope_sha256: String,
    pub run_id: Option<Uuid>,
}

impl EvidenceBinding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.case_id.is_nil() && !self.request_id.is_nil() && self.case_revision > 0,
            "Invalid evidence binding identity"
        );
        ensure!(
            self.run_id.is_none_or(|id| !id.is_nil()),
            "Invalid run identity"
        );
        ensure!(
            is_digest(&self.scope_sha256) && is_digest(&self.credential_scope_sha256),
            "Invalid evidence binding digest"
        );
        Ok(())
    }
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Live,
    ImportedUnverified,
    SimulationFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeQuality {
    Trusted,
    ClockUncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    Denied,
    Unavailable,
    Truncated,
    Canceled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub observed: u32,
    pub expected: u32,
    pub truncated: bool,
}

impl Coverage {
    pub fn complete(self) -> bool {
        self.expected > 0 && self.observed == self.expected && !self.truncated
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Network,
    Service,
    System,
    SqlRead,
    SqlPlan,
    Container,
    CloudInstance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedRecord {
    pub kind: RecordKind,
    pub observation: Observation,
    /// Stable opaque identity digest; no hostnames, provider payloads or query literals.
    pub subject_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    LatencyMs,
    CpuPercent,
    MemoryPercent,
    DiskPercent,
    Rows,
    DurationMs,
    ErrorCount,
    EstimatedCost,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedMetric {
    pub kind: MetricKind,
    pub value: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub schema: u16,
    pub id: Uuid,
    pub binding: EvidenceBinding,
    pub capability_id: CapabilityId,
    pub capability_version: u16,
    pub parser_version: u16,
    pub origin: Origin,
    /// Opaque source identifier. No paths, URLs, usernames, or free provider text.
    pub source_id: String,
    pub source_observed_at: DateTime<Utc>,
    pub retrieved_at: DateTime<Utc>,
    pub time_quality: TimeQuality,
    pub status: EvidenceStatus,
    pub coverage: Coverage,
    pub content_sha256: String,
    pub records: Vec<NormalizedRecord>,
    pub metrics: Vec<NormalizedMetric>,
    pub evidence_refs: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    Imported,
    Simulation,
    ClockUncertain,
    Future,
    Stale,
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    ActiveRun,
    AmbiguousOutcome,
    UnresolvedRestoration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionState {
    WithinWindow,
    ExpiredHeld,
    ExpiredReferenced,
    ExpiredUnheld,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceHold {
    pub run_id: Uuid,
    pub reason: HoldReason,
    pub evidence_ids: Vec<Uuid>,
}

impl EvidenceHold {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.run_id.is_nil()
                && self.evidence_ids.len() <= MAX_EVIDENCE_REFS
                && self.evidence_ids.iter().all(|id| !id.is_nil()),
            "Invalid evidence hold"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingCapture {
    pub binding: EvidenceBinding,
    pub capability_id: CapabilityId,
    pub capability_version: u16,
    pub registered_at: DateTime<Utc>,
}

impl EvidenceEnvelope {
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.schema == EVIDENCE_SCHEMA,
            "Unsupported evidence schema"
        );
        ensure!(
            !self.id.is_nil() && self.capability_version > 0 && self.parser_version > 0,
            "Invalid evidence identity/version"
        );
        self.binding.validate()?;
        ensure!(
            self.source_id.len() <= 128
                && !self.source_id.is_empty()
                && self
                    .source_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b)),
            "Unsafe evidence source identifier"
        );
        ensure!(is_digest(&self.content_sha256), "Invalid content digest");
        ensure!(
            self.records.len() <= MAX_RECORDS
                && self.metrics.len() <= MAX_METRICS
                && self.evidence_refs.len() <= MAX_EVIDENCE_REFS,
            "Evidence item limit exceeded"
        );
        ensure!(
            self.records.iter().all(|r| is_digest(&r.subject_sha256)),
            "Invalid record subject"
        );
        ensure!(
            self.metrics.iter().all(|m| m.value.is_finite()),
            "Invalid evidence metric"
        );
        ensure!(
            self.evidence_refs.iter().all(|id| !id.is_nil()),
            "Invalid evidence reference"
        );
        ensure!(
            self.coverage.observed <= self.coverage.expected,
            "Invalid evidence coverage"
        );
        ensure!(
            self.source_observed_at <= self.retrieved_at
                || self.time_quality == TimeQuality::ClockUncertain,
            "Observation after retrieval"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_ENVELOPE_BYTES,
            "Evidence envelope too large"
        );
        Ok(())
    }

    /// Compare with a separately registered trusted expected request, never with self.binding.
    pub fn validate_ingest(&self, expected: &EvidenceBinding) -> Result<()> {
        self.validate_shape()?;
        expected.validate()?;
        ensure!(
            &self.binding == expected,
            "Evidence request/case/revision/scope/credential/run mismatch"
        );
        Ok(())
    }

    pub fn eligibility(&self, now: DateTime<Utc>, freshness: Duration) -> Eligibility {
        match self.origin {
            Origin::ImportedUnverified => return Eligibility::Imported,
            Origin::SimulationFixture => return Eligibility::Simulation,
            Origin::Live => {}
        }
        if self.time_quality != TimeQuality::Trusted {
            return Eligibility::ClockUncertain;
        }
        if self.source_observed_at > now || self.retrieved_at > now {
            return Eligibility::Future;
        }
        if freshness <= Duration::zero()
            || freshness > Duration::seconds(MAX_FRESHNESS_SECS)
            || now.signed_duration_since(self.source_observed_at) > freshness
            || now.signed_duration_since(self.retrieved_at) > freshness
        {
            return Eligibility::Stale;
        }
        if self.status != EvidenceStatus::Complete
            || !self.coverage.complete()
            || self.records.len() + self.metrics.len() < self.coverage.observed as usize
            || self
                .records
                .iter()
                .any(|r| r.observation == Observation::Unknown)
        {
            return Eligibility::Incomplete;
        }
        Eligibility::Eligible
    }
}

/// The public ingest entry point; live authority requires a pending capture in the store.
pub fn attach_evidence(
    store: &mut super::store::HelperStore,
    case_id: Uuid,
    envelope: EvidenceEnvelope,
) -> Result<()> {
    store.attach_evidence(case_id, envelope)
}

/// UI/file imports can preserve simulation provenance, but can never assert a live origin.
pub fn import_evidence(
    store: &mut super::store::HelperStore,
    case_id: Uuid,
    mut envelope: EvidenceEnvelope,
) -> Result<()> {
    if envelope.origin != Origin::SimulationFixture {
        envelope.origin = Origin::ImportedUnverified;
    }
    store.attach_evidence(case_id, envelope)
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
