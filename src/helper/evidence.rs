//! Normalized evidence and its exact collection provenance.
use super::manifest::CapabilityId;
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const EVIDENCE_SCHEMA: u16 = 2;
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;
pub const MAX_RECORDS: usize = 100;
pub const MAX_METRICS: usize = 64;
pub const MAX_EVIDENCE_REFS: usize = 16;
pub const MAX_ENVELOPES_PER_CASE: usize = 1000;
/// Normalized SQL plan and workload projections use this shorter window.
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

/// Normalize a source identifier before constructing an envelope; raw input is never retained.
pub fn source_id_digest(raw: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"relayne-helper-evidence-source-v1\0");
    hash.update(raw);
    format!("{:x}", hash.finalize())
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
    Process,
    ServiceDependency,
    Event,
    Interface,
    Transport,
    OsIdentity,
    SqlRead,
    SqlPlan,
    SqlWorkload,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<SystemDetail>,
}

/// Closed, capped system facts. Names are represented only by the record's
/// subject digest; command lines, event bodies and provider objects never enter evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemDetail {
    Os {
        family: OsFamily,
        reported_host_sha256: Option<String>,
        version: Option<String>,
        uptime_seconds: Option<u64>,
        load_one: Option<f64>,
        reason: Option<MissingReason>,
    },
    Process {
        memory_bytes: Option<u64>,
        cpu_seconds: Option<f64>,
        reason: Option<MissingReason>,
    },
    ServiceDependencies {
        count: Option<u8>,
        truncated: bool,
        reason: Option<MissingReason>,
    },
    ServiceDependency,
    Event {
        id: u32,
        level: u8,
        observed_at: DateTime<Utc>,
    },
    Interface {
        rx_errors: Option<u64>,
        tx_errors: Option<u64>,
        rx_discards: Option<u64>,
        tx_discards: Option<u64>,
        reason: Option<MissingReason>,
    },
    Tcp {
        established: Option<u64>,
        retransmits_per_second: Option<f64>,
        reason: Option<MissingReason>,
    },
    Sockets {
        listening_tcp: Option<u64>,
        reason: Option<MissingReason>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Linux,
}

impl SystemDetail {
    fn validate(&self) -> bool {
        let finite = |value: &Option<f64>| value.is_none_or(|v| v.is_finite() && v >= 0.0);
        match self {
            Self::Os {
                reported_host_sha256,
                version,
                load_one,
                ..
            } => {
                reported_host_sha256.as_ref().is_none_or(|v| is_digest(v))
                    && version.as_ref().is_none_or(|v| {
                        v.len() <= 48
                            && v.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
                            })
                    })
                    && finite(load_one)
            }
            Self::Process { cpu_seconds, .. } => finite(cpu_seconds),
            Self::ServiceDependencies { count, .. } => count.is_none_or(|n| n <= 16),
            Self::Event { id, level, .. } => *id <= 65535 && *level <= 5,
            Self::Tcp {
                retransmits_per_second,
                ..
            } => finite(retransmits_per_second),
            Self::ServiceDependency | Self::Interface { .. } | Self::Sockets { .. } => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    LatencyMs,
    CpuPercent,
    MemoryPercent,
    CommitPercent,
    DiskPercent,
    InterfaceRxBytesPerSecond,
    InterfaceTxBytesPerSecond,
    ProcessCount,
    Rows,
    DurationMs,
    ErrorCount,
    EstimatedCost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricUnit {
    Milliseconds,
    Percent,
    Count,
    BytesPerSecond,
    CostUnits,
}

/// Closed counter names avoid persisting raw OS/provider counter paths or SQL text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricSourceCounter {
    NetworkRoundTrip,
    OsCpu,
    OsMemory,
    OsCommit,
    OsDisk,
    OsInterfaceRx,
    OsInterfaceTx,
    OsProcessCount,
    DockerCpu,
    DockerMemory,
    SqlRowCount,
    SqlExecutionTime,
    ErrorEvents,
    SqlEstimatedCost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    PermissionDenied,
    Unavailable,
    Unsupported,
    NoSamples,
    ClockUncertain,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleWindow {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
}

pub const MAX_METRIC_WINDOW_SECS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedMetric {
    pub kind: MetricKind,
    pub value: Option<f64>,
    pub unit: MetricUnit,
    pub source_counter: MetricSourceCounter,
    pub sample_window: SampleWindow,
    pub missing_reason: Option<MissingReason>,
}

impl NormalizedMetric {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!((self.value, self.missing_reason), (Some(v), None) if v.is_finite())
                || matches!((self.value, self.missing_reason), (None, Some(_))),
            "Metric needs one finite reading or an explicit missing reason"
        );
        ensure!(
            self.sample_window.started_at <= self.sample_window.ended_at
                && self
                    .sample_window
                    .ended_at
                    .signed_duration_since(self.sample_window.started_at)
                    <= Duration::seconds(MAX_METRIC_WINDOW_SECS),
            "Invalid metric sample window"
        );
        let expected = match self.kind {
            MetricKind::LatencyMs => (
                MetricUnit::Milliseconds,
                MetricSourceCounter::NetworkRoundTrip,
            ),
            MetricKind::CpuPercent => (MetricUnit::Percent, MetricSourceCounter::OsCpu),
            MetricKind::MemoryPercent => (MetricUnit::Percent, MetricSourceCounter::OsMemory),
            MetricKind::CommitPercent => (MetricUnit::Percent, MetricSourceCounter::OsCommit),
            MetricKind::DiskPercent => (MetricUnit::Percent, MetricSourceCounter::OsDisk),
            MetricKind::InterfaceRxBytesPerSecond => (
                MetricUnit::BytesPerSecond,
                MetricSourceCounter::OsInterfaceRx,
            ),
            MetricKind::InterfaceTxBytesPerSecond => (
                MetricUnit::BytesPerSecond,
                MetricSourceCounter::OsInterfaceTx,
            ),
            MetricKind::ProcessCount => (MetricUnit::Count, MetricSourceCounter::OsProcessCount),
            MetricKind::Rows => (MetricUnit::Count, MetricSourceCounter::SqlRowCount),
            MetricKind::DurationMs => (
                MetricUnit::Milliseconds,
                MetricSourceCounter::SqlExecutionTime,
            ),
            MetricKind::ErrorCount => (MetricUnit::Count, MetricSourceCounter::ErrorEvents),
            MetricKind::EstimatedCost => {
                (MetricUnit::CostUnits, MetricSourceCounter::SqlEstimatedCost)
            }
        };
        let docker = matches!(
            (self.kind, self.unit, self.source_counter),
            (
                MetricKind::CpuPercent,
                MetricUnit::Percent,
                MetricSourceCounter::DockerCpu
            ) | (
                MetricKind::MemoryPercent,
                MetricUnit::Percent,
                MetricSourceCounter::DockerMemory
            )
        );
        ensure!(
            (self.unit, self.source_counter) == expected || docker,
            "Metric unit/counter mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub schema: u16,
    pub id: Uuid,
    pub binding: EvidenceBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_intent_sha256: Option<String>,
    pub capability_id: CapabilityId,
    pub capability_version: u16,
    pub parser_version: u16,
    pub origin: Origin,
    /// Domain-separated SHA-256 of the source identifier; never raw provider/user text.
    pub source_id: String,
    pub source_observed_at: DateTime<Utc>,
    pub retrieved_at: DateTime<Utc>,
    pub time_quality: TimeQuality,
    pub status: EvidenceStatus,
    pub coverage: Coverage,
    pub content_sha256: String,
    pub records: Vec<NormalizedRecord>,
    pub metrics: Vec<NormalizedMetric>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sql_observations: Vec<super::sql::types::SqlObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sql_artifacts: Vec<super::sql::artifacts::SqlArtifact>,
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
    #[serde(default)]
    pub request_intent_sha256: Option<String>,
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
            self.request_intent_sha256.as_deref().is_none_or(is_digest),
            "Invalid request intent digest"
        );
        ensure!(
            is_digest(&self.source_id),
            "Evidence source ID must be a digest"
        );
        ensure!(is_digest(&self.content_sha256), "Invalid content digest");
        ensure!(
            self.records.len() <= MAX_RECORDS
                && self.metrics.len() <= MAX_METRICS
                && self.evidence_refs.len() <= MAX_EVIDENCE_REFS,
            "Evidence item limit exceeded"
        );
        ensure!(
            self.records.iter().all(|r| is_digest(&r.subject_sha256)
                && r.detail.as_ref().is_none_or(SystemDetail::validate)),
            "Invalid record subject"
        );
        ensure!(
            self.sql_observations.len() <= super::sql::types::MAX_SQL_OBSERVATIONS
                && self
                    .sql_observations
                    .iter()
                    .all(super::sql::types::SqlObservation::bounded),
            "Invalid SQL observation projection"
        );
        ensure!(
            self.sql_observations.is_empty() || self.capability_id == CapabilityId::SqlRead,
            "SQL observations require SQL read capability"
        );
        ensure!(self.sql_artifacts.len() <= 1, "SQL artifact limit exceeded");
        for artifact in &self.sql_artifacts {
            artifact.validate()?;
            ensure!(
                matches!(
                    (self.capability_id, artifact),
                    (
                        CapabilityId::SqlPlan,
                        super::sql::artifacts::SqlArtifact::Plan(_)
                    ) | (
                        CapabilityId::SqlWorkloadBaseline | CapabilityId::SqlWorkloadRehearsal,
                        super::sql::artifacts::SqlArtifact::Workload(_)
                    )
                ),
                "SQL artifact capability mismatch"
            );
            if let super::sql::artifacts::SqlArtifact::Plan(plan) = artifact {
                ensure!(
                    self.origin == Origin::ImportedUnverified
                        || plan
                            .operators
                            .iter()
                            .all(|operator| operator.actual_rows.is_none()),
                    "live plan contains imported execution counters"
                );
                ensure!(
                    self.origin != Origin::Live || plan.metadata_sha256.is_some(),
                    "live plan metadata identity missing"
                );
            }
            if let super::sql::artifacts::SqlArtifact::Workload(workload) = artifact {
                ensure!(
                    self.evidence_refs.contains(&workload.review_evidence_id),
                    "Workload review source reference missing"
                );
            }
        }
        for metric in &self.metrics {
            metric.validate()?;
            ensure!(
                (metric.sample_window.ended_at <= self.retrieved_at
                    && metric.sample_window.ended_at <= self.source_observed_at)
                    || self.time_quality == TimeQuality::ClockUncertain,
                "Metric sample after observation/retrieval"
            );
        }
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
            || self.metrics.iter().any(|m| m.value.is_none())
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
