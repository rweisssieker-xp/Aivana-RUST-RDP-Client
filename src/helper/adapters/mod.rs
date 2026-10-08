//! Closed system collectors. Selectors become validated data in fixed scripts only.
use super::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{
        Coverage, EvidenceStatus, MetricKind, MetricSourceCounter, MetricUnit, MissingReason,
        NormalizedMetric, NormalizedRecord, Observation, RecordKind, SampleWindow,
    },
    manifest::ProbeParams,
    process::ProcessFailure,
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, TimeZone, Utc};
use tokio_util::sync::CancellationToken;

mod linux;
mod network;
mod windows;
pub use network::NetworkAdapter;
pub use {linux::LinuxAdapter, windows::WindowsAdapter};

pub(crate) fn safe_identifier(
    input: Option<&str>,
    required: bool,
) -> Result<String, ProcessFailure> {
    let input = input.unwrap_or("");
    if (required && input.is_empty())
        || input.len() > 80
        || !input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || input.starts_with('-')
    {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(input.to_owned())
}

pub(crate) fn safe_service(input: Option<&str>) -> Result<String, ProcessFailure> {
    let input = input.unwrap_or("");
    if input.len() > 80
        || input.starts_with('-')
        || !input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(input.to_owned())
}

pub(crate) fn safe_host(input: &str) -> Result<String, ProcessFailure> {
    if input.is_empty()
        || input.len() > 253
        || input.starts_with('-')
        || !input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(input.to_owned())
}

pub(crate) fn safe_mount(input: Option<&str>) -> Result<String, ProcessFailure> {
    let input = input.unwrap_or("");
    if input.len() > 160
        || !input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b':'))
        || input.starts_with('-')
        || input.contains("..")
    {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(input.to_owned())
}

pub(crate) fn safe_linux_mount(input: Option<&str>) -> Result<String, ProcessFailure> {
    let mount = safe_mount(input)?;
    if !mount.is_empty() && (!mount.starts_with('/') || mount.contains("//")) {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(mount)
}

pub(crate) fn safe_windows_mount(input: Option<&str>) -> Result<String, ProcessFailure> {
    let mount = safe_mount(input)?;
    let valid_drive = mount.len() == 2
        && mount.as_bytes()[0].is_ascii_alphabetic()
        && mount.as_bytes()[1] == b':';
    if !mount.is_empty() && !valid_drive {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(mount)
}

#[derive(Clone, Debug)]
pub struct CounterSample {
    pub value: Option<f64>,
    pub at: DateTime<Utc>,
    pub missing_reason: Option<MissingReason>,
}

#[derive(Clone, Debug)]
pub struct MetricReading {
    pub value: Option<f64>,
    pub missing_reason: Option<MissingReason>,
    pub window: SampleWindow,
}

pub fn counter_delta(before: &CounterSample, after: &CounterSample) -> MetricReading {
    let window = SampleWindow {
        started_at: before.at,
        ended_at: after.at,
    };
    let reason = before
        .missing_reason
        .or(after.missing_reason)
        .unwrap_or(MissingReason::NoSamples);
    let elapsed = after.at.signed_duration_since(before.at).num_milliseconds() as f64 / 1000.0;
    let value = match (before.value, after.value) {
        (Some(a), Some(b))
            if before.missing_reason.is_none()
                && after.missing_reason.is_none()
                && a.is_finite()
                && b.is_finite()
                && a >= 0.0
                && b >= a
                && elapsed > 0.0 =>
        {
            Some((b - a) / elapsed)
        }
        _ => None,
    };
    MetricReading {
        value,
        missing_reason: value.is_none().then_some(reason),
        window,
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshot {
    schema: u8,
    start_ms: i64,
    end_ms: i64,
    cpu_before: Option<Vec<f64>>,
    cpu_after: Option<Vec<f64>>,
    interface_before: Option<Vec<f64>>,
    interface_after: Option<Vec<f64>>,
    memory: Option<Vec<f64>>,
    commit: Option<Vec<f64>>,
    disk: Option<Vec<f64>>,
    error_count: Option<f64>,
    #[serde(default)]
    events_truncated: bool,
    process_count: Option<f64>,
    service_state: Option<String>,
}

fn pair(values: Option<&Vec<f64>>) -> Option<(f64, f64)> {
    let values = values?;
    (values.len() == 2 && values.iter().all(|v| v.is_finite() && *v >= 0.0))
        .then(|| (values[0], values[1]))
}

fn instant(ms: i64) -> Result<DateTime<Utc>> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .ok_or_else(|| anyhow::anyhow!("Invalid collector timestamp"))
}

fn reading(
    kind: MetricKind,
    source: MetricSourceCounter,
    unit: MetricUnit,
    value: Option<f64>,
    reason: MissingReason,
    window: SampleWindow,
) -> NormalizedMetric {
    NormalizedMetric {
        kind,
        source_counter: source,
        unit,
        value,
        missing_reason: value.is_none().then_some(reason),
        sample_window: window,
    }
}

fn percentage(values: Option<&Vec<f64>>) -> Option<f64> {
    let (used, total) = pair(values)?;
    (total > 0.0 && used <= total).then_some(used / total * 100.0)
}

fn commit_percentage(values: Option<&Vec<f64>>) -> Option<f64> {
    let (used, total) = pair(values)?;
    (total > 0.0).then_some(used / total * 100.0)
}

fn normalize_snapshot(
    raw: RawSnapshot,
    request: &ProbeRequest,
    service: Option<&str>,
    mount: Option<&str>,
    interface: Option<&str>,
) -> Result<ProbeOutput> {
    ensure!(raw.schema == 1, "Unknown collector schema");
    let start = instant(raw.start_ms)?;
    let end = instant(raw.end_ms)?;
    ensure!(
        end > start && end.signed_duration_since(start).num_seconds() <= 10,
        "Invalid sample interval"
    );
    ensure!(
        end <= Utc::now() + chrono::Duration::seconds(30),
        "Future sample"
    );
    let window = SampleWindow {
        started_at: start,
        ended_at: end,
    };
    let cpu = match (pair(raw.cpu_before.as_ref()), pair(raw.cpu_after.as_ref())) {
        (Some((idle0, total0)), Some((idle1, total1)))
            if total1 > total0 && idle1 >= idle0 && idle1 - idle0 <= total1 - total0 =>
        {
            Some(100.0 * (1.0 - (idle1 - idle0) / (total1 - total0)))
        }
        _ => None,
    };
    let mut metrics = vec![
        reading(
            MetricKind::CpuPercent,
            MetricSourceCounter::OsCpu,
            MetricUnit::Percent,
            cpu,
            MissingReason::NoSamples,
            window,
        ),
        reading(
            MetricKind::MemoryPercent,
            MetricSourceCounter::OsMemory,
            MetricUnit::Percent,
            percentage(raw.memory.as_ref()),
            MissingReason::Unavailable,
            window,
        ),
        reading(
            MetricKind::CommitPercent,
            MetricSourceCounter::OsCommit,
            MetricUnit::Percent,
            commit_percentage(raw.commit.as_ref()),
            MissingReason::Unsupported,
            window,
        ),
        reading(
            MetricKind::DiskPercent,
            MetricSourceCounter::OsDisk,
            MetricUnit::Percent,
            percentage(raw.disk.as_ref()),
            if mount.is_some() {
                MissingReason::Unavailable
            } else {
                MissingReason::NoSamples
            },
            window,
        ),
        reading(
            MetricKind::ProcessCount,
            MetricSourceCounter::OsProcessCount,
            MetricUnit::Count,
            raw.process_count.filter(|v| v.is_finite() && *v >= 0.0),
            MissingReason::Unavailable,
            window,
        ),
    ];
    metrics.push(reading(
        MetricKind::ErrorCount,
        MetricSourceCounter::ErrorEvents,
        MetricUnit::Count,
        raw.error_count
            .filter(|v| v.is_finite() && *v >= 0.0 && *v <= 100.0),
        if matches!(request.scope, BoundScope::Linux { .. }) {
            MissingReason::Unsupported
        } else {
            MissingReason::Unavailable
        },
        SampleWindow {
            started_at: end - chrono::Duration::minutes(5),
            ended_at: end,
        },
    ));
    for (index, kind, source) in [
        (
            0,
            MetricKind::InterfaceRxBytesPerSecond,
            MetricSourceCounter::OsInterfaceRx,
        ),
        (
            1,
            MetricKind::InterfaceTxBytesPerSecond,
            MetricSourceCounter::OsInterfaceTx,
        ),
    ] {
        let before =
            pair(raw.interface_before.as_ref()).map(|p| if index == 0 { p.0 } else { p.1 });
        let after = pair(raw.interface_after.as_ref()).map(|p| if index == 0 { p.0 } else { p.1 });
        let delta = counter_delta(
            &CounterSample {
                value: before,
                at: start,
                missing_reason: None,
            },
            &CounterSample {
                value: after,
                at: end,
                missing_reason: None,
            },
        );
        metrics.push(NormalizedMetric {
            kind,
            source_counter: source,
            unit: MetricUnit::BytesPerSecond,
            value: interface.and(delta.value),
            missing_reason: if interface.is_some() {
                delta.missing_reason
            } else {
                Some(MissingReason::Unsupported)
            },
            sample_window: delta.window,
        });
    }
    let observed = metrics.iter().filter(|m| m.value.is_some()).count() as u32;
    let expected = metrics.len() as u32;
    let status = if raw.events_truncated {
        EvidenceStatus::Truncated
    } else if observed == expected {
        EvidenceStatus::Complete
    } else {
        EvidenceStatus::Partial
    };
    let mut records = vec![NormalizedRecord {
        kind: RecordKind::System,
        observation: if status == EvidenceStatus::Complete {
            Observation::Healthy
        } else {
            Observation::Unknown
        },
        subject_sha256: request.scope.resource_digest()?,
    }];
    if let Some(service) = service {
        let observation = match raw.service_state.as_deref() {
            Some("Running" | "active") => Observation::Healthy,
            Some("Stopped" | "inactive" | "failed") => Observation::Degraded,
            _ => Observation::Unknown,
        };
        let digest = super::evidence::source_id_digest(service.as_bytes());
        records.push(NormalizedRecord {
            kind: RecordKind::Service,
            observation,
            subject_sha256: digest,
        });
        if request.capability_id == super::manifest::CapabilityId::ServiceStatus {
            return Ok(ProbeOutput {
                status: if observation == Observation::Unknown {
                    EvidenceStatus::Partial
                } else {
                    EvidenceStatus::Complete
                },
                coverage: Coverage {
                    observed: u32::from(observation != Observation::Unknown),
                    expected: 1,
                    truncated: false,
                },
                records: records
                    .into_iter()
                    .filter(|r| r.kind == RecordKind::Service)
                    .collect(),
                metrics: vec![],
                evidence_refs: vec![],
                source_id: format!("service:{}", request.binding.scope_sha256).into_bytes(),
                source_observed_at: end,
                parser_version: 1,
            });
        }
    }
    Ok(ProbeOutput {
        status,
        coverage: Coverage {
            observed,
            expected,
            truncated: raw.events_truncated,
        },
        records,
        metrics,
        evidence_refs: vec![],
        source_id: format!("system:{}", request.binding.scope_sha256).into_bytes(),
        source_observed_at: end,
        parser_version: 1,
    })
}

fn selections(params: &ProbeParams) -> Result<(Option<String>, Option<String>, Option<String>)> {
    match params {
        ProbeParams::System => Ok((None, None, None)),
        ProbeParams::SystemSelected { mount, interface } => {
            Ok((None, mount.clone(), interface.clone()))
        }
        ProbeParams::ServiceName { name } => Ok((Some(name.clone()), None, None)),
        _ => anyhow::bail!("Unsupported system parameters"),
    }
}

pub struct SystemAdapter;
fn tool_gap(request: &ProbeRequest, failure: ProcessFailure) -> Result<ProbeOutput> {
    if matches!(
        failure,
        ProcessFailure::Canceled | ProcessFailure::TimedOut | ProcessFailure::InvalidInvocation
    ) {
        anyhow::bail!("System collection canceled, expired or invalid");
    }
    let status = if failure == ProcessFailure::OutputLimit {
        EvidenceStatus::Truncated
    } else {
        EvidenceStatus::Unavailable
    };
    Ok(ProbeOutput {
        status,
        coverage: Coverage {
            observed: 0,
            expected: 1,
            truncated: status == EvidenceStatus::Truncated,
        },
        records: vec![NormalizedRecord {
            kind: RecordKind::System,
            observation: Observation::Unknown,
            subject_sha256: request.scope.resource_digest()?,
        }],
        metrics: vec![],
        evidence_refs: vec![],
        source_id: format!("system:{}", request.binding.scope_sha256).into_bytes(),
        source_observed_at: Utc::now(),
        parser_version: 1,
    })
}

fn permission_gap(request: &ProbeRequest) -> Result<ProbeOutput> {
    Ok(ProbeOutput {
        status: EvidenceStatus::Denied,
        coverage: Coverage {
            observed: 0,
            expected: 1,
            truncated: false,
        },
        records: vec![NormalizedRecord {
            kind: RecordKind::System,
            observation: Observation::Unknown,
            subject_sha256: request.scope.resource_digest()?,
        }],
        metrics: vec![],
        evidence_refs: vec![],
        source_id: format!("system:{}", request.binding.scope_sha256).into_bytes(),
        source_observed_at: Utc::now(),
        parser_version: 1,
    })
}
impl ProbeAdapter for SystemAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        match request.scope {
            BoundScope::WindowsWinRm { .. } => WindowsAdapter.collect(request, secrets, cancel),
            BoundScope::Linux { .. } => LinuxAdapter.collect(request, secrets, cancel),
            _ => Box::pin(async { anyhow::bail!("Unsupported system scope") }),
        }
    }
}

#[cfg(test)]
#[path = "system_tests.rs"]
mod tests;
