//! Selected, bounded Docker and Kubernetes reads. Provider JSON is discarded at this boundary.
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{
        Coverage, EvidenceStatus, MetricKind, MetricSourceCounter, MetricUnit, NormalizedMetric,
        NormalizedRecord, Observation, RecordKind, SampleWindow, source_id_digest,
    },
    manifest::CapabilityId,
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub struct DockerAdapter;
pub struct KubernetesAdapter;
pub(crate) fn local_docker_principal_digest() -> Result<String> {
    super::docker_native::process_sid_digest()
}
pub(crate) struct LocalReadiness {
    pub(crate) label: &'static str,
    pub(crate) ready: bool,
}

pub(crate) fn local_readiness(scope: &BoundScope) -> LocalReadiness {
    let (label, ready) = local_readiness_detail(scope);
    LocalReadiness { label, ready }
}

fn local_readiness_detail(scope: &BoundScope) -> (&'static str, bool) {
    match scope {
        BoundScope::Docker {
            daemon_context,
            credential,
            ..
        } => {
            let Some(credential) = credential else {
                return ("Credential reference missing", false);
            };
            let Ok((reviewed_uri, _, _)) =
                super::docker_native::reviewed_context(&credential.context)
            else {
                return ("Reviewed pipe, daemon or peer image digest missing", false);
            };
            let configured = super::docker_native::context_meta_root()
                .and_then(|root| super::docker_native::load_context(&root, daemon_context));
            if configured.ok().as_deref() != Some(reviewed_uri) {
                return ("Docker context unavailable or changed", false);
            }
            if super::docker_native::process_sid_digest().ok().as_deref()
                != Some(&credential.principal)
            {
                return ("Local process identity differs", false);
            }
            (
                "Local context and process identity verified; peer, vault and remote access checked at capture",
                true,
            )
        }
        BoundScope::Kubernetes {
            context,
            cluster_fingerprint,
            credential,
            ..
        } => {
            if credential.is_none() {
                return ("Credential reference missing", false);
            }
            let configured = super::kube_native::config_path().and_then(|path| {
                super::kube_native::load_endpoint(&path, context, cluster_fingerprint)
            });
            if configured.is_err() {
                return (
                    "Kubernetes endpoint/CA configuration unavailable or changed",
                    false,
                );
            }
            (
                "Local HTTPS endpoint/CA verified; vault and remote access unverified",
                true,
            )
        }
        _ => ("No container capability for this scope", false),
    }
}

pub(crate) fn validate_scoped_operation(scope: &BoundScope, id: CapabilityId) -> Result<()> {
    match (scope, id) {
        (
            BoundScope::Docker {
                daemon_context,
                container_id,
                credential,
            },
            CapabilityId::DockerContainerInspect | CapabilityId::DockerContainerStats,
        ) => {
            atom(daemon_context, 128)?;
            ensure!(
                container_id.len() == 64 && container_id.bytes().all(|b| b.is_ascii_hexdigit()),
                "Full container ID required"
            );
            let credential = credential
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Read credential missing"))?;
            let (_, daemon_id, _) = super::docker_native::reviewed_context(&credential.context)?;
            atom(daemon_id, 128)?;
            ensure!(
                crate::helper::evidence::is_digest(&credential.principal),
                "Reviewed process SID digest required"
            );
            Ok(())
        }
        (
            BoundScope::Kubernetes {
                context,
                cluster_fingerprint,
                namespace,
                resource_kind,
                resource_name,
                credential,
            },
            CapabilityId::KubernetesWorkloadStatus | CapabilityId::KubernetesEvents,
        ) => {
            atom(context, 128)?;
            dns(namespace)?;
            dns(resource_name)?;
            kind(resource_kind)?;
            ensure!(
                crate::helper::evidence::is_digest(cluster_fingerprint),
                "Invalid cluster fingerprint"
            );
            ensure!(
                credential.as_ref().is_some_and(|c| c.context == *context),
                "Credential context mismatch"
            );
            Ok(())
        }
        _ => anyhow::bail!("Container operation scope mismatch"),
    }
}

fn atom(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')),
        "Invalid identifier"
    );
    Ok(())
}
fn dns(value: &str) -> Result<()> {
    atom(value, 253)?;
    ensure!(
        !value.contains(':')
            && !value.contains('_')
            && !value.starts_with('.')
            && !value.ends_with('.'),
        "Invalid DNS name"
    );
    Ok(())
}
fn kind(value: &str) -> Result<()> {
    ensure!(
        matches!(
            value.to_ascii_lowercase().as_str(),
            "pod" | "deployment" | "statefulset" | "daemonset" | "job"
        ),
        "Unsupported workload kind"
    );
    Ok(())
}
fn json(bytes: &[u8], cap: usize) -> Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= cap,
        "Missing or oversized output"
    );
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Value::deserialize(&mut de)?;
    de.end()?;
    ensure!(value.is_object(), "Expected object");
    Ok(value)
}
use serde::Deserialize;
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Missing field"))?;
    ensure!(
        !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control),
        "Invalid field"
    );
    Ok(text)
}
fn record(subject: &str, observation: Observation) -> NormalizedRecord {
    NormalizedRecord {
        kind: RecordKind::Container,
        observation,
        subject_sha256: source_id_digest(subject.as_bytes()),
        detail: None,
    }
}
fn metric(
    kind: MetricKind,
    counter: MetricSourceCounter,
    value: f64,
    window: &SampleWindow,
) -> Result<NormalizedMetric> {
    ensure!(
        value.is_finite() && (0.0..=100_000.0).contains(&value),
        "Metric out of range"
    );
    Ok(NormalizedMetric {
        kind,
        value: Some(value),
        unit: MetricUnit::Percent,
        source_counter: counter,
        sample_window: window.clone(),
        missing_reason: None,
    })
}
fn output(
    status: EvidenceStatus,
    subject: &str,
    records: Vec<NormalizedRecord>,
    metrics: Vec<NormalizedMetric>,
) -> ProbeOutput {
    let now = Utc::now();
    ProbeOutput {
        status,
        coverage: Coverage {
            observed: u32::from(!records.is_empty()),
            expected: 1,
            truncated: false,
        },
        records,
        metrics,
        sql_observations: Vec::new(),
        sql_artifacts: vec![],
        evidence_refs: Vec::new(),
        source_id: subject.as_bytes().to_vec(),
        source_observed_at: now,
        parser_version: 1,
    }
}
pub(super) fn unavailable(subject: &str, status: EvidenceStatus) -> ProbeOutput {
    output(status, subject, Vec::new(), Vec::new())
}
pub(super) fn parse_docker_inspect(bytes: &[u8], expected: &str) -> Result<ProbeOutput> {
    let value = json(bytes, 64 * 1024)?;
    let id = string(&value, "Id")?;
    ensure!(id == expected, "Container mismatch");
    let state = value
        .get("State")
        .ok_or_else(|| anyhow::anyhow!("Missing state"))?;
    let status = string(state, "Status")?;
    let health = state
        .get("Health")
        .and_then(|v| v.get("Status"))
        .and_then(Value::as_str);
    let observation = if status == "running" && health.is_none_or(|h| h == "healthy") {
        Observation::Healthy
    } else if matches!(
        status,
        "running" | "exited" | "restarting" | "paused" | "dead"
    ) {
        Observation::Degraded
    } else {
        Observation::Unknown
    };
    let evidence_status = if observation == Observation::Unknown {
        EvidenceStatus::Partial
    } else {
        EvidenceStatus::Complete
    };
    Ok(output(
        evidence_status,
        expected,
        vec![record(expected, observation)],
        Vec::new(),
    ))
}
pub(super) fn parse_docker_stats(bytes: &[u8], expected: &str) -> Result<ProbeOutput> {
    let value = json(bytes, 64 * 1024)?;
    ensure!(string(&value, "id")? == expected, "Container mismatch");
    let read = chrono::DateTime::parse_from_rfc3339(string(&value, "read")?)?.with_timezone(&Utc);
    let preread =
        chrono::DateTime::parse_from_rfc3339(string(&value, "preread")?)?.with_timezone(&Utc);
    ensure!(
        preread < read
            && read <= Utc::now()
            && read.signed_duration_since(preread).num_seconds() <= 24 * 60 * 60,
        "Invalid Docker sample window"
    );
    let window = SampleWindow {
        started_at: preread,
        ended_at: read,
    };
    let cpu_stats = value
        .get("cpu_stats")
        .ok_or_else(|| anyhow::anyhow!("CPU stats missing"))?;
    let previous = value
        .get("precpu_stats")
        .ok_or_else(|| anyhow::anyhow!("Previous CPU stats missing"))?;
    let total = |v: &Value| {
        v.get("cpu_usage")
            .and_then(|v| v.get("total_usage"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("CPU total missing"))
    };
    let cpu_delta = total(cpu_stats)?
        .checked_sub(total(previous)?)
        .ok_or_else(|| anyhow::anyhow!("CPU counter reset"))?;
    let system = |v: &Value| {
        v.get("system_cpu_usage")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("System CPU total missing"))
    };
    let system_delta = system(cpu_stats)?
        .checked_sub(system(previous)?)
        .ok_or_else(|| anyhow::anyhow!("System CPU counter reset"))?;
    ensure!(system_delta > 0, "Zero CPU sample");
    let cpus = cpu_stats
        .get("online_cpus")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("CPU count missing"))?;
    ensure!((1..=1024).contains(&cpus), "Invalid CPU count");
    let cpu = cpu_delta as f64 / system_delta as f64 * cpus as f64 * 100.0;
    let memory_stats = value
        .get("memory_stats")
        .ok_or_else(|| anyhow::anyhow!("Memory stats missing"))?;
    let used = memory_stats
        .get("usage")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("Memory usage missing"))?;
    let limit = memory_stats
        .get("limit")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("Memory limit missing"))?;
    ensure!(limit > 0, "Zero memory limit");
    let memory = used as f64 / limit as f64 * 100.0;
    let metrics = vec![
        metric(
            MetricKind::CpuPercent,
            MetricSourceCounter::DockerCpu,
            cpu,
            &window,
        )?,
        metric(
            MetricKind::MemoryPercent,
            MetricSourceCounter::DockerMemory,
            memory,
            &window,
        )?,
    ];
    Ok(output(
        EvidenceStatus::Complete,
        expected,
        vec![record(expected, Observation::Unknown)],
        metrics,
    ))
}
pub(super) fn parse_kube_status(
    bytes: &[u8],
    namespace: &str,
    resource_kind: &str,
    name: &str,
) -> Result<(ProbeOutput, String)> {
    let value = json(bytes, 64 * 1024)?;
    let found_kind = string(&value, "kind")?;
    ensure!(
        found_kind.eq_ignore_ascii_case(resource_kind),
        "Workload kind mismatch"
    );
    let metadata = value
        .get("metadata")
        .ok_or_else(|| anyhow::anyhow!("Missing metadata"))?;
    ensure!(
        string(metadata, "name")? == name && string(metadata, "namespace")? == namespace,
        "Workload identity mismatch"
    );
    let uid = string(metadata, "uid")?.to_owned();
    atom(&uid, 128)?;
    let status = value
        .get("status")
        .ok_or_else(|| anyhow::anyhow!("Missing status"))?;
    let generation = metadata.get("generation").and_then(Value::as_u64);
    let observed_generation = status.get("observedGeneration").and_then(Value::as_u64);
    let stale = matches!((generation, observed_generation), (Some(g), Some(o)) if o < g);
    let condition = |name: &str| {
        status
            .get("conditions")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|c| c.get("type").and_then(Value::as_str) == Some(name))
            })
            .and_then(|c| c.get("status"))
            .and_then(Value::as_str)
    };
    let observation = if stale {
        Observation::Unknown
    } else {
        match resource_kind.to_ascii_lowercase().as_str() {
            "pod" => {
                let containers_ready = status
                    .get("containerStatuses")
                    .and_then(Value::as_array)
                    .filter(|items| !items.is_empty() && items.len() <= 100)
                    .is_some_and(|items| {
                        items
                            .iter()
                            .all(|item| item.get("ready").and_then(Value::as_bool) == Some(true))
                    });
                match (
                    status.get("phase").and_then(Value::as_str),
                    condition("Ready"),
                ) {
                    (Some("Running"), Some("True"))
                        if metadata.get("deletionTimestamp").is_none()
                            && containers_ready
                            && generation.is_none_or(|g| {
                                g <= 1 || observed_generation.is_some_and(|o| o >= g)
                            }) =>
                    {
                        Observation::Healthy
                    }
                    (Some("Running"), Some("False")) | (Some("Failed"), _) => Observation::Degraded,
                    _ => Observation::Unknown,
                }
            }
            "job" => {
                let desired = value
                    .get("spec")
                    .and_then(|v| v.get("completions"))
                    .and_then(Value::as_u64)
                    .unwrap_or(1);
                let succeeded = status.get("succeeded").and_then(Value::as_u64).unwrap_or(0);
                if condition("Failed") == Some("True") {
                    Observation::Degraded
                } else if desired > 0
                    && succeeded >= desired
                    && condition("Complete") == Some("True")
                {
                    Observation::Healthy
                } else {
                    Observation::Unknown
                }
            }
            "daemonset" => {
                let desired = status.get("desiredNumberScheduled").and_then(Value::as_u64);
                let ready = status.get("numberReady").and_then(Value::as_u64);
                let updated = status.get("updatedNumberScheduled").and_then(Value::as_u64);
                match (generation, observed_generation, desired, ready, updated) {
                    (Some(g), Some(o), Some(d), Some(r), Some(u)) if o >= g && d == r && d == u => {
                        Observation::Healthy
                    }
                    (Some(g), Some(o), Some(d), Some(r), _) if o >= g && r < d => {
                        Observation::Degraded
                    }
                    _ => Observation::Unknown,
                }
            }
            _ => {
                let desired = value
                    .get("spec")
                    .and_then(|v| v.get("replicas"))
                    .and_then(Value::as_u64)
                    .unwrap_or(1);
                let ready = status
                    .get("readyReplicas")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let updated = status.get("updatedReplicas").and_then(Value::as_u64);
                match (generation, observed_generation, updated) {
                    (Some(g), Some(o), Some(u)) if o >= g && ready == desired && u == desired => {
                        Observation::Healthy
                    }
                    (Some(g), Some(o), _) if o >= g && ready < desired => Observation::Degraded,
                    _ => Observation::Unknown,
                }
            }
        }
    };
    let evidence_status = if observation == Observation::Unknown {
        EvidenceStatus::Partial
    } else {
        EvidenceStatus::Complete
    };
    Ok((
        output(
            evidence_status,
            &uid,
            vec![record(&uid, observation)],
            Vec::new(),
        ),
        uid,
    ))
}
pub(super) fn parse_kube_events(bytes: &[u8], uid: &str) -> Result<ProbeOutput> {
    let value = json(bytes, 128 * 1024)?;
    ensure!(string(&value, "kind")? == "EventList", "Expected events");
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Missing event list"))?;
    ensure!(items.len() <= 100, "Too many events");
    let mut degraded = false;
    for item in items {
        let involved = item
            .get("involvedObject")
            .ok_or_else(|| anyhow::anyhow!("Missing involved object"))?;
        ensure!(string(involved, "uid")? == uid, "Event target mismatch");
        let event_type = string(item, "type")?;
        let _ = string(item, "reason")?;
        let _ = string(involved, "kind")?;
        let _ = string(involved, "name")?;
        degraded |= event_type == "Warning";
    }
    // A zero-event list is observed coverage, never proof that the workload is healthy.
    let observation = if degraded {
        Observation::Degraded
    } else {
        Observation::Unknown
    };
    Ok(output(
        EvidenceStatus::Complete,
        uid,
        vec![record(uid, observation)],
        Vec::new(),
    ))
}
pub(super) fn docker_identity(bytes: &[u8], reviewed_id: &str) -> Result<()> {
    let value = json(bytes, 64 * 1024)?;
    ensure!(
        string(&value, "ID")? == reviewed_id,
        "Daemon identity mismatch"
    );
    Ok(())
}
pub(super) fn kube_principal(bytes: &[u8], reviewed: &str) -> Result<()> {
    let value = json(bytes, 64 * 1024)?;
    ensure!(
        string(&value, "kind")? == "SelfSubjectReview",
        "Missing identity proof"
    );
    let user = value
        .get("status")
        .and_then(|v| v.get("userInfo"))
        .ok_or_else(|| anyhow::anyhow!("Missing identity proof"))?;
    ensure!(
        string(user, "username")? == reviewed,
        "Kubernetes principal mismatch"
    );
    Ok(())
}
impl ProbeAdapter for DockerAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { super::docker_native::collect(request, secrets, cancel).await })
    }
}
impl ProbeAdapter for KubernetesAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { super::kube_native::collect(request, secrets, cancel).await })
    }
}
