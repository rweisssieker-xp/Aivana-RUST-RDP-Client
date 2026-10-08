//! Selected, bounded Docker and Kubernetes reads. Provider JSON is discarded at this boundary.
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{
        Coverage, EvidenceStatus, MetricKind, MetricSourceCounter, MetricUnit, NormalizedMetric,
        NormalizedRecord, Observation, RecordKind, SampleWindow, source_id_digest,
    },
    manifest::CapabilityId,
    process::{FixedToolOperation, ProcessFailure, run_fixed_tool},
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct DockerAdapter;
pub struct KubernetesAdapter;

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
            atom(&credential.context, 128)?;
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
    }
}
fn metric(kind: MetricKind, counter: MetricSourceCounter, value: f64) -> Result<NormalizedMetric> {
    ensure!(
        value.is_finite() && (0.0..=100.0).contains(&value),
        "Metric out of range"
    );
    let now = Utc::now();
    Ok(NormalizedMetric {
        kind,
        value: Some(value),
        unit: MetricUnit::Percent,
        source_counter: counter,
        sample_window: SampleWindow {
            started_at: now,
            ended_at: now,
        },
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
        evidence_refs: Vec::new(),
        source_id: subject.as_bytes().to_vec(),
        source_observed_at: now,
        parser_version: 1,
    }
}
fn failure(error: ProcessFailure, subject: &str) -> ProbeOutput {
    let status = match error {
        ProcessFailure::Canceled => EvidenceStatus::Canceled,
        ProcessFailure::OutputLimit => EvidenceStatus::Truncated,
        // Exit status alone cannot distinguish auth denial from missing object or network failure.
        ProcessFailure::ExitFailed => EvidenceStatus::Unavailable,
        ProcessFailure::Spawn | ProcessFailure::TimedOut | ProcessFailure::InvalidInvocation => {
            EvidenceStatus::Unavailable
        }
    };
    output(status, subject, Vec::new(), Vec::new())
}
fn percent(text: &str) -> Result<f64> {
    let raw = text
        .strip_suffix('%')
        .ok_or_else(|| anyhow::anyhow!("Missing percent unit"))?;
    let number: f64 = raw.trim().parse()?;
    ensure!(
        number.is_finite() && (0.0..=100.0).contains(&number),
        "Percent out of range"
    );
    Ok(number)
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
    let id = string(&value, "ID")?;
    ensure!(
        id == expected || expected.starts_with(id) && id.len() >= 12,
        "Container mismatch"
    );
    let cpu = percent(string(&value, "CPUPerc")?)?;
    let memory = percent(string(&value, "MemPerc")?)?;
    let metrics = vec![
        metric(MetricKind::CpuPercent, MetricSourceCounter::OsCpu, cpu)?,
        metric(
            MetricKind::MemoryPercent,
            MetricSourceCounter::OsMemory,
            memory,
        )?,
    ];
    let observation = if cpu < 90.0 && memory < 90.0 {
        Observation::Healthy
    } else {
        Observation::Degraded
    };
    Ok(output(
        EvidenceStatus::Complete,
        expected,
        vec![record(expected, observation)],
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
    let observation = match resource_kind.to_ascii_lowercase().as_str() {
        "pod" => match status.get("phase").and_then(Value::as_str) {
            Some("Running") => Observation::Healthy,
            Some("Pending" | "Failed" | "Unknown") => Observation::Degraded,
            _ => Observation::Unknown,
        },
        "job" => {
            if status
                .get("succeeded")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
            {
                Observation::Healthy
            } else if status
                .get("failed")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
            {
                Observation::Degraded
            } else {
                Observation::Unknown
            }
        }
        _ => {
            let desired = value
                .get("spec")
                .and_then(|v| v.get("replicas"))
                .and_then(Value::as_u64);
            let ready = status.get("readyReplicas").and_then(Value::as_u64);
            match (desired, ready) {
                (Some(d), Some(r)) if d == r => Observation::Healthy,
                (Some(_), Some(_)) => Observation::Degraded,
                _ => Observation::Unknown,
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
pub(super) fn docker_local_context(bytes: &[u8], reviewed_context: &str) -> Result<()> {
    let value = json(bytes, 64 * 1024)?;
    ensure!(
        string(&value, "Name")? == reviewed_context,
        "Docker context mismatch"
    );
    let endpoint = value
        .get("Endpoints")
        .and_then(|v| v.get("docker"))
        .ok_or_else(|| anyhow::anyhow!("Missing Docker endpoint"))?;
    ensure!(
        string(endpoint, "Host")?.starts_with("npipe:////./pipe/"),
        "Daemon authentication is not bound to local OS principal"
    );
    Ok(())
}
pub(super) fn local_principal(bytes: &[u8], reviewed: &str) -> Result<()> {
    let actual = std::str::from_utf8(bytes)?.trim();
    ensure!(
        !actual.is_empty()
            && actual.len() <= 512
            && !actual.chars().any(char::is_control)
            && actual.eq_ignore_ascii_case(reviewed),
        "Local principal mismatch"
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
pub(super) fn kube_identity(
    bytes: &[u8],
    reviewed_context: &str,
    reviewed_fingerprint: &str,
) -> Result<()> {
    let value = json(bytes, 64 * 1024)?;
    ensure!(
        string(&value, "current-context")? == reviewed_context,
        "Context mismatch"
    );
    let contexts = value
        .get("contexts")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("No context"))?;
    ensure!(
        contexts.len() == 1 && string(&contexts[0], "name")? == reviewed_context,
        "Context mismatch"
    );
    let clusters = value
        .get("clusters")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("No cluster"))?;
    ensure!(clusters.len() == 1, "Ambiguous cluster");
    let selected_cluster = string(
        contexts[0]
            .get("context")
            .ok_or_else(|| anyhow::anyhow!("No context body"))?,
        "cluster",
    )?;
    ensure!(
        string(&clusters[0], "name")? == selected_cluster,
        "Context cluster mismatch"
    );
    let selected_user = string(
        contexts[0]
            .get("context")
            .ok_or_else(|| anyhow::anyhow!("No context body"))?,
        "user",
    )?;
    let users = value
        .get("users")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("No user"))?;
    ensure!(
        users.len() == 1 && string(&users[0], "name")? == selected_user,
        "Context user mismatch"
    );
    let user = users[0]
        .get("user")
        .ok_or_else(|| anyhow::anyhow!("No user config"))?;
    ensure!(
        user.get("exec").is_none() && user.get("auth-provider").is_none(),
        "Dynamic credential plugins are unsupported"
    );
    let cluster = clusters[0]
        .get("cluster")
        .ok_or_else(|| anyhow::anyhow!("No cluster"))?;
    let server = string(cluster, "server")?;
    ensure!(server.starts_with("https://"), "Unsafe cluster endpoint");
    let ca = cluster
        .get("certificate-authority-data")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Missing CA identity"))?;
    ensure!(
        !ca.is_empty() && ca.len() <= 64 * 1024,
        "Invalid CA identity"
    );
    let mut hash = Sha256::new();
    hash.update(b"relayne-kubernetes-cluster-v1\0");
    hash.update(server.as_bytes());
    hash.update(b"\0");
    hash.update(ca.as_bytes());
    ensure!(
        format!("{:x}", hash.finalize()) == reviewed_fingerprint,
        "Cluster identity mismatch"
    );
    Ok(())
}
fn remaining(request: &ProbeRequest) -> Duration {
    Duration::from_secs(request.deadline_secs.unwrap_or(15).min(30))
}
impl ProbeAdapter for DockerAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::Docker {
                daemon_context,
                container_id,
                credential,
            } = &request.scope
            else {
                anyhow::bail!("Scope mismatch")
            };
            atom(daemon_context, 128)?;
            ensure!(
                container_id.len() == 64 && container_id.bytes().all(|b| b.is_ascii_hexdigit()),
                "Full container ID required"
            );
            let reviewed_id = credential
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Daemon identity missing"))?
                .context
                .as_str();
            atom(reviewed_id, 128)?;
            let subject = format!("docker:{daemon_context}:{container_id}");
            let reviewed_principal = &credential.as_ref().expect("checked credential").principal;
            let local_context = match run_fixed_tool(
                FixedToolOperation::DockerContextInfo {
                    context: daemon_context.clone(),
                },
                cancel.clone(),
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if docker_local_context(&local_context.stdout, daemon_context).is_err() {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let principal = match run_fixed_tool(
                FixedToolOperation::LocalCurrentPrincipal,
                cancel.clone(),
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if local_principal(&principal.stdout, reviewed_principal).is_err() {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let info = match run_fixed_tool(
                FixedToolOperation::DockerDaemonInfo {
                    context: daemon_context.clone(),
                },
                cancel.clone(),
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if docker_identity(&info.stdout, reviewed_id).is_err() {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let operation = match request.capability_id {
                CapabilityId::DockerContainerInspect => {
                    FixedToolOperation::DockerContainerInspect {
                        context: daemon_context.clone(),
                        container_id: container_id.clone(),
                    }
                }
                CapabilityId::DockerContainerStats => FixedToolOperation::DockerContainerStats {
                    context: daemon_context.clone(),
                    container_id: container_id.clone(),
                },
                _ => anyhow::bail!("Capability mismatch"),
            };
            let result = match run_fixed_tool(operation, cancel.clone(), remaining(request)).await {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if secrets
                .resolve(
                    credential.as_ref().expect("checked credential"),
                    credential.as_ref().expect("checked credential").purpose,
                )
                .is_err()
            {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let current = match run_fixed_tool(
                FixedToolOperation::DockerDaemonInfo {
                    context: daemon_context.clone(),
                },
                cancel,
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if docker_identity(&current.stdout, reviewed_id).is_err() {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let mut parsed = match request.capability_id {
                CapabilityId::DockerContainerInspect => {
                    parse_docker_inspect(&result.stdout, container_id)
                }
                _ => parse_docker_stats(&result.stdout, container_id),
            }
            .unwrap_or_else(|_| output(EvidenceStatus::Partial, &subject, Vec::new(), Vec::new()));
            // Local pipe user is checked, but the CLI does not consume the protected vault secret.
            // Keep this observation ineligible for verification of a repair.
            if parsed.status == EvidenceStatus::Complete {
                parsed.status = EvidenceStatus::Partial;
            }
            Ok(parsed)
        })
    }
}
impl ProbeAdapter for KubernetesAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::Kubernetes {
                context,
                cluster_fingerprint,
                namespace,
                resource_kind,
                resource_name,
                credential,
            } = &request.scope
            else {
                anyhow::bail!("Scope mismatch")
            };
            atom(context, 128)?;
            dns(namespace)?;
            dns(resource_name)?;
            kind(resource_kind)?;
            ensure!(
                credential.as_ref().is_some_and(|c| c.context == *context),
                "Credential context mismatch"
            );
            let subject =
                format!("kubernetes:{context}:{namespace}:{resource_kind}:{resource_name}");
            let info = match run_fixed_tool(
                FixedToolOperation::KubernetesContextInfo {
                    context: context.clone(),
                },
                cancel.clone(),
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if kube_identity(&info.stdout, context, cluster_fingerprint).is_err() {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let principal = match run_fixed_tool(
                FixedToolOperation::KubernetesCurrentPrincipal {
                    context: context.clone(),
                },
                cancel.clone(),
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if kube_principal(
                &principal.stdout,
                &credential.as_ref().expect("checked credential").principal,
            )
            .is_err()
            {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let get = FixedToolOperation::KubernetesWorkloadGet {
                context: context.clone(),
                namespace: namespace.clone(),
                kind: resource_kind.clone(),
                name: resource_name.clone(),
            };
            let result = match run_fixed_tool(get, cancel.clone(), remaining(request)).await {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            let (status, uid) =
                match parse_kube_status(&result.stdout, namespace, resource_kind, resource_name) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(output(
                            EvidenceStatus::Partial,
                            &subject,
                            Vec::new(),
                            Vec::new(),
                        ));
                    }
                };
            if request.capability_id == CapabilityId::KubernetesWorkloadStatus {
                if secrets
                    .resolve(
                        credential.as_ref().expect("checked credential"),
                        credential.as_ref().expect("checked credential").purpose,
                    )
                    .is_err()
                {
                    return Ok(output(
                        EvidenceStatus::Unavailable,
                        &subject,
                        Vec::new(),
                        Vec::new(),
                    ));
                }
                let mut status = status;
                if status.status == EvidenceStatus::Complete {
                    status.status = EvidenceStatus::Partial;
                }
                return Ok(status);
            }
            ensure!(
                request.capability_id == CapabilityId::KubernetesEvents,
                "Capability mismatch"
            );
            let result = match run_fixed_tool(
                FixedToolOperation::KubernetesEvents {
                    context: context.clone(),
                    namespace: namespace.clone(),
                    uid: uid.clone(),
                },
                cancel.clone(),
                remaining(request),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return Ok(failure(e, &subject)),
            };
            if secrets
                .resolve(
                    credential.as_ref().expect("checked credential"),
                    credential.as_ref().expect("checked credential").purpose,
                )
                .is_err()
            {
                return Ok(output(
                    EvidenceStatus::Unavailable,
                    &subject,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            let mut parsed = parse_kube_events(&result.stdout, &uid).unwrap_or_else(|_| {
                output(EvidenceStatus::Partial, &subject, Vec::new(), Vec::new())
            });
            if parsed.status == EvidenceStatus::Complete {
                parsed.status = EvidenceStatus::Partial;
            }
            Ok(parsed)
        })
    }
}
