//! Bounded asynchronous probe queue. Errors crossing this boundary have closed, redacted codes.
use super::{
    capability::{CapabilityRegistry, ProbeAdapter, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{
        self, Coverage, EvidenceEnvelope, EvidenceStatus, MetricKind, MetricSourceCounter,
        MetricUnit, NormalizedMetric, NormalizedRecord, Observation, Origin, RecordKind,
        SampleWindow, TimeQuality,
    },
    manifest::{CapabilityId, ProbeParams},
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock, mpsc},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const MAX_ACTIVE: usize = 4;
pub const MAX_QUEUED: usize = 32;
pub const DEFAULT_DEADLINE_SECS: u64 = 15;
pub const MAX_DEADLINE_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerFailure {
    AdapterUnavailable,
    InvalidOutput,
    AuthorityChanged,
}

/// The saved case and profile snapshot is published by the app before polling.
pub trait CurrentProbeAuthority: Send + Sync {
    fn validate_current(&self, request: &ProbeRequest) -> Result<()>;
}

#[derive(Default)]
pub struct SnapshotProbeAuthority {
    current: RwLock<(
        HashMap<Uuid, CaseAuthority>,
        Vec<crate::models::ConnectionProfile>,
    )>,
}

struct CaseAuthority {
    revision: u64,
    profile_ids: HashSet<Uuid>,
    scope_digests: HashSet<(super::scope::Digest, super::scope::Digest)>,
}

impl SnapshotProbeAuthority {
    pub fn publish(
        &self,
        cases: &[super::case::HelperCase],
        profiles: &[crate::models::ConnectionProfile],
    ) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *current = (
            cases
                .iter()
                .map(|case| {
                    (
                        case.id(),
                        CaseAuthority {
                            revision: case.revision(),
                            profile_ids: case.profile_ids().iter().copied().collect(),
                            scope_digests: case
                                .scopes()
                                .iter()
                                .filter_map(|scope| {
                                    Some((
                                        scope.digest().ok()?,
                                        scope.credential_scope_digest().ok()?,
                                    ))
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
            profiles.to_vec(),
        );
    }
}

impl CurrentProbeAuthority for SnapshotProbeAuthority {
    fn validate_current(&self, request: &ProbeRequest) -> Result<()> {
        if let BoundScope::WindowsWinRm { identity, .. } = &request.scope {
            ensure!(
                super::scope::current_windows_identity()? == *identity,
                "Windows identity changed since review"
            );
        }
        let current = self
            .current
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        let case = current
            .0
            .get(&request.binding.case_id)
            .ok_or_else(|| anyhow::anyhow!("Case withdrawn"))?;
        ensure!(
            case.revision == request.binding.case_revision,
            "Case changed"
        );
        ensure!(
            case.scope_digests.contains(&(
                request.binding.scope_sha256.clone(),
                request.binding.credential_scope_sha256.clone(),
            )),
            "Scope withdrawn"
        );
        ensure!(
            request.scope.digest()? == request.binding.scope_sha256
                && request.scope.credential_scope_digest()?
                    == request.binding.credential_scope_sha256,
            "Scope changed"
        );
        if let Some(target) = request.scope.target() {
            ensure!(
                case.profile_ids.contains(&target.profile_id)
                    && current.1.iter().any(|profile| target.matches(profile)),
                "Profile changed"
            );
        } else {
            ensure!(
                matches!(
                    request.scope,
                    BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
                ),
                "No profile target"
            );
        }
        Ok(())
    }
}
pub enum WorkerOutcome {
    Complete(Box<EvidenceEnvelope>),
    Canceled,
    TimedOut,
    Failed(WorkerFailure),
}
pub struct WorkerEvent {
    pub request_id: Uuid,
    pub outcome: WorkerOutcome,
}

pub struct HelperWorker {
    runtime: tokio::runtime::Runtime,
    registry: Arc<CapabilityRegistry>,
    secrets: Arc<dyn SecretResolver>,
    authority: Arc<dyn CurrentProbeAuthority>,
    active: HashMap<Uuid, CancellationToken>,
    queued: VecDeque<ProbeRequest>,
    tx: mpsc::Sender<WorkerEvent>,
    rx: mpsc::Receiver<WorkerEvent>,
}

impl HelperWorker {
    pub fn new(
        registry: Arc<CapabilityRegistry>,
        secrets: Arc<dyn SecretResolver>,
        authority: Arc<dyn CurrentProbeAuthority>,
    ) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(MAX_ACTIVE)
            .enable_all()
            .build()?;
        let (tx, rx) = mpsc::channel();
        Ok(Self {
            runtime,
            registry,
            secrets,
            authority,
            active: HashMap::new(),
            queued: VecDeque::new(),
            tx,
            rx,
        })
    }

    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
    pub fn queued_count(&self) -> usize {
        self.queued.len()
    }

    pub fn submit(&mut self, request: ProbeRequest) -> Result<Uuid> {
        self.authority.validate_current(&request)?;
        let id = request.binding.request_id;
        ensure!(
            !id.is_nil()
                && !self.active.contains_key(&id)
                && !self.queued.iter().any(|r| r.binding.request_id == id),
            "Duplicate/invalid request"
        );
        ensure!(
            self.registry
                .descriptor(request.capability_id)
                .is_some_and(|d| d.version == request.capability_version),
            "Capability has no matching executable adapter"
        );
        ensure!(
            request.scope.digest()? == request.binding.scope_sha256
                && request.scope.credential_scope_digest()?
                    == request.binding.credential_scope_sha256,
            "Request scope changed"
        );
        ensure!(
            request.deadline_secs.unwrap_or(DEFAULT_DEADLINE_SECS) > 0
                && request.deadline_secs.unwrap_or(DEFAULT_DEADLINE_SECS) <= MAX_DEADLINE_SECS,
            "Probe deadline outside limit"
        );
        ensure!(
            request.requested_at <= Utc::now() + chrono::Duration::seconds(1)
                && request.requested_at >= Utc::now() - chrono::Duration::seconds(30),
            "Probe request timestamp stale or future"
        );
        if self.active.len() < MAX_ACTIVE {
            self.launch(request);
        } else {
            ensure!(self.queued.len() < MAX_QUEUED, "Probe queue full");
            self.queued.push_back(request);
        }
        Ok(id)
    }

    fn launch(&mut self, request: ProbeRequest) {
        let id = request.binding.request_id;
        if self.authority.validate_current(&request).is_err() {
            let _ = self.tx.send(WorkerEvent {
                request_id: id,
                outcome: WorkerOutcome::Failed(WorkerFailure::AuthorityChanged),
            });
            return;
        }
        let token = CancellationToken::new();
        let adapter = self
            .registry
            .adapter(request.capability_id)
            .expect("registered adapter");
        let secrets = Arc::clone(&self.secrets);
        let authority = Arc::clone(&self.authority);
        let tx = self.tx.clone();
        let job_token = token.clone();
        self.active.insert(id, token);
        self.runtime.spawn(async move {
            let expires_at = request.requested_at
                + chrono::Duration::seconds(request.deadline_secs.unwrap_or(DEFAULT_DEADLINE_SECS) as i64);
            let remaining_ms = expires_at.signed_duration_since(Utc::now()).num_milliseconds();
            let run = async {
            authority.validate_current(&request)
                .map_err(|_| WorkerFailure::AuthorityChanged)?;
            if let Some(scope) = request.scope.credential() {
                let _secret = secrets.resolve(scope, scope.purpose)
                    .map_err(|_| WorkerFailure::AdapterUnavailable)?;
            }
            authority.validate_current(&request)
                .map_err(|_| WorkerFailure::AuthorityChanged)?;
            adapter.collect(&request, secrets.as_ref(), job_token.clone()).await
                .map_err(|_| WorkerFailure::AdapterUnavailable)
        };
        tokio::pin!(run);
        let outcome = if remaining_ms <= 0 {
            WorkerOutcome::TimedOut
        } else {
            let deadline = tokio::time::sleep(Duration::from_millis(remaining_ms as u64));
            tokio::pin!(deadline);
            tokio::select! {
                biased;
                _ = job_token.cancelled() => {
                    if request.capability_id == CapabilityId::SqlRead {
                        let _ = tokio::time::timeout(Duration::from_millis(1300), &mut run).await;
                    }
                    WorkerOutcome::Canceled
                }
                _ = &mut deadline => {
                    job_token.cancel();
                    if request.capability_id == CapabilityId::SqlRead {
                        let _ = tokio::time::timeout(Duration::from_millis(1300), &mut run).await;
                    }
                    WorkerOutcome::TimedOut
                }
                result = &mut run => match result {
                    Err(failure) => WorkerOutcome::Failed(failure),
                    Ok(output) => normalize(&request, output)
                        .map(Box::new)
                        .map(WorkerOutcome::Complete)
                        .unwrap_or(WorkerOutcome::Failed(WorkerFailure::InvalidOutput)),
                },
            }
        };
        let _ = tx.send(WorkerEvent {
                request_id: id,
                outcome,
            });
        });
    }

    pub fn cancel(&mut self, id: Uuid) -> bool {
        if let Some(token) = self.active.get(&id) {
            token.cancel();
            return true;
        }
        if let Some(position) = self.queued.iter().position(|r| r.binding.request_id == id) {
            self.queued.remove(position);
            let _ = self.tx.send(WorkerEvent {
                request_id: id,
                outcome: WorkerOutcome::Canceled,
            });
            return true;
        }
        false
    }

    pub fn poll(&mut self) -> Vec<WorkerEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            let was_active = self.active.remove(&event.request_id).is_some();
            events.push(event);
            if was_active {
                while self.active.len() < MAX_ACTIVE {
                    let Some(next) = self.queued.pop_front() else {
                        break;
                    };
                    self.launch(next);
                }
            }
        }
        events
    }
}

fn normalize(request: &ProbeRequest, output: ProbeOutput) -> Result<EvidenceEnvelope> {
    ensure!(
        output.source_id.len() <= 4096 && !output.source_id.is_empty() && output.parser_version > 0,
        "Invalid source metadata"
    );
    ensure!(
        output.records.len() <= evidence::MAX_RECORDS
            && output.metrics.len() <= evidence::MAX_METRICS
            && output.evidence_refs.len() <= evidence::MAX_EVIDENCE_REFS,
        "Probe output capacity reached"
    );
    ensure!(
        output.sql_observations.len() <= super::sql::types::MAX_SQL_OBSERVATIONS
            && output
                .sql_observations
                .iter()
                .all(super::sql::types::SqlObservation::bounded),
        "SQL observation capacity reached"
    );
    let content = if output.sql_observations.is_empty() {
        serde_json::to_vec(&(&output.records, &output.metrics, &output.evidence_refs))?
    } else {
        serde_json::to_vec(&(
            &output.records,
            &output.metrics,
            &output.evidence_refs,
            &output.sql_observations,
        ))?
    };
    ensure!(
        content.len() <= evidence::MAX_ENVELOPE_BYTES,
        "Probe output capacity reached"
    );
    let mut hash = Sha256::new();
    hash.update(b"relayne-probe-content-v1\0");
    hash.update(&content);
    let envelope = EvidenceEnvelope {
        schema: evidence::EVIDENCE_SCHEMA,
        id: Uuid::new_v4(),
        binding: request.binding.clone(),
        capability_id: request.capability_id,
        capability_version: request.capability_version,
        parser_version: output.parser_version,
        origin: Origin::Live,
        source_id: evidence::source_id_digest(&output.source_id),
        source_observed_at: output.source_observed_at,
        retrieved_at: Utc::now(),
        time_quality: TimeQuality::Trusted,
        status: output.status,
        coverage: output.coverage,
        content_sha256: format!("{:x}", hash.finalize()),
        records: output.records,
        metrics: output.metrics,
        sql_observations: output.sql_observations,
        evidence_refs: output.evidence_refs,
    };
    envelope.validate_shape()?;
    Ok(envelope)
}

/// The first executable probes use the reviewed endpoint only. Later adapters register separately.
pub fn built_in_registry() -> Result<CapabilityRegistry> {
    let mut registry = CapabilityRegistry::new();
    for descriptor in super::manifest::CapabilityManifest::built_in().declarations {
        match descriptor.id {
            CapabilityId::NetworkReachability => {
                registry.register(descriptor, Arc::new(TcpProbe))?
            }
            CapabilityId::HttpHealth => registry.register(descriptor, Arc::new(HttpProbe))?,
            CapabilityId::SqlRead => {
                registry.register(descriptor, Arc::new(super::sql::SqlReadAdapter))?
            }
            CapabilityId::AzureVmIdentity | CapabilityId::AzureVmResourceHealth => {
                registry.register(descriptor, Arc::new(super::cloud::AzureVmAdapter))?
            }
            CapabilityId::AwsEc2Inventory | CapabilityId::AwsEc2Status => {
                registry.register(descriptor, Arc::new(super::cloud::AwsEc2Adapter))?
            }
            CapabilityId::NetworkDns | CapabilityId::NetworkTls => {
                registry.register(descriptor, Arc::new(super::adapters::NetworkAdapter))?
            }
            CapabilityId::SystemResources | CapabilityId::ServiceStatus => {
                registry.register(descriptor, Arc::new(super::adapters::SystemAdapter))?
            }
            _ => {}
        }
    }
    Ok(registry)
}

struct TcpProbe;
impl ProbeAdapter for TcpProbe {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> super::capability::ProbeFuture<'a> {
        Box::pin(async move {
            let ProbeParams::Network { port } = &request.params else {
                anyhow::bail!("Invalid network parameters")
            };
            let host = request
                .scope
                .target()
                .ok_or_else(|| anyhow::anyhow!("Unsupported network scope"))?
                .host
                .clone();
            let start = Utc::now();
            let now = std::time::Instant::now();
            let connected = tokio::select! {
                _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                result = tokio::net::TcpStream::connect((host.as_str(), *port)) => result.is_ok(),
            };
            let end = Utc::now();
            let digest = request.scope.resource_digest()?;
            Ok(ProbeOutput {
                status: if connected {
                    EvidenceStatus::Complete
                } else {
                    EvidenceStatus::Unavailable
                },
                coverage: Coverage {
                    observed: 1,
                    expected: 1,
                    truncated: false,
                },
                records: vec![NormalizedRecord {
                    kind: RecordKind::Network,
                    observation: if connected {
                        Observation::Healthy
                    } else {
                        Observation::Unavailable
                    },
                    subject_sha256: digest,
                    detail: None,
                }],
                metrics: vec![NormalizedMetric {
                    kind: MetricKind::LatencyMs,
                    value: connected.then_some(now.elapsed().as_secs_f64() * 1000.0),
                    unit: MetricUnit::Milliseconds,
                    source_counter: MetricSourceCounter::NetworkRoundTrip,
                    sample_window: SampleWindow {
                        started_at: start,
                        ended_at: end,
                    },
                    missing_reason: (!connected).then_some(evidence::MissingReason::Unavailable),
                }],
                sql_observations: Vec::new(),
                evidence_refs: Vec::new(),
                source_id: format!("tcp:{host}:{port}").into_bytes(),
                source_observed_at: end,
                parser_version: 1,
            })
        })
    }
}

struct HttpProbe;
impl ProbeAdapter for HttpProbe {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> super::capability::ProbeFuture<'a> {
        Box::pin(async move {
            let (expected_status, body_sha256) = match &request.params {
                ProbeParams::Http => (None, None),
                ProbeParams::HttpAssert {
                    expected_status,
                    body_sha256,
                } => (Some(*expected_status), body_sha256.as_deref()),
                _ => anyhow::bail!("Invalid HTTP parameters"),
            };
            let BoundScope::Http {
                target,
                port,
                tls,
                path,
            } = &request.scope
            else {
                anyhow::bail!("Unsupported HTTP scope");
            };
            anyhow::ensure!(
                target.route.is_empty(),
                "HTTP probe requires a direct route"
            );
            let url = crate::helper::scope::reviewed_http_url(target, *port, *tls, path)?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()?;
            let response = tokio::select! {
                _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                response = client.get(url.clone()).send() => response?,
            };
            let actual_status = response.status();
            let mut response = response;
            let mut consumed = 0usize;
            let mut body_hash = Sha256::new();
            loop {
                let chunk = tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                    chunk = response.chunk() => chunk?,
                };
                let Some(chunk) = chunk else { break };
                consumed = consumed
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow::anyhow!("Body limit"))?;
                ensure!(consumed <= 64 * 1024, "HTTP response exceeds limit");
                body_hash.update(&chunk);
            }
            let healthy = expected_status.map_or(actual_status.is_success(), |code| {
                actual_status.as_u16() == code
            }) && body_sha256.is_none_or(|hash| {
                format!("{:x}", body_hash.finalize()).eq_ignore_ascii_case(hash)
            });
            let end = Utc::now();
            Ok(ProbeOutput {
                status: EvidenceStatus::Complete,
                coverage: Coverage {
                    observed: 1,
                    expected: 1,
                    truncated: false,
                },
                records: vec![NormalizedRecord {
                    kind: RecordKind::Network,
                    observation: if healthy {
                        Observation::Healthy
                    } else {
                        Observation::Degraded
                    },
                    subject_sha256: request.scope.resource_digest()?,
                    detail: None,
                }],
                metrics: Vec::new(),
                sql_observations: Vec::new(),
                evidence_refs: Vec::new(),
                source_id: url.as_str().as_bytes().to_vec(),
                source_observed_at: end,
                parser_version: 1,
            })
        })
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
