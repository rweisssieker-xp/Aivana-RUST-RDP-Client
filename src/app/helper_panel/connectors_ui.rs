//! Deliberate collection control; case selection and plan preview never dispatch a probe.
use super::HelperState;
use crate::{
    helper::{
        capability::ProbeRequest,
        credentials::{PersistentSecretResolver, SecretResolver},
        evidence::{EvidenceBinding, EvidenceEnvelope, EvidenceStatus, Origin},
        manifest::{CapabilityId, ProbeParams},
        scope::{BoundScope, CredentialPurpose},
        worker::{self, WorkerOutcome},
    },
    models::ConnectionProfile,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use eframe::egui;
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

#[derive(Default)]
pub(super) struct SystemInputs {
    mount: String,
    interface: String,
    service: String,
    http_status: String,
    http_body_sha256: String,
}

pub(super) struct CaptureJob {
    case_id: Uuid,
    scope_digest: String,
    capability_id: CapabilityId,
}

fn current_profile_matches(scope: &BoundScope, profiles: &[ConnectionProfile]) -> bool {
    if matches!(
        scope,
        BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
    ) {
        return true;
    }
    if let Some(target) = scope.target() {
        profiles.iter().any(|profile| target.matches(profile))
            && match scope {
                BoundScope::WindowsWinRm { identity, .. } => {
                    crate::helper::scope::current_windows_identity()
                        .is_ok_and(|current| current == *identity)
                }
                _ => true,
            }
    } else {
        matches!(
            scope,
            BoundScope::Docker { .. } | BoundScope::Kubernetes { .. }
        ) && scope.validate().is_ok()
    }
}

fn supported(scope: &BoundScope) -> Option<(CapabilityId, ProbeParams)> {
    match scope {
        BoundScope::Http { .. } => Some((CapabilityId::HttpHealth, ProbeParams::Http)),
        BoundScope::WindowsWinRm { .. }
        | BoundScope::Linux {
            credential: None, ..
        } => Some((CapabilityId::SystemResources, ProbeParams::System)),
        BoundScope::Windows { target, .. } => Some((
            CapabilityId::NetworkReachability,
            ProbeParams::Network { port: target.port },
        )),
        BoundScope::Database {
            engine: crate::helper::scope::DatabaseEngine::Postgres,
            ..
        } => Some((
            CapabilityId::SqlRead,
            ProbeParams::SqlRead {
                query_digest: crate::helper::sql::postgres::template_digest(),
            },
        )),
        BoundScope::Database {
            engine: crate::helper::scope::DatabaseEngine::SqlServer,
            ..
        } => Some((
            CapabilityId::SqlRead,
            ProbeParams::SqlRead {
                query_digest: crate::helper::sql::sql_server::template_digest(),
            },
        )),
        BoundScope::AzureVm {
            credential: Some(_),
            ..
        } => Some((
            CapabilityId::AzureVmResourceHealth,
            ProbeParams::CloudInstance,
        )),
        BoundScope::AwsEc2 {
            credential: Some(_),
            ..
        } => Some((CapabilityId::AwsEc2Status, ProbeParams::CloudInstance)),
        BoundScope::Docker { .. } => Some((
            CapabilityId::DockerContainerInspect,
            ProbeParams::DockerInspect,
        )),
        BoundScope::Kubernetes { .. } => Some((
            CapabilityId::KubernetesWorkloadStatus,
            ProbeParams::KubernetesStatus,
        )),
        _ => None,
    }
}

fn displayed_capabilities(scope: &BoundScope) -> &'static [CapabilityId] {
    match scope {
        BoundScope::WindowsWinRm { .. } | BoundScope::Linux { .. } => {
            &[CapabilityId::SystemResources, CapabilityId::ServiceStatus]
        }
        BoundScope::Http { tls: true, .. } => &[
            CapabilityId::NetworkDns,
            CapabilityId::NetworkTls,
            CapabilityId::HttpHealth,
        ],
        BoundScope::Http { .. } => &[CapabilityId::NetworkDns, CapabilityId::HttpHealth],
        BoundScope::Database { .. } => &[CapabilityId::SqlRead],
        BoundScope::AzureVm { .. } => &[CapabilityId::AzureVmResourceHealth],
        BoundScope::AwsEc2 { .. } => &[CapabilityId::AwsEc2Status],
        BoundScope::Docker { .. } => &[
            CapabilityId::DockerContainerInspect,
            CapabilityId::DockerContainerStats,
        ],
        BoundScope::Kubernetes { .. } => &[
            CapabilityId::KubernetesWorkloadStatus,
            CapabilityId::KubernetesEvents,
        ],
        _ => &[CapabilityId::NetworkReachability],
    }
}

fn capture_status_line(
    scope_digest: &str,
    capability: CapabilityId,
    evidence: &[EvidenceEnvelope],
    last_capture: &HashMap<(String, CapabilityId), String>,
) -> String {
    let live = evidence.iter().rev().find(|item| {
        item.binding.scope_sha256 == scope_digest
            && item.capability_id == capability
            && item.origin == Origin::Live
    });
    let last = last_capture.get(&(scope_digest.to_owned(), capability));
    format!(
        "{:?}: {} · last attempt: {}",
        capability,
        live.map(|item| format!(
            "live {:?} ({}/{})",
            item.status, item.coverage.observed, item.coverage.expected
        ))
        .unwrap_or_else(|| "no live evidence; fixture is not live".into()),
        last.map(String::as_str).unwrap_or("none")
    )
}

pub(super) fn cloud_credential_ready(
    scope: &BoundScope,
    resolver: Option<&dyn SecretResolver>,
) -> bool {
    if !matches!(
        scope,
        BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
    ) {
        return true;
    }
    scope.credential().is_some_and(|credential| {
        credential.purpose == CredentialPurpose::Read
            && resolver.is_some_and(|resolver| {
                resolver
                    .resolve(credential, CredentialPurpose::Read)
                    .is_ok()
            })
    })
}

pub(super) fn collect_enabled(
    scope: &BoundScope,
    profiles: &[ConnectionProfile],
    resolver: Option<&dyn SecretResolver>,
) -> bool {
    supported(scope).is_some()
        && current_profile_matches(scope, profiles)
        && cloud_credential_ready(scope, resolver)
}

fn remote_status(status: EvidenceStatus, observed: bool) -> (&'static str, bool) {
    match status {
        EvidenceStatus::Complete | EvidenceStatus::Partial if observed => (
            "last live read succeeded; remote read permission observed for that capture",
            true,
        ),
        EvidenceStatus::Complete | EvidenceStatus::Partial => (
            "last live read returned no usable observation; permission unknown",
            false,
        ),
        EvidenceStatus::Denied => ("last live read denied", false),
        EvidenceStatus::Unavailable => ("last live read unavailable; permission unknown", false),
        EvidenceStatus::Truncated => (
            "last live read exceeded output limit; permission unknown",
            false,
        ),
        EvidenceStatus::Canceled => ("last live read canceled; permission unknown", false),
        EvidenceStatus::Failed => ("last live read failed; permission unknown", false),
    }
}

fn remote_readiness(
    state: &HelperState,
    case: &crate::helper::case::HelperCase,
    scope: &BoundScope,
) -> (&'static str, bool) {
    let Ok(digest) = scope.digest() else {
        return ("scope invalid; permission unknown", false);
    };
    if let Some(attempt) = state.collect_attempts.get(&(case.id(), digest.clone())) {
        return *attempt;
    }
    case.evidence()
        .iter()
        .filter(|item| item.origin == Origin::Live && item.binding.scope_sha256 == digest)
        .filter(|item| {
            matches!(
                item.capability_id,
                CapabilityId::DockerContainerInspect
                    | CapabilityId::DockerContainerStats
                    | CapabilityId::KubernetesWorkloadStatus
                    | CapabilityId::KubernetesEvents
            )
        })
        .max_by_key(|item| item.retrieved_at)
        .map(|item| remote_status(item.status, !item.records.is_empty()))
        .unwrap_or(("unknown; no current-scope live read yet", false))
}

pub(super) fn show(
    state: &mut HelperState,
    ui: &mut egui::Ui,
    case: &crate::helper::case::HelperCase,
    profiles: &[ConnectionProfile],
) {
    ui.separator();
    ui.heading("Collect live evidence");
    let credential_resolver = PersistentSecretResolver::new().ok();
    ui.small("Cloud checks use the reviewed credential and verify provider identity for the exact resource. Missing tools, access or status never imply live readiness; fixture tests only verify parser behavior.");
    ui.label(
        "Collection uses a registered read probe on the reviewed endpoint. AI consent is separate.",
    );
    ui.label("Container reads bind a reviewed endpoint and current identity before selecting a resource. Kubernetes uses the scoped vault token; Docker uses the current Windows process token on a local named pipe.");
    if let Some(worker) = state.worker.as_ref() {
        ui.label(format!(
            "Captures: {} running, {} queued",
            worker.active_count(),
            worker.queued_count()
        ));
    }
    for (index, scope) in case.scopes().iter().enumerate() {
        let profile_current = current_profile_matches(scope, profiles);
        let credential_ready = cloud_credential_ready(
            scope,
            credential_resolver
                .as_ref()
                .map(|resolver| resolver as &dyn SecretResolver),
        );
        let (tool_ready, tool_status) = if matches!(
            scope,
            BoundScope::WindowsWinRm { .. } | BoundScope::Linux { .. }
        ) {
            crate::helper::process::system_collector_readiness(scope)
        } else {
            (
                true,
                "Local client available; remote access checked on capture",
            )
        };
        let name = match scope {
            BoundScope::Http { .. } => "HTTP health",
            BoundScope::Database {
                engine: crate::helper::scope::DatabaseEngine::Postgres,
                ..
            } => "PostgreSQL read diagnostics",
            BoundScope::Database {
                engine: crate::helper::scope::DatabaseEngine::SqlServer,
                ..
            } => "SQL Server read diagnostics",
            BoundScope::Windows { .. } => "Host TCP reachability",
            BoundScope::AzureVm { .. } => "Azure VM resource health (live ARM read)",
            BoundScope::AwsEc2 { .. } => "AWS EC2 status (live scoped read)",
            BoundScope::WindowsWinRm { .. } => "Windows WinRM resources",
            BoundScope::Linux {
                credential: None, ..
            } => "Linux SSH resources",
            BoundScope::Linux { .. } => {
                "Linux SSH requires a current-identity scope without saved credential"
            }
            BoundScope::Docker { .. } => {
                "Docker selected container inspect / single stats snapshot"
            }
            BoundScope::Kubernetes { .. } => {
                "Kubernetes selected workload status / UID-filtered events"
            }
            _ => "No executable adapter in this wave",
        };
        let container_readiness = if matches!(
            scope,
            BoundScope::Docker { .. } | BoundScope::Kubernetes { .. }
        ) {
            Some(crate::helper::adapters::containers::local_readiness(scope))
        } else {
            None
        };
        if let Some(readiness) = container_readiness.as_ref() {
            ui.small(match scope {
                BoundScope::Docker { daemon_context, container_id, .. } =>
                    format!("Docker context: {daemon_context}; selected container: {container_id}; native local pipe. {}", readiness.label),
                BoundScope::Kubernetes { context, namespace, resource_kind, resource_name, .. } =>
                    format!("Kubernetes context: {context}; namespace: {namespace}; selected {resource_kind}: {resource_name}; native HTTPS. {}", readiness.label),
                _ => unreachable!(),
            });
            let (remote, succeeded_live) = if profile_current {
                remote_readiness(state, case, scope)
            } else {
                ("reviewed profile changed; permission unknown", false)
            };
            ui.small(format!("Prerequisites: reviewed scope, current scoped read credential, target identity and remote read permission. Remote permission: {remote}."));
            ui.small(if succeeded_live {
                "Transport: fixture verified; successful live read observed for this reviewed scope."
            } else {
                "Transport: fixture verified; successful live interoperability not yet verified."
            });
        } else if supported(scope).is_none() {
            ui.small("Unsupported: no executable read adapter for this scope.");
        }
        let local_ready = container_readiness
            .as_ref()
            .is_none_or(|status| status.ready);
        ui.horizontal(|ui| {
            ui.label(format!("Scope {}: {name}", index + 1));
            if !profile_current {
                ui.label("Current profile or reviewed identity differs or is missing");
            }
            if scope.credential().is_some() {
                ui.label("Credential rechecked at dispatch");
            }
            if !credential_ready {
                ui.label("Protected cloud credential missing, revoked or mismatched");
            }
            if ui
                .add_enabled(
                    collect_enabled(
                        scope,
                        profiles,
                        credential_resolver
                            .as_ref()
                            .map(|resolver| resolver as &dyn SecretResolver),
                    ) && tool_ready
                        && supported(scope).is_some()
                        && local_ready
                        && (scope.credential().is_some()
                            || !matches!(
                                scope,
                                BoundScope::Docker { .. } | BoundScope::Kubernetes { .. }
                            )),
                    egui::Button::new("Collect"),
                )
                .clicked()
            {
                state.collect(case.id(), index, profiles);
            }
            let (second, second_label) = match scope {
                BoundScope::Docker { .. } => (
                    Some((CapabilityId::DockerContainerStats, ProbeParams::DockerStats)),
                    "Collect one stats snapshot",
                ),
                BoundScope::Kubernetes { .. } => (
                    Some((
                        CapabilityId::KubernetesEvents,
                        ProbeParams::KubernetesEvents,
                    )),
                    "Collect related events",
                ),
                _ => (None, "Collect related events"),
            };
            if ui
                .add_enabled(
                    second.is_some()
                        && local_ready
                        && profile_current
                        && scope.credential().is_some(),
                    egui::Button::new(second_label),
                )
                .clicked()
            {
                if let Some((capability, params)) = second {
                    state.collect_with(case.id(), index, profiles, capability, params);
                }
            }
        });
        ui.label(format!(
            "Local tool/auth: {tool_status}; remote permission: unknown until live capture"
        ));
        if let Ok(digest) = scope.digest() {
            for capability in displayed_capabilities(scope) {
                ui.label(capture_status_line(
                    &digest,
                    *capability,
                    case.evidence(),
                    &state.last_capture,
                ));
            }
        }
        if matches!(
            scope,
            BoundScope::WindowsWinRm { .. }
                | BoundScope::Linux {
                    credential: None,
                    ..
                }
        ) {
            ui.label("Supported: two-sample CPU/interface rates, memory/commit, selected disk, bounded process resources, OS/uptime/load, service dependencies, transport counters, and Windows event metadata. Missing fields remain unknown.");
            ui.label("WinRM uses the current Windows identity; SSH uses current-account keys and known_hosts. Saved passwords are not sent.");
            if matches!(scope, BoundScope::Linux { .. }) {
                ui.label("Unsupported on Linux: Windows System event count and metadata. Missing permissions and tools show unknown live coverage.");
            }
            ui.horizontal(|ui| {
                ui.label("Mount/volume");
                ui.text_edit_singleline(&mut state.system_inputs.mount);
                ui.label("Interface");
                ui.text_edit_singleline(&mut state.system_inputs.interface);
            });
            ui.horizontal(|ui| {
                ui.label("Service");
                ui.text_edit_singleline(&mut state.system_inputs.service);
                if ui
                    .add_enabled(
                        profile_current && tool_ready,
                        egui::Button::new("Collect selected system metrics"),
                    )
                    .clicked()
                {
                    let mount = (!state.system_inputs.mount.is_empty())
                        .then(|| state.system_inputs.mount.clone());
                    let interface = (!state.system_inputs.interface.is_empty())
                        .then(|| state.system_inputs.interface.clone());
                    state.collect_with(
                        case.id(),
                        index,
                        profiles,
                        CapabilityId::SystemResources,
                        ProbeParams::SystemSelected { mount, interface },
                    );
                }
                if ui
                    .add_enabled(
                        profile_current && tool_ready && !state.system_inputs.service.is_empty(),
                        egui::Button::new("Check service"),
                    )
                    .clicked()
                {
                    let name = state.system_inputs.service.clone();
                    state.collect_with(
                        case.id(),
                        index,
                        profiles,
                        CapabilityId::ServiceStatus,
                        ProbeParams::ServiceName { name },
                    );
                }
            });
        }
        if let BoundScope::Http { tls, .. } = scope {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        profile_current,
                        egui::Button::new("Resolve DNS from Relayne"),
                    )
                    .clicked()
                {
                    state.collect_with(
                        case.id(),
                        index,
                        profiles,
                        CapabilityId::NetworkDns,
                        ProbeParams::Dns,
                    );
                }
                if ui
                    .add_enabled(
                        profile_current && *tls,
                        egui::Button::new("Check TLS from Relayne"),
                    )
                    .clicked()
                {
                    state.collect_with(
                        case.id(),
                        index,
                        profiles,
                        CapabilityId::NetworkTls,
                        ProbeParams::Tls,
                    );
                }
            });
            ui.horizontal(|ui| {
                ui.label("Expected HTTP status");
                ui.text_edit_singleline(&mut state.system_inputs.http_status);
                ui.label("Expected body SHA-256 (optional)");
                ui.text_edit_singleline(&mut state.system_inputs.http_body_sha256);
                if ui
                    .add_enabled(
                        profile_current && !state.system_inputs.http_status.is_empty(),
                        egui::Button::new("Check HTTP assertion"),
                    )
                    .clicked()
                {
                    if let Ok(expected_status) = state.system_inputs.http_status.parse() {
                        let body_sha256 = (!state.system_inputs.http_body_sha256.is_empty())
                            .then(|| state.system_inputs.http_body_sha256.clone());
                        state.collect_with(
                            case.id(),
                            index,
                            profiles,
                            CapabilityId::HttpHealth,
                            ProbeParams::HttpAssert {
                                expected_status,
                                body_sha256,
                            },
                        );
                    } else {
                        state.notice = "HTTP status must be 100..599".into();
                    }
                }
            });
        }
    }
    let jobs: Vec<_> = state
        .collect_jobs
        .iter()
        .filter(|(_, job)| job.case_id == case.id())
        .map(|(request_id, _)| *request_id)
        .collect();
    for request_id in jobs {
        ui.horizontal(|ui| {
            ui.label(format!("Capture {request_id}"));
            if ui.button("Cancel capture").clicked()
                && let Some(worker) = state.worker.as_mut()
            {
                worker.cancel(request_id);
            }
        });
    }
}

impl HelperState {
    fn collect_with(
        &mut self,
        case_id: Uuid,
        index: usize,
        profiles: &[ConnectionProfile],
        capability_id: CapabilityId,
        params: ProbeParams,
    ) {
        self.notice = match self.try_collect_with(case_id, index, profiles, capability_id, params) {
            Ok(id) => format!("Capture {id} accepted"),
            Err(_) => {
                "Capture unavailable: review exact scope, selectors, permissions and storage".into()
            }
        };
    }
    fn collect(&mut self, case_id: Uuid, index: usize, profiles: &[ConnectionProfile]) {
        self.notice = match self.try_collect(case_id, index, profiles) {
            Ok(id) => format!("Capture {id} accepted"),
            Err(_) => {
                "Capture unavailable: review capability, endpoint, credential and storage status"
                    .into()
            }
        };
    }

    fn try_collect(
        &mut self,
        case_id: Uuid,
        index: usize,
        profiles: &[ConnectionProfile],
    ) -> Result<Uuid> {
        let scope = self
            .store
            .as_ref()
            .and_then(|store| store.case(case_id))
            .and_then(|case| case.scopes().get(index))
            .ok_or_else(|| anyhow::anyhow!("Scope missing"))?;
        let (capability_id, params) =
            supported(scope).ok_or_else(|| anyhow::anyhow!("No executable adapter"))?;
        self.try_collect_with(case_id, index, profiles, capability_id, params)
    }

    fn try_collect_with(
        &mut self,
        case_id: Uuid,
        index: usize,
        profiles: &[ConnectionProfile],
        capability_id: CapabilityId,
        params: ProbeParams,
    ) -> Result<Uuid> {
        let case = self
            .store
            .as_ref()
            .and_then(|store| store.case(case_id))
            .ok_or_else(|| anyhow::anyhow!("Case unavailable"))?
            .clone();
        let scope = case
            .scopes()
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("Scope missing"))?
            .clone();
        if matches!(
            scope,
            BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
        ) {
            ensure!(
                cloud_credential_ready(&scope, Some(&PersistentSecretResolver::new()?)),
                "Protected cloud credential unavailable"
            );
        }
        ensure!(
            current_profile_matches(&scope, profiles),
            "Saved endpoint changed"
        );
        if matches!(
            scope,
            BoundScope::Docker { .. } | BoundScope::Kubernetes { .. }
        ) {
            ensure!(
                supported(&scope) == Some((capability_id, params.clone()))
                    || matches!(
                        (&scope, capability_id, &params),
                        (
                            BoundScope::Docker { .. },
                            CapabilityId::DockerContainerStats,
                            ProbeParams::DockerStats
                        ) | (
                            BoundScope::Kubernetes { .. },
                            CapabilityId::KubernetesEvents,
                            ProbeParams::KubernetesEvents
                        )
                    ),
                "Container operation differs from reviewed scope"
            );
            crate::helper::adapters::containers::validate_scoped_operation(&scope, capability_id)?;
        }
        self.authority.publish(
            self.store
                .as_ref()
                .map(|store| store.cases())
                .unwrap_or(&[]),
            profiles,
        );
        if self.worker.is_none() {
            self.worker = Some(worker::HelperWorker::new(
                Arc::new(worker::built_in_registry()?),
                Arc::new(PersistentSecretResolver::new()?),
                self.authority.clone(),
            )?);
        }
        let id = Uuid::new_v4();
        let binding = EvidenceBinding {
            case_id,
            case_revision: case.revision(),
            request_id: id,
            scope_sha256: scope.digest()?,
            credential_scope_sha256: scope.credential_scope_digest()?,
            run_id: None,
        };
        let mut request = ProbeRequest {
            binding,
            scope,
            capability_id,
            capability_version: 1,
            params,
            requested_at: Utc::now(),
            deadline_secs: None,
        };
        let worker = self.worker.as_mut().expect("created worker");
        worker.registry().validate_request(&case, &request)?;
        let store = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Store unavailable"))?;
        request.binding = store.register_accepted_capture(worker.registry(), &request)?;
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Store path unavailable"))?;
        if store.save(path).is_err() {
            store.cancel_pending_capture(id)?;
            anyhow::bail!("Capture intent could not be persisted");
        }
        let job = CaptureJob {
            case_id,
            scope_digest: request.binding.scope_sha256.clone(),
            capability_id,
        };
        if let Err(error) = worker.submit(request) {
            store.cancel_pending_capture(id)?;
            let _ = store.save(path);
            return Err(error);
        }
        self.collect_attempts.insert(
            (case_id, job.scope_digest.clone()),
            ("capture pending; permission unknown", false),
        );
        self.collect_jobs.insert(id, job);
        Ok(id)
    }

    pub(super) fn poll_collect(&mut self, profiles: &[ConnectionProfile]) {
        self.authority.publish(
            self.store
                .as_ref()
                .map(|store| store.cases())
                .unwrap_or(&[]),
            profiles,
        );
        let events = self
            .worker
            .as_mut()
            .map(worker::HelperWorker::poll)
            .unwrap_or_default();
        for event in events {
            let Some(job) = self.collect_jobs.remove(&event.request_id) else {
                continue;
            };
            let case_id = job.case_id;
            let scope_digest = job.scope_digest.clone();
            let Some(store) = self.store.as_mut() else {
                continue;
            };
            let mut readiness = ("last capture failed; permission unknown", false);
            let status = match event.outcome {
                WorkerOutcome::Complete(envelope) => {
                    let evidence_status = envelope.status;
                    let observed = !envelope.records.is_empty();
                    let current = store.case(case_id).and_then(|case| {
                        case.scopes().iter().find(|scope| {
                            scope.digest().ok().as_deref() == Some(&envelope.binding.scope_sha256)
                        })
                    });
                    if current.is_some_and(|scope| current_profile_matches(scope, profiles))
                        && store.attach_evidence(case_id, *envelope).is_ok()
                    {
                        readiness = remote_status(evidence_status, observed);
                        "Capture attached"
                    } else {
                        let _ = store.cancel_pending_capture(event.request_id);
                        "Capture discarded: case, scope or endpoint changed"
                    }
                }
                WorkerOutcome::Canceled => {
                    readiness = ("last capture canceled; permission unknown", false);
                    let _ = store.cancel_pending_capture(event.request_id);
                    "Capture canceled"
                }
                WorkerOutcome::TimedOut => {
                    readiness = ("last capture timed out; permission unknown", false);
                    let _ = store.cancel_pending_capture(event.request_id);
                    "Capture timed out"
                }
                WorkerOutcome::Failed(failure) => {
                    readiness = ("last capture failed; permission unknown", false);
                    let _ = store.cancel_pending_capture(event.request_id);
                    match failure {
                        worker::WorkerFailure::AdapterUnavailable => {
                            "Capture unavailable or access denied"
                        }
                        worker::WorkerFailure::InvalidOutput => {
                            "Capture output invalid or over limit"
                        }
                        worker::WorkerFailure::AuthorityChanged => {
                            "Capture case, scope or saved profile changed"
                        }
                    }
                }
            };
            self.last_capture
                .insert((job.scope_digest, job.capability_id), status.to_owned());
            self.notice = if let Some(path) = self.path.as_ref() {
                if store.save(path).is_ok() {
                    status.into()
                } else {
                    readiness = ("last capture could not be saved; permission unknown", false);
                    "Capture state could not be saved".into()
                }
            } else {
                readiness = ("last capture store unavailable; permission unknown", false);
                "Capture store unavailable".into()
            };
            self.collect_attempts
                .insert((case_id, scope_digest), readiness);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        helper::{
            case::{CaseEdit, ProblemIntake},
            evidence::{Coverage, EVIDENCE_SCHEMA, EvidenceStatus, TimeQuality},
            store::HelperStore,
        },
        mission::Target,
    };
    use std::{net::TcpListener, time::Duration};

    #[test]
    fn sql_and_cloud_status_rows_use_the_collected_capability_and_attempt() {
        let profile = ConnectionProfile::sample("db", "db.example", "Default", false);
        let target = Target::from_profile(&profile);
        let tenant = Uuid::new_v4().to_string();
        let subscription = Uuid::new_v4().to_string();
        let scopes = [
            (
                BoundScope::Database {
                    target: target.clone(),
                    engine: crate::helper::scope::DatabaseEngine::Postgres,
                    port: 5432,
                    database: "app".into(),
                    schema: None,
                    object: None,
                    credential: None,
                },
                CapabilityId::SqlRead,
            ),
            (
                BoundScope::Database {
                    target,
                    engine: crate::helper::scope::DatabaseEngine::SqlServer,
                    port: 1433,
                    database: "app".into(),
                    schema: None,
                    object: None,
                    credential: None,
                },
                CapabilityId::SqlRead,
            ),
            (
                BoundScope::AzureVm {
                    tenant,
                    subscription: subscription.clone(),
                    resource_id: format!(
                        "/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
                    ),
                    credential: None,
                },
                CapabilityId::AzureVmResourceHealth,
            ),
            (
                BoundScope::AwsEc2 {
                    account: "123456789012".into(),
                    region: "eu-central-1".into(),
                    instance_id: "i-0123456789abcdef0".into(),
                    credential: None,
                },
                CapabilityId::AwsEc2Status,
            ),
        ];
        for (scope, capability) in scopes {
            assert_eq!(displayed_capabilities(&scope), &[capability]);
            let digest = scope.digest().unwrap();
            let now = Utc::now();
            let envelope = EvidenceEnvelope {
                schema: EVIDENCE_SCHEMA,
                id: Uuid::new_v4(),
                binding: EvidenceBinding {
                    case_id: Uuid::new_v4(),
                    case_revision: 1,
                    request_id: Uuid::new_v4(),
                    scope_sha256: digest.clone(),
                    credential_scope_sha256: "a".repeat(64),
                    run_id: None,
                },
                capability_id: capability,
                capability_version: 1,
                parser_version: 1,
                origin: Origin::Live,
                source_id: "b".repeat(64),
                source_observed_at: now,
                retrieved_at: now,
                time_quality: TimeQuality::Trusted,
                status: EvidenceStatus::Complete,
                coverage: Coverage {
                    observed: 1,
                    expected: 1,
                    truncated: false,
                },
                content_sha256: "c".repeat(64),
                records: vec![],
                metrics: vec![],
                sql_observations: vec![],
                evidence_refs: vec![],
            };
            let attempts = HashMap::from([((digest.clone(), capability), "completed".into())]);
            let line = capture_status_line(&digest, capability, &[envelope], &attempts);
            assert!(line.contains("live Complete (1/1)"), "{line}");
            assert!(line.contains("last attempt: completed"), "{line}");
        }
    }

    #[test]
    fn remote_labels_separate_success_denial_and_unknown() {
        assert!(remote_status(EvidenceStatus::Partial, true).1);
        assert!(!remote_status(EvidenceStatus::Partial, false).1);
        assert_eq!(
            remote_status(EvidenceStatus::Denied, false),
            ("last live read denied", false)
        );
        assert!(
            remote_status(EvidenceStatus::Unavailable, false)
                .0
                .contains("permission unknown")
        );
    }

    #[test]
    fn last_capture_readiness_is_bound_to_case_and_scope() {
        let dir = std::env::temp_dir().join(format!("relayne-readiness-ui-{}", Uuid::new_v4()));
        let mut state = HelperState::at_path(dir.join("cases.dpapi"));
        let first = state
            .store
            .as_mut()
            .unwrap()
            .create(ProblemIntake::default())
            .unwrap();
        let second = state
            .store
            .as_mut()
            .unwrap()
            .create(ProblemIntake::default())
            .unwrap();
        let scope = BoundScope::Docker {
            daemon_context: "default".into(),
            container_id: "a".repeat(64),
            credential: None,
        };
        let other_scope = BoundScope::Docker {
            daemon_context: "other".into(),
            container_id: "a".repeat(64),
            credential: None,
        };
        state.collect_attempts.insert(
            (first, scope.digest().unwrap()),
            remote_status(EvidenceStatus::Denied, false),
        );
        let store = state.store.as_ref().unwrap();
        assert_eq!(
            remote_readiness(&state, store.case(first).unwrap(), &scope).0,
            "last live read denied"
        );
        assert!(
            remote_readiness(&state, store.case(second).unwrap(), &scope)
                .0
                .contains("unknown")
        );
        assert!(
            remote_readiness(&state, store.case(first).unwrap(), &other_scope)
                .0
                .contains("unknown")
        );
    }

    #[test]
    fn selection_keeps_launched_capture_bound_to_original_case() {
        let dir = std::env::temp_dir().join(format!("relayne-collect-ui-{}", Uuid::new_v4()));
        let mut state = HelperState::at_path(dir.join("cases.dpapi"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut profile = ConnectionProfile::sample("loopback", "127.0.0.1", "Default", false);
        profile.port = listener.local_addr().unwrap().port();
        let first = state
            .store
            .as_mut()
            .unwrap()
            .create(ProblemIntake::default())
            .unwrap();
        let second = state
            .store
            .as_mut()
            .unwrap()
            .create(ProblemIntake::default())
            .unwrap();
        let scope = BoundScope::Windows {
            target: Target::from_profile(&profile),
            credential: None,
        };
        state
            .store
            .as_mut()
            .unwrap()
            .revise(first, 1, CaseEdit::Profiles(vec![profile.id]))
            .unwrap();
        state
            .store
            .as_mut()
            .unwrap()
            .revise(first, 2, CaseEdit::Scopes(vec![scope]))
            .unwrap();
        let request_id = state
            .try_collect_with(
                first,
                0,
                &[profile.clone()],
                CapabilityId::NetworkReachability,
                ProbeParams::Network { port: profile.port },
            )
            .unwrap();
        state.select(second);
        assert!(state.collect_jobs.contains_key(&request_id));
        for _ in 0..200 {
            state.poll_collect(&[profile.clone()]);
            if state.collect_jobs.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(state.collect_jobs.is_empty());
        assert_eq!(
            state
                .store
                .as_ref()
                .unwrap()
                .case(first)
                .unwrap()
                .evidence()
                .len(),
            1
        );
        assert!(
            state
                .store
                .as_ref()
                .unwrap()
                .case(second)
                .unwrap()
                .evidence()
                .is_empty()
        );
        let reopened = HelperStore::load(&dir.join("cases.dpapi")).unwrap();
        assert_eq!(reopened.case(first).unwrap().evidence().len(), 1);
        drop(listener);
        drop(state);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
