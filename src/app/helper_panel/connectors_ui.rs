//! Deliberate collection control; case selection and plan preview never dispatch a probe.
use super::HelperState;
use crate::{
    helper::{
        capability::ProbeRequest,
        credentials::{PersistentSecretResolver, SecretResolver},
        evidence::EvidenceBinding,
        manifest::{CapabilityId, ProbeParams},
        scope::{BoundScope, CredentialPurpose},
        worker::{self, WorkerOutcome},
    },
    models::ConnectionProfile,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use eframe::egui;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Default)]
pub(super) struct SystemInputs {
    mount: String,
    interface: String,
    service: String,
    http_status: String,
    http_body_sha256: String,
}

fn current_profile_matches(scope: &BoundScope, profiles: &[ConnectionProfile]) -> bool {
    if matches!(
        scope,
        BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
    ) {
        return true;
    }
    let profile_matches = scope
        .target()
        .is_some_and(|target| profiles.iter().any(|profile| target.matches(profile)));
    profile_matches
        && match scope {
            BoundScope::WindowsWinRm { identity, .. } => {
                crate::helper::scope::current_windows_identity()
                    .is_ok_and(|current| current == *identity)
            }
            _ => true,
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
        _ => None,
    }
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
    ui.label("Remote permissions remain unknown until a probe reports them. TCP and HTTP only establish reachability or HTTP status.");
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
            _ => "No executable adapter in this wave",
        };
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
                    ),
                    egui::Button::new("Collect"),
                )
                .clicked()
            {
                state.collect(case.id(), index, profiles);
            }
        });
        if matches!(
            scope,
            BoundScope::WindowsWinRm { .. }
                | BoundScope::Linux {
                    credential: None,
                    ..
                }
        ) {
            ui.label("Supported: CPU two samples, memory, selected disk, process count, selected interface RX/TX rates, selected service. Missing counters stay unknown. Remote permission and live coverage are measured only after capture.");
            ui.label("WinRM uses current Windows identity; Linux uses the current default OpenSSH identity. Saved passwords are not sent.");
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
                        profile_current,
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
                        profile_current && !state.system_inputs.service.is_empty(),
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
        .filter(|(_, case_id)| **case_id == case.id())
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
        if let Err(error) = worker.submit(request) {
            store.cancel_pending_capture(id)?;
            let _ = store.save(path);
            return Err(error);
        }
        self.collect_jobs.insert(id, case_id);
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
            let Some(case_id) = self.collect_jobs.remove(&event.request_id) else {
                continue;
            };
            let Some(store) = self.store.as_mut() else {
                continue;
            };
            let status = match event.outcome {
                WorkerOutcome::Complete(envelope) => {
                    let current = store.case(case_id).and_then(|case| {
                        case.scopes().iter().find(|scope| {
                            scope.digest().ok().as_deref() == Some(&envelope.binding.scope_sha256)
                        })
                    });
                    if current.is_some_and(|scope| current_profile_matches(scope, profiles))
                        && store.attach_evidence(case_id, *envelope).is_ok()
                    {
                        "Capture attached"
                    } else {
                        let _ = store.cancel_pending_capture(event.request_id);
                        "Capture discarded: case, scope or endpoint changed"
                    }
                }
                WorkerOutcome::Canceled => {
                    let _ = store.cancel_pending_capture(event.request_id);
                    "Capture canceled"
                }
                WorkerOutcome::TimedOut => {
                    let _ = store.cancel_pending_capture(event.request_id);
                    "Capture timed out"
                }
                WorkerOutcome::Failed(failure) => {
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
            self.notice = if let Some(path) = self.path.as_ref() {
                if store.save(path).is_ok() {
                    status.into()
                } else {
                    "Capture state could not be saved".into()
                }
            } else {
                "Capture store unavailable".into()
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        helper::{
            case::{CaseEdit, ProblemIntake},
            store::HelperStore,
        },
        mission::Target,
    };
    use std::{net::TcpListener, time::Duration};

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
        let request_id = state.try_collect(first, 0, &[profile.clone()]).unwrap();
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
