//! Background network checks with a main-thread certificate trust continuation.
use super::*;
use std::sync::mpsc::{self, Receiver, TryRecvError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProbeIntent {
    Connect,
    Trust,
    Reject,
    Inspect,
}

struct PendingProbe {
    profile: ConnectionProfile,
    intent: ProbeIntent,
    receiver: Receiver<(
        Result<String, String>,
        Option<crate::models::PreflightReport>,
    )>,
}

#[derive(Default)]
pub(super) struct ProbeCoordinator {
    pending: Option<PendingProbe>,
}

pub(super) struct ProbeCompletion {
    profile: ConnectionProfile,
    intent: ProbeIntent,
    fingerprint: Result<String, String>,
    report: Option<crate::models::PreflightReport>,
}

impl ProbeCoordinator {
    fn begin(&mut self, profile: ConnectionProfile, intent: ProbeIntent) -> bool {
        self.begin_with(profile, intent, |profile, intent| {
            let fingerprint = probe_server_fingerprint(profile).map_err(|err| format!("{err:#}"));
            let report = if intent == ProbeIntent::Connect
                && (fingerprint.is_ok()
                    || fingerprint
                        .as_ref()
                        .err()
                        .is_some_and(|err| is_standard_rdp_security_error(err)))
            {
                let mut route = profile.clone();
                if profile.options.gateway.enabled {
                    route.host = profile.options.gateway.host.clone();
                    route.port = profile.options.gateway.port;
                }
                Some(LocalPreflightService.run(&route))
            } else {
                None
            };
            (fingerprint, report)
        })
    }

    fn begin_with<F>(&mut self, profile: ConnectionProfile, intent: ProbeIntent, probe: F) -> bool
    where
        F: FnOnce(
                &ConnectionProfile,
                ProbeIntent,
            ) -> (
                Result<String, String>,
                Option<crate::models::PreflightReport>,
            ) + Send
            + 'static,
    {
        if self.pending.is_some() {
            return false;
        }
        let (sender, receiver) = mpsc::channel();
        let worker_profile = profile.clone();
        std::thread::spawn(move || {
            let _ = sender.send(probe(&worker_profile, intent));
        });
        self.pending = Some(PendingProbe {
            profile,
            intent,
            receiver,
        });
        true
    }

    fn poll(&mut self) -> Option<ProbeCompletion> {
        let pending = self.pending.as_ref()?;
        let (fingerprint, report) = match pending.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => (
                Err("Zertifikatsprüfung wurde unerwartet beendet.".into()),
                None,
            ),
        };
        let pending = self.pending.take()?;
        Some(ProbeCompletion {
            profile: pending.profile,
            intent: pending.intent,
            fingerprint,
            report,
        })
    }
}

fn still_selected(profile: &ConnectionProfile, selected: Option<&ConnectionProfile>) -> bool {
    selected.is_some_and(|current| {
        current.id == profile.id
            && current.host == profile.host
            && current.port == profile.port
            && current.updated_at == profile.updated_at
    })
}

impl AivanaApp {
    pub(super) fn probe_selected_certificate(&mut self) {
        self.begin_certificate_probe(ProbeIntent::Inspect);
    }
    pub(super) fn begin_certificate_probe(&mut self, intent: ProbeIntent) {
        let Some(profile) = self.selected_profile().cloned() else {
            self.status = "Bitte zuerst einen Rechner auswählen.".into();
            return;
        };
        if intent == ProbeIntent::Connect {
            if let Some(session) = self.sessions.iter().find(|session| {
                session.profile_id == profile.id
                    && !matches!(
                        session.status,
                        SessionStatus::Failed | SessionStatus::Disconnected
                    )
            }) {
                let id = session.id;
                self.engine.release_inputs_except(Some(id));
                self.selected_session = Some(id);
                self.desktop.focus = true;
                self.view = View::Sessions;
                self.status = format!("Bestehende Sitzung für {} geöffnet.", profile.name);
                return;
            }
        }
        let profile = match self.workbench_runtime_profile(&profile) {
            Ok(profile) => profile,
            Err(err) => {
                self.status = err.to_string();
                return;
            }
        };
        let name = profile.name.clone();
        if self.connection_probe.begin(profile, intent) {
            self.status = format!("Zertifikat und Verbindung für {name} werden geprüft …");
        } else {
            self.status = "Eine Verbindungsprüfung läuft bereits. Bitte Ergebnis abwarten.".into();
        }
    }

    pub(super) fn poll_certificate_probe(&mut self) {
        let Some(result) = self.connection_probe.poll() else {
            return;
        };
        if !still_selected(&result.profile, self.selected_profile()) {
            self.status = format!(
                "Prüfung für {} verworfen: Auswahl oder Profil wurde geändert.",
                result.profile.name
            );
            return;
        }
        if result.intent == ProbeIntent::Connect {
            self.connect_after_probe(result.profile, result.fingerprint, result.report);
            return;
        }
        let fingerprint = match result.fingerprint {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                if is_standard_rdp_security_error(&error) {
                    self.block_standard_rdp_security(&result.profile, &error);
                } else {
                    self.status = format!("Zertifikatsprüfung fehlgeschlagen: {error}");
                    self.certificate_notice =
                        "Kein echtes TLS-Zertifikat erhalten. Vertrauensstatus unverändert.".into();
                }
                return;
            }
        };
        let profile = result.profile;
        match result.intent {
            ProbeIntent::Trust => {
                let identity = self
                    .certificates
                    .trust(&profile.host, profile.port, &fingerprint);
                self.certificate_notice = format!(
                    "Trusted {}:{} fingerprint {} (RDP TLS probe)",
                    identity.host, identity.port, identity.fingerprint
                );
                self.status = "Certificate trusted locally".into();
            }
            ProbeIntent::Reject => {
                let identity = self
                    .certificates
                    .reject(&profile.host, profile.port, &fingerprint);
                self.certificate_notice = format!(
                    "Rejected {}:{} fingerprint {}",
                    identity.host, identity.port, identity.fingerprint
                );
                self.status = "Certificate rejected locally".into();
            }
            ProbeIntent::Inspect => {
                self.certificate_notice = format!(
                    "{}:{} Fingerabdruck: {fingerprint}",
                    profile.host, profile.port
                );
                self.status = format!("Zertifikatsprüfung für {} abgeschlossen.", profile.name);
            }
            ProbeIntent::Connect => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_selection_or_endpoint_cannot_receive_trust_result() {
        let profile = ConnectionProfile::sample("A", "a.example", "test", false);
        assert!(still_selected(&profile, Some(&profile)));
        let mut current = profile.clone();
        current.host = "b.example".into();
        assert!(!still_selected(&profile, Some(&current)));
        current = profile.clone();
        current.id = Uuid::new_v4();
        assert!(!still_selected(&profile, Some(&current)));
        assert!(!still_selected(&profile, None));
    }

    #[test]
    fn pending_probe_deduplicates_requests_and_keeps_original_identity() {
        let profile = ConnectionProfile::sample("A", "a.example", "test", false);
        let mut coordinator = ProbeCoordinator::default();
        let (finish, wait) = mpsc::channel::<()>();
        assert!(
            coordinator.begin_with(profile.clone(), ProbeIntent::Trust, move |_, _| {
                wait.recv().unwrap();
                (Ok("fingerprint-A".into()), None)
            })
        );
        assert!(
            !coordinator.begin_with(profile.clone(), ProbeIntent::Connect, |_, _| panic!(
                "must not dispatch twice"
            ))
        );
        assert!(coordinator.poll().is_none());
        finish.send(()).unwrap();
        let pending = coordinator.pending.as_ref().unwrap();
        // Wait in the test only, never in the GUI polling path.
        let result = pending
            .receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(result.0.unwrap(), "fingerprint-A");
        assert_eq!(pending.profile.id, profile.id);
        assert_eq!(pending.intent, ProbeIntent::Trust);
    }
}
