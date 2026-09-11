use super::*;
use crate::operations::{Endpoint, JobQueue, Query, Request, ServiceAction};

pub struct OperationsState {
    host: String,
    user: String,
    port: u16,
    mode: usize,
    command: String,
    service: String,
    local: String,
    remote: String,
    reviewed: bool,
    preview: String,
    pub queue: JobQueue,
}
impl Default for OperationsState {
    fn default() -> Self {
        Self {
            host: String::new(),
            user: String::new(),
            port: 22,
            mode: 1,
            command: String::new(),
            service: String::new(),
            local: String::new(),
            remote: "/".into(),
            reviewed: false,
            preview: String::new(),
            queue: JobQueue::default(),
        }
    }
}
impl AivanaApp {
    pub(super) fn poll_operations(&mut self) {
        self.operations.queue.poll();
    }
    pub(super) fn operations_view(&mut self, ui: &mut Ui) {
        ui.heading("Remote-Verwaltung");
        ui.label("Echte Hintergrundaufträge • SSH / SFTP / WinRM");
        ui.label("Voraussetzungen: installiertes OpenSSH, vorab geprüfter Hostschlüssel in known_hosts und Schlüssel/Agent. WinRM: Windows PowerShell, freigegebenes Remoting, aktuelle Windows-Identität (Negotiate).");
        if ui
            .button("Ziel aus ausgewähltem Verbindungsprofil übernehmen")
            .clicked()
        {
            if let Some(profile) = self
                .profiles
                .iter()
                .find(|p| Some(p.id) == self.selected_profile)
            {
                self.operations.host = profile.host.clone();
                self.operations.user = if profile.protocol == Protocol::Ssh {
                    profile.username.clone()
                } else {
                    String::new()
                };
                self.operations.port = if profile.protocol == Protocol::Ssh {
                    profile.port
                } else {
                    22
                };
                self.operations.reviewed = false;
            } else {
                self.status = "Zuerst ein Verbindungsprofil auswählen.".into();
            }
        }
        let state = &mut self.operations;
        ui.horizontal(|ui| {
            ui.label("Host");
            ui.text_edit_singleline(&mut state.host);
            ui.label("SSH-Benutzer (leer = lokal)");
            ui.text_edit_singleline(&mut state.user);
            ui.label("SSH-Port");
            ui.add(egui::DragValue::new(&mut state.port).range(1..=65535));
        });
        let modes = [
            "SSH: eigener Befehl",
            "WinRM: Systeminventar",
            "WinRM: Dienste",
            "WinRM: Prozesse",
            "WinRM: Systemereignisse (24 h)",
            "WinRM: Dienst starten",
            "WinRM: Dienst stoppen",
            "WinRM: Dienst neu starten",
            "SFTP: Verzeichnis",
            "SFTP: Upload",
            "SFTP: Download",
        ];
        egui::ComboBox::from_id_salt("operation-mode")
            .selected_text(modes[state.mode])
            .show_ui(ui, |ui| {
                for (index, label) in modes.iter().enumerate() {
                    ui.selectable_value(&mut state.mode, index, *label);
                }
            });
        let request = match state.mode {
            0 => {
                ui.label("Dieser Befehl wird durch die Shell auf dem Ziel ausgeführt. Keine Kennwörter oder Geheimnisse eintragen.");
                ui.text_edit_multiline(&mut state.command);
                Request::Ssh {
                    command: state.command.clone(),
                }
            }
            1 => Request::WinRm(Query::Inventory),
            2 => Request::WinRm(Query::Services),
            3 => Request::WinRm(Query::Processes),
            4 => Request::WinRm(Query::Events),
            5..=7 => {
                ui.horizontal(|ui| {
                    ui.label("Technischer Dienstname");
                    ui.text_edit_singleline(&mut state.service);
                });
                Request::Service {
                    name: state.service.clone(),
                    action: match state.mode {
                        5 => ServiceAction::Start,
                        6 => ServiceAction::Stop,
                        _ => ServiceAction::Restart,
                    },
                }
            }
            _ => {
                ui.horizontal(|ui| {
                    ui.label("Remote-Pfad");
                    ui.text_edit_singleline(&mut state.remote);
                });
                if state.mode != 8 {
                    ui.horizontal(|ui| {
                        ui.label("Lokaler absoluter Pfad");
                        ui.text_edit_singleline(&mut state.local);
                    });
                    ui.label("Übertragung kann vorhandene Dateien überschreiben; nach Abbruch können Teildateien bestehen. Kein automatischer Wiederanlauf.");
                }
                match state.mode {
                    8 => Request::List {
                        remote: state.remote.clone(),
                    },
                    9 => Request::Upload {
                        local: state.local.clone(),
                        remote: state.remote.clone(),
                    },
                    _ => Request::Download {
                        remote: state.remote.clone(),
                        local: state.local.clone(),
                    },
                }
            }
        };
        let spec = Endpoint::new(&state.host, &state.user, state.port)
            .and_then(|endpoint| request.build(&endpoint));
        let preview = match &spec {
            Ok(spec) => spec.preview(),
            Err(error) => error.clone(),
        };
        if preview != state.preview {
            state.reviewed = false;
            state.preview = preview;
        }
        egui::CollapsingHeader::new("Befehl und Ziel prüfen")
            .default_open(true)
            .show(ui, |ui| {
                ui.monospace(&state.preview);
            });
        ui.checkbox(
            &mut state.reviewed,
            "Ziel und Vorschau geprüft; diesen Auftrag ausdrücklich freigeben",
        );
        if ui
            .add_enabled(
                state.reviewed && spec.is_ok(),
                egui::Button::new("Freigegebenen Auftrag einreihen"),
            )
            .clicked()
        {
            if let Ok(spec) = spec {
                match state.queue.enqueue(spec) {
                    Ok(id) => self.status = format!("Remote-Auftrag #{id} eingereiht."),
                    Err(error) => self.status = error,
                };
            }
            state.reviewed = false;
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Aufträge und Dateiübertragungen • einzeln • Zeitlimit 120 s");
            if ui.button("Abgeschlossene entfernen").clicked() {
                state.queue.clear_finished();
            }
        });
        ui.small("Completed bedeutet Prozesscode 0. Ausgabe prüfen; Anwendungszustand separat bestätigen. Ausgabe je Kanal auf 128 KiB begrenzt.");
        ui.small("Abbruch stoppt lokalen Transport; bereits gestartete Remote-Aktionen können weiterlaufen. Zustand erneut prüfen.");
        ScrollArea::vertical()
            .id_salt("operations-jobs")
            .max_height(420.0)
            .show(ui, |ui| {
                for job in &state.queue.jobs {
                    egui::CollapsingHeader::new(format!(
                        "#{} · {} · {:?}",
                        job.id, job.spec.source, job.status
                    ))
                    .id_salt(job.id)
                    .show(ui, |ui| {
                        let created: chrono::DateTime<chrono::Utc> = job.created.into();
                        ui.label(format!("Erstellt: {}", created.to_rfc3339()));
                        ui.monospace(job.spec.preview());
                        if !job.status.terminal() && ui.button("Auftrag abbrechen").clicked() {
                            job.cancel();
                        }
                    if let Some(result) = &job.result {
                        if matches!(result.status, crate::operations::JobStatus::Cancelled | crate::operations::JobStatus::TimedOut) {
                            ui.colored_label(Color32::YELLOW, "Lokaler Transport abgebrochen oder Zeitlimit erreicht. Remote-Ergebnis unbekannt; Zustand vor Wiederholung prüfen.");
                        }
                            let finished: chrono::DateTime<chrono::Utc> = result.finished.into();
                            ui.label(format!("Beendet: {}", finished.to_rfc3339()));
                            if result.truncated {
                                ui.colored_label(
                                    Color32::YELLOW,
                                    "Ausgabe begrenzt oder Stream nicht vollständig geschlossen.",
                                );
                            }
                            ui.label("Standardausgabe");
                            ui.monospace(&result.stdout);
                            ui.label("Fehlerausgabe");
                            ui.monospace(&result.stderr);
                        }
                    });
                }
            });
        if state.queue.jobs.iter().any(|job| !job.status.terminal()) {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}
