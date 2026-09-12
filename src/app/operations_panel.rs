use super::*;
use crate::operations::{Endpoint, JobQueue, Query, Request, ServiceAction};
use std::sync::mpsc;

struct LocalEntry {
    path: std::path::PathBuf,
    directory: bool,
}
struct LocalListing {
    requested: String,
    path: std::path::PathBuf,
    entries: Vec<LocalEntry>,
    capped: bool,
    captured: chrono::DateTime<chrono::Utc>,
}
fn list_local_directory(requested: String) -> Result<LocalListing, String> {
    let path = std::fs::canonicalize(&requested).map_err(|e| e.to_string())?;
    // Windows canonicalize returns extended-length names; OpenSSH expects the
    // conventional absolute drive/UNC form, not a //?/ path after normalization.
    #[cfg(windows)]
    let path = {
        let text = path.to_string_lossy();
        std::path::PathBuf::from(if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{rest}")
        } else {
            text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
        })
    };
    let mut entries = Vec::new();
    let mut capped = false;
    for entry in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
        if entries.len() == 500 {
            capped = true;
            break;
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let directory = entry.file_type().map_err(|e| e.to_string())?.is_dir();
        entries.push(LocalEntry {
            path: entry.path(),
            directory,
        });
    }
    entries.sort_by(|a, b| {
        b.directory
            .cmp(&a.directory)
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(LocalListing {
        requested,
        path,
        entries,
        capped,
        captured: chrono::Utc::now(),
    })
}

pub struct OperationsState {
    host: String,
    user: String,
    port: u16,
    mode: usize,
    command: String,
    service: String,
    local: String,
    remote: String,
    resume: bool,
    recursive: bool,
    local_directory: String,
    local_listing: Option<LocalListing>,
    local_pending: Option<mpsc::Receiver<Result<LocalListing, String>>>,
    local_error: String,
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
            resume: false,
            recursive: false,
            local_directory: ".".into(),
            local_listing: None,
            local_pending: None,
            local_error: String::new(),
            reviewed: false,
            preview: String::new(),
            queue: JobQueue::default(),
        }
    }
}
impl AivanaApp {
    pub(super) fn operations_select_profile(&mut self, profile: &ConnectionProfile) {
        self.operations.host = profile.host.clone();
        self.operations.user = profile.username.clone();
        self.operations.port = profile.port;
        self.operations.mode = 0;
        self.operations.reviewed = false;
    }
    pub(super) fn poll_operations(&mut self) {
        self.operations.queue.poll();
        if let Some(rx) = &self.operations.local_pending {
            match rx.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(listing) => {
                            self.operations.local_listing = Some(listing);
                            self.operations.local_error.clear();
                        }
                        Err(error) => self.operations.local_error = error,
                    };
                    self.operations.local_pending = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.operations.local_pending = None;
                    self.operations.local_error =
                        "Lokale Verzeichnisabfrage beendet ohne Ergebnis.".into();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
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
        if state.mode >= 8 {
            transfer_browser(state, ui);
        }
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
                    ui.checkbox(&mut state.resume, "Teildatei ausdrücklich fortsetzen (-a)");
                    if state.resume {
                        ui.colored_label(Color32::YELLOW,"Voraussetzung: Die vorhandene Zieldatei entspricht bytegenau dem Anfang der unveränderten Quelle. SFTP prüft diesen Inhalt nicht; sonst drohen beschädigte Dateien. Quelle und Ziel vor Freigabe prüfen.");
                    }
                    ui.checkbox(&mut state.recursive, "Verzeichnis rekursiv übertragen (-R)");
                }
                match state.mode {
                    8 => Request::List {
                        remote: state.remote.clone(),
                    },
                    _ => Request::Transfer {
                        remote: state.remote.clone(),
                        local: state.local.clone(),
                        upload: state.mode == 9,
                        resume: state.resume,
                        recursive: state.recursive,
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
        if state.local_pending.is_some()
            || state.queue.jobs.iter().any(|job| !job.status.terminal())
        {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn transfer_browser(state: &mut OperationsState, ui: &mut Ui) {
    ui.columns(2,|columns| {
        let ui=&mut columns[0];
        ui.strong("Lokal");
        ui.text_edit_singleline(&mut state.local_directory);
        if ui.add_enabled(state.local_pending.is_none(),egui::Button::new("Lokales Verzeichnis lesen")).clicked() {
            let (tx,rx)=mpsc::channel();let requested=state.local_directory.clone();
            state.local_pending=Some(rx);state.local_error.clear();
            std::thread::spawn(move||{let _=tx.send(list_local_directory(requested));});
        }
        if state.local_pending.is_some() {ui.label("Verzeichnis wird gelesen …");}
        if !state.local_error.is_empty() {ui.colored_label(Color32::YELLOW,&state.local_error);}
        if let Some(listing)=state.local_listing.as_ref().filter(|l|l.requested==state.local_directory) {
            ui.small(format!("{} · {}",listing.path.display(),listing.captured.to_rfc3339()));
            if listing.capped {ui.label("Auf 500 Einträge begrenzt.");}
            ScrollArea::vertical().id_salt("local-transfer-files").max_height(190.0).show(ui,|ui| {
                for entry in &listing.entries {
                    let name=entry.path.file_name().unwrap_or_default().to_string_lossy();
                    ui.horizontal(|ui| {
                        if entry.directory && ui.small_button("Öffnen").clicked() {state.local_directory=entry.path.to_string_lossy().into_owned();}
                        if ui.selectable_label(state.local==entry.path.to_string_lossy(),format!("{}{}",if entry.directory {"Ordner: "} else {""},name)).clicked() {state.local=entry.path.to_string_lossy().into_owned();}
                    });
                }
            });
        } else {ui.small("Noch keine passende lokale Verzeichnisaufnahme. Datei auswählen, um den absoluten lokalen Pfad zu übernehmen.");}
        let ui=&mut columns[1];ui.strong("Remote · letzte erfolgreiche Verzeichnisaufnahme");
        ui.small("Remote-Pfad unten ausdrücklich bearbeiten. Für eine neue Aufnahme Modus SFTP: Verzeichnis wählen, Vorschau prüfen und einreihen. Namen werden aus der Textausgabe nicht automatisch übernommen.");
        if let Ok(endpoint)=Endpoint::new(&state.host,&state.user,state.port) {
            if let Some(job)=state.queue.latest_listing(&endpoint,&state.remote) {
                let result=job.result.as_ref().unwrap();let captured:chrono::DateTime<chrono::Utc>=result.finished.into();
                ui.small(format!("{}@{}:{} · {} · {}",state.user,state.host,state.port,state.remote,captured.to_rfc3339()));
                if result.truncated {ui.colored_label(Color32::YELLOW,"Unvollständige/verkleinerte Aufnahme; nicht alle Einträge sichtbar.");}
                ScrollArea::vertical().id_salt("remote-transfer-files").max_height(190.0).show(ui,|ui|{ui.monospace(&result.stdout);});
            } else {ui.label("Keine erfolgreiche Aufnahme für dieses Ziel, diesen Benutzer, Port und Pfad.");}
        }
    });
}

#[cfg(test)]
mod transfer_tests {
    use super::*;
    #[test]
    fn local_listing_has_absolute_paths_and_stops_at_500() {
        let directory =
            std::env::temp_dir().join(format!("aivana-local-listing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let files: Vec<_> = (0..501)
            .map(|i| directory.join(format!("file-{i}.txt")))
            .collect();
        for file in &files {
            std::fs::write(file, b"local-test").unwrap();
        }
        let listing = list_local_directory(directory.to_string_lossy().into_owned()).unwrap();
        for file in &files {
            std::fs::remove_file(file).unwrap();
        }
        std::fs::remove_dir(&directory).unwrap();
        assert_eq!(listing.entries.len(), 500);
        assert!(listing.capped);
        assert!(
            listing
                .entries
                .iter()
                .all(|entry| entry.path.is_absolute() && !entry.directory)
        );
        assert!(!listing.path.to_string_lossy().starts_with(r"\\?\"));
    }
}
