use super::*;
use crate::recovery_daemon::{self, Consent, Notices, Settings};
pub(super) struct RecoveryDaemonState {
    selected: Option<Uuid>,
    user: String,
    password: String,
    hours: u32,
    drill: bool,
    confirmed: bool,
    notice: String,
    worker: Option<std::sync::mpsc::Receiver<Result<usize, String>>>,
}
impl Default for RecoveryDaemonState {
    fn default() -> Self {
        Self {
            selected: None,
            user: String::new(),
            password: String::new(),
            hours: 24,
            drill: false,
            confirmed: false,
            notice: String::new(),
            worker: None,
        }
    }
}
impl AivanaApp {
    pub(super) fn recovery_daemon_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hintergrund & geplante Generalproben");
        ui.label("Prüft alle fünf Minuten fällige Verträge, auch bei geschlossener App. Läuft nur, solange dieser Windows-Benutzer angemeldet ist. Produktion wird ausschließlich gelesen.");
        ui.label("Klonproben benötigen vorhandene gestartete Hyper-V-Klone, PowerShell-Direct-Rechte und Gastzugang. Die Aufgabe erhöht keine Rechte. HTTP-Prüfungen mit zusätzlichen Geheimwerten benötigen weiterhin eine manuelle Generalprobe.");
        ui.label("Vor jeder erneuten Probe muss der Klon wieder den passenden Fehlerzustand zeigen. Gesunde Klone liefern keinen Reparaturnachweis; automatisches Zurücksetzen oder Erzeugen von Fehlern ist nicht eingerichtet.");
        let state = &mut self.recovery_daemon;
        if let Some(rx) = &state.worker {
            match rx.try_recv() {
                Ok(result) => {
                    state.notice = match result {
                        Ok(n) => format!("Hintergrunddurchlauf beendet: {n} Vorgänge"),
                        Err(e) => e,
                    };
                    state.worker = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    state.notice = "Hintergrundworker unerwartet beendet".into();
                    state.worker = None;
                }
                Err(_) => {
                    ui.spinner();
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(300));
                }
            }
        }
        let mut settings = match Settings::load() {
            Ok(s) => s,
            Err(_) => {
                ui.colored_label(
                    egui::Color32::RED,
                    "Hintergrundspeicher nicht lesbar; Konfiguration gesperrt",
                );
                return;
            }
        };
        ui.label(if settings.enabled {
            "Gespeicherte Hintergrundfreigaben aktiv (Aufgabe separat installieren)"
        } else {
            "Hintergrundarbeit ausgeschaltet"
        });
        if ui
            .checkbox(
                &mut settings.windows_hints,
                "Lokale Windows-Hinweise für neue Meldungen (auch bei geschlossener App)",
            )
            .changed()
        {
            state.notice = settings.save().map_or_else(
                |e| e.to_string(),
                |_| "Hinweiseinstellung gespeichert".into(),
            );
        }
        ui.horizontal(|ui| {
            if ui
                .button("Windows-Aufgabe installieren / aktualisieren")
                .clicked()
            {
                state.notice = match recovery_daemon::install_task() {
                    Ok(()) => "Aufgabe für diesen Benutzer installiert".into(),
                    Err(e) => e.to_string(),
                };
            }
            if ui
                .button("Alles deaktivieren & Aufgabe entfernen")
                .clicked()
            {
                state.notice = match recovery_daemon::remove_task() {
                    Ok(()) => "Deaktiviert; Gastzugänge entfernt; Aufgabe gelöscht".into(),
                    Err(e) => format!("Entfernen prüfen: {e}"),
                };
            }
            if ui
                .add_enabled(
                    state.worker.is_none() && settings.enabled,
                    egui::Button::new("Freigegebenen Durchlauf starten"),
                )
                .clicked()
            {
                let (tx, rx) = std::sync::mpsc::channel();
                state.worker = Some(rx);
                std::thread::spawn(move || {
                    let _ = tx.send(recovery_daemon::run_once().map_err(|_| {
                        "Durchlauf fehlgeschlagen; Meldungen und Speicher prüfen".into()
                    }));
                });
            }
        });
        let book = match app_data_file("relayne-recovery-contracts.dpapi")
            .and_then(|p| crate::recovery_contracts::Book::load(&p))
        {
            Ok(b) => b,
            Err(_) => {
                ui.colored_label(
                    egui::Color32::RED,
                    "Vertragsspeicher gesperrt oder nicht lesbar",
                );
                return;
            }
        };
        ui.separator();
        egui::ComboBox::from_id_salt("background-contract")
            .selected_text(
                book.contracts
                    .iter()
                    .find(|c| Some(c.id) == state.selected)
                    .map_or("Vertrag wählen", |c| c.name.as_str()),
            )
            .show_ui(ui, |ui| {
                for c in &book.contracts {
                    if ui
                        .selectable_value(&mut state.selected, Some(c.id), &c.name)
                        .changed()
                    {
                        state.confirmed = false;
                    }
                }
            });
        if let Some(c) = book.contracts.iter().find(|c| Some(c.id) == state.selected) {
            ui.label(format!(
                "Dienst: {} · Zielzustand: {} · Plan: {}",
                c.plan.service,
                c.plan.desired.label(),
                c.plan.hash().unwrap_or_default()
            ));
            for m in &c.plan.mappings {
                ui.label(format!(
                    "Produktion (lesen): {} → Klon: {} / VM {}",
                    m.production.host, m.staging.profile_id, m.staging.host
                ));
            }
            if let Some(existing) = settings.consents.iter().find(|s| s.contract_id == c.id) {
                ui.label(format!(
                    "Freigabe bis {} · Klonproben: {}",
                    existing
                        .expires
                        .with_timezone(&chrono::Local)
                        .format("%d.%m.%Y %H:%M"),
                    existing.drill
                ));
                if ui
                    .button("Diesen Vertrag deaktivieren / Gastzugang löschen")
                    .clicked()
                {
                    settings.consents.retain(|s| s.contract_id != c.id);
                    state.notice = settings
                        .save()
                        .map_or_else(|e| e.to_string(), |_| "Freigabe entfernt".into());
                }
            }
            if ui
                .checkbox(
                    &mut state.drill,
                    "Auch echte Dienständerungen ausschließlich in diesen Klonen planen",
                )
                .changed()
            {
                state.confirmed = false;
            }
            ui.horizontal(|ui| {
                ui.label("Freigabe für Stunden");
                if ui
                    .add(egui::DragValue::new(&mut state.hours).range(1..=168))
                    .changed()
                {
                    state.confirmed = false;
                }
            });
            if state.drill {
                ui.label("Gastkonto für alle ausgewählten Klone (DOMAIN\\Benutzer oder Benutzer)");
                if ui.text_edit_singleline(&mut state.user).changed() {
                    state.confirmed = false;
                }
                ui.label("Gastpasswort · verschlüsselt mit CurrentUser-DPAPI gespeichert");
                if ui
                    .add(egui::TextEdit::singleline(&mut state.password).password(true))
                    .changed()
                {
                    state.confirmed = false;
                }
            }
            ui.checkbox(&mut state.confirmed, "Ich autorisiere genau diesen Plan, diese Ziele und die gewählte Laufzeit; bei Klonproben auch deren Dienständerungen und Zugangsspeicherung.");
            if ui
                .add_enabled(
                    state.confirmed,
                    egui::Button::new("Freigabe speichern und aktivieren"),
                )
                .clicked()
            {
                let result = (|| -> anyhow::Result<()> {
                    anyhow::ensure!(
                        !state.drill
                            || (!state.user.trim().is_empty() && !state.password.is_empty()),
                        "Gastkonto und Passwort fehlen"
                    );
                    let consent = Consent {
                        contract_id: c.id,
                        plan_hash: c.plan.hash()?,
                        expires: Utc::now()
                            + chrono::Duration::hours(i64::from(state.hours.clamp(1, 168))),
                        drill: state.drill,
                        user: if state.drill {
                            state.user.clone()
                        } else {
                            String::new()
                        },
                        password: if state.drill {
                            state.password.clone()
                        } else {
                            String::new()
                        },
                    };
                    settings.consents.retain(|s| s.contract_id != c.id);
                    settings.consents.push(consent);
                    settings.enabled = true;
                    settings.save()
                })();
                state.notice = result.map_or_else(
                    |e| e.to_string(),
                    |_| {
                        "Freigabe gespeichert. Windows-Aufgabe bei Bedarf oben installieren.".into()
                    },
                );
                state.password.clear();
                state.confirmed = false;
            }
        }
        ui.label(&state.notice);
        ui.separator();
        ui.heading("Dauerhafte Meldungen");
        if ui.button("Alle als gelesen markieren").clicked() {
            if let Err(e) = Notices::mark_read() {
                state.notice = e.to_string();
            }
        }
        match Notices::load() {
            Ok(notices) => {
                for n in notices.items.iter().rev().take(64) {
                    ui.label(format!(
                        "{} {} · {} · {}",
                        if n.read { "" } else { "●" },
                        n.at.with_timezone(&chrono::Local).format("%d.%m. %H:%M"),
                        n.contract_id,
                        n.message
                    ));
                }
            }
            Err(_) => {
                ui.colored_label(egui::Color32::RED, "Meldungsspeicher nicht lesbar");
            }
        }
    }
}
