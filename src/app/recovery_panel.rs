use super::*;
use crate::recovery::{self, Book, Case, Outcome, Suggestion};
use std::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Intake,
    Rehearsal,
    Production,
    Evidence,
}

pub(super) struct RecoveryState {
    book: Book,
    error: Option<String>,
    selected: Option<Uuid>,
    objective: String,
    service: String,
    rationale: String,
    proposal_objective: Option<String>,
    consent: bool,
    planning: Option<(String, mpsc::Receiver<Result<Suggestion, String>>)>,
    stage: Stage,
    enabled: bool,
    notice: String,
}

impl Default for RecoveryState {
    fn default() -> Self {
        let (book, error) =
            match app_data_file("relayne-recovery.dpapi").and_then(|p| Book::load(&p)) {
                Ok(book) => (book, None),
                Err(e) => (
                    Book::default(),
                    Some(format!("Recovery-Speicher nicht lesbar: {e}")),
                ),
            };
        Self {
            selected: book.cases.last().map(|c| c.id),
            book,
            error,
            objective: String::new(),
            service: String::new(),
            rationale: String::new(),
            proposal_objective: None,
            consent: false,
            planning: None,
            stage: Stage::Intake,
            enabled: std::env::var("RELAYNE_RECOVERY_AGENT").as_deref() != Ok("0"),
            notice: String::new(),
        }
    }
}

fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pending => "Noch kein Produktionslauf — Zielzuordnung und Generalprobe prüfen",
        Outcome::InProgress => "Produktionslauf offen — Freigabe oder Prüfung ausstehend",
        Outcome::Verified => "Wiederherstellung durch passende Dienst- und HTTP-Belege bestätigt",
        Outcome::Failed => "Nicht behoben — Fehler, Rückkehr oder unbekannter Zustand",
        Outcome::Unverified => "Nicht als behoben nachgewiesen — Belege fehlen oder passen nicht",
    }
}

impl AivanaApp {
    pub(super) fn recovery_actions_allowed(&self) -> bool {
        self.recovery.enabled && self.recovery.error.is_none()
    }
    pub(super) fn validate_recovery_case(&self, id: Uuid, service: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recovery.enabled,
            "Neue Recovery-Aufträge sind deaktiviert"
        );
        anyhow::ensure!(self.recovery.error.is_none(), "Recovery-Speicher gesperrt");
        anyhow::ensure!(
            self.recovery
                .book
                .cases
                .iter()
                .any(|c| c.id == id && c.service == service),
            "Störungsfall fehlt oder Dienst wurde geändert. Neuen Fall mit geprüftem Dienst anlegen."
        );
        Ok(())
    }

    fn recovery_create_case(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recovery.enabled && self.recovery.error.is_none(),
            "Recovery deaktiviert oder gesperrt"
        );
        anyhow::ensure!(self.recovery.planning.is_none(), "KI-Vorschlag noch offen");
        anyhow::ensure!(
            self.recovery
                .proposal_objective
                .as_ref()
                .is_none_or(|o| o == &self.recovery.objective),
            "Störung seit dem KI-Vorschlag geändert; Vorschlag neu erstellen oder verwerfen"
        );
        self.promotion.can_adopt_recovery()?;
        let case = Case::new(
            self.recovery.objective.clone(),
            Suggestion {
                service: self.recovery.service.clone(),
                rationale: if self.recovery.rationale.trim().is_empty() {
                    "Dienst vom Operator ausgewählt; Ausgangszustand und Funktionstest noch zu prüfen.".into()
                } else {
                    self.recovery.rationale.clone()
                },
            },
        )?;
        let mut book = self.recovery.book.clone();
        book.cases.push(case.clone());
        book.save(&app_data_file("relayne-recovery.dpapi")?)?;
        self.recovery.book = book;
        self.recovery.selected = Some(case.id);
        self.promotion.adopt_recovery(&case)?;
        self.persist_recovery_promotion()?;
        self.recovery.stage = Stage::Rehearsal;
        self.recovery.notice =
            "Fall gespeichert. Jetzt Ziel, Testlabor und fachlichen HTTP-Test zuordnen.".into();
        Ok(())
    }

    pub(super) fn recovery_view(&mut self, ui: &mut Ui) {
        if let Some((objective, rx)) = &self.recovery.planning {
            let response = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("KI-Anfrage unterbrochen".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = response {
                let source = objective.clone();
                self.recovery.planning = None;
                match result {
                    Ok(suggestion) if source == self.recovery.objective => {
                        self.recovery.service = suggestion.service;
                        self.recovery.rationale = suggestion.rationale;
                        self.recovery.proposal_objective = Some(source);
                        self.recovery.notice =
                            "KI-Vorschlag liegt vor. Dienst und Begründung vor Übernahme prüfen."
                                .into();
                    }
                    Ok(_) => {
                        self.recovery.notice =
                            "Störung geändert; veralteter KI-Vorschlag verworfen.".into()
                    }
                    Err(e) => self.recovery.notice = e,
                }
            }
        }
        ui.heading("Recovery Agent");
        ui.label("Von der Störung zur geprüften Wiederherstellung eines Windows-Dienstes.");
        ui.checkbox(
            &mut self.recovery.enabled,
            "Neue Recovery-Fälle und KI-Vorschläge aktivieren",
        );
        if !self.recovery.enabled {
            ui.small(
                "Vorhandene Läufe bleiben einsehbar und können kontrolliert abgebrochen werden.",
            );
        }
        if let Some(e) = &self.recovery.error {
            ui.colored_label(tw::RED_600, e);
        }
        ui.horizontal_wrapped(|ui| {
            for (stage, label) in [
                (Stage::Intake, "1 · Störung"),
                (Stage::Rehearsal, "2 · Generalprobe"),
                (Stage::Production, "3 · Freigabe & Ausführung"),
                (Stage::Evidence, "4 · Ergebnis"),
            ] {
                ui.selectable_value(&mut self.recovery.stage, stage, label);
            }
        });
        egui::ComboBox::from_id_salt("recovery_case")
            .width(320.0)
            .selected_text(
                self.recovery
                    .selected
                    .and_then(|id| self.recovery.book.cases.iter().find(|c| c.id == id))
                    .map(|c| format!("{} · {}", c.service, c.created.format("%d.%m. %H:%M")))
                    .unwrap_or_else(|| "Noch kein gespeicherter Fall".into()),
            )
            .show_ui(ui, |ui| {
                for case in self.recovery.book.cases.iter().rev() {
                    ui.selectable_value(
                        &mut self.recovery.selected,
                        Some(case.id),
                        format!(
                            "{} · {} · {}",
                            case.service,
                            case.created.format("%d.%m. %H:%M"),
                            &case.id.to_string()[..8]
                        ),
                    );
                }
            });
        ui.separator();
        match self.recovery.stage {
            Stage::Intake => self.recovery_intake(ui),
            Stage::Rehearsal => {
                if self.recovery.selected.is_some()
                    && self.promotion.recovery_case() == self.recovery.selected
                {
                    self.promotion_view(ui);
                    if self.view == View::Execution {
                        self.view = View::Recovery;
                        self.recovery.stage = Stage::Production;
                    }
                } else {
                    ui.label("Für diesen Fall ist kein aktueller Testentwurf geladen.");
                    ui.small("Ein neuer Entwurf ersetzt den bisherigen Testentwurf und verwirft dessen Freigaben und Belegverweise.");
                    if ui
                        .add_enabled(
                            self.recovery.enabled && self.recovery.selected.is_some(),
                            egui::Button::new("Testentwurf für gewählten Fall neu vorbereiten"),
                        )
                        .clicked()
                    {
                        let case = self
                            .recovery
                            .selected
                            .and_then(|id| self.recovery.book.cases.iter().find(|c| c.id == id))
                            .cloned();
                        if let Some(case) = case {
                            let result = self
                                .promotion
                                .adopt_recovery(&case)
                                .and_then(|_| self.persist_recovery_promotion());
                            if let Err(e) = result {
                                self.recovery.notice = e.to_string();
                            }
                        }
                    }
                }
            }
            Stage::Production => {
                if let Some(id) = self.recovery.selected {
                    match self.select_recovery_execution(id) {
                        Ok(()) => self.execution_recovery_view(ui),
                        Err(e) => {
                            ui.label(e.to_string());
                        }
                    }
                } else {
                    ui.label("Zuerst einen Störungsfall und seine Generalprobe vorbereiten.");
                }
            }
            Stage::Evidence => self.recovery_evidence(ui),
        }
        ui.separator();
        ui.label(&self.recovery.notice);
        if self.recovery.planning.is_some() {
            ui.spinner();
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
    }

    fn recovery_intake(&mut self, ui: &mut Ui) {
        ui.strong("Was funktioniert nicht?");
        ui.add(egui::TextEdit::multiline(&mut self.recovery.objective).desired_width(720.0).desired_rows(3).char_limit(4096)
            .hint_text("Zum Beispiel: Die Anwendung antwortet nicht. Der zugehörige Dienst heißt AppService."));
        ui.small("Keine Passwörter oder vertraulichen Inhalte eingeben. Die KI erhält ausschließlich den unten freigegebenen Text, keine Profile oder Bildschirme.");
        ui.checkbox(
            &mut self.recovery.consent,
            "Diesen Störungstext an OpenAI senden",
        );
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(self.recovery.enabled && self.recovery.error.is_none() && self.recovery.consent
                && self.recovery.planning.is_none() && !self.recovery.objective.trim().is_empty(),
                egui::Button::new("KI-Reparaturvorschlag erstellen")).clicked() {
                let objective = self.recovery.objective.clone();
                let model = self.autopilot.settings.openai_model.clone();
                let (tx, rx) = mpsc::channel();
                self.recovery.planning = Some((objective.clone(), rx));
                self.recovery.proposal_objective = None;
                self.recovery.service.clear();
                self.recovery.rationale.clear();
                std::thread::spawn(move || {
                    let result = recovery::cloud_suggest(&objective, &model).map_err(|e| e.to_string());
                    let _ = tx.send(result);
                });
            }
            if ui.button("Vorschlag verwerfen / manuell vorbereiten").clicked() {
                self.recovery.planning = None;
                self.recovery.proposal_objective = None;
                self.recovery.service.clear();
                self.recovery.rationale.clear();
                self.recovery.notice = "Dienst selbst eingeben. Eine bereits gesendete KI-Anfrage kann noch beim Anbieter laufen.".into();
            }
        });
        ui.label(if self.recovery.proposal_objective.is_some() {
            "KI-Vorschlag — vor Übernahme prüfen"
        } else {
            "Manuelle Vorbereitung — keine KI-Diagnose"
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Exakter Windows-Dienstname");
            ui.add(egui::TextEdit::singleline(&mut self.recovery.service).char_limit(128));
        });
        ui.label("Begründung / zu prüfende Annahme");
        ui.add(
            egui::TextEdit::multiline(&mut self.recovery.rationale)
                .desired_width(720.0)
                .desired_rows(2)
                .char_limit(4096),
        );
        ui.small("Die Übernahme startet keine Verbindung. Sie ersetzt den bisherigen Testentwurf; Ziel, HTTP-Erfolgskriterien und Klon müssen anschließend ausdrücklich zugeordnet werden. Der erste Recovery-Ablauf unterstützt den Start eines gestoppten Dienstes.");
        if ui
            .add_enabled(
                self.recovery.enabled
                    && self.recovery.error.is_none()
                    && self.recovery.planning.is_none(),
                egui::Button::new("Geprüften Fall speichern und neuen Testentwurf vorbereiten"),
            )
            .clicked()
        {
            if let Err(e) = self.recovery_create_case() {
                self.recovery.notice = e.to_string();
            }
        }
    }

    fn recovery_evidence(&mut self, ui: &mut Ui) {
        let Some(case) = self
            .recovery
            .selected
            .and_then(|id| self.recovery.book.cases.iter().find(|c| c.id == id))
            .cloned()
        else {
            ui.label("Noch kein Störungsfall gespeichert.");
            return;
        };
        ui.label(&case.objective);
        ui.small(format!("Fall {} · erfasst {}", case.id, case.created));
        ui.label(format!("Geprüfte Annahme: {}", case.rationale));
        let runs = self.recovery_execution_runs();
        let outcome = recovery::outcome(&case, runs);
        ui.strong(outcome_label(outcome));
        let mut brief = format!(
            "Relayne Recovery\nFall: {}\nStörung: {}\nDienst: {}\nErgebnis: {}\n",
            case.id,
            case.objective,
            case.service,
            outcome_label(outcome)
        );
        for run in runs
            .iter()
            .filter(|r| r.recovery_case == Some(case.id) && !r.rehearsal)
        {
            ui.separator();
            ui.label(format!("Produktionslauf {} · Plan {}", run.id, run.hash));
            brief.push_str(&format!("\nLauf {} · Plan {}\n", run.id, run.hash));
            for target in &run.targets {
                let line = format!(
                    "{} · {} · {:?} · HTTP: {}",
                    target.target.name,
                    target.target.host,
                    target.phase,
                    target
                        .health
                        .as_ref()
                        .map(|h| if h.passed {
                            "bestätigt"
                        } else {
                            "fehlgeschlagen"
                        })
                        .unwrap_or("offen")
                );
                ui.label(&line);
                brief.push_str(&format!("{line}\n"));
            }
            if let Some(at) = run.finished {
                ui.small(format!("Abgeschlossen: {at}. Historischer Nachweis; keine Aussage über den aktuellen Zustand."));
                brief.push_str(&format!("Abgeschlossen: {at}\n"));
            }
        }
        ui.small("Zeitersparnis und Erfolgsquote wurden nicht gemessen. Ein laufender Dienst ohne nachgewiesene Änderung zählt hier nicht als Reparatur.");
        if ui.button("Bereinigten Ergebnisbericht kopieren").clicked() {
            ui.ctx()
                .copy_text(crate::security::redact_secret_text(&brief));
        }
    }
}
