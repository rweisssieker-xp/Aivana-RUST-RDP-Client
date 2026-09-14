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
    action: recovery::RepairAction,
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
                    Some(format!("Cannot read recovery storage: {e}")),
                ),
            };
        Self {
            selected: book.cases.last().map(|c| c.id),
            book,
            error,
            objective: String::new(),
            service: String::new(),
            rationale: String::new(),
            action: Default::default(),
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
        Outcome::Pending => "No production run yet — review target mapping and rehearsal",
        Outcome::InProgress => "Production run pending — awaiting approval or verification",
        Outcome::Verified => "Recovery confirmed by matching service and HTTP evidence",
        Outcome::Failed => "Not resolved — failure, rollback, or unknown state",
        Outcome::Unverified => "Not verified as resolved — evidence missing or mismatched",
    }
}

impl AivanaApp {
    pub(super) fn recovery_ticket_report(&self, id: Uuid) -> anyhow::Result<String> {
        let case = self
            .recovery
            .book
            .cases
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| anyhow::anyhow!("Recovery case missing"))?;
        let runs = self.recovery_execution_runs();
        let mut report = format!(
            "Historical recovery evidence (does not describe current health)\nCase: {}\nService: {}\nAction: {:?}\nJob: {}\nStatus: {}\n",
            case.id,
            case.service,
            case.action,
            case.objective,
            outcome_label(recovery::outcome(case, runs))
        );
        for run in runs
            .iter()
            .filter(|r| r.recovery_case == Some(id))
            .rev()
            .take(4)
        {
            report.push_str(&format!(
                "Run {} · Plan {} · Clone: {} · Completion: {:?}\n",
                run.id, run.hash, run.rehearsal, run.finished
            ));
            for target in &run.targets {
                report.push_str(&format!(
                    "Target {} · {:?} · Before {:?} · Baseline {:?} · After {:?}\n",
                    target.target.profile_id,
                    target.phase,
                    target.before,
                    target.baseline,
                    target.health
                ));
            }
        }
        let report = crate::security::redact_secret_text(&report);
        anyhow::ensure!(report.len() <= 16384, "Ticket report exceeds 16 KiB");
        Ok(report)
    }

    pub(super) fn import_ticket_case(
        &mut self,
        identity: &str,
        objective: String,
        service: String,
    ) -> anyhow::Result<Uuid> {
        anyhow::ensure!(
            self.recovery_actions_allowed(),
            "Recovery disabled or locked"
        );
        self.promotion.can_adopt_recovery()?;
        use sha2::{Digest, Sha256};
        anyhow::ensure!(
            !identity.is_empty() && identity.len() <= 262144,
            "Ticket identity missing or too large"
        );
        let digest = Sha256::digest(serde_json::to_vec(&(
            "relayne-ticket-case-v1",
            identity,
            &service,
        ))?);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        let id = Uuid::from_bytes(bytes);
        let mut case = Case::new(
            objective,
            Suggestion {
                action: Default::default(),
                service,
                rationale: "Explicitly reviewed ticket import; no execution approval".into(),
            },
        )?;
        case.id = id;
        let mut book = self.recovery.book.clone();
        if let Some(existing) = book.cases.iter().find(|c| c.id == id) {
            anyhow::ensure!(
                existing.objective == case.objective
                    && existing.service == case.service
                    && existing.action == case.action,
                "Ticket case identity conflicts with other content"
            );
            case = existing.clone();
        } else {
            book.cases.push(case.clone());
        }
        book.save(&app_data_file("relayne-recovery.dpapi")?)?;
        self.recovery.book = book;
        self.recovery.selected = Some(case.id);
        self.promotion.adopt_recovery(&case)?;
        self.persist_recovery_promotion()?;
        Ok(case.id)
    }
    pub(super) fn validate_recovery_action(&self, id: Uuid, restart: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recovery
                .book
                .cases
                .iter()
                .any(|c| c.id == id && (c.action == recovery::RepairAction::Restart) == restart),
            "Recovery action changed"
        );
        Ok(())
    }

    pub(super) fn recovery_objective_for(&self, id: Uuid) -> Option<String> {
        self.recovery
            .book
            .cases
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.objective.clone())
    }
    pub(super) fn recovery_actions_allowed(&self) -> bool {
        self.recovery.enabled && self.recovery.error.is_none()
    }
    pub(super) fn validate_recovery_case(&self, id: Uuid, service: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recovery.enabled,
            "New recovery jobs are disabled"
        );
        anyhow::ensure!(self.recovery.error.is_none(), "Recovery storage locked");
        anyhow::ensure!(
            self.recovery
                .book
                .cases
                .iter()
                .any(|c| c.id == id && c.service == service),
            "Incident case missing or service changed. Create a new case with a reviewed service."
        );
        Ok(())
    }

    fn recovery_create_case(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recovery.enabled && self.recovery.error.is_none(),
            "Recovery disabled or locked"
        );
        anyhow::ensure!(self.recovery.planning.is_none(), "AI suggestion still pending");
        anyhow::ensure!(
            self.recovery
                .proposal_objective
                .as_ref()
                .is_none_or(|o| o == &self.recovery.objective),
            "Incident changed since the AI suggestion; create a new suggestion or discard it"
        );
        self.promotion.can_adopt_recovery()?;
        let case = Case::new(
            self.recovery.objective.clone(),
            Suggestion {
                action: self.recovery.action,
                service: self.recovery.service.clone(),
                rationale: if self.recovery.rationale.trim().is_empty() {
                    "Service selected by operator; initial state and functional test still need verification.".into()
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
            "Case saved. Now map the target, test lab, and application HTTP test.".into();
        Ok(())
    }

    pub(super) fn recovery_view(&mut self, ui: &mut Ui) {
        if let Some((objective, rx)) = &self.recovery.planning {
            let response = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("AI request interrupted".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = response {
                let source = objective.clone();
                self.recovery.planning = None;
                match result {
                    Ok(suggestion) if source == self.recovery.objective => {
                        self.recovery.action = suggestion.action;
                        self.recovery.service = suggestion.service;
                        self.recovery.rationale = suggestion.rationale;
                        self.recovery.proposal_objective = Some(source);
                        self.recovery.notice =
                            "AI suggestion ready. Review the service and rationale before adopting it."
                                .into();
                    }
                    Ok(_) => {
                        self.recovery.notice =
                            "Incident changed; outdated AI suggestion discarded.".into()
                    }
                    Err(e) => self.recovery.notice = e,
                }
            }
        }
        ui.heading("Recovery Agent");
        ui.small("Restart: controlled stop/start. Rollback restores Running; lost process state cannot be recovered.");
        if ui.button("Open recovery plans").clicked() {
            self.view = View::RecoveryPlans;
        }
        ui.label("From incident to verified recovery of a Windows service.");
        ui.checkbox(
            &mut self.recovery.enabled,
            "Enable new recovery cases and AI suggestions",
        );
        if !self.recovery.enabled {
            ui.small(
                "Existing runs remain visible and can be canceled in a controlled way.",
            );
        }
        if let Some(e) = &self.recovery.error {
            ui.colored_label(tw::RED_600, e);
        }
        ui.horizontal_wrapped(|ui| {
            for (stage, label) in [
                (Stage::Intake, "1 · Incident"),
                (Stage::Rehearsal, "2 · Rehearsal"),
                (Stage::Production, "3 · Approval & execution"),
                (Stage::Evidence, "4 · Outcome"),
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
                    .map(|c| {
                        format!(
                            "{} · {:?} · {}",
                            c.service,
                            c.action,
                            c.created.format("%m/%d %H:%M")
                        )
                    })
                    .unwrap_or_else(|| "No saved case yet".into()),
            )
            .show_ui(ui, |ui| {
                for case in self.recovery.book.cases.iter().rev() {
                    ui.selectable_value(
                        &mut self.recovery.selected,
                        Some(case.id),
                        format!(
                            "{} · {} · {}",
                            case.service,
                            case.created.format("%m/%d %H:%M"),
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
                    ui.label("No current test draft loaded for this case.");
                    ui.small("A new draft replaces the previous test draft and discards its approvals and evidence references.");
                    if ui
                        .add_enabled(
                            self.recovery.enabled && self.recovery.selected.is_some(),
                            egui::Button::new("Prepare a new test draft for selected case"),
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
                    ui.label("Prepare an incident case and its rehearsal first.");
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
        ui.horizontal(|ui| {
            ui.label("Repair");
            ui.selectable_value(
                &mut self.recovery.action,
                recovery::RepairAction::Start,
                "Start stopped service",
            );
            ui.selectable_value(
                &mut self.recovery.action,
                recovery::RepairAction::Restart,
                "Restart running but unhealthy service",
            );
        });
        ui.strong("What is not working?");
        ui.add(egui::TextEdit::multiline(&mut self.recovery.objective).desired_width(720.0).desired_rows(3).char_limit(4096)
            .hint_text("For example: the application is not responding. Its service is named AppService."));
        ui.small("Do not enter passwords or confidential content. AI receives only the text approved below, without profiles or screens.");
        ui.checkbox(
            &mut self.recovery.consent,
            "Send this incident text to OpenAI",
        );
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(self.recovery.enabled && self.recovery.error.is_none() && self.recovery.consent
                && self.recovery.planning.is_none() && !self.recovery.objective.trim().is_empty(),
                egui::Button::new("Create AI repair suggestion")).clicked() {
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
            if ui.button("Discard suggestion / prepare manually").clicked() {
                self.recovery.planning = None;
                self.recovery.proposal_objective = None;
                self.recovery.service.clear();
                self.recovery.rationale.clear();
                self.recovery.notice = "Enter the service yourself. An AI request already sent may still be running with the provider.".into();
            }
        });
        ui.label(if self.recovery.proposal_objective.is_some() {
            "AI suggestion — review before adopting"
        } else {
            "Manual preparation — no AI diagnosis"
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Exact Windows service name");
            ui.add(egui::TextEdit::singleline(&mut self.recovery.service).char_limit(128));
        });
        ui.label("Rationale / assumption to verify");
        ui.add(
            egui::TextEdit::multiline(&mut self.recovery.rationale)
                .desired_width(720.0)
                .desired_rows(2)
                .char_limit(4096),
        );
        ui.small("Adopting does not start a connection. It replaces the previous test draft; the target, HTTP success criteria, and clone must then be explicitly mapped. Supports starting a stopped service or a controlled restart of a running service after a failed HTTP test.");
        if ui
            .add_enabled(
                self.recovery.enabled
                    && self.recovery.error.is_none()
                    && self.recovery.planning.is_none(),
                egui::Button::new("Save reviewed case and prepare new test draft"),
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
            ui.label("No incident case saved yet.");
            return;
        };
        ui.label(&case.objective);
        ui.small(format!("Case {} · captured {}", case.id, case.created));
        ui.label(format!("Reviewed assumption: {}", case.rationale));
        let runs = self.recovery_execution_runs();
        let outcome = recovery::outcome(&case, runs);
        ui.strong(outcome_label(outcome));
        let mut brief = format!(
            "Relayne Recovery\nCase: {}\nIncident: {}\nService: {}\nOutcome: {}\n",
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
            ui.label(format!("Production run {} · Plan {}", run.id, run.hash));
            brief.push_str(&format!("\nRun {} · Plan {}\n", run.id, run.hash));
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
                            "confirmed"
                        } else {
                            "failed"
                        })
                        .unwrap_or("pending")
                );
                ui.label(&line);
                brief.push_str(&format!("{line}\n"));
            }
            if let Some(at) = run.finished {
                ui.small(format!("Completed: {at}. Historical evidence; does not describe the current state."));
                brief.push_str(&format!("Completed: {at}\n"));
            }
        }
        ui.small("Time savings and success rate have not been measured. A running service without a verified change does not count as a repair here.");
        if ui.button("Copy sanitized outcome report").clicked() {
            ui.ctx()
                .copy_text(crate::security::redact_secret_text(&brief));
        }
    }
}
