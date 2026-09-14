use super::*;
use crate::intelligence::{self as intel, Dependency, Knowledge, Plan, Repair, ServiceState};
use crate::mission::{Mission, StepKind, Target};
use crate::operations::{JobQueue, JobStatus};
use std::sync::mpsc;

pub(super) struct IntelligenceState {
    diagnostic: super::diagnostic_panel::State,
    book: Knowledge,
    error: Option<String>,
    objective: String,
    plan_objective: String,
    plan: Option<Plan>,
    cloud_consent: bool,
    planning: Option<mpsc::Receiver<Result<Plan, String>>>,
    targets: Vec<Uuid>,
    service: String,
    desired: ServiceState,
    repair: Option<Uuid>,
    confirmed: bool,
    queue: JobQueue,
    pending: Option<(u64, Pending)>,
    query: String,
    dependent: Option<Uuid>,
    prerequisite: Option<Uuid>,
    dependency_reason: String,
}
enum Pending {
    Capture(Target, String, ServiceState),
    Apply(Uuid),
}
impl Default for IntelligenceState {
    fn default() -> Self {
        let (book, error) =
            match app_data_file("relayne-knowledge.dpapi").and_then(|p| Knowledge::load(&p)) {
                Ok(k) => (k, None),
                Err(e) => (
                    Knowledge::default(),
                    Some(format!("Cannot read knowledge store: {e}")),
                ),
            };
        Self {
            diagnostic: super::diagnostic_panel::State::default(),
            book,
            error,
            objective: String::new(),
            plan_objective: String::new(),
            plan: None,
            cloud_consent: false,
            planning: None,
            targets: vec![],
            service: String::new(),
            desired: ServiceState::Running,
            repair: None,
            confirmed: false,
            queue: JobQueue::default(),
            pending: None,
            query: String::new(),
            dependent: None,
            prerequisite: None,
            dependency_reason: String::new(),
        }
    }
}
impl AivanaApp {
    fn save_knowledge(&mut self) -> bool {
        if let Some(e) = &self.intelligence.error {
            self.status = e.clone();
            return false;
        }
        match app_data_file("relayne-knowledge.dpapi").and_then(|p| self.intelligence.book.save(&p))
        {
            Ok(()) => true,
            Err(e) => {
                self.status = format!("Knowledge not saved: {e}");
                false
            }
        }
    }
    pub(super) fn poll_intelligence(&mut self) {
        if let Some(rx) = &self.intelligence.planning {
            match rx.try_recv() {
                Ok(result) => {
                    self.intelligence.planning = None;
                    match result {
                        Ok(plan) => self.intelligence.plan = Some(plan),
                        Err(e) => self.status = e,
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.intelligence.planning = None;
                    self.status = "Planning job interrupted".into();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.intelligence.queue.poll();
        let Some((id, _)) = &self.intelligence.pending else {
            return;
        };
        let Some(job) = self.intelligence.queue.jobs.iter().find(|j| j.id == *id) else {
            return;
        };
        if !job.status.terminal() {
            return;
        }
        let result = job.result.clone();
        let status = job.status.clone();
        let (_, pending) = self.intelligence.pending.take().unwrap();
        self.intelligence.queue.clear_finished();
        match pending {
            Pending::Capture(target, service, desired) => {
                let captured = result
                    .as_ref()
                    .filter(|r| r.status == JobStatus::Completed && !r.truncated)
                    .ok_or_else(|| {
                        "Preflight check failed/canceled; no change".to_owned()
                    })
                    .and_then(|r| {
                        intel::captured_state(&r.stdout, &service).map_err(|e| e.to_string())
                    });
                match captured {
                    Ok(before) => {
                        let repair = Repair {
                            id: Uuid::new_v4(),
                            target,
                            service,
                            before,
                            desired,
                            captured: Utc::now(),
                            status: "Preflight check confirmed".into(),
                            evidence: None,
                        };
                        self.intelligence.repair = Some(repair.id);
                        self.intelligence.book.repairs.push(repair);
                        self.intelligence.confirmed = false;
                        self.save_knowledge();
                    }
                    Err(e) => self.status = e,
                }
            }
            Pending::Apply(id) => {
                if let Some(r) = self
                    .intelligence
                    .book
                    .repairs
                    .iter_mut()
                    .find(|r| r.id == id)
                {
                    r.status = format!("Unresolved ({status:?}); check the current state again");
                    if let Some(result) =
                        result.filter(|r| r.status == JobStatus::Completed && !r.truncated)
                    {
                        if let Err(e) = r.assess(&result.stdout) {
                            r.status = format!("Unresolved: {e}");
                        }
                    }
                    self.status = r.status.clone();
                }
                self.save_knowledge();
            }
        }
    }
    pub(super) fn intelligence_view(&mut self, ui: &mut Ui) {
        ui.heading("Plan, verify & learn");
        let diagnostic_profile = self.selected_profile().cloned();
        egui::CollapsingHeader::new("Narrow down causes with comparison tests").default_open(true).show(ui, |ui| {
            self.intelligence.diagnostic.draw(ui, diagnostic_profile.as_ref());
        });
        if let Some(e) = &self.intelligence.error {
            ui.colored_label(tw::RED_600, e);
        }
        ui.label("Describe the goal. Review the plan before adopting it as a job.");
        ui.add(egui::TextEdit::multiline(&mut self.intelligence.objective).hint_text("For example: identify why the print service stopped on the selected computers").desired_rows(2));
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.intelligence.planning.is_none(),
                    egui::Button::new("Local template"),
                )
                .clicked()
            {
                self.intelligence.plan_objective = self.intelligence.objective.clone();
                self.intelligence.plan = Some(intel::local_plan(&self.intelligence.objective));
            }
            ui.checkbox(
                &mut self.intelligence.cloud_consent,
                "Send this job text to OpenAI",
            );
            if ui
                .add_enabled(
                    self.intelligence.cloud_consent && self.intelligence.planning.is_none(),
                    egui::Button::new("Create AI plan"),
                )
                .clicked()
            {
                self.intelligence.plan = None;
                self.intelligence.plan_objective = self.intelligence.objective.clone();
                let objective = self.intelligence.objective.clone();
                let model = self.autopilot.settings.openai_model.clone();
                let (tx, rx) = mpsc::channel();
                self.intelligence.planning = Some(rx);
                std::thread::spawn(move || {
                    let result = intel::cloud_plan(&objective, &model).map_err(|e| e.to_string());
                    let _ = tx.send(result);
                });
            }
            if self.intelligence.planning.is_some() {
                ui.spinner();
            }
        });
        ui.small("Cloud planning sends only the visible job text; computer data and screens are not attached here. Key: OPENAI_API_KEY.");
        if let Some(plan) = &mut self.intelligence.plan {
            ui.label(&plan.rationale);
            for (index, step) in plan.steps.iter_mut().enumerate() {
                ui.push_id(index, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("{}.", index + 1));
                        ui.text_edit_singleline(&mut step.title);
                        egui::ComboBox::from_id_salt("kind")
                            .selected_text(format!("{:?}", step.kind))
                            .show_ui(ui, |ui| {
                                for k in [
                                    StepKind::Observe,
                                    StepKind::Operator,
                                    StepKind::WinRmInventory,
                                    StepKind::WinRmServices,
                                    StepKind::WinRmProcesses,
                                    StepKind::WinRmEvents,
                                ] {
                                    ui.selectable_value(&mut step.kind, k, format!("{k:?}"));
                                }
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Success criterion");
                        ui.text_edit_singleline(&mut step.expectation);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Rollback");
                        ui.text_edit_singleline(&mut step.recovery);
                    });
                });
            }
            ui.label("Target computers");
            for p in &self.profiles {
                if p.protocol != Protocol::Rdp {
                    continue;
                }
                let mut selected = self.intelligence.targets.contains(&p.id);
                if ui.checkbox(&mut selected, &p.name).changed() {
                    if selected {
                        self.intelligence.targets.push(p.id);
                    } else {
                        self.intelligence.targets.retain(|id| *id != p.id);
                    }
                }
            }
            if ui
                .add_enabled(
                    self.intelligence.objective == self.intelligence.plan_objective
                        && self.intelligence.planning.is_none(),
                    egui::Button::new("Adopt reviewed plan as a job"),
                )
                .clicked()
            {
                let targets = self
                    .profiles
                    .iter()
                    .filter(|p| self.intelligence.targets.contains(&p.id))
                    .map(Target::from_profile)
                    .collect();
                let result = plan
                    .mission_steps()
                    .and_then(|steps| Mission::new(&self.intelligence.objective, targets, steps));
                match result {
                    Ok(m) => {
                        let id = m.id;
                        self.missions.book.missions.push(m);
                        if self.save_missions() {
                            self.missions.selected = Some(id);
                            self.view = View::Missions;
                        } else {
                            self.missions.book.missions.retain(|m| m.id != id);
                        }
                    }
                    Err(e) => self.status = e.to_string(),
                }
            }
        }
        ui.separator();
        self.service_repair_ui(ui);
        ui.separator();
        ui.heading("Dependencies & potential causes");
        ui.label("Declared dependencies are linked to failed job steps with supporting evidence.");
        for (label, slot) in [
            ("Dependent computer", &mut self.intelligence.dependent),
            ("Requires", &mut self.intelligence.prerequisite),
        ] {
            egui::ComboBox::from_id_salt(label)
                .selected_text(
                    slot.and_then(|id| self.profiles.iter().find(|p| p.id == id))
                        .map(|p| p.name.as_str())
                        .unwrap_or(label),
                )
                .show_ui(ui, |ui| {
                    for p in &self.profiles {
                        ui.selectable_value(slot, Some(p.id), &p.name);
                    }
                });
        }
        ui.add(
            egui::TextEdit::singleline(&mut self.intelligence.dependency_reason)
                .hint_text("For example: application requires the database service"),
        );
        if ui.button("Save dependency").clicked() {
            if let (Some(a), Some(b)) =
                (self.intelligence.dependent, self.intelligence.prerequisite)
            {
                if a != b
                    && !self.intelligence.dependency_reason.trim().is_empty()
                    && self.intelligence.dependency_reason.len() <= 1024
                {
                    let previous = self.intelligence.book.dependencies.clone();
                    self.intelligence
                        .book
                        .dependencies
                        .retain(|d| !(d.dependent == a && d.prerequisite == b));
                    self.intelligence.book.dependencies.push(Dependency {
                        dependent: a,
                        prerequisite: b,
                        reason: redact_secret_text(&self.intelligence.dependency_reason),
                    });
                    if !self.save_knowledge() {
                        self.intelligence.book.dependencies = previous;
                    }
                }
            }
        }
        let name = |id: Uuid| {
            self.profiles
                .iter()
                .find(|p| p.id == id)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| id.to_string())
        };
        for candidate in
            intel::candidates(&self.missions.book, &self.intelligence.book.dependencies)
        {
            ui.collapsing(
                format!(
                    "{} → {}",
                    name(candidate.dependent),
                    name(candidate.prerequisite)
                ),
                |ui| {
                    ui.label(candidate.explanation);
                    for id in candidate.evidence {
                        ui.monospace(format!("Evidence {id}"));
                    }
                },
            );
        }
        ui.separator();
        ui.heading("Experience");
        if ui
            .button("Import confirmed and failed steps")
            .clicked()
        {
            let previous = self.intelligence.book.experiences.clone();
            self.intelligence.book.learn(&self.missions.book);
            if !self.save_knowledge() {
                self.intelligence.book.experiences = previous;
            }
        }
        ui.add(
            egui::TextEdit::singleline(&mut self.intelligence.query)
                .hint_text("Search goal, computer, prerequisite, or outcome"),
        );
        let needle = self.intelligence.query.to_lowercase();
        for e in self
            .intelligence
            .book
            .experiences
            .iter()
            .rev()
            .filter(|e| {
                format!(
                    "{} {} {} {}",
                    e.objective, e.target.name, e.prerequisites, e.outcome
                )
                .to_lowercase()
                .contains(&needle)
            })
            .take(100)
        {
            ui.collapsing(format!("{} · {}", e.target.name, e.outcome), |ui| {
                ui.label(&e.objective);
                ui.label(&e.prerequisites);
                ui.label(e.at.to_rfc3339());
                for id in &e.evidence {
                    ui.monospace(id.to_string());
                }
            });
        }
    }
    fn service_repair_ui(&mut self, ui: &mut Ui) {
        ui.heading("Repair service state");
        let profile = self.selected_profile().cloned();
        ui.label(format!(
            "Target: {}",
            profile
                .as_ref()
                .map(|p| p.name.as_str())
                .unwrap_or("Select a computer in Connections")
        ));
        ui.small("WinRM with the current Windows identity. Supports starting/stopping a service. Technical verification confirms only the service state. On failure, the previous state is restored as long as the host remains reachable.");
        ui.add(
            egui::TextEdit::singleline(&mut self.intelligence.service)
                .hint_text("Service name, e.g., Spooler"),
        );
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.intelligence.desired,
                ServiceState::Running,
                "Desired: Running",
            );
            ui.selectable_value(
                &mut self.intelligence.desired,
                ServiceState::Stopped,
                "Desired: Stopped",
            );
        });
        if ui
            .add_enabled(
                self.intelligence.pending.is_none(),
                egui::Button::new("1. Read initial state"),
            )
            .clicked()
        {
            if let Some(p) = profile.as_ref() {
                let target = Target::from_profile(p);
                let service = self.intelligence.service.trim().to_string();
                match intel::service_spec(&target, &service, None)
                    .map_err(|e| e.to_string())
                    .and_then(|spec| self.intelligence.queue.enqueue(spec))
                {
                    Ok(id) => {
                        self.intelligence.pending = Some((
                            id,
                            Pending::Capture(target, service, self.intelligence.desired),
                        ));
                        self.intelligence.repair = None;
                        self.intelligence.confirmed = false;
                    }
                    Err(e) => self.status = e,
                }
            }
        }
        if let Some(repair) = self
            .intelligence
            .repair
            .and_then(|id| self.intelligence.book.repairs.iter().find(|r| r.id == id))
            .cloned()
        {
            ui.label(format!(
                "{}: {} → {} · {}",
                repair.service,
                repair.before.label(),
                repair.desired.label(),
                repair.status
            ));
            let eligible = repair.status == "Preflight check confirmed"
                && (Utc::now() - repair.captured).num_seconds() < 120
                && profile.as_ref().is_some_and(|p| repair.target.matches(p))
                && repair.service == self.intelligence.service.trim()
                && repair.desired == self.intelligence.desired
                && repair.before != repair.desired;
            if let Ok(spec) = intel::service_spec(
                &repair.target,
                &repair.service,
                Some((repair.before, repair.desired)),
            ) {
                ui.collapsing("Review change and rollback", |ui| {
                    ui.monospace(spec.preview());
                });
                ui.checkbox(&mut self.intelligence.confirmed,"Change this service state and restore the initial state on failure");
                if ui
                    .add_enabled(
                        eligible
                            && self.intelligence.confirmed
                            && self.intelligence.pending.is_none()
                            && self.intelligence.error.is_none(),
                        egui::Button::new("2. Change and verify technically"),
                    )
                    .clicked()
                {
                    let index = self
                        .intelligence
                        .book
                        .repairs
                        .iter()
                        .position(|r| r.id == repair.id)
                        .unwrap();
                    self.intelligence.book.repairs[index].status = "Running".into();
                    if self.save_knowledge() {
                        match self.intelligence.queue.enqueue(spec) {
                            Ok(id) => {
                                self.intelligence.pending = Some((id, Pending::Apply(repair.id)))
                            }
                            Err(e) => {
                                self.intelligence.book.repairs[index].status =
                                    "Not started".into();
                                self.status = e;
                                self.save_knowledge();
                            }
                        }
                    } else {
                        self.intelligence.book.repairs[index].status =
                            "Preflight check confirmed".into();
                    }
                    self.intelligence.confirmed = false;
                }
            }
            if !eligible && repair.status == "Preflight check confirmed" {
                ui.small("Repeat the preflight check or review the target/desired state. No change is needed if the state already matches.");
            }
        }
        if let Some((id, _)) = &self.intelligence.pending {
            ui.horizontal(|ui| {
                ui.spinner();
                if ui.button("Cancel local job").clicked() {
                    if let Some(job) = self.intelligence.queue.jobs.iter().find(|j| j.id == *id) {
                        job.cancel();
                    }
                }
            });
            ui.small("Canceling cannot undo remote execution. Check again afterward.");
        }
        for r in self.intelligence.book.repairs.iter().rev().take(20) {
            ui.collapsing(
                format!("{} · {} · {}", r.target.name, r.service, r.status),
                |ui| {
                    ui.label(format!(
                        "Prerequisite: {} / {} · {}",
                        r.before.label(),
                        r.target.host,
                        r.captured
                    ));
                    if let Some(e) = &r.evidence {
                        ui.monospace(serde_json::to_string_pretty(e).unwrap_or_default());
                    }
                },
            );
        }
    }
}
