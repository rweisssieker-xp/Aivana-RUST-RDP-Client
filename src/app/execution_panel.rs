use super::*;
use crate::execution::{
    ApprovalMode, ExecutionPlan, FunctionalOutcome, FunctionalResult, HealthCheck, HealthEvidence,
    Journal, Mapping, Phase, Run,
};
use crate::intelligence::{self, ServiceState};
use crate::mission::Target;
use crate::operations::{JobQueue, JobStatus};
use crate::repair_approval::{
    self, ConsumeRepairApproval, CreateRepairApproval, ProofKind, RepairApproval, RepairBinding,
    RepairOutcome, RepairOutcomeEvent, RepairProof, RepairServiceState,
};
use std::sync::mpsc;

enum RepairWorkerResult {
    ModeVerified { origin: String, generation: Uuid },
    Requested(RepairApproval),
    Status(RepairApproval),
    Consumed(crate::repair_approval::ConsumeReceipt),
    Outcome(Uuid),
}

struct RepairWorker {
    generation: Uuid,
    run_id: Option<Uuid>,
    target_index: Option<usize>,
    binding: Option<RepairBinding>,
    receiver: mpsc::Receiver<Result<RepairWorkerResult, String>>,
}

struct RepairReceipt {
    generation: Uuid,
    run_id: Uuid,
    target_index: usize,
    binding: RepairBinding,
    approval_id: Uuid,
}

fn handoff_blocks_execution(phase: Phase, matches_current: bool) -> bool {
    matches!(phase, Phase::Capture | Phase::Apply) && !matches_current
}

pub(super) fn edit_http_steps(ui: &mut Ui, steps: &mut Vec<crate::execution::HttpGetStep>) {
    let mut remove = None;
    for (index, step) in steps.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!("Step {}", index + 2));
            ui.add(egui::TextEdit::singleline(&mut step.path).char_limit(1024));
            ui.label("Status");
            ui.add(egui::DragValue::new(&mut step.status).range(200..=599));
            if ui.small_button("Remove").clicked() {
                remove = Some(index);
            }
        });
        ui.horizontal(|ui| {
            ui.label("Response contains");
            ui.add(egui::TextEdit::singleline(&mut step.contains).char_limit(1024));
        });
        use crate::execution::http_health::Method;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut step.options.method, Method::Get, "GET");
            ui.selectable_value(&mut step.options.method, Method::Post, "POST");
        });
        if step.options.method == Method::Post {
            edit_http_fields(ui, &mut step.options.form, "Public form field", 32);
            edit_http_fields(
                ui,
                &mut step.options.secret_fields,
                "Secret field → runtime slot",
                32,
            );
        }
        ui.collapsing(format!("JSON assertions, step {}", index + 2), |ui| {
            let mut revised = std::collections::BTreeMap::new();
            for (pointer, value) in &step.options.json_equals {
                let mut pointer = pointer.clone();
                let mut value = value.clone();
                let mut remove = false;
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut pointer).char_limit(512));
                    match &mut value {
                        serde_json::Value::String(v) => {
                            ui.text_edit_singleline(v);
                        }
                        serde_json::Value::Bool(v) => {
                            ui.checkbox(v, "true");
                        }
                        _ => {
                            ui.label("null");
                        }
                    }
                    remove = ui.small_button("×").clicked();
                });
                if !remove {
                    revised.insert(pointer, value);
                }
            }
            step.options.json_equals = revised;
            ui.horizontal(|ui| {
                for (label, value) in [
                    ("String", serde_json::json!("ok")),
                    ("Bool", serde_json::json!(true)),
                    ("null", serde_json::Value::Null),
                ] {
                    if ui
                        .add_enabled(
                            step.options.json_equals.len() < 16,
                            egui::Button::new(label),
                        )
                        .clicked()
                    {
                        let key = format!("/status{}", step.options.json_equals.len() + 1);
                        step.options.json_equals.insert(key, value);
                    }
                }
            });
        });
    }
    if let Some(index) = remove {
        steps.remove(index);
    }
    if ui
        .add_enabled(
            steps.len() < 3,
            egui::Button::new("Add another HTTP check step"),
        )
        .clicked()
    {
        steps.push(crate::execution::HttpGetStep {
            path: "/health".into(),
            status: 200,
            contains: String::new(),
            options: Default::default(),
        });
    }
    ui.small("Up to four checks: first GET, then GET/POST with host-only Path=/ session cookies. JSON Pointer: string/bool/null. Secret slots require HTTPS; never enter passwords in fixed form values.");
    ui.small("POST may change application data. Automatic rollback restores the service state, not these application changes.");
}
fn edit_http_fields(
    ui: &mut Ui,
    fields: &mut crate::execution::http_health::Values,
    label: &str,
    limit: usize,
) {
    ui.collapsing(label, |ui| {
        let mut revised = Default::default();
        for (key, value) in fields.iter() {
            let mut key = key.clone();
            let mut value = value.clone();
            let mut remove = false;
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut key).char_limit(128));
                ui.add(egui::TextEdit::singleline(&mut value).char_limit(4096));
                remove = ui.small_button("×").clicked();
            });
            if !remove {
                std::collections::BTreeMap::insert(&mut revised, key, value);
            }
        }
        *fields = revised;
        if ui
            .add_enabled(fields.len() < limit, egui::Button::new("Add field"))
            .clicked()
        {
            fields.insert(format!("field{}", fields.len() + 1), String::new());
        }
    });
}

pub(super) struct ExecutionState {
    book: Journal,
    error: Option<String>,
    selected: Option<usize>,
    queue: JobQueue,
    remote: Option<u64>,
    health: Option<mpsc::Receiver<HealthEvidence>>,
    service: String,
    desired: ServiceState,
    restart: bool,
    http: bool,
    port: u16,
    tls: bool,
    path: String,
    status: u16,
    contains: String,
    followups: Vec<crate::execution::HttpGetStep>,
    http_values: String,
    http_runtime: Option<(Uuid, crate::execution::http_health::Values)>,
    mappings: Vec<(Uuid, Uuid)>,
    production: Option<Uuid>,
    staging: Option<Uuid>,
    reviewed: bool,
    distinct: bool,
    repair_worker: Option<RepairWorker>,
    repair_approval: Option<RepairApproval>,
    repair_approval_generation: Option<Uuid>,
    repair_receipt: Option<RepairReceipt>,
    repair_message: String,
    #[cfg(test)]
    journal_path_override: Option<std::path::PathBuf>,
    #[cfg(test)]
    fake_enqueue_count: Option<usize>,
}
impl Default for ExecutionState {
    fn default() -> Self {
        let (book, error) =
            match app_data_file("relayne-execution.dpapi").and_then(|p| Journal::load(&p)) {
                Ok(b) => (b, None),
                Err(e) => (
                    Journal::default(),
                    Some(format!(
                        "Cannot read journal; file remains unchanged: {e}"
                    )),
                ),
            };
        Self {
            selected: book.runs.len().checked_sub(1),
            book,
            error,
            queue: JobQueue::default(),
            remote: None,
            health: None,
            service: String::new(),
            desired: ServiceState::Running,
            restart: false,
            http: true,
            port: 80,
            tls: false,
            path: "/health".into(),
            status: 200,
            contains: String::new(),
            followups: vec![],
            http_values: "{}".into(),
            http_runtime: None,
            mappings: vec![],
            production: None,
            staging: None,
            reviewed: false,
            distinct: false,
            repair_worker: None,
            repair_approval: None,
            repair_approval_generation: None,
            repair_receipt: None,
            repair_message: String::new(),
            #[cfg(test)]
            journal_path_override: None,
            #[cfg(test)]
            fake_enqueue_count: None,
        }
    }
}
impl AivanaApp {
    pub(super) fn execution_busy(&self) -> bool {
        self.execution.remote.is_some()
            || self.execution.health.is_some()
            || self.execution.selected.is_some_and(|i| {
                self.execution
                    .book
                    .runs
                    .get(i)
                    .is_some_and(|run| run.finished.is_none())
            })
    }
    pub(super) fn diagnostic_functional_result(
        &self,
        handoff: &crate::diagnostic_lab::VerificationHandoff,
    ) -> Option<(Uuid, FunctionalResult)> {
        self.execution
            .book
            .functional_result_for(&handoff.execution_link())
    }
    pub(super) fn show_diagnostic_functional_result(
        &self,
        ui: &mut Ui,
        handoff: &crate::diagnostic_lab::VerificationHandoff,
    ) {
        if let Some(error) = &self.execution.error {
            ui.colored_label(
                tw::RED_600,
                format!(
                    "Functional verification unknown: execution journal unavailable ({error})."
                ),
            );
            return;
        }
        match self.diagnostic_functional_result(handoff) {
            None => { ui.label("Functional verification pending: no case-linked production run has observed the affected target."); }
            Some((run_id, result)) => {
                let status = match result.outcome {
                    FunctionalOutcome::Pending => "Pending",
                    FunctionalOutcome::Succeeded => "Succeeded",
                    FunctionalOutcome::Failed => "Failed",
                    FunctionalOutcome::Unknown => {
                        "Unknown — inspect the run and current system state"
                    }
                };
                ui.strong(format!("Observed check {status} · Run {run_id}"));
                ui.label(format!("Check scope: {}", result.scope));
                if let Some(at) = result.observed_at { ui.label(format!("Observed at {} UTC", at.format("%Y-%m-%d %H:%M:%S"))); }
                if let Some(detail) = result.evidence { ui.label(format!("Check evidence: {detail}")); }
            }
        }
    }
    pub(super) fn recovery_execution_runs(&self) -> &[Run] {
        &self.execution.book.runs
    }
    pub(super) fn select_recovery_execution(&mut self, id: Uuid) -> anyhow::Result<()> {
        self.execution.select_recovery(id)
    }
    pub(super) fn prepare_lab_production(
        &mut self,
        plan: ExecutionPlan,
        references: Vec<String>,
        recovery_case: Option<Uuid>,
    ) -> anyhow::Result<()> {
        self.contracts_execution_allowed(&plan, &references)?;
        if let Some(id) = recovery_case {
            self.validate_recovery_case(id, &plan.service)?;
            self.validate_recovery_action(id, plan.restart)?;
            anyhow::ensure!(
                plan.desired == ServiceState::Running,
                "Recovery supports only starting a service"
            );
        }
        anyhow::ensure!(
            self.execution.error.is_none(),
            "Execution journal locked"
        );
        anyhow::ensure!(
            !self
                .execution
                .selected
                .is_some_and(|i| self.execution.book.runs[i].finished.is_none()),
            "Complete or cancel the running job first"
        );
        crate::promotion::check_receipts(&plan, &references, Utc::now())?;
        anyhow::ensure!(
            plan.mappings
                .iter()
                .all(|m| self.profiles.iter().any(|p| m.production.matches(p))),
            "Production profile changed or removed"
        );
        let mut run = Run::new(plan, false)?;
        run.approval_mode = self.execution.book.approval_mode.clone();
        run.lab_receipts = references;
        run.recovery_case = recovery_case;
        self.execution.book.runs.push(run);
        self.execution.selected = Some(self.execution.book.runs.len() - 1);
        self.execution.reviewed = false;
        anyhow::ensure!(
            self.execution_save(),
            "Could not persist job"
        );
        self.view = View::Execution;
        self.execution_drive();
        Ok(())
    }
    fn execution_has_proof(&self, run: &Run) -> bool {
        if run
            .plan
            .mappings
            .iter()
            .any(|m| m.staging.protocol == crate::promotion::LAB_PROTOCOL)
        {
            if self
                .contracts_execution_allowed(&run.plan, &run.lab_receipts)
                .is_err()
            {
                return false;
            }
            crate::promotion::check_receipts(&run.plan, &run.lab_receipts, Utc::now()).is_ok()
        } else {
            self.execution
                .book
                .runs
                .iter()
                .any(|proof| proof.proof_for(&run.plan, Utc::now()))
        }
    }

    fn repair_binding(&self, index: usize) -> anyhow::Result<RepairBinding> {
        let now = Utc::now();
        let run = self
            .execution
            .book
            .runs
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("Repair run missing"))?;
        anyhow::ensure!(
            !run.rehearsal && run.finished.is_none() && run.current < run.targets.len(),
            "Production target unavailable"
        );
        anyhow::ensure!(run.hash == run.plan.hash()?, "Plan changed");
        anyhow::ensure!(
            run.current < 32
                && run
                    .plan
                    .mappings
                    .get(run.current)
                    .is_some_and(|m| run.targets[run.current].target.same_endpoint(&m.production)),
            "Target changed"
        );
        let t = &run.targets[run.current];
        anyhow::ensure!(
            matches!(t.phase, Phase::Review | Phase::Apply),
            "Target is not in review"
        );
        let before = t
            .before
            .ok_or_else(|| anyhow::anyhow!("Initial state missing"))?;
        let captured = t
            .captured
            .ok_or_else(|| anyhow::anyhow!("Initial capture missing"))?;
        let baseline = t
            .baseline
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Baseline missing"))?;
        anyhow::ensure!(
            (0..120).contains(&(now - captured).num_seconds()) && baseline.at >= captured && baseline.at <= now,
            "Initial finding expired; recapture and request again"
        );
        anyhow::ensure!(
            !run.plan.restart || (before == ServiceState::Running && !baseline.passed),
            "Restart prerequisites changed"
        );
        anyhow::ensure!(
            self.profiles.iter().any(|p| t.target.matches(p)),
            "Profile changed"
        );
        anyhow::ensure!(
            self.execution_has_proof(run),
            "Test proof changed or expired"
        );
        anyhow::ensure!(
            run.recovery_case.is_none() || self.recovery_actions_allowed(),
            "Recovery contract changed"
        );
        anyhow::ensure!(
            self.verification_handoff
                .as_ref()
                .is_none_or(|h| run.matches_diagnostic(&h.execution_link())),
            "Diagnostic case target changed"
        );
        anyhow::ensure!(self.execution.error.is_none(), "Journal unavailable");
        let proof = if !run.lab_receipts.is_empty() {
            let mut receipts = run
                .lab_receipts
                .iter()
                .map(|r| crate::test_lab::load_receipt(r))
                .collect::<anyhow::Result<Vec<_>>>()?;
            receipts.sort_by_key(|r| r.id);
            let reference = receipts
                .iter()
                .find(|r| {
                    run.plan.mappings[run.current]
                        .staging
                        .profile_id
                        .to_string()
                        == r.lab_id
                })
                .ok_or_else(|| anyhow::anyhow!("Matching lab proof missing"))?;
            RepairProof {
                kind: ProofKind::Lab,
                reference_id: reference.id,
                sha256: repair_approval::digest(b"relayne-repair-lab-proof-v1", &receipts)?,
                expires_at: receipts
                    .iter()
                    .map(|r| r.finished + chrono::Duration::hours(1))
                    .min()
                    .ok_or_else(|| anyhow::anyhow!("Lab proof missing"))?,
            }
        } else {
            let proof = self
                .execution
                .book
                .runs
                .iter()
                .rev()
                .find(|p| p.proof_for(&run.plan, now))
                .ok_or_else(|| anyhow::anyhow!("Matching rehearsal proof missing"))?;
            RepairProof {
                kind: ProofKind::Rehearsal,
                reference_id: proof.id,
                sha256: repair_approval::digest(b"relayne-repair-rehearsal-proof-v1", proof)?,
                expires_at: proof
                    .finished
                    .ok_or_else(|| anyhow::anyhow!("Rehearsal unfinished"))?
                    + chrono::Duration::hours(1),
            }
        };
        let state = |s| match s {
            ServiceState::Running => RepairServiceState::Running,
            ServiceState::Stopped => RepairServiceState::Stopped,
        };
        let target = &t.target;
        let binding = RepairBinding {
            version: 1,
            run_id: run.id,
            target_index: run.current as u8,
            profile_id: target.profile_id,
            plan_sha256: run.hash.clone(),
            target_sha256: repair_approval::digest(
                b"relayne-repair-endpoint-v1",
                &(
                    target.profile_id,
                    &target.host,
                    target.port,
                    &target.protocol,
                    &target.username,
                    &target.domain,
                    &target.route,
                ),
            )?,
            service: run.plan.service.clone(),
            before: state(before),
            desired: state(run.plan.desired),
            captured_at: captured,
            baseline_passed: baseline.passed,
            baseline_sha256: repair_approval::digest(
                b"relayne-repair-baseline-v1",
                &(before, captured, baseline),
            )?,
            health_sha256: repair_approval::digest(b"relayne-repair-health-v1", &run.plan.health)?,
            proof,
        };
        binding.validate(now)?;
        Ok(binding)
    }

    fn start_repair_worker(
        &mut self,
        run_id: Option<Uuid>,
        target_index: Option<usize>,
        binding: Option<RepairBinding>,
        work: impl FnOnce(crate::team_client::TeamClient) -> anyhow::Result<RepairWorkerResult>
        + Send
        + 'static,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.execution.repair_worker.is_none(),
            "Team action already in progress"
        );
        let (client, generation, _) = self.team.repair_client()?;
        let (tx, rx) = mpsc::channel();
        self.execution.repair_worker = Some(RepairWorker {
            generation,
            run_id,
            target_index,
            binding,
            receiver: rx,
        });
        std::thread::spawn(move || {
            let _ =
                tx.send(work(client).map_err(|_| {
                    "Team repair action unavailable; no Apply authorization".to_owned()
                }));
        });
        Ok(())
    }

    fn poll_repair_worker(&mut self) {
        let Some(worker) = self.execution.repair_worker.as_ref() else {
            return;
        };
        let result = match worker.receiver.try_recv() {
            Ok(v) => v,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("Team repair connection ended; no Apply authorization".into())
            }
        };
        let worker = self.execution.repair_worker.take().unwrap();
        if worker.generation != self.team.repair_generation() {
            self.execution.repair_message =
                "Team identity changed; approval action discarded".into();
            self.execution.repair_approval = None;
            self.execution.repair_receipt = None;
            return;
        }
        if worker.run_id.is_some_and(|run_id| {
            self.execution.selected.and_then(|i| self.execution.book.runs.get(i))
                .is_none_or(|r| r.id != run_id || Some(r.current) != worker.target_index)
        }) {
            self.execution.repair_message = "Run or target changed; approval action discarded".into();
            return;
        }
        match result {
            Err(message) => {
                self.execution.repair_message = message;
                self.execution.repair_receipt = None;
            }
            Ok(RepairWorkerResult::ModeVerified { origin, generation }) => {
                if generation == self.team.repair_generation() && !self.execution_busy() {
                    self.execution.book.approval_mode = ApprovalMode::TeamControlled {
                        server_origin: origin,
                    };
                    if self.execution_save() {
                        self.execution.repair_message = "Team-controlled repair enabled".into();
                    }
                }
            }
            Ok(RepairWorkerResult::Requested(item) | RepairWorkerResult::Status(item)) => {
                if worker.binding.as_ref().is_some_and(|b| {
                    *b == item.binding
                        && b.fingerprint()
                            .is_ok_and(|fingerprint| fingerprint == item.fingerprint)
                }) && item.id != Uuid::nil()
                    && (item.expires_at > Utc::now()
                        || item.state == repair_approval::RepairState::Expired)
                {
                    self.execution.repair_message = format!(
                        "Approval {:?} · fingerprint {}",
                        item.state, item.fingerprint
                    );
                    self.execution.repair_approval = Some(item);
                    self.execution.repair_approval_generation = Some(worker.generation);
                } else {
                    self.execution.repair_message =
                        "Approval binding changed; request discarded".into();
                    self.execution.repair_approval = None;
                }
            }
            Ok(RepairWorkerResult::Consumed(receipt)) => {
                let Some(i) = self.execution.selected else {
                    return;
                };
                let Some(binding) = worker.binding else {
                    return;
                };
                let matches = self
                    .repair_binding(i)
                    .is_ok_and(|current| current == binding)
                    && receipt.consume_id != Uuid::nil()
                    && binding
                        .fingerprint()
                        .is_ok_and(|fingerprint| fingerprint == receipt.fingerprint)
                    && self.execution.repair_approval.as_ref().is_some_and(|a| {
                        a.id == receipt.approval_id
                            && a.fingerprint == receipt.fingerprint
                            && a.binding == binding
                    });
                if !matches {
                    self.execution.repair_message = "Approval consumed, but local evidence changed; Apply blocked. Recapture and request again".into();
                    self.execution.repair_approval = None;
                    return;
                }
                self.execution.repair_receipt = Some(RepairReceipt {
                    generation: worker.generation,
                    run_id: binding.run_id,
                    target_index: binding.target_index as usize,
                    binding,
                    approval_id: receipt.approval_id,
                });
                let current = self.execution.book.runs[i].current;
                self.execution.book.runs[i].targets[current].phase = Phase::Apply;
                if !self.execution_save() {
                    self.execution.repair_receipt = None;
                    return;
                }
                self.execution.repair_message =
                    "Approval consumed; applying reviewed change".into();
                self.execution_drive();
            }
            Ok(RepairWorkerResult::Outcome(event_id)) => {
                for run in &mut self.execution.book.runs {
                    for target in &mut run.targets {
                    if let Some(marker) = &mut target.outcome
                        && marker.event.event_id == event_id
                    {
                        marker.delivered = true;
                        }
                    }
                }
                if self.execution_save() {
                    self.execution.repair_message = "Outcome recorded centrally".into();
                }
            }
        }
    }

    fn sync_repair_outcomes(&mut self) {
        let mut changed = false;
        for run in &mut self.execution.book.runs {
            if !matches!(run.approval_mode, ApprovalMode::TeamControlled { .. }) {
                continue;
            }
            for (index, target) in run.targets.iter_mut().enumerate() {
                if !target.apply_attempted || target.outcome.is_some() {
                    continue;
                }
                let Some(approval_id) = target.approval_id else {
                    continue;
                };
                let outcome = match target.phase {
                    Phase::Passed => RepairOutcome::Passed,
                    Phase::Failed => RepairOutcome::Failed,
                    Phase::Restored => RepairOutcome::Restored,
                    Phase::Unknown => RepairOutcome::Unknown,
                    _ => continue,
                };
                target.outcome = Some(crate::execution::PendingRepairOutcome {
                    event: RepairOutcomeEvent {
                        event_id: Uuid::new_v4(),
                        approval_id,
                        run_id: run.id,
                        target_index: index as u8,
                        outcome,
                        occurred_at: Utc::now(),
                    },
                    delivered: false,
                });
                changed = true;
            }
        }
        if changed {
            let _ = self.execution_save();
        }
    }
    pub(super) fn execution_incident_records(&self) -> Vec<crate::incident::Record> {
        use crate::incident::{Kind, Record};
        let mut records = Vec::new();
        for run in &self.execution.book.runs {
            for target in &run.targets {
                if let Some(at) = target.captured {
                    records.push(Record {
                        id: format!("execution:{}:{}:capture", run.id, target.target.profile_id),
                        profile: Some(target.target.profile_id),
                        endpoint: Some(crate::incident::endpoint_key(&target.target)),
                        at,
                        kind: Kind::Observation,
                        title: format!(
                            "{} · {}: Initial state {:?}{}",
                            target.target.name,
                            run.plan.service,
                            target.before,
                            if run.rehearsal { " (test run)" } else { "" }
                        ),
                        evidence: vec![run.id.to_string(), run.hash.clone()],
                    });
                }
                if let Some(health) = &target.health {
                    records.push(Record {
                        id: format!("execution:{}:{}:health", run.id, target.target.profile_id),
                        profile: Some(target.target.profile_id),
                        endpoint: Some(crate::incident::endpoint_key(&target.target)),
                        at: health.at,
                        kind: if health.passed {
                            Kind::Observation
                        } else {
                            Kind::Failure
                        },
                        title: format!(
                            "{} · {}: {}",
                            target.target.name, run.plan.service, health.detail
                        ),
                        evidence: vec![run.id.to_string(), run.hash.clone()],
                    });
                }
            }
        }
        records
    }
    pub(super) fn execution_lessons(&self) -> Vec<crate::execution::ExecutionLesson> {
        if self.execution.error.is_some() {
            return vec![];
        }
        self.execution.book.lessons()
    }

    pub(super) fn ranked_execution_lessons(
        &self,
        target: &crate::mission::Target,
    ) -> Vec<crate::execution::learning::RankedLesson> {
        if self.execution.error.is_some() {
            return Vec::new();
        }
        crate::execution::learning::rank(&self.execution.book, target, Utc::now())
    }

    pub(super) fn repair_impact(
        &self,
        target: &crate::mission::Target,
    ) -> Option<crate::execution::impact::Report> {
        if self.execution.error.is_some() {
            return None;
        }
        Some(crate::execution::impact::report(
            &self.execution.book,
            target,
            Utc::now(),
        ))
    }
    pub(super) fn use_execution_lesson(&mut self, lesson: &crate::execution::ExecutionLesson) {
        if self
            .execution
            .selected
            .is_some_and(|i| self.execution.book.runs[i].finished.is_none())
        {
            self.status =
                "Complete or cancel the running execution job first.".into();
            return;
        }
        self.execution.service = lesson.service.clone();
        self.execution.desired = lesson.desired;
        self.execution.restart = lesson.restart;
        match &lesson.health {
            HealthCheck::Tcp { port } => {
                self.execution.http = false;
                self.execution.port = *port;
                self.execution.tls = false;
                self.execution.path = "/health".into();
                self.execution.status = 200;
                self.execution.contains.clear();
                self.execution.followups.clear();
            }
            HealthCheck::Http {
                port,
                tls,
                path,
                status,
                contains,
                followups,
            } => {
                self.execution.http = true;
                self.execution.port = *port;
                self.execution.tls = *tls;
                self.execution.path = path.clone();
                self.execution.status = *status;
                self.execution.contains = contains.clone();
                self.execution.followups = followups.clone();
            }
        }
        self.execution.mappings.clear();
        self.execution.production = None;
        self.execution.staging = None;
        self.execution.reviewed = false;
        self.execution.distinct = false;
        self.status = "Solution adopted as a draft. Map new production/test targets and review the test run.".into();
    }
    fn execution_save(&mut self) -> bool {
        if self.execution.error.is_some() {
            return false;
        }
        #[cfg(test)]
        let path = self
            .execution
            .journal_path_override
            .clone()
            .map(Ok)
            .unwrap_or_else(|| app_data_file("relayne-execution.dpapi"));
        #[cfg(not(test))]
        let path = app_data_file("relayne-execution.dpapi");
        if let Err(e) = path.and_then(|p| self.execution.book.save(&p)) {
            self.execution.error = Some(format!(
                "Could not save journal. Execution blocked; manually check the active host: {e}"
            ));
            return false;
        }
        true
    }
    fn execution_plan(&self) -> anyhow::Result<ExecutionPlan> {
        let mut mappings = vec![];
        for (p, s) in &self.execution.mappings {
            let production = self
                .profiles
                .iter()
                .find(|v| v.id == *p)
                .ok_or_else(|| anyhow::anyhow!("Production profile missing"))?;
            let staging = self
                .profiles
                .iter()
                .find(|v| v.id == *s)
                .ok_or_else(|| anyhow::anyhow!("Test profile missing"))?;
            mappings.push(Mapping {
                production: Target::from_profile(production),
                staging: Target::from_profile(staging),
            });
        }
        let e = &self.execution;
        let plan = ExecutionPlan {
            restart: e.restart,
            service: e.service.trim().into(),
            desired: e.desired,
            mappings,
            health: if e.http {
                HealthCheck::Http {
                    port: e.port,
                    tls: e.tls,
                    path: e.path.clone(),
                    status: e.status,
                    contains: e.contains.clone(),
                    followups: e.followups.clone(),
                }
            } else {
                HealthCheck::Tcp { port: e.port }
            },
        };
        plan.validate()?;
        Ok(plan)
    }
    fn execution_fail(&mut self, message: String) {
        if let Some(i) = self.execution.selected {
            let r = &mut self.execution.book.runs[i];
            r.fail_current(message);
        }
        self.execution_save();
    }
    pub(super) fn poll_execution(&mut self) {
        if self
            .execution
            .repair_approval_generation
            .is_some_and(|g| g != self.team.repair_generation())
        {
            self.execution.repair_approval = None;
            self.execution.repair_approval_generation = None;
            self.execution.repair_receipt = None;
        }
        self.poll_repair_worker();
        self.sync_repair_outcomes();
        self.execution.queue.poll();
        // Cancelled jobs may finish after their run has been detached.
        if self.execution.remote.is_none() {
            self.execution.queue.clear_finished();
        }
        let Some(i) = self.execution.selected else {
            return;
        };
        if let Some(id) = self.execution.remote {
            let Some(job) = self.execution.queue.jobs.iter().find(|j| j.id == id) else {
                return;
            };
            if !job.status.terminal() {
                return;
            }
            let result = job.result.clone();
            self.execution.remote = None;
            self.execution.queue.clear_finished();
            let Some(result) = result.filter(|r| r.status == JobStatus::Completed && !r.truncated)
            else {
                self.execution_fail("Job failed/canceled: remote state unknown, no retry".into());
                return;
            };
            let r = &mut self.execution.book.runs[i];
            let phase = r.targets[r.current].phase;
            let result = if phase == Phase::Capture {
                intelligence::captured_state(&result.stdout, &r.plan.service).map(|before| {
                    let t = &mut r.targets[r.current];
                    t.before = Some(before);
                    t.captured = Some(Utc::now());
                    t.evidence
                        .push(crate::security::redact_secret_text(&result.stdout));
                    t.phase = Phase::Baseline;
                })
            } else {
                r.assess_mutation(&result.stdout, phase == Phase::Restore)
            };
            if let Err(e) = result {
                self.execution_fail(e.to_string());
                return;
            }
            self.execution.book.runs[i].advance();
            if !self.execution_save() {
                return;
            }
        }
        if let Some(rx) = &self.execution.health {
            let result = match rx.try_recv() {
                Ok(e) => Some(e),
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => Some(HealthEvidence {
                    at: Utc::now(),
                    passed: false,
                    detail: "Health check worker interrupted".into(),
                }),
            };
            self.execution.health = None;
            let r = &mut self.execution.book.runs[i];
            let evidence = result.unwrap();
            if let Err(e) = r.finish_health(evidence) {
                self.execution_fail(e.to_string());
                return;
            }
            self.execution.reviewed = false;
            if !self.execution_save() {
                return;
            }
        }
        self.execution_drive();
    }
    fn execution_drive(&mut self) {
        if self.execution.error.is_some()
            || self.execution.remote.is_some()
            || self.execution.health.is_some()
        {
            return;
        }
        let Some(i) = self.execution.selected else {
            return;
        };
        let r = &self.execution.book.runs[i];
        if handoff_blocks_execution(
            r.targets[r.current].phase,
            self.verification_handoff
                .as_ref()
                .is_none_or(|handoff| r.matches_diagnostic(&handoff.execution_link())),
        ) {
            self.status = "Selected execution run does not match the active diagnostic case and target; dismiss the handoff or select its linked run.".into();
            return;
        }
        if r.finished.is_some() {
            self.execution.http_runtime = None;
            return;
        }
        let t = &r.targets[r.current];
        let phase = t.phase;
        if matches!(
            phase,
            Phase::Review | Phase::Unknown | Phase::Failed | Phase::Restored | Phase::Passed
        ) {
            return;
        }
        // Bind ephemeral values once to this run before any remote change. Keep through verification/restore.
        if phase != Phase::Restore
            && self
                .execution
                .http_runtime
                .as_ref()
                .is_none_or(|(id, _)| *id != r.id)
        {
            let values: crate::execution::http_health::Values = match serde_json::from_str(
                &self.execution.http_values,
            ) {
                Ok(values) => values,
                Err(_) => {
                    self.execution_fail("HTTP runtime values require a JSON object of strings; execution not started".into());
                    return;
                }
            };
            if r.plan.health.validate_values(&values).is_err() {
                self.execution_fail(
                    "HTTP secret slots missing or invalid; execution not started"
                        .into(),
                );
                return;
            }
            self.execution.http_runtime = Some((r.id, values));
            self.execution.http_values = "{}".into();
        }
        if phase == Phase::Apply
            && (t.before.is_none()
                || t.baseline.is_none()
                || (r.plan.restart
                    && (t.before != Some(ServiceState::Running)
                        || !t.baseline.as_ref().is_some_and(|b| !b.passed)))
                || !t
                    .captured
                    .is_some_and(|at| (0..120).contains(&(Utc::now() - at).num_seconds())))
        {
            self.execution_fail("Initial finding missing or outdated; change blocked".into());
            return;
        }
        if phase == Phase::Restore && t.before.is_none() {
            self.execution_fail("Initial state unknown; restoration requires manual review".into());
            return;
        }
        // Rehearsal proof authorizes initial production run; each mutation also checks freshness.
        if phase == Phase::Apply && !r.rehearsal && !self.execution_has_proof(r) {
            self.execution_fail("Test evidence expired or changed; production not started".into());
            return;
        }
        if phase != Phase::Restore && !self.profiles.iter().any(|p| t.target.matches(p)) {
            self.execution_fail(
                "Profile changed or removed; immutable target snapshot no longer matches"
                    .into(),
            );
            return;
        }
        let consumed_approval = if phase == Phase::Apply
            && matches!(r.approval_mode, ApprovalMode::TeamControlled { .. })
        {
            let binding = self.repair_binding(i);
            let receipt = self.execution.repair_receipt.as_ref();
            match (binding, receipt) {
                (Ok(binding), Some(receipt))
                    if receipt.generation == self.team.repair_generation()
                        && receipt.run_id == r.id
                        && receipt.target_index == r.current
                        && receipt.binding == binding =>
                {
                    Some(receipt.approval_id)
                }
                _ => {
                    self.execution.repair_receipt = None;
                    let current = self.execution.book.runs[i].current;
                    self.execution.book.runs[i].targets[current].phase = Phase::Review;
                    self.execution.repair_message =
                        "Matching one-use team approval missing or evidence changed; Apply blocked"
                            .into();
                    let _ = self.execution_save();
                    return;
                }
            }
        } else {
            None
        };
        if matches!(phase, Phase::Baseline | Phase::Verify) {
            let check = r.plan.health.clone();
            let target = t.target.clone();
            let values = self
                .execution
                .http_runtime
                .as_ref()
                .filter(|(id, _)| *id == r.id)
                .map(|(_, values)| values.clone())
                .unwrap_or_default();
            if !self.execution_save() {
                return;
            }
            let (tx, rx) = mpsc::channel();
            self.execution.health = Some(rx);
            std::thread::spawn(move || {
                let _ = tx.send(check.probe_with_values(&target, &values));
            });
            return;
        }
        let change = match phase {
            Phase::Apply => Some((t.before.unwrap(), r.plan.desired)),
            Phase::Restore => Some((r.plan.desired, t.before.unwrap())),
            _ => None,
        };
        let spec = if phase == Phase::Apply && r.plan.restart {
            intelligence::restart_spec(&t.target, &r.plan.service)
        } else {
            intelligence::service_spec(&t.target, &r.plan.service, change)
        };
        match spec {
            Ok(spec) => {
                if let Some(approval_id) = consumed_approval {
                    let current = self.execution.book.runs[i].current;
                    let target = &mut self.execution.book.runs[i].targets[current];
                    target.approval_id = Some(approval_id);
                    target.apply_attempted = true;
                }
                if !self.execution_save() {
                    self.execution.repair_receipt = None;
                    return;
                }
                if consumed_approval.is_some() {
                    self.execution.repair_receipt = None;
                }
                #[cfg(test)]
                let enqueued = if let Some(count) = &mut self.execution.fake_enqueue_count {
                    *count += 1;
                    Ok(1)
                } else {
                    self.execution.queue.enqueue(spec)
                };
                #[cfg(not(test))]
                let enqueued = self.execution.queue.enqueue(spec);
                match enqueued {
                    Ok(id) => self.execution.remote = Some(id),
                    Err(e) => self.execution_fail(e),
                }
            }
            Err(e) => self.execution_fail(e.to_string()),
        }
    }
    pub(super) fn execution_view(&mut self, ui: &mut Ui) {
        self.execution_content(ui, false);
    }
    pub(super) fn execution_recovery_view(&mut self, ui: &mut Ui) {
        self.execution_content(ui, true);
    }
    fn execution_content(&mut self, ui: &mut Ui, recovery_only: bool) {
        ui.heading("Reviewed execution & test run");
        match self.execution.book.approval_mode.clone() {
            ApprovalMode::Standalone => {
                ui.label("Repair authority: Standalone local review");
                if ui
                    .add_enabled(
                        !self.execution_busy() && self.execution.repair_worker.is_none(),
                        egui::Button::new("Enable team-controlled repair for future runs"),
                    )
                    .clicked()
                {
                    match self.team.repair_client() {
                        Ok((_, generation, origin)) => {
                            if let Err(e) =
                                self.start_repair_worker(None, None, None, move |client| {
                                    let snapshot = client.snapshot()?;
                                    anyhow::ensure!(
                                        snapshot.role != crate::team_server::Role::Viewer,
                                        "Operator identity required"
                                    );
                                    Ok(RepairWorkerResult::ModeVerified { origin, generation })
                                })
                            {
                                self.execution.repair_message = e.to_string();
                            }
                        }
                        Err(e) => self.execution.repair_message = e.to_string(),
                    }
                }
            }
            ApprovalMode::TeamControlled { server_origin } => {
                ui.strong(format!(
                    "Repair authority: Team-controlled · {server_origin}"
                ));
                ui.small("Every new production Apply requires a separate consumed team approval. Service restoration after a launched Apply remains local.");
            }
        }
        if self.execution.repair_worker.is_some() {
            ui.spinner();
        }
        if !self.execution.repair_message.is_empty() {
            ui.label(&self.execution.repair_message);
        }
        if let Some(handoff) = &self.verification_handoff {
            ui.group(|ui| {
                ui.strong("Diagnostic Lab functional verification handoff");
                ui.label(format!("Incident: {} · Case {}", handoff.incident, handoff.case_id));
                ui.label(format!("Original target: {} · Profile {}", handoff.target.host, handoff.target.profile_id));
                ui.small(format!("Diagnostic binding: {} · Source record: {} · Evidence IDs: {}", handoff.binding, handoff.source_record.as_deref().unwrap_or("standalone case"), handoff.source_evidence.join(" · ")));
                if !self.selected_profile().is_some_and(|p| handoff.target.matches(p)) {
                    ui.colored_label(tw::RED_600, "The original Windows profile changed or is not selected. This handoff cannot verify another target.");
                } else {
                    ui.label("Prepare one production/test mapping with this exact production target. The existing review, rehearsal proof and journal gates still apply.");
                }
                self.show_diagnostic_functional_result(ui, handoff);
            });
            if ui.button("Dismiss incident handoff and use standalone execution").clicked() {
                self.verification_handoff = None;
            }
        }
        ui.label("HTTP runtime slots as JSON (memory only; enter again for production access)");
        let runtime_editable = self.execution.http_runtime.is_none()
            && self.execution.remote.is_none()
            && self.execution.health.is_none();
        ui.add_enabled(
            runtime_editable,
            egui::TextEdit::singleline(&mut self.execution.http_values)
                .password(true)
                .char_limit(32768),
        );
        if ui
            .add_enabled(
                runtime_editable,
                egui::Button::new("Clear HTTP runtime values"),
            )
            .clicked()
        {
            self.execution.http_values = "{}".into();
        }
        if self.execution.http_runtime.is_some() {
            ui.small(
                "Runtime values bound immutably to this job; remain in memory until completion.",
            );
        }
        ui.label("Diagnosis → reviewed service change → functional test → rollback on failure. Test environment first, then a pilot and individually approved additional targets.");
        ui.small("WinRM uses the current Windows identity. Health checks run from the Relayne computer. Test runs modify real test systems you select.");
        if let Some(e) = &self.execution.error {
            ui.colored_label(tw::RED_600, e);
        }
        if !recovery_only {
            let busy = self
                .execution
                .selected
                .is_some_and(|i| self.execution.book.runs[i].finished.is_none());
            ui.add_enabled_ui(!busy, |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.execution.restart, "Controlled restart (Running + failed HTTP test)");
                  ui.label("Service"); ui.text_edit_singleline(&mut self.execution.service);
                ui.selectable_value(&mut self.execution.desired, ServiceState::Running, "Running");
                ui.selectable_value(&mut self.execution.desired, ServiceState::Stopped, "Stopped");
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.execution.http, "HTTP functional test (otherwise TCP)");
                ui.label("Port"); ui.add(egui::DragValue::new(&mut self.execution.port).range(1..=65535));
                if self.execution.http { ui.checkbox(&mut self.execution.tls, "HTTPS"); ui.label("Status"); ui.add(egui::DragValue::new(&mut self.execution.status).range(200..=599)); }
            });
            if self.execution.http {
                ui.horizontal(|ui| { ui.label("Path"); ui.text_edit_singleline(&mut self.execution.path); });
                edit_http_steps(ui, &mut self.execution.followups);
                ui.horizontal(|ui| { ui.label("Response contains (public pattern)"); ui.text_edit_singleline(&mut self.execution.contains); });
                ui.small("No credentials in fixed values. GET/POST and session cookies, no redirects or response storage, 64 KiB response limit. Runtime slots require HTTPS.");
            }
            for (label, slot) in [("Production", &mut self.execution.production), ("Test/Staging", &mut self.execution.staging)] {
                egui::ComboBox::from_id_salt(label).selected_text(slot.and_then(|id| self.profiles.iter().find(|p| p.id==id)).map(|p| p.name.as_str()).unwrap_or(label))
                    .show_ui(ui, |ui| { for p in &self.profiles { if p.protocol == Protocol::Rdp { ui.selectable_value(slot, Some(p.id), format!("{} · {}",p.name,p.host)); } } });
            }
            if ui.button("Add target mapping").clicked() {
                if let (Some(p),Some(s))=(self.execution.production,self.execution.staging) { self.execution.mappings.push((p,s)); self.execution.reviewed=false; }
            }
            let mut remove=None;
            for (i,(p,s)) in self.execution.mappings.iter().enumerate() {
                let name=|id| self.profiles.iter().find(|p| p.id==id).map(|p|format!("{} ({})",p.name,p.host)).unwrap_or_else(||"Profile missing".into());
                ui.horizontal(|ui| { ui.label(format!("{}: {} → {}", if i==0 {"Pilot"} else {"Rollout"},name(*p),name(*s))); if ui.small_button("Remove").clicked(){remove=Some(i);} });
            }
            if let Some(i)=remove {self.execution.mappings.remove(i);self.execution.reviewed=false;}
            ui.checkbox(&mut self.execution.distinct,"I verified that test hosts are separate systems, not production DNS aliases, and actual changes are permitted there.");
        });
            let plan = self.execution_plan();
            if let Ok(p) = &plan {
                ui.monospace(format!("Plan SHA-256: {}", p.hash().unwrap_or_default()));
                let proof = self
                    .execution
                    .book
                    .runs
                    .iter()
                    .any(|r| r.proof_for(p, Utc::now()));
                ui.label(if proof {
                    "Matching successful test run available (up to 1 hour old)."
                } else {
                    "No valid test evidence for this exact plan and target mapping."
                });
                let handoff_plan_ok = self.verification_handoff.as_ref().is_none_or(|handoff| {
                    self.selected_profile().is_some_and(|profile| handoff.target.matches(profile))
                        && p.mappings.len() == 1
                        && p.mappings[0].production.same_endpoint(&handoff.target)
                });
                if !handoff_plan_ok {
                    ui.colored_label(tw::RED_600, "Active incident handoff requires one mapping with its unchanged production target. Dismiss it to prepare an unrelated run.");
                }
                let mut start = None;
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !busy && self.execution.error.is_none() && self.execution.distinct && handoff_plan_ok,
                            egui::Button::new("Prepare test run"),
                        )
                        .clicked()
                    {
                        start = Some(true);
                    }
                    if ui
                        .add_enabled(
                            !busy
                                && proof
                                && self.execution.error.is_none()
                                && self.execution.distinct
                                && handoff_plan_ok,
                            egui::Button::new("Prepare production pilot"),
                        )
                        .clicked()
                    {
                        start = Some(false);
                    }
                });
                if let Some(rehearsal) = start {
                    match Run::new(p.clone(), rehearsal).and_then(|mut run| {
                        if let Some(handoff) = &self.verification_handoff {
                            run.bind_diagnostic(handoff.execution_link())?;
                        }
                        Ok(run)
                    }) {
                        Ok(r) => {
                            let mut r = r;
                            r.approval_mode = self.execution.book.approval_mode.clone();
                            self.execution.book.runs.push(r);
                            self.execution.selected = Some(self.execution.book.runs.len() - 1);
                            self.execution.reviewed = false;
                            if self.execution_save() {
                                self.execution_drive();
                            }
                        }
                        Err(e) => self.status = e.to_string(),
                    }
                }
            } else if let Err(e) = plan {
                ui.small(e.to_string());
            }
        }
        ui.separator();
        let Some(i) = self.execution.selected else {
            return;
        };
        let run = self.execution.book.runs[i].clone();
        let handoff_run_ok = self.verification_handoff.as_ref().is_none_or(|handoff| {
            self.selected_profile().is_some_and(|profile| handoff.target.matches(profile))
                && run.matches_diagnostic(&handoff.execution_link())
        });
        if !handoff_run_ok {
            ui.colored_label(tw::RED_600, "This selected run is not linked to the active diagnostic case and target. Its approval is blocked until the handoff is dismissed or its linked run is selected.");
        }
        ui.label(format!(
            "{} · {}",
            if run.rehearsal {
                "Test run"
            } else {
                "Production"
            },
            run.id
        ));
        if !run.lab_receipts.is_empty() {
            ui.label("This production job is based on a bound clone rehearsal. Each service change rechecks the encrypted evidence; production uses its own current initial findings.");
            for reference in &run.lab_receipts {
                ui.small(format!("Clone evidence: {reference}"));
            }
            ui.label(if self.execution_has_proof(&run){"Clone evidence current and matching."}else{"Clone evidence missing, changed, or expired; further changes are blocked."});
        }
        for (n, t) in run.targets.iter().enumerate() {
            ui.collapsing(
                format!("{} · {} · {:?}", n + 1, t.target.name, t.phase),
                |ui| {
                    ui.label(format!(
                        "Host {} · Domain {} · Profile user {} · Auth: current Windows identity",
                        t.target.host, t.target.domain, t.target.username
                    ));
                    ui.label(format!(
                        "Service: {:?} → {}",
                        t.before,
                        run.plan.desired.label()
                    ));
                    if let Some(b) = &t.baseline {
                        ui.label(format!("Before: {} · {} · {}", b.passed, b.detail, b.at));
                    }
                    if let Some(b) = &t.health {
                        ui.label(format!("After: {} · {} · {}", b.passed, b.detail, b.at));
                    }
                    for e in &t.evidence {
                        ui.monospace(e);
                    }
                },
            );
        }
        let t = &run.targets[run.current];
        if t.phase == Phase::Review && run.finished.is_none() {
            if run.plan.restart {
                ui.strong("Restart: stop the running service, verify Stopped, then start it again. Rollback can restore only the Running service state, not process state.");
            }
            ui.label(format!("Review change: {} / {} / {:?} → {}. On functional failure, restore to {:?}.",t.target.host,run.plan.service,t.before,run.plan.desired.label(),t.before));
            if let Some(before) = t.before {
                if let Ok(spec) = if run.plan.restart {
                    intelligence::restart_spec(&t.target, &run.plan.service)
                } else {
                    intelligence::service_spec(
                        &t.target,
                        &run.plan.service,
                        Some((before, run.plan.desired)),
                    )
                } {
                    ui.collapsing("Exact command with safeguards and rollback", |ui| {
                        ui.monospace(spec.preview());
                    });
                }
            }
            ui.checkbox(&mut self.execution.reviewed,"Reviewed and approved this target, initial state, functional test, and automatic rollback");
            let fresh = t
                .captured
                .is_some_and(|at| (0..120).contains(&(Utc::now() - at).num_seconds()));
            let change = run.plan.restart || t.before != Some(run.plan.desired);
            if !fresh {
                ui.label("Preflight check older than 120 seconds: cancel and prepare a new run.");
            }
            if run.rehearsal && !change {
                ui.label("Test requires an actual state change. Prepare the test system manually and start a new run.");
            }
            let team_change = !run.rehearsal
                && change
                && matches!(run.approval_mode, ApprovalMode::TeamControlled { .. });
            if team_change {
                if let Some(item) = &self.execution.repair_approval
                    && item.binding.run_id == run.id
                    && item.binding.target_index as usize == run.current
                {
                    ui.label(format!(
                        "Team decision: {:?} · fingerprint {} · expires {}",
                        item.state, item.fingerprint, item.expires_at
                    ));
                }
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.execution.reviewed && fresh && self.execution.repair_worker.is_none(), egui::Button::new("Request team approval")).clicked() {
                        match self.repair_binding(i).and_then(|binding| {
                            let (client, _, origin) = self.team.repair_client()?;
                            drop(client);
                            anyhow::ensure!(matches!(&run.approval_mode, ApprovalMode::TeamControlled { server_origin } if server_origin == &origin), "Connect to the configured team server");
                            let input = CreateRepairApproval { request_id: Uuid::new_v4(), binding: binding.clone() };
                            self.start_repair_worker(Some(run.id), Some(run.current), Some(binding), move |client| Ok(RepairWorkerResult::Requested(client.request_repair(&input)?)))
                        }) {
                            Ok(()) => { self.execution.repair_approval = None; self.execution.repair_approval_generation = None; self.execution.repair_message = "Approval requested; ask a different operator to review the fingerprint".into(); }
                            Err(e) => self.execution.repair_message = e.to_string(),
                        }
                    }
                    if let Some(item) = self.execution.repair_approval.clone()
                        && item.binding.run_id == run.id && item.binding.target_index as usize == run.current
                        && ui.add_enabled(self.execution.repair_worker.is_none(), egui::Button::new("Check team decision")).clicked() {
                            let id = item.id;
                            match self.repair_binding(i).and_then(|binding| self.start_repair_worker(Some(run.id), Some(run.current), Some(binding), move |client| {
                                let found = client.list_repairs(0)?.into_iter().find(|row| row.id == id).ok_or_else(|| anyhow::anyhow!("Approval not in recent results"))?;
                                Ok(RepairWorkerResult::Status(found))
                            })) { Ok(()) => {}, Err(e) => self.execution.repair_message = e.to_string() }
                    }
                });
            }
            if ui
                .add_enabled(
                    self.execution.reviewed
                        && fresh
                        && (!run.plan.restart
                            || (t.before == Some(ServiceState::Running)
                                && t.baseline.as_ref().is_some_and(|b| !b.passed)))
                        && (!run.rehearsal || change)
                        && (run.recovery_case.is_none() || self.recovery_actions_allowed())
                        && self.execution.error.is_none()
                        && handoff_run_ok
                        && (!team_change || self.execution.repair_worker.is_none()),
                    egui::Button::new(if run.current == 0 {
                        if team_change {
                            "Consume team approval and apply pilot"
                        } else {
                            "Approve and verify pilot"
                        }
                    } else {
                        if team_change {
                            "Consume team approval for next target"
                        } else {
                            "Approve next rollout target"
                        }
                    }),
                )
                .clicked()
            {
                if team_change {
                    match self.repair_binding(i).and_then(|binding| {
                        let item = self.execution.repair_approval.as_ref().ok_or_else(|| anyhow::anyhow!("Team approval missing"))?;
                        anyhow::ensure!(item.state == repair_approval::RepairState::Approved && item.binding == binding && self.execution.repair_approval_generation == Some(self.team.repair_generation()), "Team approval missing, changed or expired");
                        let (_, _, origin) = self.team.repair_client()?;
                        anyhow::ensure!(matches!(&run.approval_mode, ApprovalMode::TeamControlled { server_origin } if server_origin == &origin), "Team server changed");
                        let id = item.id;
                        let input = ConsumeRepairApproval { binding: binding.clone() };
                        self.start_repair_worker(Some(run.id), Some(run.current), Some(binding), move |client| Ok(RepairWorkerResult::Consumed(client.consume_repair(id, &input)?)))
                    }) {
                        Ok(()) => self.execution.repair_message = "Consuming one-use approval; target remains in review".into(),
                        Err(e) => self.execution.repair_message = e.to_string(),
                    }
                } else {
                    self.execution.book.runs[i].targets[run.current].phase =
                        if change { Phase::Apply } else { Phase::Verify };
                    self.execution.reviewed = false;
                    if self.execution_save() {
                        self.execution_drive();
                    }
                }
            }
        }
        if run.finished.is_none()
            && ui
                .button("Cancel; mark remote state as unknown")
                .clicked()
        {
            if let Some(id) = self.execution.remote.take() {
                if let Some(job) = self.execution.queue.jobs.iter().find(|j| j.id == id) {
                    job.cancel();
                }
            }
            self.execution.health = None;
            self.execution_fail(
                "Canceled by operator. No automatic restart; remote execution may continue.".into(),
            );
        }
        if run.successful() && !recovery_only {
            ui.label("All targets functionally verified. Test run retains the displayed changed service state.");
        }
        if t.phase == Phase::Restore {
            ui.label("Functional check failed. Restoration of the recorded service state is pending; do not start another target.");
        }
        if matches!(t.phase, Phase::Unknown | Phase::Restored | Phase::Failed) {
            ui.label(match t.phase {
                Phase::Restored if t.health.as_ref().is_some_and(|check| !check.passed) => "Functional check failed; original service state verified. Check the application and dependencies before a new reviewed run. This is not a transaction rollback.",
                Phase::Restored => "Original service state verified; no functional check result was recorded. Check the application and dependencies before a new reviewed run. This is not a transaction rollback.",
                Phase::Failed => "Functional check failed without a service change to restore. Inspect the check and target before preparing a new reviewed run.",
                _ => "Remote or restoration outcome unknown. Inspect the journal and verify actual service and application state before a new reviewed run. A canceled job may still finish.",
            });
            ui.label("This run will not be retried; later targets remain untouched.");
        }
        let pending_outcomes = self
            .execution
            .book
            .runs
            .iter()
            .flat_map(|r| {
                r.targets.iter().filter_map(move |target| {
                    let marker = target.outcome.as_ref()?;
                    if marker.delivered {
                        return None;
                    }
                    let ApprovalMode::TeamControlled { server_origin } = &r.approval_mode else {
                        return None;
                    };
                    Some((server_origin.clone(), marker.event.clone()))
                })
            })
            .collect::<Vec<_>>();
        if !pending_outcomes.is_empty() {
            ui.group(|ui| {
                ui.strong("Central outcome delivery pending");
                for (origin, event) in pending_outcomes {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "Run {} · target {} · {:?} · event {}",
                            event.run_id,
                            event.target_index + 1,
                            event.outcome,
                            event.event_id
                        ));
                        if ui
                            .add_enabled(
                                self.execution.repair_worker.is_none(),
                                egui::Button::new(format!("Send outcome##{}", event.event_id)),
                            )
                            .clicked()
                        {
                            match self.team.repair_client().and_then(|(_, _, connected)| {
                                anyhow::ensure!(
                                    connected == origin,
                                    "Connect to the original team server to send this outcome"
                                );
                                let id = event.event_id;
                                self.start_repair_worker(None, None, None, move |client| {
                                    let ack = client.report_repair_outcome(&event)?;
                                    anyhow::ensure!(
                                        ack.accepted && ack.event_id == id,
                                        "Outcome acknowledgement mismatch"
                                    );
                                    Ok(RepairWorkerResult::Outcome(id))
                                })
                            }) {
                                Ok(()) => {
                                    self.execution.repair_message =
                                        "Sending metadata-only outcome".into()
                                }
                                Err(e) => self.execution.repair_message = e.to_string(),
                            }
                        }
                    });
                }
            });
        }
        ui.collapsing("Previous runs", |ui| {
            for r in self.execution.book.runs.iter().rev().skip(1).take(20) {
                ui.label(format!(
                    "{} · {} · Success {}",
                    r.id,
                    if r.rehearsal { "Test" } else { "Production" },
                    r.successful()
                ));
                for t in &r.targets {
                    ui.label(format!("{} · {:?}", t.target.name, t.phase));
                }
            }
        });
    }
}

impl ExecutionState {
    fn select_recovery(&mut self, case: Uuid) -> anyhow::Result<()> {
        let index = self.book.runs.iter().rposition(|r| r.recovery_case == Some(case) && !r.rehearsal)
            .ok_or_else(|| anyhow::anyhow!("No production run for this case yet. Complete the rehearsal and prepare production first."))?;
        if self.selected == Some(index) {
            return Ok(());
        }
        anyhow::ensure!(
            self.remote.is_none()
                && self.health.is_none()
                && !self.book.runs.iter().any(|r| r.finished.is_none())
                && self.queue.jobs.iter().all(|j| j.status.terminal()),
            "Another job is running. Complete or cancel it there first."
        );
        self.selected = Some(index);
        self.reviewed = false;
        self.http_values = "{}".into();
        self.http_runtime = None;
        Ok(())
    }
}

#[cfg(test)]
mod recovery_selection_tests {
    use super::*;
    #[test]
    fn changed_diagnostic_blocks_new_dispatch_but_not_in_flight_verification_or_restore() {
        assert!(handoff_blocks_execution(Phase::Capture, false));
        assert!(handoff_blocks_execution(Phase::Apply, false));
        assert!(!handoff_blocks_execution(Phase::Verify, false));
        assert!(!handoff_blocks_execution(Phase::Restore, false));
        assert!(!handoff_blocks_execution(Phase::Apply, true));
    }
    fn run(case: Uuid, finished: bool) -> Run {
        let target = |host: &str| Target {
            profile_id: Uuid::new_v4(),
            name: host.into(),
            host: host.into(),
            port: 3389,
            protocol: "RDP".into(),
            username: String::new(),
            domain: String::new(),
            route: String::new(),
        };
        let mut run = Run::new(
            ExecutionPlan {
                restart: false,
                service: "AppService".into(),
                desired: ServiceState::Running,
                health: HealthCheck::Tcp { port: 80 },
                mappings: vec![Mapping {
                    production: target("production"),
                    staging: target("staging"),
                }],
            },
            false,
        )
        .unwrap();
        run.recovery_case = Some(case);
        if finished {
            run.finished = Some(Utc::now());
        }
        run
    }
    #[test]
    fn selecting_recovery_uses_exact_case_and_clears_approval_and_runtime_values() {
        let case = Uuid::new_v4();
        let mut state = ExecutionState::default();
        state.book = Journal {
            runs: vec![run(case, true), run(Uuid::new_v4(), true)],
            approval_mode: Default::default(),
        };
        state.selected = Some(1);
        state.reviewed = true;
        state.http_values = "old-secrets".into();
        state.select_recovery(case).unwrap();
        assert_eq!(state.selected, Some(0));
        assert!(!state.reviewed);
        assert_eq!(state.http_values, "{}");
        assert!(state.remote.is_none() && state.health.is_none() && state.queue.jobs.is_empty());
        assert!(state.select_recovery(Uuid::new_v4()).is_err());
        assert_eq!(state.selected, Some(0));
    }
    #[test]
    fn selecting_recovery_never_redirects_a_running_job_to_another_case() {
        let case = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut state = ExecutionState::default();
        state.book = Journal {
            runs: vec![run(case, true), run(other, false)],
            approval_mode: Default::default(),
        };
        state.selected = Some(1);
        assert!(state.select_recovery(case).is_err());
        assert_eq!(state.selected, Some(1));
        assert!(state.select_recovery(other).is_ok());
    }
}

#[cfg(test)]
mod repair_execution_tests {
    use super::*;

    fn app_with_reviewed_run() -> (AivanaApp, std::path::PathBuf) {
        let context = eframe::CreationContext::_new_kittest(egui::Context::default());
        let mut app = AivanaApp::new(&context);
        let production = crate::models::ConnectionProfile::sample(
            "Production",
            "repair-prod.invalid",
            "Test",
            false,
        );
        let staging = crate::models::ConnectionProfile::sample(
            "Staging",
            "repair-stage.invalid",
            "Test",
            false,
        );
        let plan = ExecutionPlan {
            restart: false,
            service: "Spooler".into(),
            desired: ServiceState::Running,
            health: HealthCheck::Tcp { port: 80 },
            mappings: vec![Mapping {
                production: Target::from_profile(&production),
                staging: Target::from_profile(&staging),
            }],
        };
        let now = Utc::now();
        let mut proof = Run::new(plan.clone(), true).unwrap();
        proof.targets[0].before = Some(ServiceState::Stopped);
        proof.targets[0].captured = Some(now);
        proof.targets[0].baseline = Some(HealthEvidence {
            at: now,
            passed: false,
            detail: "test baseline".into(),
        });
        proof.targets[0].evidence.push(r#"{"service":"Spooler","state":"Stopped","dependentRunning":[],"prerequisiteStopped":[]}"#.into());
        proof.assess_mutation(r#"{"service":"Spooler","before":"Stopped","desired":"Running","actual":"Running","verified":true}"#, false).unwrap();
        proof
            .finish_health(HealthEvidence {
                at: now,
                passed: true,
                detail: "test passed".into(),
            })
            .unwrap();
        let mut run = Run::new(plan, false).unwrap();
        run.approval_mode = ApprovalMode::TeamControlled {
            server_origin: "http://127.0.0.1:47831".into(),
        };
        run.targets[0].before = Some(ServiceState::Stopped);
        run.targets[0].captured = Some(now);
        run.targets[0].baseline = Some(HealthEvidence {
            at: now,
            passed: false,
            detail: "production baseline".into(),
        });
        run.targets[0].phase = Phase::Apply;
        app.profiles = vec![production, staging];
        app.execution = ExecutionState::default();
        app.execution.error = None;
        app.execution.book = Journal {
            runs: vec![proof, run],
            approval_mode: ApprovalMode::TeamControlled {
                server_origin: "http://127.0.0.1:47831".into(),
            },
        };
        app.execution.selected = Some(1);
        app.execution.fake_enqueue_count = Some(0);
        let path =
            std::env::temp_dir().join(format!("relayne-repair-gate-{}.dpapi", Uuid::new_v4()));
        app.execution.journal_path_override = Some(path.clone());
        (app, path)
    }

    #[test]
    fn team_apply_without_matching_one_use_receipt_never_enqueues() {
        let (mut app, path) = app_with_reviewed_run();
        assert!(app.repair_binding(1).is_ok());
        app.execution_drive();
        assert_eq!(app.execution.fake_enqueue_count, Some(0));
        assert_eq!(app.execution.book.runs[1].targets[0].phase, Phase::Review);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ambiguous_or_malformed_consume_response_stays_in_review() {
        for malformed in [false, true] {
            let (mut app, path) = app_with_reviewed_run();
            app.execution.book.runs[1].targets[0].phase = Phase::Review;
            let binding = app.repair_binding(1).unwrap();
            let fingerprint = binding.fingerprint().unwrap();
            let approval_id = Uuid::new_v4();
            app.execution.repair_approval = Some(RepairApproval {
                id: approval_id, request_id: Uuid::new_v4(), binding: binding.clone(), fingerprint,
                requester: "alice".into(), approver: Some("bob".into()),
                state: repair_approval::RepairState::Approved,
                expires_at: Utc::now() + chrono::Duration::minutes(2),
            });
            let (tx, receiver) = mpsc::channel();
            let result = if malformed {
                Ok(RepairWorkerResult::Consumed(crate::repair_approval::ConsumeReceipt {
                    approval_id, consume_id: Uuid::new_v4(), fingerprint: "f".repeat(64),
                }))
            } else { Err("Team server unavailable".into()) };
            tx.send(result).unwrap();
            let run_id = app.execution.book.runs[1].id;
            app.execution.repair_worker = Some(RepairWorker {
                generation: app.team.repair_generation(), run_id: Some(run_id),
                target_index: Some(0), binding: Some(binding), receiver,
            });
            app.poll_repair_worker();
            assert_eq!(app.execution.book.runs[1].targets[0].phase, Phase::Review);
            assert_eq!(app.execution.fake_enqueue_count, Some(0));
            assert!(app.execution.repair_receipt.is_none());
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn receipt_is_exact_and_journal_failure_blocks_enqueue() {
        let (mut app, path) = app_with_reviewed_run();
        let binding = app.repair_binding(1).unwrap();
        let approval_id = Uuid::new_v4();
        app.execution.repair_receipt = Some(RepairReceipt {
            generation: app.team.repair_generation(),
            run_id: binding.run_id,
            target_index: 0,
            binding: binding.clone(),
            approval_id,
        });
        app.execution.book.runs[1].targets[0]
            .baseline
            .as_mut()
            .unwrap()
            .detail
            .push_str(" changed");
        app.execution_drive();
        assert_eq!(app.execution.fake_enqueue_count, Some(0));
        assert_eq!(app.execution.book.runs[1].targets[0].phase, Phase::Review);

        app.execution.book.runs[1].targets[0]
            .baseline
            .as_mut()
            .unwrap()
            .detail = "production baseline".into();
        app.execution.book.runs[1].targets[0].phase = Phase::Apply;
        app.execution.repair_receipt = Some(RepairReceipt {
            generation: app.team.repair_generation(),
            run_id: binding.run_id,
            target_index: 0,
            binding,
            approval_id,
        });
        app.execution.journal_path_override = Some(path.join("missing-parent"));
        app.execution_drive();
        assert_eq!(app.execution.fake_enqueue_count, Some(0));
        assert!(app.execution.error.is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn consumed_receipt_enqueues_once_and_restore_ignores_team_outage() {
        let (mut app, path) = app_with_reviewed_run();
        let binding = app.repair_binding(1).unwrap();
        let approval_id = Uuid::new_v4();
        app.execution.repair_receipt = Some(RepairReceipt {
            generation: app.team.repair_generation(),
            run_id: binding.run_id,
            target_index: 0,
            binding,
            approval_id,
        });
        app.execution_drive();
        assert_eq!(app.execution.fake_enqueue_count, Some(1));
        assert!(app.execution.repair_receipt.is_none());
        assert!(app.execution.book.runs[1].targets[0].apply_attempted);
        assert_eq!(
            app.execution.book.runs[1].targets[0].approval_id,
            Some(approval_id)
        );
        app.execution.remote = None;
        app.team = crate::app::team_panel::TeamState::default(); // no token or server session
        app.execution.book.runs[1].targets[0].phase = Phase::Restore;
        app.execution_drive();
        assert_eq!(app.execution.fake_enqueue_count, Some(2));
        app.execution.remote = None;
        app.execution.book.runs[1].targets[0].phase = Phase::Unknown;
        app.sync_repair_outcomes();
        let event = app.execution.book.runs[1].targets[0]
            .outcome
            .as_ref()
            .unwrap();
        assert_eq!(event.event.outcome, RepairOutcome::Unknown);
        assert!(!event.delivered);
        let event_id = event.event.event_id;
        app.sync_repair_outcomes();
        assert_eq!(
            app.execution.book.runs[1].targets[0]
                .outcome
                .as_ref()
                .unwrap()
                .event
                .event_id,
            event_id
        );
        app.execution.book.runs[1].targets[0]
            .outcome
            .as_mut()
            .unwrap()
            .delivered = true;
        assert!(app.execution_save());
        let loaded = Journal::load(&path).unwrap();
        assert!(
            loaded.runs[1].targets[0]
                .outcome
                .as_ref()
                .unwrap()
                .delivered
        );
        let _ = std::fs::remove_file(path);
    }
}
