use super::*;
use crate::{
    execution::ExecutionPlan,
    recovery_contracts::{Book, Check, Contract, Readiness},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

struct Worker {
    id: Uuid,
    revision: u64,
    started: chrono::DateTime<Utc>,
    cancel: Arc<AtomicBool>,
    receiver: mpsc::Receiver<Check>,
}

pub(super) struct ContractsState {
    book: Book,
    error: Option<String>,
    selected: Option<Uuid>,
    name: String,
    monitoring: bool,
    worker: Option<Worker>,
    last_tick: std::time::Instant,
    settings_for: Option<(Uuid, u64)>,
    check_minutes: u32,
    rehearsal_hours: u32,
    enabled: bool,
    notice: String,
}

impl Default for ContractsState {
    fn default() -> Self {
        let (book, error) =
            match app_data_file("relayne-recovery-contracts.dpapi").and_then(|p| Book::load(&p)) {
                Ok(book) => (book, None),
                Err(e) => (
                    Book::default(),
                    Some(format!("Cannot read recovery plans: {e}")),
                ),
            };
        Self {
            selected: book.contracts.first().map(|c| c.id),
            book,
            error,
            name: String::new(),
            monitoring: false,
            worker: None,
            last_tick: std::time::Instant::now(),
            settings_for: None,
            check_minutes: 60,
            rehearsal_hours: 24,
            enabled: true,
            notice: String::new(),
        }
    }
}

impl ContractsState {
    fn next_check_id(&self, now: chrono::DateTime<Utc>) -> Option<Uuid> {
        if !self.monitoring || self.worker.is_some() || self.error.is_some() {
            return None;
        }
        self.book
            .contracts
            .iter()
            .filter(|c| c.invalidated.is_none() && c.enabled && c.check_due(now))
            .min_by_key(|c| c.next_check_at())
            .map(|c| c.id)
    }
    fn readiness(&self, contract: &Contract, now: chrono::DateTime<Utc>) -> Readiness {
        if self.error.is_some() {
            Readiness::Unknown
        } else {
            contract.readiness(now)
        }
    }
}

fn profiles_match(plan: &ExecutionPlan, profiles: &[ConnectionProfile]) -> bool {
    plan.mappings
        .iter()
        .all(|m| profiles.iter().any(|p| m.production.matches(p)))
}

fn contract_matches(contract: &Contract, plan: &ExecutionPlan, refs: &[String]) -> bool {
    contract
        .plan
        .hash()
        .ok()
        .zip(plan.hash().ok())
        .is_some_and(|(a, b)| a == b)
        || contract.references.iter().any(|r| refs.contains(r))
}

fn status_label(status: Readiness) -> &'static str {
    match status {
        Readiness::Ready => "Ready based on last comparison",
        Readiness::CheckDue => "Production comparison due",
        Readiness::RehearsalDue => "New rehearsal due",
        Readiness::Changed => "Change detected — evidence invalidated",
        Readiness::Unknown => "Comparison failed — state unclear",
        Readiness::Paused => "Automatic comparisons paused",
    }
}

impl AivanaApp {
    fn save_contracts(&mut self) -> anyhow::Result<()> {
        let result = app_data_file("relayne-recovery-contracts.dpapi")
            .and_then(|p| self.contracts.book.save(&p));
        if let Err(e) = &result {
            self.contracts.error =
                Some(format!("Plans not saved; approvals blocked: {e}"));
            self.contracts.monitoring = false;
            if let Some(worker) = &self.contracts.worker {
                worker.cancel.store(true, Ordering::Release);
            }
        }
        result
    }

    pub(super) fn contracts_execution_allowed(
        &self,
        plan: &ExecutionPlan,
        refs: &[String],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.contracts.error.is_none(),
            "Recovery plan storage locked"
        );
        if let Some(worker) = &self.contracts.worker {
            anyhow::ensure!(
                !self
                    .contracts
                    .book
                    .contracts
                    .iter()
                    .any(|c| c.id == worker.id && contract_matches(c, plan, refs)),
                "Production comparison running; wait for the result before approving"
            );
        }
        for contract in &self.contracts.book.contracts {
            if contract_matches(contract, plan, refs) {
                anyhow::ensure!(
                    profiles_match(&contract.plan, &self.profiles),
                    "Production profile changed; new rehearsal required"
                );
            }
        }
        self.contracts.book.ensure_allowed(plan, refs, Utc::now())
    }

    fn start_contract_check(&mut self, id: Uuid) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.contracts.error.is_none() && self.contracts.worker.is_none(),
            "Comparison running or storage locked"
        );
        let index = self
            .contracts
            .book
            .contracts
            .iter()
            .position(|c| c.id == id)
            .ok_or_else(|| anyhow::anyhow!("Recovery plan missing"))?;
        if !profiles_match(&self.contracts.book.contracts[index].plan, &self.profiles) {
            self.contracts.book.contracts[index].invalidate(
                "Production profile changed or removed; renew mapping and rehearsal",
            );
            self.save_contracts()?;
            anyhow::bail!("Production profile changed; comparison not started");
        }
        let contract = self.contracts.book.contracts[index].clone();
        let started = Utc::now();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (tx, receiver) = mpsc::channel();
        self.contracts.worker = Some(Worker {
            id,
            revision: contract.revision,
            started,
            cancel,
            receiver,
        });
        std::thread::spawn(move || {
            let result = crate::equivalence::observe_production(&contract.plan, &worker_cancel);
            let (fingerprints, error) = match result {
                Ok(fingerprints) => (fingerprints, None),
                Err(e) => (
                    vec![],
                    Some(crate::security::redact_secret_text(&e.to_string())),
                ),
            };
            let _ = tx.send(Check {
                started,
                finished: Utc::now(),
                fingerprints,
                error,
            });
        });
        self.contracts.notice =
            "Read-only WinRM comparison started. Service states are not changed.".into();
        Ok(())
    }

    pub(super) fn poll_contracts(&mut self) {
        let received =
            self.contracts
                .worker
                .as_ref()
                .and_then(|worker| match worker.receiver.try_recv() {
                    Ok(check) => Some(check),
                    Err(mpsc::TryRecvError::Empty) => None,
                    Err(mpsc::TryRecvError::Disconnected) => Some(Check {
                        started: worker.started,
                        finished: Utc::now(),
                        fingerprints: vec![],
                        error: Some("Comparison process interrupted".into()),
                    }),
                });
        if let Some(mut check) = received {
            let worker = self.contracts.worker.take().unwrap();
            if worker.cancel.load(Ordering::Acquire) {
                check.fingerprints.clear();
                check.error = Some("Comparison canceled".into());
            }
            if self.contracts.error.is_none() {
                if let Some(contract) = self
                    .contracts
                    .book
                    .contracts
                    .iter_mut()
                    .find(|c| c.id == worker.id)
                {
                    if contract.revision != worker.revision {
                        self.contracts.notice = "Outdated comparison response discarded; plan changed in the meantime.".into();
                    } else {
                        let result = if !profiles_match(&contract.plan, &self.profiles) {
                            contract.invalidate("Production profile changed during check; new rehearsal required");
                            Ok(())
                        } else {
                            contract.apply_check(worker.revision, check, Utc::now())
                        };
                        match result {
                            Ok(()) => {
                                self.contracts.notice =
                                    status_label(contract.readiness(Utc::now())).into();
                                let _ = self.save_contracts();
                            }
                            Err(e) => {
                                contract.invalidate("Invalid comparison response; evidence blocked until a new rehearsal");
                                self.contracts.notice = e.to_string();
                                let _ = self.save_contracts();
                            }
                        }
                    }
                }
            }
        }
        if self.contracts.last_tick.elapsed() < std::time::Duration::from_secs(1) {
            return;
        }
        self.contracts.last_tick = std::time::Instant::now();
        if self.contracts.error.is_some() {
            return;
        }
        let mut changed = false;
        for contract in &mut self.contracts.book.contracts {
            if contract.invalidated.is_none() && !profiles_match(&contract.plan, &self.profiles) {
                contract.invalidate("Production profile changed or removed; new mapping and rehearsal required");
                changed = true;
            }
        }
        if changed && self.save_contracts().is_err() {
            return;
        }
        if let Some(id) = self.contracts.next_check_id(Utc::now()) {
            if let Err(e) = self.start_contract_check(id) {
                self.contracts.notice = e.to_string();
            }
        }
    }

    fn import_recovery_contract(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.contracts.error.is_none() && self.contracts.worker.is_none(),
            "Comparison running or storage locked"
        );
        let (plan, refs) = self.promotion_contract_source()?;
        crate::promotion::check_rehearsal_receipts(&plan, &refs, Utc::now())?;
        let baseline = crate::equivalence::rehearsal_baseline(&plan, &refs, Utc::now())?;
        let hash = plan.hash()?;
        let id = if let Some(contract) = self
            .contracts
            .book
            .contracts
            .iter_mut()
            .find(|c| c.plan.hash().ok().as_ref() == Some(&hash))
        {
            contract.renew(plan, refs, baseline, Utc::now())?;
            contract.id
        } else {
            let name = if self.contracts.name.trim().is_empty() {
                format!("{} · {} targets", plan.service, plan.mappings.len())
            } else {
                self.contracts.name.trim().into()
            };
            let contract = Contract::new(name, plan, refs, baseline, Utc::now())?;
            let id = contract.id;
            self.contracts.book.contracts.push(contract);
            id
        };
        self.save_contracts()?;
        self.contracts.selected = Some(id);
        self.contracts.settings_for = None;
        self.contracts.notice = "Passed rehearsal adopted. Automatic comparisons require separate approval for this session.".into();
        Ok(())
    }

    pub(super) fn contracts_view(&mut self, ui: &mut Ui) {
        ui.heading("Living recovery plans");
        ui.label("Keep tested repairs current: detect changes, invalidate evidence, and renew rehearsals on time.");
        ui.small("Readiness describes the last evidence. Production changes still require fresh evidence (no more than one hour old) and separate approval.");
        if let Some(e) = &self.contracts.error {
            ui.colored_label(tw::RED_600, e);
        }
        let mut monitoring = self.contracts.monitoring;
        if ui.add_enabled(self.contracts.error.is_none(), egui::Checkbox::new(&mut monitoring,
            "Allow automatic WinRM production comparisons when due during this Relayne session")).changed() {
            self.contracts.monitoring = monitoring;
            if !monitoring {
                if let Some(worker) = &self.contracts.worker { worker.cancel.store(true, Ordering::Release); }
            }
        }
        ui.small("Read only metadata from the specified production targets using the current Windows identity. No guest credentials or automatic service changes. Approval resets on restart.");
        if let Some(worker) = &self.contracts.worker {
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
                ui.label("Production comparison running …");
                if ui.button("Cancel comparison").clicked() {
                    worker.cancel.store(true, Ordering::Release);
                }
            });
        }
        if ui
            .add_enabled(
                self.contracts.worker.is_none(),
                egui::Button::new("Reload saved plans"),
            )
            .clicked()
        {
            match app_data_file("relayne-recovery-contracts.dpapi").and_then(|p| {
                self.contracts.book.persist_restrictions(&p)?;
                Book::load(&p)
            }) {
                Ok(book) => {
                    self.contracts.book = book;
                    self.contracts.error = None;
                    self.contracts.settings_for = None;
                    self.contracts.monitoring = false;
                    self.contracts.notice =
                        "Reloaded; approve automatic comparisons again.".into();
                }
                Err(e) => self.contracts.error = Some(e.to_string()),
            }
        }
        let now = Utc::now();
        let counts = self
            .contracts
            .book
            .contracts
            .iter()
            .fold([0usize; 6], |mut counts, c| {
                let i = match self.contracts.readiness(c, now) {
                    Readiness::Ready => 0,
                    Readiness::CheckDue => 1,
                    Readiness::RehearsalDue => 2,
                    Readiness::Changed => 3,
                    Readiness::Unknown => 4,
                    Readiness::Paused => 5,
                };
                counts[i] += 1;
                counts
            });
        ui.horizontal_wrapped(|ui| {
            for (label, count) in [
                "Ready",
                "Comparison due",
                "Rehearsal due",
                "Changed",
                "Unclear",
                "Paused",
            ]
            .into_iter()
            .zip(counts)
            {
                ui.group(|ui| {
                    ui.strong(count.to_string());
                    ui.label(label);
                });
            }
        });
        ui.separator();
        ui.collapsing("Adopt passed rehearsal as a plan", |ui| {
            ui.add(egui::TextEdit::singleline(&mut self.contracts.name).char_limit(256).hint_text("Name for new recovery plan"));
            ui.label("Adopts the current Clone → production draft with fresh evidence. The same plan is renewed with new evidence; changed target mappings create a new plan.");
            ui.horizontal_wrapped(|ui| {
                if ui.button("Open Clone → production").clicked() { self.view = View::Promotion; }
                if ui.add_enabled(self.contracts.error.is_none() && self.contracts.worker.is_none(), egui::Button::new("Adopt / renew passed rehearsal")).clicked() {
                    if let Err(e) = self.import_recovery_contract() { self.contracts.notice = e.to_string(); }
                }
            });
        });
        if self.contracts.book.contracts.is_empty() {
            ui.add_space(16.0);
            ui.label("No recovery plans yet. Complete a rehearsal in Clone → production first, then adopt it here.");
        }
        for contract in &self.contracts.book.contracts {
            let label = format!(
                "{} · {} · {}",
                contract.name,
                contract.plan.service,
                status_label(self.contracts.readiness(contract, now))
            );
            if ui
                .selectable_label(self.contracts.selected == Some(contract.id), label)
                .clicked()
            {
                self.contracts.selected = Some(contract.id);
                self.contracts.settings_for = None;
            }
        }
        if let Some(contract) = self
            .contracts
            .selected
            .and_then(|id| self.contracts.book.contracts.iter().find(|c| c.id == id))
            .cloned()
        {
            ui.separator();
            ui.strong(&contract.name);
            ui.label(status_label(self.contracts.readiness(&contract, now)));
            if let Some(reason) = &contract.invalidated {
                ui.colored_label(tw::RED_600, reason);
            }
            ui.label(format!(
                "Last rehearsal: {} UTC · next due: {} UTC",
                contract.baseline.rehearsed_at.format("%m/%d/%Y %H:%M"),
                contract.next_rehearsal_at().format("%m/%d/%Y %H:%M")
            ));
            ui.label(format!(
                "Next production comparison: {} UTC",
                contract.next_check_at().format("%m/%d/%Y %H:%M")
            ));
            if let Some(check) = &contract.last_check {
                ui.label(format!(
                    "Last comparison: {} UTC",
                    check.finished.format("%m/%d/%Y %H:%M")
                ));
                if let Some(error) = &check.error {
                    ui.colored_label(tw::RED_600, error);
                }
            }
            for mapping in &contract.plan.mappings {
                ui.label(format!(
                    "{} · {} ↔ {}",
                    mapping.production.name, mapping.production.host, mapping.staging.name
                ));
            }
            ui.collapsing("Check scope and evidence binding", |ui| {
                ui.label("OS version/build, architecture, service file and version, configuration hash, startup mode, and dependencies. Changes outside this scope are not covered.");
                ui.monospace(contract.plan.hash().unwrap_or_default());
                for reference in &contract.references { ui.small(reference); }
                ui.small(format!("Permanently invalidated evidence references: {}", contract.revoked_references.len()));
            });
            if self.contracts.settings_for != Some((contract.id, contract.revision)) {
                self.contracts.settings_for = Some((contract.id, contract.revision));
                self.contracts.check_minutes = contract.check_minutes;
                self.contracts.rehearsal_hours = contract.rehearsal_hours;
                self.contracts.enabled = contract.enabled;
            }
            ui.add_enabled_ui(self.contracts.worker.is_none() && self.contracts.error.is_none(), |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Compare every"); ui.add(egui::DragValue::new(&mut self.contracts.check_minutes).range(5..=1440)); ui.label("minutes");
                    ui.label("Rehearse every"); ui.add(egui::DragValue::new(&mut self.contracts.rehearsal_hours).range(1..=720)); ui.label("hours");
                });
                ui.checkbox(&mut self.contracts.enabled, "Include this plan in automatic comparisons");
                if ui.button("Save intervals").clicked() {
                    let current = self.contracts.book.contracts.iter_mut().find(|c| c.id == contract.id).unwrap();
                    let result = current.set_settings(self.contracts.check_minutes, self.contracts.rehearsal_hours, self.contracts.enabled)
                        .and_then(|_| self.save_contracts());
                    self.contracts.notice = result.map(|_| "Intervals saved. This did not renew the rehearsal.".into()).unwrap_or_else(|e| e.to_string());
                }
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Run one read-only WinRM check now").clicked() {
                        if let Err(e) = self.start_contract_check(contract.id) { self.contracts.notice = e.to_string(); }
                    }
                    if ui.button("Prepare new rehearsal …").clicked() {
                        match self.prepare_contract_rehearsal(&contract.plan) {
                            Ok(()) => self.view = View::Promotion,
                            Err(e) => self.contracts.notice = e.to_string(),
                        }
                    }
                });
                ui.small("A new rehearsal replaces the previous test draft and requires new guest credentials and explicit execution approvals.");
            });
        }
        ui.separator();
        ui.label(&self.contracts.notice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn contract(now: chrono::DateTime<Utc>) -> Contract {
        let fingerprint = crate::equivalence::Fingerprint {
            os_version: "10.0".into(),
            os_build: "20348".into(),
            architecture: "64-bit".into(),
            executable_hash: "a".repeat(64),
            executable_version: "1".into(),
            configuration_hash: "b".repeat(64),
            start_mode: "Auto".into(),
            dependencies: vec![],
        };
        Contract::new(
            "Application".into(),
            crate::promotion::tests::plan(),
            vec!["test-proof".into()],
            crate::equivalence::RehearsalBaseline {
                observed_at: now - chrono::Duration::hours(2),
                rehearsed_at: now - chrono::Duration::hours(2),
                fingerprints: vec![fingerprint],
            },
            now,
        )
        .unwrap()
    }
    #[test]
    fn contract_scheduler_requires_session_consent_and_never_duplicates_an_active_worker() {
        let now = Utc::now();
        let mut state = ContractsState::default();
        state.book = Book::default();
        state.error = None;
        let contract = contract(now);
        let id = contract.id;
        state.book.contracts.push(contract);
        assert_eq!(state.next_check_id(now), None);
        state.monitoring = true;
        assert_eq!(state.next_check_id(now), Some(id));
        let (_tx, receiver) = mpsc::channel();
        state.worker = Some(Worker {
            id,
            revision: 1,
            started: now,
            cancel: Arc::new(AtomicBool::new(false)),
            receiver,
        });
        assert_eq!(state.next_check_id(now), None);
        state.worker = None;
        state.error = Some("storage conflict".into());
        assert_eq!(state.next_check_id(now), None);
        state.error = None;
        state.book.contracts[0].invalidate("changed");
        assert_eq!(state.next_check_id(now), None);
    }
    #[test]
    fn same_plan_with_new_proofs_still_matches_worker_and_profile_guards() {
        let contract = contract(Utc::now());
        assert!(contract_matches(
            &contract,
            &contract.plan,
            &["new-proof".into()]
        ));
        let mut other = contract.plan.clone();
        other.service = "OtherService".into();
        assert!(!contract_matches(&contract, &other, &["new-proof".into()]));
        assert!(contract_matches(&contract, &other, &contract.references));
    }
    #[test]
    fn profile_identity_changes_are_rejected_even_when_id_is_unchanged() {
        let profile = ConnectionProfile::sample("Production", "prod.example.invalid", "", false);
        let mut plan = crate::promotion::tests::plan();
        plan.mappings[0].production = crate::mission::Target::from_profile(&profile);
        assert!(profiles_match(&plan, &[profile.clone()]));
        let mut changed = profile;
        changed.host = "other.example.invalid".into();
        assert!(!profiles_match(&plan, &[changed]));
        assert!(!profiles_match(&plan, &[]));
    }
}
