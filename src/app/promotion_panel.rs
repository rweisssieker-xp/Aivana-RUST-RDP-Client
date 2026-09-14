use super::*;
use crate::{
    execution::{ExecutionPlan, HealthCheck, Mapping},
    intelligence::ServiceState,
    mission::Target,
    promotion, security, test_lab,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const DRAFT_LIMIT: usize = 256 * 1024;
#[path = "health_suggestions_panel.rs"]
mod health_suggestions_panel;

#[derive(Clone, Serialize, Deserialize)]
struct Draft {
    plan: ExecutionPlan,
    refs: Vec<String>,
    #[serde(default)]
    recovery_case: Option<Uuid>,
}
impl Default for Draft {
    fn default() -> Self {
        Self {
            plan: ExecutionPlan {
                restart: false,
                service: String::new(),
                desired: ServiceState::Running,
                health: HealthCheck::Http {
                    port: 8080,
                    tls: false,
                    path: "/health".into(),
                    status: 200,
                    contains: String::new(),
                    followups: vec![],
                },
                mappings: vec![],
            },
            refs: vec![],
            recovery_case: None,
        }
    }
}
fn save(draft: &Draft) -> anyhow::Result<()> {
    let path = app_data_file("relayne-promotion.dpapi")?;
    anyhow::ensure!(
        draft.refs.len() <= 32 && draft.plan.mappings.len() <= 32,
        "Draft limit exceeded"
    );
    let raw = serde_json::to_vec(draft)?;
    anyhow::ensure!(raw.len() <= DRAFT_LIMIT, "Draft too large");
    let protected = security::protect_secret(&raw)?;
    anyhow::ensure!(
        protected.len() <= DRAFT_LIMIT,
        "Protected draft too large"
    );
    security::atomic_write(&path, &protected)
}
fn load() -> anyhow::Result<Draft> {
    let path = app_data_file("relayne-promotion.dpapi")?;
    match std::fs::File::open(path) {
        Ok(file) => {
            let mut raw = Vec::new();
            file.take((DRAFT_LIMIT + 1) as u64).read_to_end(&mut raw)?;
            anyhow::ensure!(raw.len() <= DRAFT_LIMIT, "Protected draft too large");
            let clear = security::unprotect_secret(&raw)?;
            anyhow::ensure!(clear.len() <= DRAFT_LIMIT, "Draft too large");
            let draft: Draft = serde_json::from_slice(&clear)?;
            anyhow::ensure!(
                draft.refs.len() <= 32 && draft.plan.mappings.len() <= 32,
                "Draft limit exceeded"
            );
            Ok(draft)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Draft::default()),
        Err(e) => Err(e.into()),
    }
}
struct Outcome {
    draft: Draft,
    notice: String,
    storage_failed: bool,
}
fn receipt_metadata(references: &[String]) -> Vec<String> {
    references
        .iter()
        .map(|reference| match test_lab::load_receipt(reference) {
            Ok(receipt) => format!(
                "{} · {} UTC · {} → {} · HTTP {} · {}",
                reference,
                receipt.finished.format("%Y-%m-%d %H:%M:%S"),
                receipt.before,
                receipt.after,
                receipt.health.expected_status,
                if receipt.passed {
                    "passed"
                } else {
                    "failed"
                }
            ),
            Err(_) => format!("{reference} · Evidence unreadable or invalid"),
        })
        .collect()
}
pub(super) struct PromotionState {
    health_ai: health_suggestions_panel::State,
    draft: Draft,
    labs: Vec<test_lab::Journal>,
    production: Option<Uuid>,
    lab: Option<usize>,
    user: String,
    password: String,
    http_values: String,
    acknowledged: bool,
    review: Option<Draft>,
    worker: Option<std::sync::mpsc::Receiver<Outcome>>,
    cancel: Option<Arc<AtomicBool>>,
    notice: String,
    blocked: bool,
    initialized: bool,
    receipt_info: Vec<String>,
}
impl Default for PromotionState {
    fn default() -> Self {
        let (draft, blocked, notice) = match load() {
            Ok(d) => (d, false, String::new()),
            Err(_) => (
                Draft::default(),
                true,
                "Cannot read saved draft. File unchanged; adoption blocked."
                    .into(),
            ),
        };
        Self {
            health_ai: Default::default(),
            draft,
            labs: vec![],
            production: None,
            lab: None,
            user: String::new(),
            password: String::new(),
            http_values: "{}".into(),
            acknowledged: false,
            review: None,
            worker: None,
            cancel: None,
            notice,
            blocked,
            initialized: false,
            receipt_info: vec![],
        }
    }
}
impl PromotionState {
    fn health_binding(
        &self,
        context: &crate::health_suggestions::Context,
    ) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(&self.draft, context))?)
        ))
    }
    fn adopt_health_suggestion(
        &mut self,
        binding: &str,
        context: &crate::health_suggestions::Context,
        proposal: &crate::health_suggestions::Proposal,
    ) -> anyhow::Result<()> {
        self.can_adopt_recovery()?;
        context.validate()?;
        anyhow::ensure!(
            context.service == self.draft.plan.service && self.health_binding(context)? == binding,
            "Draft or description changed; create a new suggestion"
        );
        let health = proposal.health()?;
        self.draft.plan.health = health;
        self.draft.refs.clear();
        self.receipt_info.clear();
        self.acknowledged = false;
        self.password.clear();
        self.http_values = "{}".into();
        self.health_ai = Default::default();
        self.notice = "Reviewed application tests adopted. Old evidence and approvals discarded; new rehearsal required.".into();
        Ok(())
    }
    pub(super) fn adopt_contract(&mut self, plan: &ExecutionPlan) -> anyhow::Result<()> {
        self.can_adopt_recovery()?;
        promotion::validate(plan)?;
        self.health_ai = Default::default();
        self.draft = Draft {
            plan: plan.clone(),
            refs: vec![],
            recovery_case: None,
        };
        self.production = None;
        self.lab = None;
        self.user.clear();
        self.password.clear();
        self.http_values = "{}".into();
        self.acknowledged = false;
        self.receipt_info.clear();
        self.initialized = false;
        self.notice = "New rehearsal prepared. Review mapping and guest credentials before execution; old evidence was not adopted.".into();
        Ok(())
    }
    pub(super) fn can_adopt_recovery(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.blocked,
            "Test draft locked; resolve storage error first"
        );
        anyhow::ensure!(
            self.worker.is_none() && self.review.is_none(),
            "Complete or exit the running rehearsal or pending approval first"
        );
        Ok(())
    }
    pub(super) fn recovery_case(&self) -> Option<Uuid> {
        self.draft.recovery_case
    }
    pub(super) fn adopt_recovery(&mut self, case: &crate::recovery::Case) -> anyhow::Result<()> {
        self.can_adopt_recovery()?;
        crate::recovery::Suggestion {
            action: case.action,
            service: case.service.clone(),
            rationale: case.rationale.clone(),
        }
        .validate()?;
        self.health_ai = Default::default();
        self.draft = Draft::default();
        self.draft.plan.service = case.service.clone();
        self.draft.plan.restart = case.action == crate::recovery::RepairAction::Restart;
        self.draft.recovery_case = Some(case.id);
        self.production = None;
        self.lab = None;
        self.user.clear();
        self.password.clear();
        self.http_values = "{}".into();
        self.acknowledged = false;
        self.receipt_info.clear();
        self.notice =
            "New recovery test draft. Explicitly review target and HTTP success criteria."
                .into();
        Ok(())
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn health_suggestions_adoption_revokes_old_authority_and_preserves_targets() {
        let mut state = PromotionState::default();
        state.blocked = false;
        state.draft.plan = crate::promotion::tests::plan();
        let original = state.draft.plan.clone();
        state.draft.refs = vec!["old-proof".into()];
        state.acknowledged = true;
        state.password = "old-secret".into();
        state.http_values = "old-values".into();
        let context = crate::health_suggestions::Context {
            service: original.service.clone(),
            incident: "Ausfall".into(),
            workflow: "Katalog öffnen".into(),
        };
        let proposal = crate::health_suggestions::Proposal {
            port: Some(8081),
            tls: Some(false),
            steps: vec![crate::health_suggestions::Step {
                path: "/ready".into(),
                status: 200,
                contains: "ready".into(),
                rationale: "Anwendungsbereitschaft".into(),
            }],
            assumptions: vec![],
            missing: vec![],
        };
        let binding = state.health_binding(&context).unwrap();
        state
            .adopt_health_suggestion(&binding, &context, &proposal)
            .unwrap();
        assert_eq!(state.draft.plan.service, original.service);
        assert_eq!(
            serde_json::to_value(&state.draft.plan.mappings).unwrap(),
            serde_json::to_value(original.mappings).unwrap()
        );
        assert!(state.draft.refs.is_empty());
        assert!(!state.acknowledged);
        assert!(state.password.is_empty());
        assert_eq!(state.http_values, "{}");
        assert!(state.worker.is_none());
        assert!(state.review.is_none());
        assert_ne!(state.health_binding(&context).unwrap(), binding);
    }
    #[test]
    fn health_suggestions_reject_changed_context_plan_and_pending_review() {
        let mut state = PromotionState::default();
        state.blocked = false;
        state.draft.plan = crate::promotion::tests::plan();
        let mut context = crate::health_suggestions::Context {
            service: state.draft.plan.service.clone(),
            incident: "Ausfall".into(),
            workflow: String::new(),
        };
        let proposal = crate::health_suggestions::Proposal {
            port: Some(8081),
            tls: Some(false),
            steps: vec![crate::health_suggestions::Step {
                path: "/ready".into(),
                status: 200,
                contains: "ready".into(),
                rationale: "Bereitschaft".into(),
            }],
            assumptions: vec![],
            missing: vec![],
        };
        let binding = state.health_binding(&context).unwrap();
        context.incident.push_str(" geändert");
        assert!(
            state
                .adopt_health_suggestion(&binding, &context, &proposal)
                .is_err()
        );
        let binding = state.health_binding(&context).unwrap();
        state.draft.plan.mappings[0].production.host = "other.invalid".into();
        assert!(
            state
                .adopt_health_suggestion(&binding, &context, &proposal)
                .is_err()
        );
        let binding = state.health_binding(&context).unwrap();
        state.review = Some(state.draft.clone());
        assert!(
            state
                .adopt_health_suggestion(&binding, &context, &proposal)
                .is_err()
        );
    }

    fn case() -> crate::recovery::Case {
        crate::recovery::Case {
            action: Default::default(),
            id: Uuid::new_v4(),
            objective: "Anwendung ausgefallen".into(),
            created: Utc::now(),
            service: "AppService".into(),
            rationale: "Dienst vor Änderung prüfen".into(),
        }
    }

    #[test]
    fn contract_rehearsal_keeps_exact_targets_but_discards_old_authority() {
        let mut state = PromotionState::default();
        state.blocked = false;
        state.draft.recovery_case = Some(Uuid::new_v4());
        state.draft.refs = vec!["old-proof".into()];
        state.password = "old-secret".into();
        state.http_values = "old-http-secret".into();
        state.acknowledged = true;
        let plan = crate::promotion::tests::plan();
        state.adopt_contract(&plan).unwrap();
        assert_eq!(
            state.draft.plan.mappings[0].production.host,
            "prod.example.invalid"
        );
        assert_eq!(state.draft.plan.service, "Spooler");
        assert!(state.draft.refs.is_empty() && state.draft.recovery_case.is_none());
        assert!(state.password.is_empty() && !state.acknowledged);
        assert_eq!(state.http_values, "{}");
        assert!(state.worker.is_none() && state.review.is_none());
        state.review = Some(state.draft.clone());
        let before = state.draft.plan.hash().unwrap();
        assert!(state.adopt_contract(&plan).is_err());
        assert_eq!(state.draft.plan.hash().unwrap(), before);
    }

    #[test]
    fn recovery_draft_clears_old_evidence_approval_and_secrets_without_starting_worker() {
        let mut state = PromotionState::default();
        state.blocked = false;
        state.draft.refs.push("old-proof".into());
        state.password = "old-password".into();
        state.user = "old-user".into();
        state.http_values = "old-slots".into();
        state.acknowledged = true;
        let case = case();
        state.adopt_recovery(&case).unwrap();
        assert_eq!(state.draft.recovery_case, Some(case.id));
        assert_eq!(state.draft.plan.service, "AppService");
        assert!(state.draft.plan.mappings.is_empty());
        assert!(state.draft.refs.is_empty());
        assert!(state.password.is_empty() && state.user.is_empty());
        assert_eq!(state.http_values, "{}");
        assert!(!state.acknowledged);
        assert!(state.worker.is_none() && state.review.is_none());
    }

    #[test]
    fn recovery_draft_does_not_replace_review_or_blocked_state() {
        let mut state = PromotionState::default();
        state.blocked = false;
        state.draft.plan.service = "ExistingService".into();
        state.review = Some(state.draft.clone());
        assert!(state.adopt_recovery(&case()).is_err());
        assert_eq!(state.draft.plan.service, "ExistingService");
        state.review = None;
        state.blocked = true;
        assert!(state.adopt_recovery(&case()).is_err());
        assert_eq!(state.draft.plan.service, "ExistingService");
        state.blocked = false;
        let (_tx, rx) = std::sync::mpsc::channel();
        state.worker = Some(rx);
        assert!(state.adopt_recovery(&case()).is_err());
        assert_eq!(state.draft.plan.service, "ExistingService");
    }
}
fn current_plan(
    plan: &ExecutionPlan,
    profiles: &[ConnectionProfile],
    labs: &[test_lab::Journal],
) -> anyhow::Result<Vec<test_lab::Journal>> {
    current_production(plan, profiles)?;
    let mut selected = Vec::new();
    for mapping in &plan.mappings {
        let lab = labs
            .iter()
            .find(|lab| promotion::lab_target(lab).is_ok_and(|t| mapping.staging.same_endpoint(&t)))
            .ok_or_else(|| {
                anyhow::anyhow!("Test lab changed or unavailable; recreate mapping")
            })?;
        selected.push(lab.clone());
    }
    Ok(selected)
}
fn current_production(plan: &ExecutionPlan, profiles: &[ConnectionProfile]) -> anyhow::Result<()> {
    promotion::validate(plan)?;
    for mapping in &plan.mappings {
        anyhow::ensure!(
            profiles.iter().any(|p| mapping.production.matches(p)),
            "Production profile changed or removed; recreate mapping"
        );
    }
    Ok(())
}
impl AivanaApp {
    pub(super) fn promotion_contract_source(&self) -> anyhow::Result<(ExecutionPlan, Vec<String>)> {
        self.promotion.can_adopt_recovery()?;
        current_production(&self.promotion.draft.plan, &self.profiles)?;
        Ok((
            self.promotion.draft.plan.clone(),
            self.promotion.draft.refs.clone(),
        ))
    }
    pub(super) fn prepare_contract_rehearsal(
        &mut self,
        plan: &ExecutionPlan,
    ) -> anyhow::Result<()> {
        current_production(plan, &self.profiles)?;
        self.promotion.adopt_contract(plan)?;
        self.persist_recovery_promotion()
    }
    pub(super) fn persist_recovery_promotion(&mut self) -> anyhow::Result<()> {
        if let Err(e) = save(&self.promotion.draft) {
            self.promotion.blocked = true;
            return Err(e);
        }
        Ok(())
    }
    pub(super) fn poll_promotion(&mut self) {
        if let Some(rx) = &self.promotion.worker {
            match rx.try_recv() {
                Ok(out) => {
                    self.promotion.worker = None;
                    self.promotion.cancel = None;
                    self.promotion.draft = out.draft;
                    self.promotion.receipt_info = receipt_metadata(&self.promotion.draft.refs);
                    self.promotion.notice = out.notice;
                    self.promotion.blocked |= out.storage_failed;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.promotion.worker = None;
                    self.promotion.cancel = None;
                    self.promotion.draft.refs.clear();
                    self.promotion.blocked = true;
                    self.promotion.notice = "Test worker stopped. Check persisted journals and restart the application.".into();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }
    pub(super) fn promotion_view(&mut self, ui: &mut Ui) {
        self.poll_promotion();
        let recovery_actions_allowed = self.recovery_actions_allowed();
        let health_model = self.autopilot.settings.openai_model.clone();
        let health_incident = self
            .promotion
            .recovery_case()
            .and_then(|id| self.recovery_objective_for(id));
        let state = &mut self.promotion;
        if !state.initialized {
            state.initialized = true;
            state.receipt_info = receipt_metadata(&state.draft.refs);
            match test_lab::journals() {
                Ok(l) => state.labs = l,
                Err(_) => state.notice = "Cannot read lab journals; please check.".into(),
            }
        }
        ui.heading("From test lab to production");
        ui.label("1. Map target and clone → 2. Verify service change and HTTP in clone → 3. Prepare production and approve separately.");
        ui.label("Before rehearsal, OS, service file, and configuration are automatically compared between clone (PowerShell Direct) and production (WinRM, current Windows user). Differences block adoption.");
        if ui.button("Open test lab / create clone").clicked() {
            self.view = View::TestLab;
        }
        let before = state.draft.plan.hash().ok();
        let mut prepare = None;
        ui.add_enabled_ui(state.worker.is_none() && !state.blocked
            && (state.draft.recovery_case.is_none() || recovery_actions_allowed), |ui| {
            if state.review.is_none() {
                if state.draft.recovery_case.is_some() {
                    ui.label(format!("Recovery service: {} → Running · Restart: {}", state.draft.plan.service, state.draft.plan.restart));
                } else {
                ui.horizontal(|ui| { ui.label("Windows service"); ui.text_edit_singleline(&mut state.draft.plan.service); });
                ui.horizontal(|ui| {
                    ui.label("Desired state");
                    ui.selectable_value(&mut state.draft.plan.desired, ServiceState::Running, "Running");
                    ui.selectable_value(&mut state.draft.plan.desired, ServiceState::Stopped, "Stopped");
                });
                }
                if let HealthCheck::Http { port, tls, path, status, contains, followups } = &mut state.draft.plan.health {
                    ui.checkbox(tls, "HTTPS with certificate verification");
                    ui.horizontal(|ui| { ui.label("HTTP port"); ui.add(egui::DragValue::new(port).range(1..=65535)); ui.label("Path"); ui.text_edit_singleline(path); });
                    ui.horizontal(|ui| { ui.label("Expected status"); ui.add(egui::DragValue::new(status).range(200..=599)); ui.label("Response contains (optional)"); ui.text_edit_singleline(contains); });
                    super::execution_panel::edit_http_steps(ui, followups);
                }
                ui.small("HTTP in clone: 127.0.0.1. HTTPS in clone: localhost with a certificate for localhost trusted by the guest. Production: selected host with a valid certificate. No TLS exceptions.");
                ui.separator();
                egui::ComboBox::from_id_salt("promotion_profile").selected_text(state.production.and_then(|id| self.profiles.iter().find(|p| p.id == id)).map(|p| p.name.as_str()).unwrap_or("Select production profile")).show_ui(ui, |ui| {
                    for p in &self.profiles { if p.protocol == Protocol::Rdp && !p.options.gateway.enabled { ui.selectable_value(&mut state.production, Some(p.id), format!("{} · {}", p.name, p.host)); } }
                });
                if ui.button("Refresh lab journals").clicked() {
                    match test_lab::journals() { Ok(l) => { state.labs = l; state.lab = None; }, Err(_) => { state.labs.clear(); state.notice = "Cannot read lab journals.".into(); } }
                }
                egui::ComboBox::from_id_salt("promotion_lab").selected_text(state.lab.and_then(|i| state.labs.get(i)).map(|l| l.name.as_str()).unwrap_or("Select running test lab")).show_ui(ui, |ui| {
                    for (i, lab) in state.labs.iter().enumerate() { if promotion::lab_target(lab).is_ok() { ui.selectable_value(&mut state.lab, Some(i), format!("{} · {}", lab.name, lab.phase)); } }
                });
                if ui.add_enabled(state.draft.plan.mappings.len() < 16, egui::Button::new("Add mapping")).clicked() {
                    if let (Some(p), Some(lab)) = (state.production.and_then(|id| self.profiles.iter().find(|p| p.id == id)), state.lab.and_then(|i| state.labs.get(i))) {
                        if let Ok(staging) = promotion::lab_target(lab) {
                            let mut candidate = state.draft.plan.clone();
                            candidate.mappings.push(Mapping { production: Target::from_profile(p), staging });
                            match promotion::validate(&candidate) { Ok(()) => state.draft.plan = candidate, Err(e) => state.notice = e.to_string() }
                        }
                    } else { state.notice = "Select production profile and test lab.".into(); }
                }
                let mut remove = None;
                for (i, mapping) in state.draft.plan.mappings.iter().enumerate() {
                    ui.horizontal(|ui| { ui.label(format!("{} ({}) ↔ {}", mapping.production.name, mapping.production.host, mapping.staging.name)); if ui.small_button("Remove").clicked() { remove = Some(i); } });
                    if let Some(lab) = state.labs.iter().find(|lab| lab.id == mapping.staging.profile_id.to_string()) { ui.small(format!("Template: {} · VM {}", lab.template, lab.vm_id)); }
                }
                if let Some(i) = remove { state.draft.plan.mappings.remove(i); }
                if state.draft.plan.hash().ok() != before { state.draft.refs.clear(); state.receipt_info.clear(); state.acknowledged = false; }
                state.health_suggestions_ui(ui, &health_model, health_incident.as_deref());
                ui.separator();
                ui.horizontal(|ui| { ui.label("Guest user for all mapped clones"); ui.text_edit_singleline(&mut state.user); });
                ui.horizontal(|ui| { ui.label("Guest password (memory only)"); ui.add(egui::TextEdit::singleline(&mut state.password).password(true)); });
                ui.label("HTTP runtime slots as JSON, e.g., {\"login_password\":\"...\"}. Guest rehearsal only; production requires separate values. Not stored.");
                ui.add(egui::TextEdit::singleline(&mut state.http_values).password(true).char_limit(32768));
                ui.checkbox(&mut state.acknowledged, "I authorize the read-only WinRM comparison with production and these service changes in the clones.");
                if ui.add_enabled(state.acknowledged && !state.user.trim().is_empty() && !state.password.is_empty(), egui::Button::new("Review rehearsal …")).clicked() {
                    match current_plan(&state.draft.plan, &self.profiles, &state.labs) {
                        Ok(_) => state.review = Some(state.draft.clone()), Err(e) => state.notice = e.to_string(),
                    }
                }
                if ui.button("Save draft").clicked() {
                    if save(&state.draft).is_err() { state.blocked = true; state.notice = "Could not save draft securely; execution blocked.".into(); }
                    else { state.notice = "Draft saved locally with DPAPI; guest credentials not saved.".into(); }
                }
                if ui.add_enabled(!state.draft.refs.is_empty(), egui::Button::new("Prepare production run …")).clicked() {
                    let checked = current_production(&state.draft.plan, &self.profiles).and_then(|_| promotion::check_receipts(&state.draft.plan, &state.draft.refs, Utc::now()));
                    match checked { Ok(()) => prepare = Some(state.draft.clone()), Err(e) => state.notice = e.to_string() }
                }
            }
            if let Some(review) = state.review.clone() {
                ui.separator(); ui.strong("Review rehearsal for execution");
                ui.label(format!("Service {} → {:?} · Restart: {} · {} clones", review.plan.service, review.plan.desired, review.plan.restart, review.plan.mappings.len()));
                if let HealthCheck::Http { port, tls, path, status, contains, followups } = &review.plan.health {
                    ui.label(format!("HTTP GET {}://{}:{port}{path} · Status {status} · Response contains: {}", if *tls { "https" } else { "http" }, if *tls { "localhost" } else { "127.0.0.1" }, if contains.is_empty() { "(no response pattern)" } else { contains }));
                    ui.label(format!("Production: identical path {path} and port {port} on each production host."));
                    for (index, step) in followups.iter().enumerate() { ui.label(format!("Step {}: {:?} {} · Status {} · Contains: {}", index + 2, step.options.method, step.path, step.status, step.contains));ui.monospace(serde_json::to_string_pretty(&step.options).unwrap_or_default()); }
                }
                for mapping in &review.plan.mappings {
                    ui.label(format!("Production {} ({}) → Clone {} · VM ID {}", mapping.production.name, mapping.production.host, mapping.staging.name, mapping.staging.host));
                    if let Some(lab) = state.labs.iter().find(|lab| lab.id == mapping.staging.profile_id.to_string()) { ui.label(format!("Template: {}", lab.template)); }
                }
                ui.label("Successful changes remain in the clone. On failure, restoration is attempted. Each piece of evidence is bound to this exact plan and valid for one hour.");
                ui.label("Before testing, the clone service must be in the opposite state: only an actual state change with a successful HTTP test can approve production.");
                ui.monospace(format!("Immutable plan: {}", review.plan.hash().unwrap_or_else(|_| "invalid — execution blocked".into())));
                if ui.button("Run rehearsal in the clones now").clicked() {
                    let checked = test_lab::journals().and_then(|labs| current_plan(&review.plan, &self.profiles, &labs));
                    match checked {
                        Err(e) => state.notice = e.to_string(),
                        Ok(labs) => {
                            let mut draft = review;
                            draft.refs.clear();
                            if save(&draft).is_err() { state.blocked = true; state.notice = "Draft not saved securely; no test started.".into(); }
                            else {
                                state.draft = draft.clone();
                                state.receipt_info.clear();
                                let user = state.user.clone(); let password = std::mem::take(&mut state.password);
                                let http_values = std::mem::replace(&mut state.http_values,"{}".into());
                                let (tx, rx) = std::sync::mpsc::channel(); state.worker = Some(rx);
                                let cancel = Arc::new(AtomicBool::new(false)); state.cancel = Some(cancel.clone());
                                std::thread::spawn(move || {
                                    let mut outcome = Outcome { draft, notice: "All clones verified successfully. Production can be prepared separately.".into(), storage_failed: false };
                                    let result = (|| -> anyhow::Result<()> {
                                        let hash = outcome.draft.plan.hash()?;
                                        let health = promotion::health(&outcome.draft.plan)?;
                                        let http_values:crate::execution::http_health::Values=serde_json::from_str(&http_values).map_err(|_|anyhow::anyhow!("HTTP runtime values require a JSON object of strings"))?;
                                        outcome.draft.plan.health.validate_values(&http_values)?;
                                        for lab in labs {
                                            anyhow::ensure!(!cancel.load(Ordering::Acquire), "Cancellation requested");
                                            crate::equivalence::observe(&outcome.draft.plan, &lab, &user, &password)?;
                                            anyhow::ensure!(!cancel.load(Ordering::Acquire), "Cancellation requested");
                                            let receipt = test_lab::execute_bound_repair_with_values(lab, user.clone(), password.clone(), outcome.draft.plan.service.clone(), outcome.draft.plan.desired == ServiceState::Running, health.clone(), hash.clone(),http_values.clone(),outcome.draft.plan.restart)?;
                                            outcome.draft.refs.push(receipt.reference());
                                            if let Err(e) = save(&outcome.draft) { outcome.storage_failed = true; return Err(e); }
                                            anyhow::ensure!(receipt.passed && !receipt.restored, "Rehearsal failed; remaining clones are unchanged");
                                        }
                                        promotion::check_rehearsal_receipts(&outcome.draft.plan, &outcome.draft.refs, Utc::now())
                                    })();
                                    if result.is_err() { outcome.notice = "Rehearsal or evidence storage failed. No production approval; check lab journals. Earlier successful clones may have changed.".into(); }
                                    if cancel.load(Ordering::Acquire) { outcome.notice = "Cancellation requested; the running rehearsal was allowed to finish, and no further clones will start. Existing evidence remains saved. Preparing production still requires complete valid evidence and a new explicit action.".into(); }
                                    let _ = tx.send(outcome);
                                });
                            }
                        }
                    }
                    state.review = None;
                }
                if ui.button("Back to draft").clicked() { state.review = None; }
            }
        });
        if state.worker.is_some() {
            ui.spinner();
            ui.label("Rehearsal runs sequentially in the clones. Production does not start automatically.");
            if let Some(cancel) = &state.cancel {
                if ui
                    .add_enabled(
                        !cancel.load(Ordering::Acquire),
                        egui::Button::new("Cancel: wait for running rehearsal"),
                    )
                    .clicked()
                {
                    cancel.store(true, Ordering::Release);
                }
                if cancel.load(Ordering::Acquire) {
                    ui.label("Cancellation requested. Waiting for the running guest check, including any restoration attempt.");
                }
            }
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
        ui.separator();
        ui.label(format!(
            "Saved test evidence: {} / {}",
            state.draft.refs.len(),
            state.draft.plan.mappings.len()
        ));
        for metadata in &state.receipt_info {
            ui.label(metadata);
        }
        if !state.draft.refs.is_empty() {
            ui.small("Evidence status is checked again when preparing production; valid for up to one hour.");
            if ui.button("Maintain recovery plan …").clicked() {
                self.view = View::RecoveryPlans;
            }
        }
        ui.label(&state.notice);
        if let Some(draft) = prepare {
            if let Err(e) = self.prepare_lab_production(draft.plan, draft.refs, draft.recovery_case)
            {
                self.promotion.notice = e.to_string();
            }
        }
    }
}
