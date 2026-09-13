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
        "Entwurfsgrenze überschritten"
    );
    let raw = serde_json::to_vec(draft)?;
    anyhow::ensure!(raw.len() <= DRAFT_LIMIT, "Entwurf zu groß");
    let protected = security::protect_secret(&raw)?;
    anyhow::ensure!(
        protected.len() <= DRAFT_LIMIT,
        "Geschützter Entwurf zu groß"
    );
    security::atomic_write(&path, &protected)
}
fn load() -> anyhow::Result<Draft> {
    let path = app_data_file("relayne-promotion.dpapi")?;
    match std::fs::File::open(path) {
        Ok(file) => {
            let mut raw = Vec::new();
            file.take((DRAFT_LIMIT + 1) as u64).read_to_end(&mut raw)?;
            anyhow::ensure!(raw.len() <= DRAFT_LIMIT, "Geschützter Entwurf zu groß");
            let clear = security::unprotect_secret(&raw)?;
            anyhow::ensure!(clear.len() <= DRAFT_LIMIT, "Entwurf zu groß");
            let draft: Draft = serde_json::from_slice(&clear)?;
            anyhow::ensure!(
                draft.refs.len() <= 32 && draft.plan.mappings.len() <= 32,
                "Entwurfsgrenze überschritten"
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
                    "bestanden"
                } else {
                    "fehlgeschlagen"
                }
            ),
            Err(_) => format!("{reference} · Beleg nicht lesbar oder ungültig"),
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
                "Gespeicherter Entwurf nicht lesbar. Datei bleibt unverändert; Übernahme gesperrt."
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
            "Entwurf oder Beschreibung geändert; neuen Vorschlag erstellen"
        );
        let health = proposal.health()?;
        self.draft.plan.health = health;
        self.draft.refs.clear();
        self.receipt_info.clear();
        self.acknowledged = false;
        self.password.clear();
        self.http_values = "{}".into();
        self.health_ai = Default::default();
        self.notice = "Geprüfte Anwendungstests übernommen. Alte Belege und Freigaben verworfen; neue Generalprobe erforderlich.".into();
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
        self.notice = "Neue Generalprobe vorbereitet. Zuordnung und Gastzugänge vor Ausführung prüfen; alte Belege wurden nicht übernommen.".into();
        Ok(())
    }
    pub(super) fn can_adopt_recovery(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.blocked,
            "Testentwurf gesperrt; Speicherfehler zuerst beheben"
        );
        anyhow::ensure!(
            self.worker.is_none() && self.review.is_none(),
            "Laufende Generalprobe oder offene Freigabe zuerst abschließen oder verlassen"
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
            "Neuer Recovery-Testentwurf. Ziel und HTTP-Erfolgskriterien ausdrücklich prüfen."
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
                anyhow::anyhow!("Testlabor geändert oder nicht verfügbar; Zuordnung neu erstellen")
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
            "Produktionsprofil geändert oder entfernt; Zuordnung neu erstellen"
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
                    self.promotion.notice = "Test-Worker beendet. Persistierte Journale prüfen und Anwendung neu starten.".into();
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
                Err(_) => state.notice = "Lab-Journale nicht lesbar; bitte prüfen.".into(),
            }
        }
        ui.heading("Vom Testlabor in die Produktion");
        ui.label("1. Ziel und Klon zuordnen → 2. Dienständerung und HTTP im Klon prüfen → 3. Produktion vorbereiten und separat freigeben.");
        ui.label("Vor der Probe werden OS, Dienstdatei und Konfiguration automatisch zwischen Klon (PowerShell Direct) und Produktion (WinRM, aktueller Windows-Benutzer) verglichen. Abweichungen sperren die Übernahme.");
        if ui.button("Testlabor öffnen / Klon erstellen").clicked() {
            self.view = View::TestLab;
        }
        let before = state.draft.plan.hash().ok();
        let mut prepare = None;
        ui.add_enabled_ui(state.worker.is_none() && !state.blocked
            && (state.draft.recovery_case.is_none() || recovery_actions_allowed), |ui| {
            if state.review.is_none() {
                if state.draft.recovery_case.is_some() {
                    ui.label(format!("Recovery-Dienst: {} → Running · Neustart: {}", state.draft.plan.service, state.draft.plan.restart));
                } else {
                ui.horizontal(|ui| { ui.label("Windows-Dienst"); ui.text_edit_singleline(&mut state.draft.plan.service); });
                ui.horizontal(|ui| {
                    ui.label("Zielzustand");
                    ui.selectable_value(&mut state.draft.plan.desired, ServiceState::Running, "Running");
                    ui.selectable_value(&mut state.draft.plan.desired, ServiceState::Stopped, "Stopped");
                });
                }
                if let HealthCheck::Http { port, tls, path, status, contains, followups } = &mut state.draft.plan.health {
                    ui.checkbox(tls, "HTTPS mit Zertifikatsprüfung");
                    ui.horizontal(|ui| { ui.label("HTTP-Port"); ui.add(egui::DragValue::new(port).range(1..=65535)); ui.label("Pfad"); ui.text_edit_singleline(path); });
                    ui.horizontal(|ui| { ui.label("Erwarteter Status"); ui.add(egui::DragValue::new(status).range(200..=599)); ui.label("Antwort enthält (optional)"); ui.text_edit_singleline(contains); });
                    super::execution_panel::edit_http_steps(ui, followups);
                }
                ui.small("HTTP im Klon: 127.0.0.1. HTTPS im Klon: localhost mit im Gast vertrauenswürdigem Zertifikat für localhost. Produktion: ausgewählter Host mit gültigem Zertifikat. Keine TLS-Ausnahmen.");
                ui.separator();
                egui::ComboBox::from_id_salt("promotion_profile").selected_text(state.production.and_then(|id| self.profiles.iter().find(|p| p.id == id)).map(|p| p.name.as_str()).unwrap_or("Produktionsprofil wählen")).show_ui(ui, |ui| {
                    for p in &self.profiles { if p.protocol == Protocol::Rdp && !p.options.gateway.enabled { ui.selectable_value(&mut state.production, Some(p.id), format!("{} · {}", p.name, p.host)); } }
                });
                if ui.button("Lab-Journale aktualisieren").clicked() {
                    match test_lab::journals() { Ok(l) => { state.labs = l; state.lab = None; }, Err(_) => { state.labs.clear(); state.notice = "Lab-Journale nicht lesbar.".into(); } }
                }
                egui::ComboBox::from_id_salt("promotion_lab").selected_text(state.lab.and_then(|i| state.labs.get(i)).map(|l| l.name.as_str()).unwrap_or("Laufendes Testlabor wählen")).show_ui(ui, |ui| {
                    for (i, lab) in state.labs.iter().enumerate() { if promotion::lab_target(lab).is_ok() { ui.selectable_value(&mut state.lab, Some(i), format!("{} · {}", lab.name, lab.phase)); } }
                });
                if ui.add_enabled(state.draft.plan.mappings.len() < 16, egui::Button::new("Zuordnung hinzufügen")).clicked() {
                    if let (Some(p), Some(lab)) = (state.production.and_then(|id| self.profiles.iter().find(|p| p.id == id)), state.lab.and_then(|i| state.labs.get(i))) {
                        if let Ok(staging) = promotion::lab_target(lab) {
                            let mut candidate = state.draft.plan.clone();
                            candidate.mappings.push(Mapping { production: Target::from_profile(p), staging });
                            match promotion::validate(&candidate) { Ok(()) => state.draft.plan = candidate, Err(e) => state.notice = e.to_string() }
                        }
                    } else { state.notice = "Produktionsprofil und Testlabor auswählen.".into(); }
                }
                let mut remove = None;
                for (i, mapping) in state.draft.plan.mappings.iter().enumerate() {
                    ui.horizontal(|ui| { ui.label(format!("{} ({}) ↔ {}", mapping.production.name, mapping.production.host, mapping.staging.name)); if ui.small_button("Entfernen").clicked() { remove = Some(i); } });
                    if let Some(lab) = state.labs.iter().find(|lab| lab.id == mapping.staging.profile_id.to_string()) { ui.small(format!("Vorlage: {} · VM {}", lab.template, lab.vm_id)); }
                }
                if let Some(i) = remove { state.draft.plan.mappings.remove(i); }
                if state.draft.plan.hash().ok() != before { state.draft.refs.clear(); state.receipt_info.clear(); state.acknowledged = false; }
                state.health_suggestions_ui(ui, &health_model, health_incident.as_deref());
                ui.separator();
                ui.horizontal(|ui| { ui.label("Gastbenutzer für alle zugeordneten Klone"); ui.text_edit_singleline(&mut state.user); });
                ui.horizontal(|ui| { ui.label("Gastpasswort (nur im Arbeitsspeicher)"); ui.add(egui::TextEdit::singleline(&mut state.password).password(true)); });
                ui.label("HTTP-Laufzeit-Slots als JSON, z. B. {\"login_password\":\"...\"}. Nur Gastprobe; Produktion benötigt separate Werte. Keine Speicherung.");
                ui.add(egui::TextEdit::singleline(&mut state.http_values).password(true).char_limit(32768));
                ui.checkbox(&mut state.acknowledged, "Ich autorisiere den lesenden WinRM-Vergleich mit Produktion und diese Dienständerungen in den Klonen.");
                if ui.add_enabled(state.acknowledged && !state.user.trim().is_empty() && !state.password.is_empty(), egui::Button::new("Generalprobe prüfen …")).clicked() {
                    match current_plan(&state.draft.plan, &self.profiles, &state.labs) {
                        Ok(_) => state.review = Some(state.draft.clone()), Err(e) => state.notice = e.to_string(),
                    }
                }
                if ui.button("Entwurf speichern").clicked() {
                    if save(&state.draft).is_err() { state.blocked = true; state.notice = "Entwurf konnte nicht sicher gespeichert werden; Ausführung gesperrt.".into(); }
                    else { state.notice = "Entwurf lokal mit DPAPI gespeichert; Gastzugangsdaten nicht gespeichert.".into(); }
                }
                if ui.add_enabled(!state.draft.refs.is_empty(), egui::Button::new("Produktionslauf vorbereiten …")).clicked() {
                    let checked = current_production(&state.draft.plan, &self.profiles).and_then(|_| promotion::check_receipts(&state.draft.plan, &state.draft.refs, Utc::now()));
                    match checked { Ok(()) => prepare = Some(state.draft.clone()), Err(e) => state.notice = e.to_string() }
                }
            }
            if let Some(review) = state.review.clone() {
                ui.separator(); ui.strong("Generalprobe zur Ausführung prüfen");
                ui.label(format!("Dienst {} → {:?} · Neustart: {} · {} Klone", review.plan.service, review.plan.desired, review.plan.restart, review.plan.mappings.len()));
                if let HealthCheck::Http { port, tls, path, status, contains, followups } = &review.plan.health {
                    ui.label(format!("HTTP GET {}://{}:{port}{path} · Status {status} · Antwort enthält: {}", if *tls { "https" } else { "http" }, if *tls { "localhost" } else { "127.0.0.1" }, if contains.is_empty() { "(kein Antwortmuster)" } else { contains }));
                    ui.label(format!("Produktion: identischer Pfad {path} und Port {port} am jeweiligen Produktionshost."));
                    for (index, step) in followups.iter().enumerate() { ui.label(format!("Schritt {}: {:?} {} · Status {} · enthält: {}", index + 2, step.options.method, step.path, step.status, step.contains));ui.monospace(serde_json::to_string_pretty(&step.options).unwrap_or_default()); }
                }
                for mapping in &review.plan.mappings {
                    ui.label(format!("Produktion {} ({}) → Klon {} · VM-ID {}", mapping.production.name, mapping.production.host, mapping.staging.name, mapping.staging.host));
                    if let Some(lab) = state.labs.iter().find(|lab| lab.id == mapping.staging.profile_id.to_string()) { ui.label(format!("Vorlage: {}", lab.template)); }
                }
                ui.label("Erfolgreiche Änderungen bleiben im Klon. Bei Fehler wird eine Wiederherstellung versucht. Jeder Beleg ist an exakt diesen Plan gebunden und für eine Stunde gültig.");
                ui.label("Der Klondienst muss vor dem Test im jeweils anderen Zustand sein: Nur ein tatsächlicher Zustandswechsel mit erfolgreichem HTTP-Test kann Produktion freigeben.");
                ui.monospace(format!("Unveränderlicher Plan: {}", review.plan.hash().unwrap_or_else(|_| "ungültig — Ausführung gesperrt".into())));
                if ui.button("Generalprobe jetzt in den Klonen ausführen").clicked() {
                    let checked = test_lab::journals().and_then(|labs| current_plan(&review.plan, &self.profiles, &labs));
                    match checked {
                        Err(e) => state.notice = e.to_string(),
                        Ok(labs) => {
                            let mut draft = review;
                            draft.refs.clear();
                            if save(&draft).is_err() { state.blocked = true; state.notice = "Entwurf nicht sicher gespeichert; kein Test gestartet.".into(); }
                            else {
                                state.draft = draft.clone();
                                state.receipt_info.clear();
                                let user = state.user.clone(); let password = std::mem::take(&mut state.password);
                                let http_values = std::mem::replace(&mut state.http_values,"{}".into());
                                let (tx, rx) = std::sync::mpsc::channel(); state.worker = Some(rx);
                                let cancel = Arc::new(AtomicBool::new(false)); state.cancel = Some(cancel.clone());
                                std::thread::spawn(move || {
                                    let mut outcome = Outcome { draft, notice: "Alle Klone erfolgreich geprüft. Produktion kann separat vorbereitet werden.".into(), storage_failed: false };
                                    let result = (|| -> anyhow::Result<()> {
                                        let hash = outcome.draft.plan.hash()?;
                                        let health = promotion::health(&outcome.draft.plan)?;
                                        let http_values:crate::execution::http_health::Values=serde_json::from_str(&http_values).map_err(|_|anyhow::anyhow!("HTTP-Laufzeitwerte benötigen ein JSON-Objekt aus Strings"))?;
                                        outcome.draft.plan.health.validate_values(&http_values)?;
                                        for lab in labs {
                                            anyhow::ensure!(!cancel.load(Ordering::Acquire), "Abbruch angefordert");
                                            crate::equivalence::observe(&outcome.draft.plan, &lab, &user, &password)?;
                                            anyhow::ensure!(!cancel.load(Ordering::Acquire), "Abbruch angefordert");
                                            let receipt = test_lab::execute_bound_repair_with_values(lab, user.clone(), password.clone(), outcome.draft.plan.service.clone(), outcome.draft.plan.desired == ServiceState::Running, health.clone(), hash.clone(),http_values.clone(),outcome.draft.plan.restart)?;
                                            outcome.draft.refs.push(receipt.reference());
                                            if let Err(e) = save(&outcome.draft) { outcome.storage_failed = true; return Err(e); }
                                            anyhow::ensure!(receipt.passed && !receipt.restored, "Generalprobe fehlgeschlagen; weitere Klone bleiben unverändert");
                                        }
                                        promotion::check_rehearsal_receipts(&outcome.draft.plan, &outcome.draft.refs, Utc::now())
                                    })();
                                    if result.is_err() { outcome.notice = "Generalprobe oder Belegspeicherung fehlgeschlagen. Keine Produktionsfreigabe; Lab-Journale prüfen. Erfolgreiche vorherige Klone können geändert sein.".into(); }
                                    if cancel.load(Ordering::Acquire) { outcome.notice = "Abbruch angefordert; die laufende Probe wurde abgewartet und weitere Klone werden nicht gestartet. Vorhandene Belege bleiben gespeichert. Eine Produktionsvorbereitung erfordert weiterhin vollständige gültige Belege und eine neue ausdrückliche Aktion.".into(); }
                                    let _ = tx.send(outcome);
                                });
                            }
                        }
                    }
                    state.review = None;
                }
                if ui.button("Zurück zum Entwurf").clicked() { state.review = None; }
            }
        });
        if state.worker.is_some() {
            ui.spinner();
            ui.label("Generalprobe läuft sequenziell in den Klonen. Produktion wird nicht automatisch gestartet.");
            if let Some(cancel) = &state.cancel {
                if ui
                    .add_enabled(
                        !cancel.load(Ordering::Acquire),
                        egui::Button::new("Abbrechen: laufende Probe abwarten"),
                    )
                    .clicked()
                {
                    cancel.store(true, Ordering::Release);
                }
                if cancel.load(Ordering::Acquire) {
                    ui.label("Abbruch vorgemerkt. Die laufende Gastprüfung einschließlich Wiederherstellungsversuch wird abgewartet.");
                }
            }
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
        ui.separator();
        ui.label(format!(
            "Gespeicherte Testbelege: {} / {}",
            state.draft.refs.len(),
            state.draft.plan.mappings.len()
        ));
        for metadata in &state.receipt_info {
            ui.label(metadata);
        }
        if !state.draft.refs.is_empty() {
            ui.small("Belegstatus wird bei der Produktionsvorbereitung erneut geprüft; maximal eine Stunde gültig.");
            if ui.button("Wiederherstellungsplan pflegen …").clicked() {
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
