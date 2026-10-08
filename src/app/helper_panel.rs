//! One local case workspace. Intake controls never enqueue work.
use super::*;
use crate::helper::{
    case::{Answer, CaseEdit, HelperCase, ProblemIntake},
    store::HelperStore,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

mod change_ui;
mod connectors_ui;
mod evidence_ui;
mod intake_ui;
mod planning_ui;
mod scope_ui;
mod sql_ui;

pub(super) struct HelperState {
    store: Option<HelperStore>,
    path: Option<PathBuf>,
    selected: Option<Uuid>,
    worker: Option<crate::helper::worker::HelperWorker>,
    authority: Arc<crate::helper::worker::SnapshotProbeAuthority>,
    collect_jobs: HashMap<Uuid, connectors_ui::CaptureJob>,
    last_capture: HashMap<(String, crate::helper::manifest::CapabilityId), String>,
    collect_attempts: HashMap<(Uuid, String), (&'static str, bool)>,
    editor: intake_ui::Editor,
    scope_editor: scope_ui::Editor,
    system_inputs: connectors_ui::SystemInputs,
    advisory_rx: Option<
        std::sync::mpsc::Receiver<anyhow::Result<crate::helper::advisory::AdvisoryProposal>>,
    >,
    advisory_cancel: Option<tokio_util::sync::CancellationToken>,
    advisory_candidate: Option<crate::helper::planner::HelperPlan>,
    confirmation_actor: String,
    confirmation_rationale: String,
    confirmation_kind: Option<crate::helper::planner::HypothesisKind>,
    reviewed_proposal: Option<crate::helper::catalog::HelperProposal>,
    statistics_limit_acknowledged: bool,
    statistics_ack_case: Option<(Uuid, u64)>,
    recipe_key_input: String,
    recipe_entry_input: String,
    recipe_key_reviewed: bool,
    recipe_entry_reviewed: bool,
    notice: String,
}

impl HelperState {
    pub(super) fn load() -> Self {
        match HelperStore::path() {
            Ok(path) => Self::at_path(path),
            Err(e) => Self {
                store: None,
                path: None,
                selected: None,
                worker: None,
                authority: Arc::default(),
                collect_jobs: HashMap::new(),
                last_capture: HashMap::new(),
                collect_attempts: HashMap::new(),
                editor: Default::default(),
                scope_editor: Default::default(),
                system_inputs: Default::default(),
                advisory_rx: None,
                advisory_cancel: None,
                advisory_candidate: None,
                confirmation_actor: String::new(),
                confirmation_rationale: String::new(),
                confirmation_kind: None,
                reviewed_proposal: None,
                statistics_limit_acknowledged: false,
                statistics_ack_case: None,
                recipe_key_input: String::new(),
                recipe_entry_input: String::new(),
                recipe_key_reviewed: false,
                recipe_entry_reviewed: false,
                notice: format!("Helper storage unavailable: {e}"),
            },
        }
    }
    fn at_path(path: PathBuf) -> Self {
        let recovery = HelperStore::inspect_locked(&path, |snapshot| {
            crate::helper::credentials::reconcile_scoped_at(
                &path.with_file_name("credentials.scoped.dpapi"),
                snapshot.cases(),
            )
        });
        match HelperStore::load(&path) {
            Ok(mut store) => {
                if store.cancel_abandoned_pending_captures() {
                    if let Err(error) = store.save(&path) {
                        return Self::unavailable(
                            path,
                            format!("Pending capture recovery failed: {error}"),
                        );
                    }
                }
                Self {
                    store: Some(store),
                    path: Some(path),
                    selected: None,
                    worker: None,
                    authority: Arc::default(),
                    collect_jobs: HashMap::new(),
                    last_capture: HashMap::new(),
                    collect_attempts: HashMap::new(),
                    editor: Default::default(),
                    scope_editor: Default::default(),
                    system_inputs: Default::default(),
                    advisory_rx: None,
                    advisory_cancel: None,
                    advisory_candidate: None,
                    confirmation_actor: String::new(),
                    confirmation_rationale: String::new(),
                    confirmation_kind: None,
                    reviewed_proposal: None,
                    statistics_limit_acknowledged: false,
                    statistics_ack_case: None,
                    recipe_key_input: String::new(),
                    recipe_entry_input: String::new(),
                    recipe_key_reviewed: false,
                    recipe_entry_reviewed: false,
                    notice: if recovery.is_ok() {
                        "Case workspace loaded".into()
                    } else {
                        "Case workspace loaded; protected credential recovery needs attention"
                            .into()
                    },
                }
            }
            Err(e) => Self {
                store: None,
                path: Some(path),
                selected: None,
                worker: None,
                authority: Arc::default(),
                collect_jobs: HashMap::new(),
                last_capture: HashMap::new(),
                collect_attempts: HashMap::new(),
                editor: Default::default(),
                scope_editor: Default::default(),
                system_inputs: Default::default(),
                advisory_rx: None,
                advisory_cancel: None,
                advisory_candidate: None,
                confirmation_actor: String::new(),
                confirmation_rationale: String::new(),
                confirmation_kind: None,
                reviewed_proposal: None,
                statistics_limit_acknowledged: false,
                statistics_ack_case: None,
                recipe_key_input: String::new(),
                recipe_entry_input: String::new(),
                recipe_key_reviewed: false,
                recipe_entry_reviewed: false,
                notice: format!(
                    "Helper store could not be loaded: {e}. Repair or restore the file before editing."
                ),
            },
        }
    }
    fn current(&self) -> Option<&HelperCase> {
        let id = self.selected?;
        self.store.as_ref()?.case(id)
    }
    fn select(&mut self, id: Uuid) {
        self.scope_editor.clear_cloud_draft();
        self.reviewed_proposal = None;
        self.statistics_limit_acknowledged = false;
        self.statistics_ack_case = None;
        if let Some(cancel) = self.advisory_cancel.take() {
            cancel.cancel();
        }
        self.advisory_rx = None;
        self.advisory_candidate = None;
        self.confirmation_kind = None;
        self.selected = Some(id);
        self.editor = self
            .current()
            .map(intake_ui::Editor::from_case)
            .unwrap_or_default();
    }
    fn create(&mut self) {
        let result = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))
            .and_then(|s| s.create(ProblemIntake::default()));
        match result {
            Ok(id) => {
                self.select(id);
                self.notice = "New case created locally. Save to keep it.".into();
            }
            Err(e) => self.notice = e.to_string(),
        }
    }
    fn revise(&mut self, edit: CaseEdit) {
        self.reviewed_proposal = None;
        self.statistics_limit_acknowledged = false;
        self.statistics_ack_case = None;
        if let Some(cancel) = self.advisory_cancel.take() {
            cancel.cancel();
        }
        self.advisory_rx = None;
        self.advisory_candidate = None;
        let result = self
            .current()
            .map(|c| (c.id(), c.revision()))
            .ok_or_else(|| anyhow::anyhow!("Select a case"))
            .and_then(|(id, rev)| self.store.as_mut().unwrap().revise(id, rev, edit));
        self.notice = match result {
            Ok(rev) => format!("Answer recorded at revision {rev}. Save to keep it."),
            Err(e) => format!("Answer not recorded: {e}"),
        };
    }
    fn save(&mut self) {
        self.notice = match (&mut self.store, &self.path) {
            (Some(store), Some(path)) => match store.save(path) {
                Ok(()) => "Case workspace saved securely".into(),
                Err(e) => format!("Save failed: {e}"),
            },
            _ => "Case store unavailable".into(),
        };
    }
    fn reload(&mut self) {
        if !self.collect_jobs.is_empty() {
            self.notice = "Wait for or cancel captures before reloading cases".into();
            return;
        }
        if let Some(cancel) = self.advisory_cancel.take() {
            cancel.cancel();
        }
        if let Some(path) = self.path.clone() {
            let mut replacement = Self::at_path(path);
            if let Some(id) = self.selected {
                replacement.select(id);
            }
            *self = replacement;
        }
    }
    fn unavailable(path: PathBuf, notice: String) -> Self {
        Self {
            store: None,
            path: Some(path),
            selected: None,
            worker: None,
            authority: Arc::default(),
            collect_jobs: HashMap::new(),
            last_capture: HashMap::new(),
            collect_attempts: HashMap::new(),
            editor: Default::default(),
            scope_editor: Default::default(),
            system_inputs: Default::default(),
            advisory_rx: None,
            advisory_cancel: None,
            advisory_candidate: None,
            confirmation_actor: String::new(),
            confirmation_rationale: String::new(),
            confirmation_kind: None,
            reviewed_proposal: None,
            statistics_limit_acknowledged: false,
            statistics_ack_case: None,
            recipe_key_input: String::new(),
            recipe_entry_input: String::new(),
            recipe_key_reviewed: false,
            recipe_entry_reviewed: false,
            notice,
        }
    }
    pub(super) fn adopt_incident(&mut self, source: crate::incident::Source) {
        let result = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))
            .and_then(|s| s.adopt_incident(source));
        match result {
            Ok(id) => {
                self.select(id);
                self.notice = "Incident copied for review. Save the case when ready.".into();
            }
            Err(e) => self.notice = format!("Import failed: {e}"),
        }
    }
    pub(super) fn adopt_ticket(&mut self, ticket: &crate::ticket_intake::NormalizedTicket) {
        let reference = crate::helper::case::TicketReference {
            origin: ticket.origin.clone(),
            source_id: ticket.key.clone(),
        };
        let result = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))
            .and_then(|s| s.adopt_ticket(reference, &ticket.title, &ticket.description));
        match result {
            Ok(id) => {
                self.select(id);
                self.notice = "Ticket copied for review. Save the case when ready.".into();
            }
            Err(e) => self.notice = format!("Import failed: {e}"),
        }
    }
}

impl AivanaApp {
    pub(super) fn poll_helper(&mut self) {
        self.helper.poll_advisory();
        self.helper.poll_collect(&self.profiles);
    }
    pub(super) fn helper_view(&mut self, ui: &mut Ui) {
        ui.heading("IT Helper · Describe");
        ui.label("Describe the symptom and review the facts before selecting a target or collecting evidence.");
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.helper.store.is_some(), egui::Button::new("New case"))
                .clicked()
            {
                self.helper.create();
            }
            if ui
                .add_enabled(self.helper.store.is_some(), egui::Button::new("Save cases"))
                .clicked()
            {
                self.helper.save();
            }
            if ui.button("Reload saved cases").clicked() {
                self.helper.reload();
            }
        });
        ui.label(&self.helper.notice);
        let ids = self
            .helper
            .store
            .as_ref()
            .map(|s| {
                s.cases()
                    .iter()
                    .map(|c| (c.id(), c.intake().description.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !ids.is_empty() {
            egui::ComboBox::from_id_salt("helper-case-select")
                .selected_text(
                    self.helper
                        .current()
                        .map(|c| format!("Case {} · revision {}", c.id(), c.revision()))
                        .unwrap_or_else(|| "Select case".into()),
                )
                .show_ui(ui, |ui| {
                    for (id, description) in ids {
                        let title = match description {
                            Answer::Known(s) => s.chars().take(48).collect::<String>(),
                            Answer::Unknown => "Unknown problem".into(),
                            Answer::Unanswered => "Untitled case".into(),
                        };
                        if ui
                            .selectable_label(self.helper.selected == Some(id), title)
                            .clicked()
                        {
                            self.helper.select(id);
                        }
                    }
                });
        }
        if let Some(case) = self.helper.current().cloned() {
            intake_ui::show(&mut self.helper, ui, &case);
            scope_ui::show(
                &mut self.helper,
                ui,
                &case,
                &self.profiles,
                &self.insights.store,
            );
            connectors_ui::show(&mut self.helper, ui, &case, &self.profiles);
            sql_ui::show(&mut self.helper, ui, &case, &self.profiles);
            if let Some(store) = self.helper.store.as_ref() {
                evidence_ui::show(ui, &case, store);
            }
            planning_ui::show(&mut self.helper, ui, &case);
            change_ui::show(&mut self.helper, ui, &case);
        } else if self.helper.store.is_some() {
            ui.label("Create or select a case to begin.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn navigation_save_and_answers_dispatch_zero_jobs() {
        let ctx = egui::Context::default();
        let mut app = AivanaApp::from_context(&ctx);
        let dir = std::env::temp_dir().join(format!("relayne-helper-ui-{}", Uuid::new_v4()));
        let path = dir.join("cases.dpapi");
        app.helper = HelperState::at_path(path);
        app.view = View::Helper;
        app.helper.create();
        app.helper
            .revise(CaseEdit::Description(Answer::Known("App slow".into())));
        app.helper.revise(CaseEdit::OnsetFrequency(Answer::Unknown));
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.helper_view(ui));
        });
        app.helper.save();
        app.view = View::Incident;
        app.view = View::Helper;
        app.helper.reload();
        app.poll_helper();
        assert_eq!(app.helper.current().unwrap().revision(), 3);
        assert!(matches!(
            app.helper.current().unwrap().intake().onset_frequency,
            Answer::Unknown
        ));
        assert!(
            app.operations.queue.jobs.is_empty(),
            "Intake/navigation must not dispatch jobs"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn reviewed_scope_navigation_and_reload_dispatch_zero_jobs() {
        let ctx = egui::Context::default();
        let mut app = AivanaApp::from_context(&ctx);
        let dir = std::env::temp_dir().join(format!("relayne-helper-scope-ui-{}", Uuid::new_v4()));
        app.helper = HelperState::at_path(dir.join("cases.dpapi"));
        app.helper.create();
        let profile = ConnectionProfile::sample("scope", "host.local", "", false);
        app.profiles.push(profile.clone());
        app.helper.revise(CaseEdit::Profiles(vec![profile.id]));
        let scope = crate::helper::scope::BoundScope::Windows {
            target: crate::mission::Target::from_profile(&profile),
            credential: None,
        };
        app.helper.revise(CaseEdit::Scopes(vec![scope]));
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.helper_view(ui));
        });
        app.helper.save();
        app.view = View::Incident;
        app.view = View::Helper;
        app.helper.reload();
        app.poll_helper();
        assert_eq!(app.helper.current().unwrap().scopes().len(), 1);
        assert!(app.operations.queue.jobs.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_case_discards_late_advice_and_navigation_dispatches_zero_jobs() {
        use crate::helper::advisory::{AdvisoryPreview, AdvisoryProposal, PreviewField};
        let ctx = egui::Context::default();
        let mut app = AivanaApp::from_context(&ctx);
        let dir =
            std::env::temp_dir().join(format!("relayne-helper-planning-ui-{}", Uuid::new_v4()));
        app.helper = HelperState::at_path(dir.join("cases.dpapi"));
        app.helper.create();
        let case = app.helper.current().unwrap().clone();
        let preview = AdvisoryPreview::from_case(&case, &[PreviewField::Description]).unwrap();
        let proposal = AdvisoryProposal {
            case_id: case.id(),
            case_revision: case.revision(),
            evidence_revision: case.evidence_revision(),
            preview_digest: preview.digest().unwrap(),
            preview_fields: preview.fields,
            questions: vec![],
            hypotheses: vec![],
            steps: vec![],
        };
        let (tx, rx) = std::sync::mpsc::channel();
        app.helper.advisory_rx = Some(rx);
        app.helper
            .store
            .as_mut()
            .unwrap()
            .revise(
                case.id(),
                case.revision(),
                CaseEdit::Description(Answer::Known("Changed while AI worked".into())),
            )
            .unwrap();
        tx.send(Ok(proposal)).unwrap();
        app.poll_helper();
        assert!(app.helper.advisory_candidate.is_none());
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.helper_view(ui));
        });
        assert!(app.operations.queue.jobs.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }
}
