use super::*;
use crate::health_suggestions::{self, Context, Proposal};
use std::sync::mpsc;

#[derive(Default)]
pub(super) struct State {
    recording: crate::application_checks::ImportState,
    initialized: bool,
    incident: String,
    workflow: String,
    binding: String,
    model: String,
    consent: bool,
    reviewed: bool,
    pending: Option<mpsc::Receiver<Result<Proposal, String>>>,
    proposal: Option<Proposal>,
    notice: String,
}
impl State {
    fn sync(&mut self, binding: &str, model: &str) {
        if self.binding != binding || self.model != model {
            if self.pending.is_some() || self.proposal.is_some() {
                self.notice =
                    "Description, model, or draft changed; previous proposal discarded.".into();
            }
            self.binding = binding.into();
            self.model = model.into();
            self.consent = false;
            self.reviewed = false;
            self.pending = None;
            self.proposal = None;
        }
    }
    fn poll(&mut self) {
        let result = self.pending.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("AI request interrupted".into())),
            Err(mpsc::TryRecvError::Empty) => None,
        });
        if let Some(result) = result {
            self.pending = None;
            self.reviewed = false;
            match result {
                Ok(proposal) => {
                    self.proposal = Some(proposal);
                    self.notice.clear();
                }
                Err(error) => {
                    self.proposal = None;
                    self.notice = error;
                }
            }
        }
    }
}
impl PromotionState {
    fn suggestion_context(&self) -> Context {
        Context {
            service: self.draft.plan.service.clone(),
            incident: self.health_ai.incident.clone(),
            workflow: self.health_ai.workflow.clone(),
        }
    }
    pub(super) fn health_suggestions_ui(
        &mut self,
        ui: &mut Ui,
        model: &str,
        incident: Option<&str>,
    ) {
        self.recorded_application_checks_ui(ui);
        if !self.health_ai.initialized {
            self.health_ai.initialized = true;
            self.health_ai.incident = incident.unwrap_or_default().into();
        }
        let context = self.suggestion_context();
        let Ok(binding) = self.health_binding(&context) else {
            return;
        };
        self.health_ai.sync(&binding, model);
        self.health_ai.poll();
        ui.separator();
        egui::CollapsingHeader::new("Suggest AI application checks").id_salt("health_ai_proposal").default_open(true).show(ui, |ui| {
            ui.label("Describe the expected workflow. AI proposes up to four HTTP GET checks with specific response assertions.");
            ui.small("Only the service name shown here and these two text fields are sent. Profiles, recordings, evidence, and stored credentials are excluded. Do not enter secrets.");
            ui.label(format!("Service: {} · Model: {model}", self.draft.plan.service));
            ui.label("Incident description (editable before sending)");
            ui.add(egui::TextEdit::multiline(&mut self.health_ai.incident).desired_rows(2).desired_width(720.0).char_limit(4096));
            ui.label("Observed workflow and expected result");
            ui.add(egui::TextEdit::multiline(&mut self.health_ai.workflow).desired_rows(3).desired_width(720.0).char_limit(4096)
                .hint_text("Example: HTTP on port 8080. GET /health returns status 200 and ready. GET /catalog returns status 200 and items. Both requests are read-only."));
            let context = self.suggestion_context();
            let Ok(binding) = self.health_binding(&context) else { return; };
            self.health_ai.sync(&binding, model);
            ui.checkbox(&mut self.health_ai.consent, "Send the service name and these descriptions to OpenAI for this proposal");
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(self.health_ai.consent && self.health_ai.pending.is_none() && context.validate().is_ok(), egui::Button::new("Draft application checks with AI")).clicked() {
                    let (tx,rx)=mpsc::channel();
                    self.health_ai.pending=Some(rx);
                    self.health_ai.proposal=None;
                    self.health_ai.reviewed=false;
                    self.health_ai.consent=false;
                    self.health_ai.notice="Creating proposal; no application check is running.".into();
                    let model=model.to_string();
                    let source=context.clone();
                    std::thread::spawn(move || {
                        let result=health_suggestions::cloud_suggest(&source,&model).map_err(|e|e.to_string());
                        let _=tx.send(result);
                    });
                }
                if (self.health_ai.pending.is_some() || self.health_ai.proposal.is_some()) && ui.button("Discard proposal").clicked() {
                    self.health_ai.pending=None;
                    self.health_ai.proposal=None;
                    self.health_ai.reviewed=false;
                    self.health_ai.consent=false;
                    self.health_ai.notice="Proposal discarded. A previously sent request may still be running at the provider.".into();
                }
            });
            if let Err(error)=context.validate() { ui.small(error.to_string()); }
            if let Some(proposal)=self.health_ai.proposal.clone() {
                ui.strong("Unreviewed proposal — not evidence of success");
                if !proposal.missing.is_empty() {
                    ui.label("Executable checks require more information:");
                    for missing in &proposal.missing { ui.label(format!("• {missing}")); }
                    ui.small("Expand the description and create a new proposal. Existing checks are retained.");
                } else {
                    ui.label(format!("{} · Port {} · Host from the existing target mapping", if proposal.tls==Some(true) {"HTTPS with certificate verification"} else {"HTTP"},proposal.port.unwrap_or_default()));
                    for (index,step) in proposal.steps.iter().enumerate() {
                        ui.group(|ui| {
                            ui.strong(format!("{} · GET {}",index+1,step.path));
                            ui.label(format!("Expected: HTTP {} · Response contains exactly: {}",step.status,step.contains));
                            ui.label(&step.rationale);
                        });
                    }
                }
                for assumption in &proposal.assumptions { ui.label(format!("Review: {assumption}")); }
                if proposal.health().is_ok() {
                    ui.checkbox(&mut self.health_ai.reviewed,"I reviewed the port, TLS, paths, and response assertions; these GET requests are read-only.");
                    ui.small("Adoption replaces all existing HTTP checks and clears evidence, HTTP runtime values, and execution approvals. A new rehearsal is required.");
                    if ui.add_enabled(self.health_ai.reviewed,egui::Button::new("Adopt reviewed checks")).clicked() {
                        match self.adopt_health_suggestion(&binding,&context,&proposal) {
                            Ok(()) => {
                                if save(&self.draft).is_err() {
                                    self.blocked=true;
                                    self.notice="Checks were not safely saved; execution blocked.".into();
                                }
                            }
                            Err(error) => self.health_ai.notice=error.to_string(),
                        }
                    }
                }
            }
            ui.label(&self.health_ai.notice);
        });
        if self.health_ai.pending.is_some() {
            ui.spinner();
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}

impl PromotionState {
    fn recorded_application_checks_ui(&mut self, ui: &mut Ui) {
        egui::CollapsingHeader::new("Recorded application and login checks").default_open(true).show(ui, |ui| {
            ui.label("Paste a redacted request recording to build executable checks for the existing rehearsal pipeline. Import and review run locally.");
            ui.small("Use the documented version 1 JSON schema. Include response assertions and named credential slots only. Browser screenshots, raw HAR files, cookies, tokens, passwords, JavaScript, and UI clicks are unsupported. This does not establish browser behavior or AI quality.");
            if ui.add(egui::TextEdit::multiline(&mut self.health_ai.recording.input).desired_rows(5).desired_width(720.0).char_limit(32768)).changed() {
                self.health_ai.recording.reviewed = false;
            }
            if self.health_ai.recording.input.trim().is_empty() { return; }
            let recording = match crate::application_checks::Recording::parse(&self.health_ai.recording.input) {
                Ok(value) => value,
                Err(error) => { self.health_ai.recording.reviewed = false; ui.label(format!("Recording rejected: {error}")); return; }
            };
            let Ok(draft_binding) = self.health_binding(&self.suggestion_context()) else { return; };
            let Ok(binding) = recording.digest(&draft_binding) else { return; };
            self.health_ai.recording.sync(&binding);
            ui.strong(&recording.title);
            ui.label(format!("{} · port {} · host comes from the existing target mapping", if recording.tls { "HTTPS" } else { "HTTP" }, recording.port));
            for step in &recording.steps {
                ui.label(format!("{} {} → {} · text {:?} · JSON assertions {} · runtime slots: {}", if step.login_slots.is_empty() { "GET" } else { "POST" }, step.path, step.status, step.contains, step.json_equals.len(), step.login_slots.values().cloned().collect::<Vec<_>>().join(", ")));
                for (pointer, expected) in &step.json_equals { ui.small(format!("JSON {pointer} = {expected}")); }
            }
            ui.checkbox(&mut self.health_ai.recording.reviewed, "I reviewed the target, login POST effects, runtime slots, and assertions. Replace existing checks.");
            if ui.add_enabled(self.health_ai.recording.reviewed && self.can_adopt_recovery().is_ok(), egui::Button::new("Adopt recorded checks")).clicked() {
                let result = (|| -> anyhow::Result<()> {
                    self.can_adopt_recovery()?;
                    anyhow::ensure!(recording.digest(&self.health_binding(&self.suggestion_context())?)? == binding, "Draft changed; review the recording again");
                    self.draft.plan.health = recording.health()?;
                    self.draft.refs.clear();
                    self.receipt_info.clear();
                    self.acknowledged = false;
                    self.password.clear();
                    self.http_values = "{}".into();
                    self.health_ai = Default::default();
                    if save(&self.draft).is_err() { self.blocked = true; anyhow::bail!("Checks changed in memory, but saving failed; execution is blocked"); }
                    Ok(())
                })();
                self.notice = match result { Ok(()) => "Recorded checks adopted. Previous evidence and approvals cleared; run a new rehearsal.".into(), Err(error) => error.to_string() };
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn health_suggestions_render_review_at_narrow_and_wide_sizes_without_launching() {
        for width in [640.0, 1440.0] {
            let ctx = egui::Context::default();
            let mut state = PromotionState::default();
            state.blocked = false;
            state.draft.plan = crate::promotion::tests::plan();
            state.health_ai.initialized = true;
            state.health_ai.recording.input = r#"{"schema_version":1,"title":"Recorded sign-in","port":443,"tls":true,"steps":[{"path":"/login","status":200,"contains":"Sign in"},{"path":"/session","status":200,"contains":"Welcome","login_slots":{"password":"test_password"}}]}"#.into();
            state.health_ai.incident = "Anwendung ausgefallen".into();
            let binding = state.health_binding(&state.suggestion_context()).unwrap();
            state.health_ai.sync(&binding, "test-model");
            state.health_ai.proposal = Some(Proposal {
                port: Some(8080),
                tls: Some(false),
                steps: vec![health_suggestions::Step {
                    path: "/health".into(),
                    status: 200,
                    contains: "ready".into(),
                    rationale: "Prüft Anwendungsbereitschaft".into(),
                }],
                assumptions: vec!["GET verändert keine Daten".into()],
                missing: vec![],
            });
            let before = state.health_binding(&state.suggestion_context()).unwrap();
            let out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 1200.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        state.health_suggestions_ui(ui, "test-model", None)
                    });
                },
            );
            assert!(!out.shapes.is_empty());
            assert!(state.health_ai.pending.is_none() && state.worker.is_none());
            assert_eq!(
                before,
                state.health_binding(&state.suggestion_context()).unwrap()
            );
            assert!(!state.health_ai.reviewed);
        }
    }
    #[test]
    fn health_suggestions_changed_input_discards_late_reply_and_consent() {
        let mut state = State::default();
        state.sync("draft-a", "model-a");
        state.consent = true;
        state.reviewed = true;
        let (tx, rx) = mpsc::channel();
        state.pending = Some(rx);
        state.sync("draft-b", "model-a");
        assert!(!state.consent && !state.reviewed && state.pending.is_none());
        assert!(tx.send(Err("old reply".into())).is_err());
        state.poll();
        assert!(state.proposal.is_none());
        state.consent = true;
        state.sync("draft-b", "model-b");
        assert!(!state.consent);
    }
}
