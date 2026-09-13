use super::*;
use crate::health_suggestions::{self, Context, Proposal};
use std::sync::mpsc;

#[derive(Default)]
pub(super) struct State {
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
                    "Beschreibung, Modell oder Entwurf geändert; bisherigen Vorschlag verworfen."
                        .into();
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
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("KI-Anfrage unterbrochen".into())),
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
        egui::CollapsingHeader::new("KI-Anwendungstests vorschlagen").id_salt("health_ai_proposal").default_open(true).show(ui, |ui| {
            ui.label("Beschreibe den erwarteten Ablauf. Die KI entwirft bis zu vier HTTP-GET-Prüfschritte mit konkreten Antwortmerkmalen.");
            ui.small("Gesendet werden ausschließlich der hier angezeigte Dienstname und die beiden Textfelder. Keine Profile, Bildschirmaufnahmen, Belege oder gespeicherten Zugangsdaten. Keine Geheimnisse in die Texte eingeben.");
            ui.label(format!("Dienst: {} · Modell: {model}", self.draft.plan.service));
            ui.label("Störungsbeschreibung (vor Versand bearbeitbar)");
            ui.add(egui::TextEdit::multiline(&mut self.health_ai.incident).desired_rows(2).desired_width(720.0).char_limit(4096));
            ui.label("Beobachteter Ablauf und erwartetes Ergebnis");
            ui.add(egui::TextEdit::multiline(&mut self.health_ai.workflow).desired_rows(3).desired_width(720.0).char_limit(4096)
                .hint_text("Zum Beispiel: HTTP auf Port 8080. GET /health liefert Status 200 und ready. GET /catalog liefert Status 200 und items. Beide Aufrufe verändern keine Daten."));
            let context = self.suggestion_context();
            let Ok(binding) = self.health_binding(&context) else { return; };
            self.health_ai.sync(&binding, model);
            ui.checkbox(&mut self.health_ai.consent, "Dienstname und diese Beschreibungen für diesen Vorschlag an OpenAI senden");
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(self.health_ai.consent && self.health_ai.pending.is_none() && context.validate().is_ok(), egui::Button::new("Anwendungstests mit KI entwerfen")).clicked() {
                    let (tx,rx)=mpsc::channel();
                    self.health_ai.pending=Some(rx);
                    self.health_ai.proposal=None;
                    self.health_ai.reviewed=false;
                    self.health_ai.consent=false;
                    self.health_ai.notice="Vorschlag wird erstellt; es wird kein Anwendungstest ausgeführt.".into();
                    let model=model.to_string();
                    let source=context.clone();
                    std::thread::spawn(move || {
                        let result=health_suggestions::cloud_suggest(&source,&model).map_err(|e|e.to_string());
                        let _=tx.send(result);
                    });
                }
                if (self.health_ai.pending.is_some() || self.health_ai.proposal.is_some()) && ui.button("Vorschlag verwerfen").clicked() {
                    self.health_ai.pending=None;
                    self.health_ai.proposal=None;
                    self.health_ai.reviewed=false;
                    self.health_ai.consent=false;
                    self.health_ai.notice="Vorschlag verworfen. Eine bereits gesendete Anfrage kann beim Anbieter noch laufen.".into();
                }
            });
            if let Err(error)=context.validate() { ui.small(error.to_string()); }
            if let Some(proposal)=self.health_ai.proposal.clone() {
                ui.strong("Ungeprüfter Vorschlag — kein Erfolgsnachweis");
                if !proposal.missing.is_empty() {
                    ui.label("Für ausführbare Tests fehlen noch Angaben:");
                    for missing in &proposal.missing { ui.label(format!("• {missing}")); }
                    ui.small("Beschreibung ergänzen und einen neuen Vorschlag erstellen. Die bisherigen Tests bleiben bestehen.");
                } else {
                    ui.label(format!("{} · Port {} · Host aus der bestehenden Zielzuordnung", if proposal.tls==Some(true) {"HTTPS mit Zertifikatsprüfung"} else {"HTTP"},proposal.port.unwrap_or_default()));
                    for (index,step) in proposal.steps.iter().enumerate() {
                        ui.group(|ui| {
                            ui.strong(format!("{} · GET {}",index+1,step.path));
                            ui.label(format!("Erwartet: HTTP {} · Antwort enthält exakt: {}",step.status,step.contains));
                            ui.label(&step.rationale);
                        });
                    }
                }
                for assumption in &proposal.assumptions { ui.label(format!("Zu prüfen: {assumption}")); }
                if proposal.health().is_ok() {
                    ui.checkbox(&mut self.health_ai.reviewed,"Ich habe Port, TLS, Pfade und Antwortmerkmale geprüft; diese GET-Aufrufe verändern keine Daten.");
                    ui.small("Übernahme ersetzt alle bisherigen HTTP-Prüfschritte, verwirft Belege, HTTP-Laufzeitwerte und Ausführungsfreigaben. Anschließend ist eine neue Generalprobe erforderlich.");
                    if ui.add_enabled(self.health_ai.reviewed,egui::Button::new("Geprüfte Tests übernehmen")).clicked() {
                        match self.adopt_health_suggestion(&binding,&context,&proposal) {
                            Ok(()) => {
                                if save(&self.draft).is_err() {
                                    self.blocked=true;
                                    self.notice="Tests nicht sicher gespeichert; Ausführung gesperrt.".into();
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
