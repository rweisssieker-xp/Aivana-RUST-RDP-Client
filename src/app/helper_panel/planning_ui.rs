use super::*;
use crate::helper::{
    advisory::{
        AdvisoryConsent, AdvisoryPreview, PreviewField, request_advisory, validate_advisory,
    },
    manifest::CapabilityManifest,
    planner::{HelperPlan, HumanConfirmation, plan_local},
};

const FIELDS: &[PreviewField] = &[
    PreviewField::Description,
    PreviewField::AffectedScope,
    PreviewField::Impact,
    PreviewField::OnsetFrequency,
    PreviewField::Environment,
    PreviewField::RecentChanges,
    PreviewField::EvidenceIds,
];

impl HelperState {
    pub(super) fn poll_advisory(&mut self) {
        let result = self.advisory_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        let Some(result) = result else {
            return;
        };
        self.advisory_rx = None;
        self.advisory_cancel = None;
        let case = self.current().cloned();
        self.notice = match (case, result) {
            (Some(case), Ok(proposal)) => {
                // This lookup happens at completion, after any intervening case/evidence change.
                match validate_advisory(&case, &CapabilityManifest::built_in(), proposal) {
                    Ok(plan) => {
                        self.advisory_candidate = Some(plan);
                        "AI advice received for review. No check was run.".into()
                    }
                    Err(_) => {
                        "AI reply discarded: case, preview, evidence or schema changed.".into()
                    }
                }
            }
            (_, Err(_)) => "AI advice unavailable or canceled.".into(),
            _ => "AI reply discarded: case selection changed.".into(),
        };
    }

    fn request_advisory(&mut self, case: &HelperCase, preview: AdvisoryPreview) {
        let consent =
            match AdvisoryConsent::grant(&preview, "openai", "gpt-6-luna", chrono::Utc::now()) {
                Ok(c) => c,
                Err(e) => {
                    self.notice = format!("Consent invalid: {e}");
                    return;
                }
            };
        if let Some(cancel) = self.advisory_cancel.take() {
            cancel.cancel();
        }
        self.advisory_candidate = None;
        let cancel = tokio_util::sync::CancellationToken::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_cancel = cancel.clone();
        std::thread::spawn(move || {
            let _ = tx.send(request_advisory(&preview, &consent, worker_cancel));
        });
        self.advisory_rx = Some(rx);
        self.advisory_cancel = Some(cancel);
        self.notice = format!(
            "AI advice requested for case {}. No check was run.",
            case.id()
        );
    }
}

pub(super) fn show(state: &mut HelperState, ui: &mut Ui, case: &HelperCase) {
    ui.separator();
    ui.heading("Investigation plan");
    let manifest = CapabilityManifest::built_in();
    let local = plan_local(case, case.evidence(), &manifest, chrono::Utc::now());
    match &local {
        Ok(plan) => {
            ui.label("Local assessment · unconfirmed hypotheses");
            render_plan(ui, plan);
            if ui.button("Save current assessment").clicked() {
                state.notice = match state
                    .store
                    .as_mut()
                    .unwrap()
                    .refresh_derived_plan(case.id(), plan.clone())
                {
                    Ok(()) => "Derived assessment saved; case intent revision unchanged.".into(),
                    Err(e) => format!("Assessment could not be saved: {e}"),
                };
            }
        }
        Err(e) => {
            ui.label(format!("Assessment unavailable: {e}"));
        }
    }
    if let Some(saved) = case.plan() {
        if saved.case_revision != case.revision()
            || saved.evidence_revision != case.evidence_revision()
            || case.plan_retention(chrono::Utc::now())
                != Some(crate::helper::evidence::RetentionState::WithinWindow)
        {
            ui.label("Saved plan is historical; refresh assessment before using it.");
        } else {
            ui.label("Saved case plan");
            render_plan(ui, saved);
            let choices: Vec<_> = saved
                .hypotheses
                .iter()
                .filter(|h| !h.support.is_empty() && h.confirmation.is_none())
                .collect();
            if !choices.is_empty() {
                ui.separator();
                ui.label(
                    "Human confirmation · requires an actor, rationale and cited live evidence",
                );
                ui.text_edit_singleline(&mut state.confirmation_actor);
                ui.text_edit_singleline(&mut state.confirmation_rationale);
                egui::ComboBox::from_id_salt("helper-confirm-kind")
                    .selected_text(
                        state
                            .confirmation_kind
                            .map(|k| format!("{:?}", k))
                            .unwrap_or_else(|| "Select hypothesis".into()),
                    )
                    .show_ui(ui, |ui| {
                        for h in &choices {
                            ui.selectable_value(
                                &mut state.confirmation_kind,
                                Some(h.kind),
                                format!("{:?}", h.kind),
                            );
                        }
                    });
                if ui.button("Record human confirmation").clicked() {
                    if let Some(h) = choices
                        .iter()
                        .find(|h| Some(h.kind) == state.confirmation_kind)
                    {
                        let confirmation = HumanConfirmation {
                            actor: state.confirmation_actor.clone(),
                            rationale: state.confirmation_rationale.clone(),
                            confirmed_at: chrono::Utc::now(),
                            evidence_refs: h.support.clone(),
                            case_revision: case.revision(),
                        };
                        state.notice = match state.store.as_mut().unwrap().confirm_hypothesis(
                            case.id(),
                            case.revision(),
                            h.kind,
                            confirmation,
                        ) {
                            Ok(_) => "Human confirmation recorded for this case revision.".into(),
                            Err(e) => format!("Confirmation rejected: {e}"),
                        };
                    }
                }
            }
        }
    }
    ui.add_enabled(false, egui::Button::new("Collect selected check"));
    ui.small("Collection becomes available with the reviewed connector workflow. Selecting or saving a check never starts one.");

    ui.separator();
    ui.heading("Optional AI advice");
    match AdvisoryPreview::from_case(case, FIELDS) {
        Ok(preview) => {
            ui.label("Exact redacted preview to be sent to OpenAI:");
            let mut text = serde_json::to_string_pretty(&preview).unwrap_or_default();
            ui.add(
                egui::TextEdit::multiline(&mut text)
                    .desired_rows(8)
                    .interactive(false),
            );
            if ui
                .add_enabled(
                    state.advisory_rx.is_none(),
                    egui::Button::new("I reviewed this preview · consent and request AI advice"),
                )
                .clicked()
            {
                state.request_advisory(case, preview);
            }
        }
        Err(e) => {
            ui.label(format!("AI preview unavailable: {e}"));
        }
    }
    if state.advisory_rx.is_some() {
        ui.label("Waiting for AI advice (30 second limit)…");
        if ui.button("Cancel AI request").clicked() {
            if let Some(cancel) = state.advisory_cancel.take() {
                cancel.cancel();
            }
            state.advisory_rx = None;
            state.notice = "AI request canceled; any late response will be discarded.".into();
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));
    }
    if let Some(plan) = state.advisory_candidate.clone() {
        ui.label("AI suggestion · review before accepting");
        render_plan(ui, &plan);
        if ui.button("Accept advice as case plan").clicked() {
            if plan.validate(case, &manifest).is_ok() {
                state.revise(CaseEdit::PlanIntent(plan));
            } else {
                state.advisory_candidate = None;
                state.notice = "AI suggestion expired after case or evidence changed.".into();
            }
        }
    }
}

fn render_plan(ui: &mut Ui, plan: &HelperPlan) {
    for h in &plan.hypotheses {
        ui.group(|ui| {
            ui.strong(format!("{:?} · {}", h.kind, h.explanation));
            ui.label(format!("Support: {}", refs(&h.support)));
            ui.label(format!("Counterevidence: {}", refs(&h.counterevidence)));
            for gap in &h.gaps {
                ui.label(format!("Gap: {gap}"));
            }
            ui.label(if h.confirmation.is_some() {
                "Human confirmed"
            } else {
                "Unconfirmed"
            });
        });
    }
    if plan.steps.is_empty() {
        ui.label("Next check: needs a reviewed scope and typed capability parameters.");
    }
    for step in &plan.steps {
        ui.label(format!(
            "Next check: {:?} v{} · {:?} · prerequisites {:?}",
            step.capability_id, step.version, step.role, step.prerequisites
        ));
    }
}

fn refs(ids: &[Uuid]) -> String {
    if ids.is_empty() {
        "none".into()
    } else {
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
