use super::*;
use crate::helper::case::{
    Clarification, Comparator, Environment, MAX_DESCRIPTION, MAX_FIELD, SuccessCriterion,
};

#[derive(Default)]
pub(super) struct Editor {
    description: String,
    scope: String,
    impact: String,
    onset: String,
    permission: String,
    recent_change: String,
    attempted_remedy: String,
    constraint: String,
    criterion_measure: String,
    criterion_threshold: String,
    criterion_unit: String,
    criterion_window: String,
    criterion_comparator: usize,
    criterion_index: Option<usize>,
}

fn known(answer: &Answer<String>) -> String {
    match answer {
        Answer::Known(v) => v.clone(),
        _ => String::new(),
    }
}

impl Editor {
    pub(super) fn from_case(case: &HelperCase) -> Self {
        let mut e = Self {
            description: known(&case.intake().description),
            scope: known(&case.intake().affected_scope),
            impact: known(&case.intake().impact),
            onset: known(&case.intake().onset_frequency),
            permission: known(&case.intake().permission),
            ..Default::default()
        };
        if let Some(c) = case.intake().success_criteria.first() {
            e.use_criterion(0, c);
        }
        e
    }
    fn use_criterion(&mut self, i: usize, c: &SuccessCriterion) {
        self.criterion_index = Some(i);
        self.criterion_measure = c.measure.clone();
        self.criterion_threshold = c.threshold.to_string();
        self.criterion_unit = c.unit.clone();
        self.criterion_window = c.window.clone();
        self.criterion_comparator = match c.comparator {
            Comparator::AtMost => 0,
            Comparator::AtLeast => 1,
            Comparator::Equal => 2,
        };
    }
}

fn answer_row(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    current: &Answer<String>,
    cap: usize,
) -> Option<Answer<String>> {
    let mut answer = None;
    ui.horizontal_wrapped(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .char_limit(cap)
                .desired_width(350.0),
        );
        if ui.button("Set answer").clicked() {
            answer = Some(Answer::Known(value.trim().to_owned()));
        }
        if ui.button("Unknown").clicked() {
            answer = Some(Answer::Unknown);
        }
        if matches!(current, Answer::Unknown) {
            ui.small("Marked unknown");
        }
    });
    answer
}

fn list_section(
    ui: &mut Ui,
    title: &str,
    values: &[String],
    draft: &mut String,
) -> Option<(usize, Option<String>)> {
    let mut change = None;
    ui.strong(title);
    for (i, value) in values.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(value);
            if ui.button(format!("Remove {title} #{i}")).clicked() {
                change = Some((i, None));
            }
        });
    }
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(draft)
                .char_limit(MAX_FIELD)
                .desired_width(350.0),
        );
        if ui
            .add_enabled(
                values.len() < crate::helper::case::MAX_LIST,
                egui::Button::new(format!("Add {title}")),
            )
            .clicked()
        {
            change = Some((values.len(), Some(draft.trim().to_owned())));
            draft.clear();
        }
    });
    change
}

pub(super) fn show(state: &mut HelperState, ui: &mut Ui, case: &HelperCase) {
    ui.separator();
    ui.strong(format!("Case {} · revision {}", case.id(), case.revision()));
    if case.source().is_some() {
        ui.small("Reviewed incident source copied. Its record and evidence IDs are retained as context, not proof of cause.");
    }
    if case.ticket_ref().is_some() {
        ui.small("Ticket text is untrusted context. Review and correct every answer.");
    }
    let mut edits = Vec::new();
    if let Some(v) = answer_row(
        ui,
        "Problem",
        &mut state.editor.description,
        &case.intake().description,
        MAX_DESCRIPTION,
    ) {
        edits.push(CaseEdit::Description(v));
    }
    if let Some(v) = answer_row(
        ui,
        "Affected scope",
        &mut state.editor.scope,
        &case.intake().affected_scope,
        MAX_FIELD,
    ) {
        edits.push(CaseEdit::AffectedScope(v));
    }
    if let Some(v) = answer_row(
        ui,
        "Impact",
        &mut state.editor.impact,
        &case.intake().impact,
        MAX_FIELD,
    ) {
        edits.push(CaseEdit::Impact(v));
    }
    if let Some(v) = answer_row(
        ui,
        "Onset / frequency",
        &mut state.editor.onset,
        &case.intake().onset_frequency,
        MAX_FIELD,
    ) {
        edits.push(CaseEdit::OnsetFrequency(v));
    }
    if let Some(v) = answer_row(
        ui,
        "Reported access (not authorization)",
        &mut state.editor.permission,
        &case.intake().permission,
        MAX_FIELD,
    ) {
        edits.push(CaseEdit::Permission(v));
    }
    ui.horizontal(|ui| {
        ui.label("Environment");
        for (label, value) in [
            ("Production", Environment::Production),
            ("Sandbox", Environment::Sandbox),
        ] {
            if ui
                .selectable_label(case.intake().environment == Answer::Known(value), label)
                .clicked()
            {
                edits.push(CaseEdit::Environment(Answer::Known(value)));
            }
        }
        if ui.button("Unknown").clicked() {
            edits.push(CaseEdit::Environment(Answer::Unknown));
        }
    });
    ui.collapsing("History and operating constraints", |ui| {
        if let Some((i, v)) = list_section(
            ui,
            "Recent change",
            &case.intake().recent_changes,
            &mut state.editor.recent_change,
        ) {
            edits.push(CaseEdit::RecentChange(i, v));
        }
        if let Some((i, v)) = list_section(
            ui,
            "Attempted remedy",
            &case.intake().attempted_remedies,
            &mut state.editor.attempted_remedy,
        ) {
            edits.push(CaseEdit::AttemptedRemedy(i, v));
        }
        if let Some((i, v)) = list_section(
            ui,
            "Constraint",
            &case.intake().constraints,
            &mut state.editor.constraint,
        ) {
            edits.push(CaseEdit::Constraint(i, v));
        }
    });
    ui.separator();
    ui.strong("Measurable success");
    for (i, c) in case.intake().success_criteria.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!(
                "{} {:?} {} {} over {} · {}",
                c.measure,
                c.comparator,
                c.threshold,
                c.unit,
                c.window,
                if c.reviewed { "reviewed" } else { "draft" }
            ));
            if ui.button(format!("Edit #{i}")).clicked() {
                state.editor.use_criterion(i, c);
            }
            if ui.button(format!("Remove #{i}")).clicked() {
                edits.push(CaseEdit::SuccessCriterion(i, None));
            }
        });
    }
    ui.horizontal_wrapped(|ui| {
        ui.label("Measure");
        ui.add(
            egui::TextEdit::singleline(&mut state.editor.criterion_measure)
                .char_limit(MAX_FIELD)
                .desired_width(160.0),
        );
        egui::ComboBox::from_id_salt("helper-criterion-comparator")
            .selected_text(["At most", "At least", "Equal"][state.editor.criterion_comparator])
            .show_ui(ui, |ui| {
                for (i, label) in ["At most", "At least", "Equal"].iter().enumerate() {
                    ui.selectable_value(&mut state.editor.criterion_comparator, i, *label);
                }
            });
        ui.label("Threshold");
        ui.add(
            egui::TextEdit::singleline(&mut state.editor.criterion_threshold).desired_width(75.0),
        );
        ui.label("Unit");
        ui.add(
            egui::TextEdit::singleline(&mut state.editor.criterion_unit)
                .char_limit(MAX_FIELD)
                .desired_width(90.0),
        );
        ui.label("Required window");
        ui.add(
            egui::TextEdit::singleline(&mut state.editor.criterion_window)
                .char_limit(MAX_FIELD)
                .desired_width(110.0),
        );
    });
    ui.horizontal(|ui| {
        if ui.button("Review and set criterion").clicked() {
            match state.editor.criterion_threshold.parse::<f64>() {
                Ok(threshold) => {
                    let comparator = match state.editor.criterion_comparator {
                        0 => Comparator::AtMost,
                        1 => Comparator::AtLeast,
                        _ => Comparator::Equal,
                    };
                    let criterion = SuccessCriterion {
                        measure: state.editor.criterion_measure.trim().into(),
                        comparator,
                        threshold,
                        unit: state.editor.criterion_unit.trim().into(),
                        window: state.editor.criterion_window.trim().into(),
                        reviewed: true,
                    };
                    edits.push(CaseEdit::SuccessCriterion(
                        state
                            .editor
                            .criterion_index
                            .unwrap_or(case.intake().success_criteria.len()),
                        Some(criterion),
                    ));
                }
                Err(_) => state.notice = "Enter a finite numeric threshold".into(),
            }
        }
        if ui.button("New criterion").clicked() {
            state.editor.criterion_index = None;
            state.editor.criterion_measure.clear();
            state.editor.criterion_threshold.clear();
            state.editor.criterion_unit.clear();
            state.editor.criterion_window.clear();
        }
    });
    for edit in edits {
        state.revise(edit);
    }
    ui.separator();
    let readiness = crate::helper::case::validate_intake(case.intake(), false);
    if readiness.missing.is_empty() {
        ui.label("Intake facts complete. Review and bind an exact target before preparing action.");
    } else {
        ui.strong("Still needed before action preparation:");
        for q in readiness.missing {
            ui.label(match q {
                Clarification::Description => "Describe the symptom",
                Clarification::AffectedScope => "Confirm the exact affected target and scope",
                Clarification::Environment => "Classify production or sandbox",
                Clarification::Permission => "Record permission and operating constraints",
                Clarification::SuccessCriterion => {
                    "Review a measurable success criterion and required window"
                }
            });
        }
    }
    ui.small(
        "Describe and Save only update local protected case data. No check or repair starts here.",
    );
}
