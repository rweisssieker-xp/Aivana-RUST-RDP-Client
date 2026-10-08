use super::*;

#[test]
fn sparse_report_asks_scope_and_measurable_success() {
    let intake = ProblemIntake {
        description: Answer::Known("Application is slow".into()),
        ..Default::default()
    };
    let questions = next_questions(&intake, false);
    assert!(questions.contains(&Clarification::AffectedScope));
    assert!(questions.contains(&Clarification::SuccessCriterion));
    assert!(!validate_intake(&intake, false).ready_for_action);
}

#[test]
fn complete_intake_asks_no_redundant_questions() {
    let intake = ProblemIntake {
        description: Answer::Known("Requests exceed expected latency".into()),
        affected_scope: Answer::Known("Portal login on api.example.test".into()),
        environment: Answer::Known(Environment::Sandbox),
        permission: Answer::Known("Read and diagnose selected portal".into()),
        success_criteria: vec![SuccessCriterion {
            measure: "login latency".into(),
            comparator: Comparator::AtMost,
            threshold: 2.0,
            unit: "seconds".into(),
            window: "15 minutes".into(),
            reviewed: true,
        }],
        ..Default::default()
    };
    assert!(next_questions(&intake, true).is_empty());
    assert!(validate_intake(&intake, true).ready_for_action);
}

#[test]
fn correction_changes_only_one_fact() {
    let mut c = HelperCase::new(ProblemIntake {
        description: Answer::Known("Slow".into()),
        impact: Answer::Known("One team".into()),
        ..Default::default()
    })
    .unwrap();
    let before = c.intake.impact.clone();
    c.revise(1, CaseEdit::Description(Answer::Known("Very slow".into())))
        .unwrap();
    assert_eq!(c.intake.impact, before);
    assert_eq!(c.revision, 2);
}

#[test]
fn reviewed_ticket_copy_is_bounded_and_inert() {
    let case = HelperCase::from_ticket(
        TicketReference {
            origin: "local".into(),
            source_id: "INC-42".into(),
        },
        "Portal slow",
        &"x".repeat(MAX_DESCRIPTION * 2),
    )
    .unwrap();
    assert_eq!(case.ticket_ref.as_ref().unwrap().source_id, "INC-42");
    assert!(
        matches!(&case.intake.description, Answer::Known(text) if text.chars().count() == MAX_DESCRIPTION)
    );
    assert_eq!(case.revision, 1);
    assert_eq!(case.evidence_revision, 0);
    assert!(!validate_intake(&case.intake, false).ready_for_action);
}
