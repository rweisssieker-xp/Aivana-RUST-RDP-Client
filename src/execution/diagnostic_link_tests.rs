use super::*;

fn target(host: &str) -> Target {
    Target {
        profile_id: Uuid::new_v4(),
        name: host.into(),
        host: host.into(),
        port: 3389,
        protocol: "RDP".into(),
        username: String::new(),
        domain: String::new(),
        route: String::new(),
    }
}
fn plan() -> ExecutionPlan {
    ExecutionPlan {
        restart: false,
        service: "Spooler".into(),
        desired: ServiceState::Running,
        health: HealthCheck::Tcp { port: 80 },
        mappings: vec![Mapping {
            production: target("prod.example.test"),
            staging: target("test.example.test"),
        }],
    }
}
fn link(plan: &ExecutionPlan) -> DiagnosticLink {
    DiagnosticLink {
        case_id: Uuid::new_v4(),
        case_binding: "a".repeat(64),
        target: plan.mappings[0].production.clone(),
    }
}
fn linked_run() -> (Run, DiagnosticLink) {
    let plan = plan();
    let link = link(&plan);
    let mut run = Run::new(plan, false).unwrap();
    run.bind_diagnostic(link.clone()).unwrap();
    (run, link)
}

#[test]
fn link_rejects_wrong_target_extra_mapping_and_changed_case() {
    let (mut run, correct) = linked_run();
    let mut other = correct.clone();
    other.target.host = "other.example.test".into();
    assert!(!run.matches_diagnostic(&other));
    assert_eq!(
        run.functional_result(&other).outcome,
        FunctionalOutcome::Unknown
    );
    let mut changed_case = correct.clone();
    changed_case.case_binding = "b".repeat(64);
    assert!(!run.matches_diagnostic(&changed_case));
    assert!(run.bind_diagnostic(other.clone()).is_err());

    let mut wrong = Run::new(plan(), false).unwrap();
    assert!(wrong.bind_diagnostic(other).is_err());
    let mut multiple = plan();
    multiple.mappings.push(Mapping {
        production: target("another-prod"),
        staging: target("another-test"),
    });
    let mut multiple = Run::new(multiple, false).unwrap();
    assert!(multiple.bind_diagnostic(correct).is_err());
    run.plan.health = HealthCheck::Tcp { port: 443 };
    assert!(!run.matches_diagnostic(run.diagnostic.as_ref().unwrap()));
}

#[test]
fn linked_production_result_uses_only_observed_health_and_actual_check_scope() {
    let (mut run, link) = linked_run();
    assert_eq!(
        run.functional_result(&link).outcome,
        FunctionalOutcome::Pending
    );
    let now = Utc::now();
    let target = &mut run.targets[0];
    target.before = Some(ServiceState::Stopped);
    target.captured = Some(now - chrono::Duration::seconds(3));
    target.baseline = Some(HealthEvidence {
        at: now - chrono::Duration::seconds(2),
        passed: false,
        detail: "before".into(),
    });
    target.health = Some(HealthEvidence {
        at: now - chrono::Duration::seconds(1),
        passed: true,
        detail: "port 80 accepted a TCP connection".into(),
    });
    target.evidence.push(
        r#"{"service":"Spooler","state":"Stopped","dependentRunning":[],"prerequisiteStopped":[]}"#
            .into(),
    );
    target.evidence.push(r#"{"service":"Spooler","before":"Stopped","desired":"Running","actual":"Running","verified":true}"#.into());
    target.phase = Phase::Passed;
    run.finished = Some(now);
    let result = run.functional_result(&link);
    assert_eq!(result.outcome, FunctionalOutcome::Succeeded);
    assert_eq!(result.observed_at, Some(now - chrono::Duration::seconds(1)));
    assert_eq!(
        result.evidence.as_deref(),
        Some("port 80 accepted a TCP connection")
    );
    assert_eq!(result.scope, "TCP reachability only");

    run.targets[0].phase = Phase::Restored;
    run.targets[0].health.as_mut().unwrap().passed = false;
    assert_eq!(
        run.functional_result(&link).outcome,
        FunctionalOutcome::Failed
    );
    run.targets[0].phase = Phase::Unknown;
    assert_eq!(
        run.functional_result(&link).outcome,
        FunctionalOutcome::Unknown
    );
    run.targets[0].health = None;
    run.targets[0].phase = Phase::Failed;
    assert_eq!(
        run.functional_result(&link).outcome,
        FunctionalOutcome::Unknown
    );
}

#[test]
fn rehearsal_and_legacy_run_cannot_supply_incident_functional_success() {
    let plan = plan();
    let link = link(&plan);
    let mut rehearsal = Run::new(plan.clone(), true).unwrap();
    rehearsal.bind_diagnostic(link.clone()).unwrap();
    assert_eq!(
        rehearsal.functional_result(&link).outcome,
        FunctionalOutcome::Unknown
    );
    let legacy = Run::new(plan, false).unwrap();
    let mut value = serde_json::to_value(&legacy).unwrap();
    value.as_object_mut().unwrap().remove("diagnostic");
    let reloaded: Run = serde_json::from_value(value).unwrap();
    assert!(reloaded.diagnostic.is_none());
    assert!(!reloaded.matches_diagnostic(&link));
}

#[test]
fn journal_selects_only_the_case_linked_production_check() {
    let (run, link) = linked_run();
    let unrelated = Run::new(plan(), false).unwrap();
    let mut rehearsal = Run::new(run.plan.clone(), true).unwrap();
    rehearsal.bind_diagnostic(link.clone()).unwrap();
    let journal = Journal {
        runs: vec![run.clone(), unrelated, rehearsal],
    };
    let (id, result) = journal.functional_result_for(&link).unwrap();
    assert_eq!(id, run.id);
    assert_eq!(result.outcome, FunctionalOutcome::Pending);
    let mut another_case = link.clone();
    another_case.case_id = Uuid::new_v4();
    assert!(journal.functional_result_for(&another_case).is_none());
    let mut other_target = link;
    other_target.target.host = "other.example.test".into();
    assert!(journal.functional_result_for(&other_target).is_none());
}

#[test]
fn journal_load_rejects_tampered_link_and_preserves_old_run() {
    let (run, link) = linked_run();
    let path = std::env::temp_dir().join(format!(
        "relayne-diagnostic-journal-{}.dpapi",
        Uuid::new_v4()
    ));
    let mut value = serde_json::to_value(Journal {
        runs: vec![run.clone()],
    })
    .unwrap();
    value["runs"][0]["diagnostic"]["target"]["host"] = "wrong.example.test".into();
    let raw = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, crate::security::protect_secret(&raw).unwrap()).unwrap();
    assert!(Journal::load(&path).is_err());
    value["runs"][0]["diagnostic"]["target"]["host"] = link.target.host.into();
    value["runs"][0]["diagnostic"]["case_binding"] = "short".into();
    let raw = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, crate::security::protect_secret(&raw).unwrap()).unwrap();
    assert!(Journal::load(&path).is_err());
    value["runs"][0]
        .as_object_mut()
        .unwrap()
        .remove("diagnostic");
    let raw = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, crate::security::protect_secret(&raw).unwrap()).unwrap();
    let restored = Journal::load(&path).unwrap();
    assert!(restored.runs[0].diagnostic.is_none());
    std::fs::remove_file(path).unwrap();
}
