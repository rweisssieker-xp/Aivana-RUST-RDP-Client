//! Production runner tests with simulated UI evidence and untouched loopback sentinels.
use super::*;

fn procedure() -> crate::teaching::Procedure {
    let expected = crate::vision::Anchor {
        label: "Ready".into(),
        context: String::new(),
    };
    crate::teaching::Procedure {
        title: "Procedure fixture".into(),
        dimensions: (800, 600),
        steps: vec![crate::teaching::Step::Parameter {
            name: "service".into(),
        }],
        success: "Ready is visible".into(),
        recovery: "Inspect before retry".into(),
        expected_after: BTreeMap::from([(0, expected.clone())]),
        expected_final: Some(expected),
    }
}
fn procedure_step(name: &str) -> Step {
    Step {
        name: name.into(),
        action: Action::RdpProcedure {
            target: "fixture.invalid".into(),
            procedure: procedure(),
            parameters: BTreeMap::from([("service".into(), "runtime_service".into())]),
        },
    }
}
fn sentinel() -> (std::net::TcpListener, Step) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let step = Step {
        name: "Must not send mutation".into(),
        action: Action::Http {
            url: format!("http://{}/", listener.local_addr().unwrap()),
            method: HttpMethod::Post,
            form: BTreeMap::from([("action".into(), "mutation-sentinel".into())]),
            secret_fields: BTreeMap::new(),
            status: 200,
            body_contains: None,
            json_equals: BTreeMap::new(),
        },
    };
    (listener, step)
}
fn assert_untouched(listener: &std::net::TcpListener) {
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "Following/prior mutation reached the loopback sentinel"
    );
}
fn plan(steps: Vec<Step>, verification: Vec<Step>) -> Plan {
    Plan {
        name: "Procedure gate fixture".into(),
        preconditions: vec![],
        steps,
        verification,
        restore: vec![],
    }
}
fn error(result: Result<Running, String>) -> String {
    match result {
        Err(e) => e,
        Ok(run) => {
            run.cancel();
            panic!("Invalid procedure unexpectedly started");
        }
    }
}

#[test]
fn procedure_parameters_preflight_before_earlier_network_mutation() {
    let (listener, mutation) = sentinel();
    let p = plan(
        vec![mutation, procedure_step("Later procedure")],
        vec![Step {
            name: "Final checkpoint".into(),
            action: Action::RdpCheckpoint {
                target: "fixture.invalid".into(),
                expected: "Ready".into(),
            },
        }],
    );
    let approved = review_digest(&p).unwrap();
    assert!(
        error(start(p.clone(), &approved, BTreeMap::new()))
            .contains("Missing ephemeral procedure slot")
    );
    assert_untouched(&listener);

    // Slot exists but cannot be safely typed: reject globally before the preceding POST.
    assert!(
        start(
            p.clone(),
            &approved,
            BTreeMap::from([("runtime_service".into(), "bad\r\nvalue".into())])
        )
        .is_err()
    );
    assert_untouched(&listener);

    let mut unknown = p.clone();
    if let Action::RdpProcedure { parameters, .. } = &mut unknown.steps[1].action {
        parameters.insert("unknown_parameter".into(), "runtime_service".into());
    }
    assert!(validate(&unknown).unwrap_err().contains("exactly match"));
    assert!(
        error(start(
            unknown,
            &approved,
            BTreeMap::from([("runtime_service".into(), "Spooler".into())])
        ))
        .contains("exactly match")
    );
    assert_untouched(&listener);

    let mut missing = p;
    if let Action::RdpProcedure { parameters, .. } = &mut missing.steps[1].action {
        parameters.clear();
    }
    assert!(error(start(missing, &approved, BTreeMap::new())).contains("exactly match"));
    assert_untouched(&listener);
}

#[cfg(windows)]
fn receive_procedure(run: &Running) -> String {
    loop {
        match run.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Journal(_) => {}
            Event::Procedure {
                token,
                target,
                procedure,
                values,
                ..
            } => {
                assert_eq!(target, "fixture.invalid");
                assert_eq!(procedure.steps.len(), 1);
                assert_eq!(
                    values.get("service").map(String::as_str),
                    Some("RuntimeOnlyFixtureValue")
                );
                return token;
            }
            Event::Done | Event::Checkpoint { .. } => {
                panic!("Runner did not request the procedure")
            }
        }
    }
}
#[cfg(windows)]
fn finish(run: &Running) -> Journal {
    let mut latest = None;
    loop {
        match run.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Journal(j) => latest = Some(j),
            Event::Done => return latest.expect("Final journal event missing"),
            _ => panic!("Runner dispatched a following step after failure/cancel"),
        }
    }
}

// Combined so these scenarios never race one another's process-isolated test journal.
// Run alongside the existing persistent workflow runner test with --test-threads=1.
#[test]
#[cfg(windows)]
fn procedure_nonce_failure_and_cancel_prevent_following_network_step() {
    let (listener, mutation) = sentinel();
    let p = plan(
        vec![
            procedure_step("First procedure"),
            procedure_step("Second procedure"),
        ],
        vec![mutation.clone()],
    );
    let approved = review_digest(&p).unwrap();
    let values = BTreeMap::from([("runtime_service".into(), "RuntimeOnlyFixtureValue".into())]);
    let run = start(p, &approved, values.clone()).unwrap();
    let first = receive_procedure(&run);
    run.evidence
        .send((
            uuid::Uuid::new_v4().to_string(),
            "PROCEDURE_VERIFIED".into(),
        ))
        .unwrap();
    assert!(matches!(
        run.events.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_untouched(&listener);
    run.evidence
        .send((first.clone(), "PROCEDURE_VERIFIED".into()))
        .unwrap();
    let second = receive_procedure(&run);
    assert_ne!(first, second);
    // A valid success marker for the previous identical action cannot release this gate.
    run.evidence
        .send((first, "PROCEDURE_VERIFIED".into()))
        .unwrap();
    assert!(matches!(
        run.events.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    run.evidence
        .send((second, "PROCEDURE_FAILED".into()))
        .unwrap();
    let failed = finish(&run);
    assert!(failed.state.starts_with("Failed"));
    assert_eq!(failed.completed, 1);
    assert!(
        !serde_json::to_string(&failed)
            .unwrap()
            .contains("RuntimeOnlyFixtureValue")
    );
    assert_untouched(&listener);
    drop(run);

    let p = plan(vec![procedure_step("Cancelled procedure")], vec![mutation]);
    let approved = review_digest(&p).unwrap();
    let run = start(p, &approved, values).unwrap();
    let _token = receive_procedure(&run);
    assert!(!run.is_cancelled());
    run.cancel();
    assert!(run.is_cancelled());
    let cancelled = finish(&run);
    assert_ne!(cancelled.state, "Completed");
    assert_eq!(cancelled.completed, 0);
    assert!(cancelled.events.iter().any(|e| e.contains("cancelled")));
    assert_untouched(&listener);
}
