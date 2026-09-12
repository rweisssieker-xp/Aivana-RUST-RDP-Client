use super::*;
use crate::{
    execution::{ExecutionPlan, HealthCheck, HealthEvidence, Mapping, Phase},
    intelligence::ServiceState,
    mission::Target,
};
use serde_json::json;

fn suggestion() -> Suggestion {
    Suggestion {
        service: "Spooler".into(),
        rationale: "Explizit genannter Dienst".into(),
    }
}
fn case() -> Case {
    Case::new("Spooler wiederherstellen".into(), suggestion()).unwrap()
}
fn response(text: &str) -> serde_json::Value {
    json!({"status":"completed", "output":[{"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":text}]}]})
}
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
fn successful(c: &Case) -> Run {
    let mut r = Run::new(
        ExecutionPlan {
            service: c.service.clone(),
            desired: ServiceState::Running,
            health: HealthCheck::Http {
                port: 80,
                tls: false,
                path: "/health".into(),
                status: 200,
                contains: "ok".into(),
                followups: vec![],
            },
            mappings: vec![Mapping {
                production: target("prod"),
                staging: target("test"),
            }],
        },
        false,
    )
    .unwrap();
    r.recovery_case = Some(c.id);
    r.targets[0].before = Some(ServiceState::Stopped);
    r.targets[0].captured = Some(Utc::now());
    r.targets[0].baseline = Some(HealthEvidence {
        at: Utc::now(),
        passed: false,
        detail: "HTTP 503".into(),
    });
    r.targets[0].evidence.push(
        r#"{"service":"Spooler","state":"Stopped","dependentRunning":[],"prerequisiteStopped":[]}"#
            .into(),
    );
    r.assess_mutation(r#"{"service":"Spooler","before":"Stopped","desired":"Running","actual":"Running","verified":true,"rollbackAttempted":false,"rollbackVerified":false,"problem":""}"#,false).unwrap();
    r.finish_health(HealthEvidence {
        at: Utc::now(),
        passed: true,
        detail: "HTTP 200".into(),
    })
    .unwrap();
    r
}
#[test]
fn parser_accepts_only_completed_bounded_service_suggestions() {
    assert_eq!(
        parse_response(&response(
            r#"{"service":"Spooler","rationale":"Dienst explizit genannt"}"#
        ))
        .unwrap()
        .service,
        "Spooler"
    );
    for text in [
        r#"{"service":"Spooler;Stop-Service x","rationale":"x"}"#,
        r#"{"service":"Spooler","rationale":"x","command":"evil"}"#,
        r#"{"service":"","rationale":"Unklar"}"#,
        r#"{"service":"Spooler","rationale":""}"#,
    ] {
        assert!(parse_response(&response(text)).is_err());
    }
    let mut incomplete = response(r#"{"service":"Spooler","rationale":"x"}"#);
    incomplete["status"] = json!("incomplete");
    assert!(parse_response(&incomplete).is_err());
    let mut refused = response(r#"{"service":"Spooler","rationale":"x"}"#);
    refused["output"][0]["content"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"refusal","refusal":"no"}));
    assert!(parse_response(&refused).is_err());
    assert!(
        Suggestion {
            service: "x".repeat(129),
            rationale: "x".into()
        }
        .validate()
        .is_err()
    );
    assert!(
        Suggestion {
            service: "x".into(),
            rationale: "x".repeat(4097)
        }
        .validate()
        .is_err()
    );
}
#[test]
fn case_rejects_empty_objective_and_redacts_secrets() {
    assert!(Case::new(" ".into(), suggestion()).is_err());
    assert!(Case::new("x".repeat(4097), suggestion()).is_err());
    let c = Case::new("password=highly-secret".into(), suggestion()).unwrap();
    assert!(!c.objective.contains("highly-secret"));
}
#[test]
fn only_actual_production_recovery_is_verified() {
    let c = case();
    let r = successful(&c);
    assert_eq!(outcome(&c, &[r.clone()]), Outcome::Verified);
    assert_eq!(outcome(&c, &[]), Outcome::Pending);
    let mut other = r.clone();
    other.recovery_case = Some(Uuid::new_v4());
    assert_eq!(outcome(&c, &[other]), Outcome::Pending);
    let mut rehearsal = r.clone();
    rehearsal.rehearsal = true;
    assert_eq!(outcome(&c, &[rehearsal]), Outcome::Pending);
    for kind in 0..10 {
        let mut bad = r.clone();
        match kind {
            0 => bad.hash = "wrong".into(),
            1 => bad.targets[0].target.host = "foreign".into(),
            2 => bad.plan.service = "Other".into(),
            3 => bad.targets[0].evidence.clear(),
            4 => bad.targets[0].evidence.pop().map(|_| ()).unwrap(),
            5 => bad.targets[0].before = Some(ServiceState::Running),
            6 => bad.targets[0].captured = Some(c.created - chrono::Duration::seconds(1)),
            7 => bad.finished = Some(Utc::now() + chrono::Duration::hours(1)),
            8 => {
                bad.targets[0].health.as_mut().unwrap().at =
                    c.created - chrono::Duration::seconds(1)
            }
            _ => {
                bad.plan.health = HealthCheck::Tcp { port: 80 };
                bad.hash = bad.plan.hash().unwrap();
            }
        };
        assert_eq!(outcome(&c, &[bad]), Outcome::Unverified, "variant {kind}");
    }
}
#[test]
fn latest_attempt_supersedes_old_success_and_restart_is_failed() {
    let c = case();
    let r = successful(&c);
    let mut later = r.clone();
    later.id = Uuid::new_v4();
    later.finished = None;
    later.targets[0].phase = Phase::Apply;
    assert_eq!(
        outcome(&c, &[r.clone(), later.clone()]),
        Outcome::InProgress
    );
    later.interrupt_after_restart();
    assert_eq!(outcome(&c, &[r.clone(), later.clone()]), Outcome::Failed);
    later.targets[0].phase = Phase::Restored;
    assert_eq!(outcome(&c, &[r, later]), Outcome::Failed);
}
#[test]
fn malformed_run_cursor_is_unverified_without_panicking() {
    let c = case();
    let mut r = successful(&c);
    r.current = usize::MAX;
    assert_eq!(outcome(&c, &[r]), Outcome::Unverified);
}
#[test]
fn prior_healthy_http_does_not_prove_recovery() {
    let c = case();
    let r = successful(&c);
    let mut healthy = r.clone();
    healthy.targets[0].baseline.as_mut().unwrap().passed = true;
    assert_eq!(outcome(&c, &[healthy]), Outcome::Unverified);
}
#[test]
fn incomplete_mutation_does_not_prove_recovery() {
    let c = case();
    let r = successful(&c);
    for field in ["rollbackAttempted", "rollbackVerified", "problem"] {
        let mut incomplete = r.clone();
        let mut evidence: serde_json::Value =
            serde_json::from_str(&incomplete.targets[0].evidence[1]).unwrap();
        evidence.as_object_mut().unwrap().remove(field);
        incomplete.targets[0].evidence[1] = evidence.to_string();
        assert_eq!(
            outcome(&c, &[incomplete]),
            Outcome::Unverified,
            "missing {field}"
        );
    }
}
#[cfg(windows)]
#[test]
fn encrypted_store_roundtrips_and_rejects_corruption_and_bounds() {
    let p = std::env::temp_dir().join(format!("recovery-{}.bin", Uuid::new_v4()));
    let mut b = Book {
        cases: vec![case()],
    };
    b.save(&p).unwrap();
    assert!(!String::from_utf8_lossy(&std::fs::read(&p).unwrap()).contains("Spooler"));
    assert_eq!(Book::load(&p).unwrap().cases.len(), 1);
    b.cases[0].rationale = "Geändert".into();
    b.save(&p).unwrap();
    assert_eq!(Book::load(&p).unwrap().cases[0].rationale, "Geändert");
    b.cases = vec![case(); 129];
    assert!(b.save(&p).is_err());
    std::fs::write(&p, b"broken").unwrap();
    assert!(Book::load(&p).is_err());
    std::fs::remove_file(p).unwrap();
}
