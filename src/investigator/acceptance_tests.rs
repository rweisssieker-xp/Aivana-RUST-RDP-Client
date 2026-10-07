use super::{
    config::Config,
    core::{Core, Principal},
    replay,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::path::Path;
fn now() -> DateTime<Utc> {
    "2026-09-20T10:00:00Z".parse().unwrap()
}
fn actor(role: &str) -> Principal {
    Principal {
        tenant: "DEMO".into(),
        actor: format!("{role}-person"),
        role: role.into(),
    }
}
fn core() -> Core {
    Core::open(
        Path::new(":memory:"),
        serde_json::to_value(Config::default()).unwrap(),
    )
    .unwrap()
}
fn empty(c: &mut Core) -> Value {
    c.execute(&actor("analyst"),"cases.create",json!({"title":"Acceptance","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"}),now()).unwrap()
}
#[test]
fn paused_autonomy_does_not_starve_manual_recovery_probe() {
    let mut c = core();
    let a = empty(&mut c);
    for name in ["autonomous", "manual-probe"] {
        c.execute(
            &actor("system"),
            "jobs.enqueue",
            json!({"case_id":a["id"],"dedupe_key":name}),
            now(),
        )
        .unwrap();
    }
    let first = c
        .execute(&actor("system"), "jobs.claim", json!({}), now())
        .unwrap();
    c.execute(&actor("system"),"jobs.defer",json!({"job_id":first["id"],"lease":first["lease"],"not_before":now()+chrono::Duration::minutes(1)}),now()).unwrap();
    let second = c
        .execute(&actor("system"), "jobs.claim", json!({}), now())
        .unwrap();
    assert_eq!(second["payload"]["dedupe_key"], "manual-probe");
}

#[test]
fn missing_retention_and_empty_results_never_exonerate() {
    let mut c = core();
    let a = empty(&mut c);
    c.execute(&actor("analyst"),"evidence.ingest",json!({"case_id":a["id"],"evidence":[],"coverage":[{"source":"entra","status":"outside_retention"}]}),now()).unwrap();
    let report = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(report["findings"][0]["exfiltration"], "not_decidable");
    assert_eq!(report["evidence_strength"], "incomplete");
    assert!(!report["questions"].as_array().unwrap().is_empty());
}
#[test]
fn risk_acceptance_is_not_technical_clearance_or_closure() {
    let mut c = core();
    let a = replay::scenario(&mut c).unwrap();
    let coverage = a["coverage"].clone();
    let r=c.execute(&actor("risk_owner"),"risks.accept",json!({"case_id":a["id"],"entity":{"scope":"LAB","residual_risk":"File audit missing","controls":"Restricted access and review","reason":"Temporary continuity","expires_at":"2026-09-20T12:00:00Z"}}),now()).unwrap();
    assert_eq!(r["coverage"], coverage);
    assert_ne!(r["state"], "closed");
    assert!(
        c.execute(
            &actor("system"),
            "risks.accept",
            json!({"case_id":a["id"],"entity":r["risks"][0]}),
            now()
        )
        .is_err()
    );
}
#[test]
fn unchanged_sweep_and_repeated_evidence_do_not_inflate_notifications() {
    let mut c = core();
    let a = empty(&mut c);
    let v = json!({"case_id":a["id"],"evidence":[{"source":"entra","source_id":"same","event_time":"2026-09-20T09:00:00Z","query_version":"1","fields":{"outcome":"success","account":"user-17"}}],"coverage":[{"source":"entra","status":"available"}]});
    for _ in 0..100 {
        c.execute(&actor("analyst"), "evidence.ingest", v.clone(), now())
            .unwrap();
        c.execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    }
    let before = c
        .execute(
            &actor("analyst"),
            "cases.get",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(before["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(before["notifications"].as_array().unwrap().len(), 1);
    let after = c
        .execute(
            &actor("system"),
            "governance.sweep",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(before["version"], after["version"]);
}
#[test]
fn unexamined_site_and_self_reported_supplier_cannot_be_green() {
    let mut c = core();
    let a = empty(&mut c);
    assert!(c.execute(&actor("analyst"),"sites.assess",json!({"case_id":a["id"],"entity":{"owner":"operator","scope":"LAB","site":"LAB","coverage":"none","status":"safe"}}),now()).is_err());
    let r=c.execute(&actor("analyst"),"suppliers.upsert",json!({"case_id":a["id"],"entity":{"owner":"supplier","scope":"LAB","questions":"What happened?","deliverables":"Evidence report","evidence_requirements":"Native event IDs","effort_provenance":"Supplier estimate","acceptance":"complete"}}),now()).unwrap();
    assert_eq!(r["suppliers"][0]["acceptance"], "pending");
}
#[test]
fn expired_evidence_is_removed_from_current_and_historical_extracts() {
    let mut c = core();
    let a = empty(&mut c);
    c.execute(&actor("analyst"),"evidence.ingest",json!({"case_id":a["id"],"evidence":[{"source":"manual","source_id":"sensitive","event_time":"2026-09-20T09:00:00Z","query_version":"1","retention_until":"2026-09-20T10:01:00Z","fields":{"sensitive_marker":"SYNTHETIC-RETAINED-EXTRACT"}}]}),now()).unwrap();
    c.execute(
        &actor("analyst"),
        "cases.analyze",
        json!({"case_id":a["id"]}),
        now(),
    )
    .unwrap();
    let after = c
        .execute(
            &actor("system"),
            "governance.sweep",
            json!({"case_id":a["id"]}),
            now() + chrono::Duration::minutes(2),
        )
        .unwrap();
    assert!(!after.to_string().contains("SYNTHETIC-RETAINED-EXTRACT"));
    assert_eq!(after["evidence"][0]["retrieval_status"], "expired");
    assert!(after["evidence"][0]["content_hash"].as_str().is_some());
}
#[test]
fn high_impact_context_does_not_require_high_evidence_strength() {
    let mut c = core();
    let a = empty(&mut c);
    c.execute(&actor("analyst"),"context.set",json!({"case_id":a["id"],"context":{"source":"authorized manual import","updated_at":"2026-09-20T09:00:00Z","tier0":true}}),now()).unwrap();
    let r = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(r["priority"], "U0");
    assert_eq!(r["evidence_strength"], "incomplete");
}

#[test]
fn non_applicable_measure_requires_reasoned_human_review() {
    let mut c = core();
    let a = empty(&mut c);
    let payload = json!({"case_id":a["id"],"entity":{"owner":"operator","decision_owner":"reviewer","due_at":"2026-09-20T12:00:00Z","status":"not_applicable","reason":"Control does not apply within documented scope"}});
    assert!(
        c.execute(&actor("analyst"), "actions.upsert", payload.clone(), now())
            .is_err()
    );
    let approved = c
        .execute(&actor("reviewer"), "actions.upsert", payload, now())
        .unwrap();
    assert_eq!(
        approved["actions"][0]["verification"],
        "not_applicable_reviewed"
    );
}

#[test]
fn accepted_risk_alone_cannot_approve_recovery() {
    let mut c = core();
    let a = empty(&mut c);
    let r=c.execute(&actor("risk_owner"),"risks.accept",json!({"case_id":a["id"],"entity":{"scope":"LAB","residual_risk":"Open investigation","controls":"Restricted access","reason":"Continuity","expires_at":"2026-09-20T12:00:00Z"}}),now()).unwrap();
    assert!(c.execute(&actor("risk_owner"),"recovery.gate",json!({"case_id":a["id"],"entity":{"owner":"operator","scope":"LAB","risk_id":r["risks"][0]["id"]}}),now()).is_err());
}
