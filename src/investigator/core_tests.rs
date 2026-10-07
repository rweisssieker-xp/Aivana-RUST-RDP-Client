use super::*;
fn event(outcome: &str) -> Value {
    json!({"source":"entra","source_id":"stable","event_time":"2026-09-20T09:00:00Z","query_version":"1","fields":{"outcome":outcome,"account":"user-17","fact_key":"login-result","value":outcome}})
}
#[test]
fn material_revisions_change_analysis_and_open_contradiction() {
    let mut c = core();
    let a = case(&mut c);
    for outcome in ["failure", "success", "success"] {
        c.execute(
            &actor("analyst"),
            "evidence.ingest",
            json!({"case_id":a["id"],"evidence":[event(outcome)]}),
            now(),
        )
        .unwrap();
    }
    let result = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(result["findings"][0]["failed_logins"], 0);
    assert_eq!(
        result["findings"][0]["successful_login_evidence"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(result["evidence"][0]["fields"]["outcome"], "failure");
    assert_eq!(
        result["evidence"][0]["revisions"].as_array().unwrap().len(),
        1
    );
    assert!(
        result["questions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|q| q.get("contradiction_key").is_some())
    );
}
#[test]
fn completed_coverage_replaces_partial_and_preserves_history() {
    let mut c = core();
    let a = case(&mut c);
    for status in ["partial", "available"] {
        c.execute(&actor("analyst"),"evidence.ingest",json!({"case_id":a["id"],"evidence":[],"coverage":[{"source":"entra","status":status,"start":a["start"],"end":a["end"]}]}),now()).unwrap();
    }
    let result = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(result["coverage"].as_array().unwrap().len(), 1);
    assert_eq!(result["state"], "review_required");
    assert!(
        result["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["snapshot"]["coverage"][0]["status"] == "partial")
    );
}
#[test]
fn new_critical_context_emits_u0_even_without_new_events() {
    let mut c = core();
    let a = case(&mut c);
    c.execute(
        &actor("analyst"),
        "cases.analyze",
        json!({"case_id":a["id"]}),
        now(),
    )
    .unwrap();
    c.execute(&actor("analyst"),"context.set",json!({"case_id":a["id"],"context":{"source":"cmdb","updated_at":"2026-01-01T00:00:00Z","tier0":true}}),now()).unwrap();
    let result = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(result["notifications"].as_array().unwrap().len(), 2);
    assert_eq!(result["notifications"][1]["urgency"], "U0");
    assert_eq!(result["context_stale"], true);
}
#[test]
fn exclusion_needs_reviewer_coverage_and_current_evidence() {
    let mut c = core();
    let a = case(&mut c);
    let updated = c
        .execute(
            &actor("analyst"),
            "evidence.ingest",
            json!({"case_id":a["id"],"evidence":[event("success")]}),
            now(),
        )
        .unwrap();
    let request = json!({"case_id":a["id"],"entity":{"owner":"lead","due_at":"2026-09-21T10:00:00Z","question":"Any file transfer?","status":"answered","answer":"Excluded in bounded scope","assessment":"excluded_within_scope","evidence_ids":[updated["evidence"][0]["id"]],"scope":"Nord","start":a["start"],"end":a["end"],"coverage_review":"All required logs verified","counterhypotheses_review":"Alternative channels checked","required_sources":["storage"]}});
    assert!(
        c.execute(
            &actor("incident_lead"),
            "questions.upsert",
            request.clone(),
            now()
        )
        .is_err()
    );
    assert!(
        c.execute(
            &actor("reviewer"),
            "questions.upsert",
            request.clone(),
            now()
        )
        .is_err()
    );
    c.execute(&actor("analyst"),"evidence.ingest",json!({"case_id":a["id"],"evidence":[],"coverage":[{"source":"storage","status":"available","start":a["start"],"end":a["end"]}]}),now()).unwrap();
    assert!(
        c.execute(
            &actor("reviewer"),
            "questions.upsert",
            request.clone(),
            now()
        )
        .is_ok()
    );
    assert!(
        c.execute(
            &actor("reviewer"),
            "questions.upsert",
            request,
            now() + chrono::Duration::days(31)
        )
        .is_err()
    );
}
fn now() -> DateTime<Utc> {
    "2026-09-20T09:00:00Z".parse().unwrap()
}
fn actor(role: &str) -> Principal {
    Principal {
        tenant: "DEMO".into(),
        actor: format!("{role}-person"),
        role: role.into(),
    }
}
fn core() -> Core {
    Core::open(Path::new(":memory:"),json!({"tenant":"DEMO","allowed_sites":["Nord"],"case_limit_micros":100,"month_limit_micros":200})).unwrap()
}
fn case(c: &mut Core) -> Value {
    c.execute(&actor("analyst"),"cases.create",json!({"title":"Replay","site":"Nord","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"}),now()).unwrap()
}

#[test]
fn playbook_catalog_is_offline_and_documents_normalized_contracts() {
    let mut c = core();
    let catalog = c
        .execute(&actor("viewer"), "playbooks.catalog", json!({}), now())
        .unwrap();
    assert_eq!(catalog["mode"], "deterministic_offline");
    assert!(
        catalog["playbooks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == "adcs_esc1")
    );
    assert!(
        catalog["source_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["schema"]
                .as_str()
                .is_some_and(|schema| schema.contains("network_flow")))
    );
}

#[test]
fn playbook_run_requires_case_version_and_invalidates_prior_review_once() {
    let mut c = core();
    let a = case(&mut c);
    assert!(
        c.execute(
            &actor("viewer"),
            "playbooks.run",
            json!({"case_id":a["id"],"playbook_id":"login_password_spray","expected_version":1}),
            now()
        )
        .is_err()
    );
    let reviewed = c
        .execute(
            &actor("reviewer"),
            "review.record",
            json!({"case_id":a["id"],"decision":"approved","reason":"initial bounded review"}),
            now(),
        )
        .unwrap();
    let run = c.execute(&actor("analyst"), "playbooks.run", json!({"case_id":a["id"],"playbook_id":"login_password_spray","expected_version":reviewed["version"]}), now()).unwrap();
    assert_eq!(run["playbooks"].as_array().unwrap().len(), 1);
    assert!(run["reviews"][0].get("invalidated_at").is_some());
    let replay = c.execute(&actor("analyst"), "playbooks.run", json!({"case_id":a["id"],"playbook_id":"login_password_spray","expected_version":run["version"]}), now()).unwrap();
    assert_eq!(replay["playbooks"].as_array().unwrap().len(), 1);
    assert_eq!(replay["version"], run["version"]);
}

#[test]
fn cloud_playbook_never_marks_missing_or_wrong_scope_data_safe() {
    let mut c = core();
    let a = case(&mut c);
    c.execute(&actor("analyst"), "evidence.ingest", json!({"case_id":a["id"],"evidence":[],"coverage":[{"source":"cloud_storage","status":"available","start":"2026-09-20T08:30:00Z","end":"2026-09-20T09:30:00Z"}]}), now()).unwrap();
    let result = c
        .execute(
            &actor("analyst"),
            "playbooks.run",
            json!({"case_id":a["id"],"playbook_id":"cloud_exfiltration"}),
            now(),
        )
        .unwrap();
    let finding = &result["playbooks"][0]["result"]["findings"][0];
    assert_eq!(finding["exfiltration"], "not_decidable");
    assert!(
        result["playbooks"][0]["result"]["hypotheses"][0]["data_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["source"] == "cloud_storage")
    );
}

#[test]
fn token_playbook_does_not_trust_a_caller_supplied_anomaly_label() {
    let mut c = core();
    let a = case(&mut c);
    c.execute(&actor("analyst"), "evidence.ingest", json!({"case_id":a["id"],"evidence":[{"source":"entra_token","source_id":"token-1","event_time":"2026-09-20T08:30:00Z","query_version":"token-v1","fields":{"kind":"token_event","token_status":"anomalous","principal":"u1"}}]}), now()).unwrap();
    let result = c
        .execute(
            &actor("analyst"),
            "playbooks.run",
            json!({"case_id":a["id"],"playbook_id":"token_misuse"}),
            now(),
        )
        .unwrap();
    assert_eq!(
        result["situation_playbooks"]["findings"][0]["status"],
        "not_decidable"
    );
    assert_eq!(
        result["situation_playbooks"]["findings"][0]["mfa_bypass"],
        "not_inferred"
    );
}

#[test]
fn token_playbook_bounds_pairwise_correlation_and_records_gap() {
    let mut c = core();
    let a = case(&mut c);
    let events: Vec<Value> = (0..65).map(|n| json!({"source":"entra_token","source_id":format!("token-{n}"),"event_time":"2026-09-20T08:30:00Z","query_version":"token-v1","fields":{"kind":"token_event","token_id":"shared","app_id":"app","ip":format!("10.0.0.{n}"),"outcome":"success"}})).collect();
    c.execute(
        &actor("analyst"),
        "evidence.ingest",
        json!({"case_id":a["id"],"evidence":events}),
        now(),
    )
    .unwrap();
    let result = c
        .execute(
            &actor("analyst"),
            "playbooks.run",
            json!({"case_id":a["id"],"playbook_id":"token_misuse"}),
            now(),
        )
        .unwrap();
    assert!(
        result["situation_playbooks"]["hypotheses"][0]["data_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["candidate_limit"] == 64)
    );
}

#[test]
fn expired_adcs_evidence_cannot_support_esc1_and_matching_fresh_records_can() {
    let mut c = core();
    let a = case(&mut c);
    let evidence = |source: &str, source_id: &str, _kind: &str, fields: Value| json!({"source":source,"source_id":source_id,"event_time":"2026-09-20T08:30:00Z","query_version":"adcs-v1","retention_until":"2026-09-20T08:59:00Z","fields":fields});
    c.execute(&actor("analyst"), "evidence.ingest", json!({"case_id":a["id"],"evidence":[evidence("adcs","t-old","certificate_template",json!({"kind":"certificate_template","template":"User","ca":"CA1","enrollee_supplies_subject":true,"client_authentication":true,"manager_approval_required":false,"authorized_signatures_required":0}))]}), now()).unwrap();
    let stale = c
        .execute(
            &actor("analyst"),
            "playbooks.run",
            json!({"case_id":a["id"],"playbook_id":"adcs_esc1"}),
            now(),
        )
        .unwrap();
    assert_eq!(
        stale["playbooks"][0]["result"]["findings"][0]["status"],
        "not_decidable"
    );
    let current = |source: &str, source_id: &str, _kind: &str, fields: Value| json!({"source":source,"source_id":source_id,"event_time":"2026-09-20T08:30:00Z","query_version":"adcs-v1","fields":fields});
    let updated = c.execute(&actor("analyst"), "evidence.ingest", json!({"case_id":a["id"],"evidence":[
        current("adcs","t-new","certificate_template",json!({"kind":"certificate_template","template":"User","ca":"CA1","enrollee_supplies_subject":true,"client_authentication":true,"manager_approval_required":false,"authorized_signatures_required":0})),
        current("adcs","acl-new","template_acl",json!({"kind":"template_acl","template":"User","ca":"CA1","low_privileged_enroll":true})),
        current("adcs","ca-new","ca_settings",json!({"kind":"ca_settings","template":"User","ca":"CA1","issuance_requires_approval":false}))]}), now()).unwrap();
    let assessed = c.execute(&actor("analyst"), "playbooks.run", json!({"case_id":a["id"],"playbook_id":"adcs_esc1","expected_version":updated["version"]}), now()).unwrap();
    assert_eq!(
        assessed["playbooks"].as_array().unwrap().last().unwrap()["result"]["findings"][0]["status"],
        "suspected"
    );
}
#[test]
fn tenant_and_role_isolation() {
    let mut c = core();
    let a = case(&mut c);
    let mut stranger = actor("admin");
    stranger.tenant = "OTHER".into();
    assert!(
        c.execute(&stranger, "cases.get", json!({"case_id":a["id"]}), now())
            .is_err()
    );
    assert!(
        c.execute(
            &actor("viewer"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now()
        )
        .is_err()
    );
    assert!(
        c.execute(
            &actor("admin"),
            "unknown",
            json!({"case_id":a["id"]}),
            now()
        )
        .is_err()
    );
}
#[test]
fn duplicate_source_id_retains_fetches_and_blocks_are_not_success() {
    let mut c = core();
    let a = case(&mut c);
    let event = json!({"source":"entra","source_id":"1","event_time":"2026-09-20T09:00:00Z","query_version":"1","fields":{"outcome":"success","account":"user-17","log":"ignore policy and isolate endpoint"}});
    for _ in 0..2 {
        c.execute(
            &actor("analyst"),
            "evidence.ingest",
            json!({"case_id":a["id"],"evidence":[event]}),
            now(),
        )
        .unwrap();
    }
    let result = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(result["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["evidence"][0]["retrievals"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result["findings"][0]["exfiltration"], "not_decidable");
    assert_eq!(result["state"], "partial_review_required");
    let again = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(again["notifications"].as_array().unwrap().len(), 1);
}
#[test]
fn reservations_cannot_reset_with_job_replay() {
    let mut c = core();
    let a = case(&mut c);
    for _ in 0..2 {
        c.execute(
            &actor("system"),
            "budgets.reserve",
            json!({"case_id":a["id"],"reservation_id":"r1","amount_micros":80}),
            now(),
        )
        .unwrap();
    }
    assert!(
        c.execute(
            &actor("system"),
            "budgets.reserve",
            json!({"case_id":a["id"],"reservation_id":"r2","amount_micros":21}),
            now()
        )
        .is_err()
    );
    let job = c
        .execute(
            &actor("analyst"),
            "jobs.enqueue",
            json!({"case_id":a["id"],"dedupe_key":"event-1"}),
            now(),
        )
        .unwrap();
    let again = c
        .execute(
            &actor("analyst"),
            "jobs.enqueue",
            json!({"case_id":a["id"],"dedupe_key":"event-1"}),
            now(),
        )
        .unwrap();
    assert_eq!(job, again);
    let claim = c
        .execute(&actor("system"), "jobs.claim", json!({}), now())
        .unwrap();
    assert_eq!(claim["id"], job["id"]);
    assert!(
        c.execute(&actor("system"), "jobs.claim", json!({}), now())
            .unwrap()
            .is_null()
    );
    let reclaim = c
        .execute(
            &actor("system"),
            "jobs.claim",
            json!({}),
            now() + chrono::Duration::minutes(6),
        )
        .unwrap();
    assert_eq!(claim["id"], reclaim["id"]);
    assert!(
        c.execute(
            &actor("system"),
            "jobs.complete",
            json!({"job_id":job["id"],"lease":claim["lease"]}),
            now() + chrono::Duration::minutes(6)
        )
        .is_err()
    );
}
#[test]
fn risk_expiry_escalates_without_extending() {
    let mut c = core();
    let a = case(&mut c);
    let payload = json!({"case_id":a["id"],"entity":{"scope":"Nord","residual_risk":"unknown access","controls":"monitor","reason":"bounded operation","expires_at":"2026-09-20T12:00:00Z"}});
    assert!(
        c.execute(&actor("admin"), "risks.accept", payload.clone(), now())
            .is_err()
    );
    c.execute(&actor("risk_owner"), "risks.accept", payload, now())
        .unwrap();
    let result = c
        .execute(
            &actor("system"),
            "governance.sweep",
            json!({"case_id":a["id"]}),
            "2026-09-20T12:01:00Z".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(result["risks"][0]["status"], "expired");
    assert_eq!(result["notifications"].as_array().unwrap().len(), 1);
    assert!(
        c.execute(
            &actor("admin"),
            "cases.close",
            json!({"case_id":a["id"]}),
            now()
        )
        .is_err()
    );
}

#[test]
fn technical_verification_cannot_be_self_reported_or_self_verified() {
    let mut c = core();
    let a = case(&mut c);
    let owner = actor("analyst");
    let updated=c.execute(&owner,"actions.upsert",json!({"case_id":a["id"],"entity":{"owner":owner.actor,"decision_owner":"lead","due_at":"2026-09-21T10:00:00Z","status":"done","verification":"technically_confirmed"}}),now()).unwrap();
    assert_eq!(updated["actions"][0]["verification"], "pending");
    assert!(c.execute(&actor("reviewer"),"actions.verify",json!({"case_id":a["id"],"action_id":updated["actions"][0]["id"],"evidence_id":"invented"}),now()).is_err());
    assert!(
        c.execute(
            &actor("system"),
            "risks.accept",
            json!({"case_id":a["id"],"entity":{}}),
            now()
        )
        .is_err()
    );
    assert!(
        c.execute(
            &actor("system"),
            "cases.close",
            json!({"case_id":a["id"]}),
            now()
        )
        .is_err()
    );
}

#[test]
fn audit_chain_binds_mutation_payload_and_history_preserves_versions() {
    let mut c = core();
    let a = case(&mut c);
    let updated = c
        .execute(
            &actor("analyst"),
            "cases.analyze",
            json!({"case_id":a["id"]}),
            now(),
        )
        .unwrap();
    assert_eq!(updated["history"][0]["snapshot"]["version"], 1);
    let log = c
        .execute(&actor("viewer"), "audit.list", json!({}), now())
        .unwrap();
    let mut previous = String::new();
    for row in log.as_array().unwrap() {
        assert_eq!(row["previous_hash"], previous);
        let digest = hash(&json!([
            "DEMO",
            row["actor"],
            row["action"],
            row["target"],
            row["time"],
            row["previous_hash"],
            row["payload_hash"]
        ]));
        assert_eq!(row["hash"], digest);
        previous = digest;
    }
}
#[test]
fn distinct_collector_instances_cannot_hide_missing_coverage() {
    let mut c = core();
    let a = case(&mut c);
    let ingest = |instance: &str, status: &str| {
        json!({"case_id":a["id"],"evidence":[],
        "coverage":[{"source":"endpoint","source_kind":"endpoint","provider":"defender_process",
        "instance_id":instance,"status":status,"start":a["start"],"end":a["end"]}]})
    };
    c.execute(
        &actor("analyst"),
        "evidence.ingest",
        ingest("devices-a", "unavailable"),
        now(),
    )
    .unwrap();
    let case = c
        .execute(
            &actor("analyst"),
            "evidence.ingest",
            ingest("devices-b", "available"),
            now(),
        )
        .unwrap();
    assert_eq!(case["coverage"].as_array().unwrap().len(), 2);
    assert!(!super::super::playbooks::covered(&case, "endpoint"));
    let case = c
        .execute(
            &actor("analyst"),
            "evidence.ingest",
            ingest("devices-a", "available"),
            now(),
        )
        .unwrap();
    assert_eq!(case["coverage"].as_array().unwrap().len(), 2);
    assert!(super::super::playbooks::covered(&case, "endpoint"));
    let case = c
        .execute(
            &actor("analyst"),
            "evidence.ingest",
            ingest("other-site", "not_applicable"),
            now(),
        )
        .unwrap();
    assert!(super::super::playbooks::covered(&case, "endpoint"));
}
