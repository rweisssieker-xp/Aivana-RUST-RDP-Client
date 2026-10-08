use super::*;
use crate::helper_action::{
    RestorationSpec, SqlAction, SqlEngine, StatisticsLimitation, VerifiedSqlObject,
};
use crate::helper_approval::*;
use chrono::{Duration, Utc};
use std::sync::Arc;

struct Harness {
    url: String,
    db: std::path::PathBuf,
    server: Arc<Server>,
    worker: Option<std::thread::JoinHandle<()>>,
    admin: IssuedToken,
}
impl Harness {
    fn new() -> Self {
        let db =
            std::env::temp_dir().join(format!("relayne-helper-approval-{}.sqlite", Uuid::new_v4()));
        let admin = bootstrap(&db, "admin").unwrap();
        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let url = format!("http://{}", server.server_addr());
        let receiver = server.clone();
        let path = db.clone();
        let worker = std::thread::spawn(move || {
            let mut db = open_store(&path).unwrap();
            while let Ok(request) = receiver.recv() {
                let _ = serve_request(&mut db, request);
            }
        });
        Self {
            url,
            db,
            server,
            worker: Some(worker),
            admin,
        }
    }
    fn post(
        &self,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> reqwest::blocking::Response {
        reqwest::blocking::Client::new()
            .post(format!("{}{path}", self.url))
            .bearer_auth(token)
            .json(&body)
            .send()
            .unwrap()
    }
    fn get(&self, path: &str, token: &str) -> reqwest::blocking::Response {
        reqwest::blocking::Client::new()
            .get(format!("{}{path}", self.url))
            .bearer_auth(token)
            .send()
            .unwrap()
    }
    fn actor(&self, name: &str, role: Role) -> IssuedToken {
        self.post(
            "/v1/tokens",
            &self.admin.token,
            serde_json::to_value(TokenRequest {
                actor: name.into(),
                role,
            })
            .unwrap(),
        )
        .json()
        .unwrap()
    }
    fn organization(&self, token: &str) -> String {
        self.get("/v2/helper-capabilities", token)
            .json::<serde_json::Value>()
            .unwrap()["organization_sha256"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.server.unblock();
        self.worker.take().unwrap().join().unwrap();
        let _ = std::fs::remove_file(&self.db);
        let _ = std::fs::remove_file(format!("{}-wal", self.db.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.db.display()));
    }
}
fn d() -> String {
    "a".repeat(64)
}
fn binding(org: String) -> ActionBindingV2 {
    let now = Utc::now();
    ActionBindingV2 {
        version: 2,
        case_id: Uuid::new_v4(),
        case_revision: 1,
        evidence_revision: 1,
        run_id: Uuid::new_v4(),
        run_kind: RunKind::Rehearsal,
        organization_sha256: org,
        scope_sha256: d(),
        credential_scope_sha256: d(),
        action_version: 1,
        action: SqlAction::PostgresAnalyze {
            object: VerifiedSqlObject {
                engine: SqlEngine::Postgres,
                database: "db".into(),
                schema: "public".into(),
                table: "orders".into(),
                object_id: 1,
                scope_sha256: d(),
            },
        },
        metadata_sha256: d(),
        before_sha256: d(),
        plan_sha256: d(),
        verification_sha256: d(),
        proof: ActionProof::StagingReviewProof {
            review_id: Uuid::new_v4(),
            review_sha256: d(),
            expires_at: now + Duration::minutes(5),
        },
        restoration: RestorationSpec::ManualOrUnavailable {
            limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly,
        },
        statistics_limit_acknowledged: true,
        captured_at: now,
        expires_at: now + Duration::minutes(3),
    }
}

#[test]
fn actual_client_routes_enforce_two_people_exact_binding_and_one_consumption() {
    let h = Harness::new();
    let alice = h.actor("alice", Role::Operator);
    let bob = h.actor("bob", Role::Operator);
    let viewer = h.actor("viewer", Role::Viewer);
    let client = crate::team_client::TeamClient::new(&h.url, &alice.token).unwrap();
    let org = client.helper_capabilities().unwrap().organization_sha256;
    let b = binding(org);
    let create = CreateActionApprovalV2 {
        request_id: Uuid::new_v4(),
        binding: b.clone(),
    };
    assert_eq!(
        h.post(
            "/v2/helper-action-approvals",
            &viewer.token,
            serde_json::to_value(&create).unwrap()
        )
        .status(),
        403
    );
    let item = client.request_action_v2(&create).unwrap();
    assert_eq!(client.list_actions_v2(0).unwrap().len(), 1);
    assert!(
        client
            .decide_action_v2(
                item.id,
                &DecideActionApprovalV2 {
                    decision: ActionDecisionV2::Approve
                }
            )
            .is_err()
    );
    let approver = crate::team_client::TeamClient::new(&h.url, &bob.token).unwrap();
    assert_eq!(
        approver
            .decide_action_v2(
                item.id,
                &DecideActionApprovalV2 {
                    decision: ActionDecisionV2::Approve
                }
            )
            .unwrap()
            .state,
        ActionApprovalStateV2::Approved
    );
    assert!(
        approver
            .consume_action_v2(item.id, &ConsumeActionApprovalV2 { binding: b.clone() })
            .is_err()
    );
    let mut changed = b.clone();
    changed.credential_scope_sha256 = "b".repeat(64);
    assert!(
        client
            .consume_action_v2(item.id, &ConsumeActionApprovalV2 { binding: changed })
            .is_err()
    );
    let receipt = client
        .consume_action_v2(item.id, &ConsumeActionApprovalV2 { binding: b.clone() })
        .unwrap();
    assert_eq!(receipt.fingerprint, b.fingerprint().unwrap());
    assert!(
        client
            .consume_action_v2(item.id, &ConsumeActionApprovalV2 { binding: b.clone() })
            .is_err()
    );
    let event = ActionOutcomeEventV2 {
        event_id: Uuid::new_v4(),
        approval_id: item.id,
        consume_id: receipt.consume_id,
        run_id: b.run_id,
        fingerprint: receipt.fingerprint,
        outcome: ActionOutcomeV2::OutcomeUnknown,
        occurred_at: Utc::now(),
    };
    assert!(client.report_action_outcome_v2(&event).unwrap().accepted);
    assert!(client.report_action_outcome_v2(&event).unwrap().accepted);
    let mut conflicting = event.clone();
    conflicting.outcome = ActionOutcomeV2::Failed;
    assert!(client.report_action_outcome_v2(&conflicting).is_err());
}

#[test]
fn expiry_revocation_unknown_wire_and_service_v1_isolation() {
    let h = Harness::new();
    let alice = h.actor("alice", Role::Operator);
    let bob = h.actor("bob", Role::Operator);
    let b = binding(h.organization(&alice.token));
    let create = CreateActionApprovalV2 {
        request_id: Uuid::new_v4(),
        binding: b.clone(),
    };
    let request = serde_json::to_value(&create).unwrap();
    let mut unknown = request.clone();
    unknown["binding"]["command"] = serde_json::json!("DROP TABLE users");
    assert_eq!(
        h.post("/v2/helper-action-approvals", &alice.token, unknown)
            .status(),
        400
    );
    let mut version = request.clone();
    version["binding"]["version"] = serde_json::json!(1);
    assert_eq!(
        h.post("/v2/helper-action-approvals", &alice.token, version)
            .status(),
        400
    );
    let mut tag = request.clone();
    tag["binding"]["proof"]["kind"] = serde_json::json!("service_lab_receipt");
    assert_eq!(
        h.post("/v2/helper-action-approvals", &alice.token, tag)
            .status(),
        400
    );
    let item: ActionApprovalV2 = h
        .post("/v2/helper-action-approvals", &alice.token, request)
        .json()
        .unwrap();
    assert_eq!(
        h.post(
            &format!("/v2/helper-action-approvals/{}/decision", item.id),
            &bob.token,
            serde_json::json!({"decision":"approve"})
        )
        .status(),
        200
    );
    let db = open_store(&h.db).unwrap();
    let old_count: i64 = db
        .query_row("SELECT COUNT(*) FROM repair_approvals", [], |r| r.get(0))
        .unwrap();
    assert_eq!(old_count, 0);
    db.execute(
        "UPDATE helper_action_approvals_v2 SET expires_at=?1 WHERE id=?2",
        params![
            (Utc::now() - Duration::seconds(1)).to_rfc3339(),
            item.id.to_string()
        ],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        h.post(
            &format!("/v2/helper-action-approvals/{}/consume", item.id),
            &alice.token,
            serde_json::to_value(ConsumeActionApprovalV2 { binding: b }).unwrap()
        )
        .status(),
        409
    );
    let audit = open_store(&h.db).unwrap();
    let expired: i64 = audit
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE action='helper_action_expired_v2' AND target=?1",
            [item.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(expired, 1);
    drop(audit);
    let next = binding(h.organization(&alice.token));
    let second: ActionApprovalV2 = h
        .post(
            "/v2/helper-action-approvals",
            &alice.token,
            serde_json::to_value(CreateActionApprovalV2 {
                request_id: Uuid::new_v4(),
                binding: next.clone(),
            })
            .unwrap(),
        )
        .json()
        .unwrap();
    assert_eq!(
        h.post(
            &format!("/v2/helper-action-approvals/{}/decision", second.id),
            &bob.token,
            serde_json::json!({"decision":"approve"})
        )
        .status(),
        200
    );
    assert_eq!(
        h.post(
            "/v1/revoke",
            &h.admin.token,
            serde_json::to_value(RevokeRequest { id: bob.id }).unwrap()
        )
        .status(),
        200
    );
    assert_eq!(
        h.post(
            &format!("/v2/helper-action-approvals/{}/consume", second.id),
            &alice.token,
            serde_json::to_value(ConsumeActionApprovalV2 { binding: next }).unwrap()
        )
        .status(),
        409
    );
}

#[test]
fn concurrent_consumption_has_one_winner_and_history_is_private() {
    let h = Harness::new();
    let alice = h.actor("alice", Role::Operator);
    let bob = h.actor("bob", Role::Operator);
    let other = h.actor("other", Role::Operator);
    let b = binding(h.organization(&alice.token));
    let item: ActionApprovalV2 = h
        .post(
            "/v2/helper-action-approvals",
            &alice.token,
            serde_json::to_value(CreateActionApprovalV2 {
                request_id: Uuid::new_v4(),
                binding: b.clone(),
            })
            .unwrap(),
        )
        .json()
        .unwrap();
    assert_eq!(
        h.post(
            &format!("/v2/helper-action-approvals/{}/decision", item.id),
            &bob.token,
            serde_json::json!({"decision":"approve"})
        )
        .status(),
        200
    );
    assert_eq!(
        h.get(
            "/v2/helper-action-approvals?limit=20&offset=0",
            &other.token
        )
        .json::<Vec<ActionApprovalV2>>()
        .unwrap()
        .len(),
        0
    );
    assert_eq!(
        h.get(
            &format!("/v2/helper-action-approvals/{}", item.id),
            &other.token
        )
        .status(),
        403
    );
    assert_eq!(
        h.get("/v2/helper-action-approvals?limit=51", &alice.token)
            .status(),
        400
    );
    let url = h.url.clone();
    let token = alice.token.clone();
    let payload = serde_json::to_value(ConsumeActionApprovalV2 { binding: b }).unwrap();
    let handles = (0..2)
        .map(|_| {
            let url = url.clone();
            let token = token.clone();
            let payload = payload.clone();
            let id = item.id;
            std::thread::spawn(move || {
                reqwest::blocking::Client::new()
                    .post(format!("{url}/v2/helper-action-approvals/{id}/consume"))
                    .bearer_auth(token)
                    .json(&payload)
                    .send()
                    .unwrap()
                    .status()
                    .as_u16()
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|&&s| s == 200).count(), 1);
    assert_eq!(results.iter().filter(|&&s| s == 409).count(), 1);
    let db = open_store(&h.db).unwrap();
    let consumed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE action='helper_action_consumed_v2' AND target=?1",
            [item.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(consumed, 1);
}
