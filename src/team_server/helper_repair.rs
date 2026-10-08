//! Independent v2 SQL-action authority. It stores metadata and never executes SQL.
use super::{AuthIdentity, Role, audit, err, read_json, respond};
use crate::helper_approval::*;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use tiny_http::{Method, Request};
use uuid::Uuid;

const SELECT: &str = "SELECT id,request_id,binding,fingerprint,requester_actor,approver_actor,state,expires_at FROM helper_action_approvals_v2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperCapabilitiesV2 {
    pub organization_sha256: String,
    pub authority_version: u16,
}

pub(super) fn migrate(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS helper_authority_v2 (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS helper_action_approvals_v2 (
          id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, binding TEXT NOT NULL,
          fingerprint TEXT NOT NULL, requester_actor TEXT NOT NULL, requester_token_id TEXT,
          requester_jwt_exp TEXT, approver_actor TEXT, approver_token_id TEXT,
          approver_jwt_exp TEXT, state TEXT NOT NULL, created_at TEXT NOT NULL,
          decided_at TEXT, expires_at TEXT NOT NULL, consume_id TEXT UNIQUE, consumed_at TEXT);
        CREATE INDEX IF NOT EXISTS helper_action_requester_v2 ON helper_action_approvals_v2(requester_actor, created_at);
        CREATE TABLE IF NOT EXISTS helper_action_outcome_events_v2 (
          event_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL REFERENCES helper_action_approvals_v2(id),
          sequence INTEGER NOT NULL, payload TEXT NOT NULL, sender_actor TEXT NOT NULL,
          accepted_at TEXT NOT NULL, UNIQUE(approval_id, sequence));")?;
    let identity: Option<String> = db
        .query_row(
            "SELECT value FROM helper_authority_v2 WHERE key='organization_sha256'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if identity.is_none() {
        let random = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        db.execute(
            "INSERT OR IGNORE INTO helper_authority_v2(key,value) VALUES('organization_sha256',?1)",
            [crate::helper_action::digest(
                b"relayne-helper-organization-v2",
                &random,
            )?],
        )?;
    }
    Ok(())
}

fn organization(db: &Connection) -> Result<String> {
    let value: String = db.query_row(
        "SELECT value FROM helper_authority_v2 WHERE key='organization_sha256'",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        crate::helper_action::valid_digest(&value),
        "Invalid authority identity"
    );
    Ok(value)
}
fn state_name(state: ActionApprovalStateV2) -> &'static str {
    match state {
        ActionApprovalStateV2::Pending => "pending",
        ActionApprovalStateV2::Approved => "approved",
        ActionApprovalStateV2::Denied => "denied",
        ActionApprovalStateV2::Expired => "expired",
        ActionApprovalStateV2::Consumed => "consumed",
    }
}
fn parse_state(value: &str) -> rusqlite::Result<ActionApprovalStateV2> {
    Ok(match value {
        "pending" => ActionApprovalStateV2::Pending,
        "approved" => ActionApprovalStateV2::Approved,
        "denied" => ActionApprovalStateV2::Denied,
        "expired" => ActionApprovalStateV2::Expired,
        "consumed" => ActionApprovalStateV2::Consumed,
        _ => return Err(rusqlite::Error::InvalidQuery),
    })
}
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ActionApprovalV2> {
    let uuid =
        |i| Uuid::parse_str(&r.get::<_, String>(i)?).map_err(|_| rusqlite::Error::InvalidQuery);
    let binding: ActionBindingV2 =
        serde_json::from_str(&r.get::<_, String>(2)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let item = ActionApprovalV2 {
        id: uuid(0)?,
        request_id: uuid(1)?,
        binding,
        fingerprint: r.get(3)?,
        requester: r.get(4)?,
        approver: r.get(5)?,
        state: parse_state(&r.get::<_, String>(6)?)?,
        expires_at: DateTime::parse_from_rfc3339(&r.get::<_, String>(7)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?
            .with_timezone(&Utc),
    };
    if item
        .binding
        .fingerprint()
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        != item.fingerprint
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(item)
}
fn get(db: &Connection, id: Uuid) -> Result<Option<ActionApprovalV2>> {
    Ok(db
        .query_row(&format!("{SELECT} WHERE id=?1"), [id.to_string()], row)
        .optional()?)
}
fn operator(who: &AuthIdentity) -> bool {
    matches!(who.role, Role::Operator | Role::Admin)
}
fn original_authorized(
    db: &Connection,
    actor: &str,
    token: Option<&str>,
    jwt_exp: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool> {
    if let Some(token) = token {
        return Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM tokens WHERE id=?1 AND actor=?2 AND revoked=0 AND role IN ('operator','admin'))", params![token, actor], |r| r.get(0))?);
    }
    let Some(exp) = jwt_exp else { return Ok(false) };
    Ok(DateTime::parse_from_rfc3339(exp)?.with_timezone(&Utc) > now
        && super::oidc::actor_can_operate(actor))
}
fn expire(db: &Connection, item: &mut ActionApprovalV2, now: DateTime<Utc>) -> Result<()> {
    if item.expires_at > now
        || !matches!(
            item.state,
            ActionApprovalStateV2::Pending | ActionApprovalStateV2::Approved
        )
    {
        return Ok(());
    }
    db.execute("UPDATE helper_action_approvals_v2 SET state='expired' WHERE id=?1 AND state IN ('pending','approved')", [item.id.to_string()])?;
    audit(
        db,
        &item.requester,
        "helper_action_expired_v2",
        &item.id.to_string(),
    )?;
    item.state = ActionApprovalStateV2::Expired;
    Ok(())
}
fn approval_id(path: &str, suffix: &str) -> Option<Uuid> {
    let id = path
        .strip_prefix("/v2/helper-action-approvals/")?
        .strip_suffix(suffix)?;
    if id.contains('/') {
        return None;
    }
    Uuid::parse_str(id).ok()
}
pub(super) fn serve(
    db: &mut Connection,
    mut request: Request,
    path: &str,
    method: &Method,
    who: &AuthIdentity,
) -> Result<()> {
    if !operator(who) {
        err(request, 403, "Operator role required");
        return Ok(());
    }
    let now = Utc::now();
    if path == "/v2/helper-capabilities" && *method == Method::Get {
        respond(
            request,
            200,
            serde_json::to_value(HelperCapabilitiesV2 {
                organization_sha256: organization(db)?,
                authority_version: 2,
            })?,
        );
        return Ok(());
    }
    if path == "/v2/helper-action-approvals" && *method == Method::Post {
        let input: CreateActionApprovalV2 = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid action request");
                return Ok(());
            }
        };
        if input.request_id == Uuid::nil()
            || input.binding.validate(now).is_err()
            || input.binding.organization_sha256 != organization(db)?
        {
            err(request, 400, "Invalid action binding or organization");
            return Ok(());
        }
        let fingerprint = input.binding.fingerprint()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT id FROM helper_action_approvals_v2 WHERE request_id=?1",
                [input.request_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = prior {
            let item = get(&tx, Uuid::parse_str(&id)?)?.context("Missing action request")?;
            if item.requester == who.actor && item.fingerprint == fingerprint {
                respond(request, 200, serde_json::to_value(item)?);
            } else {
                err(request, 409, "Action request conflict");
            }
            return Ok(());
        }
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM helper_action_approvals_v2", [], |r| {
                r.get(0)
            })?;
        if count >= 50_000 {
            err(request, 503, "Action request capacity reached");
            return Ok(());
        }
        let mut expires = input
            .binding
            .expires_at
            .min(input.binding.proof.expires_at())
            .min(now + Duration::minutes(10));
        if let Some(jwt_exp) = who.jwt_exp {
            expires = expires.min(jwt_exp)
        }
        if expires <= now {
            err(request, 400, "Identity or action proof expired");
            return Ok(());
        }
        let id = Uuid::new_v4();
        tx.execute("INSERT INTO helper_action_approvals_v2(id,request_id,binding,fingerprint,requester_actor,requester_token_id,requester_jwt_exp,state,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',?8,?9)", params![id.to_string(), input.request_id.to_string(), serde_json::to_string(&input.binding)?, fingerprint, who.actor, who.token_id, who.jwt_exp.map(|v| v.to_rfc3339()), now.to_rfc3339(), expires.to_rfc3339()])?;
        audit(
            &tx,
            &who.actor,
            "helper_action_requested_v2",
            &id.to_string(),
        )?;
        tx.commit()?;
        respond(
            request,
            201,
            serde_json::to_value(get(db, id)?.context("Missing created action request")?)?,
        );
        return Ok(());
    }
    if path == "/v2/helper-action-approvals" || path.starts_with("/v2/helper-action-approvals?") {
        if *method != Method::Get {
            err(request, 405, "Use GET");
            return Ok(());
        }
        let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut limit = 20i64;
        let mut offset = 0i64;
        if !query.is_empty() {
            for pair in query.split('&') {
                let Some((key, value)) = pair.split_once('=') else {
                    err(request, 400, "Invalid list query");
                    return Ok(());
                };
                let parsed = match value.parse::<i64>() {
                    Ok(v) => v,
                    Err(_) => {
                        err(request, 400, "Invalid list query");
                        return Ok(());
                    }
                };
                match key {
                    "limit" => limit = parsed,
                    "offset" => offset = parsed,
                    _ => {
                        err(request, 400, "Invalid list query");
                        return Ok(());
                    }
                }
            }
        }
        if !(1..=50).contains(&limit) || !(0..=1000).contains(&offset) {
            err(request, 400, "Invalid list bounds");
            return Ok(());
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stmt = tx.prepare(&format!("{SELECT} WHERE requester_actor=?1 OR approver_actor=?1 OR (state='pending' AND requester_actor<>?1) ORDER BY rowid DESC LIMIT ?2 OFFSET ?3"))?;
        let items = stmt
            .query_map(params![who.actor, limit, offset], row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for mut item in items.iter().cloned() {
            expire(&tx, &mut item, now)?;
        }
        tx.commit()?;
        let items = items
            .into_iter()
            .map(|mut item| {
                if item.expires_at <= now
                    && matches!(
                        item.state,
                        ActionApprovalStateV2::Pending | ActionApprovalStateV2::Approved
                    )
                {
                    item.state = ActionApprovalStateV2::Expired;
                }
                item
            })
            .collect::<Vec<_>>();
        respond(request, 200, serde_json::to_value(items)?);
        return Ok(());
    }
    if let Some(id) = approval_id(path, "") {
        if *method != Method::Get {
            err(request, 405, "Use GET");
            return Ok(());
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(mut item) = get(&tx, id)? else {
            err(request, 404, "Action request missing");
            return Ok(());
        };
        if item.requester != who.actor
            && item.approver.as_deref() != Some(who.actor.as_str())
            && item.state != ActionApprovalStateV2::Pending
        {
            err(request, 403, "Action approval unavailable");
            return Ok(());
        }
        expire(&tx, &mut item, now)?;
        tx.commit()?;
        respond(request, 200, serde_json::to_value(item)?);
        return Ok(());
    }
    if let Some(id) = approval_id(path, "/decision") {
        if *method != Method::Post {
            err(request, 405, "Use POST");
            return Ok(());
        }
        let input: DecideActionApprovalV2 = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid decision");
                return Ok(());
            }
        };
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(mut item) = get(&tx, id)? else {
            err(request, 404, "Action request missing");
            return Ok(());
        };
        expire(&tx, &mut item, now)?;
        if item.state == ActionApprovalStateV2::Expired {
            tx.commit()?;
            err(request, 409, "Action request expired");
            return Ok(());
        }
        if item.state != ActionApprovalStateV2::Pending || item.requester == who.actor {
            err(request, 409, "Decision unavailable");
            return Ok(());
        }
        let state = if input.decision == ActionDecisionV2::Approve {
            ActionApprovalStateV2::Approved
        } else {
            ActionApprovalStateV2::Denied
        };
        tx.execute("UPDATE helper_action_approvals_v2 SET state=?1,approver_actor=?2,approver_token_id=?3,approver_jwt_exp=?4,decided_at=?5 WHERE id=?6 AND state='pending'",params![state_name(state),who.actor,who.token_id,who.jwt_exp.map(|v|v.to_rfc3339()),now.to_rfc3339(),id.to_string()])?;
        audit(
            &tx,
            &who.actor,
            if state == ActionApprovalStateV2::Approved {
                "helper_action_approved_v2"
            } else {
                "helper_action_denied_v2"
            },
            &id.to_string(),
        )?;
        tx.commit()?;
        respond(
            request,
            200,
            serde_json::to_value(get(db, id)?.context("Missing decided request")?)?,
        );
        return Ok(());
    }
    if let Some(id) = approval_id(path, "/consume") {
        if *method != Method::Post {
            err(request, 405, "Use POST");
            return Ok(());
        }
        let input: ConsumeActionApprovalV2 = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid consumption");
                return Ok(());
            }
        };
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(mut item) = get(&tx, id)? else {
            err(request, 404, "Action request missing");
            return Ok(());
        };
        expire(&tx, &mut item, now)?;
        if item.state == ActionApprovalStateV2::Expired {
            tx.commit()?;
            err(request, 409, "Action request expired");
            return Ok(());
        }
        let credentials: (Option<String>,Option<String>,Option<String>,Option<String>)=tx.query_row("SELECT requester_token_id,requester_jwt_exp,approver_token_id,approver_jwt_exp FROM helper_action_approvals_v2 WHERE id=?1",[id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if item.state != ActionApprovalStateV2::Approved
            || item.requester != who.actor
            || item.binding != input.binding
            || input.binding.validate(now).is_err()
            || item.binding.organization_sha256 != organization(&tx)?
            || !original_authorized(
                &tx,
                &item.requester,
                credentials.0.as_deref(),
                credentials.1.as_deref(),
                now,
            )?
            || !original_authorized(
                &tx,
                item.approver.as_deref().unwrap_or(""),
                credentials.2.as_deref(),
                credentials.3.as_deref(),
                now,
            )?
            || item.approver.as_deref() == Some(who.actor.as_str())
        {
            err(request, 409, "Action consumption unavailable");
            return Ok(());
        }
        let consume_id = Uuid::new_v4();
        let changed=tx.execute("UPDATE helper_action_approvals_v2 SET state='consumed',consume_id=?1,consumed_at=?2 WHERE id=?3 AND state='approved'",params![consume_id.to_string(),now.to_rfc3339(),id.to_string()])?;
        ensure!(changed == 1, "Concurrent action consume conflict");
        audit(
            &tx,
            &who.actor,
            "helper_action_consumed_v2",
            &id.to_string(),
        )?;
        tx.commit()?;
        respond(
            request,
            200,
            serde_json::to_value(ConsumeReceiptV2 {
                approval_id: id,
                consume_id,
                fingerprint: item.fingerprint,
                organization_sha256: item.binding.organization_sha256,
            })?,
        );
        return Ok(());
    }
    if path == "/v2/helper-action-outcomes" && *method == Method::Post {
        let event: ActionOutcomeEventV2 = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid action outcome");
                return Ok(());
            }
        };
        if event.event_id == Uuid::nil()
            || event.sequence == 0
            || event.sequence > 16
            || event.occurred_at > now + Duration::minutes(1)
            || event.occurred_at < now - Duration::days(90)
            || !crate::helper_action::valid_digest(&event.fingerprint)
            || event
                .operator_reference_sha256
                .as_ref()
                .is_some_and(|reference| !crate::helper_action::valid_digest(reference))
        {
            err(request, 400, "Invalid action outcome");
            return Ok(());
        }
        let payload = serde_json::to_string(&event)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(item) = get(&tx, event.approval_id)? else {
            err(request, 404, "Action approval missing");
            return Ok(());
        };
        let consumed: Option<String> = tx.query_row(
            "SELECT consume_id FROM helper_action_approvals_v2 WHERE id=?1",
            [item.id.to_string()],
            |r| r.get(0),
        )?;
        if item.state != ActionApprovalStateV2::Consumed
            || consumed != Some(event.consume_id.to_string())
            || item.binding.run_id != event.run_id
            || item.fingerprint != event.fingerprint
            || (who.actor != item.requester && who.role != Role::Admin)
        {
            err(request, 403, "Action outcome unavailable");
            return Ok(());
        }
        if let Some(existing) = tx
            .query_row(
                "SELECT payload FROM helper_action_outcome_events_v2 WHERE event_id=?1",
                [event.event_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            if existing == payload {
                respond(
                    request,
                    200,
                    serde_json::to_value(ActionOutcomeAckV2 {
                        event_id: event.event_id,
                        accepted: true,
                    })?,
                )
            } else {
                err(request, 409, "Action outcome conflict")
            };
            return Ok(());
        }
        let preceding: Option<String> = tx.query_row(
            "SELECT payload FROM helper_action_outcome_events_v2 WHERE approval_id=?1 ORDER BY sequence DESC LIMIT 1",
            [event.approval_id.to_string()], |r| r.get(0)
        ).optional()?;
        let valid_sequence = match preceding {
            None => event.sequence == 1 && event.previous_event_id.is_none(),
            Some(payload) => {
                let prior: ActionOutcomeEventV2 = serde_json::from_str(&payload)?;
                event.sequence == prior.sequence + 1
                    && event.previous_event_id == Some(prior.event_id)
                    && matches!(
                        prior.outcome,
                        ActionOutcomeV2::OutcomeUnknown | ActionOutcomeV2::NeedsIntervention
                    )
                    && matches!(
                        event.outcome,
                        ActionOutcomeV2::Verified
                            | ActionOutcomeV2::Failed
                            | ActionOutcomeV2::NeedsIntervention
                    )
                    && event.outcome != prior.outcome
            }
        };
        if !valid_sequence {
            err(
                request,
                409,
                "Action outcome sequence or correction invalid",
            );
            return Ok(());
        }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM helper_action_outcome_events_v2",
            [],
            |r| r.get(0),
        )?;
        if count >= 200_000 {
            err(request, 503, "Action outcome capacity reached");
            return Ok(());
        }
        tx.execute("INSERT INTO helper_action_outcome_events_v2(event_id,approval_id,sequence,payload,sender_actor,accepted_at) VALUES(?1,?2,?3,?4,?5,?6)",params![event.event_id.to_string(),event.approval_id.to_string(),event.sequence,payload,who.actor,now.to_rfc3339()])?;
        audit(
            &tx,
            &who.actor,
            "helper_action_outcome_v2",
            &event.event_id.to_string(),
        )?;
        tx.commit()?;
        respond(
            request,
            200,
            serde_json::to_value(ActionOutcomeAckV2 {
                event_id: event.event_id,
                accepted: true,
            })?,
        );
        return Ok(());
    }
    err(request, 404, "Unknown helper action API route");
    Ok(())
}
