//! Server-owned repair authority. The client submits metadata, never identity.
use super::{AuthIdentity, Role, audit, err, read_json, respond};
use crate::repair_approval::{
    ConsumeReceipt, ConsumeRepairApproval, CreateRepairApproval, DecideRepairApproval,
    RepairApproval, RepairDecision, RepairOutcomeAck, RepairOutcomeEvent, RepairState,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use tiny_http::{Method, Request};
use uuid::Uuid;

pub(super) fn migrate(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS repair_approvals (
          id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
          binding TEXT NOT NULL, fingerprint TEXT NOT NULL,
          requester_actor TEXT NOT NULL, requester_token_id TEXT,
          requester_jwt_exp TEXT, approver_actor TEXT, approver_token_id TEXT,
          approver_jwt_exp TEXT, state TEXT NOT NULL,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          decided_at TEXT, consumed_at TEXT, consume_id TEXT UNIQUE
        );
        CREATE INDEX IF NOT EXISTS repair_approvals_requester ON repair_approvals(requester_actor, created_at);
        CREATE INDEX IF NOT EXISTS repair_approvals_state ON repair_approvals(state, created_at);
        CREATE TABLE IF NOT EXISTS repair_outcomes (
          event_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL UNIQUE REFERENCES repair_approvals(id),
          payload TEXT NOT NULL, sender_actor TEXT NOT NULL, accepted_at TEXT NOT NULL
        );"
    )?;
    Ok(())
}

fn operator(identity: &AuthIdentity) -> bool {
    identity.role != Role::Viewer
}
fn state_name(state: RepairState) -> &'static str {
    match state {
        RepairState::Pending => "pending",
        RepairState::Approved => "approved",
        RepairState::Denied => "denied",
        RepairState::Expired => "expired",
        RepairState::Consumed => "consumed",
    }
}
fn state_parse(value: &str) -> Result<RepairState> {
    Ok(match value {
        "pending" => RepairState::Pending,
        "approved" => RepairState::Approved,
        "denied" => RepairState::Denied,
        "expired" => RepairState::Expired,
        "consumed" => RepairState::Consumed,
        _ => anyhow::bail!("Invalid stored repair state"),
    })
}

fn original_authorized(
    db: &Connection,
    actor: &str,
    token_id: Option<&str>,
    jwt_exp: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool> {
    if let Some(id) = token_id {
        let found: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM tokens WHERE id=?1 AND actor=?2 AND revoked=0 AND role IN ('operator','admin'))",
            params![id, actor], |r| r.get(0),
        )?;
        return Ok(found);
    }
    let Some(exp) = jwt_exp else { return Ok(false) };
    let exp = DateTime::parse_from_rfc3339(exp)?.with_timezone(&Utc);
    Ok(exp > now && super::oidc::actor_can_operate(actor))
}

fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepairApproval> {
    let parse_uuid = |i| -> rusqlite::Result<Uuid> {
        Uuid::parse_str(&row.get::<_, String>(i)?).map_err(|_| rusqlite::Error::InvalidQuery)
    };
    let parse_time = |i| -> rusqlite::Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&row.get::<_, String>(i)?)
            .map(|at| at.with_timezone(&Utc))
            .map_err(|_| rusqlite::Error::InvalidQuery)
    };
    let item = RepairApproval {
        id: parse_uuid(0)?,
        request_id: parse_uuid(1)?,
        binding: serde_json::from_str(&row.get::<_, String>(2)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        fingerprint: row.get(3)?,
        requester: row.get(4)?,
        approver: row.get(5)?,
        state: state_parse(&row.get::<_, String>(6)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        expires_at: parse_time(7)?,
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
const SELECT: &str = "SELECT id,request_id,binding,fingerprint,requester_actor,approver_actor,state,expires_at FROM repair_approvals";

fn get(db: &Connection, id: Uuid) -> Result<Option<RepairApproval>> {
    Ok(db
        .query_row(&format!("{SELECT} WHERE id=?1"), [id.to_string()], row)
        .optional()?)
}

fn expire(db: &Connection, approval: &mut RepairApproval, now: DateTime<Utc>) -> Result<()> {
    if approval.expires_at > now
        || !matches!(approval.state, RepairState::Pending | RepairState::Approved)
    {
        return Ok(());
    }
    db.execute("UPDATE repair_approvals SET state='expired' WHERE id=?1 AND state IN ('pending','approved')", [approval.id.to_string()])?;
    audit(
        db,
        &approval.requester,
        "repair_expired",
        &approval.id.to_string(),
    )?;
    approval.state = RepairState::Expired;
    Ok(())
}

fn approval_id(path: &str, suffix: &str) -> Option<Uuid> {
    let id = path
        .strip_prefix("/v1/repair-approvals/")?
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
    if path == "/v1/repair-approvals" && *method == Method::Post {
        let input: CreateRepairApproval = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid repair request");
                return Ok(());
            }
        };
        if input.request_id == Uuid::nil() || input.binding.validate(now).is_err() {
            err(request, 400, "Invalid repair binding");
            return Ok(());
        }
        let fingerprint = input.binding.fingerprint()?;
        let payload = serde_json::to_string(&input.binding)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing_id) = tx
            .query_row(
                "SELECT id FROM repair_approvals WHERE request_id=?1",
                [input.request_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let existing =
                get(&tx, Uuid::parse_str(&existing_id)?)?.context("Missing repair request")?;
            if existing.requester == who.actor && existing.fingerprint == fingerprint {
                respond(request, 200, serde_json::to_value(existing)?);
            } else {
                err(request, 409, "Repair request conflict");
            }
            return Ok(());
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM repair_approvals", [], |r| r.get(0))?;
        if count >= 50_000 {
            err(request, 503, "Repair request capacity reached");
            return Ok(());
        }
        let mut expires = now + Duration::minutes(10);
        expires = expires.min(input.binding.proof.expires_at);
        if let Some(jwt_exp) = who.jwt_exp {
            expires = expires.min(jwt_exp)
        }
        if expires <= now {
            err(request, 400, "Repair identity or proof expired");
            return Ok(());
        }
        let id = Uuid::new_v4();
        tx.execute("INSERT INTO repair_approvals(id,request_id,binding,fingerprint,requester_actor,requester_token_id,requester_jwt_exp,state,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',?8,?9)", params![id.to_string(), input.request_id.to_string(), payload, fingerprint, who.actor, who.token_id, who.jwt_exp.map(|v| v.to_rfc3339()), now.to_rfc3339(), expires.to_rfc3339()])?;
        audit(&tx, &who.actor, "repair_request", &id.to_string())?;
        tx.commit()?;
        respond(
            request,
            201,
            serde_json::to_value(get(db, id)?.context("Missing created request")?)?,
        );
        return Ok(());
    }
    if path == "/v1/repair-approvals" || path.starts_with("/v1/repair-approvals?") {
        if *method != Method::Get {
            err(request, 405, "Use GET");
            return Ok(());
        }
        if !operator(who) {
            err(request, 403, "Operator identity required");
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
                let Ok(parsed) = value.parse::<i64>() else {
                    err(request, 400, "Invalid list query");
                    return Ok(());
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
            err(request, 400, "Invalid list range");
            return Ok(());
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut rows = {
            let mut stmt = tx.prepare(&format!("{SELECT} WHERE requester_actor=?1 OR approver_actor=?1 OR (state='pending' AND requester_actor<>?1) ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"))?;
            stmt.query_map(params![who.actor, limit, offset], row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for item in &mut rows {
            expire(&tx, item, now)?;
        }
        tx.commit()?;
        respond(request, 200, serde_json::to_value(rows)?);
        return Ok(());
    }
    if let Some(id) = approval_id(path, "/decision") {
        if *method != Method::Post {
            err(request, 405, "Use POST");
            return Ok(());
        }
        let input: DecideRepairApproval = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid decision");
                return Ok(());
            }
        };
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(mut item) = get(&tx, id)? else {
            err(request, 404, "Repair request missing");
            return Ok(());
        };
        expire(&tx, &mut item, now)?;
        if item.state == RepairState::Expired {
            tx.commit()?;
            err(request, 409, "Repair request expired");
            return Ok(());
        }
        if item.state != RepairState::Pending || item.requester == who.actor {
            err(request, 409, "Decision unavailable");
            return Ok(());
        }
        let state = if input.decision == RepairDecision::Approve {
            RepairState::Approved
        } else {
            RepairState::Denied
        };
        tx.execute("UPDATE repair_approvals SET state=?1,approver_actor=?2,approver_token_id=?3,approver_jwt_exp=?4,decided_at=?5 WHERE id=?6 AND state='pending'", params![state_name(state), who.actor, who.token_id, who.jwt_exp.map(|v| v.to_rfc3339()), now.to_rfc3339(), id.to_string()])?;
        audit(
            &tx,
            &who.actor,
            if state == RepairState::Approved {
                "repair_approved"
            } else {
                "repair_denied"
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
        let input: ConsumeRepairApproval = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid consume request");
                return Ok(());
            }
        };
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(mut item) = get(&tx, id)? else {
            err(request, 404, "Repair request missing");
            return Ok(());
        };
        expire(&tx, &mut item, now)?;
        if item.state == RepairState::Expired {
            tx.commit()?;
            err(request, 409, "Repair request expired");
            return Ok(());
        }
        let credentials = tx.query_row("SELECT requester_token_id,requester_jwt_exp,approver_token_id,approver_jwt_exp FROM repair_approvals WHERE id=?1", [id.to_string()], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?)))?;
        let valid = item.state == RepairState::Approved
            && item.requester == who.actor
            && item.binding == input.binding
            && input.binding.validate(now).is_ok()
            && original_authorized(
                &tx,
                &item.requester,
                credentials.0.as_deref(),
                credentials.1.as_deref(),
                now,
            )?
            && item.approver.as_deref().is_some_and(|actor| {
                actor != who.actor
                    && original_authorized(
                        &tx,
                        actor,
                        credentials.2.as_deref(),
                        credentials.3.as_deref(),
                        now,
                    )
                    .unwrap_or(false)
            });
        if !valid {
            err(request, 409, "Repair authorization unavailable");
            return Ok(());
        }
        let consume_id = Uuid::new_v4();
        tx.execute("UPDATE repair_approvals SET state='consumed',consume_id=?1,consumed_at=?2 WHERE id=?3 AND state='approved'", params![consume_id.to_string(), now.to_rfc3339(), id.to_string()])?;
        audit(&tx, &who.actor, "repair_consumed", &id.to_string())?;
        tx.commit()?;
        respond(
            request,
            200,
            serde_json::to_value(ConsumeReceipt {
                approval_id: id,
                consume_id,
                fingerprint: item.fingerprint,
            })?,
        );
        return Ok(());
    }
    if path == "/v1/repair-outcomes" && *method == Method::Post {
        let event: RepairOutcomeEvent = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid repair outcome");
                return Ok(());
            }
        };
        if event.event_id == Uuid::nil()
            || event.occurred_at > now + Duration::minutes(1)
            || event.occurred_at < now - Duration::days(90)
        {
            err(request, 400, "Invalid repair outcome");
            return Ok(());
        }
        let payload = serde_json::to_string(&event)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(item) = get(&tx, event.approval_id)? else {
            err(request, 404, "Repair approval missing");
            return Ok(());
        };
        if item.state != RepairState::Consumed
            || item.binding.run_id != event.run_id
            || item.binding.target_index != event.target_index
            || (who.actor != item.requester && who.role != Role::Admin)
        {
            err(request, 403, "Repair outcome unavailable");
            return Ok(());
        }
        if let Some(existing) = tx
            .query_row(
                "SELECT payload FROM repair_outcomes WHERE event_id=?1",
                [event.event_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            if existing == payload {
                respond(
                    request,
                    200,
                    serde_json::to_value(RepairOutcomeAck {
                        event_id: event.event_id,
                        accepted: true,
                    })?,
                );
            } else {
                err(request, 409, "Repair outcome conflict");
            }
            return Ok(());
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM repair_outcomes WHERE approval_id=?1)",
            [event.approval_id.to_string()],
            |r| r.get::<_, bool>(0),
        )? {
            err(request, 409, "Repair outcome already recorded");
            return Ok(());
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM repair_outcomes", [], |r| r.get(0))?;
        if count >= 200_000 {
            err(request, 503, "Repair outcome capacity reached");
            return Ok(());
        }
        tx.execute("INSERT INTO repair_outcomes(event_id,approval_id,payload,sender_actor,accepted_at) VALUES(?1,?2,?3,?4,?5)", params![event.event_id.to_string(), event.approval_id.to_string(), payload, who.actor, now.to_rfc3339()])?;
        audit(
            &tx,
            &who.actor,
            "repair_outcome",
            &event.event_id.to_string(),
        )?;
        tx.commit()?;
        respond(
            request,
            200,
            serde_json::to_value(RepairOutcomeAck {
                event_id: event.event_id,
                accepted: true,
            })?,
        );
        return Ok(());
    }
    err(request, 404, "Unknown repair API route");
    Ok(())
}
