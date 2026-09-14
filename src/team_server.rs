//! Relayne team API. Deliberately shares endpoint metadata, never credential material.
#[path = "collaboration_session.rs"]
pub mod collaboration_session;
#[path = "commerce.rs"]
pub mod commerce;
#[path = "team_oidc.rs"]
pub mod oidc;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedItem {
    pub id: Uuid,
    pub workspace: Uuid,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub source_id: Option<Uuid>,
    #[serde(default)]
    pub revision: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub actor: String,
    pub role: Role,
    pub items: Vec<SharedItem>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    pub actor: String,
    pub role: Role,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuedToken {
    pub id: Uuid,
    pub token: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Audit {
    pub sequence: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub time: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    pub id: Uuid,
    pub actor: String,
    pub role: Role,
    pub revoked: bool,
}

fn hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
fn role_name(role: &Role) -> &'static str {
    match role {
        Role::Viewer => "viewer",
        Role::Operator => "operator",
        Role::Admin => "admin",
    }
}
fn parse_role(s: &str) -> Result<Role> {
    Ok(match s {
        "viewer" => Role::Viewer,
        "operator" => Role::Operator,
        "admin" => Role::Admin,
        _ => bail!("Invalid stored role"),
    })
}
pub fn open_store(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;
      CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, payload TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, time TEXT NOT NULL);")?;
    Ok(db)
}
fn audit(db: &Connection, actor: &str, action: &str, target: &str) -> Result<()> {
    db.execute(
        "INSERT INTO audit(actor,action,target,time) VALUES(?1,?2,?3,?4)",
        params![actor, action, target, chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(())
}
fn issue(db: &Connection, actor: &str, role: &Role) -> Result<IssuedToken> {
    if actor.starts_with("oidc:")
        || actor.trim().is_empty()
        || actor.len() > 100
        || actor.chars().any(char::is_control)
    {
        bail!("Actor must contain 1–100 printable characters")
    }
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let id = Uuid::new_v4();
    db.execute(
        "INSERT INTO tokens(id,hash,actor,role) VALUES(?1,?2,?3,?4)",
        params![id.to_string(), hash(&token), actor, role_name(role)],
    )?;
    Ok(IssuedToken { id, token })
}
/// Only an explicitly invoked bootstrap command should call this; an existing installation cannot be bootstrapped again.
pub fn bootstrap(path: &Path, actor: &str) -> Result<IssuedToken> {
    let mut db = open_store(path)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM tokens", [], |r| r.get(0))?;
    if count != 0 {
        bail!("Store already initialized; use an authenticated admin to issue tokens")
    }
    let token = issue(&tx, actor, &Role::Admin)?;
    audit(&tx, actor, "bootstrap", &token.id.to_string())?;
    tx.commit()?;
    Ok(token)
}
fn valid_item(item: &SharedItem) -> bool {
    !item.name.trim().is_empty()
        && item.name.len() <= 200
        && item.host.len() <= 253
        && item.note.len() <= 8192
        && item.revision >= 0
        && item.revision < i64::MAX
        && match item.kind.as_str() {
            "workspace" => {
                item.id == item.workspace
                    && item.host.is_empty()
                    && item.port == 0
                    && item.protocol.is_empty()
            }
            "profile" => {
                !item.host.trim().is_empty()
                    && !item
                        .host
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
                    && item.port > 0
                    && ["RDP", "SSH", "VNC"].contains(&item.protocol.as_str())
            }
            "handoff" => item.host.is_empty() && item.port == 0 && item.protocol.is_empty(),
            _ => false,
        }
}
fn read_json<T: for<'a> Deserialize<'a>>(request: &mut Request) -> Result<T> {
    if request.body_length().is_some_and(|n| n > 32768) {
        bail!("Request exceeds 32 KiB")
    }
    let mut body = Vec::new();
    request.as_reader().take(32769).read_to_end(&mut body)?;
    if body.len() > 32768 {
        bail!("Request exceeds 32 KiB")
    }
    serde_json::from_slice(&body).context("Invalid JSON request")
}
fn respond(request: Request, code: u16, value: serde_json::Value) {
    let response = Response::from_string(value.to_string())
        .with_status_code(StatusCode(code))
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    let _ = request.respond(response);
}
fn err(request: Request, code: u16, message: &str) {
    respond(request, code, serde_json::json!({"error":message}));
}
/// Live role check used immediately before collaboration grant/consume.
pub fn actor_can_operate(db: &Connection, actor: &str) -> Result<bool> {
    if actor.starts_with("oidc:") {
        return Ok(oidc::actor_can_operate(actor));
    }
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM tokens WHERE actor=?1 AND revoked=0 AND role IN ('operator','admin'))", [actor], |row| row.get(0))?)
}
fn serve_request(db: &mut Connection, request: Request) -> Result<()> {
    serve_request_with_oidc(db, request, None)
}
fn serve_request_with_oidc(
    db: &mut Connection,
    mut request: Request,
    oidc: Option<&mut oidc::Verifier>,
) -> Result<()> {
    if request.url() == "/v1/tickets/webhook/github" && request.method() == &Method::Post {
        let config = match crate::ticket_intake::WebhookConfig::from_env() {
            Ok(Some(config)) => config,
            _ => {
                err(request, 503, "Ticket intake is not configured");
                return Ok(());
            }
        };
        let header = |name: &'static str| {
            let values = request
                .headers()
                .iter()
                .filter(|h| h.field.equiv(name))
                .map(|h| h.value.as_str().to_owned())
                .collect::<Vec<_>>();
            if values.len() == 1 {
                values.into_iter().next()
            } else {
                None
            }
        };
        let (Some(event), Some(delivery), Some(signature)) = (
            header("X-GitHub-Event"),
            header("X-GitHub-Delivery"),
            header("X-Hub-Signature-256"),
        ) else {
            err(
                request,
                400,
                "Unique GitHub event, delivery and signature headers required",
            );
            return Ok(());
        };
        let mut bytes = Vec::new();
        request
            .as_reader()
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        match crate::ticket_intake::receive_github(
            db, &config, &event, &delivery, &signature, &bytes,
        ) {
            Ok(receipt) => respond(request, 200, serde_json::to_value(receipt)?),
            Err(_) => err(request, 400, "Ticket webhook rejected"),
        }
        return Ok(());
    }
    if request.url() == "/v1/billing/webhook" && request.method() == &Method::Post {
        let Ok(config) = commerce::Config::from_environment() else {
            err(request, 503, "Billing is not configured");
            return Ok(());
        };
        let headers = request
            .headers()
            .iter()
            .filter(|h| h.field.equiv("Stripe-Signature"))
            .map(|h| h.value.as_str().to_owned())
            .collect::<Vec<_>>();
        if headers.len() != 1 {
            err(request, 400, "One Stripe signature is required");
            return Ok(());
        }
        let mut bytes = Vec::new();
        request
            .as_reader()
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        let now = chrono::Utc::now().timestamp();
        match commerce::webhook(db, &config, &headers[0], &bytes, now) {
            Ok(()) => respond(request, 200, serde_json::json!({"received":true})),
            Err(_) => err(
                request,
                400,
                "Webhook verification or reconciliation failed; retry required",
            ),
        }
        return Ok(());
    }
    let auth_headers = request
        .headers()
        .iter()
        .filter(|h| h.field.equiv("Authorization"))
        .count();
    if auth_headers != 1 {
        err(request, 401, "Authentication required");
        return Ok(());
    }
    let bearer = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .filter(|s| s.len() <= 16384);
    let identity = if let Some(token) = bearer
        .filter(|token| token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        db.query_row(
            "SELECT actor,role,id FROM tokens WHERE hash=?1 AND revoked=0 AND actor NOT LIKE 'oidc:%'",
            [hash(token)],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    } else if let (Some(token), Some(verifier)) = (bearer, oidc) {
        verifier
            .verify(token)
            .ok()
            .map(|(actor, role)| (actor, role_name(&role).to_owned(), String::new()))
    } else {
        None
    };
    let Some((actor, role, token_id)) = identity else {
        err(request, 401, "Authentication required");
        return Ok(());
    };
    let role = parse_role(&role)?;
    let path = request.url().to_owned();
    let method = request.method().clone();
    if path == "/v1/escalations" && method == Method::Get {
        respond(
            request,
            200,
            serde_json::to_value(crate::ticket_escalation::list(db)?)?,
        );
        return Ok(());
    }
    if path.starts_with("/v1/escalations/") {
        if path == "/v1/escalations/config" && method == Method::Get {
            match crate::ticket_escalation::Config::from_env() {
                Ok(Some(config)) => respond(
                    request,
                    200,
                    serde_json::json!({"destination":config.destination(),"fingerprint":config.fingerprint()}),
                ),
                _ => err(request, 503, "Escalation is not configured"),
            }
            return Ok(());
        }
        if method != Method::Post {
            err(request, 405, "Use POST for escalation actions");
            return Ok(());
        }
        if role == Role::Viewer {
            err(
                request,
                403,
                "Operator role required for escalation authorization",
            );
            return Ok(());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Enqueue {
            delivery: String,
            reason: String,
            expires_utc: i64,
            expected_fingerprint: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Retry {
            id: String,
            reason: String,
            expires_utc: i64,
            expected_fingerprint: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reconcile {
            id: String,
            delivered: bool,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Cancel {
            id: String,
        }
        let result = (|| -> Result<serde_json::Value> {
            match path.as_str() {
                "/v1/escalations/enqueue" => {
                    let input: Enqueue = read_json(&mut request)?;
                    let config = crate::ticket_escalation::Config::from_env()?
                        .context("Escalation not configured")?;
                    anyhow::ensure!(
                        input.expected_fingerprint == config.fingerprint(),
                        "Destination changed; review it again"
                    );
                    Ok(serde_json::to_value(crate::ticket_escalation::enqueue(
                        db,
                        &config,
                        &actor,
                        &input.delivery,
                        &input.reason,
                        input.expires_utc,
                    )?)?)
                }
                "/v1/escalations/retry" => {
                    let input: Retry = read_json(&mut request)?;
                    let config = crate::ticket_escalation::Config::from_env()?
                        .context("Escalation not configured")?;
                    anyhow::ensure!(
                        input.expected_fingerprint == config.fingerprint(),
                        "Destination changed; review it again"
                    );
                    Ok(serde_json::to_value(
                        crate::ticket_escalation::reauthorize(
                            db,
                            &config,
                            &actor,
                            &input.id,
                            &input.reason,
                            input.expires_utc,
                        )?,
                    )?)
                }
                "/v1/escalations/cancel" => {
                    let input: Cancel = read_json(&mut request)?;
                    crate::ticket_escalation::cancel(db, &actor, &input.id)?;
                    Ok(serde_json::json!({"recorded":true}))
                }
                "/v1/escalations/reconcile" => {
                    let input: Reconcile = read_json(&mut request)?;
                    crate::ticket_escalation::reconcile(db, &actor, &input.id, input.delivered)?;
                    Ok(serde_json::json!({"recorded":true}))
                }
                _ => anyhow::bail!("Unknown escalation action"),
            }
        })();
        match result {
            Ok(value) => respond(request, 200, value),
            Err(_) => err(
                request,
                409,
                "Escalation action rejected; check state, destination and authorization limits",
            ),
        }
        return Ok(());
    }
    if method == Method::Get && path == "/v1/tickets/inbox" {
        respond(
            request,
            200,
            serde_json::to_value(crate::ticket_intake::list_inbox(db)?)?,
        );
        return Ok(());
    }
    if method == Method::Post && path == "/v1/tickets/inbox" {
        if role == Role::Viewer {
            err(request, 403, "Operator role required for ticket intake");
            return Ok(());
        }
        let mut bytes = Vec::new();
        request
            .as_reader()
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        match crate::ticket_intake::receive_import(db, &actor, &bytes) {
            Ok(receipt) => respond(request, 200, serde_json::to_value(receipt)?),
            Err(_) => err(request, 400, "Ticket intake rejected"),
        }
        return Ok(());
    }
    if path.starts_with("/v1/billing/") {
        let now = chrono::Utc::now().timestamp();
        if method == Method::Get && path == "/v1/billing/entitlement" {
            respond(
                request,
                200,
                serde_json::to_value(commerce::entitlement(db, &actor, now)?)?,
            );
            return Ok(());
        }
        if method != Method::Post {
            err(request, 405, "Use POST for billing actions");
            return Ok(());
        }
        let Ok(config) = commerce::Config::from_environment() else {
            err(request, 503, "Billing is not configured");
            return Ok(());
        };
        let result = match path.as_str() {
            "/v1/billing/checkout" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Checkout {
                    attempt: Uuid,
                }
                match read_json::<Checkout>(&mut request) {
                    Ok(input) => commerce::checkout(db, &config, &actor, input.attempt),
                    Err(_) => {
                        err(request, 400, "Invalid checkout request");
                        return Ok(());
                    }
                }
            }
            "/v1/billing/portal" => commerce::portal(db, &config, &actor),
            "/v1/billing/refresh" => commerce::refresh(db, &config, &actor, now)
                .and_then(|e| Ok(serde_json::to_value(e)?)),
            _ => {
                err(request, 404, "Unknown billing action");
                return Ok(());
            }
        };
        match result {
            Ok(value) => respond(request, 200, value),
            Err(_) => err(
                request,
                409,
                "Billing action failed or requires configuration; retry with the same attempt",
            ),
        }
        return Ok(());
    }
    if method == Method::Post && path == "/v1/collaboration" {
        let mut body = Vec::new();
        request.as_reader().take(3_000_001).read_to_end(&mut body)?;
        if body.len() > 3_000_000 {
            err(request, 400, "Collaboration request too large");
            return Ok(());
        }
        let command = match serde_json::from_slice::<collaboration_session::Command>(&body) {
            Ok(c) => c,
            Err(_) => {
                err(request, 400, "Invalid collaboration request");
                return Ok(());
            }
        };
        let audit_action = match &command {
            collaboration_session::Command::Poll { .. }
            | collaboration_session::Command::Publish { .. } => None,
            collaboration_session::Command::Create { .. } => {
                Some(("collaboration_create", String::new()))
            }
            collaboration_session::Command::Close { room }
            | collaboration_session::Command::Leave { room } => {
                Some(("collaboration_leave", room.to_string()))
            }
            collaboration_session::Command::Grant { room, actor } => {
                Some(("collaboration_grant", format!("{room}:{actor}")))
            }
            collaboration_session::Command::Revoke { room } => {
                Some(("collaboration_revoke", room.to_string()))
            }
            collaboration_session::Command::Approve { id, digest, .. } => {
                Some(("collaboration_approve", format!("{id}:{digest}")))
            }
            collaboration_session::Command::Consume { id, digest, .. } => {
                Some(("collaboration_consume", format!("{id}:{digest}")))
            }
            collaboration_session::Command::Propose { room, .. } => {
                Some(("collaboration_propose", room.to_string()))
            }
            collaboration_session::Command::Annotate { room, .. } => {
                Some(("collaboration_annotate", room.to_string()))
            }
        };
        match collaboration_session::apply(
            db,
            &actor,
            &role,
            command,
            chrono::Utc::now().timestamp(),
        ) {
            Ok(value) => {
                if let Some((action, target)) = audit_action {
                    audit(
                        db,
                        &actor,
                        action,
                        &if target.is_empty() {
                            value
                                .room
                                .as_ref()
                                .map(|r| r.id.to_string())
                                .unwrap_or_default()
                        } else {
                            target
                        },
                    )?;
                }
                respond(request, 200, serde_json::to_value(value)?);
            }
            Err(message) => err(request, 403, &message),
        }
    } else if method == Method::Get && path == "/v1/state" {
        let mut statement = db.prepare("SELECT payload FROM items ORDER BY id LIMIT 10001")?;
        let values = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let items = values
            .iter()
            .map(|v| serde_json::from_str(v))
            .collect::<serde_json::Result<Vec<SharedItem>>>()?;
        respond(
            request,
            200,
            serde_json::to_value(Snapshot { actor, role, items })?,
        );
    } else if method == Method::Post && path == "/v1/items" {
        if role == Role::Viewer {
            err(request, 403, "Operator role required");
            return Ok(());
        }
        let mut item: SharedItem = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid item JSON or size");
                return Ok(());
            }
        };
        if !valid_item(&item) {
            err(request, 400, "Invalid item fields");
            return Ok(());
        }
        if item.kind == "workspace" && role != Role::Admin {
            err(request, 403, "Admin role required for workspaces");
            return Ok(());
        }
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT revision,payload FROM items WHERE id=?1",
                [item.id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if existing.as_ref().map(|v| v.0).unwrap_or(0) != item.revision {
            err(request, 409, "Revision conflict; reload before editing");
            return Ok(());
        }
        if let Some((_, payload)) = &existing {
            let old: SharedItem = serde_json::from_str(payload)?;
            if old.kind != item.kind || old.workspace != item.workspace {
                err(request, 400, "Item kind and workspace cannot change");
                return Ok(());
            }
        } else {
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
            if count >= 10000 {
                err(request, 409, "Store item limit reached");
                return Ok(());
            }
        }
        if item.kind != "workspace" {
            let workspace: Option<String> = tx
                .query_row(
                    "SELECT payload FROM items WHERE id=?1",
                    [item.workspace.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if !workspace
                .and_then(|s| serde_json::from_str::<SharedItem>(&s).ok())
                .is_some_and(|i| i.kind == "workspace")
            {
                err(request, 400, "Workspace does not exist");
                return Ok(());
            }
        }
        item.revision += 1;
        tx.execute("INSERT INTO items(id,revision,payload) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload",params![item.id.to_string(),item.revision,serde_json::to_string(&item)?])?;
        audit(
            &tx,
            &actor,
            if existing.is_some() {
                "update"
            } else {
                "create"
            },
            &item.id.to_string(),
        )?;
        tx.commit()?;
        respond(request, 200, serde_json::to_value(item)?);
    } else if path == "/v1/tokens" && method == Method::Post {
        if role != Role::Admin {
            err(request, 403, "Admin role required");
            return Ok(());
        }
        let input: TokenRequest = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid token request");
                return Ok(());
            }
        };
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let issued = match issue(&tx, &input.actor, &input.role) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid actor");
                return Ok(());
            }
        };
        audit(&tx, &actor, "issue_token", &issued.id.to_string())?;
        tx.commit()?;
        respond(request, 201, serde_json::to_value(issued)?);
    } else if path == "/v1/revoke" && method == Method::Post {
        if role != Role::Admin {
            err(request, 403, "Admin role required");
            return Ok(());
        }
        let input: RevokeRequest = match read_json(&mut request) {
            Ok(v) => v,
            Err(_) => {
                err(request, 400, "Invalid revocation request");
                return Ok(());
            }
        };
        if input.id.to_string() == token_id {
            err(
                request,
                409,
                "Cannot revoke current token; use a second admin",
            );
            return Ok(());
        }
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE tokens SET revoked=1 WHERE id=?1 AND revoked=0",
            [input.id.to_string()],
        )?;
        if changed == 0 {
            err(request, 404, "Active token not found");
            return Ok(());
        }
        let revoked_actor: String = tx.query_row(
            "SELECT actor FROM tokens WHERE id=?1",
            [input.id.to_string()],
            |r| r.get(0),
        )?;
        collaboration_session::invalidate_actor(&tx, &revoked_actor)?;
        audit(&tx, &actor, "revoke_token", &input.id.to_string())?;
        tx.commit()?;
        respond(request, 200, serde_json::json!({"revoked":true}));
    } else if method == Method::Get && (path == "/v1/audit" || path == "/v1/tokens") {
        if role != Role::Admin {
            err(request, 403, "Admin role required");
            return Ok(());
        }
        if path == "/v1/audit" {
            let mut stmt = db.prepare("SELECT sequence,actor,action,target,time FROM audit ORDER BY sequence DESC LIMIT 500")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(Audit {
                        sequence: r.get(0)?,
                        actor: r.get(1)?,
                        action: r.get(2)?,
                        target: r.get(3)?,
                        time: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            respond(request, 200, serde_json::to_value(rows)?);
        } else {
            let mut stmt =
                db.prepare("SELECT id,actor,role,revoked FROM tokens ORDER BY actor LIMIT 1000")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, bool>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let rows = rows
                .into_iter()
                .map(|(id, actor, role, revoked)| {
                    Ok(TokenInfo {
                        id: Uuid::parse_str(&id)?,
                        actor,
                        role: parse_role(&role)?,
                        revoked,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            respond(request, 200, serde_json::to_value(rows)?);
        }
    } else {
        err(request, 404, "Unknown API route");
    }
    Ok(())
}
pub fn serve(server: Server, mut db: Connection) {
    serve_with_oidc(server, &mut db, None);
}
fn serve_with_oidc(server: Server, db: &mut Connection, mut oidc: Option<oidc::Verifier>) {
    for request in server.incoming_requests() {
        // Storage errors contain no submitted payload or authorization header.
        if serve_request_with_oidc(db, request, oidc.as_mut()).is_err() {
            eprintln!("Relayne team storage/request failure");
        }
    }
}
pub fn run(path: &Path, address: &str) -> Result<()> {
    let mut db = open_store(path)?;
    let oidc = oidc::Verifier::from_environment()?;
    let initialized: i64 = db.query_row("SELECT COUNT(*) FROM tokens", [], |r| r.get(0))?;
    if initialized == 0 {
        bail!("Initialize explicitly with bootstrap before starting the server")
    }
    let server =
        Server::http(address).map_err(|e| anyhow::anyhow!("Cannot bind team server: {e}"))?;
    eprintln!("Relayne team listening on {address}");
    serve_with_oidc(server, &mut db, oidc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Harness {
        url: String,
        db: std::path::PathBuf,
        admin: IssuedToken,
        server: std::sync::Arc<Server>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Harness {
        fn new() -> Self {
            let db =
                std::env::temp_dir().join(format!("relayne-team-test-{}.sqlite", Uuid::new_v4()));
            let admin = bootstrap(&db, "test-admin").unwrap();
            let server = std::sync::Arc::new(Server::http("127.0.0.1:0").unwrap());
            let url = format!("http://{}", server.server_addr());
            let worker = server.clone();
            let path = db.clone();
            let thread = std::thread::spawn(move || {
                let mut db = open_store(&path).unwrap();
                while let Ok(req) = worker.recv() {
                    serve_request(&mut db, req).unwrap();
                }
            });
            Self {
                url,
                db,
                admin,
                server,
                thread: Some(thread),
            }
        }
        fn request(
            &self,
            method: reqwest::Method,
            path: &str,
            token: &str,
            body: serde_json::Value,
        ) -> reqwest::blocking::Response {
            reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap()
                .request(method, format!("{}{path}", self.url))
                .bearer_auth(token)
                .json(&body)
                .send()
                .unwrap()
        }
        fn issue(&self, role: Role) -> IssuedToken {
            self.request(
                reqwest::Method::POST,
                "/v1/tokens",
                &self.admin.token,
                serde_json::to_value(TokenRequest {
                    actor: role_name(&role).into(),
                    role,
                })
                .unwrap(),
            )
            .json()
            .unwrap()
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.server.unblock();
            if let Some(t) = self.thread.take() {
                t.join().unwrap();
            }
            let _ = std::fs::remove_file(&self.db);
            let _ = std::fs::remove_file(format!("{}-wal", self.db.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.db.display()));
        }
    }
    #[test]
    fn account_status_and_ticket_intake_require_authenticated_roles() {
        let h = Harness::new();
        let viewer = h.issue(Role::Viewer);
        let operator = h.issue(Role::Operator);
        let empty = serde_json::json!({});
        assert_eq!(
            h.request(
                reqwest::Method::GET,
                "/v1/billing/entitlement",
                &"f".repeat(64),
                empty.clone()
            )
            .status()
            .as_u16(),
            401
        );
        let status: serde_json::Value = h
            .request(
                reqwest::Method::GET,
                "/v1/billing/entitlement",
                &viewer.token,
                empty.clone(),
            )
            .json()
            .unwrap();
        assert_eq!(status["active"], false);
        let ticket = serde_json::json!({"provider":"jira","source":"https://example.atlassian.net","ticket":{"key":"SUP-1","fields":{"summary":"Connection issue","description":{"type":"doc","content":[]},"updated":"1"}}});
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/tickets/inbox",
                &viewer.token,
                ticket.clone()
            )
            .status()
            .as_u16(),
            403
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/tickets/inbox",
                &operator.token,
                ticket
            )
            .status()
            .as_u16(),
            200
        );
        let inbox: Vec<crate::ticket_intake::InboxItem> = h
            .request(
                reqwest::Method::GET,
                "/v1/tickets/inbox",
                &viewer.token,
                empty,
            )
            .json()
            .unwrap();
        assert_eq!(inbox.len(), 1);
    }

    #[test]
    fn collaboration_http_auth_membership_and_latest_frame() {
        use collaboration_session::{Command, Frame, Reply};
        let h = Harness::new();
        let viewer = h.issue(Role::Viewer);
        let operator = h.issue(Role::Operator);
        let create = serde_json::to_value(Command::Create {
            session: Uuid::new_v4(),
            members: vec!["viewer".into()],
        })
        .unwrap();
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/collaboration",
                "",
                create.clone()
            )
            .status(),
            401
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &viewer.token,
                create.clone()
            )
            .status(),
            403
        );
        let room = h
            .request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &h.admin.token,
                create,
            )
            .json::<Reply>()
            .unwrap()
            .room
            .unwrap();
        let publish = serde_json::to_value(Command::Publish {
            room: room.id,
            frame: Frame {
                width: 2,
                height: 1,
                rgb: vec![1, 2, 3, 4, 5, 6],
                source_hash: 42,
            },
        })
        .unwrap();
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &viewer.token,
                publish.clone()
            )
            .status(),
            403
        );
        assert!(
            h.request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &h.admin.token,
                publish
            )
            .status()
            .is_success()
        );
        let poll = serde_json::to_value(Command::Poll { room: room.id }).unwrap();
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &operator.token,
                poll.clone()
            )
            .status(),
            403
        );
        let viewed = h
            .request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &viewer.token,
                poll.clone(),
            )
            .json::<Reply>()
            .unwrap();
        assert_eq!(
            viewed.room.unwrap().frame.unwrap().rgb,
            vec![1, 2, 3, 4, 5, 6]
        );
        h.request(
            reqwest::Method::POST,
            "/v1/revoke",
            &h.admin.token,
            serde_json::to_value(RevokeRequest { id: viewer.id }).unwrap(),
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/collaboration",
                &viewer.token,
                poll
            )
            .status(),
            401
        );
    }
    #[test]
    fn authenticated_roles_conflicts_revocation_and_persistence() {
        let h = Harness::new();
        assert!(bootstrap(&h.db, "second-bootstrap").is_err());
        assert_eq!(
            h.request(
                reqwest::Method::GET,
                "/v1/state",
                "",
                serde_json::Value::Null
            )
            .status(),
            401
        );
        let viewer = h.issue(Role::Viewer);
        let operator = h.issue(Role::Operator);
        let workspace = Uuid::new_v4();
        let mut item = SharedItem {
            id: workspace,
            workspace,
            kind: "workspace".into(),
            name: "Operations".into(),
            host: String::new(),
            port: 0,
            protocol: String::new(),
            note: String::new(),
            source_id: None,
            revision: 0,
        };
        let body = serde_json::to_value(&item).unwrap();
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/items",
                &viewer.token,
                body.clone()
            )
            .status(),
            403
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/items",
                &operator.token,
                body.clone()
            )
            .status(),
            403
        );
        let saved: SharedItem = h
            .request(
                reqwest::Method::POST,
                "/v1/items",
                &h.admin.token,
                body.clone(),
            )
            .json()
            .unwrap();
        assert_eq!(saved.revision, 1);
        assert_eq!(
            h.request(reqwest::Method::POST, "/v1/items", &h.admin.token, body)
                .status(),
            409
        );
        item.id = Uuid::new_v4();
        item.kind = "profile".into();
        item.host = "example.internal".into();
        item.port = 3389;
        item.protocol = "RDP".into();
        let saved: SharedItem = h
            .request(
                reqwest::Method::POST,
                "/v1/items",
                &operator.token,
                serde_json::to_value(&item).unwrap(),
            )
            .json()
            .unwrap();
        assert_eq!(saved.revision, 1);
        let mut changed = saved.clone();
        changed.name = "Edited".into();
        let updated: SharedItem = h
            .request(
                reqwest::Method::POST,
                "/v1/items",
                &operator.token,
                serde_json::to_value(&changed).unwrap(),
            )
            .json()
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/items",
                &operator.token,
                serde_json::to_value(&changed).unwrap()
            )
            .status(),
            409
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/tokens",
                &operator.token,
                serde_json::json!({"actor":"escalate","role":"admin"})
            )
            .status(),
            403
        );
        assert_eq!(
            h.request(
                reqwest::Method::GET,
                "/v1/audit",
                &viewer.token,
                serde_json::Value::Null
            )
            .status(),
            403
        );
        let state: Snapshot = h
            .request(
                reqwest::Method::GET,
                "/v1/state",
                &viewer.token,
                serde_json::Value::Null,
            )
            .json()
            .unwrap();
        assert_eq!(state.role, Role::Viewer);
        assert_eq!(state.items.len(), 2);
        item.id = Uuid::new_v4();
        item.kind = "handoff".into();
        item.name = "Pilot handoff".into();
        item.note = "Verify service state before rollout".into();
        item.host.clear();
        item.port = 0;
        item.protocol.clear();
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/items",
                &operator.token,
                serde_json::to_value(&item).unwrap()
            )
            .status(),
            200
        );
        let mut invalid = serde_json::to_value(&item).unwrap();
        invalid["password"] = serde_json::json!("secret-must-not-store");
        assert_eq!(
            h.request(reqwest::Method::POST, "/v1/items", &operator.token, invalid)
                .status(),
            400
        );
        item.note = "x".repeat(8193);
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/items",
                &operator.token,
                serde_json::to_value(&item).unwrap()
            )
            .status(),
            400
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/revoke",
                &h.admin.token,
                serde_json::json!({"id":operator.id})
            )
            .status(),
            200
        );
        assert_eq!(
            h.request(
                reqwest::Method::GET,
                "/v1/state",
                &operator.token,
                serde_json::Value::Null
            )
            .status(),
            401
        );
        assert_eq!(
            h.request(
                reqwest::Method::POST,
                "/v1/revoke",
                &h.admin.token,
                serde_json::json!({"id":h.admin.id})
            )
            .status(),
            409
        );
        let events: Vec<Audit> = h
            .request(
                reqwest::Method::GET,
                "/v1/audit",
                &h.admin.token,
                serde_json::Value::Null,
            )
            .json()
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.action == "update" && e.actor == "operator")
        );
        assert!(events.iter().any(|e| e.action == "revoke_token"));
        assert!(events.iter().all(|e| !e.time.is_empty()));
        let serialized = serde_json::to_string(&events).unwrap();
        assert!(!serialized.contains(&operator.token));
        assert!(!serialized.contains("example.internal"));
        assert!(!serialized.contains("secret-must-not-store"));
        let reopened = open_store(&h.db).unwrap();
        let count: i64 = reopened
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);
        let hashes: Vec<String> = reopened
            .prepare("SELECT hash FROM tokens")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            hashes
                .iter()
                .all(|v| v != &h.admin.token && v != &viewer.token && v != &operator.token)
        );
    }
}
