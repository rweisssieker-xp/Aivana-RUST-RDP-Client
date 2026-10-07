use super::{
    config::Config,
    connectors,
    core::{Core, Principal},
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
pub struct Service {
    pub config: Config,
    pub core: Mutex<Core>,
    pub ops: Mutex<rusqlite::Connection>,
    credentials: Vec<([u8; 32], Principal)>,
    role: ProcessRole,
    bind: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessRole {
    Investigator,
    Executor,
}
const EXECUTOR_ACTIONS: &[&str] = &[
    "auth.me",
    "response.status",
    "response.execute",
    "service.stop",
];
const PUBLIC: &[&str] = &[
    "playbooks.catalog",
    "playbooks.run",
    "cases.create",
    "cases.list",
    "cases.get",
    "cases.export",
    "cases.analyze",
    "evidence.ingest",
    "context.set",
    "review.record",
    "questions.upsert",
    "actions.upsert",
    "actions.verify",
    "risks.accept",
    "decisions.record",
    "cases.handoff",
    "cases.close",
    "cases.reopen",
    "audit.list",
    "notifications.list",
    "notifications.ack",
    "governance.sweep",
    "budgets.increase",
    "suppliers.upsert",
    "suppliers.accept",
    "sites.assess",
    "sites.matrix",
    "recovery.gate",
];
const WRAPPERS: &[&str] = &[
    "collectors.status",
    "collectors.probe",
    "collectors.run",
    "response.status",
    "response.propose",
    "response.challenge",
    "response.execute",
    "response.reconcile",
    "pilot.status",
    "pilot.record",
    "pilot.report",
    "service.recovery_ack",
    "integrations.status",
    "integrations.probe",
    "cmdb.sync",
    "tickets.sync",
    "sources.import",
    "auth.me",
    "service.status",
    "service.stop",
    "service.resume",
    "connectors.status",
    "connectors.probe",
    "investigation.start",
    "notifications.probe",
    "notifications.status",
    "notifications.snooze",
    "releases.status",
    "releases.submit",
    "releases.review",
    "releases.shadow",
    "releases.activate",
    "releases.rollback",
];
fn lock<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| anyhow::anyhow!("Synchronization failed"))
}
fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |v, (x, y)| v | (x ^ y)) == 0
}
impl Service {
    pub fn open(path: &Path, config: Config) -> Result<Self> {
        let bind = config.bind.clone();
        Self::open_with_role(path, config, ProcessRole::Investigator, bind)
    }

    pub(crate) fn open_executor(path: &Path, config: Config, bind: &str) -> Result<Self> {
        let address: std::net::SocketAddr = bind
            .parse()
            .context("Executor bind must be numeric loopback address")?;
        let investigator_address: std::net::SocketAddr = config.bind.parse()?;
        if !address.ip().is_loopback() || address == investigator_address {
            bail!("Executor requires a separate numeric loopback bind address");
        }
        if !config.response.enabled {
            bail!("Response must be enabled for executor startup");
        }
        Self::open_with_role(path, config, ProcessRole::Executor, bind.to_owned())
    }

    fn open_with_role(
        path: &Path,
        config: Config,
        role: ProcessRole,
        bind: String,
    ) -> Result<Self> {
        config.validate()?;
        let core = Core::open(path, serde_json::to_value(&config)?)?;
        let ops = rusqlite::Connection::open(path)?;
        ops.busy_timeout(Duration::from_secs(10))?;
        ops.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS investigator_service_state(tenant TEXT NOT NULL,key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(tenant,key));")?;
        let mut credentials = Vec::new();
        for user in &config.users {
            if let Ok(token) = std::env::var(&user.token_env) {
                if token.len() < 32 || token.len() > 4096 || token.chars().any(char::is_whitespace)
                {
                    bail!("Authentication token must contain 32..4096 non-whitespace characters")
                }
                let hash = digest(&token);
                if credentials
                    .iter()
                    .any(|(existing, _)| equal(existing, &hash))
                {
                    bail!("Authentication tokens must be distinct")
                }
                credentials.push((
                    hash,
                    Principal {
                        tenant: config.tenant.clone(),
                        actor: user.actor.clone(),
                        role: user.role.clone(),
                    },
                ));
            }
        }
        Ok(Self {
            config,
            core: Mutex::new(core),
            ops: Mutex::new(ops),
            credentials,
            role,
            bind,
        })
    }

    pub(crate) fn is_executor(&self) -> bool {
        self.role == ProcessRole::Executor
    }

    fn starts_investigation_worker(&self) -> bool {
        self.role == ProcessRole::Investigator
    }
    pub fn system(&self) -> Principal {
        Principal {
            tenant: self.config.tenant.clone(),
            actor: "investigator-worker".into(),
            role: "system".into(),
        }
    }
    pub fn exec(&self, p: &Principal, action: &str, payload: Value) -> Result<Value> {
        lock(&self.core)?.execute(p, action, payload, Utc::now())
    }
    pub fn state(&self, key: &str) -> Result<Value> {
        let value: Option<String> = lock(&self.ops)?
            .query_row(
                "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key=?2",
                params![self.config.tenant, key],
                |r| r.get(0),
            )
            .optional()?;
        value
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .unwrap_or(Ok(Value::Null))
    }
    pub fn set_state(&self, key: &str, value: Value) -> Result<()> {
        lock(&self.ops)?.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,?2,?3) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value",params![self.config.tenant,key,value.to_string()])?;
        Ok(())
    }
    pub fn stopped(&self) -> bool {
        self.state("stopped")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
    }
    pub fn audit(&self, action: &str, payload: Value) -> Result<()> {
        self.exec(
            &self.system(),
            "audit.record",
            json!({"action":action,"details":payload}),
        )?;
        Ok(())
    }
    pub fn status(&self) -> Result<Value> {
        let mut health = serde_json::Map::new();
        let mut ready = true;
        for source in ["entra", "defender"] {
            let h = self.state(&format!("health:{source}"))?;
            let fresh = h["checked_at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .is_some_and(|t| {
                    t <= Utc::now() && Utc::now().signed_duration_since(t).num_seconds() < 3600
                });
            ready &= fresh && h["status"] == "passed";
            health.insert(source.into(), h);
        }
        let release = self.state("release:active")?;
        let budget = self.monthly_budget()?;
        let notification = self.state("notification:health")?;
        let notification_ready = notification["status"] == "passed"
            && notification["checked_at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .is_some_and(|t| {
                    t <= Utc::now() && Utc::now().signed_duration_since(t).num_seconds() <= 86400
                });
        Ok(
            json!({"tenant":self.config.tenant,"stopped":self.stopped(),"mode":if self.config.sources.enabled{"live_read_only"}else{"offline"},"a1_ready":self.config.a1_gate().is_ok()&&ready&&notification_ready&&release["status"]=="active"&&release["package"]["components"]==super::releases::components()&&budget["can_reserve_call"]==true&&!self.stopped(),"budget":budget,"release":release,"notification_health":notification,"connector_health":health,"jobs":self.exec(&self.system(),"jobs.status",json!({}))?,"sources_enabled":self.config.sources.enabled,"recovery":self.state("recovery:last")?}),
        )
    }
    pub fn monthly_budget(&self) -> Result<Value> {
        let month = Utc::now().format("%Y-%m").to_string();
        let used:i64=lock(&self.ops)?.query_row("SELECT COALESCE(SUM(COALESCE(actual,amount)),0) FROM investigator_budget WHERE tenant=?1 AND month=?2",params![self.config.tenant,month],|r|r.get(0))?;
        let used = used.max(0) as u64;
        let limit = self.config.budgets.monthly_cost_micros;
        let remaining = limit.saturating_sub(used);
        Ok(
            json!({"month":month,"reserved_or_settled_micros":used,"limit_micros":limit,"remaining_micros":remaining,"warning_80_percent":used>=limit.saturating_mul(80)/100,"can_reserve_call":remaining>=self.config.budgets.api_call_cost_micros,"basis":"conservative operator-configured API costs; no model calls"}),
        )
    }
    fn authenticate(&self, token: &str) -> Result<Principal> {
        if token.len() > 4096 {
            bail!("Authentication required")
        }
        let candidate = digest(token);
        let mut identity = None;
        for (expected, p) in &self.credentials {
            if equal(expected, &candidate) {
                identity = Some(p.clone())
            }
        }
        identity.context("Authentication required")
    }
    pub fn command(&self, p: &Principal, action: &str, payload: Value) -> Result<Value> {
        if !payload.is_object() {
            bail!("Command payload must be an object")
        }
        if p.tenant != self.config.tenant
            || !self
                .config
                .users
                .iter()
                .any(|u| u.actor == p.actor && u.role == p.role)
        {
            bail!("Unauthorized identity")
        }
        if payload
            .get("tenant")
            .and_then(Value::as_str)
            .is_some_and(|t| t != p.tenant)
            || ["actor", "role", "principal"]
                .iter()
                .any(|k| payload.get(k).is_some())
        {
            self.audit(
                "identity_override",
                json!({"actor":p.actor,"action":action}),
            )?;
            bail!("Identity overrides forbidden")
        }
        if self.is_executor() {
            if !EXECUTOR_ACTIONS.contains(&action) {
                bail!("Action unavailable in response executor");
            }
            if action == "service.stop" {
                if !matches!(p.role.as_str(), "admin" | "analyst" | "incident_lead") {
                    bail!("Forbidden service control");
                }
                self.set_state("stopped", json!(true))?;
                self.audit(
                    "service.stop",
                    json!({"actor":p.actor,"process_role":"executor"}),
                )?;
                return Ok(json!({"stopped":true}));
            }
        } else if action == "response.execute" {
            bail!("Response execution requires the dedicated executor process");
        }

        match action {
            "collectors.status" | "collectors.probe" | "collectors.run" => {
                super::collectors::handle(self, p, action, payload)
            }
            "response.status" | "response.propose" | "response.challenge" | "response.execute"
            | "response.reconcile" => super::response::handle(self, p, action, payload),
            "sites.matrix" => super::site_matrix::handle(self, p, payload),
            "pilot.status" | "pilot.record" | "pilot.report" => {
                super::pilot::handle(self, p, action, payload)
            }
            "integrations.status"
            | "integrations.probe"
            | "cmdb.sync"
            | "tickets.sync"
            | "sources.import" => super::integrations::handle(self, p, action, payload),
            "auth.me" => Ok(
                json!({"tenant":p.tenant,"actor":p.actor,"role":p.role,"allowed_sites":self.config.allowed_sites}),
            ),
            "notifications.probe" => super::notifications::probe(self, p),
            "notifications.snooze" => super::notifications::snooze(self, p, payload),
            "notifications.status" => {
                let health = self.state("notification:health")?;
                let db = lock(&self.ops)?;
                let mut statement=db.prepare("SELECT key,value FROM investigator_service_state WHERE tenant=?1 AND key LIKE 'notification:%' ORDER BY key")?;
                let rows = statement.query_map([&p.tenant], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?;
                let mut states = Vec::new();
                for row in rows {
                    let (key, value) = row?;
                    let value: Value = serde_json::from_str(&value)?;
                    states.push(json!({"key":key,"status":value["status"],"level":value["level"],"checked_at":value["checked_at"],"delivered_at":value["delivered_at"],"retry_at":value["retry_at"]}));
                }
                Ok(
                    json!({"health":{"status":health["status"],"checked_at":health["checked_at"]},"deliveries":states}),
                )
            }
            "notifications.list" if payload.get("case_id").is_none() => {
                let cases = self.exec(p, "cases.list", json!({}))?;
                let mut notifications = Vec::new();
                for case in cases.as_array().context("Invalid cases")? {
                    for n in case["notifications"]
                        .as_array()
                        .context("Invalid notification list")?
                    {
                        let mut item = n.clone();
                        item["case_id"] = case["id"].clone();
                        item["delivery"] =
                            self.state(&format!("notification:{}:{}", case["id"], n["id"]))?;
                        notifications.push(item);
                    }
                }
                Ok(json!(notifications))
            }
            "cases.export" if payload["format"] == "markdown" => {
                let case = self.exec(p, "cases.export", payload)?;
                Ok(
                    json!({"markdown":super::replay::markdown(&case),"case_id":case["id"],"version":case["version"]}),
                )
            }
            "service.status" => self.status(),
            "service.recovery_ack" => {
                if !["admin", "incident_lead"].contains(&p.role.as_str()) {
                    bail!("Recovery acknowledgment requires an authorized operator");
                }
                let mut recovery = self.state("recovery:last")?;
                if recovery["reconciliation_required"] != true {
                    bail!("No pending restore reconciliation");
                }
                let reason = payload["reason"]
                    .as_str()
                    .filter(|v| !v.trim().is_empty())
                    .context("Reconciliation record required")?;
                if payload["external_effects_reconciled"] != true
                    || payload["data_loss_reviewed"] != true
                {
                    bail!(
                        "Review snapshot data loss and reconcile external effects before acknowledgment"
                    );
                }
                self.audit("recovery.acknowledged", json!({"actor":p.actor,"reason":reason,"snapshot_hash":recovery["snapshot_hash"]}))?;
                recovery["reconciliation_required"] = json!(false);
                recovery["acknowledged_by"] = json!(p.actor);
                recovery["acknowledged_at"] = json!(Utc::now());
                recovery["reason"] = json!(reason);
                self.set_state("recovery:last", recovery.clone())?;
                Ok(recovery)
            }
            "service.stop" | "service.resume" => {
                if !["admin", "analyst", "incident_lead"].contains(&p.role.as_str()) {
                    bail!("Forbidden service control")
                };
                if action == "service.resume"
                    && self.state("recovery:last")?["reconciliation_required"] == true
                {
                    bail!("Restore reconciliation must be acknowledged before resuming");
                }
                if action == "service.resume" && self.config.sources.enabled {
                    self.config.live_gate()?;
                }
                self.set_state("stopped", json!(action == "service.stop"))?;
                self.audit(action, json!({"actor":p.actor}))?;
                self.status()
            }
            "connectors.status" => Ok(
                json!({"contract":connectors::contract(),"health":self.status()?["connector_health"],"enabled":self.config.sources.enabled}),
            ),
            "investigation.start" | "connectors.probe" => {
                if !["admin", "analyst", "incident_lead"].contains(&p.role.as_str()) {
                    bail!("Forbidden investigation start")
                };
                let case = self.exec(p, "cases.get", payload.clone())?;
                if !self.config.sources.enabled {
                    if action == "connectors.probe" {
                        bail!("Live connector disabled")
                    }
                    return self.exec(p, "cases.analyze", payload);
                }
                self.config.live_gate()?;
                if self.stopped() {
                    bail!("Service stopped")
                };
                super::worker::enqueue(self, p, &case, action == "connectors.probe")
            }
            _ if action.starts_with("releases.") => {
                super::releases::command(self, p, action, payload)
            }
            _ if PUBLIC.contains(&action) => self.exec(p, action, payload),
            _ => {
                self.audit("action_denied", json!({"actor":p.actor,"action":action}))?;
                bail!("Unknown or internal action denied")
            }
        }
    }
    fn rpc(&self, p: &Principal, body: Value) -> Value {
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        let result: Result<Value> = (|| {
            if body["jsonrpc"] != "2.0" {
                bail!("JSON-RPC 2.0 required")
            }
            match body["method"].as_str() {
                Some("initialize") => Ok(
                    json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"relayne-investigator","version":"0.1.0"}}),
                ),
                Some("tools/list") => {
                    let actions = if self.is_executor() {
                        EXECUTOR_ACTIONS.to_vec()
                    } else {
                        PUBLIC
                            .iter()
                            .chain(WRAPPERS.iter())
                            .copied()
                            .filter(|action| *action != "response.execute")
                            .collect::<Vec<_>>()
                    };
                    let description = if self.is_executor() {
                        "Authenticated signed A2 response executor"
                    } else {
                        "Authenticated investigation and human governance"
                    };
                    Ok(
                        json!({"tools":[{"name":"investigator_command","description":description,"inputSchema":{"type":"object","required":["action","payload"],"properties":{"action":{"type":"string","enum":actions},"payload":{"type":"object"}},"additionalProperties":false}}]}),
                    )
                }
                Some("tools/call") => {
                    if body["params"]["name"] != "investigator_command" {
                        bail!("Unknown MCP tool")
                    }
                    let args = &body["params"]["arguments"];
                    let result = self.command(
                        p,
                        args["action"].as_str().context("Action required")?,
                        args.get("payload").cloned().unwrap_or(json!({})),
                    )?;
                    Ok(
                        json!({"content":[{"type":"text","text":result.to_string()}],"isError":false}),
                    )
                }
                _ => bail!("Unknown MCP method"),
            }
        })();
        match result {
            Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
            Err(error) => {
                let _ = self.audit(
                    "mcp.request_denied",
                    json!({"actor":p.actor,"method":body.get("method")}),
                );
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":error.to_string()}})
            }
        }
    }
    fn request(&self, mut request: Request) -> Result<()> {
        let headers = |name: &str| {
            request
                .headers()
                .iter()
                .filter(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        let hosts = headers("host");
        let origins = headers("origin");
        if hosts.len() != 1
            || hosts[0] != self.bind
            || origins.len() > 1
            || origins
                .first()
                .is_some_and(|o| o != &format!("http://{}", self.bind))
        {
            return reply(
                request,
                403,
                "application/json",
                json!({"error":"Host or origin denied"}).to_string(),
            );
        }
        if request.method() == &Method::Get && request.url() == "/" {
            return reply(
                request,
                200,
                "text/html; charset=utf-8",
                if self.is_executor() {
                    include_str!("executor.html").into()
                } else {
                    include_str!("web.html").into()
                },
            );
        }
        if request.method() == &Method::Get && request.url() == "/api/health" {
            return reply(
                request,
                200,
                "application/json",
                json!({"service":"relayne-investigator","status":"running"}).to_string(),
            );
        }
        let auth = headers("authorization");
        let principal = if auth.len() == 1 {
            auth[0]
                .strip_prefix("Bearer ")
                .and_then(|t| self.authenticate(t).ok())
        } else {
            None
        };
        let Some(principal) = principal else {
            self.audit("http.authentication_denied", json!({"transport":"http"}))?;
            return reply(
                request,
                401,
                "application/json",
                json!({"error":"Authentication required"}).to_string(),
            );
        };
        if request.method() != &Method::Post || !["/api/command", "/mcp"].contains(&request.url()) {
            return reply(
                request,
                404,
                "application/json",
                json!({"error":"Unknown route"}).to_string(),
            );
        }
        if request.body_length().is_some_and(|n| n > 262144) {
            return reply(
                request,
                413,
                "application/json",
                json!({"error":"Body exceeds 256 KiB"}).to_string(),
            );
        }
        let is_mcp = request.url() == "/mcp";
        let mut bytes = Vec::new();
        request.as_reader().take(262145).read_to_end(&mut bytes)?;
        if bytes.len() > 262144 {
            return reply(
                request,
                413,
                "application/json",
                json!({"error":"Body exceeds 256 KiB"}).to_string(),
            );
        }
        let body: Value = match serde_json::from_slice(&bytes) {
            Ok(body) => body,
            Err(_) => {
                return reply(
                    request,
                    400,
                    "application/json",
                    json!({"error":"Invalid JSON"}).to_string(),
                );
            }
        };
        if is_mcp {
            if body.get("id").is_none()
                && body["jsonrpc"] == "2.0"
                && body["method"] == "notifications/initialized"
            {
                return reply(request, 202, "application/json", String::new());
            }
            return reply(
                request,
                200,
                "application/json",
                self.rpc(&principal, body).to_string(),
            );
        }
        let outcome = body["action"]
            .as_str()
            .context("Action required")
            .and_then(|action| {
                self.command(
                    &principal,
                    action,
                    body.get("payload").cloned().unwrap_or(json!({})),
                )
            });
        match outcome {
            Ok(result) => reply(
                request,
                200,
                "application/json",
                json!({"result":result}).to_string(),
            ),
            Err(error) => {
                self.audit(
                    "http.command_denied",
                    json!({"actor":principal.actor,"action":body.get("action")}),
                )?;
                reply(
                    request,
                    400,
                    "application/json",
                    json!({"error":error.to_string()}).to_string(),
                )
            }
        }
    }
    pub fn serve(self) -> Result<()> {
        if self.credentials.len() != self.config.users.len() {
            bail!("All configured token environment variables must be set before serving")
        };
        if !self.is_executor() && self.state("stopped")?.is_null() {
            self.set_state("stopped", json!(false))?;
        }
        let server = Server::http(&self.bind)
            .map_err(|_| anyhow::anyhow!("Cannot bind configured loopback service"))?;
        let shared = Arc::new(self);
        if shared.starts_investigation_worker() {
            let worker = Arc::clone(&shared);
            std::thread::spawn(move || {
                loop {
                    if let Err(error) = super::worker::tick(&worker) {
                        let _ = worker.audit("worker.failure", json!({"reason":error.to_string()}));
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
            });
        }
        eprintln!(
            "Relayne {}: http://{}",
            if shared.is_executor() {
                "response executor"
            } else {
                "investigator"
            },
            shared.bind
        );
        for request in server.incoming_requests() {
            if shared.request(request).is_err() {
                eprintln!("Investigator request failed")
            }
        }
        Ok(())
    }
}
fn reply(request: Request, status: u16, mime: &str, body: String) -> Result<()> {
    let mut response = Response::from_string(body).with_status_code(StatusCode(status));
    for (name, value) in [
        ("Content-Type", mime),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        (
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        response = response.with_header(
            Header::from_bytes(name, value)
                .map_err(|_| anyhow::anyhow!("Invalid response header"))?,
        )
    }
    request.respond(response)?;
    Ok(())
}
pub fn cli() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 2 => {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&args[1])?;
            file.write_all(serde_json::to_string_pretty(&Config::default())?.as_bytes())?;
            println!("Created configuration; set token environment references before serving.");
            Ok(())
        }
        Some("contract") => {
            println!("{}", serde_json::to_string_pretty(&connectors::contract())?);
            Ok(())
        }
        Some("serve") if args.len() == 3 => {
            Service::open(Path::new(&args[2]), Config::load(Path::new(&args[1]))?)?.serve()
        }
        Some("executor-serve") if args.len() == 4 => Service::open_executor(
            Path::new(&args[2]),
            Config::load(Path::new(&args[1]))?,
            &args[3],
        )?
        .serve(),
        Some("worker-once") if args.len() == 3 => {
            let service = Service::open(Path::new(&args[2]), Config::load(Path::new(&args[1]))?)?;
            super::worker::tick(&service)
        }
        Some("replay") if args.len() == 2 => super::replay::run(Path::new(&args[1])).map(|_| ()),
        Some("backup") if args.len() == 3 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&super::backup::create(
                    Path::new(&args[1]),
                    Path::new(&args[2])
                )?)?
            );
            Ok(())
        }
        Some("verify-backup") if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&super::backup::verify(Path::new(&args[1]))?)?
            );
            Ok(())
        }
        Some("restore") if args.len() == 3 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&super::backup::restore(
                    Path::new(&args[1]),
                    Path::new(&args[2])
                )?)?
            );
            Ok(())
        }
        _ => bail!(
            "Usage: relayne_investigator init <config.json> | serve <config.json> <database> | executor-serve <config.json> <database> <loopback-bind> | worker-once <config.json> <database> | replay <new-directory> | contract | backup <database> <new-directory> | verify-backup <directory> | restore <directory> <new-database>"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service() -> Service {
        Service::open(Path::new(":memory:"), Config::default()).unwrap()
    }
    fn admin() -> Principal {
        Principal {
            tenant: "DEMO".into(),
            actor: "local-admin".into(),
            role: "admin".into(),
        }
    }
    #[test]
    fn restored_service_requires_explicit_reconciliation_before_resume() {
        let path =
            std::env::temp_dir().join(format!("relayne-recovery-{}.sqlite", uuid::Uuid::new_v4()));
        let s = Service::open(&path, Config::default()).unwrap();
        s.set_state("stopped", json!(true)).unwrap();
        s.set_state(
            "recovery:last",
            json!({"reconciliation_required":true,"snapshot_hash":"synthetic"}),
        )
        .unwrap();
        assert!(s.command(&admin(), "service.resume", json!({})).is_err());
        assert!(
            s.command(
                &admin(),
                "service.recovery_ack",
                json!({"reason":"checked"})
            )
            .is_err()
        );
        s.command(&admin(), "service.recovery_ack", json!({"reason":"Reconciled destination receipts and snapshot interval","external_effects_reconciled":true,"data_loss_reviewed":true})).unwrap();
        assert!(s.stopped());
        s.command(&admin(), "service.resume", json!({})).unwrap();
        assert!(!s.stopped());
    }
    #[test]
    fn p1_commands_share_mcp_dispatch_and_live_adapters_remain_disabled() {
        let s = service();
        let catalog = s.command(&admin(), "playbooks.catalog", json!({})).unwrap();
        assert_eq!(catalog["playbooks"].as_array().unwrap().len(), 5);
        let rpc = s.rpc(&admin(), json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigator_command","arguments":{"action":"playbooks.catalog","payload":{}}}}));
        let via_mcp: Value =
            serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(catalog, via_mcp);
        assert_eq!(
            s.command(&admin(), "integrations.status", json!({}))
                .unwrap()["enabled"],
            false
        );
        let c = s.command(&admin(), "cases.create", json!({"title":"Synthetic P1 boundary","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"})).unwrap();
        for action in [
            "cmdb.sync",
            "tickets.sync",
            "sources.import",
            "response.execute",
        ] {
            assert!(s.command(&admin(), action, json!({"case_id":c["id"],"asset_id":"asset","provider":"unconfigured","records":[]})).is_err(), "{action}");
        }
    }

    #[test]
    fn continuation_commands_share_authenticated_boundary() {
        let s = service();
        for action in [
            "collectors.status",
            "response.status",
            "pilot.status",
            "pilot.report",
        ] {
            let direct = s.command(&admin(), action, json!({})).unwrap();
            let rpc = s.rpc(&admin(), json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigator_command","arguments":{"action":action,"payload":{}}}}));
            assert!(rpc.get("result").is_some(), "{action}: {rpc}");
            assert!(direct.is_object());
            assert!(
                s.command(&admin(), action, json!({"actor":"forged"}))
                    .is_err()
            );
        }
        for action in ["collectors.run", "response.propose", "response.execute"] {
            assert!(s.command(&admin(), action, json!({})).is_err());
        }
    }
    #[test]
    fn internal_and_spoofed_commands_denied() {
        let s = service();
        for action in [
            "jobs.claim",
            "budgets.reserve",
            "budgets.settle",
            "audit.record",
            "unknown",
        ] {
            assert!(s.command(&admin(), action, json!({})).is_err())
        }
        assert!(
            s.command(&admin(), "cases.list", json!({"role":"system"}))
                .is_err()
        );
        assert!(
            s.command(&admin(), "cases.list", json!({"tenant":"OTHER"}))
                .is_err()
        );
        let mut p = admin();
        p.role = "system".into();
        assert!(s.command(&p, "cases.list", json!({})).is_err());
    }
    #[test]
    fn mcp_delegates_identical_policy() {
        let s = service();
        let result=s.rpc(&admin(),json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigator_command","arguments":{"action":"jobs.claim","payload":{}}}}));
        assert!(result.get("error").is_some());
        let allowed=s.rpc(&admin(),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"investigator_command","arguments":{"action":"auth.me","payload":{}}}}));
        assert!(allowed.get("result").is_some());
    }

    #[test]
    fn executor_mcp_exposes_only_response_controls_and_starts_no_worker() {
        let mut s = service();
        s.role = ProcessRole::Executor;
        assert!(!s.starts_investigation_worker());
        let listed = s.rpc(
            &admin(),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        );
        let actions = listed["result"]["tools"][0]["inputSchema"]["properties"]["action"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(
            actions,
            &EXECUTOR_ACTIONS
                .iter()
                .map(|action| json!(action))
                .collect::<Vec<_>>()
        );
        let denied = s.rpc(&admin(), json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"investigator_command","arguments":{"action":"cases.list","payload":{}}}}));
        assert!(denied.get("error").is_some());
        let allowed = s.rpc(&admin(), json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"investigator_command","arguments":{"action":"auth.me","payload":{}}}}));
        assert!(allowed.get("result").is_some());
    }
    #[test]
    fn unknown_token_denied() {
        let s = service();
        assert!(s.authenticate("not-configured").is_err());
        assert!(equal(&digest("a"), &digest("a")));
        assert!(!equal(&digest("a"), &digest("b")));
    }
    #[test]
    fn http_and_mcp_share_authentication_and_rebinding_guards() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap().to_string();
        let mut s = service();
        s.config.bind = address.clone();
        s.bind = address.clone();
        let token = "unit-test-secret-with-at-least-32-characters";
        s.credentials = vec![(digest(token), admin())];
        let worker = std::thread::spawn(move || {
            for _ in 0..6 {
                let request = server
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap()
                    .expect("expected request");
                s.request(request).unwrap();
            }
        });
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("http://{address}");
        assert_eq!(
            client
                .post(format!("{url}/mcp"))
                .json(&json!({}))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            401
        );
        assert_eq!(
            client
                .post(format!("{url}/api/command"))
                .header("Host", "attacker.invalid")
                .bearer_auth(token)
                .json(&json!({}))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            403
        );
        assert_eq!(
            client
                .post(format!("{url}/api/command"))
                .header("Origin", "https://attacker.invalid")
                .bearer_auth(token)
                .json(&json!({}))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            403
        );
        let http: Value = client
            .post(format!("{url}/api/command"))
            .bearer_auth(token)
            .json(&json!({"action":"auth.me","payload":{}}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(http["result"]["actor"], "local-admin");
        let rpc:Value=client.post(format!("{url}/mcp")).bearer_auth(token).json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigator_command","arguments":{"action":"auth.me","payload":{}}}})).send().unwrap().json().unwrap();
        let identity: Value =
            serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(identity, http["result"]);
        let initialized = client
            .post(format!("{url}/mcp"))
            .bearer_auth(token)
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .unwrap();
        assert_eq!(initialized.status().as_u16(), 202);
        assert!(initialized.text().unwrap().is_empty());
        worker.join().unwrap();
    }
}
