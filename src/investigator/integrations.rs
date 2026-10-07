//! Bounded P1 adapter contracts for CMDB, tickets, and storage/network evidence.
//!
//! Adapter destinations are configured by an operator.  Commands never accept a
//! URL, credential, tenant, or role from a caller.

use super::{config::valid_env, core::Principal, service::Service, worker};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use reqwest::{Url, blocking::Client};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Read, net::IpAddr, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROWS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Adapter {
    pub enabled: bool,
    pub endpoint: String,
    pub secret_env: String,
    pub allowed_hosts: Vec<String>,
    pub approved_by: String,
    pub approved_at: String,
    pub idempotency_confirmed: bool,
    pub timeout_seconds: u64,
    pub max_response_bytes: u64,
}

impl Default for Adapter {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            secret_env: String::new(),
            allowed_hosts: Vec::new(),
            approved_by: String::new(),
            approved_at: String::new(),
            idempotency_confirmed: false,
            timeout_seconds: 15,
            max_response_bytes: 65_536,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TicketAdapter {
    #[serde(flatten)]
    pub adapter: Adapter,
    /// A separate outbound-write consent: configuring a receiver is insufficient.
    pub write_enabled: bool,
    pub write_approved_by: String,
    pub write_approved_at: String,
    pub write_idempotency_confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SourceAdapter {
    pub name: String,
    /// `storage` and `network` have different normalized schemas below.
    pub kind: String,
    pub enabled: bool,
    pub approved_by: String,
    pub approved_at: String,
    pub max_rows: u64,
    pub max_bytes: u64,
}

impl Default for SourceAdapter {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: String::new(),
            enabled: false,
            approved_by: String::new(),
            approved_at: String::new(),
            max_rows: 1_000,
            max_bytes: 1_048_576,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Integrations {
    pub enabled: bool,
    pub cmdb: Adapter,
    pub tickets: TicketAdapter,
    pub sources: Vec<SourceAdapter>,
}

impl Integrations {
    pub fn validate(&self) -> Result<()> {
        self.cmdb.validate("CMDB")?;
        self.tickets.adapter.validate("ticket")?;
        if self.tickets.write_enabled {
            if !self.enabled
                || !self.tickets.adapter.enabled
                || self.tickets.write_approved_by.trim().is_empty()
                || !self.tickets.write_idempotency_confirmed
            {
                bail!(
                    "Ticket writes require enabled adapter, explicit approval, and idempotency confirmation"
                );
            }
            approval_time(&self.tickets.write_approved_at, "ticket write")?;
        }
        let mut names = HashSet::new();
        for source in &self.sources {
            if source.name.trim().is_empty()
                || source.name.len() > 128
                || !names.insert(source.name.to_ascii_lowercase())
            {
                bail!("Source integration names must be unique and nonempty");
            }
            if !["storage", "network"].contains(&source.kind.as_str()) {
                bail!("Source integration kind must be storage or network");
            }
            if !(1..=MAX_ROWS).contains(&source.max_rows)
                || !(1024..=MAX_RESPONSE_BYTES).contains(&source.max_bytes)
            {
                bail!("Source integration rows and bytes must be bounded");
            }
            if source.enabled {
                if source.approved_by.trim().is_empty() {
                    bail!("Enabled source import requires explicit approval");
                }
                approval_time(&source.approved_at, &format!("source {}", source.name))?;
            }
        }
        Ok(())
    }

    fn source(&self, name: &str) -> Result<&SourceAdapter> {
        self.sources
            .iter()
            .find(|s| s.name == name && s.enabled)
            .context("Configured evidence source unavailable")
    }
}

impl Adapter {
    fn validate(&self, label: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.endpoint.is_empty()
            || !valid_env(&self.secret_env)
            || self.allowed_hosts.is_empty()
            || self.approved_by.trim().is_empty()
            || !self.idempotency_confirmed
        {
            bail!(
                "Enabled {label} adapter requires endpoint, secret reference, allowlist, approval, and idempotency confirmation"
            );
        }
        approval_time(&self.approved_at, label)?;
        if !(1..=15).contains(&self.timeout_seconds)
            || !(1024..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            bail!("{label} timeout or response byte limit is outside permitted bounds");
        }
        let _ = destination(self)?;
        Ok(())
    }
}

fn approval_time(value: &str, label: &str) -> Result<()> {
    let at = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{label} approval timestamp required"))?
        .with_timezone(&Utc);
    if at > Utc::now() + chrono::Duration::minutes(5) {
        bail!("{label} approval timestamp is in the future");
    }
    Ok(())
}

fn destination(adapter: &Adapter) -> Result<Url> {
    let url = Url::parse(&adapter.endpoint).context("Configured adapter endpoint is not a URL")?;
    let host = url
        .host_str()
        .context("Configured adapter endpoint needs a host")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || !adapter
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        bail!("Configured adapter endpoint is outside approved HTTPS host scope");
    }
    Ok(url)
}

fn sha(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}

fn case_id(payload: &Value) -> Result<&str> {
    payload
        .get("case_id")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty() && v.len() <= 128)
        .context("case_id required")
}
fn require_role(p: &Principal, roles: &[&str]) -> Result<()> {
    if roles.contains(&p.role.as_str()) {
        Ok(())
    } else {
        bail!("Forbidden integration action")
    }
}

fn integration_gate(s: &Service) -> Result<()> {
    if !s.config.integrations.enabled {
        bail!("Integrations disabled");
    }
    if !s.config.operations.encrypted_volume_confirmed || !s.config.operations.retention_approved {
        bail!("Integration evidence requires encrypted-volume and retention approval");
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct OutboundRequest {
    method: &'static str,
    url: Url,
    secret: String,
    key: String,
    body: Value,
    max_bytes: u64,
    timeout_seconds: u64,
}

trait Transport {
    fn send(&self, request: &OutboundRequest) -> Result<Value>;
}
struct HttpTransport;
impl Transport for HttpTransport {
    fn send(&self, request: &OutboundRequest) -> Result<Value> {
        let response = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(request.timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .request(
                request.method.parse::<reqwest::Method>()?,
                request.url.clone(),
            )
            .bearer_auth(&request.secret)
            .header("Idempotency-Key", &request.key)
            .json(&request.body)
            .send()
            .map_err(|_| anyhow::anyhow!("Internal adapter transport failed"))?;
        if !response.status().is_success() {
            bail!(
                "Internal adapter rejected request (HTTP {})",
                response.status().as_u16()
            );
        }
        if request.method == "HEAD" {
            return Ok(json!({}));
        }
        let mut bytes = Vec::new();
        response
            .take(request.max_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > request.max_bytes {
            bail!("Adapter response exceeded configured byte limit");
        }
        serde_json::from_slice(&bytes).context("Adapter response must be JSON")
    }
}

#[derive(Debug)]
struct ActiveReceipt {
    generation: i64,
    lease: String,
}
#[derive(Debug)]
enum Receipt {
    Active(ActiveReceipt),
    Delivered(Value),
    Completed(Value),
}
type PriorReceipt = (String, String, Option<String>, i64, Option<String>);

fn setup(s: &Service) -> Result<()> {
    s.ops.lock().map_err(|_| anyhow::anyhow!("Integration state lock poisoned"))?.execute_batch(
        "CREATE TABLE IF NOT EXISTS investigator_integration_receipts_v2(tenant TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,case_id TEXT NOT NULL,payload_hash TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL,generation INTEGER NOT NULL,lease TEXT,lease_expires_at TEXT,response TEXT,error TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant,operation,idempotency_key));"
    )?;
    Ok(())
}

fn begin(s: &Service, operation: &str, cid: &str, key: &str, body: &Value) -> Result<Receipt> {
    let mut db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Integration state lock poisoned"))?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let digest = sha(body);
    let prior: Option<PriorReceipt> = tx.query_row("SELECT state,payload_hash,response,generation,lease_expires_at FROM investigator_integration_receipts_v2 WHERE tenant=?1 AND operation=?2 AND idempotency_key=?3", params![s.config.tenant, operation, key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).optional()?;
    let now = Utc::now().to_rfc3339();
    let lease = uuid::Uuid::new_v4().to_string();
    let expires = (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let outcome = match prior {
        Some((state, old, response, generation, expiry)) => {
            if old != digest {
                bail!("Idempotency key conflicts with a different integration request");
            }
            match state.as_str() {
                "completed" => Receipt::Completed(serde_json::from_str(
                    &response.context("Completed receipt missing response")?,
                )?),
                "delivered" => Receipt::Delivered(serde_json::from_str(
                    &response.context("Delivered receipt missing response")?,
                )?),
                "pending"
                    if expiry
                        .as_deref()
                        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                        .is_some_and(|v| v.with_timezone(&Utc) > Utc::now()) =>
                {
                    bail!("Equivalent integration request is already in progress")
                }
                "pending" | "failed" => {
                    let next = generation + 1;
                    tx.execute("UPDATE investigator_integration_receipts_v2 SET state='pending',attempts=attempts+1,generation=?4,lease=?5,lease_expires_at=?6,error=NULL,updated_at=?7 WHERE tenant=?1 AND operation=?2 AND idempotency_key=?3", params![s.config.tenant, operation, key, next, lease, expires, now])?;
                    Receipt::Active(ActiveReceipt {
                        generation: next,
                        lease,
                    })
                }
                _ => bail!("Invalid integration receipt state"),
            }
        }
        None => {
            tx.execute("INSERT INTO investigator_integration_receipts_v2(tenant,operation,idempotency_key,case_id,payload_hash,state,attempts,generation,lease,lease_expires_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,'pending',1,1,?6,?7,?8,?8)", params![s.config.tenant, operation, key, cid, digest, lease, expires, now])?;
            Receipt::Active(ActiveReceipt {
                generation: 1,
                lease,
            })
        }
    };
    tx.commit()?;
    Ok(outcome)
}

fn delivered(
    s: &Service,
    operation: &str,
    key: &str,
    active: &ActiveReceipt,
    response: &Value,
) -> Result<()> {
    let count = s.ops.lock().map_err(|_| anyhow::anyhow!("Integration state lock poisoned"))?.execute("UPDATE investigator_integration_receipts_v2 SET state='delivered',response=?4,lease=NULL,lease_expires_at=NULL,updated_at=?5 WHERE tenant=?1 AND operation=?2 AND idempotency_key=?3 AND state='pending' AND generation=?6 AND lease=?7", params![s.config.tenant, operation, key, response.to_string(), Utc::now().to_rfc3339(), active.generation, active.lease])?;
    if count != 1 {
        bail!("Integration receipt lease lost");
    }
    Ok(())
}
fn complete(s: &Service, operation: &str, key: &str, response: &Value) -> Result<()> {
    let count = s.ops.lock().map_err(|_| anyhow::anyhow!("Integration state lock poisoned"))?.execute("UPDATE investigator_integration_receipts_v2 SET state='completed',response=?4,updated_at=?5 WHERE tenant=?1 AND operation=?2 AND idempotency_key=?3 AND state='delivered'", params![s.config.tenant, operation, key, response.to_string(), Utc::now().to_rfc3339()])?;
    if count != 1 {
        bail!("Integration receipt completion conflict");
    }
    Ok(())
}
fn failed(s: &Service, operation: &str, key: &str, active: &ActiveReceipt, error: &anyhow::Error) {
    if let Ok(db) = s.ops.lock() {
        let _ = db.execute("UPDATE investigator_integration_receipts_v2 SET state='failed',error=?4,lease=NULL,lease_expires_at=NULL,updated_at=?5 WHERE tenant=?1 AND operation=?2 AND idempotency_key=?3 AND state='pending' AND generation=?6 AND lease=?7", params![s.config.tenant, operation, key, error.to_string(), Utc::now().to_rfc3339(), active.generation, active.lease]);
    }
}

/// Conservatively reserve a whole bounded response before connecting, in the
/// same durable usage record used by the investigation worker.
fn reserve_response(s: &Service, cid: &str, bytes: u64) -> Result<()> {
    let key = format!("worker:usage:{cid}");
    let mut db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Integration state lock poisoned"))?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key=?2",
            params![s.config.tenant, key],
            |r| r.get(0),
        )
        .optional()?;
    let mut usage: Value = raw
        .map(|v| serde_json::from_str(&v))
        .transpose()?
        .unwrap_or_else(|| json!({}));
    let used = usage["bytes"].as_u64().unwrap_or(0);
    if bytes > s.config.budgets.case_result_bytes.saturating_sub(used) {
        bail!("Cumulative case result budget exhausted");
    }
    usage["bytes"] = json!(used + bytes);
    usage["integration_reserved_bytes"] = json!(
        usage["integration_reserved_bytes"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(bytes)
    );
    tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,?2,?3) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value", params![s.config.tenant, key, usage.to_string()])?;
    tx.commit()?;
    Ok(())
}

fn request<T: Transport>(
    s: &Service,
    cid: &str,
    operation: &str,
    key: &str,
    adapter: &Adapter,
    body: Value,
    transport: &T,
) -> Result<Value> {
    // `charge` is persisted before any network operation and checks the stop switch.
    worker::charge(s, cid, operation)?;
    reserve_response(s, cid, adapter.max_response_bytes)?;
    if s.stopped() {
        bail!("Service stopped before integration transport");
    }
    let secret =
        std::env::var(&adapter.secret_env).context("Adapter secret reference unavailable")?;
    if secret.is_empty() {
        bail!("Adapter secret is empty");
    }
    transport.send(&OutboundRequest {
        method: "POST",
        url: destination(adapter)?,
        secret,
        key: key.into(),
        body,
        max_bytes: adapter.max_response_bytes,
        timeout_seconds: adapter.timeout_seconds,
    })
}

fn case(s: &Service, p: &Principal, payload: &Value) -> Result<Value> {
    s.exec(p, "cases.get", json!({"case_id":case_id(payload)?}))
}
fn stable_case_id(p: &Principal, c: &Value) -> Result<String> {
    Ok(format!(
        "relayne:{}:{}",
        p.tenant,
        c["id"].as_str().context("Case ID invalid")?
    ))
}

fn cmdb_response(c: &Value, asset_id: &str, response: &Value) -> Result<Value> {
    let site = c["site"].as_str().context("Case site invalid")?;
    let record = response.get("record").unwrap_or(response);
    if record["tenant"] != c["tenant"] || record["site"].as_str() != Some(site) {
        bail!("CMDB record tenant or site outside case scope");
    }
    let updated = DateTime::parse_from_rfc3339(
        record["updated_at"]
            .as_str()
            .context("CMDB freshness timestamp required")?,
    )?
    .with_timezone(&Utc);
    if updated < Utc::now() - chrono::Duration::hours(24)
        || updated > Utc::now() + chrono::Duration::minutes(5)
    {
        bail!("CMDB record is stale or future-dated");
    }
    let external_id = record["external_id"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .context("CMDB external ID required")?;
    if external_id != asset_id {
        bail!("CMDB record external ID does not match requested asset");
    }
    let attributes = record
        .get("attributes")
        .and_then(Value::as_object)
        .context("CMDB attributes object required")?;
    if attributes.len() > 32
        || attributes.values().any(|v| {
            !(v.is_null()
                || v.is_boolean()
                || v.is_number()
                || v.as_str().is_some_and(|s| s.len() <= 1024))
        })
    {
        bail!("CMDB attributes are not a bounded normalized object");
    }
    let criticality = attributes
        .get("criticality")
        .and_then(Value::as_str)
        .filter(|v| ["unknown", "low", "medium", "high", "critical"].contains(v))
        .unwrap_or("unknown");
    let owner = attributes
        .get("owner")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 256);
    let tier0 = attributes
        .get("tier0")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let privileged = attributes
        .get("privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_critical = attributes
        .get("service_critical")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(
        json!({"external_id":external_id,"site":site,"updated_at":updated,"owner":owner,"criticality":criticality,"tier0":tier0,"privileged":privileged,"service_critical":service_critical,"cmdb_attributes":attributes}),
    )
}

fn bounded_title(case: &Value) -> Result<String> {
    let title = case["title"]
        .as_str()
        .filter(|v| !v.trim().is_empty())
        .context("Case title invalid")?;
    Ok(title.chars().take(256).collect())
}

fn validate_record(source: &SourceAdapter, case: &Value, record: &Value) -> Result<Value> {
    let event_id = record["event_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .context("Provider event_id required")?;
    let native_id = record["native_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .context("Provider native_id required")?;
    if record["tenant"] != case["tenant"] || record["site"] != case["site"] {
        bail!("Evidence record outside case tenant or site scope");
    }
    let event_time = DateTime::parse_from_rfc3339(
        record["event_time"]
            .as_str()
            .context("Evidence event_time required")?,
    )?
    .with_timezone(&Utc);
    let start =
        DateTime::parse_from_rfc3339(case["start"].as_str().context("Case start invalid")?)?
            .with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339(case["end"].as_str().context("Case end invalid")?)?
        .with_timezone(&Utc);
    if event_time < start || event_time > end || event_time > Utc::now() {
        bail!("Evidence record outside case interval");
    }
    let fields = match source.kind.as_str() {
        "storage" => {
            let object = record["object_id"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .context("Storage object_id required")?;
            let principal = record["principal"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .context("Storage principal required")?;
            let operation = record["operation"]
                .as_str()
                .filter(|v| ["read", "download"].contains(v))
                .context("Invalid storage operation")?;
            let outcome = record["outcome"]
                .as_str()
                .filter(|v| ["success", "blocked", "denied", "failure"].contains(v))
                .context("Storage outcome required")?;
            let object_count = record["object_count"]
                .as_u64()
                .filter(|n| (*n > 0 || outcome != "success") && *n <= source.max_rows)
                .context("Storage object_count invalid")?;
            let destination = record["destination"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 512)
                .context("Storage destination required")?;
            let native_action = record["native_action"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .context("Storage native_action required")?;
            json!({"kind":"object_access","native_id":native_id,"object_id":object,"principal":principal,"operation":operation,"object_count":object_count,"destination":destination,"outcome":outcome,"native_action":native_action})
        }
        "network" => {
            let source_ip: IpAddr = record["source_ip"]
                .as_str()
                .context("Network source_ip required")?
                .parse()
                .context("Invalid network source_ip")?;
            let destination_ip: IpAddr = record["destination_ip"]
                .as_str()
                .context("Network destination_ip required")?
                .parse()
                .context("Invalid network destination_ip")?;
            let principal = record["principal"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .context("Network principal required")?;
            let destination = record["destination"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 512)
                .context("Network destination required")?;
            let direction = record["direction"]
                .as_str()
                .filter(|v| *v == "outbound")
                .context("Network direction must be outbound")?;
            let outcome = record["outcome"]
                .as_str()
                .filter(|v| ["success", "blocked", "denied", "failure"].contains(v))
                .context("Network outcome required")?;
            let bytes_out = record["bytes_out"]
                .as_u64()
                .filter(|v| (*v > 0 || outcome != "success") && *v <= source.max_bytes)
                .context("Invalid network bytes_out")?;
            let native_action = record["native_action"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .context("Network native_action required")?;
            json!({"kind":"network_flow","native_id":native_id,"source_ip":source_ip.to_string(),"destination_ip":destination_ip.to_string(),"principal":principal,"destination":destination,"direction":direction,"bytes_out":bytes_out,"outcome":outcome,"native_action":native_action})
        }
        _ => bail!("Unsupported source kind"),
    };
    Ok(
        json!({"source":format!("integration:{}",source.name),"source_id":event_id,"event_time":event_time,"query_version":"integration-normalized-2026-09-20.1","fields":fields}),
    )
}

fn import(s: &Service, p: &Principal, payload: Value) -> Result<Value> {
    require_role(p, &["admin", "analyst", "incident_lead"])?;
    integration_gate(s)?;
    let c = case(s, p, &payload)?;
    let source = s
        .config
        .integrations
        .source(payload["provider"].as_str().context("provider required")?)?;
    let records = payload["records"]
        .as_array()
        .context("records array required")?;
    let import_bytes = payload.to_string().len() as u64;
    if records.len() as u64 > source.max_rows || import_bytes > source.max_bytes {
        bail!("Evidence import exceeds configured bounds");
    }
    reserve_response(s, c["id"].as_str().unwrap_or_default(), import_bytes)?;
    let coverage = payload
        .get("coverage")
        .and_then(Value::as_object)
        .context("coverage required")?;
    let status = coverage
        .get("status")
        .and_then(Value::as_str)
        .filter(|v| {
            [
                "available",
                "partial",
                "unavailable",
                "outside_retention",
                "permission_denied",
                "schema_invalid",
            ]
            .contains(v)
        })
        .context("Invalid coverage status")?;
    let start = DateTime::parse_from_rfc3339(
        coverage
            .get("start")
            .and_then(Value::as_str)
            .context("coverage start required")?,
    )?
    .with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339(
        coverage
            .get("end")
            .and_then(Value::as_str)
            .context("coverage end required")?,
    )?
    .with_timezone(&Utc);
    if start > end
        || start
            < DateTime::parse_from_rfc3339(c["start"].as_str().unwrap_or_default())?
                .with_timezone(&Utc)
        || end
            > DateTime::parse_from_rfc3339(c["end"].as_str().unwrap_or_default())?
                .with_timezone(&Utc)
    {
        bail!("Coverage outside case scope");
    }
    if status != "available"
        && coverage
            .get("reason")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .is_none()
    {
        bail!("Non-available coverage requires a reason");
    }
    let events = records
        .iter()
        .map(|r| validate_record(source, &c, r))
        .collect::<Result<Vec<_>>>()?;
    let response = s.exec(p, "evidence.ingest", json!({"case_id":c["id"],"evidence":events,"coverage":[{"source":format!("integration:{}",source.name),"source_kind":if source.kind=="storage"{"cloud_storage"}else{"network"},"provider":source.name,"status":status,"reason":coverage.get("reason").cloned().unwrap_or(Value::Null),"start":start,"end":end,"observed_at":Utc::now(),"owner":p.actor}]}))?;
    s.audit("integrations.sources.import", json!({"case_id":c["id"],"provider":source.name,"kind":source.kind,"records":records.len(),"coverage":status}))?;
    Ok(
        json!({"case_id":c["id"],"provider":source.name,"imported":records.len(),"coverage":status,"case_version":response["version"]}),
    )
}

fn cmdb<T: Transport>(s: &Service, p: &Principal, payload: Value, transport: &T) -> Result<Value> {
    require_role(p, &["admin", "analyst", "incident_lead"])?;
    integration_gate(s)?;
    if !s.config.integrations.cmdb.enabled {
        bail!("CMDB adapter disabled");
    }
    let c = case(s, p, &payload)?;
    let asset_id = payload["asset_id"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .context("asset_id required")?;
    let refresh = match payload.get("refresh_id") {
        Some(Value::String(value)) if !value.trim().is_empty() && value.len() <= 128 => {
            value.clone()
        }
        None | Some(Value::Null) => Utc::now().format("%Y-%m-%dT%H").to_string(),
        Some(Value::String(value)) if value.is_empty() => {
            Utc::now().format("%Y-%m-%dT%H").to_string()
        }
        _ => bail!("refresh_id must be a bounded nonempty string"),
    };
    let body = json!({"operation":"cmdb_sync","external_case_id":stable_case_id(p,&c)?,"asset_id":asset_id,"site":c["site"],"refresh_id":refresh});
    let key = sha(&json!([
        "cmdb.sync",
        p.tenant,
        c["id"],
        configuration_hash(&s.config.integrations),
        body.clone()
    ]));
    let received = match begin(
        s,
        "cmdb.sync",
        c["id"].as_str().unwrap_or_default(),
        &key,
        &body,
    )? {
        Receipt::Completed(v) => return Ok(v),
        Receipt::Delivered(v) => v,
        Receipt::Active(active) => match request(
            s,
            c["id"].as_str().unwrap_or_default(),
            "cmdb.sync",
            &key,
            &s.config.integrations.cmdb,
            body,
            transport,
        ) {
            Ok(v) => {
                delivered(s, "cmdb.sync", &key, &active, &v)?;
                v
            }
            Err(e) => {
                failed(s, "cmdb.sync", &key, &active, &e);
                return Err(e);
            }
        },
    };
    let normalized = cmdb_response(&c, asset_id, &received)?;
    // This call's budget reservation advances the case version. Preserve
    // concurrent context edits, then atomically write against the latest version.
    let latest = case(s, p, &payload)?;
    if latest["context"] != c["context"] {
        bail!("CMDB context changed during retrieval; review before retrying");
    }
    let result = s.exec(p, "context.set", json!({"case_id":c["id"],"expected_version":latest["version"],"context":{"source":"approved_cmdb","updated_at":normalized["updated_at"],"site":normalized["site"],"external_id":normalized["external_id"],"owner":normalized["owner"],"criticality":normalized["criticality"],"tier0":normalized["tier0"],"privileged":normalized["privileged"],"service_critical":normalized["service_critical"],"cmdb_attributes":normalized["cmdb_attributes"]}}))?;
    let receipt = json!({"case_id":c["id"],"external_id":normalized["external_id"],"context_version":result["version"]});
    complete(s, "cmdb.sync", &key, &receipt)?;
    s.audit(
        "integrations.cmdb.sync",
        json!({"case_id":c["id"],"external_id":normalized["external_id"]}),
    )?;
    Ok(receipt)
}

fn tickets<T: Transport>(
    s: &Service,
    p: &Principal,
    payload: Value,
    transport: &T,
) -> Result<Value> {
    require_role(p, &["admin", "incident_lead"])?;
    let ticket = &s.config.integrations.tickets;
    integration_gate(s)?;
    if !ticket.adapter.enabled || !ticket.write_enabled {
        bail!("Ticket writes are disabled");
    }
    let c = case(s, p, &payload)?;
    // Deliberately minimal: no evidence fields, source records, tokens, or URLs leave the service.
    let body = json!({"operation":"ticket_sync","external_case_id":stable_case_id(p,&c)?,"site":c["site"],"title":bounded_title(&c)?,"state":c["state"],"approval":{"by":ticket.write_approved_by,"at":ticket.write_approved_at}});
    let key = sha(&json!([
        "tickets.sync",
        p.tenant,
        c["id"],
        configuration_hash(&s.config.integrations),
        body.clone()
    ]));
    let result = match begin(
        s,
        "tickets.sync",
        c["id"].as_str().unwrap_or_default(),
        &key,
        &body,
    )? {
        Receipt::Completed(v) => return Ok(v),
        Receipt::Delivered(v) => v,
        Receipt::Active(active) => match request(
            s,
            c["id"].as_str().unwrap_or_default(),
            "tickets.sync",
            &key,
            &ticket.adapter,
            body,
            transport,
        ) {
            Ok(v) => {
                delivered(s, "tickets.sync", &key, &active, &v)?;
                v
            }
            Err(e) => {
                failed(s, "tickets.sync", &key, &active, &e);
                return Err(e);
            }
        },
    };
    let provider_ticket_id = result["ticket_id"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .context("Ticket adapter response requires ticket_id")?;
    let external_case_id = stable_case_id(p, &c)?;
    if result.get("external_case_id").and_then(Value::as_str) != Some(external_case_id.as_str()) {
        bail!("Ticket adapter response does not bind the stable external case ID");
    }
    let receipt = json!({"case_id":c["id"],"external_case_id":external_case_id,"ticket_id":provider_ticket_id,"delivery":"externally_delivered","technical_verification":"pending_human_or_provider_confirmation"});
    complete(s, "tickets.sync", &key, &receipt)?;
    s.audit(
        "integrations.tickets.sync",
        json!({"case_id":c["id"],"ticket_id":provider_ticket_id,"delivery":"externally_delivered"}),
    )?;
    Ok(receipt)
}

fn probe<T: Transport>(s: &Service, p: &Principal, payload: Value, transport: &T) -> Result<Value> {
    require_role(p, &["admin", "incident_lead"])?;
    integration_gate(s)?;
    let c = case(s, p, &payload)?;
    // Clear a prior green result before any secret, budget, or transport step can fail.
    s.set_state("integrations:health", json!({"status":"checking","checked_at":Utc::now(),"config_hash":configuration_hash(&s.config.integrations),"probes":[]}))?;
    let mut probes = Vec::new();
    let adapters: Vec<(&str, &Adapter)> = vec![
        ("cmdb", &s.config.integrations.cmdb),
        ("tickets", &s.config.integrations.tickets.adapter),
    ];
    for (name, adapter) in adapters.into_iter().filter(|(_, a)| a.enabled) {
        let probe_key = sha(&json!(["integrations.probe", p.tenant, c["id"], name]));
        worker::charge(
            s,
            c["id"].as_str().unwrap_or_default(),
            "integrations.probe",
        )?;
        reserve_response(
            s,
            c["id"].as_str().unwrap_or_default(),
            adapter.max_response_bytes,
        )?;
        if s.stopped() {
            bail!("Service stopped before integration probe");
        }
        let secret =
            std::env::var(&adapter.secret_env).context("Adapter secret reference unavailable")?;
        // A HEAD request has no payload and does not invoke ticket creation/update semantics.
        let response = transport.send(&OutboundRequest {
            method: "HEAD",
            url: destination(adapter)?,
            secret,
            key: probe_key,
            body: Value::Null,
            max_bytes: adapter.max_response_bytes,
            timeout_seconds: adapter.timeout_seconds,
        });
        let status = if response.is_ok() { "passed" } else { "failed" };
        probes.push(json!({"adapter":name,"status":status,"checked_at":Utc::now(),"error":response.err().map(|e|e.to_string())}));
    }
    s.set_state("integrations:health", json!({"status":if probes.iter().all(|p|p["status"]=="passed"){ "passed" }else{"failed"},"checked_at":Utc::now(),"config_hash":configuration_hash(&s.config.integrations),"probes":probes}))?;
    s.audit(
        "integrations.probe",
        json!({"case_id":c["id"],"actor":p.actor}),
    )?;
    Ok(json!({"case_id":c["id"],"probes":probes}))
}

fn configuration_hash(i: &Integrations) -> String {
    sha(&serde_json::to_value(i).unwrap_or(Value::Null))
}

fn status(s: &Service) -> Result<Value> {
    let i = &s.config.integrations;
    let sources = i.sources.iter().map(|source| json!({"name":source.name,"kind":source.kind,"enabled":i.enabled && source.enabled,"max_rows":source.max_rows,"max_bytes":source.max_bytes,"approved":!source.approved_by.is_empty()})).collect::<Vec<_>>();
    let current = configuration_hash(i);
    let health = s.state("integrations:health")?;
    let health = if health["config_hash"] == current {
        health
    } else {
        json!({"status":"stale","reason":"Adapter configuration changed or has not been probed"})
    };
    let db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Integration state lock poisoned"))?;
    let mut q = db.prepare("SELECT operation,state,COUNT(*) FROM investigator_integration_receipts_v2 WHERE tenant=?1 GROUP BY operation,state ORDER BY operation,state")?;
    let receipts = q.query_map([&s.config.tenant], |r| Ok(json!({"operation":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"count":r.get::<_,i64>(2)?})))?.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(
        json!({"enabled":i.enabled,"cmdb":{"enabled":i.enabled && i.cmdb.enabled,"approved":!i.cmdb.approved_by.is_empty()},"tickets":{"enabled":i.enabled && i.tickets.adapter.enabled,"write_enabled":i.enabled && i.tickets.write_enabled,"approved":!i.tickets.write_approved_by.is_empty()},"sources":sources,"health":health,"receipts":receipts}),
    )
}

pub fn handle(s: &Service, p: &Principal, action: &str, payload: Value) -> Result<Value> {
    setup(s)?;
    let transport = HttpTransport;
    handle_with(s, p, action, payload, &transport)
}

fn handle_with<T: Transport>(
    s: &Service,
    p: &Principal,
    action: &str,
    payload: Value,
    transport: &T,
) -> Result<Value> {
    if !payload.is_object() {
        bail!("Integration payload must be an object");
    }
    match action {
        "integrations.status" => status(s),
        "integrations.probe" => probe(s, p, payload, transport),
        "cmdb.sync" => cmdb(s, p, payload, transport),
        "tickets.sync" => tickets(s, p, payload, transport),
        "sources.import" => import(s, p, payload),
        _ => bail!("Unknown integration action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn approved() -> Adapter {
        Adapter {
            enabled: true,
            endpoint: "https://tickets.internal.example/api/relay".into(),
            secret_env: "RELAYNE_TEST_ADAPTER_SECRET".into(),
            allowed_hosts: vec!["tickets.internal.example".into()],
            approved_by: "operator".into(),
            approved_at: "2026-09-20T08:00:00Z".into(),
            idempotency_confirmed: true,
            timeout_seconds: 15,
            max_response_bytes: 4096,
        }
    }

    #[test]
    fn integrations_default_to_disabled_and_reject_unknown_fields() {
        assert!(!Integrations::default().enabled);
        assert!(serde_json::from_str::<Integrations>(r#"{"unknown":true}"#).is_err());
    }

    #[test]
    fn config_and_flattened_ticket_configuration_round_trip() {
        let config = super::super::config::Config::default();
        let value = serde_json::to_value(&config).unwrap();
        let loaded: super::super::config::Config = serde_json::from_value(value).unwrap();
        assert!(!loaded.integrations.enabled);

        let mut integrations = Integrations::default();
        integrations.enabled = true;
        integrations.tickets.adapter = approved();
        integrations.tickets.write_enabled = true;
        integrations.tickets.write_approved_by = "incident-lead".into();
        integrations.tickets.write_approved_at = "2026-09-20T08:00:00Z".into();
        integrations.tickets.write_idempotency_confirmed = true;
        let ticket_json = serde_json::to_value(&integrations).unwrap();
        let loaded: Integrations = serde_json::from_value(ticket_json).unwrap();
        assert!(loaded.tickets.write_enabled);
        assert!(loaded.validate().is_ok());
    }

    #[test]
    fn enabled_adapters_need_fixed_https_approval_and_separate_ticket_write_consent() {
        let mut integrations = Integrations::default();
        integrations.enabled = true;
        integrations.cmdb = approved();
        assert!(integrations.validate().is_ok());
        integrations.cmdb.endpoint = "https://tickets.internal.example:444/api".into();
        assert!(integrations.validate().is_err());
        integrations.cmdb = approved();
        integrations.tickets.adapter = approved();
        integrations.tickets.write_enabled = true;
        assert!(integrations.validate().is_err());
        integrations.tickets.write_approved_by = "incident-lead".into();
        integrations.tickets.write_approved_at = "2026-09-20T08:00:00Z".into();
        integrations.tickets.write_idempotency_confirmed = true;
        assert!(integrations.validate().is_ok());
    }

    #[test]
    fn storage_and_network_counterevidence_are_normalized_with_native_ids() {
        let case = json!({"tenant":"DEMO","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"});
        let storage = SourceAdapter {
            name: "cloud".into(),
            kind: "storage".into(),
            enabled: true,
            approved_by: "owner".into(),
            approved_at: "2026-09-20T08:00:00Z".into(),
            max_rows: 100,
            max_bytes: 4096,
        };
        let normalized = validate_record(&storage, &case, &json!({"event_id":"evt-1","native_id":"native-1","tenant":"DEMO","site":"LAB","event_time":"2026-09-20T09:00:00Z","object_id":"obj","principal":"user-17","operation":"read","object_count":0,"destination":"app","outcome":"blocked","native_action":"GetObject"})).unwrap();
        assert_eq!(normalized["source_id"], "evt-1");
        assert_eq!(normalized["fields"]["native_id"], "native-1");
        assert_eq!(normalized["fields"]["outcome"], "blocked");
        let network = SourceAdapter {
            name: "flow".into(),
            kind: "network".into(),
            ..storage.clone()
        };
        let flow = validate_record(&network, &case, &json!({"event_id":"evt-2","native_id":"native-2","tenant":"DEMO","site":"LAB","event_time":"2026-09-20T09:01:00Z","source_ip":"10.0.0.2","destination_ip":"10.0.0.3","principal":"user-17","destination":"app","direction":"outbound","bytes_out":0,"outcome":"denied","native_action":"deny"})).unwrap();
        assert_eq!(flow["fields"]["kind"], "network_flow");
    }

    #[test]
    fn future_provider_events_are_rejected() {
        let case = json!({"tenant":"DEMO","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2999-09-20T10:00:00Z"});
        let source = SourceAdapter {
            name: "cloud".into(),
            kind: "storage".into(),
            enabled: true,
            approved_by: "owner".into(),
            approved_at: "2026-09-20T08:00:00Z".into(),
            max_rows: 100,
            max_bytes: 4096,
        };
        let record = json!({"event_id":"evt","native_id":"native","tenant":"DEMO","site":"LAB","event_time":"2999-09-20T09:00:00Z","object_id":"obj","principal":"user","operation":"read","object_count":1,"destination":"app","outcome":"success","native_action":"GetObject"});
        assert!(validate_record(&source, &case, &record).is_err());
    }

    struct Mock {
        calls: Arc<Mutex<u32>>,
    }
    fn synthetic_service(mut config: super::super::config::Config) -> (Service, Principal, Value) {
        config.integrations.enabled = true;
        config.operations.encrypted_volume_confirmed = true;
        config.operations.retention_approved = true;
        let path = std::env::temp_dir().join(format!(
            "relayne-p1-contract-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let s = Service::open(&path, config).unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let p = Principal {
            tenant: "DEMO".into(),
            actor: "local-admin".into(),
            role: "admin".into(),
        };
        let c = s.exec(&p, "cases.create", json!({"title":"Synthetic adapter contract","site":"LAB","start":Utc::now()-chrono::Duration::hours(2),"end":Utc::now()})).unwrap();
        setup(&s).unwrap();
        (s, p, c)
    }
    #[test]
    fn imported_provider_coverage_and_counterevidence_reach_playbook() {
        let mut config = super::super::config::Config::default();
        config.integrations.sources = ["storage", "network"]
            .into_iter()
            .map(|kind| SourceAdapter {
                name: format!("provider-{kind}"),
                kind: kind.into(),
                enabled: true,
                approved_by: "synthetic-owner".into(),
                approved_at: (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
                ..Default::default()
            })
            .collect();
        let (s, p, c) = synthetic_service(config);
        let event_time = Utc::now() - chrono::Duration::minutes(10);
        let common = json!({"event_id":"event-1","native_id":"native-1","tenant":"DEMO","site":"LAB","event_time":event_time,"principal":"person","destination":"203.0.113.1","outcome":"success"});
        for kind in ["storage", "network"] {
            let mut event = common.clone();
            if kind == "storage" {
                for (key,value) in json!({"object_id":"object-1","operation":"download","object_count":1,"native_action":"GetObject"}).as_object().unwrap() { event[key]=value.clone(); }
            } else {
                for (key,value) in json!({"source_ip":"192.0.2.1","destination_ip":"203.0.113.1","direction":"outbound","bytes_out":100,"native_action":"ALLOW"}).as_object().unwrap() { event[key]=value.clone(); }
            }
            let mut blocked = event.clone();
            blocked["event_id"] = json!("event-blocked");
            blocked["outcome"] = json!("blocked");
            import(&s,&p,json!({"case_id":c["id"],"provider":format!("provider-{kind}"),"records":[event,blocked],"coverage":{"status":"available","start":c["start"],"end":c["end"]}})).unwrap();
        }
        let evaluated = s
            .exec(
                &p,
                "playbooks.run",
                json!({"case_id":c["id"],"playbook_id":"cloud_exfiltration"}),
            )
            .unwrap();
        let result = &evaluated["playbooks"][0]["result"];
        assert_eq!(result["findings"][0]["status"], "suspected");
        assert_eq!(result["hypotheses"][0]["data_gaps"], json!([]));
        assert_eq!(
            result["findings"][0]["blocked_or_denied_evidence_ids"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn cmdb_retry_is_cached_but_new_refresh_reads_new_snapshot() {
        struct CmdbMock(Arc<Mutex<u32>>);
        impl Transport for CmdbMock {
            fn send(&self, request: &OutboundRequest) -> Result<Value> {
                *self.0.lock().unwrap() += 1;
                Ok(
                    json!({"external_id":request.body["asset_id"],"tenant":"DEMO","site":"LAB","updated_at":Utc::now(),"attributes":{"owner":"synthetic-operator","criticality":"high","tier0":true}}),
                )
            }
        }
        let mut config = super::super::config::Config::default();
        config.integrations.cmdb = approved();
        config.integrations.cmdb.secret_env = "RELAYNE_TEST_CMDB_REFRESH".into();
        unsafe {
            std::env::set_var("RELAYNE_TEST_CMDB_REFRESH", "synthetic-secret");
        }
        let (s, p, c) = synthetic_service(config);
        let calls = Arc::new(Mutex::new(0));
        let mock = CmdbMock(calls.clone());
        let payload = json!({"case_id":c["id"],"asset_id":"asset-1","refresh_id":"snapshot-1"});
        let first = handle_with(&s, &p, "cmdb.sync", payload.clone(), &mock).unwrap();
        assert_eq!(
            first,
            handle_with(&s, &p, "cmdb.sync", payload, &mock).unwrap()
        );
        assert_eq!(*calls.lock().unwrap(), 1);
        handle_with(
            &s,
            &p,
            "cmdb.sync",
            json!({"case_id":c["id"],"asset_id":"asset-1","refresh_id":"snapshot-2"}),
            &mock,
        )
        .unwrap();
        assert_eq!(*calls.lock().unwrap(), 2);
        assert_eq!(
            s.exec(&p, "cases.get", json!({"case_id":c["id"]})).unwrap()["context"]["tier0"],
            true
        );
    }
    #[test]
    fn cmdb_never_overwrites_context_edited_during_retrieval() {
        struct MutatingMock<'a>(&'a Service, &'a Principal, Value);
        impl Transport for MutatingMock<'_> {
            fn send(&self, request: &OutboundRequest) -> Result<Value> {
                self.0.exec(self.1,"context.set",json!({"case_id":self.2,"context":{"source":"independent operator","owner":"manual-owner","updated_at":Utc::now()}}))?;
                Ok(
                    json!({"external_id":request.body["asset_id"],"tenant":"DEMO","site":"LAB","updated_at":Utc::now(),"attributes":{"owner":"cmdb-owner"}}),
                )
            }
        }
        let mut config = super::super::config::Config::default();
        config.integrations.cmdb = approved();
        config.integrations.cmdb.secret_env = "RELAYNE_TEST_CMDB_CONCURRENT".into();
        unsafe {
            std::env::set_var("RELAYNE_TEST_CMDB_CONCURRENT", "synthetic-secret");
        }
        let (s, p, c) = synthetic_service(config);
        let mock = MutatingMock(&s, &p, c["id"].clone());
        assert!(
            handle_with(
                &s,
                &p,
                "cmdb.sync",
                json!({"case_id":c["id"],"asset_id":"asset-1","refresh_id":"concurrent"}),
                &mock
            )
            .is_err()
        );
        assert_eq!(
            s.exec(&p, "cases.get", json!({"case_id":c["id"]})).unwrap()["context"]["owner"],
            "manual-owner"
        );
    }
    impl Transport for Mock {
        fn send(&self, request: &OutboundRequest) -> Result<Value> {
            *self.calls.lock().unwrap() += 1;
            assert_eq!(request.method, "POST");
            assert!(request.body.get("evidence").is_none());
            Ok(json!({"ticket_id":"INT-42","external_case_id":request.body["external_case_id"]}))
        }
    }

    #[test]
    fn ticket_retry_reuses_durable_receipt_and_never_sends_evidence() {
        let mut config = super::super::config::Config::default();
        config.integrations.enabled = true;
        config.operations.encrypted_volume_confirmed = true;
        config.operations.retention_approved = true;
        config.integrations.tickets.adapter = approved();
        config.integrations.tickets.write_enabled = true;
        config.integrations.tickets.write_approved_by = "incident-lead".into();
        config.integrations.tickets.write_approved_at = "2026-09-20T08:00:00Z".into();
        config.integrations.tickets.write_idempotency_confirmed = true;
        unsafe {
            std::env::set_var("RELAYNE_INVESTIGATOR_TOKEN", "x".repeat(32));
            std::env::set_var("RELAYNE_TEST_ADAPTER_SECRET", "test-secret");
        }
        let path =
            std::env::temp_dir().join(format!("relayne-integration-{}.db", uuid::Uuid::new_v4()));
        let service = Service::open(&path, config).unwrap();
        service.set_state("stopped", json!(false)).unwrap();
        let p = Principal {
            tenant: "DEMO".into(),
            actor: "local-admin".into(),
            role: "admin".into(),
        };
        let c = service.exec(&p, "cases.create", json!({"title":"Synthetic","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"})).unwrap();
        setup(&service).unwrap();
        let calls = Arc::new(Mutex::new(0));
        let mock = Mock {
            calls: calls.clone(),
        };
        let payload = json!({"case_id":c["id"]});
        let first = handle_with(&service, &p, "tickets.sync", payload.clone(), &mock).unwrap();
        let second = handle_with(&service, &p, "tickets.sync", payload, &mock).unwrap();
        assert_eq!(first, second);
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}
