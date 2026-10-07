//! FR-18: narrowly scoped A2 response, with durable at-most-once dispatch.
//! A remote call can have an unknown outcome; it is never retried automatically.
use super::{core::Principal, service::Service, worker};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use reqwest::{Method, blocking::Client, header};
use ring::signature::{ED25519, UnparsedPublicKey};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::Read,
    time::{Duration, Instant},
};
use uuid::Uuid;

const DOMAIN: &[u8] = b"relayne-investigator-response-a2-v1\n";
const ACTION_CONTRACT_VERSION: &str = "graph-v1.0-revokeSignInSessions-post-empty-v1";
const MAX_HTTP_BYTES: u64 = 16_384;
const RESERVED_CALLS: u64 = 4;
const RESERVED_BYTES: u64 = MAX_HTTP_BYTES * RESERVED_CALLS;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseConfig {
    pub enabled: bool,
    pub graph_client_id: String,
    pub graph_secret_env: String,
    pub policy_version: String,
    pub valid_from: String,
    pub valid_until: String,
    pub max_approval_seconds: u64,
    pub max_executions_per_day: u64,
    pub max_runtime_seconds: u64,
    pub targets: Vec<ResponseTarget>,
    pub signers: Vec<ResponseSigner>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseTarget {
    pub user_id: String,
    pub site: String,
    /// `normal`, `critical`, or `tier0`. Unknown classification is never normal.
    pub classification: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSigner {
    pub actor: String,
    pub tenant: String,
    pub public_key_base64: String,
    pub sites: Vec<String>,
}

impl ResponseConfig {
    pub fn validate_isolation(&self, config: &super::config::Config) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let response_client =
            Uuid::parse_str(&self.graph_client_id).context("Graph response client must be UUID")?;
        let same_client_id =
            |other: &str| Uuid::parse_str(other).is_ok_and(|client| client == response_client);
        let source = &config.sources;
        if source.enabled
            && (same_client_id(&source.client_id)
                || self
                    .graph_secret_env
                    .eq_ignore_ascii_case(&source.secret_env))
        {
            bail!("Response identity must differ from read source identity");
        }
        for collector in config.collectors.enabled_cloud_sources() {
            if same_client_id(&collector.client_id)
                || self
                    .graph_secret_env
                    .eq_ignore_ascii_case(&collector.secret_env)
            {
                bail!("Response identity must differ from every enabled read collector");
            }
        }
        let other_secret_refs = config
            .users
            .iter()
            .map(|user| user.token_env.as_str())
            .chain([
                config.sources.secret_env.as_str(),
                config.integrations.cmdb.secret_env.as_str(),
                config.integrations.tickets.adapter.secret_env.as_str(),
                config.operations.notification_webhook_env.as_str(),
                config.operations.notification_backup_webhook_env.as_str(),
            ]);
        if other_secret_refs
            .filter(|reference| !reference.is_empty())
            .any(|reference| self.graph_secret_env.eq_ignore_ascii_case(reference))
        {
            bail!("Response credential environment reference must be exclusive");
        }
        Ok(())
    }
    pub fn validate(
        &self,
        tenant: &str,
        sites: &[String],
        users: &[super::config::User],
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        Uuid::parse_str(tenant).context("Response tenant must be a UUID")?;
        Uuid::parse_str(&self.graph_client_id).context("Graph response client must be a UUID")?;
        if !super::config::valid_env(&self.graph_secret_env) {
            bail!("Invalid response secret environment reference");
        }
        if self.policy_version.trim().is_empty() || self.policy_version.len() > 128 {
            bail!("Response policy version required");
        }
        let start = parse_time(&self.valid_from)?;
        let end = parse_time(&self.valid_until)?;
        if start >= end || end <= Utc::now() {
            bail!("Response policy window invalid or expired");
        }
        if !(1..=600).contains(&self.max_approval_seconds)
            || !(1..=100).contains(&self.max_executions_per_day)
            || !(1..=30).contains(&self.max_runtime_seconds)
        {
            bail!("Response limits invalid");
        }
        if self.targets.is_empty() || self.signers.is_empty() {
            bail!("Explicit response targets and signers required");
        }
        let mut targets = HashSet::new();
        for target in &self.targets {
            Uuid::parse_str(&target.user_id)
                .context("Response target must be an Entra object UUID")?;
            if !sites.contains(&target.site) || !targets.insert(&target.user_id) {
                bail!("Invalid or duplicate response target/site");
            }
            if !matches!(
                target.classification.as_str(),
                "normal" | "critical" | "tier0"
            ) {
                bail!("Unknown response target classification");
            }
        }
        let mut actors = HashSet::new();
        let mut keys = HashSet::new();
        for signer in &self.signers {
            if signer.tenant != tenant || !actors.insert(&signer.actor) {
                bail!("Signer tenant/actor invalid");
            }
            if !users.iter().any(|u| {
                u.actor == signer.actor
                    && matches!(u.role.as_str(), "reviewer" | "incident_lead" | "admin")
            }) {
                bail!("Response signer must map to a privileged configured user");
            }
            let key = STANDARD
                .decode(&signer.public_key_base64)
                .context("Invalid response public key")?;
            if key.len() != 32 || !keys.insert(key) {
                bail!("Response signing key must be unique Ed25519 key");
            }
            if signer.sites.is_empty() || signer.sites.iter().any(|site| !sites.contains(site)) {
                bail!("Signer site scope invalid");
            }
        }
        if self.targets.iter().any(|t| t.classification != "normal") && self.signers.len() < 2 {
            bail!("Critical/Tier0 targets require two eligible signers");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Grant {
    domain_version: u32,
    tenant: String,
    case_id: String,
    case_version: i64,
    proposal_id: String,
    target_user_id: String,
    site: String,
    classification: String,
    action: String,
    /// Empty object is the only parameter set for revokeSignInSessions.
    parameters: Value,
    requested_actor: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
    policy_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposeInput {
    case_id: String,
    target_user_id: String,
    site: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdInput {
    proposal_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedInput {
    proposal_id: String,
    approvals: Vec<Approval>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    actor: String,
    signature_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileInput {
    proposal_id: String,
    finding: String,
    evidence_ref: String,
}

fn parse_time(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical(grant: &Grant) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(grant)?);
    Ok(bytes)
}
fn policy_hash(config: &ResponseConfig) -> Result<String> {
    policy_hash_with_components(config, &super::releases::components())
}
fn policy_hash_with_components(config: &ResponseConfig, components: &Value) -> Result<String> {
    let material = json!({
        "response_config": config,
        "software_components": components,
        "action_contract": ACTION_CONTRACT_VERSION,
    });
    Ok(hash(&serde_json::to_vec(&material)?))
}
fn uuid(s: &str) -> Result<()> {
    Uuid::parse_str(s).context("Expected UUID")?;
    Ok(())
}
fn now() -> DateTime<Utc> {
    Utc::now()
}

fn schema(db: &rusqlite::Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS investigator_response_proposals(
        tenant TEXT NOT NULL, id TEXT NOT NULL, nonce TEXT NOT NULL,
        case_id TEXT NOT NULL, grant_json TEXT NOT NULL, state TEXT NOT NULL,
        reserved_calls INTEGER NOT NULL, reserved_bytes INTEGER NOT NULL,
        accepted_result TEXT, reconciliation TEXT, created_at TEXT NOT NULL,
        PRIMARY KEY(tenant,id), UNIQUE(tenant,nonce));
        CREATE TABLE IF NOT EXISTS investigator_response_attempts(
        tenant TEXT NOT NULL, proposal_id TEXT NOT NULL, dispatch_id TEXT NOT NULL,
        case_id TEXT NOT NULL, target_user_id TEXT NOT NULL,
        state TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT,
        result_json TEXT, PRIMARY KEY(tenant,proposal_id), UNIQUE(tenant,dispatch_id),
        UNIQUE(tenant,case_id,target_user_id));",
    )?;
    Ok(())
}
fn read_grant(db: &rusqlite::Connection, tenant: &str, id: &str) -> Result<(Grant, String)> {
    let row: Option<(String,String)> = db.query_row(
        "SELECT grant_json,state FROM investigator_response_proposals WHERE tenant=?1 AND id=?2",
        params![tenant,id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let (raw, state) = row.context("Unknown response proposal")?;
    Ok((serde_json::from_str(&raw)?, state))
}
fn case_scope(db: &rusqlite::Connection, tenant: &str, id: &str, site: &str) -> Result<i64> {
    let row: Option<(i64, String)> = db
        .query_row(
            "SELECT version,body FROM investigator_cases WHERE tenant=?1 AND id=?2",
            params![tenant, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (version, raw) = row.context("Response case not found")?;
    let body: Value = serde_json::from_str(&raw)?;
    if body["tenant"] != tenant || body["site"] != site || body["state"] == "closed" {
        bail!("Response case tenant/site mismatch or case closed");
    }
    Ok(version)
}
fn reserve_response_bytes(s: &Service, cid: &str) -> Result<()> {
    let key = format!("worker:usage:{cid}");
    let mut db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Response budget lock poisoned"))?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key=?2",
            params![s.config.tenant, key],
            |r| r.get(0),
        )
        .optional()?;
    let mut usage: Value = raw
        .map(|r| serde_json::from_str(&r))
        .transpose()?
        .unwrap_or(json!({}));
    let next = usage["bytes"]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(RESERVED_BYTES);
    if next > s.config.budgets.case_result_bytes {
        bail!("Response byte envelope exceeds case budget");
    }
    usage["bytes"] = json!(next);
    usage["response_reserved_bytes"] = json!(
        usage["response_reserved_bytes"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(RESERVED_BYTES)
    );
    tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,?2,?3) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value",
        params![s.config.tenant,key,usage.to_string()])?;
    tx.commit()?;
    Ok(())
}
fn recovery_clear(db: &rusqlite::Connection, tenant: &str) -> Result<bool> {
    let raw: Option<String> = db
        .query_row(
            "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key='recovery:last'",
            [tenant],
            |r| r.get(0),
        )
        .optional()?;
    Ok(!raw
        .map(|s| {
            serde_json::from_str::<Value>(&s)
                .ok()
                .and_then(|v| v["reconciliation_required"].as_bool())
                .unwrap_or(true)
        })
        .unwrap_or(false))
}
fn gate(s: &Service, db: &rusqlite::Connection) -> Result<()> {
    if !s.config.response.enabled {
        bail!("A2 response disabled");
    }
    let stopped: Option<String> = db
        .query_row(
            "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key='stopped'",
            [&s.config.tenant],
            |r| r.get(0),
        )
        .optional()?;
    if stopped.as_deref() != Some("false") {
        bail!("Global stop is active");
    }
    if !recovery_clear(db, &s.config.tenant)? {
        bail!("Recovery reconciliation required before response");
    }
    let current = now();
    if current < parse_time(&s.config.response.valid_from)?
        || current >= parse_time(&s.config.response.valid_until)?
    {
        bail!("Response policy outside approved time window");
    }
    Ok(())
}
fn validate_grant(s: &Service, db: &rusqlite::Connection, grant: &Grant) -> Result<()> {
    if grant.domain_version != 1
        || grant.tenant != s.config.tenant
        || grant.action != "microsoft_graph.revoke_sign_in_sessions"
        || grant.parameters != json!({})
        || grant.policy_hash != policy_hash(&s.config.response)?
    {
        bail!("Signed response scope changed");
    }
    uuid(&grant.target_user_id)?;
    if !s.config.response.targets.iter().any(|t| {
        t.user_id == grant.target_user_id
            && t.site == grant.site
            && t.classification == grant.classification
    }) {
        bail!("Response target no longer explicitly allowed");
    }
    if case_scope(db, &grant.tenant, &grant.case_id, &grant.site)? != grant.case_version {
        bail!("Case version changed; new approval required");
    }
    let issued = parse_time(&grant.issued_at)?;
    let expiry = parse_time(&grant.expires_at)?;
    let current = now();
    if current < issued
        || current >= expiry
        || expiry.signed_duration_since(issued).num_seconds() as u64
            > s.config.response.max_approval_seconds
    {
        bail!("Response approval expired or invalid");
    }
    Ok(())
}
fn reservation_valid(db: &rusqlite::Connection, grant: &Grant) -> Result<()> {
    let row:Option<(i64,i64)>=db.query_row("SELECT reserved_calls,reserved_bytes FROM investigator_response_proposals WHERE tenant=?1 AND id=?2",
        params![grant.tenant,grant.proposal_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if row != Some((RESERVED_CALLS as i64, RESERVED_BYTES as i64)) {
        bail!("Response network envelope was not persistently reserved");
    }
    Ok(())
}
fn verify_approvals(config: &ResponseConfig, grant: &Grant, approvals: &[Approval]) -> Result<()> {
    let needed = if grant.classification == "normal" {
        1
    } else {
        2
    };
    if approvals.len() != needed {
        bail!("Exact number of human response signatures required");
    }
    let bytes = canonical(grant)?;
    let mut seen = HashSet::new();
    for approval in approvals {
        if approval.actor == grant.requested_actor || !seen.insert(&approval.actor) {
            bail!("Self or duplicate response approval");
        }
        let signer = config
            .signers
            .iter()
            .find(|s| {
                s.actor == approval.actor
                    && s.tenant == grant.tenant
                    && s.sites.contains(&grant.site)
            })
            .context("Response signer not authorized for target site")?;
        let key = STANDARD
            .decode(&signer.public_key_base64)
            .context("Invalid signer key")?;
        let signature = STANDARD
            .decode(&approval.signature_base64)
            .context("Invalid response signature encoding")?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&bytes, &signature)
            .map_err(|_| anyhow::anyhow!("Invalid response signature"))?;
    }
    Ok(())
}

trait ResponseTransport {
    fn revoke(&self, s: &Service, grant: &Grant) -> Result<Value>;
}
struct GraphTransport;
impl ResponseTransport for GraphTransport {
    fn revoke(&self, s: &Service, grant: &Grant) -> Result<Value> {
        graph_revoke(s, grant)
    }
}

pub fn handle(s: &Service, p: &Principal, action: &str, payload: Value) -> Result<Value> {
    handle_with_transport(s, p, action, payload, &GraphTransport)
}

fn handle_with_transport(
    s: &Service,
    p: &Principal,
    action: &str,
    payload: Value,
    transport: &impl ResponseTransport,
) -> Result<Value> {
    if action == "response.execute" && !s.is_executor() {
        bail!("Response execution requires the dedicated executor process");
    }
    if p.tenant != s.config.tenant || p.role == "system" {
        bail!("Response principal not authorized");
    }
    if !s
        .config
        .users
        .iter()
        .any(|u| u.actor == p.actor && u.role == p.role)
    {
        bail!("Response principal is not a configured user");
    }
    let mut db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Response database lock poisoned"))?;
    schema(&db)?;
    match action {
        "response.status" => {
            if !matches!(p.role.as_str(), "admin" | "incident_lead" | "reviewer") {
                bail!("Response status role required");
            }
            if payload == json!({}) {
                let stopped:Option<String>=db.query_row("SELECT value FROM investigator_service_state WHERE tenant=?1 AND key='stopped'",[&p.tenant],|r|r.get(0)).optional()?;
                return Ok(
                    json!({"enabled":s.config.response.enabled,"a2_action":"microsoft_graph.revoke_sign_in_sessions",
                    "a3_enabled":false,"stopped":stopped.as_deref()!=Some("false"),"recovery_clear":recovery_clear(&db,&p.tenant)?,
                    "target_count":s.config.response.targets.len(),"signer_count":s.config.response.signers.len(),
                    "max_executions_per_day":s.config.response.max_executions_per_day,
                    "max_runtime_seconds":s.config.response.max_runtime_seconds,"executor_required":true,
                    "process_role":if s.is_executor() {"executor"} else {"investigator"},
                    "technical_effect_verified":false}),
                );
            }
            let id: IdInput = serde_json::from_value(payload)?;
            uuid(&id.proposal_id)?;
            let (grant, state) = read_grant(&db, &p.tenant, &id.proposal_id)?;
            let result: Option<String> = db.query_row("SELECT result_json FROM investigator_response_attempts WHERE tenant=?1 AND proposal_id=?2",params![p.tenant,id.proposal_id],|r|r.get(0)).optional()?.flatten();
            Ok(
                json!({"proposal_id":id.proposal_id,"case_id":grant.case_id,"target_user_id":grant.target_user_id,
                "site":grant.site,"action":grant.action,"classification":grant.classification,"state":state,
                "dispatch_result":result.and_then(|r|serde_json::from_str::<Value>(&r).ok()),"technical_effect_verified":false}),
            )
        }
        "response.propose" => {
            if !matches!(p.role.as_str(), "admin" | "incident_lead") {
                bail!("Response proposal role required");
            }
            gate(s, &db)?;
            let input: ProposeInput = serde_json::from_value(payload)?;
            uuid(&input.case_id)?;
            uuid(&input.target_user_id)?;
            let target = s
                .config
                .response
                .targets
                .iter()
                .find(|t| t.user_id == input.target_user_id && t.site == input.site)
                .context("Target/site not explicitly allowed")?;
            case_scope(&db, &p.tenant, &input.case_id, &input.site)?;
            // Reserve the entire fixed network envelope before calculating the signed
            // case version. Worker accounting itself advances that version.
            drop(db);
            for _ in 0..RESERVED_CALLS {
                worker::charge(s, &input.case_id, "response.a2")?;
            }
            reserve_response_bytes(s, &input.case_id)?;
            let db = s
                .ops
                .lock()
                .map_err(|_| anyhow::anyhow!("Response database lock poisoned"))?;
            gate(s, &db)?;
            let current = now();
            let id = Uuid::new_v4().to_string();
            let grant = Grant {
                domain_version: 1,
                tenant: p.tenant.clone(),
                case_id: input.case_id.clone(),
                case_version: case_scope(&db, &p.tenant, &input.case_id, &input.site)?,
                proposal_id: id.clone(),
                target_user_id: input.target_user_id,
                site: input.site,
                classification: target.classification.clone(),
                action: "microsoft_graph.revoke_sign_in_sessions".into(),
                parameters: json!({}),
                requested_actor: p.actor.clone(),
                issued_at: current.to_rfc3339(),
                expires_at: (current
                    + chrono::Duration::seconds(s.config.response.max_approval_seconds as i64))
                .to_rfc3339(),
                nonce: Uuid::new_v4().to_string(),
                policy_hash: policy_hash(&s.config.response)?,
            };
            db.execute("INSERT INTO investigator_response_proposals(tenant,id,nonce,case_id,grant_json,state,reserved_calls,reserved_bytes,created_at) VALUES(?1,?2,?3,?4,?5,'proposed',?6,?7,?8)",
                params![p.tenant,id,grant.nonce,grant.case_id,serde_json::to_string(&grant)?,RESERVED_CALLS as i64,RESERVED_BYTES as i64,current.to_rfc3339()])?;
            s.audit("response.proposed",json!({"proposal_id":id,"case_id":grant.case_id,"target_user_id":grant.target_user_id,
                "actor":p.actor,"policy_hash":grant.policy_hash,"case_version":grant.case_version}))?;
            Ok(
                json!({"proposal_id":id,"challenge_base64":STANDARD.encode(canonical(&grant)?),"grant":grant,
                "required_distinct_signers":if target.classification == "normal" {1} else {2}}),
            )
        }
        "response.challenge" => {
            if !matches!(p.role.as_str(), "admin" | "incident_lead" | "reviewer") {
                bail!("Response review role required");
            }
            gate(s, &db)?;
            let input: IdInput = serde_json::from_value(payload)?;
            uuid(&input.proposal_id)?;
            let (grant, state) = read_grant(&db, &p.tenant, &input.proposal_id)?;
            if state != "proposed" {
                bail!("Response proposal is no longer signable");
            }
            validate_grant(s, &db, &grant)?;
            Ok(json!({"challenge_base64":STANDARD.encode(canonical(&grant)?),"grant":grant}))
        }
        "response.execute" => {
            if !matches!(p.role.as_str(), "admin" | "incident_lead") {
                bail!("Response execution role required");
            }
            gate(s, &db)?;
            let input: SignedInput = serde_json::from_value(payload)?;
            uuid(&input.proposal_id)?;
            let (grant, state) = read_grant(&db, &p.tenant, &input.proposal_id)?;
            if state != "proposed" || grant.requested_actor != p.actor {
                bail!("Response proposal cannot be executed by this actor");
            }
            validate_grant(s, &db, &grant)?;
            reservation_valid(&db, &grant)?;
            verify_approvals(&s.config.response, &grant, &input.approvals)?;
            // Transaction seals the attempt before any remote call. A crash leaves `dispatching`,
            // which is an unknown outcome requiring explicit reconciliation, never a retry.
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            gate(s, &tx)?;
            validate_grant(s, &tx, &grant)?;
            reservation_valid(&tx, &grant)?;
            let day = now().format("%Y-%m-%d").to_string();
            let count:i64=tx.query_row("SELECT COUNT(*) FROM investigator_response_attempts WHERE tenant=?1 AND substr(started_at,1,10)=?2",params![p.tenant,day],|r|r.get(0))?;
            if count >= s.config.response.max_executions_per_day as i64 {
                bail!("Daily response execution limit reached");
            }
            if tx.execute("UPDATE investigator_response_proposals SET state='dispatching' WHERE tenant=?1 AND id=?2 AND state='proposed'",params![p.tenant,input.proposal_id])? != 1 {
                bail!("Response already dispatched");
            }
            let dispatch_id = Uuid::new_v4().to_string();
            tx.execute("INSERT INTO investigator_response_attempts(tenant,proposal_id,dispatch_id,case_id,target_user_id,state,started_at) VALUES(?1,?2,?3,?4,?5,'dispatching',?6)",
                params![p.tenant,input.proposal_id,dispatch_id,grant.case_id,grant.target_user_id,now().to_rfc3339()])?;
            tx.commit()?;
            drop(db);
            let result=s.audit("response.dispatch_sealed",json!({"proposal_id":input.proposal_id,"dispatch_id":dispatch_id,
                "case_id":grant.case_id,"target_user_id":grant.target_user_id,"approved_by":input.approvals.iter().map(|a|a.actor.as_str()).collect::<Vec<_>>()}))
                .and_then(|_|transport.revoke(s,&grant));
            let (state, public) = match result {
                Ok(v) => ("accepted_unverified", v),
                Err(e) => (
                    "unknown_outcome",
                    json!({"accepted":false,"effect_verified":false,"outcome":"unknown","error":e.to_string()}),
                ),
            };
            let db = s
                .ops
                .lock()
                .map_err(|_| anyhow::anyhow!("Response database lock poisoned"))?;
            db.execute("UPDATE investigator_response_attempts SET state=?3,completed_at=?4,result_json=?5 WHERE tenant=?1 AND proposal_id=?2 AND state='dispatching'",
                params![p.tenant,input.proposal_id,state,now().to_rfc3339(),public.to_string()])?;
            db.execute("UPDATE investigator_response_proposals SET state=?3,accepted_result=?4 WHERE tenant=?1 AND id=?2 AND state='dispatching'",
                params![p.tenant,input.proposal_id,state,public.to_string()])?;
            s.audit(
                "response.dispatch_result",
                json!({"proposal_id":input.proposal_id,"state":state,"actor":p.actor}),
            )?;
            Ok(
                json!({"proposal_id":input.proposal_id,"state":state,"dispatch_result":public,"technical_effect_verified":false}),
            )
        }
        "response.reconcile" => {
            if !matches!(p.role.as_str(), "admin" | "reviewer") {
                bail!("Independent response reviewer required");
            }
            let input: ReconcileInput = serde_json::from_value(payload)?;
            uuid(&input.proposal_id)?;
            if !matches!(
                input.finding.as_str(),
                "effect_observed" | "no_effect_observed" | "indeterminate"
            ) || input.evidence_ref.trim().is_empty()
                || input.evidence_ref.len() > 512
            {
                bail!("Explicit bounded reconciliation evidence required");
            }
            let (grant, state) = read_grant(&db, &p.tenant, &input.proposal_id)?;
            if p.actor == grant.requested_actor
                || !matches!(
                    state.as_str(),
                    "dispatching" | "accepted_unverified" | "unknown_outcome"
                )
            {
                bail!("Reconciliation must be independent and follow a dispatch");
            }
            let record = json!({"finding":input.finding,"evidence_ref":input.evidence_ref,"reviewer":p.actor,"reviewed_at":now(),
                "technical_effect_verified":false,"note":"Human-reported evidence is not independent machine verification"});
            db.execute("UPDATE investigator_response_proposals SET state='reconciled_human_report',reconciliation=?3 WHERE tenant=?1 AND id=?2",
                params![p.tenant,input.proposal_id,record.to_string()])?;
            s.audit(
                "response.reconciled",
                json!({"proposal_id":input.proposal_id,"finding":input.finding,"reviewer":p.actor}),
            )?;
            Ok(
                json!({"proposal_id":input.proposal_id,"state":"reconciled_human_report","reconciliation":record}),
            )
        }
        _ => bail!("Unknown response action"),
    }
}

fn limited_json(response: reqwest::blocking::Response) -> Result<Value> {
    let mut body = Vec::new();
    response.take(MAX_HTTP_BYTES + 1).read_to_end(&mut body)?;
    if body.len() as u64 > MAX_HTTP_BYTES {
        bail!("Graph response exceeds byte limit");
    }
    serde_json::from_slice(&body).context("Invalid Graph JSON response")
}

fn read_provider_watermark(
    client: &Client,
    token: &str,
    target_user_id: &str,
    deadline: Instant,
) -> Option<DateTime<Utc>> {
    if deadline <= Instant::now() {
        return None;
    }
    let url = format!(
        "https://graph.microsoft.com/v1.0/users/{target_user_id}?$select=signInSessionsValidFromDateTime"
    );
    let response = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .timeout(deadline.saturating_duration_since(Instant::now()))
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = limited_json(response).ok()?;
    parse_time(body["signInSessionsValidFromDateTime"].as_str()?).ok()
}

fn graph_revoke(s: &Service, grant: &Grant) -> Result<Value> {
    // The action is fixed here; neither host nor URL nor HTTP method comes from a proposal.
    let secret = std::env::var(&s.config.response.graph_secret_env)
        .context("Response credential unavailable")?;
    if secret.is_empty() {
        bail!("Response credential unavailable");
    }
    let deadline = Instant::now() + Duration::from_secs(s.config.response.max_runtime_seconds);
    let client = Client::builder()
        .timeout(Duration::from_secs(s.config.response.max_runtime_seconds))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        grant.tenant
    );
    let token_response = client
        .post(token_url)
        .timeout(deadline.saturating_duration_since(Instant::now()))
        .form(&[
            ("client_id", s.config.response.graph_client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()?;
    if !token_response.status().is_success() {
        bail!(
            "Graph token request failed with HTTP {}",
            token_response.status()
        );
    }
    let token = limited_json(token_response)?["access_token"]
        .as_str()
        .context("Graph token missing")?
        .to_owned();
    if token.len() > 8192 || token.is_empty() {
        bail!("Graph token invalid");
    }
    if deadline <= Instant::now() {
        bail!("Response runtime budget exhausted before side effect");
    }
    // Bound the optional baseline so it cannot consume the entire mutation window.
    let baseline_budget =
        (deadline.saturating_duration_since(Instant::now()) / 4).min(Duration::from_secs(2));
    let before = read_provider_watermark(
        &client,
        &token,
        &grant.target_user_id,
        Instant::now() + baseline_budget,
    );
    {
        let db = s
            .ops
            .lock()
            .map_err(|_| anyhow::anyhow!("Response database lock poisoned"))?;
        gate(s, &db)?;
        validate_grant(s, &db, grant)?;
        reservation_valid(&db, grant)?;
    }
    let url = format!(
        "https://graph.microsoft.com/v1.0/users/{}/revokeSignInSessions",
        grant.target_user_id
    );
    let response = client
        .request(Method::POST, url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .timeout(deadline.saturating_duration_since(Instant::now()))
        .body("{}")
        .send()?;
    let status = response.status();
    if !status.is_success() {
        bail!(
            "Graph response HTTP {} (remote outcome not assumed)",
            status
        );
    }
    let body = limited_json(response)?;
    if body["value"] != true {
        bail!("Graph did not acknowledge session revocation");
    }
    // A changed provider watermark is a state observation. Another administrator
    // may change it, and it does not prove that existing tokens stopped working.
    let after = read_provider_watermark(&client, &token, &grant.target_user_id, deadline);
    let advanced = before
        .as_ref()
        .zip(after.as_ref())
        .map(|(earlier, later)| later > earlier);
    let observation = json!({
        "before": before,
        "after": after,
        "advanced": advanced,
        "causal_proof": false,
        "session_effect_verified": false
    });
    Ok(
        json!({"accepted":true,"effect_verified":false,"outcome":"graph_acknowledged_unverified",
        "http_status":status.as_u16(),"target_user_id":grant.target_user_id,
        "provider_timestamp_observation":observation}),
    )
}

#[cfg(test)]
mod tests {
    use super::super::config::{Config, User};
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct MockTransport(AtomicUsize);
    impl ResponseTransport for MockTransport {
        fn revoke(&self, _: &Service, _: &Grant) -> Result<Value> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"accepted":true,"effect_verified":false,"outcome":"mock_acknowledged"}))
        }
    }
    fn key() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }
    fn fixture(classification: &str) -> (Config, Vec<Ed25519KeyPair>, PathBuf, Principal) {
        let tenant = Uuid::new_v4().to_string();
        let target = Uuid::new_v4().to_string();
        let keys = vec![key(), key()];
        let mut c = Config::default();
        c.tenant = tenant.clone();
        c.users = vec![
            User {
                actor: "proposer".into(),
                role: "admin".into(),
                token_env: "RESPONSE_TEST_PROPOSER".into(),
            },
            User {
                actor: "reviewer1".into(),
                role: "reviewer".into(),
                token_env: "RESPONSE_TEST_REVIEWER1".into(),
            },
            User {
                actor: "reviewer2".into(),
                role: "reviewer".into(),
                token_env: "RESPONSE_TEST_REVIEWER2".into(),
            },
        ];
        c.response = ResponseConfig {
            enabled: true,
            graph_client_id: Uuid::new_v4().to_string(),
            graph_secret_env: "RESPONSE_TEST_GRAPH_SECRET".into(),
            policy_version: "synthetic-v1".into(),
            valid_from: (now() - chrono::Duration::minutes(1)).to_rfc3339(),
            valid_until: (now() + chrono::Duration::minutes(10)).to_rfc3339(),
            max_approval_seconds: 300,
            max_executions_per_day: 2,
            max_runtime_seconds: 3,
            targets: vec![ResponseTarget {
                user_id: target,
                site: "LAB".into(),
                classification: classification.into(),
            }],
            signers: keys
                .iter()
                .enumerate()
                .map(|(i, k)| ResponseSigner {
                    actor: format!("reviewer{}", i + 1),
                    tenant: tenant.clone(),
                    public_key_base64: STANDARD.encode(k.public_key().as_ref()),
                    sites: vec!["LAB".into()],
                })
                .collect(),
        };
        let path = std::env::temp_dir().join(format!("response-{}.sqlite", Uuid::new_v4()));
        let principal = Principal {
            tenant,
            actor: "proposer".into(),
            role: "admin".into(),
        };
        (c, keys, path, principal)
    }
    fn case(s: &Service, p: &Principal) -> String {
        s.exec(
            p,
            "cases.create",
            json!({"title":"synthetic","site":"LAB",
            "start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:00Z"}),
        )
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn approvals(challenge: &Value, keys: &[Ed25519KeyPair], count: usize) -> Vec<Value> {
        let bytes = STANDARD
            .decode(challenge["challenge_base64"].as_str().unwrap())
            .unwrap();
        keys.iter()
            .take(count)
            .enumerate()
            .map(|(i, k)| {
                json!({"actor":format!("reviewer{}",i+1),
            "signature_base64":STANDARD.encode(k.sign(&bytes).as_ref())})
            })
            .collect()
    }
    #[test]
    fn signed_grant_rejects_tamper_tenant_target_duplicate_and_self_approval() {
        let (config, keys, _, principal) = fixture("critical");
        let grant = Grant {
            domain_version: 1,
            tenant: principal.tenant.clone(),
            case_id: Uuid::new_v4().to_string(),
            case_version: 1,
            proposal_id: Uuid::new_v4().to_string(),
            target_user_id: config.response.targets[0].user_id.clone(),
            site: "LAB".into(),
            classification: "critical".into(),
            action: "microsoft_graph.revoke_sign_in_sessions".into(),
            parameters: json!({}),
            requested_actor: principal.actor,
            issued_at: now().to_rfc3339(),
            expires_at: (now() + chrono::Duration::minutes(2)).to_rfc3339(),
            nonce: Uuid::new_v4().to_string(),
            policy_hash: policy_hash(&config.response).unwrap(),
        };
        let bytes = canonical(&grant).unwrap();
        let approvals = [
            Approval {
                actor: "reviewer1".into(),
                signature_base64: STANDARD.encode(keys[0].sign(&bytes).as_ref()),
            },
            Approval {
                actor: "reviewer2".into(),
                signature_base64: STANDARD.encode(keys[1].sign(&bytes).as_ref()),
            },
        ];
        verify_approvals(&config.response, &grant, &approvals).unwrap();
        assert!(verify_approvals(&config.response, &grant, &approvals[..1]).is_err());
        let mut changed = grant.clone();
        changed.target_user_id = Uuid::new_v4().to_string();
        assert!(verify_approvals(&config.response, &changed, &approvals).is_err());
        changed = grant.clone();
        changed.tenant = Uuid::new_v4().to_string();
        assert!(verify_approvals(&config.response, &changed, &approvals).is_err());
        changed = grant.clone();
        changed.case_version += 1;
        assert!(verify_approvals(&config.response, &changed, &approvals).is_err());
        let duplicate = [approvals[0].clone(), approvals[0].clone()];
        assert!(verify_approvals(&config.response, &grant, &duplicate).is_err());
    }
    #[test]
    fn dispatch_is_fenced_across_restart_and_unknown_outcome() {
        let (config, keys, path, p) = fixture("normal");
        let s = Service::open(&path, config.clone()).unwrap();
        let executor = Service::open_executor(&path, config.clone(), "127.0.0.1:47842").unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let cid = case(&s, &p);
        let target = config.response.targets[0].user_id.clone();
        let proposal = handle_with_transport(
            &s,
            &p,
            "response.propose",
            json!({"case_id":cid,"target_user_id":target,"site":"LAB"}),
            &MockTransport(AtomicUsize::new(0)),
        )
        .unwrap();
        let id = proposal["proposal_id"].as_str().unwrap();
        let mock = MockTransport(AtomicUsize::new(0));
        let signed = json!({"proposal_id":id,"approvals":approvals(&proposal,&keys,1)});
        assert!(handle_with_transport(&s, &p, "response.execute", signed.clone(), &mock).is_err());
        let result =
            handle_with_transport(&executor, &p, "response.execute", signed.clone(), &mock)
                .unwrap();
        assert_eq!(result["state"], "accepted_unverified");
        assert_eq!(mock.0.load(Ordering::SeqCst), 1);
        assert!(
            handle_with_transport(&executor, &p, "response.execute", signed.clone(), &mock)
                .is_err()
        );
        drop(s);
        drop(executor);
        let executor = Service::open_executor(&path, config, "127.0.0.1:47842").unwrap();
        assert!(handle_with_transport(&executor, &p, "response.execute", signed, &mock).is_err());
        assert_eq!(mock.0.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn stop_and_expiry_block_before_dispatch() {
        let (config, keys, path, p) = fixture("normal");
        let s = Service::open(&path, config.clone()).unwrap();
        let executor = Service::open_executor(&path, config.clone(), "127.0.0.1:47842").unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let cid = case(&s, &p);
        let target = config.response.targets[0].user_id.clone();
        let mock = MockTransport(AtomicUsize::new(0));
        let proposal = handle_with_transport(
            &s,
            &p,
            "response.propose",
            json!({"case_id":cid,"target_user_id":target,"site":"LAB"}),
            &mock,
        )
        .unwrap();
        let signed =
            json!({"proposal_id":proposal["proposal_id"],"approvals":approvals(&proposal,&keys,1)});
        s.set_state("stopped", json!(true)).unwrap();
        assert!(
            handle_with_transport(&executor, &p, "response.execute", signed.clone(), &mock)
                .is_err()
        );
        s.set_state("stopped", json!(false)).unwrap();
        {
            let db = s.ops.lock().unwrap();
            let (mut grant, _) =
                read_grant(&db, &p.tenant, proposal["proposal_id"].as_str().unwrap()).unwrap();
            grant.expires_at = (now() - chrono::Duration::seconds(1)).to_rfc3339();
            db.execute("UPDATE investigator_response_proposals SET grant_json=?3 WHERE tenant=?1 AND id=?2",
                params![p.tenant,grant.proposal_id,serde_json::to_string(&grant).unwrap()]).unwrap();
        }
        assert!(handle_with_transport(&executor, &p, "response.execute", signed, &mock).is_err());
        assert_eq!(mock.0.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn forged_privileged_principal_cannot_read_response_status() {
        let (config, _, path, p) = fixture("normal");
        let s = Service::open(&path, config).unwrap();
        let forged = Principal {
            tenant: p.tenant.clone(),
            actor: "unconfigured-admin".into(),
            role: "admin".into(),
        };
        assert!(
            handle_with_transport(
                &s,
                &forged,
                "response.status",
                json!({}),
                &MockTransport(AtomicUsize::new(0))
            )
            .is_err()
        );
        let role_forged = Principal {
            tenant: p.tenant,
            actor: "reviewer1".into(),
            role: "admin".into(),
        };
        assert!(
            handle_with_transport(
                &s,
                &role_forged,
                "response.status",
                json!({}),
                &MockTransport(AtomicUsize::new(0))
            )
            .is_err()
        );
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn proposal_rejects_case_from_another_site_before_budget_reservation() {
        let (mut config, _, path, p) = fixture("normal");
        config.allowed_sites.push("OTHER".into());
        let target = config.response.targets[0].user_id.clone();
        let s = Service::open(&path, config).unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let case = s
            .exec(
                &p,
                "cases.create",
                json!({"title":"other site","site":"OTHER",
            "start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:00Z"}),
            )
            .unwrap();
        let cid = case["id"].as_str().unwrap();
        assert!(
            handle_with_transport(
                &s,
                &p,
                "response.propose",
                json!({"case_id":cid,"target_user_id":target,"site":"LAB"}),
                &MockTransport(AtomicUsize::new(0))
            )
            .is_err()
        );
        assert!(s.state(&format!("worker:usage:{cid}")).unwrap().is_null());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn executor_allowlist_and_shared_stop_restore_gate() {
        let (config, keys, path, p) = fixture("normal");
        assert!(Service::open_executor(&path, config.clone(), &config.bind).is_err());
        assert!(Service::open_executor(&path, config.clone(), "0.0.0.0:47842").is_err());
        let main = Service::open(&path, config.clone()).unwrap();
        let executor = Service::open_executor(&path, config.clone(), "127.0.0.1:47842").unwrap();
        main.set_state("stopped", json!(false)).unwrap();
        let cid = case(&main, &p);
        let target = &config.response.targets[0].user_id;
        let proposal = handle_with_transport(
            &main,
            &p,
            "response.propose",
            json!({"case_id":cid,"target_user_id":target,"site":"LAB"}),
            &MockTransport(AtomicUsize::new(0)),
        )
        .unwrap();
        let signed = json!({"proposal_id":proposal["proposal_id"],
            "approvals":approvals(&proposal, &keys, 1)});
        let mock = MockTransport(AtomicUsize::new(0));
        assert!(
            main.command(&p, "response.execute", signed.clone())
                .is_err()
        );
        assert!(executor.command(&p, "response.propose", json!({})).is_err());
        assert!(
            executor
                .command(&p, "investigation.start", json!({}))
                .is_err()
        );
        assert!(executor.command(&p, "service.resume", json!({})).is_err());
        let forged = Principal {
            tenant: p.tenant.clone(),
            actor: "forged".into(),
            role: "admin".into(),
        };
        assert!(
            executor
                .command(&forged, "response.status", json!({}))
                .is_err()
        );
        assert_eq!(
            executor.command(&p, "response.status", json!({})).unwrap()["process_role"],
            "executor"
        );

        main.set_state("recovery:last", json!({"reconciliation_required":true}))
            .unwrap();
        assert!(
            handle_with_transport(&executor, &p, "response.execute", signed.clone(), &mock)
                .is_err()
        );
        main.set_state("recovery:last", json!({"reconciliation_required":false}))
            .unwrap();
        assert_eq!(
            executor.command(&p, "service.stop", json!({})).unwrap()["stopped"],
            true
        );
        assert!(main.stopped());
        assert!(
            handle_with_transport(&executor, &p, "response.execute", signed.clone(), &mock)
                .is_err()
        );
        main.command(&p, "service.resume", json!({})).unwrap();
        assert_eq!(
            handle_with_transport(&executor, &p, "response.execute", signed, &mock).unwrap()["state"],
            "accepted_unverified"
        );
        assert_eq!(mock.0.load(Ordering::SeqCst), 1);
        drop(executor);
        drop(main);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn response_secret_cannot_double_as_main_process_credential() {
        let (config, _, _, _) = fixture("normal");
        let secret = config.response.graph_secret_env.clone();
        let mut overlap = config.clone();
        overlap.users[0].token_env = secret.clone();
        assert!(overlap.validate().is_err());
        let mut overlap = config.clone();
        overlap.integrations.cmdb.secret_env = secret.clone();
        assert!(overlap.response.validate_isolation(&overlap).is_err());
        let mut overlap = config.clone();
        overlap.integrations.tickets.adapter.secret_env = secret.clone();
        assert!(overlap.response.validate_isolation(&overlap).is_err());
        let mut overlap = config.clone();
        overlap.operations.notification_webhook_env = secret.clone();
        assert!(overlap.response.validate_isolation(&overlap).is_err());
        let mut overlap = config.clone();
        overlap.operations.notification_backup_webhook_env = secret.to_ascii_lowercase();
        assert!(overlap.response.validate_isolation(&overlap).is_err());
        let mut overlap = config.clone();
        overlap.sources.secret_env = secret;
        assert!(overlap.response.validate_isolation(&overlap).is_err());
    }

    #[test]
    fn response_client_id_comparison_uses_uuid_value() {
        let (config, _, _, _) = fixture("normal");
        let mut overlap = config.clone();
        overlap.sources.enabled = true;
        overlap.sources.client_id = config.response.graph_client_id.to_ascii_uppercase();
        assert!(overlap.response.validate_isolation(&overlap).is_err());
        let mut overlap = config.clone();
        overlap.collectors.entra_token.enabled = true;
        overlap.collectors.entra_token.client_id =
            config.response.graph_client_id.to_ascii_uppercase();
        assert!(overlap.response.validate_isolation(&overlap).is_err());
    }

    #[test]
    fn pending_grant_is_invalid_after_software_component_change() {
        let (config, keys, path, p) = fixture("normal");
        let s = Service::open(&path, config.clone()).unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let cid = case(&s, &p);
        let proposal = handle_with_transport(
            &s,
            &p,
            "response.propose",
            json!({"case_id":cid,"target_user_id":config.response.targets[0].user_id.clone(),"site":"LAB"}),
            &MockTransport(AtomicUsize::new(0)),
        ).unwrap();
        let db = s.ops.lock().unwrap();
        let (mut grant, _) =
            read_grant(&db, &p.tenant, proposal["proposal_id"].as_str().unwrap()).unwrap();
        let mut previous_components = super::super::releases::components();
        previous_components["policy"] = json!("previous-policy-version");
        grant.policy_hash =
            policy_hash_with_components(&config.response, &previous_components).unwrap();
        assert_ne!(grant.policy_hash, policy_hash(&config.response).unwrap());
        let signature = keys[0].sign(&canonical(&grant).unwrap());
        verify_approvals(
            &config.response,
            &grant,
            &[Approval {
                actor: "reviewer1".into(),
                signature_base64: STANDARD.encode(signature.as_ref()),
            }],
        )
        .unwrap();
        assert!(validate_grant(&s, &db, &grant).is_err());
        drop(db);
        drop(s);
        let _ = std::fs::remove_file(path);
    }
}
