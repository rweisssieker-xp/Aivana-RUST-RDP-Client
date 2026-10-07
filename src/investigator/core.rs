//! Persistent, tenant-scoped investigation domain. No network or response permissions.
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Principal {
    pub tenant: String,
    pub actor: String,
    pub role: String,
}
pub struct Core {
    db: Connection,
    config: Value,
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .with_context(|| format!("Missing {key}"))
}
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn hash(v: &Value) -> String {
    format!("{:x}", Sha256::digest(v.to_string().as_bytes()))
}
fn site_allowed(config: &Value, site: &Value) -> bool {
    match config.get("allowed_sites") {
        None => true,
        Some(allowed) => allowed.as_array().is_some_and(|sites| sites.contains(site)),
    }
}
fn effective_fields(e: &Value) -> &Value {
    e["revisions"]
        .as_array()
        .and_then(|r| r.last())
        .map(|r| &r["fields"])
        .unwrap_or(&e["fields"])
}
fn evidence_current(e: &Value, now: DateTime<Utc>) -> bool {
    e["retrieval_status"] != "expired"
        && e["retention_until"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|t| t > now)
}
fn review_hash(c: &Value) -> Value {
    json!(hash(&json!([
        c["evidence"],
        c["findings"],
        c["coverage"],
        c["questions"],
        c["actions"],
        c["risks"],
        c["decisions"],
        c["playbooks"],
        c["context"]
    ])))
}
fn purge_expired_evidence(value: &mut Value, now: DateTime<Utc>) {
    match value {
        Value::Object(map) => {
            let expired = map
                .get("retention_until")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .is_some_and(|t| t <= now);
            if expired && map.contains_key("content_hash") {
                map.insert("fields".into(), json!({}));
                map.insert("revisions".into(), json!([]));
                map.insert("retrieval_status".into(), json!("expired"));
            }
            for v in map.values_mut() {
                purge_expired_evidence(v, now);
            }
        }
        Value::Array(items) => {
            for v in items {
                purge_expired_evidence(v, now);
            }
        }
        _ => {}
    }
}
fn permit(p: &Principal, roles: &[&str]) -> Result<()> {
    if (roles.is_empty() && p.role == "system") || roles.contains(&p.role.as_str()) {
        Ok(())
    } else {
        bail!("Forbidden role for action")
    }
}
impl Core {
    pub fn open(path: &Path, config: Value) -> Result<Self> {
        let mut config = config;
        if config.get("versions").is_none() {
            config["versions"] = super::releases::components();
        }
        for (target, source) in [
            ("case_limit_micros", "case_cost_micros"),
            ("month_limit_micros", "monthly_cost_micros"),
        ] {
            if config.get(target).is_none()
                && let Some(value) = config.get("budgets").and_then(|b| b.get(source)).cloned()
            {
                config[target] = value;
            }
        }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;
CREATE TABLE IF NOT EXISTS investigator_cases(tenant TEXT NOT NULL,id TEXT NOT NULL,version INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS investigator_case_keys(tenant TEXT NOT NULL,key TEXT NOT NULL,case_id TEXT NOT NULL,PRIMARY KEY(tenant,key));
CREATE TABLE IF NOT EXISTS investigator_audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,time TEXT NOT NULL,previous_hash TEXT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS investigator_audit_payload(seq INTEGER PRIMARY KEY,payload_hash TEXT NOT NULL); CREATE TABLE IF NOT EXISTS investigator_jobs(tenant TEXT NOT NULL,id TEXT NOT NULL,case_id TEXT NOT NULL,dedupe TEXT NOT NULL,state TEXT NOT NULL,lease TEXT,attempts INTEGER NOT NULL DEFAULT 0,body TEXT NOT NULL,PRIMARY KEY(tenant,id),UNIQUE(tenant,dedupe));
CREATE TABLE IF NOT EXISTS investigator_budget(tenant TEXT NOT NULL,id TEXT NOT NULL,case_id TEXT NOT NULL,month TEXT NOT NULL,amount INTEGER NOT NULL,actual INTEGER,state TEXT NOT NULL,PRIMARY KEY(tenant,id));")?;
        Ok(Self { db, config })
    }
    pub fn execute(
        &mut self,
        p: &Principal,
        action: &str,
        payload: Value,
        now: DateTime<Utc>,
    ) -> Result<Value> {
        if p.tenant.trim().is_empty() || p.actor.trim().is_empty() {
            bail!("Authenticated identity required")
        }
        if let Some(t) = self.config.get("tenant").and_then(Value::as_str)
            && t != p.tenant
        {
            bail!("Tenant denied")
        }
        if payload
            .get("tenant")
            .and_then(Value::as_str)
            .is_some_and(|t| t != p.tenant)
        {
            bail!("Tenant denied")
        }
        if ![
            "viewer",
            "analyst",
            "operator",
            "incident_lead",
            "risk_owner",
            "reviewer",
            "admin",
            "system",
        ]
        .contains(&p.role.as_str())
        {
            bail!("Unknown role")
        }
        let config = self.config.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = Self::dispatch(&tx, &config, p, action, &payload, now);
        match result {
            Ok(value) => {
                if !matches!(
                    action,
                    "cases.list" | "cases.get" | "audit.list" | "notifications.list"
                ) {
                    Self::audit_payload(
                        &tx,
                        p,
                        action,
                        payload.get("case_id").and_then(Value::as_str).unwrap_or(""),
                        now,
                        &payload,
                    )?;
                }
                tx.commit()?;
                Ok(value)
            }
            Err(e) => {
                tx.rollback()?;
                let denied_tx = self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                Self::audit_payload(
                    &denied_tx,
                    p,
                    &format!("denied:{action}"),
                    "",
                    now,
                    &payload,
                )?;
                denied_tx.commit()?;
                Err(e)
            }
        }
    }
    fn audit(
        db: &Connection,
        p: &Principal,
        action: &str,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        Self::audit_payload(db, p, action, target, now, &Value::Null)
    }
    fn audit_payload(
        db: &Connection,
        p: &Principal,
        action: &str,
        target: &str,
        now: DateTime<Utc>,
        payload: &Value,
    ) -> Result<()> {
        let previous: String = db
            .query_row(
                "SELECT hash FROM investigator_audit WHERE tenant=?1 ORDER BY seq DESC LIMIT 1",
                [&p.tenant],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_default();
        let time = now.to_rfc3339();
        let payload_hash = hash(payload);
        db.execute_batch("CREATE TABLE IF NOT EXISTS investigator_audit_payload(seq INTEGER PRIMARY KEY,payload_hash TEXT NOT NULL)")?;
        let digest = hash(&json!([
            p.tenant,
            p.actor,
            action,
            target,
            time,
            previous,
            payload_hash
        ]));
        db.execute("INSERT INTO investigator_audit(tenant,actor,action,target,time,previous_hash,hash) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![p.tenant,p.actor,action,target,time,previous,digest])?;
        db.execute(
            "INSERT INTO investigator_audit_payload(seq,payload_hash) VALUES(?1,?2)",
            params![db.last_insert_rowid(), payload_hash],
        )?;
        Ok(())
    }
    fn get(db: &Connection, p: &Principal, id: &str) -> Result<Value> {
        let body: String = db
            .query_row(
                "SELECT body FROM investigator_cases WHERE tenant=?1 AND id=?2",
                params![p.tenant, id],
                |r| r.get(0),
            )
            .optional()?
            .context("Case not found in tenant")?;
        Ok(serde_json::from_str(&body)?)
    }
    fn save(db: &Connection, p: &Principal, c: &mut Value, now: DateTime<Utc>) -> Result<()> {
        let version = c["version"].as_u64().unwrap_or(0) + 1;
        c["version"] = json!(version);
        c["updated_at"] = json!(now);
        db.execute(
            "UPDATE investigator_cases SET version=?3,body=?4 WHERE tenant=?1 AND id=?2",
            params![p.tenant, field(c, "id")?, version, c.to_string()],
        )?;
        Ok(())
    }
    fn dispatch(
        db: &Connection,
        config: &Value,
        p: &Principal,
        action: &str,
        v: &Value,
        now: DateTime<Utc>,
    ) -> Result<Value> {
        match action {
            "audit.record" => {
                permit(p, &[])?;
                let event = field(v, "action")?;
                let target = v.get("target").and_then(Value::as_str).unwrap_or("");
                Self::audit(db, p, &format!("{event}:{}", hash(v)), target, now)?;
                return Ok(json!({"recorded":true}));
            }
            "jobs.status" => {
                let mut q=db.prepare("SELECT id,case_id,state,lease,attempts FROM investigator_jobs WHERE tenant=?1 ORDER BY rowid DESC LIMIT 1000")?;
                let rows=q.query_map([&p.tenant],|r|Ok(json!({"id":r.get::<_,String>(0)?,"case_id":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,"lease":r.get::<_,Option<String>>(3)?,"attempts":r.get::<_,i64>(4)?})))?;
                return Ok(json!(rows.collect::<rusqlite::Result<Vec<_>>>()?));
            }
            "cases.create" => {
                permit(
                    p,
                    &["admin", "analyst", "operator", "incident_lead", "system"],
                )?;
                let dedupe = v
                    .get("dedupe_key")
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|s| !s.is_empty() && s.len() <= 512)
                            .context("Invalid dedupe key")
                    })
                    .transpose()?;
                if let Some(key) = dedupe {
                    let previous: Option<String> = db
                        .query_row(
                            "SELECT case_id FROM investigator_case_keys WHERE tenant=?1 AND key=?2",
                            params![p.tenant, key],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if let Some(existing) = previous {
                        let existing_case = Self::get(db, p, &existing)?;
                        if !site_allowed(config, &existing_case["site"]) {
                            bail!("Case site no longer approved")
                        }
                        return Ok(existing_case);
                    }
                }
                let site = field(v, "site")?;
                if !site_allowed(config, &json!(site)) {
                    bail!("Site not approved")
                }
                let start = DateTime::parse_from_rfc3339(field(v, "start")?)?;
                let end = DateTime::parse_from_rfc3339(field(v, "end")?)?;
                if start >= end {
                    bail!("Invalid investigation interval")
                }
                let cid = id();
                let c = json!({"id":cid,"tenant":p.tenant,"version":1,"title":field(v,"title")?,"site":site,"start":start,"end":end,"owner":v.get("owner").and_then(Value::as_str).filter(|s|!s.trim().is_empty()).unwrap_or(p.actor.as_str()),"state":"new","created_at":now,"updated_at":now,"versions":config.get("versions").cloned().unwrap_or(json!({"model":"deterministic-1","prompt":"none-1","playbook":"login-spray-1","query":"1","policy":"1","normalization":"1"})),"evidence":[],"coverage":[],"hypotheses":[],"findings":[],"questions":[],"actions":[],"risks":[],"decisions":[],"reviews":[],"playbooks":[],"history":[],"notifications":[],"context":{},"budget_limit_micros":config.get("case_limit_micros").and_then(Value::as_i64).unwrap_or(1000000)});
                db.execute(
                    "INSERT INTO investigator_cases(tenant,id,version,body) VALUES(?1,?2,1,?3)",
                    params![p.tenant, cid, c.to_string()],
                )?;
                if let Some(key) = dedupe {
                    db.execute(
                        "INSERT INTO investigator_case_keys(tenant,key,case_id) VALUES(?1,?2,?3)",
                        params![p.tenant, key, cid],
                    )?;
                }
                return Ok(c);
            }
            "cases.list" => {
                let mut q =
                    db.prepare("SELECT body FROM investigator_cases WHERE tenant=?1 ORDER BY id")?;
                let rows = q.query_map([&p.tenant], |r| r.get::<_, String>(0))?;
                let mut out = Vec::new();
                for row in rows {
                    let mut summary = serde_json::from_str::<Value>(&row?)?;
                    if !site_allowed(config, &summary["site"]) {
                        continue;
                    }
                    if let Some(object) = summary.as_object_mut() {
                        object.remove("history");
                        object.remove("evidence");
                    }
                    out.push(summary);
                }
                return Ok(json!(out));
            }
            "playbooks.catalog" => return Ok(super::playbooks::catalog()),
            "audit.list" => {
                let mut q=db.prepare("SELECT a.seq,a.actor,a.action,a.target,a.time,a.previous_hash,a.hash,p.payload_hash FROM investigator_audit a LEFT JOIN investigator_audit_payload p ON a.seq=p.seq WHERE a.tenant=?1 ORDER BY a.seq")?;
                let rows=q.query_map([&p.tenant],|r|Ok(json!({"seq":r.get::<_,i64>(0)?,"actor":r.get::<_,String>(1)?,"action":r.get::<_,String>(2)?,"target":r.get::<_,String>(3)?,"time":r.get::<_,String>(4)?,"previous_hash":r.get::<_,String>(5)?,"hash":r.get::<_,String>(6)?,"payload_hash":r.get::<_,Option<String>>(7)?})))?;
                return Ok(json!(rows.collect::<rusqlite::Result<Vec<_>>>()?));
            }
            "jobs.claim" => {
                permit(p, &[])?;
                let job:Option<(String,String)>=db.query_row("SELECT id,body FROM investigator_jobs WHERE tenant=?1 AND (state='queued' OR (state IN ('running','deferred') AND lease<?2)) ORDER BY rowid LIMIT 1",params![p.tenant,now.to_rfc3339()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                if let Some((jid, body)) = job {
                    let lease = (now + chrono::Duration::minutes(5)).to_rfc3339();
                    db.execute("UPDATE investigator_jobs SET state='running',lease=?3,attempts=attempts+1 WHERE tenant=?1 AND id=?2",params![p.tenant,jid,lease])?;
                    return Ok(
                        json!({"id":jid,"lease":lease,"payload":serde_json::from_str::<Value>(&body)?}),
                    );
                }
                return Ok(Value::Null);
            }
            "jobs.defer" => {
                permit(p, &[])?;
                let until = DateTime::parse_from_rfc3339(field(v, "not_before")?)?;
                if until <= now || until > now + chrono::Duration::hours(1) {
                    bail!("Deferred job requires bounded future time");
                }
                let n=db.execute("UPDATE investigator_jobs SET state='deferred',lease=?5 WHERE tenant=?1 AND id=?2 AND state='running' AND lease=?3 AND lease>?4",params![p.tenant,field(v,"job_id")?,field(v,"lease")?,now.to_rfc3339(),until.to_rfc3339()])?;
                if n != 1 {
                    bail!("Job lease lost");
                }
                return Ok(json!({"state":"deferred","not_before":until}));
            }
            "jobs.complete" | "jobs.fail" => {
                permit(p, &[])?;
                let state = if action == "jobs.complete" {
                    "completed"
                } else {
                    "failed"
                };
                let n=db.execute("UPDATE investigator_jobs SET state=?3,lease=NULL WHERE tenant=?1 AND id=?2 AND state='running' AND lease=?4",params![p.tenant,field(v,"job_id")?,state,field(v,"lease")?])?;
                if n != 1 {
                    bail!("Job lease lost")
                }
                return Ok(json!({"state":state}));
            }
            _ => {}
        }
        let cid = field(v, "case_id")?;
        let mut c = Self::get(db, p, cid)?;
        if !site_allowed(config, &c["site"]) {
            bail!("Case site no longer approved")
        }
        let mut prior_snapshot = c.clone();
        if let Some(obj) = prior_snapshot.as_object_mut() {
            obj.remove("history");
        }
        if matches!(action, "cases.get" | "cases.export") {
            return Ok(c);
        }
        if action == "notifications.list" {
            return Ok(c["notifications"].clone());
        }
        permit(
            p,
            &[
                "admin",
                "analyst",
                "operator",
                "incident_lead",
                "risk_owner",
                "reviewer",
                "system",
            ],
        )?;
        if let Some(expected) = v.get("expected_version").and_then(Value::as_u64)
            && c["version"].as_u64() != Some(expected)
        {
            bail!("Version conflict")
        }
        let was_closed = c["state"] == "closed";
        if was_closed
            && !matches!(
                action,
                "cases.reopen" | "governance.sweep" | "evidence.ingest"
            )
        {
            bail!("Closed case requires explicit reopening")
        }
        match action {
            "evidence.ingest" => {
                let events = v
                    .get("evidence")
                    .and_then(Value::as_array)
                    .context("evidence array required")?;
                if events.len() > 10000 {
                    bail!("Evidence limit exceeded")
                }
                let mut contradictions = Vec::new();
                for event in events {
                    let source = field(event, "source")?;
                    field(event, "query_version")?;
                    let retention_until =
                        event.get("retention_until").cloned().unwrap_or_else(|| {
                            json!(
                                now + chrono::Duration::days(
                                    config
                                        .get("retention_days")
                                        .and_then(Value::as_i64)
                                        .unwrap_or(30)
                                        .clamp(1, 3650)
                                )
                            )
                        });
                    let retention = DateTime::parse_from_rfc3339(
                        retention_until
                            .as_str()
                            .context("Retention must be UTC timestamp")?,
                    )?;
                    if retention
                        > now
                            + chrono::Duration::days(
                                config
                                    .get("retention_days")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(30)
                                    .clamp(1, 3650),
                            )
                    {
                        bail!("Evidence retention exceeds approved policy");
                    }
                    let event_time = DateTime::parse_from_rfc3339(field(event, "event_time")?)?;
                    let case_start = DateTime::parse_from_rfc3339(field(&c, "start")?)?;
                    let case_end = DateTime::parse_from_rfc3339(field(&c, "end")?)?;
                    if event_time < case_start || event_time > case_end {
                        bail!("Evidence outside case interval")
                    }
                    if event
                        .get("tenant")
                        .and_then(Value::as_str)
                        .is_some_and(|t| t != p.tenant)
                    {
                        bail!("Cross-tenant evidence")
                    }
                    let content = event.get("fields").cloned().unwrap_or(json!({}));
                    let digest = hash(&content);
                    let native = event
                        .get("source_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| hash(&json!([source, event_time, content])));
                    let key = format!("{source}:{native}");
                    let evs = c["evidence"].as_array_mut().unwrap();
                    if let Some(fact_key) = content.get("fact_key").and_then(Value::as_str) {
                        for prior in evs.iter() {
                            let fields = effective_fields(prior);
                            if fields["fact_key"] == fact_key
                                && fields.get("value").is_some()
                                && content.get("value").is_some()
                                && fields["value"] != content["value"]
                            {
                                contradictions.push(json!({"key":format!("fact:{fact_key}:{}:{}",prior["id"],digest),"reason":"Conflicting source facts require review","source_evidence":prior["id"],"incoming_source":source,"incoming_source_id":native}));
                            }
                        }
                    }
                    if let Some(existing) = evs.iter_mut().find(|e| e["key"] == key) {
                        existing["retrievals"].as_array_mut().unwrap().push(json!({"time":now,"status":event.get("retrieval_status").cloned().unwrap_or(json!("success")),"hash":digest}));
                        let latest_hash = existing["revisions"]
                            .as_array()
                            .and_then(|r| r.last())
                            .map(|r| &r["hash"])
                            .unwrap_or(&existing["content_hash"]);
                        if latest_hash != &json!(digest) {
                            contradictions.push(json!({"key":format!("revision:{}:{digest}",existing["id"]),"reason":"Material source revision conflicts with earlier observation","source_evidence":existing["id"],"incoming_source":source,"incoming_source_id":native}));
                            existing["revisions"]
                                .as_array_mut()
                                .unwrap()
                                .push(json!({"time":now,"fields":content,"hash":digest}));
                        }
                    } else {
                        evs.push(json!({"id":id(),"key":key,"source":source,"source_id":native,"tenant":p.tenant,"event_time":event_time,"retrieved_at":now,"content_hash":digest,"fields":content,"query_version":field(event,"query_version")?,"retention_until":retention_until,"retrieval_status":event.get("retrieval_status").cloned().unwrap_or(json!("success")),"retrievals":[{"time":now,"hash":digest}],"revisions":[]}));
                    }
                }
                for contradiction in contradictions {
                    let key = contradiction["key"].clone();
                    if !c["questions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|q| q["contradiction_key"] == key)
                    {
                        let question = json!({"id":id(),"version":1,"question":contradiction["reason"],"owner":c["owner"],"due_at":now+chrono::Duration::hours(4),"status":"open","assessment":"not_decidable","contradiction_key":key,"contradiction":contradiction});
                        c["questions"].as_array_mut().unwrap().push(question);
                    }
                }
                if let Some(coverage) = v.get("coverage").and_then(Value::as_array) {
                    for gap in coverage {
                        field(gap, "source")?;
                        field(gap, "status")?;
                        let rows = c["coverage"].as_array_mut().unwrap();
                        if let Some(current) = rows.iter_mut().find(|current| {
                            current["source"] == gap["source"]
                                && current["instance_id"].as_str().unwrap_or("legacy")
                                    == gap["instance_id"].as_str().unwrap_or("legacy")
                                && current.get("provider").unwrap_or(&current["source"])
                                    == gap.get("provider").unwrap_or(&gap["source"])
                                && current["start"] == gap["start"]
                                && current["end"] == gap["end"]
                        }) {
                            *current = gap.clone();
                        } else {
                            rows.push(gap.clone());
                        }
                    }
                }
                if was_closed {
                    c["reopening_proposal"] = json!({"reason":"Late evidence requires human assessment","created_at":now,"trigger":"material_evidence"});
                    Self::notify(
                        &mut c,
                        &format!("late-evidence-{}", now.timestamp()),
                        "U1",
                        "Closed case received late evidence; reopening requires human decision",
                        now,
                    );
                } else {
                    c["state"] = json!("investigating");
                }
            }
            "context.set" => {
                let context = v.get("context").context("context required")?;
                field(context, "source")?;
                DateTime::parse_from_rfc3339(field(context, "updated_at")?)?;
                c["context"] = context.clone();
            }
            "cases.analyze" => {
                Self::analyze(&mut c, now)?;
            }
            "playbooks.run" => {
                let playbook_id = field(v, "playbook_id")?;
                let prior_runs = c["playbooks"].as_array().map_or(0, Vec::len);
                let _result = super::playbooks::run(&mut c, playbook_id, now)?;
                let changed = c["playbooks"].as_array().map_or(0, Vec::len) != prior_runs;
                if !changed {
                    return Ok(c);
                }
                for review in c["reviews"].as_array_mut().into_iter().flatten() {
                    if review
                        .get("reviewed_content_hash")
                        .and_then(Value::as_str)
                        .is_some()
                    {
                        review["invalidated_at"] = json!(now);
                        review["invalidation_reason"] =
                            json!("New deterministic playbook result requires review");
                    }
                }
                if c["situation_playbooks"]["findings"]
                    .as_array()
                    .is_some_and(|findings| findings.iter().any(|f| f["status"] == "suspected"))
                {
                    let urgency = if c["context"]["tier0"] == true
                        || c["context"]["asset_criticality"] == "critical"
                    {
                        "U0"
                    } else {
                        "U1"
                    };
                    let key = c["situation_playbooks"]["latest_run_id"]
                        .as_str()
                        .unwrap_or(playbook_id)
                        .to_owned();
                    Self::notify(
                        &mut c,
                        &format!("playbook-{key}"),
                        urgency,
                        "Deterministic playbook finding requires human review",
                        now,
                    );
                }
            }
            "review.record" => {
                permit(p, &["reviewer", "incident_lead", "admin"])?;
                let mut r = v.clone();
                r["id"] = json!(id());
                r["actor"] = json!(p.actor);
                r["time"] = json!(now);
                r["situation_version"] = c["version"].clone();
                r["reviewed_content_hash"] = review_hash(&c);
                field(v, "decision")?;
                field(v, "reason")?;
                c["reviews"].as_array_mut().unwrap().push(r);
            }
            "questions.upsert" | "actions.upsert" => {
                let key = if action == "questions.upsert" {
                    "questions"
                } else {
                    "actions"
                };
                let mut entity = v.get("entity").cloned().context("entity required")?;
                field(&entity, "owner")?;
                DateTime::parse_from_rfc3339(field(&entity, "due_at")?)?;
                if key == "actions" {
                    field(&entity, "decision_owner")?;
                    entity["verification"] = json!("pending");
                    if entity["status"] == "not_applicable" {
                        permit(p, &["reviewer", "incident_lead"])?;
                        field(&entity, "reason")?;
                        entity["verification"] = json!("not_applicable_reviewed");
                        entity["verifier"] = json!(p.actor);
                    }
                } else {
                    field(&entity, "question")?;
                    let assessment = entity
                        .get("assessment")
                        .and_then(Value::as_str)
                        .unwrap_or("not_decidable");
                    if ![
                        "proven",
                        "suspected",
                        "no_evidence_with_coverage",
                        "excluded_within_scope",
                        "not_decidable",
                    ]
                    .contains(&assessment)
                    {
                        bail!("Unknown investigation assessment")
                    }
                    if assessment == "excluded_within_scope" {
                        permit(p, &["reviewer"])?;
                        for key in [
                            "scope",
                            "start",
                            "end",
                            "coverage_review",
                            "counterhypotheses_review",
                        ] {
                            field(&entity, key)?;
                        }
                        let start = DateTime::parse_from_rfc3339(field(&entity, "start")?)?;
                        let end = DateTime::parse_from_rfc3339(field(&entity, "end")?)?;
                        if start >= end
                            || start < DateTime::parse_from_rfc3339(field(&c, "start")?)?
                            || end > DateTime::parse_from_rfc3339(field(&c, "end")?)?
                        {
                            bail!("Exclusion must be within case scope and interval")
                        }
                        let sources = entity
                            .get("required_sources")
                            .and_then(Value::as_array)
                            .filter(|s| !s.is_empty())
                            .context("Required exclusion sources missing")?;
                        if let Some(original) = c["questions"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|q| q["id"] == entity["id"] && !entity["id"].is_null())
                            && original["required_sources"]
                                .as_array()
                                .is_some_and(|required| {
                                    required.iter().any(|source| !sources.contains(source))
                                })
                        {
                            bail!("Required sources cannot be removed from an exclusion assessment")
                        }
                        for source in sources {
                            if source.as_str().is_none_or(|source| {
                                !super::playbooks::covered_interval(&c, source, start, end)
                            }) {
                                bail!("Missing required source coverage prevents exclusion")
                            }
                        }
                        if entity
                            .get("evidence_ids")
                            .and_then(Value::as_array)
                            .is_none_or(|ids| {
                                ids.is_empty()
                                    || ids.iter().any(|eid| {
                                        !c["evidence"]
                                            .as_array()
                                            .unwrap()
                                            .iter()
                                            .any(|e| &e["id"] == eid && evidence_current(e, now))
                                    })
                            })
                        {
                            bail!("Nonexpired evidence required for exclusion")
                        }
                    }
                    entity["assessment"] = json!(assessment);
                    if entity["status"] == "answered" {
                        permit(p, &["reviewer", "incident_lead"])?;
                        field(&entity, "answer")?;
                        if entity
                            .get("evidence_ids")
                            .and_then(Value::as_array)
                            .is_none_or(|a| {
                                a.is_empty()
                                    || a.iter().any(|eid| {
                                        !c["evidence"]
                                            .as_array()
                                            .unwrap()
                                            .iter()
                                            .any(|e| &e["id"] == eid)
                                    })
                            })
                        {
                            bail!("Answer requires existing case evidence")
                        }
                    }
                }
                entity["updated_at"] = json!(now);
                Self::upsert(&mut c, key, entity)?;
            }
            "suppliers.upsert" | "sites.assess" | "recovery.gate" => {
                let key = match action {
                    "suppliers.upsert" => "suppliers",
                    "sites.assess" => "sites",
                    _ => "recovery_gates",
                };
                let mut entity = v.get("entity").cloned().context("entity required")?;
                field(&entity, "owner")?;
                field(&entity, "scope")?;
                if key == "suppliers" {
                    for f in [
                        "questions",
                        "deliverables",
                        "evidence_requirements",
                        "effort_provenance",
                    ] {
                        field(&entity, f)?;
                    }
                    entity["acceptance"] = json!("pending");
                }
                if key == "sites" {
                    field(&entity, "site")?;
                    field(&entity, "coverage")?;
                    let status = entity
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("not_checked");
                    if ![
                        "not_checked",
                        "in_progress",
                        "finding",
                        "no_evidence_in_scope",
                        "insufficient_data",
                        "not_applicable",
                    ]
                    .contains(&status)
                    {
                        bail!("Unsupported site assessment status");
                    }
                    if status == "no_evidence_in_scope" {
                        permit(p, &["reviewer", "incident_lead"])?;
                        let refs = entity
                            .get("evidence_ids")
                            .and_then(Value::as_array)
                            .context("Reviewed site evidence is required")?;
                        if refs.is_empty()
                            || refs.iter().any(|r| {
                                !c["evidence"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .any(|e| &e["id"] == r)
                            })
                        {
                            bail!(
                                "Existing case evidence required for a positive scoped site assessment"
                            );
                        }
                    }
                    if status == "not_applicable" {
                        field(&entity, "reason")?;
                    }
                    entity["status"] = json!(status);
                    if let Some(sites) = config.get("allowed_sites").and_then(Value::as_array)
                        && !sites.iter().any(|s| s == &entity["site"])
                    {
                        bail!("Site not approved")
                    }
                    entity["origin_snapshot_digest"] =
                        json!(super::site_matrix::assessment_snapshot_digest(&c));
                }
                if key == "recovery_gates" {
                    permit(p, &["risk_owner"])?;
                    for key in [
                        "remediation_evidence_id",
                        "function_test_evidence_id",
                        "monitoring_evidence_id",
                    ] {
                        let proof = field(&entity, key)?;
                        if !c["evidence"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|e| e["id"] == proof && evidence_current(e, now))
                        {
                            bail!(
                                "Recovery requires current remediation, functional-test and monitoring evidence"
                            );
                        }
                    }
                    for key in [
                        "operator",
                        "fallback_plan",
                        "allowed_identities",
                        "access_hours",
                    ] {
                        field(&entity, key)?;
                    }
                    let rid = field(&entity, "risk_id")?;
                    let risk = c["risks"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["id"] == rid)
                        .context("Risk decision required")?;
                    if risk["status"] != "accepted"
                        || DateTime::parse_from_rfc3339(field(risk, "expires_at")?)? <= now
                    {
                        bail!("Valid unexpired risk decision required")
                    }
                    entity["risk_owner"] = json!(p.actor);
                    entity["status"] = json!("human_approved");
                }
                if c.get(key).is_none() {
                    c[key] = json!([])
                }
                Self::upsert(&mut c, key, entity)?;
            }
            "suppliers.accept" => {
                permit(p, &["incident_lead", "reviewer"])?;
                field(v, "reason")?;
                let evidence_id = field(v, "evidence_id")?;
                if !c["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["id"] == evidence_id)
                {
                    bail!("Deliverable evidence required")
                }
                let supplier = c
                    .get_mut("suppliers")
                    .and_then(Value::as_array_mut)
                    .context("No suppliers")?
                    .iter_mut()
                    .find(|s| s["id"] == v["supplier_id"])
                    .context("Supplier missing")?;
                if supplier["owner"] == p.actor {
                    bail!("Independent deliverable acceptance required");
                }
                supplier["acceptance"] = json!("human_accepted");
                supplier["accepted_by"] = json!(p.actor);
                supplier["accepted_at"] = json!(now);
                supplier["acceptance_evidence_id"] = json!(evidence_id);
            }
            "actions.verify" => {
                permit(p, &["reviewer", "incident_lead", "admin"])?;
                let eid = field(v, "action_id")?;
                let evidence = field(v, "evidence_id")?;
                if !c["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["id"] == evidence && evidence_current(e, now))
                {
                    bail!("Technical evidence required")
                }
                let a = c["actions"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|a| a["id"] == eid)
                    .context("Action not found")?;
                if a["owner"] == p.actor {
                    bail!("Independent verifier required")
                }
                a["verification"] = json!("technically_confirmed");
                a["verifier"] = json!(p.actor);
                a["evidence_id"] = json!(evidence);
                a["verified_at"] = json!(now);
            }
            "risks.accept" => {
                permit(p, &["risk_owner"])?;
                let mut r = v.get("entity").cloned().context("entity required")?;
                for f in ["scope", "residual_risk", "controls", "reason", "expires_at"] {
                    field(&r, f)?;
                }
                if DateTime::parse_from_rfc3339(field(&r, "expires_at")?)? <= now {
                    bail!("Risk acceptance already expired")
                }
                r["risk_owner"] = json!(p.actor);
                r["accepted_at"] = json!(now);
                r["status"] = json!("accepted");
                r["situation_version"] = c["version"].clone();
                Self::upsert(&mut c, "risks", r)?;
            }
            "decisions.record" => {
                permit(p, &["incident_lead", "risk_owner", "admin"])?;
                let mut d = v.get("entity").cloned().context("entity required")?;
                for f in ["reason", "alternatives", "review_at"] {
                    field(&d, f)?;
                }
                DateTime::parse_from_rfc3339(field(&d, "review_at")?)?;
                d["decider"] = json!(p.actor);
                d["situation_version"] = c["version"].clone();
                Self::upsert(&mut c, "decisions", d)?;
            }
            "cases.handoff" => {
                permit(p, &["incident_lead", "reviewer", "admin"])?;
                let owner = field(v, "owner")?;
                if v.get("acknowledged_by").and_then(Value::as_str) != Some(p.actor.as_str())
                    || owner != p.actor
                {
                    bail!("Receiving owner must acknowledge own handoff")
                }
                c["handoff"] = json!({"owner":owner,"acknowledged_at":now,"version":c["version"]});
                c["state"] = json!("handoff_confirmed");
            }
            "cases.close" => {
                permit(p, &["incident_lead", "reviewer"])?;
                if c["handoff"].is_null()
                    || !c["reviews"].as_array().unwrap().iter().any(|r| {
                        (r["decision"] == "approved" || r["decision"] == "accepted")
                            && r["reviewed_content_hash"] == review_hash(&c)
                    })
                {
                    bail!("Approved review and confirmed handoff required")
                }
                if c["risks"].as_array().unwrap().iter().any(|r| {
                    r["status"] == "expired"
                        || r.get("expires_at")
                            .and_then(Value::as_str)
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .is_some_and(|t| t <= now)
                }) {
                    bail!("Expired risk decisions remain unresolved")
                }
                if c["actions"].as_array().unwrap().iter().any(|a| {
                    a["verification"] != "technically_confirmed"
                        && a["verification"] != "not_applicable_reviewed"
                }) {
                    bail!("Unverified actions remain open")
                }
                if c["questions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|q| q["status"] != "answered")
                {
                    bail!("Unanswered investigation questions")
                }
                c["state"] = json!("closed");
                c["closed_by"] = json!(p.actor);
            }
            "cases.reopen" => {
                let trigger = field(v, "trigger")?;
                if ![
                    "new_source_id",
                    "material_evidence",
                    "source_restored",
                    "human_request",
                ]
                .contains(&trigger)
                {
                    bail!("Invalid reopening trigger")
                }
                field(v, "reason")?;
                c["state"] = json!("investigating");
            }
            "jobs.enqueue" => {
                permit(
                    p,
                    &["admin", "analyst", "operator", "incident_lead", "system"],
                )?;
                let dedupe = field(v, "dedupe_key")?;
                let jid = id();
                db.execute("INSERT OR IGNORE INTO investigator_jobs(tenant,id,case_id,dedupe,state,body) VALUES(?1,?2,?3,?4,'queued',?5)",params![p.tenant,jid,cid,dedupe,v.to_string()])?;
                let actual: String = db.query_row(
                    "SELECT id FROM investigator_jobs WHERE tenant=?1 AND dedupe=?2",
                    params![p.tenant, dedupe],
                    |r| r.get(0),
                )?;
                return Ok(json!({"id":actual}));
            }
            "budgets.reserve" => {
                permit(p, &[])?;
                let amount = v
                    .get("amount_micros")
                    .and_then(Value::as_i64)
                    .filter(|x| *x > 0)
                    .context("Positive conservative reservation required")?;
                let month = now.format("%Y-%m").to_string();
                let reservation = field(v, "reservation_id")?;
                let existing: Option<(String, i64)> = db
                    .query_row(
                        "SELECT case_id,amount FROM investigator_budget WHERE tenant=?1 AND id=?2",
                        params![p.tenant, reservation],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((old_case, old_amount)) = existing {
                    if old_case != cid || old_amount != amount {
                        bail!("Reservation id conflict")
                    }
                    return Ok(json!({"id":reservation,"duplicate":true}));
                }
                let total:i64=db.query_row("SELECT COALESCE(SUM(COALESCE(actual,amount)),0) FROM investigator_budget WHERE tenant=?1 AND case_id=?2",params![p.tenant,cid],|r|r.get(0))?;
                let monthly:i64=db.query_row("SELECT COALESCE(SUM(COALESCE(actual,amount)),0) FROM investigator_budget WHERE tenant=?1 AND month=?2",params![p.tenant,month],|r|r.get(0))?;
                let limit = c["budget_limit_micros"].as_i64().unwrap_or(0);
                let monthly_limit = config
                    .get("month_limit_micros")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if amount > limit.saturating_sub(total)
                    || amount > monthly_limit.saturating_sub(monthly)
                {
                    bail!("Budget exhausted")
                }
                db.execute("INSERT INTO investigator_budget(tenant,id,case_id,month,amount,state) VALUES(?1,?2,?3,?4,?5,'reserved')",params![p.tenant,reservation,cid,month,amount])?;
                c["budget_warning"] =
                    json!(total.saturating_add(amount) >= limit.saturating_mul(80) / 100);
            }
            "budgets.settle" => {
                permit(p, &[])?;
                let actual = v
                    .get("actual_micros")
                    .and_then(Value::as_i64)
                    .filter(|x| *x >= 0)
                    .context("Actual cost required")?;
                let reserved:i64=db.query_row("SELECT amount FROM investigator_budget WHERE tenant=?1 AND case_id=?2 AND id=?3 AND state='reserved'",params![p.tenant,cid,field(v,"reservation_id")?],|r|r.get(0))?;
                if actual > reserved {
                    bail!("Actual exceeds conservative reservation")
                }
                db.execute("UPDATE investigator_budget SET actual=?4,state='settled' WHERE tenant=?1 AND case_id=?2 AND id=?3",params![p.tenant,cid,field(v,"reservation_id")?,actual])?;
            }
            "budgets.increase" => {
                permit(p, &["admin", "risk_owner"])?;
                field(v, "reason")?;
                let limit = v
                    .get("limit_micros")
                    .and_then(Value::as_i64)
                    .context("limit required")?;
                if limit <= c["budget_limit_micros"].as_i64().unwrap_or(0) {
                    bail!("Increase required")
                }
                c["budget_limit_micros"] = json!(limit);
            }
            "notifications.ack" => {
                let nid = field(v, "notification_id")?;
                let n = c["notifications"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|n| n["id"] == nid)
                    .context("Notification missing")?;
                n["acknowledged_by"] = json!(p.actor);
                n["acknowledged_at"] = json!(now);
            }
            "governance.sweep" => {
                let before = c.clone();
                purge_expired_evidence(&mut c, now);
                for r in c["risks"].as_array_mut().unwrap() {
                    if r["status"] == "accepted"
                        && DateTime::parse_from_rfc3339(field(r, "expires_at")?)? <= now
                    {
                        r["status"] = json!("expired")
                    }
                }
                let expired = c["risks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["status"] == "expired")
                    .count();
                if expired > 0 {
                    Self::notify(
                        &mut c,
                        &format!("expired-risks-{expired}"),
                        "U1",
                        "Risk acceptance expired; human decision required",
                        now,
                    );
                }
                for key in ["questions", "actions", "decisions"] {
                    let due: Vec<Value> = c
                        .get(key)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter(|e| {
                            let time = e
                                .get("due_at")
                                .or_else(|| e.get("review_at"))
                                .and_then(Value::as_str)
                                .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
                            time.is_some_and(|t| t <= now)
                                && e["verification"] != "technically_confirmed"
                                && e["status"] != "answered"
                        })
                        .cloned()
                        .collect();
                    for e in due {
                        Self::notify(
                            &mut c,
                            &format!("overdue-{key}-{}", e["id"]),
                            "U1",
                            &format!("Overdue {key}; owner {} must act", e["owner"]),
                            now,
                        );
                    }
                }
                if c == before {
                    return Ok(c);
                }
                purge_expired_evidence(&mut prior_snapshot, now);
            }
            _ => bail!("Unknown action denied"),
        }
        let prior = c["version"].clone();
        c["history"].as_array_mut().unwrap().push(json!({"action":action,"actor":p.actor,"time":now,"previous_version":prior,"snapshot":prior_snapshot}));
        Self::save(db, p, &mut c, now)?;
        Ok(c)
    }
    fn upsert(c: &mut Value, key: &str, mut entity: Value) -> Result<()> {
        let values = c[key].as_array_mut().unwrap();
        if let Some(eid) = entity.get("id").and_then(Value::as_str) {
            let old = values
                .iter_mut()
                .find(|e| e["id"] == eid)
                .context("Entity does not exist")?;
            entity["version"] = json!(old["version"].as_u64().unwrap_or(0) + 1);
            *old = entity;
        } else {
            entity["id"] = json!(id());
            entity["version"] = json!(1);
            values.push(entity)
        }
        Ok(())
    }
    fn notify(c: &mut Value, key: &str, urgency: &str, message: &str, now: DateTime<Utc>) {
        let ns = c["notifications"].as_array_mut().unwrap();
        if !ns.iter().any(|n| n["key"] == key) {
            ns.push(json!({"id":id(),"key":key,"urgency":urgency,"message":message,"created_at":now,"delivery_status":"local_only","acknowledged_at":null}));
        }
    }
    fn analyze(c: &mut Value, now: DateTime<Utc>) -> Result<()> {
        let evs = c["evidence"].as_array().unwrap();
        let mut failures = 0usize;
        let mut successes = Vec::new();
        let mut blocks = Vec::new();
        let mut accounts = std::collections::BTreeSet::new();
        for e in evs {
            if !evidence_current(e, now) {
                continue;
            }
            let f = effective_fields(e);
            let outcome = f.get("outcome").and_then(Value::as_str).or_else(|| {
                f.get("success")
                    .and_then(Value::as_bool)
                    .map(|success| if success { "success" } else { "failure" })
            });
            match outcome {
                Some("failure") => {
                    failures += 1;
                    if let Some(account) = f
                        .get("account")
                        .or_else(|| f.get("user"))
                        .and_then(Value::as_str)
                    {
                        accounts.insert(account.to_owned());
                    }
                }
                Some("success") => successes.push(e["id"].clone()),
                Some("blocked") => blocks.push(e["id"].clone()),
                _ => {}
            }
        }
        let has_gap = c["coverage"].as_array().unwrap().is_empty()
            || evs.iter().any(|e| !evidence_current(e, now))
            || c["coverage"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g["status"] != "available");
        let urgency = if c["context"]["tier0"] == true
            || c["context"]["active_spread"] == true
            || c["context"]["destructive_activity"] == true
        {
            "U0"
        } else if failures >= 20 && !successes.is_empty() {
            "U1"
        } else {
            "U2"
        };
        let fingerprint = hash(&json!([
            failures,
            accounts,
            successes,
            blocks,
            c["coverage"],
            urgency,
            c["context"]
        ]));
        c["priority"] = json!(urgency);
        c["priority_reason"] = json!(if urgency == "U0" {
            "Context reports critical identity/system or active destructive/spreading activity; evidence strength remains separate"
        } else if urgency == "U1" {
            "Repeated failed logins followed by successful authentication require prompt review"
        } else {
            "Bounded login investigation; no critical context supplied"
        });
        c["evidence_strength"] = json!(if has_gap {
            "incomplete"
        } else {
            "bounded_observations"
        });
        c["context_missing"] = json!(c["context"].as_object().is_none_or(|m| m.is_empty()));
        c["context_stale"] = json!(
            c["context"]["updated_at"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .is_none_or(|t| t > now || now.signed_duration_since(t).num_seconds() > 30 * 86400)
        );
        if urgency == "U0" {
            for notification in c["notifications"].as_array_mut().unwrap() {
                if notification.get("snoozed_until").is_some() {
                    notification["snoozed_until"] = Value::Null;
                    notification["snooze_overridden_at"] = json!(now);
                }
            }
        }
        let defaults = json!([
            {"id":id(),"version":1,"question":"Was user-initiated activity legitimate?","owner":c["owner"],"due_at":now+chrono::Duration::hours(4),"required_sources":["user confirmation","approved changes"],"status":"open"},
            {"id":id(),"version":1,"question":"Was resource access or exfiltration observed within the scoped time window?","owner":c["owner"],"due_at":now+chrono::Duration::hours(4),"required_sources":["resource audit","storage","network"],"status":"open"}
        ]);
        for question in defaults.as_array().unwrap() {
            if !c["questions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|q| q["question"] == question["question"])
            {
                c["questions"]
                    .as_array_mut()
                    .unwrap()
                    .push(question.clone());
            }
        }
        c["hypotheses"] = json!([{"id":"attack","claim":"Password spray followed by login","support":successes,"counterevidence":blocks,"status":"unconfirmed"},{"id":"legitimate","claim":"Legitimate user activity","needed":"Independent user confirmation","status":"open"},{"id":"automation","claim":"Automated stale credentials","needed":"Approved job and credential-change context","status":"open"}]);
        c["findings"] = json!([{"id":"login-assessment","rule_version":"login-spray-1","urgency":urgency,"failed_logins":failures,"distinct_accounts":accounts.len(),"successful_login_evidence":successes,"blocked_access_evidence":blocks,"conclusion":"Login success and resource access are separate. No inferred MFA bypass or compromise.","exfiltration":"not_decidable","uncertainty":if has_gap{"Coverage incomplete; no exoneration"}else{"Login telemetry does not establish file access or exfiltration"},"evidence_fingerprint":fingerprint}]);
        c["state"] = json!(if has_gap {
            "partial_review_required"
        } else {
            "review_required"
        });
        Self::notify(
            c,
            &format!("finding-{fingerprint}"),
            urgency,
            "Investigation ready for human review",
            now,
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
