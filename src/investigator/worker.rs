//! Durable bounded read-only connector worker. Network work never holds a database transaction.
use super::{connectors, core::Principal, service::Service};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("Missing {key}"))
}
fn stamp(v: &Value, key: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(string(v, key)?)?.with_timezone(&Utc))
}
fn signature(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
fn system(s: &Service, action: &str, payload: Value) -> Result<Value> {
    s.exec(&s.system(), action, payload)
}
fn state(s: &Service, key: &str) -> Result<Value> {
    let value = s.state(key)?;
    Ok(if value.is_object() { value } else { json!({}) })
}
fn validate_window(config: &super::config::Config, payload: &Value) -> Result<()> {
    let start = stamp(payload, "start")?;
    let end = stamp(payload, "end")?;
    if start >= end || end - start > Duration::hours(24) {
        bail!("Investigation window must be positive and at most 24 hours")
    }
    // Validate the same fixed provider query and coverage BEFORE OAuth or charging.
    connectors::query_url("entra", start, end)?;
    let first = DateTime::parse_from_rfc3339(&config.sources.coverage_start)?.with_timezone(&Utc);
    let last = DateTime::parse_from_rfc3339(&config.sources.coverage_end)?.with_timezone(&Utc);
    if start < first || end > last {
        bail!("Case interval is outside verified source coverage")
    }
    Ok(())
}
fn failed_request(s: &Service, cid: &str, source: &str, reason: &str) -> Result<()> {
    let key = format!("worker:usage:{cid}");
    let mut usage = state(s, &key)?;
    usage["failed_attempts"] = json!(
        usage["failed_attempts"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(1)
    );
    s.set_state(&key, usage)?;
    s.audit(
        "query.failed",
        json!({"case_id":cid,"source":source,"reason":reason,"at":Utc::now()}),
    )
}

fn release_matches(release: &Value) -> bool {
    release["status"] == "active"
        && release["package"]["components"] == super::releases::components()
}
fn a1_ready(s: &Service) -> Result<bool> {
    if s.stopped() || s.config.a1_gate().is_err() || s.monthly_budget()?["can_reserve_call"] != true
    {
        return Ok(false);
    }
    let release = state(s, "release:active")?;
    if !release_matches(&release) {
        return Ok(false);
    }
    let n = state(s, "notification:health")?;
    if n["status"] != "passed"
        || stamp(&n, "checked_at").map_or(true, |t| {
            t < Utc::now() - Duration::hours(24) || t > Utc::now()
        })
    {
        return Ok(false);
    }
    for source in ["entra", "defender"] {
        let h = state(s, &format!("health:{source}"))?;
        if h["status"] != "passed"
            || stamp(&h, "expires_at").map_or(true, |t| t <= Utc::now())
            || stamp(&h, "checked_at").map_or(true, |t| {
                t < Utc::now() - Duration::hours(1) || t > Utc::now()
            })
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn renew(s: &Service, owner: &str) -> Result<bool> {
    let mut db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Worker state lock poisoned"))?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key='worker:lease'",
            [&s.config.tenant],
            |r| r.get(0),
        )
        .optional()?;
    let Some(raw) = raw else { return Ok(false) };
    let mut lease: Value = serde_json::from_str(&raw)?;
    if lease["owner"] != owner || stamp(&lease, "expires_at").map_or(true, |t| t <= Utc::now()) {
        return Ok(false);
    }
    lease["expires_at"] = json!(Utc::now() + Duration::seconds(90));
    tx.execute(
        "UPDATE investigator_service_state SET value=?2 WHERE tenant=?1 AND key='worker:lease'",
        params![s.config.tenant, lease.to_string()],
    )?;
    tx.commit()?;
    Ok(true)
}
pub(crate) fn ready_for_call(s: &Service, owner: &str, job: &Value) -> Result<bool> {
    if !renew(s, owner)? {
        return Ok(false);
    }
    if s.stopped() || (job["payload"]["autonomous"] == true && !a1_ready(s)?) {
        s.set_state(&format!("worker:paused:{}",string(job,"id")?),json!({"paused":true,"reason":"Readiness unavailable; restore approved configuration and source probes before continuing","at":Utc::now()}))?;
        // A short durable deferral lets queued manual probes restore health.
        // Ownership was checked above; never defer a different worker's job.
        if let Some(lease) = job["lease"].as_str() {
            system(
                s,
                "jobs.defer",
                json!({"job_id":job["id"],"lease":lease,"not_before":Utc::now()+Duration::seconds(60)}),
            )?;
        }
        s.set_state("worker:active", Value::Null)?;
        return Ok(false);
    }
    Ok(true)
}
pub fn enqueue(s: &Service, p: &Principal, case: &Value, probe: bool) -> Result<Value> {
    if s.stopped() {
        bail!("Service stopped; no new investigation work")
    }
    s.config.live_gate()?;
    validate_window(&s.config, case)?;
    let payload = json!({"case_id":case["id"],"start":case["start"],"end":case["end"],"probe":probe,
        "question":"Do validated login and alert records distinguish attack from legitimate access?",
        "expected_information_gain":"Correlate outcomes and counterevidence within approved scope; no exfiltration inference",
        "query_version":connectors::CONTRACT_VERSION,"model":"none","trigger_revision":signature(&case["evidence"].as_array().map(|rows|rows.iter().map(|r|json!([r["source"],r["source_id"],r["content_hash"],r["revisions"].as_array().and_then(|a|a.last()).map(|v|v["hash"].clone())])).collect::<Vec<_>>()).unwrap_or_default().into())});
    let mut payload = payload;
    payload["dedupe_key"] = json!(signature(&payload));
    s.exec(p, "jobs.enqueue", payload)
}

/// Reserve both persistent API count and monetary cost before every attempted request.
pub(crate) fn charge(s: &Service, cid: &str, job: &str) -> Result<()> {
    if s.stopped() {
        bail!("Service stopped")
    }
    let key = format!("worker:usage:{cid}");
    {
        let mut db = s
            .ops
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker state lock poisoned"))?;
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
            .unwrap_or(json!({}));
        let calls = usage["calls"].as_u64().unwrap_or(0);
        let runtime = usage["runtime_ms"].as_u64().unwrap_or(0);
        if runtime.saturating_add(15_000)
            > s.config.budgets.case_runtime_seconds.saturating_mul(1000)
        {
            bail!("Cumulative case runtime budget exhausted")
        }
        if calls >= s.config.budgets.case_api_calls {
            bail!("Cumulative case API budget exhausted")
        }
        if usage["bytes"].as_u64().unwrap_or(0) >= s.config.budgets.case_result_bytes {
            bail!("Cumulative case result budget exhausted")
        }
        usage["calls"] = json!(calls + 1);
        usage["runtime_ms"] = json!(runtime.saturating_add(15_000));
        usage["last_job"] = json!(job);
        tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,?2,?3) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value",params![s.config.tenant,key,usage.to_string()])?;
        tx.commit()?;
    }
    let reservation = uuid::Uuid::new_v4().to_string();
    system(
        s,
        "budgets.reserve",
        json!({"case_id":cid,"reservation_id":reservation,"amount_micros":s.config.budgets.api_call_cost_micros}),
    )?;
    // Conservative accounting includes failed attempts and interrupted requests.
    system(
        s,
        "budgets.settle",
        json!({"case_id":cid,"reservation_id":reservation,"actual_micros":s.config.budgets.api_call_cost_micros}),
    )?;
    if s.stopped() {
        bail!("Service stopped before request")
    }
    Ok(())
}
fn coverage(s: &Service, cid: &str, source: &str, status: &str, reason: &str) -> Result<()> {
    system(
        s,
        "evidence.ingest",
        json!({"case_id":cid,"evidence":[],"coverage":[{"source":source,"status":status,"reason":reason,"observed_at":Utc::now(),"owner":s.config.operations.connector_owner}]}),
    )?;
    Ok(())
}
fn finish(s: &Service, job: &Value, success: bool) -> Result<()> {
    let cid = string(&job["payload"], "case_id")?;
    let _ = system(s, "cases.analyze", json!({"case_id":cid}));
    system(
        s,
        if success {
            "jobs.complete"
        } else {
            "jobs.fail"
        },
        json!({"job_id":job["id"],"lease":job["lease"]}),
    )?;
    s.set_state("worker:active", Value::Null)?;
    Ok(())
}
fn health(s: &Service, source: &str, passed: bool, reason: &str) -> Result<()> {
    s.set_state(&format!("health:{source}"),json!({"source":source,"status":if passed{"passed"}else{"failed"},"checked_at":Utc::now(),"expires_at":Utc::now()+Duration::hours(1),"reason":reason,"contract_version":connectors::CONTRACT_VERSION}))
}
fn retry_delay(message: &str) -> Option<u64> {
    if !message.contains("HTTP 429") && !message.contains("HTTP 503") {
        return None;
    }
    Some(
        message
            .split("retry_after_seconds=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(1, 3600),
    )
}
fn run_job(s: &Service, job: &Value, owner: &str) -> Result<()> {
    if !ready_for_call(s, owner, job)? {
        return Ok(());
    }
    let payload = &job["payload"];
    let cid = string(payload, "case_id")?;
    let jid = string(job, "id")?;
    let jobkey = format!("worker:job:{jid}");
    let mut progress = state(s, &jobkey)?;
    if progress["next_at"]
        .as_str()
        .is_some_and(|x| DateTime::parse_from_rfc3339(x).is_ok_and(|d| d > Utc::now()))
    {
        return Ok(());
    }
    validate_window(&s.config, payload)?;
    let used = progress["runtime_ms"].as_u64().unwrap_or(0);
    if used.saturating_add(30_000) > s.config.budgets.case_runtime_seconds * 1000 {
        coverage(
            s,
            cid,
            "all",
            "budget_exhausted",
            "Job runtime budget exhausted; partial report requires review",
        )?;
        return finish(s, job, false);
    }
    let source = if progress["source"].as_u64().unwrap_or(0) == 0 {
        "defender"
    } else {
        "entra"
    };
    let start = stamp(payload, "start")?;
    let end = stamp(payload, "end")?;
    let qkey = format!(
        "worker:query:{}",
        signature(&json!([
            cid,
            source,
            start,
            end,
            connectors::CONTRACT_VERSION,
            payload["trigger_revision"]
        ]))
    );
    let mut query = state(s, &qkey)?;
    if query["complete"] == true {
        return next_source(s, owner, job, progress, source);
    }
    let pages = query["pages"].as_u64().unwrap_or(0);
    if pages >= 10 {
        coverage(s, cid, source, "truncated", "Ten-page limit reached")?;
        health(s, source, false, "Pagination budget exhausted")?;
        return finish(s, job, false);
    }
    s.audit("query.start",json!({"case_id":cid,"job_id":jid,"source":source,"question":payload["question"],"expected_information_gain":payload["expected_information_gain"],"query_signature":qkey,"cursor_hash":query["next"].as_str().map(|v|signature(&json!(v))),"start":start,"end":end,"query_version":connectors::CONTRACT_VERSION,"model":"none"}))?;
    // Reserve the maximum timeout BEFORE each call, so a crash cannot erase runtime.
    progress["runtime_ms"] = json!(used + 30_000);
    s.set_state(&jobkey, progress.clone())?;
    if !ready_for_call(s, owner, job)? {
        return Ok(());
    }
    if let Err(e) = charge(s, cid, jid) {
        coverage(s, cid, source, "budget_exhausted", &e.to_string())?;
        return finish(s, job, false);
    }
    if !ready_for_call(s, owner, job)? {
        return Ok(());
    }
    let access = match connectors::token(&s.config) {
        Ok(t) => t,
        Err(e) => {
            failed_request(s, cid, "oauth", &e.to_string())?;
            health(s, source, false, &e.to_string())?;
            coverage(s, cid, source, "authentication_failed", &e.to_string())?;
            if payload["autonomous"] == true {
                let _ = ready_for_call(s, owner, job)?;
                return Ok(());
            }
            return finish(s, job, false);
        }
    };
    if !ready_for_call(s, owner, job)? {
        return Ok(());
    }
    if let Err(e) = charge(s, cid, jid) {
        coverage(s, cid, source, "budget_exhausted", &e.to_string())?;
        return finish(s, job, false);
    }
    if !ready_for_call(s, owner, job)? {
        return Ok(());
    }
    let result = connectors::fetch(
        &s.config,
        &access,
        source,
        start,
        end,
        query["next"].as_str(),
    );
    match result {
        Err(e) => {
            let reason = e.to_string();
            failed_request(s, cid, source, &reason)?;
            health(s, source, false, &reason)?;
            if payload["autonomous"] == true {
                coverage(s, cid, source, "paused_source_unavailable", &reason)?;
                let _ = ready_for_call(s, owner, job)?;
                return Ok(());
            }
            let attempts = progress["retries"].as_u64().unwrap_or(0);
            if let Some(delay) = retry_delay(&reason).filter(|_| attempts < 2) {
                progress["retries"] = json!(attempts + 1);
                progress["next_at"] = json!(Utc::now() + Duration::seconds(delay as i64));
                s.set_state(&jobkey, progress)?;
                coverage(s, cid, source, "retry_pending", &reason)?;
                return Ok(());
            }
            coverage(s, cid, source, "unavailable", &reason)?;
            finish(s, job, false)
        }
        Ok(page) => {
            let usagekey = format!("worker:usage:{cid}");
            let mut usage = state(s, &usagekey)?;
            let bytes = usage["bytes"]
                .as_u64()
                .unwrap_or(0)
                .saturating_add(page.bytes);
            usage["bytes"] = json!(bytes);
            s.set_state(&usagekey, usage)?;
            if bytes > s.config.budgets.case_result_bytes {
                coverage(
                    s,
                    cid,
                    source,
                    "truncated",
                    "Cumulative result byte budget exhausted; excess page discarded; no followup requests",
                )?;
                health(s, source, false, "Result byte budget exceeded")?;
                return finish(s, job, false);
            }
            let evidence = page
                .records
                .iter()
                .map(|r| connectors::normalize(source, r, page.fetched_at))
                .collect::<Result<Vec<_>>>()?;
            system(
                s,
                "evidence.ingest",
                json!({"case_id":cid,"evidence":evidence,"coverage":[{"source":source,"status":if page.next.is_none(){"available"}else{"partial"},"start":start,"end":end,"checked_at":page.fetched_at,"contract_version":page.query_version,"retention_attested":true,"model":"none"}]}),
            )?;
            if payload["alarm_intake"] == true && source == "defender" {
                for alert in &page.records {
                    if !ready_for_call(s, owner, job)? {
                        return Ok(());
                    }
                    create_alarm(s, payload, alert)?
                }
            }
            let mut seen = query["seen"].as_array().cloned().unwrap_or_default();
            if let Some(next) = &page.next {
                if seen.iter().any(|v| v.as_str() == Some(next)) {
                    coverage(
                        s,
                        cid,
                        source,
                        "truncated",
                        "Repeated pagination cursor blocked",
                    )?;
                    return finish(s, job, false);
                }
                seen.push(json!(next));
            }
            query = json!({"pages":pages+1,"next":page.next,"seen":seen,"complete":page.next.is_none(),"checked_at":Utc::now()});
            s.set_state(&qkey, query.clone())?;
            progress["retries"] = json!(0);
            progress["next_at"] = Value::Null;
            s.set_state(&jobkey, progress.clone())?;
            if query["complete"] == true {
                health(
                    s,
                    source,
                    true,
                    "Bounded query completed inside operator-attested coverage",
                )?;
                next_source(s, owner, job, progress, source)
            } else {
                Ok(())
            }
        }
    }
}
fn next_source(
    s: &Service,
    owner: &str,
    job: &Value,
    mut progress: Value,
    source: &str,
) -> Result<()> {
    if source == "entra" {
        if s.config.collectors.enabled && job["payload"]["probe"] != true {
            if !ready_for_call(s, owner, job)? {
                return Ok(());
            }
            let case = system(s, "cases.get", json!({"case_id":job["payload"]["case_id"]}))?;
            let collected =
                super::collectors::run_for_worker(s, &case, || ready_for_call(s, owner, job))?;
            if collected["paused"] == true {
                return Ok(());
            }
            for playbook in [
                "token_misuse",
                "endpoint_process_chain",
                "cloud_exfiltration",
                "adcs_esc1",
            ] {
                if !ready_for_call(s, owner, job)? {
                    return Ok(());
                }
                system(
                    s,
                    "playbooks.run",
                    json!({"case_id":case["id"],"playbook_id":playbook}),
                )?;
            }
        }
        finish(s, job, true)
    } else {
        progress["source"] = json!(1);
        s.set_state(&format!("worker:job:{}", string(job, "id")?), progress)
    }
}
fn create_alarm(s: &Service, payload: &Value, alert: &Value) -> Result<()> {
    let release = state(s, "release:active")?;
    if release["status"] != "active" {
        return Ok(());
    }
    let percent = release["canary_percent"].as_u64().unwrap_or(0);
    let hash = Sha256::digest(string(alert, "id")?.as_bytes());
    let bucket = u64::from_be_bytes(hash[..8].try_into().unwrap()) % 100;
    if bucket >= percent {
        return Ok(());
    }
    let dedupe = format!("graph-alert:{}", string(alert, "id")?);
    let markerkey = format!("worker:alert:{}", signature(&json!(dedupe)));
    let marker = state(s, &markerkey)?;
    let digest = signature(alert);
    if marker["content_hash"] == digest {
        return Ok(());
    }
    let case = system(
        s,
        "cases.create",
        json!({"title":alert["title"].as_str().unwrap_or("Security alert"),"site":payload["site"],"start":payload["start"],"end":payload["end"],"dedupe_key":dedupe,"owner":s.config.operations.soc_owner}),
    )?;
    let cid = string(&case, "id")?;
    if case["state"] == "closed" {
        system(
            s,
            "evidence.ingest",
            json!({"case_id":cid,"evidence":[connectors::normalize("defender",alert,Utc::now())?]}),
        )?;
        s.set_state(&markerkey, json!({"content_hash":digest,"case_id":cid}))?;
        return Ok(());
    }
    system(
        s,
        "context.set",
        json!({"case_id":cid,"context":{"source":"Defender alert ingestion","updated_at":Utc::now(),"actual_site":"unknown","scope_site":payload["site"],"asset_criticality":"unknown","provenance":dedupe}}),
    )?;
    system(
        s,
        "evidence.ingest",
        json!({"case_id":cid,"evidence":[connectors::normalize("defender",alert,Utc::now())?]}),
    )?;
    let mut job = json!({"case_id":cid,"start":payload["start"],"end":payload["end"],"probe":false,"autonomous":true,"dedupe_key":format!("{dedupe}:{digest}"),"question":"Investigate new alert with login counterevidence","expected_information_gain":"Distinguish alert from successful unauthorized access"});
    job["model"] = json!("none");
    job["trigger_revision"] = json!(digest);
    system(s, "jobs.enqueue", job)?;
    s.set_state(&markerkey, json!({"content_hash":digest,"case_id":cid}))?;
    Ok(())
}
fn poll(s: &Service) -> Result<()> {
    if !a1_ready(s)? {
        return Ok(());
    }
    let notification = state(s, "notification:health")?;
    if notification["status"] != "passed"
        || stamp(&notification, "checked_at")
            .map_or(true, |at| at < Utc::now() - Duration::hours(24))
    {
        return Ok(());
    }
    let release = state(s, "release:active")?;
    if release["status"] != "active" {
        return Ok(());
    }
    if s.config.a1_gate().is_err()
        || !s
            .config
            .allowed_sites
            .contains(&s.config.operations.alarm_scope_site)
    {
        return Ok(());
    }
    for source in ["defender", "entra"] {
        let h = state(s, &format!("health:{source}"))?;
        if h["status"] != "passed" || stamp(&h, "expires_at").map_or(true, |d| d <= Utc::now()) {
            return Ok(());
        }
    }
    let now = Utc::now();
    let previous = state(s, "worker:poll")?;
    if previous["next_at"]
        .as_str()
        .is_some_and(|t| DateTime::parse_from_rfc3339(t).is_ok_and(|d| d > now))
    {
        return Ok(());
    }
    let seconds = s.config.operations.poll_seconds.max(60) as i64;
    let bucket = now.timestamp() / seconds;
    let end = DateTime::from_timestamp(bucket * seconds, 0).context("Invalid poll window")?;
    let start = end - Duration::minutes(15);
    let dedupe = format!("alarm-intake:{bucket}");
    let c = system(
        s,
        "cases.create",
        json!({"title":"Bounded alert source intake","site":s.config.operations.alarm_scope_site,"start":start,"end":end,"owner":s.config.operations.connector_owner,"dedupe_key":dedupe}),
    )?;
    system(
        s,
        "jobs.enqueue",
        json!({"case_id":c["id"],"dedupe_key":dedupe,"start":start,"end":end,"site":s.config.operations.alarm_scope_site,"alarm_intake":true,"autonomous":true,"question":"Which new stable alert IDs need investigation?","expected_information_gain":"Bounded new alert detection in 15-minute overlap","model":"none"}),
    )?;
    s.set_state(
        "worker:poll",
        json!({"next_at":end+Duration::seconds(seconds),"window_end":end}),
    )
}

fn tick_inner(s: &Service, owner: &str) -> Result<()> {
    // Governance deadlines remain enforced while autonomous work is stopped.
    let sweep = state(s, "worker:sweep")?;
    if stamp(&sweep, "next_at").map_or(true, |d| d <= Utc::now()) {
        if let Ok(cases) = system(s, "cases.list", json!({}))
            && let Some(cases) = cases.as_array()
        {
            for c in cases {
                if !renew(s, owner)? {
                    return Ok(());
                }
                let _ = system(s, "governance.sweep", json!({"case_id":c["id"]}));
            }
        }
        s.set_state(
            "worker:sweep",
            json!({"next_at":Utc::now()+Duration::seconds(60)}),
        )?;
    }
    if !renew(s, owner)? {
        return Ok(());
    }
    super::notifications::tick(s)?;
    if !renew(s, owner)? {
        return Ok(());
    }
    if s.stopped() {
        return Ok(());
    }
    let mut job = state(s, "worker:active")?;
    if job["id"].is_null() || stamp(&job, "lease").map_or(true, |d| d <= Utc::now()) {
        job = system(s, "jobs.claim", json!({}))?;
        if job.is_null() || job["id"].is_null() {
            return poll(s);
        }
        s.set_state("worker:active", job.clone())?;
    }
    if let Err(e) = run_job(s, &job, owner) {
        if !renew(s, owner)? {
            return Ok(());
        }
        let cid = job["payload"]["case_id"].as_str().unwrap_or("");
        let _ = coverage(s, cid, "all", "technical_error", &e.to_string());
        let _ = finish(s, &job, false);
        return Err(e);
    }
    Ok(())
}

/// Cross-process lease covers at most two fixed 15-second calls per tick.
/// Active job checkpoints are consumed only by the current lease holder.
pub fn tick(s: &Service) -> Result<()> {
    let owner = uuid::Uuid::new_v4().to_string();
    {
        let mut db = s
            .ops
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker state lock poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw:Option<String>=tx.query_row("SELECT value FROM investigator_service_state WHERE tenant=?1 AND key='worker:lease'",[&s.config.tenant],|r|r.get(0)).optional()?;
        if let Some(raw) = raw {
            let lease: Value = serde_json::from_str(&raw)?;
            if stamp(&lease, "expires_at").is_ok_and(|t| t > Utc::now()) {
                return Ok(());
            }
        }
        let lease = json!({"owner":owner,"expires_at":Utc::now()+Duration::seconds(90)});
        tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,'worker:lease',?2) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value",params![s.config.tenant,lease.to_string()])?;
        tx.commit()?;
    }
    let result = tick_inner(s, &owner);
    {
        let db = s
            .ops
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker state lock poisoned"))?;
        db.execute("DELETE FROM investigator_service_state WHERE tenant=?1 AND key='worker:lease' AND json_extract(value,'$.owner')=?2",params![s.config.tenant,owner])?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_compiled_release_cannot_authorize_autonomy() {
        let mut release = json!({"status":"active","package":{"components":super::super::releases::components()}});
        assert!(release_matches(&release));
        release["package"]["components"]["policy"] = json!("old-policy");
        assert!(!release_matches(&release));
        release["package"]["components"] = super::super::releases::components();
        release["status"] = json!("awaiting_review");
        assert!(!release_matches(&release));
    }
    #[test]
    fn claimed_autonomous_job_pauses_before_network_when_readiness_lost() {
        let dir = std::env::temp_dir().join(format!("relayne-readiness-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let s = Service::open(
            &dir.join("worker.sqlite"),
            super::super::config::Config::default(),
        )
        .unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        s.set_state(
            "worker:lease",
            json!({"owner":"test-owner","expires_at":Utc::now()+Duration::seconds(90)}),
        )
        .unwrap();
        let job = json!({"id":"queued-before-gate-change","payload":{"case_id":"unqueried","autonomous":true}});
        run_job(&s, &job, "test-owner").unwrap();
        assert_eq!(
            state(&s, "worker:paused:queued-before-gate-change").unwrap()["paused"],
            true
        );
        assert!(state(&s, "worker:usage:unqueried").unwrap()["calls"].is_null());
        assert!(
            ready_for_call(
                &s,
                "test-owner",
                &json!({"id":"manual-probe","payload":{"autonomous":false}})
            )
            .unwrap()
        );
        s.set_state(
            "worker:lease",
            json!({"owner":"other-process","expires_at":Utc::now()+Duration::seconds(90)}),
        )
        .unwrap();
        assert!(!ready_for_call(&s, "test-owner", &job).unwrap());
        drop(s);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn invalid_window_is_rejected_before_any_request() {
        let mut config = super::super::config::Config::default();
        config.sources.coverage_start = "2026-09-19T00:00:00Z".into();
        config.sources.coverage_end = "2026-09-22T00:00:00Z".into();
        assert!(
            validate_window(
                &config,
                &json!({"start":"2026-09-19T00:00:00Z","end":"2026-09-20T00:00:01Z"})
            )
            .is_err()
        );
        assert!(
            validate_window(
                &config,
                &json!({"start":"2026-09-18T23:00:00Z","end":"2026-09-19T01:00:00Z"})
            )
            .is_err()
        );
    }
    #[test]
    fn different_jobs_cannot_reset_persistent_case_runtime() {
        let dir = std::env::temp_dir().join(format!("relayne-runtime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("worker.sqlite");
        let mut config = super::super::config::Config::default();
        config.budgets.case_runtime_seconds = 15;
        let s = Service::open(&path, config.clone()).unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let case=system(&s,"cases.create",json!({"title":"Runtime fixture","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T09:00:00Z"})).unwrap();
        let cid = case["id"].as_str().unwrap().to_string();
        charge(&s, &cid, "first-run").unwrap();
        drop(s);
        let s = Service::open(&path, config).unwrap();
        assert!(
            charge(&s, &cid, "new-human-approved-job")
                .unwrap_err()
                .to_string()
                .contains("runtime")
        );
        assert_eq!(
            state(&s, &format!("worker:usage:{cid}")).unwrap()["runtime_ms"],
            15_000
        );
        drop(s);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn retries_are_bounded_to_transient_contract_statuses() {
        assert_eq!(
            retry_delay("Source entra HTTP 429; retry_after_seconds=90"),
            Some(90)
        );
        assert_eq!(
            retry_delay("Source entra HTTP 503; retry_after_seconds=99999"),
            Some(3600)
        );
        assert_eq!(retry_delay("OAuth failed HTTP 401"), None);
        assert_eq!(retry_delay("Source schema changed"), None);
    }
    #[test]
    fn persisted_query_identity_changes_only_with_scope_or_contract() {
        let query = json!([
            "case",
            "entra",
            "start",
            "end",
            connectors::CONTRACT_VERSION
        ]);
        let a = signature(&query);
        assert_eq!(
            a,
            signature(&serde_json::from_str::<Value>(&query.to_string()).unwrap())
        );
        assert_ne!(
            a,
            signature(&json!([
                "other-case",
                "entra",
                "start",
                "end",
                connectors::CONTRACT_VERSION
            ]))
        );
    }
    #[test]
    fn stop_and_case_budgets_survive_restart_without_network() {
        let dir = std::env::temp_dir().join(format!("relayne-worker-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("worker.sqlite");
        let mut config = super::super::config::Config::default();
        config.budgets.case_api_calls = 1;
        let s = Service::open(&path, config.clone()).unwrap();
        s.set_state("stopped", json!(false)).unwrap();
        let case=system(&s,"cases.create",json!({"title":"Budget fixture","site":"LAB","start":"2026-09-20T08:00:00Z","end":"2026-09-20T09:00:00Z"})).unwrap();
        let cid = case["id"].as_str().unwrap().to_string();
        charge(&s, &cid, "first").unwrap();
        assert!(charge(&s, &cid, "second").is_err());
        s.set_state("stopped", json!(true)).unwrap();
        tick(&s).unwrap();
        drop(s);
        let reopened = Service::open(&path, config).unwrap();
        assert!(reopened.stopped());
        assert_eq!(
            state(&reopened, &format!("worker:usage:{cid}")).unwrap()["calls"],
            1
        );
        assert!(charge(&reopened, &cid, "third").is_err());
        tick(&reopened).unwrap();
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn another_worker_lease_prevents_shared_active_job_execution() {
        let dir = std::env::temp_dir().join(format!("relayne-worker-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("worker.sqlite");
        let s = Service::open(&path, super::super::config::Config::default()).unwrap();
        s.set_state(
            "worker:lease",
            json!({"owner":"other-process","expires_at":Utc::now()+Duration::minutes(1)}),
        )
        .unwrap();
        s.set_state("worker:active", json!({"id":"must-not-execute"}))
            .unwrap();
        tick(&s).unwrap();
        assert_eq!(
            state(&s, "worker:active").unwrap()["id"],
            "must-not-execute"
        );
        drop(s);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
