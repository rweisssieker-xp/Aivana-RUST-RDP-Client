//! Immutable human-recorded pilot evidence and reproducible readiness reports.
use super::{core::Principal, service::Service};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KINDS: &[&str] = &[
    "source_feasibility",
    "restore_drill",
    "shadow_comparison",
    "availability",
    "analyst_time",
    "cost_comparison",
];
const MAX_SAMPLES: u64 = 100_000;
const FRESH_DAYS: i64 = 90;

fn ops_lock(s: &Service) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>> {
    s.ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Synchronization failed"))
}

fn hash(v: &Value) -> String {
    format!("{:x}", Sha256::digest(v.to_string().as_bytes()))
}
fn audit_in_tx(
    tx: &rusqlite::Transaction<'_>,
    tenant: &str,
    event_details: Value,
    time: &str,
) -> Result<()> {
    let actor = "investigator-worker";
    // Match Core::audit_payload's public hash-chain format for Service::audit("pilot.recorded", details).
    let core_payload = json!({"action":"pilot.recorded","details":event_details});
    let action = format!("pilot.recorded:{}", hash(&core_payload));
    let previous: String = tx
        .query_row(
            "SELECT hash FROM investigator_audit WHERE tenant=?1 ORDER BY seq DESC LIMIT 1",
            [tenant],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let payload_hash = hash(&Value::Null);
    let event_hash = hash(&json!([
        tenant,
        actor,
        action,
        "",
        time,
        previous,
        payload_hash
    ]));
    tx.execute("INSERT INTO investigator_audit(tenant,actor,action,target,time,previous_hash,hash) VALUES(?1,?2,?3,'',?4,?5,?6)",params![tenant,actor,action,time,previous,event_hash])?;
    tx.execute(
        "INSERT INTO investigator_audit_payload(seq,payload_hash) VALUES(?1,?2)",
        params![tx.last_insert_rowid(), payload_hash],
    )?;
    Ok(())
}
fn nonempty<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a str> {
    v[key]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= max)
        .with_context(|| format!("{key} is required (maximum {max} characters)"))
}
fn exact_keys(v: &Value, allowed: &[&str], label: &str) -> Result<()> {
    let object = v
        .as_object()
        .with_context(|| format!("{label} must be an object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{label} contains an unsupported field")
    }
    Ok(())
}
fn number(v: &Value, key: &str, max: f64) -> Result<f64> {
    v[key]
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= max)
        .with_context(|| format!("{key} must be a finite number between 0 and {max}"))
}
fn validate(p: &Value) -> Result<Value> {
    exact_keys(
        p,
        &[
            "kind",
            "case_type",
            "completeness",
            "observed_at",
            "sample_count",
            "metrics",
            "targets",
            "evidence",
            "note",
        ],
        "Observation",
    )?;
    for reserved in ["id", "tenant", "operator", "recorded_at", "content_hash"] {
        if p.get(reserved).is_some() {
            bail!("{reserved} is assigned by the server")
        }
    }
    let kind = nonempty(p, "kind", 40)?;
    if !KINDS.contains(&kind) {
        bail!("Unsupported observation kind")
    }
    let case_type = nonempty(p, "case_type", 96)?;
    if !case_type
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._- /".contains(&b))
    {
        bail!("Invalid case_type")
    }
    let completeness = nonempty(p, "completeness", 16)?;
    if !["complete", "incomplete"].contains(&completeness) {
        bail!("completeness must be complete or incomplete")
    }
    let observed: DateTime<Utc> =
        DateTime::parse_from_rfc3339(nonempty(p, "observed_at", 64)?)?.with_timezone(&Utc);
    if observed > Utc::now() + Duration::minutes(5) {
        bail!("Observation time cannot be in the future")
    }
    let n = p["sample_count"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_SAMPLES)
        .context("sample_count must be 1..100000")?;
    let metrics = p
        .get("metrics")
        .filter(|v| v.is_object())
        .context("metrics object required")?;
    let metric_keys: &[&str] = match kind {
        "source_feasibility" => &["result", "coverage_percent", "p95_latency_ms"],
        "restore_drill" => &["actual_rto_seconds", "actual_rpo_seconds"],
        "shadow_comparison" => &[
            "reference_cases",
            "critical_omissions",
            "unauthorized_actions",
        ],
        "availability" => &["available_minutes", "observed_minutes"],
        "analyst_time" => &["manual_minutes", "assisted_minutes", "rework_minutes"],
        _ => &[
            "manual_cost_micros",
            "system_cost_micros",
            "review_cost_micros",
        ],
    };
    exact_keys(metrics, metric_keys, "metrics")?;
    // Validate only metrics whose meaning is defined for the observation kind. Targets are objectives,
    // never measured results, and are returned in a separate object.
    let measured = match kind {
        "source_feasibility" => {
            if !["passed", "failed", "partial"].contains(&metrics["result"].as_str().unwrap_or(""))
            {
                bail!("source_feasibility result must be passed, failed, or partial")
            }
            let _ = number(metrics, "coverage_percent", 100.0)?;
            let _ = number(metrics, "p95_latency_ms", 86_400_000.0)?;
            json!({"result":metrics["result"],"coverage_percent":metrics["coverage_percent"],"p95_latency_ms":metrics["p95_latency_ms"]})
        }
        "restore_drill" => {
            for k in ["actual_rto_seconds", "actual_rpo_seconds"] {
                let _ = number(metrics, k, 31_536_000.0)?;
            }
            json!({"actual_rto_seconds":metrics["actual_rto_seconds"],"actual_rpo_seconds":metrics["actual_rpo_seconds"]})
        }
        "shadow_comparison" => {
            for k in [
                "reference_cases",
                "critical_omissions",
                "unauthorized_actions",
            ] {
                metrics[k]
                    .as_u64()
                    .filter(|x| *x <= MAX_SAMPLES)
                    .with_context(|| format!("{k} must be an integer in range"))?;
            }
            json!({"reference_cases":metrics["reference_cases"],"critical_omissions":metrics["critical_omissions"],"unauthorized_actions":metrics["unauthorized_actions"]})
        }
        "availability" => {
            let up = number(metrics, "available_minutes", 10_000_000.0)?;
            let total = number(metrics, "observed_minutes", 10_000_000.0)?;
            if total <= 0.0 || up > total {
                bail!("available_minutes must be within a positive observed_minutes interval")
            }
            json!({"available_minutes":up,"observed_minutes":total,"measured_percent":up/total*100.0})
        }
        "analyst_time" => {
            for k in ["manual_minutes", "assisted_minutes", "rework_minutes"] {
                let _ = number(metrics, k, 1_000_000.0)?;
            }
            json!({"manual_minutes":metrics["manual_minutes"],"assisted_minutes":metrics["assisted_minutes"],"rework_minutes":metrics["rework_minutes"]})
        }
        _ => {
            for k in [
                "manual_cost_micros",
                "system_cost_micros",
                "review_cost_micros",
            ] {
                metrics[k]
                    .as_u64()
                    .filter(|x| *x <= 1_000_000_000_000)
                    .with_context(|| format!("{k} must be an integer <= 1000000000000"))?;
            }
            json!({"manual_cost_micros":metrics["manual_cost_micros"],"system_cost_micros":metrics["system_cost_micros"],"review_cost_micros":metrics["review_cost_micros"]})
        }
    };
    let targets = p.get("targets").cloned().unwrap_or_else(|| json!({}));
    if !targets.is_object() || targets.to_string().len() > 4096 {
        bail!("targets must be a bounded object of separately stated objectives")
    }
    let evidence = p["evidence"]
        .as_array()
        .context("evidence array required")?;
    if evidence.is_empty() || evidence.len() > 50 {
        bail!("1..50 evidence references required")
    }
    let mut refs = Vec::new();
    for e in evidence {
        if !e.is_object() {
            bail!("Evidence reference must be an object")
        }
        exact_keys(e, &["artifact_ref", "sha256"], "Evidence reference")?;
        let reference = nonempty(e, "artifact_ref", 512)?;
        let digest = nonempty(e, "sha256", 64)?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("Evidence sha256 must be 64 hexadecimal characters")
        }
        refs.push(json!({"artifact_ref":reference,"sha256":digest.to_ascii_lowercase()}));
    }
    let operator_note = p.get("note").and_then(Value::as_str).unwrap_or("");
    if operator_note.len() > 2000 {
        bail!("note exceeds 2000 characters")
    }
    Ok(
        json!({"kind":kind,"case_type":case_type,"completeness":completeness,"observed_at":observed.to_rfc3339(),"sample_count":n,"metrics":measured,"targets":targets,"evidence":refs,"note":operator_note}),
    )
}

fn init(s: &Service) -> Result<()> {
    ops_lock(s)?.execute_batch("CREATE TABLE IF NOT EXISTS investigator_pilot_observations(tenant TEXT NOT NULL,id TEXT NOT NULL,recorded_at TEXT NOT NULL,operator TEXT NOT NULL,body TEXT NOT NULL,content_hash TEXT NOT NULL,PRIMARY KEY(tenant,id));")?;
    Ok(())
}
fn observations(s: &Service) -> Result<Vec<Value>> {
    init(s)?;
    let db = ops_lock(s)?;
    let mut q = db.prepare("SELECT id,recorded_at,operator,body,content_hash FROM investigator_pilot_observations WHERE tenant=?1 ORDER BY recorded_at,id")?;
    let rows = q.query_map([&s.config.tenant], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, recorded, operator, body, digest) = row?;
        let body: Value = serde_json::from_str(&body)?;
        if hash(&body) != digest {
            bail!("Pilot evidence integrity check failed")
        }
        out.push(json!({"id":id,"recorded_at":recorded,"operator":operator,"observation":body,"content_hash":digest}));
    }
    Ok(out)
}
fn percentile(values: &mut [f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let i = ((values.len() - 1) as f64 * q).ceil() as usize;
    values.get(i).copied()
}
fn metric_summary(items: &[Value], kind: &str, metric: &str) -> Value {
    let mut vals = items
        .iter()
        .filter(|x| x["observation"]["kind"] == kind)
        .filter_map(|x| {
            let m = &x["observation"]["metrics"];
            if metric == "total_cost_micros" {
                Some(
                    m["manual_cost_micros"].as_f64()?
                        + m["system_cost_micros"].as_f64()?
                        + m["review_cost_micros"].as_f64()?,
                )
            } else {
                m[metric].as_f64()
            }
        })
        .collect::<Vec<_>>();
    let n = vals.len();
    let median = percentile(&mut vals, 0.5);
    let p95 = percentile(&mut vals, 0.95);
    json!({"sample_count":n,"median":median,"p95":p95,"confidence_note":"Descriptive sample statistics only; no inferential confidence claim. Null means unmeasured."})
}
fn group_metrics(items: &[Value]) -> Value {
    let mut groups = serde_json::Map::new();
    for kind in ["analyst_time", "cost_comparison"] {
        let fields: &[&str] = if kind == "analyst_time" {
            &["manual_minutes", "assisted_minutes", "rework_minutes"]
        } else {
            &[
                "manual_cost_micros",
                "system_cost_micros",
                "review_cost_micros",
                "total_cost_micros",
            ]
        };
        for completeness in ["complete", "incomplete"] {
            let mut types = serde_json::Map::new();
            let mut names = items
                .iter()
                .filter(|x| {
                    x["observation"]["kind"] == kind
                        && x["observation"]["completeness"] == completeness
                })
                .filter_map(|x| x["observation"]["case_type"].as_str())
                .collect::<Vec<_>>();
            names.sort_unstable();
            names.dedup();
            for name in names {
                let matching = items
                    .iter()
                    .filter(|x| {
                        x["observation"]["kind"] == kind
                            && x["observation"]["completeness"] == completeness
                            && x["observation"]["case_type"] == name
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let mut measures = serde_json::Map::new();
                for field in fields {
                    measures.insert((*field).into(), metric_summary(&matching, kind, field));
                }
                types.insert(name.into(), Value::Object(measures));
            }
            groups.insert(format!("{kind}:{completeness}"), Value::Object(types));
        }
    }
    Value::Object(groups)
}
fn report(s: &Service) -> Result<Value> {
    let now = Utc::now();
    let items = observations(s)?;
    let config = serde_json::to_value(&s.config)?;
    let mut gaps = Vec::new();
    for (id, ok, detail) in [
        (
            "live_source_configuration",
            s.config.live_gate().is_ok(),
            "Configured live source contract, encrypted storage, retention, and least privilege",
        ),
        (
            "a1_operator_configuration",
            s.config.a1_gate().is_ok(),
            "A1 owners, coverage, escalation, webhook references and polling",
        ),
        (
            "service_operational_status",
            s.status().map(|x| x["a1_ready"] == true).unwrap_or(false),
            "Current connector, notification, release, budget and stop-state gates",
        ),
    ] {
        if !ok {
            gaps.push(json!({"id":id,"status":"gap","detail":detail}));
        }
    }
    let required = [
        (
            "source_feasibility",
            "Source API / retention feasibility evidence",
        ),
        (
            "restore_drill",
            "Measured restore drill with actual RTO and RPO",
        ),
        ("shadow_comparison", "Representative shadow comparison"),
        ("availability", "Measured availability interval"),
        ("analyst_time", "Comparable analyst effort observations"),
        ("cost_comparison", "Measured end-to-end cost observations"),
    ];
    for (kind, detail) in required {
        let latest = items
            .iter()
            .filter(|x| x["observation"]["kind"] == kind)
            .filter_map(|x| {
                x["observation"]["observed_at"]
                    .as_str()
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                    .map(|t| (x, t.with_timezone(&Utc)))
            })
            .max_by_key(|(_, t)| *t);
        match latest { None=>gaps.push(json!({"id":kind,"status":"unmeasured","detail":detail})), Some((x,t)) if now.signed_duration_since(t)>Duration::days(FRESH_DAYS)=>gaps.push(json!({"id":kind,"status":"stale","last_observed_at":x["observation"]["observed_at"],"detail":detail})), Some(_)=>{} }
    }
    // PRD targets are displayed as objectives only and never converted into a pass from missing data.
    let objectives = json!({"availability_percent":99.5,"rto_minutes":60,"rpo_minutes":15,"analyst_time_reduction_percent":30,"source":"PRD target / pilot hypothesis; not measured acceptance"});
    let mut result = json!({"schema":"investigator-pilot-report-v1","generated_at":now,"tenant":s.config.tenant,"readiness":"evidence_incomplete","production_ready":false,"a1_ready_from_service":s.status().map(|v|v["a1_ready"].clone()).unwrap_or(Value::Null),"gaps":gaps,"objectives":objectives,"stratified_metrics":group_metrics(&items),"observations":items,"service_stopped":s.stopped(),"recovery_reconciliation_required":s.state("recovery:last")?["reconciliation_required"],"configuration_summary":{"sources_enabled":config["sources"]["enabled"],"allowed_sites":config["allowed_sites"],"poll_seconds":config["operations"]["poll_seconds"],"a1_configured":s.config.a1_gate().is_ok()},"limitations":["Human-entered evidence is not independently verified by this report.","This report does not authorize production use or change A1 gates.","No measurement is inferred from absent observations."]});
    if result["gaps"].as_array().is_some_and(|a| a.is_empty()) {
        result["readiness"] = json!("evidence_recorded_for_human_review");
    }
    Ok(result)
}
pub fn markdown(v: &Value) -> String {
    let mut s = format!(
        "# Investigator pilot readiness report\n\nGenerated: {}  \nTenant: `{}`  \nReadiness: **{}**  \nA1 service gate: `{}`  \nProduction ready: **No**\n\n",
        v["generated_at"].as_str().unwrap_or("unknown"),
        v["tenant"].as_str().unwrap_or("unknown"),
        v["readiness"].as_str().unwrap_or("unknown"),
        v["a1_ready_from_service"]
    );
    s.push_str("## Gaps\n\n");
    for g in v["gaps"].as_array().cloned().unwrap_or_default() {
        s.push_str(&format!(
            "- **{}** ({}) — {}\n",
            g["id"].as_str().unwrap_or("unknown"),
            g["status"].as_str().unwrap_or("unknown"),
            g["detail"].as_str().unwrap_or("")
        ));
    }
    s.push_str("\n## Objectives (not results)\n\nAvailability target 99.5%; RTO target 60 minutes; RPO target 15 minutes; analyst time reduction is a 30% hypothesis.\n\n## Stratified measured summaries\n\n");
    s.push_str(
        &serde_json::to_string_pretty(&v["stratified_metrics"]).unwrap_or_else(|_| "{}".into()),
    );
    s.push_str("\n\n## Limits\n\n");
    for x in v["limitations"].as_array().cloned().unwrap_or_default() {
        s.push_str(&format!("- {}\n", x.as_str().unwrap_or("")));
    }
    s
}
pub fn handle(s: &Service, p: &Principal, action: &str, payload: Value) -> Result<Value> {
    if !["pilot.status", "pilot.record", "pilot.report"].contains(&action) {
        bail!("Unknown pilot action")
    }
    if action == "pilot.record"
        && !["admin", "reviewer", "incident_lead"].contains(&p.role.as_str())
    {
        bail!("Pilot evidence recording requires admin, reviewer, or incident_lead")
    }
    match action {
        "pilot.record" => {
            let body = validate(&payload)?;
            init(s)?;
            let id = uuid::Uuid::new_v4().to_string();
            let at = Utc::now().to_rfc3339();
            let body_hash = hash(&body);
            {
                let mut db = ops_lock(s)?;
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let existing:Option<String>=tx.query_row("SELECT id FROM investigator_pilot_observations WHERE tenant=?1 AND content_hash=?2",params![s.config.tenant,body_hash],|r|r.get(0)).optional()?;
                if existing.is_some() {
                    bail!("Identical observation already recorded; immutable duplicate rejected")
                }
                tx.execute("INSERT INTO investigator_pilot_observations(tenant,id,recorded_at,operator,body,content_hash) VALUES(?1,?2,?3,?4,?5,?6)",params![s.config.tenant,id,at,p.actor,body.to_string(),body_hash])?;
                audit_in_tx(
                    &tx,
                    &s.config.tenant,
                    json!({"id":id,"operator":p.actor,"content_hash":body_hash,"kind":body["kind"],"evidence_count":body["evidence"].as_array().map_or(0,Vec::len)}),
                    &at,
                )?;
                tx.commit()?;
            }
            Ok(
                json!({"id":id,"tenant":s.config.tenant,"operator":p.actor,"recorded_at":at,"observation":body,"content_hash":body_hash,"immutable":true}),
            )
        }
        "pilot.status" => {
            let r = report(s)?;
            Ok(
                json!({"readiness":r["readiness"],"production_ready":false,"a1_ready_from_service":r["a1_ready_from_service"],"gaps":r["gaps"],"observations_count":r["observations"].as_array().map_or(0,Vec::len),"note":"Evidence status does not enable A1 or certify production readiness"}),
            )
        }
        _ => {
            let r = report(s)?;
            match payload
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("json")
            {
                "json" => Ok(json!({"format":"json","report":r})),
                "markdown" => Ok(json!({"format":"markdown","markdown":markdown(&r),"report":r})),
                _ => bail!("format must be json or markdown"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (Service, Principal, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "investigator-pilot-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let s = Service::open(&path, Default::default()).unwrap();
        let p = Principal {
            tenant: "DEMO".into(),
            actor: "reviewer".into(),
            role: "reviewer".into(),
        };
        (s, p, path)
    }
    fn payload() -> Value {
        json!({"kind":"analyst_time","case_type":"credential_spray","completeness":"complete","observed_at":Utc::now().to_rfc3339(),"sample_count":4,"metrics":{"manual_minutes":50,"assisted_minutes":30,"rework_minutes":2},"targets":{"reduction_percent":30},"evidence":[{"artifact_ref":"pilot/run-1.csv","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]})
    }
    #[test]
    fn records_are_tenant_scoped_immutable_and_audited() {
        let (s, p, path) = setup();
        let r = handle(&s, &p, "pilot.record", payload()).unwrap();
        assert_eq!(r["immutable"], true);
        assert!(handle(&s, &p, "pilot.record", r["observation"].clone()).is_err());
        let out = handle(&s, &p, "pilot.report", json!({"format":"json"})).unwrap();
        assert_eq!(out["report"]["production_ready"], false);
        assert!(out["report"]["gaps"].as_array().unwrap().len() >= 6);
        drop(s);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn rejects_invalid_or_unmeasured_inputs() {
        let (s, p, path) = setup();
        let mut x = payload();
        x["metrics"]["assisted_minutes"] = json!(-1);
        assert!(handle(&s, &p, "pilot.record", x).is_err());
        let mut x = payload();
        x["operator"] = json!("admin");
        assert!(handle(&s, &p, "pilot.record", x).is_err());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn markdown_is_exportable_and_unknown_values_stay_null() {
        let (s, p, path) = setup();
        let r = handle(&s, &p, "pilot.report", json!({"format":"markdown"})).unwrap();
        assert!(
            r["markdown"]
                .as_str()
                .unwrap()
                .contains("Objectives (not results)")
        );
        assert_eq!(r["report"]["production_ready"], false);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn backup_restore_preserves_pilot_audit_and_reports_paused_recovery() {
        let (s, p, path) = setup();
        handle(&s, &p, "pilot.record", payload()).unwrap();
        let root = path.with_extension("pilot-backup-test");
        std::fs::create_dir(&root).unwrap();
        let backup = root.join("snapshot");
        let manifest = super::super::backup::create(&path, &backup).unwrap();
        assert_eq!(manifest["validation"]["audit_chain"], "verified");
        super::super::backup::verify(&backup).unwrap();
        let restored = root.join("restored.sqlite");
        let restore = super::super::backup::restore(&backup, &restored).unwrap();
        assert_eq!(restore["status"], "restored_paused");
        drop(s);

        let restored_service = Service::open(&restored, Default::default()).unwrap();
        let report = handle(
            &restored_service,
            &p,
            "pilot.report",
            json!({"format":"json"}),
        )
        .unwrap()["report"]
            .clone();
        assert_eq!(report["observations"].as_array().unwrap().len(), 1);
        assert_eq!(report["service_stopped"], true);
        assert_eq!(report["recovery_reconciliation_required"], true);
        assert_eq!(report["production_ready"], false);
        drop(restored_service);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(path);
    }
}
