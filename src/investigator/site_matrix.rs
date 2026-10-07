//! Read-only, tenant-scoped cross-site view of explicit assessments.
use super::{core::Principal, service::Service};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const DISPLAY_LIMIT: usize = 20;
const STATUSES: &[&str] = &[
    "not_checked",
    "in_progress",
    "finding",
    "no_evidence_in_scope",
    "insufficient_data",
    "not_applicable",
];

pub(crate) fn assessment_snapshot_digest(case: &Value) -> String {
    let material = json!({
        "tenant":case["tenant"], "case_id":case["id"],
        "start":case["start"], "end":case["end"],
        "evidence":case["evidence"], "coverage":case["coverage"],
        "findings":case["findings"], "hypotheses":case["hypotheses"],
        "situation_playbooks":case["situation_playbooks"],
    });
    format!("{:x}", Sha256::digest(material.to_string().as_bytes()))
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn evidence_refs(item: &Value) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    if let Some(fields) = item.as_object() {
        for (key, value) in fields {
            if (key == "evidence_ids" || key.ends_with("_evidence_ids"))
                && let Some(ids) = value.as_array()
            {
                refs.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
    }
    refs
}

fn targets(case: &Value) -> (Vec<Value>, usize) {
    let mut found = BTreeMap::<String, Value>::new();
    let mut unidentified = 0;
    for (kind, collection) in [
        ("finding", &case["findings"]),
        ("hypothesis", &case["hypotheses"]),
        ("finding", &case["situation_playbooks"]["findings"]),
        ("hypothesis", &case["situation_playbooks"]["hypotheses"]),
    ] {
        for item in collection.as_array().into_iter().flatten() {
            let Some(id) = string(item, "id") else {
                unidentified += 1;
                continue;
            };
            let refs = evidence_refs(item);
            let entry = found.entry(id.to_owned()).or_insert_with(|| {
                json!({
                    "finding_id":id,
                    "finding_status":Value::Null,
                    "hypothesis_status":Value::Null,
                    "evidence_ids":[],
                })
            });
            if kind == "finding" {
                entry["finding_status"] = item.get("status").cloned().unwrap_or(Value::Null);
            } else {
                entry["hypothesis_status"] = item.get("status").cloned().unwrap_or(Value::Null);
            }
            let mut all_refs: BTreeSet<String> = entry["evidence_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            all_refs.extend(refs);
            entry["evidence_ids"] = json!(all_refs);
        }
    }
    (found.into_values().collect(), unidentified)
}

fn assessment_matches(assessment: &Value, target: &Value) -> bool {
    let id = target["finding_id"].as_str().unwrap_or("");
    let refs: BTreeSet<&str> = target["evidence_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let explicit: Vec<&str> = ["finding_id", "hypothesis_id"]
        .iter()
        .filter_map(|key| string(assessment, key))
        .collect();
    if !explicit.is_empty() {
        return explicit.iter().all(|reference| *reference == id);
    }
    if let Some(evidence_id) = string(assessment, "evidence_id") {
        return refs.contains(evidence_id);
    }
    string(assessment, "scope").is_some_and(|scope| scope == id || refs.contains(scope))
}

fn assessment_view(assessment: &Value, case: &Value) -> Value {
    json!({
        "id": assessment["id"], "case_id": case["id"],
        "recorded_in_site": case["site"], "site": assessment["site"],
        "finding_id": assessment["finding_id"], "hypothesis_id": assessment["hypothesis_id"],
        "evidence_id": assessment["evidence_id"], "evidence_ids": assessment["evidence_ids"],
        "scope": assessment["scope"], "coverage": assessment["coverage"],
        "status": assessment["status"], "owner": assessment["owner"],
        "reason": assessment["reason"], "updated_at": assessment["updated_at"],
        "origin_snapshot_digest": assessment["origin_snapshot_digest"],
    })
}

pub fn handle(s: &Service, p: &Principal, payload: Value) -> Result<Value> {
    let object = payload
        .as_object()
        .context("Matrix payload must be an object")?;
    if object.len() != 1 || !object.contains_key("case_id") {
        bail!("Matrix accepts only case_id");
    }
    let case_id = string(&payload, "case_id").context("Case ID required")?;
    Uuid::parse_str(case_id).context("Case ID must be UUID")?;
    if p.tenant != s.config.tenant
        || p.role == "system"
        || !s
            .config
            .users
            .iter()
            .any(|u| u.actor == p.actor && u.role == p.role)
    {
        bail!("Matrix principal not authorized");
    }
    let origin = s.exec(p, "cases.get", json!({"case_id":case_id}))?;
    let origin_site = string(&origin, "site").context("Origin case has no site")?;
    if !s
        .config
        .allowed_sites
        .iter()
        .any(|site| site == origin_site)
    {
        bail!("Origin case site outside current approved scope");
    }
    let all = s.exec(p, "cases.list", json!({}))?;
    let current_snapshot_digest = assessment_snapshot_digest(&origin);
    let cases = all.as_array().context("Invalid case listing")?;
    let mut sites = s.config.allowed_sites.clone();
    sites.sort();
    sites.dedup();
    let (mut findings, unidentified_finding_count) = targets(&origin);

    for finding in &mut findings {
        let mut rows = Vec::new();
        for site in &sites {
            let mut assessments = Vec::new();
            let mut case_refs = Vec::new();
            let mut supplier_handoffs = Vec::new();
            for case in cases {
                let case_site = string(case, "site").unwrap_or("");
                if !sites.iter().any(|approved| approved == case_site) {
                    continue;
                }
                if case_site == site {
                    case_refs.push(json!({"case_id":case["id"],"title":case["title"],
                        "state":case["state"],"updated_at":case["updated_at"],
                        "handoff":case["handoff"]}));
                    for supplier in case["suppliers"].as_array().into_iter().flatten() {
                        supplier_handoffs.push(json!({"case_id":case["id"],"supplier_id":supplier["id"],
                            "scope":supplier["scope"],"owner":supplier["owner"],
                            "acceptance":supplier["acceptance"],"accepted_by":supplier["accepted_by"],
                            "accepted_at":supplier["accepted_at"]}));
                    }
                }
            }
            for assessment in origin["sites"].as_array().into_iter().flatten() {
                if string(assessment, "site") == Some(site.as_str())
                    && assessment_matches(assessment, finding)
                {
                    assessments.push(assessment_view(assessment, &origin));
                }
            }
            let stale_negative = assessments.len() == 1
                && matches!(
                    assessments[0]["status"].as_str(),
                    Some("no_evidence_in_scope" | "not_applicable")
                )
                && assessments[0]["origin_snapshot_digest"].as_str()
                    != Some(current_snapshot_digest.as_str());
            let status = if assessments.is_empty() {
                "not_checked"
            } else if assessments.len() > 1 {
                "requires_review"
            } else if stale_negative {
                "insufficient_data"
            } else {
                assessments[0]["status"]
                    .as_str()
                    .filter(|status| STATUSES.contains(status))
                    .unwrap_or("requires_review")
            }
            .to_owned();
            let coverage = if assessments.len() == 1 && !stale_negative {
                assessments[0]["coverage"].clone()
            } else {
                Value::Null
            };
            let assessment_count = assessments.len();
            let case_count = case_refs.len();
            let supplier_handoff_count = supplier_handoffs.len();
            assessments.truncate(DISPLAY_LIMIT);
            case_refs.truncate(DISPLAY_LIMIT);
            supplier_handoffs.truncate(DISPLAY_LIMIT);
            rows.push(json!({"site":site,"status":status,"coverage":coverage,
                "stale_evidence_binding":stale_negative,
                "reason_code":if stale_negative {Some("stale_evidence_binding")} else {None},
                "assessment_count":assessment_count,"assessments":assessments,
                "assessments_truncated":assessment_count>DISPLAY_LIMIT,
                "case_count":case_count,"case_refs":case_refs,"case_refs_truncated":case_count>DISPLAY_LIMIT,
                "supplier_handoff_count":supplier_handoff_count,"supplier_handoffs":supplier_handoffs,
                "supplier_handoffs_truncated":supplier_handoff_count>DISPLAY_LIMIT}));
        }
        finding["site_rows"] = json!(rows);
    }

    let mut unlinked = Vec::new();
    for assessment in origin["sites"].as_array().into_iter().flatten() {
        if string(assessment, "site")
            .is_some_and(|site| sites.iter().any(|approved| approved == site))
            && !findings
                .iter()
                .any(|finding| assessment_matches(assessment, finding))
        {
            unlinked.push(assessment_view(assessment, &origin));
        }
    }
    let unlinked_count = unlinked.len();
    unlinked.truncate(DISPLAY_LIMIT);
    Ok(
        json!({"tenant":p.tenant,"case_id":case_id,"origin_site":origin_site,
        "approved_sites":sites,"findings":findings,"unidentified_finding_count":unidentified_finding_count,
        "unlinked_assessment_count":unlinked_count,"unlinked_assessments":unlinked,
        "unlinked_assessments_truncated":unlinked_count>DISPLAY_LIMIT,
        "note":"Only assessments explicitly linked within the selected origin case change site status; other cases and supplier context are not proof of coverage."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigator::config::{Config, User};
    use chrono::{Duration, Utc};
    use rusqlite::params;

    fn principal(tenant: &str) -> Principal {
        Principal {
            tenant: tenant.into(),
            actor: "local-admin".into(),
            role: "admin".into(),
        }
    }

    fn create_case(s: &Service, p: &Principal, site: &str) -> Value {
        let end = Utc::now();
        s.command(
            p,
            "cases.create",
            json!({"title":"Synthetic scope case","site":site,
            "start":(end-Duration::hours(1)).to_rfc3339(),"end":end.to_rfc3339()}),
        )
        .unwrap()
    }

    fn row<'a>(matrix: &'a Value, finding_id: &str, site: &str) -> &'a Value {
        let finding = matrix["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["finding_id"] == finding_id)
            .unwrap();
        finding["site_rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["site"] == site)
            .unwrap()
    }

    #[test]
    fn other_cases_and_suppliers_do_not_turn_missing_assessment_into_clearance() {
        let path = std::env::temp_dir().join(format!("site-matrix-{}.sqlite", Uuid::new_v4()));
        let mut config = Config::default();
        config.allowed_sites.push("REMOTE".into());
        let s = Service::open(&path, config).unwrap();
        let p = principal("DEMO");
        let origin = create_case(&s, &p, "LAB");
        s.command(
            &p,
            "playbooks.run",
            json!({"case_id":origin["id"],
            "playbook_id":"login_password_spray","expected_version":1}),
        )
        .unwrap();
        let other = create_case(&s, &p, "REMOTE");
        s.command(
            &p,
            "sites.assess",
            json!({"case_id":other["id"],"entity":{
                "owner":"operator","scope":"login_password_spray","site":"REMOTE",
                "coverage":"other case only","status":"finding","finding_id":"login_password_spray"
            }}),
        )
        .unwrap();
        s.command(
            &p,
            "suppliers.upsert",
            json!({"case_id":other["id"],"entity":{
                "owner":"supplier","scope":"REMOTE","questions":"What happened?",
                "deliverables":"Report","evidence_requirements":"Native IDs",
                "effort_provenance":"Estimate"
            }}),
        )
        .unwrap();
        let matrix = s
            .command(&p, "sites.matrix", json!({"case_id":origin["id"]}))
            .unwrap();
        let remote = row(&matrix, "login_password_spray", "REMOTE");
        assert_eq!(remote["status"], "not_checked");
        assert!(remote["coverage"].is_null());
        assert_eq!(remote["case_count"], 1);
        assert_eq!(remote["supplier_handoff_count"], 1);

        let mut foreign_config = Config::default();
        foreign_config.tenant = "OTHER".into();
        foreign_config.allowed_sites = vec!["REMOTE".into()];
        let foreign = Service::open(&path, foreign_config).unwrap();
        let foreign_case = create_case(&foreign, &principal("OTHER"), "REMOTE");
        assert!(
            s.command(&p, "sites.matrix", json!({"case_id":foreign_case["id"]}))
                .is_err()
        );
        let matrix = s
            .command(&p, "sites.matrix", json!({"case_id":origin["id"]}))
            .unwrap();
        assert_eq!(
            row(&matrix, "login_password_spray", "REMOTE")["case_count"],
            1
        );
        drop(foreign);
        drop(s);
        let reduced = Service::open(&path, Config::default()).unwrap();
        let visible = reduced.command(&p, "cases.list", json!({})).unwrap();
        assert_eq!(visible.as_array().unwrap().len(), 1);
        assert_eq!(visible[0]["id"], origin["id"]);
        assert!(
            reduced
                .command(&p, "cases.get", json!({"case_id":other["id"]}))
                .is_err()
        );
        let reduced_matrix = reduced
            .command(&p, "sites.matrix", json!({"case_id":origin["id"]}))
            .unwrap();
        assert_eq!(reduced_matrix["approved_sites"], json!(["LAB"]));
        assert_eq!(
            reduced_matrix["findings"][0]["site_rows"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        drop(reduced);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn explicit_finding_link_prevents_shared_evidence_from_assessing_another_finding() {
        let path = std::env::temp_dir().join(format!("site-matrix-{}.sqlite", Uuid::new_v4()));
        let mut config = Config::default();
        config.allowed_sites.push("REMOTE".into());
        let s = Service::open(&path, config).unwrap();
        let p = principal("DEMO");
        let mut origin = create_case(&s, &p, "LAB");
        origin["findings"] = json!([
            {"id":"A","status":"suspected","evidence_ids":["shared-evidence"]},
            {"id":"B","status":"suspected","evidence_ids":["shared-evidence"]}
        ]);
        origin["sites"] = json!([{"id":"historical","owner":"operator","site":"REMOVED",
            "scope":"unlinked","coverage":"historical","status":"not_checked"}]);
        s.ops
            .lock()
            .unwrap()
            .execute(
                "UPDATE investigator_cases SET body=?3 WHERE tenant=?1 AND id=?2",
                params![p.tenant, origin["id"].as_str().unwrap(), origin.to_string()],
            )
            .unwrap();
        s.command(
            &p,
            "sites.assess",
            json!({"case_id":origin["id"],"entity":{
                "owner":"operator","site":"REMOTE","scope":"shared-evidence",
                "finding_id":"A","coverage":"one scoped check","status":"finding"
            }}),
        )
        .unwrap();
        let matrix = s
            .command(&p, "sites.matrix", json!({"case_id":origin["id"]}))
            .unwrap();
        assert_eq!(row(&matrix, "A", "REMOTE")["status"], "finding");
        assert_eq!(row(&matrix, "B", "REMOTE")["status"], "not_checked");
        assert!(row(&matrix, "B", "REMOTE")["coverage"].is_null());
        assert_eq!(matrix["unlinked_assessment_count"], 0);
        drop(s);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn new_evidence_invalidates_old_negative_assessment() {
        let path = std::env::temp_dir().join(format!("site-matrix-{}.sqlite", Uuid::new_v4()));
        let mut config = Config::default();
        config.allowed_sites.push("REMOTE".into());
        config.users.push(User {
            actor: "reviewer".into(),
            role: "reviewer".into(),
            token_env: "MATRIX_TEST_REVIEWER_TOKEN".into(),
        });
        let s = Service::open(&path, config).unwrap();
        let admin = principal("DEMO");
        let reviewer = Principal {
            tenant: "DEMO".into(),
            actor: "reviewer".into(),
            role: "reviewer".into(),
        };
        let mut origin = create_case(&s, &admin, "LAB");
        origin["findings"] = json!([{"id":"A","status":"suspected","evidence_ids":["existing"]}]);
        origin["evidence"] = json!([{"id":"existing"}]);
        s.ops
            .lock()
            .unwrap()
            .execute(
                "UPDATE investigator_cases SET body=?3 WHERE tenant=?1 AND id=?2",
                params!["DEMO", origin["id"].as_str().unwrap(), origin.to_string()],
            )
            .unwrap();
        s.command(
            &reviewer,
            "sites.assess",
            json!({"case_id":origin["id"],"entity":{
                "owner":"reviewer","site":"REMOTE","scope":"A","finding_id":"A",
                "coverage":"reviewed current scoped evidence","status":"no_evidence_in_scope",
                "evidence_ids":["existing"]
            }}),
        )
        .unwrap();
        s.command(
            &reviewer,
            "sites.assess",
            json!({"case_id":origin["id"],"entity":{
                "owner":"reviewer","site":"LAB","scope":"A","finding_id":"A",
                "coverage":"not relevant at assessment time","status":"not_applicable",
                "reason":"No matching asset at assessment time"
            }}),
        )
        .unwrap();
        let before = s
            .command(&admin, "sites.matrix", json!({"case_id":origin["id"]}))
            .unwrap();
        assert_eq!(
            row(&before, "A", "REMOTE")["status"],
            "no_evidence_in_scope"
        );
        assert_eq!(row(&before, "A", "LAB")["status"], "not_applicable");

        let mut changed = s
            .command(&admin, "cases.get", json!({"case_id":origin["id"]}))
            .unwrap();
        changed["evidence"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"new"}));
        s.ops
            .lock()
            .unwrap()
            .execute(
                "UPDATE investigator_cases SET body=?3 WHERE tenant=?1 AND id=?2",
                params!["DEMO", origin["id"].as_str().unwrap(), changed.to_string()],
            )
            .unwrap();
        let after = s
            .command(&admin, "sites.matrix", json!({"case_id":origin["id"]}))
            .unwrap();
        for site in ["LAB", "REMOTE"] {
            let assessed = row(&after, "A", site);
            assert_eq!(assessed["status"], "insufficient_data");
            assert_eq!(assessed["reason_code"], "stale_evidence_binding");
            assert_eq!(assessed["stale_evidence_binding"], true);
            assert!(assessed["coverage"].is_null());
            assert_eq!(assessed["assessment_count"], 1);
        }
        assert_eq!(
            row(&after, "A", "REMOTE")["assessments"][0]["status"],
            "no_evidence_in_scope"
        );
        drop(s);
        let _ = std::fs::remove_file(path);
    }
}
