//! Deterministic, evidence-only investigation playbooks.  These routines never
//! query a source or infer facts that are absent from the normalized record.
use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const VERSION: &str = "playbooks-2026-09-20.1";

fn digest(v: &Value) -> String {
    format!("{:x}", Sha256::digest(v.to_string().as_bytes()))
}
fn fields(e: &Value) -> &Value {
    e["revisions"]
        .as_array()
        .and_then(|v| v.last())
        .map(|v| &v["fields"])
        .unwrap_or(&e["fields"])
}
fn current(e: &Value, now: DateTime<Utc>) -> bool {
    e["retrieval_status"] != "expired"
        && e["retention_until"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|t| t > now)
}
fn evidence<'a>(c: &'a Value, now: DateTime<Utc>, source: &str, kind: &str) -> Vec<&'a Value> {
    let start = c["start"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    let end = c["end"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    c["evidence"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            current(e, now)
                && e["source"] == source
                && fields(e)["kind"] == kind
                && e["event_time"]
                    .as_str()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .is_some_and(|t| {
                        t <= now && start.is_some_and(|s| t >= s) && end.is_some_and(|e| t <= e)
                    })
        })
        .collect()
}
fn evidence_kind<'a>(c: &'a Value, now: DateTime<Utc>, kind: &str) -> Vec<&'a Value> {
    let start = c["start"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    let end = c["end"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    c["evidence"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            current(e, now)
                && fields(e)["kind"] == kind
                && e["event_time"]
                    .as_str()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .is_some_and(|t| {
                        t <= now && start.is_some_and(|s| t >= s) && end.is_some_and(|e| t <= e)
                    })
        })
        .collect()
}
fn refs(items: &[&Value]) -> Vec<Value> {
    items.iter().map(|e| e["id"].clone()).collect()
}
pub(crate) fn covered(c: &Value, source: &str) -> bool {
    let case_start = c["start"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    let case_end = c["end"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    case_start
        .zip(case_end)
        .is_some_and(|(start, end)| covered_interval(c, source, start, end))
}
pub(crate) fn covered_interval(
    c: &Value,
    source: &str,
    case_start: DateTime<chrono::FixedOffset>,
    case_end: DateTime<chrono::FixedOffset>,
) -> bool {
    let mut rows = c["coverage"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            (r["source"] == source || r["source_kind"] == source) && r["status"] != "not_applicable"
        })
        .peekable();
    rows.peek().is_some() && rows.all(|r| {
        let start = r["start"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
        let end = r["end"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
        (r["source"] == source || r["source_kind"] == source)
            && r["status"] == "available"
            && matches!((start, end), (Some(rs), Some(re)) if rs <= case_start && re >= case_end)
    })
}
fn gap(c: &Value, source: &str, schema: &str) -> Option<Value> {
    (!covered(c, source)).then(|| json!({"source":source,"reason":"No available coverage for the case interval","normalized_schema":schema}))
}
fn fresh_adcs(e: &Value, now: DateTime<Utc>) -> bool {
    e["event_time"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|t| t >= now - Duration::hours(24) && t <= now)
}
fn hypothesis(
    id: &str,
    claim: &str,
    status: &str,
    support: Vec<Value>,
    counter: Vec<Value>,
    gaps: Vec<Value>,
) -> Value {
    json!({"id":id,"claim":claim,"status":status,"supporting_evidence_ids":support,"counterevidence_ids":counter,"data_gaps":gaps})
}
fn run_login(c: &Value, now: DateTime<Utc>) -> Value {
    let events = evidence(c, now, "entra", "login");
    let failures: Vec<_> = events
        .iter()
        .copied()
        .filter(|e| {
            matches!(fields(e)["outcome"].as_str(), Some("failure"))
                || fields(e)["success"] == false
        })
        .collect();
    let successes: Vec<_> = events
        .iter()
        .copied()
        .filter(|e| {
            matches!(fields(e)["outcome"].as_str(), Some("success")) || fields(e)["success"] == true
        })
        .collect();
    let blocked: Vec<_> = events
        .iter()
        .copied()
        .filter(|e| fields(e)["outcome"] == "blocked")
        .collect();
    let mut accounts = std::collections::BTreeSet::new();
    for e in &failures {
        if let Some(a) = fields(e)
            .get("account")
            .or_else(|| fields(e).get("user"))
            .and_then(Value::as_str)
        {
            accounts.insert(a);
        }
    }
    let gaps = gap(
        c,
        "entra",
        "login{outcome|success,user|account,conditional_access,resource}",
    )
    .into_iter()
    .collect();
    let status = if failures.len() >= 2 && accounts.len() >= 2 && !successes.is_empty() {
        "suspected"
    } else {
        "not_decidable"
    };
    let mut support = refs(&failures);
    support.extend(refs(&successes));
    json!({"hypotheses":[
        hypothesis("password_spray","Password spray may be followed by successful authentication",status,support,refs(&blocked),gaps),
        hypothesis("legitimate_activity","Successful authentication may be legitimate activity","open",Vec::new(),Vec::new(),vec![json!({"required":"independent user or approved automation confirmation"})])
    ],"findings":[{"id":"login_password_spray","status":status,"failed_login_count":failures.len(),"distinct_failed_accounts":accounts.len(),"successful_login_evidence_ids":refs(&successes),"blocked_login_evidence_ids":refs(&blocked),"mfa_bypass":"not_inferred","resource_access":"not_inferred_from_login","exfiltration":"not_decidable","limitation":"Login evidence does not establish MFA bypass, resource access, or exfiltration."}]})
}
fn run_token(c: &Value, now: DateTime<Utc>) -> Value {
    let all_tokens = evidence(c, now, "entra_token", "token_event");
    let token_truncated = all_tokens.len() > 64;
    let tokens: Vec<_> = all_tokens.into_iter().take(64).collect();
    let mut suspicious = Vec::new();
    let mut counter = Vec::new();
    let mut gaps = gap(
        c,
        "entra_token",
        "token_event{token_id|session_id,app_id,ip|device_id,event_time}",
    )
    .into_iter()
    .collect::<Vec<_>>();
    if token_truncated {
        gaps.push(json!({"reason":"Token correlation candidate limit reached; remaining events were not assessed.","candidate_limit":64}));
    }
    for (index, first) in tokens.iter().enumerate() {
        let f = fields(first);
        let token = f
            .get("token_id")
            .or_else(|| f.get("session_id"))
            .and_then(Value::as_str);
        let app = f["app_id"].as_str();
        let context = f
            .get("ip")
            .or_else(|| f.get("device_id"))
            .and_then(Value::as_str);
        if token.is_none() || app.is_none() || context.is_none() {
            continue;
        }
        for second in tokens.iter().skip(index + 1) {
            let s = fields(second);
            let same_token = s
                .get("token_id")
                .or_else(|| s.get("session_id"))
                .and_then(Value::as_str)
                == token;
            let same_app = s["app_id"].as_str() == app;
            let distinct_context = s
                .get("ip")
                .or_else(|| s.get("device_id"))
                .and_then(Value::as_str)
                .is_some_and(|v| Some(v) != context);
            let near = first["event_time"]
                .as_str()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .zip(
                    second["event_time"]
                        .as_str()
                        .and_then(|v| DateTime::parse_from_rfc3339(v).ok()),
                )
                .is_some_and(|(a, b)| (a - b).num_minutes().abs() <= 15);
            if same_token && same_app && distinct_context && near {
                suspicious.push(*first);
                suspicious.push(*second);
            }
        }
        if f["token_status"] == "revoked" || f["session_terminated"] == true {
            counter.push(*first);
        }
    }
    if tokens.iter().any(|e| {
        fields(e)
            .get("token_id")
            .or_else(|| fields(e).get("session_id"))
            .is_none()
            || fields(e)["app_id"].as_str().is_none()
            || fields(e)
                .get("ip")
                .or_else(|| fields(e).get("device_id"))
                .is_none()
    }) {
        gaps.push(json!({"reason":"Token-reuse assessment requires token/session ID, app ID, and IP or device context."}));
    }
    suspicious.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    suspicious.dedup_by(|a, b| a["id"] == b["id"]);
    let status = if suspicious.is_empty() {
        "not_decidable"
    } else {
        "suspected"
    };
    json!({"hypotheses":[hypothesis("token_misuse","The same token/session was observed for the same app in distinct contexts within 15 minutes",status,refs(&suspicious),refs(&counter),gaps)],"findings":[{"id":"token_misuse","status":status,"evidence_ids":refs(&suspicious),"mfa_bypass":"not_inferred","exfiltration":"not_decidable","limitation":"Context variation may be legitimate. Token reuse evidence does not prove MFA bypass, session takeover, or data access."}]})
}
fn run_process(c: &Value, now: DateTime<Utc>) -> Value {
    let processes = evidence(c, now, "endpoint", "process_event");
    let office = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"];
    let launchers = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    ];
    let proxy = [
        "certutil.exe",
        "bitsadmin.exe",
        "regsvr32.exe",
        "rundll32.exe",
    ];
    let suspicious: Vec<_> = processes
        .iter()
        .copied()
        .filter(|e| {
            let f = fields(e);
            let parent = f["parent_process"]
                .as_str()
                .unwrap_or("")
                .to_ascii_lowercase();
            let child = f
                .get("process")
                .or_else(|| f.get("child_process"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            (office.contains(&parent.as_str()) && launchers.contains(&child.as_str()))
                || (parent == "powershell.exe" && proxy.contains(&child.as_str()))
        })
        .collect();
    let counter: Vec<_> = processes
        .iter()
        .copied()
        .filter(|e| fields(e)["approved_change"] == true || fields(e)["signer_trusted"] == true)
        .collect();
    let mut gaps = gap(
        c,
        "endpoint",
        "process_event{device_id,parent_process,process|child_process,event_time}",
    )
    .into_iter()
    .collect::<Vec<_>>();
    if processes.iter().any(|e| {
        fields(e)["parent_process"].as_str().is_none()
            || fields(e)
                .get("process")
                .or_else(|| fields(e).get("child_process"))
                .and_then(Value::as_str)
                .is_none()
    }) {
        gaps.push(json!({"reason":"Parent and child process names are required to evaluate bounded chain patterns."}));
    }
    let status = if suspicious.is_empty() {
        "not_decidable"
    } else {
        "suspected"
    };
    json!({"hypotheses":[hypothesis("endpoint_process_chain","Observed office-to-script-launcher or PowerShell-to-proxy execution chain",status,refs(&suspicious),refs(&counter),gaps)],"findings":[{"id":"endpoint_process_chain","status":status,"evidence_ids":refs(&suspicious),"exfiltration":"not_decidable","limitation":"A process chain alone does not prove execution intent, network transfer, or exfiltration."}]})
}
fn run_exfil(c: &Value, now: DateTime<Utc>) -> Value {
    let all_objects = evidence_kind(c, now, "object_access");
    let all_flows = evidence_kind(c, now, "network_flow");
    let cloud_truncated = all_objects.len() > 64 || all_flows.len() > 64;
    let objects: Vec<_> = all_objects.into_iter().take(64).collect();
    let flows: Vec<_> = all_flows.into_iter().take(64).collect();
    let blocked_objects: Vec<_> = objects
        .iter()
        .copied()
        .filter(|e| {
            matches!(
                fields(e)["outcome"].as_str(),
                Some("blocked") | Some("denied") | Some("failure")
            )
        })
        .collect();
    let blocked_flows: Vec<_> = flows
        .iter()
        .copied()
        .filter(|e| {
            matches!(
                fields(e)["outcome"].as_str(),
                Some("blocked") | Some("denied") | Some("failure")
            )
        })
        .collect();
    let downloads: Vec<_> = objects
        .iter()
        .copied()
        .filter(|e| {
            fields(e)["outcome"] == "success"
                && matches!(
                    fields(e)["operation"].as_str(),
                    Some("download") | Some("read")
                )
                && fields(e)
                    .get("object_count")
                    .or_else(|| fields(e).get("bytes"))
                    .and_then(Value::as_i64)
                    .is_some_and(|n| n > 0)
        })
        .collect();
    let outbound: Vec<_> = flows
        .iter()
        .copied()
        .filter(|e| {
            fields(e)["outcome"] == "success"
                && (fields(e)["direction"] == "outbound" || fields(e)["direction"] == "egress")
                && fields(e)
                    .get("bytes_out")
                    .or_else(|| fields(e).get("bytes"))
                    .and_then(Value::as_i64)
                    .is_some_and(|n| n > 0)
        })
        .collect();
    let mut correlated = Vec::new();
    for object in &downloads {
        for flow in &outbound {
            let same_principal = fields(object)
                .get("principal")
                .or_else(|| fields(object).get("actor"))
                .and_then(Value::as_str)
                .is_some_and(|p| {
                    Some(p)
                        == fields(flow)
                            .get("principal")
                            .or_else(|| fields(flow).get("actor"))
                            .and_then(Value::as_str)
                });
            let same_destination = fields(object)
                .get("destination")
                .or_else(|| fields(object).get("destination_ip"))
                .and_then(Value::as_str)
                .is_some_and(|d| {
                    Some(d)
                        == fields(flow)
                            .get("destination")
                            .or_else(|| fields(flow).get("destination_ip"))
                            .and_then(Value::as_str)
                });
            let close_in_time = object["event_time"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .zip(
                    flow["event_time"]
                        .as_str()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok()),
                )
                .is_some_and(|(a, b)| (a - b).num_minutes().abs() <= 15);
            if same_principal && same_destination && close_in_time {
                correlated.push((*object, *flow));
            }
        }
    }
    let mut gaps = Vec::new();
    if let Some(g) = gap(
        c,
        "cloud_storage",
        "object_access{operation,object_count,principal,object_id}",
    ) {
        gaps.push(g)
    };
    if let Some(g) = gap(
        c,
        "network",
        "network_flow{direction,bytes_out,principal,destination}",
    ) {
        gaps.push(g)
    };
    if cloud_truncated {
        gaps.push(json!({"reason":"Cloud correlation candidate limit reached; remaining events were not assessed.","candidate_limit_per_source":64}));
    }
    if !downloads.is_empty() && !outbound.is_empty() && correlated.is_empty() {
        gaps.push(json!({"reason":"Object access and network flow were not correlated by principal, destination, and a 15-minute time window."}));
    }
    let status = if !correlated.is_empty() {
        "suspected"
    } else {
        "not_decidable"
    };
    let mut support = Vec::new();
    for (object, flow) in &correlated {
        support.push(object["id"].clone());
        support.push(flow["id"].clone());
    }
    let mut counter = refs(&blocked_objects);
    counter.extend(refs(&blocked_flows));
    json!({"hypotheses":[hypothesis("cloud_exfiltration","Correlated cloud object access and outbound network activity require review",status,support.clone(),counter.clone(),gaps)],"findings":[{"id":"cloud_exfiltration","status":status,"correlated_evidence_ids":support,"object_access_evidence_ids":refs(&downloads),"network_flow_evidence_ids":refs(&outbound),"blocked_or_denied_evidence_ids":counter,"conclusion":"No exfiltration conclusion is made from either source alone.","exfiltration":if status=="suspected"{"requires_human_review"}else{"not_decidable"},"limitation":"Missing object-access or network logs cannot support an exfiltration-safe finding."}]})
}
fn run_adcs(c: &Value, now: DateTime<Utc>) -> Value {
    let templates = evidence(c, now, "adcs", "certificate_template");
    let acls = evidence(c, now, "adcs", "template_acl");
    let cas = evidence(c, now, "adcs", "ca_settings");
    let mut matched = Vec::new();
    let mut gaps = Vec::new();
    for template in templates.iter().filter(|e| fresh_adcs(e, now)) {
        let name = fields(template)["template"]
            .as_str()
            .filter(|s| !s.is_empty());
        let ca = fields(template)["ca"].as_str().filter(|s| !s.is_empty());
        if name.is_none() || ca.is_none() {
            gaps.push(json!({"reason":"A nonempty template and CA identifier is required before ESC1 assessment."}));
            continue;
        }
        let acl = acls
            .iter()
            .filter(|e| fresh_adcs(e, now))
            .find(|e| fields(e)["template"].as_str() == name && fields(e)["ca"].as_str() == ca);
        let setting = cas
            .iter()
            .filter(|e| fresh_adcs(e, now))
            .find(|e| fields(e)["template"].as_str() == name && fields(e)["ca"].as_str() == ca);
        if let (Some(acl), Some(setting)) = (acl, setting) {
            matched.push((*template, *acl, *setting));
        } else {
            gaps.push(json!({"template":name,"ca":ca,"reason":"Fresh template, ACL, and CA settings for the same template/CA are required before ESC1 assessment."}));
        }
    }
    if templates.iter().find(|e| fresh_adcs(e, now)).is_none() {
        gaps.push(
            json!({"source":"adcs","reason":"Fresh certificate template inventory is required."}),
        );
    }
    let positives: Vec<&Value> = matched
        .iter()
        .filter_map(|(t, a, ca)| {
            (fields(t)["enrollee_supplies_subject"] == true
                && fields(t)["client_authentication"] == true
                && fields(a)["low_privileged_enroll"] == true
                && fields(t)["manager_approval_required"] == false
                && fields(t)["authorized_signatures_required"].as_u64() == Some(0)
                && fields(ca)["issuance_requires_approval"] == false)
                .then_some(*t)
        })
        .collect();
    if matched.iter().any(|(t, _, _)| {
        fields(t)["authorized_signatures_required"]
            .as_u64()
            .is_none()
            || fields(t)["manager_approval_required"].as_bool().is_none()
    }) {
        gaps.push(json!({"reason":"Template manager approval and authorized_signatures_required (msPKI-RA-Signature) are required before ESC1 assessment."}));
    }
    let status = if matched.is_empty() || positives.is_empty() {
        "not_decidable"
    } else {
        "suspected"
    };
    let support: Vec<Value> = matched
        .iter()
        .flat_map(|(t, a, ca)| vec![t["id"].clone(), a["id"].clone(), ca["id"].clone()])
        .collect();
    json!({"hypotheses":[hypothesis("adcs_esc1","ESC1 conditions may exist",status,support,Vec::new(),gaps)],"findings":[{"id":"adcs_esc1","status":status,"positive_template_evidence_ids":refs(&positives),"assessment_basis":"Fresh template, ACL, and CA settings matched on template and CA.","limitation":"The configuration conditions do not confirm certificate abuse or exploitation. Missing, stale, or unmatched inventory cannot support a safe ESC1 conclusion."}]})
}

pub fn catalog() -> Value {
    json!({"version":VERSION,"mode":"deterministic_offline","source_contracts":[
     {"source":"entra","schema":"login{outcome|success,user|account,conditional_access,resource}","playbooks":["login_password_spray"]},
     {"source":"entra_token","schema":"token_event{token_id|session_id,app_id,ip|device_id,outcome,token_status|session_terminated}","playbooks":["token_misuse"],"correlation":"same token/session and app, distinct context, 15-minute window"},
     {"source":"endpoint","schema":"process_event{device_id,parent_process,process|child_process,chain_status}","playbooks":["endpoint_process_chain"]},
     {"source":"integration:* (configured storage provider)","schema":"object_access{operation,object_count|bytes,principal|actor,object_id,destination|destination_ip}","playbooks":["cloud_exfiltration"],"accepts":"provider-prefixed imports selected by fields.kind"},
     {"source":"integration:* (configured network provider)","schema":"network_flow{direction:outbound|egress,bytes_out|bytes,principal|actor,destination|destination_ip}","playbooks":["cloud_exfiltration"],"accepts":"provider-prefixed imports selected by fields.kind"},
     {"source":"adcs","schema":"certificate_template{template,ca,enrollee_supplies_subject,client_authentication,manager_approval_required,authorized_signatures_required}; template_acl{template,ca,low_privileged_enroll}; ca_settings{template,ca,issuance_requires_approval}","playbooks":["adcs_esc1"],"freshness":"event_time within 24h; all three records must match nonempty template and CA identifiers"}
    ],"playbooks":[
     {"id":"login_password_spray","version":VERSION,"default":true,"description":"Repeated failed logins with separately evidenced success; never infers MFA bypass, resource access, or exfiltration."},
     {"id":"token_misuse","version":VERSION,"description":"Explicit normalized token anomaly evidence only."},
     {"id":"endpoint_process_chain","version":VERSION,"description":"Explicit normalized endpoint process-chain evidence only."},
     {"id":"cloud_exfiltration","version":VERSION,"description":"Requires separately evidenced object access and outbound network activity; missing data never establishes safety."},
     {"id":"adcs_esc1","version":VERSION,"description":"Requires fresh, matching template, ACL, and CA settings before an assessment."}
    ]})
}

pub fn run(c: &mut Value, playbook_id: &str, now: DateTime<Utc>) -> Result<Value> {
    let output = match playbook_id {
        "login_password_spray" => run_login(c, now),
        "token_misuse" => run_token(c, now),
        "endpoint_process_chain" => run_process(c, now),
        "cloud_exfiltration" => run_exfil(c, now),
        "adcs_esc1" => run_adcs(c, now),
        _ => bail!("Unknown playbook"),
    };
    let result = json!({"id":format!("{}:{}",playbook_id,digest(&json!([playbook_id,VERSION,output,c["evidence"],c["coverage"]]))),"playbook_id":playbook_id,"version":VERSION,"ran_at":now,"result":output});
    if c.get("playbooks").is_none() {
        c["playbooks"] = json!([])
    };
    if let Some(existing) = c["playbooks"]
        .as_array()
        .and_then(|runs| runs.iter().find(|run| run["id"] == result["id"]))
    {
        return Ok(existing.clone());
    }
    c["playbooks"].as_array_mut().unwrap().push(result.clone());
    c["situation_playbooks"] = json!({"latest_run_id":result["id"],"playbook_id":playbook_id,"findings":result["result"]["findings"],"hypotheses":result["result"]["hypotheses"],"updated_at":now});
    c["state"] = json!("review_required");
    Ok(result)
}
