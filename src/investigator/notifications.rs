//! Metadata-only delivery to explicitly approved internal webhook destinations.
use super::{config::valid_env, core::Principal, service::Service};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Timelike, Utc};
use reqwest::{Url, blocking::Client};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn destination(s: &Service, reference: &str) -> Result<Url> {
    if !valid_env(reference) {
        bail!("Notification destination is not configured");
    }
    let value =
        std::env::var(reference).context("Notification destination reference unavailable")?;
    validate_destination(&value, &s.config.operations.notification_allowed_hosts)
}
fn validate_destination(value: &str, hosts: &[String]) -> Result<Url> {
    let u = Url::parse(value).context("Invalid notification URL")?;
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.host_str().is_none_or(|h| !hosts.iter().any(|a| a == h))
    {
        bail!("Notification destination is outside approved HTTPS host scope");
    }
    Ok(u)
}
fn send(s: &Service, reference: &str, key: &str, payload: &Value) -> Result<()> {
    let url = destination(s, reference)?;
    let response = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(url)
        .header("Idempotency-Key", key)
        .json(payload)
        .send()
        .map_err(|_| anyhow::anyhow!("Internal notification transport failed"))?;
    if !response.status().is_success() {
        bail!(
            "Internal notification rejected (HTTP {})",
            response.status().as_u16()
        );
    }
    Ok(())
}
pub fn probe(s: &Service, p: &Principal) -> Result<Value> {
    if !["admin", "incident_lead"].contains(&p.role.as_str()) {
        bail!("Forbidden: notification probe requires operator");
    }
    let o = &s.config.operations;
    if !o.escalation_confirmed || !o.notification_idempotency_confirmed {
        bail!("Explicit internal integration and recipient consent required");
    }
    let key = format!("probe-{}", uuid::Uuid::new_v4());
    let payload = json!({"kind":"readiness_probe","tenant":p.tenant,"recipient":o.escalation_recipient,"message":"Relayne internal escalation readiness test; acknowledge using your configured operational procedure"});
    let backup = json!({"kind":"readiness_probe","tenant":p.tenant,"recipient":o.escalation_backup,"message":"Relayne backup escalation readiness test"});
    s.set_state(
        "notification:health",
        json!({"status":"checking","checked_at":Utc::now()}),
    )?;
    let result = send(s, &o.notification_webhook_env, &key, &payload).and_then(|_| {
        send(
            s,
            &o.notification_backup_webhook_env,
            &format!("{key}-backup"),
            &backup,
        )
    });
    if let Err(e) = result {
        s.set_state(
            "notification:health",
            json!({"status":"failed","checked_at":Utc::now(),"error":e.to_string()}),
        )?;
        s.audit(
            "notifications.probe",
            json!({"actor":p.actor,"status":"failed"}),
        )?;
        return Err(e);
    }
    let health = json!({"status":"passed","checked_at":Utc::now(),"actor":p.actor,"scope":"primary and backup HTTPS accepted test delivery; human readiness still operator-attested"});
    s.set_state("notification:health", health.clone())?;
    s.audit(
        "notifications.probe",
        json!({"actor":p.actor,"status":"passed"}),
    )?;
    Ok(health)
}
pub fn tick(s: &Service) -> Result<()> {
    if s.state("recovery:last")?["reconciliation_required"] == true {
        return Ok(());
    }
    let o = &s.config.operations;
    if !o.escalation_confirmed
        || !o.notification_idempotency_confirmed
        || !valid_env(&o.notification_webhook_env)
    {
        return Ok(());
    }
    let cases = s.exec(&s.system(), "cases.list", json!({}))?;
    let mut attempts = 0;
    let digest_key = format!("notification:daily:{}", Utc::now().format("%Y-%m-%d"));
    let previous_digest = s.state(&digest_key)?;
    let digest_attempts = previous_digest["attempts"].as_u64().unwrap_or(0);
    let retry_due = previous_digest["retry_at"]
        .as_str()
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .is_none_or(|t| t <= Utc::now());
    if Utc::now().hour() >= 8
        && previous_digest["status"] != "sent"
        && digest_attempts < 3
        && retry_due
    {
        let mut items = Vec::new();
        let mut total = 0;
        for c in cases.as_array().context("Invalid case list")? {
            for n in c["notifications"].as_array().into_iter().flatten() {
                if ["U2", "U3"].contains(&n["urgency"].as_str().unwrap_or(""))
                    && n["acknowledged_at"].is_null()
                {
                    total += 1;
                    if items.len() < 100 {
                        items.push(json!({"case_id":c["id"],"notification_id":n["id"],"urgency":n["urgency"],"message":n["message"]}));
                    }
                }
            }
        }
        if !items.is_empty() {
            attempts += 1;
            let key = format!(
                "{:x}",
                Sha256::digest(format!("{}:{digest_key}", s.config.tenant).as_bytes())
            );
            let payload = json!({"kind":"daily_summary","tenant":s.config.tenant,"recipient":o.escalation_recipient,"total_open_notifications":total,"omitted_from_summary":total-items.len(),"items":items});
            let result = send(s, &o.notification_webhook_env, &key, &payload);
            s.set_state(&digest_key,json!({"status":if result.is_ok(){"sent"}else{"failed"},"time":Utc::now(),"count":items.len(),"attempts":digest_attempts+1,"retry_at":Utc::now()+chrono::Duration::minutes(5)}))?;
            if let Err(e) = result {
                s.set_state(
                    "notification:health",
                    json!({"status":"failed","checked_at":Utc::now(),"error":e.to_string()}),
                )?;
                let fallback = json!({"kind":"delivery_failure","tenant":s.config.tenant,"recipient":o.escalation_backup,"message":"Daily summary delivery failed; inspect local notification outbox"});
                let _ = send(
                    s,
                    &o.notification_backup_webhook_env,
                    &format!("{key}-failure"),
                    &fallback,
                );
            }
        }
    }
    for c in cases.as_array().context("Invalid case list")? {
        for n in c["notifications"].as_array().into_iter().flatten() {
            if !n["acknowledged_at"].is_null() {
                continue;
            }
            if ["U2", "U3"].contains(&n["urgency"].as_str().unwrap_or("")) {
                continue;
            }
            let key = format!("notification:{}:{}", c["id"], n["id"]);
            let mut state = s.state(&key)?;
            let snooze = s.state(&format!("snooze:{}:{}", c["id"], n["id"]))?;
            if snooze["until"]
                .as_str()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .is_some_and(|t| t > Utc::now())
            {
                continue;
            }
            let age = n["created_at"]
                .as_str()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|t| Utc::now() - t.with_timezone(&Utc))
                .unwrap_or_default();
            let escalate = if n["urgency"] == "U0" {
                age.num_minutes() >= 15
            } else {
                age.num_minutes() >= 60
            };
            let level = if escalate { "backup" } else { "primary" };
            if state["level"] == level && state["status"] == "sent" {
                continue;
            }
            if state["retry_at"]
                .as_str()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .is_some_and(|t| t > Utc::now())
            {
                continue;
            }
            let previous_attempts = if state["level"] == level {
                state["attempts"].as_u64().unwrap_or(0)
            } else {
                0
            };
            if previous_attempts >= 3 {
                continue;
            }
            if attempts >= 2 {
                return Ok(());
            }
            attempts += 1;
            let idempotency = format!(
                "{:x}",
                Sha256::digest(format!("{}:{key}:{level}", s.config.tenant).as_bytes())
            );
            let payload = json!({"tenant":s.config.tenant,"case_id":c["id"],"notification_id":n["id"],"urgency":n["urgency"],"level":level,"recipient":if escalate{&o.escalation_backup}else{&o.escalation_recipient},"message":n["message"]});
            let endpoint = if escalate {
                &o.notification_backup_webhook_env
            } else {
                &o.notification_webhook_env
            };
            match send(s, endpoint, &idempotency, &payload) {
                Ok(()) => {
                    state = json!({"status":"sent","level":level,"sent_at":Utc::now(),"idempotency_key":idempotency,"note":"Delivery is not human acknowledgement or case closure"});
                }
                Err(e) => {
                    state = json!({"status":"failed","level":level,"attempts":previous_attempts+1,"error":e.to_string(),"retry_at":Utc::now()+chrono::Duration::minutes(5),"idempotency_key":idempotency});
                    s.set_state(
                        "notification:health",
                        json!({"status":"failed","checked_at":Utc::now(),"error":e.to_string()}),
                    )?;
                    if !escalate {
                        let fallback = json!({"kind":"delivery_failure","tenant":s.config.tenant,"case_id":c["id"],"recipient":o.escalation_backup,"message":"Primary escalation delivery failed; human intervention required"});
                        let _ = send(
                            s,
                            &o.notification_backup_webhook_env,
                            &format!("{idempotency}-failure"),
                            &fallback,
                        );
                    }
                }
            }
            s.set_state(&key, state.clone())?;
            s.audit("notifications.delivery",json!({"case_id":c["id"],"notification_id":n["id"],"status":state["status"],"level":level}))?;
        }
    }
    Ok(())
}

pub fn snooze(s: &Service, p: &Principal, v: Value) -> Result<Value> {
    if !["analyst", "incident_lead", "admin"].contains(&p.role.as_str()) {
        bail!("Forbidden: snooze requires responsible operator");
    }
    let cid = v["case_id"].as_str().context("case_id required")?;
    let nid = v["notification_id"]
        .as_str()
        .context("notification_id required")?;
    let c = s.exec(p, "cases.get", json!({"case_id":cid}))?;
    if !c["notifications"]
        .as_array()
        .context("No notifications")?
        .iter()
        .any(|n| n["id"] == nid)
    {
        bail!("Notification is not in this case");
    }
    let until = DateTime::parse_from_rfc3339(v["until"].as_str().context("Snooze end required")?)?;
    if until <= Utc::now()
        || until > Utc::now() + chrono::Duration::hours(24)
        || v["reason"].as_str().is_none_or(|s| s.trim().is_empty())
    {
        bail!("Snooze requires reason and future end within 24 hours");
    }
    let key = format!("snooze:{}:{}", c["id"], json!(nid));
    if !s.state(&key)?.is_null() {
        bail!("Only one snooze is allowed for this notification");
    }
    let record = json!({"owner":p.actor,"reason":v["reason"],"until":until,"notification_id":nid,"case_id":cid});
    s.set_state(&key, record.clone())?;
    s.audit("notifications.snooze", record.clone())?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_reprobe_replaces_previously_passed_health_without_network() {
        let mut c = super::super::config::Config::default();
        c.operations.escalation_confirmed = true;
        c.operations.notification_idempotency_confirmed = true;
        c.operations.notification_webhook_env = "RELAYNE_TEST_UNSET_DESTINATION_572EBF".into();
        let s = Service::open(std::path::Path::new(":memory:"), c).unwrap();
        s.set_state(
            "notification:health",
            json!({"status":"passed","checked_at":Utc::now()}),
        )
        .unwrap();
        let p = Principal {
            tenant: "DEMO".into(),
            actor: "local-admin".into(),
            role: "admin".into(),
        };
        assert!(probe(&s, &p).is_err());
        assert_eq!(s.state("notification:health").unwrap()["status"], "failed");
    }
    #[test]
    fn webhook_scope_cannot_be_widened_by_payload() {
        let hosts = vec!["internal.example".into()];
        assert!(validate_destination("https://internal.example/hooks/relayne", &hosts).is_ok());
        for u in [
            "http://internal.example/hooks",
            "https://evil.example/hooks",
            "https://user@internal.example/hooks",
        ] {
            assert!(validate_destination(u, &hosts).is_err());
        }
    }
}
