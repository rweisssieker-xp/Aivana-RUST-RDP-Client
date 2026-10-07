//! Human-controlled release evidence. It cannot download code or alter historical case versions.
use super::{core::Principal, service::Service};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn components() -> Value {
    json!({"model":"deterministic-1","prompt":"none-1","playbook":"multi-instance-evidence-4","query":"native-collectors-2026-10-06.2","policy":"separate-executor-2026-10-06.2","normalization":"scoped-ca-provider-evidence-4"})
}
fn require_role(p: &Principal, roles: &[&str]) -> Result<()> {
    if !roles.contains(&p.role.as_str()) {
        bail!("Forbidden: release authority required");
    }
    Ok(())
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .filter(|s| !s.trim().is_empty())
        .with_context(|| format!("Missing release {k}"))
}
fn validate(v: &Value) -> Result<()> {
    field(v, "id")?;
    field(v, "reason")?;
    field(v, "test_artifact")?;
    field(v, "rollback_version")?;
    if v["components"] != components() {
        bail!(
            "Release components are not supported by this installed binary; deploy and verify a matching binary first"
        );
    }
    for k in [
        "policy_tests_passed",
        "reference_replay_passed",
        "benchmark_passed",
        "provenance_complete",
        "migration_restore_tested",
    ] {
        if v["validation"][k] != true {
            bail!("Release gate failed: {k}");
        }
    }
    for k in ["critical_omissions", "unauthorized_actions"] {
        if v["validation"][k].as_u64() != Some(0) {
            bail!("Release gate failed: {k}");
        }
    }
    for k in ["cost_change_percent", "analyst_rework_change_percent"] {
        let actual = v["validation"][k]
            .as_f64()
            .filter(|n| n.is_finite())
            .context("Measured comparative release metrics required")?;
        let limit = v["tolerances"][k]
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .context("Pre-agreed release tolerances required")?;
        if actual > limit {
            bail!("Release exceeds agreed tolerance: {k}");
        }
    }
    Ok(())
}
pub fn command(s: &Service, p: &Principal, action: &str, v: Value) -> Result<Value> {
    if action == "releases.status" {
        return Ok(
            json!({"installed_components":components(),"active":s.state("release:active")?,"previous":s.state("release:previous")?,"note":"Evidence gates are human-attested; code deployment is separate and cannot be performed by the model"}),
        );
    }
    require_role(p, &["admin", "reviewer", "incident_lead"])?;
    let id = field(&v, "id")?;
    if id.len() > 128
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        bail!("Invalid release identifier");
    }
    let key = format!("release:package:{id}");
    let mut package = s.state(&key)?;
    match action {
        "releases.submit" => {
            require_role(p, &["admin", "incident_lead"])?;
            validate(&v)?;
            if !package.is_null() {
                bail!("Release packages are immutable; choose a new identifier");
            }
            package = json!({"package":v,"submitted_by":p.actor,"submitted_at":Utc::now(),"status":"awaiting_review","content_hash":format!("{:x}",Sha256::digest(v.to_string().as_bytes()))});
        }
        "releases.review" => {
            require_role(p, &["reviewer"])?;
            validate(&package["package"])?;
            if package["submitted_by"] == p.actor {
                bail!("Independent release reviewer required");
            }
            field(&v, "reason")?;
            package["reviewed_by"] = json!(p.actor);
            package["reviewed_at"] = json!(Utc::now());
            package["status"] = json!("approved_for_shadow");
        }
        "releases.shadow" => {
            require_role(p, &["reviewer", "incident_lead"])?;
            if package["status"] != "approved_for_shadow" {
                bail!("Independent approval required before shadow acceptance");
            }
            field(&v, "shadow_artifact")?;
            if v["shadow_passed"] != true || v["critical_omissions"].as_u64() != Some(0) {
                bail!("Shadow validation failed");
            }
            package["shadow"] =
                json!({"artifact":v["shadow_artifact"],"accepted_by":p.actor,"time":Utc::now()});
            package["status"] = json!("shadow_passed");
        }
        "releases.activate" => {
            require_role(p, &["admin"])?;
            if package["status"] != "shadow_passed" {
                bail!("Shadow evidence required before canary release");
            }
            let percent = v["canary_percent"]
                .as_u64()
                .filter(|n| *n > 0 && *n <= 100)
                .context("canary_percent must be 1..100")?;
            let active = s.state("release:active")?;
            s.set_state("release:previous", active)?;
            package["status"] = json!("active");
            package["canary_percent"] = json!(percent);
            package["activated_at"] = json!(Utc::now());
            package["activated_by"] = json!(p.actor);
            s.set_state("release:active", package.clone())?;
        }
        "releases.rollback" => {
            require_role(p, &["admin", "incident_lead"])?;
            field(&v, "reason")?;
            let previous = s.state("release:previous")?;
            if previous["package"]["id"] != id || previous["status"] != "active" {
                bail!(
                    "Requested previous approved version is unavailable; stop work and restore verified deployment"
                );
            }
            // Pause new jobs before the operational rollback. Existing case evidence is immutable.
            s.set_state("stopped", json!(true))?;
            s.set_state("release:active", previous.clone())?;
            s.audit(
                action,
                json!({"actor":p.actor,"reason":v["reason"],"id":id,"new_work_paused":true}),
            )?;
            return Ok(previous);
        }
        _ => bail!("Unknown release action denied"),
    }
    s.set_state(&key, package.clone())?;
    s.audit(
        action,
        json!({"actor":p.actor,"id":id,"content_hash":package["content_hash"]}),
    )?;
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Value {
        json!({"id":"candidate-1","reason":"Validation","test_artifact":"local-test-report.json","rollback_version":"baseline","components":components(),"validation":{"policy_tests_passed":true,"reference_replay_passed":true,"benchmark_passed":true,"provenance_complete":true,"migration_restore_tested":true,"critical_omissions":0,"unauthorized_actions":0,"cost_change_percent":0,"analyst_rework_change_percent":0},"tolerances":{"cost_change_percent":10,"analyst_rework_change_percent":10}})
    }
    #[test]
    fn bad_playbook_or_quality_regression_cannot_pass_release_gate() {
        validate(&good()).unwrap();
        let mut x = good();
        x["validation"]["critical_omissions"] = json!(1);
        assert!(validate(&x).is_err());
        let mut x = good();
        x["components"]["policy"] = json!("allow-all");
        assert!(validate(&x).is_err());
        let mut x = good();
        x["validation"]["cost_change_percent"] = json!(11);
        assert!(validate(&x).is_err());
    }
}
