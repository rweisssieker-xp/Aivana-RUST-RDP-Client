//! Synthetic PRD reference case; never reads credentials or opens a network connection.
use super::{
    config::Config,
    core::{Core, Principal},
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::path::Path;

pub fn scenario(core: &mut Core) -> Result<Value> {
    let analyst = Principal {
        tenant: "DEMO".into(),
        actor: "demo-analyst".into(),
        role: "analyst".into(),
    };
    let now: DateTime<Utc> = "2026-09-20T09:05:00Z".parse()?;
    let c=core.execute(&analyst,"cases.create",json!({"title":"DEMO: password spray and blocked resource","site":"LAB","owner":"demo-analyst","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"}),now)?;
    let cid = c["id"].clone();
    let mut evidence = Vec::new();
    for i in 0..40 {
        evidence.push(json!({"source":"entra","source_id":format!("failed-{i}"),"event_time":"2026-09-20T09:00:00Z","query_version":"demo-1","fields":{"kind":"login","outcome":"failure","success":false,"user":format!("user-{}",i%10),"account":format!("user-{}",i%10),"ip":"192.0.2.17"}}));
    }
    let success = json!({"source":"entra","source_id":"login-17","event_time":"2026-09-20T09:02:00Z","query_version":"demo-1","fields":{"kind":"login","outcome":"success","success":true,"user":"user-17","account":"user-17","ip":"192.0.2.17"}});
    evidence.push(success.clone());
    evidence.push(json!({"source":"resource_audit","source_id":"blocked-17","event_time":"2026-09-20T09:03:00Z","query_version":"demo-1","fields":{"kind":"resource","outcome":"blocked","resource_access":"blocked","user":"user-17","resource":"demo-client-17"}}));
    core.execute(&analyst,"evidence.ingest",json!({"case_id":cid,"evidence":evidence,"coverage":[{"source":"entra","status":"available","start":"2026-09-20T08:00:00Z","end":"2026-09-20T10:00:00Z"},{"source":"storage","status":"unavailable","reason":"No file audit in reference scenario"}]}),now)?;
    core.execute(
        &analyst,
        "evidence.ingest",
        json!({"case_id":cid,"evidence":[success]}),
        now + chrono::Duration::minutes(1),
    )?;
    core.execute(
        &analyst,
        "cases.analyze",
        json!({"case_id":cid}),
        now + chrono::Duration::minutes(2),
    )
}

pub fn markdown(c: &Value) -> String {
    let mut out = format!(
        "# Security investigation\n\nCase: {}\n\nState: {} · version {}\n\nScope: {} · {} to {}\n\nOwner: {}\n\n",
        c["id"], c["state"], c["version"], c["site"], c["start"], c["end"], c["owner"]
    );
    for (heading, keys) in [
        (
            "Situation and evidence",
            vec![
                "findings",
                "hypotheses",
                "coverage",
                "evidence",
                "context",
                "playbooks",
            ],
        ),
        (
            "Measures and technical verification",
            vec!["actions", "questions"],
        ),
        (
            "Emergency operation and decision record",
            vec!["risks", "decisions", "recovery_gates", "reviews", "handoff"],
        ),
    ] {
        out.push_str(&format!("## {heading}\n\n"));
        for key in keys {
            out.push_str(&format!(
                "### {key}\n\n```json\n{}\n```\n\n",
                serde_json::to_string_pretty(&c[key]).unwrap_or_default()
            ));
        }
    }
    out.push_str("Login success is not proof of resource access, MFA bypass or exfiltration. Unavailable sources remain open limitations. Findings require human review; local notifications do not prove external delivery.\n");
    out
}
pub fn run(output: &Path) -> Result<()> {
    if output.exists() {
        bail!("Replay output must be a new directory");
    }
    std::fs::create_dir_all(output)?;
    let mut core = Core::open(
        &output.join("replay.sqlite"),
        serde_json::to_value(Config::default())?,
    )?;
    let report = scenario(&mut core)?;
    std::fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    std::fs::write(output.join("report.md"), markdown(&report))?;
    println!(
        "Synthetic DEMO replay: {} unique events, saved to {}. No network or model calls.",
        report["evidence"].as_array().map(Vec::len).unwrap_or(0),
        output.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supplied_reference_case_preserves_counterevidence_and_uncertainty() {
        let mut core = Core::open(
            Path::new(":memory:"),
            serde_json::to_value(Config::default()).unwrap(),
        )
        .unwrap();
        let c = scenario(&mut core).unwrap();
        assert_eq!(c["evidence"].as_array().unwrap().len(), 42);
        let login = c["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["source_id"] == "login-17")
            .unwrap();
        assert_ne!(
            login["retrievals"][0]["time"],
            login["retrievals"][1]["time"]
        );
        assert_eq!(c["findings"][0]["failed_logins"], 40);
        assert_eq!(c["findings"][0]["distinct_accounts"], 10);
        assert_eq!(c["findings"][0]["exfiltration"], "not_decidable");
        assert_eq!(
            c["findings"][0]["successful_login_evidence"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            c["findings"][0]["blocked_access_evidence"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_ne!(c["state"], "closed");
        assert!(markdown(&c).contains("Emergency operation and decision record"));
    }
}
