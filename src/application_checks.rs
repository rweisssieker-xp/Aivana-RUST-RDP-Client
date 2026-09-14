//! Local recording-derived checks. Importing evidence never contacts an application.
use crate::execution::{
    HealthCheck, HttpGetStep,
    http_health::{Method, Options},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod recorded_ui;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recording {
    pub schema_version: u8,
    pub title: String,
    pub port: u16,
    pub tls: bool,
    pub steps: Vec<RecordedStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedStep {
    pub path: String,
    pub status: u16,
    pub contains: String,
    #[serde(default)]
    pub login_slots: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub json_equals: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Recording {
    pub fn parse(input: &str) -> Result<Self> {
        ensure!(input.len() <= 32_768, "Recording exceeds 32 KiB");
        let recording: Self = serde_json::from_str(input)?;
        recording.health()?;
        Ok(recording)
    }

    pub fn digest(&self, draft_binding: &str) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(self, draft_binding))?)
        ))
    }

    pub fn health(&self) -> Result<HealthCheck> {
        ensure!(self.schema_version == 1, "Unsupported recording schema");
        ensure!(
            !self.title.trim().is_empty()
                && self.title.len() <= 160
                && !self.title.chars().any(char::is_control),
            "Invalid recording title"
        );
        ensure!(
            (1..=4).contains(&self.steps.len()),
            "Record one to four application requests"
        );
        for step in &self.steps {
            ensure!(
                (200..=299).contains(&step.status),
                "A successful response status is required"
            );
            ensure!(
                !step.path.contains('%')
                    && !step.path.chars().any(char::is_whitespace)
                    && !step.path.split('/').any(|part| matches!(part, "." | "..")),
                "Use a literal application path without traversal or encoding"
            );
            ensure!(
                !step.contains.trim().is_empty() || !step.json_equals.is_empty(),
                "Every request needs a response assertion"
            );
            ensure!(
                !step.contains.chars().any(char::is_control),
                "Invalid response assertion"
            );
            for (field, slot) in &step.login_slots {
                ensure!(
                    [field, slot].iter().all(|s| !s.is_empty()
                        && s.len() <= 128
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))),
                    "Login fields must reference named runtime slots, never credentials"
                );
            }
        }
        let first = &self.steps[0];
        ensure!(
            first.login_slots.is_empty()
                && first.json_equals.is_empty()
                && !first.contains.trim().is_empty(),
            "First request must be a GET with a text assertion"
        );
        let health = HealthCheck::Http {
            port: self.port,
            tls: self.tls,
            path: first.path.clone(),
            status: first.status,
            contains: first.contains.clone(),
            followups: self
                .steps
                .iter()
                .skip(1)
                .map(|step| HttpGetStep {
                    path: step.path.clone(),
                    status: step.status,
                    contains: step.contains.clone(),
                    options: Options {
                        method: if step.login_slots.is_empty() {
                            Method::Get
                        } else {
                            Method::Post
                        },
                        secret_fields: step.login_slots.clone(),
                        json_equals: step.json_equals.clone(),
                        ..Default::default()
                    },
                })
                .collect(),
        };
        health.validate()?;
        Ok(health)
    }
}

#[derive(Default)]
pub struct ImportState {
    pub input: String,
    pub reviewed: bool,
    binding: String,
}

impl ImportState {
    pub fn sync(&mut self, binding: &str) {
        if self.binding != binding {
            self.binding = binding.into();
            self.reviewed = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn recording() -> Recording {
        Recording::parse(r#"{"schema_version":1,"title":"Sign in and open dashboard","port":443,"tls":true,"steps":[{"path":"/login","status":200,"contains":"Sign in"},{"path":"/session","status":200,"contains":"Welcome","login_slots":{"username":"test_user","password":"test_password"}},{"path":"/api/dashboard","status":200,"contains":"","json_equals":{"/ready":true}}]}"#).unwrap()
    }
    #[test]
    fn recorded_login_compiles_to_existing_session_pipeline() {
        let HealthCheck::Http { followups, .. } = recording().health().unwrap() else {
            panic!()
        };
        assert_eq!(followups[0].options.method, Method::Post);
        assert_eq!(
            followups[0].options.secret_fields["password"],
            "test_password"
        );
        assert_eq!(followups[1].options.json_equals["/ready"], true);
    }
    #[test]
    fn rejects_unprotected_login_and_missing_assertions() {
        let mut r = recording();
        r.tls = false;
        assert!(r.health().is_err());
        r.tls = true;
        r.steps[1].contains.clear();
        assert!(r.health().is_err());
    }
    #[test]
    fn binding_changes_with_evidence_and_draft_and_revokes_review() {
        let mut r = recording();
        let original = r.digest("draft-a").unwrap();
        assert_ne!(original, r.digest("draft-b").unwrap());
        r.steps[1].contains = "Different".into();
        let changed = r.digest("draft-a").unwrap();
        assert_ne!(original, changed);
        let mut state = ImportState::default();
        state.sync(&original);
        state.reviewed = true;
        state.sync(&changed);
        assert!(!state.reviewed);
    }
    #[test]
    fn rejects_raw_browser_payload_and_unknown_fields() {
        assert!(Recording::parse(r#"{"schema_version":1,"cookies":"secret"}"#).is_err());
        let mut r = recording();
        r.steps[0].path = "/%2e%2e/admin".into();
        assert!(r.health().is_err());
        r.steps[0].path = "https://other.example/".into();
        assert!(r.health().is_err());
    }
}
