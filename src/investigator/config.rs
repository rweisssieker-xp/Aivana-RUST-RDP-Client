use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub actor: String,
    pub role: String,
    pub token_env: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Budgets {
    pub case_api_calls: u64,
    pub case_result_bytes: u64,
    pub case_cost_micros: u64,
    pub monthly_cost_micros: u64,
    pub case_runtime_seconds: u64,
    pub api_call_cost_micros: u64,
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            case_api_calls: 20,
            case_result_bytes: 1_048_576,
            case_cost_micros: 100_000,
            monthly_cost_micros: 1_000_000,
            case_runtime_seconds: 300,
            api_call_cost_micros: 1000,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sources {
    pub enabled: bool,
    pub client_id: String,
    pub secret_env: String,
    pub contract_approved_by: String,
    pub contract_approved_at: String,
    pub coverage_start: String,
    pub coverage_end: String,
    pub retention_days: u32,
    pub license_confirmed: bool,
    pub least_privilege_confirmed: bool,
    pub region: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Operations {
    pub alarm_scope_site: String,
    pub notification_webhook_env: String,
    pub notification_backup_webhook_env: String,
    pub notification_allowed_hosts: Vec<String>,
    pub notification_idempotency_confirmed: bool,
    pub a1_enabled: bool,
    pub platform_owner: String,
    pub soc_owner: String,
    pub connector_owner: String,
    pub privacy_owner: String,
    pub release_owner: String,
    pub backup_owner: String,
    pub escalation_recipient: String,
    pub escalation_backup: String,
    pub escalation_confirmed: bool,
    pub coverage_24x7_confirmed: bool,
    pub encrypted_volume_confirmed: bool,
    pub retention_approved: bool,
    pub poll_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub tenant: String,
    pub allowed_sites: Vec<String>,
    pub users: Vec<User>,
    pub budgets: Budgets,
    pub sources: Sources,
    pub operations: Operations,
    pub integrations: super::integrations::Integrations,
    pub collectors: super::collectors::Collectors,
    pub response: super::response::ResponseConfig,
    pub retention_days: u32,
    pub bind: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            tenant: "DEMO".into(),
            allowed_sites: vec!["LAB".into()],
            users: vec![User {
                actor: "local-admin".into(),
                role: "admin".into(),
                token_env: "RELAYNE_INVESTIGATOR_TOKEN".into(),
            }],
            budgets: Budgets::default(),
            sources: Sources::default(),
            operations: Operations {
                poll_seconds: 300,
                ..Default::default()
            },
            integrations: Default::default(),
            collectors: Default::default(),
            response: Default::default(),
            retention_days: 30,
            bind: "127.0.0.1:47841".into(),
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context("Cannot read investigator configuration")?;
        if bytes.len() > 262_144 {
            bail!("Configuration exceeds 256 KiB");
        }
        let c: Self =
            serde_json::from_slice(&bytes).context("Invalid investigator configuration")?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        self.integrations.validate()?;
        self.collectors.validate()?;
        self.response
            .validate(&self.tenant, &self.allowed_sites, &self.users)?;
        self.response.validate_isolation(self)?;
        if self.integrations.enabled
            && (!self.operations.encrypted_volume_confirmed || !self.operations.retention_approved)
        {
            bail!("Integrations require approved encrypted evidence storage and retention");
        }
        let address: std::net::SocketAddr = self
            .bind
            .parse()
            .context("Bind must be a numeric loopback address")?;
        if !address.ip().is_loopback() {
            bail!(
                "Only loopback binding is allowed; use an authenticated TLS reverse proxy for remote access"
            );
        }
        if self.tenant.trim().is_empty()
            || self.allowed_sites.is_empty()
            || self.allowed_sites.iter().any(|s| s.trim().is_empty())
        {
            bail!("Tenant and explicit sites are required");
        }
        if !(1..=365).contains(&self.retention_days) {
            bail!("Retention must be 1..365 days");
        }
        let mut actors = HashSet::new();
        let mut envs = HashSet::new();
        for u in &self.users {
            if u.actor.trim().is_empty() || !actors.insert(&u.actor) || !envs.insert(&u.token_env) {
                bail!("Actors and token references must be unique");
            }
            if ![
                "viewer",
                "analyst",
                "incident_lead",
                "risk_owner",
                "reviewer",
                "admin",
            ]
            .contains(&u.role.as_str())
            {
                bail!("Invalid external role");
            }
            if !valid_env(&u.token_env) {
                bail!("Invalid token environment reference");
            }
        }
        if self.users.is_empty() {
            bail!("At least one authenticated user required");
        }
        let b = &self.budgets;
        if b.case_api_calls == 0
            || b.case_api_calls > 1000
            || b.case_result_bytes < 1024
            || b.case_result_bytes > 16_777_216
            || b.case_cost_micros == 0
            || b.monthly_cost_micros < b.case_cost_micros
            || b.api_call_cost_micros == 0
            || !(10..=3600).contains(&b.case_runtime_seconds)
        {
            bail!("Invalid bounded budget configuration");
        }
        if self.sources.enabled {
            uuid::Uuid::parse_str(&self.tenant).context("Live tenant must be a UUID")?;
            uuid::Uuid::parse_str(&self.sources.client_id)
                .context("Live client ID must be a UUID")?;
            if !valid_env(&self.sources.secret_env) {
                bail!("Live sources require a secret environment reference");
            }
        }
        Ok(())
    }
    pub fn live_gate(&self) -> Result<()> {
        self.validate()?;
        let s = &self.sources;
        if !s.enabled
            || s.contract_approved_by.trim().is_empty()
            || s.region.trim().is_empty()
            || !s.license_confirmed
            || !s.least_privilege_confirmed
            || s.retention_days == 0
        {
            bail!(
                "Source feasibility contract, license, least privilege and region have not been approved"
            );
        }
        let approved = chrono::DateTime::parse_from_rfc3339(&s.contract_approved_at)
            .context("Contract approval timestamp missing")?;
        if approved > chrono::Utc::now() {
            bail!("Contract approval is in the future");
        }
        let start = chrono::DateTime::parse_from_rfc3339(&s.coverage_start)
            .context("Verified coverage start missing")?;
        let end = chrono::DateTime::parse_from_rfc3339(&s.coverage_end)
            .context("Verified coverage end missing")?;
        if start >= end {
            bail!("Coverage window is invalid");
        }
        if !self.operations.encrypted_volume_confirmed || !self.operations.retention_approved {
            bail!("Encrypted evidence storage and retention approval are required for live data");
        }
        Ok(())
    }
    pub fn a1_gate(&self) -> Result<()> {
        self.live_gate()?;
        let o = &self.operations;
        if !o.a1_enabled
            || !valid_env(&o.notification_webhook_env)
            || !valid_env(&o.notification_backup_webhook_env)
            || o.notification_allowed_hosts.is_empty()
            || !o.notification_idempotency_confirmed
            || !self.allowed_sites.contains(&o.alarm_scope_site)
            || !o.escalation_confirmed
            || !o.coverage_24x7_confirmed
            || o.poll_seconds < 60
            || [
                &o.platform_owner,
                &o.soc_owner,
                &o.connector_owner,
                &o.privacy_owner,
                &o.release_owner,
                &o.backup_owner,
                &o.escalation_recipient,
                &o.escalation_backup,
            ]
            .iter()
            .any(|s| s.trim().is_empty())
        {
            bail!(
                "A1 requires named operators/backups, a confirmed reachable escalation path, explicit continuous coverage and polling >=60 seconds"
            );
        }
        Ok(())
    }
}
pub fn valid_env(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_offline_and_fail_closed() {
        let c = Config::default();
        c.validate().unwrap();
        assert!(c.live_gate().is_err());
        assert!(c.a1_gate().is_err());
    }
    #[test]
    fn cannot_bind_public_or_create_system_identity() {
        let mut c = Config::default();
        c.bind = "0.0.0.0:47841".into();
        assert!(c.validate().is_err());
        c.bind = "127.0.0.1:47841".into();
        c.users[0].role = "system".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn reject_unknown_configuration() {
        assert!(serde_json::from_str::<Config>(r#"{"allow_everything":true}"#).is_err());
    }
}
