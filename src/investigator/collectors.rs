//! Native, bounded, read-only evidence collectors. Caller input selects a case and a
//! configured source; query text, endpoints, credentials and LDAP commands are fixed.
use super::{config::valid_env, core::Principal, service::Service, worker};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::{Url, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::{io::Read, time::Duration};

pub const CONTRACT_VERSION: &str = "native-collectors-2026-10-06.2";
const LIMIT_BYTES: u64 = 1_048_576;
const LIMIT_ROWS: u64 = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudSource {
    pub enabled: bool,
    pub client_id: String,
    pub secret_env: String,
    pub approved_by: String,
    pub approved_at: String,
    pub coverage_start: String,
    pub coverage_end: String,
    pub retention_days: u32,
    pub region: String,
    pub site: String,
    pub site_scope_confirmed: bool,
    /// Entra userId UUIDs or Defender DeviceIds, according to the collector.
    pub target_ids: Vec<String>,
    pub rights_confirmed: bool,
    pub license_confirmed: bool,
    pub max_rows: u64,
    pub max_bytes: u64,
}
impl Default for CloudSource {
    fn default() -> Self {
        Self {
            enabled: false,
            client_id: String::new(),
            secret_env: String::new(),
            approved_by: String::new(),
            approved_at: String::new(),
            coverage_start: String::new(),
            coverage_end: String::new(),
            retention_days: 0,
            region: String::new(),
            site: String::new(),
            site_scope_confirmed: false,
            target_ids: Vec::new(),
            rights_confirmed: false,
            license_confirmed: false,
            max_rows: LIMIT_ROWS,
            max_bytes: LIMIT_BYTES,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogAnalyticsSource {
    #[serde(flatten)]
    pub cloud: CloudSource,
    pub workspace_id: String,
    /// Exact table schema, ingestion pipeline and field contract approved by the operator.
    pub table_schema_approved: bool,
    pub ingestion_pipeline: String,
    /// Required for network direction: source in this range, destination outside.
    pub internal_networks: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdcsSource {
    pub enabled: bool,
    /// Directory server used only for LDAP configuration discovery.
    pub server: String,
    /// CA host used for exact LDAP publication matching and native policy read.
    pub ca_host: String,
    /// Exact enrollment-service CN on the configured CA host. Required for new instances.
    pub ca_name: String,
    pub approved_by: String,
    pub approved_at: String,
    pub coverage_start: String,
    pub coverage_end: String,
    pub region: String,
    pub site: String,
    pub site_scope_confirmed: bool,
    pub read_rights_confirmed: bool,
    pub max_rows: u64,
    pub max_bytes: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Collectors {
    pub enabled: bool,
    pub entra_token: CloudSource,
    pub defender_process: CloudSource,
    pub log_analytics_storage: LogAnalyticsSource,
    pub log_analytics_network: LogAnalyticsSource,
    pub adcs: AdcsSource,
    /// Additional independently approved, site-bound instances.
    pub instances: Vec<CollectorInstance>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorInstance {
    pub id: String,
    pub source: String,
    pub cloud: Option<CloudSource>,
    pub analytics: Option<LogAnalyticsSource>,
    pub adcs: Option<AdcsSource>,
}

fn stamp(s: &str, label: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("{label} requires RFC3339 UTC time"))?
        .with_timezone(&Utc))
}
fn window(start: &str, end: &str, label: &str) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let a = stamp(start, label)?;
    let b = stamp(end, label)?;
    if a >= b {
        bail!("{label} has invalid time bounds")
    }
    Ok((a, b))
}
fn approval(by: &str, at: &str, label: &str) -> Result<()> {
    if by.trim().is_empty() || stamp(at, label)? > Utc::now() {
        bail!("{label} requires current named approval")
    }
    Ok(())
}
impl CloudSource {
    fn validate(&self, label: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        uuid::Uuid::parse_str(&self.client_id)
            .with_context(|| format!("{label}: client ID must be a UUID"))?;
        if !valid_env(&self.secret_env)
            || self.region.trim().is_empty()
            || self.site.trim().is_empty()
            || !self.site_scope_confirmed
            || !self.rights_confirmed
            || !self.license_confirmed
            || self.retention_days == 0
            || self.retention_days > 365
            || !(1..=LIMIT_ROWS).contains(&self.max_rows)
            || !(1024..=LIMIT_BYTES).contains(&self.max_bytes)
        {
            bail!(
                "{label}: missing secret reference, site scope, rights, license, region, retention or valid limits"
            )
        }
        if label == "Entra token collector" || label == "Defender process collector" {
            if self.target_ids.is_empty() || self.target_ids.len() > 20 {
                bail!("Cloud target_ids must contain 1..20 identities")
            }
            let mut unique = std::collections::HashSet::new();
            for id in &self.target_ids {
                if !unique.insert(id.to_ascii_lowercase()) {
                    bail!("Duplicate collector target ID")
                }
                if label == "Entra token collector" {
                    uuid::Uuid::parse_str(id).context("Entra target_ids must be userId UUIDs")?;
                } else if id.len() < 32
                    || id.len() > 128
                    || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
                {
                    bail!("Defender target_ids must be bounded hexadecimal DeviceIds")
                }
            }
        }
        approval(&self.approved_by, &self.approved_at, label)?;
        window(&self.coverage_start, &self.coverage_end, label)?;
        Ok(())
    }
}
impl LogAnalyticsSource {
    fn validate(&self, label: &str) -> Result<()> {
        self.cloud.validate(label)?;
        if self.cloud.enabled {
            uuid::Uuid::parse_str(&self.workspace_id)
                .with_context(|| format!("{label}: workspace ID must be a UUID"))?;
            if !self.table_schema_approved || self.ingestion_pipeline.trim().is_empty() {
                bail!("{label}: exact table schema and ingestion pipeline approval required")
            }
            if label == "CommonSecurityLog collector"
                && (self.internal_networks.is_empty()
                    || self
                        .internal_networks
                        .iter()
                        .any(|n| parse_cidr(n).is_err()))
            {
                bail!("Network collector requires valid internal CIDR ranges")
            }
        }
        Ok(())
    }
}
impl AdcsSource {
    fn validate(&self, require_name: bool) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.server.is_empty()
            || self.server.len() > 253
            || !self
                .server
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || (require_name && self.ca_host.is_empty())
            || self.ca_host.len() > 253
            || !self
                .ca_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || (require_name && self.ca_name.is_empty())
            || self.ca_name.len() > 128
            || !self
                .ca_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.')
            || self.region.trim().is_empty()
            || self.site.trim().is_empty()
            || !self.site_scope_confirmed
            || !self.read_rights_confirmed
            || !(1..=LIMIT_ROWS).contains(&self.max_rows)
            || !(1024..=LIMIT_BYTES).contains(&self.max_bytes)
        {
            bail!("AD CS server, CA name, site scope, read rights, region or limits invalid")
        }
        approval(&self.approved_by, &self.approved_at, "AD CS collector")?;
        window(&self.coverage_start, &self.coverage_end, "AD CS collector")?;
        Ok(())
    }
}
impl Collectors {
    pub fn validate(&self) -> Result<()> {
        self.entra_token.validate("Entra token collector")?;
        self.defender_process
            .validate("Defender process collector")?;
        self.log_analytics_storage
            .validate("StorageBlobLogs collector")?;
        self.log_analytics_network
            .validate("CommonSecurityLog collector")?;
        if self.adcs.enabled {
            if self.adcs.server.is_empty()
                || self.adcs.server.len() > 253
                || !self
                    .adcs
                    .server
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                || self.adcs.region.trim().is_empty()
                || self.adcs.site.trim().is_empty()
                || !self.adcs.site_scope_confirmed
                || !self.adcs.read_rights_confirmed
                || !(1..=LIMIT_ROWS).contains(&self.adcs.max_rows)
                || !(1024..=LIMIT_BYTES).contains(&self.adcs.max_bytes)
            {
                bail!("AD CS server, site scope, read rights, region or limits invalid")
            }
            approval(
                &self.adcs.approved_by,
                &self.adcs.approved_at,
                "AD CS collector",
            )?;
            window(
                &self.adcs.coverage_start,
                &self.adcs.coverage_end,
                "AD CS collector",
            )?;
        }
        if self.instances.len() > 50 {
            bail!("Too many collector instances")
        }
        let mut ids = std::collections::HashSet::new();
        for instance in &self.instances {
            if instance.id.is_empty()
                || instance.id.eq_ignore_ascii_case("legacy")
                || instance.id.len() > 64
                || !instance
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || !ids.insert(instance.id.to_ascii_lowercase())
            {
                bail!("Collector instance ID invalid or duplicated")
            }
            match instance.source.as_str() {
                "entra_token" | "defender_process"
                    if instance.cloud.is_some()
                        && instance.analytics.is_none()
                        && instance.adcs.is_none() =>
                {
                    let c = instance.cloud.as_ref().unwrap();
                    if !c.enabled {
                        bail!("Collector instance must be enabled")
                    }
                    c.validate(if instance.source == "entra_token" {
                        "Entra token collector"
                    } else {
                        "Defender process collector"
                    })?;
                }
                "log_analytics_storage" | "log_analytics_network"
                    if instance.analytics.is_some()
                        && instance.cloud.is_none()
                        && instance.adcs.is_none() =>
                {
                    let c = instance.analytics.as_ref().unwrap();
                    if !c.cloud.enabled {
                        bail!("Collector instance must be enabled")
                    }
                    c.validate(if instance.source == "log_analytics_storage" {
                        "StorageBlobLogs collector"
                    } else {
                        "CommonSecurityLog collector"
                    })?;
                }
                "adcs"
                    if instance.adcs.is_some()
                        && instance.cloud.is_none()
                        && instance.analytics.is_none() =>
                {
                    let c = instance.adcs.as_ref().unwrap();
                    if !c.enabled {
                        bail!("Collector instance must be enabled")
                    }
                    c.validate(true)?;
                }
                _ => bail!("Collector instance source and typed config mismatch"),
            }
        }
        if !self.enabled
            && (self.entra_token.enabled
                || self.defender_process.enabled
                || self.log_analytics_storage.cloud.enabled
                || self.log_analytics_network.cloud.enabled
                || self.adcs.enabled
                || !self.instances.is_empty())
        {
            bail!("Enable collector group explicitly before enabling a source")
        }
        Ok(())
    }
    pub(crate) fn enabled_cloud_sources(&self) -> Vec<&CloudSource> {
        let mut sources = Vec::new();
        for c in [
            &self.entra_token,
            &self.defender_process,
            &self.log_analytics_storage.cloud,
            &self.log_analytics_network.cloud,
        ] {
            if c.enabled {
                sources.push(c)
            }
        }
        for i in &self.instances {
            if let Some(c) = &i.cloud
                && c.enabled
            {
                sources.push(c)
            }
            if let Some(a) = &i.analytics
                && a.cloud.enabled
            {
                sources.push(&a.cloud)
            }
        }
        sources
    }
    fn selected(&self, source: &str) -> Result<Selected<'_>> {
        if !self.enabled {
            bail!("Native collectors disabled")
        }
        match source {
            "entra_token" if self.entra_token.enabled => Ok(Selected::Cloud(&self.entra_token)),
            "defender_process" if self.defender_process.enabled => {
                Ok(Selected::Cloud(&self.defender_process))
            }
            "log_analytics_storage" if self.log_analytics_storage.cloud.enabled => {
                Ok(Selected::Analytics(&self.log_analytics_storage))
            }
            "log_analytics_network" if self.log_analytics_network.cloud.enabled => {
                Ok(Selected::Analytics(&self.log_analytics_network))
            }
            "adcs" if self.adcs.enabled => Ok(Selected::Adcs(&self.adcs)),
            _ => bail!("Collector source disabled or unknown"),
        }
    }
}
#[derive(Clone, Copy)]
enum Selected<'a> {
    Cloud(&'a CloudSource),
    Analytics(&'a LogAnalyticsSource),
    Adcs(&'a AdcsSource),
}
impl CollectorInstance {
    fn selected(&self) -> Selected<'_> {
        if let Some(c) = &self.cloud {
            Selected::Cloud(c)
        } else if let Some(c) = &self.analytics {
            Selected::Analytics(c)
        } else {
            Selected::Adcs(self.adcs.as_ref().expect("validated AD CS instance"))
        }
    }
}
impl Collectors {
    fn candidates<'a>(&'a self, source: &str, site: &str) -> Vec<(&'a str, Selected<'a>)> {
        let mut all = Vec::new();
        if let Ok(selected) = self.selected(source)
            && selected.site() == site
        {
            all.push(("legacy", selected));
        }
        for instance in &self.instances {
            if instance.source == source {
                let selected = instance.selected();
                if selected.site() == site {
                    all.push((&instance.id, selected));
                }
            }
        }
        all
    }
    fn resolve<'a>(
        &'a self,
        source: &str,
        site: &str,
        instance_id: Option<&str>,
    ) -> Result<(&'a str, Selected<'a>)> {
        let all = self.candidates(source, site);
        if let Some(id) = instance_id {
            all.into_iter()
                .find(|(candidate, _)| *candidate == id)
                .context("Collector instance not enabled for case site")
        } else if all.len() == 1 {
            Ok(all[0])
        } else {
            bail!("Collector source absent or ambiguous for case site; specify instance_id")
        }
    }
}
impl Selected<'_> {
    fn limits(&self) -> (u64, u64) {
        match self {
            Self::Cloud(c) => (c.max_rows, c.max_bytes),
            Self::Analytics(c) => (c.cloud.max_rows, c.cloud.max_bytes),
            Self::Adcs(c) => (c.max_rows, c.max_bytes),
        }
    }
    fn coverage(&self) -> (&str, &str) {
        match self {
            Self::Cloud(c) => (&c.coverage_start, &c.coverage_end),
            Self::Analytics(c) => (&c.cloud.coverage_start, &c.cloud.coverage_end),
            Self::Adcs(c) => (&c.coverage_start, &c.coverage_end),
        }
    }
    fn site(&self) -> &str {
        match self {
            Self::Cloud(c) => &c.site,
            Self::Analytics(c) => &c.cloud.site,
            Self::Adcs(c) => &c.site,
        }
    }
}

#[derive(Clone, Debug)]
struct Request {
    url: Url,
    body: Option<Value>,
    token: Option<String>,
    form: Option<Vec<(String, String)>>,
    max_bytes: u64,
}
#[derive(Clone, Debug)]
struct Reply {
    status: u16,
    body: Value,
    bytes: u64,
}
trait Transport {
    fn send(&self, request: Request) -> Result<Reply>;
}
struct Http;
impl Transport for Http {
    fn send(&self, r: Request) -> Result<Reply> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut req = if r.body.is_some() || r.form.is_some() {
            client.post(r.url)
        } else {
            client.get(r.url)
        };
        if let Some(t) = r.token {
            req = req.bearer_auth(t)
        }
        if let Some(f) = r.form {
            req = req.form(&f)
        }
        if let Some(b) = r.body {
            req = req.json(&b)
        }
        let response = req
            .send()
            .map_err(|_| anyhow::anyhow!("Collector transport failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response.take(r.max_bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > r.max_bytes {
            bail!("Collector response exceeds byte limit")
        }
        let body =
            serde_json::from_slice(&bytes).context("Collector response is not valid JSON")?;
        Ok(Reply {
            status,
            body,
            bytes: bytes.len() as u64,
        })
    }
}
fn fixed_url(source: &str, tenant: &str, workspace: Option<&str>) -> Result<Url> {
    let url = match source {
        "oauth" => format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
        "entra_token" => "https://graph.microsoft.com/beta/auditLogs/signIns".into(),
        "defender_process" => "https://api.security.microsoft.com/api/advancedhunting/run".into(),
        "log_analytics_storage" | "log_analytics_network" => format!(
            "https://api.loganalytics.azure.com/v1/workspaces/{}/query",
            workspace.context("Workspace required")?
        ),
        _ => bail!("Unknown provider endpoint"),
    };
    Ok(Url::parse(&url)?)
}
fn scope(source: &str) -> Result<&'static str> {
    match source {
        "entra_token" => Ok("https://graph.microsoft.com/.default"),
        "defender_process" => Ok("https://api.security.microsoft.com/.default"),
        "log_analytics_storage" | "log_analytics_network" => {
            Ok("https://api.loganalytics.io/.default")
        }
        _ => bail!("No OAuth scope"),
    }
}
fn source_kind(source: &str) -> &'static str {
    match source {
        "entra_token" => "entra_token",
        "defender_process" => "endpoint",
        "log_analytics_storage" => "cloud_storage",
        "log_analytics_network" => "network",
        _ => "adcs",
    }
}
fn parse_cidr(s: &str) -> Result<(std::net::IpAddr, u8)> {
    let (ip, prefix) = s.split_once('/').context("CIDR prefix required")?;
    let ip: std::net::IpAddr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        bail!("CIDR prefix too long")
    }
    Ok((ip, prefix))
}
fn contains_cidr(cidr: &str, ip: std::net::IpAddr) -> Result<bool> {
    let (base, prefix) = parse_cidr(cidr)?;
    match (base, ip) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            let bits = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok((u32::from(a) & bits) == (u32::from(b) & bits))
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            let bits = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Ok((u128::from(a) & bits) == (u128::from(b) & bits))
        }
        _ => Ok(false),
    }
}
fn required<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .with_context(|| format!("Missing {key}"))
}
fn checked_time(v: &Value, key: &str) -> Result<String> {
    let s = required(v, key)?;
    stamp(s, key)?;
    Ok(s.to_owned())
}
fn charge_request(s: &Service, cid: &str, source: &str) -> Result<()> {
    worker::charge(s, cid, source)
}
fn reserve_bytes(s: &Service, cid: &str, bytes: u64) -> Result<()> {
    // Retain the worker's persistent case counter, including failed or malformed responses.
    let key = format!("worker:usage:{cid}");
    let mut db = s
        .ops
        .lock()
        .map_err(|_| anyhow::anyhow!("Collector budget lock poisoned"))?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM investigator_service_state WHERE tenant=?1 AND key=?2",
            rusqlite::params![s.config.tenant, key],
            |r| r.get(0),
        )
        .optional()?;
    let mut usage: Value = raw
        .map(|v| serde_json::from_str(&v))
        .transpose()?
        .unwrap_or(json!({}));
    let total = usage["bytes"].as_u64().unwrap_or(0).saturating_add(bytes);
    usage["bytes"] = json!(total);
    tx.execute("INSERT INTO investigator_service_state(tenant,key,value) VALUES(?1,?2,?3) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value",rusqlite::params![s.config.tenant,key,usage.to_string()])?;
    tx.commit()?;
    if total > s.config.budgets.case_result_bytes {
        bail!("Case response byte budget exceeded")
    }
    Ok(())
}
use rusqlite::OptionalExtension;
fn send<T: Transport>(
    t: &T,
    s: &Service,
    cid: &str,
    source: &str,
    r: Request,
    before_call: &dyn Fn() -> Result<bool>,
) -> Result<Reply> {
    if !(before_call)()? || s.stopped() {
        bail!("Collector worker readiness lost")
    }
    charge_request(s, cid, source)?;
    let response = t.send(r)?;
    reserve_bytes(s, cid, response.bytes)?;
    if !(200..300).contains(&response.status) {
        bail!("{source} provider returned HTTP {}", response.status)
    }
    Ok(response)
}
fn oauth<T: Transport>(
    t: &T,
    s: &Service,
    cid: &str,
    source: &str,
    c: &CloudSource,
    before_call: &dyn Fn() -> Result<bool>,
) -> Result<String> {
    let secret = std::env::var(&c.secret_env).context("Collector secret reference unavailable")?;
    if secret.is_empty() {
        bail!("Collector secret empty")
    }
    let reply = send(
        t,
        s,
        cid,
        source,
        Request {
            url: fixed_url("oauth", &s.config.tenant, None)?,
            body: None,
            token: None,
            form: Some(vec![
                ("grant_type".into(), "client_credentials".into()),
                ("client_id".into(), c.client_id.clone()),
                ("client_secret".into(), secret),
                ("scope".into(), scope(source)?.into()),
            ]),
            max_bytes: 65_536,
        },
        before_call,
    )?;
    Ok(required(&reply.body, "access_token")?.to_owned())
}
fn graph_url(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    rows: u64,
    targets: &[String],
) -> Result<Url> {
    let mut url = fixed_url("entra_token", "", None)?;
    let users = targets
        .iter()
        .map(|u| format!("userId eq '{u}'"))
        .collect::<Vec<_>>()
        .join(" or ");
    url.query_pairs_mut()
        .append_pair("$top", &rows.to_string())
        .append_pair(
            "$filter",
            &format!(
                "createdDateTime ge {} and createdDateTime le {} and ({users})",
                start.to_rfc3339(),
                end.to_rfc3339()
            ),
        );
    Ok(url)
}
fn kql(
    source: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    rows: u64,
    targets: &[String],
) -> Result<String> {
    // Only numeric limits and validated timestamps enter the fixed templates.
    let time = format!(
        "| where TimeGenerated between (datetime({}) .. datetime({}))",
        start.to_rfc3339(),
        end.to_rfc3339()
    );
    let q = match source {
        "defender_process" => {
            let ids = targets
                .iter()
                .map(|id| format!("'{id}'"))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "DeviceProcessEvents\n| where Timestamp between (datetime({}) .. datetime({}))\n| where DeviceId in ({ids})\n| project Timestamp, DeviceId, DeviceName, ReportId, ProcessId, FileName, InitiatingProcessFileName, InitiatingProcessId, AccountSid\n| take {rows}",
                start.to_rfc3339(),
                end.to_rfc3339()
            )
        }
        "log_analytics_storage" => format!(
            "StorageBlobLogs\n{time}\n| project TimeGenerated, IngestedAt=ingestion_time(), Uri, OperationName, StatusCode, RequesterObjectId, CallerIpAddress, ResponseBodySize, ClientRequestId, CorrelationId\n| take {rows}"
        ),
        "log_analytics_network" => format!(
            "CommonSecurityLog\n{time}\n| project TimeGenerated, IngestedAt=ingestion_time(), SourceIP, DestinationIP, SourceUserName, SentBytes, DeviceAction, DeviceVendor, DeviceProduct\n| take {rows}"
        ),
        _ => bail!("Unknown fixed query template"),
    };
    Ok(q)
}
fn record(source: &str, v: &Value, observed: DateTime<Utc>, internal: &[String]) -> Result<Value> {
    let (native, event, fields) = match source {
        "entra_token" => {
            let id = required(v, "id")?.to_owned();
            let at = checked_time(v, "createdDateTime")?;
            let token = v["uniqueTokenIdentifier"]
                .as_str()
                .filter(|x| !x.is_empty());
            let session = v["sessionId"].as_str().filter(|x| !x.is_empty());
            let mut f = json!({"kind":"token_event","app_id":v["appId"],"ip":v["ipAddress"],"device_id":v["deviceDetail"]["deviceId"],"outcome":if v["status"]["errorCode"]==0{"success"}else{"failure"},"native_signin_id":id,"token_identifier_available":token.is_some(),"session_identifier_available":session.is_some(),"ingestion_time":observed,"provider":"microsoft_graph_signins"});
            if let Some(x) = token {
                f["token_id"] = json!(x)
            }
            if let Some(x) = session {
                f["session_id"] = json!(x)
            }
            (id, at, f)
        }
        "defender_process" => {
            let at = checked_time(v, "Timestamp")?;
            let device = required(v, "DeviceId")?;
            let report = v["ReportId"]
                .as_i64()
                .context("Defender ReportId required")?;
            let pid = v["ProcessId"]
                .as_i64()
                .context("Defender ProcessId required")?;
            let id = format!("{device}:{report}:{pid}:{at}");
            (
                id,
                at,
                json!({"kind":"process_event","device_id":device,"device_name":v["DeviceName"],"parent_process":required(v,"InitiatingProcessFileName")?,"process":required(v,"FileName")?,"initiating_process_id":v["InitiatingProcessId"],"account_sid":v["AccountSid"],"ingestion_time":observed,"provider":"microsoft_defender_advanced_hunting"}),
            )
        }
        "log_analytics_storage" => {
            let at = checked_time(v, "TimeGenerated")?;
            let op = required(v, "OperationName")?;
            let status = required(v, "StatusCode")?;
            let status_code = status.parse::<u16>().ok();
            let uri = required(v, "Uri")?;
            let url = Url::parse(uri).context("Storage Uri invalid")?;
            if url.scheme() != "https"
                || !url
                    .host_str()
                    .is_some_and(|h| h.ends_with(".blob.core.windows.net"))
            {
                bail!("Storage Uri outside Azure Blob scope")
            }
            let host = url.host_str().unwrap();
            let mut clean = url.clone();
            clean.set_query(None);
            clean.set_fragment(None);
            let id = format!(
                "{}:{}:{}:{}",
                v["CorrelationId"].as_str().unwrap_or(""),
                at,
                op,
                clean
            );
            (
                id,
                at,
                json!({"kind":"object_access","object_id":clean.to_string(),"operation":if op.contains("GetBlob"){"read"}else{"other"},"native_action":op,"object_count":1,"bytes":v["ResponseBodySize"],"principal":v["RequesterObjectId"],"destination":host,"caller_ip":v["CallerIpAddress"],"client_request_id":v["ClientRequestId"],"native_correlation_id":v["CorrelationId"],"outcome":if status_code.is_some_and(|x|(200..300).contains(&x)){"success"}else if matches!(status_code,Some(401|403)){"denied"}else{"failure"},"ingestion_time":v["IngestedAt"],"provider":"azure_monitor_StorageBlobLogs"}),
            )
        }
        "log_analytics_network" => {
            let at = checked_time(v, "TimeGenerated")?;
            let src = required(v, "SourceIP")?;
            let dest = required(v, "DestinationIP")?;
            let src_ip = src.parse::<std::net::IpAddr>()?;
            let dest_ip = dest.parse::<std::net::IpAddr>()?;
            let inside_src = internal
                .iter()
                .map(|n| contains_cidr(n, src_ip))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|x| x);
            let inside_dest = internal
                .iter()
                .map(|n| contains_cidr(n, dest_ip))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|x| x);
            let bytes = v["SentBytes"].as_i64().context("SentBytes required")?;
            if bytes < 0 {
                bail!("Negative SentBytes")
            }
            let action = required(v, "DeviceAction")?;
            let success = ["allow", "allowed", "accept", "accepted"]
                .iter()
                .any(|x| action.eq_ignore_ascii_case(x));
            let id = format!(
                "{:x}",
                sha2::Sha256::digest(json!([at, v]).to_string().as_bytes())
            );
            (
                id,
                at,
                json!({"kind":"network_flow","source_ip":src,"destination_ip":dest,"destination":dest,"principal":v["SourceUserName"],"bytes_out":bytes,"direction":if inside_src&&!inside_dest{"outbound"}else{"unknown"},"native_action":action,"outcome":if success{"success"}else{"blocked"},"ingestion_time":v["IngestedAt"],"device_vendor":v["DeviceVendor"],"device_product":v["DeviceProduct"],"provider":"azure_monitor_CommonSecurityLog","source_id_kind":"deterministic_content_digest"}),
            )
        }
        _ => bail!("Unsupported normalized source"),
    };
    Ok(
        json!({"source":source_kind(source),"source_id":native,"event_time":event,"query_version":CONTRACT_VERSION,"fields":fields}),
    )
}

fn analytics_rows(body: &Value) -> Result<Vec<Value>> {
    let tables = body["tables"]
        .as_array()
        .context("Log Analytics tables missing")?;
    if tables.len() != 1 {
        bail!("Log Analytics returned unexpected table count")
    }
    let table = &tables[0];
    let columns = table["columns"]
        .as_array()
        .context("Log Analytics columns missing")?;
    let mut names = std::collections::HashSet::new();
    let mut labels = Vec::new();
    for c in columns {
        let name = required(c, "name")?;
        if !names.insert(name.to_owned()) {
            bail!("Duplicate Log Analytics column")
        }
        labels.push(name.to_owned());
    }
    let rows = table["rows"]
        .as_array()
        .context("Log Analytics rows missing")?;
    rows.iter()
        .map(|r| {
            let cells = r.as_array().context("Log Analytics row is not an array")?;
            if cells.len() != labels.len() {
                bail!("Log Analytics row width changed")
            }
            Ok(Value::Object(
                labels.iter().cloned().zip(cells.iter().cloned()).collect(),
            ))
        })
        .collect()
}
fn validate_case_scope(
    s: &Service,
    p: &Principal,
    payload: &Value,
    source: &str,
    selected: &Selected<'_>,
) -> Result<(Value, DateTime<Utc>, DateTime<Utc>)> {
    let internal = p.role == "system" && p.actor == s.system().actor && p.tenant == s.config.tenant;
    if !internal && !["admin", "analyst", "incident_lead"].contains(&p.role.as_str()) {
        bail!("Collector action forbidden")
    }
    if !internal
        && (p.tenant != s.config.tenant
            || !s
                .config
                .users
                .iter()
                .any(|u| u.actor == p.actor && u.role == p.role))
    {
        bail!("Collector identity invalid")
    }
    if payload.as_object().is_none_or(|o| {
        (o.len() != 2 && o.len() != 3)
            || !o.contains_key("source")
            || !o.contains_key("case_id")
            || (o.len() == 3 && !o.contains_key("instance_id"))
    }) {
        bail!("Collector accepts only source, case_id and optional instance_id")
    }
    if s.stopped() {
        bail!("Service stopped")
    }
    if s.state("recovery:last")?["reconciliation_required"] == true {
        bail!("Restore reconciliation required")
    }
    if !s.config.operations.encrypted_volume_confirmed || !s.config.operations.retention_approved {
        bail!("Encrypted storage and retention approval required")
    }
    if s.config.tenant != p.tenant {
        bail!("Cross-tenant collection denied")
    }
    let cid = required(payload, "case_id")?;
    let case = s.exec(p, "cases.get", json!({"case_id":cid}))?;
    if case["tenant"] != p.tenant
        || !s
            .config
            .allowed_sites
            .iter()
            .any(|site| case["site"] == *site)
    {
        bail!("Case tenant or site outside approved scope")
    }
    if case["site"] != selected.site() {
        bail!("Case site does not match approved native source binding")
    }
    let (start, end) = window(required(&case, "start")?, required(&case, "end")?, "case")?;
    if end > Utc::now() + ChronoDuration::minutes(5) {
        bail!("Case interval extends into the future")
    }
    if end - start > ChronoDuration::hours(24) {
        bail!("Case window exceeds 24 hours")
    }
    let (first, last) = selected.coverage();
    let (first, last) = window(first, last, source)?;
    if start < first || end > last {
        bail!("Requested case interval is outside attested source coverage or retention")
    }
    if source == "adcs" && (end < Utc::now() || start > Utc::now()) {
        bail!("AD CS is a current snapshot; case interval must include collection time")
    }
    Ok((case, start, end))
}
#[allow(clippy::too_many_arguments)] // Explicit immutable query scope and pre-call gate stay visible at the transport boundary.
fn response_rows<T: Transport>(
    t: &T,
    s: &Service,
    cid: &str,
    source: &str,
    c: &CloudSource,
    workspace: Option<&str>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    before_call: &dyn Fn() -> Result<bool>,
) -> Result<(Vec<Value>, u64, bool)> {
    let token = oauth(t, s, cid, source, c, before_call)?;
    let (url, body) = match source {
        "entra_token" => (graph_url(start, end, c.max_rows, &c.target_ids)?, None),
        "defender_process" => (
            fixed_url(source, &s.config.tenant, None)?,
            Some(json!({"Query":kql(source,start,end,c.max_rows,&c.target_ids)?})),
        ),
        "log_analytics_storage" | "log_analytics_network" => {
            let mut url = fixed_url(source, &s.config.tenant, workspace)?;
            url.query_pairs_mut().append_pair(
                "timespan",
                &format!("{}/{}", start.to_rfc3339(), end.to_rfc3339()),
            );
            (
                url,
                Some(json!({"query":kql(source,start,end,c.max_rows,&[])?})),
            )
        }
        _ => bail!("Unknown cloud collector"),
    };
    let reply = send(
        t,
        s,
        cid,
        source,
        Request {
            url,
            body,
            token: Some(token),
            form: None,
            max_bytes: c.max_bytes,
        },
        before_call,
    )?;
    let (rows, continued) = match source {
        "entra_token" => {
            let rows = reply.body["value"]
                .as_array()
                .context("Graph signIns value missing")?
                .clone();
            let continued = reply.body.get("@odata.nextLink").is_some();
            if continued {
                // A single bounded page is intentional. Never follow an untrusted nextLink.
                let next = required(&reply.body, "@odata.nextLink")?;
                let parsed = Url::parse(next)?;
                if parsed.scheme() != "https"
                    || parsed.host_str() != Some("graph.microsoft.com")
                    || parsed.path() != "/beta/auditLogs/signIns"
                    || parsed.port_or_known_default() != Some(443)
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                {
                    bail!("Graph continuation left approved endpoint")
                }
            }
            (rows, continued)
        }
        "defender_process" => (
            reply.body["Results"]
                .as_array()
                .context("Defender Results missing")?
                .clone(),
            false,
        ),
        _ => (
            analytics_rows(&reply.body)?,
            reply.body.get("error").is_some() || reply.body.get("partialError").is_some(),
        ),
    };
    if rows.len() as u64 > c.max_rows {
        bail!("Provider exceeded row limit")
    }
    validate_target_rows(source, &rows, &c.target_ids)?;
    let partial = continued || rows.len() as u64 == c.max_rows;
    Ok((rows, reply.bytes, partial))
}
fn validate_target_rows(source: &str, rows: &[Value], targets: &[String]) -> Result<()> {
    let field = match source {
        "entra_token" => "userId",
        "defender_process" => "DeviceId",
        _ => return Ok(()),
    };
    if rows.iter().any(|r| {
        r[field]
            .as_str()
            .is_none_or(|id| !targets.iter().any(|t| t.eq_ignore_ascii_case(id)))
    }) {
        bail!("Provider row outside configured {field} scope")
    }
    Ok(())
}
fn coverage(
    source: &str,
    instance_id: &str,
    status: &str,
    reason: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    owner: &str,
) -> Value {
    json!({"source":source_kind(source),"source_kind":source_kind(source),"provider":source,"instance_id":instance_id,"status":status,"reason":reason,"start":start,"end":end,"observed_at":Utc::now(),"owner":owner,"query_version":CONTRACT_VERSION})
}
fn health(
    s: &Service,
    source: &str,
    instance_id: &str,
    status: &str,
    reason: &str,
    rows: usize,
) -> Result<()> {
    s.set_state(&format!("collector:health:{source}:{instance_id}"),json!({"source":source,"instance_id":instance_id,"status":status,"reason":reason,"records":rows,"checked_at":Utc::now(),"query_version":CONTRACT_VERSION}))
}
fn run_with<T: Transport>(
    t: &T,
    s: &Service,
    p: &Principal,
    action: &str,
    payload: Value,
    before_call: &dyn Fn() -> Result<bool>,
) -> Result<Value> {
    s.config.collectors.validate()?;
    if !s.config.collectors.enabled {
        bail!("Native collectors disabled")
    }
    let source = required(&payload, "source")?;
    let id = payload
        .get("instance_id")
        .map(|_| required(&payload, "instance_id"))
        .transpose()?;
    let preliminary = s.exec(
        p,
        "cases.get",
        json!({"case_id":required(&payload,"case_id")?}),
    )?;
    let site = required(&preliminary, "site")?;
    let (instance_id, selected) = s.config.collectors.resolve(source, site, id)?;
    let (case, start, end) = validate_case_scope(s, p, &payload, source, &selected)?;
    let cid = required(&case, "id")?;
    let result = (match &selected {
        Selected::Cloud(c) => response_rows(t, s, cid, source, c, None, start, end, before_call),
        Selected::Analytics(c) => response_rows(
            t,
            s,
            cid,
            source,
            &c.cloud,
            Some(&c.workspace_id),
            start,
            end,
            before_call,
        ),
        Selected::Adcs(c) => adcs_snapshot(s, cid, c, start, end, before_call),
    })
    .and_then(|(rows, bytes, partial)| {
        if rows.len() as u64 > selected.limits().0 {
            bail!("Collector row limit exceeded")
        }
        let internal: &[String] = if source == "log_analytics_network" {
            match &selected {
                Selected::Analytics(c) => &c.internal_networks,
                _ => &[],
            }
        } else {
            &[]
        };
        let observed = Utc::now();
        for row in &rows {
            let event = if source == "adcs" {
                adcs_record(row, observed)?
            } else {
                record(source, row, observed, internal)?
            };
            let at = stamp(required(&event, "event_time")?, "event time")?;
            if at < start || at > end {
                bail!("Provider returned event outside case interval")
            }
        }
        Ok((rows, bytes, partial))
    });
    let (rows, bytes, partial) = match result {
        Ok(v) => v,
        Err(e) => {
            if e.to_string().contains("Collector worker readiness lost") {
                return Err(e);
            }
            let reason = format!("{e:#}");
            health(s, source, instance_id, "failed", &reason, 0)?;
            if action == "collectors.run" {
                s.exec(p,"evidence.ingest",json!({"case_id":cid,"evidence":[],"coverage":[coverage(source,instance_id,"unavailable",&reason,start,end,&p.actor)]}))?;
            }
            s.audit(
                "collectors.failed",
                json!({"case_id":cid,"source":source,"reason":reason}),
            )?;
            return Err(e);
        }
    };
    let max_rows = selected.limits().0;
    if rows.len() as u64 > max_rows {
        bail!("Collector row limit exceeded")
    }
    let fetched = Utc::now();
    let internal: &[String] = if source == "log_analytics_network" {
        match &selected {
            Selected::Analytics(c) => &c.internal_networks,
            _ => &[],
        }
    } else {
        &[]
    };
    let events = rows
        .iter()
        .map(|r| {
            let mut event = if source == "adcs" {
                adcs_record(r, fetched)
            } else {
                record(source, r, fetched, internal)
            }?;
            event["fields"]["collector_instance_id"] = json!(instance_id);
            Ok(event)
        })
        .collect::<Result<Vec<_>>>()?;
    if events.iter().any(|e| {
        stamp(required(e, "event_time").unwrap_or(""), "event time")
            .map_or(true, |at| at < start || at > end)
    }) {
        bail!("Provider returned event outside case interval")
    }
    let id_gaps = source == "entra_token"
        && events.iter().any(|e| {
            e["fields"]["token_identifier_available"] != true
                && e["fields"]["session_identifier_available"] != true
        });
    let status = if partial || id_gaps || events.is_empty() {
        "partial"
    } else {
        "available"
    };
    let reason = if events.is_empty() {
        "No rows observed; source data, schema and retention coverage remain unproven"
    } else if partial {
        "Provider reported partial results, additional rows, or configured row limit reached; bounded page only"
    } else if id_gaps {
        "Graph signIn record lacks a provider token/session identifier; token reuse cannot be correlated for that record"
    } else {
        "Bounded native query returned within approved interval and schema"
    };
    if action == "collectors.run" {
        s.exec(p,"evidence.ingest",json!({"case_id":cid,"evidence":events,"coverage":[coverage(source,instance_id,status,reason,start,end,&p.actor)]}))?;
    }
    health(
        s,
        source,
        instance_id,
        if status == "available" {
            "passed"
        } else {
            "partial"
        },
        reason,
        events.len(),
    )?;
    s.audit("collectors.query",json!({"case_id":cid,"source":source,"instance_id":instance_id,"mode":action,"rows":events.len(),"bytes":bytes,"coverage":status}))?;
    Ok(
        json!({"case_id":cid,"source":source,"instance_id":instance_id,"rows":events.len(),"bytes":bytes,"coverage":status,"reason":reason,"query_version":CONTRACT_VERSION,"probe":action=="collectors.probe"}),
    )
}
pub fn handle(s: &Service, p: &Principal, action: &str, payload: Value) -> Result<Value> {
    match action {
        "collectors.status" => {
            if p.tenant != s.config.tenant
                || !s
                    .config
                    .users
                    .iter()
                    .any(|u| u.actor == p.actor && u.role == p.role)
            {
                bail!("Unauthorized collector status")
            }
            let c = &s.config.collectors;
            let mut sources = Vec::new();
            for (source, enabled) in [
                ("entra_token", c.entra_token.enabled),
                ("defender_process", c.defender_process.enabled),
                (
                    "log_analytics_storage",
                    c.log_analytics_storage.cloud.enabled,
                ),
                (
                    "log_analytics_network",
                    c.log_analytics_network.cloud.enabled,
                ),
                ("adcs", c.adcs.enabled),
            ] {
                sources.push(
                    json!({"id":source,"source":source,"instance_id":"legacy","enabled":enabled,
                    "health":s.state(&format!("collector:health:{source}:legacy"))?}),
                );
            }
            for i in &c.instances {
                sources.push(
                    json!({"id":i.id,"source":i.source,"instance_id":i.id,"enabled":true,
                    "health":s.state(&format!("collector:health:{}:{}",i.source,i.id))?}),
                );
            }
            Ok(json!({"enabled":c.enabled,"contract_version":CONTRACT_VERSION,"sources":sources}))
        }
        "collectors.probe" | "collectors.run" => {
            run_with(&Http, s, p, action, payload, &|| Ok(true))
        }
        _ => bail!("Unknown collector action"),
    }
}

/// Called only by the leased worker after its readiness checks. Never exposed as an RPC action.
pub(crate) fn run_for_worker(
    s: &Service,
    case: &Value,
    before_call: impl Fn() -> Result<bool>,
) -> Result<Value> {
    if !s.config.collectors.enabled {
        return Ok(json!({"status":"disabled","sources":[]}));
    }
    let cid = required(case, "id")?;
    let site = required(case, "site")?;
    let p = s.system();
    let mut results = Vec::new();
    for source in [
        "entra_token",
        "defender_process",
        "log_analytics_storage",
        "log_analytics_network",
        "adcs",
    ] {
        for (instance_id, _) in s.config.collectors.candidates(source, site) {
            if !(before_call)()? || s.stopped() {
                return Ok(
                    json!({"paused":true,"case_id":cid,"reason":"Collector worker readiness lost","sources":results}),
                );
            }
            let result = run_with(
                &Http,
                s,
                &p,
                "collectors.run",
                json!({"case_id":cid,"source":source,"instance_id":instance_id}),
                &before_call,
            );
            results.push(match result {
                Ok(v) => v,
                Err(e) if e.to_string().contains("Collector worker readiness lost") =>
                    return Ok(json!({"paused":true,"case_id":cid,"reason":"Collector worker readiness lost","sources":results})),
                Err(e) => json!({"source":source,"instance_id":instance_id,"coverage":"unavailable","reason":format!("{e:#}")}),
            });
        }
    }
    Ok(json!({"case_id":cid,"sources":results}))
}
#[cfg(windows)]
struct TempSnapshotFile(std::path::PathBuf);
#[cfg(windows)]
impl Drop for TempSnapshotFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[cfg(windows)]
struct SnapshotChild(std::process::Child);
#[cfg(windows)]
impl Drop for SnapshotChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn adcs_snapshot(
    s: &Service,
    cid: &str,
    c: &AdcsSource,
    _start: DateTime<Utc>,
    _end: DateTime<Utc>,
    before_call: &dyn Fn() -> Result<bool>,
) -> Result<(Vec<Value>, u64, bool)> {
    #[cfg(not(windows))]
    {
        let _ = (s, cid, c, before_call);
        bail!("Native AD CS collector requires Windows")
    }
    #[cfg(windows)]
    {
        use base64::Engine;
        use std::{
            ffi::OsString,
            fs::File,
            io::Read,
            os::windows::{ffi::OsStringExt, process::CommandExt},
            process::{Command, Stdio},
            thread,
            time::Instant,
        };
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        }
        let mut system_dir = [0u16; 32768];
        let n = unsafe { GetSystemDirectoryW(system_dir.as_mut_ptr(), system_dir.len() as u32) }
            as usize;
        if n == 0 || n >= system_dir.len() {
            bail!("Cannot resolve Windows system directory")
        }
        let powershell = std::path::PathBuf::from(OsString::from_wide(&system_dir[..n]))
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !(before_call)()? || s.stopped() {
            bail!("Collector worker readiness lost")
        }
        charge_request(s, cid, "adcs")?;
        let script = include_str!("../../integrations/investigator/collectors/adcs-snapshot.ps1");
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        let db_path: String = {
            let db = s
                .ops
                .lock()
                .map_err(|_| anyhow::anyhow!("Collector database lock poisoned"))?;
            db.query_row("PRAGMA database_list", [], |row| row.get(2))?
        };
        let approved_dir = std::path::PathBuf::from(db_path).canonicalize()?;
        let approved_dir = approved_dir
            .parent()
            .context("Investigator database has no directory")?;
        let path = approved_dir.join(format!("aivana-adcs-{}.json", uuid::Uuid::new_v4()));
        let _cleanup = TempSnapshotFile(path.clone());
        let output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut child = SnapshotChild(
            Command::new(powershell)
                .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
                .env("AIVANA_ADCS_LDAP_SERVER", &c.server)
                .env(
                    "AIVANA_ADCS_CA_HOST",
                    if c.ca_host.is_empty() {
                        &c.server
                    } else {
                        &c.ca_host
                    },
                )
                .env("AIVANA_ADCS_CA_NAME", &c.ca_name)
                .stdin(Stdio::null())
                .stdout(Stdio::from(output))
                .stderr(Stdio::null())
                .creation_flags(0x08000000)
                .spawn()
                .context("Cannot start bundled read-only AD CS snapshot")?,
        );
        let began = Instant::now();
        let status = loop {
            if !(before_call)().unwrap_or(false) || s.stopped() {
                let _ = child.0.kill();
                let _ = child.0.wait();
                let _ = std::fs::remove_file(&path);
                bail!("Collector worker readiness lost")
            }
            if began.elapsed() >= Duration::from_secs(15) {
                let _ = child.0.kill();
                let _ = child.0.wait();
                let _ = std::fs::remove_file(&path);
                bail!("AD CS snapshot timed out")
            }
            if std::fs::metadata(&path).is_ok_and(|m| m.len() > c.max_bytes) {
                let _ = child.0.kill();
                let _ = child.0.wait();
                let _ = std::fs::remove_file(&path);
                bail!("AD CS snapshot exceeds byte limit")
            }
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            thread::sleep(Duration::from_millis(250));
        };
        let mut bytes = Vec::new();
        let read = File::open(&path)?
            .take(c.max_bytes + 1)
            .read_to_end(&mut bytes);
        let _ = std::fs::remove_file(&path);
        read?;
        reserve_bytes(s, cid, bytes.len() as u64)?;
        if bytes.len() as u64 > c.max_bytes {
            bail!("AD CS snapshot exceeds byte limit")
        }
        if !status.success() {
            bail!(
                "AD CS LDAP snapshot failed; verify directory read rights and server connectivity"
            )
        }
        // PowerShell may emit a UTF-8 BOM and a single object instead of an array.
        let raw = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
        let value: Value = serde_json::from_slice(raw).context("AD CS snapshot JSON invalid")?;
        let rows = match value {
            Value::Array(a) => a,
            Value::Object(_) => vec![value],
            Value::Null => vec![],
            _ => bail!("AD CS snapshot shape invalid"),
        };
        if rows.len() as u64 > c.max_rows {
            bail!("AD CS snapshot row limit exceeded")
        }
        if rows.iter().any(|r| {
            r["ca_dns_host"].as_str().is_none_or(|host| {
                !host.eq_ignore_ascii_case(if c.ca_host.is_empty() {
                    &c.server
                } else {
                    &c.ca_host
                })
            }) || (!c.ca_name.is_empty() && r["ca_name"].as_str() != Some(c.ca_name.as_str()))
        }) {
            bail!("AD CS snapshot contains a CA outside approved host/name scope")
        }
        let partial = rows.len() as u64 == c.max_rows
            || rows.iter().any(|r| {
                (r["kind"] == "ca_settings" && r["ca_policy_status"] != "native_registry")
                    || (r["kind"] == "template_acl" && r["low_privileged_enroll"].is_null())
            });
        Ok((rows, bytes.len() as u64, partial))
    }
}
fn native_ca_approval(raw: Option<i64>) -> Option<bool> {
    match raw {
        Some(0 | 257) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}
fn adcs_record(v: &Value, at: DateTime<Utc>) -> Result<Value> {
    let kind = required(v, "kind")?;
    if !["certificate_template", "template_acl", "ca_settings"].contains(&kind) {
        bail!("Unknown AD CS snapshot kind")
    }
    if kind == "ca_settings" {
        let expected = native_ca_approval(v["request_disposition"].as_i64());
        let actual = v["issuance_requires_approval"].as_bool();
        if expected != actual
            || (expected.is_some() != (v["ca_policy_status"] == "native_registry"))
        {
            bail!("AD CS CA policy status/value inconsistent")
        }
    }
    let native = required(v, "native_id")?;
    required(v, "template")?;
    required(v, "ca")?;
    let mut fields = v.clone();
    if let Some(map) = fields.as_object_mut() {
        map.remove("native_id");
    }
    Ok(
        json!({"source":"adcs","source_id":native,"event_time":at,"query_version":CONTRACT_VERSION,"fields":fields}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn local_service(mut config: super::super::config::Config) -> Service {
        config.users[0].token_env = "AIVANA_TEST_COLLECTOR_UNUSED_TOKEN".into();
        let path = std::env::temp_dir().join(format!(
            "aivana-collector-test-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        Service::open(&path, config).unwrap()
    }
    fn playbook_case(events: Vec<Value>, now: DateTime<Utc>) -> Value {
        let evidence=events.into_iter().enumerate().map(|(i,e)|json!({"id":format!("e{i}"),"source":e["source"],"source_id":e["source_id"],"event_time":e["event_time"],"fields":e["fields"],"retention_until":now+ChronoDuration::days(1),"retrieval_status":"success"})).collect::<Vec<_>>();
        json!({"start":now-ChronoDuration::hours(1),"end":now+ChronoDuration::minutes(1),"evidence":evidence,"coverage":[],"playbooks":[]})
    }
    #[test]
    fn all_native_queries_are_fixed_and_bounded() {
        let end = Utc::now();
        let start = end - ChronoDuration::hours(1);
        for source in [
            "defender_process",
            "log_analytics_storage",
            "log_analytics_network",
        ] {
            let query = kql(
                source,
                start,
                end,
                20,
                &["abcdef0123456789abcdef0123456789".into()],
            )
            .unwrap();
            assert!(query.contains("take 20"));
            assert!(!query.contains("let "));
        }
        assert!(kql("arbitrary", start, end, 20, &[]).is_err());
    }
    #[test]
    fn graph_signin_never_invents_token_or_session_identifier() {
        let raw = json!({"id":"signin-1","createdDateTime":"2026-10-05T09:00:00Z","appId":"app","ipAddress":"192.0.2.1","status":{"errorCode":0}});
        let event = record("entra_token", &raw, Utc::now(), &[]).unwrap();
        assert!(event["fields"].get("token_id").is_none());
        assert!(event["fields"].get("session_id").is_none());
        assert_eq!(event["fields"]["token_identifier_available"], false);
    }
    #[test]
    fn source_configuration_fails_closed() {
        let mut cfg = Collectors::default();
        cfg.entra_token.enabled = true;
        assert!(cfg.validate().is_err());
        cfg.enabled = true;
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn analytics_schema_columns_are_checked() {
        let body = json!({"tables":[{"columns":[{"name":"TimeGenerated"},{"name":"_ItemId"}],"rows":[["2026-10-05T09:00:00Z","id"]]}]});
        assert_eq!(analytics_rows(&body).unwrap()[0]["_ItemId"], "id");
        let bad = json!({"tables":[{"columns":[{"name":"id"},{"name":"id"}],"rows":[[1,2]]}]});
        assert!(analytics_rows(&bad).is_err());
    }
    #[test]
    fn defender_native_row_drives_existing_process_playbook() {
        let now = Utc::now();
        let raw = json!({"Timestamp":now.to_rfc3339(),"DeviceId":"abcdef0123456789abcdef0123456789","ReportId":42,"ProcessId":7,"FileName":"powershell.exe","InitiatingProcessFileName":"winword.exe"});
        let event = record("defender_process", &raw, now, &[]).unwrap();
        let mut case = playbook_case(vec![event], now);
        let finding =
            super::super::playbooks::run(&mut case, "endpoint_process_chain", now).unwrap();
        assert_eq!(finding["result"]["findings"][0]["status"], "suspected");
    }
    #[test]
    fn graph_beta_session_rows_drive_existing_token_playbook() {
        let now = Utc::now();
        let first = json!({"id":"signin-1","createdDateTime":now.to_rfc3339(),"appId":"app","ipAddress":"192.0.2.1","sessionId":"provider-session","status":{"errorCode":0}});
        let second = json!({"id":"signin-2","createdDateTime":(now+ChronoDuration::minutes(2)).to_rfc3339(),"appId":"app","ipAddress":"198.51.100.2","sessionId":"provider-session","status":{"errorCode":0}});
        let a = record("entra_token", &first, now, &[]).unwrap();
        let b = record("entra_token", &second, now, &[]).unwrap();
        let mut case = playbook_case(vec![a, b], now + ChronoDuration::minutes(3));
        let finding = super::super::playbooks::run(
            &mut case,
            "token_misuse",
            now + ChronoDuration::minutes(3),
        )
        .unwrap();
        assert_eq!(finding["result"]["findings"][0]["status"], "suspected");
    }
    #[test]
    fn storage_and_network_keep_native_semantics_and_analysis_gap() {
        let now = Utc::now();
        let storage = json!({"TimeGenerated":now.to_rfc3339(),"IngestedAt":now.to_rfc3339(),"Uri":"https://account.blob.core.windows.net/c/object?sig=secret","OperationName":"GetBlob","StatusCode":"200","RequesterObjectId":"user","CallerIpAddress":"10.0.0.5","ResponseBodySize":2000,"CorrelationId":"corr"});
        let network = json!({"TimeGenerated":now.to_rfc3339(),"IngestedAt":now.to_rfc3339(),"SourceIP":"10.0.0.5","DestinationIP":"198.51.100.8","SourceUserName":"user","SentBytes":2000,"DeviceAction":"allow","DeviceVendor":"vendor","DeviceProduct":"product"});
        let object = record("log_analytics_storage", &storage, now, &[]).unwrap();
        let flow = record(
            "log_analytics_network",
            &network,
            now,
            &["10.0.0.0/8".into()],
        )
        .unwrap();
        assert!(
            !object["fields"]["object_id"]
                .as_str()
                .unwrap()
                .contains("sig=")
        );
        assert_eq!(flow["fields"]["direction"], "outbound");
        let mut case = playbook_case(vec![object, flow], now);
        let finding = super::super::playbooks::run(&mut case, "cloud_exfiltration", now).unwrap();
        assert_eq!(finding["result"]["findings"][0]["status"], "not_decidable");
    }
    #[test]
    fn network_direction_requires_configured_internal_source() {
        let now = Utc::now();
        let raw = json!({"TimeGenerated":now.to_rfc3339(),"SourceIP":"192.0.2.1","DestinationIP":"198.51.100.8","SourceUserName":"user","SentBytes":2,"DeviceAction":"allow"});
        let event = record("log_analytics_network", &raw, now, &["10.0.0.0/8".into()]).unwrap();
        assert_eq!(event["fields"]["direction"], "unknown");
    }
    #[test]
    fn foreign_target_response_is_rejected_before_normalization() {
        let allowed = vec!["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into()];
        assert!(
            validate_target_rows(
                "entra_token",
                &[json!({"userId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"})],
                &allowed
            )
            .is_err()
        );
        assert!(
            validate_target_rows(
                "defender_process",
                &[json!({"DeviceId":"foreign"})],
                &allowed
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_site_is_rejected_before_source_request() {
        let mut config = super::super::config::Config::default();
        config.operations.encrypted_volume_confirmed = true;
        config.operations.retention_approved = true;
        let service = local_service(config);
        let p = Principal {
            tenant: "DEMO".into(),
            actor: "local-admin".into(),
            role: "admin".into(),
        };
        let now = Utc::now();
        let case=service.exec(&p,"cases.create",json!({"title":"scope fixture","site":"LAB","start":now-ChronoDuration::minutes(10),"end":now})).unwrap();
        let mut cloud = CloudSource::default();
        cloud.site = "OTHER".into();
        let selected = Selected::Cloud(&cloud);
        assert!(
            validate_case_scope(
                &service,
                &p,
                &json!({"source":"entra_token","case_id":case["id"]}),
                "entra_token",
                &selected
            )
            .is_err()
        );
    }
    #[test]
    fn worker_readiness_false_pauses_before_secrets_or_requests() {
        let mut config = super::super::config::Config::default();
        let now = Utc::now();
        config.collectors.enabled = true;
        let source = &mut config.collectors.entra_token;
        source.enabled = true;
        source.client_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into();
        source.secret_env = "AIVANA_TEST_COLLECTOR_MISSING_SECRET".into();
        source.approved_by = "test".into();
        source.approved_at = (now - ChronoDuration::minutes(1)).to_rfc3339();
        source.coverage_start = (now - ChronoDuration::hours(1)).to_rfc3339();
        source.coverage_end = (now + ChronoDuration::hours(1)).to_rfc3339();
        source.retention_days = 1;
        source.region = "test".into();
        source.site = "LAB".into();
        source.site_scope_confirmed = true;
        source.rights_confirmed = true;
        source.license_confirmed = true;
        source.target_ids = vec!["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into()];
        let service = local_service(config);
        let paused = run_for_worker(
            &service,
            &json!({"id":"case","site":"LAB","start":now-ChronoDuration::minutes(10),"end":now}),
            || Ok(false),
        )
        .unwrap();
        assert_eq!(paused["paused"], true);
    }
    #[test]
    fn instance_selection_is_site_scoped_and_ambiguity_fails_closed() {
        let mut c = Collectors::default();
        c.enabled = true;
        c.entra_token.enabled = true;
        c.entra_token.site = "BERLIN".into();
        for (id, site) in [("munich-one", "MUNICH"), ("munich-two", "MUNICH")] {
            let mut cloud = CloudSource::default();
            cloud.enabled = true;
            cloud.site = site.into();
            c.instances.push(CollectorInstance {
                id: id.into(),
                source: "entra_token".into(),
                cloud: Some(cloud),
                ..Default::default()
            });
        }
        assert_eq!(
            c.resolve("entra_token", "BERLIN", None).unwrap().0,
            "legacy"
        );
        assert!(c.resolve("entra_token", "MUNICH", None).is_err());
        assert_eq!(
            c.resolve("entra_token", "MUNICH", Some("munich-two"))
                .unwrap()
                .0,
            "munich-two"
        );
        assert!(
            c.resolve("entra_token", "BERLIN", Some("munich-two"))
                .is_err()
        );
        assert!(c.resolve("entra_token", "HAMBURG", None).is_err());
    }

    #[test]
    fn native_ca_policy_accepts_only_documented_dispositions() {
        assert_eq!(native_ca_approval(Some(0)), Some(true));
        assert_eq!(native_ca_approval(Some(1)), Some(false));
        assert_eq!(native_ca_approval(Some(0x101)), Some(true));
        for raw in [None, Some(2), Some(3), Some(0x100), Some(0x102), Some(-1)] {
            assert_eq!(native_ca_approval(raw), None);
        }
        let now = Utc::now();
        let base = json!({"kind":"ca_settings","native_id":"ca|template|ca",
            "template":"CN=Template","ca":"CN=CA","request_disposition":2,
            "ca_policy_status":"unsupported_policy_value","issuance_requires_approval":null});
        assert!(adcs_record(&base, now).is_ok());
        let mut false_clearance = base.clone();
        false_clearance["issuance_requires_approval"] = json!(false);
        assert!(adcs_record(&false_clearance, now).is_err());
    }
    #[test]
    fn instance_json_roundtrip_uses_flattened_analytics_fields() {
        let wire = json!({"enabled":true,"instances":[
            {"id":"a","source":"entra_token","cloud":{"enabled":true,"site":"A"}},
            {"id":"b","source":"log_analytics_storage","analytics":{
                "enabled":true,"site":"B","workspace_id":"00000000-0000-0000-0000-000000000002",
                "table_schema_approved":true,"ingestion_pipeline":"B only"}},
            {"id":"c","source":"adcs","adcs":{
                "enabled":true,"server":"dc.example.test","ca_host":"ca.example.test",
                "ca_name":"Example CA","site":"C"}}
        ]});
        let parsed: Collectors = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.instances.len(), 3);
        assert_eq!(
            parsed.instances[1].analytics.as_ref().unwrap().cloud.site,
            "B"
        );
        assert_eq!(
            parsed.instances[2].adcs.as_ref().unwrap().ca_host,
            "ca.example.test"
        );
        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["instances"][1]["analytics"]["site"], "B");
        assert!(written["instances"][1]["analytics"].get("cloud").is_none());
        let reparsed: Collectors = serde_json::from_value(written).unwrap();
        assert_eq!(reparsed.instances.len(), 3);
        let mut unexpected = serde_json::to_value(&reparsed).unwrap();
        unexpected["instances"][1]["analytics"]["unknown_field"] = json!(true);
        assert!(serde_json::from_value::<Collectors>(unexpected).is_err());
    }
}
