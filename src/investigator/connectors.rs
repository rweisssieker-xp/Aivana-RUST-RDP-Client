//! Fixed, read-only Graph v1.0 contracts. No model-generated query or URL is accepted.
use super::config::Config;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use reqwest::{Url, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

pub const CONTRACT_VERSION: &str = "graph-v1-login-2026-09-20.1";
const GRAPH: &str = "https://graph.microsoft.com";
const MAX_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page {
    pub source: String,
    pub records: Vec<Value>,
    pub next: Option<String>,
    pub bytes: u64,
    pub fetched_at: DateTime<Utc>,
    pub query_version: String,
}

pub fn contract() -> Value {
    json!({"version":CONTRACT_VERSION,"mode":"read_only","api_version":"v1.0",
        "auth":"OAuth2 client_credentials; tenant-specific authority; environment secret reference",
        "sources":[
            {"id":"defender","endpoint":"https://graph.microsoft.com/v1.0/security/alerts_v2","application_permission":"SecurityAlert.Read.All","fields":["id","createdDateTime","title","severity","status"],"question":"Which alerts require bounded investigation?"},
            {"id":"entra","endpoint":"https://graph.microsoft.com/v1.0/auditLogs/signIns","application_permission":"AuditLog.Read.All","fields":["id","createdDateTime","userId","ipAddress","status","conditionalAccessStatus","resourceDisplayName"],"question":"Was a login successful, blocked, or part of repeated failures?"}],
        "page_size":100,"max_response_bytes":MAX_BYTES,"timeout_seconds":15,"redirects":false,
        "retention":"deployment-attested window; a successful empty query does not prove coverage",
        "license":"operator must verify current Entra/Defender licensing, consent, actual fields and retention in target tenant",
        "endpoint_pivot":"disabled: no independently validated endpoint contract",
        "storage_network":"unavailable: no exfiltration exclusion",
        "retry":"429/503 bounded persisted retry; Retry-After capped to one hour; all attempts charged",
        "references":["https://learn.microsoft.com/graph/api/security-list-alerts_v2?view=graph-rest-1.0","https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0"]})
}
fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
pub fn token(config: &Config) -> Result<String> {
    config.live_gate()?;
    let secret = std::env::var(&config.sources.secret_env)
        .context("Connector secret reference is unavailable")?;
    if secret.is_empty() {
        bail!("Connector secret is empty");
    }
    let endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant
    );
    let response = client()?
        .post(endpoint)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", config.sources.client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .send()
        .map_err(|_| anyhow::anyhow!("OAuth transport failed"))?;
    let status = response.status();
    if !status.is_success() {
        bail!(
            "OAuth authentication failed (HTTP {}); no response secrets logged",
            status.as_u16()
        );
    }
    let mut bytes = Vec::new();
    response.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        bail!("OAuth response exceeds limit");
    }
    let value: Value = serde_json::from_slice(&bytes).context("Invalid OAuth response")?;
    value["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .context("OAuth response has no access token")
}
fn path(source: &str) -> Result<&'static str> {
    match source {
        "defender" => Ok("/v1.0/security/alerts_v2"),
        "entra" => Ok("/v1.0/auditLogs/signIns"),
        _ => bail!("Unknown or unapproved source"),
    }
}
pub fn query_url(source: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Url> {
    if start >= end
        || end - start > chrono::Duration::hours(24)
        || end > Utc::now() + chrono::Duration::minutes(5)
    {
        bail!("Query window must be ordered, at most 24 hours and not in the future");
    }
    let mut url = Url::parse(&format!("{GRAPH}{}", path(source)?))?;
    let time_field = "createdDateTime";
    url.query_pairs_mut()
        .append_pair("$top", "100")
        .append_pair(
            "$filter",
            &format!(
                "{time_field} ge {} and {time_field} le {}",
                start.to_rfc3339(),
                end.to_rfc3339()
            ),
        );
    Ok(url)
}
pub fn validate_next(source: &str, next: &str) -> Result<Url> {
    let u = Url::parse(next)?;
    if u.scheme() != "https"
        || u.host_str() != Some("graph.microsoft.com")
        || u.port_or_known_default() != Some(443)
        || u.path() != path(source)?
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || next.len() > 16384
    {
        bail!("Pagination URL leaves approved source contract");
    }
    Ok(u)
}
fn continuation_url(
    source: &str,
    next: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Url> {
    let supplied = validate_next(source, next)?;
    let mut bounded = query_url(source, start, end)?;
    let filter = bounded
        .query_pairs()
        .find(|(k, _)| k == "$filter")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let mut cursor = false;
    let mut seen = std::collections::HashSet::new();
    for (key, value) in supplied.query_pairs() {
        if !seen.insert(key.to_string()) {
            bail!("Repeated pagination parameter");
        }
        match key.as_ref() {
            "$filter" if value == filter => {}
            "$top" if value == "100" => {}
            "$skiptoken" if !value.is_empty() && value.len() <= 8192 => {
                bounded.query_pairs_mut().append_pair("$skiptoken", &value);
                cursor = true;
            }
            "$skip" if value.parse::<u64>().is_ok_and(|n| n > 0 && n <= 1000) => {
                bounded.query_pairs_mut().append_pair("$skip", &value);
                cursor = true;
            }
            _ => bail!("Pagination attempts to change approved filter, limit or query shape"),
        }
    }
    if !cursor {
        bail!("Pagination has no valid continuation token");
    }
    Ok(bounded)
}
pub fn fetch(
    config: &Config,
    access_token: &str,
    source: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    next: Option<&str>,
) -> Result<Page> {
    config.live_gate()?;
    let coverage_start =
        DateTime::parse_from_rfc3339(&config.sources.coverage_start)?.with_timezone(&Utc);
    let coverage_end =
        DateTime::parse_from_rfc3339(&config.sources.coverage_end)?.with_timezone(&Utc);
    if start < coverage_start || end > coverage_end {
        bail!(
            "Requested window is outside verified source coverage; missing retention is not a zero result"
        );
    }
    let first = query_url(source, start, end)?;
    let url = match next {
        Some(s) => continuation_url(source, s, start, end)?,
        None => first,
    };
    let response = client()?
        .get(url)
        .bearer_auth(access_token)
        .send()
        .map_err(|_| anyhow::anyhow!("Source transport failed"))?;
    let status = response.status();
    if !status.is_success() {
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(1, 3600);
        bail!(
            "Source {source} HTTP {}; retry_after_seconds={retry}",
            status.as_u16()
        );
    }
    let mut bytes = Vec::new();
    response.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("Truncated source response: byte limit reached");
    }
    let body: Value =
        serde_json::from_slice(&bytes).context("Source response is not valid JSON")?;
    let records = body["value"]
        .as_array()
        .context("Source schema changed: value array absent")?;
    if records.len() > 100 {
        bail!("Source exceeded contracted page size");
    }
    for record in records {
        validate_record(source, record)?;
    }
    let next = body
        .get("@odata.nextLink")
        .map(|v| v.as_str().context("Invalid nextLink type"))
        .transpose()?
        .map(str::to_owned);
    if let Some(n) = &next {
        validate_next(source, n)?;
    }
    Ok(Page {
        source: source.into(),
        records: records.clone(),
        next,
        bytes: bytes.len() as u64,
        fetched_at: Utc::now(),
        query_version: CONTRACT_VERSION.into(),
    })
}
pub fn validate_record(source: &str, v: &Value) -> Result<()> {
    path(source)?;
    if v["id"].as_str().is_none_or(|s| s.is_empty()) {
        bail!("Schema changed: source ID missing");
    }
    DateTime::parse_from_rfc3339(
        v["createdDateTime"]
            .as_str()
            .context("Schema changed: event time missing")?,
    )
    .context("Invalid UTC event time")?;
    if source == "entra"
        && (v["status"]["errorCode"].as_i64().is_none() || v["userId"].as_str().is_none())
    {
        bail!("Schema changed: login result/user missing");
    }
    Ok(())
}
pub fn normalize(source: &str, v: &Value, fetched: DateTime<Utc>) -> Result<Value> {
    validate_record(source, v)?;
    let fields = if source == "entra" {
        json!({"kind":"login","user":v["userId"],"ip":v["ipAddress"],"success":v["status"]["errorCode"]==0,"result_code":v["status"]["errorCode"],"conditional_access":v["conditionalAccessStatus"],"resource":v["resourceDisplayName"],"resource_access":"not_proven_by_login"})
    } else {
        json!({"kind":"alert","title":v["title"],"severity":v["severity"],"status":v["status"]})
    };
    Ok(
        json!({"source":source,"source_id":v["id"],"event_time":v["createdDateTime"],"retrieved_at":fetched,"query_version":CONTRACT_VERSION,"fields":fields,"kind":fields["kind"],"content":fields,"status":"available"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pagination_cannot_replace_time_scope_or_result_limit() {
        let end = Utc::now();
        let start = end - chrono::Duration::hours(1);
        let bounded = continuation_url(
            "entra",
            "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=opaque",
            start,
            end,
        )
        .unwrap();
        assert!(bounded.query_pairs().any(|(k, _)| k == "$filter"));
        for q in [
            "$skiptoken=x&$top=10000",
            "$skiptoken=x&$filter=id%20ne%20null",
            "$skiptoken=x&$skiptoken=y",
            "$select=*",
            "$skip=100000",
        ] {
            assert!(
                continuation_url(
                    "entra",
                    &format!("https://graph.microsoft.com/v1.0/auditLogs/signIns?{q}"),
                    start,
                    end
                )
                .is_err()
            );
        }
    }
    #[test]
    fn pagination_cannot_exfiltrate_credentials() {
        for n in [
            "https://evil.test/v1.0/auditLogs/signIns",
            "http://graph.microsoft.com/v1.0/auditLogs/signIns",
            "https://graph.microsoft.com/v1.0/users",
            "https://a@graph.microsoft.com/v1.0/auditLogs/signIns",
            "https://graph.microsoft.com:444/v1.0/auditLogs/signIns",
        ] {
            assert!(validate_next("entra", n).is_err());
        }
        assert!(
            validate_next(
                "entra",
                "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc"
            )
            .is_ok()
        );
    }
    #[test]
    fn unknown_source_and_unbounded_window_are_denied() {
        let n = Utc::now();
        assert!(query_url("shell", n - chrono::Duration::hours(1), n).is_err());
        assert!(query_url("entra", n - chrono::Duration::hours(25), n).is_err());
    }
    #[test]
    fn login_does_not_prove_resource_access() {
        let v = json!({"id":"1","createdDateTime":"2026-09-20T09:00:00Z","userId":"u","status":{"errorCode":0},"conditionalAccessStatus":"success"});
        let n = normalize("entra", &v, Utc::now()).unwrap();
        assert_eq!(n["fields"]["resource_access"], "not_proven_by_login");
        assert!(
            validate_record(
                "entra",
                &json!({"id":"1","createdDateTime":"2026-09-20T09:00:00Z"})
            )
            .is_err()
        );
    }
}
