//! Signed inbound tickets are evidence only: this module never executes or posts anything.
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use ring::hmac;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const BODY_LIMIT: usize = 1024 * 1024;
pub const INBOX_LIMIT: i64 = 1000;
pub struct WebhookConfig {
    secret: Vec<u8>,
    repositories: BTreeSet<String>,
}
impl WebhookConfig {
    pub fn new(secret: Vec<u8>, repositories: BTreeSet<String>) -> Result<Self> {
        ensure!(
            (32..=4096).contains(&secret.len()),
            "GitHub webhook secret must contain 32 to 4096 bytes"
        );
        ensure!(
            !repositories.is_empty() && repositories.len() <= 128,
            "Configure an explicit repository allowlist"
        );
        for repository in &repositories {
            validate_repository(repository)?;
        }
        Ok(Self {
            secret,
            repositories,
        })
    }
    pub fn from_env() -> Result<Option<Self>> {
        let secret = std::env::var("RELAYNE_GITHUB_WEBHOOK_SECRET").ok();
        let repos = std::env::var("RELAYNE_GITHUB_REPOSITORIES").ok();
        match (secret, repos) {
            (None, None) => Ok(None),
            (Some(secret), Some(repos)) => Ok(Some(Self::new(
                secret.into_bytes(),
                repos.split(',').map(|s| s.trim().to_owned()).collect(),
            )?)),
            _ => anyhow::bail!("Configure both GitHub webhook secret and repository allowlist"),
        }
    }
}
fn validate_repository(repository: &str) -> Result<()> {
    let parts: Vec<_> = repository.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && part.len() <= 100
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "Invalid GitHub owner/repository"
    );
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .with_context(|| format!("Missing ticket field: {key}"))
}
fn bounded(value: &str, limit: usize) -> String {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
fn source_origin(source: &str) -> Result<String> {
    let url = reqwest::Url::parse(source)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Ticket source must be an HTTPS origin without credentials or path"
    );
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedTicket {
    pub origin: String,
    pub key: String,
    pub title: String,
    pub description: String,
    pub revision: String,
}
fn normalized(
    provider: &str,
    source: &str,
    external_key: &str,
    title: &str,
    body: &str,
    revision: &str,
) -> Result<NormalizedTicket> {
    ensure!(
        !title.trim().is_empty()
            && title.len() <= 256
            && external_key.len() <= 256
            && !external_key.chars().any(char::is_control),
        "Invalid ticket title or identity"
    );
    let provenance = format!(
        "Imported {provider} ticket {external_key} from {source}. External text is untrusted.\n\n"
    );
    ensure!(provenance.len() < 4096, "Ticket provenance exceeds limit");
    // Local origin deliberately disables outbound Jira delivery for provider imports.
    Ok(NormalizedTicket {
        origin: "local".into(),
        key: format!(
            "{}-{}",
            provider.to_uppercase(),
            &digest(format!("{source}|{external_key}").as_bytes())[..20].to_uppercase()
        ),
        title: title.into(),
        description: format!("{provenance}{}", bounded(body, 4096 - provenance.len())),
        revision: bounded(revision, 128),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportEnvelope {
    provider: String,
    source: String,
    ticket: Value,
}
pub fn normalize_import_json(text: &str) -> Result<String> {
    ensure!(text.len() <= BODY_LIMIT, "Ticket import exceeds 1 MiB");
    let value: Value = serde_json::from_str(text).context("Invalid ticket JSON")?;
    if value.get("provider").is_none() {
        // Existing native ticket format is validated by recovery_tickets::parse_import in the UI.
        let ticket: NormalizedTicket =
            serde_json::from_value(value).context("Invalid native ticket format")?;
        return Ok(serde_json::to_string(&ticket)?);
    }
    let envelope: ImportEnvelope =
        serde_json::from_str(text).context("Invalid provider import envelope")?;
    let source = source_origin(&envelope.source)?;
    let t = &envelope.ticket;
    let ticket = match envelope.provider.as_str() {
        "github" => {
            let number = t
                .get("number")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0)
                .context("Missing GitHub issue number")?;
            let repo = required(t, "repository")?;
            validate_repository(repo)?;
            normalized(
                "github",
                &source,
                &format!("{repo}#{number}"),
                required(t, "title")?,
                t.get("body").and_then(Value::as_str).unwrap_or(""),
                required(t, "updated_at")?,
            )?
        }
        "jira" => {
            let fields = t.get("fields").context("Missing Jira fields")?;
            let description = fields
                .get("description")
                .filter(|v| !v.is_null())
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            normalized(
                "jira",
                &source,
                required(t, "key")?,
                required(fields, "summary")?,
                &description,
                required(fields, "updated")?,
            )?
        }
        "servicenow" => normalized(
            "servicenow",
            &source,
            required(t, "number")?,
            required(t, "short_description")?,
            t.get("description").and_then(Value::as_str).unwrap_or(""),
            required(t, "sys_updated_on")?,
        )?,
        _ => anyhow::bail!("Unsupported ticket provider"),
    };
    Ok(serde_json::to_string(&ticket)?)
}
pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS github_ticket_inbox(delivery TEXT PRIMARY KEY, repository TEXT NOT NULL, action TEXT NOT NULL, payload_sha256 TEXT NOT NULL, received_utc TEXT NOT NULL, ticket_json TEXT NOT NULL); CREATE UNIQUE INDEX IF NOT EXISTS github_ticket_payload_unique ON github_ticket_inbox(payload_sha256);")?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS ticket_import_provenance(delivery TEXT PRIMARY KEY, actor TEXT NOT NULL, provider TEXT NOT NULL, source TEXT NOT NULL);")?;
    Ok(())
}

fn only_fields(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().context("Ticket fields must be an object")?;
    ensure!(object.keys().all(|key| fields.contains(&key.as_str())), "Unknown ticket import field");
    Ok(())
}

/// Receives evidence from an authenticated operator, never execution consent.
/// `actor` must be supplied by the server's authenticated identity, not the body.
pub fn receive_import(db: &mut Connection, actor: &str, raw: &[u8]) -> Result<Receipt> {
    ensure!(!raw.is_empty() && raw.len() <= BODY_LIMIT, "Ticket import exceeds 1 MiB or is empty");
    ensure!(!actor.trim().is_empty() && actor.len() <= 256 && !actor.chars().any(char::is_control), "Invalid authenticated actor");
    let text = std::str::from_utf8(raw).context("Ticket import must be UTF-8")?;
    let value: Value = serde_json::from_str(text).context("Invalid ticket JSON")?;
    let ticket_json = normalize_import_json(text)?;
    let ticket: NormalizedTicket = serde_json::from_str(&ticket_json)?;
    ensure!(ticket.origin == "local", "Inbox imports require local ticket origin");
    ensure!(!ticket.key.is_empty() && ticket.key.len() <= 64 && ticket.key.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'), "Invalid ticket key");
    ensure!(!ticket.title.trim().is_empty() && ticket.title.len() <= 256 && ticket.description.len() <= 4096 && !ticket.revision.trim().is_empty() && ticket.revision.len() <= 128, "Ticket text exceeds limits or revision is missing");
    // The interactive normalizer truncates long descriptions. Automated intake
    // instead rejects them so a receipt always describes the complete input.
    let (provider, source) = if value.get("provider").is_some() {
        let envelope: ImportEnvelope = serde_json::from_str(text)?;
        let source = source_origin(&envelope.source)?;
        let t = &envelope.ticket;
        let (body, revision, external_key) = match envelope.provider.as_str() {
            "github" => {
                only_fields(t, &["repository", "number", "title", "body", "updated_at"])?;
                let body = match t.get("body") { None | Some(Value::Null) => "", Some(v) => v.as_str().context("Invalid GitHub body")? };
                (body.to_owned(), required(t, "updated_at")?, format!("{}#{}", required(t, "repository")?, t["number"].as_u64().context("Invalid GitHub issue number")?))
            }
            "jira" => {
                only_fields(t, &["key", "fields"])?;
                let fields = t.get("fields").context("Missing Jira fields")?;
                only_fields(fields, &["summary", "description", "updated"])?;
                let body = match fields.get("description") {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(v @ Value::Object(_)) => v.to_string(),
                    _ => anyhow::bail!("Invalid Jira description"),
                };
                (body, required(fields, "updated")?, required(t, "key")?.to_owned())
            }
            "servicenow" => {
                only_fields(t, &["number", "short_description", "description", "sys_updated_on"])?;
                let body = match t.get("description") { None | Some(Value::Null) => "", Some(v) => v.as_str().context("Invalid ServiceNow description")? };
                (body.to_owned(), required(t, "sys_updated_on")?, required(t, "number")?.to_owned())
            }
            _ => anyhow::bail!("Unsupported ticket provider"),
        };
        let provenance = format!("Imported {} ticket {external_key} from {source}. External text is untrusted.\n\n", envelope.provider);
        ensure!(revision.len() <= 128 && provenance.len() + body.len() <= 4096, "Ticket description or revision exceeds inbox limits");
        (envelope.provider, source)
    } else {
        ("native".to_owned(), "local".to_owned())
    };
    ensure!(ticket_json.len() <= 8192, "Normalized ticket exceeds local import capacity");
    initialize(db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let hash = digest(raw);
    let existing: Option<String> = tx.query_row("SELECT delivery FROM github_ticket_inbox WHERE payload_sha256=?1", [&hash], |row| row.get(0)).optional()?;
    if let Some(delivery) = existing { return Ok(Receipt { delivery, duplicate: true }); }
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM github_ticket_inbox", [], |row| row.get(0))?;
    ensure!(count < INBOX_LIMIT, "Ticket inbox is full; operator retention review required");
    let delivery = Uuid::new_v4().to_string();
    tx.execute("INSERT INTO github_ticket_inbox(delivery,repository,action,payload_sha256,received_utc,ticket_json) VALUES(?1,?2,?3,?4,?5,?6)", params![delivery,source,format!("{provider}-import"),hash,Utc::now().to_rfc3339(),ticket_json])?;
    tx.execute("INSERT INTO ticket_import_provenance(delivery,actor,provider,source) VALUES(?1,?2,?3,?4)", params![delivery,actor,provider,source])?;
    tx.commit()?;
    Ok(Receipt { delivery, duplicate: false })
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub delivery: String,
    pub duplicate: bool,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct InboxItem {
    pub delivery: String,
    pub repository: String,
    pub action: String,
    pub received_utc: String,
    pub payload_sha256: String,
    pub ticket: NormalizedTicket,
}
pub fn receive_github(
    db: &mut Connection,
    config: &WebhookConfig,
    event: &str,
    delivery: &str,
    signature: &str,
    body: &[u8],
) -> Result<Receipt> {
    ensure!(body.len() <= BODY_LIMIT, "Webhook exceeds 1 MiB");
    ensure!(event == "issues", "Only GitHub issues events are supported");
    let id = Uuid::parse_str(delivery).context("Invalid delivery UUID")?;
    ensure!(
        !id.is_nil() && id.to_string() == delivery,
        "Delivery must be a canonical UUID"
    );
    let hex = signature
        .strip_prefix("sha256=")
        .context("Missing SHA-256 signature")?;
    ensure!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid SHA-256 signature"
    );
    let signature: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()?;
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, &config.secret),
        body,
        &signature,
    )
    .map_err(|_| anyhow::anyhow!("Webhook signature verification failed"))?;
    let payload: Value = serde_json::from_slice(body).context("Invalid webhook JSON")?;
    let repository = required(
        payload.get("repository").context("Missing repository")?,
        "full_name",
    )?;
    ensure!(
        config.repositories.contains(repository),
        "Repository is not allowed"
    );
    let action = required(&payload, "action")?;
    ensure!(
        [
            "opened",
            "edited",
            "reopened",
            "closed",
            "assigned",
            "unassigned",
            "labeled",
            "unlabeled"
        ]
        .contains(&action),
        "Unsupported issue action"
    );
    let issue = payload.get("issue").context("Missing issue")?;
    ensure!(
        issue.get("pull_request").is_none(),
        "Pull requests are not issue intake"
    );
    let mut imported = issue.clone();
    imported
        .as_object_mut()
        .context("Invalid issue object")?
        .insert("repository".into(), json!(repository));
    let ticket_json = normalize_import_json(
        &json!({"provider":"github","source":"https://github.com","ticket":imported}).to_string(),
    )?;
    initialize(db)?;
    let tx = db.transaction()?;
    let hash = digest(body);
    let existing: Option<String> = tx
        .query_row(
            "SELECT payload_sha256 FROM github_ticket_inbox WHERE delivery=?1",
            [delivery],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        ensure!(
            existing == hash,
            "Delivery UUID was reused with different content"
        );
        return Ok(Receipt {
            delivery: delivery.into(),
            duplicate: true,
        });
    }
    let repeated: Option<String> = tx
        .query_row(
            "SELECT delivery FROM github_ticket_inbox WHERE payload_sha256=?1",
            [&hash],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(original) = repeated {
        // Delivery headers are unsigned: deduplicate authenticated body bytes as well.
        return Ok(Receipt {
            delivery: original,
            duplicate: true,
        });
    }
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM github_ticket_inbox", [], |row| {
        row.get(0)
    })?;
    ensure!(
        count < INBOX_LIMIT,
        "Ticket inbox is full; operator retention review required"
    );
    tx.execute("INSERT INTO github_ticket_inbox(delivery,repository,action,payload_sha256,received_utc,ticket_json) VALUES(?1,?2,?3,?4,?5,?6)",params![delivery,repository,action,hash,Utc::now().to_rfc3339(),ticket_json])?;
    tx.commit()?;
    Ok(Receipt {
        delivery: delivery.into(),
        duplicate: false,
    })
}
pub fn list_inbox(db: &Connection) -> Result<Vec<InboxItem>> {
    initialize(db)?;
    let mut statement=db.prepare("SELECT delivery,repository,action,received_utc,payload_sha256,ticket_json FROM github_ticket_inbox ORDER BY received_utc DESC, delivery DESC LIMIT 100")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    let mut result = Vec::new();
    for row in rows {
        let (delivery, repository, action, received_utc, payload_sha256, ticket) = row?;
        result.push(InboxItem {
            delivery,
            repository,
            action,
            received_utc,
            payload_sha256,
            ticket: serde_json::from_str(&ticket)?,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn jira_import(revision: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"provider":"jira","source":"https://example.atlassian.net","ticket":{"key":"SUP-1","fields":{"summary":"Connection issue","description":"Review this evidence","updated":revision}}})).unwrap()
    }
    #[test]
    fn authenticated_import_deduplicates_durably_and_retains_new_revisions() {
        let path = std::env::temp_dir().join(format!("relayne-inbox-{}.sqlite", Uuid::new_v4()));
        let original = {
            let mut db = Connection::open(&path).unwrap();
            receive_import(&mut db, "operator-a", &jira_import("1")).unwrap()
        };
        assert!(!original.duplicate);
        {
            let mut db = Connection::open(&path).unwrap();
            let repeated = receive_import(&mut db, "operator-b", &jira_import("1")).unwrap();
            assert!(repeated.duplicate);
            assert_eq!(repeated.delivery, original.delivery);
            let revised = receive_import(&mut db, "operator-a", &jira_import("2")).unwrap();
            assert!(!revised.duplicate);
            assert_ne!(revised.delivery, original.delivery);
            let inbox = list_inbox(&db).unwrap();
            assert_eq!(inbox.len(), 2);
            assert_eq!(inbox[0].ticket.key, inbox[1].ticket.key);
            let actor: String = db.query_row("SELECT actor FROM ticket_import_provenance WHERE delivery=?1", [&original.delivery], |row| row.get(0)).unwrap();
            assert_eq!(actor, "operator-a", "a replay must not rewrite original provenance");
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn authenticated_import_rejects_unsafe_sources_unknown_fields_and_bounds() {
        let mut db = Connection::open_in_memory().unwrap();
        for source in ["http://example.atlassian.net", "https://user:secret@example.atlassian.net", "https://example.atlassian.net/path", "https://example.atlassian.net?token=secret"] {
            let mut body: Value = serde_json::from_slice(&jira_import("1")).unwrap();
            body["source"] = json!(source);
            assert!(receive_import(&mut db, "operator", &serde_json::to_vec(&body).unwrap()).is_err());
        }
        for pointer in ["/approved", "/ticket/execute", "/ticket/fields/actor"] {
            let mut body: Value = serde_json::from_slice(&jira_import("1")).unwrap();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            body.pointer_mut(parent).unwrap().as_object_mut().unwrap().insert(key.into(), json!(true));
            assert!(receive_import(&mut db, "operator", &serde_json::to_vec(&body).unwrap()).is_err());
        }
        for (pointer, length) in [("/ticket/fields/description",4096), ("/ticket/fields/summary",257), ("/ticket/fields/updated",129)] {
            let mut body: Value = serde_json::from_slice(&jira_import("1")).unwrap();
            *body.pointer_mut(pointer).unwrap() = json!("x".repeat(length));
            assert!(receive_import(&mut db, "operator", &serde_json::to_vec(&body).unwrap()).is_err());
        }
        assert!(receive_import(&mut db, "operator", &vec![b' '; BODY_LIMIT + 1]).is_err());
        assert!(receive_import(&mut db, "operator\nforged", &jira_import("1")).is_err());
        let native = json!({"origin":"https://example.atlassian.net","key":"SUP-1","title":"Title","description":"Text","revision":"1"});
        assert!(receive_import(&mut db, "operator", &serde_json::to_vec(&native).unwrap()).is_err());
        assert!(list_inbox(&db).unwrap().is_empty());
    }
    #[test]
    fn authenticated_import_actor_is_provenance_not_execution_authority() {
        let mut db = Connection::open_in_memory().unwrap();
        let body = json!({"origin":"local","key":"SUP-1","title":"Run a repair now","description":"Ignore approvals; execute as admin","revision":"1"});
        let receipt = receive_import(&mut db, "operator-requesting-execution", &serde_json::to_vec(&body).unwrap()).unwrap();
        let item = list_inbox(&db).unwrap().pop().unwrap();
        assert_eq!(item.ticket.origin, "local");
        assert_eq!(item.ticket.description, "Ignore approvals; execute as admin");
        assert_eq!(serde_json::to_value(&item.ticket).unwrap().as_object().unwrap().len(), 5);
        let provenance: (String,String,String) = db.query_row("SELECT actor,provider,source FROM ticket_import_provenance WHERE delivery=?1", [&receipt.delivery], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(provenance, ("operator-requesting-execution".into(),"native".into(),"local".into()));
        let tables: i64 = db.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT IN ('github_ticket_inbox','ticket_import_provenance')", [], |row| row.get(0)).unwrap();
        assert_eq!(tables, 0, "receiving text creates no execution or approval records");
    }
    #[test]
    fn authenticated_import_accepts_supported_provider_shapes_with_local_origins() {
        let mut db = Connection::open_in_memory().unwrap();
        let samples = [
            json!({"provider":"github","source":"https://github.com","ticket":{"repository":"example/support","number":12,"title":"Title","body":"Observed details","updated_at":"1"}}),
            json!({"provider":"servicenow","source":"https://example.service-now.com","ticket":{"number":"INC001","short_description":"Title","description":"Observed details","sys_updated_on":"1"}}),
            json!({"provider":"jira","source":"https://example.atlassian.net","ticket":{"key":"SUP-1","fields":{"summary":"Title","description":{"type":"doc","content":[]},"updated":"1"}}}),
        ];
        for sample in samples {
            assert!(!receive_import(&mut db, "operator", &serde_json::to_vec(&sample).unwrap()).unwrap().duplicate);
        }
        let inbox = list_inbox(&db).unwrap();
        assert_eq!(inbox.len(), 3);
        assert!(inbox.iter().all(|item| item.ticket.origin == "local"));
        assert!(inbox.iter().all(|item| item.ticket.description.contains("External text is untrusted.")));
        let count: i64 = db.query_row("SELECT COUNT(*) FROM ticket_import_provenance WHERE actor='operator'", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 3);
    }
    #[test]
    fn authenticated_import_shares_capacity_and_accepts_duplicate_when_full() {
        let mut db = Connection::open_in_memory().unwrap();
        let body = jira_import("1");
        let first = receive_import(&mut db, "operator", &body).unwrap();
        let tx = db.transaction().unwrap();
        for index in 1..INBOX_LIMIT {
            tx.execute("INSERT INTO github_ticket_inbox(delivery,repository,action,payload_sha256,received_utc,ticket_json) VALUES(?1,'fixture','opened',?2,'2026-09-14','{}')", params![format!("fixture-{index}"),format!("hash-{index}")]).unwrap();
        }
        tx.commit().unwrap();
        assert!(receive_import(&mut db, "operator", &jira_import("2")).is_err());
        let repeated = receive_import(&mut db, "operator", &body).unwrap();
        assert!(repeated.duplicate);
        assert_eq!(repeated.delivery, first.delivery);
        assert!(receive_github(&mut db, &config(), "issues", &Uuid::new_v4().to_string(), &sign(&payload()), &payload()).is_err());
    }
    fn config() -> WebhookConfig {
        WebhookConfig::new(vec![7; 32], BTreeSet::from(["example/support".into()])).unwrap()
    }
    fn payload() -> Vec<u8> {
        serde_json::to_vec(&json!({"action":"opened","repository":{"full_name":"example/support"},"issue":{"number":12,"title":"Connection issue","body":"Operator review required","updated_at":"2026-09-14T00:00:00Z"}})).unwrap()
    }
    fn sign(body: &[u8]) -> String {
        format!(
            "sha256={}",
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]), body)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
    #[test]
    fn valid_signed_delivery_is_idempotent_and_read_only_evidence() {
        let mut db = Connection::open_in_memory().unwrap();
        let body = payload();
        let id = Uuid::new_v4().to_string();
        assert!(
            !receive_github(&mut db, &config(), "issues", &id, &sign(&body), &body)
                .unwrap()
                .duplicate
        );
        assert!(
            receive_github(&mut db, &config(), "issues", &id, &sign(&body), &body)
                .unwrap()
                .duplicate
        );
        let replay = receive_github(
            &mut db,
            &config(),
            "issues",
            &Uuid::new_v4().to_string(),
            &sign(&body),
            &body,
        )
        .unwrap();
        assert!(replay.duplicate);
        assert_eq!(replay.delivery, id);
        let inbox = list_inbox(&db).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].ticket.origin, "local");
        assert!(inbox[0].ticket.description.contains("example/support#12"));
        let altered = String::from_utf8(body)
            .unwrap()
            .replace("Connection issue", "Other issue")
            .into_bytes();
        assert!(
            receive_github(&mut db, &config(), "issues", &id, &sign(&altered), &altered).is_err()
        );
    }
    #[test]
    fn bad_auth_event_repository_and_bounds_are_rejected() {
        let mut db = Connection::open_in_memory().unwrap();
        let body = payload();
        let id = Uuid::new_v4().to_string();
        assert!(
            receive_github(
                &mut db,
                &config(),
                "issues",
                &id,
                &format!("sha256={}", "0".repeat(64)),
                &body
            )
            .is_err()
        );
        assert!(receive_github(&mut db, &config(), "ping", &id, &sign(&body), &body).is_err());
        assert!(
            receive_github(
                &mut db,
                &config(),
                "issues",
                "not-uuid",
                &sign(&body),
                &body
            )
            .is_err()
        );
        let foreign = String::from_utf8(body.clone())
            .unwrap()
            .replace("example/support", "other/support")
            .into_bytes();
        assert!(
            receive_github(&mut db, &config(), "issues", &id, &sign(&foreign), &foreign).is_err()
        );
        assert!(
            receive_github(
                &mut db,
                &config(),
                "issues",
                &id,
                &sign(&body),
                &vec![0; BODY_LIMIT + 1]
            )
            .is_err()
        );
        assert!(list_inbox(&db).unwrap().is_empty());
    }
    #[test]
    fn all_provider_imports_are_local_and_bounded() {
        let samples = [
            json!({"provider":"github","source":"https://github.com","ticket":{"repository":"org/repo","number":1,"title":"Title","body":"Text","updated_at":"1"}}),
            json!({"provider":"jira","source":"https://example.atlassian.net","ticket":{"key":"SUP-1","fields":{"summary":"Title","description":{"type":"doc","content":[]},"updated":"1"}}}),
            json!({"provider":"servicenow","source":"https://example.service-now.com","ticket":{"number":"INC001","short_description":"Title","description":"Text","sys_updated_on":"1"}}),
        ];
        for sample in samples {
            let ticket: NormalizedTicket =
                serde_json::from_str(&normalize_import_json(&sample.to_string()).unwrap()).unwrap();
            assert_eq!(ticket.origin, "local");
            assert!(ticket.description.len() <= 4096);
            assert!(ticket.key.len() <= 64);
        }
        assert!(
            normalize_import_json(
                &json!({"provider":"github","source":"http://github.com","ticket":{}}).to_string()
            )
            .is_err()
        );
    }
}
