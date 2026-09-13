//! Explicit ticket intake and reviewed Jira delivery; ticket text never authorizes execution.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path, time::Duration};
use uuid::Uuid;
const LIMIT: usize = 2 * 1024 * 1024;
fn bounded_read(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![];
    std::fs::File::open(path)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Ticketspeicher zu groß",
        ));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub origin: String,
    pub key: String,
    pub title: String,
    pub description: String,
    pub revision: String,
}
impl Ticket {
    pub fn validate(&self) -> Result<()> {
        if self.origin != "local" {
            ensure!(
                jira_origin(&self.origin)? == self.origin,
                "Ticket-Ursprung nicht kanonisch"
            );
        }
        valid_key(&self.key)?;
        ensure!(
            !self.title.trim().is_empty()
                && self.title.len() <= 256
                && self.description.len() <= 4096
                && self.revision.len() <= 128,
            "Ticket überschreitet Textgrenzen"
        );
        Ok(())
    }
    pub fn objective(&self) -> Result<String> {
        self.validate()?;
        let text = format!("{}\n{}", self.title, self.description);
        ensure!(
            text.len() <= 4096,
            "Störung überschreitet 4096 Bytes; Ticketbeschreibung kürzen"
        );
        Ok(crate::security::redact_secret_text(&text))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delivery {
    pub id: Uuid,
    pub digest: String,
    pub state: String,
    pub at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub ticket: Ticket,
    pub case: Option<Uuid>,
    pub deliveries: Vec<Delivery>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Book {
    pub records: Vec<Record>,
    #[serde(skip)]
    source: Option<String>,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
impl Book {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match bounded_read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        ensure!(bytes.len() <= LIMIT, "Ticketspeicher zu groß");
        let clear = crate::security::unprotect_secret(&bytes)?;
        ensure!(clear.len() <= LIMIT, "Ticketspeicher zu groß");
        let mut book: Self = serde_json::from_slice(&clear)?;
        book.validate()?;
        book.source = Some(digest(&bytes));
        Ok(book)
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.records.len() <= 128, "Maximal 128 Tickets");
        let mut seen = std::collections::BTreeSet::new();
        for r in &self.records {
            r.ticket.validate()?;
            ensure!(
                seen.insert((&r.ticket.origin, &r.ticket.key)) && r.deliveries.len() <= 64,
                "Doppeltes Ticket oder zu viele Zustellungen"
            );
            for d in &r.deliveries {
                ensure!(
                    matches!(
                        d.state.as_str(),
                        "sending" | "sent" | "unknown" | "confirmed" | "not_sent"
                    ) && d.digest.len() == 64
                        && !d.id.is_nil(),
                    "Ungültige Zustellung"
                );
            }
        }
        Ok(())
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(windows)]
        let _lock = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .share_mode(0)
                .open(path.with_extension("lock"))?
        };
        let current = match bounded_read(path) {
            Ok(b) => Some(digest(&b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            current == self.source,
            "Ticketspeicher parallel geändert; neu laden"
        );
        let raw = serde_json::to_vec(self)?;
        ensure!(raw.len() <= LIMIT, "Ticketspeicher zu groß");
        let protected = crate::security::protect_secret(&raw)?;
        ensure!(protected.len() <= LIMIT, "Ticketspeicher zu groß");
        crate::security::atomic_write(path, &protected)?;
        self.source = Some(digest(&protected));
        Ok(())
    }
    pub fn import(&mut self, mut ticket: Ticket) -> Result<usize> {
        ticket.validate()?;
        ticket.title = crate::security::redact_secret_text(&ticket.title);
        ticket.description = crate::security::redact_secret_text(&ticket.description);
        if let Some(i) = self
            .records
            .iter()
            .position(|r| r.ticket.origin == ticket.origin && r.ticket.key == ticket.key)
        {
            if self.records[i].ticket != ticket {
                self.records[i].ticket = ticket;
                self.records[i].case = None;
            }
            return Ok(i);
        }
        ensure!(self.records.len() < 128, "Ticketspeicher voll");
        self.records.push(Record {
            ticket,
            case: None,
            deliveries: vec![],
        });
        Ok(self.records.len() - 1)
    }
    pub fn reserve(&mut self, index: usize, report: &str) -> Result<Uuid> {
        ensure!(
            !report.trim().is_empty() && report.len() <= 16384,
            "Bericht fehlt oder zu groß"
        );
        let record = self.records.get_mut(index).context("Ticket fehlt")?;
        ensure!(
            record.case.is_some(),
            "Ticket keinem Recovery-Fall zugeordnet"
        );
        let hash = digest(report.as_bytes());
        ensure!(
            record.deliveries.len() < 64
                && !record
                    .deliveries
                    .iter()
                    .any(|d| (d.digest == hash && d.state != "not_sent")
                        || d.state == "sending"
                        || d.state == "unknown"),
            "Bericht bereits gesendet oder Zustellung ungeklärt; keine automatische Wiederholung"
        );
        let id = Uuid::new_v4();
        record.deliveries.push(Delivery {
            id,
            digest: hash,
            state: "sending".into(),
            at: chrono::Utc::now(),
        });
        Ok(id)
    }
    pub fn finish(&mut self, id: Uuid, success: bool) -> Result<()> {
        let d = self
            .records
            .iter_mut()
            .flat_map(|r| &mut r.deliveries)
            .find(|d| d.id == id)
            .context("Zustellung fehlt")?;
        ensure!(d.state == "sending", "Zustellung bereits abgeschlossen");
        d.state = if success { "sent" } else { "unknown" }.into();
        Ok(())
    }
    pub fn resolve_delivery(
        &mut self,
        id: Uuid,
        delivered: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let d = self
            .records
            .iter_mut()
            .flat_map(|r| &mut r.deliveries)
            .find(|d| d.id == id)
            .context("Zustellung fehlt")?;
        ensure!(
            matches!(d.state.as_str(), "unknown" | "sending")
                && now >= d.at + chrono::Duration::minutes(2),
            "Aktive Zustellung erst nach mindestens zwei Minuten manuell klären"
        );
        d.state = if delivered { "confirmed" } else { "not_sent" }.into();
        Ok(())
    }
}
pub fn parse_import(text: &str) -> Result<Ticket> {
    ensure!(text.len() <= 8192, "Ticket-JSON zu groß");
    let t: Ticket =
        serde_json::from_str(text).map_err(|_| anyhow::anyhow!("Ticket-JSON ungültig"))?;
    t.validate()?;
    Ok(t)
}
pub fn jira_origin(input: &str) -> Result<String> {
    let u = reqwest::Url::parse(input)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && (u.path() == "/" || u.path().is_empty()),
        "Jira benötigt HTTPS-Ursprung ohne Pfad, Benutzer oder Query"
    );
    Ok(u.as_str().trim_end_matches('/').into())
}
fn valid_key(key: &str) -> Result<()> {
    ensure!(
        !key.is_empty()
            && key.len() <= 64
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'),
        "Ticket-Schlüssel ungültig"
    );
    Ok(())
}
fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
fn response_json(response: reqwest::blocking::Response) -> Result<serde_json::Value> {
    ensure!(
        response.status().is_success(),
        "Jira meldet HTTP {}",
        response.status()
    );
    let mut bytes = vec![];
    response.take(262145).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 262144, "Jira-Antwort zu groß");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Jira-Antwort ungültig"))
}
fn adf_text(
    v: &serde_json::Value,
    depth: usize,
    budget: &mut usize,
    out: &mut String,
) -> Result<()> {
    ensure!(depth <= 16 && *budget > 0, "Jira-Beschreibung zu komplex");
    *budget -= 1;
    if let Some(t) = v.get("text").and_then(|x| x.as_str()) {
        out.push_str(t);
        out.push(' ');
        ensure!(out.len() <= 4096, "Jira-Beschreibung zu lang");
    }
    if let Some(a) = v.get("content").and_then(|x| x.as_array()) {
        for child in a {
            adf_text(child, depth + 1, budget, out)?;
        }
    }
    Ok(())
}
pub fn fetch(origin: &str, key: &str, email: &str, token: &str) -> Result<Ticket> {
    let origin = jira_origin(origin)?;
    valid_key(key)?;
    ensure!(
        !email.is_empty() && !token.is_empty(),
        "Jira-E-Mail und API-Token fehlen"
    );
    let json = response_json(
        client()?
            .get(format!(
                "{origin}/rest/api/3/issue/{key}?fields=summary,description,updated"
            ))
            .basic_auth(email, Some(token))
            .send()
            .map_err(|_| anyhow::anyhow!("Jira nicht erreichbar"))?,
    )?;
    ensure!(
        json["key"].as_str() == Some(key),
        "Jira lieferte anderes Ticket"
    );
    let mut description = String::new();
    if let Some(s) = json["fields"]["description"].as_str() {
        description = s.into();
    } else {
        adf_text(
            &json["fields"]["description"],
            0,
            &mut 512,
            &mut description,
        )?;
    }
    let ticket = Ticket {
        origin,
        key: key.into(),
        title: json["fields"]["summary"]
            .as_str()
            .context("Jira-Titel fehlt")?
            .into(),
        description,
        revision: json["fields"]["updated"]
            .as_str()
            .context("Jira-Revision fehlt")?
            .into(),
    };
    ticket.validate()?;
    Ok(ticket)
}
pub fn post_report(
    ticket: &Ticket,
    email: &str,
    token: &str,
    report: &str,
    id: Uuid,
) -> Result<()> {
    ticket.validate()?;
    let origin = jira_origin(&ticket.origin)?;
    ensure!(
        !email.is_empty()
            && !token.is_empty()
            && report.len() <= 16384
            && !report.trim().is_empty(),
        "Zustellung unvollständig"
    );
    let text = format!(
        "{}\nRelayne delivery: {id}",
        crate::security::redact_secret_text(report)
    );
    let response=client()?.post(format!("{origin}/rest/api/3/issue/{}/comment",ticket.key)).basic_auth(email,Some(token)).json(&serde_json::json!({"body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":text}]}]}})).send().map_err(|_|anyhow::anyhow!("Jira-Zustellung ungeklärt; Ticket vor erneutem Versand manuell prüfen"))?;
    ensure!(
        response.status() == reqwest::StatusCode::CREATED,
        "Jira-Zustellung ungeklärt (HTTP {})",
        response.status()
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ticket() -> Ticket {
        Ticket {
            origin: "local".into(),
            key: "TEST-1".into(),
            title: "Application down".into(),
            description: "Service App stopped".into(),
            revision: "1".into(),
        }
    }
    #[test]
    fn ticket_import_deduplicates_and_changed_revision_requires_new_case() {
        let mut b = Book::default();
        let i = b.import(ticket()).unwrap();
        b.records[i].case = Some(Uuid::new_v4());
        assert_eq!(b.import(ticket()).unwrap(), i);
        assert!(b.records[i].case.is_some());
        let mut t = ticket();
        t.revision = "2".into();
        b.import(t).unwrap();
        assert!(b.records[i].case.is_none());
        assert_eq!(b.records.len(), 1);
    }
    #[test]
    fn ticket_delivery_requires_case_and_blocks_duplicates_and_uncertain_retries() {
        let mut b = Book::default();
        b.import(ticket()).unwrap();
        assert!(b.reserve(0, "report").is_err());
        b.records[0].case = Some(Uuid::new_v4());
        let id = b.reserve(0, "report").unwrap();
        assert!(b.reserve(0, "report2").is_err());
        b.finish(id, false).unwrap();
        assert!(b.reserve(0, "report2").is_err());
    }
    #[test]
    fn ticket_endpoints_and_payload_are_bounded() {
        for u in [
            "http://jira.invalid",
            "https://u:p@jira.invalid",
            "https://jira.invalid/path",
            "https://jira.invalid?x=y",
        ] {
            assert!(jira_origin(u).is_err());
        }
        assert_eq!(
            jira_origin("https://jira.invalid/").unwrap(),
            "https://jira.invalid"
        );
        assert!(parse_import("{}").is_err());
        let mut t = ticket();
        t.key = "TEST-1/other".into();
        assert!(t.validate().is_err());
    }
    #[test]
    fn ticket_manual_resolution_waits_for_request_bound_and_preserves_duplicate_guard() {
        let mut b = Book::default();
        b.import(ticket()).unwrap();
        b.records[0].case = Some(Uuid::new_v4());
        let id = b.reserve(0, "report").unwrap();
        let at = b.records[0].deliveries[0].at;
        assert!(b.resolve_delivery(id, false, at).is_err());
        b.resolve_delivery(id, false, at + chrono::Duration::minutes(2))
            .unwrap();
        let next = b.reserve(0, "report").unwrap();
        let at = b.records[0].deliveries[1].at;
        b.resolve_delivery(next, true, at + chrono::Duration::minutes(2))
            .unwrap();
        assert!(b.reserve(0, "report").is_err());
    }
    #[test]
    fn ticket_oversized_store_rejected_before_decode() {
        let path =
            std::env::temp_dir().join(format!("relayne-ticket-large-{}.dpapi", Uuid::new_v4()));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len((LIMIT + 1) as u64).unwrap();
        drop(file);
        assert!(Book::load(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn ticket_store_rejects_stale_saves() {
        let path = std::env::temp_dir().join(format!("relayne-ticket-{}.dpapi", Uuid::new_v4()));
        let mut b = Book::default();
        b.import(ticket()).unwrap();
        b.save(&path).unwrap();
        let mut stale = Book::load(&path).unwrap();
        b.records[0].case = Some(Uuid::new_v4());
        b.save(&path).unwrap();
        assert!(stale.save(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
