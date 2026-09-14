//! Explicitly authorized outbound evidence. No repair or native provider API actions.
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use ring::hmac;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

pub struct Config {
    url: String,
    bearer: String,
}
impl Config {
    pub fn new(url: &str, bearer: &str) -> Result<Self> {
        let u = reqwest::Url::parse(url)?;
        ensure!(
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && url.len() <= 2048,
            "Escalation destination requires HTTPS without credentials, query, or fragment"
        );
        ensure!(
            (32..=4096).contains(&bearer.len()) && bearer.bytes().all(|b| b.is_ascii_graphic()),
            "Escalation bearer must contain 32 to 4096 printable non-space ASCII bytes"
        );
        Ok(Self {
            url: u.to_string(),
            bearer: bearer.into(),
        })
    }
    pub fn from_env() -> Result<Option<Self>> {
        match (
            std::env::var("RELAYNE_ESCALATION_URL").ok(),
            std::env::var("RELAYNE_ESCALATION_BEARER").ok(),
        ) {
            (None, None) => Ok(None),
            (Some(u), Some(b)) => Ok(Some(Self::new(&u, &b)?)),
            _ => anyhow::bail!("Configure both escalation destination and bearer"),
        }
    }
    pub fn fingerprint(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(format!("{}\0{}", self.url, self.bearer).as_bytes())
        )
    }
    pub fn destination(&self) -> &str {
        &self.url
    }
}
#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub delivery: String,
    pub actor: String,
    pub destination_fingerprint: String,
    pub expires_utc: i64,
    pub state: String,
    pub payload: serde_json::Value,
    pub note: String,
    pub parent_id: Option<String>,
}
fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS ticket_escalation_outbox(id TEXT PRIMARY KEY,delivery TEXT NOT NULL,actor TEXT NOT NULL,destination_fingerprint TEXT NOT NULL,expires_utc INTEGER NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,note TEXT NOT NULL,updated_utc INTEGER NOT NULL,parent_id TEXT UNIQUE); CREATE UNIQUE INDEX IF NOT EXISTS escalation_original_delivery ON ticket_escalation_outbox(delivery) WHERE parent_id IS NULL; CREATE TABLE IF NOT EXISTS ticket_escalation_reconciliation(id TEXT PRIMARY KEY,actor TEXT NOT NULL,delivered INTEGER NOT NULL,checked_utc INTEGER NOT NULL);")?;
    Ok(())
}
fn actor_valid(actor: &str) -> Result<()> {
    ensure!(
        !actor.trim().is_empty() && actor.len() <= 256 && !actor.chars().any(char::is_control),
        "Invalid authenticated actor"
    );
    Ok(())
}
fn sanitize(text: &str, limit: usize) -> String {
    // Best effort: omit entire potentially sensitive text rather than forwarding
    // detected credentials. No ticket description or original payload is sent.
    let lower = text.to_ascii_lowercase();
    if [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "bearer",
        "api_key",
        "api-key",
        "private key",
        "://",
        "@",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return "[redacted sensitive text]".into();
    }
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut end = clean.len().min(limit);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}
fn read_entry(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    Option<String>,
)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}
const SELECT: &str = "SELECT id,delivery,actor,destination_fingerprint,expires_utc,state,payload,note,parent_id FROM ticket_escalation_outbox";
fn entry(
    row: (
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        Option<String>,
    ),
) -> Result<Entry> {
    let (
        id,
        delivery,
        actor,
        destination_fingerprint,
        expires_utc,
        state,
        payload,
        note,
        parent_id,
    ) = row;
    Ok(Entry {
        id,
        delivery,
        actor,
        destination_fingerprint,
        expires_utc,
        state,
        payload: serde_json::from_str(&payload)?,
        note,
        parent_id,
    })
}
pub fn list(db: &Connection) -> Result<Vec<Entry>> {
    initialize(db)?;
    let mut statement = db.prepare(&format!("{SELECT} ORDER BY updated_utc DESC,id LIMIT 100"))?;
    statement
        .query_map([], read_entry)?
        .map(|r| entry(r?))
        .collect()
}
/// The server must authenticate Operator/Admin and supply the authenticated actor.
pub fn enqueue(
    db: &mut Connection,
    config: &Config,
    actor: &str,
    delivery: &str,
    reason: &str,
    expires_utc: i64,
) -> Result<Entry> {
    enqueue_at(
        db,
        config,
        actor,
        delivery,
        reason,
        expires_utc,
        Utc::now().timestamp(),
    )
}
fn enqueue_at(
    db: &mut Connection,
    config: &Config,
    actor: &str,
    delivery: &str,
    reason: &str,
    expires: i64,
    now: i64,
) -> Result<Entry> {
    actor_valid(actor)?;
    ensure!(
        expires > now && expires <= now.saturating_add(168 * 3600),
        "Escalation authorization must expire within 168 hours"
    );
    ensure!(
        !reason.trim().is_empty() && reason.len() <= 1024,
        "Escalation reason must contain 1 to 1024 bytes"
    );
    ensure!(
        Uuid::parse_str(delivery).is_ok_and(|u| !u.is_nil() && u.to_string() == delivery),
        "Invalid inbox delivery ID"
    );
    crate::ticket_intake::initialize(db)?;
    initialize(db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if let Some(existing) = tx
        .query_row(
            &format!("{SELECT} WHERE delivery=?1 AND parent_id IS NULL"),
            [delivery],
            read_entry,
        )
        .optional()?
    {
        return entry(existing);
    }
    let raw: String = tx
        .query_row(
            "SELECT ticket_json FROM github_ticket_inbox WHERE delivery=?1",
            [delivery],
            |r| r.get(0),
        )
        .optional()?
        .context("Inbox delivery not found")?;
    ensure!(raw.len() <= 8192, "Stored ticket exceeds summary limits");
    let ticket: crate::ticket_intake::NormalizedTicket = serde_json::from_str(&raw)?;
    ensure!(
        ticket.origin == "local"
            && !ticket.key.is_empty()
            && ticket.key.len() <= 64
            && ticket
                .key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'),
        "Inbox ticket identity is invalid"
    );
    let id = Uuid::new_v4().to_string();
    let payload = json!({"schema":"relayne-escalation-v1","escalation_id":id,"delivery":delivery,"ticket_key":ticket.key,"title":sanitize(&ticket.title,256),"reason":sanitize(reason,1024),"evidence_only":true});
    let serialized = serde_json::to_string(&payload)?;
    ensure!(serialized.len() <= 4096, "Escalation summary exceeds 4 KiB");
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM ticket_escalation_outbox", [], |r| {
        r.get(0)
    })?;
    ensure!(
        count < 1000,
        "Escalation outbox full; operator retention review required"
    );
    let fingerprint = config.fingerprint();
    tx.execute(
        "INSERT INTO ticket_escalation_outbox VALUES(?1,?2,?3,?4,?5,'queued',?6,'',?7,NULL)",
        params![id, delivery, actor, fingerprint, expires, serialized, now],
    )?;
    tx.commit()?;
    Ok(Entry {
        id,
        delivery: delivery.into(),
        actor: actor.into(),
        destination_fingerprint: fingerprint,
        expires_utc: expires,
        state: "queued".into(),
        payload,
        note: String::new(),
        parent_id: None,
    })
}
/// Reconciliation records external inspection; it never queues another send.
pub fn reconcile(db: &Connection, actor: &str, id: &str, delivered: bool) -> Result<()> {
    actor_valid(actor)?;
    initialize(db)?;
    let tx = db.unchecked_transaction()?;
    let changed=tx.execute("UPDATE ticket_escalation_outbox SET state=?1,note='Operator inspected destination; no resend authorized',updated_utc=?2 WHERE id=?3 AND state IN ('unknown','failed')",params![if delivered{"sent"}else{"not_delivered"},Utc::now().timestamp(),id])?;
    ensure!(
        changed == 1,
        "Only unknown or rejected deliveries can be reconciled"
    );
    tx.execute(
        "INSERT INTO ticket_escalation_reconciliation VALUES(?1,?2,?3,?4)",
        params![id, actor, delivered, Utc::now().timestamp()],
    )?;
    tx.commit()?;
    Ok(())
}
pub fn cancel(db: &Connection, actor: &str, id: &str) -> Result<()> {
    actor_valid(actor)?;
    initialize(db)?;
    let changed=db.execute("UPDATE ticket_escalation_outbox SET state='canceled',note=?1,updated_utc=?2 WHERE id=?3 AND state='queued'",params![format!("Authorization revoked by {actor}"),Utc::now().timestamp(),id])?;
    ensure!(
        changed == 1,
        "Only queued authorization can be canceled; in-flight delivery cannot be revoked"
    );
    Ok(())
}
pub fn reauthorize(
    db: &mut Connection,
    config: &Config,
    actor: &str,
    id: &str,
    reason: &str,
    expires_utc: i64,
) -> Result<Entry> {
    reauthorize_at(
        db,
        config,
        actor,
        id,
        reason,
        expires_utc,
        Utc::now().timestamp(),
    )
}
fn reauthorize_at(
    db: &mut Connection,
    config: &Config,
    actor: &str,
    id: &str,
    reason: &str,
    expires: i64,
    now: i64,
) -> Result<Entry> {
    actor_valid(actor)?;
    ensure!(
        expires > now && expires <= now.saturating_add(168 * 3600),
        "Escalation authorization must expire within 168 hours"
    );
    ensure!(
        !reason.trim().is_empty() && reason.len() <= 1024,
        "Escalation reason must contain 1 to 1024 bytes"
    );
    initialize(db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if let Some(existing) = tx
        .query_row(&format!("{SELECT} WHERE parent_id=?1"), [id], read_entry)
        .optional()?
    {
        return entry(existing);
    }
    let parent = entry(
        tx.query_row(&format!("{SELECT} WHERE id=?1"), [id], read_entry)
            .optional()?
            .context("Escalation attempt not found")?,
    )?;
    let confirmed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM ticket_escalation_reconciliation WHERE id=?1 AND delivered=0)",
        [id],
        |r| r.get(0),
    )?;
    ensure!(
        matches!(parent.state.as_str(), "expired" | "blocked" | "canceled")
            || (parent.state == "not_delivered" && confirmed),
        "A new attempt requires proven non-dispatch or operator-confirmed non-delivery; queued, in-flight, unknown, and delivered attempts cannot retry"
    );
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM ticket_escalation_outbox", [], |r| {
        r.get(0)
    })?;
    ensure!(
        count < 1000,
        "Escalation outbox full; operator retention review required"
    );
    let new_id = Uuid::new_v4().to_string();
    let mut payload = parent.payload;
    payload["escalation_id"] = json!(new_id);
    payload["reason"] = json!(sanitize(reason, 1024));
    let serialized = serde_json::to_string(&payload)?;
    ensure!(serialized.len() <= 4096, "Escalation summary exceeds 4 KiB");
    let fingerprint = config.fingerprint();
    tx.execute(
        "INSERT INTO ticket_escalation_outbox VALUES(?1,?2,?3,?4,?5,'queued',?6,'',?7,?8)",
        params![
            new_id,
            parent.delivery,
            actor,
            fingerprint,
            expires,
            serialized,
            now,
            id
        ],
    )?;
    tx.commit()?;
    Ok(Entry {
        id: new_id,
        delivery: parent.delivery,
        actor: actor.into(),
        destination_fingerprint: fingerprint,
        expires_utc: expires,
        state: "queued".into(),
        payload,
        note: String::new(),
        parent_id: Some(id.into()),
    })
}
enum Outcome {
    Sent,
    Rejected,
    Unknown,
}
fn step(
    db: &mut Connection,
    config: &Config,
    now: i64,
    send: &mut impl FnMut(&str, &[u8]) -> Outcome,
) -> Result<bool> {
    initialize(db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute("UPDATE ticket_escalation_outbox SET state='unknown',note='Sending lease elapsed; inspect destination before reconciliation',updated_utc=?1 WHERE state='sending' AND updated_utc<=?2",params![now,now.saturating_sub(60)])?;
    let pending = tx
        .query_row(
            &format!("{SELECT} WHERE state='queued' ORDER BY updated_utc,id LIMIT 1"),
            [],
            read_entry,
        )
        .optional()?;
    let Some(pending) = pending else {
        tx.commit()?;
        return Ok(false);
    };
    let pending = entry(pending)?;
    let blocked = if pending.expires_utc <= now {
        Some(("expired", "Authorization expired"))
    } else if pending.destination_fingerprint != config.fingerprint() {
        Some((
            "blocked",
            "Destination or credential changed; authorization is invalid",
        ))
    } else {
        None
    };
    if let Some((state, note)) = blocked {
        tx.execute(
            "UPDATE ticket_escalation_outbox SET state=?1,note=?2,updated_utc=?3 WHERE id=?4",
            params![state, note, now, pending.id],
        )?;
        tx.commit()?;
        return Ok(true);
    }
    let body = serde_json::to_vec(&pending.payload)?;
    ensure!(body.len() <= 4096, "Stored summary exceeds 4 KiB");
    tx.execute(
        "UPDATE ticket_escalation_outbox SET state='sending',updated_utc=?1 WHERE id=?2",
        params![now, pending.id],
    )?;
    tx.commit()?; // Commit authorization consumption before any external call.
    let (state, note) = match send(&pending.id, &body) {
        Outcome::Sent => (
            "sent",
            "Destination returned HTTP success; downstream action not verified",
        ),
        Outcome::Rejected => ("failed", "Destination rejected the request; no retry"),
        Outcome::Unknown => (
            "unknown",
            "Delivery uncertain; inspect destination before reconciliation",
        ),
    };
    db.execute("UPDATE ticket_escalation_outbox SET state=?1,note=?2,updated_utc=?3 WHERE id=?4 AND state='sending'",params![state,note,now,pending.id])?;
    Ok(true)
}
/// Explicit deployment worker: at most 32 entries, one attempt each.
pub fn worker(db: &mut Connection, config: &Config) -> Result<usize> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()?;
    let mut send = |delivery: &str, body: &[u8]| {
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, config.bearer.as_bytes()),
            body,
        )
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
        match client
            .post(&config.url)
            .bearer_auth(&config.bearer)
            .header("Content-Type", "application/json")
            .header("Idempotency-Key", delivery)
            .header("X-Relayne-Signature", format!("sha256={signature}"))
            .body(body.to_vec())
            .send()
        {
            Ok(r) if r.status().is_success() => Outcome::Sent,
            Ok(r)
                if matches!(
                    r.status().as_u16(),
                    400 | 401 | 403 | 404 | 405 | 410 | 413 | 415 | 422
                ) =>
            {
                Outcome::Rejected
            }
            _ => Outcome::Unknown,
        }
    };
    let mut count = 0;
    while count < 32 && step(db, config, Utc::now().timestamp(), &mut send)? {
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Connection, Config, String) {
        let mut db = Connection::open_in_memory().unwrap();
        let raw = json!({"origin":"local","key":"SUP-1","title":"password=never-forward","description":"RAW SECRET BODY","revision":"1"});
        let delivery =
            crate::ticket_intake::receive_import(&mut db, "operator", raw.to_string().as_bytes())
                .unwrap()
                .delivery;
        (
            db,
            Config::new(
                "https://automation.example.invalid/escalate",
                &"x".repeat(32),
            )
            .unwrap(),
            delivery,
        )
    }
    #[test]
    fn queue_is_explicit_bounded_deduplicated_and_sanitized() {
        let (mut db, c, d) = fixture();
        assert!(enqueue_at(&mut db, &c, "operator", &d, "review", 100, 100).is_err());
        assert!(
            enqueue_at(
                &mut db,
                &c,
                "operator",
                &d,
                "review",
                100 + 168 * 3600 + 1,
                100
            )
            .is_err()
        );
        let a = enqueue_at(
            &mut db,
            &c,
            "operator",
            &d,
            "Escalate unresolved incident",
            200,
            100,
        )
        .unwrap();
        let b = enqueue_at(
            &mut db,
            &c,
            "another-actor",
            &d,
            "Different reason",
            300,
            100,
        )
        .unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(b.actor, "operator");
        assert_eq!(b.expires_utc, 200);
        assert_eq!(a.payload["title"], "[redacted sensitive text]");
        assert!(!a.payload.to_string().contains("RAW SECRET BODY"));
        assert_eq!(list(&db).unwrap().len(), 1);
        let stored = Connection::open_in_memory().unwrap();
        assert!(list(&stored).unwrap().is_empty());
    }
    #[test]
    fn expiry_and_destination_drift_never_send() {
        for drift in [false, true] {
            let (mut db, c, d) = fixture();
            enqueue_at(&mut db, &c, "operator", &d, "review", 200, 100).unwrap();
            let changed =
                Config::new("https://other.example.invalid/escalate", &"x".repeat(32)).unwrap();
            step(
                &mut db,
                if drift { &changed } else { &c },
                if drift { 101 } else { 200 },
                &mut |_, _| panic!("not authorized"),
            )
            .unwrap();
            assert_eq!(
                list(&db).unwrap()[0].state,
                if drift { "blocked" } else { "expired" }
            );
        }
    }
    #[test]
    fn unknown_is_not_resent_and_reconciliation_never_requeues() {
        let (mut db, c, d) = fixture();
        let queued = enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
        let mut calls = 0;
        step(&mut db, &c, 101, &mut |id, body| {
            calls += 1;
            assert_eq!(id, queued.id);
            assert!(body.len() <= 4096);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(body).unwrap()["escalation_id"],
                id
            );
            Outcome::Unknown
        })
        .unwrap();
        assert!(
            !step(&mut db, &c, 102, &mut |_, _| panic!(
                "never retry uncertain delivery"
            ))
            .unwrap()
        );
        assert_eq!(calls, 1);
        assert_eq!(list(&db).unwrap()[0].state, "unknown");
        reconcile(&db, "reviewer", &queued.id, false).unwrap();
        assert_eq!(list(&db).unwrap()[0].state, "not_delivered");
        assert!(
            !step(&mut db, &c, 103, &mut |_, _| panic!(
                "reconciliation is not authorization"
            ))
            .unwrap()
        );
    }
    #[test]
    fn interrupted_sending_becomes_unknown_after_lease_without_network() {
        let (mut db, c, d) = fixture();
        let q = enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
        db.execute(
            "UPDATE ticket_escalation_outbox SET state='sending',updated_utc=100 WHERE id=?1",
            [&q.id],
        )
        .unwrap();
        assert!(reconcile(&db, "reviewer", &q.id, true).is_err());
        assert!(!step(&mut db, &c, 159, &mut |_, _| panic!("in flight")).unwrap());
        assert_eq!(list(&db).unwrap()[0].state, "sending");
        assert!(
            !step(&mut db, &c, 160, &mut |_, _| panic!(
                "crash recovery never resends"
            ))
            .unwrap()
        );
        assert_eq!(list(&db).unwrap()[0].state, "unknown");
        reconcile(&db, "reviewer", &q.id, true).unwrap();
        assert_eq!(list(&db).unwrap()[0].state, "sent");
        assert!(reauthorize_at(&mut db, &c, "operator", &q.id, "retry", 700, 161).is_err());
    }
    #[test]
    fn success_and_confirmed_rejection_are_not_retried() {
        for rejected in [false, true] {
            let (mut db, c, d) = fixture();
            enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
            step(&mut db, &c, 101, &mut |_, _| {
                if rejected {
                    Outcome::Rejected
                } else {
                    Outcome::Sent
                }
            })
            .unwrap();
            assert_eq!(
                list(&db).unwrap()[0].state,
                if rejected { "failed" } else { "sent" }
            );
            assert!(!step(&mut db, &c, 102, &mut |_, _| panic!("already attempted")).unwrap());
        }
        assert!(Config::new("http://automation.invalid", &"x".repeat(32)).is_err());
        assert!(Config::new("https://automation.invalid?token=secret", &"x".repeat(32)).is_err());
    }
    #[test]
    fn retry_requires_confirmed_non_delivery_and_creates_one_immutable_child() {
        let (mut db, c, d) = fixture();
        let first = enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
        step(&mut db, &c, 101, &mut |_, _| Outcome::Unknown).unwrap();
        assert!(reauthorize_at(&mut db, &c, "operator", &first.id, "retry", 500, 102).is_err());
        reconcile(&db, "reviewer", &first.id, false).unwrap();
        assert!(
            !step(&mut db, &c, 103, &mut |_, _| panic!(
                "confirmation cannot send"
            ))
            .unwrap()
        );
        let child = reauthorize_at(
            &mut db,
            &c,
            "operator",
            &first.id,
            "Checked destination; retry",
            600,
            104,
        )
        .unwrap();
        let repeated = reauthorize_at(
            &mut db,
            &c,
            "other",
            &first.id,
            "duplicate request",
            700,
            105,
        )
        .unwrap();
        assert_eq!(child.id, repeated.id);
        assert_ne!(child.id, first.id);
        assert_eq!(child.parent_id, Some(first.id.clone()));
        assert_eq!(repeated.expires_utc, 600);
        step(&mut db, &c, 106, &mut |id, _| {
            assert_eq!(id, child.id);
            Outcome::Sent
        })
        .unwrap();
        assert!(reauthorize_at(&mut db, &c, "operator", &child.id, "retry", 700, 107).is_err());
        let original = list(&db)
            .unwrap()
            .into_iter()
            .find(|x| x.id == first.id)
            .unwrap();
        assert_eq!(original.state, "not_delivered");
        assert_eq!(original.expires_utc, 500);
    }
    #[test]
    fn cancel_only_revokes_queued_authority_and_credential_rotation_blocks_send() {
        let (mut db, c, d) = fixture();
        let q = enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
        cancel(&db, "operator", &q.id).unwrap();
        assert_eq!(list(&db).unwrap()[0].state, "canceled");
        assert!(!step(&mut db, &c, 101, &mut |_, _| panic!("canceled")).unwrap());
        assert!(cancel(&db, "operator", &q.id).is_err());
        let (mut db, c, d) = fixture();
        let q = enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
        let rotated = Config::new(c.destination(), &"y".repeat(32)).unwrap();
        assert_ne!(c.fingerprint(), rotated.fingerprint());
        step(&mut db, &rotated, 101, &mut |_, _| {
            panic!("credential drift")
        })
        .unwrap();
        assert_eq!(list(&db).unwrap()[0].state, "blocked");
        assert!(cancel(&db, "operator", &q.id).is_err());
    }
    #[test]
    fn proven_non_dispatch_requires_explicit_new_authorization_and_preserves_parent() {
        for state in ["expired", "blocked", "canceled"] {
            let (mut db, original_config, delivery) = fixture();
            let parent = enqueue_at(&mut db, &original_config, "operator", &delivery, "Initial review", 200, 100).unwrap();
            let current_config = Config::new("https://new.example.invalid/escalate", &"y".repeat(32)).unwrap();
            match state {
                "expired" => { step(&mut db, &original_config, 200, &mut |_, _| panic!("expired authorization cannot send")).unwrap(); }
                "blocked" => { step(&mut db, &current_config, 101, &mut |_, _| panic!("changed destination cannot send")).unwrap(); }
                _ => cancel(&db, "operator", &parent.id).unwrap(),
            }
            assert!(!step(&mut db, &current_config, 201, &mut |_, _| panic!("closed state must not autoqueue")).unwrap());
            let child = reauthorize_at(&mut db, &current_config, "reviewer", &parent.id, "New destination and summary reviewed", 500, 202).unwrap();
            let repeated = reauthorize_at(&mut db, &current_config, "other", &parent.id, "Duplicate request", 600, 203).unwrap();
            assert_eq!(child.id, repeated.id);
            assert_eq!(child.expires_utc, 500);
            assert_eq!(child.actor, "reviewer");
            assert_eq!(child.destination_fingerprint, current_config.fingerprint());
            assert_eq!(child.parent_id.as_deref(), Some(parent.id.as_str()));
            let entries = list(&db).unwrap();
            assert_eq!(entries.len(), 2);
            let unchanged = entries.iter().find(|entry| entry.id == parent.id).unwrap();
            assert_eq!(unchanged.state, state);
            assert_eq!(unchanged.destination_fingerprint, original_config.fingerprint());
            assert_eq!(unchanged.expires_utc, 200);
            assert_eq!(entries.iter().find(|entry| entry.id == child.id).unwrap().state, "queued");
            step(&mut db, &current_config, 204, &mut |id, _| { assert_eq!(id, child.id); Outcome::Sent }).unwrap();
        }
    }
    #[test]
    fn new_attempt_rejects_unresolved_or_unconfirmed_states() {
        for state in ["queued", "sending", "unknown", "sent", "failed", "not_delivered"] {
            let (mut db, config, delivery) = fixture();
            let parent = enqueue_at(&mut db, &config, "operator", &delivery, "Initial review", 500, 100).unwrap();
            db.execute("UPDATE ticket_escalation_outbox SET state=?1 WHERE id=?2", params![state, parent.id]).unwrap();
            assert!(reauthorize_at(&mut db, &config, "operator", &parent.id, "New review", 600, 101).is_err(), "state {state} must not authorize a new attempt without proof");
            assert_eq!(list(&db).unwrap().len(), 1);
        }
    }
    #[test]
    fn sending_is_committed_before_fake_transport_and_survives_reopen() {
        let path =
            std::env::temp_dir().join(format!("relayne-escalation-{}.sqlite", Uuid::new_v4()));
        {
            let mut db = Connection::open(&path).unwrap();
            let raw = json!({"origin":"local","key":"SUP-1","title":"Issue","description":"Do not forward","revision":"1"});
            let d = crate::ticket_intake::receive_import(
                &mut db,
                "operator",
                raw.to_string().as_bytes(),
            )
            .unwrap()
            .delivery;
            let c = Config::new("https://automation.example.invalid", &"x".repeat(32)).unwrap();
            let q = enqueue_at(&mut db, &c, "operator", &d, "review", 500, 100).unwrap();
            step(&mut db, &c, 101, &mut |id, _| {
                let reader = Connection::open(&path).unwrap();
                let state: String = reader
                    .query_row(
                        "SELECT state FROM ticket_escalation_outbox WHERE id=?1",
                        [id],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(state, "sending");
                Outcome::Unknown
            })
            .unwrap();
            assert_eq!(list(&db).unwrap()[0].id, q.id);
        }
        {
            let db = Connection::open(&path).unwrap();
            assert_eq!(list(&db).unwrap()[0].state, "unknown");
        }
        std::fs::remove_file(path).unwrap();
    }
}
