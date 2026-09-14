//! Server-side Stripe subscription integration. Secrets never enter the desktop client.
use anyhow::{Context, Result, ensure};
use reqwest::blocking::Client;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
pub struct Entitlement {
    pub active: bool,
    pub status: String,
    pub valid_until: i64,
    pub checked_at: i64,
}

pub struct Config {
    secret: String,
    webhook: String,
    price: String,
    return_url: String,
    live: bool,
}
impl Config {
    pub fn from_environment() -> Result<Self> {
        let read = |name| std::env::var(name).with_context(|| format!("Missing {name}"));
        let secret = read("RELAYNE_STRIPE_SECRET_KEY")?;
        let live = stripe_key_mode(&secret)?;
        ensure!(
            !live || std::env::var("RELAYNE_COMMERCE_APPROVED").as_deref() == Ok("true"),
            "Live commerce requires explicit commercial approval"
        );
        let webhook = read("RELAYNE_STRIPE_WEBHOOK_SECRET")?;
        ensure!(webhook.starts_with("whsec_"), "Invalid webhook secret");
        let price = read("RELAYNE_STRIPE_PRICE_ID")?;
        ensure!(valid_id(&price, "price_"), "Invalid price ID");
        let return_url = read("RELAYNE_STRIPE_RETURN_URL")?;
        let url = reqwest::Url::parse(&return_url)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "Return URL must use HTTPS without credentials or fragment"
        );
        Ok(Self {
            secret,
            webhook,
            price,
            return_url,
            live,
        })
    }
    fn api(
        &self,
        path: &str,
        form: Option<&[(String, String)]>,
        idempotency: Option<&str>,
    ) -> Result<Value> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let url = format!("https://api.stripe.com/v1/{path}");
        let request = match form {
            Some(form) => client.post(url).form(form),
            None => client.get(url),
        };
        let mut request = request
            .bearer_auth(&self.secret)
            .header("Stripe-Version", "2025-03-31.basil");
        if let Some(key) = idempotency {
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send().context("Stripe unavailable")?;
        ensure!(
            response.status().is_success(),
            "Stripe request failed ({})",
            response.status().as_u16()
        );
        let mut bytes = Vec::new();
        response.take(1_048_577).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "Stripe response too large");
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn stripe_key_mode(secret: &str) -> Result<bool> {
    for (prefix, live) in [
        ("sk_test_", false),
        ("rk_test_", false),
        ("sk_live_", true),
        ("rk_live_", true),
    ] {
        if let Some(tail) = secret.strip_prefix(prefix) {
            ensure!(
                !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric()),
                "Invalid Stripe secret key"
            );
            return Ok(live);
        }
    }
    anyhow::bail!("Invalid Stripe secret key")
}
fn valid_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS billing_accounts(actor TEXT PRIMARY KEY,customer TEXT UNIQUE NOT NULL,subscription TEXT,status TEXT NOT NULL DEFAULT 'none',valid_until INTEGER NOT NULL DEFAULT 0,checked_at INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS billing_events(id TEXT PRIMARY KEY,received_at INTEGER NOT NULL);")?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS billing_checkout(actor TEXT PRIMARY KEY,attempt TEXT NOT NULL,created_at INTEGER NOT NULL,session TEXT,state TEXT NOT NULL DEFAULT 'pending'); CREATE TABLE IF NOT EXISTS billing_retired_subscriptions(subscription TEXT PRIMARY KEY,customer TEXT NOT NULL);")?;
    Ok(())
}
pub fn entitlement(db: &Connection, actor: &str, now: i64) -> Result<Entitlement> {
    initialize(db)?;
    let row = db
        .query_row(
            "SELECT status,valid_until,checked_at FROM billing_accounts WHERE actor=?1",
            [actor],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let (status, valid_until, checked_at) = row.unwrap_or(("none".into(), 0, 0));
    // Stale webhook state must not grant indefinite access. Explicit refresh is available.
    let active = status == "active"
        && valid_until > now
        && checked_at <= now
        && now.saturating_sub(checked_at) < 86_400;
    Ok(Entitlement {
        active,
        status,
        valid_until,
        checked_at,
    })
}
pub fn checkout(
    db: &Connection,
    config: &Config,
    actor: &str,
    attempt: uuid::Uuid,
) -> Result<Value> {
    checkout_with(
        db,
        config,
        actor,
        attempt,
        chrono::Utc::now().timestamp(),
        |path, form, key| config.api(path, form, key),
    )
}

fn checkout_with(
    db: &Connection,
    config: &Config,
    actor: &str,
    attempt: uuid::Uuid,
    now: i64,
    mut api: impl FnMut(&str, Option<&[(String, String)]>, Option<&str>) -> Result<Value>,
) -> Result<Value> {
    initialize(db)?;
    let existing: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT customer,subscription FROM billing_accounts WHERE actor=?1",
            [actor],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((_, Some(_))) = &existing {
        anyhow::bail!("An existing subscription must be managed in the customer portal");
    }
    let pending: Option<(String, i64, Option<String>)> = db
        .query_row(
            "SELECT attempt,created_at,session FROM billing_checkout WHERE actor=?1",
            [actor],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let selected_attempt = if let Some((saved_attempt, created_at, session)) = pending {
        if let Some(session) = session {
            ensure!(valid_id(&session, "cs_"), "Invalid stored checkout session");
            let value = api(&format!("checkout/sessions/{session}"), None, None)?;
            let customer = existing
                .as_ref()
                .context("Checkout customer missing")?
                .0
                .as_str();
            validate_session(&value, customer)?;
            ensure!(value["id"] == session, "Checkout session identity changed");
            match value["status"].as_str() {
                Some("open") => return session_link(&value, now),
                Some("complete") => {
                    let sub = value["subscription"]
                        .as_str()
                        .context("Completed subscription missing")?;
                    ensure!(valid_id(sub, "sub_"), "Invalid subscription ID");
                    let canonical = api(
                        &format!("subscriptions/{sub}?expand[]=latest_invoice"),
                        None,
                        None,
                    )?;
                    ensure!(
                        canonical["id"] == sub && canonical["customer"] == customer,
                        "Subscription identity mismatch"
                    );
                    apply_subscription(db, &canonical, &config.price, now)?;
                    if matches!(
                        canonical["status"].as_str(),
                        Some("canceled" | "incomplete_expired")
                    ) {
                        replace_checkout_intent(db, actor, &saved_attempt, &session, attempt, now)?
                    } else {
                        db.execute(
                            "UPDATE billing_checkout SET state='complete' WHERE actor=?1",
                            [actor],
                        )?;
                        anyhow::bail!("Checkout completed; verify subscription or manage billing");
                    }
                }
                Some("expired") => {
                    replace_checkout_intent(db, actor, &saved_attempt, &session, attempt, now)?
                }
                _ => anyhow::bail!("Unknown checkout state; do not create another payment session"),
            }
        } else {
            // Stripe may expire idempotency records after 24 hours. An uncertain request
            // must not become a second checkout merely because that window has elapsed.
            ensure!(
                created_at <= now && now - created_at < 23 * 3600,
                "Unresolved checkout requires billing support before another attempt"
            );
            saved_attempt
        }
    } else {
        db.execute(
            "INSERT INTO billing_checkout(actor,attempt,created_at) VALUES(?1,?2,?3)",
            params![actor, attempt.to_string(), now],
        )?;
        attempt.to_string()
    };
    let customer = if let Some((customer, subscription)) = existing {
        ensure!(
            subscription.is_none(),
            "An existing subscription must be managed in the customer portal"
        );
        customer
    } else {
        use sha2::{Digest, Sha256};
        let actor_hash = format!("{:x}", Sha256::digest(actor.as_bytes()));
        let response = api(
            "customers",
            Some(&[("metadata[relayne_account]".into(), actor_hash.clone())]),
            Some(&format!("relayne-customer-{actor_hash}")),
        )?;
        let customer = response["id"].as_str().context("Customer ID missing")?;
        ensure!(valid_id(customer, "cus_"), "Invalid customer ID");
        db.execute(
            "INSERT INTO billing_accounts(actor,customer) VALUES(?1,?2)",
            params![actor, customer],
        )?;
        customer.to_owned()
    };
    // Validate the configured Price before sending the customer to checkout.
    let price = api(&format!("prices/{}", config.price), None, None)?;
    ensure!(
        price["active"] == true
            && price["type"] == "recurring"
            && price["recurring"]["usage_type"] == "licensed",
        "Configure an active licensed recurring Price"
    );
    ensure!(
        matches!(
            price["tax_behavior"].as_str(),
            Some("inclusive" | "exclusive")
        ),
        "Set the Price tax treatment explicitly in Stripe"
    );
    let response = api(
        "checkout/sessions",
        Some(&[
            ("mode".into(), "subscription".into()),
            ("customer".into(), customer.clone()),
            ("line_items[0][price]".into(), config.price.clone()),
            ("line_items[0][quantity]".into(), "1".into()),
            ("success_url".into(), config.return_url.clone()),
            ("cancel_url".into(), config.return_url.clone()),
            ("automatic_tax[enabled]".into(), "true".into()),
            ("customer_update[address]".into(), "auto".into()),
        ]),
        Some(&format!("relayne-checkout-{customer}-{selected_attempt}")),
    )?;
    validate_session(&response, &customer)?;
    let session = response["id"]
        .as_str()
        .context("Checkout session missing")?;
    ensure!(
        db.execute(
            "UPDATE billing_checkout SET session=?1,state='open' WHERE actor=?2 AND attempt=?3",
            params![session, actor, selected_attempt]
        )? == 1,
        "Checkout intent changed; reconcile before retrying"
    );
    session_link(&response, now)
}

fn replace_checkout_intent(
    db: &Connection,
    actor: &str,
    previous: &str,
    session: &str,
    next: uuid::Uuid,
    now: i64,
) -> Result<String> {
    let next = next.to_string();
    ensure!(
        previous != next,
        "Checkout expired or subscription ended; start a new attempt"
    );
    ensure!(db.execute("UPDATE billing_checkout SET attempt=?1,created_at=?2,session=NULL,state='pending' WHERE actor=?3 AND attempt=?4 AND session=?5", params![next,now,actor,previous,session])? == 1,"Checkout changed concurrently; retry its saved attempt");
    Ok(next)
}

fn validate_session(value: &Value, customer: &str) -> Result<()> {
    ensure!(
        value["id"].as_str().is_some_and(|id| valid_id(id, "cs_"))
            && value["customer"] == customer
            && value["mode"] == "subscription",
        "Checkout account or mode mismatch"
    );
    Ok(())
}

fn session_link(value: &Value, now: i64) -> Result<Value> {
    ensure!(
        value["status"] == "open" && value["expires_at"].as_i64().is_some_and(|at| at > now),
        "Checkout is not open; verify its state before starting another attempt"
    );
    let url = value["url"].as_str().context("Checkout URL missing")?;
    validate_stripe_url(url, "checkout.stripe.com")?;
    Ok(json!({"url":url,"entitlement_granted":false}))
}
pub fn portal(db: &Connection, config: &Config, actor: &str) -> Result<Value> {
    initialize(db)?;
    let customer: String = db
        .query_row(
            "SELECT customer FROM billing_accounts WHERE actor=?1",
            [actor],
            |r| r.get(0),
        )
        .context("No billing account")?;
    let response = config.api(
        "billing_portal/sessions",
        Some(&[
            ("customer".into(), customer),
            ("return_url".into(), config.return_url.clone()),
        ]),
        None,
    )?;
    let url = response["url"].as_str().context("Portal URL missing")?;
    validate_stripe_url(url, "billing.stripe.com")?;
    Ok(json!({"url":url}))
}
fn validate_stripe_url(value: &str, host: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some(host)
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none(),
        "Invalid Stripe URL"
    );
    Ok(())
}
pub fn verify_webhook(secret: &str, header: &str, body: &[u8], now: i64) -> Result<()> {
    ensure!(
        body.len() <= 1_048_576 && header.len() <= 4096,
        "Webhook too large"
    );
    let parts = header
        .split(',')
        .filter_map(|v| v.trim().split_once('='))
        .collect::<Vec<_>>();
    let times = parts.iter().filter(|(k, _)| *k == "t").collect::<Vec<_>>();
    ensure!(times.len() == 1, "Ambiguous webhook timestamp");
    let timestamp: i64 = times[0].1.parse()?;
    ensure!(timestamp.abs_diff(now) <= 300, "Webhook timestamp expired");
    let mut payload = format!("{timestamp}.").into_bytes();
    payload.extend_from_slice(body);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let valid = parts.iter().filter(|(k, _)| *k == "v1").any(|(_, hex)| {
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        let bytes = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        ring::hmac::verify(&key, &payload, &bytes).is_ok()
    });
    ensure!(valid, "Invalid webhook signature");
    Ok(())
}
fn apply_subscription(db: &Connection, value: &Value, price: &str, now: i64) -> Result<()> {
    let customer = value["customer"].as_str().context("Customer missing")?;
    let subscription = value["id"].as_str().context("Subscription missing")?;
    ensure!(
        valid_id(customer, "cus_") && valid_id(subscription, "sub_"),
        "Invalid subscription identity"
    );
    let existing: Option<Option<String>> = db
        .query_row(
            "SELECT subscription FROM billing_accounts WHERE customer=?1",
            [customer],
            |r| r.get(0),
        )
        .optional()?;
    let Some(existing) = existing else {
        return Ok(());
    };
    let retired: Option<String> = db
        .query_row(
            "SELECT customer FROM billing_retired_subscriptions WHERE subscription=?1",
            [subscription],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(owner) = retired {
        ensure!(owner == customer, "Retired subscription account mismatch");
        return Ok(());
    }
    if matches!(
        value["status"].as_str(),
        Some("canceled" | "incomplete_expired")
    ) {
        db.execute(
            "INSERT INTO billing_retired_subscriptions(subscription,customer) VALUES(?1,?2)",
            params![subscription, customer],
        )?;
        if existing.as_deref().is_none_or(|id| id == subscription) {
            db.execute("UPDATE billing_accounts SET subscription=NULL,status='inactive',valid_until=0,checked_at=?1 WHERE customer=?2", params![now,customer])?;
        }
        return Ok(());
    }
    ensure!(
        existing.as_deref().is_none_or(|id| id == subscription),
        "Another subscription is already bound to this account"
    );
    let items = value["items"]["data"]
        .as_array()
        .context("Subscription items missing")?;
    let eligible =
        items.len() == 1 && items[0]["price"]["id"] == price && items[0]["quantity"] == 1;
    let paid = value["latest_invoice"]["status"] == "paid"
        && value["latest_invoice"]["amount_remaining"].as_i64() == Some(0);
    let status = if eligible && paid && value["status"] == "active" {
        "active"
    } else {
        "inactive"
    };
    let period_end = items
        .first()
        .and_then(|i| i["current_period_end"].as_i64())
        .or_else(|| value["current_period_end"].as_i64())
        .unwrap_or(0);
    db.execute("UPDATE billing_accounts SET subscription=?1,status=?2,valid_until=?3,checked_at=?4 WHERE customer=?5", params![subscription,status,period_end,now,customer])?;
    Ok(())
}
pub fn refresh(db: &Connection, config: &Config, actor: &str, now: i64) -> Result<Entitlement> {
    initialize(db)?;
    let sub: Option<String> = db
        .query_row(
            "SELECT subscription FROM billing_accounts WHERE actor=?1",
            [actor],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    if let Some(id) = sub {
        ensure!(valid_id(&id, "sub_"), "Invalid stored subscription");
        let value = config.api(
            &format!("subscriptions/{id}?expand[]=latest_invoice"),
            None,
            None,
        )?;
        apply_subscription(db, &value, &config.price, now)?;
    }
    entitlement(db, actor, now)
}
pub fn webhook(
    db: &mut Connection,
    config: &Config,
    signature: &str,
    body: &[u8],
    now: i64,
) -> Result<()> {
    webhook_with(db, config, signature, body, now, |path, form, key| {
        config.api(path, form, key)
    })
}

fn webhook_with(
    db: &mut Connection,
    config: &Config,
    signature: &str,
    body: &[u8],
    now: i64,
    mut api: impl FnMut(&str, Option<&[(String, String)]>, Option<&str>) -> Result<Value>,
) -> Result<()> {
    verify_webhook(&config.webhook, signature, body, now)?;
    let event: Value = serde_json::from_slice(body)?;
    ensure!(
        event["livemode"].as_bool() == Some(config.live),
        "Stripe mode mismatch"
    );
    let id = event["id"].as_str().context("Event ID missing")?;
    ensure!(valid_id(id, "evt_"), "Invalid event ID");
    initialize(db)?;
    if db
        .query_row("SELECT 1 FROM billing_events WHERE id=?1", [id], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?
        .is_some()
    {
        return Ok(());
    }
    let Some(sub) = subscription_for_event(&event)? else {
        return Ok(());
    };
    // Fetch authoritative current state: out-of-order webhook bodies never reactivate old state.
    let value = api(
        &format!("subscriptions/{sub}?expand[]=latest_invoice"),
        None,
        None,
    )?;
    ensure!(
        value["id"] == sub,
        "Canonical subscription identity mismatch"
    );
    let tx = db.transaction()?;
    apply_subscription(&tx, &value, &config.price, now)?;
    tx.execute(
        "INSERT INTO billing_events(id,received_at) VALUES(?1,?2)",
        params![id, now],
    )?;
    tx.commit()?;
    Ok(())
}

fn subscription_for_event(event: &Value) -> Result<Option<String>> {
    let kind = event["type"].as_str().context("Event type missing")?;
    let object = &event["data"]["object"];
    let sub = match kind {
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            object["id"].as_str().context("Subscription missing")?
        }
        "invoice.paid" | "invoice.payment_failed" => {
            // Basil places an invoice's subscription under parent.subscription_details.
            // Accept a consistent legacy subscription field during endpoint migration.
            let current = object["parent"]["subscription_details"]["subscription"].as_str();
            let legacy = object["subscription"].as_str();
            ensure!(
                current.is_none() || legacy.is_none() || current == legacy,
                "Ambiguous invoice subscription"
            );
            let Some(sub) = current.or(legacy) else {
                return Ok(None);
            };
            sub
        }
        _ => return Ok(None),
    };
    ensure!(valid_id(sub, "sub_"), "Invalid subscription");
    Ok(Some(sub.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restricted_and_standard_keys_require_correct_mode_and_nonempty_payload() {
        for prefix in ["sk_test_", "rk_test_"] {
            assert!(!stripe_key_mode(&format!("{prefix}fixture")).unwrap());
        }
        for prefix in ["sk_live_", "rk_live_"] {
            assert!(stripe_key_mode(&format!("{prefix}fixture")).unwrap());
        }
        for invalid in [
            "pk_test_fixture",
            "rk_test_",
            "rk_test_has space",
            "sk_live_bad\n",
        ] {
            assert!(stripe_key_mode(invalid).is_err());
        }
    }
    fn signed(body: &[u8], now: i64) -> String {
        let mut payload = format!("{now}.").into_bytes();
        payload.extend_from_slice(body);
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"whsec_test");
        let signature = ring::hmac::sign(&key, &payload)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        format!("t={now},v1={signature}")
    }
    #[test]
    fn signed_invoice_replay_skips_provider_and_failed_binding_is_not_acknowledged() {
        let mut db = account();
        let config = test_config();
        let event = json!({"id":"evt_one","livemode":false,"type":"invoice.paid","data":{"object":{"parent":{"subscription_details":{"subscription":"sub_one"}}}}});
        let body = serde_json::to_vec(&event).unwrap();
        let header = signed(&body, 1000);
        let mut calls = 0;
        webhook_with(&mut db, &config, &header, &body, 1000, |path, _, _| {
            calls += 1;
            assert_eq!(path, "subscriptions/sub_one?expand[]=latest_invoice");
            Ok(subscription("sub_one", "active"))
        })
        .unwrap();
        assert_eq!(calls, 1);
        webhook_with(&mut db, &config, &header, &body, 1001, |_, _, _| {
            panic!("Replay must not contact provider")
        })
        .unwrap();
        let mut conflict = event;
        conflict["id"] = json!("evt_other");
        conflict["data"]["object"]["parent"]["subscription_details"]["subscription"] =
            json!("sub_second");
        let body = serde_json::to_vec(&conflict).unwrap();
        let header = signed(&body, 1002);
        assert!(
            webhook_with(&mut db, &config, &header, &body, 1002, |_, _, _| Ok(
                subscription("sub_second", "active")
            ))
            .is_err()
        );
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM billing_events WHERE id='evt_other'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert!(entitlement(&db, "alice", 1003).unwrap().active);
    }
    fn test_config() -> Config {
        Config {
            secret: "unused".into(),
            webhook: "whsec_test".into(),
            price: "price_one".into(),
            return_url: "https://example.invalid/account".into(),
            live: false,
        }
    }
    fn account() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db.execute("INSERT INTO billing_accounts(actor,customer) VALUES('alice','cus_alice'),('bob','cus_bob')",[]).unwrap();
        db
    }
    fn session(status: &str) -> Value {
        json!({"id":"cs_one","customer":"cus_alice","mode":"subscription","status":status,"expires_at":9000,"url":"https://checkout.stripe.com/session"})
    }
    fn subscription(id: &str, status: &str) -> Value {
        json!({"id":id,"customer":"cus_alice","status":status,"latest_invoice":{"status":"paid","amount_remaining":0},"items":{"data":[{"price":{"id":"price_one"},"quantity":1,"current_period_end":9000}]}})
    }
    #[test]
    fn uncertain_checkout_reuses_durable_account_attempt_even_after_client_changes_uuid() {
        let db = account();
        let config = test_config();
        let first = uuid::Uuid::new_v4();
        let mut keys = vec![];
        let failed = checkout_with(&db, &config, "alice", first, 1000, |path, _, key| {
            let count: i64 = db.query_row(
                "SELECT COUNT(*) FROM billing_checkout WHERE actor='alice'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(count, 1, "Intent must exist before every provider request");
            if path.starts_with("prices/") {
                return Ok(
                    json!({"active":true,"type":"recurring","recurring":{"usage_type":"licensed"},"tax_behavior":"inclusive"}),
                );
            }
            keys.push(key.unwrap().to_owned());
            anyhow::bail!("Simulated timeout after provider accepted checkout")
        });
        assert!(failed.is_err());
        checkout_with(&db,&config,"alice",uuid::Uuid::new_v4(),1001,|path,_,key| {
            if path.starts_with("prices/") { return Ok(json!({"active":true,"type":"recurring","recurring":{"usage_type":"licensed"},"tax_behavior":"inclusive"})); }
            keys.push(key.unwrap().to_owned()); Ok(session("open"))
        }).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], keys[1]);
        assert!(keys[0].contains("cus_alice"));
        let mut calls = 0;
        checkout_with(
            &db,
            &config,
            "alice",
            uuid::Uuid::new_v4(),
            1002,
            |path, form, _| {
                calls += 1;
                assert_eq!(path, "checkout/sessions/cs_one");
                assert!(form.is_none());
                Ok(session("open"))
            },
        )
        .unwrap();
        assert_eq!(
            calls, 1,
            "Open checkout must never create a second payable session"
        );
    }
    #[test]
    fn uncertain_checkout_after_idempotency_window_blocks_without_provider_call() {
        let db = account();
        let attempt = uuid::Uuid::new_v4();
        db.execute(
            "INSERT INTO billing_checkout(actor,attempt,created_at) VALUES('alice',?1,1000)",
            [attempt.to_string()],
        )
        .unwrap();
        assert!(
            checkout_with(
                &db,
                &test_config(),
                "alice",
                uuid::Uuid::new_v4(),
                1000 + 23 * 3600,
                |_, _, _| panic!("must not call provider")
            )
            .is_err()
        );
    }
    #[test]
    fn expired_session_requires_new_attempt_and_wrong_account_response_is_rejected() {
        let db = account();
        let attempt = uuid::Uuid::new_v4();
        db.execute("INSERT INTO billing_checkout(actor,attempt,created_at,session) VALUES('alice',?1,1000,'cs_one')",[attempt.to_string()]).unwrap();
        assert!(
            checkout_with(&db, &test_config(), "alice", attempt, 1001, |_, _, _| Ok(
                session("expired")
            ))
            .is_err()
        );
        assert!(
            checkout_with(
                &db,
                &test_config(),
                "alice",
                uuid::Uuid::new_v4(),
                1001,
                |_, _, _| {
                    let mut s = session("open");
                    s["customer"] = json!("cus_bob");
                    Ok(s)
                }
            )
            .is_err()
        );
        let next = uuid::Uuid::new_v4();
        let mut calls = 0;
        checkout_with(&db,&test_config(),"alice",next,1001,|path,_,key| {
            calls+=1;
            if path=="checkout/sessions/cs_one" {return Ok(session("expired"));}
            if path.starts_with("prices/") {return Ok(json!({"active":true,"type":"recurring","recurring":{"usage_type":"licensed"},"tax_behavior":"exclusive"}));}
            assert!(key.unwrap().contains(&next.to_string()));let mut s=session("open");s["id"]=json!("cs_two");Ok(s)
        }).unwrap();
        assert_eq!(calls, 3);
    }
    #[test]
    fn terminal_subscription_releases_binding_and_old_events_cannot_replace_new_subscription() {
        let db = account();
        apply_subscription(&db, &subscription("sub_old", "active"), "price_one", 1000).unwrap();
        apply_subscription(&db, &subscription("sub_old", "canceled"), "price_one", 1001).unwrap();
        assert!(!entitlement(&db, "alice", 1002).unwrap().active);
        let bound: Option<String> = db
            .query_row(
                "SELECT subscription FROM billing_accounts WHERE actor='alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(bound.is_none());
        apply_subscription(&db, &subscription("sub_new", "active"), "price_one", 1002).unwrap();
        apply_subscription(&db, &subscription("sub_old", "active"), "price_one", 1003).unwrap();
        apply_subscription(&db, &subscription("sub_old", "canceled"), "price_one", 1004).unwrap();
        let bound: String = db
            .query_row(
                "SELECT subscription FROM billing_accounts WHERE actor='alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bound, "sub_new");
        assert!(entitlement(&db, "alice", 1005).unwrap().active);
        assert!(!entitlement(&db, "bob", 1005).unwrap().active);
        assert!(
            apply_subscription(
                &db,
                &subscription("sub_second", "active"),
                "price_one",
                1006
            )
            .is_err()
        );
    }
    #[test]
    fn retired_subscription_preserves_checkout_until_its_own_session_is_reconciled() {
        let db = account();
        let first = uuid::Uuid::new_v4();
        db.execute("INSERT INTO billing_checkout(actor,attempt,created_at,session) VALUES('alice',?1,1000,'cs_one')",[first.to_string()]).unwrap();
        apply_subscription(&db, &subscription("sub_old", "active"), "price_one", 1000).unwrap();
        apply_subscription(&db, &subscription("sub_old", "canceled"), "price_one", 1001).unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM billing_checkout WHERE actor='alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let next = uuid::Uuid::new_v4();
        let mut calls = 0;
        checkout_with(&db,&test_config(),"alice",next,1002,|path,_,_| {
            calls+=1;
            if path=="checkout/sessions/cs_one" {let mut s=session("complete");s["subscription"]=json!("sub_old");return Ok(s);}
            if path.starts_with("subscriptions/"){return Ok(subscription("sub_old","canceled"));}
            if path.starts_with("prices/"){return Ok(json!({"active":true,"type":"recurring","recurring":{"usage_type":"licensed"},"tax_behavior":"exclusive"}));}
            let mut s=session("open");s["id"]=json!("cs_new");Ok(s)
        }).unwrap();
        assert_eq!(calls, 4);
        assert!(
            replace_checkout_intent(
                &db,
                "alice",
                &first.to_string(),
                "cs_one",
                uuid::Uuid::new_v4(),
                1003
            )
            .is_err()
        );
        apply_subscription(&db, &subscription("sub_old", "active"), "price_one", 1003).unwrap();
        assert!(!entitlement(&db, "alice", 1004).unwrap().active);
        let saved: String = db
            .query_row(
                "SELECT session FROM billing_checkout WHERE actor='alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(saved, "cs_new");
    }
    #[test]
    fn invoice_events_resolve_basil_subscription_without_trusting_payment_claim() {
        for kind in ["invoice.paid", "invoice.payment_failed"] {
            let event = json!({"type":kind,"data":{"object":{"parent":{"type":"subscription_details","subscription_details":{"subscription":"sub_one"}}}}});
            assert_eq!(
                subscription_for_event(&event).unwrap().as_deref(),
                Some("sub_one")
            );
        }
        assert!(subscription_for_event(&json!({"type":"invoice.paid","data":{"object":{"subscription":"sub_other","parent":{"subscription_details":{"subscription":"sub_one"}}}}})).is_err());
        assert!(
            subscription_for_event(
                &json!({"type":"invoice.paid","data":{"object":{"id":"in_standalone"}}})
            )
            .unwrap()
            .is_none()
        );
        let db = account();
        let mut current = subscription("sub_one", "active");
        current["latest_invoice"]["paid"] = json!(false);
        current["latest_invoice"]["status"] = json!("open");
        apply_subscription(&db, &current, "price_one", 1000).unwrap();
        assert!(!entitlement(&db, "alice", 1001).unwrap().active);
        apply_subscription(&db, &subscription("sub_one", "active"), "price_one", 1002).unwrap();
        assert!(entitlement(&db, "alice", 1003).unwrap().active);
    }
    #[test]
    fn paid_invoice_requires_explicit_zero_remaining_balance() {
        let db = account();
        for remaining in [Value::Null, json!(-1), json!(100), json!("0")] {
            let mut value = subscription("sub_one", "active");
            value["latest_invoice"]["amount_remaining"] = remaining;
            apply_subscription(&db, &value, "price_one", 1000).unwrap();
            assert!(!entitlement(&db, "alice", 1001).unwrap().active);
        }
        let mut value = subscription("sub_one", "active");
        value["latest_invoice"]
            .as_object_mut()
            .unwrap()
            .remove("amount_remaining");
        apply_subscription(&db, &value, "price_one", 1000).unwrap();
        assert!(!entitlement(&db, "alice", 1001).unwrap().active);
        value = subscription("sub_one", "active");
        value["latest_invoice"]["status"] = json!("open");
        apply_subscription(&db, &value, "price_one", 1000).unwrap();
        assert!(!entitlement(&db, "alice", 1001).unwrap().active);
        apply_subscription(&db, &subscription("sub_one", "active"), "price_one", 1000).unwrap();
        assert!(entitlement(&db, "alice", 1001).unwrap().active);
    }
    #[test]
    fn signatures_bind_exact_body_and_time() {
        let body = b"{\"id\":\"evt_test\"}";
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"whsec_test");
        let mut signed = b"1000.".to_vec();
        signed.extend_from_slice(body);
        let mac = ring::hmac::sign(&key, &signed)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let header = format!("t=1000,v1={mac}");
        assert!(verify_webhook("whsec_test", &header, body, 1001).is_ok());
        assert!(verify_webhook("whsec_test", &header, b"changed", 1001).is_err());
        assert!(verify_webhook("whsec_test", &header, body, 1301).is_err());
        assert!(verify_webhook("whsec_test", &format!("{header},t=1000"), body, 1001).is_err());
    }
    #[test]
    fn entitlement_requires_paid_exact_account_price_and_fresh_state() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db.execute("INSERT INTO billing_accounts(actor,customer) VALUES('alice','cus_alice'),('bob','cus_bob')",[]).unwrap();
        let mut value = json!({"id":"sub_one","customer":"cus_alice","status":"active","latest_invoice":{"status":"paid","amount_remaining":0},"items":{"data":[{"price":{"id":"price_one"},"quantity":1,"current_period_end":1000000}]}});
        apply_subscription(&db, &value, "price_one", 1000).unwrap();
        assert!(entitlement(&db, "alice", 1001).unwrap().active);
        assert!(!entitlement(&db, "bob", 1001).unwrap().active);
        assert!(!entitlement(&db, "alice", 87400).unwrap().active);
        value["latest_invoice"]["amount_remaining"] = json!(100);
        apply_subscription(&db, &value, "price_one", 1002).unwrap();
        assert!(!entitlement(&db, "alice", 1002).unwrap().active);
        value["id"] = json!("sub_foreign");
        assert!(apply_subscription(&db, &value, "price_one", 1003).is_err());
    }
}
