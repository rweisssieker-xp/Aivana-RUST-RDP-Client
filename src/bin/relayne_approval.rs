//! Offline signing tool. Never linked into the investigator or executor process.
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};
use uuid::Uuid;

const DOMAIN: &[u8] = b"relayne-investigator-response-a2-v1\n";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    domain_version: u32,
    tenant: String,
    case_id: String,
    case_version: i64,
    proposal_id: String,
    target_user_id: String,
    site: String,
    classification: String,
    action: String,
    parameters: Value,
    requested_actor: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
    policy_hash: String,
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut result)?;
    if result.len() as u64 > limit {
        bail!("Input exceeds size limit")
    }
    Ok(result)
}

fn decode(input: &Value, now: DateTime<Utc>) -> Result<(Grant, Vec<u8>)> {
    let input = input.get("result").unwrap_or(input);
    let encoded = input["challenge_base64"]
        .as_str()
        .context("challenge_base64 required")?;
    if encoded.len() > 16_384 {
        bail!("Challenge exceeds size limit")
    }
    let bytes = STANDARD
        .decode(encoded)
        .context("Invalid base64 challenge")?;
    let raw = bytes
        .strip_prefix(DOMAIN)
        .context("Unknown approval domain")?;
    let grant: Grant = serde_json::from_slice(raw).context("Invalid approval grant")?;
    if serde_json::to_vec(&grant)? != raw {
        bail!("Challenge is not canonical")
    }
    if let Some(displayed) = input.get("grant")
        && *displayed != serde_json::to_value(&grant)?
    {
        bail!("Displayed grant differs from signed challenge")
    }
    if grant.domain_version != 1
        || grant.action != "microsoft_graph.revoke_sign_in_sessions"
        || grant.parameters != json!({})
        || grant.case_version < 1
        || !["normal", "critical", "tier0"].contains(&grant.classification.as_str())
    {
        bail!("Unsupported response scope")
    }
    for id in [
        &grant.tenant,
        &grant.case_id,
        &grant.proposal_id,
        &grant.target_user_id,
        &grant.nonce,
    ] {
        Uuid::parse_str(id).context("Scope identifiers must be UUIDs")?;
    }
    if grant.site.trim().is_empty()
        || grant.site.len() > 128
        || grant.requested_actor.trim().is_empty()
        || grant.requested_actor.len() > 128
        || grant.policy_hash.len() != 64
        || !grant.policy_hash.bytes().all(|v| v.is_ascii_hexdigit())
    {
        bail!("Invalid scope or policy digest")
    }
    let issued = DateTime::parse_from_rfc3339(&grant.issued_at)?.with_timezone(&Utc);
    let expires = DateTime::parse_from_rfc3339(&grant.expires_at)?.with_timezone(&Utc);
    if issued > now || expires <= now || expires <= issued || (expires - issued).num_seconds() > 600
    {
        bail!("Approval is expired or outside its permitted time window")
    }
    Ok((grant, bytes))
}

fn key(path: &Path) -> Result<Ed25519KeyPair> {
    let mut bytes = read_bounded(path, 4096)?;
    let result = Ed25519KeyPair::from_pkcs8(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid Ed25519 PKCS8 private key"));
    bytes.fill(0);
    result
}

fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Output must be a new file")?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn sign(grant: &Grant, bytes: &[u8], key: &Ed25519KeyPair, actor: &str) -> Result<Value> {
    if actor.trim().is_empty()
        || actor.len() > 128
        || actor == grant.requested_actor
        || actor.chars().any(char::is_control)
    {
        bail!("Approval requires an independent signer identity")
    }
    Ok(json!({"actor":actor,"signature_base64":STANDARD.encode(key.sign(bytes).as_ref())}))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("public-key") if args.len() == 3 => {
            let key = key(Path::new(&args[1]))?;
            write_new(
                Path::new(&args[2]),
                &json!({"public_key_base64":STANDARD.encode(key.public_key().as_ref())}),
            )?;
        }
        Some("inspect") if args.len() == 2 => {
            let input: Value = serde_json::from_slice(&read_bounded(Path::new(&args[1]), 65_536)?)?;
            let (grant, _) = decode(&input, Utc::now())?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"grant":grant,"warning":"Signing approves exactly this action. Review its tenant, target, parameters and expiry before signing."})
                )?
            );
        }
        Some("sign") if args.len() == 6 && args[5] == "--reviewed" => {
            let input: Value = serde_json::from_slice(&read_bounded(Path::new(&args[2]), 65_536)?)?;
            let (grant, bytes) = decode(&input, Utc::now())?;
            let key = key(Path::new(&args[1]))?;
            write_new(Path::new(&args[4]), &sign(&grant, &bytes, &key, &args[3])?)?;
        }
        _ => bail!(
            "Usage: relayne_approval public-key <Ed25519-PKCS8.der> <new-public.json> | inspect <challenge.json> | sign <Ed25519-PKCS8.der> <challenge.json> <independent-actor> <new-approval.json> --reviewed"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{ED25519, UnparsedPublicKey},
    };

    fn challenge() -> Value {
        let now = Utc::now();
        let id = || Uuid::new_v4().to_string();
        let grant = Grant {
            domain_version: 1,
            tenant: id(),
            case_id: id(),
            case_version: 1,
            proposal_id: id(),
            target_user_id: id(),
            site: "LAB".into(),
            classification: "tier0".into(),
            action: "microsoft_graph.revoke_sign_in_sessions".into(),
            parameters: json!({}),
            requested_actor: "operator".into(),
            issued_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
            nonce: id(),
            policy_hash: "a".repeat(64),
        };
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(&grant).unwrap());
        json!({"challenge_base64":STANDARD.encode(bytes),"grant":grant})
    }

    #[test]
    fn exact_challenge_is_inspectable_and_independently_signed() {
        let value = challenge();
        let (grant, bytes) = decode(&value, Utc::now()).unwrap();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let approval = sign(&grant, &bytes, &key, "reviewer").unwrap();
        UnparsedPublicKey::new(&ED25519, key.public_key().as_ref())
            .verify(
                &bytes,
                &STANDARD
                    .decode(approval["signature_base64"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert!(sign(&grant, &bytes, &key, "operator").is_err());
    }

    #[test]
    fn misleading_display_unknown_domain_and_expiry_are_rejected() {
        let mut value = challenge();
        value["grant"]["site"] = json!("OTHER");
        assert!(decode(&value, Utc::now()).is_err());
        let mut value = challenge();
        value["challenge_base64"] = json!(STANDARD.encode(b"unknown-domain"));
        assert!(decode(&value, Utc::now()).is_err());
        assert!(decode(&challenge(), Utc::now() + chrono::Duration::hours(1)).is_err());
    }

    #[test]
    fn outputs_are_never_overwritten() {
        let path = std::env::temp_dir().join(format!("approval-output-{}.json", Uuid::new_v4()));
        write_new(&path, &json!({"public_key_base64":"synthetic"})).unwrap();
        assert!(write_new(&path, &json!({"replacement":true})).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
