//! Optional strict RS256 bearer validation for the team API. Trust starts in a local
//! administrator-owned config, never in token headers or proxy-supplied identities.
use super::Role;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Url, blocking::Client};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectBinding {
    pub sub: String,
    pub role: Role,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    pub audience: String,
    pub bindings: Vec<SubjectBinding>,
    /// For example {"token_use":"access"} for a provider that distinguishes token types.
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
}
static CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

fn secure_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("OIDC endpoints require HTTPS without credentials or fragments");
    }
    Ok(url)
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).context("Read OIDC configuration")?;
        let mut bytes = Vec::new();
        file.take(131073).read_to_end(&mut bytes)?;
        if bytes.len() > 131072 {
            bail!("OIDC configuration too large");
        }
        let config: Self = serde_json::from_slice(&bytes).context("Invalid OIDC configuration")?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        let issuer = secure_url(&self.issuer)?;
        if issuer.query().is_some()
            || self.issuer.trim() != self.issuer
            || self.issuer.len() > 2048
            || self.audience.is_empty()
            || self.audience.len() > 2048
            || self.bindings.len() > 1000
        {
            bail!("Invalid OIDC issuer, audience or binding count");
        }
        let mut subjects = std::collections::BTreeSet::new();
        for binding in &self.bindings {
            if binding.sub.is_empty()
                || binding.sub.len() > 512
                || binding.sub.chars().any(char::is_control)
                || !subjects.insert(&binding.sub)
            {
                bail!("OIDC subjects must be nonempty, bounded and unique");
            }
        }
        if self.required_claims.len() > 16
            || self.required_claims.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 100
                    || value.len() > 2048
                    || ["iss", "aud", "exp", "nbf", "sub"].contains(&key.as_str())
            })
        {
            bail!("Invalid additional OIDC claim requirements");
        }
        Ok(())
    }
    fn binding(&self, sub: &str) -> Option<&SubjectBinding> {
        self.bindings.iter().find(|binding| binding.sub == sub)
    }
}
pub fn actor_id(issuer: &str, sub: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(issuer.as_bytes());
    hash.update([0]);
    hash.update(sub.as_bytes());
    format!("oidc:{:x}", hash.finalize())
}
/// Read current bindings on every operation. Deleting/invalidating the file fails closed.
pub fn actor_can_operate(actor: &str) -> bool {
    CONFIG_PATH
        .get()
        .and_then(|path| Config::load(path).ok())
        .is_some_and(|config| {
            config.bindings.iter().any(|binding| {
                matches!(binding.role, Role::Operator | Role::Admin)
                    && actor_id(&config.issuer, &binding.sub) == actor
            })
        })
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}
#[derive(Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: Option<String>,
    #[serde(rename = "x5t")]
    _thumbprint: Option<String>,
    #[serde(rename = "x5t#S256")]
    _sha256_thumbprint: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    nbf: Option<u64>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

pub struct Verifier {
    path: PathBuf,
    config: Config,
    keys: Vec<Jwk>,
    fetched: Option<Instant>,
    attempted: Option<Instant>,
    client: Client,
}
impl Verifier {
    pub fn from_environment() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("RELAYNE_TEAM_OIDC_CONFIG") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        let config = Config::load(&path)?;
        CONFIG_PATH
            .set(path.clone())
            .map_err(|_| anyhow::anyhow!("OIDC configuration already initialized"))?;
        Ok(Some(Self {
            path,
            config,
            keys: vec![],
            fetched: None,
            attempted: None,
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        }))
    }
    fn fetch<T: for<'de> Deserialize<'de>>(&self, url: Url) -> Result<T> {
        let response = self.client.get(url).send()?.error_for_status()?;
        if !response.status().is_success() {
            bail!("OIDC redirects are not accepted");
        }
        let mut bytes = Vec::new();
        response.take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            bail!("OIDC provider response exceeds limit");
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    fn refresh(&mut self) -> Result<()> {
        self.attempted = Some(Instant::now());
        let issuer = secure_url(&self.config.issuer)?;
        let discovery: Discovery = self.fetch(secure_url(&format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        ))?)?;
        if discovery.issuer != self.config.issuer {
            bail!("OIDC discovery issuer mismatch");
        }
        let jwks_url = secure_url(&discovery.jwks_uri)?;
        if issuer.origin() != jwks_url.origin() {
            bail!("OIDC JWKS must use the configured issuer origin");
        }
        let jwks: Jwks = self.fetch(jwks_url)?;
        if jwks.keys.is_empty() || jwks.keys.len() > 128 {
            bail!("Invalid OIDC key count");
        }
        let mut ids = std::collections::BTreeSet::new();
        for key in &jwks.keys {
            if let Some(kid) = &key.kid {
                if kid.is_empty() || kid.len() > 256 || !ids.insert(kid) {
                    bail!("Invalid/ambiguous OIDC key identifier");
                }
            }
        }
        self.keys = jwks.keys;
        self.fetched = Some(Instant::now());
        Ok(())
    }
    pub fn verify(&mut self, token: &str) -> Result<(String, Role)> {
        let config = Config::load(&self.path)?;
        if self.config != config {
            self.config = config;
            self.keys.clear();
            self.fetched = None;
            self.attempted = None;
        }
        let header = token_header(token)?;
        let stale = self
            .fetched
            .is_none_or(|time| time.elapsed() >= Duration::from_secs(300));
        let unknown = !self
            .keys
            .iter()
            .any(|key| key.kid.as_deref() == Some(&header.kid));
        if stale || unknown {
            if self
                .attempted
                .is_some_and(|time| time.elapsed() < Duration::from_secs(60))
            {
                bail!("OIDC keys unavailable; refresh throttled");
            }
            self.refresh()?;
        }
        verify_with_keys(
            &self.config,
            &self.keys,
            token,
            chrono::Utc::now().timestamp().try_into()?,
        )
    }
}

fn token_header(token: &str) -> Result<Header> {
    if token.len() > 16384
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        bail!("Malformed JWT");
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        bail!("Malformed JWT");
    }
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header.alg != "RS256"
        || header.kid.is_empty()
        || header.kid.len() > 256
        || header
            .typ
            .as_deref()
            .is_some_and(|typ| !["JWT", "at+jwt"].contains(&typ))
    {
        bail!("Unsupported JWT header");
    }
    Ok(header)
}
fn verify_with_keys(
    config: &Config,
    keys: &[Jwk],
    token: &str,
    now: u64,
) -> Result<(String, Role)> {
    let header = token_header(token)?;
    let key = keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(&header.kid))
        .context("Unknown JWT signing key")?;
    if key.kty != "RSA"
        || key.alg.as_deref().is_some_and(|alg| alg != "RS256")
        || key.usage.as_deref().is_some_and(|usage| usage != "sig")
        || key
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.iter().any(|op| op == "verify"))
    {
        bail!("Incompatible JWT signing key");
    }
    let n = URL_SAFE_NO_PAD.decode(&key.n)?;
    let e = URL_SAFE_NO_PAD.decode(&key.e)?;
    let (signed, signature) = token.rsplit_once('.').context("Malformed JWT")?;
    let signature = URL_SAFE_NO_PAD.decode(signature)?;
    ring::signature::RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    }
    .verify(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        signed.as_bytes(),
        &signature,
    )
    .map_err(|_| anyhow::anyhow!("Invalid JWT signature"))?;
    let payload = signed.split_once('.').context("Malformed JWT")?.1;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    let audience_ok = match &claims.aud {
        Audience::One(aud) => aud == &config.audience,
        Audience::Many(aud) => aud.iter().any(|aud| aud == &config.audience),
    };
    if claims.iss != config.issuer
        || !audience_ok
        || claims.exp <= now
        || claims.nbf.is_some_and(|nbf| nbf > now)
    {
        bail!("JWT issuer, audience or validity mismatch");
    }
    for (key, expected) in &config.required_claims {
        if claims.extra.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
            bail!("Required JWT claim mismatch");
        }
    }
    let binding = config
        .binding(&claims.sub)
        .context("OIDC subject has no explicit role binding")?;
    Ok((actor_id(&config.issuer, &claims.sub), binding.role.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Config, Vec<Jwk>, ring::signature::RsaKeyPair) {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/oidc-synthetic-key.json"))
                .unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(fixture["private_pkcs8"].as_str().unwrap())
            .unwrap();
        let key = ring::signature::RsaKeyPair::from_pkcs8(&der).unwrap();
        let jwk: Jwk = serde_json::from_value(json!({"kid":"test-key","kty":"RSA","n":fixture["n"],"e":fixture["e"],"alg":"RS256","use":"sig"})).unwrap();
        let config: Config = serde_json::from_value(json!({"issuer":"https://id.example/tenant","audience":"relayne-api","bindings":[{"sub":"known-user","role":"operator"}],"required_claims":{"token_use":"access"}})).unwrap();
        (config, vec![jwk], key)
    }
    fn claims() -> serde_json::Value {
        json!({"iss":"https://id.example/tenant","sub":"known-user","aud":"relayne-api","exp":2000,"nbf":900,"token_use":"access"})
    }
    fn signed(
        key: &ring::signature::RsaKeyPair,
        header: serde_json::Value,
        claims: serde_json::Value,
    ) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
    fn header() -> serde_json::Value {
        json!({"alg":"RS256","kid":"test-key","typ":"at+jwt"})
    }
    #[test]
    fn signed_bound_identity_and_exact_claims() {
        let (config, keys, key) = fixture();
        let token = signed(&key, header(), claims());
        let (actor, role) = verify_with_keys(&config, &keys, &token, 1000).unwrap();
        assert_eq!(actor, actor_id(&config.issuer, "known-user"));
        assert_eq!(role, Role::Operator);
        for (field, value) in [
            ("iss", json!("https://evil.example")),
            ("aud", json!("other-api")),
            ("sub", json!("unbound")),
            ("exp", json!(1000)),
            ("nbf", json!(1001)),
            ("token_use", json!("id")),
        ] {
            let mut bad = claims();
            bad[field] = value;
            assert!(
                verify_with_keys(&config, &keys, &signed(&key, header(), bad), 1000).is_err(),
                "{field}"
            );
        }
        let mut missing = claims();
        missing.as_object_mut().unwrap().remove("exp");
        assert!(verify_with_keys(&config, &keys, &signed(&key, header(), missing), 1000).is_err());
        let mut multi = claims();
        multi["aud"] = json!(["other", "relayne-api"]);
        assert!(verify_with_keys(&config, &keys, &signed(&key, header(), multi), 1000).is_ok());
    }
    #[test]
    fn algorithm_key_confusion_and_signature_tampering_fail_closed() {
        let (config, keys, key) = fixture();
        for alg in ["none", "HS256", "RS512"] {
            let mut h = header();
            h["alg"] = json!(alg);
            assert!(verify_with_keys(&config, &keys, &signed(&key, h, claims()), 1000).is_err());
        }
        let mut h = header();
        h["jku"] = json!("https://attacker.example/keys");
        assert!(verify_with_keys(&config, &keys, &signed(&key, h, claims()), 1000).is_err());
        let token = signed(&key, header(), claims());
        let (body, _) = token.rsplit_once('.').unwrap();
        assert!(
            verify_with_keys(
                &config,
                &keys,
                &format!("{body}.{}", URL_SAFE_NO_PAD.encode([0u8; 256])),
                1000
            )
            .is_err()
        );
        let mut wrong_key = keys.clone();
        wrong_key[0].kty = "oct".into();
        assert!(verify_with_keys(&config, &wrong_key, &token, 1000).is_err());
    }
    #[test]
    fn explicit_configuration_and_role_removal() {
        let (mut config, keys, key) = fixture();
        config.validate().unwrap();
        let token = signed(&key, header(), claims());
        config.bindings.clear();
        assert!(verify_with_keys(&config, &keys, &token, 1000).is_err());
        config.issuer = "http://id.example".into();
        assert!(config.validate().is_err());
        assert!(secure_url("https://user:password@id.example").is_err());
        assert_ne!(
            actor_id("https://one", "user"),
            actor_id("https://two", "user")
        );
        assert_ne!(
            actor_id("https://one", "user"),
            actor_id("https://one", "other")
        );
    }
}
