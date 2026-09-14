//! Public-client OAuth authorization code + PKCE. No browser is opened by this module.
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Url, blocking::Client};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
pub struct LoginOptions {
    pub issuer: String,
    pub client_id: String,
    pub scopes: String,
    /// Optional provider-specific `audience` authorization parameter (not universal OAuth).
    pub audience: String,
}
pub enum LoginEvent {
    OpenBrowser(String),
    Finished(Result<String, String>),
}
pub struct LoginFlow {
    pub events: mpsc::Receiver<LoginEvent>,
    cancelled: Arc<AtomicBool>,
}
impl Drop for LoginFlow {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

fn https_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        bail!("OAuth endpoints require HTTPS without credentials, query, or fragment");
    }
    Ok(url)
}
fn validate(options: &LoginOptions) -> Result<()> {
    https_url(&options.issuer)?;
    for value in [
        &options.issuer,
        &options.client_id,
        &options.scopes,
        &options.audience,
    ] {
        if value.len() > 2048 || value.chars().any(char::is_control) {
            bail!("OAuth input is invalid or too long");
        }
    }
    if options.client_id.trim().is_empty() || options.scopes.trim().is_empty() {
        bail!("A public client ID and API scopes are required");
    }
    Ok(())
}
pub fn start(options: LoginOptions) -> Result<LoginFlow> {
    validate(&options)?;
    let (sender, events) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = cancelled.clone();
    std::thread::spawn(move || {
        let result = run(options, &sender, &stop).map_err(|error| error.to_string());
        if !stop.load(Ordering::Relaxed) {
            let _ = sender.send(LoginEvent::Finished(result));
        }
    });
    Ok(LoginFlow { events, cancelled })
}
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    code_challenge_methods_supported: Option<Vec<String>>,
    authorization_response_iss_parameter_supported: Option<bool>,
}
fn endpoint(discovery: &Discovery, issuer: &str, raw: &str) -> Result<Url> {
    if discovery.issuer != issuer {
        bail!("OIDC discovery reports a different issuer");
    }
    let issuer = https_url(issuer)?;
    let endpoint = https_url(raw)?;
    if endpoint.origin() != issuer.origin() {
        bail!("OAuth endpoints must belong to the configured issuer origin");
    }
    Ok(endpoint)
}
fn read_json<T: for<'de> Deserialize<'de>>(response: reqwest::blocking::Response) -> Result<T> {
    if !response.status().is_success() {
        bail!(
            "OAuth provider rejected the request (HTTP {})",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    response.take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        bail!("OAuth response exceeds the size limit");
    }
    serde_json::from_slice(&bytes).context("OAuth response has an invalid format")
}
fn random_secret() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Secure random value is unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn run(
    options: LoginOptions,
    sender: &mpsc::Sender<LoginEvent>,
    cancelled: &AtomicBool,
) -> Result<String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let discovery: Discovery = read_json(
        client
            .get(format!(
                "{}/.well-known/openid-configuration",
                options.issuer.trim_end_matches('/')
            ))
            .send()
            .context("OIDC discovery is unreachable")?,
    )?;
    let mut authorization = endpoint(
        &discovery,
        &options.issuer,
        &discovery.authorization_endpoint,
    )?;
    let token_endpoint = endpoint(&discovery, &options.issuer, &discovery.token_endpoint)?;
    if discovery
        .code_challenge_methods_supported
        .as_ref()
        .is_some_and(|methods| !methods.iter().any(|method| method == "S256"))
    {
        bail!("OAuth provider does not support PKCE S256");
    }
    if cancelled.load(Ordering::Relaxed) {
        bail!("Sign-in canceled");
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = tiny_http::Server::from_listener(listener, None)
        .map_err(|_| anyhow::anyhow!("Local OAuth callback is unavailable"))?;
    let redirect = format!("http://{address}/oauth/callback");
    let state = random_secret()?;
    let verifier = random_secret()?;
    authorization.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", options.client_id.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("scope", options.scopes.as_str()),
        ("state", state.as_str()),
        ("code_challenge", challenge(&verifier).as_str()),
        ("code_challenge_method", "S256"),
        ("response_mode", "query"),
    ]);
    if !options.audience.is_empty() {
        authorization
            .query_pairs_mut()
            .append_pair("audience", &options.audience);
    }
    sender
        .send(LoginEvent::OpenBrowser(authorization.to_string()))
        .map_err(|_| anyhow::anyhow!("Sign-in window closed"))?;
    let code = wait_callback(
        &server,
        &address.to_string(),
        &state,
        &options.issuer,
        discovery
            .authorization_response_iss_parameter_supported
            .unwrap_or(false),
        cancelled,
        Duration::from_secs(120),
    )?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("Sign-in canceled");
    }
    let response = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", options.client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .context("OAuth token endpoint is unreachable")?;
    let token: TokenResponse = read_json(response)?;
    access_token(token)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
}
fn access_token(token: TokenResponse) -> Result<String> {
    if !token.token_type.eq_ignore_ascii_case("bearer") || token.expires_in == Some(0) {
        bail!("OAuth provider did not return a valid bearer access token");
    }
    let value = token.access_token;
    if value.len() > 16384
        || value.split('.').count() != 3
        || value.split('.').any(str::is_empty)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        bail!(
            "The team server requires a JWT access token for its API. ID tokens are not used as a substitute."
        );
    }
    Ok(value)
}
enum Callback {
    Code(String),
    ProviderError,
}
fn parse_callback(raw: &str, state: &str, issuer: &str, require_issuer: bool) -> Result<Callback> {
    if raw.len() > 8192 || !raw.starts_with("/oauth/callback?") {
        bail!("Invalid OAuth callback");
    }
    let url = Url::parse(&format!("http://127.0.0.1{raw}"))?;
    if url.path() != "/oauth/callback" || url.fragment().is_some() {
        bail!("Invalid OAuth callback");
    }
    let mut params = std::collections::BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            bail!("Duplicate OAuth response parameters");
        }
    }
    if params.get("state").map(String::as_str) != Some(state) {
        bail!("OAuth state does not match");
    }
    if (require_issuer && !params.contains_key("iss"))
        || params.get("iss").is_some_and(|value| value != issuer)
    {
        bail!("OAuth response issuer does not match");
    }
    if params.contains_key("error") {
        if params.contains_key("code") {
            bail!("Ambiguous OAuth response");
        }
        return Ok(Callback::ProviderError);
    }
    let code = params.remove("code").context("OAuth code is missing")?;
    if code.is_empty() || code.len() > 4096 || code.chars().any(char::is_control) {
        bail!("OAuth code is invalid");
    }
    Ok(Callback::Code(code))
}
fn wait_callback(
    server: &tiny_http::Server,
    authority: &str,
    state: &str,
    issuer: &str,
    require_issuer: bool,
    cancelled: &AtomicBool,
    timeout: Duration,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let mut invalid = 0;
    while Instant::now() < deadline {
        if cancelled.load(Ordering::Relaxed) {
            bail!("Sign-in canceled");
        }
        let Some(request) = server.recv_timeout(Duration::from_millis(100))? else {
            continue;
        };
        let hosts: Vec<_> = request
            .headers()
            .iter()
            .filter(|header| header.field.equiv("Host"))
            .collect();
        let response = if request.method() == &tiny_http::Method::Get
            && hosts.len() == 1
            && hosts[0].value.as_str() == authority
        {
            parse_callback(request.url(), state, issuer, require_issuer)
        } else {
            Err(anyhow::anyhow!("Invalid OAuth callback request"))
        };
        let accepted = response.is_ok();
        let body = if accepted {
            "Sign-in response received. Return to Relayne."
        } else {
            "This sign-in response was rejected."
        };
        let answer = tiny_http::Response::from_string(body)
            .with_status_code(if accepted { 200 } else { 400 })
            .with_header(tiny_http::Header::from_bytes("Cache-Control", "no-store").unwrap())
            .with_header(tiny_http::Header::from_bytes("Referrer-Policy", "no-referrer").unwrap())
            .with_header(
                tiny_http::Header::from_bytes(
                    "Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'",
                )
                .unwrap(),
            );
        let _ = request.respond(answer);
        match response {
            Ok(Callback::Code(code)) => return Ok(code),
            Ok(Callback::ProviderError) => {
                bail!("Provider sign-in was denied or canceled")
            }
            Err(_) => {
                invalid += 1;
                if invalid >= 32 {
                    bail!("Too many invalid OAuth callbacks");
                }
            }
        }
    }
    bail!("Sign-in timed out after 120 seconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pkce_rfc7636_vector() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let one = random_secret().unwrap();
        assert_eq!(one.len(), 43);
        assert_ne!(one, random_secret().unwrap());
    }
    #[test]
    fn callback_state_duplicates_issuer_and_error_are_checked() {
        for query in [
            "state=wrong&code=x",
            "state=s&state=s&code=x",
            "state=s&code=x&iss=https%3A%2F%2Fevil.example",
            "state=s&code=x&error=denied",
        ] {
            assert!(
                parse_callback(
                    &format!("/oauth/callback?{query}"),
                    "s",
                    "https://id.example",
                    false
                )
                .is_err()
            );
        }
        assert!(
            parse_callback(
                "/oauth/callback?state=s&code=x",
                "s",
                "https://id.example",
                true
            )
            .is_err()
        );
        assert!(matches!(
            parse_callback(
                "/oauth/callback?state=s&error=access_denied",
                "s",
                "https://id.example",
                false
            )
            .unwrap(),
            Callback::ProviderError
        ));
        assert!(
            serde_json::from_str::<TokenResponse>(r#"{"id_token":"a.b.c","token_type":"Bearer"}"#)
                .is_err()
        );
        assert!(
            access_token(TokenResponse {
                access_token: "opaque-token".into(),
                token_type: "Bearer".into(),
                expires_in: Some(3600)
            })
            .is_err()
        );
        assert!(
            access_token(TokenResponse {
                access_token: "a.b.c".into(),
                token_type: "Basic".into(),
                expires_in: Some(3600)
            })
            .is_err()
        );
        assert!(https_url("http://identity.example").is_err());
        let discovery = Discovery {
            issuer: "https://identity.example".into(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            code_challenge_methods_supported: None,
            authorization_response_iss_parameter_supported: None,
        };
        assert!(
            endpoint(
                &discovery,
                "https://identity.example",
                "https://other.example/token"
            )
            .is_err()
        );
    }
    #[test]
    fn ephemeral_loopback_accepts_valid_callback_and_closes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        let worker = std::thread::spawn(move || {
            wait_callback(
                &server,
                &address.to_string(),
                "test-state",
                "https://id.example",
                false,
                &AtomicBool::new(false),
                Duration::from_secs(3),
            )
            .unwrap()
        });
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!(
                    "http://{address}/oauth/callback?state=wrong&code=bad"
                ))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            400
        );
        assert_eq!(
            client
                .get(format!(
                    "http://{address}/oauth/callback?state=test-state&code=good"
                ))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            200
        );
        assert_eq!(worker.join().unwrap(), "good");
    }
    #[test]
    fn callback_cancel_and_deadline_fail_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        assert!(
            wait_callback(
                &server,
                &address.to_string(),
                "state",
                "https://id.example",
                false,
                &AtomicBool::new(true),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            wait_callback(
                &server,
                &address.to_string(),
                "state",
                "https://id.example",
                false,
                &AtomicBool::new(false),
                Duration::ZERO
            )
            .is_err()
        );
    }
}
