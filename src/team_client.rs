//! Explicit, foreground initiated team operations; bearer tokens remain in memory.
#[path = "team_login.rs"]
pub mod login;
use crate::team_server::{
    Audit, IssuedToken, RevokeRequest, SharedItem, Snapshot, TokenInfo, TokenRequest,
};
use anyhow::{Context, Result, bail};
use reqwest::{Url, blocking::Client};
use serde::{Serialize, de::DeserializeOwned};
use std::io::Read;
#[derive(Clone)]
pub struct TeamClient {
    endpoint: String,
    token: String,
}
impl TeamClient {
    pub fn new(endpoint: &str, token: &str) -> Result<Self> {
        let url = Url::parse(endpoint.trim()).context("Invalid team URL")?;
        let local = matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        );
        if url.scheme() != "https" && !(url.scheme() == "http" && local) {
            bail!("Remote team servers require HTTPS")
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            bail!("Use a server origin without credentials, path, query or fragment")
        }
        let token = token.trim();
        let legacy = token.len() == 64 && token.bytes().all(|c| c.is_ascii_hexdigit());
        let jwt = token.len() <= 16384
            && token.split('.').count() == 3
            && token.split('.').all(|part| !part.is_empty())
            && token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c));
        if !legacy && !jwt {
            bail!("Enter a team bearer token or a signed JWT for this team server")
        }
        Ok(Self {
            endpoint: endpoint.trim().trim_end_matches('/').to_owned(),
            token: token.trim().to_owned(),
        })
    }
    fn request<T: DeserializeOwned>(
        &self,
        path: &str,
        payload: Option<impl Serialize>,
    ) -> Result<T> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let url = format!("{}{path}", self.endpoint);
        let request = match payload {
            Some(value) => client.post(url).json(&value),
            None => client.get(url),
        };
        let response = request
            .bearer_auth(&self.token)
            .send()
            .context("Team server unavailable")?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "Team API {}: {}",
                status.as_u16(),
                match status.as_u16() {
                    401 => "token missing, expired, revoked or identity not authorized",
                    403 => "server role does not permit this action",
                    409 => "revision conflict or protected operation; reload",
                    400 => "invalid request",
                    _ => "request failed",
                }
            )
        }
        let mut bytes = Vec::new();
        let limit = if path == "/v1/collaboration" {
            4_000_000u64
        } else {
            64_000_000u64
        };
        std::io::Read::take(response, limit + 1)
            .read_to_end(&mut bytes)
            .context("Read team response")?;
        if bytes.len() as u64 > limit {
            bail!("Team response exceeds limit")
        }
        serde_json::from_slice(&bytes).context("Invalid team response")
    }
    pub fn collaborate(
        &self,
        command: &crate::team_server::collaboration_session::Command,
    ) -> Result<crate::team_server::collaboration_session::Reply> {
        self.request("/v1/collaboration", Some(command))
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        self.request("/v1/state", None::<()>)
    }
    pub fn save(&self, item: &SharedItem) -> Result<SharedItem> {
        self.request("/v1/items", Some(item))
    }
    pub fn issue(&self, input: &TokenRequest) -> Result<IssuedToken> {
        self.request("/v1/tokens", Some(input))
    }
    pub fn revoke(&self, id: uuid::Uuid) -> Result<serde_json::Value> {
        self.request("/v1/revoke", Some(RevokeRequest { id }))
    }
    pub fn audit(&self) -> Result<Vec<Audit>> {
        self.request("/v1/audit", None::<()>)
    }
    pub fn tokens(&self) -> Result<Vec<TokenInfo>> {
        self.request("/v1/tokens", None::<()>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bearer_requests_do_not_follow_redirects() {
        let destination = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let redirect = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", redirect.server_addr());
        let location = format!("http://{}/v1/state", destination.server_addr());
        let worker = std::thread::spawn(move || {
            let request = redirect
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .unwrap();
            request
                .respond(
                    tiny_http::Response::empty(302)
                        .with_header(tiny_http::Header::from_bytes("Location", location).unwrap()),
                )
                .unwrap();
        });
        let client = TeamClient::new(&origin, &"a".repeat(64)).unwrap();
        assert!(client.snapshot().unwrap_err().to_string().contains("302"));
        worker.join().unwrap();
        assert!(
            destination
                .recv_timeout(std::time::Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn rejects_cleartext_remote_origins_and_embedded_credentials() {
        let token = "a".repeat(64);
        assert!(TeamClient::new("http://127.0.0.1:47831", &token).is_ok());
        assert!(TeamClient::new("https://team.example", &token).is_ok());
        for url in [
            "http://team.example",
            "https://user:pass@team.example",
            "https://team.example/api",
            "https://team.example/?token=x",
            "https://team.example/#x",
            "file:///tmp/a",
        ] {
            assert!(TeamClient::new(url, &token).is_err(), "{url}");
        }
        assert!(TeamClient::new("https://team.example", "short").is_err());
    }
}
