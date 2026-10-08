//! Explicit, foreground initiated team operations; bearer tokens remain in memory.
#[path = "team_login.rs"]
pub mod login;
use crate::helper_approval::{
    ActionApprovalV2, ActionOutcomeAckV2, ActionOutcomeEventV2, ConsumeActionApprovalV2,
    ConsumeReceiptV2, CreateActionApprovalV2, DecideActionApprovalV2,
};
use crate::repair_approval::{
    ConsumeReceipt, ConsumeRepairApproval, CreateRepairApproval, DecideRepairApproval,
    RepairApproval, RepairOutcomeAck, RepairOutcomeEvent,
};
use crate::team_server::{
    Audit, IssuedToken, RevokeRequest, SharedItem, Snapshot, TokenInfo, TokenRequest,
};
use anyhow::{Context, Result, bail};
use reqwest::{Url, blocking::Client};
use serde::{Serialize, de::DeserializeOwned};
use std::io::Read;
/// Proof that this client received and checked a consume response over its
/// authenticated team transport. A wire receipt alone cannot create this type.
#[derive(Clone)]
pub struct VerifiedConsumeV2 {
    receipt: ConsumeReceiptV2,
    endpoint: String,
}
impl VerifiedConsumeV2 {
    pub fn receipt(&self) -> &ConsumeReceiptV2 {
        &self.receipt
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}
#[derive(Clone)]
pub struct TeamClient {
    endpoint: String,
    token: String,
}
impl TeamClient {
    pub fn helper_capabilities(
        &self,
    ) -> Result<crate::team_server::helper_repair::HelperCapabilitiesV2> {
        self.request("/v2/helper-capabilities", None::<()>)
    }
    pub fn request_action_v2(&self, input: &CreateActionApprovalV2) -> Result<ActionApprovalV2> {
        self.request("/v2/helper-action-approvals", Some(input))
    }
    pub fn list_actions_v2(&self, offset: usize) -> Result<Vec<ActionApprovalV2>> {
        self.request(
            &format!("/v2/helper-action-approvals?limit=20&offset={offset}"),
            None::<()>,
        )
    }
    pub fn action_v2(&self, id: uuid::Uuid) -> Result<ActionApprovalV2> {
        self.request(&format!("/v2/helper-action-approvals/{id}"), None::<()>)
    }
    pub fn decide_action_v2(
        &self,
        id: uuid::Uuid,
        input: &DecideActionApprovalV2,
    ) -> Result<ActionApprovalV2> {
        self.request(
            &format!("/v2/helper-action-approvals/{id}/decision"),
            Some(input),
        )
    }
    pub fn consume_action_v2(
        &self,
        id: uuid::Uuid,
        input: &ConsumeActionApprovalV2,
    ) -> Result<VerifiedConsumeV2> {
        let capabilities = self.helper_capabilities()?;
        anyhow::ensure!(
            capabilities.authority_version == 2
                && capabilities.organization_sha256 == input.binding.organization_sha256
                && id != uuid::Uuid::nil(),
            "Team organization changed before consumption"
        );
        input.binding.validate(chrono::Utc::now())?;
        let receipt: ConsumeReceiptV2 = self.request(
            &format!("/v2/helper-action-approvals/{id}/consume"),
            Some(input),
        )?;
        anyhow::ensure!(
            receipt.approval_id == id
                && receipt.consume_id != uuid::Uuid::nil()
                && receipt.fingerprint == input.binding.fingerprint()?
                && receipt.organization_sha256 == capabilities.organization_sha256,
            "Authenticated consume response differs from the requested action"
        );
        Ok(VerifiedConsumeV2 {
            receipt,
            endpoint: self.endpoint.clone(),
        })
    }
    pub fn report_action_outcome_v2(
        &self,
        input: &ActionOutcomeEventV2,
    ) -> Result<ActionOutcomeAckV2> {
        self.request("/v2/helper-action-outcomes", Some(input))
    }
    pub fn request_repair(&self, input: &CreateRepairApproval) -> Result<RepairApproval> {
        self.request("/v1/repair-approvals", Some(input))
    }
    pub fn list_repairs(&self, offset: usize) -> Result<Vec<RepairApproval>> {
        self.request(
            &format!("/v1/repair-approvals?limit=20&offset={offset}"),
            None::<()>,
        )
    }
    pub fn decide_repair(
        &self,
        id: uuid::Uuid,
        input: &DecideRepairApproval,
    ) -> Result<RepairApproval> {
        self.request(&format!("/v1/repair-approvals/{id}/decision"), Some(input))
    }
    pub fn consume_repair(
        &self,
        id: uuid::Uuid,
        input: &ConsumeRepairApproval,
    ) -> Result<ConsumeReceipt> {
        self.request(&format!("/v1/repair-approvals/{id}/consume"), Some(input))
    }
    pub fn report_repair_outcome(&self, input: &RepairOutcomeEvent) -> Result<RepairOutcomeAck> {
        self.request("/v1/repair-outcomes", Some(input))
    }
    pub fn escalation(&self, action: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        match action {
            "config" => self.request("/v1/escalations/config", None::<()>),
            "list" => self.request("/v1/escalations", None::<()>),
            "enqueue" | "cancel" | "reconcile" | "retry" => {
                self.request(&format!("/v1/escalations/{action}"), Some(body))
            }
            _ => bail!("Unknown escalation action"),
        }
    }
    pub fn ticket_inbox(&self) -> Result<Vec<crate::ticket_intake::InboxItem>> {
        self.request("/v1/tickets/inbox", None::<()>)
    }
    pub fn billing(&self, action: &str, attempt: uuid::Uuid) -> Result<serde_json::Value> {
        match action {
            "checkout" => self.request(
                "/v1/billing/checkout",
                Some(serde_json::json!({"attempt":attempt})),
            ),
            "portal" => self.request("/v1/billing/portal", Some(serde_json::json!({}))),
            "refresh" => self.request("/v1/billing/refresh", Some(serde_json::json!({}))),
            "entitlement" => self.request("/v1/billing/entitlement", None::<()>),
            _ => bail!("Unknown billing action"),
        }
    }
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
        let limit = if path.starts_with("/v1/repair-") || path.starts_with("/v2/helper-") {
            256_000u64
        } else if path == "/v1/collaboration" {
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
