//! Native MS-TSGU WebSocket transport with explicit Basic or NTLM extended authentication.
use crate::models::ConnectionProfile;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type InteractionBus = (
    std::sync::mpsc::SyncSender<ironrdp_mstsgu::GatewayInteraction>,
    std::sync::Mutex<std::sync::mpsc::Receiver<ironrdp_mstsgu::GatewayInteraction>>,
);
static INTERACTIONS: std::sync::OnceLock<InteractionBus> = std::sync::OnceLock::new();

/// Called only by the GUI. Headless consumers do not silently enable prompts.
pub fn register_interaction_ui() {
    INTERACTIONS.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(8);
        (sender, std::sync::Mutex::new(receiver))
    });
}
pub fn interaction_sender()
-> Option<std::sync::mpsc::SyncSender<ironrdp_mstsgu::GatewayInteraction>> {
    INTERACTIONS.get().map(|bus| bus.0.clone())
}
pub fn poll_interaction() -> Option<ironrdp_mstsgu::GatewayInteraction> {
    INTERACTIONS.get()?.1.lock().ok()?.try_recv().ok()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GatewayOptions {
    pub enabled: bool,
    /// NTLM extended authentication; false retains explicit HTTP Basic compatibility.
    pub ntlm: bool,
    /// Gateway-provider-issued PAA cookie. Requested per connection, never persisted.
    pub paa: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub use_profile_credentials: bool,
    pub credential_id: Option<uuid::Uuid>,
    #[serde(skip)]
    pub password: String,
}
impl Default for GatewayOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            ntlm: true,
            paa: false,
            host: String::new(),
            port: 443,
            username: String::new(),
            domain: String::new(),
            use_profile_credentials: true,
            credential_id: None,
            password: String::new(),
        }
    }
}
impl std::fmt::Debug for GatewayOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayOptions")
            .field("enabled", &self.enabled)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("use_profile_credentials", &self.use_profile_credentials)
            .field("password", &"[redacted]")
            .finish()
    }
}

pub fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.trim() != host || host.len() > 253 {
        bail!("Host is missing or invalid");
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let dns = host.strip_suffix('.').unwrap_or(host);
    if dns.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) {
        bail!("Host must be a DNS name or IP address (without URL, path, or port)");
    }
    if dns.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        bail!("Invalid IP address");
    }
    Ok(())
}

pub fn validate_gateway(options: &GatewayOptions, target_port: u16) -> Result<()> {
    if !options.enabled {
        return Ok(());
    }
    validate_host(&options.host)?;
    if options.port == 0 {
        bail!("Gateway port must be between 1 and 65535");
    }
    if options.host.contains(':') {
        bail!(
            "This RD Gateway version does not support an IPv6 gateway address; use a DNS name"
        );
    }
    if target_port == 0 {
        bail!("Destination port must be between 1 and 65535");
    }
    Ok(())
}

pub struct GatewayStream {
    client: ironrdp_mstsgu::GwClient,
    runtime: tokio::runtime::Runtime,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    local_addr: SocketAddr,
}
impl GatewayStream {
    /// `password` is ephemeral gateway credential input and is never serialized/logged.
    pub fn connect(
        profile: &ConnectionProfile,
        options: &GatewayOptions,
        password: &str,
    ) -> Result<(Self, SocketAddr)> {
        Self::connect_with_messages(profile, options, password, None)
    }
    pub fn connect_with_messages(
        profile: &ConnectionProfile,
        options: &GatewayOptions,
        password: &str,
        messages: Option<std::sync::mpsc::SyncSender<String>>,
    ) -> Result<(Self, SocketAddr)> {
        Self::connect_interactive(profile, options, password, messages, None)
    }
    pub fn connect_interactive(
        profile: &ConnectionProfile,
        options: &GatewayOptions,
        password: &str,
        messages: Option<std::sync::mpsc::SyncSender<String>>,
        interactions: Option<std::sync::mpsc::SyncSender<ironrdp_mstsgu::GatewayInteraction>>,
    ) -> Result<(Self, SocketAddr)> {
        validate_gateway(options, profile.port)?;
        validate_host(&profile.host)?;
        let (username, domain, password) = if options.use_profile_credentials {
            (
                profile.username.as_str(),
                profile.domain.as_str(),
                profile.password.as_str(),
            )
        } else {
            (
                options.username.as_str(),
                options.domain.as_str(),
                if password.is_empty() {
                    options.password.as_str()
                } else {
                    password
                },
            )
        };
        let user = if domain.is_empty() || username.contains('\\') || username.contains('@') {
            username.to_owned()
        } else {
            format!("{domain}\\{username}")
        };
        if !options.paa && (user.is_empty() || password.is_empty()) {
            bail!("RD Gateway requires a username and password");
        }
        let target = ironrdp_mstsgu::GwConnectTarget {
            ntlm: options.ntlm,
            paa: options.paa,
            interactions,
            target_port: profile.port,
            messages,
            gw_endpoint: format!("{}:{}", options.host, options.port),
            gw_user: user,
            gw_pass: password.to_owned(),
            server: profile.host.clone(),
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (client, local_addr) = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(120), ironrdp_mstsgu::GwClient::connect(&target, "Relayne" )).await
        }).context("RD Gateway connection timed out")?
            .map_err(|error| anyhow::anyhow!("RD Gateway connection failed ({error}). Verify the gateway certificate, WebSocket support, and authentication mode. Confirm the second factor for NTLM MFA; PAA requires a cookie issued by the gateway provider. No automatic retry."))?;
        Ok((
            Self {
                client,
                runtime,
                read_timeout: Some(Duration::from_secs(30)),
                write_timeout: Some(Duration::from_secs(30)),
                local_addr,
            },
            local_addr,
        ))
    }
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout = timeout;
        Ok(())
    }
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout = timeout;
        Ok(())
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}
impl Read for GatewayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.runtime.block_on(async {
            if let Some(timeout) = self.read_timeout {
                tokio::time::timeout(timeout, self.client.read(buf))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Gateway read timeout"))?
            } else {
                self.client.read(buf).await
            }
        })
    }
}
impl Write for GatewayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.runtime.block_on(async {
            if let Some(timeout) = self.write_timeout {
                tokio::time::timeout(timeout, self.client.write(buf))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Gateway write timeout"))?
            } else {
                self.client.write(buf).await
            }
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.runtime.block_on(self.client.flush())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_hosts() {
        for host in ["server", "server.example.com", "10.1.2.3", "::1"] {
            assert!(validate_host(host).is_ok());
        }
        for host in [
            "",
            "https://example.com",
            "host:3389",
            "bad host",
            "host/path",
            "-bad",
            "999.1.2.3",
            "host\r\nX",
        ] {
            assert!(validate_host(host).is_err());
        }
    }
    #[test]
    fn unsupported_gateway_targets_fail_before_connect() {
        let options = GatewayOptions {
            enabled: true,
            host: "gateway.example.com".into(),
            ..Default::default()
        };
        assert!(validate_gateway(&options, 3389).is_ok());
        assert!(validate_gateway(&options, 3390).is_ok());
        assert!(validate_gateway(&options, 0).is_err());
        assert!(validate_gateway(&GatewayOptions { port: 0, ..options }, 3389).is_err());
    }
}
