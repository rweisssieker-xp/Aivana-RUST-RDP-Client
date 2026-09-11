//! Native MS-TSGU transport. The published IronRDP gateway supports WebSocket /
//! HTTP Basic authentication and resource port 3389; unsupported variants fail closed.
use crate::models::ConnectionProfile;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GatewayOptions {
    pub enabled: bool,
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
        bail!("Host fehlt oder ist ungültig");
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
        bail!("Host muss ein DNS-Name oder eine IP-Adresse sein (ohne URL/Pfad/Port)");
    }
    if dns.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        bail!("Ungültige IP-Adresse");
    }
    Ok(())
}

pub fn validate_gateway(options: &GatewayOptions, target_port: u16) -> Result<()> {
    if !options.enabled {
        return Ok(());
    }
    validate_host(&options.host)?;
    if options.port == 0 {
        bail!("Gateway-Port muss zwischen 1 und 65535 liegen");
    }
    if options.host.contains(':') {
        bail!(
            "Diese RD-Gateway-Version unterstützt keine IPv6-Gateway-Adresse; bitte DNS-Namen verwenden"
        );
    }
    if target_port != 3389 {
        bail!("Diese RD-Gateway-Version unterstützt nur RDP-Zielport 3389");
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
        if user.is_empty() || password.is_empty() {
            bail!("RD Gateway benötigt Benutzername und Kennwort");
        }
        let target = ironrdp_mstsgu::GwConnectTarget {
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
            tokio::time::timeout(Duration::from_secs(30), ironrdp_mstsgu::GwClient::connect(&target, "Aivana" )).await
        }).context("RD-Gateway-Verbindungszeit überschritten")?
            .map_err(|_| anyhow::anyhow!("RD-Gateway-Verbindung fehlgeschlagen. Gateway-Zertifikat, WebSocket-Unterstützung und HTTP-Basic-Anmeldung prüfen; NTLM/MFA und Zustimmungsmeldungen werden von dieser Version nicht unterstützt."))?;
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
        assert!(validate_gateway(&options, 3390).is_err());
        assert!(validate_gateway(&GatewayOptions { port: 0, ..options }, 3389).is_err());
    }
}
