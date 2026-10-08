//! Reviewed, exact system identities. These are declarations, not live access grants.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::net::IpAddr;
use uuid::Uuid;

use super::case::{CaseEdit, HelperCase};
use crate::{mission::Target, models::ConnectionProfile};

pub type Digest = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEngine {
    Postgres,
    SqlServer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPurpose {
    Read,
    Diagnose,
    ControlledChange,
}

/// Metadata only. A resolver must independently verify the reference and exact context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialScope {
    pub reference: Uuid,
    pub purpose: CredentialPurpose,
    pub generation: u64,
    pub principal: String,
    pub context: String,
    /// SHA-256 of the exact resource identity without credential metadata.
    pub context_digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundScope {
    Windows {
        target: Target,
        credential: Option<CredentialScope>,
    },
    /// WSMan endpoint reviewed separately from the saved RDP profile port.
    WindowsWinRm {
        target: Target,
        winrm_port: u16,
        identity: String,
        credential: Option<CredentialScope>,
    },
    Linux {
        target: Target,
        credential: Option<CredentialScope>,
    },
    Database {
        target: Target,
        engine: DatabaseEngine,
        port: u16,
        database: String,
        schema: Option<String>,
        object: Option<String>,
        credential: Option<CredentialScope>,
    },
    Http {
        target: Target,
        port: u16,
        tls: bool,
        path: String,
    },
    Docker {
        daemon_context: String,
        container_id: String,
        credential: Option<CredentialScope>,
    },
    Kubernetes {
        context: String,
        cluster_fingerprint: String,
        namespace: String,
        resource_kind: String,
        resource_name: String,
        credential: Option<CredentialScope>,
    },
    AzureVm {
        tenant: String,
        subscription: String,
        resource_id: String,
        credential: Option<CredentialScope>,
    },
    AwsEc2 {
        account: String,
        region: String,
        instance_id: String,
        credential: Option<CredentialScope>,
    },
}

fn field(s: &str) -> Result<()> {
    ensure!(
        !s.trim().is_empty() && s.len() <= 512 && !s.chars().any(char::is_control),
        "Invalid scope identifier"
    );
    Ok(())
}
fn credential(c: &Option<CredentialScope>) -> Result<()> {
    if let Some(c) = c {
        ensure!(
            !c.reference.is_nil() && c.generation > 0,
            "Invalid credential reference/generation"
        );
        field(&c.principal)?;
        field(&c.context)?;
    }
    Ok(())
}
fn target(t: &Target, protocol: Option<&str>) -> Result<()> {
    ensure!(
        !t.profile_id.is_nil() && t.port > 0,
        "Invalid saved profile target"
    );
    for s in [&t.host, &t.protocol, &t.username] {
        field(s)?;
    }
    for s in [&t.domain, &t.route] {
        ensure!(
            s.len() <= 512 && !s.chars().any(char::is_control),
            "Invalid target identity"
        );
    }
    ensure!(
        matches!(t.protocol.as_str(), "RDP" | "SSH" | "VNC"),
        "Unsupported target protocol"
    );
    if let Some(protocol) = protocol {
        ensure!(t.protocol == protocol, "Scope/profile protocol mismatch");
    }
    Ok(())
}

/// Build the only URL that a reviewed HTTP scope may contact. Parsing both the
/// isolated authority and the final URL prevents userinfo or path syntax from
/// silently changing the destination.
pub(crate) fn reviewed_http_url(
    target: &Target,
    port: u16,
    tls: bool,
    path: &str,
) -> Result<reqwest::Url> {
    ensure!(
        port > 0 && !target.host.is_empty(),
        "Invalid HTTP authority"
    );
    ensure!(
        path.starts_with('/')
            && path.len() <= 512
            && path
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'\\' && b != b'#'),
        "Invalid HTTP path"
    );
    let host = target.host.as_str();
    ensure!(
        !host.chars().any(|c| c.is_control() || c.is_whitespace())
            && !host
                .chars()
                .any(|c| matches!(c, '@' | '/' | '?' | '#' | '\\' | '%')),
        "Invalid HTTP host"
    );
    let authority = if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        match ip {
            IpAddr::V4(_) => ip.to_string(),
            IpAddr::V6(_) => format!("[{ip}]"),
        }
    } else {
        ensure!(
            !host.chars().any(|c| matches!(c, '[' | ']' | ':')),
            "Invalid HTTP host"
        );
        host.to_owned()
    };
    let scheme = if tls { "https" } else { "http" };
    let isolated = reqwest::Url::parse(&format!("{scheme}://{authority}/"))?;
    let canonical = isolated
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing HTTP host"))?;
    if host.is_ascii() && !host.contains(':') {
        ensure!(
            canonical.eq_ignore_ascii_case(host),
            "HTTP host was reinterpreted"
        );
    }
    ensure!(
        canonical.split('.').all(|label| !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            || canonical.trim_matches(['[', ']']).parse::<IpAddr>().is_ok(),
        "Invalid DNS name or IP"
    );
    let url = reqwest::Url::parse(&format!("{scheme}://{authority}:{port}{path}"))?;
    let parsed_path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    ensure!(
        url.scheme() == scheme
            && url.host_str() == Some(canonical)
            && url.port_or_known_default() == Some(port)
            && parsed_path == path
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "HTTP URL differs from reviewed endpoint"
    );
    Ok(url)
}

fn valid_aws_region(region: &str) -> bool {
    let parts: Vec<_> = region.split('-').collect();
    let number =
        |s: &str| !s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit());
    let geography = |s: &str| {
        matches!(
            s,
            "north"
                | "south"
                | "east"
                | "west"
                | "central"
                | "northeast"
                | "northwest"
                | "southeast"
                | "southwest"
        )
    };
    match parts.as_slice() {
        [partition, area, index] => {
            matches!(
                *partition,
                "af" | "ap" | "ca" | "cn" | "eu" | "il" | "me" | "mx" | "sa" | "us"
            ) && geography(area)
                && number(index)
        }
        [
            "us",
            partition @ ("gov" | "iso" | "isob" | "isof"),
            area,
            index,
        ] => !partition.is_empty() && geography(area) && number(index),
        ["eu", "isoe", area, index] => geography(area) && number(index),
        _ => false,
    }
}

impl BoundScope {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Windows {
                target: t,
                credential: c,
            } => {
                target(t, Some("RDP"))?;
                credential(c)?;
            }
            Self::WindowsWinRm {
                target: t,
                winrm_port,
                identity,
                credential: c,
            } => {
                target(t, Some("RDP"))?;
                ensure!(matches!(winrm_port, 5985 | 5986), "Unsupported WSMan port");
                ensure!(c.is_none(), "WinRM uses current Windows identity");
                field(identity)?;
                ensure!(
                    t.route.is_empty(),
                    "WinRM collector requires a direct reviewed endpoint"
                );
                ensure!(
                    t.host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')),
                    "Invalid WinRM host"
                );
            }
            Self::Linux {
                target: t,
                credential: c,
            } => {
                target(t, Some("SSH"))?;
                credential(c)?;
            }
            Self::Database {
                target: t,
                port,
                database,
                schema,
                object,
                credential: c,
                ..
            } => {
                target(t, None)?;
                ensure!(
                    matches!(t.protocol.as_str(), "RDP" | "SSH") && *port > 0,
                    "Invalid database route/port"
                );
                field(database)?;
                if let Some(s) = schema {
                    field(s)?;
                }
                if let Some(s) = object {
                    field(s)?;
                }
                credential(c)?;
            }
            Self::Http {
                target: t,
                port,
                tls,
                path,
            } => {
                target(t, None)?;
                ensure!(
                    matches!(t.protocol.as_str(), "RDP" | "SSH"),
                    "HTTP scope requires a supported management profile"
                );
                ensure!(
                    *port > 0
                        && path.starts_with('/')
                        && path.len() <= 512
                        && !path.chars().any(char::is_control),
                    "Invalid HTTP port/path"
                );
                reviewed_http_url(t, *port, *tls, path)?;
            }
            Self::Docker {
                daemon_context,
                container_id,
                credential: c,
            } => {
                field(daemon_context)?;
                field(container_id)?;
                credential(c)?;
            }
            Self::Kubernetes {
                context,
                cluster_fingerprint,
                namespace,
                resource_kind,
                resource_name,
                credential: c,
            } => {
                for s in [
                    context,
                    cluster_fingerprint,
                    namespace,
                    resource_kind,
                    resource_name,
                ] {
                    field(s)?;
                }
                credential(c)?;
            }
            Self::AzureVm {
                tenant,
                subscription,
                resource_id,
                credential: c,
            } => {
                ensure!(
                    Uuid::parse_str(tenant).is_ok() && Uuid::parse_str(subscription).is_ok(),
                    "Invalid Azure tenant/subscription"
                );
                field(resource_id)?;
                let parts: Vec<_> = resource_id.split('/').collect();
                ensure!(
                    parts.len() == 9
                        && parts[0].is_empty()
                        && parts[1] == "subscriptions"
                        && parts[2] == subscription
                        && parts[3] == "resourceGroups"
                        && !parts[4].is_empty()
                        && parts[5] == "providers"
                        && parts[6] == "Microsoft.Compute"
                        && parts[7] == "virtualMachines"
                        && !parts[8].is_empty(),
                    "Invalid Azure VM resource ID"
                );
                ensure!(
                    [parts[4], parts[8]].iter().all(|part| part.len() <= 90
                        && part.bytes().all(|b| b.is_ascii_alphanumeric()
                            || matches!(b, b'-' | b'_' | b'.' | b'(' | b')'))),
                    "Invalid Azure VM path segment"
                );
                credential(c)?;
            }
            Self::AwsEc2 {
                account,
                region,
                instance_id,
                credential: c,
            } => {
                ensure!(
                    account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()),
                    "Invalid AWS account"
                );
                ensure!(
                    region.len() <= 32 && valid_aws_region(region),
                    "Invalid AWS region"
                );
                ensure!(
                    instance_id.starts_with("i-")
                        && matches!(instance_id.len(), 10 | 19)
                        && instance_id[2..].bytes().all(|b| b.is_ascii_hexdigit()),
                    "Invalid EC2 instance ID"
                );
                credential(c)?;
            }
        }
        if let Some(c) = self.credential() {
            ensure!(
                c.context_digest == self.unchecked_resource_digest()?,
                "Credential context does not match exact resource identity"
            );
        }
        Ok(())
    }

    pub fn credential(&self) -> Option<&CredentialScope> {
        match self {
            Self::Windows { credential, .. }
            | Self::WindowsWinRm { credential, .. }
            | Self::Linux { credential, .. }
            | Self::Database { credential, .. }
            | Self::Docker { credential, .. }
            | Self::Kubernetes { credential, .. }
            | Self::AzureVm { credential, .. }
            | Self::AwsEc2 { credential, .. } => credential.as_ref(),
            Self::Http { .. } => None,
        }
    }

    /// Stamp a newly reviewed credential reference with this exact resource context.
    /// Persisted scopes are validated, never silently restamped on load.
    pub fn bind_credential_context(mut self) -> Result<Self> {
        let digest = self.unchecked_resource_digest()?;
        match &mut self {
            Self::Windows { credential, .. }
            | Self::WindowsWinRm { credential, .. }
            | Self::Linux { credential, .. }
            | Self::Database { credential, .. }
            | Self::Docker { credential, .. }
            | Self::Kubernetes { credential, .. }
            | Self::AzureVm { credential, .. }
            | Self::AwsEc2 { credential, .. } => {
                if let Some(credential) = credential {
                    credential.context_digest = digest;
                }
            }
            Self::Http { .. } => {}
        }
        self.validate()?;
        Ok(self)
    }

    pub fn target(&self) -> Option<&Target> {
        match self {
            Self::Windows { target, .. }
            | Self::WindowsWinRm { target, .. }
            | Self::Linux { target, .. }
            | Self::Database { target, .. }
            | Self::Http { target, .. } => Some(target),
            _ => None,
        }
    }

    pub fn matches_profile(&self, profile: &ConnectionProfile) -> bool {
        self.validate().is_ok() && self.target().is_some_and(|t| t.matches(profile))
    }

    fn identity_value(&self, include_credential: bool) -> Result<serde_json::Value> {
        // Exclude display name and profile options. Include the full reviewed route and
        // every scoped resource and credential metadata field via the tagged variant.
        let mut value = serde_json::to_value(self)?;
        if let Some(target) = value
            .get_mut("target")
            .and_then(serde_json::Value::as_object_mut)
        {
            target.remove("name");
        }
        if !include_credential {
            value.as_object_mut().unwrap().remove("credential");
        }
        Ok(value)
    }

    /// Exact resource context for a credential binding; excludes credentials to avoid
    /// a circular digest. Task 5 can bind persisted references to this value.
    pub fn resource_digest(&self) -> Result<Digest> {
        self.validate()?;
        self.unchecked_resource_digest()
    }

    fn unchecked_resource_digest(&self) -> Result<Digest> {
        hash(
            b"relayne-helper-resource-v1\0",
            &self.identity_value(false)?,
        )
    }

    /// Full reviewed identity, including the purpose-specific credential metadata.
    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        hash(b"relayne-helper-scope-v1\0", &self.identity_value(true)?)
    }
    /// Purpose-specific reviewed credential metadata, or a domain-separated absent marker.
    pub fn credential_scope_digest(&self) -> Result<Digest> {
        self.validate()?;
        hash(
            b"relayne-helper-credential-scope-v1\0",
            &serde_json::to_value(self.credential())?,
        )
    }
}

/// The OS process token, never a saved RDP username or environment variable.
pub fn current_windows_identity() -> Result<String> {
    #[cfg(windows)]
    {
        #[link(name = "secur32")]
        unsafe extern "system" {
            fn GetUserNameExW(format: u32, buffer: *mut u16, size: *mut u32) -> u8;
        }
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        ensure!(
            unsafe { GetUserNameExW(2, buffer.as_mut_ptr(), &mut size) } != 0
                && size > 0
                && (size as usize) < buffer.len(),
            "Windows identity unavailable"
        );
        Ok(String::from_utf16(&buffer[..size as usize])?)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("WinRM requires Windows")
    }
}

fn hash(domain: &[u8], value: &serde_json::Value) -> Result<Digest> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value)?);
    Ok(format!("{:x}", hash.finalize()))
}

pub fn review_scopes(case: &mut HelperCase, scopes: Vec<BoundScope>) -> Result<()> {
    case.revise(case.revision(), CaseEdit::Scopes(scopes))?;
    Ok(())
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
