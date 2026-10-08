//! Immutable per-capture Kubernetes transport. Kubeconfig supplies endpoint/CA only;
//! authentication comes from the exact current scoped vault record.
use super::containers::{parse_kube_events, parse_kube_status, unavailable};
use crate::helper::{
    capability::{ProbeOutput, ProbeRequest},
    credentials::{ResolvedSecret, SecretResolver},
    evidence::EvidenceStatus,
    manifest::CapabilityId,
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use base64::Engine;
use reqwest::{Certificate, Client, StatusCode, Url, redirect::Policy};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const MAX_CONFIG: usize = 128 * 1024;
const MAX_BODY: usize = 128 * 1024;

#[derive(Deserialize)]
struct Config {
    contexts: Vec<NamedContext>,
    clusters: Vec<NamedCluster>,
    #[serde(default)]
    users: Vec<NamedUser>,
}
#[derive(Deserialize)]
struct NamedContext {
    name: String,
    context: Context,
}
#[derive(Deserialize)]
struct Context {
    cluster: String,
    #[serde(default)]
    user: String,
}
#[derive(Deserialize)]
struct NamedCluster {
    name: String,
    cluster: Cluster,
}
#[derive(Deserialize)]
struct Cluster {
    server: String,
    #[serde(rename = "certificate-authority-data")]
    ca_data: Option<String>,
    #[serde(rename = "certificate-authority")]
    ca_file: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify")]
    insecure: Option<bool>,
    #[serde(rename = "tls-server-name")]
    tls_server_name: Option<String>,
    #[serde(rename = "proxy-url")]
    proxy_url: Option<String>,
}
#[derive(Deserialize)]
struct NamedUser {
    name: String,
    user: User,
}
#[derive(Deserialize)]
struct User {
    exec: Option<serde::de::IgnoredAny>,
    #[serde(rename = "auth-provider")]
    auth_provider: Option<serde::de::IgnoredAny>,
}

pub(super) struct Endpoint {
    url: Url,
    ca_pem: Vec<u8>,
}

pub(super) fn config_path() -> Result<PathBuf> {
    ensure!(
        std::env::var_os("KUBECONFIG").is_none(),
        "Ambient KUBECONFIG is unsupported"
    );
    let home = std::env::var_os("USERPROFILE")
        .ok_or_else(|| anyhow::anyhow!("User profile unavailable"))?;
    Ok(PathBuf::from(home).join(".kube").join("config"))
}

pub(super) fn load_endpoint(
    path: &Path,
    reviewed_context: &str,
    reviewed_fingerprint: &str,
) -> Result<Endpoint> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_CONFIG + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_CONFIG, "Kubeconfig too large");
    let config: Config = serde_yaml::from_slice(&bytes)?;
    let mut matches = config
        .contexts
        .iter()
        .filter(|c| c.name == reviewed_context);
    let context = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("Context missing"))?;
    ensure!(matches.next().is_none(), "Duplicate context");
    let mut clusters = config
        .clusters
        .iter()
        .filter(|c| c.name == context.context.cluster);
    let cluster = &clusters
        .next()
        .ok_or_else(|| anyhow::anyhow!("Cluster missing"))?
        .cluster;
    ensure!(clusters.next().is_none(), "Duplicate cluster");
    // No kubeconfig credential may invoke a plugin or override the vault identity.
    if !context.context.user.is_empty() {
        let mut users = config
            .users
            .iter()
            .filter(|u| u.name == context.context.user);
        let user = &users
            .next()
            .ok_or_else(|| anyhow::anyhow!("Context user missing"))?
            .user;
        ensure!(
            users.next().is_none() && user.exec.is_none() && user.auth_provider.is_none(),
            "Dynamic credential config unsupported"
        );
    }
    ensure!(
        cluster.insecure != Some(true)
            && cluster.tls_server_name.is_none()
            && cluster.proxy_url.is_none()
            && cluster.ca_file.is_none(),
        "Unsafe or conflicting TLS configuration"
    );
    let ca_data = cluster
        .ca_data
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("CA data missing"))?;
    ensure!(
        !ca_data.is_empty() && ca_data.len() <= 64 * 1024,
        "Invalid CA data"
    );
    let url = Url::parse(&cluster.server)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Invalid Kubernetes endpoint"
    );
    let mut hash = Sha256::new();
    hash.update(b"relayne-kubernetes-cluster-v1\0");
    hash.update(cluster.server.as_bytes());
    hash.update(b"\0");
    hash.update(ca_data.as_bytes());
    ensure!(
        format!("{:x}", hash.finalize()) == reviewed_fingerprint,
        "Cluster fingerprint mismatch"
    );
    let ca_pem = base64::engine::general_purpose::STANDARD.decode(ca_data)?;
    ensure!(
        !ca_pem.is_empty() && ca_pem.len() <= 64 * 1024,
        "Invalid CA certificate"
    );
    Ok(Endpoint { url, ca_pem })
}

struct Transport {
    client: Client,
    root: Url,
    secret: ResolvedSecret,
}
impl Transport {
    fn new(endpoint: Endpoint, secret: ResolvedSecret) -> Result<Self> {
        let cert = Certificate::from_pem(&endpoint.ca_pem)?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            root: endpoint.url,
            secret,
        })
    }
    async fn request(
        &self,
        path: &str,
        body: Option<&'static str>,
        cancel: &CancellationToken,
    ) -> std::result::Result<Vec<u8>, EvidenceStatus> {
        let url = self
            .root
            .join(path)
            .map_err(|_| EvidenceStatus::Unavailable)?;
        ensure_same_origin(&self.root, &url).map_err(|_| EvidenceStatus::Unavailable)?;
        let request = if let Some(body) = body {
            self.client
                .post(url)
                .header("content-type", "application/json")
                .body(body)
        } else {
            self.client.get(url)
        }
        .header("connection", "close")
        .bearer_auth(self.secret.password());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(EvidenceStatus::Canceled),
            result = request.send() => result.map_err(|_| EvidenceStatus::Unavailable)?,
        };
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(EvidenceStatus::Denied);
        }
        if !status.is_success() {
            return Err(EvidenceStatus::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(EvidenceStatus::Truncated);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        loop {
            let chunk = tokio::select! {
                _ = cancel.cancelled() => return Err(EvidenceStatus::Canceled),
                result = response.chunk() => result.map_err(|_| EvidenceStatus::Unavailable)?,
            };
            let Some(chunk) = chunk else { break };
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|n| n > MAX_BODY)
            {
                return Err(EvidenceStatus::Truncated);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
fn ensure_same_origin(root: &Url, candidate: &Url) -> Result<()> {
    ensure!(
        candidate.scheme() == root.scheme()
            && candidate.host_str() == root.host_str()
            && candidate.port_or_known_default() == root.port_or_known_default(),
        "Origin changed"
    );
    Ok(())
}
fn resource_path(kind: &str, namespace: &str, name: &str) -> Result<String> {
    let base = match kind.to_ascii_lowercase().as_str() {
        "pod" => "api/v1",
        "deployment" | "statefulset" | "daemonset" => "apis/apps/v1",
        "job" => "apis/batch/v1",
        _ => anyhow::bail!("Unsupported kind"),
    };
    let plural = match kind.to_ascii_lowercase().as_str() {
        "pod" => "pods",
        "deployment" => "deployments",
        "statefulset" => "statefulsets",
        "daemonset" => "daemonsets",
        "job" => "jobs",
        _ => unreachable!(),
    };
    Ok(format!("{base}/namespaces/{namespace}/{plural}/{name}"))
}

pub(super) async fn collect(
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<ProbeOutput> {
    let path = match config_path() {
        Ok(v) => v,
        Err(_) => {
            return Ok(unavailable(
                "kubernetes:configuration",
                EvidenceStatus::Unavailable,
            ));
        }
    };
    collect_from_path(request, secrets, cancel, &path).await
}

pub(super) async fn collect_from_path(
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
    path: &Path,
) -> Result<ProbeOutput> {
    let BoundScope::Kubernetes {
        context,
        cluster_fingerprint,
        namespace,
        resource_kind,
        resource_name,
        credential,
    } = &request.scope
    else {
        anyhow::bail!("Scope mismatch")
    };
    let subject = format!("kubernetes:{context}:{namespace}:{resource_kind}:{resource_name}");
    let cred = credential
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Credential missing"))?;
    let endpoint = match load_endpoint(path, context, cluster_fingerprint) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    let secret = match secrets.resolve(cred, cred.purpose) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    if secret.username() != cred.principal || secret.password().is_empty() {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let transport = match Transport::new(endpoint, secret) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    let review =
        r#"{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","metadata":{}}"#;
    let who = match transport
        .request(
            "apis/authentication.k8s.io/v1/selfsubjectreviews",
            Some(review),
            &cancel,
        )
        .await
    {
        Ok(v) => v,
        Err(s) => return Ok(unavailable(&subject, s)),
    };
    if super::containers::kube_principal(&who, &cred.principal).is_err() {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let path = resource_path(resource_kind, namespace, resource_name)?;
    let workload = match transport.request(&path, None, &cancel).await {
        Ok(v) => v,
        Err(s) => return Ok(unavailable(&subject, s)),
    };
    let (status, uid) = match parse_kube_status(&workload, namespace, resource_kind, resource_name)
    {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Partial)),
    };
    if request.capability_id == CapabilityId::KubernetesWorkloadStatus {
        if secrets.resolve(cred, cred.purpose).is_err() {
            return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
        }
        return Ok(status);
    }
    ensure!(
        request.capability_id == CapabilityId::KubernetesEvents,
        "Capability mismatch"
    );
    let events_path = format!(
        "api/v1/namespaces/{namespace}/events?fieldSelector=involvedObject.uid%3D{uid}&limit=100"
    );
    let events = match transport.request(&events_path, None, &cancel).await {
        Ok(v) => v,
        Err(s) => return Ok(unavailable(&subject, s)),
    };
    if secrets.resolve(cred, cred.purpose).is_err() {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    Ok(parse_kube_events(&events, &uid)
        .unwrap_or_else(|_| unavailable(&subject, EvidenceStatus::Partial)))
}
