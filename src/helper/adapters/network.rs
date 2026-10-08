//! Relayne-origin checks against an exactly reviewed HTTP endpoint.
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::{Coverage, EvidenceStatus, NormalizedRecord, Observation, RecordKind},
    manifest::ProbeParams,
    scope::BoundScope,
};
use chrono::Utc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

async fn verified_tls_handshake(
    connect_host: &str,
    port: u16,
    verify_host: &str,
    roots: rustls::RootCertStore,
    cancel: CancellationToken,
) -> anyhow::Result<bool> {
    let name = match verify_host.parse::<std::net::IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => match rustls::pki_types::ServerName::try_from(verify_host.to_owned()) {
            Ok(name) => name,
            Err(_) => return Ok(false),
        },
    };
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connect = async {
        let socket = tokio::net::TcpStream::connect((connect_host, port)).await?;
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
            .connect(name, socket)
            .await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("Canceled"),
        result = tokio::time::timeout(Duration::from_secs(8), connect) => Ok(result.is_ok_and(|result| result.is_ok())),
    }
}

pub struct NetworkAdapter;

impl ProbeAdapter for NetworkAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::Http {
                target,
                port,
                tls,
                path,
            } = &request.scope
            else {
                anyhow::bail!("Explicit HTTP scope required");
            };
            anyhow::ensure!(
                target.route.is_empty(),
                "HTTP probe requires a direct route"
            );
            let url = crate::helper::scope::reviewed_http_url(target, *port, *tls, path)?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Missing reviewed host"))?;
            let host = host.trim_matches(['[', ']']);
            let success = match request.params {
                ProbeParams::Dns => tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                    result = tokio::time::timeout(Duration::from_secs(8), tokio::net::lookup_host((host, *port))) =>
                        result.is_ok_and(|result| result.is_ok_and(|mut values| values.next().is_some())),
                },
                ProbeParams::Tls if *tls => {
                    let native = tokio::select! {
                        _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                        result = tokio::time::timeout(Duration::from_secs(3),
                            tokio::task::spawn_blocking(rustls_native_certs::load_native_certs)) => result??,
                    };
                    let mut roots = rustls::RootCertStore::empty();
                    let (accepted, _) = roots.add_parsable_certificates(native.certs);
                    if accepted == 0 {
                        anyhow::bail!("No OS-trusted TLS roots available");
                    }
                    verified_tls_handshake(host, *port, host, roots, cancel).await?
                }
                _ => anyhow::bail!("Unsupported network parameters"),
            };
            let now = Utc::now();
            Ok(ProbeOutput {
                status: if success {
                    EvidenceStatus::Complete
                } else {
                    EvidenceStatus::Unavailable
                },
                coverage: Coverage {
                    observed: u32::from(success),
                    expected: 1,
                    truncated: false,
                },
                records: vec![NormalizedRecord {
                    kind: RecordKind::Network,
                    observation: if success {
                        Observation::Healthy
                    } else {
                        Observation::Unavailable
                    },
                    subject_sha256: request.scope.resource_digest()?,
                    detail: None,
                }],
                metrics: vec![],
                sql_observations: vec![],
                sql_artifacts: vec![],
                evidence_refs: vec![],
                source_id: format!("relayne-local:{:?}:{}:{port}", request.capability_id, host)
                    .into_bytes(),
                source_observed_at: now,
                parser_version: 1,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn tls_handshake_uses_trust_and_name_without_http_head() {
        let cert = rustls::pki_types::CertificateDer::from(
            include_bytes!("fixtures/tls-localhost-cert.der").to_vec(),
        );
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                include_bytes!("fixtures/tls-localhost-key.der").to_vec(),
            ));
        let server = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    // The application rejects HEAD; the TLS capability must still succeed.
                    let _ = tls
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            }
        });
        let mut trusted = rustls::RootCertStore::empty();
        trusted
            .add(rustls::pki_types::CertificateDer::from(
                include_bytes!("fixtures/tls-localhost-root.der").to_vec(),
            ))
            .unwrap();
        assert!(
            verified_tls_handshake(
                "127.0.0.1",
                port,
                "localhost",
                trusted,
                CancellationToken::new()
            )
            .await
            .unwrap()
        );
        assert!(
            !verified_tls_handshake(
                "127.0.0.1",
                port,
                "localhost",
                rustls::RootCertStore::empty(),
                CancellationToken::new()
            )
            .await
            .unwrap()
        );
        let mut trusted_wrong_name = rustls::RootCertStore::empty();
        trusted_wrong_name
            .add(rustls::pki_types::CertificateDer::from(
                include_bytes!("fixtures/tls-localhost-root.der").to_vec(),
            ))
            .unwrap();
        assert!(
            !verified_tls_handshake(
                "127.0.0.1",
                port,
                "wrong.example",
                trusted_wrong_name,
                CancellationToken::new()
            )
            .await
            .unwrap()
        );
        server_task.abort();
    }
}
