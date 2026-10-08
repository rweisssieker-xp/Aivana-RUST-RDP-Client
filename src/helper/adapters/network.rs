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
            let host = target.host.as_str();
            let success = match request.params {
                ProbeParams::Dns => tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                    result = tokio::net::lookup_host((host, *port)) => result.is_ok_and(|mut values| values.next().is_some()),
                },
                ProbeParams::Tls if *tls => {
                    let authority = if host.contains(':') {
                        format!("[{host}]")
                    } else {
                        host.to_owned()
                    };
                    let url = format!("https://{authority}:{port}{path}");
                    let client = reqwest::Client::builder()
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(Duration::from_secs(8))
                        .build()?;
                    tokio::select! {
                        _ = cancel.cancelled() => anyhow::bail!("Canceled"),
                        result = client.head(&url).send() => result.is_ok(),
                    }
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
                }],
                metrics: vec![],
                evidence_refs: vec![],
                source_id: format!("relayne-local:{:?}:{}:{port}", request.capability_id, host)
                    .into_bytes(),
                source_observed_at: now,
                parser_version: 1,
            })
        })
    }
}
