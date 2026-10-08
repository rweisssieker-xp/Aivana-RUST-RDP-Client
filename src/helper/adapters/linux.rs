use super::{RawSnapshot, normalize_snapshot, selections};
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeRequest},
    credentials::SecretResolver,
    process::{FixedToolOperation, run_fixed_tool},
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use std::{collections::HashMap, time::Duration};
use tokio_util::sync::CancellationToken;

pub struct LinuxAdapter;

fn parse_pair(input: &str) -> Result<Option<Vec<f64>>> {
    if input.is_empty() {
        return Ok(None);
    }
    let values = input
        .split_whitespace()
        .map(str::parse::<f64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 2 && values.iter().all(|v| v.is_finite() && *v >= 0.0),
        "Invalid collector pair"
    );
    Ok(Some(values))
}

pub(super) fn parse_snapshot(bytes: &[u8]) -> Result<RawSnapshot> {
    ensure!(bytes.len() <= 4096, "Oversized Linux collector output");
    let text = std::str::from_utf8(bytes)?;
    let mut fields = HashMap::new();
    const KEYS: [&str; 14] = [
        "schema",
        "start_ms",
        "end_ms",
        "cpu_before",
        "cpu_after",
        "interface_before",
        "interface_after",
        "memory",
        "commit",
        "disk",
        "error_count",
        "events_truncated",
        "process_count",
        "service_state",
    ];
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Malformed collector line"))?;
        ensure!(
            KEYS.contains(&key) && fields.insert(key, value).is_none(),
            "Unknown/duplicate collector key"
        );
    }
    ensure!(fields.len() == KEYS.len(), "Incomplete collector output");
    let get = |key| fields.get(key).copied().unwrap_or("");
    let state = get("service_state");
    ensure!(
        state.is_empty() || matches!(state, "active" | "inactive" | "failed" | "unknown"),
        "Invalid service state"
    );
    Ok(RawSnapshot {
        schema: get("schema").parse()?,
        start_ms: get("start_ms").parse()?,
        end_ms: get("end_ms").parse()?,
        cpu_before: parse_pair(get("cpu_before"))?,
        cpu_after: parse_pair(get("cpu_after"))?,
        interface_before: parse_pair(get("interface_before"))?,
        interface_after: parse_pair(get("interface_after"))?,
        memory: parse_pair(get("memory"))?,
        commit: parse_pair(get("commit"))?,
        disk: parse_pair(get("disk"))?,
        error_count: if get("error_count").is_empty() {
            None
        } else {
            Some(get("error_count").parse()?)
        },
        events_truncated: get("events_truncated").parse()?,
        process_count: if get("process_count").is_empty() {
            None
        } else {
            Some(get("process_count").parse()?)
        },
        service_state: (!state.is_empty()).then(|| state.to_owned()),
    })
}

impl ProbeAdapter for LinuxAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::Linux {
                target,
                credential: None,
            } = &request.scope
            else {
                anyhow::bail!("Linux current-identity SSH scope required");
            };
            anyhow::ensure!(
                target.route.is_empty(),
                "SSH collector requires direct reviewed endpoint"
            );
            let (service, mount, interface) = selections(&request.params)?;
            let output = match run_fixed_tool(
                FixedToolOperation::LinuxCollector {
                    host: target.host.clone(),
                    user: target.username.clone(),
                    port: target.port,
                    service: service.clone(),
                    mount: mount.clone(),
                    interface: interface.clone(),
                },
                cancel,
                Duration::from_secs(15),
            )
            .await
            {
                Ok(output) => output,
                Err(failure) => return super::tool_gap(request, failure),
            };
            normalize_snapshot(
                parse_snapshot(&output.stdout)?,
                request,
                service.as_deref(),
                mount.as_deref(),
                interface.as_deref(),
            )
        })
    }
}
