use super::{RawProcess, RawSnapshot, normalize_snapshot, selections};
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
    ensure!(bytes.len() <= 16384, "Oversized Linux collector output");
    let text = std::str::from_utf8(bytes)?;
    let mut fields = HashMap::new();
    const KEYS: [&str; 27] = [
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
        "events_metadata_truncated",
        "process_count",
        "service_state",
        "os_version",
        "os_name",
        "uptime_seconds",
        "load_one",
        "processes",
        "service_dependencies",
        "service_dependencies_truncated",
        "events",
        "interface_extra",
        "tcp_before",
        "tcp_after",
        "listening_tcp",
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
    ensure!(get("events").is_empty(), "Linux event metadata unsupported");
    let optional_number = |key| -> Result<Option<f64>> {
        if get(key).is_empty() {
            Ok(None)
        } else {
            Ok(Some(get(key).parse()?))
        }
    };
    let processes =
        if get("processes").is_empty() {
            None
        } else {
            let entries: Vec<_> = get("processes")
                .split(';')
                .filter(|v| !v.is_empty())
                .collect();
            ensure!(entries.len() <= 5, "Too many process summaries");
            Some(
                entries
                    .into_iter()
                    .map(|entry| {
                        let parts: Vec<_> = entry.split(',').collect();
                        ensure!(
                            parts.len() == 3
                                && !parts[0].is_empty()
                                && parts[0].len() <= 64
                                && parts[0].bytes().all(|b| b.is_ascii_alphanumeric()
                                    || matches!(b, b'_' | b'.' | b'-')),
                            "Invalid process summary"
                        );
                        Ok(RawProcess {
                            name: parts[0].to_owned(),
                            memory_bytes: Some(parts[1].parse()?),
                            cpu_seconds: Some(parts[2].parse()?),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
        };
    let service_dependencies = match get("service_dependencies") {
        "" => None,
        "-" => Some(Vec::new()),
        value => {
            let names: Vec<_> = value
                .split(';')
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect();
            ensure!(names.len() <= 16, "Too many dependencies");
            Some(names)
        }
    };
    let interface_extra = if get("interface_extra").is_empty() {
        None
    } else {
        let values = get("interface_extra")
            .split_whitespace()
            .map(str::parse::<f64>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            values.len() == 4 && values.iter().all(|v| v.is_finite() && *v >= 0.0),
            "Invalid interface counters"
        );
        Some(values)
    };
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
        events_metadata_truncated: get("events_metadata_truncated").parse()?,
        process_count: if get("process_count").is_empty() {
            None
        } else {
            Some(get("process_count").parse()?)
        },
        service_state: (!state.is_empty()).then(|| state.to_owned()),
        os_version: (!get("os_version").is_empty()).then(|| get("os_version").to_owned()),
        os_name: (!get("os_name").is_empty()).then(|| get("os_name").to_owned()),
        uptime_seconds: optional_number("uptime_seconds")?,
        load_one: optional_number("load_one")?,
        processes,
        service_dependencies,
        service_dependencies_truncated: match get("service_dependencies_truncated") {
            "true" => true,
            "false" => false,
            _ => anyhow::bail!("Invalid dependency truncation state"),
        },
        events: None,
        interface_extra,
        tcp_before: parse_pair(get("tcp_before"))?,
        tcp_after: parse_pair(get("tcp_after"))?,
        listening_tcp: optional_number("listening_tcp")?,
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
