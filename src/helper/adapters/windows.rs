use super::{RawSnapshot, normalize_snapshot, selections};
use crate::helper::{
    capability::{ProbeAdapter, ProbeFuture, ProbeRequest},
    credentials::SecretResolver,
    process::{FixedToolOperation, run_fixed_tool},
    scope::BoundScope,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct WindowsAdapter;
impl ProbeAdapter for WindowsAdapter {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let BoundScope::WindowsWinRm {
                target,
                winrm_port,
                identity,
                credential: None,
            } = &request.scope
            else {
                anyhow::bail!("Reviewed current-identity WinRM scope required");
            };
            anyhow::ensure!(
                crate::helper::scope::current_windows_identity()? == *identity,
                "Windows identity changed since review"
            );
            let (service, mount, interface) = selections(&request.params)?;
            let output = match run_fixed_tool(
                FixedToolOperation::WindowsCollector {
                    host: target.host.clone(),
                    port: *winrm_port,
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
            let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if value.as_object().is_some_and(|object| {
                object.len() == 1
                    && object
                        .get("collector_status")
                        .and_then(serde_json::Value::as_str)
                        == Some("denied")
            }) {
                return super::permission_gap(request);
            }
            let raw: RawSnapshot = serde_json::from_value(value)?;
            normalize_snapshot(
                raw,
                request,
                service.as_deref(),
                mount.as_deref(),
                interface.as_deref(),
            )
        })
    }
}
