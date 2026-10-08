//! Fixed external-tool operations for later adapters. No shell, arbitrary command, or raw error API.
use std::{ffi::OsString, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;

const MAX_TOOL_STDOUT: usize = 128 * 1024;
const MAX_TOOL_STDERR: usize = 4 * 1024;

pub(crate) enum FixedToolOperation {
    DockerContainerInspect {
        container_id: String,
    },
    DockerContainerStats {
        container_id: String,
    },
    KubernetesWorkloadGet {
        context: String,
        namespace: String,
        kind: String,
        name: String,
    },
    KubernetesEvents {
        context: String,
        namespace: String,
    },
    AzureVmShow {
        resource_id: String,
    },
    AzureVmInstanceView {
        resource_id: String,
    },
    AwsEc2Describe {
        region: String,
        instance_id: String,
    },
    AwsEc2Status {
        region: String,
        instance_id: String,
    },
    #[cfg(test)]
    TestPing,
    #[cfg(test)]
    TestWhoami,
    #[cfg(test)]
    TestWhereSecret,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProcessFailure {
    InvalidInvocation,
    Spawn,
    Canceled,
    TimedOut,
    OutputLimit,
    ExitFailed,
}
pub(crate) struct ProcessOutput {
    pub(crate) stdout: Vec<u8>,
}

fn value(input: &str) -> Result<OsString, ProcessFailure> {
    if input.is_empty()
        || input.starts_with('-')
        || input.len() > 512
        || input.chars().any(char::is_control)
    {
        return Err(ProcessFailure::InvalidInvocation);
    }
    Ok(OsString::from(input))
}

impl FixedToolOperation {
    fn argv(self) -> Result<(&'static str, Vec<OsString>), ProcessFailure> {
        let program = match &self {
            Self::DockerContainerInspect { .. } | Self::DockerContainerStats { .. } => "docker.exe",
            Self::KubernetesWorkloadGet { .. } | Self::KubernetesEvents { .. } => "kubectl.exe",
            Self::AzureVmShow { .. } | Self::AzureVmInstanceView { .. } => "az.exe",
            Self::AwsEc2Describe { .. } | Self::AwsEc2Status { .. } => "aws.exe",
            #[cfg(test)]
            Self::TestPing => "ping.exe",
            #[cfg(test)]
            Self::TestWhoami => "whoami.exe",
            #[cfg(test)]
            Self::TestWhereSecret => "where.exe",
        };
        let args: Vec<OsString> = match self {
            Self::DockerContainerInspect { container_id } => {
                vec!["container".into(), "inspect".into(), value(&container_id)?]
            }
            Self::DockerContainerStats { container_id } => vec![
                "stats".into(),
                "--no-stream".into(),
                "--format".into(),
                "{{json .}}".into(),
                value(&container_id)?,
            ],
            Self::KubernetesWorkloadGet {
                context,
                namespace,
                kind,
                name,
            } => vec![
                "--context".into(),
                value(&context)?,
                "--namespace".into(),
                value(&namespace)?,
                "get".into(),
                value(&kind)?,
                value(&name)?,
                "-o".into(),
                "json".into(),
            ],
            Self::KubernetesEvents { context, namespace } => vec![
                "--context".into(),
                value(&context)?,
                "--namespace".into(),
                value(&namespace)?,
                "get".into(),
                "events".into(),
                "-o".into(),
                "json".into(),
            ],
            Self::AzureVmShow { resource_id } => vec![
                "vm".into(),
                "show".into(),
                "--ids".into(),
                value(&resource_id)?,
                "--output".into(),
                "json".into(),
            ],
            Self::AzureVmInstanceView { resource_id } => vec![
                "vm".into(),
                "get-instance-view".into(),
                "--ids".into(),
                value(&resource_id)?,
                "--output".into(),
                "json".into(),
            ],
            Self::AwsEc2Describe {
                region,
                instance_id,
            } => vec![
                "ec2".into(),
                "describe-instances".into(),
                "--region".into(),
                value(&region)?,
                "--instance-ids".into(),
                value(&instance_id)?,
                "--output".into(),
                "json".into(),
            ],
            Self::AwsEc2Status {
                region,
                instance_id,
            } => vec![
                "ec2".into(),
                "describe-instance-status".into(),
                "--region".into(),
                value(&region)?,
                "--instance-ids".into(),
                value(&instance_id)?,
                "--include-all-instances".into(),
                "--output".into(),
                "json".into(),
            ],
            #[cfg(test)]
            Self::TestPing => vec!["-n".into(), "30".into(), "127.0.0.1".into()],
            #[cfg(test)]
            Self::TestWhoami => Vec::new(),
            #[cfg(test)]
            Self::TestWhereSecret => vec!["secret-sentinel-never-matches".into()],
        };
        Ok((program, args))
    }
}

async fn capture<R: AsyncRead + Unpin>(
    mut reader: R,
    cap: usize,
    overflow: Arc<Notify>,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = reader.read(&mut chunk).await.ok()?;
        if n == 0 {
            return Some(bytes);
        }
        if bytes.len().checked_add(n).is_none_or(|length| length > cap) {
            overflow.notify_one();
            return None;
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
}

async fn terminate_tree(child: &mut Child) {
    #[cfg(windows)]
    if let Some(pid) = child.id() {
        let mut kill = Command::new("taskkill.exe");
        kill.args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000);
        if let Ok(mut process) = kill.spawn() {
            let _ = tokio::time::timeout(Duration::from_secs(2), process.wait()).await;
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

/// Also terminates descendants when an adapter future is dropped by its parent worker.
struct ProcessTreeGuard {
    pid: Option<u32>,
}
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(pid) = self.pid {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("taskkill.exe")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(0x08000000)
                .spawn();
        }
    }
}

pub(crate) async fn run_fixed_tool(
    operation: FixedToolOperation,
    cancel: CancellationToken,
    deadline: Duration,
) -> Result<ProcessOutput, ProcessFailure> {
    run_with_limit(operation, cancel, deadline, MAX_TOOL_STDOUT).await
}

async fn run_with_limit(
    operation: FixedToolOperation,
    cancel: CancellationToken,
    deadline: Duration,
    stdout_limit: usize,
) -> Result<ProcessOutput, ProcessFailure> {
    if deadline.is_zero() || deadline > Duration::from_secs(30) || stdout_limit > MAX_TOOL_STDOUT {
        return Err(ProcessFailure::InvalidInvocation);
    }
    if cancel.is_cancelled() {
        return Err(ProcessFailure::Canceled);
    }
    let (program, args) = operation.argv()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
    }
    let mut child = command.spawn().map_err(|_| ProcessFailure::Spawn)?;
    let mut tree_guard = ProcessTreeGuard { pid: child.id() };
    let overflow = Arc::new(Notify::new());
    let stdout = tokio::spawn(capture(
        child.stdout.take().ok_or(ProcessFailure::Spawn)?,
        stdout_limit,
        Arc::clone(&overflow),
    ));
    let stderr = tokio::spawn(capture(
        child.stderr.take().ok_or(ProcessFailure::Spawn)?,
        MAX_TOOL_STDERR,
        Arc::clone(&overflow),
    ));
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(ProcessFailure::Canceled),
        _ = tokio::time::sleep(deadline) => Err(ProcessFailure::TimedOut),
        _ = overflow.notified() => Err(ProcessFailure::OutputLimit),
        status = child.wait() => match status {
            Ok(status) if status.success() => Ok(()),
            _ => Err(ProcessFailure::ExitFailed),
        },
    };
    if matches!(
        &result,
        Err(ProcessFailure::Canceled | ProcessFailure::TimedOut | ProcessFailure::OutputLimit)
    ) {
        terminate_tree(&mut child).await;
    }
    tree_guard.pid = None;
    let out = stdout
        .await
        .map_err(|_| ProcessFailure::OutputLimit)?
        .ok_or(ProcessFailure::OutputLimit)?;
    let _ = stderr
        .await
        .map_err(|_| ProcessFailure::OutputLimit)?
        .ok_or(ProcessFailure::OutputLimit)?;
    result?;
    Ok(ProcessOutput { stdout: out })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_process_is_bounded_cancellable_and_redacted() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let out = run_fixed_tool(
                FixedToolOperation::TestWhoami,
                CancellationToken::new(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert!(!out.stdout.is_empty());
            let result = run_with_limit(
                FixedToolOperation::TestWhoami,
                CancellationToken::new(),
                Duration::from_secs(5),
                1,
            )
            .await;
            assert!(matches!(result, Err(ProcessFailure::OutputLimit)));
            let result = run_fixed_tool(
                FixedToolOperation::TestWhereSecret,
                CancellationToken::new(),
                Duration::from_secs(5),
            )
            .await;
            assert!(matches!(&result, Err(ProcessFailure::ExitFailed)));
            assert!(!format!("{:?}", result.err().unwrap()).contains("secret-sentinel"));
            let cancel = CancellationToken::new();
            cancel.cancel();
            let result =
                run_fixed_tool(FixedToolOperation::TestPing, cancel, Duration::from_secs(5)).await;
            assert!(matches!(result, Err(ProcessFailure::Canceled)));
            let result = run_fixed_tool(
                FixedToolOperation::TestPing,
                CancellationToken::new(),
                Duration::from_millis(50),
            )
            .await;
            assert!(matches!(result, Err(ProcessFailure::TimedOut)));
            #[cfg(windows)]
            {
                let mut process = Command::new("ping.exe");
                process
                    .args(["-n", "30", "127.0.0.1"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(0x08000000);
                let mut child = process.spawn().unwrap();
                drop(ProcessTreeGuard { pid: child.id() });
                assert!(
                    tokio::time::timeout(Duration::from_secs(3), child.wait())
                        .await
                        .is_ok()
                );
            }
        });
    }
}
