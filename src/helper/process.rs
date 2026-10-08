//! Fixed external-tool operations for later adapters. No shell, arbitrary command, or raw error API.
use std::{ffi::OsString, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
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
    AwsCallerIdentity {
        region: String,
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
    #[cfg(test)]
    TestPipeParent {
        pid_file: std::path::PathBuf,
    },
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

#[cfg(not(test))]
fn trusted_aws_program() -> Result<OsString, ProcessFailure> {
    #[cfg(windows)]
    let candidates = [std::env::var_os("ProgramFiles")
        .map(|root| std::path::PathBuf::from(root).join("Amazon/AWSCLIV2/aws.exe"))
        .ok_or(ProcessFailure::Spawn)?];
    #[cfg(not(windows))]
    let candidates = [
        std::path::PathBuf::from("/usr/local/bin/aws"),
        std::path::PathBuf::from("/usr/bin/aws"),
    ];
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(std::path::PathBuf::into_os_string)
        .ok_or(ProcessFailure::Spawn)
}

impl FixedToolOperation {
    fn argv(self) -> Result<(OsString, Vec<OsString>), ProcessFailure> {
        let program = match &self {
            Self::DockerContainerInspect { .. } | Self::DockerContainerStats { .. } => "docker.exe",
            Self::KubernetesWorkloadGet { .. } | Self::KubernetesEvents { .. } => "kubectl.exe",
            Self::AzureVmShow { .. } | Self::AzureVmInstanceView { .. } => "az.exe",
            Self::AwsCallerIdentity { .. }
            | Self::AwsEc2Describe { .. }
            | Self::AwsEc2Status { .. } => "aws.exe",
            #[cfg(test)]
            Self::TestPing => "ping.exe",
            #[cfg(test)]
            Self::TestWhoami => "whoami.exe",
            #[cfg(test)]
            Self::TestWhereSecret => "where.exe",
            #[cfg(test)]
            Self::TestPipeParent { .. } => "",
        };
        #[cfg(test)]
        let program = if matches!(&self, Self::TestPipeParent { .. }) {
            std::env::current_exe()
                .map_err(|_| ProcessFailure::Spawn)?
                .into_os_string()
        } else {
            OsString::from(program)
        };
        #[cfg(not(test))]
        let program = if program == "aws.exe" {
            trusted_aws_program()?
        } else {
            OsString::from(program)
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
            Self::AwsCallerIdentity { region } => vec![
                "sts".into(),
                "get-caller-identity".into(),
                "--region".into(),
                value(&region)?,
                "--output".into(),
                "json".into(),
                "--no-cli-pager".into(),
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
                "--no-cli-pager".into(),
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
                "--no-cli-pager".into(),
            ],
            #[cfg(test)]
            Self::TestPing => vec!["-n".into(), "30".into(), "127.0.0.1".into()],
            #[cfg(test)]
            Self::TestWhoami => Vec::new(),
            #[cfg(test)]
            Self::TestWhereSecret => vec!["secret-sentinel-never-matches".into()],
            #[cfg(test)]
            Self::TestPipeParent { .. } => vec![
                "--exact".into(),
                "helper::process::tests::pipe_parent_fixture".into(),
                "--nocapture".into(),
            ],
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

#[cfg(windows)]
struct JobGuard(std::os::windows::io::OwnedHandle);

#[cfg(windows)]
impl JobGuard {
    fn attach_suspended(pid: u32) -> Result<Self, ProcessFailure> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            System::{
                Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
                JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                    SetInformationJobObject, TerminateJobObject,
                },
                Threading::{
                    OpenProcess, OpenThread, PROCESS_SET_QUOTA, PROCESS_TERMINATE, ResumeThread,
                    THREAD_SUSPEND_RESUME,
                },
            },
        };
        // SAFETY: All returned handles are checked and immediately owned. The root stays
        // suspended until it is assigned to the kill-on-close job.
        unsafe {
            let raw_job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if raw_job.is_null() {
                return Err(ProcessFailure::Spawn);
            }
            let job = std::os::windows::io::OwnedHandle::from_raw_handle(raw_job);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const std::ffi::c_void,
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                return Err(ProcessFailure::Spawn);
            }
            let raw_process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if raw_process.is_null() {
                return Err(ProcessFailure::Spawn);
            }
            let process = std::os::windows::io::OwnedHandle::from_raw_handle(raw_process);
            if AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) == 0 {
                return Err(ProcessFailure::Spawn);
            }
            // ToolHelp can briefly lag a newly created suspended process.
            for _ in 0..20 {
                let raw_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if raw_snapshot != INVALID_HANDLE_VALUE {
                    let snapshot = std::os::windows::io::OwnedHandle::from_raw_handle(raw_snapshot);
                    let mut entry: THREADENTRY32 = std::mem::zeroed();
                    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    let mut found = Thread32First(snapshot.as_raw_handle(), &mut entry) != 0;
                    while found {
                        if entry.th32OwnerProcessID == pid {
                            let raw_thread =
                                OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                            if !raw_thread.is_null() {
                                let thread =
                                    std::os::windows::io::OwnedHandle::from_raw_handle(raw_thread);
                                if ResumeThread(thread.as_raw_handle()) != u32::MAX {
                                    return Ok(Self(job));
                                }
                            }
                            break;
                        }
                        found = Thread32Next(snapshot.as_raw_handle(), &mut entry) != 0;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = TerminateJobObject(job.as_raw_handle(), 1);
            Err(ProcessFailure::Spawn)
        }
    }

    fn terminate(&self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: The owned handle remains valid for this call.
        unsafe {
            let _ = TerminateJobObject(self.0.as_raw_handle(), 1);
        }
    }
}

pub(crate) async fn run_fixed_tool(
    operation: FixedToolOperation,
    cancel: CancellationToken,
    deadline: Duration,
) -> Result<ProcessOutput, ProcessFailure> {
    if matches!(
        operation,
        FixedToolOperation::AzureVmShow { .. }
            | FixedToolOperation::AzureVmInstanceView { .. }
            | FixedToolOperation::AwsCallerIdentity { .. }
            | FixedToolOperation::AwsEc2Describe { .. }
            | FixedToolOperation::AwsEc2Status { .. }
    ) {
        return Err(ProcessFailure::InvalidInvocation);
    }
    run_with_limit(operation, cancel, deadline, MAX_TOOL_STDOUT, None).await
}
pub(crate) async fn run_aws_tool(
    operation: FixedToolOperation,
    access_key: &str,
    secret_key: &str,
    session_token: &str,
    cancel: CancellationToken,
    deadline: Duration,
) -> Result<ProcessOutput, ProcessFailure> {
    if !matches!(
        operation,
        FixedToolOperation::AwsCallerIdentity { .. }
            | FixedToolOperation::AwsEc2Describe { .. }
            | FixedToolOperation::AwsEc2Status { .. }
    ) || access_key.is_empty()
        || secret_key.is_empty()
        || access_key.len() > 128
        || secret_key.len() > 4096
        || session_token.len() > 4096
        || [access_key, secret_key, session_token]
            .iter()
            .any(|value| value.chars().any(char::is_control))
    {
        return Err(ProcessFailure::InvalidInvocation);
    }
    run_with_limit(
        operation,
        cancel,
        deadline,
        MAX_TOOL_STDOUT,
        Some((access_key, secret_key, session_token)),
    )
    .await
}

async fn run_with_limit(
    operation: FixedToolOperation,
    cancel: CancellationToken,
    deadline: Duration,
    stdout_limit: usize,
    aws: Option<(&str, &str, &str)>,
) -> Result<ProcessOutput, ProcessFailure> {
    if deadline.is_zero() || deadline > Duration::from_secs(30) || stdout_limit > MAX_TOOL_STDOUT {
        return Err(ProcessFailure::InvalidInvocation);
    }
    if cancel.is_cancelled() {
        return Err(ProcessFailure::Canceled);
    }
    #[cfg(test)]
    let pipe_pid_file = match &operation {
        FixedToolOperation::TestPipeParent { pid_file } => Some(pid_file.clone()),
        _ => None,
    };
    let (program, args) = operation.argv()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some((access_key, secret_key, session_token)) = aws {
        command
            .env("AWS_ACCESS_KEY_ID", access_key)
            .env("AWS_SECRET_ACCESS_KEY", secret_key)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env(
                "AWS_CONFIG_FILE",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            );
        if !session_token.is_empty() {
            command.env("AWS_SESSION_TOKEN", session_token);
        }
    }
    #[cfg(test)]
    if let Some(path) = pipe_pid_file {
        command
            .env("RELAYNE_PIPE_FIXTURE", "1")
            .env("RELAYNE_PIPE_PID_FILE", path);
    }
    #[cfg(windows)]
    {
        command
            .creation_flags(0x08000000 | windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
    }
    let expires_at = tokio::time::Instant::now() + deadline;
    let mut child = command.spawn().map_err(|_| ProcessFailure::Spawn)?;
    #[cfg(windows)]
    let job = match child
        .id()
        .and_then(|pid| JobGuard::attach_suspended(pid).ok())
    {
        Some(job) => job,
        None => {
            let _ = child.start_kill();
            return Err(ProcessFailure::Spawn);
        }
    };
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
        _ = tokio::time::sleep_until(expires_at) => Err(ProcessFailure::TimedOut),
        _ = overflow.notified() => Err(ProcessFailure::OutputLimit),
        completed = async {
            let status = child.wait().await.map_err(|_| ProcessFailure::ExitFailed)?;
            let out = stdout.await.map_err(|_| ProcessFailure::OutputLimit)?
                .ok_or(ProcessFailure::OutputLimit)?;
            let _ = stderr.await.map_err(|_| ProcessFailure::OutputLimit)?
                .ok_or(ProcessFailure::OutputLimit)?;
            if !status.success() { return Err(ProcessFailure::ExitFailed); }
            Ok(out)
        } => completed,
    };
    if result.is_err() {
        #[cfg(windows)]
        job.terminate();
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    let out = result?;
    Ok(ProcessOutput { stdout: out })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aws_commands_are_fixed_exact_read_only_and_reject_option_ids() {
        let (_, sts) = FixedToolOperation::AwsCallerIdentity {
            region: "eu-central-1".into(),
        }
        .argv()
        .unwrap();
        assert_eq!(
            sts,
            vec![
                "sts",
                "get-caller-identity",
                "--region",
                "eu-central-1",
                "--output",
                "json",
                "--no-cli-pager"
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        let (_, inventory) = FixedToolOperation::AwsEc2Describe {
            region: "eu-central-1".into(),
            instance_id: "i-0123456789abcdef0".into(),
        }
        .argv()
        .unwrap();
        assert!(inventory.contains(&OsString::from("--no-cli-pager")));
        assert_eq!(
            inventory
                .iter()
                .filter(|arg| *arg == "--instance-ids")
                .count(),
            1
        );
        assert!(
            FixedToolOperation::AwsEc2Describe {
                region: "--endpoint-url".into(),
                instance_id: "i-0123456789abcdef0".into()
            }
            .argv()
            .is_err()
        );
    }

    #[tokio::test]
    async fn generic_runner_rejects_unscoped_cloud_command() {
        assert!(matches!(
            run_fixed_tool(
                FixedToolOperation::AwsCallerIdentity {
                    region: "eu-central-1".into()
                },
                CancellationToken::new(),
                Duration::from_secs(1)
            )
            .await,
            Err(ProcessFailure::InvalidInvocation)
        ));
        assert!(matches!(
            run_fixed_tool(
                FixedToolOperation::AzureVmShow {
                    resource_id: "vm".into()
                },
                CancellationToken::new(),
                Duration::from_secs(1)
            )
            .await,
            Err(ProcessFailure::InvalidInvocation)
        ));
    }

    #[test]
    fn pipe_parent_fixture() {
        if std::env::var_os("RELAYNE_PIPE_FIXTURE").is_none() {
            return;
        }
        let child = std::process::Command::new("ping.exe")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let path = std::env::var_os("RELAYNE_PIPE_PID_FILE").unwrap();
        std::fs::write(path, child.id().to_string()).unwrap();
    }

    #[cfg(windows)]
    fn process_alive(pid: u32) -> bool {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
            },
        };
        // SAFETY: PID comes from the fixture child; handle is checked and closed.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return false;
            }
            let active = WaitForSingleObject(handle, 0) != 0;
            CloseHandle(handle);
            active
        }
    }

    #[cfg(windows)]
    #[test]
    fn parent_exit_with_child_holding_pipes_obeys_deadline_and_kills_child() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let pid_file =
            std::env::temp_dir().join(format!("relayne-pipe-child-{}", uuid::Uuid::new_v4()));
        let started = std::time::Instant::now();
        let result = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(3),
                run_fixed_tool(
                    FixedToolOperation::TestPipeParent {
                        pid_file: pid_file.clone(),
                    },
                    CancellationToken::new(),
                    Duration::from_millis(750),
                ),
            )
            .await
        });
        let pid: u32 = std::fs::read_to_string(&pid_file)
            .unwrap_or_else(|error| {
                panic!(
                    "fixture did not launch: {error}; runner: {:?}",
                    result.as_ref().map(|inner| inner.as_ref().map(|_| ()))
                )
            })
            .parse()
            .unwrap();
        let _ = std::fs::remove_file(&pid_file);
        let mut alive = process_alive(pid);
        for _ in 0..30 {
            if !alive {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            alive = process_alive(pid);
        }
        if alive {
            let _ = std::process::Command::new("taskkill.exe")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .and_then(|mut child| child.wait());
        }
        assert!(
            matches!(result, Ok(Err(ProcessFailure::TimedOut))),
            "runner escaped deadline"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "drain exceeded deadline"
        );
        assert!(!alive, "owned descendant survived timeout");
    }
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
                None,
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
                    .creation_flags(
                        0x08000000 | windows_sys::Win32::System::Threading::CREATE_SUSPENDED,
                    );
                let mut child = process.spawn().unwrap();
                let job = JobGuard::attach_suspended(child.id().unwrap()).unwrap();
                drop(job);
                assert!(
                    tokio::time::timeout(Duration::from_secs(3), child.wait())
                        .await
                        .is_ok()
                );
            }
        });
    }
}
