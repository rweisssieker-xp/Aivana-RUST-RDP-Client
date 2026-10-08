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

#[cfg(windows)]
fn windows_system_directory() -> Result<std::path::PathBuf, ProcessFailure> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = [0u16; 32768];
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(ProcessFailure::Spawn);
    }
    Ok(std::path::PathBuf::from(OsString::from_wide(
        &buffer[..len],
    )))
}

#[cfg(windows)]
fn process_token_profile() -> Result<std::path::PathBuf, ProcessFailure> {
    use std::os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process: *mut std::ffi::c_void,
            access: u32,
            token: *mut *mut std::ffi::c_void,
        ) -> i32;
    }
    #[link(name = "userenv")]
    unsafe extern "system" {
        fn GetUserProfileDirectoryW(
            token: *mut std::ffi::c_void,
            buffer: *mut u16,
            size: *mut u32,
        ) -> i32;
    }
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut raw) } == 0 || raw.is_null() {
        return Err(ProcessFailure::Spawn);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut buffer = [0u16; 32768];
    let mut len = buffer.len() as u32;
    if unsafe { GetUserProfileDirectoryW(token.as_raw_handle(), buffer.as_mut_ptr(), &mut len) }
        == 0
        || len == 0
        || len as usize >= buffer.len()
    {
        return Err(ProcessFailure::Spawn);
    }
    let copied = len as usize;
    let copied = if buffer[copied - 1] == 0 {
        copied - 1
    } else {
        copied
    };
    let path = std::path::PathBuf::from(OsString::from_wide(&buffer[..copied]));
    if !path.is_absolute() {
        return Err(ProcessFailure::Spawn);
    }
    Ok(path)
}

pub(crate) fn system_collector_readiness(
    scope: &crate::helper::scope::BoundScope,
) -> (bool, &'static str) {
    #[cfg(windows)]
    {
        let Ok(system) = windows_system_directory() else {
            return (false, "OS system directory unavailable");
        };
        match scope {
            crate::helper::scope::BoundScope::WindowsWinRm { .. } => {
                if system
                    .join("WindowsPowerShell/v1.0/powershell.exe")
                    .is_file()
                {
                    (
                        true,
                        "OS PowerShell present; remote WinRM rights checked on capture",
                    )
                } else {
                    (false, "OS PowerShell unavailable")
                }
            }
            crate::helper::scope::BoundScope::Linux { .. } => {
                if !system.join("OpenSSH/ssh.exe").is_file() {
                    return (false, "OS OpenSSH unavailable");
                }
                let Ok(profile) = process_token_profile() else {
                    return (false, "Windows token profile unavailable");
                };
                let ssh = profile.join(".ssh");
                if !ssh.join("known_hosts").is_file() {
                    return (false, "Current account known_hosts unavailable");
                }
                if !["id_ed25519", "id_ecdsa", "id_rsa"]
                    .iter()
                    .any(|name| ssh.join(name).is_file())
                {
                    return (false, "Current account default SSH key unavailable");
                }
                (
                    true,
                    "OS OpenSSH and current-account key/host trust present; remote SSH rights checked on capture",
                )
            }
            _ => (false, "No system collector for scope"),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        (false, "System collectors require Windows host")
    }
}

pub(crate) enum FixedToolOperation {
    WindowsCollector {
        host: String,
        port: u16,
        service: Option<String>,
        mount: Option<String>,
        interface: Option<String>,
    },
    LinuxCollector {
        host: String,
        user: String,
        port: u16,
        service: Option<String>,
        mount: Option<String>,
        interface: Option<String>,
    },
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
    #[cfg(test)]
    TestLocalLinuxScript {
        shell: std::path::PathBuf,
    },
    #[cfg(test)]
    TestLocalWindowsScript {
        denied: bool,
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

#[cfg(windows)]
fn system_program_files() -> Result<std::path::PathBuf, ProcessFailure> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
    };
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the shell writes a CoTaskMem-owned terminated UTF-16 string.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut raw) };
    if result < 0 || raw.is_null() {
        return Err(ProcessFailure::Spawn);
    }
    let mut length = 0usize;
    // SAFETY: SHGetKnownFolderPath returns a terminated string. The bound prevents runaway reads.
    while length < 32768 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    let root = if length < 32768 {
        // SAFETY: the returned buffer has at least `length` initialized UTF-16 units.
        std::path::PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(raw, length)
        }))
    } else {
        std::path::PathBuf::new()
    };
    // SAFETY: raw is the CoTaskMem allocation returned by the shell.
    unsafe { CoTaskMemFree(raw.cast()) };
    if !root.is_absolute() {
        return Err(ProcessFailure::Spawn);
    }
    Ok(root)
}

#[cfg(windows)]
fn verified_windows_aws_program() -> Result<OsString, ProcessFailure> {
    let root = system_program_files()?
        .canonicalize()
        .map_err(|_| ProcessFailure::Spawn)?;
    let candidate = root.join("Amazon/AWSCLIV2/aws.exe");
    if !candidate.is_file() {
        return Err(ProcessFailure::Spawn);
    }
    let actual = candidate
        .canonicalize()
        .map_err(|_| ProcessFailure::Spawn)?;
    let relative = actual
        .strip_prefix(&root)
        .map_err(|_| ProcessFailure::Spawn)?;
    if !relative
        .to_string_lossy()
        .replace('\\', "/")
        .eq_ignore_ascii_case("Amazon/AWSCLIV2/aws.exe")
    {
        return Err(ProcessFailure::Spawn);
    }
    Ok(actual.into_os_string())
}

#[cfg(all(not(windows), not(test)))]
fn trusted_aws_program() -> Result<OsString, ProcessFailure> {
    ["/usr/local/bin/aws", "/usr/bin/aws"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_file())
        .map(std::path::PathBuf::into_os_string)
        .ok_or(ProcessFailure::Spawn)
}

#[cfg(all(windows, not(test)))]
fn trusted_aws_program() -> Result<OsString, ProcessFailure> {
    verified_windows_aws_program()
}

impl FixedToolOperation {
    fn script_input(&self) -> Result<Option<Vec<u8>>, ProcessFailure> {
        match self {
            Self::LinuxCollector {
                service,
                mount,
                interface,
                ..
            } => {
                let service = crate::helper::adapters::safe_service(service.as_deref())?;
                let mount = crate::helper::adapters::safe_linux_mount(mount.as_deref())?;
                let interface =
                    crate::helper::adapters::safe_identifier(interface.as_deref(), false)?;
                let prelude =
                    format!("service='{service}'\nmount='{mount}'\ninterface='{interface}'\n");
                Ok(Some(
                    [
                        prelude.as_bytes(),
                        include_str!("adapters/linux.sh").as_bytes(),
                    ]
                    .concat(),
                ))
            }
            #[cfg(test)]
            Self::TestLocalLinuxScript { .. } => Ok(Some(
                [
                    b"PATH=/usr/bin:/bin\nservice=''\nmount='/'\ninterface=''\n".as_slice(),
                    include_str!("adapters/linux.sh").as_bytes(),
                ]
                .concat(),
            )),
            _ => Ok(None),
        }
    }
    fn argv(self) -> Result<(OsString, Vec<OsString>), ProcessFailure> {
        let program = match &self {
            Self::WindowsCollector { .. } => "powershell.exe",
            Self::LinuxCollector { .. } => "ssh.exe",
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
            #[cfg(test)]
            Self::TestLocalLinuxScript { .. } => "",
            #[cfg(test)]
            Self::TestLocalWindowsScript { .. } => "",
        };
        #[cfg(windows)]
        let program = match &self {
            Self::WindowsCollector { .. } => windows_system_directory()?
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
                .into_os_string(),
            Self::LinuxCollector { .. } => windows_system_directory()?
                .join("OpenSSH")
                .join("ssh.exe")
                .into_os_string(),
            #[cfg(test)]
            Self::TestLocalWindowsScript { .. } => windows_system_directory()?
                .join("WindowsPowerShell/v1.0/powershell.exe")
                .into_os_string(),
            _ => OsString::from(program),
        };
        #[cfg(test)]
        let program = if matches!(&self, Self::TestPipeParent { .. }) {
            std::env::current_exe()
                .map_err(|_| ProcessFailure::Spawn)?
                .into_os_string()
        } else if let Self::TestLocalLinuxScript { shell } = &self {
            shell.as_os_str().to_os_string()
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
            Self::WindowsCollector {
                host,
                port,
                service,
                mount,
                interface,
            } => {
                use base64::Engine as _;
                let host = crate::helper::adapters::safe_host(&host)?;
                if !matches!(port, 5985 | 5986) {
                    return Err(ProcessFailure::InvalidInvocation);
                }
                let service = crate::helper::adapters::safe_service(service.as_deref())?;
                let mount = crate::helper::adapters::safe_windows_mount(mount.as_deref())?;
                let interface =
                    crate::helper::adapters::safe_identifier(interface.as_deref(), false)?;
                let script = include_str!("adapters/windows.ps1")
                    .replace("__HOST__", &host)
                    .replace("__PORT__", &port.to_string())
                    .replace("__SERVICE__", &service)
                    .replace("__MOUNT__", &mount)
                    .replace("__INTERFACE__", &interface);
                let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-EncodedCommand".into(),
                    encoded.into(),
                ]
            }
            Self::LinuxCollector {
                host, user, port, ..
            } => {
                let host = crate::helper::adapters::safe_host(&host)?;
                let user = crate::helper::adapters::safe_identifier(Some(&user), true)?;
                if port == 0 {
                    return Err(ProcessFailure::InvalidInvocation);
                }
                #[cfg(windows)]
                let ssh_dir = process_token_profile()?.join(".ssh");
                #[cfg(not(windows))]
                return Err(ProcessFailure::Spawn);
                #[cfg(windows)]
                let mut args: Vec<OsString> = vec![
                    "-F".into(),
                    "none".into(),
                    "-o".into(),
                    "BatchMode=yes".into(),
                    "-o".into(),
                    "StrictHostKeyChecking=yes".into(),
                    "-o".into(),
                    "IdentitiesOnly=yes".into(),
                    "-o".into(),
                    "IdentityAgent=none".into(),
                    "-o".into(),
                    "PreferredAuthentications=publickey".into(),
                    "-o".into(),
                    format!(
                        "UserKnownHostsFile={}",
                        ssh_dir.join("known_hosts").display()
                    )
                    .into(),
                    "-o".into(),
                    "GlobalKnownHostsFile=none".into(),
                    "-o".into(),
                    "ConnectTimeout=10".into(),
                    "-o".into(),
                    "ConnectionAttempts=1".into(),
                ];
                #[cfg(windows)]
                for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                    args.push("-i".into());
                    args.push(ssh_dir.join(name).into_os_string());
                }
                #[cfg(windows)]
                args.extend([
                    "-p".into(),
                    port.to_string().into(),
                    "--".into(),
                    format!("{user}@{host}").into(),
                    "sh".into(),
                    "-s".into(),
                ]);
                #[cfg(windows)]
                args
            }
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
            #[cfg(test)]
            Self::TestLocalLinuxScript { .. } => vec!["-s".into()],
            #[cfg(test)]
            Self::TestLocalWindowsScript { denied } => {
                use base64::Engine as _;
                let script = format!(
                    "$script:denyFixture = ${}\n{}\n{}",
                    if denied { "true" } else { "false" },
                    include_str!("adapters/windows-fixture.ps1"),
                    include_str!("adapters/windows.ps1")
                        .replace("__HOST__", "fixture.invalid")
                        .replace("__PORT__", "5985")
                        .replace("__SERVICE__", "FixtureService")
                        .replace("__MOUNT__", "C:")
                        .replace("__INTERFACE__", "FixtureInterface")
                );
                let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-EncodedCommand".into(),
                    base64::engine::general_purpose::STANDARD
                        .encode(utf16)
                        .into(),
                ]
            }
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
    #[cfg(test)]
    let local_shell_path = match &operation {
        FixedToolOperation::TestLocalLinuxScript { shell } => {
            shell.parent().map(std::path::Path::to_path_buf)
        }
        _ => None,
    };
    #[cfg(windows)]
    let ssh_profile = if matches!(&operation, FixedToolOperation::LinuxCollector { .. }) {
        Some(process_token_profile()?.into_os_string())
    } else {
        None
    };
    #[cfg(windows)]
    let system_collector = matches!(
        &operation,
        FixedToolOperation::WindowsCollector { .. } | FixedToolOperation::LinuxCollector { .. }
    );
    #[cfg(test)]
    let system_collector = system_collector
        || matches!(
            &operation,
            FixedToolOperation::TestLocalWindowsScript { .. }
        );
    let script_input = operation.script_input()?;
    let (program, args) = operation.argv()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(if script_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
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
    #[cfg(windows)]
    if let Some(profile) = ssh_profile.filter(|p| std::path::Path::new(p).is_absolute()) {
        command.env("USERPROFILE", profile);
    }
    #[cfg(test)]
    if let Some(path) = pipe_pid_file {
        command
            .env("RELAYNE_PIPE_FIXTURE", "1")
            .env("RELAYNE_PIPE_PID_FILE", path);
    }
    #[cfg(test)]
    if let Some(path) = local_shell_path {
        command.env("PATH", path);
    }
    #[cfg(windows)]
    {
        command
            .creation_flags(0x08000000 | windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
        if system_collector {
            let system = windows_system_directory()?;
            let root = system.parent().ok_or(ProcessFailure::Spawn)?;
            command.current_dir(&system).env("SystemRoot", root);
        } else if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
    }
    let expires_at = tokio::time::Instant::now() + deadline;
    let mut child = command.spawn().map_err(|_| ProcessFailure::Spawn)?;
    if let Some(input) = script_input {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().ok_or(ProcessFailure::Spawn)?;
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
        });
    }
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
    fn fixed_system_collectors_bind_endpoint_and_reject_selectors() {
        let windows = FixedToolOperation::WindowsCollector {
            host: "host.example".into(),
            port: 5986,
            service: Some("Spooler".into()),
            mount: Some("C:".into()),
            interface: Some("Ethernet_1".into()),
        };
        let (program, args) = windows.argv().unwrap();
        assert_eq!(
            std::path::Path::new(&program),
            windows_system_directory()
                .unwrap()
                .join("WindowsPowerShell/v1.0/powershell.exe")
        );
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(args.last().unwrap().to_str().unwrap())
            .unwrap();
        let script = String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(script.contains("https://host.example:5986/wsman"));
        assert!(script.contains("-Authentication Negotiate"));
        assert!(
            FixedToolOperation::WindowsCollector {
                host: "host;id".into(),
                port: 5985,
                service: None,
                mount: None,
                interface: None
            }
            .argv()
            .is_err()
        );
        assert!(
            FixedToolOperation::WindowsCollector {
                host: "host".into(),
                port: 3389,
                service: None,
                mount: None,
                interface: None
            }
            .argv()
            .is_err()
        );

        let linux = FixedToolOperation::LinuxCollector {
            host: "linux.example".into(),
            user: "deploy".into(),
            port: 2222,
            service: Some("sshd".into()),
            mount: Some("/var/lib/data".into()),
            interface: Some("eth0".into()),
        };
        let input = linux.script_input().unwrap().unwrap();
        let script = std::str::from_utf8(&input).unwrap();
        assert!(script.starts_with("service='sshd'\nmount='/var/lib/data'\ninterface='eth0'\n"));
        let (ssh_program, args) = linux.argv().unwrap();
        assert_eq!(
            std::path::Path::new(&ssh_program),
            windows_system_directory().unwrap().join("OpenSSH/ssh.exe")
        );
        let profile = process_token_profile().unwrap();
        assert!(args.iter().any(|arg| arg
            == &OsString::from(format!(
                "UserKnownHostsFile={}",
                profile.join(".ssh").join("known_hosts").display()
            ))));
        assert!(args.iter().any(|arg| arg == "IdentitiesOnly=yes"));
        assert!(args.iter().any(|arg| arg == "IdentityAgent=none"));
        assert_eq!(&args[..2], &[OsString::from("-F"), OsString::from("none")]);
        assert!(args.iter().any(|arg| arg == "StrictHostKeyChecking=yes"));
        assert!(args.iter().any(|arg| arg == "deploy@linux.example"));
        assert!(
            FixedToolOperation::LinuxCollector {
                host: "linux.example".into(),
                user: "a;id".into(),
                port: 22,
                service: None,
                mount: None,
                interface: None
            }
            .argv()
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn aws_program_does_not_follow_mutated_programfiles_environment() {
        let root = system_program_files().unwrap();
        let before = verified_windows_aws_program();
        let previous = std::env::var_os("ProgramFiles");
        // SAFETY: this test runs with --test-threads=1 and restores the variable below.
        unsafe {
            std::env::set_var(
                "ProgramFiles",
                std::env::temp_dir().join("attacker-selected"),
            )
        };
        assert_eq!(system_program_files().unwrap(), root);
        assert_eq!(verified_windows_aws_program(), before);
        // SAFETY: restore the process environment before leaving this serial test.
        unsafe {
            if let Some(previous) = previous {
                std::env::set_var("ProgramFiles", previous)
            } else {
                std::env::remove_var("ProgramFiles")
            }
        }
    }
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
    fn profile_and_executable_shadows_do_not_change_collector_identity() {
        if std::env::var_os("RELAYNE_SHADOW_FIXTURE").is_some() {
            let token_profile = process_token_profile().unwrap();
            assert_ne!(
                std::env::var_os("USERPROFILE"),
                Some(token_profile.clone().into_os_string())
            );
            let (ssh, args) = FixedToolOperation::LinuxCollector {
                host: "host.example".into(),
                user: "operator".into(),
                port: 22,
                service: None,
                mount: None,
                interface: None,
            }
            .argv()
            .unwrap();
            assert_eq!(
                std::path::Path::new(&ssh),
                windows_system_directory().unwrap().join("OpenSSH/ssh.exe")
            );
            assert!(args.iter().any(|arg| arg
                == &OsString::from(format!(
                    "UserKnownHostsFile={}",
                    token_profile.join(".ssh").join("known_hosts").display()
                ))));
            let (powershell, _) = FixedToolOperation::WindowsCollector {
                host: "host.example".into(),
                port: 5985,
                service: None,
                mount: None,
                interface: None,
            }
            .argv()
            .unwrap();
            assert_eq!(
                std::path::Path::new(&powershell),
                windows_system_directory()
                    .unwrap()
                    .join("WindowsPowerShell/v1.0/powershell.exe")
            );
            return;
        }
        let shadow =
            std::env::temp_dir().join(format!("relayne-tool-shadow-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&shadow).unwrap();
        for file in ["ssh.exe", "powershell.exe"] {
            std::fs::write(shadow.join(file), b"shadow").unwrap();
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "helper::process::tests::profile_and_executable_shadows_do_not_change_collector_identity", "--nocapture"])
            .env("RELAYNE_SHADOW_FIXTURE", "1")
            .env("USERPROFILE", &shadow)
            .env("PATH", format!("{};{}", shadow.display(), std::env::var("PATH").unwrap_or_default()))
            .current_dir(&shadow).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        for file in ["ssh.exe", "powershell.exe"] {
            std::fs::remove_file(shadow.join(file)).unwrap();
        }
        std::fs::remove_dir(&shadow).unwrap();
    }

    #[tokio::test]
    async fn guarded_local_script_obeys_output_cap_and_deadline() {
        let shell = std::path::PathBuf::from(r"C:\Program Files\Git\usr\bin\sh.exe");
        if !shell.is_file() {
            return;
        }
        let failure = run_with_limit(
            FixedToolOperation::TestLocalLinuxScript {
                shell: shell.clone(),
            },
            CancellationToken::new(),
            Duration::from_secs(30),
            1,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failure, ProcessFailure::OutputLimit);
        let failure = run_with_limit(
            FixedToolOperation::TestLocalLinuxScript { shell },
            CancellationToken::new(),
            Duration::from_millis(1),
            MAX_TOOL_STDOUT,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failure, ProcessFailure::TimedOut);
    }

    #[test]
    fn pipe_parent_fixture() {
        if std::env::var_os("RELAYNE_PIPE_FIXTURE").is_none() {
            return;
        }
        let child =
            std::process::Command::new(windows_system_directory().unwrap().join("ping.exe"))
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
