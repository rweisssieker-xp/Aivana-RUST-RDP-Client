//! Deliberate, noninteractive remote jobs. No authentication or I/O at construction.
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

pub const OUTPUT_LIMIT: usize = 128 * 1024;
pub const JOB_LIMIT: usize = 32;
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
}
impl Endpoint {
    pub fn new(host: &str, user: &str, port: u16) -> Result<Self, String> {
        if host.is_empty()
            || host.len() > 253
            || host.starts_with('-')
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
            || port == 0
        {
            return Err("Invalid host or port (a DNS name or IP address is required).".into());
        }
        if user.len() > 128
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || user.starts_with('-')
        {
            return Err(
                "SSH usernames may contain only letters, digits, periods, underscores, and hyphens.".into(),
            );
        }
        Ok(Self {
            host: host.into(),
            user: user.into(),
            port,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query {
    Inventory,
    Services,
    Processes,
    Events,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}
#[derive(Clone, Debug)]
pub enum Request {
    Ssh {
        command: String,
    },
    WinRm(Query),
    Service {
        name: String,
        action: ServiceAction,
    },
    List {
        remote: String,
    },
    Upload {
        local: String,
        remote: String,
    },
    Download {
        remote: String,
        local: String,
    },
    Transfer {
        local: String,
        remote: String,
        upload: bool,
        resume: bool,
        recursive: bool,
    },
}
#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: String,
    pub source: String,
}
pub fn sftp_path(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 2048
        || value.starts_with('-')
        || value
            .chars()
            .any(|c| c.is_control() || "\"*?[]{}!`".contains(c))
    {
        return Err("The file path is empty or contains control characters or SFTP patterns.".into());
    }
    Ok(format!("\"{}\"", value.replace('\\', "/")))
}
impl Request {
    pub fn build(&self, endpoint: &Endpoint) -> Result<CommandSpec, String> {
        Endpoint::new(&endpoint.host, &endpoint.user, endpoint.port)?;
        if let Self::Transfer {
            local,
            remote,
            upload,
            resume,
            recursive,
        } = self
        {
            let base = if *upload {
                Self::Upload {
                    local: local.clone(),
                    remote: remote.clone(),
                }
            } else {
                Self::Download {
                    local: local.clone(),
                    remote: remote.clone(),
                }
            };
            let mut spec = base.build(endpoint)?;
            let verb = if *upload { "put" } else { "get" };
            let flags = format!(
                "{}{}",
                if *resume { " -a" } else { "" },
                if *recursive { " -R" } else { "" }
            );
            let (source, destination) = if *upload {
                (local, remote)
            } else {
                (remote, local)
            };
            spec.stdin = format!(
                "{verb}{flags} {} {}\n",
                sftp_path(source)?,
                sftp_path(destination)?
            );
            return Ok(spec);
        }
        if let Self::Upload { local, .. } | Self::Download { local, .. } = self {
            if !std::path::Path::new(local).is_absolute() {
                return Err("The local file path must be absolute.".into());
            }
        }
        let mut spec = CommandSpec {
            program: "ssh.exe".into(),
            args: vec![],
            stdin: String::new(),
            source: endpoint.host.clone(),
        };
        match self {
            Self::Transfer { .. } => unreachable!("Transfer options handled before base request"),
            Self::Ssh { command } => {
                if command.trim().is_empty() || command.len() > 8192 || command.contains('\0') {
                    return Err("The SSH command is empty or too long.".into());
                }
                spec.args = ssh_options();
                spec.args.extend(["-p".into(), endpoint.port.to_string()]);
                if !endpoint.user.is_empty() {
                    spec.args.extend(["-l".into(), endpoint.user.clone()]);
                }
                spec.args.extend([endpoint.host.clone(), command.clone()]);
            }
            Self::WinRm(query) => {
                let body = match query {
                    Query::Inventory => {
                        "Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Caption,Version,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory"
                    }
                    Query::Services => {
                        "Get-Service | Select-Object Name,DisplayName,Status,StartType"
                    }
                    Query::Processes => {
                        "Get-Process | Select-Object -First 500 Id,ProcessName,CPU,WorkingSet64"
                    }
                    Query::Events => {
                        "Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message"
                    }
                };
                winrm(&mut spec, endpoint, body);
            }
            Self::Service { name, action } => {
                if name.is_empty()
                    || name.len() > 128
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                {
                    return Err("Invalid service name.".into());
                }
                let (verb, expected) = match action {
                    ServiceAction::Start => ("Start", "Running"),
                    ServiceAction::Stop => ("Stop", "Stopped"),
                    ServiceAction::Restart => ("Restart", "Running"),
                };
                winrm(
                    &mut spec,
                    endpoint,
                    &format!(
                        "{verb}-Service -Name '{name}' -ErrorAction Stop; $s=Get-Service -Name '{name}' -ErrorAction Stop; $s.WaitForStatus('{expected}',[TimeSpan]::FromSeconds(30)); $s.Refresh(); $s | Select-Object Name,Status"
                    ),
                );
            }
            Self::List { remote } => {
                spec.stdin = format!("ls -l {}\n", sftp_path(remote)?);
            }
            Self::Upload { local, remote } => {
                spec.stdin = format!("put {} {}\n", sftp_path(local)?, sftp_path(remote)?);
            }
            Self::Download { remote, local } => {
                spec.stdin = format!("get {} {}\n", sftp_path(remote)?, sftp_path(local)?);
            }
        }
        if matches!(
            self,
            Self::List { .. } | Self::Upload { .. } | Self::Download { .. }
        ) {
            spec.program = "sftp.exe".into();
            spec.args = ssh_options();
            spec.args.extend([
                "-P".into(),
                endpoint.port.to_string(),
                "-b".into(),
                "-".into(),
            ]);
            let host = if endpoint.host.contains(':') {
                format!("[{}]", endpoint.host)
            } else {
                endpoint.host.clone()
            };
            spec.args.push(if endpoint.user.is_empty() {
                host
            } else {
                format!("{}@{host}", endpoint.user)
            });
        }
        Ok(spec)
    }
}
fn ssh_options() -> Vec<String> {
    [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
pub(crate) fn winrm(spec: &mut CommandSpec, endpoint: &Endpoint, body: &str) {
    spec.program = "powershell.exe".into();
    spec.args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    spec.stdin = format!(
        "$ErrorActionPreference='Stop'\n[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)\ntry {{ Invoke-Command -ComputerName '{}' -Authentication Negotiate -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 45000) -ScriptBlock {{ $ErrorActionPreference='Stop'; {} }} -ErrorAction Stop | ConvertTo-Json -Depth 4 -Compress; exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}\n",
        endpoint.host, body
    );
}
impl CommandSpec {
    pub fn preview(&self) -> String {
        format!(
            "Source: {}\n{} {:?}\n{}",
            self.source, self.program, self.args, self.stdin
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed(String),
    Cancelled,
    TimedOut,
}
impl JobStatus {
    pub fn terminal(&self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}
#[derive(Clone, Debug)]
pub struct JobResult {
    pub status: JobStatus,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub finished: SystemTime,
}
pub struct Job {
    pub id: u64,
    pub spec: CommandSpec,
    pub created: SystemTime,
    pub status: JobStatus,
    pub result: Option<JobResult>,
    cancel: Arc<AtomicBool>,
    receiver: Option<mpsc::Receiver<JobResult>>,
}
#[derive(Default)]
pub struct JobQueue {
    pub jobs: Vec<Job>,
    next: u64,
}
impl Drop for JobQueue {
    fn drop(&mut self) {
        for job in &self.jobs {
            job.cancel();
        }
    }
}
impl JobQueue {
    /// Only stdout from an exact endpoint+path List command can be a listing.
    pub fn latest_listing(&self, endpoint: &Endpoint, remote: &str) -> Option<&Job> {
        let expected = Request::List {
            remote: remote.into(),
        }
        .build(endpoint)
        .ok()?;
        self.jobs.iter().rev().find(|job| {
            job.status == JobStatus::Completed
                && job
                    .result
                    .as_ref()
                    .is_some_and(|r| r.status == JobStatus::Completed)
                && job.spec.program == expected.program
                && job.spec.args == expected.args
                && job.spec.stdin == expected.stdin
                && job.spec.source == expected.source
        })
    }
    pub fn enqueue(&mut self, spec: CommandSpec) -> Result<u64, String> {
        if self.jobs.len() >= JOB_LIMIT {
            return Err("The job list is full; remove completed jobs.".into());
        }
        self.next += 1;
        self.jobs.push(Job {
            id: self.next,
            spec,
            created: SystemTime::now(),
            status: JobStatus::Queued,
            result: None,
            cancel: Arc::new(AtomicBool::new(false)),
            receiver: None,
        });
        Ok(self.next)
    }
    pub fn poll(&mut self) {
        for job in &mut self.jobs {
            if let Some(rx) = &job.receiver {
                match rx.try_recv() {
                    Ok(result) => {
                        job.status = result.status.clone();
                        job.result = Some(result);
                        job.receiver = None;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        job.status = JobStatus::Failed("The worker ended without a result".into());
                        job.receiver = None;
                    }
                    Err(_) => {}
                }
            }
            if job.status == JobStatus::Queued && job.cancel.load(Ordering::Relaxed) {
                job.status = JobStatus::Cancelled;
            }
        }
        if self.jobs.iter().any(|j| j.status == JobStatus::Running) {
            return;
        }
        if let Some(job) = self.jobs.iter_mut().find(|j| j.status == JobStatus::Queued) {
            let (tx, rx) = mpsc::channel();
            job.receiver = Some(rx);
            job.status = JobStatus::Running;
            let spec = job.spec.clone();
            let cancel = job.cancel.clone();
            thread::spawn(move || {
                let _ = tx.send(run(spec, cancel, Duration::from_secs(120)));
            });
        }
    }
    pub fn clear_finished(&mut self) {
        self.jobs.retain(|j| !j.status.terminal());
    }
}
impl Job {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    truncated: bool,
}
#[cfg(windows)]
trait CaptureRead: Read + std::os::windows::io::AsRawHandle + Send + 'static {}
#[cfg(windows)]
impl<T: Read + std::os::windows::io::AsRawHandle + Send + 'static> CaptureRead for T {}
#[cfg(not(windows))]
trait CaptureRead: Read + Send + 'static {}
#[cfg(not(windows))]
impl<T: Read + Send + 'static> CaptureRead for T {}
fn capture(
    mut reader: impl CaptureRead,
    stop: Arc<AtomicBool>,
) -> (Arc<Mutex<Output>>, thread::JoinHandle<()>) {
    let data = Arc::new(Mutex::new(Output::default()));
    let output = data.clone();
    let handle = thread::spawn(move || {
        let mut buf = [0; 4096];
        loop {
            #[cfg(windows)]
            let available = {
                #[link(name = "kernel32")]
                unsafe extern "system" {
                    fn PeekNamedPipe(
                        handle: *mut std::ffi::c_void,
                        buffer: *mut std::ffi::c_void,
                        size: u32,
                        read: *mut u32,
                        available: *mut u32,
                        left: *mut u32,
                    ) -> i32;
                }
                let mut available = 0;
                // The capture worker owns the sole read handle. Peek does not wait for data.
                let ok = unsafe {
                    PeekNamedPipe(
                        reader.as_raw_handle(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    break;
                }
                if stop.load(Ordering::Acquire) {
                    output.lock().unwrap().truncated |= available > 0;
                    break;
                }
                if available == 0 {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                (available as usize).min(buf.len())
            };
            #[cfg(not(windows))]
            let available = {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                buf.len()
            };
            let n = match reader.read(&mut buf[..available]) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            let mut output = output.lock().unwrap();
            let keep = n.min(OUTPUT_LIMIT - output.bytes.len());
            output.bytes.extend_from_slice(&buf[..keep]);
            output.truncated |= keep < n;
        }
    });
    (data, handle)
}
fn hidden(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    let _ = command;
}
fn terminate(child: &mut std::process::Child) {
    #[cfg(windows)]
    {
        let mut command = Command::new("taskkill.exe");
        command
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        hidden(&mut command);
        if let Ok(mut killer) = command.spawn() {
            let start = Instant::now();
            loop {
                if !matches!(killer.try_wait(), Ok(None)) {
                    break;
                }
                if start.elapsed() > Duration::from_secs(2) {
                    let _ = killer.kill();
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    let _ = child.kill();
}
fn run(spec: CommandSpec, cancel: Arc<AtomicBool>, timeout: Duration) -> JobResult {
    let mut result = JobResult {
        status: JobStatus::Running,
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        finished: SystemTime::now(),
    };
    if cancel.load(Ordering::Relaxed) {
        result.status = JobStatus::Cancelled;
        return result;
    }
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hidden(&mut command);
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            result.status = JobStatus::Failed(format!("{}: {e}", spec.program));
            return result;
        }
    };
    let stop_capture = Arc::new(AtomicBool::new(false));
    let (out, out_done) = capture(child.stdout.take().unwrap(), stop_capture.clone());
    let (err, err_done) = capture(child.stderr.take().unwrap(), stop_capture.clone());
    if let Some(mut stdin) = child.stdin.take() {
        thread::spawn(move || {
            let _ = stdin.write_all(spec.stdin.as_bytes());
        });
    }
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            terminate(&mut child);
            result.status = JobStatus::Cancelled;
            break;
        }
        if start.elapsed() >= timeout {
            terminate(&mut child);
            result.status = JobStatus::TimedOut;
            break;
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                result.status = if exit.success() {
                    JobStatus::Completed
                } else {
                    JobStatus::Failed(format!("Process ended: {exit}"))
                };
                break;
            }
            Ok(None) => {}
            Err(e) => {
                terminate(&mut child);
                result.status = JobStatus::Failed(e.to_string());
                break;
            }
        }
        thread::sleep(Duration::from_millis(30));
    }
    // Never block indefinitely on inherited pipes or an unresponsive child.
    let cleanup = Instant::now();
    while matches!(child.try_wait(), Ok(None)) && cleanup.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(20));
    }
    let drain = Instant::now();
    while (!out_done.is_finished() || !err_done.is_finished())
        && drain.elapsed() < Duration::from_millis(500)
    {
        thread::sleep(Duration::from_millis(10));
    }
    let out_closed = out_done.is_finished();
    let err_closed = err_done.is_finished();
    stop_capture.store(true, Ordering::Release);
    // On Windows, all reads use PeekNamedPipe and consume only already-available
    // bytes. Joining therefore closes both owned read handles even if descendants
    // indefinitely retain the write end. No abandoned capture workers accumulate.
    #[cfg(windows)]
    {
        let _ = out_done.join();
        let _ = err_done.join();
    }
    let out = out.lock().unwrap();
    let err = err.lock().unwrap();
    result.stdout = String::from_utf8_lossy(&out.bytes).into_owned();
    result.stderr = String::from_utf8_lossy(&err.bytes).into_owned();
    result.truncated = out.truncated || err.truncated || !out_closed || !err_closed;
    result.finished = SystemTime::now();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_recursive_specs_and_listing_identity() {
        let endpoint = Endpoint::new("host", "alice", 22).unwrap();
        let local = if cfg!(windows) {
            "C:/tmp/file"
        } else {
            "/tmp/file"
        };
        for upload in [true, false] {
            for resume in [true, false] {
                for recursive in [true, false] {
                    let spec = Request::Transfer {
                        local: local.into(),
                        remote: "/remote file".into(),
                        upload,
                        resume,
                        recursive,
                    }
                    .build(&endpoint)
                    .unwrap();
                    assert!(spec.stdin.starts_with(if upload { "put " } else { "get " }));
                    assert_eq!(spec.stdin.contains(" -a"), resume);
                    assert_eq!(spec.stdin.contains(" -R"), recursive);
                    assert!(spec.stdin.contains("\"/remote file\""));
                }
            }
        }
        assert!(
            Request::Transfer {
                local: "relative".into(),
                remote: "/remote".into(),
                upload: true,
                resume: true,
                recursive: true
            }
            .build(&endpoint)
            .is_err()
        );
        assert!(
            Request::Transfer {
                local: local.into(),
                remote: "/remote\n!evil".into(),
                upload: false,
                resume: true,
                recursive: false
            }
            .build(&endpoint)
            .is_err()
        );
        let mut queue = JobQueue::default();
        queue
            .enqueue(
                Request::List {
                    remote: "/files".into(),
                }
                .build(&endpoint)
                .unwrap(),
            )
            .unwrap();
        assert!(queue.latest_listing(&endpoint, "/files").is_none());
        queue.jobs[0].status = JobStatus::Completed;
        queue.jobs[0].result = Some(JobResult {
            status: JobStatus::Completed,
            stdout: "actual listing".into(),
            stderr: "not a listing".into(),
            truncated: false,
            finished: SystemTime::now(),
        });
        assert_eq!(
            queue
                .latest_listing(&endpoint, "/files")
                .unwrap()
                .result
                .as_ref()
                .unwrap()
                .stdout,
            "actual listing"
        );
        assert!(queue.latest_listing(&endpoint, "/other").is_none());
        assert!(
            queue
                .latest_listing(&Endpoint::new("host", "bob", 22).unwrap(), "/files")
                .is_none()
        );
        assert!(
            queue
                .latest_listing(&Endpoint::new("host", "alice", 23).unwrap(), "/files")
                .is_none()
        );
        assert!(
            queue
                .latest_listing(&Endpoint::new("other", "alice", 22).unwrap(), "/files")
                .is_none()
        );
        queue.jobs[0].result.as_mut().unwrap().status = JobStatus::Failed("no access".into());
        assert!(queue.latest_listing(&endpoint, "/files").is_none());
    }
    #[cfg(windows)]
    fn stub(script: &str) -> CommandSpec {
        CommandSpec {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script.into(),
            ],
            stdin: String::new(),
            source: "local-test".into(),
        }
    }
    #[test]
    #[cfg(windows)]
    fn timeout_cancel_and_output_are_bounded() {
        let start = Instant::now();
        let result = run(
            stub("Start-Sleep -Seconds 30"),
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(100),
        );
        assert_eq!(result.status, JobStatus::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(8));
        let flag = Arc::new(AtomicBool::new(false));
        let signal = flag.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            signal.store(true, Ordering::Relaxed);
        });
        assert_eq!(
            run(
                stub("Start-Sleep -Seconds 30"),
                flag,
                Duration::from_secs(20)
            )
            .status,
            JobStatus::Cancelled
        );
        let result = run(
            stub("[Console]::Write('x' * 200000); [Console]::Error.Write('y' * 200000)"),
            Arc::new(AtomicBool::new(false)),
            Duration::from_secs(10),
        );
        assert_eq!(result.status, JobStatus::Completed);
        assert!(result.truncated);
        assert_eq!(result.stdout.len(), OUTPUT_LIMIT);
        assert_eq!(result.stderr.len(), OUTPUT_LIMIT);
    }
    #[test]
    #[cfg(windows)]
    fn queue_lifecycle_and_nonzero_exit() {
        let mut queue = JobQueue::default();
        queue
            .enqueue(stub("[Console]::Write('actual-result')"))
            .unwrap();
        queue.enqueue(stub("exit 7")).unwrap();
        let start = Instant::now();
        while queue.jobs.iter().any(|j| !j.status.terminal()) {
            queue.poll();
            assert!(start.elapsed() < Duration::from_secs(15));
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            queue.jobs[0].result.as_ref().unwrap().stdout,
            "actual-result"
        );
        assert!(matches!(queue.jobs[1].status, JobStatus::Failed(_)));
        queue.clear_finished();
        assert!(queue.jobs.is_empty());
        queue.enqueue(stub("exit 0")).unwrap();
        queue.jobs[0].cancel();
        queue.poll();
        assert_eq!(queue.jobs[0].status, JobStatus::Cancelled);
    }
    #[test]
    #[cfg(windows)]
    fn inherited_stdout_after_parent_exit_closes_capture_workers() {
        let start = Instant::now();
        let result = run(
            stub(
                "$p=[Diagnostics.ProcessStartInfo]::new(); $p.FileName='powershell.exe'; $p.Arguments='-NoProfile -NonInteractive -Command Start-Sleep -Seconds 8'; $p.UseShellExecute=$false; $p.CreateNoWindow=$true; $child=[Diagnostics.Process]::Start($p); [Console]::WriteLine($child.Id); exit 0",
            ),
            Arc::new(AtomicBool::new(false)),
            Duration::from_secs(15),
        );
        assert_eq!(result.status, JobStatus::Completed);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(
            result.truncated,
            "descendant must keep a capture pipe open for this regression test"
        );
        // run only returns after joining BOTH capture threads, despite the child
        // retaining its inherited standard handles. Clean up this local stub.
        let pid = result.stdout.trim().parse::<u32>().unwrap();
        let mut cleanup = Command::new("taskkill.exe");
        cleanup
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        hidden(&mut cleanup);
        let _ = cleanup.status();
    }
    #[test]
    fn rejects_injected_endpoints_and_sftp_paths() {
        for host in ["-oProxyCommand=evil", "host;evil", "host\nother", ""] {
            assert!(Endpoint::new(host, "admin", 22).is_err());
        }
        assert!(sftp_path("/safe\n!evil").is_err());
        assert!(sftp_path("/safe*wildcard").is_err());
        assert!(sftp_path("/safe folder/file.txt").is_ok());
    }
    #[test]
    fn ssh_is_noninteractive_and_strict() {
        let endpoint = Endpoint::new("server.example", "admin", 2222).unwrap();
        let spec = Request::Ssh {
            command: "uname -a".into(),
        }
        .build(&endpoint)
        .unwrap();
        assert!(spec.args.contains(&"StrictHostKeyChecking=yes".into()));
        assert!(spec.args.contains(&"BatchMode=yes".into()));
        assert_eq!(spec.args.last().unwrap(), "uname -a");
    }
    #[test]
    fn service_action_is_typed_and_verified() {
        let endpoint = Endpoint::new("server", "admin", 22).unwrap();
        assert!(
            Request::Service {
                name: "Spooler';evil".into(),
                action: ServiceAction::Stop
            }
            .build(&endpoint)
            .is_err()
        );
        let spec = Request::Service {
            name: "Spooler".into(),
            action: ServiceAction::Stop,
        }
        .build(&endpoint)
        .unwrap();
        assert!(spec.stdin.contains("WaitForStatus"));
        assert!(spec.stdin.contains("ConvertTo-Json"));
    }
    #[test]
    fn transfer_paths_are_absolute_and_quoted() {
        let endpoint = Endpoint::new("server", "admin", 22).unwrap();
        assert!(
            Request::Upload {
                local: "relative.txt".into(),
                remote: "/target".into()
            }
            .build(&endpoint)
            .is_err()
        );
        let local = if cfg!(windows) {
            "C:/tmp/local file.txt"
        } else {
            "/tmp/local file.txt"
        };
        let spec = Request::Upload {
            local: local.into(),
            remote: "/target file.txt".into(),
        }
        .build(&endpoint)
        .unwrap();
        assert!(spec.stdin.contains("\"/target file.txt\""));
        assert!(spec.args.contains(&"-b".into()));
    }
}
