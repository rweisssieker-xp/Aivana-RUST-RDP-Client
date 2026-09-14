//! Hyper-V lab adapter. All mutations are explicit; journals are CurrentUser DPAPI protected.
use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub mod change_trial;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preflight {
    #[serde(rename = "hyperV")]
    pub hyper_v: bool,
    pub administrator: bool,
    pub vmms: String,
    #[serde(rename = "powerShellDirect")]
    pub power_shell_direct: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Journal {
    pub id: String,
    pub name: String,
    pub template: String,
    pub directory: String,
    #[serde(default)]
    pub vm_id: String,
    #[serde(default)]
    pub switch_id: String,
    pub phase: String,
    #[serde(default)]
    pub detail: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbe {
    pub url: String,
    pub expected_status: u16,
    pub body_marker: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub followups: Vec<crate::execution::HttpGetStep>,
}
impl HealthProbe {
    pub fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            anyhow::ensure!(
                self.followups.is_empty(),
                "Follow-up checks require a base URL"
            );
            return Ok(());
        }
        let u = reqwest::Url::parse(&self.url)?;
        crate::execution::HealthCheck::Http {
            port: u.port_or_known_default().unwrap_or(0),
            tls: u.scheme() == "https",
            path: u.path().into(),
            status: self.expected_status,
            contains: self.body_marker.clone(),
            followups: self.followups.clone(),
        }
        .validate()?;
        if self.url.len() > 2048
            || self.body_marker.len() > 1024
            || !(100..=599).contains(&self.expected_status)
            || !matches!(u.scheme(), "http" | "https")
            || !matches!(
                u.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            )
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
        {
            bail!(
                "HTTP(S) probe: localhost or loopback IP only, without credentials/query/fragment; valid TLS certificate required"
            );
        }
        Ok(())
    }
}
fn read_journal(path: &std::path::Path) -> Result<Journal> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        bail!("Lab journal exceeds 1 MiB");
    }
    Ok(serde_json::from_slice(&crate::security::unprotect_secret(
        &bytes,
    )?)?)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Preflight,
    Create,
    Test,
    Cleanup,
}
impl Action {
    fn key(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Create => "create",
            Self::Test => "test",
            Self::Cleanup => "cleanup",
        }
    }
}
pub fn root() -> Result<PathBuf> {
    Ok(crate::security::app_data_file("test-labs")?)
}
pub fn journals() -> Result<Vec<Journal>> {
    let root = root()?;
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut result: Vec<Journal> = vec![];
    for entry in std::fs::read_dir(root)? {
        let p = entry?.path().join("journal.dpapi");
        if p.is_file() {
            result.push(read_journal(&p)?);
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
pub fn new_lab(template: &str) -> Result<Journal> {
    let p = std::fs::canonicalize(template).context("Offline VHDX not found")?;
    if p.extension()
        .and_then(|s| s.to_str())
        .is_none_or(|s| !s.eq_ignore_ascii_case("vhdx"))
    {
        bail!("A VHDX template is required");
    }
    let id = uuid::Uuid::new_v4().to_string();
    Ok(Journal {
        id: id.clone(),
        name: format!("Relayne-Lab-{id}"),
        template: p.to_string_lossy().trim_start_matches(r"\\?\").into(),
        directory: root()?.join(&id).to_string_lossy().into(),
        vm_id: String::new(),
        switch_id: String::new(),
        phase: "planned".into(),
        detail: String::new(),
    })
}
pub fn execute(
    action: Action,
    journal: Option<Journal>,
    user: String,
    password: String,
    service: String,
    desired_running: bool,
    health: HealthProbe,
) -> Result<String> {
    // Keep this OS-owned lock alive across the entire adapter operation.
    let _lab_lock = if action == Action::Preflight {
        None
    } else {
        Some(lock_lab(&journal.as_ref().context("No lab selected")?.id)?)
    };
    execute_with_binding(
        action,
        journal,
        user,
        password,
        service,
        desired_running,
        health,
        None,
        Default::default(),
    )
}
// Caller owns the lab lock; the bound wrapper retains it through receipt persistence.
fn execute_with_binding(
    action: Action,
    journal: Option<Journal>,
    user: String,
    password: String,
    service: String,
    desired_running: bool,
    health: HealthProbe,
    bound_request: Option<String>,
    http_values: crate::execution::http_health::Values,
) -> Result<String> {
    if !cfg!(windows) {
        bail!("Hyper-V labs require Windows");
    }
    if action != Action::Preflight {
        let j = journal.as_ref().context("No lab selected")?;
        let id = uuid::Uuid::parse_str(&j.id)?;
        if j.directory != root()?.join(id.to_string()).to_string_lossy()
            || j.name != format!("Relayne-Lab-{id}")
        {
            bail!("Invalid lab ownership evidence");
        }
    }
    if action == Action::Test
        && (user.trim().is_empty()
            || user.len() > 256
            || password.is_empty()
            || password.len() > 4096
            || service.is_empty()
            || service.len() > 128
            || service.eq_ignore_ascii_case("vmicvmsession")
            || !service
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_- .".contains(&c)))
    {
        bail!("Guest credentials and a valid service name required");
    }
    if action == Action::Test {
        health.validate()?;
        for step in &health.followups {
            step.options.validate_values(&http_values)?;
        }
    }
    let journal = if matches!(action, Action::Test | Action::Cleanup) {
        let j = journal.context("No lab")?;
        let current = read_journal(&PathBuf::from(&j.directory).join("journal.dpapi"))?;
        if current.id != j.id || current.directory != j.directory || current.name != j.name {
            bail!("Journal identity changed");
        }
        Some(current)
    } else {
        journal
    };
    let payload = serde_json::json!({"action":action.key(),"lab":journal,"user":user,"password":password,"service":service,"desiredRunning":desired_running,"health":health,"boundRequest":bound_request,"httpValues":http_values});
    let output = run_script(SCRIPT, payload)?;
    if action == Action::Preflight {
        let _: Preflight =
            serde_json::from_str(&output).context("Invalid Hyper-V preflight report")?;
    }
    Ok(output)
}

fn run_script(script: &str, payload: serde_json::Value) -> Result<String> {
    let mut command = Command::new("powershell.exe");
    // Windows PowerShell must resolve its own modules, not inherited PowerShell 7 modules.
    command.env_remove("PSModulePath");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_bootstrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .context("stdin")?
        .write_all(&script_envelope(script, payload)?)?;
    let out = child.stdout.take().context("stdout")?;
    let err = child.stderr.take().context("stderr")?;
    let reader = |mut stream: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stream.by_ref().take(128 * 1024).read_to_string(&mut s);
            std::io::copy(&mut stream, &mut std::io::sink()).ok();
            s
        })
    };
    let output = reader(Box::new(out));
    let error = reader(Box::new(err));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > Duration::from_secs(180) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Timeout: review the lab journal; resources may remain.");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let text = output.join().unwrap_or_default();
    let errors = error.join().unwrap_or_default();
    if !status.success() {
        bail!(
            "{}",
            crate::security::redact_secret_text(&format!("{text}\n{errors}"))
        );
    }
    Ok(text.trim().into())
}
/// A completed adapter run. Promotion must load it by reference, never accept UI JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LabReceipt {
    #[serde(default, skip_serializing_if = "crate::execution::is_false")]
    pub restart: bool,
    pub id: Uuid,
    pub lab_id: String,
    pub vm_id: String,
    pub binding: String,
    pub service: String,
    pub desired_running: bool,
    pub health: HealthProbe,
    pub started: DateTime<Utc>,
    pub finished: DateTime<Utc>,
    pub before: String,
    pub after: String,
    pub passed: bool,
    pub restored: bool,
    pub proof_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BoundRequest {
    #[serde(default, skip_serializing_if = "crate::execution::is_false")]
    restart: bool,
    id: Uuid,
    lab_id: String,
    vm_id: String,
    binding: String,
    service: String,
    desired_running: bool,
    health: HealthProbe,
    started: DateTime<Utc>,
}
#[derive(Deserialize)]
struct TestProof {
    #[serde(default, rename = "stoppedVerified")]
    stopped_verified: bool,
    #[serde(default, rename = "baselineFailed")]
    baseline_failed: bool,
    #[serde(rename = "requestHash")]
    request_hash: String,
    binding: String,
    service: String,
    before: String,
    desired: String,
    after: String,
    passed: bool,
    restored: bool,
    #[serde(rename = "healthPassed")]
    health_passed: Option<bool>,
    #[serde(rename = "healthStatus")]
    health_status: Option<u16>,
}
fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
impl LabReceipt {
    pub fn reference(&self) -> String {
        format!("{}/{}", self.lab_id, self.id)
    }
    pub fn verify_integrity(&self) -> Result<()> {
        self.health.validate()?;
        if self.proof_hash != self.calculated_hash()?
            || self.finished < self.started
            || self.finished - self.started > chrono::Duration::minutes(4)
            || !matches!(self.before.as_str(), "Running" | "Stopped")
            || !matches!(self.after.as_str(), "Running" | "Stopped")
            || self.binding.len() != 64
            || !self.binding.bytes().all(|b| b.is_ascii_hexdigit())
            || (self.passed
                && (self.health.url.is_empty()
                    || self.restored
                    || (if self.restart {
                        self.before != "Running" || !self.desired_running
                    } else {
                        self.before == self.after
                    })
                    || self.after
                        != if self.desired_running {
                            "Running"
                        } else {
                            "Stopped"
                        }))
        {
            bail!("Invalid lab receipt integrity");
        }
        Uuid::parse_str(&self.lab_id)?;
        Uuid::parse_str(&self.vm_id)?;
        Ok(())
    }
    fn calculated_hash(&self) -> Result<String> {
        let mut proof = self.clone();
        proof.proof_hash.clear();
        Ok(hash_bytes(&serde_json::to_vec(&proof)?))
    }
}
fn assert_plain_path(path: &std::path::Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if let Ok(metadata) = std::fs::symlink_metadata(ancestor) {
            if metadata.file_type().is_symlink() {
                bail!("Lab path contains a symbolic link");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    bail!("Lab path contains a reparse point");
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn lock_lab(lab_id: &str) -> Result<std::fs::File> {
    let id = Uuid::parse_str(lab_id)?;
    if id.is_nil() || id.to_string() != lab_id {
        bail!("Invalid or noncanonical lab ID");
    }
    #[cfg(not(windows))]
    {
        bail!("Hyper-V labs require Windows");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let directory = root()?;
        assert_plain_path(&directory)?;
        std::fs::create_dir_all(&directory)?;
        // Outside the VM directory: Create still requires that directory to be absent.
        // Never unlink lock files: Windows releases the exclusive handle on exit/crash.
        let path = directory.join(format!("{id}.lock"));
        assert_plain_path(&path)?;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(path)
            .context("Lab is in use by another action or the lock file is inaccessible")
    }
}
fn receipt_directory(lab_id: &str) -> Result<PathBuf> {
    let id = Uuid::parse_str(lab_id)?;
    if id.to_string() != lab_id {
        bail!("Noncanonical lab ID");
    }
    let directory = root()?.join(lab_id);
    assert_plain_path(&directory)?;
    assert_plain_path(&directory.join("journal.dpapi"))?;
    let current = read_journal(&directory.join("journal.dpapi"))?;
    if current.id != lab_id
        || current.directory != directory.to_string_lossy()
        || current.name != format!("Relayne-Lab-{lab_id}")
    {
        bail!("Lab receipt ownership mismatch");
    }
    let receipts = directory.join("receipts");
    assert_plain_path(&receipts)?;
    Ok(receipts)
}
fn write_immutable<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    assert_plain_path(path)?;
    let bytes = crate::security::protect_secret(&serde_json::to_vec(value)?)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read_protected<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    assert_plain_path(path)?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        bail!("Lab receipt exceeds size limit");
    }
    Ok(serde_json::from_slice(&crate::security::unprotect_secret(
        &bytes,
    )?)?)
}
fn complete_receipt(
    request: &BoundRequest,
    proof: TestProof,
    finished: DateTime<Utc>,
) -> Result<LabReceipt> {
    let desired = if request.desired_running {
        "Running"
    } else {
        "Stopped"
    };
    if proof.request_hash != hash_bytes(&serde_json::to_vec(request)?)
        || proof.binding != request.binding
        || proof.service != request.service
        || proof.desired != desired
        || !matches!(proof.before.as_str(), "Running" | "Stopped")
        || !matches!(proof.after.as_str(), "Running" | "Stopped")
        || finished < request.started
        || finished - request.started > chrono::Duration::minutes(4)
    {
        bail!("Lab result does not match the durable request");
    }
    let passed = proof.passed
        && !proof.restored
        && (if request.restart {
            proof.before == "Running"
                && request.desired_running
                && proof.stopped_verified
                && proof.baseline_failed
        } else {
            proof.before != proof.after
        })
        && proof.after == desired
        && !request.health.url.is_empty()
        && proof.health_passed == Some(true)
        && proof.health_status
            == Some(
                request
                    .health
                    .followups
                    .last()
                    .map_or(request.health.expected_status, |s| s.status),
            );
    let mut receipt = LabReceipt {
        restart: request.restart,
        id: request.id,
        lab_id: request.lab_id.clone(),
        vm_id: request.vm_id.clone(),
        binding: request.binding.clone(),
        service: request.service.clone(),
        desired_running: request.desired_running,
        health: request.health.clone(),
        started: request.started,
        finished,
        before: proof.before,
        after: proof.after,
        passed,
        restored: proof.restored,
        proof_hash: String::new(),
    };
    receipt.proof_hash = receipt.calculated_hash()?;
    Ok(receipt)
}
pub fn execute_bound_test(
    journal: Journal,
    user: String,
    password: String,
    service: String,
    desired_running: bool,
    health: HealthProbe,
    binding: String,
) -> Result<LabReceipt> {
    execute_bound_test_with_values(
        journal,
        user,
        password,
        service,
        desired_running,
        health,
        binding,
        Default::default(),
    )
}
pub fn execute_bound_test_with_values(
    journal: Journal,
    user: String,
    password: String,
    service: String,
    desired_running: bool,
    health: HealthProbe,
    binding: String,
    http_values: crate::execution::http_health::Values,
) -> Result<LabReceipt> {
    execute_bound_repair_with_values(
        journal,
        user,
        password,
        service,
        desired_running,
        health,
        binding,
        http_values,
        false,
    )
}
pub fn execute_bound_repair_with_values(
    journal: Journal,
    user: String,
    password: String,
    service: String,
    desired_running: bool,
    health: HealthProbe,
    binding: String,
    http_values: crate::execution::http_health::Values,
    restart: bool,
) -> Result<LabReceipt> {
    anyhow::ensure!(!restart || desired_running, "Restart requires Running");
    for step in &health.followups {
        step.options.validate_values(&http_values)?;
    }
    let _lab_lock = lock_lab(&journal.id)?;
    health.validate()?;
    if health.url.is_empty()
        || binding.len() != 64
        || !binding.bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("A bound lab test requires HTTP health and a SHA256 plan binding");
    }
    let directory = receipt_directory(&journal.id)?;
    let current = read_journal(&root()?.join(&journal.id).join("journal.dpapi"))?;
    if journal.vm_id != current.vm_id || current.vm_id.is_empty() {
        bail!("Lab VM changed");
    }
    Uuid::parse_str(&current.vm_id)?;
    let request = BoundRequest {
        restart,
        id: Uuid::new_v4(),
        lab_id: current.id.clone(),
        vm_id: current.vm_id.clone(),
        binding,
        service: service.clone(),
        desired_running,
        health: health.clone(),
        started: Utc::now(),
    };
    std::fs::create_dir_all(&directory)?;
    write_immutable(
        &directory.join(format!("{}.pending.dpapi", request.id)),
        &request,
    )?;
    let output = execute_with_binding(
        Action::Test,
        Some(current),
        user,
        password,
        service,
        desired_running,
        health,
        Some(serde_json::to_string(&request)?),
        http_values,
    )?;
    let returned: Journal = serde_json::from_str(&output)?;
    let saved = read_journal(&root()?.join(&request.lab_id).join("journal.dpapi"))?;
    if saved.id != request.lab_id || saved.vm_id != request.vm_id || saved.detail != returned.detail
    {
        bail!("Persisted lab result differs from the completed adapter run");
    }
    let receipt = complete_receipt(&request, serde_json::from_str(&saved.detail)?, Utc::now())?;
    write_immutable(&directory.join(format!("{}.dpapi", receipt.id)), &receipt)?;
    load_receipt(&receipt.reference())
}
pub fn load_receipt(reference: &str) -> Result<LabReceipt> {
    let (lab, id) = reference
        .split_once('/')
        .context("Invalid lab receipt reference")?;
    let receipt_id = Uuid::parse_str(id)?;
    if receipt_id.to_string() != id {
        bail!("Noncanonical receipt ID");
    }
    let directory = receipt_directory(lab)?;
    let receipt: LabReceipt = read_protected(&directory.join(format!("{id}.dpapi")))?;
    receipt.verify_integrity()?;
    let request: BoundRequest = read_protected(&directory.join(format!("{id}.pending.dpapi")))?;
    if receipt.lab_id != lab
        || receipt.id != receipt_id
        || receipt.proof_hash != receipt.calculated_hash()?
        || request.id != receipt.id
        || request.lab_id != receipt.lab_id
        || request.vm_id != receipt.vm_id
        || request.binding != receipt.binding
        || request.service != receipt.service
        || request.desired_running != receipt.desired_running
        || request.restart != receipt.restart
        || request.health != receipt.health
        || request.started != receipt.started
        || receipt.finished < receipt.started
        || receipt.finished - receipt.started > chrono::Duration::minutes(4)
    {
        bail!("Invalid lab receipt proof");
    }
    receipt.health.validate()?;
    if receipt.passed
        && (receipt.health.url.is_empty()
            || receipt.restored
            || (if receipt.restart {
                receipt.before != "Running" || !receipt.desired_running
            } else {
                receipt.before == receipt.after
            })
            || receipt.after
                != if receipt.desired_running {
                    "Running"
                } else {
                    "Stopped"
                })
    {
        bail!("Lab receipt does not prove a changed, healthy service");
    }
    Ok(receipt)
}
// Only this short, fixed bootstrap appears on the command line. Both trusted
// adapter code and the data-only request travel through stdin, without temp files.
const BOOTSTRAP: &str = r#"
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$envelope=[Console]::In.ReadToEnd()|ConvertFrom-Json
$p=$envelope.payload
& ([scriptblock]::Create([string]$envelope.script))
"#;
fn encoded_bootstrap() -> String {
    base64::engine::general_purpose::STANDARD.encode(
        BOOTSTRAP
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}
fn script_envelope(script: &str, payload: serde_json::Value) -> Result<Vec<u8>> {
    // `script` is always SCRIPT (or the compile-time fixture prefix in tests),
    // never request/user text. JSON keeps payload strings separate from code.
    Ok(serde_json::to_vec(
        &serde_json::json!({"script": script, "payload": payload}),
    )?)
}
pub const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Add-Type -AssemblyName System.Security
$j=$p.lab
$secretForRedaction=[string]$p.password
function Safe-Error([string]$message) {
 if($secretForRedaction){$message=$message.Replace($secretForRedaction,'[REDACTED]')}
 if($p.user){$message=$message.Replace([string]$p.user,'[USER]')}
 foreach($field in $p.httpValues.PSObject.Properties){if([string]$field.Value){$message=$message.Replace([string]$field.Value,'[REDACTED]')}}
 return $message.Substring(0,[Math]::Min(1000,$message.Length))
}
function Save-Journal {
 $clear=[Text.Encoding]::UTF8.GetBytes(($j|ConvertTo-Json -Depth 8 -Compress))
 $bytes=[Security.Cryptography.ProtectedData]::Protect($clear,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $tmp=Join-Path $j.directory 'journal.tmp'
 [IO.File]::WriteAllBytes($tmp,$bytes)
 $dest=Join-Path $j.directory 'journal.dpapi'
 if(Test-Path -LiteralPath $dest){[IO.File]::Replace($tmp,$dest,[NullString]::Value)}else{[IO.File]::Move($tmp,$dest)}
}
function Assert-OwnedVM {
 if(!$j.vm_id){throw 'No recorded VM ID; manual inspection required'}
 $vm=Get-VM -Id ([guid]$j.vm_id)
 if($vm.Name -ne $j.name -or $vm.Notes -ne $j.id){throw 'VM ownership mismatch'}
 $drives=@($vm|Get-VMHardDiskDrive)
 if($drives.Count -ne 1 -or $drives[0].Path -ne (Join-Path $j.directory 'child.vhdx')){throw 'VM disk ownership mismatch'}
 $nic=@($vm|Get-VMNetworkAdapter)
 if($nic.Count -ne 1 -or [string]$nic[0].SwitchId -ne $j.switch_id){throw 'VM network changed; refusing operation'}
 $sw=Get-VMSwitch -Id ([guid]$j.switch_id)
 if($sw.Name -ne $j.name -or [string]$sw.SwitchType -ne 'Private'){throw 'Switch ownership/isolation mismatch'}
 return $vm
}
try {
 Import-Module Hyper-V
 if($p.action -eq 'preflight') {
  $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  [pscustomobject]@{hyperV=$true;administrator=$admin;vmms=[string](Get-Service vmms).Status;powerShellDirect=(Get-Command Invoke-Command).Parameters.ContainsKey('VMId')}|ConvertTo-Json -Compress
  exit 0
 }
 $ancestor=[IO.DirectoryInfo]$j.directory
 while($ancestor){
  if($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Lab directory contains a reparse point'}
  $ancestor=$ancestor.Parent
 }
 if($p.action -eq 'create') {
  if(Test-Path -LiteralPath $j.directory){throw 'Lab directory already exists'}
  $source=Get-Item -LiteralPath $j.template
  if($source.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Template reparse points are forbidden'}
  if(!$source.IsReadOnly){throw 'Template must have ReadOnly file attribute before creation'}
  $vhd=Get-VHD -Path $j.template
  if($vhd.Attached -or $vhd.ParentPath){throw 'Template must be offline and standalone'}
  if(@(Get-VM|Get-VMHardDiskDrive|Where-Object Path -eq $j.template).Count){throw 'Template is assigned to an existing VM'}
  New-Item -ItemType Directory -Path $j.directory|Out-Null
  $j.phase='creating'; Save-Journal
  $sw=New-VMSwitch -Name $j.name -SwitchType Private
  $j.switch_id=[string]$sw.Id;Save-Journal
  New-VHD -Path (Join-Path $j.directory 'child.vhdx') -ParentPath $j.template -Differencing|Out-Null
  $vm=New-VM -Name $j.name -Generation 2 -MemoryStartupBytes 2GB -Path $j.directory -VHDPath (Join-Path $j.directory 'child.vhdx') -SwitchName $j.name
  $j.vm_id=[string]$vm.Id;Save-Journal
  $vm|Set-VM -Notes $j.id -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -CheckpointType Standard
  $vm=Assert-OwnedVM
  $vm|Start-VM
  $j.phase='running';$j.detail='VM started; guest readiness not yet verified';Save-Journal
 } elseif($p.action -eq 'test') {
  $vm=Assert-OwnedVM
  $requestHash='';$binding='';$bound=$null
  if($p.boundRequest){
   $bound=$p.boundRequest|ConvertFrom-Json
   if($bound.lab_id -cne $j.id -or $bound.vm_id -cne $j.vm_id -or $bound.service -cne $p.service -or [bool]$bound.desired_running -ne [bool]$p.desiredRunning -or $bound.health.url -cne $p.health.url -or $bound.health.expected_status -ne $p.health.expected_status -or $bound.health.body_marker -cne $p.health.body_marker){throw 'Bound request mismatch'}
   # The durable typed request is authoritative, including all ordered HTTP options.
   # Do not compare JSON strings: property order differs between struct and Value serialization.
   $p.health=$bound.health
   $binding=[string]$bound.binding
   $requestSha=[Security.Cryptography.SHA256]::Create()
   $requestHash=([BitConverter]::ToString($requestSha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$p.boundRequest)))).Replace('-','').ToLowerInvariant()
   $requestSha.Dispose()
  }
  $plan=(@{vm=$j.vm_id;service=$p.service;desiredRunning=[bool]$p.desiredRunning;health=$p.health}|ConvertTo-Json -Compress)
  $sha=[Security.Cryptography.SHA256]::Create()
  $planHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($plan)))).Replace('-','').ToLowerInvariant()
  $j.phase='testing';$j.detail='Plan SHA256: '+$planHash+' '+$plan;Save-Journal
  $secure=New-Object Security.SecureString
  foreach($character in ([string]$p.password).ToCharArray()){$secure.AppendChar($character)}
  $secure.MakeReadOnly()
  $credential=New-Object Management.Automation.PSCredential($p.user,$secure)
  $p.password=$null
  $result=Invoke-Command -VMId ([guid]$j.vm_id) -Credential $credential -ScriptBlock {
    param($service,$desiredRunning,$health,$httpValues,$restart)
    function Assert-Json($body,$assertions){
     if(!$assertions -or @($assertions.PSObject.Properties).Count -eq 0){return}
     Add-Type -AssemblyName System.Web.Extensions
     $parser=New-Object Web.Script.Serialization.JavaScriptSerializer
     $parser.MaxJsonLength=65536;$parser.RecursionLimit=32
     $json=$parser.DeserializeObject($body)
     foreach($assertion in $assertions.PSObject.Properties){
      $node=$json;$pointer=[string]$assertion.Name
      if($pointer){foreach($segment in $pointer.Substring(1).Split('/')){
       $key=$segment.Replace('~1','/').Replace('~0','~')
       if($node -is [Collections.IDictionary]){if(!$node.ContainsKey($key)){throw 'JSON pointer missing'};$node=$node[$key]}
       elseif($node -is [Collections.IList]){if($key -notmatch '^(0|[1-9][0-9]*)$' -or $key.Length -gt 9 -or [int]$key -ge $node.Count){throw 'JSON array pointer missing'};$node=$node[[int]$key]}
       else{throw 'JSON pointer missing'}
      }}
      $expected=$assertion.Value
      if($null -eq $expected){if($null -ne $node){throw 'JSON null assertion failed'}}
      elseif($expected -is [bool]){if($node -isnot [bool] -or $node -ne $expected){throw 'JSON boolean assertion failed'}}
      elseif($expected -is [string]){if($node -isnot [string] -or $node -cne $expected){throw 'JSON string assertion failed'}}
      elseif($expected -is [int] -or $expected -is [long]){
       if($expected -lt -9007199254740991L -or $expected -gt 9007199254740991L){throw 'JSON integer assertion out of range'}
       if(($node -isnot [int] -and $node -isnot [long]) -or $node -ne $expected){throw 'JSON integer assertion failed'}
      }
      else{throw 'Unsupported JSON assertion type'}
     }
    }
    function Save-Cookies($response,$jar,$tls){
     foreach($raw in $response.Headers.GetValues('Set-Cookie')){
      if($raw.Length -gt 4096 -or $raw -cmatch '[^\x00-\x7f]'){throw 'Cookie limit or non-ASCII cookie'}
      $parts=@($raw.Split(';')|ForEach-Object{$_.Trim()});$attrs=@($parts|Select-Object -Skip 1)
      if(!($attrs|Where-Object{$_ -ieq 'path=/'}) -or ($attrs|Where-Object{$_ -imatch '^domain=' -or ($_ -imatch '^path=' -and $_ -ine 'path=/')})){throw 'Cookie scope unsupported'}
      $separator=$parts[0].IndexOf('=');if($separator -lt 1){throw 'Invalid cookie'};$name=$parts[0].Substring(0,$separator);$value=$parts[0].Substring($separator+1)
      if($name -notmatch '^[A-Za-z0-9_-]{1,128}$' -or $value -cmatch '[^\x21-\x7e]|[";,\\]'){throw 'Invalid cookie characters'}
      if(($attrs|Where-Object{$_ -ieq 'secure'}) -and !$tls){continue}
      $age=@($attrs|Where-Object{$_ -imatch '^max-age='})
      if($age.Count){$number=0L;if([long]::TryParse($age[0].Substring(8),[ref]$number) -and $number -le 0){$null=$jar.Remove($name);continue};throw 'Persistent cookies unsupported'}
      if($attrs|Where-Object{$_ -imatch '^expires='}){throw 'Persistent cookies unsupported'}
      if($jar.Count -ge 32 -and !$jar.ContainsKey($name)){throw 'Cookie count limit'};$jar[$name]=$value
     }
    }
    function Test-RepairHealth {
      $passed=$true;$healthPassed=$null;$healthStatus=$null
      try {
      if($health.url){
       $stage='http';$passed=$false
       $baseUri=[uri]$health.url
       $checks=@([pscustomobject]@{url=$health.url;status=$health.expected_status;marker=$health.body_marker;options=$null})
       $cookies=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
       if(@($health.followups).Count -gt 3){throw 'HTTP step limit exceeded'}
       foreach($step in $health.followups){$checks += [pscustomobject]@{url=($baseUri.GetLeftPart([UriPartial]::Authority)+$step.path);status=$step.status;marker=$step.contains;options=$step.options}}
       foreach($check in $checks){
       $passed=$false;$healthPassed=$false;$healthStatus=$null
       $uri=[uri]$check.url
       if($uri.Scheme -notin @('http','https') -or $uri.Host -notin @('localhost','127.0.0.1','[::1]','::1') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'Non-loopback health URI rejected'}
       $request=[Net.HttpWebRequest]::Create($uri)
       $request.Method='GET';$request.AllowAutoRedirect=$false;$request.Proxy=$null;$request.Credentials=$null;$request.UseDefaultCredentials=$false
       if($cookies.Count){$request.Headers['Cookie']=(@($cookies.GetEnumerator()|ForEach-Object{$_.Key+'='+$_.Value}) -join '; ')}
       $request.Timeout=10000;$request.ReadWriteTimeout=10000;$request.MaximumResponseHeadersLength=16
       $response=$null;$reader=$null
       try {
        if($check.options.method -eq 'Post'){
         $fields=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
         foreach($field in $check.options.form.PSObject.Properties){$fields[$field.Name]=[string]$field.Value}
         foreach($field in $check.options.secret_fields.PSObject.Properties){
          if($uri.Scheme -ne 'https'){throw 'Secret fields require HTTPS'}
          $found=@($httpValues.PSObject.Properties|Where-Object{$_.Name -ceq $field.Value})
          if($found.Count -ne 1 -or ![string]$found[0].Value){throw 'Secret slot missing'};$fields[$field.Name]=[string]$found[0].Value
         }
         $encoded=@($fields.GetEnumerator()|ForEach-Object{[Net.WebUtility]::UrlEncode($_.Key)+'='+[Net.WebUtility]::UrlEncode($_.Value)}) -join '&'
         $data=[Text.Encoding]::UTF8.GetBytes($encoded);if($data.Length -gt 196608){throw 'Form size limit'}
         $request.Method='POST';$request.ContentType='application/x-www-form-urlencoded';$request.ContentLength=$data.Length
         $upload=$request.GetRequestStream();try{$upload.Write($data,0,$data.Length)}finally{$upload.Dispose()}
        }
        try {$response=$request.GetResponse()} catch [Net.WebException] {if($_.Exception.Response){$response=$_.Exception.Response}else{throw}}
        $healthStatus=[int]$response.StatusCode
        Save-Cookies $response $cookies ($uri.Scheme -eq 'https')
        $reader=$response.GetResponseStream()
        $buffer=New-Object byte[] 65537;$count=0
        $deadline=[Diagnostics.Stopwatch]::StartNew()
        while($count -lt $buffer.Length){$remaining=10000-[int]$deadline.ElapsedMilliseconds;if($remaining -le 0){$request.Abort();throw 'HTTP body deadline exceeded'};$pending=$reader.ReadAsync($buffer,$count,$buffer.Length-$count);if(!$pending.Wait($remaining)){$request.Abort();throw 'HTTP body deadline exceeded'};$read=$pending.Result;if($read -eq 0){break};$count += $read}
        if($count -gt 65536){throw 'HTTP response limit exceeded'}
        $body=[Text.Encoding]::UTF8.GetString($buffer,0,$count)
        $healthPassed=($healthStatus -eq [int]$check.status -and (!$check.marker -or $body.Contains([string]$check.marker)))
        if(!$healthPassed){throw 'HTTP health verification failed'}
        Assert-Json $body $check.options.json_equals
        $passed=$true
       } finally {$request.Abort();if($reader){$reader.Dispose()};if($response){$response.Close()}}
       }
      }
      } catch { $passed=$false;$healthPassed=$false }
      [pscustomobject]@{passed=$passed;status=$healthStatus}
    }
    Add-Type -AssemblyName System.ServiceProcess
    $s=Get-Service -Name $service -ErrorAction Stop
    $before=[string]$s.Status
    if($before -notin @('Running','Stopped')){throw 'Service must be in stable Running/Stopped state'}
    $desired=if($desiredRunning){'Running'}else{'Stopped'}
    $stoppedVerified=$false;$baselineFailed=$false;
    if($restart -and ($before -ne 'Running' -or !$desiredRunning)){throw 'Restart requires running service'}
    if(@($s.DependentServices | Where-Object Status -eq Running).Count -gt 0){throw 'Running dependents; no mutation attempted'}
    if(@($s.ServicesDependedOn | Where-Object Status -ne Running).Count -gt 0){throw 'Inactive prerequisites; no mutation attempted'}
    if($restart){$baseline=Test-RepairHealth;$baselineFailed=(!$baseline.passed);if(!$baselineFailed){throw 'Restart baseline is healthy; no mutation attempted'}}
    $passed=$false;$restored=$false;$failure='';$after=$before;$healthStatus=$null;$healthPassed=$null;$stage='service'
    try {
      if($restart){$s|Stop-Service -ErrorAction Stop;$s.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30));$s.Refresh();if([string]$s.Status -ne 'Stopped'){throw 'Stop verification failed'};$stoppedVerified=$true}
      if($desiredRunning){$s|Start-Service -ErrorAction Stop}else{$s|Stop-Service -ErrorAction Stop}
      $s.WaitForStatus([ServiceProcess.ServiceControllerStatus]$desired,[TimeSpan]::FromSeconds(30))
      $s.Refresh();$after=[string]$s.Status;$passed=($after -eq $desired)
      if(!$passed){throw 'Service verification did not reach requested state'}
      $stage='http';$httpResult=Test-RepairHealth
      $healthStatus=$httpResult.status;$healthPassed=$httpResult.passed;$passed=$healthPassed
      if(!$passed){throw 'HTTP health verification failed'}
    } catch {
      $failure=$stage+' check failed: '+$_.Exception.GetType().Name
      try {
        if($before -eq 'Running'){$s|Start-Service -ErrorAction Stop}else{$s|Stop-Service -ErrorAction Stop}
        $s.WaitForStatus([ServiceProcess.ServiceControllerStatus]$before,[TimeSpan]::FromSeconds(30))
        $s.Refresh();$after=[string]$s.Status;$restored=($after -eq $before)
      } catch {$failure += '; restore failed: ' + $_.Exception.GetType().Name}
    }
    [pscustomobject]@{computer=$env:COMPUTERNAME;service=$s.Name;before=$before;desired=$desired;after=$after;passed=$passed;restored=$restored;failure=$failure;healthStatus=$healthStatus;healthPassed=$healthPassed;stoppedVerified=$stoppedVerified;baselineFailed=$baselineFailed}
  } -ArgumentList $p.service,$p.desiredRunning,$p.health,$p.httpValues,([bool]$bound.restart)
  $result|Add-Member -NotePropertyName planHash -NotePropertyValue $planHash
  $result|Add-Member -NotePropertyName requestHash -NotePropertyValue $requestHash
  $result|Add-Member -NotePropertyName binding -NotePropertyValue $binding
  $j.detail=$result|Select-Object planHash,requestHash,binding,computer,service,before,desired,after,passed,restored,failure,healthStatus,healthPassed,stoppedVerified,baselineFailed|ConvertTo-Json -Compress
  $j.phase=if($result.passed){'test_passed'}else{'test_failed'};Save-Journal
 } elseif($p.action -eq 'cleanup') {
  # Identity and topology checks happen before the first destructive operation.
  if($j.vm_id){$vm=Assert-OwnedVM}
  if($j.switch_id){
   $sw=Get-VMSwitch -Id ([guid]$j.switch_id)
   if($sw.Name -ne $j.name -or [string]$sw.SwitchType -ne 'Private'){throw 'Switch mismatch'}
   $other=@(Get-VM|Get-VMNetworkAdapter|Where-Object { [string]$_.SwitchId -eq $j.switch_id -and [string]$_.VMId -ne $j.vm_id })
   if($other.Count){throw 'Switch has foreign adapters; cleanup refused'}
  }
  $child=Join-Path $j.directory 'child.vhdx'
  $foreignDisks=@(Get-VM|Get-VMHardDiskDrive|Where-Object {$_.Path -eq $child -and [string]$_.VMId -ne $j.vm_id})
  if($foreignDisks.Count){throw 'Child disk attached to foreign VM; cleanup refused'}
  if(Test-Path -LiteralPath $child){
   $disk=Get-Item -LiteralPath $child
   if($disk.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Child disk is a reparse point'}
   if((Get-VHD -Path $child).ParentPath -ne $j.template){throw 'Child parent mismatch'}
  }
  $j.phase='cleaning';Save-Journal
  if($j.vm_id){$vm|Stop-VM -TurnOff -Force;$vm|Remove-VM -Force;$j.vm_id='';Save-Journal}
  if($j.switch_id){$sw|Remove-VMSwitch -Force;$j.switch_id='';Save-Journal}
  if(Test-Path -LiteralPath $child){Remove-Item -LiteralPath $child -Force}
  $j.phase='cleaned';$j.detail='Owned VM, private switch and child disk removed. Journal retained.';Save-Journal
 } else {throw 'Unknown action'}
 $j|ConvertTo-Json -Depth 8 -Compress
} catch {
 $message=Safe-Error $_.Exception.Message
 if($j -and (Test-Path -LiteralPath (Join-Path $j.directory 'journal.dpapi'))){$j.phase='failed';$j.detail=$message;Save-Journal}
 [Console]::Error.WriteLine($message);exit 1
}
"#;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_is_short_and_request_strings_remain_json_data() {
        let payload = serde_json::json!({"password":"'; throw 'must-not-run'; # ä", "service":"FixtureService"});
        let envelope: serde_json::Value =
            serde_json::from_slice(&script_envelope(SCRIPT, payload.clone()).unwrap()).unwrap();
        assert_eq!(envelope["script"], SCRIPT);
        assert_eq!(envelope["payload"], payload);
        assert!(encoded_bootstrap().len() < 4096);
        assert!(!SCRIPT.contains("[Console]::In.ReadToEnd()"));
    }
    #[test]
    #[cfg(windows)]
    fn lab_lock_excludes_same_lab_until_handle_is_dropped() {
        let first = Uuid::new_v4().to_string();
        let second = Uuid::new_v4().to_string();
        let held = lock_lab(&first).unwrap();
        assert!(lock_lab(&first).is_err());
        let independent = lock_lab(&second).unwrap();
        assert!(lock_lab(&second).is_err());
        assert!(lock_lab(&Uuid::nil().to_string()).is_err());
        assert!(lock_lab(&Uuid::new_v4().simple().to_string()).is_err());
        drop(held);
        let reacquired = lock_lab(&first).unwrap();
        assert!(lock_lab(&first).is_err());
        drop(reacquired);
        drop(independent);
        // Leave the empty stable lock files, exactly as real operations do.
    }
    #[test]
    fn schema_round_trip() {
        let j = Journal {
            id: uuid::Uuid::nil().to_string(),
            name: "lab".into(),
            template: "base.vhdx".into(),
            directory: "lab".into(),
            vm_id: String::new(),
            switch_id: String::new(),
            phase: "planned".into(),
            detail: String::new(),
        };
        assert_eq!(
            serde_json::from_str::<Journal>(&serde_json::to_string(&j).unwrap())
                .unwrap()
                .phase,
            "planned"
        );
    }
    #[test]
    fn cleanup_never_recursively_deletes() {
        assert!(!SCRIPT.contains("-Recurse"));
        assert!(!SCRIPT.contains("Remove-Item -LiteralPath $j.template"));
        assert!(SCRIPT.contains("Assert-OwnedVM"));
        assert!(SCRIPT.contains("-SwitchType Private"));
    }
    #[cfg(windows)]
    fn fake_run(prefix: &str, payload: serde_json::Value) -> std::process::Output {
        let code = format!("{prefix}\n{SCRIPT}");
        let encoded = encoded_bootstrap();
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&script_envelope(&code, payload).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    }
    #[cfg(windows)]
    const FAKE_GUARDS: &str = r#"
 function Import-Module { param($Name) if($Name -ne 'Hyper-V'){throw 'Unexpected module'} }
 function New-VM {throw 'UNEXPECTED MUTATION'}
 function New-VHD {throw 'UNEXPECTED MUTATION'}
 function New-VMSwitch {throw 'UNEXPECTED MUTATION'}
 function Start-VM {throw 'UNEXPECTED MUTATION'}
 function Stop-VM {throw 'UNEXPECTED MUTATION'}
 function Remove-VM {throw 'UNEXPECTED MUTATION'}
 function Remove-VMSwitch {throw 'UNEXPECTED MUTATION'}
 function Remove-Item {throw 'UNEXPECTED MUTATION'}
 "#;
    #[test]
    #[cfg(windows)]
    fn fake_preflight_has_typed_schema() {
        let prefix = format!(
            "{FAKE_GUARDS}\nfunction Get-Service {{ [pscustomobject]@{{Status='Running'}} }}"
        );
        let result = fake_run(
            &prefix,
            serde_json::json!({"action":"preflight","lab":null}),
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(parsed["hyperV"], true);
        assert!(parsed["administrator"].is_boolean());
        assert_eq!(parsed["vmms"], "Running");
        assert!(parsed["powerShellDirect"].is_boolean());
    }
    #[test]
    #[cfg(windows)]
    fn fake_foreign_vm_cleanup_is_refused_before_mutation() {
        let prefix = format!(
            "{FAKE_GUARDS}\nfunction Get-VM {{ param($Id) [pscustomobject]@{{Name='Foreign';Notes='foreign'}} }}"
        );
        let result = fake_run(
            &prefix,
            serde_json::json!({"action":"cleanup","lab":{"id":"00000000-0000-0000-0000-000000000000","name":"Owned","directory":std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()).to_string_lossy(),"vm_id":"00000000-0000-0000-0000-000000000000","switch_id":"","template":"template.vhdx","phase":"running","detail":""}}),
        );
        assert!(!result.status.success());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains("VM ownership mismatch"), "{error}");
        assert!(!error.contains("UNEXPECTED MUTATION"));
    }

    #[test]
    fn health_probe_rejects_routes_and_credentials() {
        for url in [
            "http://example.com/",
            "http://127.0.0.1@evil.test/",
            "http://127.0.0.1/?token=secret",
            "https://example.com/",
            "file:///c:/x",
        ] {
            assert!(
                HealthProbe {
                    url: url.into(),
                    expected_status: 200,
                    body_marker: String::new(),
                    followups: vec![],
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            HealthProbe {
                url: "http://127.0.0.1:8080/health".into(),
                expected_status: 200,
                body_marker: "ok".into(),
                followups: vec![],
            }
            .validate()
            .is_ok()
        );
    }
    #[cfg(windows)]
    const FAKE_REHEARSAL: &str = r#"
 function Get-VM { param($Id) [pscustomobject]@{Name=$j.name;Notes=$j.id} }
 function Get-VMHardDiskDrive { param([Parameter(ValueFromPipeline=$true)]$InputObject) process {[pscustomobject]@{Path=(Join-Path $j.directory 'child.vhdx')}} }
 function Get-VMNetworkAdapter { param([Parameter(ValueFromPipeline=$true)]$InputObject) process {[pscustomobject]@{SwitchId=$j.switch_id}} }
 function Get-VMSwitch { param($Id) [pscustomobject]@{Name=$j.name;SwitchType='Private'} }
 function Get-Service {
  param($Name)
  $service=[pscustomobject]@{Name=$Name;Status='Stopped';DependentServices=@();ServicesDependedOn=@()}
  $service|Add-Member ScriptMethod Refresh {}
  $service|Add-Member ScriptMethod WaitForStatus {param($expected,$timeout) if($global:failOnce){$global:failOnce=$false;throw 'Synthetic verification failure'};if([string]$this.Status -ne [string]$expected){throw 'Wrong fake state'}}
  return $service
 }
 function Start-Service {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$InputObject.Status='Running'} }
 function Stop-Service {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$InputObject.Status='Stopped'} }
 function Invoke-Command {param($VMId,$Credential,$ScriptBlock,$ArgumentList) & $ScriptBlock @ArgumentList }
 "#;
    #[test]
    #[cfg(windows)]
    fn fake_rehearsal_applies_verifies_restores_and_excludes_credentials() {
        for fail in [false, true] {
            let dir =
                std::env::temp_dir().join(format!("relayne-lab-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let prefix = format!(
                "{FAKE_GUARDS}\n{FAKE_REHEARSAL}\n$global:failOnce=${}",
                if fail { "true" } else { "false" }
            );
            let result = fake_run(
                &prefix,
                serde_json::json!({"action":"test","user":"fixture-user","password":"fixture-password-do-not-persist","service":"FixtureService","desiredRunning":true,"health":{"url":"","expected_status":200,"body_marker":""},"lab":{"id":id,"name":"Owned","directory":dir.to_string_lossy(),"vm_id":id,"switch_id":id,"template":"template.vhdx","phase":"running","detail":""}}),
            );
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let journal = read_journal(&dir.join("journal.dpapi")).unwrap();
            assert!(!journal.detail.contains("fixture-password"));
            assert!(!journal.detail.contains("fixture-user"));
            let proof: serde_json::Value = serde_json::from_str(&journal.detail).unwrap();
            assert_eq!(proof["before"], "Stopped");
            assert_eq!(proof["passed"], !fail);
            assert_eq!(proof["restored"], fail);
            assert_eq!(proof["after"], if fail { "Stopped" } else { "Running" });
            assert_eq!(proof["planHash"].as_str().unwrap().len(), 64);
            std::fs::remove_file(dir.join("journal.dpapi")).unwrap();
            std::fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    #[cfg(windows)]
    fn fake_restart_proves_stop_start_and_restores_on_failure() {
        for mode in ["success", "http_failure", "stop_failure", "healthy"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now();
                let mut count = 0;
                let expected = if mode == "healthy" || mode == "stop_failure" {
                    1
                } else {
                    2
                };
                while count < expected && deadline.elapsed() < Duration::from_secs(15) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut buffer = [0; 2048];
                            let _ = stream.read(&mut buffer);
                            let status = if mode == "healthy" || (count == 1 && mode == "success") {
                                "200 OK"
                            } else {
                                "503 Unavailable"
                            };
                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            );
                            stream.write_all(response.as_bytes()).unwrap();
                            count += 1;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
                assert_eq!(count, expected);
            });
            let dir = std::env::temp_dir().join(format!("relayne-restart-{}", Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let id = Uuid::new_v4().to_string();
            let mut prefix = format!(
                "{FAKE_GUARDS}\n{}\n$global:failOnce=${}",
                FAKE_REHEARSAL
                    .replace("Name=$Name;Status='Stopped'", "Name=$Name;Status='Running'"),
                if mode == "stop_failure" {
                    "true"
                } else {
                    "false"
                }
            );
            if mode == "healthy" {
                prefix.push_str("\nfunction Start-Service {throw 'UNEXPECTED MUTATION'}; function Stop-Service {throw 'UNEXPECTED MUTATION'}");
            }
            let request = BoundRequest {
                restart: true,
                id: Uuid::new_v4(),
                lab_id: id.clone(),
                vm_id: id.clone(),
                binding: "a".repeat(64),
                service: "FixtureService".into(),
                desired_running: true,
                health: HealthProbe {
                    url: format!("http://{address}/health"),
                    expected_status: 200,
                    body_marker: "ok".into(),
                    followups: vec![],
                },
                started: Utc::now(),
            };
            let output = fake_run(
                &prefix,
                serde_json::json!({"action":"test","boundRequest":serde_json::to_string(&request).unwrap(),"user":"fixture","password":"fixture-secret","service":request.service,"desiredRunning":true,"health":request.health,"lab":{"id":id,"name":"Owned","directory":dir.to_string_lossy(),"vm_id":id,"switch_id":id,"template":"fixture.vhdx","phase":"running","detail":""}}),
            );
            assert!(
                output.status.success() || mode == "healthy",
                "restart fake error: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            server.join().unwrap();
            if mode == "healthy" {
                assert!(!output.status.success());
                assert!(String::from_utf8_lossy(&output.stderr).contains("baseline is healthy"));
                assert!(!String::from_utf8_lossy(&output.stderr).contains("UNEXPECTED MUTATION"));
            } else {
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let journal = read_journal(&dir.join("journal.dpapi")).unwrap();
                let raw: serde_json::Value = serde_json::from_str(&journal.detail).unwrap();
                assert_eq!(raw["baselineFailed"], true);
                let receipt = complete_receipt(
                    &request,
                    serde_json::from_str(&journal.detail).unwrap(),
                    Utc::now(),
                )
                .unwrap();
                receipt.verify_integrity().unwrap();
                assert!(receipt.restart);
                assert_eq!(receipt.before, "Running");
                assert_eq!(receipt.after, "Running");
                assert_eq!(receipt.passed, mode == "success");
                assert_eq!(receipt.restored, mode != "success");
                if mode == "success" {
                    assert_eq!(raw["stoppedVerified"], true);
                    let mut missing = raw.clone();
                    missing["stoppedVerified"] = serde_json::json!(false);
                    assert!(
                        !complete_receipt(
                            &request,
                            serde_json::from_value(missing).unwrap(),
                            Utc::now()
                        )
                        .unwrap()
                        .passed
                    );
                }
            }
            if dir.join("journal.dpapi").exists() {
                std::fs::remove_file(dir.join("journal.dpapi")).unwrap();
            }
            std::fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    #[cfg(windows)]
    fn fake_http_health_failure_restores_service() {
        for (expected_marker, desired_running) in
            [("healthy", true), ("absent", true), ("healthy", false)]
        {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now();
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(3)))
                                .unwrap();
                            let mut buffer = [0; 2048];
                            let _ = stream.read(&mut buffer);
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nhealthy").unwrap();
                            return;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if deadline.elapsed() > Duration::from_secs(15) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => return,
                    }
                }
            });
            let dir =
                std::env::temp_dir().join(format!("relayne-lab-http-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let prefix = format!("{FAKE_GUARDS}\n{FAKE_REHEARSAL}\n$global:failOnce=$false");
            let request = BoundRequest {
                restart: false,
                id: Uuid::new_v4(),
                lab_id: id.clone(),
                vm_id: id.clone(),
                binding: "a".repeat(64),
                service: "FixtureService".into(),
                desired_running,
                health: HealthProbe {
                    url: format!("http://{address}/health"),
                    expected_status: 200,
                    body_marker: expected_marker.into(),
                    followups: vec![],
                },
                started: Utc::now(),
            };
            let output = fake_run(
                &prefix,
                serde_json::json!({"action":"test","boundRequest":serde_json::to_string(&request).unwrap(),"user":"fixture-user","password":"fixture-secret","service":"FixtureService","desiredRunning":desired_running,"health":request.health,"lab":{"id":id,"name":"Owned","directory":dir.to_string_lossy(),"vm_id":id,"switch_id":id,"template":"template.vhdx","phase":"running","detail":""}}),
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let journal = read_journal(&dir.join("journal.dpapi")).unwrap();
            let proof: serde_json::Value = serde_json::from_str(&journal.detail).unwrap();
            let passed = expected_marker == "healthy";
            assert_eq!(proof["passed"], passed);
            assert_eq!(proof["healthPassed"], passed);
            assert_eq!(proof["healthStatus"], 200);
            assert_eq!(proof["restored"], !passed);
            assert!(!journal.detail.contains("fixture-secret"));
            let receipt = complete_receipt(
                &request,
                serde_json::from_str(&journal.detail).unwrap(),
                Utc::now(),
            )
            .unwrap();
            receipt.verify_integrity().unwrap();
            assert_eq!(receipt.passed, passed && desired_running);
            let mut tampered = receipt.clone();
            tampered.binding = "b".repeat(64);
            assert!(tampered.verify_integrity().is_err());
            assert!(
                complete_receipt(
                    &request,
                    serde_json::from_str(&journal.detail).unwrap(),
                    request.started - chrono::Duration::seconds(1)
                )
                .is_err()
            );
            assert!(
                complete_receipt(
                    &request,
                    serde_json::from_str(&journal.detail).unwrap(),
                    request.started + chrono::Duration::minutes(5)
                )
                .is_err()
            );
            let mut wrong = request.clone();
            wrong.binding = "c".repeat(64);
            assert!(
                complete_receipt(
                    &wrong,
                    serde_json::from_str(&journal.detail).unwrap(),
                    Utc::now()
                )
                .is_err()
            );
            server.join().unwrap();
            std::fs::remove_file(dir.join("journal.dpapi")).unwrap();
            std::fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    #[cfg(windows)]
    fn generated_guest_script_runs_ordered_gets_and_restores_on_later_failure() {
        for expected in [201, 202] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now();
                let mut requests = vec![];
                while requests.len() < 2 && deadline.elapsed() < Duration::from_secs(20) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(3)))
                                .unwrap();
                            let mut bytes = [0; 4096];
                            let n = stream.read(&mut bytes).unwrap();
                            requests.push(
                                String::from_utf8_lossy(&bytes[..n])
                                    .lines()
                                    .next()
                                    .unwrap()
                                    .to_string(),
                            );
                            let status = if requests.len() == 1 { 200 } else { 201 };
                            write!(stream,"HTTP/1.1 {status} OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20))
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
                requests
            });
            let id = Uuid::new_v4().to_string();
            let dir = std::env::temp_dir().join(format!("relayne-multiget-{id}"));
            std::fs::create_dir(&dir).unwrap();
            let result = fake_run(
                &format!("{FAKE_GUARDS}\n{FAKE_REHEARSAL}\n$global:failOnce=$false"),
                serde_json::json!({"action":"test","user":"fixture","password":"fixture","service":"FixtureService","desiredRunning":true,"health":{"url":format!("http://{address}/first"),"expected_status":200,"body_marker":"ok","followups":[{"path":"/second","status":expected,"contains":"ok"}]},"lab":{"id":id,"name":"Owned","directory":dir.to_string_lossy(),"vm_id":id,"switch_id":id,"template":"fixture.vhdx","phase":"running","detail":""}}),
            );
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let journal = read_journal(&dir.join("journal.dpapi")).unwrap();
            let proof: serde_json::Value = serde_json::from_str(&journal.detail).unwrap();
            assert_eq!(proof["passed"], expected == 201);
            assert_eq!(proof["restored"], expected != 201);
            assert_eq!(
                server.join().unwrap(),
                vec!["GET /first HTTP/1.1", "GET /second HTTP/1.1"]
            );
            std::fs::remove_file(dir.join("journal.dpapi")).unwrap();
            std::fs::remove_dir(dir).unwrap();
        }
    }
    #[test]
    #[cfg(windows)]
    fn identical_guest_and_production_post_session_and_json_assertions() {
        use crate::execution::{
            HttpGetStep,
            http_health::{self, Method, Options, Values},
        };
        for guest in [false, true] {
            for (expected, count_body, count_expected, should_pass) in [
                ("ready", "3", 3_i64, true),
                ("wrong", "3", 3, false),
                ("ready", "4", 3, false),
                ("ready", "\"3\"", 3, false),
                ("ready", "3.0", 3, false),
                ("ready", "3e0", 3, false),
                ("ready", "null", 0, false),
                ("ready", "true", 1, false),
                ("ready", "9007199254740991", 9_007_199_254_740_991, true),
                ("ready", "-9007199254740991", -9_007_199_254_740_991, true),
            ] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let address = listener.local_addr().unwrap();
                let server = std::thread::spawn(move || {
                    let started = Instant::now();
                    let mut requests = vec![];
                    while requests.len() < 3 && started.elapsed() < Duration::from_secs(20) {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                stream.set_nonblocking(false).unwrap();
                                stream
                                    .set_read_timeout(Some(Duration::from_secs(3)))
                                    .unwrap();
                                let mut bytes = vec![];
                                let mut buf = [0; 4096];
                                loop {
                                    let n = stream.read(&mut buf).unwrap();
                                    if n == 0 {
                                        break;
                                    }
                                    bytes.extend_from_slice(&buf[..n]);
                                    if let Some(end) =
                                        bytes.windows(4).position(|w| w == b"\r\n\r\n")
                                    {
                                        let head = String::from_utf8_lossy(&bytes[..end]);
                                        let size = head
                                            .lines()
                                            .find_map(|l| {
                                                l.to_ascii_lowercase()
                                                    .strip_prefix("content-length:")
                                                    .map(|v| v.trim().parse::<usize>().unwrap())
                                            })
                                            .unwrap_or(0);
                                        if bytes.len() >= end + 4 + size {
                                            break;
                                        }
                                    }
                                }
                                requests.push(String::from_utf8(bytes).unwrap());
                                let account_body = format!(
                                    "{{\"state\":\"ready\",\"nothing\":null,\"count\":{count_body}}}"
                                );
                                let (body, cookie) = match requests.len() {
                                    1 => ("ok", ""),
                                    2 => (
                                        "{\"logged\":true}",
                                        "Set-Cookie: sid=fixture-session; Path=/; HttpOnly\r\n",
                                    ),
                                    _ => (account_body.as_str(), ""),
                                };
                                write!(stream,"HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(10))
                            }
                            Err(e) => panic!("{e}"),
                        }
                    }
                    requests
                });
                let steps = vec![
                    HttpGetStep {
                        path: "/login".into(),
                        status: 200,
                        contains: String::new(),
                        options: Options {
                            method: Method::Post,
                            form: Values::from([("username".into(), "public fixture".into())]),
                            secret_fields: Values::new(),
                            json_equals: std::collections::BTreeMap::from([(
                                "/logged".into(),
                                serde_json::json!(true),
                            )]),
                        },
                    },
                    HttpGetStep {
                        path: "/account".into(),
                        status: 200,
                        contains: String::new(),
                        options: Options {
                            json_equals: std::collections::BTreeMap::from([
                                ("/state".into(), serde_json::json!(expected)),
                                ("/nothing".into(), serde_json::Value::Null),
                                ("/count".into(), serde_json::json!(count_expected)),
                            ]),
                            ..Default::default()
                        },
                    },
                ];
                let health = HealthProbe {
                    url: format!("http://{address}/ready"),
                    expected_status: 200,
                    body_marker: "ok".into(),
                    followups: steps,
                };
                health.validate().unwrap();
                let passed = if guest {
                    let id = Uuid::new_v4().to_string();
                    let dir = std::env::temp_dir().join(format!("relayne-session-{id}"));
                    std::fs::create_dir(&dir).unwrap();
                    let request = BoundRequest {
                        restart: false,
                        id: Uuid::new_v4(),
                        lab_id: id.clone(),
                        vm_id: id.clone(),
                        binding: "a".repeat(64),
                        service: "FixtureService".into(),
                        desired_running: true,
                        health: health.clone(),
                        started: Utc::now(),
                    };
                    let result = fake_run(
                        &format!("{FAKE_GUARDS}\n{FAKE_REHEARSAL}\n$global:failOnce=$false"),
                        serde_json::json!({"action":"test","user":"fixture","password":"fixture","httpValues":{},"boundRequest":serde_json::to_string(&request).unwrap(),"service":"FixtureService","desiredRunning":true,"health":health,"lab":{"id":id,"name":"Owned","directory":dir.to_string_lossy(),"vm_id":id,"switch_id":id,"template":"fixture.vhdx","phase":"running","detail":""}}),
                    );
                    assert!(
                        result.status.success(),
                        "{}",
                        String::from_utf8_lossy(&result.stderr)
                    );
                    let journal = read_journal(&dir.join("journal.dpapi")).unwrap();
                    let receipt = complete_receipt(
                        &request,
                        serde_json::from_str(&journal.detail).unwrap(),
                        Utc::now(),
                    )
                    .unwrap();
                    assert_eq!(receipt.restored, !should_pass);
                    assert!(!journal.detail.contains("fixture-session"));
                    std::fs::remove_file(dir.join("journal.dpapi")).unwrap();
                    std::fs::remove_dir(dir).unwrap();
                    receipt.passed
                } else {
                    http_health::execute(&health.url, 200, "ok", &health.followups, &Values::new())
                        .unwrap()
                };
                assert_eq!(
                    passed, should_pass,
                    "guest {guest}, count {count_body}, expected {count_expected}"
                );
                let requests = server.join().unwrap();
                assert_eq!(requests.len(), 3);
                assert!(requests[0].starts_with("GET /ready "));
                assert!(requests[1].starts_with("POST /login "));
                assert!(requests[1].ends_with("username=public+fixture"));
                assert!(requests[2].starts_with("GET /account "));
                assert!(
                    requests[2]
                        .to_ascii_lowercase()
                        .contains("cookie: sid=fixture-session")
                );
            }
        }
    }
}
