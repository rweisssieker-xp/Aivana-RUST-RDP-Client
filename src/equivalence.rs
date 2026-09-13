//! Read-only, bounded observations required before a clone rehearsal can authorize production.
use crate::{
    execution::ExecutionPlan,
    security,
    test_lab::{Journal, LabReceipt},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub os_version: String,
    pub os_build: String,
    pub architecture: String,
    pub executable_hash: String,
    pub executable_version: String,
    pub configuration_hash: String,
    pub start_mode: String,
    pub dependencies: Vec<String>,
}
impl Fingerprint {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.os_version.is_empty()
                && !self.os_build.is_empty()
                && !self.architecture.is_empty()
                && matches!(
                    self.start_mode.as_str(),
                    "Auto" | "Manual" | "Disabled" | "Boot" | "System"
                ),
            "OS-Beobachtung unvollständig"
        );
        for hash in [&self.executable_hash, &self.configuration_hash] {
            ensure!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "Fingerprint unvollständig"
            );
        }
        ensure!(
            self.dependencies.len() <= 128 && serde_json::to_vec(self)?.len() <= 32768,
            "Fingerprint überschreitet Grenze"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Observation {
    plan_hash: String,
    lab_id: String,
    vm_id: String,
    started: DateTime<Utc>,
    finished: DateTime<Utc>,
    production: Fingerprint,
    guest: Fingerprint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RehearsalBaseline {
    pub observed_at: DateTime<Utc>,
    pub rehearsed_at: DateTime<Utc>,
    pub fingerprints: Vec<Fingerprint>,
}
pub fn rehearsal_baseline(
    plan: &ExecutionPlan,
    references: &[String],
    now: DateTime<Utc>,
) -> Result<RehearsalBaseline> {
    ensure!(references.len() <= 32, "Zu viele Nachweise");
    let receipts = references
        .iter()
        .map(|reference| crate::test_lab::load_receipt(reference))
        .collect::<Result<Vec<_>>>()?;
    crate::promotion::check_evidence(plan, &receipts, now)?;
    let mut observations = Vec::new();
    let mut rehearsed = Vec::new();
    for mapping in &plan.mappings {
        let receipt = receipts
            .iter()
            .find(|r| {
                r.lab_id == mapping.staging.profile_id.to_string()
                    && r.vm_id == mapping.staging.host
            })
            .context("Passender Lab-/VM-Nachweis fehlt")?;
        check(plan, receipt, now)?;
        let observation = load_observation(plan, receipt)?;
        // Validate the same loaded object used for the baseline, including on concurrent replacement.
        validate_observation(plan, receipt, now, &observation)?;
        rehearsed.push(receipt.finished);
        observations.push(observation);
    }
    Ok(RehearsalBaseline {
        observed_at: observations
            .iter()
            .map(|o| o.started)
            .min()
            .context("Beobachtung fehlt")?,
        rehearsed_at: rehearsed.into_iter().min().context("Nachweis fehlt")?,
        fingerprints: observations.into_iter().map(|o| o.production).collect(),
    })
}
pub fn observe_production(
    plan: &ExecutionPlan,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<Vec<Fingerprint>> {
    crate::promotion::validate(plan)?;
    let script = script(true);
    let mut fingerprints = Vec::with_capacity(plan.mappings.len());
    for mapping in &plan.mappings {
        let raw = run_raw(
            &script,
            serde_json::json!({"host":mapping.production.host,"service":plan.service}),
            cancel,
            Duration::from_secs(90),
        )?;
        fingerprints.push(decode_production(&raw)?);
    }
    ensure!(
        !cancel.load(std::sync::atomic::Ordering::Relaxed),
        "Beobachtung abgebrochen"
    );
    Ok(fingerprints)
}
fn decode_production(raw: &[u8]) -> Result<Fingerprint> {
    let fingerprint: Fingerprint = serde_json::from_slice(raw)
        .map_err(|_| anyhow::anyhow!("Fingerprint-Antwort unvollständig oder ungültig"))?;
    fingerprint.validate()?;
    Ok(fingerprint)
}
fn path(hash: &str, lab: &str) -> Result<std::path::PathBuf> {
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "Plan-Hash ungültig"
    );
    let id = uuid::Uuid::parse_str(lab)?;
    ensure!(!id.is_nil() && id.to_string() == lab, "Lab-ID ungültig");
    Ok(security::app_data_file("equivalence")?.join(format!("{hash}-{id}.dpapi")))
}
fn compare(production: &Fingerprint, guest: &Fingerprint) -> Result<()> {
    production.validate()?;
    guest.validate()?;
    // Explicit tolerance: machine identity and runtime state are excluded. Everything collected must match.
    ensure!(
        production == guest,
        "Vorlage/Produktion weichen ab: OS, Dienstbinärdatei, Startkonfiguration oder Abhängigkeiten. Vorlage aktualisieren und erneut prüfen."
    );
    Ok(())
}
pub(crate) fn check(plan: &ExecutionPlan, receipt: &LabReceipt, now: DateTime<Utc>) -> Result<()> {
    validate_observation(plan, receipt, now, &load_observation(plan, receipt)?)
}
fn load_observation(plan: &ExecutionPlan, receipt: &LabReceipt) -> Result<Observation> {
    let hash = plan.hash()?;
    let file = std::fs::File::open(path(&hash, &receipt.lab_id)?)
        .context("Automatischer Vorlage-/Produktionsvergleich fehlt")?;
    let mut raw = Vec::new();
    file.take(131073).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 131072, "Vergleichsbeleg zu groß");
    serde_json::from_slice(&security::unprotect_secret(&raw)?).context("Vergleichsbeleg ungültig")
}
fn validate_observation(
    plan: &ExecutionPlan,
    receipt: &LabReceipt,
    now: DateTime<Utc>,
    observation: &Observation,
) -> Result<()> {
    let hash = plan.hash()?;
    ensure!(
        observation.plan_hash == hash
            && observation.lab_id == receipt.lab_id
            && observation.vm_id == receipt.vm_id,
        "Vergleich gehört zu anderem Plan oder Klon"
    );
    ensure!(
        observation.started <= observation.finished
            && observation.finished <= receipt.started
            && receipt.started - observation.finished <= chrono::Duration::minutes(10)
            && observation.finished <= now
            && now - observation.started <= chrono::Duration::hours(1),
        "Vergleich veraltet oder zeitlich ungültig"
    );
    compare(&observation.production, &observation.guest)
}
pub fn observe(plan: &ExecutionPlan, lab: &Journal, user: &str, password: &str) -> Result<()> {
    crate::promotion::validate(plan)?;
    ensure!(
        !user.trim().is_empty()
            && user.len() <= 256
            && !password.is_empty()
            && password.len() <= 4096,
        "Gastzugang erforderlich"
    );
    let mapping = plan
        .mappings
        .iter()
        .find(|m| m.staging.profile_id.to_string() == lab.id && m.staging.host == lab.vm_id)
        .context("Lab-Zuordnung fehlt")?;
    let _lock = crate::test_lab::lock_lab(&lab.id)?;
    let current = crate::test_lab::journals()?
        .into_iter()
        .find(|j| j.id == lab.id && j.vm_id == lab.vm_id && j.directory == lab.directory)
        .context("Lab-Identität geändert")?;
    crate::promotion::lab_target(&current)?;
    let started = Utc::now();
    let payload = serde_json::json!({"host":mapping.production.host,"vm":lab.vm_id,"name":lab.name,"switch":lab.switch_id,"user":user,"password":password,"service":plan.service});
    let (production, guest) = collect(payload)?;
    compare(&production, &guest)?;
    let observation = Observation {
        plan_hash: plan.hash()?,
        lab_id: lab.id.clone(),
        vm_id: lab.vm_id.clone(),
        started,
        finished: Utc::now(),
        production,
        guest,
    };
    let target = path(&observation.plan_hash, &observation.lab_id)?;
    std::fs::create_dir_all(target.parent().context("Vergleichspfad")?)?;
    security::atomic_write(
        &target,
        &security::protect_secret(&serde_json::to_vec(&observation)?)?,
    )
}
fn collect(payload: serde_json::Value) -> Result<(Fingerprint, Fingerprint)> {
    run_script(&script(false), payload)
}
fn run_script(script: &str, payload: serde_json::Value) -> Result<(Fingerprint, Fingerprint)> {
    let raw = run_raw(
        script,
        payload,
        &std::sync::atomic::AtomicBool::new(false),
        Duration::from_secs(90),
    )?;
    #[derive(Deserialize)]
    struct Pair {
        production: Fingerprint,
        guest: Fingerprint,
    }
    let pair: Pair = serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("Fingerprint-Antwort unvollständig oder ungültig"))?;
    pair.production.validate()?;
    pair.guest.validate()?;
    Ok((pair.production, pair.guest))
}
fn run_raw(
    script: &str,
    payload: serde_json::Value,
    cancel: &std::sync::atomic::AtomicBool,
    timeout: Duration,
) -> Result<Vec<u8>> {
    ensure!(
        !cancel.load(std::sync::atomic::Ordering::Relaxed),
        "Beobachtung abgebrochen"
    );
    use base64::Engine;
    let bootstrap = format!(
        "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;try{{ {script} }}catch{{[Console]::Error.WriteLine('Readonly fingerprint collection failed');exit 1}}"
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        bootstrap
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
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
        .write_all(&serde_json::to_vec(&payload)?)?;
    let mut out = child.stdout.take().context("stdout")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut raw = Vec::new();
        let read = Read::by_ref(&mut out).take(131073).read_to_end(&mut raw);
        let _ = sender.send((read, raw));
    });
    let deadline = Instant::now();
    let mut status = None;
    let mut output = None;
    loop {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) || deadline.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Beobachtung abgebrochen oder Zeitgrenze überschritten");
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        if output.is_none() {
            output = receiver.try_recv().ok();
        }
        if output.as_ref().is_some_and(|(_, raw)| raw.len() > 131072) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Fingerprint überschreitet Ausgabegrenze");
        }
        if status.is_some_and(|s| !s.success()) {
            anyhow::bail!("Produktion konnte nicht gelesen werden; keine Freigabe");
        }
        if status.is_some() && output.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (read, raw) = output.context("Fingerprint-Leser fehlgeschlagen")?;
    read?;
    ensure!(
        raw.len() <= 131072,
        "Fingerprint überschreitet Ausgabegrenze"
    );
    Ok(raw)
}
fn script(production_only: bool) -> String {
    format!(
        "{FINGERPRINT_SCRIPT}\n{}",
        if production_only {
            PRODUCTION_SCRIPT
        } else {
            PAIR_SCRIPT
        }
    )
}
const FINGERPRINT_SCRIPT: &str = r#"
$fingerprint={param($service)
 $ErrorActionPreference='Stop'
 $os=Get-CimInstance Win32_OperatingSystem
 $s=Get-CimInstance Win32_Service -Filter ('Name='''+$service+'''')
 if(!$s){throw 'Service missing'}
 $key=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$service)
 $binary=[Environment]::ExpandEnvironmentVariables([string]$s.PathName)
 if($binary -match '^"([^"]+)"'){ $exe=$matches[1] }elseif($binary -match '^([^\s]+\.exe)(?:\s|$)'){ $exe=$matches[1] }else{throw 'Ambiguous executable path'}
 $item=Get-Item -LiteralPath $exe -ErrorAction Stop
 if($item.Length -gt 268435456){throw 'Executable exceeds 256 MiB'}
 $dependencies=@((Get-Service -Name $service -ErrorAction Stop).ServicesDependedOn | ForEach-Object {$_.Name.ToLowerInvariant()} | Sort-Object)
 if($dependencies.Count -gt 128){throw 'Dependency limit'}
 # Persist only a digest of command/account/configuration, never raw potentially secret arguments.
 $dllHash='';$parameterPath='HKLM:\SYSTEM\CurrentControlSet\Services\'+$service+'\Parameters'
 if(Test-Path -LiteralPath $parameterPath){
  $parameters=Get-ItemProperty -LiteralPath $parameterPath
  if($parameters.ServiceDll){
   $dll=[Environment]::ExpandEnvironmentVariables([string]$parameters.ServiceDll)
   if((Get-Item -LiteralPath $dll -ErrorAction Stop).Length -gt 268435456){throw 'Service DLL exceeds 256 MiB'}
   $dllHash=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
  }
 }
 $config=@([string]$s.PathName,[string]$s.StartName,[string]$s.ServiceType,[string]$key.Start,[string]$key.DelayedAutoStart,[string]$key.ErrorControl,$dllHash) | ConvertTo-Json -Compress
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$configHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($config)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 [pscustomobject]@{os_version=[string]$os.Version;os_build=[string]$os.BuildNumber;architecture=[string]$os.OSArchitecture;executable_hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant();executable_version=[string]$item.VersionInfo.FileVersion;configuration_hash=$configHash;start_mode=[string]$s.StartMode;dependencies=$dependencies}
}
"#;
const PRODUCTION_SCRIPT: &str = r#"
Invoke-Command -ComputerName $p.host -Authentication Negotiate -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000) -ScriptBlock $fingerprint -ArgumentList $p.service -ErrorAction Stop | ConvertTo-Json -Depth 5 -Compress
"#;
const PAIR_SCRIPT: &str = r#"
$vm=Get-VM -Id ([guid]$p.vm) -ErrorAction Stop
if($vm.Name -cne $p.name -or $vm.State -ne 'Running'){throw 'VM identity/state mismatch'}
$switch=Get-VMSwitch -Id ([guid]$p.switch) -ErrorAction Stop
if($switch.SwitchType -ne 'Private'){throw 'Isolation mismatch'}
$adapters=@(Get-VMNetworkAdapter -VM $vm)
if($adapters.Count -ne 1 -or $adapters[0].SwitchId -ne $switch.Id){throw 'VM topology mismatch'}
$production=Invoke-Command -ComputerName $p.host -Authentication Negotiate -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000) -ScriptBlock $fingerprint -ArgumentList $p.service -ErrorAction Stop
$secure=New-Object Security.SecureString
foreach($character in ([string]$p.password).ToCharArray()){$secure.AppendChar($character)}
$secure.MakeReadOnly();$credential=New-Object Management.Automation.PSCredential($p.user,$secure);$p.password=$null
try{$guest=Invoke-Command -VMId ([guid]$p.vm) -Credential $credential -ScriptBlock $fingerprint -ArgumentList $p.service -ErrorAction Stop}finally{$secure.Dispose()}
@{production=$production;guest=$guest}|ConvertTo-Json -Depth 5 -Compress
"#;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn fixture() -> Fingerprint {
        Fingerprint {
            os_version: "10.0.20348".into(),
            os_build: "20348".into(),
            architecture: "64-bit".into(),
            executable_hash: "a".repeat(64),
            executable_version: "1".into(),
            configuration_hash: "b".repeat(64),
            start_mode: "Auto".into(),
            dependencies: vec!["rpcss".into()],
        }
    }
    pub(crate) fn save_fixture(plan: &ExecutionPlan, receipt: &LabReceipt) {
        let observation = Observation {
            plan_hash: plan.hash().unwrap(),
            lab_id: receipt.lab_id.clone(),
            vm_id: receipt.vm_id.clone(),
            started: receipt.started - chrono::Duration::seconds(2),
            finished: receipt.started - chrono::Duration::seconds(1),
            production: fixture(),
            guest: fixture(),
        };
        let target = path(&observation.plan_hash, &observation.lab_id).unwrap();
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        security::atomic_write(
            &target,
            &security::protect_secret(&serde_json::to_vec(&observation).unwrap()).unwrap(),
        )
        .unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn actual_generated_script_uses_guarded_local_fixture() {
        // All remote and system-reading cmdlets are shadowed before the actual generated script runs.
        let prefix = SYSTEM_FIXTURE;
        let payload = serde_json::json!({"host":"fixture.invalid","vm":uuid::Uuid::new_v4(),"name":"fixture","switch":uuid::Uuid::new_v4(),"service":"fixture","user":"fixture","password":"fixture"});
        let (production, guest) =
            run_script(&format!("{prefix}\n{}", script(false)), payload).unwrap();
        compare(&production, &guest).unwrap();
        assert_eq!(guest.dependencies, vec!["rpcss"]);
    }
    #[test]
    #[cfg(windows)]
    fn production_script_is_readonly_and_uses_current_identity() {
        let guards = r#"
function Get-VM {throw 'Forbidden VM access'}
function Get-VMSwitch {throw 'Forbidden VM access'}
function Get-VMNetworkAdapter {throw 'Forbidden VM access'}
function Start-Service {throw 'Forbidden mutation'}
function Stop-Service {throw 'Forbidden mutation'}
function Set-ItemProperty {throw 'Forbidden mutation'}
function Invoke-Command {param($ComputerName,$Authentication,$SessionOption,$VMId,$Credential,$ScriptBlock,$ArgumentList,$ErrorAction)
 if($VMId -or $Credential -or $ComputerName -ne 'fixture.invalid' -or $Authentication -ne 'Negotiate'){throw 'Wrong transport'}
 & $ScriptBlock @ArgumentList
}
"#;
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let raw = run_raw(
            &format!("{SYSTEM_FIXTURE}\n{guards}\n{}", script(true)),
            serde_json::json!({"host":"fixture.invalid","service":"fixture"}),
            &cancel,
            Duration::from_secs(10),
        )
        .unwrap();
        let fingerprint = decode_production(&raw).unwrap();
        assert_eq!(fingerprint.dependencies, vec!["rpcss"]);
        assert!(decode_production(b"{}").is_err());
        assert!(
            decode_production(b"secret invalid json")
                .unwrap_err()
                .to_string()
                .find("secret")
                .is_none()
        );
    }
    #[test]
    #[cfg(windows)]
    fn collector_cancels_and_bounds_output() {
        let cancel = std::sync::atomic::AtomicBool::new(true);
        assert!(
            run_raw(
                "throw 'must not execute'",
                serde_json::json!({}),
                &cancel,
                Duration::from_secs(1)
            )
            .is_err()
        );
        cancel.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(
            run_raw(
                "[Console]::Write('x'*131073)",
                serde_json::json!({}),
                &cancel,
                Duration::from_secs(10)
            )
            .is_err()
        );
        assert!(
            run_raw(
                "Start-Sleep -Seconds 10",
                serde_json::json!({}),
                &cancel,
                Duration::from_millis(100)
            )
            .is_err()
        );
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = cancel.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            signal.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let started = Instant::now();
        assert!(
            run_raw(
                "Start-Sleep -Seconds 10",
                serde_json::json!({}),
                &cancel,
                Duration::from_secs(10)
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        worker.join().unwrap();
    }
    #[test]
    fn production_rejects_invalid_targets_before_starting_collection() {
        let target = crate::mission::Target {
            profile_id: uuid::Uuid::new_v4(),
            name: "fixture".into(),
            host: "fixture.invalid".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: String::new(),
            domain: String::new(),
            route: String::new(),
        };
        let staging = crate::mission::Target {
            profile_id: uuid::Uuid::new_v4(),
            host: uuid::Uuid::new_v4().to_string(),
            port: 0,
            protocol: crate::promotion::LAB_PROTOCOL.into(),
            route: "PowerShellDirect/private-switch".into(),
            ..target.clone()
        };
        let mut plan = ExecutionPlan {
            restart: false,
            service: "Spooler".into(),
            desired: crate::intelligence::ServiceState::Running,
            health: crate::execution::HealthCheck::Http {
                port: 8080,
                tls: false,
                path: "/health".into(),
                status: 200,
                contains: String::new(),
                followups: vec![],
            },
            mappings: vec![crate::execution::Mapping {
                production: target,
                staging,
            }],
        };
        let cancel = std::sync::atomic::AtomicBool::new(false);
        plan.mappings[0].production.host = "bad;host".into();
        assert!(observe_production(&plan, &cancel).is_err());
        plan.mappings[0].production.host = "fixture.invalid".into();
        plan.service = "bad'command".into();
        assert!(observe_production(&plan, &cancel).is_err());
    }
    const SYSTEM_FIXTURE: &str = r#"
function Get-VM {param($Id,$ErrorAction) [pscustomobject]@{Name=$p.name;State='Running'}}
function Get-VMSwitch {param($Id,$ErrorAction) [pscustomobject]@{Id=$p.switch;SwitchType='Private'}}
function Get-VMNetworkAdapter {param($VM) [pscustomobject]@{SwitchId=$p.switch}}
function Invoke-Command {param($ComputerName,$Authentication,$SessionOption,$VMId,$Credential,$ScriptBlock,$ArgumentList,$ErrorAction) & $ScriptBlock @ArgumentList}
function Get-CimInstance {param($ClassName,$Filter) if($ClassName -eq 'Win32_OperatingSystem'){[pscustomobject]@{Version='10.0';BuildNumber='20348';OSArchitecture='64-bit'}}else{[pscustomobject]@{PathName='C:\fixture.exe';StartName='LocalSystem';ServiceType='Own Process';StartMode='Auto'}}}
function Get-ItemProperty {param($LiteralPath) [pscustomobject]@{Start=2;DelayedAutoStart=0;ErrorControl=1}}
function Test-Path {param($LiteralPath) $false}
function Get-Item {param($LiteralPath,$ErrorAction) [pscustomobject]@{Length=20;VersionInfo=[pscustomobject]@{FileVersion='1'}}}
function Get-Service {param($Name,$ErrorAction) [pscustomobject]@{ServicesDependedOn=@([pscustomobject]@{Name='RpcSs'})}}
function Get-FileHash {param($LiteralPath,$Algorithm) [pscustomobject]@{Hash=('A'*64)}}
"#;
    #[test]
    fn comparison_is_strict_and_missing_observations_fail() {
        let base = fixture();
        assert!(compare(&base, &base).is_ok());
        for field in 0..8 {
            let mut changed = base.clone();
            match field {
                0 => changed.os_build.push('1'),
                1 => changed.os_version.push('1'),
                2 => changed.architecture.clear(),
                3 => changed.executable_hash = "c".repeat(64),
                4 => changed.executable_version.push('2'),
                5 => changed.configuration_hash = "d".repeat(64),
                6 => changed.start_mode = "Manual".into(),
                _ => changed.dependencies.clear(),
            };
            assert!(compare(&base, &changed).is_err());
        }
    }
}
