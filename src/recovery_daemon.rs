//! Explicit per-user scheduling. The only unattended mutation target is a bound Hyper-V clone.
use crate::{
    execution::ExecutionPlan,
    recovery_contracts::{Book, Check},
    security,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path, sync::atomic::AtomicBool};
use uuid::Uuid;
const SETTINGS: &str = "relayne-background.dpapi";
const NOTICES: &str = "relayne-background-notices.dpapi";
const CONTRACTS: &str = "relayne-recovery-contracts.dpapi";
fn task_name() -> Result<String> {
    use sha2::{Digest, Sha256};
    let directory = security::app_data_file(SETTINGS)?;
    Ok(format!(
        "RelayneRecoveryMonitor-{:x}",
        Sha256::digest(directory.to_string_lossy().as_bytes())
    ))
}
fn current_user() -> Result<String> {
    #[cfg(windows)]
    {
        #[link(name = "secur32")]
        unsafe extern "system" {
            fn GetUserNameExW(format: u32, buffer: *mut u16, size: *mut u32) -> u8;
        }
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        // NameSamCompatible identifies the actual process user as DOMAIN\\username.
        ensure!(
            unsafe { GetUserNameExW(2, buffer.as_mut_ptr(), &mut size) } != 0
                && size > 0
                && (size as usize) < buffer.len(),
            "Windows-Benutzeridentität nicht lesbar"
        );
        Ok(String::from_utf16(&buffer[..size as usize])?)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("Benötigt Windows")
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    pub contract_id: Uuid,
    pub plan_hash: String,
    pub expires: DateTime<Utc>,
    pub drill: bool,
    pub user: String,
    pub password: String,
}
impl Consent {
    fn authorizes(
        &self,
        id: Uuid,
        plan: &ExecutionPlan,
        now: DateTime<Utc>,
        drill: bool,
    ) -> Result<()> {
        ensure!(
            id == self.contract_id && self.plan_hash == plan.hash()?,
            "Freigabe passt nicht zum exakten Plan und seinen Klonen"
        );
        ensure!(now < self.expires, "Hintergrundfreigabe abgelaufen");
        ensure!(
            !drill || (self.drill && !self.user.trim().is_empty() && !self.password.is_empty()),
            "Keine Klonfreigabe mit Gastzugang"
        );
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub consents: Vec<Consent>,
    #[serde(default)]
    pub windows_hints: bool,
    #[serde(skip)]
    source_digest: Option<Vec<u8>>,
}
impl Settings {
    pub fn load() -> Result<Self> {
        Self::load_named(SETTINGS)
    }
    fn load_named(name: &str) -> Result<Self> {
        let Some(bytes) = read(name)? else {
            return Ok(Self::default());
        };
        let raw = security::unprotect_secret(&bytes)?;
        ensure!(raw.len() <= 2 * 1024 * 1024, "Hintergrundspeicher zu groß");
        let mut settings: Self =
            serde_json::from_slice(&raw).context("Hintergrundspeicher beschädigt")?;
        settings.validate()?;
        settings.source_digest = Some(digest(&bytes));
        Ok(settings)
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.consents.len() <= 128, "Zu viele Freigaben");
        let mut ids = std::collections::BTreeSet::new();
        for c in &self.consents {
            ensure!(
                ids.insert(c.contract_id)
                    && !c.contract_id.is_nil()
                    && c.plan_hash.len() == 64
                    && c.plan_hash.bytes().all(|b| b.is_ascii_hexdigit())
                    && c.user.len() <= 256
                    && c.password.len() <= 4096
                    && (!c.drill || (!c.user.trim().is_empty() && !c.password.is_empty()))
                    && (c.drill || (c.user.is_empty() && c.password.is_empty())),
                "Freigabe ungültig"
            );
            ensure!(
                c.expires <= Utc::now() + chrono::Duration::hours(168),
                "Freigabe maximal 168 Stunden"
            );
        }
        Ok(())
    }
    pub fn save(&mut self) -> Result<()> {
        self.save_named(SETTINGS)
    }
    fn save_named(&mut self, name: &str) -> Result<()> {
        self.validate()?;
        let _lock = lock(&format!("{name}.lock"))?;
        ensure!(
            read(name)?.map(|bytes| digest(&bytes)) == self.source_digest,
            "Freigaben wurden parallel geändert; neu laden"
        );
        let bytes = security::protect_secret(&serde_json::to_vec(self)?)?;
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "Hintergrundspeicher zu groß"
        );
        security::atomic_write(&security::app_data_file(name)?, &bytes)?;
        self.source_digest = Some(digest(&bytes));
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Notice {
    pub id: Uuid,
    pub contract_id: Uuid,
    pub at: DateTime<Utc>,
    pub kind: String,
    pub message: String,
    pub read: bool,
}
#[derive(Default, Serialize, Deserialize)]
pub struct Notices {
    pub items: Vec<Notice>,
}
impl Notices {
    pub fn load() -> Result<Self> {
        load(NOTICES)
    }
    fn push(&mut self, contract_id: Uuid, kind: &str, message: &str) -> bool {
        if let Some(previous) = self
            .items
            .iter()
            .rev()
            .filter(|n| n.contract_id == contract_id)
            .take_while(|n| !(matches!(n.kind.as_str(), "renewed" | "ready") && n.kind != kind))
            .find(|n| {
                n.kind == kind
                    && n.message == message
                    && Utc::now() < n.at + chrono::Duration::hours(24)
            })
        {
            if matches!(
                kind,
                "changed" | "failed" | "drill-failed" | "storage" | "expired" | "due" | "missing"
            ) && Utc::now() >= previous.at + chrono::Duration::hours(1)
            {
                return self.push(contract_id, &format!("{kind}-escalated"), "Seit mindestens einer Stunde offen: Recovery-Nachweise oder Hintergrundfreigabe prüfen");
            }
            return false;
        }
        self.items.push(Notice {
            id: Uuid::new_v4(),
            contract_id,
            at: Utc::now(),
            kind: kind.into(),
            message: message.chars().take(512).collect(),
            read: false,
        });
        if self.items.len() > 256 {
            self.items.drain(..self.items.len() - 256);
        }
        true
    }
    pub fn mark_read() -> Result<()> {
        let _lock = lock("relayne-background-notices.lock")?;
        let mut notices = Self::load()?;
        for n in &mut notices.items {
            n.read = true;
        }
        save(NOTICES, &notices)
    }
}
pub fn unread_count() -> usize {
    Notices::load().map_or(0, |n| n.items.iter().filter(|n| !n.read).count())
}
fn notify(id: Uuid, kind: &str, message: &str) -> Result<()> {
    let _lock = lock("relayne-background-notices.lock")?;
    let mut notices = Notices::load()?;
    let added = notices.push(id, kind, message);
    save(NOTICES, &notices)?;
    drop(_lock);
    if added && Settings::load().is_ok_and(|s| s.windows_hints) {
        let _ = windows_hint();
    }
    Ok(())
}
const HINT_SCRIPT: &str = r#"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $n=New-Object System.Windows.Forms.NotifyIcon; try {$n.Icon=[System.Drawing.SystemIcons]::Warning; $n.Visible=$true; $n.ShowBalloonTip(5000,'Relayne Recovery','Neue Recovery-Meldung. Hintergrundbereich in Relayne oeffnen.',[System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 6} finally {$n.Dispose()}"#;
fn windows_hint() -> Result<()> {
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", HINT_SCRIPT]);
    bounded_process(cmd, std::time::Duration::from_secs(10)).map(|_| ())
}
fn bounded_process(
    mut command: std::process::Command,
    timeout: std::time::Duration,
) -> Result<std::process::ExitStatus> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Lokaler Windows-Helfer überschreitet Zeitlimit");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
fn load<T: serde::de::DeserializeOwned + Default>(name: &str) -> Result<T> {
    let Some(bytes) = read(name)? else {
        return Ok(T::default());
    };
    let raw = security::unprotect_secret(&bytes)?;
    ensure!(raw.len() <= 2 * 1024 * 1024, "Hintergrundspeicher zu groß");
    serde_json::from_slice(&raw).context("Hintergrundspeicher beschädigt")
}
fn read(name: &str) -> Result<Option<Vec<u8>>> {
    let path = security::app_data_file(name)?;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        file.metadata()?.len() <= 2 * 1024 * 1024,
        "Hintergrundspeicher zu groß"
    );
    let mut bytes = vec![];
    file.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 2 * 1024 * 1024,
        "Hintergrundspeicher zu groß"
    );
    Ok(Some(bytes))
}
fn save<T: Serialize>(name: &str, value: &T) -> Result<()> {
    let bytes = security::protect_secret(&serde_json::to_vec(value)?)?;
    ensure!(
        bytes.len() <= 2 * 1024 * 1024,
        "Hintergrundspeicher zu groß"
    );
    security::atomic_write(&security::app_data_file(name)?, &bytes)
}
fn lock(name: &str) -> Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(security::app_data_file(name)?)
            .context("Hintergrundvorgang läuft bereits")
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        anyhow::bail!("Benötigt Windows")
    }
}
fn active(id: Uuid, plan: &ExecutionPlan, drill: bool) -> Result<Consent> {
    let settings = Settings::load()?;
    ensure!(settings.enabled, "Hintergrundarbeit deaktiviert");
    let consent = settings
        .consents
        .into_iter()
        .find(|c| c.contract_id == id)
        .context("Freigabe entfernt")?;
    consent.authorizes(id, plan, Utc::now(), drill)?;
    let book = Book::load(&security::app_data_file(CONTRACTS)?)?;
    let current = book
        .contracts
        .iter()
        .find(|c| c.id == id)
        .context("Vertrag entfernt")?;
    ensure!(
        current.enabled && current.plan.hash()? == plan.hash()?,
        "Vertrag pausiert oder geändert"
    );
    let profiles = crate::services::ProfileStore::new()?.load()?;
    ensure!(
        profiles_match(plan, &profiles),
        "Produktionsprofil geändert oder entfernt"
    );
    Ok(consent)
}
fn profiles_match(plan: &ExecutionPlan, profiles: &[crate::models::ConnectionProfile]) -> bool {
    plan.mappings
        .iter()
        .all(|mapping| profiles.iter().any(|p| mapping.production.matches(p)))
}
fn observe_check(
    plan: &ExecutionPlan,
    observer: impl FnOnce(&ExecutionPlan) -> Result<Vec<crate::equivalence::Fingerprint>>,
) -> Check {
    let started = Utc::now();
    let (fingerprints, error) = match observer(plan) {
        Ok(f) => (f, None),
        Err(_) => (vec![], Some("Produktionsvergleich fehlgeschlagen".into())),
    };
    Check {
        started,
        finished: Utc::now(),
        fingerprints,
        error,
    }
}
fn rehearse(contract: &mut crate::recovery_contracts::Contract) -> Result<()> {
    let hash = contract.plan.hash()?;
    let health = crate::promotion::health(&contract.plan)?;
    let mut refs = vec![];
    for mapping in &contract.plan.mappings {
        let consent = active(contract.id, &contract.plan, true)?;
        let lab = crate::test_lab::journals()?
            .into_iter()
            .find(|l| {
                l.id == mapping.staging.profile_id.to_string() && l.vm_id == mapping.staging.host
            })
            .context("Autorisierter Klon fehlt oder VM wurde ersetzt")?;
        ensure!(
            crate::promotion::lab_target(&lab)?.host == mapping.staging.host,
            "Klon nicht bereit"
        );
        crate::equivalence::observe(&contract.plan, &lab, &consent.user, &consent.password)?;
        let consent = active(contract.id, &contract.plan, true)?;
        let receipt = crate::test_lab::execute_bound_repair_with_values(
            lab,
            consent.user,
            consent.password,
            contract.plan.service.clone(),
            contract.plan.desired.label() == "Running",
            health.clone(),
            hash.clone(),
            Default::default(),
            contract.plan.restart,
        )?;
        refs.push(receipt.reference());
    }
    active(contract.id, &contract.plan, true)?;
    let now = Utc::now();
    crate::promotion::check_rehearsal_receipts(&contract.plan, &refs, now)?;
    let baseline = crate::equivalence::rehearsal_baseline(&contract.plan, &refs, now)?;
    contract.renew(contract.plan.clone(), refs, baseline, now)
}
/// One bounded pass. Production is observed only; clone drills cannot call production execution.
pub fn run_once() -> Result<usize> {
    let _run = lock("relayne-background-worker.lock")?;
    let settings = Settings::load()?;
    if !settings.enabled {
        return Ok(0);
    }
    ensure!(settings.consents.len() <= 128, "Zu viele Freigaben");
    let path = security::app_data_file(CONTRACTS)?;
    let mut count = 0;
    for consent in settings.consents.iter().take(128) {
        let mut book = Book::load(&path)?;
        let Some(index) = book
            .contracts
            .iter()
            .position(|c| c.id == consent.contract_id)
        else {
            notify(
                consent.contract_id,
                "missing",
                "Vertrag fehlt; Freigabe entfernen oder neu konfigurieren",
            )?;
            continue;
        };
        let c = &book.contracts[index];
        if !c.enabled {
            continue;
        }
        if active(c.id, &c.plan, false).is_err() {
            notify(
                c.id,
                "expired",
                "Freigabe abgelaufen, entfernt oder Plan geändert; Hintergrundarbeit pausiert",
            )?;
            continue;
        }
        if c.check_due(Utc::now()) {
            let was_failed = c
                .last_check
                .as_ref()
                .is_some_and(|check| check.error.is_some());
            let check = observe_check(&c.plan, |plan| {
                crate::equivalence::observe_production(plan, &AtomicBool::new(false))
            });
            let c = &mut book.contracts[index];
            c.apply_check(c.revision, check, Utc::now())?;
            if let Err(e) = book.save(&path) {
                notify(
                    consent.contract_id,
                    "storage",
                    "Vergleich nicht vollständig gespeichert; Ausführung gesperrt oder erneutes Laden erforderlich",
                )?;
                return Err(e);
            }
            count += 1;
            let saved = &book.contracts[index];
            if was_failed
                && saved.invalidated.is_none()
                && saved
                    .last_check
                    .as_ref()
                    .is_some_and(|check| check.error.is_none())
            {
                notify(
                    saved.id,
                    "ready",
                    "Produktionsvergleich wieder erfolgreich; Frist für Generalprobe bleibt unverändert",
                )?;
            }
        }
        let c = &book.contracts[index];
        let due = Utc::now() >= c.next_rehearsal_at() || c.invalidated.is_some();
        if c.invalidated.is_some() {
            notify(
                c.id,
                "changed",
                "Produktionsänderung erkannt; Nachweise entwertet",
            )?;
        } else if c.last_check.as_ref().is_some_and(|c| c.error.is_some()) {
            notify(
                c.id,
                "failed",
                "Produktionsvergleich fehlgeschlagen; Zustand unbekannt",
            )?;
        }
        if count >= 4 {
            break;
        }
        if due {
            if consent.drill {
                // Persist the attempt before touching a clone: failures and process crashes back off one hour.
                let mut attempts: Attempts = load("relayne-background-attempts.dpapi")?;
                if attempts
                    .last
                    .get(&c.id)
                    .is_some_and(|at| Utc::now() < *at + chrono::Duration::hours(1))
                {
                    continue;
                }
                attempts.last.insert(c.id, Utc::now());
                attempts
                    .last
                    .retain(|id, _| settings.consents.iter().any(|c| c.contract_id == *id));
                save("relayne-background-attempts.dpapi", &attempts)?;
                match rehearse(&mut book.contracts[index]) {
                    Ok(()) => {
                        book.save(&path)?;
                        notify(
                            consent.contract_id,
                            "renewed",
                            "Echte Klon-Generalprobe bestanden; Vertrag mit frischen Nachweisen erneuert",
                        )?;
                    }
                    Err(_) => {
                        notify(
                            consent.contract_id,
                            "drill-failed",
                            "Klon-Generalprobe fehlgeschlagen; keine Erneuerung. Lab-Journal und Zugang prüfen; frühester Neuversuch in einer Stunde",
                        )?;
                    }
                }
                count += 1;
            } else {
                notify(
                    c.id,
                    "due",
                    "Neue Klon-Generalprobe fällig; keine unbeaufsichtigte Klonfreigabe",
                )?;
            }
        }
        if count >= 4 {
            break;
        }
    }
    Ok(count)
}
#[derive(Default, Serialize, Deserialize)]
struct Attempts {
    last: std::collections::BTreeMap<Uuid, DateTime<Utc>>,
}
fn task_xml(executable: &Path, user: &str) -> Result<String> {
    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
    let executable = executable.to_str().context("Ungültiger Programmpfad")?;
    ensure!(
        !executable.chars().any(char::is_control)
            && !user.is_empty()
            && !user.chars().any(char::is_control),
        "Ungültiger Programmpfad"
    );
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{}</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id="Author"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>{}</Command><Arguments>--recovery-worker-once</Arguments></Exec></Actions></Task>"#,
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        escape(user),
        escape(executable)
    ))
}
fn scheduler(args: &[&std::ffi::OsStr]) -> Result<()> {
    let mut command = std::process::Command::new("schtasks.exe");
    command.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Aufgabenplanung überschreitet Zeitlimit; Windows-Aufgabenstatus prüfen");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    ensure!(
        status.success(),
        "Windows-Aufgabenplanung fehlgeschlagen; Rechte und Aufgabenplanung prüfen"
    );
    Ok(())
}
pub fn install_task() -> Result<()> {
    let settings = Settings::load()?;
    ensure!(
        settings.enabled && settings.consents.iter().any(|c| c.expires > Utc::now()),
        "Zuerst ausdrückliche Freigaben speichern"
    );
    let path = security::app_data_file(&format!("recovery-task-{}.xml", Uuid::new_v4()))?;
    let xml = task_xml(&std::env::current_exe()?, &current_user()?)?;
    let bytes: Vec<u8> = std::iter::once(0xfeffu16)
        .chain(xml.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    std::fs::write(&path, bytes)?;
    let name = task_name()?;
    let result = scheduler(&[
        "/Create".as_ref(),
        "/TN".as_ref(),
        name.as_ref(),
        "/XML".as_ref(),
        path.as_os_str(),
        "/F".as_ref(),
    ]);
    let _ = std::fs::remove_file(path);
    result
}
pub fn remove_task() -> Result<()> {
    let mut settings = Settings::load()?;
    settings.enabled = false;
    settings.consents.clear();
    settings.save()?;
    let name = task_name()?;
    scheduler(&[
        "/Delete".as_ref(),
        "/TN".as_ref(),
        name.as_ref(),
        "/F".as_ref(),
    ])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unresolved_notice_escalates_after_an_hour_without_flooding() {
        let mut notices = Notices::default();
        let id = Uuid::new_v4();
        assert!(notices.push(id, "failed", "failure"));
        assert!(!notices.push(id, "failed", "failure"));
        notices.items[0].at = Utc::now() - chrono::Duration::minutes(61);
        assert!(notices.push(id, "failed", "failure"));
        assert_eq!(notices.items[1].kind, "failed-escalated");
        assert!(!notices.push(id, "failed", "failure"));
        assert_eq!(notices.items.len(), 2);
        assert!(notices.push(id, "renewed", "success"));
        assert!(notices.push(id, "failed", "failure"));
        assert_eq!(notices.items.last().unwrap().kind, "failed");
        assert!(!HINT_SCRIPT.contains("password"));
    }
    #[test]
    fn production_profile_removal_or_endpoint_change_blocks_work() {
        let profile =
            crate::models::ConnectionProfile::sample("fixture", "prod.example.invalid", "", false);
        let mut plan = crate::promotion::tests::plan();
        plan.mappings[0].production = crate::mission::Target::from_profile(&profile);
        assert!(profiles_match(&plan, std::slice::from_ref(&profile)));
        assert!(!profiles_match(&plan, &[]));
        let mut changed = profile;
        changed.host = "different.example.invalid".into();
        assert!(!profiles_match(&plan, &[changed]));
    }
    #[test]
    fn stale_settings_cannot_resurrect_removed_consent() {
        let name = format!("daemon-cas-{}.dpapi", Uuid::new_v4());
        let mut initial = Settings::load_named(&name).unwrap();
        initial.enabled = true;
        initial.save_named(&name).unwrap();
        let mut stale = Settings::load_named(&name).unwrap();
        let mut fresh = Settings::load_named(&name).unwrap();
        fresh.enabled = false;
        fresh.save_named(&name).unwrap();
        stale.enabled = true;
        assert!(stale.save_named(&name).is_err());
        assert!(!Settings::load_named(&name).unwrap().enabled);
    }
    #[test]
    fn invalid_loaded_settings_fail_closed() {
        let name = format!("daemon-invalid-{}.dpapi", Uuid::new_v4());
        let mut invalid = Settings::default();
        invalid.consents.push(Consent {
            contract_id: Uuid::nil(),
            plan_hash: "bad".into(),
            expires: Utc::now(),
            drill: true,
            user: String::new(),
            password: String::new(),
        });
        save(&name, &invalid).unwrap();
        assert!(Settings::load_named(&name).is_err());
    }
    #[test]
    fn failed_observer_never_exports_adapter_secrets() {
        let check = observe_check(&crate::promotion::tests::plan(), |_| {
            anyhow::bail!("password=secret-example")
        });
        assert!(check.error.is_some());
        assert!(check.fingerprints.is_empty());
        assert!(
            !serde_json::to_string(&check)
                .unwrap()
                .contains("secret-example")
        );
        assert!(check.finished >= check.started);
    }
    #[test]
    fn scheduled_command_has_no_credentials_and_uses_interactive_user() {
        let xml = task_xml(
            Path::new("C:\\Program Files\\A&B\\relayne.exe"),
            "DOMAIN\\fixture",
        )
        .unwrap();
        assert!(xml.contains("A&amp;B"));
        assert!(xml.contains("InteractiveToken"));
        assert!(xml.contains("--recovery-worker-once"));
        assert!(xml.contains("LeastPrivilege"));
        assert!(!xml.contains("Password"));
        assert!(xml.contains("IgnoreNew"));
    }
    #[test]
    fn exact_consent_expires_and_rejects_changed_plan() {
        let now = Utc::now();
        let plan = crate::promotion::tests::plan();
        let mut consent = Consent {
            contract_id: Uuid::new_v4(),
            plan_hash: plan.hash().unwrap(),
            expires: now + chrono::Duration::hours(1),
            drill: true,
            user: "guest".into(),
            password: "fixture".into(),
        };
        assert!(
            consent
                .authorizes(consent.contract_id, &plan, now, true)
                .is_ok()
        );
        assert!(
            consent
                .authorizes(consent.contract_id, &plan, consent.expires, true)
                .is_err()
        );
        let mut changed = plan.clone();
        changed.service = "OtherService".into();
        assert!(
            consent
                .authorizes(consent.contract_id, &changed, now, true)
                .is_err()
        );
        consent.drill = false;
        assert!(
            consent
                .authorizes(consent.contract_id, &plan, now, true)
                .is_err()
        );
        assert!(
            consent
                .authorizes(consent.contract_id, &plan, now, false)
                .is_ok()
        );
    }
    #[test]
    fn notifications_are_bounded_and_identical_results_deduplicated() {
        let mut notices = Notices::default();
        let id = Uuid::new_v4();
        notices.push(id, "changed", "changed");
        notices.push(id, "changed", "changed");
        assert_eq!(notices.items.len(), 1);
        for _ in 0..400 {
            notices.push(Uuid::new_v4(), "due", "due");
        }
        assert_eq!(notices.items.len(), 256);
    }
}
