//! Local recovery contracts: observations never renew successful rehearsal evidence.
use crate::{
    equivalence::{Fingerprint, RehearsalBaseline},
    execution::ExecutionPlan,
    security,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};
use uuid::Uuid;
const MAX_STORE: usize = 4 * 1024 * 1024;
const MAX_REVOKED: usize = 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub started: DateTime<Utc>,
    pub finished: DateTime<Utc>,
    pub fingerprints: Vec<Fingerprint>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub id: Uuid,
    pub revision: u64,
    pub name: String,
    pub plan: ExecutionPlan,
    pub references: Vec<String>,
    pub baseline: RehearsalBaseline,
    pub check_minutes: u32,
    pub rehearsal_hours: u32,
    pub enabled: bool,
    pub last_check: Option<Check>,
    pub invalidated: Option<String>,
    pub invalidated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked_references: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    CheckDue,
    RehearsalDue,
    Changed,
    Unknown,
    Paused,
}
fn refs_valid(refs: &[String], max: usize) -> Result<()> {
    ensure!(refs.len() <= max, "Zu viele Nachweisverweise");
    let mut seen = BTreeSet::new();
    for reference in refs {
        ensure!(
            !reference.trim().is_empty()
                && reference.len() <= 1024
                && !reference.chars().any(char::is_control)
                && seen.insert(reference),
            "Nachweisverweis ungültig oder doppelt"
        );
    }
    Ok(())
}
fn safe(text: &str) -> String {
    security::redact_secret_text(text)
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}
fn baseline_valid(
    plan: &ExecutionPlan,
    refs: &[String],
    baseline: &RehearsalBaseline,
    now: DateTime<Utc>,
) -> Result<()> {
    crate::promotion::validate(plan)?;
    refs_valid(refs, 32)?;
    ensure!(
        refs.len() == plan.mappings.len() && baseline.fingerprints.len() == plan.mappings.len(),
        "Nachweise und Fingerprints müssen allen Zielen entsprechen"
    );
    ensure!(
        baseline.observed_at <= baseline.rehearsed_at && baseline.rehearsed_at <= now,
        "Rehearsal-Zeitfolge ungültig"
    );
    for fp in &baseline.fingerprints {
        fp.validate()?;
    }
    Ok(())
}
impl Contract {
    pub fn new(
        name: String,
        plan: ExecutionPlan,
        references: Vec<String>,
        baseline: RehearsalBaseline,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let c = Self {
            id: Uuid::new_v4(),
            revision: 1,
            name: safe(&name),
            plan,
            references,
            baseline,
            check_minutes: 60,
            rehearsal_hours: 24,
            enabled: true,
            last_check: None,
            invalidated: None,
            invalidated_at: None,
            revoked_references: vec![],
        };
        c.validate_at(now)?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_at(Utc::now())
    }
    fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            !self.id.is_nil()
                && self.revision > 0
                && !self.name.trim().is_empty()
                && self.name.len() <= 1024,
            "Vertrag ungültig"
        );
        Self::validate_settings(self.check_minutes, self.rehearsal_hours)?;
        baseline_valid(&self.plan, &self.references, &self.baseline, now)?;
        refs_valid(&self.revoked_references, MAX_REVOKED)?;
        ensure!(
            !self
                .references
                .iter()
                .any(|r| self.revoked_references.contains(r)),
            "Aktiver Nachweis wurde widerrufen"
        );
        ensure!(
            self.invalidated.is_some() == self.invalidated_at.is_some()
                && self.invalidated_at.is_none_or(|at| at <= now),
            "Widerrufszeit ungültig"
        );
        if let Some(reason) = &self.invalidated {
            ensure!(
                !reason.trim().is_empty() && reason.len() <= 4096,
                "Ungültiger Widerrufsgrund"
            );
        }
        if let Some(check) = &self.last_check {
            self.validate_check(check, self.baseline.observed_at, now)?;
            ensure!(
                check.error.is_some()
                    || check.fingerprints == self.baseline.fingerprints
                    || self.invalidated.is_some(),
                "Drift ohne Widerruf"
            );
        }
        Ok(())
    }
    fn validate_settings(minutes: u32, hours: u32) -> Result<()> {
        ensure!(
            (5..=1440).contains(&minutes) && (1..=720).contains(&hours),
            "Prüfintervall 5–1440 Minuten; Generalprobe 1–720 Stunden"
        );
        Ok(())
    }
    pub fn set_settings(&mut self, minutes: u32, hours: u32, enabled: bool) -> Result<()> {
        Self::validate_settings(minutes, hours)?;
        let revision = self
            .revision
            .checked_add(1)
            .context("Vertragsrevision erschöpft")?;
        self.check_minutes = minutes;
        self.rehearsal_hours = hours;
        self.enabled = enabled;
        self.revision = revision;
        Ok(())
    }
    pub fn invalidate(&mut self, reason: &str) {
        self.invalidate_at(reason, Utc::now());
    }
    pub fn invalidate_at(&mut self, reason: &str, at: DateTime<Utc>) {
        self.invalidated_at = Some(self.invalidated_at.map_or(at, |previous| previous.max(at)));
        if self.invalidated.is_none() {
            let reason = safe(reason);
            self.invalidated = Some(if reason.trim().is_empty() {
                "Nachweis widerrufen".into()
            } else {
                reason
            });
        }
    }
    fn validate_check(
        &self,
        check: &Check,
        after: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        ensure!(
            after <= check.started && check.started <= check.finished && check.finished <= now,
            "Prüfzeitfolge ungültig"
        );
        ensure!(
            check.fingerprints.len() <= self.plan.mappings.len(),
            "Zu viele Fingerprints"
        );
        if let Some(error) = &check.error {
            ensure!(
                !error.trim().is_empty() && error.len() <= 4096,
                "Prüffehler ungültig"
            );
        } else {
            ensure!(
                check.fingerprints.len() == self.plan.mappings.len(),
                "Zielbeobachtungen fehlen"
            );
        }
        for fp in &check.fingerprints {
            fp.validate()?;
        }
        Ok(())
    }
    pub fn apply_check(
        &mut self,
        revision: u64,
        mut check: Check,
        now: DateTime<Utc>,
    ) -> Result<()> {
        ensure!(revision == self.revision, "Veraltete Vertragsrevision");
        let after = self
            .last_check
            .as_ref()
            .map_or(self.baseline.observed_at, |c| c.finished);
        self.validate_check(&check, after, now)?;
        if check.error.is_none() {
            let changes = drift(&self.baseline.fingerprints, &check.fingerprints);
            if !changes.is_empty() {
                self.invalidate_at(&changes.join("; "), check.finished);
            }
        }
        check.error = check
            .error
            .map(|_| "Read-only-Prüfung fehlgeschlagen; Zielzustand unbekannt".into());
        self.last_check = Some(check);
        Ok(())
    }
    pub fn renew(
        &mut self,
        plan: ExecutionPlan,
        references: Vec<String>,
        baseline: RehearsalBaseline,
        now: DateTime<Utc>,
    ) -> Result<()> {
        baseline_valid(&plan, &references, &baseline, now)?;
        ensure!(
            plan.hash()? == self.plan.hash()?,
            "Neuer Plan benötigt eigenen Vertrag"
        );
        ensure!(
            baseline.rehearsed_at > self.baseline.rehearsed_at
                && baseline.observed_at > self.baseline.observed_at
                && self
                    .invalidated_at
                    .is_none_or(|at| baseline.observed_at >= at)
                && self
                    .last_check
                    .as_ref()
                    .is_none_or(|c| baseline.observed_at >= c.finished),
            "Neue erfolgreiche Generalprobe erforderlich"
        );
        ensure!(
            references
                .iter()
                .all(|r| !self.references.contains(r) && !self.revoked_references.contains(r)),
            "Neue Nachweise erforderlich"
        );
        ensure!(
            self.revoked_references.len() + self.references.len() <= MAX_REVOKED,
            "Widerrufsspeicher voll; Vertrag kann nicht erneuert werden"
        );
        let revision = self
            .revision
            .checked_add(1)
            .context("Vertragsrevision erschöpft")?;
        self.revoked_references.extend(self.references.clone());
        self.references = references;
        self.plan = plan;
        self.baseline = baseline;
        self.last_check = None;
        self.invalidated = None;
        self.invalidated_at = None;
        self.revision = revision;
        Ok(())
    }
    pub fn next_check_at(&self) -> DateTime<Utc> {
        self.last_check
            .as_ref()
            .map_or(self.baseline.observed_at, |c| c.finished)
            + Duration::minutes(i64::from(self.check_minutes))
    }
    pub fn next_rehearsal_at(&self) -> DateTime<Utc> {
        self.baseline.rehearsed_at + Duration::hours(i64::from(self.rehearsal_hours))
    }
    pub fn check_due(&self, now: DateTime<Utc>) -> bool {
        self.enabled && now >= self.next_check_at()
    }
    fn active_readiness(&self, now: DateTime<Utc>) -> Readiness {
        if self.invalidated.is_some() {
            return Readiness::Changed;
        }
        if self.validate_at(now).is_err() {
            return Readiness::Unknown;
        }
        if now >= self.next_rehearsal_at() {
            return Readiness::RehearsalDue;
        }
        if self.last_check.as_ref().is_some_and(|c| c.error.is_some()) {
            return Readiness::Unknown;
        }
        if now >= self.next_check_at() {
            Readiness::CheckDue
        } else {
            Readiness::Ready
        }
    }
    pub fn readiness(&self, now: DateTime<Utc>) -> Readiness {
        let state = self.active_readiness(now);
        if state == Readiness::Changed {
            state
        } else if !self.enabled {
            Readiness::Paused
        } else {
            state
        }
    }
}
fn drift(baseline: &[Fingerprint], current: &[Fingerprint]) -> Vec<String> {
    let mut changes = vec![];
    for (i, (a, b)) in baseline.iter().zip(current).enumerate() {
        let fields = [
            ("OS-Version", a.os_version != b.os_version),
            ("OS-Build", a.os_build != b.os_build),
            ("Architektur", a.architecture != b.architecture),
            ("Binärdatei", a.executable_hash != b.executable_hash),
            ("Dateiversion", a.executable_version != b.executable_version),
            (
                "Konfiguration",
                a.configuration_hash != b.configuration_hash,
            ),
            ("Startmodus", a.start_mode != b.start_mode),
            ("Abhängigkeiten", a.dependencies != b.dependencies),
        ];
        let names: Vec<_> = fields
            .into_iter()
            .filter_map(|(name, different)| different.then_some(name))
            .collect();
        if !names.is_empty() {
            changes.push(format!("Ziel {}: {}", i + 1, names.join(", ")));
        }
    }
    changes
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Book {
    pub contracts: Vec<Contract>,
    #[serde(skip)]
    source_digest: Option<Vec<u8>>,
    #[serde(skip)]
    source_contracts: Vec<Contract>,
}
impl Book {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.contracts.len() <= 128, "Maximal 128 Recovery-Verträge");
        let mut ids = BTreeSet::new();
        for c in &self.contracts {
            ensure!(ids.insert(c.id), "Doppelte Vertrags-ID");
            c.validate()?;
        }
        Ok(())
    }
    pub fn ensure_allowed(
        &self,
        plan: &ExecutionPlan,
        refs: &[String],
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        let hash = plan.hash()?;
        for c in &self.contracts {
            ensure!(
                !refs.iter().any(|r| c.revoked_references.contains(r)),
                "Recovery-Nachweis dauerhaft widerrufen; neue Generalprobe erforderlich"
            );
            if c.plan.hash()? == hash || refs.iter().any(|r| c.references.contains(r)) {
                ensure!(
                    c.active_readiness(now) == Readiness::Ready,
                    "Recovery-Vertrag nicht bereit; aktuelle Prüfung und Generalprobe erforderlich"
                );
            }
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Pair the base snapshot and its restriction journal under the same lock as save.
        // Otherwise a reader could read old Ready data just before a writer commits and
        // drains the only pending restriction that would have made that snapshot unsafe.
        let _lock = lock_store(path)?;
        ensure!(
            !path.with_extension("blocked").try_exists()?,
            "Recovery-Speicherung fehlgeschlagen; Ausführung gesperrt"
        );
        let mut book = Self::load_main(path)?;
        for (_, pending) in read_pending(path)? {
            book.merge_restrictions(&pending.contracts)?;
        }
        book.validate()?;
        book.source_contracts = book.contracts.clone();
        Ok(book)
    }
    fn load_main(path: &Path) -> Result<Self> {
        let Some(bytes) = read_store(path)? else {
            return Ok(Self::default());
        };
        let raw =
            security::unprotect_secret(&bytes).context("Recovery-Vertragsspeicher nicht lesbar")?;
        ensure!(raw.len() <= MAX_STORE, "Vertragsspeicher zu groß");
        let mut book: Self = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("Recovery-Vertragsspeicher beschädigt"))?;
        book.validate()?;
        book.sanitize();
        book.source_digest = Some(Sha256::digest(&bytes).to_vec());
        book.source_contracts = book.contracts.clone();
        Ok(book)
    }
    fn new_restrictions(&self) -> Vec<Contract> {
        self.contracts
            .iter()
            .filter(|c| {
                let old = self.source_contracts.iter().find(|old| old.id == c.id);
                (c.invalidated.is_some()
                    && old.is_none_or(|old| {
                        old.invalidated != c.invalidated || old.invalidated_at != c.invalidated_at
                    }))
                    || (c
                        .last_check
                        .as_ref()
                        .is_some_and(|check| check.error.is_some())
                        && old.is_none_or(|old| old.last_check != c.last_check))
                    || c.revoked_references
                        .iter()
                        .any(|r| old.is_none_or(|old| !old.revoked_references.contains(r)))
            })
            .cloned()
            .collect()
    }
    /// Write safety evidence before acquiring the main-store lock. Reload must call this first
    /// after any failed save; it never publishes stale settings or a stale renewal.
    pub fn persist_restrictions(&self, path: &Path) -> Result<()> {
        let contracts = self.new_restrictions();
        if contracts.is_empty() {
            return Ok(());
        }
        let result = (|| -> Result<()> {
            let mut pending = Self {
                contracts,
                ..Self::default()
            };
            pending.sanitize();
            pending.validate()?;
            let raw = serde_json::to_vec(&pending)?;
            ensure!(raw.len() <= MAX_STORE, "Restriktionsjournal zu groß");
            let directory = path.with_extension("pending");
            std::fs::create_dir_all(&directory)?;
            let target = directory.join(format!("{:x}.dpapi", Sha256::digest(&raw)));
            // Hash-addressed duplicates carry identical restrictions and need no extra entry.
            if !target.try_exists()? {
                // Writers can drain committed entries while this pre-lock publication runs.
                // Count names only; reading/decrypting an entry being removed here would
                // turn harmless concurrency into a permanent storage-failure marker.
                let existing = std::fs::read_dir(&directory)?
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "dpapi"))
                    .take(128)
                    .count();
                ensure!(existing < 128, "Restriktionsjournal voll");
                let protected = security::protect_secret(&raw)?;
                ensure!(protected.len() <= MAX_STORE, "Restriktionsjournal zu groß");
                security::atomic_write(&target, &protected)?;
            }
            Ok(())
        })();
        if result.is_err() {
            // Even if the encrypted journal cannot be written, leave a zero-content durable
            // fail-closed signal. Never silently clear it: the lost evidence needs repair.
            let marker = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path.with_extension("blocked"));
            if let Ok(marker) = marker {
                let _ = marker.sync_all();
            }
        }
        result
    }
    fn merge_restrictions(&mut self, incoming: &[Contract]) -> Result<()> {
        for source in incoming {
            let Some(current) = self.contracts.iter_mut().find(|c| c.id == source.id) else {
                self.contracts.push(source.clone());
                continue;
            };
            ensure!(
                current.plan.hash()? == source.plan.hash()?,
                "Restriktionsjournal hat andere Planbindung"
            );
            if let (Some(reason), Some(at)) = (&source.invalidated, source.invalidated_at) {
                let superseded = current.baseline.rehearsed_at > source.baseline.rehearsed_at
                    && current.baseline.observed_at >= at
                    && source
                        .references
                        .iter()
                        .all(|r| current.revoked_references.contains(r));
                if !superseded {
                    current.invalidate_at(reason, at);
                }
            }
            for reference in &source.revoked_references {
                if current.references.contains(reference) {
                    current.invalidate_at("Nachweis parallel widerrufen", Utc::now());
                } else if !current.revoked_references.contains(reference) {
                    current.revoked_references.push(reference.clone());
                }
            }
            if let Some(failed) = source
                .last_check
                .as_ref()
                .filter(|check| check.error.is_some())
            {
                let superseded = current.baseline.rehearsed_at > source.baseline.rehearsed_at
                    && current.baseline.observed_at >= failed.finished
                    && source
                        .references
                        .iter()
                        .all(|r| current.revoked_references.contains(r));
                if superseded {
                    continue;
                }
                // A failed parallel observation must not be hidden by a clean save. Keep the
                // latest known time while storing only an explicit unknown/error result.
                let finished = current
                    .last_check
                    .as_ref()
                    .map_or(current.baseline.observed_at, |c| c.finished)
                    .max(failed.finished);
                current.last_check = Some(Check {
                    started: finished,
                    finished,
                    fingerprints: vec![],
                    error: Some(
                        "Parallele Read-only-Prüfung fehlgeschlagen; Zielzustand unbekannt".into(),
                    ),
                });
            }
        }
        self.validate()
    }
    fn sanitize(&mut self) {
        for c in &mut self.contracts {
            c.name = safe(&c.name);
            c.invalidated = c.invalidated.as_deref().map(safe);
            if let Some(check) = &mut c.last_check {
                check.error = check
                    .error
                    .as_ref()
                    .map(|_| "Read-only-Prüfung fehlgeschlagen; Zielzustand unbekannt".into());
            }
        }
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let restrictive = !self.new_restrictions().is_empty();
        self.persist_restrictions(path)?;
        self.validate()?;
        let _lock = lock_store(path)?;
        ensure!(
            !path.with_extension("blocked").try_exists()?,
            "Recovery-Speicherung fehlgeschlagen; Ausführung gesperrt"
        );
        let disk = read_store(path)?.map(|bytes| Sha256::digest(bytes).to_vec());
        let conflict = disk != self.source_digest;
        ensure!(
            !conflict || restrictive,
            "Vertragsspeicher wurde parallel geändert; neu laden erforderlich"
        );
        let mut clean = if conflict {
            Self::load_main(path)?
        } else {
            self.clone()
        };
        let pending = read_pending(path)?;
        for (_, evidence) in &pending {
            clean.merge_restrictions(&evidence.contracts)?;
        }
        clean.sanitize();
        clean.validate()?;
        let raw = serde_json::to_vec(&clean)?;
        ensure!(raw.len() <= MAX_STORE, "Vertragsspeicher zu groß");
        let protected = security::protect_secret(&raw)?;
        ensure!(protected.len() <= MAX_STORE, "Vertragsspeicher zu groß");
        security::atomic_write(path, &protected)?;
        clean.source_digest = Some(Sha256::digest(&protected).to_vec());
        clean.source_contracts = clean.contracts.clone();
        *self = clean;
        // Delete only the entries read under this lock, and only after the durable commit.
        // Entries published concurrently after enumeration remain visible to every loader.
        for (entry, _) in pending {
            std::fs::remove_file(entry)?;
        }
        ensure!(
            !conflict,
            "Restriktive Befunde wurden gespeichert; parallele Änderungen erfordern erneutes Laden"
        );
        Ok(())
    }
}
fn read_pending(path: &Path) -> Result<Vec<(std::path::PathBuf, Book)>> {
    let directory = path.with_extension("pending");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut result = vec![];
    let mut total = 0usize;
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "tmp") {
            continue;
        }
        ensure!(
            path.extension().is_some_and(|ext| ext == "dpapi"),
            "Restriktionsjournal beschädigt"
        );
        ensure!(result.len() < 128, "Restriktionsjournal voll");
        let bytes = read_store(&path)?.context("Restriktionsjournal wurde verändert; neu laden")?;
        total = total
            .checked_add(bytes.len())
            .context("Restriktionsjournal zu groß")?;
        ensure!(total <= MAX_STORE, "Restriktionsjournal zu groß");
        let raw = security::unprotect_secret(&bytes)?;
        ensure!(raw.len() <= MAX_STORE, "Restriktionsjournal zu groß");
        let mut book: Book = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("Restriktionsjournal beschädigt"))?;
        book.validate()?;
        book.sanitize();
        result.push((path, book));
    }
    Ok(result)
}
fn read_store(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => anyhow::bail!("Vertragsspeicher nicht lesbar"),
    };
    ensure!(
        file.metadata()?.len() <= MAX_STORE as u64,
        "Vertragsspeicher zu groß"
    );
    let mut bytes = vec![];
    file.take((MAX_STORE + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_STORE, "Vertragsspeicher zu groß");
    Ok(Some(bytes))
}
fn lock_store(path: &Path) -> Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(path.with_extension("lock"))
            .context("Vertragsspeicher wird bereits aktualisiert")
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        anyhow::bail!("Vertragsspeicherung benötigt Windows-Sperre")
    }
}
pub fn ensure_execution_allowed(
    plan: &ExecutionPlan,
    refs: &[String],
    now: DateTime<Utc>,
) -> Result<()> {
    Book::load(&security::app_data_file(
        "relayne-recovery-contracts.dpapi",
    )?)?
    .ensure_allowed(plan, refs, now)
}
#[cfg(test)]
#[path = "recovery_contracts_tests.rs"]
mod tests;
