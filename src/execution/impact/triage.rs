//! Local warning acknowledgements. Never evidence of repair or execution consent.
use super::*;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn fingerprint(report: &Report, signal: &radar::Signal) -> Result<String> {
    let ids = signal.source_runs.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        ids.len() == signal.source_runs.len() && !ids.is_empty(),
        "Invalid signal references"
    );
    let mut samples = report
        .samples
        .iter()
        .filter(|s| ids.contains(&s.run))
        .collect::<Vec<_>>();
    samples.sort_by_key(|s| s.run);
    ensure!(
        samples.len() == ids.len() && samples.iter().map(|s| s.run).collect::<BTreeSet<_>>() == ids,
        "Missing signal evidence"
    );
    Ok(digest(&serde_json::to_vec(&(
        "relayne-warning-review-v1",
        report.selected_profile,
        signal.kind,
        &signal.procedure_key,
        &signal.service,
        signal.restart,
        signal.baseline_median_ms,
        signal.recent_median_ms,
        signal.rule,
        ids,
        samples,
    ))?))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub note: String,
    pub at: DateTime<Utc>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Book {
    pub entries: BTreeMap<String, Acknowledgement>,
    #[serde(skip)]
    base: Option<String>,
}
impl Book {
    fn validate(&self) -> Result<()> {
        ensure!(self.entries.len() <= 256, "Acknowledgement limit reached");
        for (key, item) in &self.entries {
            ensure!(
                key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
                "Invalid fingerprint"
            );
            ensure!(
                !item.note.trim().is_empty() && item.note.len() <= 1024,
                "Invalid note"
            );
        }
        Ok(())
    }
    pub fn current(&self, key: &str, now: DateTime<Utc>) -> Option<&Acknowledgement> {
        self.entries
            .get(key)
            .filter(|a| a.at <= now && now - a.at < chrono::Duration::days(30))
    }
    pub fn acknowledge(&mut self, key: String, note: &str, now: DateTime<Utc>) -> Result<()> {
        let note = crate::security::redact_secret_text(note.trim());
        ensure!(
            !note.is_empty() && note.len() <= 1024,
            "Review note required (max 1024 bytes)"
        );
        ensure!(
            key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid fingerprint"
        );
        ensure!(
            self.entries.contains_key(&key) || self.entries.len() < 256,
            "Acknowledgement limit reached"
        );
        self.entries.insert(key, Acknowledgement { note, at: now });
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let Some(raw) = read(path)? else {
            return Ok(Self::default());
        };
        let mut book: Self = serde_json::from_slice(&crate::security::unprotect_secret(&raw)?)?;
        book.validate()?;
        book.base = Some(digest(&raw));
        Ok(book)
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path.parent().context("Store parent missing")?;
        std::fs::create_dir_all(parent)?;
        #[cfg(windows)]
        use std::os::windows::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(false);
        #[cfg(windows)]
        options.share_mode(0);
        let _lock = options.open(path.with_extension("review.lock"))?;
        ensure!(
            read(path)?.map(|bytes| digest(&bytes)) == self.base,
            "Store changed; reload required"
        );
        let protected = crate::security::protect_secret(&serde_json::to_vec(self)?)?;
        crate::security::atomic_write(path, &protected)?;
        self.base = Some(digest(&protected));
        Ok(())
    }
}
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1_048_576, "Store too large");
    Ok(Some(bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fingerprint_tracks_evidence_not_refresh_time() {
        let now = Utc::now();
        let run = Uuid::new_v4();
        let mut report = Report {
            selected_profile: Uuid::new_v4(),
            schema: "test",
            as_of: now,
            window_days: 90,
            production: Default::default(),
            rehearsal: Default::default(),
            excluded_results: 0,
            labor_savings_measured: false,
            roi_measured: false,
            not_execution_authorization: true,
            signals: vec![],
            samples: vec![Sample {
                procedure_key: "procedure".into(),
                service: "service".into(),
                restart: false,
                run,
                target: Uuid::new_v4(),
                rehearsal: false,
                observed_at: now,
                healthy_at: now + chrono::Duration::seconds(5),
                interval_ms: 5000,
            }],
        };
        let mut signal = radar::Signal {
            kind: radar::Kind::RepeatedRepairs,
            procedure_key: "procedure".into(),
            service: "service".into(),
            restart: false,
            source_runs: vec![run],
            baseline_median_ms: None,
            recent_median_ms: None,
            rule: "test",
            predicts_outage: false,
        };
        let key = fingerprint(&report, &signal).unwrap();
        report.as_of += chrono::Duration::hours(1);
        assert_eq!(key, fingerprint(&report, &signal).unwrap());
        report.samples[0].interval_ms += 1;
        let changed = fingerprint(&report, &signal).unwrap();
        assert_ne!(key, changed);
        let mut book = Book::default();
        book.acknowledge(key, "Investigated", now).unwrap();
        assert!(book.current(&changed, now).is_none());
        signal.source_runs.push(run);
        assert!(fingerprint(&report, &signal).is_err());
        signal.source_runs = vec![Uuid::new_v4()];
        assert!(fingerprint(&report, &signal).is_err());
    }
    #[test]
    fn triage_requires_note_and_expires_without_execution_authority() {
        let now = Utc::now();
        let mut book = Book::default();
        let key = "a".repeat(64);
        assert!(book.acknowledge(key.clone(), " ", now).is_err());
        book.acknowledge(key.clone(), "Reviewed locally", now)
            .unwrap();
        assert!(book.current(&key, now).is_some());
        assert!(
            book.current(&key, now - chrono::Duration::seconds(1))
                .is_none()
        );
        assert!(
            book.current(&key, now + chrono::Duration::days(30))
                .is_none()
        );
        assert!(book.current(&"b".repeat(64), now).is_none());
    }
    #[test]
    fn triage_store_roundtrips_and_rejects_stale_writes() {
        let path = std::env::temp_dir().join(format!("relayne-triage-{}.dpapi", Uuid::new_v4()));
        let mut first = Book::load(&path).unwrap();
        let mut stale = Book::load(&path).unwrap();
        first
            .acknowledge("a".repeat(64), "Reviewed", Utc::now())
            .unwrap();
        first.save(&path).unwrap();
        stale
            .acknowledge("b".repeat(64), "Other review", Utc::now())
            .unwrap();
        assert!(stale.save(&path).is_err());
        assert_eq!(Book::load(&path).unwrap().entries.len(), 1);
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(Book::load(&path).is_err());
    }
}
