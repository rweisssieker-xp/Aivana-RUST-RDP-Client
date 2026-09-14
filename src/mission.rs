//! Evidence-backed, restartable multi-host work. Sending input is never proof of success.
use crate::{
    models::ConnectionProfile,
    security::{protect_secret, redact_secret_text, unprotect_secret},
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub profile_id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub route: String,
}
impl Target {
    pub fn from_profile(p: &ConnectionProfile) -> Self {
        Self {
            profile_id: p.id,
            name: p.name.clone(),
            host: p.host.clone(),
            port: p.port,
            protocol: p.protocol.label().into(),
            username: p.username.clone(),
            domain: p.domain.clone(),
            route: if p.options.gateway.enabled {
                format!("{}:{}", p.options.gateway.host, p.options.gateway.port)
            } else {
                String::new()
            },
        }
    }
    pub fn matches(&self, p: &ConnectionProfile) -> bool {
        self.same_endpoint(&Self::from_profile(p))
    }
    pub fn same_endpoint(&self, t: &Self) -> bool {
        self.profile_id == t.profile_id
            && self.host == t.host
            && self.port == t.port
            && self.protocol == t.protocol
            && self.username == t.username
            && self.domain == t.domain
            && self.route == t.route
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    Observe,
    Operator,
    WinRmInventory,
    WinRmServices,
    WinRmProcesses,
    WinRmEvents,
    SshCommand,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    pub title: String,
    pub kind: StepKind,
    pub expectation: String,
    pub recovery: String,
    #[serde(default)]
    pub command: String,
}
impl Default for Step {
    fn default() -> Self {
        Self {
            title: "Capture observations".into(),
            kind: StepKind::Observe,
            expectation: "Assess current state using observations".into(),
            recovery: "Capture does not change the target".into(),
            command: String::new(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Pending,
    Running,
    Review,
    Passed,
    Failed,
    Interrupted,
}
impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Running => "Running",
            Self::Review => "Review needed",
            Self::Passed => "Confirmed",
            Self::Failed => "Failed",
            Self::Interrupted => "Interrupted",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub target: Target,
    pub at: DateTime<Utc>,
    pub source: String,
    pub facts: BTreeMap<String, String>,
    pub notes: String,
}
impl Evidence {
    pub fn new(target: Target, source: &str, facts: BTreeMap<String, String>, notes: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            target,
            at: Utc::now(),
            source: source.into(),
            facts: facts
                .into_iter()
                .map(|(k, v)| (k, redact_secret_text(&v)))
                .collect(),
            notes: redact_secret_text(notes),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub target: Uuid,
    pub step: usize,
    pub status: Status,
    pub evidence: Vec<Uuid>,
    pub verification: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mission {
    pub id: Uuid,
    pub objective: String,
    pub targets: Vec<Target>,
    pub steps: Vec<Step>,
    pub outcomes: Vec<Outcome>,
    pub evidence: Vec<Evidence>,
    pub pilot: Uuid,
    pub rollout: bool,
    pub paused: bool,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub handoff: String,
}
impl Mission {
    pub fn new(objective: &str, targets: Vec<Target>, steps: Vec<Step>) -> Result<Self> {
        if objective.trim().is_empty() || objective.len() > 4096 {
            bail!("Mission is missing or too long");
        }
        if targets.is_empty() || targets.len() > 256 || steps.is_empty() || steps.len() > 64 {
            bail!("1–256 computers and 1–64 steps required");
        }
        if targets
            .iter()
            .map(|t| t.profile_id)
            .collect::<BTreeSet<_>>()
            .len()
            != targets.len()
        {
            bail!("Computer selected more than once");
        }
        if targets
            .iter()
            .any(|t| t.host.trim().is_empty() || t.port == 0)
            || steps
                .iter()
                .any(|s| s.title.trim().is_empty() || s.expectation.trim().is_empty())
        {
            bail!("Target, step, or success criterion is missing");
        }
        if steps.iter().any(|s| {
            s.title.len() > 4096
                || s.expectation.len() > 8192
                || s.recovery.len() > 8192
                || s.command.len() > 8192
                || (s.kind == StepKind::SshCommand
                    && (s.command.trim().is_empty() || s.recovery.trim().is_empty()))
        }) {
            bail!("Step is too long or SSH command/recovery path is missing");
        }
        let pilot = targets[0].profile_id;
        let outcomes = targets
            .iter()
            .flat_map(|t| {
                (0..steps.len()).map(move |step| Outcome {
                    target: t.profile_id,
                    step,
                    status: Status::Pending,
                    evidence: vec![],
                    verification: String::new(),
                })
            })
            .collect();
        Ok(Self {
            id: Uuid::new_v4(),
            objective: redact_secret_text(objective),
            targets,
            steps,
            outcomes,
            evidence: vec![],
            pilot,
            rollout: false,
            paused: false,
            created: Utc::now(),
            updated: Utc::now(),
            handoff: String::new(),
        })
    }
    pub fn pilot_passed(&self) -> bool {
        self.outcomes
            .iter()
            .filter(|o| o.target == self.pilot)
            .all(|o| o.status == Status::Passed)
    }
    pub fn allow_rollout(&mut self) -> Result<()> {
        if !self.pilot_passed() {
            bail!("Rehearsal must be fully confirmed first");
        }
        self.rollout = true;
        self.updated = Utc::now();
        Ok(())
    }
    pub fn begin(&mut self, target: Uuid, step: usize) -> Result<()> {
        if self.paused {
            bail!("Job is paused");
        }
        if target != self.pilot && (!self.rollout || !self.pilot_passed()) {
            bail!("Rehearsal and rollout approval are missing");
        }
        if self
            .outcomes
            .iter()
            .any(|o| o.target == target && o.step < step && o.status != Status::Passed)
        {
            bail!("Review the previous step first");
        }
        let o = self
            .outcomes
            .iter_mut()
            .find(|o| o.target == target && o.step == step)
            .context("Step does not exist")?;
        if matches!(o.status, Status::Running | Status::Passed | Status::Review) {
            bail!("Step already started or confirmed");
        }
        o.status = Status::Running;
        o.evidence.clear();
        o.verification.clear();
        self.updated = Utc::now();
        Ok(())
    }
    pub fn record(&mut self, target: Uuid, step: usize, evidence: Evidence) -> Result<()> {
        if evidence.target.profile_id != target {
            bail!("Observation belongs to another computer");
        }
        let t = self
            .targets
            .iter()
            .find(|t| t.profile_id == target)
            .context("Computer is missing")?;
        if !t.same_endpoint(&evidence.target) {
            bail!("Observation belongs to another endpoint");
        }
        let o = self
            .outcomes
            .iter_mut()
            .find(|o| o.target == target && o.step == step)
            .context("Step is missing")?;
        if o.status != Status::Running {
            bail!("Step is no longer running");
        }
        if evidence.facts.is_empty() && evidence.notes.trim().is_empty() {
            bail!("Leerer Befund");
        }
        o.status = Status::Review;
        o.evidence.push(evidence.id);
        self.evidence.push(evidence);
        self.updated = Utc::now();
        Ok(())
    }
    pub fn verify(&mut self, target: Uuid, step: usize, passed: bool, note: &str) -> Result<()> {
        if note.trim().is_empty() {
            bail!("Explain the review result");
        }
        let o = self
            .outcomes
            .iter_mut()
            .find(|o| o.target == target && o.step == step)
            .context("Step is missing")?;
        if o.status != Status::Review || o.evidence.is_empty() {
            bail!("Capture a current finding first");
        }
        o.status = if passed {
            Status::Passed
        } else {
            Status::Failed
        };
        o.verification = redact_secret_text(note);
        self.updated = Utc::now();
        Ok(())
    }
    pub fn pause(&mut self) {
        self.paused = true;
        for o in &mut self.outcomes {
            if o.status == Status::Running {
                o.status = Status::Interrupted;
            }
        }
        self.updated = Utc::now();
    }
    pub fn completed(&self) -> bool {
        !self.outcomes.is_empty() && self.outcomes.iter().all(|o| o.status == Status::Passed)
    }
    pub fn map_local_profiles(&mut self, profiles: &[ConnectionProfile]) -> Result<()> {
        if !self.paused {
            bail!("Pause the job before mapping");
        }
        let mut mapped = BTreeMap::new();
        let mut used = BTreeSet::new();
        for t in &self.targets {
            let candidates: Vec<_> = profiles
                .iter()
                .filter(|p| {
                    let mut probe = Target::from_profile(p);
                    probe.profile_id = t.profile_id;
                    t.same_endpoint(&probe)
                })
                .collect();
            if candidates.len() != 1 {
                bail!("No unique identical local profile exists for {}", t.name);
            }
            let local = Target::from_profile(candidates[0]);
            if !used.insert(local.profile_id) {
                bail!("Multiple targets would point to the same profile");
            }
            mapped.insert(t.profile_id, local);
        }
        for o in &mut self.outcomes {
            o.target = mapped[&o.target].profile_id;
        }
        for e in &mut self.evidence {
            e.target = mapped[&e.target.profile_id].clone();
        }
        self.pilot = mapped[&self.pilot].profile_id;
        self.targets = self
            .targets
            .iter()
            .map(|t| mapped[&t.profile_id].clone())
            .collect();
        self.updated = Utc::now();
        Ok(())
    }
    pub fn markdown(&self) -> String {
        let mut s = format!(
            "# {}\n\nStand: {}\n\n{}\n\n",
            self.objective, self.updated, self.handoff
        );
        for t in &self.targets {
            s.push_str(&format!("## {} ({}:{})\n", t.name, t.host, t.port));
            for o in self.outcomes.iter().filter(|o| o.target == t.profile_id) {
                s.push_str(&format!(
                    "- {}: {} — {}\n",
                    self.steps[o.step].title,
                    o.status.label(),
                    o.verification
                ));
            }
        }
        for e in &self.evidence {
            s.push_str(&format!(
                "\n### Befund {} · {} · {}\n{}\n",
                e.target.name, e.at, e.source, e.notes
            ));
            for (k, v) in &e.facts {
                s.push_str(&format!("- {k}: {v}\n"));
            }
        }
        s
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Procedure {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<Step>,
    pub source: Uuid,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MissionBook {
    pub missions: Vec<Mission>,
    pub procedures: Vec<Procedure>,
}
impl MissionBook {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        if std::fs::metadata(path)?.len() > 64 * 1024 * 1024 {
            bail!("Mission store is too large");
        }
        let clear = unprotect_secret(&std::fs::read(path)?)?;
        let mut book: Self = serde_json::from_slice(&clear).context("Auftragsspeicher lesen")?;
        for m in &mut book.missions {
            validate_mission(m)?;
            for o in &mut m.outcomes {
                if o.status == Status::Running {
                    o.status = Status::Interrupted;
                    m.paused = true;
                }
            }
        }
        Ok(book)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        #[cfg(not(windows))]
        {
            let _ = path;
            bail!("Encrypted mission store requires Windows DPAPI");
        }
        #[cfg(windows)]
        {
            if let Some(p) = path.parent() {
                std::fs::create_dir_all(p)?;
            }
            let clear = serde_json::to_vec(self)?;
            if clear.len() > 64 * 1024 * 1024 {
                bail!("Mission store exceeds 64 MiB");
            }
            let bytes = protect_secret(&clear)?;
            let temp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
            std::fs::write(&temp, bytes)?;
            if let Err(e) = std::fs::rename(&temp, path) {
                let _ = std::fs::remove_file(&temp);
                return Err(e.into());
            }
            Ok(())
        }
    }
    pub fn learn(&mut self, id: Uuid) -> Result<()> {
        let m = self
            .missions
            .iter()
            .find(|m| m.id == id)
            .context("Mission is missing")?;
        if !m.completed() {
            bail!("Only fully confirmed missions are saved as verified workflows");
        }
        self.procedures.push(Procedure {
            id: Uuid::new_v4(),
            name: m.objective.clone(),
            steps: m.steps.clone(),
            source: m.id,
        });
        Ok(())
    }
    pub fn search(&self, query: &str) -> Vec<(&Mission, &Evidence)> {
        let words: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
        self.missions
            .iter()
            .flat_map(|m| m.evidence.iter().map(move |e| (m, e)))
            .filter(|(m, e)| {
                let text = format!(
                    "{} {} {} {} {:?}",
                    m.objective, e.target.name, e.source, e.notes, e.facts
                )
                .to_lowercase();
                words.iter().all(|w| text.contains(w))
            })
            .take(200)
            .collect()
    }
    pub fn import(&mut self, json: &str) -> Result<Uuid> {
        if json.len() > 16 * 1024 * 1024 {
            bail!("Handoff exceeds 16 MiB");
        }
        let mut m: Mission = serde_json::from_str(json).context("Read handoff")?;
        validate_mission(&m)?;
        // Imported reports are history; local execution must be explicitly resumed and targets matched.
        m.id = Uuid::new_v4();
        m.paused = true;
        m.rollout = false;
        let mut ids = BTreeMap::new();
        for e in &mut m.evidence {
            let old = e.id;
            e.id = Uuid::new_v4();
            ids.insert(old, e.id);
        }
        for o in &mut m.outcomes {
            for id in &mut o.evidence {
                *id = ids[id];
            }
        }
        for o in &mut m.outcomes {
            if o.status == Status::Running {
                o.status = Status::Interrupted;
            }
        }
        m.objective = redact_secret_text(&m.objective);
        m.handoff = redact_secret_text(&m.handoff);
        for e in &mut m.evidence {
            e.notes = redact_secret_text(&e.notes);
            for v in e.facts.values_mut() {
                *v = redact_secret_text(v);
            }
        }
        let id = m.id;
        self.missions.push(m);
        Ok(id)
    }
}
fn validate_mission(m: &Mission) -> Result<()> {
    let template = Mission::new(&m.objective, m.targets.clone(), m.steps.clone())?;
    if !m.targets.iter().any(|t| t.profile_id == m.pilot)
        || m.outcomes.len() != template.outcomes.len()
    {
        bail!("Invalid mission structure");
    }
    let keys: BTreeSet<_> = m.outcomes.iter().map(|o| (o.target, o.step)).collect();
    if keys.len() != m.outcomes.len()
        || template
            .outcomes
            .iter()
            .any(|o| !keys.contains(&(o.target, o.step)))
    {
        bail!("Invalid step mapping");
    }
    let evidence_ids: BTreeSet<_> = m.evidence.iter().map(|e| e.id).collect();
    if evidence_ids.len() != m.evidence.len() || m.evidence.len() > 16384 {
        bail!("Invalid observation list");
    }
    for o in &m.outcomes {
        if matches!(o.status, Status::Passed | Status::Review) && o.evidence.is_empty() {
            bail!("Review result without an observation");
        }
        if o.status == Status::Passed && o.verification.trim().is_empty() {
            bail!("Success without a review note");
        }
        for id in &o.evidence {
            if !m
                .evidence
                .iter()
                .any(|e| e.id == *id && e.target.profile_id == o.target)
            {
                bail!("Invalid observation mapping");
            }
        }
    }
    for e in &m.evidence {
        if !m.targets.iter().any(|t| t.same_endpoint(&e.target))
            || (e.facts.is_empty() && e.notes.trim().is_empty())
        {
            bail!("Observation has no content or belongs to another endpoint");
        }
    }
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
pub struct Change {
    pub key: String,
    pub before: Option<String>,
    pub after: Option<String>,
}
pub fn diff(a: &Evidence, b: &Evidence) -> Vec<Change> {
    a.facts
        .keys()
        .chain(b.facts.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|k| {
            let before = a.facts.get(k).cloned();
            let after = b.facts.get(k).cloned();
            (before != after).then(|| Change {
                key: k.clone(),
                before,
                after,
            })
        })
        .collect()
}
/// Stable record keys make reordered service/process JSON comparable.
pub fn structured_facts(text: &str) -> BTreeMap<String, String> {
    fn visit(v: &serde_json::Value, path: &str, out: &mut BTreeMap<String, String>, depth: usize) {
        if depth > 8 || out.len() >= 4096 {
            return;
        }
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    visit(v, &format!("{path}/{k}"), out, depth + 1)
                }
            }
            serde_json::Value::Array(items) => {
                for (i, v) in items.iter().take(1000).enumerate() {
                    let key = ["Name", "Id", "CSName", "ProcessName"]
                        .iter()
                        .find_map(|k| {
                            v.get(k).and_then(|v| {
                                v.as_str()
                                    .map(str::to_owned)
                                    .or_else(|| v.as_u64().map(|n| n.to_string()))
                            })
                        })
                        .unwrap_or_else(|| i.to_string());
                    visit(
                        v,
                        &format!("{path}/{}", key.replace('/', "%2F")),
                        out,
                        depth + 1,
                    );
                }
            }
            _ => {
                out.insert(
                    path.to_owned(),
                    redact_secret_text(
                        &v.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| v.to_string()),
                    ),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    if let Ok(v) = serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        visit(&v, "Daten", &mut out, 0);
    }
    out
}
pub fn export_new(path: &Path, contents: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(contents)?;
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mission() -> Mission {
        Mission::new(
            "Diagnose",
            vec![
                Target::from_profile(&ConnectionProfile::sample("a", "host-a", "", false)),
                Target::from_profile(&ConnectionProfile::sample("b", "host-b", "", false)),
            ],
            vec![Step::default()],
        )
        .unwrap()
    }
    fn evidence(m: &Mission) -> Evidence {
        Evidence::new(
            m.targets[0].clone(),
            "test",
            BTreeMap::from([("state".into(), "observed".into())]),
            "",
        )
    }
    #[test]
    fn pilot_requires_evidence_and_verification() {
        let mut m = mission();
        let pilot = m.pilot;
        assert!(m.begin(m.targets[1].profile_id, 0).is_err());
        m.begin(pilot, 0).unwrap();
        assert!(m.verify(pilot, 0, true, "okay").is_err());
        let e = evidence(&m);
        m.record(pilot, 0, e).unwrap();
        assert!(m.verify(pilot, 0, true, "").is_err());
        m.verify(pilot, 0, true, "Zustand geprüft").unwrap();
        assert!(m.begin(m.targets[1].profile_id, 0).is_err());
        m.allow_rollout().unwrap();
        m.begin(m.targets[1].profile_id, 0).unwrap();
    }
    #[test]
    fn cancellation_rejects_late_result() {
        let mut m = mission();
        m.begin(m.pilot, 0).unwrap();
        let e = evidence(&m);
        m.pause();
        assert!(m.record(m.pilot, 0, e).is_err());
        assert_eq!(m.outcomes[0].status, Status::Interrupted);
    }
    #[test]
    fn imported_outcome_cannot_point_to_wrong_host() {
        let mut m = mission();
        m.outcomes[0].target = Uuid::new_v4();
        assert!(
            MissionBook::default()
                .import(&serde_json::to_string(&m).unwrap())
                .is_err()
        );
    }
    #[test]
    fn diff_finds_removed_added_changed() {
        let m = mission();
        let mut a = evidence(&m);
        a.facts.insert("gone".into(), "x".into());
        let mut b = evidence(&m);
        b.facts.insert("state".into(), "changed".into());
        b.facts.insert("new".into(), "y".into());
        assert_eq!(diff(&a, &b).len(), 3);
    }
    #[test]
    fn search_matches_all_words() {
        let mut m = mission();
        m.evidence.push(evidence(&m));
        let book = MissionBook {
            missions: vec![m],
            procedures: vec![],
        };
        assert_eq!(book.search("diagnose observed").len(), 1);
        assert!(book.search("absent observed").is_empty());
    }
    #[test]
    fn learn_requires_all_targets() {
        let m = mission();
        let id = m.id;
        let mut b = MissionBook {
            missions: vec![m],
            procedures: vec![],
        };
        assert!(b.learn(id).is_err());
    }
    #[test]
    fn repeated_begin_does_not_replace_review() {
        let mut m = mission();
        m.begin(m.pilot, 0).unwrap();
        let e = evidence(&m);
        m.record(m.pilot, 0, e).unwrap();
        assert!(m.begin(m.pilot, 0).is_err());
    }
    #[test]
    fn endpoint_binding_includes_protocol_and_username() {
        let mut p = ConnectionProfile::sample("a", "host-a", "", false);
        let t = Target::from_profile(&p);
        p.username = "other".into();
        assert!(!t.matches(&p));
        p.username = t.username.clone();
        p.protocol = crate::models::Protocol::Ssh;
        assert!(!t.matches(&p));
    }
    #[test]
    fn repeated_import_remaps_evidence() {
        let mut m = mission();
        m.begin(m.pilot, 0).unwrap();
        let e = evidence(&m);
        m.record(m.pilot, 0, e).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let mut book = MissionBook::default();
        book.import(&json).unwrap();
        book.import(&json).unwrap();
        assert_ne!(
            book.missions[0].evidence[0].id,
            book.missions[1].evidence[0].id
        );
        assert_eq!(
            book.missions[0].outcomes[0].evidence[0],
            book.missions[0].evidence[0].id
        );
    }
    #[test]
    fn rejects_foreign_endpoint_and_false_success() {
        let mut m = mission();
        m.begin(m.pilot, 0).unwrap();
        let e = evidence(&m);
        m.record(m.pilot, 0, e).unwrap();
        m.outcomes[0].status = Status::Passed;
        assert!(validate_mission(&m).is_err());
        m.outcomes[0].verification = "checked".into();
        m.evidence[0].target.host = "foreign".into();
        assert!(validate_mission(&m).is_err());
    }
    #[test]
    fn stable_service_comparison_ignores_order() {
        let a = structured_facts(r#"[{"Name":"Spooler","Status":4},{"Name":"WinRM","Status":4}]"#);
        let b = structured_facts(r#"[{"Name":"WinRM","Status":4},{"Name":"Spooler","Status":4}]"#);
        assert_eq!(a, b);
    }
    #[cfg(windows)]
    #[test]
    fn protected_store_roundtrip_recovers_running() {
        let p = std::env::temp_dir().join(format!("mission-{}.bin", Uuid::new_v4()));
        let mut m = mission();
        m.begin(m.pilot, 0).unwrap();
        let b = MissionBook {
            missions: vec![m],
            procedures: vec![],
        };
        b.save(&p).unwrap();
        assert!(!String::from_utf8_lossy(&std::fs::read(&p).unwrap()).contains("host-a"));
        let loaded = MissionBook::load(&p).unwrap();
        assert_eq!(loaded.missions[0].outcomes[0].status, Status::Interrupted);
        assert!(loaded.missions[0].paused);
        let _ = std::fs::remove_file(p);
    }
}
