//! Reviewed, journaled service workflows with real staging evidence.
use crate::{
    intelligence::{self, ServiceState},
    mission::Target,
    security,
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};
use uuid::Uuid;
#[path = "http_health.rs"]
pub(crate) mod http_health;
pub(crate) mod learning;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpGetStep {
    pub path: String,
    pub status: u16,
    pub contains: String,
    #[serde(default, skip_serializing_if = "http_health::Options::is_default")]
    pub options: http_health::Options,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HealthCheck {
    Tcp {
        port: u16,
    },
    Http {
        port: u16,
        tls: bool,
        path: String,
        status: u16,
        contains: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        followups: Vec<HttpGetStep>,
    },
}
impl HealthCheck {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Tcp { port } if *port > 0 => Ok(()),
            Self::Http {
                port,
                tls,
                path,
                status,
                contains,
                followups,
                ..
            } if *port > 0
                && (200..=599).contains(status)
                && path.starts_with('/')
                && !path.starts_with("//")
                && path.len() <= 1024
                && !path.contains(['?', '#', '\\'])
                && !path.chars().any(char::is_control)
                && contains.len() <= 1024 =>
            {
                anyhow::ensure!(followups.len() <= 3, "Maximal vier HTTP-Prüfschritte");
                for step in followups {
                    step.options.validate(*tls)?;
                    Self::Http {
                        port: *port,
                        tls: false,
                        path: step.path.clone(),
                        status: step.status,
                        contains: step.contains.clone(),
                        followups: vec![],
                    }
                    .validate()?;
                }
                Ok(())
            }
            _ => bail!(
                "Ungültiger Healthcheck; nur öffentlicher Pfad ohne Query/Token, begrenztes Antwortmuster"
            ),
        }
    }
    /// Local worker only: never send credentials, follow redirects or retain response bodies.
    pub fn probe(&self, target: &Target) -> HealthEvidence {
        self.probe_with_values(target, &http_health::Values::new())
    }
    pub fn validate_values(&self, values: &http_health::Values) -> Result<()> {
        if let Self::Http { followups, .. } = self {
            for step in followups {
                step.options.validate_values(values)?;
            }
        }
        Ok(())
    }
    pub fn probe_with_values(
        &self,
        target: &Target,
        values: &http_health::Values,
    ) -> HealthEvidence {
        let result = self.check_with_values(target, values);
        HealthEvidence {
            at: Utc::now(),
            passed: result.as_ref().is_ok_and(|v| *v),
            detail: match result {
                Ok(true) => "Erfolgskriterium erfüllt".into(),
                Ok(false) => "Erfolgskriterium nicht erfüllt".into(),
                Err(_) => {
                    "Prüfung nicht erfolgreich (Verbindung, Timeout oder Antwortgrenze)".into()
                }
            },
        }
    }
    fn check_with_values(&self, target: &Target, values: &http_health::Values) -> Result<bool> {
        self.validate()?;
        crate::operations::Endpoint::new(&target.host, "", target.port)
            .map_err(anyhow::Error::msg)?;
        match self {
            Self::Tcp { port } => {
                let addresses: Vec<_> = (target.host.as_str(), *port)
                    .to_socket_addrs()?
                    .take(4)
                    .collect();
                Ok(addresses
                    .iter()
                    .any(|a| TcpStream::connect_timeout(a, Duration::from_secs(3)).is_ok()))
            }
            Self::Http {
                port,
                tls,
                path,
                status,
                contains,
                followups,
            } => {
                let host = if target.host.contains(':') {
                    format!("[{}]", target.host)
                } else {
                    target.host.clone()
                };
                let url = format!(
                    "{}://{host}:{port}{path}",
                    if *tls { "https" } else { "http" }
                );
                http_health::execute(&url, *status, contains, followups, values)
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub production: Target,
    pub staging: Target,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionPlan {
    #[serde(default, skip_serializing_if = "is_false")]
    pub restart: bool,
    pub service: String,
    pub desired: ServiceState,
    pub health: HealthCheck,
    pub mappings: Vec<Mapping>,
}
pub fn is_false(value: &bool) -> bool {
    !*value
}
impl ExecutionPlan {
    pub fn validate(&self) -> Result<()> {
        self.health.validate()?;
        anyhow::ensure!(
            !self.restart
                || (self.desired == ServiceState::Running
                    && matches!(self.health, HealthCheck::Http { .. })),
            "Neustart benötigt Running und HTTP-Nachweis"
        );
        if self.mappings.is_empty() || self.mappings.len() > 32 {
            bail!("1–32 Zielzuordnungen erforderlich");
        }
        let mut hosts = std::collections::BTreeSet::new();
        let mut labs = std::collections::BTreeSet::new();
        let mut vms = std::collections::BTreeSet::new();
        for m in &self.mappings {
            for target in [&m.production, &m.staging] {
                if std::ptr::eq(target, &m.staging)
                    && target.protocol == crate::promotion::LAB_PROTOCOL
                {
                    if !crate::promotion::valid_lab_target(target)
                        || !labs.insert(target.profile_id)
                        || !vms.insert(target.host.clone())
                    {
                        bail!("Ungültige oder doppelte Lab-/VM-Zuordnung");
                    }
                    continue;
                }
                intelligence::service_spec(target, &self.service, None)?;
                // WinRM uses host, not the saved RDP port or profile identity.
                if !hosts.insert(target.host.trim_end_matches('.').to_ascii_lowercase()) {
                    bail!("Produktion und Test müssen verschiedene, eindeutige Hosts sein");
                }
            }
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthEvidence {
    pub at: DateTime<Utc>,
    pub passed: bool,
    pub detail: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Capture,
    Baseline,
    Review,
    Apply,
    Verify,
    Restore,
    Passed,
    Restored,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetRun {
    pub target: Target,
    pub phase: Phase,
    pub before: Option<ServiceState>,
    pub captured: Option<DateTime<Utc>>,
    pub baseline: Option<HealthEvidence>,
    pub health: Option<HealthEvidence>,
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run {
    pub id: Uuid,
    pub plan: ExecutionPlan,
    pub hash: String,
    pub rehearsal: bool,
    pub targets: Vec<TargetRun>,
    pub current: usize,
    pub finished: Option<DateTime<Utc>>,
    #[serde(default)]
    pub lab_receipts: Vec<String>,
    #[serde(default)]
    pub recovery_case: Option<Uuid>,
}
impl Run {
    pub fn new(plan: ExecutionPlan, rehearsal: bool) -> Result<Self> {
        if rehearsal
            && plan
                .mappings
                .iter()
                .any(|m| m.staging.protocol == crate::promotion::LAB_PROTOCOL)
        {
            bail!("Hyper-V-Proben müssen über den Lab-Adapter ausgeführt werden");
        }
        let hash = plan.hash()?;
        let targets = plan
            .mappings
            .iter()
            .map(|m| TargetRun {
                target: if rehearsal {
                    m.staging.clone()
                } else {
                    m.production.clone()
                },
                phase: Phase::Capture,
                before: None,
                captured: None,
                baseline: None,
                health: None,
                evidence: vec![],
            })
            .collect();
        Ok(Self {
            id: Uuid::new_v4(),
            plan,
            hash,
            rehearsal,
            targets,
            current: 0,
            finished: None,
            lab_receipts: vec![],
            recovery_case: None,
        })
    }
    pub fn successful(&self) -> bool {
        self.finished.is_some()
            && !self.targets.is_empty()
            && self.targets.iter().all(|t| t.phase == Phase::Passed)
    }
    pub fn proof_for(&self, plan: &ExecutionPlan, now: DateTime<Utc>) -> bool {
        self.rehearsal
            && !self
                .plan
                .mappings
                .iter()
                .any(|m| m.staging.protocol == crate::promotion::LAB_PROTOCOL)
            && self.successful()
            && self.hash == plan.hash().unwrap_or_default()
            && self.hash == self.plan.hash().unwrap_or_default()
            && self.targets.len() == plan.mappings.len()
            && self.targets.iter().zip(&plan.mappings).all(|(t, m)| {
                t.target.same_endpoint(&m.staging)
                    && t.before.is_some_and(|before| {
                        if plan.restart {
                            before == ServiceState::Running
                        } else {
                            before != plan.desired
                        }
                    })
                    && t.baseline
                        .as_ref()
                        .is_some_and(|b| !plan.restart || !b.passed)
                    && t.health.as_ref().is_some_and(|h| h.passed)
                    && (!plan.restart || evidenced_success(self, t))
            })
            && self
                .finished
                .is_some_and(|at| now >= at && (now - at).num_seconds() <= 3600)
    }
    pub fn finish_health(&mut self, evidence: HealthEvidence) -> Result<()> {
        let t = &mut self.targets[self.current];
        match t.phase {
            Phase::Baseline => {
                t.baseline = Some(evidence);
                t.phase = Phase::Review;
            }
            Phase::Verify => {
                t.phase = if evidence.passed {
                    Phase::Passed
                } else if t.before == Some(self.plan.desired) && !self.plan.restart {
                    Phase::Failed
                } else {
                    Phase::Restore
                };
                t.health = Some(evidence);
            }
            _ => bail!("Healthantwort ohne passenden laufenden Prüfschritt"),
        }
        self.advance();
        Ok(())
    }
    pub fn advance(&mut self) {
        if self.targets[self.current].phase == Phase::Passed {
            if self.current + 1 < self.targets.len() {
                self.current += 1;
            } else {
                self.finished = Some(Utc::now());
            }
        } else if matches!(
            self.targets[self.current].phase,
            Phase::Failed | Phase::Restored | Phase::Unknown
        ) {
            self.finished = Some(Utc::now());
        }
    }
    pub fn interrupt_after_restart(&mut self) {
        if self.finished.is_none() {
            for t in &mut self.targets {
                if !matches!(t.phase, Phase::Passed | Phase::Restored | Phase::Failed) {
                    t.phase = Phase::Unknown;
                    t.evidence
                        .push("Neustart: kein automatisches Fortsetzen oder Wiederholen".into());
                }
            }
            self.finished = Some(Utc::now());
        }
    }
    pub fn assess_mutation(&mut self, stdout: &str, restore: bool) -> Result<()> {
        let target = &mut self.targets[self.current];
        let original = target
            .before
            .ok_or_else(|| anyhow::anyhow!("Ausgangszustand fehlt"))?;
        let (before, desired) = if restore {
            (self.plan.desired, original)
        } else {
            (original, self.plan.desired)
        };
        let v: serde_json::Value = serde_json::from_str(stdout)?;
        if v["service"] != self.plan.service
            || v["before"] != before.label()
            || v["desired"] != desired.label()
        {
            bail!("Antwort passt nicht zum geprüften Auftrag");
        }
        target.phase = if v["verified"] == true
            && v["actual"] == desired.label()
            && (!self.plan.restart || restore || v["stoppedVerified"] == true)
        {
            if restore {
                Phase::Restored
            } else {
                Phase::Verify
            }
        } else if !restore
            && v["rollbackVerified"] == true
            && v["rollbackAttempted"] == true
            && v["actual"] == original.label()
        {
            Phase::Restored
        } else {
            Phase::Unknown
        };
        target.evidence.push(security::redact_secret_text(stdout));
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Journal {
    pub runs: Vec<Run>,
}
#[derive(Clone, Debug, Default)]
pub struct LessonCounts {
    pub successes: usize,
    pub failures: usize,
    pub restored: usize,
    pub unknown: usize,
}
#[derive(Clone, Debug)]
pub struct LessonEvidence {
    pub run_id: Uuid,
    pub target_profile_id: Uuid,
    pub rehearsal: bool,
    pub phase: Phase,
}
#[derive(Clone, Debug)]
pub struct ExecutionLesson {
    pub restart: bool,
    pub key: String,
    pub service: String,
    pub desired: ServiceState,
    pub health: HealthCheck,
    pub production: LessonCounts,
    pub rehearsal: LessonCounts,
    /// References resolve to the run/target records and their before/after evidence.
    pub evidence: Vec<LessonEvidence>,
}
impl ExecutionLesson {
    fn from_plan(plan: &ExecutionPlan) -> Result<Self> {
        plan.validate()?;
        let key = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                "relayne-service-health-v1",
                &plan.service,
                plan.desired,
                &plan.health,
            ))?)
        );
        let key = if plan.restart {
            format!("restart:{key}")
        } else {
            key
        };
        Ok(Self {
            restart: plan.restart,
            key,
            service: plan.service.clone(),
            desired: plan.desired,
            health: plan.health.clone(),
            production: LessonCounts::default(),
            rehearsal: LessonCounts::default(),
            evidence: vec![],
        })
    }
}
fn evidenced_success(run: &Run, target: &TargetRun) -> bool {
    let Some(before) = target.before else {
        return false;
    };
    let Some(captured) = target.captured else {
        return false;
    };
    let Some(baseline) = &target.baseline else {
        return false;
    };
    let Some(health) = &target.health else {
        return false;
    };
    if target.phase != Phase::Passed
        || !health.passed
        || baseline.at < captured
        || health.at < baseline.at
        || !run
            .finished
            .is_some_and(|at| at >= health.at && at <= Utc::now())
    {
        return false;
    }
    if !target
        .evidence
        .iter()
        .any(|text| intelligence::captured_state(text, &run.plan.service).ok() == Some(before))
    {
        return false;
    }
    if before == run.plan.desired && !run.plan.restart {
        return !run.rehearsal;
    }
    target.evidence.iter().any(|text| {
        serde_json::from_str::<serde_json::Value>(text).is_ok_and(|v| {
            v["service"] == run.plan.service
                && v["before"] == before.label()
                && v["desired"] == run.plan.desired.label()
                && v["actual"] == run.plan.desired.label()
                && v["verified"] == true
                && (!run.plan.restart || v["stoppedVerified"] == true)
        })
    })
}
impl Journal {
    /// Recomputed from current journal evidence; no manual registration or probability estimates.
    pub fn lessons(&self) -> Vec<ExecutionLesson> {
        let mut groups = std::collections::BTreeMap::<String, ExecutionLesson>::new();
        let mut seen = std::collections::BTreeSet::new();
        for run in &self.runs {
            if run.finished.is_none() {
                continue;
            }
            let Ok(lesson) = ExecutionLesson::from_plan(&run.plan) else {
                continue;
            };
            let bound = run.plan.hash().is_ok_and(|hash| hash == run.hash)
                && run.targets.len() == run.plan.mappings.len();
            for (index, target) in run.targets.iter().enumerate() {
                if !matches!(
                    target.phase,
                    Phase::Passed | Phase::Failed | Phase::Restored | Phase::Unknown
                ) || !seen.insert((run.id, target.target.profile_id))
                {
                    continue;
                }
                let group = groups
                    .entry(lesson.key.clone())
                    .or_insert_with(|| lesson.clone());
                let counts = if run.rehearsal {
                    &mut group.rehearsal
                } else {
                    &mut group.production
                };
                let target_bound = bound
                    && run.plan.mappings.get(index).is_some_and(|m| {
                        target.target.same_endpoint(if run.rehearsal {
                            &m.staging
                        } else {
                            &m.production
                        })
                    });
                let phase = if !target_bound
                    || (target.phase == Phase::Passed && !evidenced_success(run, target))
                {
                    Phase::Unknown
                } else {
                    target.phase
                };
                match phase {
                    Phase::Passed => counts.successes += 1,
                    Phase::Failed => counts.failures += 1,
                    Phase::Restored => counts.restored += 1,
                    _ => counts.unknown += 1,
                }
                group.evidence.push(LessonEvidence {
                    run_id: run.id,
                    target_profile_id: target.target.profile_id,
                    rehearsal: run.rehearsal,
                    phase,
                });
            }
        }
        groups.into_values().collect()
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if !cfg!(windows) {
            bail!("Windows DPAPI erforderlich");
        }
        let raw = serde_json::to_vec(self)?;
        if raw.len() > 16 * 1024 * 1024 {
            bail!("Journalgrenze erreicht");
        }
        security::atomic_write(path, &security::protect_secret(&raw)?)
    }
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        if path.metadata()?.len() > 24 * 1024 * 1024 {
            bail!("Journal zu groß");
        }
        let mut book: Self =
            serde_json::from_slice(&security::unprotect_secret(&std::fs::read(path)?)?)?;
        for run in &mut book.runs {
            if run.hash != run.plan.hash()?
                || run.targets.len() != run.plan.mappings.len()
                || run.current >= run.targets.len()
                || !run.targets.iter().zip(&run.plan.mappings).all(|(t, m)| {
                    t.target.same_endpoint(if run.rehearsal {
                        &m.staging
                    } else {
                        &m.production
                    })
                })
            {
                bail!("Journal enthält inkonsistente Ziel- oder Planbindung");
            }
            run.interrupt_after_restart();
        }
        Ok(book)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ordered_http_gets_require_every_assertion() {
        use std::io::{Read, Write};
        for expected_second in [201, 202] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now();
                let mut paths = vec![];
                while paths.len() < 2 && deadline.elapsed() < std::time::Duration::from_secs(10) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                                .unwrap();
                            let mut request = [0; 4096];
                            let n = stream.read(&mut request).unwrap();
                            paths.push(
                                String::from_utf8_lossy(&request[..n])
                                    .lines()
                                    .next()
                                    .unwrap()
                                    .to_owned(),
                            );
                            let status = if paths.len() == 1 { 200 } else { 201 };
                            write!(stream,"HTTP/1.1 {status} OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10))
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
                paths
            });
            let health = super::HealthCheck::Http {
                port,
                tls: false,
                path: "/first".into(),
                status: 200,
                contains: "ok".into(),
                followups: vec![super::HttpGetStep {
                    path: "/second".into(),
                    status: expected_second,
                    contains: "ok".into(),
                    options: Default::default(),
                }],
            };
            assert_eq!(
                health.probe(&target("127.0.0.1")).passed,
                expected_second == 201
            );
            assert_eq!(
                server.join().unwrap(),
                vec!["GET /first HTTP/1.1", "GET /second HTTP/1.1"]
            );
        }
    }
    use super::*;
    fn target(host: &str) -> Target {
        Target {
            profile_id: Uuid::new_v4(),
            name: host.into(),
            host: host.into(),
            port: 3389,
            protocol: "RDP".into(),
            username: String::new(),
            domain: String::new(),
            route: String::new(),
        }
    }
    fn plan() -> ExecutionPlan {
        ExecutionPlan {
            restart: false,
            service: "Spooler".into(),
            desired: ServiceState::Running,
            health: HealthCheck::Tcp { port: 80 },
            mappings: vec![Mapping {
                production: target("prod"),
                staging: target("test"),
            }],
        }
    }
    fn health(passed: bool) -> HealthEvidence {
        HealthEvidence {
            at: Utc::now(),
            passed,
            detail: "fixture".into(),
        }
    }
    fn completed_success(plan: ExecutionPlan, rehearsal: bool) -> Run {
        let mut run = Run::new(plan, rehearsal).unwrap();
        run.targets[0].before = Some(ServiceState::Stopped);
        run.targets[0].captured = Some(Utc::now());
        run.targets[0].evidence.push(r#"{"service":"Spooler","state":"Stopped","dependentRunning":[],"prerequisiteStopped":[]}"#.into());
        run.targets[0].baseline = Some(health(false));
        run.assess_mutation(r#"{"service":"Spooler","before":"Stopped","desired":"Running","actual":"Running","verified":true}"#, false).unwrap();
        run.finish_health(health(true)).unwrap();
        run
    }

    fn learning_http_plan() -> ExecutionPlan {
        let mut p = plan();
        p.health = HealthCheck::Http { port: 80, path: "/health".into(), status: 200, contains: "healthy".into(), tls: false, followups: vec![] };
        p
    }

    #[test]
    fn learning_repair_history_is_target_bound_and_separates_rehearsal() {
        let p=learning_http_plan(); let selected=p.mappings[0].production.clone();
        let good=completed_success(p.clone(),false);
        let rehearsal=completed_success(p,true);
        let mut other=learning_http_plan();other.mappings[0].production=target("other");
        let other=completed_success(other,false);
        let rows=learning::rank(&Journal{runs:vec![good,rehearsal,other]},&selected,Utc::now());
        assert_eq!(rows.len(),1);assert_eq!(rows[0].lesson.production.successes,1);
        assert_eq!(rows[0].lesson.rehearsal.successes,1);assert_eq!(rows[0].excluded,1);
        assert!(rows[0].eligible());assert_eq!(rows[0].score,5);
    }

    #[test]
    fn learning_new_adverse_result_retracts_prior_recommendation() {
        let p=learning_http_plan();let selected=p.mappings[0].production.clone();
        let mut good=completed_success(p.clone(),false);
        let past=Utc::now()-chrono::Duration::days(1);
        good.finished=Some(past);good.targets[0].captured=Some(past);
        good.targets[0].baseline.as_mut().unwrap().at=past;good.targets[0].health.as_mut().unwrap().at=past;
        let mut bad=completed_success(p,false);bad.targets[0].phase=Phase::Restored;
        let rows=learning::rank(&Journal{runs:vec![bad,good]},&selected,Utc::now());
        assert_eq!(rows[0].lesson.production.successes,1);assert_eq!(rows[0].lesson.production.restored,1);
        assert!(!rows[0].eligible());assert_eq!(rows[0].score,-3);
    }

    #[test]
    fn learning_rejects_duplicates_expired_and_future_records() {
        let p=learning_http_plan();let selected=p.mappings[0].production.clone();
        let good=completed_success(p.clone(),false);
        let mut old=completed_success(p.clone(),false);old.finished=Some(Utc::now()-chrono::Duration::days(91));
        let mut future=completed_success(p,false);future.finished=Some(Utc::now()+chrono::Duration::days(1));
        let rows=learning::rank(&Journal{runs:vec![good.clone(),good,old,future]},&selected,Utc::now());
        assert_eq!(rows[0].excluded,4);assert_eq!(rows[0].lesson.production.successes,0);assert!(!rows[0].eligible());
    }

    #[test]
    fn learning_healthy_noop_and_tcp_are_not_repair_success() {
        let p=learning_http_plan();let selected=p.mappings[0].production.clone();
        let mut noop=completed_success(p,false);noop.targets[0].before=Some(ServiceState::Running);
        noop.targets[0].baseline.as_mut().unwrap().passed=true;
        let rows=learning::rank(&Journal{runs:vec![noop]},&selected,Utc::now());
        assert_eq!(rows[0].lesson.production.unknown,1);assert!(!rows[0].eligible());
        assert!(rows[0].gaps.contains(&"gap_baseline"));assert!(rows[0].gaps.contains(&"gap_transition"));
        let tcp=completed_success(plan(),false);let selected=tcp.plan.mappings[0].production.clone();
        assert!(!learning::rank(&Journal{runs:vec![tcp]},&selected,Utc::now())[0].eligible());
    }
    #[test]
    fn execution_lessons_group_hosts_but_separate_rehearsal_and_health_plan() {
        let first = completed_success(plan(), false);
        let mut other_plan = plan();
        other_plan.mappings[0].production = target("different-prod");
        other_plan.mappings[0].staging = target("different-test");
        let second = completed_success(other_plan.clone(), false);
        let rehearsal = completed_success(other_plan.clone(), true);
        other_plan.health = HealthCheck::Tcp { port: 443 };
        let another_check = completed_success(other_plan, false);
        let journal = Journal {
            runs: vec![first, second, rehearsal, another_check],
        };
        let lessons = journal.lessons();
        assert_eq!(lessons.len(), 2);
        let combined = lessons
            .iter()
            .find(|l| matches!(l.health, HealthCheck::Tcp { port: 80 }))
            .unwrap();
        assert_eq!(combined.production.successes, 2);
        assert_eq!(combined.rehearsal.successes, 1);
        assert_eq!(combined.evidence.len(), 3);
    }
    #[test]
    fn execution_lessons_do_not_promote_incomplete_or_corrupted_results() {
        let mut missing_health = completed_success(plan(), false);
        missing_health.targets[0].health = None;
        let mut corrupt_binding = completed_success(plan(), false);
        corrupt_binding.hash = "changed".into();
        let mut missing_change = completed_success(plan(), false);
        missing_change.targets[0].evidence.truncate(1);
        let mut unfinished = completed_success(plan(), false);
        unfinished.finished = None;
        let mut restored = completed_success(plan(), false);
        restored.targets[0].phase = Phase::Restored;
        let mut failed = completed_success(plan(), true);
        failed.targets[0].phase = Phase::Failed;
        let lessons = Journal {
            runs: vec![
                missing_health,
                corrupt_binding,
                missing_change,
                unfinished,
                restored,
                failed,
            ],
        }
        .lessons();
        assert_eq!(lessons.len(), 1);
        let lesson = &lessons[0];
        assert_eq!(lesson.production.successes, 0);
        assert_eq!(lesson.production.unknown, 3);
        assert_eq!(lesson.production.restored, 1);
        assert_eq!(lesson.rehearsal.failures, 1);
        assert_eq!(lesson.evidence.len(), 5);
    }
    #[test]
    fn actual_http_failure_drives_restore_and_stops_rollout() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut b = [0; 4096];
            let _ = stream.read(&mut b);
            write!(
                stream,
                "HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndown"
            )
            .unwrap();
        });
        let mut p = plan();
        p.health = HealthCheck::Http {
            port,
            tls: false,
            path: "/health".into(),
            status: 200,
            contains: "healthy".into(),
            followups: vec![],
        };
        p.mappings[0].production = target("127.0.0.1");
        p.mappings.push(Mapping {
            production: target("untouched-prod"),
            staging: target("untouched-test"),
        });
        let mut run = Run::new(p, false).unwrap();
        run.targets[0].before = Some(ServiceState::Stopped);
        run.assess_mutation(r#"{"service":"Spooler","before":"Stopped","desired":"Running","actual":"Running","verified":true}"#,false).unwrap();
        let evidence = run.plan.health.probe(&run.targets[0].target);
        run.finish_health(evidence).unwrap();
        assert_eq!(run.targets[0].phase, Phase::Restore);
        let spec = intelligence::service_spec(
            &run.targets[0].target,
            &run.plan.service,
            Some((run.plan.desired, run.targets[0].before.unwrap())),
        )
        .unwrap();
        assert!(!spec.args.is_empty()); // Generated guarded restoration is never executed by this fixture.
        run.assess_mutation(r#"{"service":"Spooler","before":"Running","desired":"Stopped","actual":"Stopped","verified":true}"#,true).unwrap();
        run.advance();
        assert!(run.finished.is_some());
        assert_eq!(run.targets[0].phase, Phase::Restored);
        assert_eq!(run.targets[1].phase, Phase::Capture);
        assert!(!run.successful());
        worker.join().unwrap();
    }
    #[test]
    fn proof_is_bound_and_expires() {
        let p = plan();
        let mut r = Run::new(p.clone(), true).unwrap();
        assert!(!r.proof_for(&p, Utc::now()));
        r.targets[0].before = Some(ServiceState::Stopped);
        r.targets[0].baseline = Some(health(false));
        r.targets[0].phase = Phase::Verify;
        r.finish_health(health(true)).unwrap();
        assert!(r.proof_for(&p, Utc::now()));
        let mut changed = p.clone();
        changed.service = "Other".into();
        assert!(!r.proof_for(&changed, Utc::now()));
        assert!(!r.proof_for(&p, Utc::now() + chrono::Duration::hours(2)));
        changed = p.clone();
        changed.mappings[0].production.domain = "elsewhere".into();
        assert!(!r.proof_for(&changed, Utc::now()));
    }
    #[test]
    fn reject_same_winrm_host_despite_profile_port() {
        let mut p = plan();
        p.mappings[0].staging.host = "PROD.".into();
        p.mappings[0].staging.port = 3390;
        assert!(p.validate().is_err());
    }
    #[test]
    fn verified_state_still_requires_health() {
        let mut r = Run::new(plan(), true).unwrap();
        r.targets[0].before = Some(ServiceState::Stopped);
        r.assess_mutation(r#"{"service":"Spooler","before":"Stopped","desired":"Running","actual":"Running","verified":true}"#, false).unwrap();
        assert_eq!(r.targets[0].phase, Phase::Verify);
        assert!(!r.successful());
        r.finish_health(health(false)).unwrap();
        assert_eq!(r.targets[0].phase, Phase::Restore);
        assert!(r.finished.is_none());
        r.assess_mutation(r#"{"service":"Spooler","before":"Running","desired":"Stopped","actual":"Stopped","verified":true}"#, true).unwrap();
        assert_eq!(r.targets[0].phase, Phase::Restored);
        r.advance();
        assert!(!r.successful());
    }
    #[test]
    fn rollout_waits_for_pilot_and_stops_on_restored_failure() {
        let mut p = plan();
        p.mappings.push(Mapping {
            production: target("prod2"),
            staging: target("test2"),
        });
        let mut r = Run::new(p, false).unwrap();
        r.targets[0].phase = Phase::Verify;
        r.targets[0].before = Some(ServiceState::Stopped);
        r.finish_health(health(false)).unwrap();
        assert_eq!(r.current, 0);
        r.targets[0].phase = Phase::Restored;
        r.advance();
        assert!(r.finished.is_some());
        assert_eq!(r.targets[1].phase, Phase::Capture);
        assert!(!r.successful());
    }
    #[test]
    fn restart_never_repeats_apply_or_restore() {
        for phase in [
            Phase::Capture,
            Phase::Review,
            Phase::Apply,
            Phase::Verify,
            Phase::Restore,
        ] {
            let mut r = Run::new(plan(), true).unwrap();
            r.targets[0].phase = phase;
            r.interrupt_after_restart();
            assert_eq!(r.targets[0].phase, Phase::Unknown);
            assert!(r.finished.is_some());
            assert!(!r.proof_for(&r.plan, Utc::now()));
            let finished = r.finished;
            r.interrupt_after_restart();
            assert_eq!(r.finished, finished);
        }
    }
    #[test]
    fn local_http_fixture_checks_body_and_does_not_follow_redirect() {
        use std::io::{Read, Write};
        for (status, body, expected) in [
            (200, "healthy", true),
            (200, "unavailable", false),
            (302, "healthy", false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut b = [0; 4096];
                let _ = stream.read(&mut b);
                write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            });
            let health = HealthCheck::Http {
                port,
                tls: false,
                path: "/health".into(),
                status: 200,
                contains: "healthy".into(),
                followups: vec![],
            };
            assert_eq!(health.probe(&target("127.0.0.1")).passed, expected);
            worker.join().unwrap();
        }
    }
    #[test]
    fn local_tcp_fixture() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(
            HealthCheck::Tcp {
                port: listener.local_addr().unwrap().port()
            }
            .probe(&target("127.0.0.1"))
            .passed
        );
    }
}
