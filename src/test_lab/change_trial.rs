//! Bounded clone experiments. These receipts confer no production authority.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Startup {
    #[default]
    Automatic,
    Manual,
}
impl Startup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Automatic => "Automatic",
            Self::Manual => "Manual",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub service: String,
    pub startup: Startup,
    pub health: HealthProbe,
}
impl Spec {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.service.is_empty()
                && self.service.len() <= 128
                && self
                    .service
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_- .".contains(&c)),
            "Invalid service name"
        );
        anyhow::ensure!(
            ![
                "vmicvmsession",
                "vmicheartbeat",
                "vmicshutdown",
                "rpcss",
                "dcomlaunch",
                "rpceptmapper",
                "winrm",
                "eventlog",
                "samss",
                "lsm",
                "schedule",
                "bfe",
                "mpssvc",
                "dhcp",
                "dnscache",
                "nsi",
                "power",
                "profsvc",
                "gpsvc",
                "plugplay",
                "winmgmt"
            ]
            .iter()
            .any(|s| self.service.eq_ignore_ascii_case(s)),
            "System service is blocked for fault experiments"
        );
        self.health.validate()?;
        anyhow::ensure!(
            !self.health.url.is_empty() && self.health.followups.is_empty(),
            "Initial version requires exactly one public loopback HTTP check"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: Uuid,
    pub lab_id: String,
    pub vm_id: String,
    pub spec: Spec,
    pub started: DateTime<Utc>,
}
impl Request {
    fn hash(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
    pub fn checkpoint_name(&self) -> String {
        format!("Relayne-Trial-{}", self.id)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub request_hash: String,
    pub baseline: bool,
    pub changed: bool,
    pub fault_observed: bool,
    pub repaired: bool,
    pub returned: bool,
    pub checkpoint_removed: bool,
    pub untouched: bool,
    pub baseline_mode: String,
    pub stage: String,
}
impl Proof {
    pub fn passed(&self) -> bool {
        self.baseline
            && self.changed
            && self.fault_observed
            && self.repaired
            && self.returned
            && self.checkpoint_removed
            && !self.untouched
    }
    fn settled(&self) -> bool {
        self.untouched || (self.returned && self.checkpoint_removed)
    }
    fn validate(&self, request: &Request) -> Result<()> {
        anyhow::ensure!(
            self.request_hash == request.hash()?,
            "Trial binding does not match"
        );
        anyhow::ensure!(
            [
                "baseline",
                "checkpoint",
                "change",
                "fault",
                "repair",
                "return",
                "complete"
            ]
            .contains(&self.stage.as_str()),
            "Unknown trial phase"
        );
        anyhow::ensure!(
            !self.untouched
                || (!self.changed
                    && !self.fault_observed
                    && !self.repaired
                    && !self.returned
                    && self.stage == "baseline"),
            "Contradictory unchanged state"
        );
        anyhow::ensure!(
            !self.repaired || self.fault_observed,
            "Repair without a fault observation"
        );
        anyhow::ensure!(
            !self.fault_observed || self.changed,
            "Fault without a change"
        );
        anyhow::ensure!(!self.changed || self.baseline, "Change without a baseline");
        anyhow::ensure!(
            !self.checkpoint_removed || self.returned,
            "Checkpoint removed without a verified recovery path"
        );
        anyhow::ensure!(
            !(self.baseline || self.returned)
                || ["Auto", "Manual"].contains(&self.baseline_mode.as_str()),
            "Unknown startup type baseline"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Restoration {
    request_hash: String,
    finished: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct Record {
    pub request: Request,
    pub proof: Option<Proof>,
    pub recovered: bool,
}
impl Record {
    pub fn unresolved(&self) -> bool {
        !self.recovered && self.proof.as_ref().is_none_or(|p| !p.settled())
    }
}

fn directory(lab: &str) -> Result<PathBuf> {
    let path = receipt_directory(lab)?.join("change-trials");
    assert_plain_path(&path)?;
    Ok(path)
}
fn optional<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<Option<T>> {
    match read_protected(path) {
        Ok(v) => Ok(Some(v)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
pub fn history(lab: &str) -> Result<Vec<Record>> {
    let dir = directory(lab)?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut records = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("Invalid evidence name")?;
        if !name.ends_with(".request.dpapi") {
            continue;
        }
        anyhow::ensure!(records.len() < 100, "Trial limit reached");
        let request: Request = read_protected(&path)?;
        request.spec.validate()?;
        anyhow::ensure!(
            request.lab_id == lab && name == format!("{}.request.dpapi", request.id),
            "Trial identity changed"
        );
        Uuid::parse_str(&request.vm_id)?;
        let proof: Option<Proof> = optional(&dir.join(format!("{}.result.dpapi", request.id)))?;
        if let Some(p) = &proof {
            p.validate(&request)?;
        }
        let recovery: Option<Restoration> =
            optional(&dir.join(format!("{}.restore.dpapi", request.id)))?;
        if let Some(r) = &recovery {
            anyhow::ensure!(
                r.request_hash == request.hash()?,
                "Recovery path belongs to another trial"
            );
        }
        records.push(Record {
            request,
            proof,
            recovered: recovery.is_some(),
        });
    }
    records.sort_by_key(|r| std::cmp::Reverse(r.request.started));
    Ok(records)
}

fn current(journal: &Journal) -> Result<Journal> {
    // receipt_directory verifies canonical lab identity and rejects reparse paths.
    directory(&journal.id)?;
    let saved = read_journal(&root()?.join(&journal.id).join("journal.dpapi"))?;
    anyhow::ensure!(
        saved.vm_id == journal.vm_id
            && saved.directory == journal.directory
            && saved.name == journal.name,
        "Clone changed; select it again"
    );
    Uuid::parse_str(&saved.vm_id)?;
    Ok(saved)
}
fn credentials(user: &str, password: &str) -> Result<()> {
    anyhow::ensure!(
        !user.trim().is_empty()
            && user.len() <= 256
            && !password.is_empty()
            && password.len() <= 4096,
        "Guest credentials required"
    );
    Ok(())
}

pub fn run(journal: Journal, spec: Spec, user: String, password: String) -> Result<Record> {
    spec.validate()?;
    credentials(&user, &password)?;
    let _lock = lock_lab(&journal.id)?;
    let journal = current(&journal)?;
    let records = history(&journal.id)?;
    anyhow::ensure!(
        records.len() < 100 && !records.iter().any(Record::unresolved),
        "Recover the open trial first (or trial limit reached)"
    );
    let request = Request {
        id: Uuid::new_v4(),
        lab_id: journal.id.clone(),
        vm_id: journal.vm_id.clone(),
        spec,
        started: Utc::now(),
    };
    let dir = directory(&journal.id)?;
    std::fs::create_dir_all(&dir)?;
    write_immutable(&dir.join(format!("{}.request.dpapi", request.id)), &request)?;
    let payload = serde_json::json!({"lab":journal,"request":request,"hash":request.hash()?,"checkpoint":request.checkpoint_name(),"user":user,"password":password,"recover":false});
    let proof: Proof =
        serde_json::from_str(&run_script(include_str!("change_trial.ps1"), payload)?)?;
    proof.validate(&request)?;
    write_immutable(&dir.join(format!("{}.result.dpapi", request.id)), &proof)?;
    Ok(Record {
        request,
        proof: Some(proof),
        recovered: false,
    })
}

pub fn recover(journal: Journal, id: Uuid, user: String, password: String) -> Result<()> {
    credentials(&user, &password)?;
    let _lock = lock_lab(&journal.id)?;
    let journal = current(&journal)?;
    let record = history(&journal.id)?
        .into_iter()
        .find(|r| r.request.id == id)
        .context("Trial is missing")?;
    anyhow::ensure!(
        record.unresolved() && record.request.vm_id == journal.vm_id,
        "Trial completed or VM changed"
    );
    let request = record.request;
    let payload = serde_json::json!({"lab":journal,"request":request,"hash":request.hash()?,"checkpoint":request.checkpoint_name(),"user":user,"password":password,"recover":true});
    let proof: Proof =
        serde_json::from_str(&run_script(include_str!("change_trial.ps1"), payload)?)?;
    proof.validate(&request)?;
    anyhow::ensure!(
        proof.returned && proof.checkpoint_removed,
        "Recovery path not confirmed; review clone and checkpoint manually"
    );
    write_immutable(
        &directory(&request.lab_id)?.join(format!("{}.restore.dpapi", request.id)),
        &Restoration {
            request_hash: request.hash()?,
            finished: Utc::now(),
        },
    )
}

#[cfg(test)]
#[path = "change_trial_tests.rs"]
mod tests;
