//! Explicitly reviewed serial workflows. Imported packages are inert data.
use crate::operations::{Endpoint, JobQueue, JobStatus, Query, Request, ServiceAction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

const LIMIT: usize = 256 * 1024;
#[cfg(test)]
#[path = "workflow_procedure_tests.rs"]
mod procedure_tests;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub host: String,
    pub user: String,
    pub port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "protocol", deny_unknown_fields)]
pub enum Action {
    Ssh {
        target: Target,
        command: String,
        stdout_contains: String,
    },
    WinRm {
        target: Target,
        operation: WinOperation,
        stdout_contains: String,
    },
    Http {
        url: String,
        method: HttpMethod,
        form: BTreeMap<String, String>,
        secret_fields: BTreeMap<String, String>,
        status: u16,
        body_contains: Option<String>,
        json_equals: BTreeMap<String, serde_json::Value>,
    },
    RdpCheckpoint {
        target: String,
        expected: String,
    },
    RdpProcedure {
        target: String,
        procedure: crate::teaching::Procedure,
        parameters: BTreeMap<String, String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum WinOperation {
    Inventory,
    Services,
    Processes,
    Events,
    Start { service: String },
    Stop { service: String },
    Restart { service: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub name: String,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub name: String,
    pub preconditions: Vec<Step>,
    pub steps: Vec<Step>,
    pub verification: Vec<Step>,
    pub restore: Vec<Step>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub schema: u32,
    pub recipe_version: String,
    pub provenance: String,
    pub plan: Plan,
    pub sha256: String,
}
fn validate_recipe_version(version: &str) -> Result<(), String> {
    let parts: Vec<_> = version.split('.').collect();
    if version.len() > 64
        || parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
                || p.parse::<u64>().is_err()
        })
    {
        return Err("Recipe version must be numeric MAJOR.MINOR.PATCH, e.g. 1.0.0".into());
    }
    Ok(())
}
fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|e| e.to_string())?)
    ))
}
impl Package {
    pub fn new(plan: Plan, provenance: String) -> Result<Self, String> {
        Self::new_version(plan, provenance, "1.0.0".into())
    }
    pub fn new_version(
        plan: Plan,
        provenance: String,
        recipe_version: String,
    ) -> Result<Self, String> {
        validate(&plan)?;
        validate_recipe_version(&recipe_version)?;
        let sha256 = digest(&(1_u32, &recipe_version, &provenance, &plan))?;
        Ok(Self {
            schema: 1,
            recipe_version,
            provenance,
            plan,
            sha256,
        })
    }
    pub fn import(text: &str) -> Result<Self, String> {
        if text.len() > LIMIT {
            return Err("Package exceeds 256 KiB".into());
        }
        let p: Self = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if p.schema != 1 {
            return Err("Unsupported package schema".into());
        }
        validate_recipe_version(&p.recipe_version)?;
        validate(&p.plan)?;
        if p.sha256 != digest(&(p.schema, &p.recipe_version, &p.provenance, &p.plan))? {
            return Err("Package integrity mismatch".into());
        }
        Ok(p)
    }
    pub fn export(&self) -> Result<String, String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        Self::import(&text)?;
        Ok(text)
    }
}
fn command(action: &Action) -> Result<Option<crate::operations::CommandSpec>, String> {
    if let Action::WinRm { target, .. } = action {
        if target.port != 5985 || !target.user.is_empty() {
            return Err("WinRM workflow adapter requires port 5985 and an empty user field: authentication uses the current Windows identity".into());
        }
    }
    let (t, r) = match action {
        Action::Ssh {
            target, command, ..
        } => (
            target,
            Request::Ssh {
                command: command.clone(),
            },
        ),
        Action::WinRm {
            target, operation, ..
        } => (
            target,
            match operation {
                WinOperation::Inventory => Request::WinRm(Query::Inventory),
                WinOperation::Services => Request::WinRm(Query::Services),
                WinOperation::Processes => Request::WinRm(Query::Processes),
                WinOperation::Events => Request::WinRm(Query::Events),
                WinOperation::Start { service } => Request::Service {
                    name: service.clone(),
                    action: ServiceAction::Start,
                },
                WinOperation::Stop { service } => Request::Service {
                    name: service.clone(),
                    action: ServiceAction::Stop,
                },
                WinOperation::Restart { service } => Request::Service {
                    name: service.clone(),
                    action: ServiceAction::Restart,
                },
            },
        ),
        _ => return Ok(None),
    };
    Ok(Some(r.build(&Endpoint::new(&t.host, &t.user, t.port)?)?))
}
fn http_url(value: &str) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(value).map_err(|_| "Invalid HTTP URL")?;
    if !matches!(u.scheme(), "https" | "http")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err("HTTP URL must have host and no credentials or fragment".into());
    }
    Ok(u)
}
pub fn validate(p: &Plan) -> Result<(), String> {
    if serde_json::to_vec(p).map_err(|e| e.to_string())?.len() > LIMIT
        || p.name.trim().is_empty()
        || p.steps.is_empty()
        || p.verification.is_empty()
    {
        return Err("Plan needs name, action and application verification; max 256 KiB".into());
    }
    let steps: Vec<_> = p
        .preconditions
        .iter()
        .chain(&p.steps)
        .chain(&p.verification)
        .chain(&p.restore)
        .collect();
    if steps.len() > 32 {
        return Err("Maximum 32 total steps".into());
    }
    for s in &p.preconditions {
        if !matches!(
            &s.action,
            Action::Http {
                method: HttpMethod::Get,
                ..
            } | Action::WinRm {
                operation: WinOperation::Inventory
                    | WinOperation::Services
                    | WinOperation::Processes
                    | WinOperation::Events,
                ..
            } | Action::RdpCheckpoint { .. }
        ) {
            return Err(
                "Preconditions allow HTTP GET, fixed WinRM queries or manual checkpoints only"
                    .into(),
            );
        }
    }
    for s in steps {
        if s.name.trim().is_empty() || s.name.len() > 256 {
            return Err("Step name required; maximum 256 bytes".into());
        }
        command(&s.action)?;
        match &s.action {
            Action::RdpProcedure {
                target,
                procedure,
                parameters,
            } => {
                if target.trim().is_empty()
                    || target.len() > 512
                    || parameters.len() > 64
                    || parameters.iter().any(|(k, v)| {
                        k.is_empty() || v.is_empty() || k.len() > 256 || v.len() > 256
                    })
                {
                    return Err("Procedure requires bounded target and parameter slot names".into());
                }
                crate::teaching::validate_workflow_procedure(procedure)
                    .map_err(|e| e.to_string())?;
                let names: std::collections::BTreeSet<_> = procedure
                    .steps
                    .iter()
                    .filter_map(|step| match step {
                        crate::teaching::Step::Parameter { name } => Some(name),
                        _ => None,
                    })
                    .collect();
                if names != parameters.keys().collect() {
                    return Err(
                        "Procedure parameter mapping must exactly match declared parameters".into(),
                    );
                }
            }
            Action::Ssh {
                stdout_contains, ..
            }
            | Action::WinRm {
                stdout_contains, ..
            } if stdout_contains.trim().is_empty() => {
                return Err("Remote command requires an explicit nonempty expected output".into());
            }
            Action::Http {
                url,
                status,
                method,
                form,
                secret_fields,
                json_equals,
                ..
            } => {
                let u = http_url(url)?;
                if !secret_fields.is_empty()
                    && u.scheme() != "https"
                    && !u
                        .host_str()
                        .is_some_and(|h| h == "127.0.0.1" || h == "[::1]" || h == "::1")
                {
                    return Err("HTTP secret submission requires HTTPS (except literal loopback test addresses)".into());
                }
                if !(100..=599).contains(status)
                    || json_equals
                        .keys()
                        .any(|k| !k.is_empty() && !k.starts_with('/'))
                {
                    return Err("Invalid HTTP assertion".into());
                }
                if matches!(method, HttpMethod::Get)
                    && (!form.is_empty() || !secret_fields.is_empty())
                {
                    return Err("GET cannot submit form fields".into());
                }
                if form.keys().any(|k| secret_fields.contains_key(k)) {
                    return Err("Duplicate form and secret field".into());
                }
                if secret_fields.values().any(|v| v.is_empty()) {
                    return Err("Secret slot name required".into());
                }
            }
            Action::RdpCheckpoint { target, expected }
                if target.trim().is_empty()
                    || expected.trim().is_empty()
                    || target.len() > 512
                    || expected.len() > 4096 =>
            {
                return Err("Checkpoint requires bounded target and expected result".into());
            }
            _ => {}
        }
    }
    Ok(())
}
pub fn review_digest(p: &Plan) -> Result<String, String> {
    validate(p)?;
    digest(p)
}

/// Cookie session is strictly keyed to exact scheme/host/port and never serialized.
#[derive(Default)]
struct HttpSession {
    cookies: BTreeMap<String, BTreeMap<String, String>>,
}
impl HttpSession {
    fn execute(
        &mut self,
        a: &Action,
        secrets: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let Action::Http {
            url,
            method,
            form,
            secret_fields,
            status,
            body_contains,
            json_equals,
        } = a
        else {
            return Err("Not HTTP".into());
        };
        let u = http_url(url)?;
        let origin = u.origin().ascii_serialization();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| "HTTP client unavailable")?;
        let mut req = match method {
            HttpMethod::Get => client.get(u.clone()),
            HttpMethod::Post => client.post(u.clone()),
        };
        if let Some(cookies) = self.cookies.get(&origin) {
            req = req.header(
                reqwest::header::COOKIE,
                cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        let mut fields = form.clone();
        for (field, slot) in secret_fields {
            fields.insert(
                field.clone(),
                secrets
                    .get(slot)
                    .ok_or_else(|| format!("Missing ephemeral secret slot: {slot}"))?
                    .clone(),
            );
        }
        if matches!(method, HttpMethod::Post) {
            req = req.form(&fields);
        }
        let response = req
            .send()
            .map_err(|_| "HTTP transport failed (details suppressed to protect credentials)")?;
        if response.status().as_u16() != *status {
            return Err(format!(
                "Expected HTTP {status}, observed {}",
                response.status().as_u16()
            ));
        }
        // Deliberately constrained session: only host cookies with Path=/; reject broader Domain or narrower Path scope.
        for value in response.headers().get_all(reqwest::header::SET_COOKIE) {
            let value = value.to_str().map_err(|_| "Invalid cookie")?;
            let parts: Vec<_> = value.split(';').map(str::trim).collect();
            if !parts
                .iter()
                .skip(1)
                .any(|s| s.eq_ignore_ascii_case("path=/"))
                || parts.iter().skip(1).any(|s| {
                    s.to_ascii_lowercase().starts_with("domain=")
                        || (s.to_ascii_lowercase().starts_with("path=")
                            && !s.eq_ignore_ascii_case("path=/"))
                })
            {
                return Err(
                    "Cookie scope unsupported: use host-only Path=/ session cookies".into(),
                );
            }
            if parts
                .iter()
                .skip(1)
                .any(|s| s.eq_ignore_ascii_case("secure"))
                && u.scheme() != "https"
            {
                continue;
            }
            let (name, value) = parts[0].split_once('=').ok_or("Invalid cookie")?;
            if name.is_empty() || value.len() > 4096 {
                return Err("Invalid cookie length".into());
            }
            if self.cookies.len() >= 32 && !self.cookies.contains_key(&origin) {
                return Err("Cookie origin cap reached".into());
            }
            let jar = self.cookies.entry(origin.clone()).or_default();
            if jar.len() >= 32 && !jar.contains_key(name) {
                return Err("Cookie cap reached".into());
            }
            let age = parts.iter().find_map(|s| {
                s.split_once('=')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("max-age"))
                    .map(|(_, v)| v.parse::<i64>())
            });
            if age.as_ref().is_some_and(|a| matches!(a,Ok(n) if *n<=0)) {
                jar.remove(name);
                continue;
            }
            if age.is_some()
                || parts
                    .iter()
                    .any(|s| s.to_ascii_lowercase().starts_with("expires="))
            {
                return Err("Persistent cookies unsupported; require session cookie without Expires/positive Max-Age".into());
            }
            jar.insert(name.into(), value.into());
        }
        let mut bytes = Vec::new();
        response
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "HTTP body read failed")?;
        if bytes.len() > LIMIT {
            return Err("HTTP response exceeds 256 KiB".into());
        }
        let body = String::from_utf8(bytes).map_err(|_| "HTTP response is not UTF-8")?;
        if body_contains.as_ref().is_some_and(|s| !body.contains(s)) {
            return Err("HTTP body assertion failed".into());
        }
        if !json_equals.is_empty() {
            let json: serde_json::Value =
                serde_json::from_str(&body).map_err(|_| "Expected JSON response")?;
            for (ptr, expected) in json_equals {
                if json.pointer(ptr) != Some(expected) {
                    return Err(format!("JSON assertion failed at {ptr}"));
                }
            }
        }
        Ok(format!("HTTP {status}; body and JSON assertions passed"))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Journal {
    pub run_id: String,
    pub digest: String,
    pub at: chrono::DateTime<chrono::Utc>,
    pub state: String,
    pub completed: usize,
    pub events: Vec<String>,
    #[serde(default)]
    pub records: Vec<crate::incident::Record>,
}
fn journal_path() -> Result<std::path::PathBuf, String> {
    crate::security::app_data_file("workflow-journal.dpapi").map_err(|e| e.to_string())
}
fn save(j: &Journal) -> Result<(), String> {
    // Do not overwrite evidence if either existing encrypted store is corrupt.
    load_journal()?;
    let mut history = load_history()?;
    let clear = serde_json::to_vec(j).map_err(|e| e.to_string())?;
    let encrypted = crate::security::protect_secret(&clear).map_err(|e| e.to_string())?;
    let path = journal_path()?;
    crate::security::atomic_write(&path, &encrypted).map_err(|e| e.to_string())?;
    history.retain(|old| old.run_id != j.run_id);
    history.push(j.clone());
    if history.len() > 50 {
        history.drain(..history.len() - 50);
    }
    let mut bytes = serde_json::to_vec(&history).map_err(|e| e.to_string())?;
    while bytes.len() > 8 * 1024 * 1024 && history.len() > 1 {
        history.remove(0);
        bytes = serde_json::to_vec(&history).map_err(|e| e.to_string())?;
    }
    let protected = crate::security::protect_secret(&bytes).map_err(|e| e.to_string())?;
    let path =
        crate::security::app_data_file("workflow-history.dpapi").map_err(|e| e.to_string())?;
    crate::security::atomic_write(&path, &protected).map_err(|e| e.to_string())
}
pub fn load_history() -> Result<Vec<Journal>, String> {
    let path =
        crate::security::app_data_file("workflow-history.dpapi").map_err(|e| e.to_string())?;
    if !path.exists() {
        return Ok(vec![]);
    }
    if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
        return Err("History exceeds safe cap".into());
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let clear = crate::security::unprotect_secret(&bytes).map_err(|e| e.to_string())?;
    serde_json::from_slice(&clear).map_err(|e| e.to_string())
}
fn record(
    j: &mut Journal,
    s: &Step,
    kind: crate::incident::Kind,
    text: &str,
    secrets: &BTreeMap<String, String>,
    profiles: &[crate::mission::Target],
) {
    let (_, endpoint): (Option<uuid::Uuid>, String) = match &s.action {
        Action::Ssh { target, .. } | Action::WinRm { target, .. } => (
            None,
            format!("{}:{} user={}", target.host, target.port, target.user),
        ),
        Action::Http { url, .. } => (
            None,
            http_url(url)
                .map(|u| u.origin().ascii_serialization())
                .unwrap_or_default(),
        ),
        Action::RdpCheckpoint { target, .. } | Action::RdpProcedure { target, .. } => {
            (None, target.clone())
        }
    };
    let mut text = format!("{}: {text}", s.name);
    for value in secrets.values().filter(|s| !s.is_empty()) {
        text = text.replace(value, "[REDACTED]");
    }
    text = crate::security::redact_secret_text(&text)
        .chars()
        .take(2048)
        .collect();
    j.events.push(text.clone());
    let binding = trusted_binding(&s.action, profiles);
    j.records.push(crate::incident::Record {
        id: format!("workflow:{}:{}", j.run_id, j.records.len()),
        profile: binding.as_ref().map(|t| t.profile_id),
        endpoint: binding.as_ref().map(crate::incident::endpoint_key),
        at: chrono::Utc::now(),
        kind,
        title: text,
        evidence: vec![format!("Plan {}; endpoint {endpoint}", j.digest)],
    });
}

// Only locally loaded, uniquely matching transport identities can link incidents.
// WinRM uses current-user authentication independently of saved RDP credentials;
// HTTP origins likewise do not imply an RDP/SSH profile identity.
fn trusted_binding(
    action: &Action,
    profiles: &[crate::mission::Target],
) -> Option<crate::mission::Target> {
    let mut matches = profiles.iter().filter(|p| match action {
        Action::Ssh { target, .. } => {
            p.protocol == "SSH"
                && p.host == target.host
                && p.port == target.port
                && p.username == target.user
                && p.domain.is_empty()
                && p.route.is_empty()
        }
        Action::RdpProcedure { target, .. } => {
            p.protocol == "RDP" && p.route.is_empty() && p.host.eq_ignore_ascii_case(target)
        }
        _ => false,
    });
    let result = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(result.clone())
}
pub fn load_journal() -> Result<Option<Journal>, String> {
    let path = journal_path()?;
    if !path.exists() {
        return Ok(None);
    }
    if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Journal too large".into());
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let clear = crate::security::unprotect_secret(&bytes).map_err(|e| e.to_string())?;
    let mut j: Journal = serde_json::from_slice(&clear).map_err(|e| e.to_string())?;
    if j.state == "Running" || j.state == "Awaiting evidence" {
        j.state = "Interrupted — remote outcome uncertain; verify before any retry".into();
    }
    Ok(Some(j))
}
pub enum Event {
    Journal(Journal),
    Checkpoint {
        token: String,
        target: String,
        expected: String,
    },
    Procedure {
        token: String,
        target: String,
        binding: Option<crate::mission::Target>,
        procedure: crate::teaching::Procedure,
        values: BTreeMap<String, String>,
    },
    Done,
}
pub struct Running {
    pub events: mpsc::Receiver<Event>,
    pub evidence: mpsc::Sender<(String, String)>,
    cancel: Arc<AtomicBool>,
}
impl Running {
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel();
    }
}
pub fn start(
    plan: Plan,
    approved_digest: &str,
    secrets: BTreeMap<String, String>,
) -> Result<Running, String> {
    start_with_profiles(plan, approved_digest, secrets, &[])
}
pub fn start_with_profiles(
    plan: Plan,
    approved_digest: &str,
    secrets: BTreeMap<String, String>,
    profiles: &[crate::models::ConnectionProfile],
) -> Result<Running, String> {
    let profiles: Vec<_> = profiles
        .iter()
        .map(crate::mission::Target::from_profile)
        .collect();
    if review_digest(&plan)? != approved_digest {
        return Err("Plan changed after review".into());
    }
    for step in plan
        .preconditions
        .iter()
        .chain(&plan.steps)
        .chain(&plan.verification)
    {
        if let Action::RdpProcedure {
            procedure,
            parameters,
            ..
        } = &step.action
        {
            for slot in parameters.values() {
                if !secrets.contains_key(slot) {
                    return Err(format!("Missing ephemeral procedure slot: {slot}"));
                }
            }
            let values = parameters
                .iter()
                .map(|(name, slot)| (name.clone(), secrets[slot].clone()))
                .collect();
            crate::transferable::validate_run(procedure, &values).map_err(|e| e.to_string())?;
        }
        if let Action::Http { secret_fields, .. } = &step.action {
            for slot in secret_fields.values() {
                if !secrets.contains_key(slot) {
                    return Err(format!("Missing ephemeral secret slot: {slot}"));
                }
            }
        }
    }
    let mut j = Journal {
        run_id: uuid::Uuid::new_v4().to_string(),
        digest: approved_digest.into(),
        at: chrono::Utc::now(),
        state: "Running".into(),
        completed: 0,
        events: vec![],
        records: vec![],
    };
    save(&j)?;
    let (tx, events) = mpsc::channel();
    let (evidence, rx) = mpsc::channel::<(String, String)>();
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    std::thread::spawn(move || {
        let mut http = HttpSession::default();
        for s in plan
            .preconditions
            .iter()
            .chain(&plan.steps)
            .chain(&plan.verification)
        {
            if stop.load(Ordering::Relaxed) {
                j.state = "Cancelled — verify in-flight effects before retry".into();
                break;
            }
            j.state = "Running".into();
            record(
                &mut j,
                s,
                crate::incident::Kind::Action,
                "Starting reviewed step",
                &secrets,
                &profiles,
            );
            j.at = chrono::Utc::now();
            if let Err(e) = save(&j) {
                j.state = format!("Journal write failed: {e}");
                break;
            }
            let _ = tx.send(Event::Journal(j.clone()));
            let result = (|| -> Result<String, String> {
                if let Some(spec) = command(&s.action)? {
                    let mut q = JobQueue::default();
                    let id = q.enqueue(spec)?;
                    loop {
                        q.poll();
                        let job = q.jobs.iter().find(|j| j.id == id).ok_or("Job missing")?;
                        if stop.load(Ordering::Relaxed) {
                            job.cancel();
                        }
                        if job.status.terminal() {
                            if job.status != JobStatus::Completed {
                                return Err("Remote job failed/cancelled/timed out; outcome may be uncertain".into());
                            }
                            let r = job.result.as_ref().ok_or("Missing job result")?;
                            let expected = match &s.action {
                                Action::Ssh {
                                    stdout_contains, ..
                                }
                                | Action::WinRm {
                                    stdout_contains, ..
                                } => stdout_contains,
                                _ => unreachable!(),
                            };
                            if r.truncated || !r.stdout.contains(expected) {
                                return Err("Remote output assertion failed or truncated".into());
                            }
                            return Ok("Remote command completed; output assertion passed".into());
                        }
                        std::thread::sleep(Duration::from_millis(30));
                    }
                }
                match &s.action {
                    Action::RdpProcedure {
                        target,
                        procedure,
                        parameters,
                    } => {
                        j.state = "Awaiting evidence".into();
                        save(&j)?;
                        let token = uuid::Uuid::new_v4().to_string();
                        let values = parameters
                            .iter()
                            .map(|(name, slot)| (name.clone(), secrets[slot].clone()))
                            .collect();
                        tx.send(Event::Procedure {
                            token: token.clone(),
                            target: target.clone(),
                            binding: trusted_binding(&s.action, &profiles),
                            procedure: procedure.clone(),
                            values,
                        })
                        .map_err(|_| "Procedure UI unavailable")?;
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                return Err("Procedure cancelled; verify in-flight effects".into());
                            }
                            match rx.recv_timeout(Duration::from_millis(100)) {
                                Ok((received, _)) if received != token => continue,
                                Ok((_, value)) if value == "PROCEDURE_VERIFIED" => return Ok(
                                    "Demonstrated procedure completed with verified postconditions"
                                        .into(),
                                ),
                                Ok(_) => {
                                    return Err(
                                        "Demonstrated procedure failed or could not start".into()
                                    );
                                }
                                Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    return Err("Procedure UI disconnected".into());
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    Action::Http { .. } => http.execute(&s.action, &secrets),
                    Action::RdpCheckpoint { target, expected } => {
                        j.state = "Awaiting evidence".into();
                        save(&j)?;
                        let token = uuid::Uuid::new_v4().to_string();
                        let _ = tx.send(Event::Checkpoint {
                            token: token.clone(),
                            target: target.clone(),
                            expected: expected.clone(),
                        });
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                return Err("Checkpoint cancelled".into());
                            }
                            match rx.recv_timeout(Duration::from_millis(100)) {
                                Ok((received, _)) if received != token => continue,
                                Ok((_, value))
                                    if !value.trim().is_empty() && value.len() <= 4096 =>
                                {
                                    return Ok(format!(
                                        "Checkpoint evidence: {}",
                                        crate::security::redact_secret_text(&value)
                                    ));
                                }
                                Ok(_) => {
                                    return Err("Checkpoint evidence is empty or too long".into());
                                }
                                Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    return Err("Evidence channel closed".into());
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            })();
            match result {
                Ok(e) => {
                    j.completed += 1;
                    record(
                        &mut j,
                        s,
                        crate::incident::Kind::Observation,
                        &e,
                        &secrets,
                        &profiles,
                    );
                }
                Err(e) => {
                    j.state = "Failed — no automatic compensation".into();
                    record(
                        &mut j,
                        s,
                        crate::incident::Kind::Failure,
                        &e,
                        &secrets,
                        &profiles,
                    );
                    break;
                }
            }
        }
        if j.state == "Running" || j.state == "Awaiting evidence" {
            j.state = "Completed".into();
        }
        if stop.load(Ordering::Relaxed) && j.state == "Completed" {
            j.state = "Cancelled — verify in-flight effects".into();
        }
        j.at = chrono::Utc::now();
        if let Err(e) = save(&j) {
            j.state = format!("Outcome recorded in memory only; journal persistence failed: {e}");
        }
        let _ = tx.send(Event::Journal(j));
        let _ = tx.send(Event::Done);
    });
    Ok(Running {
        events,
        evidence,
        cancel,
    })
}
pub fn example() -> Plan {
    Plan {
        name: "Local application smoke test".into(),
        preconditions: vec![],
        steps: vec![Step {
            name: "Open health endpoint".into(),
            action: Action::Http {
                url: "http://127.0.0.1:8080/health".into(),
                method: HttpMethod::Get,
                form: BTreeMap::new(),
                secret_fields: BTreeMap::new(),
                status: 200,
                body_contains: None,
                json_equals: BTreeMap::new(),
            },
        }],
        verification: vec![Step {
            name: "Verify application state".into(),
            action: Action::Http {
                url: "http://127.0.0.1:8080/health".into(),
                method: HttpMethod::Get,
                form: BTreeMap::new(),
                secret_fields: BTreeMap::new(),
                status: 200,
                body_contains: None,
                json_equals: BTreeMap::from([("/status".into(), serde_json::json!("ok"))]),
            },
        }],
        restore: vec![],
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn winrm_cannot_declare_an_ignored_port_or_identity() {
        let mut action = Action::WinRm {
            target: Target {
                host: "fixture.invalid".into(),
                user: String::new(),
                port: 5985,
            },
            operation: WinOperation::Inventory,
            stdout_contains: "fixture".into(),
        };
        assert!(command(&action).unwrap().is_some());
        if let Action::WinRm { target, .. } = &mut action {
            target.port = 1234;
        }
        assert!(command(&action).is_err());
        if let Action::WinRm { target, .. } = &mut action {
            target.port = 5985;
            target.user = "other identity".into();
        }
        assert!(command(&action).is_err());
    }
    #[test]
    fn incident_binding_requires_unique_local_transport_identity() {
        let mut profile = crate::models::ConnectionProfile::sample("fixture", "host", "", false);
        profile.protocol = crate::models::Protocol::Ssh;
        profile.port = 22;
        profile.username = "operator".into();
        let t = crate::mission::Target::from_profile(&profile);
        let action = Action::Ssh {
            target: Target {
                host: "host".into(),
                user: "operator".into(),
                port: 22,
            },
            command: "uname".into(),
            stdout_contains: "Linux".into(),
        };
        assert_eq!(
            trusted_binding(&action, &[t.clone()]).unwrap().profile_id,
            profile.id
        );
        assert!(trusted_binding(&action, &[t.clone(), t.clone()]).is_none());
        let mut changed = t.clone();
        changed.username = "other".into();
        assert!(trusted_binding(&action, &[changed]).is_none());
        let mut routed = t.clone();
        routed.route = "gateway".into();
        assert!(trusted_binding(&action, &[routed]).is_none());
        let win = Action::WinRm {
            target: Target {
                host: "host".into(),
                user: "operator".into(),
                port: 22,
            },
            operation: WinOperation::Services,
            stdout_contains: "Running".into(),
        };
        assert!(trusted_binding(&win, &[t]).is_none());
    }
    fn serve(response: &str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = response.to_owned();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut b = [0; 4096];
            let _ = stream.read(&mut b);
            std::io::Write::write_all(&mut stream, response.as_bytes()).unwrap();
        });
        format!("http://{address}/")
    }
    #[test]
    fn package_tamper_and_unknown_schema_rejected() {
        let p = Package::new(example(), "local test".into()).unwrap();
        let text = p.export().unwrap();
        assert!(Package::import(&text).is_ok());
        assert!(Package::import(&text.replace("Local application smoke test", "changed")).is_err());
        assert!(Package::import(&text.replace("\"schema\": 1", "\"schema\": 2")).is_err());
        assert!(Package::import(&text.replacen('{', "{\"extra\":true,", 1)).is_err());
        assert!(Package::import(&text.replace("1.0.0", "1.0.1")).is_err());
        for invalid in ["1.0", "01.0.0", "1.0.0-beta", "1.-1.0", ""] {
            assert!(Package::new_version(example(), "local".into(), invalid.into()).is_err());
        }
        let newer = Package::new_version(example(), "local".into(), "2.3.4".into()).unwrap();
        assert_eq!(
            Package::import(&newer.export().unwrap())
                .unwrap()
                .recipe_version,
            "2.3.4"
        );
    }
    #[test]
    fn review_binds_targets_and_restore() {
        let mut p = example();
        let d = review_digest(&p).unwrap();
        p.restore = p.steps.clone();
        assert_ne!(d, review_digest(&p).unwrap());
    }
    #[test]
    fn actual_http_status_and_json_failure() {
        let mut a = example().verification.remove(0).action;
        if let Action::Http { url, .. } = &mut a {
            *url =
                serve("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        assert!(
            HttpSession::default()
                .execute(&a, &BTreeMap::new())
                .unwrap_err()
                .contains("503")
        );
        if let Action::Http { url, .. } = &mut a {
            *url = serve(
                "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"status\":\"bad\"}",
            );
        }
        assert!(
            HttpSession::default()
                .execute(&a, &BTreeMap::new())
                .unwrap_err()
                .contains("JSON assertion")
        );
    }
    #[test]
    fn actual_http_body_pass_and_redirect_rejection() {
        let mut a = example().steps.remove(0).action;
        if let Action::Http {
            url, body_contains, ..
        } = &mut a
        {
            *url = serve("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            *body_contains = Some("ok".into());
        }
        assert!(HttpSession::default().execute(&a, &BTreeMap::new()).is_ok());
        if let Action::Http { url, .. } = &mut a {
            *url = serve(
                "HTTP/1.1 302 Found\r\nLocation: http://example.invalid\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
        assert!(
            HttpSession::default()
                .execute(&a, &BTreeMap::new())
                .is_err()
        );
    }
    #[test]
    fn real_login_cookie_and_application_request() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for n in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0; 1024];
                loop {
                    let count = stream.read(&mut buf).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buf[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                let response = if n == 0 {
                    assert!(request.starts_with("POST /login "));
                    assert!(request.contains("password=ephemeral"));
                    "HTTP/1.1 200 OK\r\nSet-Cookie: sid=local-session; Path=/; HttpOnly\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                } else {
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains("cookie: sid=local-session")
                    );
                    "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}"
                };
                std::io::Write::write_all(&mut stream, response.as_bytes()).unwrap();
            }
        });
        let mut session = HttpSession::default();
        let mut login = example().steps.remove(0).action;
        if let Action::Http {
            url,
            method,
            secret_fields,
            ..
        } = &mut login
        {
            *url = format!("http://{addr}/login");
            *method = HttpMethod::Post;
            secret_fields.insert("password".into(), "password_slot".into());
        }
        session
            .execute(
                &login,
                &BTreeMap::from([("password_slot".into(), "ephemeral".into())]),
            )
            .unwrap();
        let mut verify = example().verification.remove(0).action;
        if let Action::Http { url, .. } = &mut verify {
            *url = format!("http://{addr}/test");
        }
        session.execute(&verify, &BTreeMap::new()).unwrap();
        server.join().unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn runner_persists_failure_and_never_launches_following_step() {
        let untouched = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        untouched.set_nonblocking(true).unwrap();
        let mut p = example();
        if let Action::Http { url, .. } = &mut p.steps[0].action {
            *url = serve("HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        if let Action::Http { url, .. } = &mut p.verification[0].action {
            *url = format!("http://{}/", untouched.local_addr().unwrap());
        }
        let d = review_digest(&p).unwrap();
        let run = start(p, &d, BTreeMap::new()).unwrap();
        let mut final_j = None;
        loop {
            match run.events.recv_timeout(Duration::from_secs(10)).unwrap() {
                Event::Journal(j) => final_j = Some(j),
                Event::Done => break,
                Event::Checkpoint { .. } | Event::Procedure { .. } => {
                    panic!("unexpected checkpoint")
                }
            }
        }
        let j = final_j.unwrap();
        assert!(j.state.starts_with("Failed"));
        assert_eq!(j.completed, 0);
        assert_eq!(j.records.len(), 2);
        assert!(untouched.accept().is_err());
        assert_eq!(load_journal().unwrap().unwrap().run_id, j.run_id);
        assert!(
            load_history()
                .unwrap()
                .iter()
                .any(|old| old.run_id == j.run_id)
        );
        let mut success = example();
        if let Action::Http { url, .. } = &mut success.steps[0].action {
            *url = serve("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
        if let Action::Http { url, .. } = &mut success.verification[0].action {
            *url = serve(
                "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}",
            );
        }
        let approved = review_digest(&success).unwrap();
        let run = start(success, &approved, BTreeMap::new()).unwrap();
        let mut completed = None;
        loop {
            match run.events.recv_timeout(Duration::from_secs(10)).unwrap() {
                Event::Journal(j) => completed = Some(j),
                Event::Done => break,
                _ => panic!("unexpected checkpoint"),
            }
        }
        let mut completed = completed.unwrap();
        assert_eq!(completed.state, "Completed");
        assert_eq!(completed.completed, 2);
        assert_eq!(completed.records.len(), 4);
        assert!(completed.records.windows(2).all(|r| r[0].at <= r[1].at));
        let history = load_history().unwrap();
        assert!(history.iter().any(|old| old.run_id == j.run_id));
        assert!(history.iter().any(|old| old.run_id == completed.run_id));
        completed.state = "Running".into();
        save(&completed).unwrap();
        assert!(
            load_journal()
                .unwrap()
                .unwrap()
                .state
                .starts_with("Interrupted")
        );
        completed.state = "Completed".into();
        save(&completed).unwrap();
        let checkpoint = Step {
            name: "Same visible checkpoint".into(),
            action: Action::RdpCheckpoint {
                target: "test-host".into(),
                expected: "Ready".into(),
            },
        };
        let p = Plan {
            name: "Checkpoint token test".into(),
            preconditions: vec![],
            steps: vec![checkpoint.clone()],
            verification: vec![checkpoint],
            restore: vec![],
        };
        let d = review_digest(&p).unwrap();
        let run = start(p, &d, BTreeMap::new()).unwrap();
        let receive_checkpoint = || loop {
            match run.events.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Checkpoint { token, .. } => break token,
                Event::Journal(_) => {}
                Event::Done | Event::Procedure { .. } => panic!("finished before checkpoint"),
            }
        };
        let first = receive_checkpoint();
        run.evidence
            .send((first.clone(), "Operator attestation: observed Ready".into()))
            .unwrap();
        let second = receive_checkpoint();
        assert_ne!(first, second);
        run.evidence
            .send((
                first,
                "stale result from preceding identical checkpoint".into(),
            ))
            .unwrap();
        assert!(matches!(
            run.events.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        run.evidence
            .send((second, "fresh observed result".into()))
            .unwrap();
        loop {
            match run.events.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Journal(j) => assert_eq!(j.state, "Completed"),
                Event::Done => break,
                _ => panic!("unexpected checkpoint"),
            }
        }
    }
}
