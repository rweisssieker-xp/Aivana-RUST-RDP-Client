use super::*;
use crate::mission::{self, Evidence, Mission, MissionBook, Status, Step, StepKind, Target};
use std::{
    collections::BTreeMap,
    sync::mpsc,
    time::{Duration, Instant},
};

pub(super) struct MissionState {
    pub book: MissionBook,
    pub selected: Option<Uuid>,
    objective: String,
    targets: Vec<Uuid>,
    steps: Vec<Step>,
    query: String,
    note: String,
    path: String,
    error: Option<String>,
    tab: usize,
    comparison: [Option<Uuid>; 2],
    pending: Option<Pending>,
    remote: Option<(Uuid, Uuid, usize, u64)>,
}
struct Pending {
    mission: Uuid,
    target: Uuid,
    step: usize,
    rx: mpsc::Receiver<(bool, String)>,
    started: Instant,
    evidence: Evidence,
}
impl Default for MissionState {
    fn default() -> Self {
        let loaded = app_data_file("missions.dpapi").and_then(|p| MissionBook::load(&p));
        let (book, error) = match loaded {
            Ok(b) => (b, None),
            Err(e) => (
                MissionBook::default(),
                Some(format!(
                    "Cannot read job storage: {e:#}. File remains unchanged."
                )),
            ),
        };
        let selected = book.missions.first().map(|m| m.id);
        Self {
            book,
            selected,
            objective: String::new(),
            targets: vec![],
            steps: vec![Step::default()],
            query: String::new(),
            note: String::new(),
            path: String::new(),
            error,
            tab: 0,
            comparison: [None, None],
            pending: None,
            remote: None,
        }
    }
}
impl AivanaApp {
    pub(super) fn save_missions(&mut self) -> bool {
        if self.missions.error.is_some() {
            return false;
        }
        if let Err(e) = app_data_file("missions.dpapi").and_then(|p| self.missions.book.save(&p)) {
            self.status = format!("Could not save job: {e:#}");
            false
        } else {
            true
        }
    }
    pub(super) fn poll_missions(&mut self) {
        if let Some((id, target, step, job_id)) = self.missions.remote {
            let done = self
                .operations
                .queue
                .jobs
                .iter()
                .find(|j| j.id == job_id)
                .and_then(|j| {
                    j.result
                        .as_ref()
                        .cloned()
                        .or_else(|| {
                            j.status.terminal().then(|| crate::operations::JobResult {
                                status: j.status.clone(),
                                stdout: String::new(),
                                stderr: "Job ended without output; check remote state"
                                    .into(),
                                truncated: false,
                                finished: std::time::SystemTime::now(),
                            })
                        })
                        .map(|r| (j.spec.source.clone(), r))
                });
            if let Some((source, r)) = done {
                self.missions.remote = None;
                if let Some(m) = self.missions.book.missions.iter_mut().find(|m| m.id == id) {
                    if let Some(t) = m.targets.iter().find(|t| t.profile_id == target).cloned() {
                        let mut facts = mission::structured_facts(&r.stdout);
                        facts.insert("Job · process status".into(), format!("{:?}", r.status));
                        facts.insert("Job · output limited".into(), r.truncated.to_string());
                        let notes = format!(
                            "Standard output:\n{}\nStandard error:\n{}",
                            r.stdout, r.stderr
                        );
                        let e =
                            Evidence::new(t, &format!("Remote tool · {source}"), facts, &notes);
                        if let Err(e) = m.record(target, step, e) {
                            self.status = e.to_string();
                        }
                    }
                }
                self.save_missions();
            } else if !self.operations.queue.jobs.iter().any(|j| j.id == job_id) {
                self.missions.remote = None;
                if let Some(m) = self.missions.book.missions.iter_mut().find(|m| m.id == id) {
                    m.pause();
                }
                self.status =
                    "Tool job no longer exists. Mission paused.".into();
                self.save_missions();
            }
        }
        let result = self
            .missions
            .pending
            .as_ref()
            .and_then(|p| match p.rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => Some((false, "Check worker stopped".into())),
                Err(mpsc::TryRecvError::Empty) if p.started.elapsed() > Duration::from_secs(12) => {
                    Some((
                        false,
                        "Timed out after 12 seconds; DNS/TCP result unavailable".into(),
                    ))
                }
                _ => None,
            });
        if let Some((ok, message)) = result {
            let mut p = self.missions.pending.take().unwrap();
            p.evidence
                .facts
                .insert("TCP reachable".into(), ok.to_string());
            p.evidence
                .notes
                .push_str(&format!("\nTCP check: {message}"));
            if let Some(m) = self
                .missions
                .book
                .missions
                .iter_mut()
                .find(|m| m.id == p.mission)
            {
                if let Err(e) = m.record(p.target, p.step, p.evidence) {
                    self.status = e.to_string();
                }
            }
            self.save_missions();
        }
    }
    fn mission_evidence(&self, t: Target) -> Evidence {
        let mut facts = BTreeMap::new();
        if let Some(p) = self.profiles.iter().find(|p| t.matches(p)) {
            facts.insert("Profile · group".into(), p.group.clone());
            facts.insert("Profile · protocol".into(), p.protocol.label().into());
            facts.insert(
                "Profile · gateway".into(),
                if p.options.gateway.enabled {
                    p.options.gateway.host.clone()
                } else {
                    "Direct".into()
                },
            );
            facts.insert(
                "Profile · resolution".into(),
                format!("{} × {}", p.options.width, p.options.height),
            );
        }
        let mut notes = String::new();
        if let Some(s) = self.sessions.iter().rev().find(|s| {
            self.session_sources
                .get(&s.id)
                .is_some_and(|source| source.same_endpoint(&t))
        }) {
            facts.insert("Session · status".into(), format!("{:?}", s.status));
            if let Some(e) = &s.last_error {
                facts.insert("Session · last error".into(), e.clone());
            }
            if let Some(f) = self.latest_frames.get(&s.id) {
                facts.insert("Image · size".into(), format!("{} × {}", f.width, f.height));
                facts.insert("Image · hash".into(), f.frame_hash.to_string());
            }
            for e in self
                .timeline
                .events_for_session(s.id)
                .iter()
                .rev()
                .take(40)
                .rev()
            {
                notes.push_str(&format!("{} {}\n", e.created_at, e.message));
            }
        } else {
            facts.insert(
                "Session · status".into(),
                "No session context with a matching endpoint identity".into(),
            );
        }
        Evidence::new(t, "Profile and local session history", facts, &notes)
    }
    fn start_mission_step(&mut self, id: Uuid, target: Uuid, step: usize) {
        if self.missions.pending.is_some() || self.missions.remote.is_some() {
            self.status = "A mission step is already running".into();
            return;
        }
        let Some(m) = self.missions.book.missions.iter().find(|m| m.id == id) else {
            return;
        };
        let Some(t) = m.targets.iter().find(|t| t.profile_id == target).cloned() else {
            return;
        };
        let Some(p) = self.profiles.iter().find(|p| t.matches(p)) else {
            self.status =
                "Profile missing or endpoint changed. Create a new job.".into();
            return;
        };
        let endpoint = if p.options.gateway.enabled {
            (p.options.gateway.host.clone(), p.options.gateway.port)
        } else {
            (p.host.clone(), p.port)
        };
        let kind = m.steps[step].kind;
        if kind == StepKind::SshCommand && p.protocol != Protocol::Ssh {
            self.status="SSH steps require an SSH profile with a verified user and port (can be imported through Inventory).".into();
            return;
        }
        if !matches!(kind, StepKind::Observe | StepKind::Operator) {
            use crate::operations::{Endpoint, Query, Request};
            let request = match kind {
                StepKind::WinRmInventory => Request::WinRm(Query::Inventory),
                StepKind::WinRmServices => Request::WinRm(Query::Services),
                StepKind::WinRmProcesses => Request::WinRm(Query::Processes),
                StepKind::WinRmEvents => Request::WinRm(Query::Events),
                _ => Request::Ssh {
                    command: m.steps[step].command.clone(),
                },
            };
            let endpoint = Endpoint::new(
                &p.host,
                if kind == StepKind::SshCommand {
                    &p.username
                } else {
                    ""
                },
                if p.protocol == Protocol::Ssh {
                    p.port
                } else {
                    22
                },
            );
            let spec = match endpoint.and_then(|e| request.build(&e)) {
                Ok(s) => s,
                Err(e) => {
                    self.status = e;
                    return;
                }
            };
            let m = self
                .missions
                .book
                .missions
                .iter_mut()
                .find(|m| m.id == id)
                .unwrap();
            if let Err(e) = m.begin(target, step) {
                self.status = e.to_string();
                return;
            }
            if !self.save_missions() {
                self.missions
                    .book
                    .missions
                    .iter_mut()
                    .find(|m| m.id == id)
                    .unwrap()
                    .pause();
                return;
            }
            match self.operations.queue.enqueue(spec) {
                Ok(job) => self.missions.remote = Some((id, target, step, job)),
                Err(e) => {
                    self.missions
                        .book
                        .missions
                        .iter_mut()
                        .find(|m| m.id == id)
                        .unwrap()
                        .pause();
                    self.status = e;
                }
            }
            self.save_missions();
            return;
        }
        let mut evidence = self.mission_evidence(t);
        let m = self
            .missions
            .book
            .missions
            .iter_mut()
            .find(|m| m.id == id)
            .unwrap();
        if let Err(e) = m.begin(target, step) {
            self.status = e.to_string();
            return;
        }
        if kind == StepKind::Operator {
            evidence.source = "Manual execution · context captured".into();
            evidence.notes.push_str("\nThe operator performs the action in the remote desktop or under Tools. This capture does not make changes.");
            if let Err(e) = m.record(target, step, evidence) {
                self.status = e.to_string();
            }
        } else {
            evidence.facts.insert(
                "TCP · verified target".into(),
                format!("{}:{}", endpoint.0, endpoint.1),
            );
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                use std::net::{TcpStream, ToSocketAddrs};
                let result=(endpoint.0.as_str(),endpoint.1).to_socket_addrs().map_err(|e|e.to_string()).and_then(|addresses|{
                    let mut last="No address found".to_owned();
                    for a in addresses.take(3){match TcpStream::connect_timeout(&a,Duration::from_secs(2)){Ok(_)=>return Ok("TCP connection established; this does not verify sign-in or service functionality".into()),Err(e)=>last=e.to_string()}}
                    Err(last)
                });
                let _ = tx.send(match result {
                    Ok(s) => (true, s),
                    Err(e) => (false, e),
                });
            });
            self.missions.pending = Some(Pending {
                mission: id,
                target,
                step,
                rx,
                started: Instant::now(),
                evidence,
            });
        }
        self.save_missions();
    }
    pub(super) fn missions_view(&mut self, ui: &mut Ui) {
        ui.heading("Mission Control");
        ui.label("Plan a job · verify on the first computer · continue with approval");
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            for (number, label) in [
                (self.profiles.len(), "Computers in inventory"),
                (
                    self.missions
                        .book
                        .missions
                        .iter()
                        .filter(|m| !m.completed())
                        .count(),
                    "Open jobs",
                ),
                (
                    self.missions
                        .book
                        .missions
                        .iter()
                        .map(|m| m.evidence.len())
                        .sum(),
                    "Captured findings",
                ),
            ] {
                ui.group(|ui| {
                    ui.label(
                        RichText::new(number.to_string())
                            .size(28.0)
                            .strong()
                            .color(Color32::from_rgb(0, 108, 123)),
                    );
                    ui.small(label);
                });
            }
        });
        ui.add_space(12.0);
        if let Some(error) = &self.missions.error {
            ui.colored_label(tw::RED_600, error);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (i, label) in [
                "Jobs",
                "New job",
                "Search findings",
                "Compare computers & times",
                "Proven workflows",
            ]
            .iter()
            .enumerate()
            {
                ui.selectable_value(&mut self.missions.tab, i, *label);
            }
        });
        ui.separator();
        match self.missions.tab {
            1 => self.mission_create_ui(ui),
            2 => self.mission_search_ui(ui),
            3 => self.mission_compare_ui(ui),
            4 => self.mission_procedures_ui(ui),
            _ => self.mission_detail_ui(ui),
        }
    }
    fn mission_create_ui(&mut self, ui: &mut Ui) {
        ui.label("Desired outcome");
        ui.add(
            egui::TextEdit::multiline(&mut self.missions.objective)
                .desired_rows(2)
                .desired_width(f32::INFINITY)
                .hint_text("For example: narrow down the cause of dropped connections"),
        );
        ui.label("Select computers – the first selected computer is the trial run");
        for p in &self.profiles {
            let mut selected = self.missions.targets.contains(&p.id);
            if ui
                .checkbox(
                    &mut selected,
                    format!(
                        "{} · {}{}",
                        p.name,
                        p.host,
                        if self.missions.targets.first() == Some(&p.id) {
                            " · TRIAL RUN"
                        } else {
                            ""
                        }
                    ),
                )
                .changed()
            {
                if selected {
                    self.missions.targets.push(p.id)
                } else {
                    self.missions.targets.retain(|id| *id != p.id)
                }
            }
        }
        ui.separator();
        ui.label("Workflow and change preview");
        let mut remove = None;
        for (i, s) in self.missions.steps.iter_mut().enumerate() {
            ui.push_id(i, |ui| {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("Step {}", i + 1));
                        ui.text_edit_singleline(&mut s.title);
                        if ui.small_button("Remove").clicked() {
                            remove = Some(i);
                        }
                    });
                    egui::ComboBox::from_id_salt("step-kind")
                        .selected_text(step_kind_label(s.kind))
                        .show_ui(ui, |ui| {
                            for kind in [
                                StepKind::Observe,
                                StepKind::Operator,
                                StepKind::WinRmInventory,
                                StepKind::WinRmServices,
                                StepKind::WinRmProcesses,
                                StepKind::WinRmEvents,
                                StepKind::SshCommand,
                            ] {
                                ui.selectable_value(&mut s.kind, kind, step_kind_label(kind));
                            }
                        });
                    if s.kind == StepKind::SshCommand {
                        ui.label("SSH command – runs on the selected computer:");
                        ui.add(
                            egui::TextEdit::multiline(&mut s.command)
                                .code_editor()
                                .desired_width(f32::INFINITY),
                        );
                    }
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Success criterion:");
                        ui.text_edit_singleline(&mut s.expectation);
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Rollback if problems occur:");
                        ui.text_edit_singleline(&mut s.recovery);
                    });
                });
            });
        }
        if let Some(i) = remove {
            self.missions.steps.remove(i);
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("Add step").clicked() {
                self.missions.steps.push(Step {
                    title: "Manual task".into(),
                    kind: StepKind::Operator,
                    expectation: String::new(),
                    recovery: String::new(),
                    command: String::new(),
                });
            }
            if ui.button("Create job").clicked() {
                let targets = self
                    .missions
                    .targets
                    .iter()
                    .filter_map(|id| {
                        self.profiles
                            .iter()
                            .find(|p| p.id == *id)
                            .map(Target::from_profile)
                    })
                    .collect();
                match Mission::new(
                    &self.missions.objective,
                    targets,
                    self.missions.steps.clone(),
                ) {
                    Ok(m) => {
                        self.missions.selected = Some(m.id);
                        self.missions.book.missions.push(m);
                        self.missions.tab = 0;
                        if self.save_missions() {
                            self.status =
                                "Job created. No connection has started yet."
                                    .into();
                        }
                    }
                    Err(e) => self.status = e.to_string(),
                }
            }
        });
        ui.label("Evidence capture checks TCP and local session context. WinRM uses the current Windows identity; SSH requires known host keys and a key/agent. SSH commands may make changes. Each step starts only when clicked. Rollbacks are instructions, not system snapshots.");
    }
    fn mission_detail_ui(&mut self, ui: &mut Ui) {
        if self.missions.book.missions.is_empty() {
            ui.add_space(14.0);
            ui.heading("What would you like to investigate?");
            ui.label("Start with a workflow. Then select the affected computers and adjust the verification criteria.");
            ui.add_space(10.0);
            for (title, description, kind) in [
                (
                    "Narrow down a connection problem",
                    "Collect TCP reachability and existing session events.",
                    StepKind::Observe,
                ),
                (
                    "Compare services across computers",
                    "Capture service states using WinRM and review differences.",
                    StepKind::WinRmServices,
                ),
                (
                    "Inspect system state",
                    "Query operating system and memory using WinRM.",
                    StepKind::WinRmInventory,
                ),
            ] {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(RichText::new(title).strong()).clicked() {
                            self.missions.objective = title.into();
                            self.missions.steps = vec![Step {
                                title: title.into(),
                                kind,
                                expectation: "Review findings and document the conclusion"
                                    .into(),
                                recovery: "Read-only query; no change planned".into(),
                                command: String::new(),
                            }];
                            self.missions.targets.clear();
                            self.missions.tab = 1;
                        }
                        ui.label(description);
                    });
                });
            }
            ui.add_space(18.0);
            ui.small("Your findings and jobs stay local and are stored encrypted on Windows. No connection starts automatically.");
        }
        let choices: Vec<_> = self
            .missions
            .book
            .missions
            .iter()
            .map(|m| (m.id, m.objective.clone(), m.completed()))
            .collect();
        egui::ComboBox::from_id_salt("mission-select")
            .selected_text(
                choices
                    .iter()
                    .find(|c| Some(c.0) == self.missions.selected)
                    .map(|c| c.1.as_str())
                    .unwrap_or("Select job"),
            )
            .show_ui(ui, |ui| {
                for (id, name, done) in choices {
                    ui.selectable_value(
                        &mut self.missions.selected,
                        Some(id),
                        format!("{}{name}", if done { "✓ " } else { "" }),
                    );
                }
            });
        let Some(id) = self.missions.selected else {
            self.mission_exchange_ui(ui);
            return;
        };
        let Some(m) = self
            .missions
            .book
            .missions
            .iter()
            .find(|m| m.id == id)
            .cloned()
        else {
            return;
        };
        let confirmed = m
            .outcomes
            .iter()
            .filter(|o| o.status == Status::Passed)
            .count();
        ui.add(
            egui::ProgressBar::new(confirmed as f32 / m.outcomes.len().max(1) as f32).text(
                format!("{confirmed} / {} steps confirmed", m.outcomes.len()),
            ),
        );
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    m.paused,
                    egui::Button::new("Map identical local profiles"),
                )
                .clicked()
            {
                let result = self
                    .missions
                    .book
                    .missions
                    .iter_mut()
                    .find(|m| m.id == id)
                    .unwrap()
                    .map_local_profiles(&self.profiles);
                match result {
                    Ok(()) => {
                        if self.save_missions() {
                            self.status =
                                "Local profiles mapped. Endpoints and identities unchanged."
                                    .into();
                        }
                    }
                    Err(e) => self.status = e.to_string(),
                }
            }
            if ui
                .button(if m.paused {
                    "Resume"
                } else {
                    "Pause / cancel capture"
                })
                .clicked()
            {
                let current = self
                    .missions
                    .book
                    .missions
                    .iter_mut()
                    .find(|m| m.id == id)
                    .unwrap();
                if current.paused {
                    current.paused = false;
                } else {
                    current.pause();
                    if self
                        .missions
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.mission == id)
                    {
                        self.missions.pending = None;
                    }
                    if let Some((mid, _, _, job)) = self.missions.remote {
                        if mid == id {
                            if let Some(j) = self.operations.queue.jobs.iter().find(|j| j.id == job)
                            {
                                j.cancel();
                            }
                            self.missions.remote = None;
                        }
                    }
                }
                self.save_missions();
            }
            if ui
                .add_enabled(
                    !m.rollout && m.pilot_passed() && !m.paused,
                    egui::Button::new("Approve additional computers"),
                )
                .clicked()
            {
                let result = self
                    .missions
                    .book
                    .missions
                    .iter_mut()
                    .find(|m| m.id == id)
                    .unwrap()
                    .allow_rollout();
                if let Err(e) = result {
                    self.status = e.to_string();
                }
                self.save_missions();
            }
            if ui
                .add_enabled(
                    m.completed(),
                    egui::Button::new("Save as a proven workflow"),
                )
                .clicked()
            {
                if let Err(e) = self.missions.book.learn(id) {
                    self.status = e.to_string();
                }
                self.save_missions();
            }
        });
        ui.label("Verification note for the next step to confirm:");
        ui.add(
            egui::TextEdit::multiline(&mut self.missions.note)
                .desired_rows(2)
                .desired_width(f32::INFINITY),
        );
        for t in &m.targets {
            ui.push_id(t.profile_id,|ui|{ui.group(|ui|{
            ui.strong(format!("{} · {}:{}{}",t.name,t.host,t.port,if t.profile_id==m.pilot{" · Trial run"}else{""}));
            for o in m.outcomes.iter().filter(|o|o.target==t.profile_id){ui.push_id(o.step,|ui|{
                let s=&m.steps[o.step];ui.label(format!("{}. {} · {}",o.step+1,s.title,o.status.label()));
                ui.small(format!("Verify: {} | Rollback: {}",s.expectation,s.recovery));
                ui.small(step_kind_label(s.kind));if s.kind==StepKind::SshCommand{ui.monospace(&s.command);ui.colored_label(tw::RED_600,"Run starts this command on this computer. Canceling cannot undo changes already made.");}
                ui.horizontal_wrapped(|ui|{
                    let allowed=!m.paused&&self.missions.pending.is_none()&&self.missions.remote.is_none()&&(t.profile_id==m.pilot||m.rollout)&&(o.step==0||m.outcomes.iter().filter(|prev|prev.target==t.profile_id&&prev.step<o.step).all(|prev|prev.status==Status::Passed));
                    if ui.add_enabled(allowed&&matches!(o.status,Status::Pending|Status::Failed|Status::Interrupted),egui::Button::new(if s.kind==StepKind::Observe{"Capture finding"}else if s.kind==StepKind::Operator{"Begin execution"}else{"Run on this computer"})).clicked(){self.start_mission_step(id,t.profile_id,o.step);}
                    for (passed,label)in [(true,"Confirm success"),(false,"Not met")]{if ui.add_enabled(!m.paused&&o.status==Status::Review&&!self.missions.note.trim().is_empty(),egui::Button::new(label)).clicked(){let note=self.missions.note.clone();let result=self.missions.book.missions.iter_mut().find(|m|m.id==id).unwrap().verify(t.profile_id,o.step,passed,&note);match result{Ok(())=>self.missions.note.clear(),Err(e)=>self.status=e.to_string()};self.save_missions();}}
                    if ui.button("Open computer").clicked(){if self.profiles.iter().any(|p|t.matches(p)){self.selected_profile=Some(t.profile_id);self.connect_selected();}else{self.status="Endpoint changed; no connection started.".into();}}
                });
                if !o.verification.is_empty(){ui.label(&o.verification);}
                for e in m.evidence.iter().filter(|e|o.evidence.contains(&e.id)){ui.collapsing(format!("Finding {} · {}",e.at.format("%m/%d %H:%M:%S"),e.source),|ui|{for(k,v)in &e.facts{ui.label(format!("{k}: {v}"));}ui.label(&e.notes);});}
            });}
        });});
        }
        ui.separator();
        ui.label("Handoff note / next step");
        let current = self
            .missions
            .book
            .missions
            .iter_mut()
            .find(|m| m.id == id)
            .unwrap();
        if ui
            .add(
                egui::TextEdit::multiline(&mut current.handoff)
                    .desired_width(f32::INFINITY)
                    .desired_rows(2),
            )
            .lost_focus()
        {
            self.save_missions();
        }
        self.mission_exchange_ui(ui);
    }
    fn mission_exchange_ui(&mut self, ui: &mut Ui) {
        ui.collapsing("Import / export handoff",|ui|{
            ui.label("Export includes computer names and findings in a readable file. Review before sharing. Existing files are not overwritten.");
            ui.add(egui::TextEdit::singleline(&mut self.missions.path).hint_text("Absolute file path (.json or .md)").desired_width(f32::INFINITY));
            ui.horizontal_wrapped(|ui|{
                if ui.button("Import JSON").clicked(){let result=(||{let p=Path::new(&self.missions.path);if std::fs::metadata(p)?.len()>16*1024*1024{anyhow::bail!("File larger than 16 MiB");}let json=std::fs::read_to_string(p)?;self.missions.book.import(&json)})();match result{Ok(id)=>{self.missions.selected=Some(id);if self.save_missions(){self.status="Handoff imported; job paused. Review targets before resuming.".into();}},Err(e)=>self.status=format!("Import: {e:#}")}}
                for(markdown,label)in [(false,"Export JSON"),(true,"Export report")]{if ui.button(label).clicked(){if let Some(m)=self.missions.book.missions.iter().find(|m|Some(m.id)==self.missions.selected){let text=if markdown{Ok(m.markdown())}else{serde_json::to_string_pretty(m)};self.status=match text.map_err(anyhow::Error::from).and_then(|s|mission::export_new(Path::new(&self.missions.path),s.as_bytes())){Ok(p)=>format!("Saved: {}",p.display()),Err(e)=>format!("Export: {e:#}")};}}}
            });
        });
    }
    fn mission_search_ui(&mut self, ui: &mut Ui) {
        ui.add(
            egui::TextEdit::singleline(&mut self.missions.query)
                .hint_text("Search error message, computer, or finding …")
                .desired_width(f32::INFINITY),
        );
        ui.small("Searches captured findings and session events in local job storage. No comprehensive screen OCR.");
        for (m, e) in self.missions.book.search(&self.missions.query) {
            ui.group(|ui| {
                ui.strong(format!("{} · {}", e.target.name, m.objective));
                ui.small(format!("{} · {}", e.at, e.source));
                ui.label(&e.notes);
                for (k, v) in &e.facts {
                    ui.label(format!("{k}: {v}"));
                }
            });
        }
    }
    fn mission_compare_ui(&mut self, ui: &mut Ui) {
        ui.label("Select two findings from the same computer or different computers. Existing measurement and profile fields are compared.");
        let all: Vec<_> = self
            .missions
            .book
            .missions
            .iter()
            .flat_map(|m| m.evidence.iter())
            .collect();
        for i in 0..2 {
            egui::ComboBox::from_id_salt(("compare", i))
                .selected_text(
                    all.iter()
                        .find(|e| Some(e.id) == self.missions.comparison[i])
                        .map(|e| format!("{} · {}", e.target.name, e.at))
                        .unwrap_or_else(|| format!("Select finding {}", i + 1)),
                )
                .show_ui(ui, |ui| {
                    for e in &all {
                        ui.selectable_value(
                            &mut self.missions.comparison[i],
                            Some(e.id),
                            format!("{} · {} · {}", e.target.name, e.at, e.source),
                        );
                    }
                });
        }
        if let (Some(a), Some(b)) = (
            all.iter()
                .find(|e| Some(e.id) == self.missions.comparison[0]),
            all.iter()
                .find(|e| Some(e.id) == self.missions.comparison[1]),
        ) {
            let changes = mission::diff(a, b);
            ui.strong(format!("{} differences", changes.len()));
            egui::Grid::new("evidence-diff")
                .striped(true)
                .num_columns(3)
                .show(ui, |ui| {
                    ui.strong("Field");
                    ui.strong("Before / A");
                    ui.strong("After / B");
                    ui.end_row();
                    for c in changes {
                        ui.label(c.key);
                        ui.label(c.before.as_deref().unwrap_or("Not captured"));
                        ui.label(c.after.as_deref().unwrap_or("Not captured"));
                        ui.end_row();
                    }
                });
            if a.source != b.source {
                ui.colored_label(tw::RED_600,"Different sources: missing fields are not verified server changes.");
            }
        }
    }
    fn mission_procedures_ui(&mut self, ui: &mut Ui) {
        ui.label("Steps adopted from fully confirmed jobs. New executions start with another trial run.");
        for p in self.missions.book.procedures.clone() {
            ui.group(|ui| {
                ui.strong(&p.name);
                for s in &p.steps {
                    ui.label(format!("{} → {}", s.title, s.expectation));
                }
                if ui.button("Use for new computers").clicked() {
                    self.missions.objective = p.name;
                    self.missions.steps = p.steps;
                    self.missions.targets.clear();
                    self.missions.tab = 1;
                }
            });
        }
    }
}
fn step_kind_label(kind: StepKind) -> &'static str {
    match kind {
        StepKind::Observe => "Capture findings + TCP",
        StepKind::Operator => "Manual execution",
        StepKind::WinRmInventory => "WinRM · system inventory",
        StepKind::WinRmServices => "WinRM · services",
        StepKind::WinRmProcesses => "WinRM · processes",
        StepKind::WinRmEvents => "WinRM · system events",
        StepKind::SshCommand => "SSH · custom command",
    }
}
