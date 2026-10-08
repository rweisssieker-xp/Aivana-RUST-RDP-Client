use crate::{
    diagnostic_lab::{self as d, Book, Case, Config, Mode, Probe, Request, Scenario, Value},
    mission::Target,
    models::ConnectionProfile,
    operations::JobQueue,
};
use chrono::Utc;
use eframe::egui;
use uuid::Uuid;

pub(super) struct State {
    book: Book,
    store_error: bool,
    selected: Option<Uuid>,
    incident: String,
    service: String,
    application: String,
    dependency: String,
    mode: Mode,
    scenario: Scenario,
    review: Option<Config>,
    source: Option<crate::incident::Source>,
    review_source: Option<crate::incident::Source>,
    chosen: Option<Probe>,
    ai_json: String,
    ai_preview: Option<d::Proposal>,
    queue: JobQueue,
    pending: Option<(u64, Uuid, Request)>,
    read_review: Option<(Uuid, Request)>,
    notice: String,
    comparison: Option<d::comparison::Report>,
}
impl Default for State {
    fn default() -> Self {
        let args = std::env::args().collect::<Vec<_>>();
        let capture = args.iter().any(|a| a == "--gui-capture")
            && args
                .windows(2)
                .any(|w| w[0] == "--gui-capture-view" && w[1] == "diagnostics");
        let result = if capture {
            Ok(Book::default())
        } else {
            Book::path().and_then(|p| Book::load(&p))
        };
        let error = result.is_err();
        let mut state = Self {
            book: result.unwrap_or_default(),
            store_error: error,
            selected: None,
            incident: "The application is unreachable.".into(),
            service: "ExampleService".into(),
            application: "https://app.example.invalid/".into(),
            dependency: "https://dependency.example.invalid/health".into(),
            mode: Mode::Simulation,
            scenario: Scenario::Service,
            review: None,
            source: None,
            review_source: None,
            chosen: None,
            ai_json: String::new(),
            ai_preview: None,
            queue: JobQueue::default(),
            pending: None,
            read_review: None,
            comparison: None,
            notice: if error {
                "Cannot read diagnostic storage".into()
            } else {
                String::new()
            },
        };
        if capture {
            let now = Utc::now();
            let config = Config {
                mode: Mode::Simulation,
                scenario: Some(Scenario::Dns),
                target: None,
                incident: "Dev example: application unreachable".into(),
                service: state.service.clone(),
                application: state.application.clone(),
                dependency: state.dependency.clone(),
            };
            if let Ok(mut case) = Case::new(config, now) {
                let _ = case.simulate(Probe::Service, now);
                let _ = case.simulate(Probe::Dns, now);
                state.selected = Some(case.id);
                state.book.cases.push(case);
            }
        }
        if capture && args.iter().any(|a| a == "--gui-capture-compare") {
            state.comparison = d::comparison::run(Utc::now()).ok();
        }
        state
    }
}
impl State {
    pub(super) fn setup_snapshot(&self) -> super::setup_panel::Snapshot {
        super::setup_panel::Snapshot {
            incident: self.incident.clone(),
            service: self.service.clone(),
            application: self.application.clone(),
            dependency: self.dependency.clone(),
            mode: self.mode,
            source: self.source.clone(),
            selected_case: self
                .selected
                .and_then(|id| self.book.cases.iter().find(|case| case.id == id))
                .cloned(),
            store_error: self.store_error,
            awaiting_approval: self.read_review.is_some(),
            running: self.pending.is_some(),
        }
    }

    pub(super) fn accept_incident(&mut self, source: crate::incident::Source) {
        self.incident = source.title.clone();
        self.mode = Mode::ReadOnly;
        self.source = Some(source);
        self.review = None;
        self.review_source = None;
        self.selected = None;
        self.clear_review();
        self.notice = "Incident context loaded. Complete the case settings, then review and save; no check has run.".into();
    }
    pub(super) fn verification_handoff(
        &self,
        profile: Option<&ConnectionProfile>,
    ) -> anyhow::Result<d::VerificationHandoff> {
        let case = self
            .selected
            .and_then(|id| self.book.cases.iter().find(|c| c.id == id))
            .ok_or_else(|| anyhow::anyhow!("Select a saved diagnostic case"))?;
        case.verification_handoff(
            profile.ok_or_else(|| anyhow::anyhow!("Select the original Windows profile"))?,
        )
    }
    pub(super) fn selected_matches_handoff(&self, handoff: &d::VerificationHandoff) -> bool {
        self.selected
            .and_then(|id| self.book.cases.iter().find(|case| case.id == id))
            .is_some_and(|case| {
                case.id == handoff.case_id
                    && case
                        .binding()
                        .is_ok_and(|binding| binding == handoff.binding)
                    && case
                        .config
                        .target
                        .as_ref()
                        .is_some_and(|target| target.same_endpoint(&handoff.target))
            })
    }
    pub(super) fn clear_stale_handoff(&self, active: &mut Option<d::VerificationHandoff>) {
        if active
            .as_ref()
            .is_some_and(|handoff| !self.selected_matches_handoff(handoff))
        {
            *active = None;
        }
    }
    fn save(&mut self, mut next: Book) -> bool {
        if self.store_error {
            return false;
        }
        match Book::path().and_then(|p| next.save(&p)) {
            Ok(()) => {
                self.book = next;
                true
            }
            Err(e) => {
                self.notice = e.to_string();
                self.store_error = true;
                false
            }
        }
    }
    fn clear_review(&mut self) {
        self.chosen = None;
        self.ai_preview = None;
        self.read_review = None;
        self.ai_json.clear();
    }
    fn poll(&mut self, profile: Option<&ConnectionProfile>) {
        if let Some((job_id, id, request)) = &self.pending {
            let eligible = Utc::now() >= request.started
                && Utc::now().signed_duration_since(request.started)
                    <= chrono::Duration::seconds(120)
                && self
                    .book
                    .cases
                    .iter()
                    .find(|c| c.id == *id)
                    .is_some_and(|c| {
                        profile
                            .is_some_and(|p| c.config.target.as_ref().is_some_and(|t| t.matches(p)))
                    });
            if !eligible {
                if let Some(job) =
                    self.queue.jobs.iter().find(|j| {
                        j.id == *job_id && j.status == crate::operations::JobStatus::Queued
                    })
                {
                    job.cancel();
                }
            }
        }
        self.queue.poll();
        let Some((job_id, _, _)) = &self.pending else {
            return;
        };
        let Some(job) = self.queue.jobs.iter().find(|j| j.id == *job_id) else {
            return;
        };
        if !job.status.terminal() {
            return;
        }
        let result = job.result.clone();
        let (_, id, request) = self.pending.take().unwrap();
        self.queue.clear_finished();
        let Some(result) = result else {
            self.notice = "Check did not complete; no new observation accepted".into();
            return;
        };
        let value = d::adapter::value(&request, &result).unwrap_or(Value::Unknown);
        let mut next = self.book.clone();
        if let Some(case) = next.cases.iter_mut().find(|c| c.id == id) {
            match case.record(&request, value, result.finished.into()) {
                Ok(()) => {
                    if self.save(next) {
                        self.notice = format!("Read-only check: {}", value.label());
                        self.clear_review();
                    }
                }
                Err(e) => self.notice = e.to_string(),
            }
        }
    }
    fn draw_foresight(ui: &mut egui::Ui, case: &Case, probe: Probe, now: chrono::DateTime<Utc>) {
        egui::CollapsingHeader::new("What would this check clarify?")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(format!("Hypothetical preview: {}", probe.label()));
                ui.label("Assumptions, not measurements. The preview does not change a diagnosis or run a check. It shows possibilities, not probabilities.");
                match case.preview(probe, now) {
                    Ok(branches) => {
                        for branch in branches {
                            ui.group(|ui| {
                                ui.strong(format!("If {} …", branch.assumed.label()));
                                let causes = branch.compatible.iter().map(|p| p.cause()).collect::<Vec<_>>().join(", ");
                                ui.label(if causes.is_empty() {
                                    "Then no model hypothesis matches: investigate other causes or multiple failures.".into()
                                } else {
                                    format!("Still possible: {causes}")
                                });
                                ui.label(format!("Checks that can then be evaluated: {}/4", branch.known));
                                ui.label(branch.conclusion);
                                if let Some(next) = branch.next {
                                    ui.label(format!("Recommended next: {}", next.label()));
                                }
                            });
                        }
                    }
                    Err(error) => { ui.label(format!("No current preview: {error}")); }
                }
            });
    }

    fn draw_comparison(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Dev scenario comparison · seven fixed cases")
            .default_open(self.comparison.is_some())
            .show(ui, |ui| {
            ui.label("Local model test in memory: no connections or saved diagnostic cases. Does not measure AI quality or real incident resolution.");
            if ui.button("Compare all seven simulations").clicked() {
                match d::comparison::run(Utc::now()) {
                    Ok(report) => self.comparison = Some(report),
                    Err(error) => {
                        self.comparison = None;
                        self.notice = format!("Scenario comparison failed: {error}");
                    }
                }
            }
            if let Some(report) = &self.comparison {
                ui.strong(format!("DEV SIMULATION: {}/{} expectations met", report.passed(), report.rows.len()));
                ui.label(format!("Model: {} · {} UTC", report.model_version, report.generated_at.format("%Y-%m-%d %H:%M:%S")));
                for row in &report.rows {
                    ui.push_id(format!("comparison-{:?}", row.scenario), |ui| {
                        ui.collapsing(format!("{} · {} · {} checks", row.scenario.label(), if row.passed { "Expectation met" } else { "MISMATCH" }, row.steps.len()), |ui| {
                            ui.label(format!("Expected: {}", row.expected.label()));
                            ui.label(format!("Determined: {}", row.actual.label()));
                            for (index, step) in row.steps.iter().enumerate() {
                                ui.label(format!("{}. {}: {} · {} distinguishable hypothesis pairs", index + 1, step.probe.label(), step.value.label(), step.distinguished_pairs));
                            }
                        });
                    });
                }
                if ui.button("Copy simulation comparison as JSON").clicked() {
                    match serde_json::to_string_pretty(report) {
                        Ok(json) => ui.ctx().copy_text(json),
                        Err(error) => self.notice = error.to_string(),
                    }
                }
            }
        });
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, profile: Option<&ConnectionProfile>) {
        self.poll(profile);
        self.draw_comparison(ui);
        ui.label("Model: one dominant failure in a service, DNS, TLS, or HTTP dependency. Multiple failures and unknown causes remain possible. Matching a model does not establish causation.");
        ui.add_enabled_ui(self.pending.is_none(),|ui|{
            if ui.button("Reload diagnostic cases").clicked(){
                match Book::path().and_then(|p|Book::load(&p)){Ok(book)=>{self.book=book;self.store_error=false;self.clear_review();},Err(e)=>{self.store_error=true;self.notice=e.to_string();}}
            }
            egui::ComboBox::from_id_salt("diagnostic_case").selected_text(self.selected.and_then(|id|self.book.cases.iter().find(|c|c.id==id)).map(|c|format!("{} · {:?}",c.config.incident,c.config.mode)).unwrap_or("Select diagnostic case".into())).show_ui(ui,|ui|{
                let mut changed=false;
                for case in &self.book.cases {if ui.selectable_value(&mut self.selected,Some(case.id),format!("{} · {:?} · {}",case.config.incident,case.config.mode,case.created.format("%H:%M UTC"))).changed(){changed=true;}}
                if changed{self.clear_review();}
            });
            ui.collapsing("Prepare new diagnostic case",|ui|{
                ui.horizontal_wrapped(|ui|{if self.source.is_none(){ui.selectable_value(&mut self.mode,Mode::Simulation,"Dev simulation (no connection)");}ui.selectable_value(&mut self.mode,Mode::ReadOnly,"Subsequent read-only check");});
                if let Some(source) = &self.source {
                    ui.label(format!("Incident source: {} · {} UTC", source.record_id, source.observed_at.format("%Y-%m-%d %H:%M:%S")));
                    ui.small(format!("Source evidence: {}", source.evidence.join(" · ")));
                    if !profile.is_some_and(|p| source.matches(&Target::from_profile(p))) {
                        ui.colored_label(egui::Color32::RED, "Select the original unchanged Windows profile before preparing this case.");
                    }
                    if ui.button("Clear incident context").clicked() { self.source = None; self.review = None; self.review_source = None; }
                }
                if self.mode==Mode::Simulation {
                    egui::ComboBox::from_id_salt("diagnostic_scenario").selected_text(self.scenario.label()).show_ui(ui,|ui|{for s in Scenario::ALL{ui.selectable_value(&mut self.scenario,s,s.label());}});
                    ui.label("Example values and simulated results; no claims about real systems.");
                }else{ui.label(format!("Selected profile: {}. WinRM uses the current Windows identity; saved RDP passwords are not used.",profile.map(|p|p.name.as_str()).unwrap_or("none")));}
                ui.label("Incident");ui.text_edit_multiline(&mut self.incident);
                ui.horizontal(|ui|{ui.label("Application service");ui.text_edit_singleline(&mut self.service);});
                ui.horizontal(|ui|{ui.label("HTTPS application with DNS name");ui.text_edit_singleline(&mut self.application);});
                ui.horizontal(|ui|{ui.label("Public HTTP(S) dependency check");ui.text_edit_singleline(&mut self.dependency);});
                if ui.add_enabled(!self.store_error && self.book.cases.len()<64,egui::Button::new("Create case preview")).clicked(){
                    let config=Config{mode:self.mode,scenario:if self.mode==Mode::Simulation{Some(self.scenario)}else{None},target:if self.mode==Mode::ReadOnly{profile.map(Target::from_profile)}else{None},incident:self.incident.clone(),service:self.service.trim().into(),application:self.application.trim().into(),dependency:self.dependency.trim().into()};
                    match config.validate().and_then(|()| {
                        if let Some(source) = &self.source {
                            anyhow::ensure!(config.target.as_ref().is_some_and(|t| source.matches(t)), "Incident source and selected profile differ");
                        }
                        Ok(())
                    }){Ok(())=>{self.review=Some(config);self.review_source=self.source.clone();},Err(e)=>self.notice=e.to_string()}
                }
                if let Some(config)=self.review.clone(){
                    ui.group(|ui|{
                        ui.strong("Frozen case configuration");
                        ui.label(format!("Incident: {}",config.incident));
                        ui.label(format!("{:?} · {}\nService: {}\nApplication: {}\nDependency: {}",config.mode,config.target.as_ref().map(|t|t.host.as_str()).unwrap_or("no host"),config.service,config.application,config.dependency));
                        ui.label("Saving does not run a check. Each real read-only check then requires its own preview and approval.");
                        if ui.add_enabled(!self.store_error,egui::Button::new("Save this case")).clicked(){
                            let result = match self.review_source.clone() { Some(source) => Case::new_from_incident(config,source,Utc::now()), None => Case::new(config,Utc::now()) };
                            match result{
                                Ok(case)=>{let id=case.id;let mut next=self.book.clone();next.cases.push(case);if self.save(next){self.selected=Some(id);self.review=None;self.review_source=None;self.source=None;self.clear_review();}}
                                Err(e)=>self.notice=e.to_string(),
                            }
                        }
                        if ui.button("Discard case preview").clicked(){self.review=None;self.review_source=None;}
                    });
                }
            });
        });
        if let Some(case) = self
            .selected
            .and_then(|id| self.book.cases.iter().find(|c| c.id == id))
            .cloned()
        {
            let now = Utc::now();
            let assessment = case.assess(now);
            ui.separator();
            ui.strong(if case.config.mode == Mode::Simulation {
                "DEV SIMULATION — no actual system observation"
            } else {
                "Read-only diagnosis — no repair approval"
            });
            ui.label(&case.config.incident);
            ui.strong("1. Scope and source");
            if let Some(source) = &case.source {
                ui.label(format!("Selected failure {} at {} UTC. Historical evidence; timing alone does not establish cause.", source.record_id, source.observed_at.format("%Y-%m-%d %H:%M:%S")));
                ui.small(format!(
                    "Source evidence IDs: {}",
                    source.evidence.join(" · ")
                ));
            } else {
                ui.label("Standalone case: no incident timeline event attached.");
            }
            ui.label(format!(
                "Check environment: {} · Service: {}",
                case.config
                    .target
                    .as_ref()
                    .map(|t| t.host.as_str())
                    .unwrap_or("local dev scenario"),
                case.config.service
            ));
            if let Some(s) = case.config.scenario {
                ui.label(format!("Simulated scenario: {}", s.label()));
            }
            ui.strong("2. Approved read-only checks");
            for probe in Probe::ALL {
                let latest = case
                    .observations
                    .iter()
                    .filter(|o| o.probe == probe && o.at <= now)
                    .max_by_key(|o| o.at);
                let status = match latest {
                    None => "Missing: no observation".to_owned(),
                    Some(o) if now.signed_duration_since(o.at) > chrono::Duration::minutes(5) => {
                        format!(
                            "Stale: last {} at {} UTC",
                            o.value.label(),
                            o.at.format("%H:%M:%S")
                        )
                    }
                    Some(o) if o.value == Value::Unknown => format!(
                        "Missing: check was inconclusive at {} UTC",
                        o.at.format("%H:%M:%S")
                    ),
                    Some(o) => format!(
                        "Observed {} at {} UTC · request {}",
                        o.value.label(),
                        o.at.format("%H:%M:%S"),
                        o.request
                    ),
                };
                ui.label(format!("{} — {}", probe.label(), status));
            }
            ui.strong("3. Interpret the model");
            ui.label(assessment.conclusion());
            for c in &assessment.candidates {
                ui.collapsing(
                    format!(
                        "{} · {}",
                        c.cause.cause(),
                        if c.contradicts.is_empty() {
                            "still consistent"
                        } else {
                            "contradicts observations"
                        }
                    ),
                    |ui| {
                        for p in &c.supports {
                            ui.label(format!("Matches expectation: {}", p.label()));
                        }
                        for p in &c.contradicts {
                            ui.label(format!("Contradiction: {}", p.label()));
                        }
                        for p in &c.missing {
                            ui.label(format!("Missing or undetermined: {}", p.label()));
                        }
                    },
                );
            }
            if let Some(next) = assessment.next {
                if assessment.pairs == 0 {
                    ui.label(format!("Further model check needed: {}", next.label()));
                } else {
                    ui.label(format!(
                        "Next local recommendation: {} · distinguishes {} hypothesis pairs",
                        next.label(),
                        assessment.pairs
                    ));
                }
            }
            ui.strong("4. Functional verification");
            ui.label("Pending. A diagnostic model match, including four of four checks, is not evidence that the affected function works or that a repair succeeded. Use the reviewed execution workflow for a separate, observed functional check with its own time and evidence.");
            ui.add_enabled_ui(self.pending.is_none() && !self.store_error,|ui|{
                egui::ComboBox::from_id_salt("diagnostic_probe").selected_text(self.chosen.or(assessment.next).map(|p|p.label()).unwrap_or("No check available")).show_ui(ui,|ui|{
                    for p in Probe::ALL {if case.request(p,now).is_ok(){ui.selectable_value(&mut self.chosen,Some(p),p.label());}}
                });
            if let Some(probe)=self.chosen.or(assessment.next).filter(|p|case.request(*p,now).is_ok()){
                Self::draw_foresight(ui, &case, probe, now);
                if case.config.mode==Mode::Simulation {
                        if ui.button("Simulate this check locally").clicked(){
                            let mut next=self.book.clone();let selected=next.cases.iter_mut().find(|c|c.id==case.id).unwrap();
                            match selected.simulate(probe,now){Ok(())=>{if self.save(next){self.clear_review();self.notice="Simulated observation saved".into();}},Err(e)=>self.notice=e.to_string()}
                        }
                    } else {
                        let matches=profile.is_some_and(|p|case.config.target.as_ref().is_some_and(|t|t.matches(p)));
                        if ui.add_enabled(matches,egui::Button::new("Prepare read-only check …")).clicked(){self.read_review=case.request(probe,now).ok().map(|r|(case.id,r));}
                        if !matches{ui.label("The saved Windows profile must remain selected and unchanged.");}
                    }
                }
                if let Some((id,request))=self.read_review.clone().filter(|(id,_)|*id==case.id){
                    if let Ok(spec)=d::adapter::build(&case,&request){
                        ui.collapsing("Review exact read-only job",|ui|{ui.monospace(spec.preview());});
                        ui.label(format!("Reads on {}: {}. No service or VM changes.",case.config.target.as_ref().map(|t|t.host.as_str()).unwrap_or("—"),request.probe.label()));
                        let current=profile.is_some_and(|p|case.config.target.as_ref().is_some_and(|t|t.matches(p))) && now>=request.started && now.signed_duration_since(request.started)<chrono::Duration::seconds(120) && case.request(request.probe,now).is_ok();
                        if ui.add_enabled(current,egui::Button::new("Approve this read-only job now")).clicked(){
                            // Refresh execution timestamp without changing the reviewed command identity.
                            let mut request=request;request.started=Utc::now();
                            match self.queue.enqueue(spec){Ok(job)=>{self.pending=Some((job,id,request));self.read_review=None;},Err(e)=>self.notice=e}
                        }
                        if ui.button("Discard read-only job").clicked(){self.read_review=None;}
                    }
                }
                ui.collapsing("Prepare AI check suggestion offline",|ui|{
                    ui.label("Copies a structured request with the incident and current check results. No hostnames from profiles, credentials, or API calls. AI text never becomes a finding or executable code.");
                    if ui.button("Copy AI check request").clicked(){match case.ai_prompt(now){Ok(text)=>ui.ctx().copy_text(text),Err(e)=>self.notice=e.to_string()}}
                    if ui.add(egui::TextEdit::multiline(&mut self.ai_json).hint_text("Paste JSON suggestion").desired_rows(3)).changed(){self.ai_preview=None;}
                    if ui.button("Review suggestion").clicked(){match case.proposal(&self.ai_json,now){Ok(p)=>self.ai_preview=Some(p),Err(e)=>{self.ai_preview=None;self.notice=e.to_string();}}}
                    if let Some(p)=&self.ai_preview{
                        ui.label(format!("{}: {}",p.probe.label(),p.rationale));
                        if ui.button("Adopt reviewed check selection").clicked(){match case.proposal(&self.ai_json,now){Ok(p)=>{self.chosen=Some(p.probe);self.ai_preview=None;self.read_review=None;},Err(e)=>self.notice=e.to_string()}}
                    }
                });
                if ui.button("Copy diagnostic report as JSON").clicked(){
                    if let Ok(text)=serde_json::to_string_pretty(&serde_json::json!({"kind":"diagnostic-model-report","not_a_causal_or_repair_proof":true,"mode":case.config.mode,"case":case,"conclusion":assessment.conclusion(),"as_of":now})){ui.ctx().copy_text(text);}
                }
            });
            ui.collapsing("Observation history", |ui| {
                for o in case.observations.iter().rev() {
                    ui.label(format!(
                        "{} · {:?} · {}: {} · Job {}",
                        o.at.format("%H:%M:%S UTC"),
                        o.mode,
                        o.probe.label(),
                        o.value.label(),
                        o.request
                    ));
                }
                ui.label(
                    "Only observations from the last five minutes contribute to the current assessment.",
                );
            });
        }
        if self.pending.is_some() {
            ui.spinner();
            if ui.button("Cancel read-only check").clicked() {
                if let Some((id, _, _)) = &self.pending {
                    if let Some(job) = self.queue.jobs.iter().find(|j| j.id == *id) {
                        job.cancel();
                    }
                }
            }
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
        if self.store_error {
            ui.colored_label(
                egui::Color32::RED,
                "Storage problem: adopting results is blocked until reloading succeeds.",
            );
        }
        ui.label(&self.notice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changing_case_binding_or_incident_clears_active_verification_context() {
        let mut state = State::default();
        let profile = ConnectionProfile::sample("Affected", "affected.example.test", "", false);
        let case = Case::new(
            Config {
                mode: Mode::ReadOnly,
                scenario: None,
                target: Some(Target::from_profile(&profile)),
                incident: "Failure one".into(),
                service: "ExampleSvc".into(),
                application: "https://app.example.test/".into(),
                dependency: "https://dependency.example.test/health".into(),
            },
            Utc::now(),
        )
        .unwrap();
        state.selected = Some(case.id);
        state.book.cases.push(case);
        let mut active = Some(state.verification_handoff(Some(&profile)).unwrap());
        state.clear_stale_handoff(&mut active);
        assert!(active.is_some());

        state.book.cases.last_mut().unwrap().config.incident = "Edited case".into();
        state.clear_stale_handoff(&mut active);
        assert!(active.is_none());
        active = Some(state.verification_handoff(Some(&profile)).unwrap());
        state.selected = None;
        state.clear_stale_handoff(&mut active);
        assert!(active.is_none());

        state.selected = state.book.cases.last().map(|case| case.id);
        active = Some(state.verification_handoff(Some(&profile)).unwrap());
        let target = Target::from_profile(&profile);
        state.accept_incident(crate::incident::Source {
            record_id: "new-failure".into(),
            profile_id: profile.id,
            endpoint: crate::incident::endpoint_key(&target),
            observed_at: Utc::now(),
            title: "Failure two".into(),
            evidence: vec!["new-evidence".into()],
        });
        state.clear_stale_handoff(&mut active);
        assert!(active.is_none());
    }
    #[test]
    fn accepting_incident_context_is_inert_and_requires_real_case_preparation() {
        let mut state = State::default();
        let before_cases = state.book.cases.len();
        let profile = ConnectionProfile::sample("Affected", "affected.example.test", "", false);
        let target = Target::from_profile(&profile);
        let source = crate::incident::Source {
            record_id: "failure-1".into(),
            profile_id: profile.id,
            endpoint: crate::incident::endpoint_key(&target),
            observed_at: Utc::now(),
            title: "Application unavailable".into(),
            evidence: vec!["capture-1".into()],
        };
        state.accept_incident(source);
        assert_eq!(state.mode, Mode::ReadOnly);
        assert!(state.selected.is_none());
        assert!(state.review.is_none());
        assert_eq!(state.source.as_ref().unwrap().evidence, vec!["capture-1"]);
        assert_eq!(state.book.cases.len(), before_cases);
        assert!(state.queue.jobs.is_empty());
        assert!(state.pending.is_none());
    }
    #[test]
    fn diagnostic_panel_is_offline_by_default_and_renders() {
        let ctx = egui::Context::default();
        let mut state = State::default();
        for width in [640.0, 1440.0] {
            let out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 1000.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| state.draw(ui, None));
                },
            );
            assert!(!out.shapes.is_empty());
            assert_eq!(state.mode, Mode::Simulation);
            assert!(state.queue.jobs.is_empty());
            assert!(state.pending.is_none());
        }
    }

    #[test]
    fn diagnostic_comparison_renders_without_changing_cases_or_queue() {
        let mut state = State::default();
        let before = serde_json::to_value(&state.book).unwrap();
        state.comparison = Some(d::comparison::run(Utc::now()).unwrap());
        for width in [640.0, 1440.0] {
            let ctx = egui::Context::default();
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 1200.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| state.draw(ui, None));
                },
            );
            assert!(!output.shapes.is_empty());
        }
        assert_eq!(serde_json::to_value(&state.book).unwrap(), before);
        assert!(state.queue.jobs.is_empty());
        assert!(state.pending.is_none());
        assert!(state.read_review.is_none());
    }

    #[test]
    fn diagnostic_foresight_renders_at_both_widths_without_case_changes() {
        let now = Utc::now();
        let case = Case::new(
            Config {
                mode: Mode::Simulation,
                scenario: Some(Scenario::Dns),
                target: None,
                incident: "Dev preview".into(),
                service: "ExampleService".into(),
                application: "https://app.example.invalid/".into(),
                dependency: "https://dependency.example.invalid/health".into(),
            },
            now,
        )
        .unwrap();
        let before = serde_json::to_value(&case).unwrap();
        for width in [640.0, 1440.0] {
            let ctx = egui::Context::default();
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 1400.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        State::draw_foresight(ui, &case, Probe::Service, now)
                    });
                },
            );
            assert!(!output.shapes.is_empty());
        }
        assert_eq!(serde_json::to_value(&case).unwrap(), before);
    }
    #[test]
    fn diagnostic_queued_request_cannot_run_after_profile_changes() {
        let mut state = State::default();
        let now = Utc::now();
        let config = Config {
            mode: Mode::ReadOnly,
            scenario: None,
            target: Some(Target {
                profile_id: Uuid::new_v4(),
                name: "fixture".into(),
                host: "fixture.invalid".into(),
                port: 3389,
                protocol: "RDP".into(),
                username: String::new(),
                domain: String::new(),
                route: String::new(),
            }),
            incident: "test".into(),
            service: "ExampleSvc".into(),
            application: "https://app.example.invalid/".into(),
            dependency: "http://dependency.example.invalid/health".into(),
        };
        let case = Case::new(config, now).unwrap();
        let request = case.request(Probe::Service, now).unwrap();
        let job = state
            .queue
            .enqueue(d::adapter::build(&case, &request).unwrap())
            .unwrap();
        state.pending = Some((job, case.id, request));
        state.book.cases.push(case);
        state.poll(None);
        assert!(state.pending.is_none());
        assert!(state.queue.jobs.is_empty());
        assert!(state.book.cases[0].observations.is_empty());
    }
}
