use super::*;
use crate::{
    mission::{Mission, Target},
    operations::{JobQueue, JobStatus},
    recommendations::{Library, Requirements},
    telemetry::{self, Edge, Observation, Store},
};
#[derive(Clone)]
enum Work {
    Collect(Target),
    Probe(Edge),
}
pub(super) struct InsightsState {
    pub store: Store,
    library: Library,
    error: Option<String>,
    selected: Vec<Uuid>,
    queue: JobQueue,
    pending: HashMap<u64, Work>,
    query: String,
    os_prefix: String,
    required_services: String,
}
impl Default for InsightsState {
    fn default() -> Self {
        let result = (|| -> anyhow::Result<(Store, Library)> {
            Ok((
                Store::load(&app_data_file("relayne-telemetry.dpapi")?)?,
                Library::load(&app_data_file("relayne-solutions.dpapi")?)?,
            ))
        })();
        let (store, library, error) = match result {
            Ok((s, l)) => (s, l, None),
            Err(e) => (
                Store::default(),
                Library::default(),
                Some(format!(
                    "Cannot read knowledge data; writes blocked: {e}"
                )),
            ),
        };
        Self {
            store,
            library,
            error,
            selected: vec![],
            queue: JobQueue::default(),
            pending: HashMap::new(),
            query: String::new(),
            os_prefix: String::new(),
            required_services: String::new(),
        }
    }
}
impl AivanaApp {
    fn save_insights(&mut self) -> bool {
        if self.insights.error.is_some() {
            return false;
        }
        let result = app_data_file("relayne-telemetry.dpapi")
            .and_then(|p| self.insights.store.save(&p))
            .and_then(|_| app_data_file("relayne-solutions.dpapi"))
            .and_then(|p| self.insights.library.save(&p));
        if let Err(e) = result {
            self.status = format!("Knowledge not saved: {e}");
            false
        } else {
            true
        }
    }
    pub(super) fn poll_insights(&mut self) {
        self.insights.queue.poll();
        let done: Vec<_> = self
            .insights
            .queue
            .jobs
            .iter()
            .filter(|j| j.status.terminal() && self.insights.pending.contains_key(&j.id))
            .map(|j| (j.id, j.result.clone()))
            .collect();
        if done.is_empty() {
            return;
        }
        for (id, result) in done {
            let Some(work) = self.insights.pending.remove(&id) else {
                continue;
            };
            let Some(result) = result.filter(|r| r.status == JobStatus::Completed && !r.truncated)
            else {
                self.status =
                    "Telemetry/check failed or was canceled. No finding inferred."
                        .into();
                continue;
            };
            let result = match work {
                Work::Collect(target) => {
                    Observation::parse(target, &result.stdout).map(|o| self.insights.store.add(o))
                }
                Work::Probe(edge) => telemetry::parse_probe(edge, &result.stdout).map(|p| {
                    self.insights.store.probes.push(p);
                    if self.insights.store.probes.len() > 512 {
                        self.insights.store.probes.remove(0);
                    }
                }),
            };
            if let Err(e) = result {
                self.status = e.to_string();
            }
        }
        self.insights.queue.clear_finished();
        self.save_insights();
    }
    pub(super) fn insights_view(&mut self, ui: &mut Ui) {
        ui.heading("Causes & matching solutions");
        if let Some(e) = &self.insights.error {
            ui.colored_label(tw::RED_600, e);
        }
        ui.label("TCP relationships, service mappings, and error timestamps from explicitly selected Windows computers. WinRM uses the current Windows identity.");
        ui.horizontal_wrapped(|ui| {
            for p in &self.profiles {
                if p.protocol != Protocol::Rdp {
                    continue;
                }
                let mut selected = self.insights.selected.contains(&p.id);
                if ui.checkbox(&mut selected, &p.name).changed() {
                    if selected {
                        self.insights.selected.push(p.id);
                    } else {
                        self.insights.selected.retain(|id| *id != p.id);
                    }
                }
            }
        });
        if ui
            .add_enabled(
                self.insights.pending.is_empty() && self.insights.error.is_none(),
                egui::Button::new("Inspect selected computers"),
            )
            .clicked()
        {
            for p in self
                .profiles
                .clone()
                .iter()
                .filter(|p| self.insights.selected.contains(&p.id))
            {
                let t = Target::from_profile(p);
                match telemetry::collect_spec(&t)
                    .map_err(|e| e.to_string())
                    .and_then(|spec| self.insights.queue.enqueue(spec))
                {
                    Ok(id) => {
                        self.insights.pending.insert(id, Work::Collect(t));
                    }
                    Err(e) => self.status = e,
                }
            }
        }
        if !self.insights.pending.is_empty() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!(
                    "{} captures/checks pending",
                    self.insights.pending.len()
                ));
                if ui.button("Cancel").clicked() {
                    for j in &self.insights.queue.jobs {
                        j.cancel();
                    }
                }
            });
        }
        for o in telemetry::latest(&self.insights.store.observations) {
            ui.collapsing(format!("{} · {} · {}",o.target.name,o.received.format("%H:%M:%S"),if o.fresh(){"current"}else{"outdated"}),|ui|{ui.label(format!("OS {} · {} services · {} TCP entries · {} error events",o.payload.os_version,o.payload.services.len(),o.payload.sockets.len(),o.payload.events.len()));ui.small(format!("Evidence {} · Remote time {}",o.id,o.payload.observed_at));if o.payload.truncated{ui.label("Output limited: missing entries do not support a negative conclusion.");}if !o.payload.events_available{ui.label("Event source unavailable or no matching events.");}});
        }
        ui.separator();
        ui.heading("Observed connections");
        for edge in self.insights.store.edges.clone() {
            let identity_ok = self.profiles.iter().any(|p| edge.source.matches(p))
                && self.profiles.iter().any(|p| edge.destination.matches(p));
            ui.collapsing(
                format!(
                    "{} → {}:{}",
                    edge.source.name, edge.destination.name, edge.port
                ),
                |ui| {
                    ui.label(format!(
                        "Mapping: {}",
                        if edge.services.is_empty() {
                            "No unique service identified".into()
                        } else {
                            edge.services.join(", ")
                        }
                    ));
                    ui.label(self.insights.store.explanation(&edge));
                    ui.small(format!(
                        "Observed {} · Evidence {:?}",
                        edge.observed, edge.evidence
                    ));
                    if ui
                        .add_enabled(
                            identity_ok && self.insights.pending.is_empty(),
                            egui::Button::new("Check path from the affected computer"),
                        )
                        .clicked()
                    {
                        match telemetry::probe_spec(&edge)
                            .map_err(|e| e.to_string())
                            .and_then(|spec| self.insights.queue.enqueue(spec))
                        {
                            Ok(id) => {
                                self.insights.pending.insert(id, Work::Probe(edge.clone()));
                            }
                            Err(e) => self.status = e,
                        }
                    }
                },
            );
        }
        ui.collapsing("Error event timeline", |ui| {
            ui.small("Remote clocks may differ. Events occurring close together alone do not establish a cause.");
            let mut events: Vec<_> = self
                .insights
                .store
                .observations
                .iter()
                .flat_map(|o| {
                    o.payload.events.iter().map(move |e| {
                        (
                            e.at.clone(),
                            o.target.name.clone(),
                            e.provider.clone(),
                            e.id,
                            o.id,
                        )
                    })
                })
                .collect();
            events.sort();
            events.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3 == b.3);
            for (at, host, provider, id, evidence) in events.into_iter().rev().take(100) {
                ui.label(format!("{at} · {host} · {provider} #{id}"));
                ui.small(format!("Evidence {evidence}"));
            }
        });
        ui.separator();
        self.solution_recommendations_ui(ui);
    }
    fn solution_recommendations_ui(&mut self, ui: &mut Ui) {
        self.learned_repairs_ui(ui);
        ui.heading("Matching solutions from experience");
        ui.collapsing("Automatically learned verified service workflows", |ui| {
            let lessons=self.execution_lessons();
            if lessons.is_empty(){ui.label("Solutions and outcomes from completed test/production runs appear here automatically.");}
            for lesson in lessons {ui.push_id(&lesson.key,|ui| {
                ui.strong(format!("{} → {}",lesson.service,lesson.desired.label()));
                ui.label(format!("Production: {} confirmed, {} failed, {} restored, {} unresolved",lesson.production.successes,lesson.production.failures,lesson.production.restored,lesson.production.unknown));
                ui.label(format!("Test environment: {} confirmed, {} failed, {} restored, {} unresolved",lesson.rehearsal.successes,lesson.rehearsal.failures,lesson.rehearsal.restored,lesson.rehearsal.unknown));
                ui.label(format!("Functional test: {:?}",lesson.health));
                ui.collapsing("Evidence",|ui|{for e in &lesson.evidence {ui.monospace(format!("Run {} · Target {} · {:?} · Test {}",e.run_id,e.target_profile_id,e.phase,e.rehearsal));}});
                if ui.button("Prepare solution as a new review plan").clicked(){self.use_execution_lesson(&lesson);self.view=View::Execution;}
            });}
            ui.small("Every new target requires a new test mapping, preflight check, and approval. Failures are learned as failures; they do not cause a solution to be recommended as successful.");
        });
        ui.label("A job is registered as a reusable solution. Its rating follows its documented target outcomes and verified prerequisites.");
        ui.collapsing("Register selected job as a solution", |ui| {
            ui.label(
                self.missions
                    .selected
                    .and_then(|id| self.missions.book.missions.iter().find(|m| m.id == id))
                    .map(|m| m.objective.as_str())
                    .unwrap_or("Select a job in Mission Control first"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.insights.os_prefix)
                    .hint_text("Required OS version, e.g., 10.0 (optional)"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.insights.required_services)
                    .hint_text("Required services, separated by commas (optional)"),
            );
            if ui
                .add_enabled(
                    self.insights.error.is_none(),
                    egui::Button::new("Save solution with prerequisites"),
                )
                .clicked()
            {
                if let Some(m) = self
                    .missions
                    .selected
                    .and_then(|id| self.missions.book.missions.iter().find(|m| m.id == id))
                    .cloned()
                {
                    let req = Requirements {
                        protocol: m
                            .targets
                            .first()
                            .map(|t| t.protocol.clone())
                            .unwrap_or_default(),
                        os_prefix: self.insights.os_prefix.trim().into(),
                        services: self
                            .insights
                            .required_services
                            .split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                    };
                    let previous = self.insights.library.clone();
                    match self.insights.library.remember(&m, req) {
                        Ok(_) => {
                            if !self.save_insights() {
                                self.insights.library = previous;
                            }
                        }
                        Err(e) => self.status = e.to_string(),
                    }
                }
            }
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.insights.query)
                .hint_text("Describe the current incident, e.g., print service down"),
        );
        let Some(profile) = self.selected_profile().cloned() else {
            ui.label("Select a target profile to compare prerequisites.");
            return;
        };
        let target = Target::from_profile(&profile);
        ui.label(format!("Recommendations for {}", profile.name));
        let ranked = self.insights.library.recommend(
            &self.insights.query,
            &target,
            self.insights.store.current(&target),
            &self.missions.book,
        );
        if ranked.is_empty() {
            ui.label(
                "No matching registered solution yet. Capture and verify a job first.",
            );
        }
        for suggestion in ranked.into_iter().take(20) {
            let Some(recipe) = self
                .insights
                .library
                .recipes
                .iter()
                .find(|r| r.id == suggestion.recipe)
                .cloned()
            else {
                continue;
            };
            ui.collapsing(&recipe.title, |ui| {
                ui.label(format!(
                    "{} confirmed · {} failed · {} interrupted target outcomes",
                    suggestion.successes, suggestion.failures, suggestion.interrupted
                ));
                ui.small("Documented current outcomes, not a probability of success.");
                for matched in &suggestion.matches {
                    ui.label(format!("✓ {matched}"));
                }
                for missing in &suggestion.missing {
                    ui.label(format!("? {missing}"));
                }
                for conflict in &suggestion.conflicts {
                    ui.colored_label(tw::RED_600, format!("× {conflict}"));
                }
                for (index, s) in recipe.steps.iter().enumerate() {
                    ui.label(format!("{}. {} — {}", index + 1, s.title, s.expectation));
                }
                ui.small(format!(
                    "Source job {} · Evidence {:?}",
                    recipe.source, suggestion.evidence
                ));
                if ui
                    .add_enabled(
                        suggestion.eligible(),
                        egui::Button::new("Use as a new job for review"),
                    )
                    .clicked()
                {
                    match Mission::new(
                        &recipe.objective,
                        vec![target.clone()],
                        recipe.steps.clone(),
                    ) {
                        Ok(m) => {
                            let id = m.id;
                            self.missions.book.missions.push(m);
                            if self.save_missions() {
                                self.missions.selected = Some(id);
                                self.view = View::Missions;
                            } else {
                                self.missions.book.missions.retain(|m| m.id != id);
                            }
                        }
                        Err(e) => self.status = e.to_string(),
                    }
                }
            });
        }
    }
}
