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
                    "Wissensdaten nicht lesbar; Schreiben gesperrt: {e}"
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
            self.status = format!("Wissen nicht gespeichert: {e}");
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
                    "Telemetrie/Prüfung fehlgeschlagen oder abgebrochen. Kein Befund abgeleitet."
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
        ui.heading("Ursachen & passende Lösungen");
        if let Some(e) = &self.insights.error {
            ui.colored_label(tw::RED_600, e);
        }
        ui.label("TCP-Beziehungen, Dienstzuordnung und Fehlerzeitpunkte aus ausdrücklich ausgewählten Windows-Rechnern. WinRM nutzt die aktuelle Windows-Identität.");
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
                egui::Button::new("Ausgewählte Rechner untersuchen"),
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
                    "{} Erfassungen/Prüfungen offen",
                    self.insights.pending.len()
                ));
                if ui.button("Abbrechen").clicked() {
                    for j in &self.insights.queue.jobs {
                        j.cancel();
                    }
                }
            });
        }
        for o in telemetry::latest(&self.insights.store.observations) {
            ui.collapsing(format!("{} · {} · {}",o.target.name,o.received.format("%H:%M:%S"),if o.fresh(){"aktuell"}else{"veraltet"}),|ui|{ui.label(format!("OS {} · {} Dienste · {} TCP-Einträge · {} Fehlerereignisse",o.payload.os_version,o.payload.services.len(),o.payload.sockets.len(),o.payload.events.len()));ui.small(format!("Beleg {} · Remote-Zeit {}",o.id,o.payload.observed_at));if o.payload.truncated{ui.label("Ausgabe begrenzt: fehlende Einträge erlauben keinen negativen Schluss.");}if !o.payload.events_available{ui.label("Ereignisquelle nicht verfügbar oder keine passenden Ereignisse.");}});
        }
        ui.separator();
        ui.heading("Beobachtete Verbindungen");
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
                        "Zuordnung: {}",
                        if edge.services.is_empty() {
                            "Kein eindeutiger Dienst bekannt".into()
                        } else {
                            edge.services.join(", ")
                        }
                    ));
                    ui.label(self.insights.store.explanation(&edge));
                    ui.small(format!(
                        "Beobachtet {} · Belege {:?}",
                        edge.observed, edge.evidence
                    ));
                    if ui
                        .add_enabled(
                            identity_ok && self.insights.pending.is_empty(),
                            egui::Button::new("Pfad vom betroffenen Rechner aus prüfen"),
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
        ui.collapsing("Zeitlicher Verlauf der Fehlerereignisse", |ui| {
            ui.small("Remote-Uhren können abweichen. Zeitliche Nähe allein belegt keine Ursache.");
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
                ui.small(format!("Beleg {evidence}"));
            }
        });
        ui.separator();
        self.solution_recommendations_ui(ui);
    }
    fn solution_recommendations_ui(&mut self, ui: &mut Ui) {
        self.learned_repairs_ui(ui);
        ui.heading("Passende Lösungen aus Erfahrung");
        ui.collapsing("Automatisch gelernte geprüfte Dienstabläufe", |ui| {
            let lessons=self.execution_lessons();
            if lessons.is_empty(){ui.label("Nach abgeschlossenen Test-/Produktionsläufen erscheinen hier automatisch deren Lösungen und Ergebnisse.");}
            for lesson in lessons {ui.push_id(&lesson.key,|ui| {
                ui.strong(format!("{} → {}",lesson.service,lesson.desired.label()));
                ui.label(format!("Produktion: {} bestätigt, {} fehlgeschlagen, {} wiederhergestellt, {} ungeklärt",lesson.production.successes,lesson.production.failures,lesson.production.restored,lesson.production.unknown));
                ui.label(format!("Testumgebung: {} bestätigt, {} fehlgeschlagen, {} wiederhergestellt, {} ungeklärt",lesson.rehearsal.successes,lesson.rehearsal.failures,lesson.rehearsal.restored,lesson.rehearsal.unknown));
                ui.label(format!("Funktionstest: {:?}",lesson.health));
                ui.collapsing("Belege",|ui|{for e in &lesson.evidence {ui.monospace(format!("Lauf {} · Ziel {} · {:?} · Test {}",e.run_id,e.target_profile_id,e.phase,e.rehearsal));}});
                if ui.button("Lösung als neuen Prüfplan vorbereiten").clicked(){self.use_execution_lesson(&lesson);self.view=View::Execution;}
            });}
            ui.small("Jedes neue Ziel benötigt erneut Testzuordnung, Vorprüfung und Freigabe. Fehler werden als Fehler gelernt; eine Lösung wird dadurch nicht als erfolgreich empfohlen.");
        });
        ui.label("Ein Auftrag wird als wiederverwendbare Lösung registriert. Die Bewertung folgt seinen tatsächlich belegten Zielergebnissen und den geprüften Voraussetzungen.");
        ui.collapsing("Ausgewählten Auftrag als Lösung registrieren", |ui| {
            ui.label(
                self.missions
                    .selected
                    .and_then(|id| self.missions.book.missions.iter().find(|m| m.id == id))
                    .map(|m| m.objective.as_str())
                    .unwrap_or("Zuerst einen Auftrag unter Mission Control auswählen"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.insights.os_prefix)
                    .hint_text("Benötigte OS-Version, z. B. 10.0 (optional)"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.insights.required_services)
                    .hint_text("Benötigte Dienste, durch Komma getrennt (optional)"),
            );
            if ui
                .add_enabled(
                    self.insights.error.is_none(),
                    egui::Button::new("Lösung mit Voraussetzungen merken"),
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
                .hint_text("Aktuelle Störung beschreiben, z. B. Druckdienst ausgefallen"),
        );
        let Some(profile) = self.selected_profile().cloned() else {
            ui.label("Zielprofil auswählen, um Voraussetzungen abzugleichen.");
            return;
        };
        let target = Target::from_profile(&profile);
        ui.label(format!("Empfehlungen für {}", profile.name));
        let ranked = self.insights.library.recommend(
            &self.insights.query,
            &target,
            self.insights.store.current(&target),
            &self.missions.book,
        );
        if ranked.is_empty() {
            ui.label(
                "Noch keine passende registrierte Lösung. Erfasse und prüfe zuerst einen Auftrag.",
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
                    "{} bestätigte · {} fehlgeschlagene · {} unterbrochene Zielergebnisse",
                    suggestion.successes, suggestion.failures, suggestion.interrupted
                ));
                ui.small("Dokumentierte aktuelle Ergebnisstände, keine Erfolgswahrscheinlichkeit.");
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
                    "Quellauftrag {} · Belege {:?}",
                    recipe.source, suggestion.evidence
                ));
                if ui
                    .add_enabled(
                        suggestion.eligible(),
                        egui::Button::new("Als neuen Auftrag zur Prüfung übernehmen"),
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
