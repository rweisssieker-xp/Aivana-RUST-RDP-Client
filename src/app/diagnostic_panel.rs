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
            incident: "Die Anwendung ist nicht erreichbar.".into(),
            service: "ExampleService".into(),
            application: "https://app.example.invalid/".into(),
            dependency: "https://dependency.example.invalid/health".into(),
            mode: Mode::Simulation,
            scenario: Scenario::Service,
            review: None,
            chosen: None,
            ai_json: String::new(),
            ai_preview: None,
            queue: JobQueue::default(),
            pending: None,
            read_review: None,
            comparison: None,
            notice: if error {
                "Diagnosespeicher nicht lesbar".into()
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
                incident: "Dev-Beispiel: Anwendung nicht erreichbar".into(),
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
            self.notice = "Prüfung ohne Abschluss; keine neue Beobachtung übernommen".into();
            return;
        };
        let value = d::adapter::value(&request, &result).unwrap_or(Value::Unknown);
        let mut next = self.book.clone();
        if let Some(case) = next.cases.iter_mut().find(|c| c.id == id) {
            match case.record(&request, value, result.finished.into()) {
                Ok(()) => {
                    if self.save(next) {
                        self.notice = format!("Lesende Prüfung: {}", value.label());
                        self.clear_review();
                    }
                }
                Err(e) => self.notice = e.to_string(),
            }
        }
    }
    fn draw_foresight(ui: &mut egui::Ui, case: &Case, probe: Probe, now: chrono::DateTime<Utc>) {
        egui::CollapsingHeader::new("Was würde diese Prüfung klären?")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(format!("Gedankliche Vorschau: {}", probe.label()));
                ui.label("Annahmen, keine Messwerte. Die Vorschau verändert keine Diagnose und führt keine Prüfung aus. Sie zeigt Möglichkeiten, keine Wahrscheinlichkeiten.");
                match case.preview(probe, now) {
                    Ok(branches) => {
                        for branch in branches {
                            ui.group(|ui| {
                                ui.strong(format!("Falls {} …", branch.assumed.label()));
                                let causes = branch.compatible.iter().map(|p| p.cause()).collect::<Vec<_>>().join(", ");
                                ui.label(if causes.is_empty() {
                                    "Dann passt keine Modellhypothese: weitere Ursachen oder mehrere Fehler prüfen.".into()
                                } else {
                                    format!("Weiter möglich: {causes}")
                                });
                                ui.label(format!("Dann auswertbare Prüfungen: {}/4", branch.known));
                                ui.label(branch.conclusion);
                                if let Some(next) = branch.next {
                                    ui.label(format!("Danach empfohlen: {}", next.label()));
                                }
                            });
                        }
                    }
                    Err(error) => { ui.label(format!("Keine aktuelle Vorschau: {error}")); }
                }
            });
    }

    fn draw_comparison(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Dev-Szenariovergleich · sieben feste Fälle")
            .default_open(self.comparison.is_some())
            .show(ui, |ui| {
            ui.label("Lokaler Modelltest im Speicher: keine Verbindungen und keine gespeicherten Diagnosefälle. Keine Messung von KI-Qualität oder realer Störungsbehebung.");
            if ui.button("Alle sieben Simulationen vergleichen").clicked() {
                match d::comparison::run(Utc::now()) {
                    Ok(report) => self.comparison = Some(report),
                    Err(error) => {
                        self.comparison = None;
                        self.notice = format!("Szenariovergleich fehlgeschlagen: {error}");
                    }
                }
            }
            if let Some(report) = &self.comparison {
                ui.strong(format!("DEV-SIMULATION: {}/{} Erwartungen erfüllt", report.passed(), report.rows.len()));
                ui.label(format!("Modell: {} · {} UTC", report.model_version, report.generated_at.format("%Y-%m-%d %H:%M:%S")));
                for row in &report.rows {
                    ui.push_id(format!("comparison-{:?}", row.scenario), |ui| {
                        ui.collapsing(format!("{} · {} · {} Prüfungen", row.scenario.label(), if row.passed { "Erwartung erfüllt" } else { "ABWEICHUNG" }, row.steps.len()), |ui| {
                            ui.label(format!("Erwartet: {}", row.expected.label()));
                            ui.label(format!("Ermittelt: {}", row.actual.label()));
                            for (index, step) in row.steps.iter().enumerate() {
                                ui.label(format!("{}. {}: {} · {} unterscheidbare Hypothesenpaare", index + 1, step.probe.label(), step.value.label(), step.distinguished_pairs));
                            }
                        });
                    });
                }
                if ui.button("Simulationsvergleich als JSON kopieren").clicked() {
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
        ui.label("Modell: ein dominanter Fehler bei Dienst, DNS, TLS oder HTTP-Abhängigkeit. Mehrere Fehler und unbekannte Ursachen bleiben ausdrücklich möglich. Übereinstimmung mit einem Modell ist kein Kausalitätsnachweis.");
        ui.add_enabled_ui(self.pending.is_none(),|ui|{
            if ui.button("Diagnosefälle neu laden").clicked(){
                match Book::path().and_then(|p|Book::load(&p)){Ok(book)=>{self.book=book;self.store_error=false;self.clear_review();},Err(e)=>{self.store_error=true;self.notice=e.to_string();}}
            }
            egui::ComboBox::from_id_salt("diagnostic_case").selected_text(self.selected.and_then(|id|self.book.cases.iter().find(|c|c.id==id)).map(|c|format!("{} · {:?}",c.config.incident,c.config.mode)).unwrap_or("Diagnosefall wählen".into())).show_ui(ui,|ui|{
                let mut changed=false;
                for case in &self.book.cases {if ui.selectable_value(&mut self.selected,Some(case.id),format!("{} · {:?} · {}",case.config.incident,case.config.mode,case.created.format("%H:%M UTC"))).changed(){changed=true;}}
                if changed{self.clear_review();}
            });
            ui.collapsing("Neuen Diagnosefall vorbereiten",|ui|{
                ui.horizontal_wrapped(|ui|{ui.selectable_value(&mut self.mode,Mode::Simulation,"Dev-Simulation (ohne Verbindung)");ui.selectable_value(&mut self.mode,Mode::ReadOnly,"Spätere lesende Prüfung");});
                if self.mode==Mode::Simulation {
                    egui::ComboBox::from_id_salt("diagnostic_scenario").selected_text(self.scenario.label()).show_ui(ui,|ui|{for s in Scenario::ALL{ui.selectable_value(&mut self.scenario,s,s.label());}});
                    ui.label("Beispielwerte und simulierte Ergebnisse; keine Aussagen über echte Systeme.");
                }else{ui.label(format!("Ausgewähltes Profil: {}. WinRM verwendet die aktuelle Windows-Identität; es werden keine gespeicherten RDP-Passwörter übernommen.",profile.map(|p|p.name.as_str()).unwrap_or("keines")));}
                ui.label("Störung");ui.text_edit_multiline(&mut self.incident);
                ui.horizontal(|ui|{ui.label("Anwendungsdienst");ui.text_edit_singleline(&mut self.service);});
                ui.horizontal(|ui|{ui.label("HTTPS-Anwendung mit DNS-Namen");ui.text_edit_singleline(&mut self.application);});
                ui.horizontal(|ui|{ui.label("Öffentliche HTTP(S)-Abhängigkeitsprüfung");ui.text_edit_singleline(&mut self.dependency);});
                if ui.add_enabled(!self.store_error && self.book.cases.len()<64,egui::Button::new("Fallvorschau erstellen")).clicked(){
                    let config=Config{mode:self.mode,scenario:if self.mode==Mode::Simulation{Some(self.scenario)}else{None},target:if self.mode==Mode::ReadOnly{profile.map(Target::from_profile)}else{None},incident:self.incident.clone(),service:self.service.trim().into(),application:self.application.trim().into(),dependency:self.dependency.trim().into()};
                    match config.validate(){Ok(())=>self.review=Some(config),Err(e)=>self.notice=e.to_string()}
                }
                if let Some(config)=self.review.clone(){
                    ui.group(|ui|{
                        ui.strong("Eingefrorene Fallkonfiguration");
                        ui.label(format!("Störung: {}",config.incident));
                        ui.label(format!("{:?} · {}\nDienst: {}\nAnwendung: {}\nAbhängigkeit: {}",config.mode,config.target.as_ref().map(|t|t.host.as_str()).unwrap_or("kein Host"),config.service,config.application,config.dependency));
                        ui.label("Speichern führt keine Prüfung aus. Jede reale Leseprüfung benötigt anschließend eine eigene Vorschau und Freigabe.");
                        if ui.add_enabled(!self.store_error,egui::Button::new("Diesen Fall speichern")).clicked(){
                            match Case::new(config,Utc::now()){
                                Ok(case)=>{let id=case.id;let mut next=self.book.clone();next.cases.push(case);if self.save(next){self.selected=Some(id);self.review=None;self.clear_review();}}
                                Err(e)=>self.notice=e.to_string(),
                            }
                        }
                        if ui.button("Fallvorschau verwerfen").clicked(){self.review=None;}
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
                "DEV-SIMULATION — keine echte Systembeobachtung"
            } else {
                "Lesende Diagnose — keine Reparaturfreigabe"
            });
            ui.label(&case.config.incident);
            ui.label(format!(
                "Prüfumgebung: {} · Dienst: {}",
                case.config
                    .target
                    .as_ref()
                    .map(|t| t.host.as_str())
                    .unwrap_or("lokales Dev-Szenario"),
                case.config.service
            ));
            if let Some(s) = case.config.scenario {
                ui.label(format!("Simuliertes Szenario: {}", s.label()));
            }
            ui.label(assessment.conclusion());
            for c in &assessment.candidates {
                ui.collapsing(
                    format!(
                        "{} · {}",
                        c.cause.cause(),
                        if c.contradicts.is_empty() {
                            "noch vereinbar"
                        } else {
                            "widerspricht Beobachtungen"
                        }
                    ),
                    |ui| {
                        for p in &c.supports {
                            ui.label(format!("Passt zur Erwartung: {}", p.label()));
                        }
                        for p in &c.contradicts {
                            ui.label(format!("Widerspruch: {}", p.label()));
                        }
                        for p in &c.missing {
                            ui.label(format!("Fehlt oder nicht feststellbar: {}", p.label()));
                        }
                    },
                );
            }
            if let Some(next) = assessment.next {
                if assessment.pairs == 0 {
                    ui.label(format!("Weitere Modellprüfung nötig: {}", next.label()));
                } else {
                    ui.label(format!(
                        "Nächste lokale Empfehlung: {} · unterscheidet {} Hypothesenpaare",
                        next.label(),
                        assessment.pairs
                    ));
                }
            }
            ui.add_enabled_ui(self.pending.is_none() && !self.store_error,|ui|{
                egui::ComboBox::from_id_salt("diagnostic_probe").selected_text(self.chosen.or(assessment.next).map(|p|p.label()).unwrap_or("Keine Prüfung verfügbar")).show_ui(ui,|ui|{
                    for p in Probe::ALL {if case.request(p,now).is_ok(){ui.selectable_value(&mut self.chosen,Some(p),p.label());}}
                });
            if let Some(probe)=self.chosen.or(assessment.next).filter(|p|case.request(*p,now).is_ok()){
                Self::draw_foresight(ui, &case, probe, now);
                if case.config.mode==Mode::Simulation {
                        if ui.button("Diese Prüfung lokal simulieren").clicked(){
                            let mut next=self.book.clone();let selected=next.cases.iter_mut().find(|c|c.id==case.id).unwrap();
                            match selected.simulate(probe,now){Ok(())=>{if self.save(next){self.clear_review();self.notice="Simulierte Beobachtung gespeichert".into();}},Err(e)=>self.notice=e.to_string()}
                        }
                    } else {
                        let matches=profile.is_some_and(|p|case.config.target.as_ref().is_some_and(|t|t.matches(p)));
                        if ui.add_enabled(matches,egui::Button::new("Lesende Prüfung vorbereiten …")).clicked(){self.read_review=case.request(probe,now).ok().map(|r|(case.id,r));}
                        if !matches{ui.label("Das gespeicherte Windows-Profil muss unverändert ausgewählt sein.");}
                    }
                }
                if let Some((id,request))=self.read_review.clone().filter(|(id,_)|*id==case.id){
                    if let Ok(spec)=d::adapter::build(&case,&request){
                        ui.collapsing("Exakten Leseauftrag prüfen",|ui|{ui.monospace(spec.preview());});
                        ui.label(format!("Liest auf {}: {}. Keine Dienst- oder VM-Änderung.",case.config.target.as_ref().map(|t|t.host.as_str()).unwrap_or("—"),request.probe.label()));
                        let current=profile.is_some_and(|p|case.config.target.as_ref().is_some_and(|t|t.matches(p))) && now>=request.started && now.signed_duration_since(request.started)<chrono::Duration::seconds(120) && case.request(request.probe,now).is_ok();
                        if ui.add_enabled(current,egui::Button::new("Diesen Leseauftrag jetzt freigeben")).clicked(){
                            // Refresh execution timestamp without changing the reviewed command identity.
                            let mut request=request;request.started=Utc::now();
                            match self.queue.enqueue(spec){Ok(job)=>{self.pending=Some((job,id,request));self.read_review=None;},Err(e)=>self.notice=e}
                        }
                        if ui.button("Leseauftrag verwerfen").clicked(){self.read_review=None;}
                    }
                }
                ui.collapsing("KI-Prüfvorschlag offline vorbereiten",|ui|{
                    ui.label("Kopiert einen strukturierten Auftrag mit Störung und aktuellen Prüfergebnissen. Keine Hostnamen aus Profilen, Zugangsdaten oder API-Aufrufe. KI-Text wird niemals zum Befund oder ausführbaren Code.");
                    if ui.button("KI-Prüfauftrag kopieren").clicked(){match case.ai_prompt(now){Ok(text)=>ui.ctx().copy_text(text),Err(e)=>self.notice=e.to_string()}}
                    if ui.add(egui::TextEdit::multiline(&mut self.ai_json).hint_text("JSON-Vorschlag einfügen").desired_rows(3)).changed(){self.ai_preview=None;}
                    if ui.button("Vorschlag prüfen").clicked(){match case.proposal(&self.ai_json,now){Ok(p)=>self.ai_preview=Some(p),Err(e)=>{self.ai_preview=None;self.notice=e.to_string();}}}
                    if let Some(p)=&self.ai_preview{
                        ui.label(format!("{}: {}",p.probe.label(),p.rationale));
                        if ui.button("Geprüfte Prüfauswahl übernehmen").clicked(){match case.proposal(&self.ai_json,now){Ok(p)=>{self.chosen=Some(p.probe);self.ai_preview=None;self.read_review=None;},Err(e)=>self.notice=e.to_string()}}
                    }
                });
                if ui.button("Diagnosebericht als JSON kopieren").clicked(){
                    if let Ok(text)=serde_json::to_string_pretty(&serde_json::json!({"kind":"diagnostic-model-report","not_a_causal_or_repair_proof":true,"mode":case.config.mode,"case":case,"conclusion":assessment.conclusion(),"as_of":now})){ui.ctx().copy_text(text);}
                }
            });
            ui.collapsing("Beobachtungsverlauf", |ui| {
                for o in case.observations.iter().rev() {
                    ui.label(format!(
                        "{} · {:?} · {}: {} · Auftrag {}",
                        o.at.format("%H:%M:%S UTC"),
                        o.mode,
                        o.probe.label(),
                        o.value.label(),
                        o.request
                    ));
                }
                ui.label(
                    "Nur Beobachtungen der letzten fünf Minuten tragen die aktuelle Bewertung.",
                );
            });
        }
        if self.pending.is_some() {
            ui.spinner();
            if ui.button("Leseprüfung abbrechen").clicked() {
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
                "Speicherproblem: Übernahmen sind bis zum erfolgreichen Neuladen gesperrt.",
            );
        }
        ui.label(&self.notice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
