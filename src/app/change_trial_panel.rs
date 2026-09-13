use crate::test_lab::{
    HealthProbe, Journal,
    change_trial::{self, Record, Spec, Startup},
};
use eframe::egui;

pub(super) struct State {
    service: String,
    startup: Startup,
    health: HealthProbe,
    user: String,
    password: String,
    lab: String,
    records: Vec<Record>,
    store_error: bool,
    notice: String,
    review: Option<(Journal, Spec)>,
    restore_review: Option<uuid::Uuid>,
    worker: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            service: String::new(),
            startup: Startup::Manual,
            health: HealthProbe {
                url: "http://127.0.0.1:8080/health".into(),
                expected_status: 200,
                ..Default::default()
            },
            user: String::new(),
            password: String::new(),
            lab: String::new(),
            records: vec![],
            store_error: false,
            notice: String::new(),
            review: None,
            restore_review: None,
            worker: None,
        }
    }
}
impl State {
    pub fn busy(&self) -> bool {
        self.worker.is_some()
    }
    fn reload(&mut self, lab: &str) {
        match change_trial::history(lab) {
            Ok(records) => {
                self.records = records;
                self.store_error = false;
            }
            Err(_) => {
                self.records.clear();
                self.store_error = true;
                self.notice = "Versuchsspeicher nicht lesbar; neue Versuche gesperrt".into();
            }
        }
    }
    pub fn draw(&mut self, ui: &mut egui::Ui, journal: &Journal, lab_busy: bool) {
        if self.lab != journal.id {
            self.lab = journal.id.clone();
            self.review = None;
            self.restore_review = None;
            self.reload(&journal.id);
        }
        if let Some(rx) = &self.worker {
            match rx.try_recv() {
                Ok(result) => {
                    self.worker = None;
                    self.notice = result.unwrap_or_else(|e| e);
                    self.reload(&journal.id);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.worker = None;
                    self.notice = "Versuch unterbrochen. Gespeicherten Rückweg prüfen.".into();
                    self.reload(&journal.id);
                }
                Err(_) => {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(200));
                }
            }
        }
        ui.separator();
        ui.heading("Änderung & Fehler im Klon erproben");
        ui.label("Starttyp eines Anwendungsdienstes ändern → HTTP prüfen → Dienst stoppen und Ausfall nachweisen → Dienst starten → Checkpoint zurückspielen und Ausgangszustand prüfen.");
        ui.label("Nur dieser isolierte Klon. Erste Version: Automatic ↔ Manual, eine öffentliche HTTP-Prüfung, keine Updates oder beliebigen Skripte. Ein positiver Test belegt keinen Start nach einem Neustart des Betriebssystems.");
        ui.label("Erfordert Standardprüfpunkte mit Arbeitsspeicher und einen Klon ohne vorhandene Prüfpunkte. Neue Relayne-Klone werden entsprechend eingerichtet; ältere Klone im Hyper-V-Manager prüfen.");
        ui.add_enabled_ui(!self.busy() && !lab_busy, |ui| {
            if ui.button("Versuchsbelege laden").clicked(){self.reload(&journal.id);}
            ui.horizontal(|ui|{ui.label("Anwendungsdienst");ui.text_edit_singleline(&mut self.service);});
            ui.horizontal(|ui|{ui.label("Neuer Starttyp");ui.selectable_value(&mut self.startup,Startup::Automatic,"Automatisch");ui.selectable_value(&mut self.startup,Startup::Manual,"Manuell");});
            ui.horizontal(|ui|{ui.label("Loopback-HTTP-URL");ui.text_edit_singleline(&mut self.health.url);});
            ui.horizontal(|ui|{ui.label("Erwarteter Status");ui.add(egui::DragValue::new(&mut self.health.expected_status).range(100..=599));ui.label("Text im Ergebnis");ui.text_edit_singleline(&mut self.health.body_marker);});
            ui.horizontal(|ui|{ui.label("Gastbenutzer für Versuch/Rückweg");ui.text_edit_singleline(&mut self.user);});
            ui.horizontal(|ui|{ui.label("Gastpasswort (nur für diesen Lauf)");ui.add(egui::TextEdit::singleline(&mut self.password).password(true));});
            let blocked=self.store_error || self.records.iter().any(Record::unresolved) || self.records.len()>=100;
            if ui.add_enabled(!blocked,egui::Button::new("Versuch vorbereiten …")).clicked(){
                let spec=Spec{service:self.service.trim().into(),startup:self.startup,health:self.health.clone()};
                match spec.validate(){Ok(())=>{self.review=Some((journal.clone(),spec));self.restore_review=None;},Err(e)=>self.notice=e.to_string()}
            }
            if blocked {ui.label("Ein ungeklärter Versuch oder ein Speicherproblem sperrt weitere Änderungen in diesem Klon.");}
            if let Some((lab,spec))=self.review.clone(){
                ui.group(|ui|{
                    ui.strong("Geprüfte Auswahl ausführen");
                    ui.label(format!("Klon: {} · VM {}\nDienst: {} → {}\nHTTP: {} · Status {} · Text: {}",lab.name,lab.vm_id,spec.service,spec.startup.label(),spec.health.url,spec.health.expected_status,spec.health.body_marker));
                    ui.label("Erzeugt einen Checkpoint und einen echten Dienstausfall im Klon. Alle Änderungen seit dem Checkpoint werden beim Rückweg verworfen. Keine parallele Nutzung dieses Klons während des Versuchs.");
                    ui.horizontal(|ui|{
                        if ui.add_enabled(!blocked && !self.user.trim().is_empty() && !self.password.is_empty(),egui::Button::new("Diesen Klonversuch jetzt ausführen")).clicked(){
                            let user=self.user.clone();let password=std::mem::take(&mut self.password);
                            let(tx,rx)=std::sync::mpsc::channel();self.worker=Some(rx);self.review=None;
                            std::thread::spawn(move||{let result=change_trial::run(lab,spec,user,password).map(|record|{
                                if record.proof.as_ref().is_some_and(|p|p.passed()){"Änderung, Fehler, Reparatur und Rückweg nachgewiesen.".into()}
                                else if record.unresolved(){"Versuch nicht bestanden; Rückweg ungeklärt. Gespeicherten Checkpoint wiederherstellen.".into()}
                                else{"Versuch nicht bestanden. Klon unverändert oder Rückweg bestätigt; Phasen im Beleg prüfen.".into()}
                            }).map_err(|_|"Versuch nicht abgeschlossen. Belege laden und Rückweg prüfen.".into());let _=tx.send(result);});
                        }
                        if ui.button("Vorschau verwerfen").clicked(){self.review=None;}
                    });
                });
            }
            ui.strong("Gespeicherte Versuche");
            for record in &self.records {
                ui.group(|ui|{
                    ui.label(format!("{} · {} · {} → {}",record.request.started.format("%d.%m.%Y %H:%M UTC"),record.request.id,record.request.spec.service,record.request.spec.startup.label()));
                    if let Some(p)=&record.proof {
                        ui.label(format!("Baseline {} · Änderung {} · Ausfall {} · Reparatur {} · Rückweg {}",mark(p.baseline),mark(p.changed),mark(p.fault_observed),mark(p.repaired),mark(p.returned)));
                        ui.label(if p.passed(){"Bestanden — historischer Klonbeleg, keine Produktionsfreigabe"}else{"Nicht bestanden"});
                        if p.untouched{ui.label("Vor einer Änderung abgebrochen; Klon unverändert.");}
                    }else{ui.label("Kein Abschlussbeleg; Zustand ungeklärt.");}
                    if record.recovered{ui.label("Rückweg separat bestätigt; Versuch bleibt ohne Erfolgsnachweis.");}
                    if record.unresolved() && ui.button(format!("Rückweg für {} vorbereiten …",record.request.id)).clicked(){self.restore_review=Some(record.request.id);self.review=None;}
                });
            }
            if let Some(id)=self.restore_review {
                ui.label(format!("Checkpoint Relayne-Trial-{id} zurückspielen und HTTP sowie Starttyp prüfen. Änderungen im Klon seit diesem Checkpoint werden verworfen."));
                if ui.add_enabled(!self.user.trim().is_empty() && !self.password.is_empty(),egui::Button::new("Gespeicherten Rückweg jetzt ausführen")).clicked(){
                    let lab=journal.clone();let user=self.user.clone();let password=std::mem::take(&mut self.password);
                    let(tx,rx)=std::sync::mpsc::channel();self.worker=Some(rx);self.restore_review=None;
                    std::thread::spawn(move||{let _=tx.send(change_trial::recover(lab,id,user,password).map(|_|"Rückweg bestätigt, eigener Checkpoint entfernt.".into()).map_err(|_|"Rückweg nicht bestätigt. VM und Checkpoint müssen geprüft werden; weitere Versuche bleiben gesperrt.".into()));});
                }
                if ui.button("Rückweg verwerfen").clicked(){self.restore_review=None;}
            }
        });
        if self.busy() {
            ui.spinner();
            ui.label("Klonversuch läuft. Bei Abbruch bleibt der gespeicherte Auftrag zur Klärung erhalten.");
        }
        ui.label(&self.notice);
    }
}
fn mark(value: bool) -> &'static str {
    if value { "belegt" } else { "nicht belegt" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trial_panel_renders_without_starting_a_worker() {
        let ctx = egui::Context::default();
        let id = uuid::Uuid::new_v4().to_string();
        let journal = Journal {
            id: id.clone(),
            name: format!("Relayne-Lab-{id}"),
            template: String::new(),
            directory: String::new(),
            vm_id: uuid::Uuid::new_v4().to_string(),
            switch_id: String::new(),
            phase: "running".into(),
            detail: String::new(),
        };
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
                    egui::CentralPanel::default().show(ctx, |ui| state.draw(ui, &journal, false));
                },
            );
            assert!(!out.shapes.is_empty());
            assert!(!state.busy());
            assert!(state.review.is_none());
            assert!(state.store_error);
        }
    }
}
