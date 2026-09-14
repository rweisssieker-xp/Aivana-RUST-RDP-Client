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
                self.notice = "Trial storage cannot be read; new trials are blocked".into();
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
                    self.notice = "Trial interrupted. Check the saved rollback.".into();
                    self.reload(&journal.id);
                }
                Err(_) => {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(200));
                }
            }
        }
        ui.separator();
        ui.heading("Test changes and failures in a clone");
        ui.label("Change an application service startup type → check HTTP → stop the service and verify the failure → start the service → restore the checkpoint and verify the initial state.");
        ui.label("This isolated clone only. Initial version: Automatic ↔ Manual, one public HTTP check, no updates or arbitrary scripts. A passing test does not demonstrate startup after an operating system restart.");
        ui.label("Requires standard checkpoints with memory and a clone without existing checkpoints. New Relayne clones are configured accordingly; check older clones in Hyper-V Manager.");
        ui.add_enabled_ui(!self.busy() && !lab_busy, |ui| {
            if ui.button("Load trial evidence").clicked(){self.reload(&journal.id);}
            ui.horizontal(|ui|{ui.label("Application service");ui.text_edit_singleline(&mut self.service);});
            ui.horizontal(|ui|{ui.label("New startup type");ui.selectable_value(&mut self.startup,Startup::Automatic,"Automatic");ui.selectable_value(&mut self.startup,Startup::Manual,"Manual");});
            ui.horizontal(|ui|{ui.label("Loopback HTTP URL");ui.text_edit_singleline(&mut self.health.url);});
            ui.horizontal(|ui|{ui.label("Expected status");ui.add(egui::DragValue::new(&mut self.health.expected_status).range(100..=599));ui.label("Text in result");ui.text_edit_singleline(&mut self.health.body_marker);});
            ui.horizontal(|ui|{ui.label("Guest user for trial/rollback");ui.text_edit_singleline(&mut self.user);});
            ui.horizontal(|ui|{ui.label("Guest password (this run only)");ui.add(egui::TextEdit::singleline(&mut self.password).password(true));});
            let blocked=self.store_error || self.records.iter().any(Record::unresolved) || self.records.len()>=100;
            if ui.add_enabled(!blocked,egui::Button::new("Prepare trial …")).clicked(){
                let spec=Spec{service:self.service.trim().into(),startup:self.startup,health:self.health.clone()};
                match spec.validate(){Ok(())=>{self.review=Some((journal.clone(),spec));self.restore_review=None;},Err(e)=>self.notice=e.to_string()}
            }
            if blocked {ui.label("An unresolved trial or a storage problem blocks further changes in this clone.");}
            if let Some((lab,spec))=self.review.clone(){
                ui.group(|ui|{
                    ui.strong("Run reviewed selection");
                    ui.label(format!("Clone: {} · VM {}\nService: {} → {}\nHTTP: {} · Status {} · Text: {}",lab.name,lab.vm_id,spec.service,spec.startup.label(),spec.health.url,spec.health.expected_status,spec.health.body_marker));
                    ui.label("Creates a checkpoint and a real service outage in the clone. Rollback discards all changes since the checkpoint. Do not use this clone concurrently during the trial.");
                    ui.horizontal(|ui|{
                        if ui.add_enabled(!blocked && !self.user.trim().is_empty() && !self.password.is_empty(),egui::Button::new("Run this clone trial now")).clicked(){
                            let user=self.user.clone();let password=std::mem::take(&mut self.password);
                            let(tx,rx)=std::sync::mpsc::channel();self.worker=Some(rx);self.review=None;
                            std::thread::spawn(move||{let result=change_trial::run(lab,spec,user,password).map(|record|{
                                if record.proof.as_ref().is_some_and(|p|p.passed()){"Change, failure, repair, and rollback verified.".into()}
                                else if record.unresolved(){"Trial failed; rollback unresolved. Restore the saved checkpoint.".into()}
                                else{"Trial failed. Clone unchanged or rollback confirmed; review the phases in the evidence.".into()}
                            }).map_err(|_|"Trial incomplete. Load the evidence and check the rollback.".into());let _=tx.send(result);});
                        }
                        if ui.button("Discard preview").clicked(){self.review=None;}
                    });
                });
            }
            ui.strong("Saved trials");
            for record in &self.records {
                ui.group(|ui|{
                    ui.label(format!("{} · {} · {} → {}",record.request.started.format("%m/%d/%Y %H:%M UTC"),record.request.id,record.request.spec.service,record.request.spec.startup.label()));
                    if let Some(p)=&record.proof {
                        ui.label(format!("Baseline {} · Change {} · Outage {} · Repair {} · Rollback {}",mark(p.baseline),mark(p.changed),mark(p.fault_observed),mark(p.repaired),mark(p.returned)));
                        ui.label(if p.passed(){"Passed — historical clone evidence, no production approval"}else{"Failed"});
                        if p.untouched{ui.label("Stopped before making a change; clone unchanged.");}
                    }else{ui.label("No completion evidence; state unresolved.");}
                    if record.recovered{ui.label("Rollback confirmed separately; trial still has no evidence of success.");}
                    if record.unresolved() && ui.button(format!("Prepare rollback for {} …",record.request.id)).clicked(){self.restore_review=Some(record.request.id);self.review=None;}
                });
            }
            if let Some(id)=self.restore_review {
                ui.label(format!("Restore checkpoint Relayne-Trial-{id} and check HTTP and startup type. Changes in the clone since this checkpoint will be discarded."));
                if ui.add_enabled(!self.user.trim().is_empty() && !self.password.is_empty(),egui::Button::new("Run saved rollback now")).clicked(){
                    let lab=journal.clone();let user=self.user.clone();let password=std::mem::take(&mut self.password);
                    let(tx,rx)=std::sync::mpsc::channel();self.worker=Some(rx);self.restore_review=None;
                    std::thread::spawn(move||{let _=tx.send(change_trial::recover(lab,id,user,password).map(|_|"Rollback confirmed; trial checkpoint removed.".into()).map_err(|_|"Rollback not confirmed. Check the VM and checkpoint; further trials remain blocked.".into()));});
                }
                if ui.button("Discard rollback").clicked(){self.restore_review=None;}
            }
        });
        if self.busy() {
            ui.spinner();
            ui.label("Clone trial running. If canceled, the saved job remains available for investigation.");
        }
        ui.label(&self.notice);
    }
}
fn mark(value: bool) -> &'static str {
    if value { "verified" } else { "not verified" }
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
