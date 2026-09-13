use super::*;
use crate::test_lab::{self, Action, Journal};
#[derive(Default)]
pub(super) struct TestLabState {
    trial: super::change_trial_panel::State,
    template: String,
    user: String,
    password: String,
    service: String,
    desired_running: bool,
    health_enabled: bool,
    health: test_lab::HealthProbe,
    labs: Vec<Journal>,
    selected: Option<usize>,
    notice: String,
    review: Option<(Action, Option<Journal>)>,
    worker: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    initialized: bool,
}
impl AivanaApp {
    pub(super) fn poll_test_lab(&mut self) {
        if let Some(rx) = &self.test_lab.worker {
            match rx.try_recv() {
                Ok(result) => {
                    self.test_lab.worker = None;
                    self.test_lab.notice = result.unwrap_or_else(|e| e);
                    match test_lab::journals() {
                        Ok(l) => self.test_lab.labs = l,
                        Err(e) => self.test_lab.notice.push_str(&format!("\nJournal: {e:#}")),
                    };
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.test_lab.worker = None;
                    self.test_lab.notice = "Lab-Worker unerwartet beendet; Journal prüfen".into();
                }
                _ => {}
            }
        }
    }
    pub(super) fn test_lab_view(&mut self, ui: &mut Ui) {
        self.poll_test_lab();
        let state = &mut self.test_lab;
        if !state.initialized {
            state.initialized = true;
            state.service = "Spooler".into();
            state.desired_running = true;
            state.health = test_lab::HealthProbe {
                url: "http://127.0.0.1:8080/health".into(),
                expected_status: 200,
                body_marker: String::new(),
                followups: vec![],
            };
            match test_lab::journals() {
                Ok(l) => state.labs = l,
                Err(e) => state.notice = format!("Journal: {e:#}"),
            };
        }
        ui.heading("Isoliertes Hyper-V-Testlabor");
        ui.label("Generation 2 · 2 GB RAM · eigener privater Switch · differenzierende VHDX. Windows-Gast mit PowerShell Direct und lokalem Gastkonto erforderlich.");
        ui.label("Vorlage: offline, keinem bestehenden VM-Laufwerk zugeordnet, eigenständige VHDX mit Schreibschutz. Den Eltern-Datenträger unverändert lassen, solange ein Lab besteht.");
        ui.add_enabled_ui(state.worker.is_none() && !state.trial.busy(),|ui| {
   if ui.button("Host-Voraussetzungen prüfen (nur lesen)").clicked(){state.review=Some((Action::Preflight,None));}
   ui.horizontal(|ui|{ui.label("Offline-Vorlage VHDX");ui.text_edit_singleline(&mut state.template);});
   if ui.button("Neues Lab vorbereiten …").clicked(){match test_lab::new_lab(&state.template){Ok(j)=>state.review=Some((Action::Create,Some(j))),Err(e)=>state.notice=format!("{e:#}")};}
   ui.separator();
   if ui.button("Journale neu laden").clicked(){match test_lab::journals(){Ok(l)=>{state.labs=l;state.selected=None;},Err(e)=>state.notice=format!("{e:#}")};}
   for (i,j) in state.labs.iter().enumerate(){if ui.selectable_label(state.selected==Some(i),format!("{} · {}",j.name,j.phase)).clicked(){state.selected=Some(i);}}
   if let Some(j)=state.selected.and_then(|i|state.labs.get(i)).cloned(){
    ui.label(format!("VM-ID: {}\nSwitch-ID: {}\n{}\n{}",j.vm_id,j.switch_id,j.directory,j.detail));
    ui.horizontal(|ui|{ui.label("Gastbenutzer");ui.text_edit_singleline(&mut state.user);});
    ui.horizontal(|ui|{ui.label("Gastpasswort (nur dieser Test)");ui.add(egui::TextEdit::singleline(&mut state.password).password(true));});
    ui.horizontal(|ui|{ui.label("Gastdienst für Generalprobe");ui.text_edit_singleline(&mut state.service);});
    ui.checkbox(&mut state.desired_running,"Gewünschter Zustand: läuft (sonst gestoppt)");
    ui.checkbox(&mut state.health_enabled,"HTTP-Funktionsprüfung im Gast nach Dienständerung");
    if state.health_enabled {ui.horizontal(|ui|{ui.label("Loopback-URL");ui.text_edit_singleline(&mut state.health.url);});ui.horizontal(|ui|{ui.label("HTTP-Status");ui.add(egui::DragValue::new(&mut state.health.expected_status).range(100..=599));ui.label("Text muss enthalten sein (optional)");ui.text_edit_singleline(&mut state.health.body_marker);});}
    if ui.add_enabled(!j.vm_id.is_empty(),egui::Button::new("Dienständerung im Klon proben …")).clicked(){state.review=Some((Action::Test,Some(j.clone())));}
    if ui.add_enabled(j.phase!="cleaned",egui::Button::new("Dieses Lab aufräumen …")).clicked(){state.review=Some((Action::Cleanup,Some(j)));}
   }
   if let Some((action,j))=state.review.clone(){
    ui.separator();ui.strong("Ausführung prüfen");
    ui.label(match action{Action::Preflight=>"Hyper-V-Modul, Administratorrechte, VMMS und PowerShell-Direct-Unterstützung lesen.",Action::Create=>"Privaten Switch, Kind-VHDX und neue VM anlegen; VM starten. Keine Netzwerkverbindung zum Host oder Produktionsnetz.",Action::Test=>"Den Gastdienst starten/stoppen, den Zielzustand prüfen und optional den lokalen HTTP-Endpunkt abrufen. Bei Fehler ursprünglichen Dienstzustand wiederherstellen. Erfolgreiche Änderungen bleiben im Klon.",Action::Cleanup=>"Nach Besitzprüfung ausschließlich diese VM hart ausschalten, entfernen, ihren privaten Switch und ihre Kind-VHDX löschen. Journal und Restverzeichnisse bleiben erhalten."});
    if action==Action::Test {ui.label(format!("Dienst: {} · Ziel: {}",state.service,if state.desired_running{"Running"}else{"Stopped"}));}
    if action==Action::Test && state.health_enabled {ui.label(format!("HTTP GET {} · Status {} · Text: {}",state.health.url,state.health.expected_status,state.health.body_marker));}
    if let Some(j)=&j{ui.label(format!("{}\nVorlage: {}\nZiel: {}",j.name,j.template,j.directory));}
    ui.horizontal(|ui|{
     if ui.button("Jetzt ausführen").clicked(){
      let (tx,rx)=std::sync::mpsc::channel();state.worker=Some(rx);state.review=None;
      let user=state.user.clone();let password=std::mem::take(&mut state.password);let service=state.service.clone();let desired_running=state.desired_running;let health=if state.health_enabled{state.health.clone()}else{test_lab::HealthProbe::default()};
      std::thread::spawn(move||{let _=tx.send(test_lab::execute(action,j,user,password,service,desired_running,health).map_err(|e|format!("{e:#}")));});
     }
     if ui.button("Verwerfen").clicked(){state.review=None;}
    });
   }
  });
        if state.worker.is_some() {
            ui.spinner();
            ui.label(
                "Lab-Aktion läuft (max. 180 Sekunden). Bei Abbruch Journal und Ressourcen prüfen.",
            );
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
        ui.separator();
        ui.label(&state.notice);
        if let Some(journal) = state.selected.and_then(|i| state.labs.get(i)).cloned() {
            state.trial.draw(ui, &journal, state.worker.is_some());
        } else {
            ui.separator();
            ui.heading("Änderung & Fehler im Klon erproben");
            ui.label("Wähle einen laufenden Relayne-Klon, um eine Starttypänderung, einen gezielten Dienstausfall und den Rückweg per Checkpoint zu prüfen.");
        }
    }
}
