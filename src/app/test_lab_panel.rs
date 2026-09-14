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
                    self.test_lab.notice = "Lab worker ended unexpectedly; check the journal".into();
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
        ui.heading("Isolated Hyper-V test lab");
        ui.label("Generation 2 · 2 GB RAM · dedicated private switch · differencing VHDX. Requires a Windows guest with PowerShell Direct and a local guest account.");
        ui.label("Template: offline, not attached to an existing VM drive, standalone read-only VHDX. Keep the parent disk unchanged while a lab exists.");
        ui.add_enabled_ui(state.worker.is_none() && !state.trial.busy(),|ui| {
   if ui.button("Check host prerequisites (read-only)").clicked(){state.review=Some((Action::Preflight,None));}
   ui.horizontal(|ui|{ui.label("Offline VHDX template");ui.text_edit_singleline(&mut state.template);});
   if ui.button("Prepare new lab …").clicked(){match test_lab::new_lab(&state.template){Ok(j)=>state.review=Some((Action::Create,Some(j))),Err(e)=>state.notice=format!("{e:#}")};}
   ui.separator();
   if ui.button("Reload journals").clicked(){match test_lab::journals(){Ok(l)=>{state.labs=l;state.selected=None;},Err(e)=>state.notice=format!("{e:#}")};}
   for (i,j) in state.labs.iter().enumerate(){if ui.selectable_label(state.selected==Some(i),format!("{} · {}",j.name,j.phase)).clicked(){state.selected=Some(i);}}
   if let Some(j)=state.selected.and_then(|i|state.labs.get(i)).cloned(){
    ui.label(format!("VM-ID: {}\nSwitch-ID: {}\n{}\n{}",j.vm_id,j.switch_id,j.directory,j.detail));
    ui.horizontal(|ui|{ui.label("Guest user");ui.text_edit_singleline(&mut state.user);});
    ui.horizontal(|ui|{ui.label("Guest password (this test only)");ui.add(egui::TextEdit::singleline(&mut state.password).password(true));});
    ui.horizontal(|ui|{ui.label("Guest service for rehearsal");ui.text_edit_singleline(&mut state.service);});
    ui.checkbox(&mut state.desired_running,"Desired state: running (otherwise stopped)");
    ui.checkbox(&mut state.health_enabled,"HTTP functional check in the guest after service change");
    if state.health_enabled {ui.horizontal(|ui|{ui.label("Loopback URL");ui.text_edit_singleline(&mut state.health.url);});ui.horizontal(|ui|{ui.label("HTTP status");ui.add(egui::DragValue::new(&mut state.health.expected_status).range(100..=599));ui.label("Required text (optional)");ui.text_edit_singleline(&mut state.health.body_marker);});}
    if ui.add_enabled(!j.vm_id.is_empty(),egui::Button::new("Rehearse service change in clone …")).clicked(){state.review=Some((Action::Test,Some(j.clone())));}
    if ui.add_enabled(j.phase!="cleaned",egui::Button::new("Clean up this lab …")).clicked(){state.review=Some((Action::Cleanup,Some(j)));}
   }
   if let Some((action,j))=state.review.clone(){
    ui.separator();ui.strong("Review execution");
    ui.label(match action{Action::Preflight=>"Check the Hyper-V module, administrator privileges, VMMS, and PowerShell Direct support.",Action::Create=>"Create a private switch, child VHDX, and new VM; start the VM. No network connection to the host or production network.",Action::Test=>"Start/stop the guest service, verify the target state, and optionally fetch the local HTTP endpoint. Restore the original service state on failure. Successful changes remain in the clone.",Action::Cleanup=>"After verifying ownership, forcibly turn off and remove only this VM, and delete its private switch and child VHDX. The journal and remaining directories are retained."});
    if action==Action::Test {ui.label(format!("Service: {} · Target: {}",state.service,if state.desired_running{"Running"}else{"Stopped"}));}
    if action==Action::Test && state.health_enabled {ui.label(format!("HTTP GET {} · Status {} · Text: {}",state.health.url,state.health.expected_status,state.health.body_marker));}
    if let Some(j)=&j{ui.label(format!("{}\nTemplate: {}\nTarget: {}",j.name,j.template,j.directory));}
    ui.horizontal(|ui|{
     if ui.button("Run now").clicked(){
      let (tx,rx)=std::sync::mpsc::channel();state.worker=Some(rx);state.review=None;
      let user=state.user.clone();let password=std::mem::take(&mut state.password);let service=state.service.clone();let desired_running=state.desired_running;let health=if state.health_enabled{state.health.clone()}else{test_lab::HealthProbe::default()};
      std::thread::spawn(move||{let _=tx.send(test_lab::execute(action,j,user,password,service,desired_running,health).map_err(|e|format!("{e:#}")));});
     }
     if ui.button("Discard").clicked(){state.review=None;}
    });
   }
  });
        if state.worker.is_some() {
            ui.spinner();
            ui.label(
                "Lab action running (up to 180 seconds). If canceled, check the journal and resources.",
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
            ui.heading("Test changes and failures in a clone");
            ui.label("Select a running Relayne clone to test a startup type change, a deliberate service outage, and checkpoint rollback.");
        }
    }
}
