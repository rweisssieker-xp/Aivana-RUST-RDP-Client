use super::*;
use crate::workflow::{self, Event, Journal, Package, Plan, Running};
use std::collections::BTreeMap;

fn preset(kind: usize) -> Plan {
    use crate::workflow::{Action, HttpMethod, Step, Target};
    let application = || Action::Http {
        url: "https://app.example.invalid/api/health".into(),
        method: HttpMethod::Get,
        form: BTreeMap::new(),
        secret_fields: BTreeMap::new(),
        status: 200,
        body_contains: None,
        json_equals: BTreeMap::from([("/status".into(), serde_json::json!("ok"))]),
    };
    let (name, action) = match kind {
        0 => (
            "HTTP sign-in and application check",
            Action::Http {
                url: "https://app.example.invalid/login".into(),
                method: HttpMethod::Post,
                form: BTreeMap::from([("username".into(), "ENTER_USERNAME".into())]),
                secret_fields: BTreeMap::from([("password".into(), "login_password".into())]),
                status: 200,
                body_contains: None,
                json_equals: BTreeMap::new(),
            },
        ),
        1 => (
            "SSH check and application test",
            Action::Ssh {
                target: Target {
                    host: "server.example.invalid".into(),
                    user: "ENTER_USERNAME".into(),
                    port: 22,
                },
                command: "uname -s".into(),
                stdout_contains: "Linux".into(),
            },
        ),
        _ => (
            "RDP checkpoint and application test",
            Action::RdpCheckpoint {
                target: "ENTER_RDP_PROFILE_OR_HOST".into(),
                expected: "Ready".into(),
            },
        ),
    };
    Plan {
        name: name.into(),
        preconditions: vec![],
        steps: vec![Step {
            name: match kind {
                0 => "Sign in and receive session cookie",
                1 => "Check operating system over SSH",
                _ => "Verify visible text at the RDP checkpoint",
            }
            .into(),
            action,
        }],
        verification: vec![Step {
            name: "Check application state".into(),
            action: application(),
        }],
        restore: vec![],
    }
}
fn plan_summary(ui: &mut Ui, plan: &Plan) {
    use crate::workflow::Action;
    ui.strong(&plan.name);
    for (label, steps) in [
        ("Voraussetzungen", &plan.preconditions),
        ("Steps", &plan.steps),
        ("Check", &plan.verification),
        ("Recovery · only after separate approval", &plan.restore),
    ] {
        egui::CollapsingHeader::new(format!("{label} ({})",steps.len())).id_salt(label).default_open(!steps.is_empty()).show(ui,|ui|{
            if steps.is_empty(){ui.label("No steps declared.");}
            for (index,step) in steps.iter().enumerate(){
                ui.group(|ui|{
                    ui.strong(format!("{}. {}",index+1,step.name));
                    match &step.action {
                        Action::RdpProcedure{target,procedure,parameters}=>{ui.label(format!("RDP procedure · {target}"));ui.monospace(serde_json::to_string_pretty(procedure).unwrap_or_default());ui.label(format!("Parameter slots: {}",serde_json::to_string(parameters).unwrap_or_default()));},
                        Action::Ssh{target,command,stdout_contains}=>{ui.label(format!("SSH · {}@{}:{}",target.user,target.host,target.port));ui.monospace(command);ui.label(format!("Expected: successful completion and output contains {stdout_contains:?}"));},
                        Action::WinRm{target,operation,stdout_contains}=>{ui.label(format!("WinRM · {} · integrated Windows authentication",target.host));ui.monospace(format!("{operation:?}"));ui.label(format!("Expected: successful completion and output contains {stdout_contains:?}"));},
                        Action::Http{url,method,form,secret_fields,status,body_contains,json_equals}=>{
                            ui.label(format!("HTTP {method:?} · {url}"));ui.label(format!("Expected: status {status}; no redirect"));
                            if !form.is_empty(){ui.label(format!("Fixed form values: {}",serde_json::to_string(form).unwrap_or_default()));}
                            if !secret_fields.is_empty(){ui.label(format!("Temporary secret slots: {}",serde_json::to_string(secret_fields).unwrap_or_default()));}
                            if let Some(expected)=body_contains{ui.label(format!("Response contains: {expected:?}"));}
                            for (pointer,value) in json_equals{ui.label(format!("JSON {pointer} = {value}"));}
                        },
                        Action::RdpCheckpoint{target,expected}=>{ui.label(format!("RDP · {target}"));ui.label(format!("Expected visible state / exact OCR word: {expected}"));ui.label("Manual confirmation or optional native OCR evidence in the selected matching RDP window. No automatic clicks.");}
                    }
                });
            }
        });
    }
}

pub struct WorkflowState {
    publisher_key: String,
    distribution_url: String,
    allow_unsigned: bool,
    download: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    editor: String,
    path: String,
    recipe_version: String,
    reviewed: Option<String>,
    secrets: String,
    message: String,
    running: Option<Running>,
    journal: Option<Journal>,
    history: Vec<Journal>,
    checkpoint: Option<(String, String, String)>,
    procedure: Option<(String, uuid::Uuid)>,
    evidence: String,
}
impl Default for WorkflowState {
    fn default() -> Self {
        let (journal, message) = match workflow::load_journal() {
            Ok(j) => (j, String::new()),
            Err(e) => (None, format!("Journal unavailable: {e}")),
        };
        Self {
            publisher_key: String::new(),
            distribution_url: String::new(),
            allow_unsigned: false,
            download: None,
            editor: serde_json::to_string_pretty(&workflow::example()).unwrap_or_default(),
            path: String::new(),
            recipe_version: "1.0.0".into(),
            reviewed: None,
            secrets: "{}".into(),
            message,
            running: None,
            journal,
            history: workflow::load_history().unwrap_or_default(),
            checkpoint: None,
            procedure: None,
            evidence: String::new(),
        }
    }
}
impl AivanaApp {
    pub(super) fn prepare_recorded_check_workflow(&mut self, plan: Plan) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.workflow.running.is_none() && self.workflow.download.is_none(),
            "Complete the active workflow or import first"
        );
        workflow::validate(&plan).map_err(anyhow::Error::msg)?;
        self.workflow.editor = serde_json::to_string_pretty(&plan)?;
        self.workflow.reviewed = None;
        self.workflow.secrets = "{}".into();
        self.workflow.checkpoint = None;
        self.workflow.evidence.clear();
        self.workflow.recipe_version = "1.0.0".into();
        self.workflow.message="Recorded visible checks prepared; review targets, assertions, and runtime slots before approval. Nothing executed.".into();
        self.view = View::Workflow;
        Ok(())
    }
    pub(super) fn prepare_teaching_workflow(
        &mut self,
        target: String,
        procedure: crate::teaching::Procedure,
    ) {
        if self.workflow.running.is_some() || self.workflow.download.is_some() {
            self.status = "Complete the active workflow first".into();
            return;
        }
        use crate::workflow::{Action, Step};
        let expected = procedure
            .expected_final
            .as_ref()
            .map(|a| a.label.clone())
            .unwrap_or_default();
        let parameters = procedure
            .steps
            .iter()
            .filter_map(|s| match s {
                crate::teaching::Step::Parameter { name } => Some((name.clone(), name.clone())),
                _ => None,
            })
            .collect();
        let plan = Plan {
            name: procedure.title.clone(),
            preconditions: vec![],
            steps: vec![Step {
                name: "Run the demonstrated workflow and verify after each step".into(),
                action: Action::RdpProcedure {
                    target: target.clone(),
                    procedure,
                    parameters,
                },
            }],
            verification: vec![Step {
                name: "Confirm the final state independently".into(),
                action: Action::RdpCheckpoint { target, expected },
            }],
            restore: vec![],
        };
        match workflow::validate(&plan) {
            Ok(()) => {
                self.workflow.editor = serde_json::to_string_pretty(&plan).unwrap_or_default();
                self.workflow.reviewed = None;
                self.workflow.message="Demonstration adopted. Review the target, workflow, and parameter slots, enter temporary values, and approve.".into();
                self.view = View::Workflow;
            }
            Err(e) => self.status = e,
        }
    }
    pub(super) fn workflow_checkpoint_request(&self) -> Option<(String, String, String)> {
        self.workflow.running.as_ref()?;
        let (token, target, expected) = self.workflow.checkpoint.as_ref()?;
        Some((token.clone(), target.clone(), expected.clone()))
    }
    pub(super) fn workflow_submit_ocr_evidence(&mut self, token: &str, evidence: String) -> bool {
        if evidence.is_empty()
            || evidence.len() > 4096
            || self
                .workflow
                .checkpoint
                .as_ref()
                .is_none_or(|(active, _, _)| active != token)
        {
            return false;
        }
        let Some(run) = &self.workflow.running else {
            return false;
        };
        if run.evidence.send((token.into(), evidence)).is_err() {
            return false;
        }
        self.workflow.checkpoint = None;
        true
    }
    pub(super) fn poll_workflow(&mut self, ctx: &Context) {
        if let Some((token, id)) = self.workflow.procedure.clone() {
            if self
                .workflow
                .running
                .as_ref()
                .is_none_or(|run| run.is_cancelled())
            {
                self.cancel_workflow_procedure(id);
                self.workflow.procedure = None;
            } else if let Some(result) = self.workflow_procedure_status(id) {
                if let Some(run) = &self.workflow.running {
                    let _ = run.evidence.send((
                        token,
                        if result.is_ok() {
                            "PROCEDURE_VERIFIED"
                        } else {
                            "PROCEDURE_FAILED"
                        }
                        .into(),
                    ));
                }
                self.workflow.procedure = None;
            }
        }
        let mut requested_procedure = None;
        let s = &mut self.workflow;
        if let Some(rx) = &s.download {
            match rx.try_recv() {
                Ok(result) => {
                    s.download = None;
                    match result.and_then(|text| {
                        crate::package_trust::TrustStore::load()
                            .and_then(|t| t.verify(&text))
                            .map_err(|e| e.to_string())
                    }) {
                        Ok(p) => {
                            s.editor = serde_json::to_string_pretty(&p.plan).unwrap_or_default();
                            s.recipe_version = p.recipe_version;
                            s.reviewed = None;
                            s.message="Signed package loaded and publisher verified; review targets and content before execution.".into()
                        }
                        Err(e) => s.message = e,
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    s.download = None;
                    s.message = "Paketdownload unterbrochen".into()
                }
                _ => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(100));
                }
            }
        }
        let mut done = false;
        if let Some(run) = &s.running {
            while let Ok(event) = run.events.try_recv() {
                match event {
                    Event::Procedure {
                        token,
                        target,
                        binding,
                        procedure,
                        values,
                    } => requested_procedure = Some((token, target, binding, procedure, values)),
                    Event::Journal(j) => s.journal = Some(j),
                    Event::Checkpoint {
                        token,
                        target,
                        expected,
                    } => s.checkpoint = Some((token, target, expected)),
                    Event::Done => done = true,
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if done {
            s.running = None;
            s.checkpoint = None;
            match workflow::load_history() {
                Ok(h) => s.history = h,
                Err(e) => s.message = e,
            }
        }
        if done {
            if let Some((_, id)) = self.workflow.procedure.take() {
                self.cancel_workflow_procedure(id);
            }
        } else if let Some((token, target, binding, procedure, values)) = requested_procedure
            .filter(|_| {
                self.workflow
                    .running
                    .as_ref()
                    .is_some_and(|run| !run.is_cancelled())
            })
        {
            match self.start_workflow_procedure(&target, procedure, values, binding) {
                Ok(id) => self.workflow.procedure = Some((token, id)),
                Err(_) => {
                    if let Some(run) = &self.workflow.running {
                        let _ = run.evidence.send((token, "PROCEDURE_FAILED".into()));
                    }
                }
            }
        }
    }
    pub(super) fn workflow_view(&mut self, ui: &mut Ui) {
        let s = &mut self.workflow;
        ui.heading("Workflows · Application checks · Repair packages");
        ui.label("SSH, WinRM, HTTP, and demonstrated RDP procedures in one reviewed workflow. Approval binds targets, checks, and recovery.");
        ui.label("Runtime secrets are not exported. Check commands and fixed form values for secrets before sharing. Import verifies the publisher signature by default and starts nothing.");
        ui.horizontal_wrapped(|ui|{
            ui.label("Prepare template:");
            for (kind,label) in [(0,"HTTP-Login + Anwendungstest"),(1,"SSH + HTTP check"),(2,"RDP/OCR + HTTP check")] {
                if ui.add_enabled(s.running.is_none() && s.download.is_none(),egui::Button::new(label)).clicked(){
                    s.editor=serde_json::to_string_pretty(&preset(kind)).unwrap_or_default();s.recipe_version="1.0.0".into();s.reviewed=None;s.secrets="{}".into();
                    s.message=match kind {
                        0=>"Template loaded; nothing started. Enter your HTTPS URLs, user, and expected response under Advanced plan. Set the password later as the temporary login_password slot. Host session cookies with explicit Path=/ are supported.",
                        1=>"Template loaded; nothing started. Enter the SSH target, user, command, expected output, and your HTTP check under Advanced plan. After approval, the template runs only uname -s.",
                        _=>"Template loaded; nothing started. Enter the RDP target (profile name, UUID, or host), an exact visible word, and your HTTP check under Advanced plan. Trigger OCR evidence after reaching the checkpoint in the matching connected RDP window.",
                    }.into();
                }
            }
        });
        ui.horizontal(|ui|{
            ui.label("Package file (.json)");ui.text_edit_singleline(&mut s.path);
            if ui.add_enabled(s.running.is_none() && s.download.is_none(),egui::Button::new("Import")).clicked(){
                let result=(||->Result<Package,String>{
                    let meta=std::fs::metadata(&s.path).map_err(|e|e.to_string())?;
                    if meta.len()>512*1024{return Err("Package exceeds 512 KiB".into());}
                    let text=std::fs::read_to_string(&s.path).map_err(|e|e.to_string())?;
                    match crate::package_trust::TrustStore::load().and_then(|t|t.verify(&text)){Ok(p)=>Ok(p),Err(e)=>if s.allow_unsigned{Package::import(&text)}else{Err(e.to_string())}}
                })();
                match result {Ok(p)=>{s.editor=serde_json::to_string_pretty(&p.plan).unwrap_or_default();s.recipe_version=p.recipe_version.clone();s.reviewed=None;s.message=format!("Imported, not started · Recipe {} · Package origin claim: {} · SHA-256 {}",p.recipe_version,p.provenance,p.sha256);},Err(e)=>s.message=e}
            }
            if ui.button("Export package").clicked(){
                let result=(||->Result<(),String>{
                    let p:Plan=serde_json::from_str(&s.editor).map_err(|e|e.to_string())?;
                    let package=Package::new_version(p,"Signed with the local Relayne publisher key".into(),s.recipe_version.clone())?;
                    let text=crate::package_trust::sign(&package).map_err(|e|e.to_string())?;
                    // Never overwrite a file silently.
                    let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(&s.path).map_err(|e|e.to_string())?;
                    std::io::Write::write_all(&mut f,text.as_bytes()).map_err(|e|e.to_string())
                })();s.message=match result{Ok(())=>"Package exported; inspect literal form fields and commands for embedded secrets before sharing".into(),Err(e)=>e};
            }
        });
        ui.collapsing("Publisher signatures and trusted distribution",|ui|{
            ui.label("An Ed25519 signature and explicitly enrolled public key are required. Compare the fingerprint through an independent trusted channel.");
            if ui.button("Create local signing key once").clicked(){s.message=match crate::package_trust::create_key(){Ok(k)=>{s.publisher_key=k;"Private key saved with Windows DPAPI; add the public key to the trust list.".into()},Err(e)=>e.to_string()};}
            if ui.button("Show own public key").clicked(){match crate::package_trust::public_key(){Ok(k)=>s.publisher_key=k,Err(e)=>s.message=e.to_string()}}
            ui.add(egui::TextEdit::singleline(&mut s.publisher_key).hint_text("Public Ed25519 key (Base64)").desired_width(f32::INFINITY));
            if let Ok(id)=crate::package_trust::fingerprint(&s.publisher_key){ui.monospace(format!("SHA-256: {id}"));}
            if ui.button("Trust this reviewed publisher key").clicked(){s.message=match crate::package_trust::TrustStore::load().and_then(|mut t|{let id=t.enroll(&s.publisher_key)?;t.save()?;Ok(id)}){Ok(id)=>format!("Publisher enrolled: {id}"),Err(e)=>e.to_string()};}
            match crate::package_trust::TrustStore::load(){Ok(mut trust)=>{for id in trust.publishers.keys().cloned().collect::<Vec<_>>(){ui.horizontal_wrapped(|ui|{ui.monospace(&id);if ui.small_button("Revoke trust").clicked(){trust.publishers.remove(&id);s.message=match trust.save(){Ok(())=>"Trust revoked; future package imports blocked.".into(),Err(e)=>e.to_string()};}});}},Err(e)=>{ui.label(e.to_string());}}
            ui.checkbox(&mut s.allow_unsigned,"Explicitly allow unsigned drafts for this local import");
            ui.add(egui::TextEdit::singleline(&mut s.distribution_url).hint_text("HTTPS address of a signed package").desired_width(f32::INFINITY));
            if ui.add_enabled(s.running.is_none() && s.download.is_none()&&s.download.is_none(),egui::Button::new("Download and verify signed package")).clicked(){
                let url=s.distribution_url.clone();let(tx,rx)=std::sync::mpsc::channel();s.download=Some(rx);std::thread::spawn(move||{let result=(||->anyhow::Result<String>{use std::io::Read;let u=reqwest::Url::parse(&url)?;anyhow::ensure!(u.scheme()=="https"&&u.username().is_empty()&&u.password().is_none()&&u.query().is_none()&&u.fragment().is_none(),"HTTPS without credentials, query, or fragment required");let response=reqwest::blocking::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(20)).build()?.get(u).send()?;anyhow::ensure!(response.status().as_u16()==200,"Package server did not return HTTP 200");let mut b=vec![];response.take(512*1024+1).read_to_end(&mut b)?;anyhow::ensure!(b.len()<=512*1024,"Package is too large");Ok(String::from_utf8(b)? )})();let _=tx.send(result.map_err(|_|"Package download failed; check TLS, status, or size limit".into()));});
            }
        });
        ui.horizontal(|ui| {
            ui.label("Recipe version (MAJOR.MINOR.PATCH)");
            ui.add_enabled(
                s.running.is_none() && s.download.is_none(),
                egui::TextEdit::singleline(&mut s.recipe_version).desired_width(110.0),
            );
        });
        match serde_json::from_str::<Plan>(&s.editor) {
            Ok(plan) => {
                egui::ScrollArea::vertical()
                    .id_salt("workflow_summary")
                    .max_height(330.0)
                    .show(ui, |ui| plan_summary(ui, &plan));
            }
            Err(_) => {
                ui.label("Plan cannot be read yet. Correct JSON in Advanced plan.");
            }
        }
        egui::CollapsingHeader::new("Advanced plan · JSON bearbeiten")
            .id_salt("workflow_advanced")
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("workflow_editor")
                    .max_height(280.0)
                    .show(ui, |ui| {
                        if ui
                            .add_enabled(
                                s.running.is_none() && s.download.is_none(),
                                egui::TextEdit::multiline(&mut s.editor)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(12),
                            )
                            .changed()
                        {
                            s.reviewed = None;
                        }
                    });
            });
        ui.horizontal(|ui|{
            if ui.add_enabled(s.running.is_none() && s.download.is_none(),egui::Button::new("Validate and review plan")).clicked(){
                let result=serde_json::from_str::<Plan>(&s.editor).map_err(|e|e.to_string()).and_then(|p|workflow::review_digest(&p));
                match result {Ok(d)=>{s.reviewed=Some(d);s.message="Review commands, all endpoints, expected results and compensation in the plan above, then run explicitly.".into();},Err(e)=>{s.reviewed=None;s.message=e;}}
            }
            if ui.add_enabled(s.running.is_none() && s.download.is_none(),egui::Button::new("Prepare recovery for review")).clicked(){
                match serde_json::from_str::<Plan>(&s.editor){
                    Ok(mut p) if !p.restore.is_empty()=>{p.name=format!("Restore: {}",p.name);p.steps=std::mem::take(&mut p.restore);s.editor=serde_json::to_string_pretty(&p).unwrap_or_default();s.reviewed=None;s.message="Restore prepared. Review preconditions and verification for the restored state before running.".into();},
                    _=>s.message="No declared restore steps in this plan".into()
                }
            }
        });
        if let Some(d) = &s.reviewed {
            ui.monospace(format!("Reviewed SHA-256: {d}"));
        }
        ui.label("Temporary secrets as JSON (for example {\"login_password\":\"...\"}), for HTTP sign-ins and procedure parameters; no export or journal.");
        ui.add_enabled(
            s.running.is_none() && s.download.is_none(),
            egui::TextEdit::singleline(&mut s.secrets)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    s.running.is_none() && s.download.is_none() && s.reviewed.is_some(),
                    egui::Button::new("Approve reviewed targets and start"),
                )
                .clicked()
            {
                let result = (|| -> Result<Running, String> {
                    let p: Plan = serde_json::from_str(&s.editor).map_err(|e| e.to_string())?;
                    let secrets: BTreeMap<String, String> = serde_json::from_str(&s.secrets)
                        .map_err(|_| "Secret slots must be a JSON object of strings".to_string())?;
                    workflow::start_with_profiles(
                        p,
                        s.reviewed.as_deref().ok_or("Review required")?,
                        secrets,
                        &self.profiles,
                    )
                })();
                match result {
                    Ok(run) => {
                        s.running = Some(run);
                        s.secrets = "{}".into();
                        s.reviewed = None;
                        s.message = "Approved workflow is running".into();
                    }
                    Err(e) => s.message = e,
                }
            }
            if ui
                .add_enabled(
                    s.running.is_some(),
                    egui::Button::new("Cancel · wait for the current request"),
                )
                .clicked()
            {
                if let Some(run) = &s.running {
                    run.cancel();
                }
            }
        });
        if let Some((token, target, expected)) = &s.checkpoint {
            ui.separator();
            ui.strong(format!("Manual RDP checkpoint · {target}"));
            ui.label(expected);
            ui.label("Perform and verify in the native desktop. Enter the observation as evidence; this is manual confirmation.");
            ui.text_edit_singleline(&mut s.evidence);
            if ui
                .add_enabled(
                    !s.evidence.trim().is_empty() && s.evidence.len() <= 4000,
                    egui::Button::new("Confirm observed result"),
                )
                .clicked()
            {
                if let Some(run) = &s.running {
                    let _ = run.evidence.send((
                        token.clone(),
                        format!("Operator attestation: {}", std::mem::take(&mut s.evidence)),
                    ));
                }
                s.checkpoint = None;
            }
        }
        if !s.message.is_empty() {
            ui.label(&s.message);
        }
        if let Some(j) = &s.journal {
            ui.separator();
            ui.strong(format!("{} · {} steps completed", j.state, j.completed));
            ui.monospace(format!("Run {} · {}", j.run_id, j.at));
            egui::ScrollArea::vertical()
                .id_salt("workflow_journal")
                .max_height(190.0)
                .show(ui, |ui| {
                    for event in &j.events {
                        ui.label(event);
                    }
                });
        }
        if self
            .workflow
            .running
            .as_ref()
            .is_some_and(|run| run.is_cancelled())
        {
            if let Some((_, id)) = self.workflow.procedure.take() {
                self.cancel_workflow_procedure(id);
            }
        }
    }
    pub(super) fn workflow_incident_records(&self) -> Vec<crate::incident::Record> {
        let mut records: Vec<_> = self
            .workflow
            .history
            .iter()
            .flat_map(|j| j.records.iter().cloned())
            .collect();
        if let Some(j) = &self.workflow.journal {
            records.extend(j.records.iter().cloned());
        }
        crate::incident::normalize(records)
    }
}
