use super::*;
use crate::repair_approval::{DecideRepairApproval, RepairApproval, RepairDecision, RepairState};
use crate::team_client::TeamClient;
use crate::team_server::{Audit, IssuedToken, Role, SharedItem, Snapshot, TokenInfo, TokenRequest};
use std::sync::mpsc;

pub(super) struct TeamState {
    pub(super) endpoint: String,
    pub(super) token: String,
    pub(super) snapshot: Option<Snapshot>,
    pub(super) live: super::collaboration_panel::CollaborationState,
    login_options: crate::team_client::login::LoginOptions,
    login: Option<crate::team_client::login::LoginFlow>,
    selected: Option<Uuid>,
    workspace_name: String,
    handoff_name: String,
    handoff_note: String,
    edit: Option<SharedItem>,
    actor: String,
    role: Role,
    issued: Option<IssuedToken>,
    tokens: Vec<TokenInfo>,
    audit: Vec<Audit>,
    repairs: Vec<RepairApproval>,
    repairs_loaded: bool,
    repairs_offset: usize,
    pending: Option<mpsc::Receiver<Result<TeamResult, String>>>,
    message: String,
    repair_identity_generation: Uuid,
}
enum TeamResult {
    State(Snapshot),
    Saved(SharedItem),
    Issued(IssuedToken),
    Admin(Vec<TokenInfo>, Vec<Audit>),
    Revoked,
    Repairs(usize, Vec<RepairApproval>),
    RepairDecision(RepairApproval),
}
impl Default for TeamState {
    fn default() -> Self {
        Self {
            live: Default::default(),
            login_options: Default::default(),
            login: None,
            endpoint: "http://127.0.0.1:47831".into(),
            token: String::new(),
            snapshot: None,
            selected: None,
            workspace_name: String::new(),
            handoff_name: String::new(),
            handoff_note: String::new(),
            edit: None,
            actor: String::new(),
            role: Role::Viewer,
            issued: None,
            tokens: vec![],
            audit: vec![],
            repairs: vec![],
            repairs_loaded: false,
            repairs_offset: 0,
            pending: None,
            message: String::new(),
            repair_identity_generation: Uuid::new_v4(),
        }
    }
}
impl TeamState {
    pub(super) fn repair_client(&self) -> anyhow::Result<(TeamClient, Uuid, String)> {
        let client = TeamClient::new(&self.endpoint, &self.token)?;
        Ok((
            client,
            self.repair_identity_generation,
            self.endpoint.trim().trim_end_matches('/').to_owned(),
        ))
    }
    pub(super) fn repair_generation(&self) -> Uuid {
        self.repair_identity_generation
    }
    fn invalidate_repair_identity(&mut self) {
        self.repair_identity_generation = Uuid::new_v4();
    }
    fn clear_repair_history(&mut self) {
        self.repairs.clear();
        self.repairs_loaded = false;
        self.repairs_offset = 0;
    }
    fn load_repairs(&mut self, offset: usize) {
        if offset > 1000 || self.pending.is_some() {
            return;
        }
        self.clear_repair_history();
        self.start(move |client| Ok(TeamResult::Repairs(offset, client.list_repairs(offset)?)));
    }
    fn start(
        &mut self,
        work: impl FnOnce(TeamClient) -> anyhow::Result<TeamResult> + Send + 'static,
    ) {
        if self.pending.is_some() {
            return;
        }
        match TeamClient::new(&self.endpoint, &self.token) {
            Err(e) => self.message = e.to_string(),
            Ok(client) => {
                let (tx, rx) = mpsc::channel();
                self.pending = Some(rx);
                self.message = "Team request running …".into();
                std::thread::spawn(move || {
                    let _ = tx.send(work(client).map_err(|e| e.to_string()));
                });
            }
        }
    }
}

fn repair_state_label(state: RepairState) -> &'static str {
    match state {
        RepairState::Pending => "Pending decision",
        RepairState::Approved => "Approved; not yet consumed",
        RepairState::Consumed => "Consumed for one Apply attempt",
        RepairState::Expired => "Expired",
        RepairState::Denied => "Denied",
    }
}

fn visible_repair_state(item: &RepairApproval) -> RepairState {
    if item.expires_at <= chrono::Utc::now()
        && matches!(item.state, RepairState::Pending | RepairState::Approved)
    {
        RepairState::Expired
    } else {
        item.state
    }
}

fn visible_repair_label(item: &RepairApproval) -> &'static str {
    if item.state != RepairState::Expired && visible_repair_state(item) == RepairState::Expired {
        "Deadline passed locally; reload to confirm recorded expiry"
    } else {
        repair_state_label(item.state)
    }
}

fn repair_role_summary(role: &Role) -> &'static str {
    match role {
        Role::Viewer => {
            "Viewer: read shared records; cannot request, decide, or consume repair approvals."
        }
        Role::Operator => {
            "Operator: may request and decide for a different actor; server checks current role and exact binding before consume."
        }
        Role::Admin => {
            "Admin: operator repair rights plus token administration and metadata audit access."
        }
    }
}

fn can_decide_repair(role: &Role, actor: &str, item: &RepairApproval) -> bool {
    *role != Role::Viewer
        && visible_repair_state(item) == RepairState::Pending
        && item.requester != actor
}

fn abbreviated_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(12).collect()
}

#[cfg(test)]
mod repair_status_tests {
    use super::*;

    #[test]
    fn every_server_state_has_a_distinct_operator_label() {
        let states = [
            RepairState::Pending,
            RepairState::Approved,
            RepairState::Consumed,
            RepairState::Expired,
            RepairState::Denied,
        ];
        let labels: std::collections::HashSet<_> =
            states.into_iter().map(repair_state_label).collect();
        assert_eq!(labels.len(), states.len());
        assert!(repair_state_label(RepairState::Consumed).contains("one Apply"));
    }

    #[test]
    fn decision_controls_require_nonviewer_different_actor_and_pending_state() {
        let mut item = RepairApproval {
            id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            binding: crate::repair_approval::RepairBinding {
                version: 1,
                run_id: Uuid::new_v4(),
                target_index: 0,
                profile_id: Uuid::new_v4(),
                plan_sha256: String::new(),
                target_sha256: String::new(),
                service: String::new(),
                before: crate::repair_approval::RepairServiceState::Stopped,
                desired: crate::repair_approval::RepairServiceState::Running,
                captured_at: chrono::Utc::now(),
                baseline_passed: false,
                baseline_sha256: String::new(),
                health_sha256: String::new(),
                proof: crate::repair_approval::RepairProof {
                    kind: crate::repair_approval::ProofKind::Rehearsal,
                    reference_id: Uuid::new_v4(),
                    sha256: String::new(),
                    expires_at: chrono::Utc::now(),
                },
            },
            fingerprint: String::new(),
            requester: "alice".into(),
            approver: None,
            state: RepairState::Pending,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(2),
        };
        assert!(!can_decide_repair(&Role::Viewer, "bob", &item));
        assert!(!can_decide_repair(&Role::Operator, "alice", &item));
        assert!(can_decide_repair(&Role::Operator, "bob", &item));
        item.state = RepairState::Approved;
        assert!(!can_decide_repair(&Role::Admin, "bob", &item));
        item.state = RepairState::Pending;
        item.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(visible_repair_state(&item), RepairState::Expired);
        assert!(visible_repair_label(&item).contains("reload"));
        assert!(!can_decide_repair(&Role::Operator, "bob", &item));
        item.state = RepairState::Approved;
        assert_eq!(visible_repair_state(&item), RepairState::Expired);
        assert!(visible_repair_label(&item).contains("reload"));
        item.state = RepairState::Expired;
        assert_eq!(visible_repair_label(&item), "Expired");
        item.state = RepairState::Consumed;
        assert_eq!(visible_repair_state(&item), RepairState::Consumed);
        item.state = RepairState::Denied;
        assert_eq!(visible_repair_state(&item), RepairState::Denied);
    }

    #[test]
    fn history_reset_removes_previous_identity_and_unicode_fingerprint_is_safe() {
        let mut state = TeamState::default();
        state.repairs_loaded = true;
        state.repairs_offset = 20;
        state.clear_repair_history();
        assert!(!state.repairs_loaded);
        assert_eq!(state.repairs_offset, 0);
        assert!(state.repairs.is_empty());
        assert_eq!(abbreviated_fingerprint("ä💡fingerprint"), "ä💡fingerprin");
    }
}
impl AivanaApp {
    fn team_browser_login(&mut self, ui: &mut Ui) {
        use crate::team_client::login::{LoginEvent, start};
        let event = self
            .team
            .login
            .as_ref()
            .and_then(|flow| match flow.events.try_recv() {
                Ok(event) => Some(event),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(LoginEvent::Finished(Err("Browser sign-in ended.".into())))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(event) = event {
            match event {
                LoginEvent::OpenBrowser(url) => {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                    self.team.message = "Confirm sign-in in the browser. Return to Relayne through a local callback (up to 120 seconds).".into();
                }
                LoginEvent::Finished(result) => {
                    self.team.login = None;
                    match result {
                        Ok(token) => {
                            self.team.live = Default::default();
                            self.team.snapshot = None;
                            self.team.selected = None;
                            self.team.edit = None;
                            self.team.tokens.clear();
                            self.team.audit.clear();
                            self.team.issued = None;
                            self.team.token = token;
                            self.team.invalidate_repair_identity();
                            self.team.clear_repair_history();
                            self.team
                                .start(|client| Ok(TeamResult::State(client.snapshot()?)));
                        }
                        Err(error) => self.team.message = error,
                    }
                }
            }
        }
        ui.collapsing("Sign in with your organization identity in the browser", |ui| {
            ui.add_enabled_ui(self.team.login.is_none() && self.team.pending.is_none(), |ui| {
                text_field(ui, "HTTPS issuer", &mut self.team.login_options.issuer);
                text_field(ui, "Public OAuth client ID", &mut self.team.login_options.client_id);
                text_field(ui, "API scopes (space-separated)", &mut self.team.login_options.scopes);
                text_field(ui, "Audience parameter (optional, provider-specific)", &mut self.team.login_options.audience);
                ui.small("The provider must allow a public desktop app with Authorization Code + PKCE and http://127.0.0.1:<dynamic port>/oauth/callback. Configure the API target and roles on the team server.");
                if ui.button("Start organization sign-in in browser").clicked() {
                    match start(self.team.login_options.clone()) {
                        Ok(flow) => { self.team.login = Some(flow); self.team.message = "Checking provider configuration …".into(); }
                        Err(error) => self.team.message = error.to_string(),
                    }
                }
            });
            if self.team.login.is_some() && ui.button("Cancel browser sign-in").clicked() {
                self.team.login = None;
                self.team.message = "Browser sign-in canceled.".into();
            }
        });
        if self.team.login.is_some() {
            ui.spinner();
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    pub(super) fn poll_team(&mut self) {
        let result = self
            .team
            .pending
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(v) => Some(v),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err("Team request canceled".into())),
                Err(_) => None,
            });
        if let Some(result) = result {
            self.team.pending = None;
            match result {
                Err(e) => self.team.message = e,
                Ok(result) => {
                    self.team.message = "Team request completed".into();
                    match result {
                        TeamResult::State(state) => {
                            self.team.clear_repair_history();
                            self.team.snapshot = Some(state);
                            self.team.edit = None;
                        }
                        TeamResult::Saved(item) => {
                            if let Some(state) = &mut self.team.snapshot {
                                state.items.retain(|i| i.id != item.id);
                                state.items.push(item);
                            }
                            self.team.edit = None;
                        }
                        TeamResult::Issued(token) => self.team.issued = Some(token),
                        TeamResult::Admin(tokens, audit) => {
                            self.team.tokens = tokens;
                            self.team.audit = audit;
                        }
                        TeamResult::Revoked => {
                            self.team.message = "Token revoked. Reload administration.".into();
                            self.team.tokens.clear();
                        }
                        TeamResult::Repairs(offset, items) => {
                            self.team.repairs_offset = offset;
                            self.team.repairs = items;
                            self.team.repairs_loaded = true;
                        }
                        TeamResult::RepairDecision(item) => {
                            self.team.repairs.retain(|old| old.id != item.id);
                            self.team.repairs.push(item);
                        }
                    }
                }
            }
        }
    }
    pub(super) fn team_view(&mut self, ui: &mut Ui) {
        self.poll_team();
        ui.heading("Relayne Team");
        ui.label("Central team server · workspaces, connection targets, and job handoffs");
        ui.label(
            "Endpoints are shared without credentials. Roles apply to the entire team server.",
        );
        self.team_browser_login(ui);
        let mut identity_changed = false;
        ui.horizontal(|ui| {
            ui.label("Server");
            identity_changed |= ui
                .add_enabled(
                    self.team.pending.is_none() && self.team.login.is_none(),
                    egui::TextEdit::singleline(&mut self.team.endpoint),
                )
                .changed();
        });
        ui.horizontal(|ui| {
            ui.label("Team token / organization JWT");
            identity_changed |= ui
                .add_enabled(
                    self.team.pending.is_none() && self.team.login.is_none(),
                    egui::TextEdit::singleline(&mut self.team.token).password(true),
                )
                .changed();
        });
        ui.small("Organization JWTs require a server-configured OIDC provider and an explicit user role. Tokens are held only in memory.");
        if identity_changed {
            self.team.invalidate_repair_identity();
            self.team.clear_repair_history();
            self.team.live = Default::default();
            self.team.snapshot = None;
            self.team.selected = None;
            self.team.edit = None;
            self.team.tokens.clear();
            self.team.audit.clear();
            self.team.issued = None;
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.team.pending.is_none() && self.team.login.is_none(),
                    egui::Button::new("Connect / reload"),
                )
                .clicked()
            {
                self.team.clear_repair_history();
                self.team.snapshot = None;
                self.team.edit = None;
                self.team.tokens.clear();
                self.team.audit.clear();
                self.team.issued = None;
                self.team.start(|c| Ok(TeamResult::State(c.snapshot()?)));
            }
            if ui
                .add_enabled(self.team.pending.is_none(), egui::Button::new("Sign out"))
                .clicked()
            {
                self.team = TeamState::default();
            }
        });
        self.collaboration_view(ui);
        ui.label(&self.team.message);
        if self.team.pending.is_some() {
            ui.spinner();
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
        let Some(snapshot) = self.team.snapshot.clone() else {
            ui.label("Start the server separately: relayne_team bootstrap <database> <admin>, then relayne_team serve <database>.");
            return;
        };
        ui.label(format!(
            "Signed in: {} · Server role: {:?}",
            snapshot.actor, snapshot.role
        ));
        ui.small(repair_role_summary(&snapshot.role));
        ui.small("Legacy actor labels are assigned by an administrator; different labels do not prove different people. OIDC checks signed token expiry and current local subject role, without instant external identity-provider revocation.");
        ui.small("Team records contain credential-free endpoints and repair metadata. RDP credentials stay local; WinRM uses your current Windows identity. The masked team token stays in this app's memory and is cleared on sign-out.");
        ui.small("Server refresh records elapsed approval deadlines and expiry audit together. A cached row can pass its deadline between refreshes; reload to confirm the server record. Only admins can load the latest 500 audit entries; an approval state is not a delivered outcome.");
        ui.collapsing("Repair approval status", |ui| {
            ui.small("The server makes the final authorization decision. A requester and approver must be different authenticated actors. Compare the full fingerprint and intended change through your review channel; a digest alone does not reveal the command.");
            if ui.add_enabled(self.team.pending.is_none() && snapshot.role != Role::Viewer, egui::Button::new("Load recent repair approvals")).clicked() {
                self.team.load_repairs(0);
            }
            if snapshot.role == Role::Viewer {
                ui.small("Repair approval history requires an operator or admin role.");
            }
            if !self.team.repairs_loaded {
                ui.small("Repair status unavailable until a successful load.");
            } else {
                ui.small(format!("Showing {} approvals from offset {} (up to 20 per page).", self.team.repairs.len(), self.team.repairs_offset));
                for item in self.team.repairs.clone() {
                    ui.group(|ui| {
                        ui.strong(visible_repair_label(&item));
                        ui.label(format!("Requester {} · Approver {} · Run {} · target {}", item.requester, item.approver.as_deref().unwrap_or("—"), item.binding.run_id, item.binding.target_index + 1));
                        ui.label(format!("Service {} · {:?} → {:?} · expires {} UTC", item.binding.service, item.binding.before, item.binding.desired, item.expires_at));
                        ui.small(format!("Fingerprint {}…", abbreviated_fingerprint(&item.fingerprint)));
                        ui.collapsing("Full binding fingerprint", |ui| { ui.monospace(&item.fingerprint); });
                        if can_decide_repair(&snapshot.role, &snapshot.actor, &item) {
                            ui.horizontal(|ui| {
                                for (label, decision) in [("Approve", RepairDecision::Approve), ("Deny", RepairDecision::Deny)] {
                                    if ui.add_enabled(self.team.pending.is_none(), egui::Button::new(format!("{label}##{}", item.id))).clicked() {
                                        let id = item.id;
                                        self.team.start(move |client| Ok(TeamResult::RepairDecision(client.decide_repair(id, &DecideRepairApproval { decision })?)));
                                    }
                                }
                            });
                        }
                    });
                }
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.team.pending.is_none() && self.team.repairs_offset >= 20, egui::Button::new("Previous approvals")).clicked() {
                        self.team.load_repairs(self.team.repairs_offset - 20);
                    }
                    if ui.add_enabled(self.team.pending.is_none() && self.team.repairs.len() == 20 && self.team.repairs_offset < 1000, egui::Button::new("Next approvals")).clicked() {
                        self.team.load_repairs(self.team.repairs_offset + 20);
                    }
                });
            }
        });
        let busy = self.team.pending.is_some();
        ui.add_enabled_ui(!busy,|ui|{
            if snapshot.role==Role::Admin {
                ui.horizontal(|ui|{ui.text_edit_singleline(&mut self.team.workspace_name);if ui.button("Create workspace").clicked(){let id=Uuid::new_v4();let item=SharedItem{id,workspace:id,kind:"workspace".into(),name:self.team.workspace_name.clone(),host:String::new(),port:0,protocol:String::new(),note:String::new(),source_id:None,revision:0};self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));}});
            }
            let workspaces:Vec<_>=snapshot.items.iter().filter(|i|i.kind=="workspace").collect();
            egui::ComboBox::from_label("Team workspace").selected_text(workspaces.iter().find(|w|Some(w.id)==self.team.selected).map(|w|w.name.as_str()).unwrap_or("Select")).show_ui(ui,|ui|{for w in &workspaces {ui.selectable_value(&mut self.team.selected,Some(w.id),&w.name);}});
            if let Some(workspace)=self.team.selected {
                if snapshot.role!=Role::Viewer {
                    if ui.button("Share selected local profile").clicked(){
                        if let Some(p)=self.selected_profile() {
                            let existing=snapshot.items.iter().find(|i|i.workspace==workspace && i.kind=="profile" && i.source_id==Some(p.id));
                            let item=SharedItem{id:existing.map(|i|i.id).unwrap_or_else(Uuid::new_v4),workspace,kind:"profile".into(),name:p.name.clone(),host:p.host.clone(),port:p.port,protocol:p.protocol.label().into(),note:String::new(),source_id:Some(p.id),revision:existing.map(|i|i.revision).unwrap_or(0)};
                            self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));
                        } else {self.team.message="Select a local connection profile first".into();}
                    }
                    ui.collapsing("Publish job handoff",|ui|{
                        ui.label("Title and handoff notes; do not enter passwords or confidential findings.");
                        ui.text_edit_singleline(&mut self.team.handoff_name);
                        ui.text_edit_multiline(&mut self.team.handoff_note);
                        if ui.button("Use selected job").clicked(){
                            if let Some(m)=self.missions.book.missions.iter().find(|m|Some(m.id)==self.missions.selected){self.team.handoff_name=m.objective.clone();self.team.handoff_note=m.handoff.clone();}
                        }
                        if ui.button("Save handoff").clicked(){let item=SharedItem{id:Uuid::new_v4(),workspace,kind:"handoff".into(),name:self.team.handoff_name.clone(),host:String::new(),port:0,protocol:String::new(),note:self.team.handoff_note.clone(),source_id:self.missions.selected,revision:0};self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));}
                    });
                }
                for item in snapshot.items.iter().filter(|i|i.workspace==workspace && i.kind!="workspace") {
                    ui.separator();ui.label(format!("{} · {} · Revision {}",item.name,item.kind,item.revision));
                    if item.kind=="profile" {ui.label(format!("{} {}:{}",item.protocol,item.host,item.port));if ui.button(format!("Import locally##{}",item.id)).clicked(){
                        let mut profile=ConnectionProfile::sample(&item.name,&item.host,"Relayne Team",false);
                        profile.id=Uuid::new_v4();profile.port=item.port;profile.username.clear();profile.protocol=match item.protocol.as_str(){"SSH"=>Protocol::Ssh,"VNC"=>Protocol::Vnc,_=>Protocol::Rdp};
                        self.profiles.push(profile);self.save_profiles();self.team.message="Imported as a new local profile; add credentials locally.".into();
                    }}
                    if !item.note.is_empty(){ui.label(&item.note);}
                    if snapshot.role!=Role::Viewer && ui.button(format!("Edit##{}",item.id)).clicked(){self.team.edit=Some(item.clone());}
                }
                if let Some(edit)=&mut self.team.edit {
                    ui.separator();ui.label(format!("Editing based on revision {}",edit.revision));ui.text_edit_singleline(&mut edit.name);
                    if edit.kind=="profile"{ui.text_edit_singleline(&mut edit.host);ui.add(egui::DragValue::new(&mut edit.port).range(1..=65535));}
                    ui.text_edit_multiline(&mut edit.note);
                    let save=ui.button("Save change").clicked();let item=edit.clone();if save{self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));}
                }
            }
            if snapshot.role==Role::Admin {
                ui.separator();ui.collapsing("Team administration",|ui|{
                    if ui.button("Load tokens and audit").clicked(){self.team.start(|c|Ok(TeamResult::Admin(c.tokens()?,c.audit()?)));}
                    ui.text_edit_singleline(&mut self.team.actor);
                    egui::ComboBox::from_label("New token role").selected_text(format!("{:?}",self.team.role)).show_ui(ui,|ui|{ui.selectable_value(&mut self.team.role,Role::Viewer,"Viewer");ui.selectable_value(&mut self.team.role,Role::Operator,"Operator");ui.selectable_value(&mut self.team.role,Role::Admin,"Admin");});
                    if ui.button("Issue token").clicked(){let input=TokenRequest{actor:self.team.actor.clone(),role:self.team.role.clone()};self.team.start(move|c|Ok(TeamResult::Issued(c.issue(&input)?)));}
                    if let Some(token)=&self.team.issued {ui.label("Newly issued token – deliver securely to the recipient:");let mut text=token.token.clone();ui.add(egui::TextEdit::singleline(&mut text).password(true).interactive(false));if ui.button("Copy token").clicked(){ui.ctx().copy_text(token.token.clone());}}
                    for token in self.team.tokens.clone(){ui.horizontal(|ui|{ui.label(format!("{} · {:?} · {}",token.actor,token.role,if token.revoked{"revoked"}else{"active"}));if !token.revoked && ui.button(format!("Revoke##{}",token.id)).clicked(){self.team.start(move|c|{c.revoke(token.id)?;Ok(TeamResult::Revoked)});}});}
                    for entry in &self.team.audit {ui.label(format!("{} · {} · {} · {}",entry.time,entry.actor,entry.action,entry.target));}
                });
            }
        });
    }
}
