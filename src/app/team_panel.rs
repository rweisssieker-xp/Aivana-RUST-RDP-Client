use super::*;
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
    pending: Option<mpsc::Receiver<Result<TeamResult, String>>>,
    message: String,
}
enum TeamResult {
    State(Snapshot),
    Saved(SharedItem),
    Issued(IssuedToken),
    Admin(Vec<TokenInfo>, Vec<Audit>),
    Revoked,
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
            pending: None,
            message: String::new(),
        }
    }
}
impl TeamState {
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
                self.message = "Team-Anfrage läuft …".into();
                std::thread::spawn(move || {
                    let _ = tx.send(work(client).map_err(|e| e.to_string()));
                });
            }
        }
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
                Err(mpsc::TryRecvError::Disconnected) => Some(LoginEvent::Finished(Err(
                    "Browseranmeldung wurde beendet.".into(),
                ))),
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(event) = event {
            match event {
                LoginEvent::OpenBrowser(url) => {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                    self.team.message = "Anmeldung im Browser bestätigen. Rückkehr zu Relayne erfolgt über einen lokalen Rückkanal (max. 120 Sekunden).".into();
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
                            self.team
                                .start(|client| Ok(TeamResult::State(client.snapshot()?)));
                        }
                        Err(error) => self.team.message = error,
                    }
                }
            }
        }
        ui.collapsing("Mit Unternehmensidentität im Browser anmelden", |ui| {
            ui.add_enabled_ui(self.team.login.is_none() && self.team.pending.is_none(), |ui| {
                text_field(ui, "HTTPS-Issuer", &mut self.team.login_options.issuer);
                text_field(ui, "Öffentliche OAuth-Client-ID", &mut self.team.login_options.client_id);
                text_field(ui, "API-Scopes (leerzeichengetrennt)", &mut self.team.login_options.scopes);
                text_field(ui, "Audience-Parameter (optional, anbieterspezifisch)", &mut self.team.login_options.audience);
                ui.small("Der Anbieter muss eine öffentliche Desktop-App mit Authorization Code + PKCE und http://127.0.0.1:<dynamischer Port>/oauth/callback erlauben. API-Ziel und Rollen müssen im Teamserver konfiguriert sein.");
                if ui.button("Unternehmensanmeldung im Browser starten").clicked() {
                    match start(self.team.login_options.clone()) {
                        Ok(flow) => { self.team.login = Some(flow); self.team.message = "Anbieter-Konfiguration wird geprüft …".into(); }
                        Err(error) => self.team.message = error.to_string(),
                    }
                }
            });
            if self.team.login.is_some() && ui.button("Browseranmeldung abbrechen").clicked() {
                self.team.login = None;
                self.team.message = "Browseranmeldung abgebrochen.".into();
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
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Team-Anfrage abgebrochen".into()))
                }
                Err(_) => None,
            });
        if let Some(result) = result {
            self.team.pending = None;
            match result {
                Err(e) => self.team.message = e,
                Ok(result) => {
                    self.team.message = "Team-Anfrage abgeschlossen".into();
                    match result {
                        TeamResult::State(state) => {
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
                            self.team.message = "Token widerrufen. Verwaltung neu laden.".into();
                            self.team.tokens.clear();
                        }
                    }
                }
            }
        }
    }
    pub(super) fn team_view(&mut self, ui: &mut Ui) {
        self.poll_team();
        ui.heading("Relayne Team");
        ui.label("Zentraler Teamserver · Workspaces, Verbindungsziele und Auftragsübergaben");
        ui.label("Endpunkte werden ohne Zugangsdaten geteilt. Rollen gelten für den gesamten Teamserver.");
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
            ui.label("Team-Token / Unternehmens-JWT");
            identity_changed |= ui
                .add_enabled(
                    self.team.pending.is_none() && self.team.login.is_none(),
                    egui::TextEdit::singleline(&mut self.team.token).password(true),
                )
                .changed();
        });
        ui.small("Unternehmens-JWTs benötigen einen serverseitig konfigurierten OIDC-Anbieter und eine explizite Benutzerrolle. Token werden nur im Arbeitsspeicher gehalten.");
        if identity_changed {
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
                    egui::Button::new("Verbinden / neu laden"),
                )
                .clicked()
            {
                self.team.snapshot = None;
                self.team.edit = None;
                self.team.tokens.clear();
                self.team.audit.clear();
                self.team.issued = None;
                self.team.start(|c| Ok(TeamResult::State(c.snapshot()?)));
            }
            if ui
                .add_enabled(self.team.pending.is_none(), egui::Button::new("Abmelden"))
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
            ui.label("Server separat starten: relayne_team bootstrap <Datenbank> <Admin>, anschließend relayne_team serve <Datenbank>.");
            return;
        };
        ui.label(format!(
            "Angemeldet: {} · Serverrolle: {:?}",
            snapshot.actor, snapshot.role
        ));
        let busy = self.team.pending.is_some();
        ui.add_enabled_ui(!busy,|ui|{
            if snapshot.role==Role::Admin {
                ui.horizontal(|ui|{ui.text_edit_singleline(&mut self.team.workspace_name);if ui.button("Workspace erstellen").clicked(){let id=Uuid::new_v4();let item=SharedItem{id,workspace:id,kind:"workspace".into(),name:self.team.workspace_name.clone(),host:String::new(),port:0,protocol:String::new(),note:String::new(),source_id:None,revision:0};self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));}});
            }
            let workspaces:Vec<_>=snapshot.items.iter().filter(|i|i.kind=="workspace").collect();
            egui::ComboBox::from_label("Team-Workspace").selected_text(workspaces.iter().find(|w|Some(w.id)==self.team.selected).map(|w|w.name.as_str()).unwrap_or("Auswählen")).show_ui(ui,|ui|{for w in &workspaces {ui.selectable_value(&mut self.team.selected,Some(w.id),&w.name);}});
            if let Some(workspace)=self.team.selected {
                if snapshot.role!=Role::Viewer {
                    if ui.button("Ausgewähltes lokales Profil teilen").clicked(){
                        if let Some(p)=self.selected_profile() {
                            let existing=snapshot.items.iter().find(|i|i.workspace==workspace && i.kind=="profile" && i.source_id==Some(p.id));
                            let item=SharedItem{id:existing.map(|i|i.id).unwrap_or_else(Uuid::new_v4),workspace,kind:"profile".into(),name:p.name.clone(),host:p.host.clone(),port:p.port,protocol:p.protocol.label().into(),note:String::new(),source_id:Some(p.id),revision:existing.map(|i|i.revision).unwrap_or(0)};
                            self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));
                        } else {self.team.message="Zuerst ein lokales Verbindungsprofil auswählen".into();}
                    }
                    ui.collapsing("Auftragsübergabe veröffentlichen",|ui|{
                        ui.label("Titel und Übergabehinweise; keine Kennwörter oder vertraulichen Befunde eintragen.");
                        ui.text_edit_singleline(&mut self.team.handoff_name);
                        ui.text_edit_multiline(&mut self.team.handoff_note);
                        if ui.button("Aus ausgewähltem Auftrag übernehmen").clicked(){
                            if let Some(m)=self.missions.book.missions.iter().find(|m|Some(m.id)==self.missions.selected){self.team.handoff_name=m.objective.clone();self.team.handoff_note=m.handoff.clone();}
                        }
                        if ui.button("Übergabe speichern").clicked(){let item=SharedItem{id:Uuid::new_v4(),workspace,kind:"handoff".into(),name:self.team.handoff_name.clone(),host:String::new(),port:0,protocol:String::new(),note:self.team.handoff_note.clone(),source_id:self.missions.selected,revision:0};self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));}
                    });
                }
                for item in snapshot.items.iter().filter(|i|i.workspace==workspace && i.kind!="workspace") {
                    ui.separator();ui.label(format!("{} · {} · Revision {}",item.name,item.kind,item.revision));
                    if item.kind=="profile" {ui.label(format!("{} {}:{}",item.protocol,item.host,item.port));if ui.button(format!("Lokal importieren##{}",item.id)).clicked(){
                        let mut profile=ConnectionProfile::sample(&item.name,&item.host,"Relayne Team",false);
                        profile.id=Uuid::new_v4();profile.port=item.port;profile.username.clear();profile.protocol=match item.protocol.as_str(){"SSH"=>Protocol::Ssh,"VNC"=>Protocol::Vnc,_=>Protocol::Rdp};
                        self.profiles.push(profile);self.save_profiles();self.team.message="Als neues lokales Profil importiert; Zugangsdaten lokal ergänzen.".into();
                    }}
                    if !item.note.is_empty(){ui.label(&item.note);}
                    if snapshot.role!=Role::Viewer && ui.button(format!("Bearbeiten##{}",item.id)).clicked(){self.team.edit=Some(item.clone());}
                }
                if let Some(edit)=&mut self.team.edit {
                    ui.separator();ui.label(format!("Bearbeitung auf Basis Revision {}",edit.revision));ui.text_edit_singleline(&mut edit.name);
                    if edit.kind=="profile"{ui.text_edit_singleline(&mut edit.host);ui.add(egui::DragValue::new(&mut edit.port).range(1..=65535));}
                    ui.text_edit_multiline(&mut edit.note);
                    let save=ui.button("Änderung speichern").clicked();let item=edit.clone();if save{self.team.start(move|c|Ok(TeamResult::Saved(c.save(&item)?)));}
                }
            }
            if snapshot.role==Role::Admin {
                ui.separator();ui.collapsing("Team-Verwaltung",|ui|{
                    if ui.button("Tokens und Audit laden").clicked(){self.team.start(|c|Ok(TeamResult::Admin(c.tokens()?,c.audit()?)));}
                    ui.text_edit_singleline(&mut self.team.actor);
                    egui::ComboBox::from_label("Neue Token-Rolle").selected_text(format!("{:?}",self.team.role)).show_ui(ui,|ui|{ui.selectable_value(&mut self.team.role,Role::Viewer,"Viewer");ui.selectable_value(&mut self.team.role,Role::Operator,"Operator");ui.selectable_value(&mut self.team.role,Role::Admin,"Admin");});
                    if ui.button("Token ausstellen").clicked(){let input=TokenRequest{actor:self.team.actor.clone(),role:self.team.role.clone()};self.team.start(move|c|Ok(TeamResult::Issued(c.issue(&input)?)));}
                    if let Some(token)=&self.team.issued {ui.label("Neu ausgestellter Token – sicher an den Empfänger übergeben:");let mut text=token.token.clone();ui.add(egui::TextEdit::singleline(&mut text).password(true).interactive(false));if ui.button("Token kopieren").clicked(){ui.ctx().copy_text(token.token.clone());}}
                    for token in self.team.tokens.clone(){ui.horizontal(|ui|{ui.label(format!("{} · {:?} · {}",token.actor,token.role,if token.revoked{"widerrufen"}else{"aktiv"}));if !token.revoked && ui.button(format!("Widerrufen##{}",token.id)).clicked(){self.team.start(move|c|{c.revoke(token.id)?;Ok(TeamResult::Revoked)});}});}
                    for entry in &self.team.audit {ui.label(format!("{} · {} · {} · {}",entry.time,entry.actor,entry.action,entry.target));}
                });
            }
        });
    }
}
