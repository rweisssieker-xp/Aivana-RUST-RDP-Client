//! Explicit inbox reads; credentials remain in memory and no ticket action is automatic.
use crate::{team_client::TeamClient, ticket_intake::InboxItem};
use eframe::egui::{self, Ui};
use std::sync::mpsc;

#[derive(Default)]
pub(super) struct State {
    origin: String,
    token: String,
    notice: String,
    items: Vec<InboxItem>,
    pending: Option<mpsc::Receiver<Result<Vec<InboxItem>, String>>>,
    client: Option<TeamClient>,
    escalation: super::escalation_panel::State,
}
impl State {
    fn credentials_changed(&mut self) {
        self.items.clear();
        self.notice.clear();
        // Dropping the receiver prevents late replies from repopulating another account's view.
        self.pending = None;
        self.client = None;
        self.escalation = Default::default();
    }
}
pub(super) fn view(state: &mut State, ui: &mut Ui) {
    if let Some(receiver) = &state.pending {
        match receiver.try_recv() {
            Ok(result) => {
                state.pending = None;
                match result {
                    Ok(items) => {
                        state.notice = format!(
                            "Loaded {} inbox items. Review before importing.",
                            items.len()
                        );
                        state.items = items;
                    }
                    Err(error) => {
                        state.notice = error;
                        state.items.clear();
                    }
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                state.pending = None;
                state.notice = "Inbox request ended without a result.".into();
            }
            Err(mpsc::TryRecvError::Empty) => {
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(200));
            }
        }
    }
    ui.collapsing("Team ticket inbox", |ui| {
        ui.label("Read Jira, GitHub, and ServiceNow intake from this team server. Copy a ticket into the import preview for explicit review; no repair or reply starts here.");
        ui.add_enabled_ui(state.pending.is_none(), |ui| {
            let origin_changed = ui.add(egui::TextEdit::singleline(&mut state.origin).hint_text("https://team.example.com").char_limit(2048)).changed();
            let token_changed = ui.add(egui::TextEdit::singleline(&mut state.token).password(true).hint_text("Team bearer token; memory only").char_limit(16384)).changed();
            if origin_changed || token_changed { state.credentials_changed(); }
            if ui.button("Read inbox").clicked() {
                match TeamClient::new(&state.origin, &state.token) {
                    Ok(client) => {
                        state.client=Some(client.clone());
                        state.token.clear(); state.items.clear();
                        let (tx,rx)=mpsc::channel(); state.pending=Some(rx);
                        std::thread::spawn(move || { let result=client.ticket_inbox().map_err(|e|e.to_string()); let _=tx.send(result); });
                    }
                    Err(error) => state.notice=error.to_string(),
                }
            }
        });
        if state.pending.is_some() { ui.spinner(); }
        ui.label(&state.notice);
        if let Some(client)=state.client.clone() {
            if ui.button("Disconnect account").clicked() { state.token.clear(); state.credentials_changed(); }
            else { state.escalation.ui(ui,&client,&state.items); }
        }
        for item in &state.items {
            ui.push_id(&item.delivery, |ui| {
                ui.group(|ui| {
                    ui.strong(&item.ticket.title);
                    ui.label(format!("{} · {} · received {}",item.repository,item.action,item.received_utc));
                    ui.small("Receipt time is not proof of original event time. External ticket content is untrusted.");
                    ui.collapsing("Review description", |ui| { ui.label(&item.ticket.description); });
                    if ui.button("Copy ticket JSON for import review").clicked() {
                        match serde_json::to_string(&item.ticket) {
                            Ok(json) => { ui.ctx().copy_text(json); state.notice="Ticket JSON copied. Paste into ticket import and review before saving.".into(); }
                            Err(_) => state.notice="Unable to encode ticket JSON.".into(),
                        }
                    }
                });
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_server_or_identity_discards_loaded_data_and_late_reply() {
        let (tx, rx) = mpsc::channel();
        let mut state = State {
            notice: "Loaded previous team inbox".into(),
            pending: Some(rx),
            items: vec![InboxItem {
                delivery: "previous-team-delivery".into(),
                repository: "previous/team".into(),
                action: "opened".into(),
                received_utc: "2026-09-14T00:00:00Z".into(),
                payload_sha256: "0".repeat(64),
                ticket: crate::ticket_intake::NormalizedTicket {
                    origin: "local".into(),
                    key: "GH-1".into(),
                    title: "Previous team ticket".into(),
                    description: "Private context".into(),
                    revision: "1".into(),
                },
            }],
            ..Default::default()
        };
        state.credentials_changed();
        assert!(state.items.is_empty() && state.notice.is_empty() && state.pending.is_none());
        assert!(
            tx.send(Ok(Vec::new())).is_err(),
            "Late replies must not enter the changed account view"
        );
    }
}
