//! Explicit authorization of a bounded outbound queue, separate from ticket intake.
use crate::{team_client::TeamClient, ticket_intake::InboxItem};
use eframe::egui;
use serde_json::{Value, json};
#[derive(Default)]
pub(super) struct State {
    destination: Option<(String, String)>,
    selected: String,
    reason: String,
    hours: u16,
    approved: bool,
    retry_approved: Option<String>,
    notice: String,
    entries: Vec<Value>,
    pending: Option<std::sync::mpsc::Receiver<Result<Value, String>>>,
}
impl State {
    pub(super) fn ui(&mut self, ui: &mut egui::Ui, client: &TeamClient, inbox: &[InboxItem]) {
        if let Some(rx) = &self.pending {
            match rx.try_recv() {
                Ok(result) => {
                    self.pending = None;
                    match result {
                        Ok(value) => {
                            if let (Some(url), Some(fingerprint)) =
                                (value["destination"].as_str(), value["fingerprint"].as_str())
                            {
                                self.destination = Some((url.into(), fingerprint.into()));
                                self.revoke_review();
                            } else if let Some(entries) = value.as_array() {
                                self.entries = entries.clone();
                            }
                            self.notice = "Server action completed. Reload the queue to inspect its current state. This does not prove that an external ticket was created.".into();
                        }
                        Err(error) => self.notice = error,
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.notice =
                        "Request ended without a result. Read the queue before retrying.".into();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => ui
                    .ctx()
                    .request_repaint_after(std::time::Duration::from_millis(200)),
            }
        }
        ui.collapsing("External escalation authorization", |ui| {
            ui.label("Intake alone never sends anything. Authorize one selected ticket summary for the configured destination. A separately configured worker can then deliver it before expiry. Disconnecting this screen does not revoke a queued authorization.");
            ui.add_enabled_ui(self.pending.is_none(), |ui| {
                if ui.button("Read configured destination").clicked() { self.start(client,"config",json!({})); }
                if ui.button("Read escalation queue").clicked() { self.start(client,"list",json!({})); }
                if let Some((url,fingerprint)) = self.destination.clone() {
                    ui.label(format!("Destination: {url}"));
                    ui.collapsing("Destination verification",|ui|{ui.monospace(&fingerprint);});
                    let previous=self.selected.clone();
                    egui::ComboBox::from_id_salt("escalation-ticket").selected_text(if self.selected.is_empty(){"Select a received ticket"}else{&self.selected}).show_ui(ui,|ui| {
                        for item in inbox { ui.selectable_value(&mut self.selected,item.delivery.clone(),&item.ticket.title); }
                    });
                    if previous!=self.selected { self.revoke_review(); }
                    if let Some(item)=inbox.iter().find(|i|i.delivery==self.selected) { ui.label(format!("Summary: {} · {}",item.ticket.key,item.ticket.title)); }
                    if ui.add(egui::TextEdit::singleline(&mut self.reason).hint_text("Escalation reason; do not include secrets").char_limit(256)).changed() { self.revoke_review(); }
                    if self.hours==0 {self.hours=24;}
                    if ui.add(egui::DragValue::new(&mut self.hours).range(1..=168).suffix(" hours of authorization")).changed() {self.revoke_review();}
                    ui.checkbox(&mut self.approved,"I authorize this summary and reason to be sent to the displayed destination before expiry.");
                    if ui.add_enabled(self.approved&&!self.selected.is_empty()&&!self.reason.trim().is_empty(),egui::Button::new("Authorize queued escalation")).clicked() {
                        let body=self.authorization(&fingerprint,json!({"delivery":self.selected}));
                        self.start(client,"enqueue",body);self.approved=false;
                    }
                }
                    let fingerprint=self.destination.as_ref().map(|(_,f)|f.clone()).unwrap_or_default();
                    let entries=self.entries.clone();
                    for entry in entries {
                        let Some(id)=entry["id"].as_str() else {continue;};
                        ui.group(|ui| {
                            ui.strong(format!("Delivery state: {}",entry["state"].as_str().unwrap_or("unknown")));
                            ui.label(entry["payload"]["title"].as_str().unwrap_or("Ticket summary"));
                            ui.label(entry["payload"]["reason"].as_str().unwrap_or(""));
                            ui.collapsing("Delivery evidence",|ui|{ui.monospace(id);ui.label(serde_json::to_string_pretty(&entry).unwrap_or_default());});
                            if ui.button("Cancel if still queued").clicked() { self.start(client,"cancel",json!({"id":id})); }
                            ui.label("Only reconcile uncertain delivery after checking the destination. Confirmation does not send another request.");
                            if ui.button("I checked: delivered").clicked() { self.start(client,"reconcile",json!({"id":id,"delivered":true})); }
                            if ui.button("I checked: not delivered").clicked() { self.start(client,"reconcile",json!({"id":id,"delivered":false})); }
                            if !fingerprint.is_empty() {
                            let mut approved = self.retry_approved.as_deref()==Some(id);
                            if ui.checkbox(&mut approved,format!("I authorize a new attempt for {id} with the displayed destination, reason and expiry.")).changed() {
                                self.retry_approved=if approved {Some(id.to_owned())} else {None};
                            }
                            if ui.add_enabled(self.retry_approved.as_deref()==Some(id)&&!self.reason.trim().is_empty(),egui::Button::new("Authorize a new attempt")).clicked() {
                                let body=self.authorization(&fingerprint,json!({"id":id}));self.start(client,"retry",body);self.revoke_review();
                            }
                            }
                        });
                    }
            });
            if self.pending.is_some(){ui.spinner();}
            ui.label(&self.notice);
        });
    }
    fn authorization(&self, fingerprint: &str, mut value: Value) -> Value {
        value["reason"] = json!(self.reason);
        value["expires_utc"] = json!(chrono::Utc::now().timestamp() + i64::from(self.hours) * 3600);
        value["expected_fingerprint"] = json!(fingerprint);
        value
    }
    fn revoke_review(&mut self) {
        self.approved = false;
        self.retry_approved = None;
    }
    fn start(&mut self, client: &TeamClient, action: &'static str, body: Value) {
        if self.pending.is_some() {
            return;
        }
        let client = client.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.pending = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(client.escalation(action, body).map_err(|e| e.to_string()));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn editing_authorization_revokes_both_new_and_retry_consent() {
        let mut state = State {
            approved: true,
            retry_approved: Some("old-attempt".into()),
            ..Default::default()
        };
        state.revoke_review();
        assert!(!state.approved && state.retry_approved.is_none());
    }
}
