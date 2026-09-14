//! Explicit account actions; network requests run off the UI thread.
use eframe::egui;
#[derive(Default)]
pub(super) struct State {
    origin: String,
    token: String,
    notice: String,
    link: Option<String>,
    pending: Option<std::sync::mpsc::Receiver<Result<serde_json::Value, String>>>,
    attempt: Option<uuid::Uuid>,
}
impl State {
    pub(super) fn ui(&mut self, ui: &mut egui::Ui) {
        if let Some(receiver) = &self.pending {
            match receiver.try_recv() {
                Ok(result) => {
                    self.pending = None;
                    match result {
                        Ok(value) => {
                            if let Some(url) = value["url"].as_str() {
                                let allowed = reqwest::Url::parse(url).ok().is_some_and(|u| {
                                    u.scheme() == "https"
                                        && matches!(
                                            u.host_str(),
                                            Some("checkout.stripe.com" | "billing.stripe.com")
                                        )
                                        && u.username().is_empty()
                                        && u.password().is_none()
                                        && u.port_or_known_default() == Some(443)
                                });
                                if allowed {
                                    self.link = Some(url.to_owned());
                                    self.notice = "Session ready. Open Stripe to review and continue. No license is granted by this link.".into();
                                } else {
                                    self.notice =
                                        "The server returned an invalid payment URL.".into();
                                }
                            } else {
                                self.notice = format!(
                                    "Subscription active: {}. Status: {}. Last verified (UTC Unix time): {}. Access requires fresh server verification.",
                                    value["active"] == true,
                                    value["status"].as_str().unwrap_or("unknown"),
                                    value["checked_at"]
                                );
                            }
                        }
                        Err(error) => self.notice = error,
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.notice =
                        "Account request interrupted. Retry uses the same checkout attempt.".into();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(200));
                }
            }
        }
        ui.collapsing("Account and subscription (Stripe)", |ui| {
            ui.label("Connect to your configured Relayne team server. Stripe secrets stay on the server. Prices, taxes, invoices and cancellation are reviewed in Stripe. A subscription never authorizes a remote repair.");
            ui.add_enabled_ui(self.pending.is_none(), |ui| {
                let origin_changed = ui.add(egui::TextEdit::singleline(&mut self.origin).hint_text("Team server HTTPS origin")).changed();
                let token_changed = ui.add(egui::TextEdit::singleline(&mut self.token).password(true).hint_text("Team access token (memory only)")).changed();
                if origin_changed || token_changed { self.clear_account_result(); }
                ui.horizontal_wrapped(|ui| {
                    for (label, action) in [("Review subscription in Stripe", "checkout"),("Manage billing / cancel", "portal"),("Verify subscription", "refresh")] {
                        if ui.button(label).clicked() { self.start(action); }
                    }
                });
                if ui.button("Start a new checkout attempt").clicked() {
                    self.clear_account_result();
                    self.attempt = Some(uuid::Uuid::new_v4());
                    self.notice = "New attempt prepared. The server will keep any existing open or uncertain checkout to prevent duplicate subscriptions.".into();
                }
            });
            if self.pending.is_some() { ui.spinner(); }
            ui.label(&self.notice);
            if let Some(url) = &self.link { ui.hyperlink_to("Open secure Stripe session", url); }
        });
    }
    fn start(&mut self, action: &'static str) {
        self.link = None;
        let client = match crate::team_client::TeamClient::new(&self.origin, &self.token) {
            Ok(client) => client,
            Err(error) => {
                self.notice = error.to_string();
                return;
            }
        };
        self.token.clear();
        let attempt = *self.attempt.get_or_insert_with(uuid::Uuid::new_v4);
        let (sender, receiver) = std::sync::mpsc::channel();
        self.pending = Some(receiver);
        self.notice = "Contacting the configured account server…".into();
        std::thread::spawn(move || {
            let _ = sender.send(client.billing(action,attempt).map_err(|_| "Account action failed. Check the server configuration and account access; no payment success is assumed.".into()));
        });
    }

    fn clear_account_result(&mut self) {
        self.link = None;
        self.notice.clear();
        self.attempt = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_change_clears_previous_payment_links_and_status() {
        let mut state = State {
            link: Some("https://billing.stripe.com/session/test".into()),
            notice: "Subscription active".into(),
            attempt: Some(uuid::Uuid::new_v4()),
            ..Default::default()
        };
        state.clear_account_result();
        assert!(state.link.is_none());
        assert!(state.notice.is_empty());
        assert!(state.attempt.is_none());
    }
}
