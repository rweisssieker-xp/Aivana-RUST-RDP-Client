use super::*;

pub(super) struct InvestigatorState {
    endpoint: String,
}

impl Default for InvestigatorState {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:47841".into(),
        }
    }
}

impl AivanaApp {
    pub(super) fn investigator_view(&mut self, ui: &mut Ui) {
        ui.heading("Security Investigator");
        ui.label("Investigate sign-in, endpoint, storage, network and AD CS evidence; review signed A2 actions and pilot acceptance.");
        ui.add_space(12.0);
        ui.label("The independent investigator service keeps processing its persistent queue when Relayne or the browser closes.");
        ui.horizontal(|ui| {
            ui.label("Service address");
            ui.text_edit_singleline(&mut self.investigator.endpoint);
        });
        let valid = reqwest::Url::parse(self.investigator.endpoint.trim()).is_ok_and(|url| {
            (url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        });
        if ui
            .add_enabled(valid, egui::Button::new("Open investigator"))
            .clicked()
        {
            ui.ctx()
                .open_url(egui::OpenUrl::new_tab(self.investigator.endpoint.trim()));
        }
        if !valid {
            ui.label("Use HTTPS or a local loopback HTTP address without credentials or query parameters.");
        }
        ui.separator();
        ui.label("Start the separately installed relayne_investigator service, then sign in on its page with an investigator token. The browser and plugin use the same authenticated case API.");
        ui.label("Cases · Evidence and counterevidence · Open questions · Review and handoff · Verified measures · Time-limited risk decisions · Versioned exports");
        ui.add_space(8.0);
        ui.label("A1 investigation is read-only at connected sources. Missing telemetry remains visible. Risk acceptance does not establish technical safety, and reported implementation does not establish verified effectiveness.");
    }
}
