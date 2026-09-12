use super::*;
use ironrdp_mstsgu::GatewayInteraction;

#[derive(Default)]
pub(super) struct ProtocolState {
    pub(super) launch: Option<ConnectionProfile>,
    prompt: Option<GatewayInteraction>,
    token: String,
    #[cfg(windows)]
    native: Option<(String, crate::native_remoteapp::NativeRemoteApp)>,
}

fn prompt_expired(prompt: &GatewayInteraction) -> bool {
    match prompt {
        GatewayInteraction::Consent { reply, .. } => reply.is_closed(),
        GatewayInteraction::PaaToken { reply, .. } => reply.is_closed(),
    }
}

impl AivanaApp {
    pub(super) fn protocol_windows(&mut self, ctx: &Context, frame: &mut eframe::Frame) {
        if self.protocols.prompt.as_ref().is_some_and(prompt_expired) {
            self.protocols.prompt = None;
            self.protocols.token.clear();
        }
        if self.protocols.prompt.is_none() {
            while let Some(prompt) = crate::rd_gateway::poll_interaction() {
                if !prompt_expired(&prompt) {
                    self.protocols.prompt = Some(prompt);
                    break;
                }
            }
        }
        if let Some(prompt) = &self.protocols.prompt {
            let mut decision = None;
            let mut open = true;
            egui::Window::new("RD Gateway · Bestätigung erforderlich")
                .id(egui::Id::new("gateway_interaction"))
                .open(&mut open).collapsible(false).resizable(true).default_width(560.0)
                .show(ctx, |ui| {
                    match prompt {
                        GatewayInteraction::Consent { gateway, message, .. } => {
                            ui.label(RichText::new(gateway).strong());
                            ui.label("Der Gateway verlangt Ihre Zustimmung vor dem Verbindungsaufbau.");
                            egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| { ui.label(message); });
                            ui.horizontal(|ui| {
                                if ui.button("Zustimmen und fortfahren").clicked() { decision = Some(true); }
                                if ui.button("Ablehnen").clicked() { decision = Some(false); }
                            });
                        }
                        GatewayInteraction::PaaToken { gateway, .. } => {
                            ui.label(RichText::new(gateway).strong());
                            ui.label("PAA-Cookie Ihres Gateway-Anbieters eingeben. Der Cookie wird nur für diese Verbindung verwendet.");
                            ui.small("Kein allgemeines OAuth-Token und kein OTP-Code. Die Anmeldung im Anbieter-Browser muss über dessen dokumentierten Ablauf erfolgen.");
                            ui.add(egui::TextEdit::singleline(&mut self.protocols.token).password(true).char_limit(32749).hint_text("PAA-Cookie"));
                            ui.horizontal(|ui| {
                                if ui.add_enabled(!self.protocols.token.is_empty(), egui::Button::new("Cookie verwenden")).clicked() { decision = Some(true); }
                                if ui.button("Abbrechen").clicked() { decision = Some(false); }
                            });
                        }
                    }
                });
            if !open {
                decision = Some(false);
            }
            if let Some(accepted) = decision {
                if let Some(prompt) = self.protocols.prompt.take() {
                    match prompt {
                        GatewayInteraction::Consent { reply, .. } => {
                            let _ = reply.send(accepted);
                        }
                        GatewayInteraction::PaaToken { reply, .. } => {
                            let value = if accepted {
                                Some(std::mem::take(&mut self.protocols.token))
                            } else {
                                None
                            };
                            let _ = reply.send(value);
                        }
                    }
                }
                self.protocols.token.clear();
            }
        }

        #[cfg(windows)]
        {
            use raw_window_handle::{HasWindowHandle, RawWindowHandle};
            if let Some(profile) = self.protocols.launch.take() {
                if self.protocols.native.is_some() {
                    self.status =
                        "Bitte die aktive RemoteApp zuerst über ihr Fenster schließen.".into();
                } else {
                    let result =
                        (|| -> anyhow::Result<crate::native_remoteapp::NativeRemoteApp> {
                            let handle = frame
                                .window_handle()
                                .map_err(|error| anyhow::anyhow!("Fensterzugriff: {error}"))?;
                            let RawWindowHandle::Win32(handle) = handle.as_raw() else {
                                anyhow::bail!("Windows-Fenster erforderlich");
                            };
                            let host =
                                crate::native_remoteapp::NativeRemoteApp::new(handle.hwnd.get())?;
                            host.connect(&profile, &profile.options.remote_app)?;
                            Ok(host)
                        })();
                    match result {
                        Ok(host) => {
                            self.protocols.native = Some((profile.name, host));
                            self.status = "RemoteApp-Verbindung gestartet. Anmeldung erfolgt im Windows-Control.".into();
                        }
                        Err(error) => self.status = format!("RemoteApp: {error:#}"),
                    }
                }
            }
            if let Some((title, host)) = &self.protocols.native {
                let mut open = true;
                let mut disconnect = false;
                let prompt_visible = self.protocols.prompt.is_some();
                let mut bounds = None;
                egui::Window::new(format!("RemoteApp · {title}"))
                    .id(egui::Id::new("native_remoteapp"))
                    .open(&mut open).default_size([640.0, 420.0]).show(ctx, |ui| {
                        let state = match host.state() { Ok(0) => "Getrennt", Ok(1) => "Verbunden", Ok(2) => "Verbindungsaufbau", _ => "Status nicht verfügbar" };
                        ui.label(format!("Windows-RDP-Control · {state}"));
                        ui.small("Die RemoteApp kann eigene native Programmfenster öffnen. Schließen dieses Fensters trennt die Sitzung.");
                        if ui.button("RemoteApp trennen").clicked() { disconnect = true; }
                        let (rect, _) = ui.allocate_exact_size(ui.available_size().max(egui::vec2(100.0, 100.0)), Sense::hover());
                        bounds = Some(rect);
                    });
                open &= !disconnect;
                if let Some(rect) = bounds {
                    let scale = ctx.pixels_per_point();
                    if let Err(error) = host.place(
                        (rect.left() * scale) as i32,
                        (rect.top() * scale) as i32,
                        (rect.width() * scale) as i32,
                        (rect.height() * scale) as i32,
                        open && !prompt_visible,
                    ) {
                        self.status = format!("RemoteApp-Fenster: {error}");
                    }
                } else {
                    let _ = host.place(0, 0, 1, 1, false);
                }
                if !open {
                    self.protocols.native = None;
                }
            }
        }
        #[cfg(not(windows))]
        if self.protocols.launch.take().is_some() {
            let _ = frame;
            self.status = "Eingebettete RemoteApps benötigen Windows.".into();
        }
    }
}
