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

impl ProtocolState {
    /// Legacy encryption belongs to the Windows control. Keep the user's
    /// authentication, redirection and credential settings unchanged.
    pub(super) fn queue_standard_rdp(&mut self, profile: ConnectionProfile) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            self.launch = Some(profile);
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = profile;
            anyhow::bail!("Standard RDP Security requires the embedded Windows RDP control. Enable TLS/NLA on the server to use the Rust engine on this platform.")
        }
    }
}

#[cfg(all(test, windows))]
mod legacy_routing_tests {
    use super::*;

    #[test]
    fn standard_rdp_is_queued_for_windows_without_changing_security_or_identity() {
        let mut profile = ConnectionProfile::sample("legacy", "legacy.example", "test", false);
        profile.username = "test-user".into();
        profile.domain = "test-domain".into();
        profile.password = "fixture-only".into();
        profile.port = 3390;
        profile.options.mstsc.set("authentication level", 1).unwrap();
        profile.options.mstsc.set("enablecredsspsupport", 1).unwrap();
        let before = serde_json::to_value(&profile).unwrap();
        let mut protocols = ProtocolState::default();
        protocols.queue_standard_rdp(profile).unwrap();
        assert_eq!(serde_json::to_value(protocols.launch.unwrap()).unwrap(), before);
        assert!(protocols.native.is_none(), "queuing must not initiate a connection in a test or worker");
    }
}

fn prompt_expired(prompt: &GatewayInteraction) -> bool {
    match prompt {
        GatewayInteraction::Consent { reply, .. } => reply.is_closed(),
        GatewayInteraction::PaaToken { reply, .. } => reply.is_closed(),
    }
}

// Windows can display its own connection and credential UI before a desktop
// exists. Only a disconnected control should be hidden.
#[cfg(any(windows, test))]
fn native_surface_visible(state: Option<i32>) -> bool {
    matches!(state, Some(1 | 2))
}

#[cfg(test)]
mod native_surface_tests {
    use super::native_surface_visible;

    #[test]
    fn keeps_windows_connection_ui_visible_until_disconnected() {
        assert!(native_surface_visible(Some(2)));
        assert!(native_surface_visible(Some(1)));
        assert!(!native_surface_visible(Some(0)));
        assert!(!native_surface_visible(None));
    }
}

impl AivanaApp {
    pub(super) fn connect_vnc(&mut self, mut profile: ConnectionProfile) {
        // RDP options retained in a switched profile must not affect VNC.
        profile.options = Default::default();
        let result = self
            .workbench_runtime_profile(&profile)
            .and_then(|runtime| self.engine.connect(&runtime));
        match result {
            Ok(session) => {
                self.session_sources
                    .insert(session.id, crate::mission::Target::from_profile(&profile));
                self.autopilot.abort();
                self.selected_session = Some(session.id);
                self.sessions.push(session);
                self.desktop.focus = true;
                self.view = View::Sessions;
                self.status = format!("Connecting via VNC to {}", profile.name);
            }
            Err(error) => self.status = format!("VNC: {error:#}"),
        }
    }

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
            egui::Window::new("RD Gateway · confirmation required")
                .id(egui::Id::new("gateway_interaction"))
                .open(&mut open).collapsible(false).resizable(true).default_width(560.0)
                .show(ctx, |ui| {
                    match prompt {
                        GatewayInteraction::Consent { gateway, message, .. } => {
                            ui.label(RichText::new(gateway).strong());
                            ui.label("The gateway requires your consent before connecting.");
                            egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| { ui.label(message); });
                            ui.horizontal(|ui| {
                                if ui.button("Agree and continue").clicked() { decision = Some(true); }
                                if ui.button("Decline").clicked() { decision = Some(false); }
                            });
                        }
                        GatewayInteraction::PaaToken { gateway, .. } => {
                            ui.label(RichText::new(gateway).strong());
                            ui.label("Enter your gateway provider's PAA cookie. The cookie is used only for this connection.");
                            ui.small("This is not a general OAuth token or OTP code. Sign in through the provider's documented browser flow.");
                            ui.add(egui::TextEdit::singleline(&mut self.protocols.token).password(true).char_limit(32749).hint_text("PAA cookie"));
                            ui.horizontal(|ui| {
                                if ui.add_enabled(!self.protocols.token.is_empty(), egui::Button::new("Use cookie")).clicked() { decision = Some(true); }
                                if ui.button("Cancel").clicked() { decision = Some(false); }
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
                        "Close the active Windows RDP session through its window first.".into();
                } else {
                    let result =
                        (|| -> anyhow::Result<crate::native_remoteapp::NativeRemoteApp> {
                            let handle = frame
                                .window_handle()
                                .map_err(|error| anyhow::anyhow!("Window access: {error}"))?;
                            let RawWindowHandle::Win32(handle) = handle.as_raw() else {
                                anyhow::bail!("Windows window required");
                            };
                            let host =
                                crate::native_remoteapp::NativeRemoteApp::new(handle.hwnd.get())?;
                            host.connect(&profile, &profile.options.remote_app)?;
                            Ok(host)
                        })();
                    match result {
                        Ok(host) => {
                            self.protocols.native = Some((profile.name, host));
                            self.status = "Windows RDP connection started. Authentication is handled by the Windows control.".into();
                        }
                        Err(error) => self.status = format!("Windows RDP: {error:#}"),
                    }
                }
            }
            if let Some((title, host)) = &self.protocols.native {
                let mut open = true;
                let mut disconnect = false;
                let prompt_visible = self.protocols.prompt.is_some();
                let connection_state = host.state().ok();
                let mut bounds = None;
                egui::Window::new(format!("Windows RDP · {title}"))
                    .id(egui::Id::new("native_remoteapp"))
                    .open(&mut open).default_size([640.0, 420.0]).show(ctx, |ui| {
                        let state = match connection_state { Some(0) => "Disconnected", Some(1) => "Connected", Some(2) => "Connecting", _ => "Status unavailable" };
                        ui.label(format!("Windows RDP control · {state}"));
                        ui.small("Closing this window disconnects the session. Published RemoteApps may open separate application windows.");
                        if ui.button("Disconnect Windows RDP").clicked() { disconnect = true; }
                        if connection_state == Some(2) {
                            ui.spinner();
                            ui.label("Connecting. Complete any Windows sign-in dialog to continue.");
                        }
                        if native_surface_visible(connection_state) {
                            let (rect, _) = ui.allocate_exact_size(ui.available_size().max(egui::vec2(100.0, 100.0)), Sense::hover());
                            bounds = Some(rect);
                        } else {
                            ui.label("No remote desktop is connected. Close this session window and reconnect to try again.");
                            ui.label("If sign-in was rejected, check the username, domain and saved credentials.");
                            if let Ok(reason) = host.disconnect_reason() {
                                ui.label(format!("Windows extended disconnect reason: {reason}"));
                            }
                        }
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
                        self.status = format!("RemoteApp window: {error}");
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
            self.status = "This profile requires Windows RDP. Use the Rust connection mode on this platform.".into();
        }
    }
}
