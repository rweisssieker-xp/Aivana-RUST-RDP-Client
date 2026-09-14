//! Directory-first workspace and optional comparison view.
use super::*;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(super) struct WorkbenchState {
    pub directory: bool,
    pub favorites: bool,
    pub split: bool,
    pub scale: f32,
    #[serde(skip)]
    filter: String,
    #[serde(skip)]
    selected: Vec<Uuid>,
    #[serde(skip)]
    exchange: bool,
    #[serde(skip)]
    exchange_path: String,
    #[serde(skip)]
    exchange_message: String,
    #[serde(skip)]
    batch_group: String,
    #[serde(skip)]
    second: Option<Uuid>,
    #[serde(skip)]
    transfer: bool,
    #[serde(skip)]
    upload_paths: String,
    #[serde(skip)]
    download_directory: String,
}

impl Default for WorkbenchState {
    fn default() -> Self {
        Self {
            directory: true,
            favorites: false,
            split: false,
            scale: 1.0,
            filter: String::new(),
            selected: Vec::new(),
            exchange: false,
            exchange_path: String::new(),
            exchange_message: String::new(),
            batch_group: String::new(),
            second: None,
            transfer: false,
            upload_paths: String::new(),
            download_directory: String::new(),
        }
    }
}

fn label_in(ui: &mut Ui, rect: Rect, text: &str, strong: bool, color: Color32) {
    let mut cell = child(ui, (text, rect.left().to_bits()), rect);
    let full_text = text;
    let mut text = RichText::new(text).size(14.0).color(color);
    if strong {
        text = text.strong();
    }
    cell.add(egui::Label::new(text).truncate())
        .on_hover_text(full_text);
}

impl AivanaApp {
    pub(in crate::app) fn workbench_runtime_profile(
        &self,
        source: &ConnectionProfile,
    ) -> anyhow::Result<ConnectionProfile> {
        let mut profile = source.clone();
        if let Some(id) = profile.credential_id {
            if let Some(secret) = self.credentials.get(id)? {
                profile.password = secret.password;
            }
        }
        let gateway = &mut profile.options.gateway;
        if gateway.enabled && !gateway.paa && !gateway.use_profile_credentials {
            let id = gateway.credential_id.ok_or_else(|| {
                anyhow::anyhow!("Gateway credentials missing. Save them in the profile.")
            })?;
            let secret = self.credentials.get(id)?.ok_or_else(|| {
                anyhow::anyhow!("Saved gateway credentials are unavailable.")
            })?;
            gateway.password = secret.password;
        }
        Ok(profile)
    }

    pub(in crate::app) fn workbench_display_settings(&mut self, ui: &mut Ui) {
        ui.heading("Appearance");
        if ui
            .add(
                egui::Slider::new(&mut self.desktop.workbench.scale, 0.8..=1.75)
                    .text("Zoom"),
            )
            .changed()
        {
            ui.ctx().set_zoom_factor(self.desktop.workbench.scale);
            self.save_desktop_layout();
        }
        ui.label("Zoom applies to the user interface. Remote resolution is configured per connection.");
        ui.add_space(16.0);
    }

    pub(in crate::app) fn workbench_profile_options(&mut self, ui: &mut Ui) {
        let options = &mut self.draft.options;
        ui.collapsing("Display & reconnection", |ui| {
            ui.checkbox(&mut options.dynamic_resolution, "Automatically fit resolution to the session window");
            ui.horizontal_wrapped(|ui| {
                ui.label("Starting resolution:");
                ui.add(egui::DragValue::new(&mut options.width).range(200..=8192).suffix(" px wide"));
                ui.add(egui::DragValue::new(&mut options.height).range(200..=8192).suffix(" px high"));
            });
            ui.checkbox(&mut options.auto_reconnect, "Automatically reconnect after a dropped connection");
            ui.label("Multiple remote monitors");
            let mut remove = None;
            for (index, monitor) in options.monitors.iter_mut().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Monitor {}", index + 1));
                    ui.add(egui::DragValue::new(&mut monitor.x).prefix("X "));
                    ui.add(egui::DragValue::new(&mut monitor.y).prefix("Y "));
                    ui.add(egui::DragValue::new(&mut monitor.width).range(200..=8192).suffix(" wide"));
                    ui.add(egui::DragValue::new(&mut monitor.height).range(200..=8192).suffix(" high"));
                    ui.checkbox(&mut monitor.primary, "Primary");
                    if ui.button("Remove").clicked() { remove = Some(index); }
                });
            }
            if let Some(index) = remove { options.monitors.remove(index); }
            if options.monitors.len() < 8 && ui.button("Add monitor").clicked() {
                let x = options.monitors.iter().map(|m| m.x + m.width as i32).max().unwrap_or(0);
                options.monitors.push(crate::connection_options::MonitorLayout {
                    x, y: 0, width: u32::from(options.width), height: u32::from(options.height), primary: options.monitors.is_empty(),
                });
            }
            ui.label("With no entries, a single remote monitor is used. The server must support the layout.");
        });
        ui.collapsing("Clipboard, files & audio", |ui| {
            ui.checkbox(
                &mut options.clipboard,
                "Share clipboard between this computer and the session",
            );
            ui.checkbox(
                &mut options.audio_playback,
                "Play remote audio on this computer",
            );
            ui.checkbox(
                &mut options.microphone,
                "Forward local microphone to the session",
            );
            ui.label("Shared local folders");
            let mut remove = None;
            for (index, folder) in options.shared_folders.iter_mut().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut folder.name)
                            .hint_text("Share name")
                            .desired_width(100.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut folder.path)
                            .hint_text("Local folder path")
                            .desired_width(220.0),
                    );
                    ui.checkbox(&mut folder.read_only, "Read-only");
                    if ui.button("Remove").clicked() {
                        remove = Some(index);
                    }
                });
            }
            if let Some(index) = remove {
                options.shared_folders.remove(index);
            }
            if ui.button("Add folder").clicked() {
                options
                    .shared_folders
                    .push(crate::connection_options::SharedFolder {
                        name: "Files".to_owned(),
                        path: String::new(),
                        read_only: true,
                    });
            }
        });
        ui.collapsing("RD Gateway", |ui| {
            let gateway = &mut options.gateway;
            ui.checkbox(&mut gateway.enabled, "Connect through RD Gateway");
            ui.add_enabled_ui(gateway.enabled, |ui| {
                ui.checkbox(&mut gateway.ntlm, "NTLM (SSPI_NTLM); disabled: Basic over TLS");
                ui.checkbox(&mut gateway.paa, "PAA: enter provider cookie for each connection");
                ui.small("PAA takes precedence over NTLM/Basic. Use only a PAA cookie issued by the gateway provider. General OAuth tokens and OTP codes are not supported. Gateway consent prompts are shown for confirmation; external MFA is awaited for up to 120 seconds.");
                text_field(ui, "Gateway host", &mut gateway.host);
                ui.add(
                    egui::DragValue::new(&mut gateway.port)
                        .range(1..=65535)
                        .prefix("HTTPS port "),
                );
                ui.checkbox(
                    &mut gateway.use_profile_credentials,
                    "Use RDP connection credentials",
                );
                if !gateway.use_profile_credentials {
                    text_field(ui, "Gateway user", &mut gateway.username);
                    text_field(ui, "Gateway domain", &mut gateway.domain);
                    password_field(
                        ui,
                        "Gateway password (blank = use saved password)",
                        &mut gateway.password,
                    );
                }
            });
        });
        ui.label(RichText::new("Changes are saved with the profile and applied on the next connection.").small().color(MUTED));
        ui.collapsing("RemoteApp · embedded Windows control", |ui| {
            ui.small("The session runs in the integrated Windows control; RemoteApps may open their own application windows. Custom working directories are not yet supported.");
            text_field(ui, "Published program (e.g., ||Calculator)", &mut options.remote_app.program);
            text_field(ui, "Display name", &mut options.remote_app.name);
            text_field(ui, "Arguments", &mut options.remote_app.arguments);
            text_field(ui, "Working directory", &mut options.remote_app.working_directory);
            ui.small("Save with the profile. Start under Connections; sign in through the Windows RDP client.");
        });
    }

    pub(super) fn workbench_session_strip(&mut self, ui: &mut Ui) {
        ScrollArea::horizontal()
            .id_salt("workbench-sessions")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for session in self.sessions.clone() {
                        if ui
                            .selectable_label(
                                self.selected_session == Some(session.id),
                                format!("{}  ·  {}", session.title, status_label(session.status)),
                            )
                            .clicked()
                        {
                            self.focus_session(session.id);
                        }
                        ui.separator();
                    }
                });
            });
    }

    pub(super) fn workbench_directory(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(RichText::new("Computer hub").size(28.0).color(INK));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("New connection").clicked() {
                    self.start_new_profile();
                    self.view = View::Connections;
                }
                if ui.button("Import / Export").clicked() {
                    self.desktop.workbench.exchange = true;
                }
                if ui.button("Previews").clicked() {
                    self.desktop.workbench.directory = false;
                    self.save_desktop_layout();
                }
            });
        });
        ui.label(
            RichText::new(
                "Select a computer and connect. Active sessions remain accessible below.",
            )
            .color(MUTED),
        );
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.desktop.workbench.filter)
                    .hint_text("Search computers, addresses, or tags …")
                    .desired_width((ui.available_width() - 180.0).max(180.0)),
            );
            if ui.button("Clear search").clicked() {
                self.desktop.workbench.filter.clear();
            }
        });
        let needle = self.desktop.workbench.filter.trim().to_lowercase();
        let profiles: Vec<_> = self
            .profiles
            .iter()
            .filter(|p| {
                (self.desktop.group.is_empty() || p.group == self.desktop.group)
                    && (!self.desktop.workbench.favorites || p.favorite)
                    && (needle.is_empty()
                        || format!("{} {} {} {}", p.name, p.host, p.group, p.tags.join(" "))
                            .to_lowercase()
                            .contains(&needle))
            })
            .cloned()
            .collect();
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!(
                "{} computers · {} selected",
                profiles.len(),
                self.desktop.workbench.selected.len()
            ))
            .small()
            .color(MUTED),
        );
        if !self.desktop.workbench.selected.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label("Group for selection:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.desktop.workbench.batch_group)
                        .desired_width(130.0),
                );
                if ui.button("Apply").clicked() {
                    let group = self.desktop.workbench.batch_group.trim().to_owned();
                    if !group.is_empty() {
                        let edit = crate::profile_exchange::BatchProfileEdit {
                            group: Some(group),
                            ..Default::default()
                        };
                        if let Err(error) = crate::profile_exchange::apply_batch_edit(
                            &mut self.profiles,
                            &self.desktop.workbench.selected,
                            &edit,
                        ) {
                            self.status = format!("Group change failed: {error}");
                            return;
                        }
                        self.save_profiles();
                    }
                }
                if ui.button("Mark as favorites").clicked() {
                    for p in &mut self.profiles {
                        if self.desktop.workbench.selected.contains(&p.id) {
                            p.favorite = true;
                            p.updated_at = Utc::now();
                        }
                    }
                    self.save_profiles();
                }
                if ui.button("Clear selection").clicked() {
                    self.desktop.workbench.selected.clear();
                }
            });
        }
        ui.add_space(10.0);
        let rect = ui.available_rect_before_wrap();
        let wide = rect.width() >= 900.0;
        let inspector = if wide { 330.0 } else { 0.0 };
        let table_rect = Rect::from_min_max(
            rect.min,
            pos2(
                rect.right() - inspector - if wide { 16.0 } else { 0.0 },
                rect.bottom(),
            ),
        );
        let mut table = child(ui, "directory-table", table_rect);
        self.workbench_table(&mut table, &profiles, !wide);
        if wide {
            let mut detail = child(
                ui,
                "directory-inspector",
                Rect::from_min_max(pos2(rect.right() - inspector, rect.top()), rect.max),
            );
            ScrollArea::vertical()
                .id_salt("inspector-scroll")
                .show(&mut detail, |ui| self.workbench_inspector(ui));
        }
    }

    fn workbench_table(&mut self, ui: &mut Ui, profiles: &[ConnectionProfile], show_actions: bool) {
        let width = ui.available_width();
        let (header, _) = ui.allocate_exact_size(egui::vec2(width, 30.0), Sense::hover());
        let name_x = 36.0;
        let group_x = width * 0.48;
        let status_x = width * 0.73;
        for (left, right, text) in [
            (name_x, group_x, "Computer"),
            (group_x, status_x, "Environment"),
            (status_x, width, "Status"),
        ] {
            label_in(
                ui,
                Rect::from_min_max(
                    header.min + egui::vec2(left, 4.0),
                    pos2(header.left() + right - 8.0, header.bottom()),
                ),
                text,
                false,
                MUTED,
            );
        }
        ui.separator();
        if profiles.is_empty() {
            ui.label("No matching computers. Adjust the search or create a connection.");
            return;
        }
        // At small widths the selected profile actions stay reachable without an inspector.
        if show_actions && self.selected_profile.is_some() {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Connect").clicked() {
                    self.connect_selected();
                }
                if ui.button("Edit profile").clicked() {
                    self.edit_selected_profile();
                    self.view = View::Connections;
                }
            });
        }
        ScrollArea::vertical().id_salt("directory-rows").show_rows(
            ui,
            54.0,
            profiles.len(),
            |ui, rows| {
                for index in rows {
                    let profile = &profiles[index];
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 54.0), Sense::hover());
                    let selected = self.selected_profile == Some(profile.id);
                    if selected {
                        ui.painter()
                            .rect_filled(rect, 3, Color32::from_rgb(221, 237, 239));
                    }
                    ui.painter().hline(
                        rect.x_range(),
                        rect.bottom(),
                        Stroke::new(1.0, tw::SLATE_200),
                    );
                    let mut checked = self.desktop.workbench.selected.contains(&profile.id);
                    let mut check = child(
                        ui,
                        (profile.id, "select"),
                        Rect::from_min_size(
                            rect.min + egui::vec2(6.0, 15.0),
                            egui::vec2(26.0, 26.0),
                        ),
                    );
                    if check
                        .checkbox(&mut checked, "")
                        .on_hover_text("Select for bulk editing")
                        .changed()
                    {
                        if checked {
                            self.desktop.workbench.selected.push(profile.id);
                        } else {
                            self.desktop
                                .workbench
                                .selected
                                .retain(|id| *id != profile.id);
                        }
                    }
                    let status = self
                        .sessions
                        .iter()
                        .rev()
                        .find(|s| s.profile_id == profile.id)
                        .map(|s| status_label(s.status))
                        .unwrap_or("Ready");
                    for (left, right, text, strong) in [
                        (name_x, group_x, profile.name.as_str(), true),
                        (group_x, status_x, profile.group.as_str(), false),
                        (status_x, width, status, false),
                    ] {
                        label_in(
                            ui,
                            Rect::from_min_max(
                                rect.min + egui::vec2(left, 16.0),
                                pos2(rect.left() + right - 8.0, rect.bottom() - 6.0),
                            ),
                            text,
                            strong,
                            if strong { INK } else { MUTED },
                        );
                    }
                    let response = ui
                        .interact(
                            Rect::from_min_max(rect.min + egui::vec2(32.0, 0.0), rect.max),
                            ui.id().with(profile.id),
                            Sense::click(),
                        )
                        .on_hover_text(format!(
                            "{}\n{}:{}",
                            profile.name, profile.host, profile.port
                        ));
                    if response.clicked() {
                        self.selected_profile = Some(profile.id);
                    }
                    response.context_menu(|ui| {
                        if ui.button("Edit profile").clicked() {
                            self.load_profile_into_editor(profile.id);
                            self.view = View::Connections;
                            ui.close();
                        }
                        if ui.button("Duplicate").clicked() {
                            self.workbench_duplicate(profile);
                            ui.close();
                        }
                        if ui.button("Connect").clicked() {
                            self.selected_profile = Some(profile.id);
                            self.connect_selected();
                            ui.close();
                        }
                    });
                }
            },
        );
    }

    fn workbench_duplicate(&mut self, source: &ConnectionProfile) {
        let copy = crate::profile_exchange::duplicate_profile(source);
        self.selected_profile = Some(copy.id);
        self.profiles.push(copy);
        self.save_profiles();
    }

    fn workbench_inspector(&mut self, ui: &mut Ui) {
        let Some(profile) = self.selected_profile().cloned() else {
            ui.label("Select a computer.");
            return;
        };
        ui.heading(RichText::new(&profile.name).size(23.0).color(INK));
        ui.label(
            RichText::new(environment_label(&profile))
                .color(TEAL)
                .strong(),
        );
        ui.add_space(14.0);
        ui.label("Computer address");
        ui.label(RichText::new(format!("{}:{}", profile.host, profile.port)).strong());
        ui.add_space(8.0);
        ui.label(format!("User: {}", profile.username));
        ui.label(format!(
            "Modified: {}",
            profile
                .updated_at
                .with_timezone(&chrono::Local)
                .format("%m/%d/%Y %H:%M")
        ));
        ui.add_space(16.0);
        let session = self
            .sessions
            .iter()
            .rev()
            .find(|s| s.profile_id == profile.id)
            .cloned();
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 180.0), Sense::hover());
        ui.painter().rect_filled(rect, 5, tw::SLATE_900);
        if let Some(session) = &session {
            self.desktop_preview(ui, rect, session);
        } else {
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "No session yet",
                FontId::proportional(15.0),
                tw::SLATE_300,
            );
        }
        ui.add_space(12.0);
        if ui
            .add_sized(
                egui::vec2(ui.available_width(), 40.0),
                egui::Button::new(
                    RichText::new(if session.is_some() {
                        "Open session"
                    } else {
                        "Connect"
                    })
                    .color(Color32::WHITE),
                )
                .fill(TEAL),
            )
            .clicked()
        {
            if let Some(session) = session {
                self.focus_session(session.id);
            } else {
                self.connect_selected();
            }
        }
        ui.horizontal(|ui| {
            if ui.button("Edit").clicked() {
                self.load_profile_into_editor(profile.id);
                self.view = View::Connections;
            }
            if ui.button("Duplicate").clicked() {
                self.workbench_duplicate(&profile);
            }
            let mut favorite = profile.favorite;
            if ui.checkbox(&mut favorite, "Favorite").changed() {
                if let Some(p) = self.profiles.iter_mut().find(|p| p.id == profile.id) {
                    p.favorite = favorite;
                }
                self.save_profiles();
            }
        });
        ui.add_space(10.0);
        ui.collapsing("Certificate & access", |ui| {
            ui.label(&self.certificate_notice);
            if ui.button("Check certificate").clicked() {
                self.probe_selected_certificate();
            }
            if ui.button("Trust certificate").clicked() {
                self.trust_selected_certificate();
            }
            if ui.button("Edit credentials").clicked() {
                self.load_profile_into_editor(profile.id);
                self.view = View::Connections;
            }
        });
    }

    pub(super) fn workbench_open_transfer(&mut self) {
        self.desktop.workbench.transfer = true;
    }

    pub(super) fn workbench_split(&mut self, ui: &mut Ui, active: &RemoteSession) {
        let candidates: Vec<_> = self
            .sessions
            .iter()
            .filter(|s| s.id != active.id)
            .cloned()
            .collect();
        if candidates.is_empty() {
            ui.label("Open another session for the side-by-side view.");
            self.remote_canvas(ui, active.id);
            return;
        }
        if !candidates
            .iter()
            .any(|s| Some(s.id) == self.desktop.workbench.second)
        {
            self.desktop.workbench.second = Some(candidates[0].id);
        }
        ui.horizontal_wrapped(|ui| {
            ui.label("Second session:");
            egui::ComboBox::from_id_salt("second-session")
                .selected_text(
                    candidates
                        .iter()
                        .find(|s| Some(s.id) == self.desktop.workbench.second)
                        .map(|s| s.title.as_str())
                        .unwrap_or("Select"),
                )
                .show_ui(ui, |ui| {
                    for s in &candidates {
                        ui.selectable_value(
                            &mut self.desktop.workbench.second,
                            Some(s.id),
                            &s.title,
                        );
                    }
                });
            ui.label(
                RichText::new("Only the active session receives input.")
                    .small()
                    .color(tw::SLATE_300),
            );
        });
        let second = candidates
            .iter()
            .find(|s| Some(s.id) == self.desktop.workbench.second)
            .unwrap();
        let rect = ui.available_rect_before_wrap();
        let horizontal = rect.width() >= 850.0;
        let (left, right) = if horizontal {
            (
                Rect::from_min_max(rect.min, pos2(rect.center().x - 6.0, rect.bottom())),
                Rect::from_min_max(pos2(rect.center().x + 6.0, rect.top()), rect.max),
            )
        } else {
            (
                Rect::from_min_max(rect.min, pos2(rect.right(), rect.center().y - 6.0)),
                Rect::from_min_max(pos2(rect.left(), rect.center().y + 6.0), rect.max),
            )
        };
        let mut primary = child(ui, (active.id, "split-active"), left);
        primary.label(
            RichText::new(format!("{} · Active", active.title))
                .strong()
                .color(Color32::from_rgb(132, 211, 221)),
        );
        self.remote_canvas(&mut primary, active.id);
        let mut secondary = child(ui, (second.id, "split-preview"), right);
        if secondary
            .button(format!("{} · Activate", second.title))
            .clicked()
        {
            self.desktop.workbench.second = Some(active.id);
            self.focus_session(second.id);
        }
        let preview = secondary.available_rect_before_wrap();
        secondary.painter().rect_filled(preview, 3, tw::SLATE_900);
        self.desktop_preview(&secondary, preview, second);
        if secondary
            .interact(preview, secondary.id().with("activate"), Sense::click())
            .clicked()
        {
            self.desktop.workbench.second = Some(active.id);
            self.focus_session(second.id);
        }
    }

    pub(super) fn workbench_dialogs(&mut self, ctx: &Context) {
        if self.desktop.workbench.transfer {
            let mut open = true;
            egui::Window::new("File transfer").open(&mut open).default_width(570.0).show(ctx, |ui| {
                let Some(session) = self.selected_session().cloned() else { ui.label("Open a session first."); return; };
                ui.label(RichText::new(format!("Target: {}", session.title)).strong());
                let enabled = session.status == SessionStatus::Connected && self.profiles.iter().find(|p| p.id == session.profile_id).is_some_and(|p| p.options.clipboard);
                ui.label("File transfer requires clipboard sharing enabled in the connection profile.");
                ui.add_enabled_ui(enabled, |ui| {
                    ui.label("Local files (one full path per line)");
                    ui.add(egui::TextEdit::multiline(&mut self.desktop.workbench.upload_paths).desired_rows(3).desired_width(f32::INFINITY));
                    if ui.button("Make files available to paste").clicked() {
                        let paths: Vec<String> = self.desktop.workbench.upload_paths.lines().map(str::trim).filter(|p| !p.is_empty()).map(str::to_owned).collect();
                        self.status = if paths.is_empty() { "Select at least one file path.".to_owned() }
                        else { match self.engine.send_input(session.id, InputAction::ClipboardFiles { paths }) {
                            Ok(()) => "Files requested. After confirmation in event history, paste them in remote File Explorer.".to_owned(),
                            Err(err) => format!("Could not make files available: {err}"),
                        }};
                    }
                    ui.separator();
                    ui.label("From the remote computer: copy files there, then retrieve them locally.");
                    text_field(ui, "Local destination folder", &mut self.desktop.workbench.download_directory);
                    if ui.button("Save copied files here").clicked() {
                        let directory = self.desktop.workbench.download_directory.trim().to_owned();
                        self.status = if directory.is_empty() { "Enter a local destination folder.".to_owned() }
                        else { match self.engine.send_input(session.id, InputAction::ClipboardDownload { directory }) {
                            Ok(()) => "File retrieval requested. See event history for the result.".to_owned(),
                            Err(err) => format!("File retrieval failed: {err}"),
                        }};
                    }
                });
                ui.label(&self.status);
                if ui.button("Show event history").clicked() { self.desktop.timeline = true; }
            });
            self.desktop.workbench.transfer = open;
        }
        if !self.desktop.workbench.exchange {
            return;
        }
        let mut open = true;
        egui::Window::new("Import / export connections")
            .open(&mut open)
            .default_width(540.0)
            .show(ctx, |ui| {
                ui.label("File path (.rdp, .csv, or .json)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.desktop.workbench.exchange_path)
                        .desired_width(f32::INFINITY),
                );
                ui.label("Credentials are managed separately in protected storage.");
                self.workbench_exchange_actions(ui);
                ui.label(&self.desktop.workbench.exchange_message);
            });
        self.desktop.workbench.exchange = open;
    }

    fn workbench_exchange_actions(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("Import").clicked() {
                match crate::profile_exchange::import_profiles(std::path::Path::new(
                    self.desktop.workbench.exchange_path.trim(),
                )) {
                    Ok(profiles) => {
                        let count = profiles.len();
                        self.profiles.extend(profiles);
                        self.save_profiles();
                        self.desktop.workbench.exchange_message =
                            format!("{count} connections imported.");
                    }
                    Err(err) => {
                        self.desktop.workbench.exchange_message =
                            format!("Import failed: {err}")
                    }
                }
            }
            if ui.button("Export selection").clicked() {
                let profiles: Vec<_> = self
                    .profiles
                    .iter()
                    .filter(|p| self.desktop.workbench.selected.contains(&p.id))
                    .cloned()
                    .collect();
                self.desktop.workbench.exchange_message = if profiles.is_empty() {
                    "Select connections using the checkboxes first.".to_owned()
                } else {
                    match crate::profile_exchange::export_profiles(
                        std::path::Path::new(self.desktop.workbench.exchange_path.trim()),
                        &profiles,
                    ) {
                        Ok(()) => format!("{} connections exported.", profiles.len()),
                        Err(err) => format!("Export failed: {err}"),
                    }
                };
            }
        });
    }
}
