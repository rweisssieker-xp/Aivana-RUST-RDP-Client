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
        if gateway.enabled && !gateway.use_profile_credentials {
            let id = gateway.credential_id.ok_or_else(|| {
                anyhow::anyhow!("Gateway-Zugangsdaten fehlen. Bitte im Profil speichern.")
            })?;
            let secret = self.credentials.get(id)?.ok_or_else(|| {
                anyhow::anyhow!("Gespeicherte Gateway-Zugangsdaten sind nicht verfügbar.")
            })?;
            gateway.password = secret.password;
        }
        Ok(profile)
    }

    pub(in crate::app) fn workbench_display_settings(&mut self, ui: &mut Ui) {
        ui.heading("Darstellung");
        if ui
            .add(
                egui::Slider::new(&mut self.desktop.workbench.scale, 0.8..=1.75)
                    .text("Vergrößerung"),
            )
            .changed()
        {
            ui.ctx().set_zoom_factor(self.desktop.workbench.scale);
            self.save_desktop_layout();
        }
        ui.label("Die Vergrößerung gilt für die Bedienoberfläche. Die Remote-Auflösung wird je Verbindung eingestellt.");
        ui.add_space(16.0);
    }

    pub(in crate::app) fn workbench_profile_options(&mut self, ui: &mut Ui) {
        let options = &mut self.draft.options;
        ui.collapsing("Anzeige & Wiederverbindung", |ui| {
            ui.checkbox(&mut options.dynamic_resolution, "Auflösung automatisch an das Sitzungsfenster anpassen");
            ui.horizontal_wrapped(|ui| {
                ui.label("Startauflösung:");
                ui.add(egui::DragValue::new(&mut options.width).range(200..=8192).suffix(" px breit"));
                ui.add(egui::DragValue::new(&mut options.height).range(200..=8192).suffix(" px hoch"));
            });
            ui.checkbox(&mut options.auto_reconnect, "Bei Verbindungsabbruch automatisch erneut verbinden");
            ui.label("Mehrere Remote-Monitore");
            let mut remove = None;
            for (index, monitor) in options.monitors.iter_mut().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Monitor {}", index + 1));
                    ui.add(egui::DragValue::new(&mut monitor.x).prefix("X "));
                    ui.add(egui::DragValue::new(&mut monitor.y).prefix("Y "));
                    ui.add(egui::DragValue::new(&mut monitor.width).range(200..=8192).suffix(" breit"));
                    ui.add(egui::DragValue::new(&mut monitor.height).range(200..=8192).suffix(" hoch"));
                    ui.checkbox(&mut monitor.primary, "Primär");
                    if ui.button("Entfernen").clicked() { remove = Some(index); }
                });
            }
            if let Some(index) = remove { options.monitors.remove(index); }
            if options.monitors.len() < 8 && ui.button("Monitor hinzufügen").clicked() {
                let x = options.monitors.iter().map(|m| m.x + m.width as i32).max().unwrap_or(0);
                options.monitors.push(crate::connection_options::MonitorLayout {
                    x, y: 0, width: u32::from(options.width), height: u32::from(options.height), primary: options.monitors.is_empty(),
                });
            }
            ui.label("Ohne Einträge wird ein einzelner Remote-Monitor verwendet. Die Anordnung benötigt Unterstützung durch den Server.");
        });
        ui.collapsing("Zwischenablage, Dateien & Audio", |ui| {
            ui.checkbox(
                &mut options.clipboard,
                "Zwischenablage zwischen diesem Rechner und der Sitzung freigeben",
            );
            ui.checkbox(
                &mut options.audio_playback,
                "Remote-Audio auf diesem Rechner wiedergeben",
            );
            ui.checkbox(
                &mut options.microphone,
                "Lokales Mikrofon an die Sitzung weiterleiten",
            );
            ui.label("Freigegebene lokale Ordner");
            let mut remove = None;
            for (index, folder) in options.shared_folders.iter_mut().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut folder.name)
                            .hint_text("Freigabename")
                            .desired_width(100.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut folder.path)
                            .hint_text("Lokaler Ordnerpfad")
                            .desired_width(220.0),
                    );
                    ui.checkbox(&mut folder.read_only, "Nur lesen");
                    if ui.button("Entfernen").clicked() {
                        remove = Some(index);
                    }
                });
            }
            if let Some(index) = remove {
                options.shared_folders.remove(index);
            }
            if ui.button("Ordner hinzufügen").clicked() {
                options
                    .shared_folders
                    .push(crate::connection_options::SharedFolder {
                        name: "Dateien".to_owned(),
                        path: String::new(),
                        read_only: true,
                    });
            }
        });
        ui.collapsing("RD Gateway", |ui| {
            let gateway = &mut options.gateway;
            ui.checkbox(&mut gateway.enabled, "Über RD Gateway verbinden");
            ui.add_enabled_ui(gateway.enabled, |ui| {
                text_field(ui, "Gateway-Rechner", &mut gateway.host);
                ui.add(
                    egui::DragValue::new(&mut gateway.port)
                        .range(1..=65535)
                        .prefix("HTTPS-Port "),
                );
                ui.checkbox(
                    &mut gateway.use_profile_credentials,
                    "Zugangsdaten der RDP-Verbindung verwenden",
                );
                if !gateway.use_profile_credentials {
                    text_field(ui, "Gateway-Benutzer", &mut gateway.username);
                    text_field(ui, "Gateway-Domäne", &mut gateway.domain);
                    password_field(
                        ui,
                        "Gateway-Passwort (leer = gespeichertes verwenden)",
                        &mut gateway.password,
                    );
                }
            });
        });
        ui.label(RichText::new("Änderungen werden mit dem Profil gespeichert und beim nächsten Verbindungsaufbau angewendet.").small().color(MUTED));
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
            ui.heading(RichText::new("Rechnerzentrale").size(28.0).color(INK));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Neue Verbindung").clicked() {
                    self.start_new_profile();
                    self.view = View::Connections;
                }
                if ui.button("Import / Export").clicked() {
                    self.desktop.workbench.exchange = true;
                }
                if ui.button("Vorschauen").clicked() {
                    self.desktop.workbench.directory = false;
                    self.save_desktop_layout();
                }
            });
        });
        ui.label(
            RichText::new(
                "Rechner auswählen und verbinden. Aktive Sitzungen bleiben unten erreichbar.",
            )
            .color(MUTED),
        );
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.desktop.workbench.filter)
                    .hint_text("Rechner, Adresse oder Schlagwort suchen …")
                    .desired_width((ui.available_width() - 180.0).max(180.0)),
            );
            if ui.button("Suche leeren").clicked() {
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
                "{} Rechner · {} ausgewählt",
                profiles.len(),
                self.desktop.workbench.selected.len()
            ))
            .small()
            .color(MUTED),
        );
        if !self.desktop.workbench.selected.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label("Gruppe für Auswahl:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.desktop.workbench.batch_group)
                        .desired_width(130.0),
                );
                if ui.button("Anwenden").clicked() {
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
                            self.status = format!("Gruppenänderung fehlgeschlagen: {error}");
                            return;
                        }
                        self.save_profiles();
                    }
                }
                if ui.button("Als Favoriten markieren").clicked() {
                    for p in &mut self.profiles {
                        if self.desktop.workbench.selected.contains(&p.id) {
                            p.favorite = true;
                            p.updated_at = Utc::now();
                        }
                    }
                    self.save_profiles();
                }
                if ui.button("Auswahl aufheben").clicked() {
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
            (name_x, group_x, "Rechner"),
            (group_x, status_x, "Umgebung"),
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
            ui.label("Keine passenden Rechner. Passe die Suche an oder lege eine Verbindung an.");
            return;
        }
        // At small widths the selected profile actions stay reachable without an inspector.
        if show_actions && self.selected_profile.is_some() {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Verbinden").clicked() {
                    self.connect_selected();
                }
                if ui.button("Profil bearbeiten").clicked() {
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
                        .on_hover_text("Für gemeinsame Bearbeitung auswählen")
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
                        .unwrap_or("Bereit");
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
                        if ui.button("Profil bearbeiten").clicked() {
                            self.load_profile_into_editor(profile.id);
                            self.view = View::Connections;
                            ui.close();
                        }
                        if ui.button("Duplizieren").clicked() {
                            self.workbench_duplicate(profile);
                            ui.close();
                        }
                        if ui.button("Verbinden").clicked() {
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
            ui.label("Wähle einen Rechner aus.");
            return;
        };
        ui.heading(RichText::new(&profile.name).size(23.0).color(INK));
        ui.label(
            RichText::new(environment_label(&profile))
                .color(TEAL)
                .strong(),
        );
        ui.add_space(14.0);
        ui.label("Rechneradresse");
        ui.label(RichText::new(format!("{}:{}", profile.host, profile.port)).strong());
        ui.add_space(8.0);
        ui.label(format!("Benutzer: {}", profile.username));
        ui.label(format!(
            "Geändert: {}",
            profile
                .updated_at
                .with_timezone(&chrono::Local)
                .format("%d.%m.%Y %H:%M")
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
                "Noch keine Sitzung",
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
                        "Sitzung öffnen"
                    } else {
                        "Verbinden"
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
            if ui.button("Bearbeiten").clicked() {
                self.load_profile_into_editor(profile.id);
                self.view = View::Connections;
            }
            if ui.button("Duplizieren").clicked() {
                self.workbench_duplicate(&profile);
            }
            let mut favorite = profile.favorite;
            if ui.checkbox(&mut favorite, "Favorit").changed() {
                if let Some(p) = self.profiles.iter_mut().find(|p| p.id == profile.id) {
                    p.favorite = favorite;
                }
                self.save_profiles();
            }
        });
        ui.add_space(10.0);
        ui.collapsing("Zertifikat & Zugang", |ui| {
            ui.label(&self.certificate_notice);
            if ui.button("Zertifikat prüfen").clicked() {
                self.probe_selected_certificate();
            }
            if ui.button("Zertifikat vertrauen").clicked() {
                self.trust_selected_certificate();
            }
            if ui.button("Zugangsdaten bearbeiten").clicked() {
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
            ui.label("Öffne eine weitere Sitzung für die Ansicht nebeneinander.");
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
            ui.label("Zweite Sitzung:");
            egui::ComboBox::from_id_salt("second-session")
                .selected_text(
                    candidates
                        .iter()
                        .find(|s| Some(s.id) == self.desktop.workbench.second)
                        .map(|s| s.title.as_str())
                        .unwrap_or("Auswählen"),
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
                RichText::new("Nur die aktive Sitzung erhält Eingaben.")
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
            RichText::new(format!("{} · Aktiv", active.title))
                .strong()
                .color(Color32::from_rgb(132, 211, 221)),
        );
        self.remote_canvas(&mut primary, active.id);
        let mut secondary = child(ui, (second.id, "split-preview"), right);
        if secondary
            .button(format!("{} · Aktivieren", second.title))
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
            egui::Window::new("Dateiübertragung").open(&mut open).default_width(570.0).show(ctx, |ui| {
                let Some(session) = self.selected_session().cloned() else { ui.label("Öffne zuerst eine Sitzung."); return; };
                ui.label(RichText::new(format!("Ziel: {}", session.title)).strong());
                let enabled = session.status == SessionStatus::Connected && self.profiles.iter().find(|p| p.id == session.profile_id).is_some_and(|p| p.options.clipboard);
                ui.label("Für Dateien muss die Zwischenablage im Verbindungsprofil freigegeben sein.");
                ui.add_enabled_ui(enabled, |ui| {
                    ui.label("Lokale Dateien (ein vollständiger Pfad pro Zeile)");
                    ui.add(egui::TextEdit::multiline(&mut self.desktop.workbench.upload_paths).desired_rows(3).desired_width(f32::INFINITY));
                    if ui.button("Dateien zum Einfügen bereitstellen").clicked() {
                        let paths: Vec<String> = self.desktop.workbench.upload_paths.lines().map(str::trim).filter(|p| !p.is_empty()).map(str::to_owned).collect();
                        self.status = if paths.is_empty() { "Wähle mindestens einen Dateipfad.".to_owned() }
                        else { match self.engine.send_input(session.id, InputAction::ClipboardFiles { paths }) {
                            Ok(()) => "Dateien angefordert. Nach Bestätigung im Ereignisverlauf im Remote-Explorer einfügen.".to_owned(),
                            Err(err) => format!("Dateien konnten nicht bereitgestellt werden: {err}"),
                        }};
                    }
                    ui.separator();
                    ui.label("Vom Remote-Rechner: Dateien dort kopieren, dann lokal abrufen.");
                    text_field(ui, "Lokaler Zielordner", &mut self.desktop.workbench.download_directory);
                    if ui.button("Kopierte Dateien hier speichern").clicked() {
                        let directory = self.desktop.workbench.download_directory.trim().to_owned();
                        self.status = if directory.is_empty() { "Gib einen lokalen Zielordner an.".to_owned() }
                        else { match self.engine.send_input(session.id, InputAction::ClipboardDownload { directory }) {
                            Ok(()) => "Dateiabruf angefordert. Ergebnis im Ereignisverlauf.".to_owned(),
                            Err(err) => format!("Dateiabruf fehlgeschlagen: {err}"),
                        }};
                    }
                });
                ui.label(&self.status);
                if ui.button("Ereignisverlauf anzeigen").clicked() { self.desktop.timeline = true; }
            });
            self.desktop.workbench.transfer = open;
        }
        if !self.desktop.workbench.exchange {
            return;
        }
        let mut open = true;
        egui::Window::new("Verbindungen importieren / exportieren")
            .open(&mut open)
            .default_width(540.0)
            .show(ctx, |ui| {
                ui.label("Dateipfad (.rdp, .csv oder .json)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.desktop.workbench.exchange_path)
                        .desired_width(f32::INFINITY),
                );
                ui.label("Zugangsdaten werden separat im geschützten Speicher verwaltet.");
                self.workbench_exchange_actions(ui);
                ui.label(&self.desktop.workbench.exchange_message);
            });
        self.desktop.workbench.exchange = open;
    }

    fn workbench_exchange_actions(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("Importieren").clicked() {
                match crate::profile_exchange::import_profiles(std::path::Path::new(
                    self.desktop.workbench.exchange_path.trim(),
                )) {
                    Ok(profiles) => {
                        let count = profiles.len();
                        self.profiles.extend(profiles);
                        self.save_profiles();
                        self.desktop.workbench.exchange_message =
                            format!("{count} Verbindungen importiert.");
                    }
                    Err(err) => {
                        self.desktop.workbench.exchange_message =
                            format!("Import fehlgeschlagen: {err}")
                    }
                }
            }
            if ui.button("Auswahl exportieren").clicked() {
                let profiles: Vec<_> = self
                    .profiles
                    .iter()
                    .filter(|p| self.desktop.workbench.selected.contains(&p.id))
                    .cloned()
                    .collect();
                self.desktop.workbench.exchange_message = if profiles.is_empty() {
                    "Wähle zuerst Verbindungen über die Kontrollkästchen aus.".to_owned()
                } else {
                    match crate::profile_exchange::export_profiles(
                        std::path::Path::new(self.desktop.workbench.exchange_path.trim()),
                        &profiles,
                    ) {
                        Ok(()) => format!("{} Verbindungen exportiert.", profiles.len()),
                        Err(err) => format!("Export fehlgeschlagen: {err}"),
                    }
                };
            }
        });
    }
}
