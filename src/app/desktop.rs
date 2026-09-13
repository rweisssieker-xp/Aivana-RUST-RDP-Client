//! Native spatial workspace, focused session and contextual incident investigation.
use super::*;

mod workbench;

const INK: Color32 = Color32::from_rgb(24, 43, 53);
const TEAL: Color32 = Color32::from_rgb(0, 108, 123);
const PAPER: Color32 = Color32::from_rgb(245, 248, 248);
const MUTED: Color32 = Color32::from_rgb(91, 111, 120);
const AMBER: Color32 = Color32::from_rgb(159, 87, 12);

#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(super) struct DesktopState {
    locale: crate::localization::Locale,
    order: Vec<Uuid>,
    group: String,
    compact: bool,
    featured: Option<Uuid>,
    workbench: workbench::WorkbenchState,
    #[serde(skip)]
    pub focus: bool,
    #[serde(skip)]
    pub assistant: bool,
    #[serde(skip)]
    pub(super) timeline: bool,
    #[serde(skip)]
    pub(super) palette: bool,
    #[serde(skip)]
    palette_focus: bool,
    #[serde(skip)]
    query: String,
    #[serde(skip)]
    dragging: Option<Uuid>,
    #[serde(skip)]
    event: Option<Uuid>,
}

impl DesktopState {
    pub fn load() -> Self {
        let mut state: Self = app_data_file("desktop-layout.json")
            .ok()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let args = std::env::args().collect::<Vec<_>>();
        if let Some(language) = args.windows(2).find(|w| w[0] == "--language")
            .and_then(|w| crate::localization::Locale::parse(&w[1])) {
            state.locale = language;
        }
        state
    }

    fn save(&self) -> anyhow::Result<()> {
        let path = app_data_file("desktop-layout.json")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    fn move_before(&mut self, source: Uuid, target: Uuid) {
        if source == target || !self.order.contains(&target) {
            return;
        }
        self.order.retain(|id| *id != source);
        if let Some(index) = self.order.iter().position(|id| *id == target) {
            self.order.insert(index, source);
        }
    }
}

pub(super) fn needs_attention(status: SessionStatus) -> bool {
    matches!(
        status,
        SessionStatus::Failed | SessionStatus::Disconnected | SessionStatus::Reconnecting
    )
}

fn status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Connected => "Verbunden",
        SessionStatus::Connecting => "Verbindungsaufbau",
        SessionStatus::Authenticating => "Anmeldung",
        SessionStatus::Reconnecting => "Wiederverbinden",
        SessionStatus::Suspended => "Pausiert",
        SessionStatus::Disconnected => "Getrennt",
        SessionStatus::Failed => "Verbindung fehlgeschlagen",
    }
}

fn environment_label(profile: &ConnectionProfile) -> String {
    if std::iter::once(&profile.group)
        .chain(profile.tags.iter())
        .any(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "production" | "produktion" | "prod"
            )
        })
    {
        "PRODUKTION".to_owned()
    } else {
        profile.group.clone()
    }
}

fn child(ui: &mut Ui, id: impl std::hash::Hash, rect: Rect) -> Ui {
    let mut child = ui.new_child(
        UiBuilder::new()
            .id_salt(id)
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
    );
    child.set_clip_rect(rect.intersect(ui.clip_rect()));
    child
}

impl AivanaApp {
    pub(super) fn desktop_shell(&mut self, ui: &mut Ui) {
        let locale = self.desktop.locale;
        let ctx = ui.ctx().clone();
        let scale = self.desktop.workbench.scale.clamp(0.8, 1.75);
        if (ctx.zoom_factor() - scale).abs() > 0.01 {
            ctx.set_zoom_factor(scale);
        }
        let shortcut = if self.desktop.focus {
            egui::Modifiers::CTRL | egui::Modifiers::SHIFT
        } else {
            egui::Modifiers::CTRL
        };
        if ctx.input_mut(|input| input.consume_key(shortcut, egui::Key::K)) {
            self.desktop.palette = !self.desktop.palette;
            self.desktop.palette_focus = self.desktop.palette;
            self.desktop.query.clear();
        }
        let focused =
            self.view == View::Sessions && self.desktop.focus && self.selected_session.is_some();
        let root = ui.max_rect();
        ui.painter().rect_filled(
            root,
            0,
            if focused {
                Color32::from_rgb(30, 36, 43)
            } else {
                PAPER
            },
        );
        let header = Rect::from_min_size(root.min, egui::vec2(root.width(), 62.0));
        let mut top = child(ui, "desktop-header", header.shrink2(egui::vec2(18.0, 10.0)));
        if focused {
            top.style_mut().visuals = egui::Visuals::dark();
        }
        top.horizontal(|ui| {
            let previous = self.desktop.locale;
            egui::ComboBox::from_id_salt("application-language")
                .selected_text(self.desktop.locale.name())
                .show_ui(ui, |ui| {
                    for language in crate::localization::Locale::ALL {
                        ui.selectable_value(&mut self.desktop.locale, language, language.name());
                    }
                });
            if previous != self.desktop.locale { self.save_desktop_layout(); }
            ui.label(
                RichText::new("Relayne")
                    .size(25.0)
                    .strong()
                    .color(if focused {
                        Color32::from_rgb(132, 211, 221)
                    } else {
                        TEAL
                    }),
            );
            ui.add_space(12.0);
            if (focused || self.view != View::Sessions) && ui.button(crate::localization::tr(locale, "Arbeitsbereich")).clicked() {
                self.desktop.focus = false;
                self.view = View::Sessions;
            }
            if !focused {
                ui.label(
                    RichText::new(if self.view == View::Missions {
                        "MISSION CONTROL"
                    } else {
                        crate::localization::tr(locale, "RECHNERZENTRALE")
                    })
                    .size(11.0)
                    .color(MUTED),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .button(if focused {
                        "Aktionen · Strg Umschalt K"
                    } else {
                        crate::localization::tr(locale, "Suchen & Aktionen · Strg K")
                    })
                    .clicked()
                {
                    self.desktop.palette = true;
                    self.desktop.palette_focus = true;
                }
            });
        });
        ui.painter().hline(
            root.x_range(),
            header.bottom(),
            Stroke::new(1.0, tw::SLATE_200),
        );
        let rail_width = if focused || root.width() < 850.0 {
            0.0
        } else {
            184.0
        };
        let footer_height = if !focused && !self.sessions.is_empty() {
            46.0
        } else {
            0.0
        };
        let content = Rect::from_min_max(
            pos2(root.left() + rail_width, header.bottom()),
            pos2(root.right(), root.bottom() - footer_height),
        );
        if footer_height > 0.0 {
            let rect = Rect::from_min_max(
                pos2(root.left() + rail_width, root.bottom() - footer_height),
                root.max,
            );
            self.workbench_session_strip(&mut child(ui, "session-strip", rect.shrink(6.0)));
        }
        if rail_width > 0.0 {
            let rail = Rect::from_min_max(
                pos2(root.left(), header.bottom()),
                pos2(content.left(), root.bottom()),
            );
            let mut nav = child(ui, "desktop-navigation", rail.shrink(14.0));
            ScrollArea::vertical()
                .id_salt("main-navigation-scroll")
                .auto_shrink([false, false])
                .show(&mut nav, |ui| self.desktop_navigation(ui));
        }
        let mut body = child(ui, "desktop-content", content.shrink(16.0));
        if focused {
            body.style_mut().visuals = egui::Visuals::dark();
        }
        if !focused {
            body.label(RichText::new(&self.status).size(12.0).color(MUTED));
            body.add_space(8.0);
        }
        if self.view == View::Sessions {
            if focused {
                self.desktop_focus(&mut body);
            } else {
                if self.desktop.workbench.directory {
                    self.workbench_directory(&mut body);
                } else {
                    if body.button("Zur Rechnerzentrale").clicked() {
                        self.desktop.workbench.directory = true;
                        self.save_desktop_layout();
                    }
                    self.desktop_overview(&mut body);
                }
            }
        } else if self.view == View::Terminal {
            body.heading("SSH-Terminal");
            if let Some(terminal) = self.terminal.as_mut() {
                terminal_panel::show(&mut body, terminal);
            } else {
                body.label("SSH-Profil auswählen und Verbinden starten.");
            }
        } else {
            ScrollArea::vertical()
                .auto_shrink([false, false])
                    .show(&mut body, |ui| match self.view {
                        View::Release => super::release_panel::draw(ui, self.desktop.locale),
                    View::Missions => self.missions_view(ui),
                    View::Operations => self.operations_view(ui),
                    View::SessionWindows => self.session_layouts_ui(ui),
                    View::Integrations => self.integrations_view(ui),
                    View::Recordings => self.recordings_view(ui),
                    View::Teaching => self.teaching_view(ui),
                    View::Team => self.team_view(ui),
                    View::Vision => self.vision_view(ui),
                    View::Intelligence => self.intelligence_view(ui),
                    View::Insights => self.insights_view(ui),
                    View::Execution => self.execution_view(ui),
                    View::ChangeHistory => self.change_history_view(ui),
                    View::TestLab => self.test_lab_view(ui),
                    View::Workflow => self.workflow_with_proof_view(ui),
                    View::Incident => self.incident_view(ui),
                    View::Promotion => self.promotion_view(ui),
                    View::Recovery => self.recovery_view(ui),
                    View::RecoveryPlans => self.contracts_view(ui),
                    View::RecoveryDaemon => self.recovery_daemon_panel(ui),
                    View::RecoveryExtensions => self.recovery_extensions_view(ui),
                    View::Terminal => {}
                    View::Connections => self.connections_view(ui),
                    View::Approvals => self.approvals_view(ui),
                    View::Workspaces => self.workspaces_view(ui),
                    View::Settings => self.settings_view(ui),
                    View::Sessions => {}
                });
        }
        self.desktop_palette(&ctx);
        self.workbench_dialogs(&ctx);
    }

    fn desktop_navigation(&mut self, ui: &mut Ui) {
        ui.label(RichText::new(crate::localization::tr(self.desktop.locale,"ARBEITSBEREICHE")).size(11.0).color(MUTED));
        ui.add_space(12.0);
        if ui
            .selectable_label(
                self.view == View::Sessions && self.desktop.group.is_empty(),
                crate::localization::tr(self.desktop.locale,"Alle Rechner"),
            )
            .clicked()
        {
            self.desktop.workbench.favorites = false;
            self.desktop.workbench.directory = true;
            self.desktop.group.clear();
            self.desktop.focus = false;
            self.view = View::Sessions;
            self.save_desktop_layout();
        }
        if ui
            .selectable_label(self.desktop.workbench.favorites, crate::localization::tr(self.desktop.locale,"Favoriten"))
            .clicked()
        {
            self.desktop.workbench.favorites = true;
            self.desktop.workbench.directory = true;
            self.desktop.focus = false;
            self.desktop.group.clear();
            self.view = View::Sessions;
        }
        let mut groups: Vec<_> = self.profiles.iter().map(|p| p.group.clone()).collect();
        groups.sort();
        groups.dedup();
        ScrollArea::vertical()
            .id_salt("workspace-groups")
            .max_height(260.0)
            .show(ui, |ui| {
                for group in groups {
                    if ui
                        .selectable_label(
                            self.desktop.group == group && self.view == View::Sessions,
                            &group,
                        )
                        .clicked()
                    {
                        self.desktop.workbench.favorites = false;
                        self.desktop.group = group;
                        self.desktop.focus = false;
                        self.view = View::Sessions;
                        self.save_desktop_layout();
                    }
                }
            });
        ui.add_space(26.0);
        ui.label(RichText::new(crate::localization::tr(self.desktop.locale,"VERWALTEN")).size(11.0).color(MUTED));
        let recovery_notices = crate::recovery_daemon::unread_count();
        for (view, label) in [
            (View::Missions, "Mission Control"),
            (View::Operations, "Remote-Werkzeuge"),
            (View::SessionWindows, "Sitzungsfenster"),
            (View::Integrations, "Inventar & Vault"),
            (View::Recordings, "Aufzeichnungen"),
            (View::Teaching, "Vormachen & Lernen"),
            (View::Team, "Team"),
            (View::Vision, "Bildschirm verstehen"),
            (View::Intelligence, "Planen & Lernen"),
            (View::Recovery, "Recovery Agent"),
            (View::RecoveryPlans, "Recovery-Pläne"),
            (View::RecoveryDaemon, "Hintergrund"),
            (View::RecoveryExtensions, "Tickets & Katalog"),
            (View::Insights, "Ursachen & Lösungen"),
            (View::Execution, "Prüfen & Ausführen"),
            (View::Promotion, "Klon → Produktion"),
            (View::ChangeHistory, "Änderungen & Rückkehr"),
            (View::TestLab, "Isoliertes Testlabor"),
            (View::Workflow, "Aufträge & Pakete"),
            (View::Incident, "Störung rekonstruieren"),
            (View::Terminal, "SSH-Terminal"),
            (View::Connections, "Verbindungen"),
            (View::Approvals, "Freigaben"),
            (View::Workspaces, "Abläufe & Wissen"),
            (View::Settings, "Einstellungen"),
            (View::Release, "Verkaufsbereitschaft"),
        ] {
            let label = if view == View::RecoveryDaemon && recovery_notices > 0 {
                format!("{} ({recovery_notices})", crate::localization::tr(self.desktop.locale, "Hintergrund"))
            } else {
                crate::localization::tr(self.desktop.locale, label).to_owned()
            };
            if ui.selectable_label(self.view == view, label).clicked() {
                self.view = view;
            }
        }
        ui.add_space(30.0);
        ui.label(
            RichText::new("Lokal. Nativ. In deinem Kontext.")
                .small()
                .color(MUTED),
        );
    }

    fn save_desktop_layout(&mut self) {
        self.status = match self.desktop.save() {
            Ok(()) => "Ansicht gespeichert".to_owned(),
            Err(err) => format!("Ansicht konnte nicht gespeichert werden: {err}"),
        };
    }

    fn focus_session(&mut self, id: Uuid) {
        self.engine.release_inputs_except(Some(id));
        if let Some(session) = self.sessions.iter().find(|s| s.id == id) {
            if self.selected_session != Some(id) {
                self.autopilot.abort();
                self.computer_use_status =
                    "Neue Sitzung ausgewählt. KI-Aufgabe bei Bedarf neu starten.".to_owned();
                self.diagnostics.clear();
                self.ai_diagnosis = session
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "Noch keine Diagnose für diese Sitzung.".to_owned());
            }
            self.selected_session = Some(id);
            self.selected_profile = Some(session.profile_id);
            self.desktop.focus = true;
            self.desktop.assistant = needs_attention(session.status);
            self.desktop.timeline = needs_attention(session.status);
            self.desktop.event = None;
            self.view = View::Sessions;
        }
    }

    fn desktop_overview(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(
                RichText::new(if self.desktop.group.is_empty() {
                    "Dein Arbeitsbereich"
                } else {
                    &self.desktop.group
                })
                .size(28.0)
                .color(INK),
            );
            if ui.button("Neue Verbindung").clicked() {
                self.start_new_profile();
                self.view = View::Connections;
            }
            if ui.button("Ansicht speichern").clicked() {
                self.save_desktop_layout();
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Ansicht:");
            let changed = ui
                .selectable_value(&mut self.desktop.compact, false, "Raster")
                .changed()
                | ui.selectable_value(&mut self.desktop.compact, true, "Liste")
                    .changed();
            if changed {
                self.save_desktop_layout();
            }
            if self.desktop.featured.is_some() && ui.button("Hervorhebung aufheben").clicked() {
                self.desktop.featured = None;
                self.save_desktop_layout();
            }
        });
        ui.add_space(8.0);
        self.desktop
            .order
            .retain(|id| self.profiles.iter().any(|p| p.id == *id));
        for profile in &self.profiles {
            if !self.desktop.order.contains(&profile.id) {
                self.desktop.order.push(profile.id);
            }
        }
        let mut profiles: Vec<_> = self
            .desktop
            .order
            .iter()
            .filter_map(|id| self.profiles.iter().find(|p| p.id == *id))
            .filter(|p| self.desktop.group.is_empty() || p.group == self.desktop.group)
            .cloned()
            .collect();
        if profiles.is_empty() {
            ui.add_space(60.0);
            ui.heading("Platz für deinen nächsten Remote-Desktop.");
            ui.label(
                "Lege eine Verbindung an. Nach dem Verbinden erscheint hier die Live-Vorschau.",
            );
            if ui.button("Verbindung anlegen").clicked() {
                self.start_new_profile();
                self.view = View::Connections;
            }
            return;
        }
        let live = profiles
            .iter()
            .filter(|profile| {
                self.sessions
                    .iter()
                    .rev()
                    .find(|s| s.profile_id == profile.id)
                    .is_some_and(|s| s.status == SessionStatus::Connected)
            })
            .count();
        ui.label(
            RichText::new(format!(
                "{} Verbindungen · {live} verbunden · Am Griff ziehen zum Anordnen",
                profiles.len()
            ))
            .small()
            .color(MUTED),
        );
        ui.add_space(10.0);
        let featured = if !self.desktop.compact {
            self.desktop
                .featured
                .and_then(|id| profiles.iter().position(|p| p.id == id))
                .map(|index| profiles.remove(index))
        } else {
            None
        };
        ScrollArea::vertical()
            .id_salt((
                "spatial-sessions",
                self.desktop.compact,
                self.desktop.group.clone(),
            ))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width();
                if let Some(profile) = &featured {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(width, 420.0), Sense::hover());
                    self.desktop_tile(
                        &mut child(ui, (profile.id, "featured"), rect),
                        profile,
                        false,
                    );
                    ui.add_space(12.0);
                }
                let columns = if self.desktop.compact {
                    1
                } else {
                    (((width + 12.0) / 360.0).floor().max(1.0) as usize).min(profiles.len().max(1))
                };
                let tile_width = (width - 12.0 * (columns - 1) as f32) / columns as f32;
                let tile_height = if self.desktop.compact { 112.0 } else { 290.0 };
                for row in profiles.chunks(columns) {
                    let (row_rect, _) =
                        ui.allocate_exact_size(egui::vec2(width, tile_height), Sense::hover());
                    // Off-screen previews need no painting or texture lookup.
                    if ui.is_rect_visible(row_rect) {
                        for (column, profile) in row.iter().enumerate() {
                            let rect = Rect::from_min_size(
                                row_rect.min + egui::vec2(column as f32 * (tile_width + 12.0), 0.0),
                                egui::vec2(tile_width, tile_height),
                            );
                            self.desktop_tile(
                                &mut child(ui, profile.id, rect),
                                profile,
                                self.desktop.compact,
                            );
                        }
                    }
                    ui.add_space(12.0);
                }
            });
        if ui.input(|i| i.pointer.any_released()) {
            self.desktop.dragging = None;
        }
    }

    fn desktop_tile(&mut self, ui: &mut Ui, profile: &ConnectionProfile, compact: bool) {
        let rect = ui.max_rect();
        let session = self
            .sessions
            .iter()
            .rev()
            .find(|s| s.profile_id == profile.id)
            .cloned();
        let selected = session
            .as_ref()
            .is_some_and(|s| Some(s.id) == self.selected_session);
        ui.painter().rect_filled(rect, 9, tw::WHITE);
        ui.painter().rect_stroke(
            rect,
            9,
            Stroke::new(
                if selected { 2.0 } else { 1.0 },
                if selected { TEAL } else { tw::SLATE_200 },
            ),
            StrokeKind::Inside,
        );
        let mut header = child(
            ui,
            (profile.id, "header"),
            Rect::from_min_max(
                rect.min + egui::vec2(12.0, 10.0),
                pos2(rect.right() - 12.0, rect.top() + 68.0),
            ),
        );
        header.horizontal(|ui| {
            let grip = ui
                .add(egui::Label::new(RichText::new("::").color(MUTED)).sense(Sense::drag()))
                .on_hover_text("Ziehen zum Anordnen");
            if grip.drag_started() {
                self.desktop.dragging = Some(profile.id);
            }
            ui.add_sized(
                egui::vec2((ui.available_width() - 42.0).max(40.0), 20.0),
                egui::Label::new(RichText::new(&profile.name).strong().color(INK)).truncate(),
            )
            .on_hover_text(&profile.name);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button("…", |ui| {
                    let featured = self.desktop.featured == Some(profile.id);
                    if ui
                        .button(if featured {
                            "Hervorhebung aufheben"
                        } else {
                            "Groß hervorheben"
                        })
                        .clicked()
                    {
                        self.desktop.featured = if featured { None } else { Some(profile.id) };
                        if !featured {
                            self.desktop.compact = false;
                        }
                        self.save_desktop_layout();
                        ui.close();
                    }
                    if ui.button("Profil bearbeiten").clicked() {
                        self.load_profile_into_editor(profile.id);
                        self.view = View::Connections;
                        ui.close();
                    }
                    if ui.button("Nach vorne").clicked() {
                        if let Some(first) = self.desktop.order.first().copied() {
                            self.desktop.move_before(profile.id, first);
                            self.save_desktop_layout();
                        }
                        ui.close();
                    }
                });
            });
        });
        header.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(
                    session
                        .as_ref()
                        .map(|s| status_label(s.status))
                        .unwrap_or("Bereit zum Verbinden"),
                )
                .size(12.0)
                .color(
                    if session.as_ref().is_some_and(|s| needs_attention(s.status)) {
                        AMBER
                    } else {
                        TEAL
                    },
                ),
            );
            ui.label(
                RichText::new(environment_label(profile))
                    .size(11.0)
                    .strong()
                    .color(MUTED),
            );
        });
        if !compact {
            let preview = Rect::from_min_max(
                pos2(rect.left() + 8.0, rect.top() + 76.0),
                pos2(rect.right() - 8.0, rect.bottom() - 46.0),
            );
            ui.painter().rect_filled(preview, 4, tw::SLATE_900);
            if let Some(session) = &session {
                self.desktop_preview(ui, preview, session);
            } else {
                ui.painter().text(
                    preview.center(),
                    egui::Align2::CENTER_CENTER,
                    "Noch keine Sitzung",
                    FontId::proportional(16.0),
                    tw::SLATE_300,
                );
            }
            let response = ui.interact(
                preview,
                ui.id().with((profile.id, "preview")),
                Sense::click(),
            );
            if response.clicked() {
                if let Some(session) = &session {
                    self.focus_session(session.id);
                } else {
                    self.load_profile_into_editor(profile.id);
                    self.view = View::Connections;
                }
            }
        }
        if rect.contains(ui.input(|i| i.pointer.interact_pos()).unwrap_or(Pos2::ZERO))
            && ui.input(|i| i.pointer.any_released())
        {
            if let Some(source) = self.desktop.dragging.take() {
                self.desktop.move_before(source, profile.id);
                self.save_desktop_layout();
            }
        }
        let mut footer = child(
            ui,
            (profile.id, "footer"),
            Rect::from_min_max(
                pos2(rect.left() + 12.0, rect.bottom() - 38.0),
                rect.max - egui::vec2(12.0, 4.0),
            ),
        );
        footer.horizontal(|ui| {
            ui.add_sized(
                egui::vec2((ui.available_width() - 120.0).max(40.0), 20.0),
                egui::Label::new(RichText::new(&profile.host).small().color(MUTED)).truncate(),
            )
            .on_hover_text(&profile.host);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .button(if session.is_some() {
                        "Fokussieren"
                    } else {
                        "Profil öffnen"
                    })
                    .clicked()
                {
                    if let Some(session) = &session {
                        self.focus_session(session.id);
                    } else {
                        self.load_profile_into_editor(profile.id);
                        self.view = View::Connections;
                    }
                }
            });
        });
    }

    fn desktop_preview(&self, ui: &Ui, rect: Rect, session: &RemoteSession) {
        if let (Some(texture), Some(frame)) = (
            self.textures.get(&session.id),
            self.latest_frames.get(&session.id),
        ) {
            let image = remote_image_rect(
                rect,
                egui::vec2(frame.width as f32, frame.height as f32),
                RemoteViewMode::Fit,
            );
            ui.painter().image(
                texture.id(),
                image,
                Rect::from_min_max(Pos2::ZERO, pos2(1.0, 1.0)),
                Color32::WHITE,
            );
            if session.status != SessionStatus::Connected {
                let band = Rect::from_min_size(rect.min, egui::vec2(rect.width(), 28.0));
                ui.painter().rect_filled(band, 0, tw::SLATE_900);
                ui.painter().text(
                    band.center(),
                    egui::Align2::CENTER_CENTER,
                    "LETZTES BILD · NICHT LIVE",
                    FontId::proportional(12.0),
                    Color32::from_rgb(255, 196, 113),
                );
            }
        } else {
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                status_label(session.status),
                FontId::proportional(16.0),
                tw::SLATE_300,
            );
        }
    }

    fn desktop_focus(&mut self, ui: &mut Ui) {
        let Some(session) = self.selected_session().cloned() else {
            self.desktop.focus = false;
            return;
        };
        ScrollArea::horizontal()
            .id_salt("focus-tabs")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for item in self.sessions.clone() {
                        if ui
                            .selectable_label(
                                item.id == session.id,
                                format!("{} · {}", item.title, status_label(item.status)),
                            )
                            .clicked()
                        {
                            self.focus_session(item.id);
                        }
                    }
                });
            });
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&session.title).strong().color(tw::SLATE_100));
            if let Some(profile) = self.profiles.iter().find(|p| p.id == session.profile_id) {
                ui.label(
                    RichText::new(environment_label(profile))
                        .small()
                        .strong()
                        .color(Color32::from_rgb(255, 196, 113)),
                );
            }
            ui.selectable_value(&mut self.remote_view_mode, RemoteViewMode::Fit, "Anpassen");
            ui.selectable_value(
                &mut self.remote_view_mode,
                RemoteViewMode::ActualSize,
                "100 %",
            );
            ui.toggle_value(&mut self.desktop.workbench.split, "Nebeneinander");
            if ui.button("Dateien").clicked() {
                self.workbench_open_transfer();
            }
            if ui.button("Eigenes Fenster").clicked()
                && !self.session_windows.open.contains(&session.id)
            {
                self.session_windows.open.push(session.id);
            }
            ui.toggle_value(&mut self.desktop.assistant, "KI & Diagnose");
            ui.toggle_value(&mut self.desktop.timeline, "Zeitleiste");
            if ui.button("Vollbild").clicked() {
                self.remote_fullscreen = !self.remote_fullscreen;
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.remote_fullscreen));
            }
            if ui.button("Trennen").clicked() {
                self.disconnect_selected_session();
                return;
            }
        });
        ui.add_space(6.0);
        if let Some((attempt, delay)) = self.engine.retry_status(session.id) {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    AMBER,
                    format!(
                        "Wiederverbindung · Versuch {attempt} · in {} s",
                        delay.as_secs()
                    ),
                );
                if ui.button("Wiederverbindung abbrechen").clicked() {
                    self.engine.cancel_reconnect(session.id);
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.id == session.id) {
                        s.status = SessionStatus::Disconnected;
                    }
                }
            });
        }
        if self.selected_session != Some(session.id) {
            return;
        }
        if self.session_windows.open.contains(&session.id) {
            ui.label("Diese Sitzung ist in einem eigenen Fenster geöffnet.");
            if ui.button("Hier anzeigen").clicked() {
                self.session_windows.open.retain(|id| *id != session.id);
            }
            return;
        }
        let rect = ui.available_rect_before_wrap();
        let timeline_height = if self.desktop.timeline {
            (rect.height() * 0.30).clamp(110.0, 205.0)
        } else {
            0.0
        };
        let main = Rect::from_min_max(
            rect.min,
            pos2(rect.right(), rect.bottom() - timeline_height),
        );
        let assistant_width = if self.desktop.assistant {
            (main.width() * 0.32).clamp(290.0, 390.0).min(main.width())
        } else {
            0.0
        };
        let narrow = main.width() < 760.0 && self.desktop.assistant;
        if narrow {
            self.engine.release_inputs_except(None);
        }
        if !narrow {
            let canvas = Rect::from_min_max(
                main.min,
                pos2(
                    main.right() - assistant_width - if assistant_width > 0.0 { 12.0 } else { 0.0 },
                    main.bottom(),
                ),
            );
            let mut remote = child(ui, "focused-desktop", canvas);
            if session.status != SessionStatus::Connected {
                remote.colored_label(
                    AMBER,
                    format!(
                        "{} · {}",
                        status_label(session.status),
                        if self.latest_frames.contains_key(&session.id) {
                            "Letztes Bild, nicht live"
                        } else {
                            "Noch kein Bild empfangen"
                        }
                    ),
                );
            }
            if self.desktop.workbench.split {
                self.workbench_split(&mut remote, &session);
            } else {
                remote.add_enabled_ui(
                    session.status == SessionStatus::Connected && !self.desktop.palette,
                    |ui| self.remote_canvas(ui, session.id),
                );
            }
        }
        if self.desktop.assistant {
            let side = if narrow {
                main
            } else {
                Rect::from_min_max(pos2(main.right() - assistant_width, main.top()), main.max)
            };
            let mut assistant = child(ui, "context-assistant", side);
            Frame::new()
                .fill(tw::WHITE)
                .corner_radius(8)
                .inner_margin(14)
                .show(&mut assistant, |ui| {
                    ScrollArea::vertical()
                        .id_salt("context-scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.desktop_diagnosis(ui, &session));
                });
        }
        if self.desktop.timeline {
            let mut history = child(
                ui,
                "session-history",
                Rect::from_min_max(pos2(rect.left(), main.bottom() + 8.0), rect.max),
            );
            self.desktop_timeline(&mut history, session.id);
        }
    }

    fn desktop_diagnosis(&mut self, ui: &mut Ui, session: &RemoteSession) {
        ui.style_mut().visuals = egui::Visuals::light();
        ui.horizontal(|ui| {
            ui.heading(if needs_attention(session.status) {
                "Was ist passiert?"
            } else {
                "KI-Begleiter"
            });
            if ui.small_button("Schließen").clicked() {
                self.desktop.assistant = false;
            }
        });
        ui.label(
            RichText::new(format!("Kontext: {}", session.title))
                .small()
                .color(MUTED),
        );
        ui.separator();
        ui.label(RichText::new(status_label(session.status)).strong().color(
            if needs_attention(session.status) {
                AMBER
            } else {
                TEAL
            },
        ));
        if let Some(error) = &session.last_error {
            ui.label(redact_secret_text(error));
        }
        if let Some(frame) = self.latest_frames.get(&session.id) {
            ui.label(format!(
                "Letztes Bild: {} · {} × {}",
                frame
                    .captured_at
                    .with_timezone(&chrono::Local)
                    .format("%H:%M:%S"),
                frame.width,
                frame.height
            ));
        }
        ui.add_space(8.0);
        if needs_attention(session.status) {
            ui.label("Die Ursache ist erst durch weitere Befunde gesichert. Die Zeitleiste zeigt die empfangenen Sitzungsereignisse.");
            if ui.button("Erneut verbinden").clicked() {
                self.reconnect_selected_session();
            }
        } else {
            ui.label("Beschreibe eine Aufgabe oder untersuche die bisherigen Sitzungsereignisse.");
        }
        if ui.button("Ereignisse zusammenfassen").clicked() {
            let messages = self.session_messages(session.id);
            self.computer_use_status = self.ai.write_incident_report(&messages).customer_text;
        }
        ui.label(redact_secret_text(&self.computer_use_status));
        ui.add_space(12.0);
        ui.collapsing("Aufgabe, Runbooks & KI-Aktionen", |ui| {
            self.ai_session_panel(ui, session.id)
        });
        ui.collapsing("Technische Sitzungsdaten",|ui| {
            ui.label(format!("Sitzung: {}",session.id));
            ui.label(format!("Sitzungsbeginn: {}", session.connected_at.with_timezone(&chrono::Local).format("%d.%m.%Y %H:%M:%S")));
            ui.label(self.canvas_status(session.id));
            ui.label("Qualitätsmesswerte werden hier erst angezeigt, wenn reale Messdaten verfügbar sind.");
        });
    }

    fn desktop_timeline(&mut self, ui: &mut Ui, id: Uuid) {
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Ereignisverlauf")
                    .strong()
                    .color(tw::SLATE_100),
            );
            ui.label(
                RichText::new("Sitzungsprotokoll · keine Video-Wiedergabe")
                    .small()
                    .color(tw::SLATE_300),
            );
            if ui.small_button("Schließen").clicked() {
                self.desktop.timeline = false;
            }
        });
        let events = self.timeline.events_for_session(id);
        if events.is_empty() {
            ui.label("Noch keine Ereignisse für diese Sitzung.");
            return;
        }
        ScrollArea::horizontal()
            .id_salt("event-track")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for event in events
                        .iter()
                        .rev()
                        .take(100)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                    {
                        let selected = self.desktop.event == Some(event.id);
                        if ui
                            .selectable_label(
                                selected,
                                format!(
                                    "{}  {:?}",
                                    event
                                        .created_at
                                        .with_timezone(&chrono::Local)
                                        .format("%H:%M:%S"),
                                    event.kind
                                ),
                            )
                            .clicked()
                        {
                            self.desktop.event = Some(event.id);
                        }
                    }
                });
            });
        let event = self
            .desktop
            .event
            .and_then(|id| events.iter().find(|e| e.id == id))
            .or_else(|| events.last());
        if let Some(event) = event {
            ScrollArea::vertical()
                .id_salt("event-detail")
                .show(ui, |ui| {
                    ui.label(redact_secret_text(&event.message));
                });
        }
    }

    fn desktop_palette(&mut self, ctx: &Context) {
        if !self.desktop.palette {
            return;
        }
        let mut open = true;
        egui::Window::new(RichText::new("Suchen & Aktionen").size(18.0))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 80.0))
            .default_width(510.0)
            .show(ctx, |ui| {
                let query = ui.add(
                    egui::TextEdit::singleline(&mut self.desktop.query)
                        .hint_text("Rechner, Sitzung oder Aktion suchen …")
                        .desired_width(f32::INFINITY),
                );
                if self.desktop.palette_focus {
                    query.request_focus();
                    self.desktop.palette_focus = false;
                }
                ui.separator();
                let needle = self.desktop.query.trim().to_lowercase();
                ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                    for (label, view) in [
                        ("Mission Control", View::Missions),
                        ("Remote-Werkzeuge", View::Operations),
                        ("Sitzungsfenster", View::SessionWindows),
                        ("Inventar & Vault", View::Integrations),
                        ("Aufzeichnungen", View::Recordings),
                        ("Vormachen & Lernen", View::Teaching),
                        ("Team", View::Team),
                        ("Bildschirm verstehen", View::Vision),
                        ("Planen & Lernen", View::Intelligence),
                        ("Recovery Agent", View::Recovery),
                        ("Wiederherstellungspläne", View::RecoveryPlans),
                        ("Recovery-Hintergrundbetrieb", View::RecoveryDaemon),
                        (
                            "Tickets und Kompatibilitätskatalog",
                            View::RecoveryExtensions,
                        ),
                        ("Ursachen & Lösungen", View::Insights),
                        ("Prüfen & Ausführen", View::Execution),
                        ("Klon → Produktion", View::Promotion),
                        ("Änderungen & Rückkehr", View::ChangeHistory),
                        ("Isoliertes Testlabor", View::TestLab),
                        ("Aufträge & Pakete", View::Workflow),
                        ("Störung rekonstruieren", View::Incident),
                        ("SSH-Terminal", View::Terminal),
                        ("Arbeitsbereich", View::Sessions),
                        ("Verbindungen", View::Connections),
                        ("Freigaben", View::Approvals),
                        ("Abläufe & Wissen", View::Workspaces),
                        ("Einstellungen", View::Settings),
                    ] {
                        if label.to_lowercase().contains(&needle) && ui.button(label).clicked() {
                            self.view = view;
                            self.desktop.focus = false;
                            self.desktop.palette = false;
                        }
                    }
                    for session in self.sessions.clone() {
                        if session.title.to_lowercase().contains(&needle)
                            && ui
                                .button(format!("Sitzung öffnen · {}", session.title))
                                .clicked()
                        {
                            self.focus_session(session.id);
                            self.desktop.palette = false;
                        }
                    }
                    for profile in self.profiles.clone() {
                        if format!("{} {} {}", profile.name, profile.host, profile.group)
                            .to_lowercase()
                            .contains(&needle)
                            && ui
                                .button(format!("Profil · {} · {}", profile.name, profile.host))
                                .clicked()
                        {
                            self.load_profile_into_editor(profile.id);
                            self.view = View::Connections;
                            self.desktop.palette = false;
                        }
                    }
                });
            });
        if !open || ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.desktop.palette = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(ctx: &Context) -> AivanaApp {
        let mut app = AivanaApp::from_context(ctx);
        app.view = View::Sessions;
        app.profiles = ["WIN-ADMIN-01", "APP-SERVER-02", "TEST-LAB-03"]
            .iter()
            .map(|name| ConnectionProfile::sample(name, "test.invalid", "Test", false))
            .collect();
        app.sessions = app
            .profiles
            .iter()
            .map(|profile| RemoteSession {
                id: Uuid::new_v4(),
                profile_id: profile.id,
                title: profile.name.clone(),
                status: SessionStatus::Connected,
                connected_at: Utc::now(),
                metrics: Default::default(),
                last_error: None,
                frame_size: None,
            })
            .collect();
        app.desktop = DesktopState::default();
        app.desktop.workbench.directory = false;
        app.selected_session = None;
        app
    }

    fn render(
        app: &mut AivanaApp,
        ctx: &Context,
        size: Vec2,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ui| app.desktop_shell(ui),
        )
    }

    fn text_center(output: &egui::FullOutput, label: &str) -> Option<Pos2> {
        output.shapes.iter().find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.text() == label => {
                Some(text.pos + text.galley.size() * 0.5)
            }
            _ => None,
        })
    }

    fn click(app: &mut AivanaApp, ctx: &Context, size: Vec2, pos: Pos2) {
        render(
            app,
            ctx,
            size,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        render(
            app,
            ctx,
            size,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
    }

    #[test]
    fn directory_selection_never_starts_a_connection_and_actions_fit_narrow_windows() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.desktop.workbench.directory = true;
        app.selected_profile = None;
        let original_sessions = app.sessions.len();
        for width in [1440.0, 640.0] {
            let size = egui::vec2(width, 900.0);
            render(&mut app, &ctx, size, vec![]);
            let output = render(&mut app, &ctx, size, vec![]);
            assert!(text_center(&output, "Rechnerzentrale").is_some());
            let host = text_center(&output, "APP-SERVER-02").expect("host visible");
            click(&mut app, &ctx, size, host);
            assert_eq!(app.selected_profile, Some(app.profiles[1].id));
            assert_eq!(app.sessions.len(), original_sessions);
            assert!(!app.desktop.focus);
            let output = render(&mut app, &ctx, size, vec![]);
            let action = if width < 900.0 {
                "Profil bearbeiten"
            } else {
                "Sitzung öffnen"
            };
            let center = text_center(&output, action).expect("selected profile actions visible");
            assert!(center.y < size.y && center.x < size.x);
        }
    }

    #[test]
    fn comparison_switches_active_session_without_connecting_again() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.focus_session(app.sessions[0].id);
        app.desktop.workbench.split = true;
        let size = egui::vec2(1440.0, 1024.0);
        render(&mut app, &ctx, size, vec![]);
        let output = render(&mut app, &ctx, size, vec![]);
        let activate = text_center(&output, "APP-SERVER-02 · Aktivieren").unwrap();
        click(&mut app, &ctx, size, activate);
        assert_eq!(app.selected_session, Some(app.sessions[1].id));
        assert!(app.desktop.workbench.split);
        assert_eq!(app.sessions.len(), 3);
    }

    #[test]
    fn grid_keeps_three_sessions_equal_and_feature_is_explicit() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        let size = egui::vec2(1440.0, 1024.0);
        render(&mut app, &ctx, size, vec![]);
        let output = render(&mut app, &ctx, size, vec![]);
        let first = text_center(&output, "WIN-ADMIN-01").unwrap();
        let third = text_center(&output, "TEST-LAB-03").unwrap();
        assert!((first.y - third.y).abs() < 2.0);
        app.desktop.featured = Some(app.profiles[2].id);
        let output = render(&mut app, &ctx, size, vec![]);
        let first = text_center(&output, "WIN-ADMIN-01").unwrap();
        let third = text_center(&output, "TEST-LAB-03").unwrap();
        assert!(first.y > third.y + 400.0);
        assert_eq!(app.profiles[0].name, "WIN-ADMIN-01");
    }

    #[test]
    fn list_is_compact_on_narrow_windows_and_opens_sessions() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.desktop.compact = true;
        for width in [640.0, 1440.0] {
            let size = egui::vec2(width, 900.0);
            render(&mut app, &ctx, size, vec![]);
            let output = render(&mut app, &ctx, size, vec![]);
            let first = text_center(&output, "WIN-ADMIN-01").unwrap();
            let third = text_center(&output, "TEST-LAB-03").unwrap();
            assert!((third.x - first.x).abs() < 20.0);
            assert!(third.y - first.y < 270.0);
            assert!(third.y > first.y + 200.0);
        }
        let size = egui::vec2(640.0, 900.0);
        let output = render(&mut app, &ctx, size, vec![]);
        let button = text_center(&output, "Fokussieren").unwrap();
        click(&mut app, &ctx, size, button);
        assert!(app.desktop.focus);
    }

    #[test]
    fn old_layouts_default_to_grid_and_new_preferences_round_trip() {
        let old: DesktopState = serde_json::from_str(r#"{"order":[],"group":"Test"}"#).unwrap();
        assert!(!old.compact);
        assert!(old.featured.is_none());
        let state = DesktopState {
            compact: true,
            featured: Some(Uuid::new_v4()),
            ..Default::default()
        };
        let restored: DesktopState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert!(restored.compact);
        assert_eq!(restored.featured, state.featured);
    }

    #[test]
    fn two_sessions_share_a_row_on_wide_windows() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.profiles.truncate(2);
        app.sessions.truncate(2);
        let size = egui::vec2(1280.0, 820.0);
        render(&mut app, &ctx, size, vec![]);
        let output = render(&mut app, &ctx, size, vec![]);
        let first = text_center(&output, "WIN-ADMIN-01").unwrap();
        let second = text_center(&output, "APP-SERVER-02").unwrap();
        assert!((first.y - second.y).abs() < 2.0);
        assert!(second.x > first.x + 300.0);
    }

    #[test]
    fn workspace_to_focus_and_back_via_visible_controls() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        let size = egui::vec2(1440.0, 1024.0);
        render(&mut app, &ctx, size, vec![]);
        let output = render(&mut app, &ctx, size, vec![]);
        let button = text_center(&output, "Fokussieren").expect("visible focus action");
        click(&mut app, &ctx, size, button);
        assert!(app.desktop.focus);
        assert!(app.selected_session.is_some());
        let output = render(&mut app, &ctx, size, vec![]);
        let back = text_center(&output, "Arbeitsbereich").expect("visible back action");
        click(&mut app, &ctx, size, back);
        assert!(!app.desktop.focus);
        assert_eq!(app.sessions.len(), 3);
    }

    #[test]
    fn interrupted_session_has_context_and_responsive_diagnosis() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.sessions[1].status = SessionStatus::Failed;
        app.sessions[1].last_error = Some("Transport interrupted".to_owned());
        let id = app.sessions[1].id;
        app.timeline.append_event(
            id,
            None,
            SessionEventKind::Error,
            "Transport interrupted".to_owned(),
        );
        app.focus_session(id);
        assert!(app.desktop.assistant && app.desktop.timeline);
        for width in [1440.0, 800.0, 640.0] {
            let output = render(&mut app, &ctx, egui::vec2(width, 800.0), vec![]);
            assert!(text_center(&output, "Was ist passiert?").is_some());
            assert!(text_center(&output, "Ereignisverlauf").is_some());
        }
    }

    #[test]
    fn command_palette_shortcut_does_not_change_active_session() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        let id = app.sessions[0].id;
        app.focus_session(id);
        render(
            &mut app,
            &ctx,
            egui::vec2(1440.0, 1024.0),
            vec![egui::Event::Key {
                key: egui::Key::K,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::CTRL | egui::Modifiers::SHIFT,
            }],
        );
        assert!(app.desktop.palette);
        assert_eq!(app.selected_session, Some(id));
        render(
            &mut app,
            &ctx,
            egui::vec2(1440.0, 1024.0),
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(!app.desktop.palette);
    }
    #[test]
    fn reorder_keeps_profiles_unique_and_survives_restart() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let mut state = DesktopState {
            order: vec![a, b, c],
            focus: true,
            assistant: true,
            ..Default::default()
        };
        state.move_before(c, a);
        assert_eq!(state.order, vec![c, a, b]);
        state.move_before(a, a);
        state.move_before(b, Uuid::new_v4());
        assert_eq!(state.order, vec![c, a, b]);
        let restored: DesktopState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(restored.order, vec![c, a, b]);
        assert!(!restored.focus);
        assert!(!restored.assistant);
    }
    #[test]
    fn interruption_opens_investigation_but_connecting_does_not() {
        assert!(needs_attention(SessionStatus::Failed));
        assert!(needs_attention(SessionStatus::Reconnecting));
        assert!(!needs_attention(SessionStatus::Connected));
        assert!(!needs_attention(SessionStatus::Authenticating));
    }
    #[test]
    fn mission_and_tools_render_at_narrow_and_wide_sizes_without_connections() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.sessions.clear();
        app.selected_session = None;
        for width in [640.0, 1440.0] {
            for view in [
                View::Missions,
                View::Operations,
                View::SessionWindows,
                View::Integrations,
                View::Recordings,
                View::Teaching,
                View::Team,
                View::Vision,
                View::Intelligence,
                View::Insights,
                View::Execution,
                View::ChangeHistory,
                View::TestLab,
                View::Workflow,
                View::Incident,
                View::Promotion,
                View::Recovery,
                View::RecoveryPlans,
                View::RecoveryDaemon,
                View::RecoveryExtensions,
                View::Terminal,
            ] {
                app.view = view;
                let out = render(&mut app, &ctx, egui::vec2(width, 1000.0), vec![]);
                assert!(!out.shapes.is_empty());
                assert!(app.sessions.is_empty());
            }
        }
    }
    #[test]
    fn invalid_ssh_endpoint_is_rejected_before_starting_terminal() {
        let ctx = Context::default();
        let mut app = fixture(&ctx);
        app.sessions.clear();
        app.profiles[0].protocol = Protocol::Ssh;
        app.profiles[0].port = 2222;
        app.profiles[0].host = "invalid host".into();
        app.selected_profile = Some(app.profiles[0].id);
        app.connect_selected();
        assert!(app.terminal.is_none());
        assert!(app.sessions.is_empty());
        assert!(app.status.contains("Ungültiger Host"));
    }
}
