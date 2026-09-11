//! Native detached session windows and named layouts. Restoring never authenticates.
use super::*;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct SavedWindow {
    profile: Uuid,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
}
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct SavedLayout {
    name: String,
    windows: Vec<SavedWindow>,
}
#[derive(Default)]
pub(super) struct SessionWindows {
    pub open: Vec<Uuid>,
    positions: HashMap<Uuid, SavedWindow>,
    layouts: Vec<SavedLayout>,
    name: String,
    loaded: bool,
    load_error: Option<String>,
}
impl AivanaApp {
    pub(super) fn remote_input_owner(&self, ui: &Ui) -> Option<Uuid> {
        if self.desktop.palette {
            return None;
        }
        for id in &self.session_windows.open {
            if ui.input(|i| {
                i.raw
                    .viewports
                    .get(&window_id(*id))
                    .and_then(|v| v.focused)
                    .unwrap_or(false)
            }) {
                return Some(*id);
            }
        }
        if ui.input(|i| i.focused)
            && self.desktop.focus
            && self.view == View::Sessions
            && !self
                .selected_session
                .is_some_and(|id| self.session_windows.open.contains(&id))
        {
            self.selected_session
        } else {
            None
        }
    }
    pub(super) fn detached_sessions(&mut self, ctx: &Context) {
        let mut close = vec![];
        for id in self.session_windows.open.clone() {
            let Some(s) = self.sessions.iter().find(|s| s.id == id).cloned() else {
                close.push(id);
                continue;
            };
            let mut builder = egui::ViewportBuilder::default()
                .with_title(format!("Aivana · {}", s.title))
                .with_inner_size([1100.0, 760.0])
                .with_min_inner_size([480.0, 320.0]);
            if let Some(p) = self.session_windows.positions.get(&id) {
                builder = builder
                    .with_position([p.x, p.y])
                    .with_inner_size([p.width, p.height]);
            }
            ctx.show_viewport_immediate(window_id(id), builder, |ui, _class| {
                if ui.input(|i| i.viewport().close_requested()) {
                    close.push(id);
                    return;
                }
                ui.style_mut().visuals = egui::Visuals::dark();
                let focused = ui.input(|i| i.focused);
                if focused && self.selected_session != Some(id) {
                    self.autopilot.abort();
                    self.engine.release_inputs_except(Some(id));
                    self.selected_session = Some(id);
                    self.selected_profile = Some(s.profile_id);
                }
                if let Some(rect) = ui.input(|i| i.viewport().outer_rect) {
                    let size = ui
                        .input(|i| i.viewport().inner_rect)
                        .map(|r| r.size())
                        .unwrap_or(rect.size());
                    self.session_windows.positions.insert(
                        id,
                        SavedWindow {
                            profile: s.profile_id,
                            x: rect.left(),
                            y: rect.top(),
                            width: size.x,
                            height: size.y,
                        },
                    );
                }
                ui.horizontal_wrapped(|ui| {
                    ui.strong(&s.title);
                    ui.label(format!("{:?}", s.status));
                    if ui.button("Zurück in Hauptfenster").clicked() {
                        close.push(id);
                    }
                    if ui.button("Vollbild umschalten").clicked() {
                        let full = ui.input(|i| i.viewport().fullscreen).unwrap_or(false);
                        ui.ctx()
                            .send_viewport_cmd(egui::ViewportCommand::Fullscreen(!full));
                    }
                });
                if s.status != SessionStatus::Connected {
                    ui.label("Letztes empfangenes Bild – Sitzung nicht verbunden");
                }
                ui.add_enabled_ui(focused && s.status == SessionStatus::Connected, |ui| {
                    self.remote_canvas(ui, id)
                });
            });
        }
        for id in close {
            self.session_windows.open.retain(|s| *s != id);
            self.engine.release_inputs(id);
        }
    }
    pub(super) fn session_layouts_ui(&mut self, ui: &mut Ui) {
        if !self.session_windows.loaded {
            self.session_windows.loaded = true;
            match app_data_file("session-layouts.json").and_then(|p| {
                if p.exists() {
                    Ok(serde_json::from_slice::<Vec<SavedLayout>>(&std::fs::read(
                        p,
                    )?)?)
                } else {
                    Ok(vec![])
                }
            }) {
                Ok(layouts) => self.session_windows.layouts = layouts,
                Err(e) => {
                    self.session_windows.load_error = Some(format!(
                        "Gespeicherte Fensteranordnungen nicht lesbar: {e:#}"
                    ))
                }
            }
        }
        ui.heading("Sitzungsfenster");
        ui.label("Jede Sitzung kann ein eigenes natives Fenster erhalten und auf einen lokalen Monitor verschoben werden.");
        for s in self.sessions.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.label(&s.title);
                if ui
                    .add_enabled(
                        !self.session_windows.open.contains(&s.id),
                        egui::Button::new("Eigenes Fenster"),
                    )
                    .clicked()
                {
                    self.session_windows.open.push(s.id);
                }
            });
        }
        if let Some(e) = &self.session_windows.load_error {
            ui.colored_label(tw::RED_600, e);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.session_windows.name)
                    .hint_text("Name der Fensteranordnung"),
            );
            if ui
                .add_enabled(
                    !self.session_windows.name.trim().is_empty()
                        && !self.session_windows.open.is_empty(),
                    egui::Button::new("Anordnung speichern"),
                )
                .clicked()
            {
                let windows = self
                    .session_windows
                    .open
                    .iter()
                    .filter_map(|id| self.session_windows.positions.get(id).cloned())
                    .collect();
                self.session_windows.layouts.push(SavedLayout {
                    name: self.session_windows.name.trim().to_owned(),
                    windows,
                });
                self.status = match app_data_file("session-layouts.json").and_then(|p| {
                    std::fs::write(p, serde_json::to_vec_pretty(&self.session_windows.layouts)?)?;
                    Ok(())
                }) {
                    Ok(()) => "Fensteranordnung gespeichert".into(),
                    Err(e) => format!("Speichern: {e:#}"),
                };
            }
        });
        for layout in self.session_windows.layouts.clone() {
            ui.horizontal_wrapped(|ui|{ui.label(&layout.name);if ui.button("Für offene Sitzungen anwenden").clicked(){let mut missing=0;for w in layout.windows {if let Some(s)=self.sessions.iter().find(|s|s.profile_id==w.profile){if !self.session_windows.open.contains(&s.id){self.session_windows.open.push(s.id);}let mut w=w;w.width=w.width.clamp(480.0,7680.0);w.height=w.height.clamp(320.0,4320.0);self.session_windows.positions.insert(s.id,w);}else{missing+=1;}}self.status=format!("Anordnung angewendet. {missing} Rechner haben keine offene Sitzung; es wurde keine Verbindung gestartet.");}});
        }
    }
}
fn window_id(id: Uuid) -> egui::ViewportId {
    egui::ViewportId::from_hash_of(("aivana-session", id))
}
