//! Native session/monitor windows. Layout restore never authenticates or connects.
use super::*;
use crate::connection_options::MonitorLayout;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct SavedWindow {
    profile: Uuid,
    #[serde(default)]
    monitor: Option<usize>,
    #[serde(default)]
    topology: Vec<MonitorLayout>,
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
    focused_pane: Option<egui::ViewportId>,
    monitors: HashMap<Uuid, Vec<usize>>,
    topology: HashMap<Uuid, Vec<MonitorLayout>>,
    positions: HashMap<(Uuid, Option<usize>), SavedWindow>,
    layouts: Vec<SavedLayout>,
    name: String,
    loaded: bool,
    load_error: Option<String>,
}
impl SessionWindows {
    fn panes(&self, id: Uuid) -> Vec<Option<usize>> {
        self.monitors
            .get(&id)
            .map(|v| v.iter().copied().map(Some).collect())
            .unwrap_or_else(|| vec![None])
    }
}
/// Normalize virtual desktop coordinates (including left/up monitors) into framebuffer pixels.
/// Reject mismatched framebuffer geometry: a requested topology is not proof that the server applied it.
fn monitor_source(
    monitors: &[MonitorLayout],
    index: usize,
    width: u16,
    height: u16,
) -> Option<RemoteFrameSource> {
    if monitors.is_empty()
        || monitors.len() > 16
        || monitors.iter().any(|m| m.width == 0 || m.height == 0)
    {
        return None;
    }
    let left = monitors.iter().map(|m| i64::from(m.x)).min()?;
    let top = monitors.iter().map(|m| i64::from(m.y)).min()?;
    let right = monitors
        .iter()
        .map(|m| i64::from(m.x) + i64::from(m.width))
        .max()?;
    let bottom = monitors
        .iter()
        .map(|m| i64::from(m.y) + i64::from(m.height))
        .max()?;
    if right - left != i64::from(width) || bottom - top != i64::from(height) {
        return None;
    }
    let m = monitors.get(index)?;
    Some(RemoteFrameSource {
        left: u16::try_from(i64::from(m.x) - left).ok()?,
        top: u16::try_from(i64::from(m.y) - top).ok()?,
        right: u16::try_from(i64::from(m.x) - left + i64::from(m.width)).ok()?,
        bottom: u16::try_from(i64::from(m.y) - top + i64::from(m.height)).ok()?,
    })
}
impl AivanaApp {
    pub(super) fn remote_input_owner(&self, ui: &Ui) -> Option<Uuid> {
        if self.desktop.palette {
            return None;
        }
        for id in &self.session_windows.open {
            for monitor in self.session_windows.panes(*id) {
                if ui.input(|i| {
                    i.raw
                        .viewports
                        .get(&window_id(*id, monitor))
                        .and_then(|v| v.focused)
                        .unwrap_or(false)
                }) {
                    return Some(*id);
                }
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
                close.push((id, None));
                continue;
            };
            for monitor in self.session_windows.panes(id) {
                let title = monitor
                    .map(|m| format!("Relayne · {} · Monitor {}", s.title, m + 1))
                    .unwrap_or_else(|| format!("Relayne · {}", s.title));
                let mut builder = egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([1100.0, 760.0])
                    .with_min_inner_size([320.0, 240.0]);
                if let Some(p) = self.session_windows.positions.get(&(id, monitor)) {
                    builder = builder
                        .with_position([p.x, p.y])
                        .with_inner_size([p.width, p.height]);
                }
                ctx.show_viewport_immediate(window_id(id,monitor),builder,|ui,_class|{
                    if ui.input(|i|i.viewport().close_requested()){close.push((id,monitor));return}
                    ui.style_mut().visuals=egui::Visuals::dark();
                    let focused=ui.input(|i|i.focused);
                    let pane=window_id(id,monitor);
                    if focused && self.session_windows.focused_pane!=Some(pane){
                        // A monitor switch can retain the same session ID. Release the
                        // previous pane's held input before changing coordinate spaces.
                        self.engine.release_inputs(id);
                        self.session_windows.focused_pane=Some(pane);
                    }
                    if focused && self.selected_session!=Some(id){self.autopilot.abort();self.engine.release_inputs_except(Some(id));self.selected_session=Some(id);self.selected_profile=Some(s.profile_id);}
                    if let Some(rect)=ui.input(|i|i.viewport().outer_rect){let size=ui.input(|i|i.viewport().inner_rect).map(|r|r.size()).unwrap_or(rect.size());self.session_windows.positions.insert((id,monitor),SavedWindow{profile:s.profile_id,monitor,topology:self.session_windows.topology.get(&id).cloned().unwrap_or_default(),x:rect.left(),y:rect.top(),width:size.x,height:size.y});}
                    ui.horizontal_wrapped(|ui|{
                        ui.strong(&s.title);if let Some(m)=monitor{ui.label(format!("Remote monitor {}",m+1));}ui.label(format!("{:?}",s.status));
                        if ui.button("Close window").clicked(){close.push((id,monitor));}
                        if ui.button("Toggle full screen").clicked(){let full=ui.input(|i|i.viewport().fullscreen).unwrap_or(false);ui.ctx().send_viewport_cmd(egui::ViewportCommand::Fullscreen(!full));}
                    });
                    if s.status!=SessionStatus::Connected{ui.label("Last received image – session disconnected");}
                    let source=monitor.and_then(|index|self.latest_frames.get(&id).and_then(|frame|self.session_windows.topology.get(&id).and_then(|m|monitor_source(m,index,frame.width,frame.height))));
                    if monitor.is_some() && source.is_none(){ui.label("Waiting for a framebuffer image that matches the configured monitor layout. Input remains blocked.");return}
                    ui.add_enabled_ui(focused && s.status==SessionStatus::Connected,|ui|self.remote_canvas_region(ui,id,source));
                });
            }
        }
        for (id, monitor) in close {
            if let Some(index) = monitor {
                if let Some(indices) = self.session_windows.monitors.get_mut(&id) {
                    indices.retain(|i| *i != index);
                    if indices.is_empty() {
                        self.session_windows.open.retain(|s| *s != id);
                        self.session_windows.monitors.remove(&id);
                    }
                }
            } else {
                self.session_windows.open.retain(|s| *s != id);
                self.session_windows.monitors.remove(&id);
            }
            self.engine.release_inputs(id);
        }
    }
    pub(super) fn session_layouts_ui(&mut self, ui: &mut Ui) {
        if !self.session_windows.loaded {
            self.session_windows.loaded = true;
            match app_data_file("session-layouts.json").and_then(|p| {
                if p.exists() {
                    if std::fs::metadata(&p)?.len() > 1024 * 1024 {
                        anyhow::bail!("Layout file is too large")
                    };
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
                        "Cannot read saved window layouts: {e:#}"
                    ))
                }
            }
        }
        ui.heading("Session windows and monitors");
        ui.label("Open remote monitors in separate native windows, move them to local displays, and save the mapping as a layout.");
        for s in self.sessions.clone() {
            let monitors = self
                .profiles
                .iter()
                .find(|p| p.id == s.profile_id)
                .map(|p| p.options.monitors.clone())
                .unwrap_or_default();
            ui.horizontal_wrapped(|ui| {
                ui.label(&s.title);
                if ui.button("Entire desktop in a window").clicked() {
                    if !self.session_windows.open.contains(&s.id) {
                        self.session_windows.open.push(s.id);
                    }
                    self.session_windows.monitors.remove(&s.id);
                }
                if ui
                    .add_enabled(
                        monitors.len() > 1,
                        egui::Button::new("One window per remote monitor"),
                    )
                    .clicked()
                {
                    if !self.session_windows.open.contains(&s.id) {
                        self.session_windows.open.push(s.id);
                    }
                    self.session_windows
                        .monitors
                        .insert(s.id, (0..monitors.len().min(16)).collect());
                    self.session_windows.topology.insert(s.id, monitors.clone());
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
                    .hint_text("Window layout name"),
            );
            if ui
                .add_enabled(
                    !self.session_windows.name.trim().is_empty()
                        && self.session_windows.name.len() <= 100
                        && !self.session_windows.open.is_empty(),
                    egui::Button::new("Save layout"),
                )
                .clicked()
            {
                let mut windows = vec![];
                for id in &self.session_windows.open {
                    for monitor in self.session_windows.panes(*id) {
                        if let Some(window) = self.session_windows.positions.get(&(*id, monitor)) {
                            windows.push(window.clone());
                        }
                    }
                }
                let name = self.session_windows.name.trim().to_owned();
                self.session_windows.layouts.retain(|l| l.name != name);
                self.session_windows
                    .layouts
                    .push(SavedLayout { name, windows });
                self.status = match app_data_file("session-layouts.json").and_then(|p| {
                    std::fs::write(p, serde_json::to_vec_pretty(&self.session_windows.layouts)?)?;
                    Ok(())
                }) {
                    Ok(()) => "Window and monitor mapping saved".into(),
                    Err(e) => format!("Save: {e:#}"),
                };
            }
        });
        for layout in self.session_windows.layouts.clone() {
            ui.horizontal_wrapped(|ui|{
            ui.label(&layout.name);if ui.button("Apply to open sessions").clicked(){
                let mut missing=0;let mut reset=std::collections::HashSet::new();
                for mut w in layout.windows{
                    if ![w.x,w.y,w.width,w.height].iter().all(|v|v.is_finite()) || w.topology.len()>16 || w.monitor.is_some_and(|i|i>=w.topology.len()){missing+=1;continue}
                    if let Some(s)=self.sessions.iter().find(|s|s.profile_id==w.profile){
                        if reset.insert(s.id){self.session_windows.monitors.remove(&s.id);}
                        if !self.session_windows.open.contains(&s.id){self.session_windows.open.push(s.id);}
                        if let Some(index)=w.monitor{let indices=self.session_windows.monitors.entry(s.id).or_default();if !indices.contains(&index){indices.push(index);}self.session_windows.topology.insert(s.id,w.topology.clone());}
                        w.width=w.width.clamp(320.0,7680.0);w.height=w.height.clamp(240.0,4320.0);w.x=w.x.clamp(-32768.0,32768.0);w.y=w.y.clamp(-32768.0,32768.0);self.session_windows.positions.insert((s.id,w.monitor),w);
                    }else{missing+=1}
                }
                self.status=format!("Layout applied. {missing} windows not mapped. No connections were started.");
            }
        });
        }
    }
}
fn window_id(id: Uuid, monitor: Option<usize>) -> egui::ViewportId {
    egui::ViewportId::from_hash_of(("aivana-session", id, monitor))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn m(x: i32, y: i32, width: u32, height: u32) -> MonitorLayout {
        MonitorLayout {
            x,
            y,
            width,
            height,
            primary: x == 0 && y == 0,
        }
    }
    #[test]
    fn monitor_mapping_normalizes_negative_origins_and_rejects_stale_geometry() {
        let monitors = vec![
            m(-1920, 0, 1920, 1080),
            m(0, 0, 2560, 1440),
            m(0, -1200, 1600, 1200),
        ];
        let left = monitor_source(&monitors, 0, 4480, 2640).unwrap();
        assert_eq!(
            (left.left, left.top, left.right, left.bottom),
            (0, 1200, 1920, 2280)
        );
        let primary = monitor_source(&monitors, 1, 4480, 2640).unwrap();
        assert_eq!(
            (primary.left, primary.top, primary.right, primary.bottom),
            (1920, 1200, 4480, 2640)
        );
        let above = monitor_source(&monitors, 2, 4480, 2640).unwrap();
        assert_eq!(
            (above.left, above.top, above.right, above.bottom),
            (1920, 0, 3520, 1200)
        );
        assert!(monitor_source(&monitors, 0, 1920, 1080).is_none());
        assert!(monitor_source(&monitors, 3, 4480, 2640).is_none());
        assert!(monitor_source(&[m(i32::MAX, 0, u32::MAX, 1080)], 0, 1920, 1080).is_none());
    }
    #[test]
    fn cropped_monitor_pointer_and_uv_use_the_same_remote_offset() {
        let monitors = vec![m(-1920, 0, 1920, 1080), m(0, 0, 1920, 1080)];
        let source = monitor_source(&monitors, 1, 3840, 1080).unwrap();
        let frame = FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 3840,
            height: 1080,
            pixels_rgba: vec![],
            dirty_regions: vec![],
            frame_hash: 0,
            captured_at: chrono::Utc::now(),
        };
        let image = Rect::from_min_size(pos2(100.0, 50.0), Vec2::new(960.0, 540.0));
        assert_eq!(
            viewport_to_remote(image.left_top(), image, source, &frame),
            (1920, 0)
        );
        assert_eq!(
            viewport_to_remote(image.center(), image, source, &frame),
            (2880, 540)
        );
        assert_eq!(
            viewport_to_remote(image.right_bottom(), image, source, &frame),
            (3839, 1079)
        );
        let uv = source.uv_rect(&frame);
        assert_eq!(uv.left(), 0.5);
        assert_eq!(uv.right(), 1.0);
        let left_source = monitor_source(&monitors, 0, 3840, 1080).unwrap();
        assert_eq!(
            viewport_to_remote(image.right_bottom(), image, left_source, &frame),
            (1919, 1079)
        );
        assert_eq!(
            viewport_to_remote(pos2(5000.0, 5000.0), image, left_source, &frame),
            (1919, 1079)
        );
        assert_eq!(
            viewport_to_remote(pos2(-500.0, -500.0), image, source, &frame),
            (1920, 0)
        );
    }
    #[test]
    fn layout_preserves_remote_monitor_and_old_layouts_remain_readable() {
        let profile = Uuid::new_v4();
        let saved = SavedWindow {
            profile,
            monitor: Some(1),
            topology: vec![m(0, 0, 1920, 1080), m(1920, 0, 1920, 1080)],
            x: -1920.0,
            y: 0.0,
            width: 1920.0,
            height: 1080.0,
        };
        let restored: SavedWindow =
            serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
        assert_eq!(restored.monitor, Some(1));
        assert_eq!(restored.topology, saved.topology);
        assert_eq!(restored.x, -1920.0);
        let old =
            serde_json::json!({"profile":profile,"x":0.0,"y":0.0,"width":1100.0,"height":760.0});
        let old: SavedWindow = serde_json::from_value(old).unwrap();
        assert!(old.monitor.is_none());
        assert!(old.topology.is_empty());
        assert_ne!(window_id(profile, Some(0)), window_id(profile, Some(1)));
        assert_ne!(window_id(profile, None), window_id(profile, Some(0)));
    }
}
