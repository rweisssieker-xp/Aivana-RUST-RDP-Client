use super::*;
use crate::recording::{self, Mask, Recorder, Recording};
#[derive(Default)]
pub(super) struct RecordingsState {
    pub active: Option<Recorder>,
    catalog: Vec<Recording>,
    masks: Vec<Mask>,
    selected: Option<Uuid>,
    frame: usize,
    query: String,
    note: String,
    path: String,
    texture: Option<TextureHandle>,
    loaded: Option<(Uuid, usize)>,
    stopping: bool,
    refreshed: bool,
}
impl AivanaApp {
    pub(super) fn poll_recordings(&mut self) {
        if let Some(rec) = &self.recordings.active {
            if !self.recordings.stopping {
                if let Some(f) = self.latest_frames.get(&rec.session) {
                    let mut note = self.recordings.note.clone();
                    for e in self
                        .timeline
                        .events_for_session(rec.session)
                        .iter()
                        .rev()
                        .take(6)
                        .rev()
                    {
                        note.push_str(&format!("\n{} {}", e.created_at, e.message));
                    }
                    self.recordings.active.as_mut().unwrap().capture(f, &note);
                }
            }
        }
        let mut updates = vec![];
        let mut disconnected = false;
        if let Some(rec) = &self.recordings.active {
            loop {
                match rec.rx.try_recv() {
                    Ok(r) => updates.push(r),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
        for update in updates {
            match update {
                Ok(r) => {
                    if r.finished {
                        self.recordings.active = None;
                        self.recordings.stopping = false;
                    }
                    self.recordings.catalog.retain(|old| old.id != r.id);
                    self.recordings.selected.get_or_insert(r.id);
                    self.recordings.catalog.push(r);
                }
                Err(e) => {
                    self.status = format!("Aufzeichnung: {e}");
                    if let Some(rec) = &mut self.recordings.active {
                        rec.stop();
                    }
                    self.recordings.stopping = true;
                }
            }
        }
        if disconnected && self.recordings.active.is_some() {
            self.recordings.active = None;
            self.recordings.stopping = false;
            self.status="Aufzeichnungsworker beendet. Archivstatus prüfen; letzte Speicherung möglicherweise fehlgeschlagen.".into();
        }
    }
    pub(super) fn recordings_view(&mut self, ui: &mut Ui) {
        ui.heading("Lokale Aufzeichnungen");
        ui.label("Verschlüsselte Schlüsselbilder mit Zeitmarken und Suchnotizen. Höchstens ein verändertes Bild pro Sekunde, 600 Bilder / 128 MiB je Aufzeichnung. Lokale Windows OCR schwärzt erkannte Geheimnisfelder vor Speicherung und ergänzt den Suchindex. OCR-Fehler stoppen die Aufnahme. Erkennung ist keine Garantie für vollständige Geheimniserkennung; ergänzen Sie manuelle Masken. Kein Video oder Audio.");
        if !self.recordings.refreshed {
            self.refresh_recordings();
        }
        if self.recordings.active.is_none() {
            ui.label(
                "Schwärzung vor der Aufnahme: Koordinaten als Anteil des Remote-Bildes (0 bis 1).",
            );
            let mut remove = None;
            for (i, m) in self.recordings.masks.iter_mut().enumerate() {
                ui.push_id(i, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::DragValue::new(&mut m.x)
                                .speed(0.01)
                                .range(0.0..=1.0)
                                .prefix("X "),
                        );
                        ui.add(
                            egui::DragValue::new(&mut m.y)
                                .speed(0.01)
                                .range(0.0..=1.0)
                                .prefix("Y "),
                        );
                        ui.add(
                            egui::DragValue::new(&mut m.w)
                                .speed(0.01)
                                .range(0.01..=1.0)
                                .prefix("Breite "),
                        );
                        ui.add(
                            egui::DragValue::new(&mut m.h)
                                .speed(0.01)
                                .range(0.01..=1.0)
                                .prefix("Höhe "),
                        );
                        if ui.small_button("Entfernen").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove {
                self.recordings.masks.remove(i);
            }
            if ui.button("Schwärzungsbereich ergänzen").clicked() {
                self.recordings.masks.push(Mask {
                    x: 0.0,
                    y: 0.0,
                    w: 0.25,
                    h: 0.15,
                });
            }
            if let Some(s) = self.selected_session().cloned() {
                ui.label(format!("Aufnahmeziel: {}", s.title));
                if ui
                    .add_enabled(
                        s.status == SessionStatus::Connected
                            && self.latest_frames.contains_key(&s.id),
                        egui::Button::new("Aufzeichnung dieser Sitzung starten"),
                    )
                    .clicked()
                {
                    let result = app_data_file("recordings").and_then(|root| {
                        Recorder::start(
                            root,
                            s.id,
                            s.profile_id,
                            s.title,
                            self.recordings.masks.clone(),
                        )
                    });
                    match result {
                        Ok(rec) => {
                            self.recordings.active = Some(rec);
                            self.recordings.stopping = false;
                        }
                        Err(e) => self.status = e.to_string(),
                    }
                }
            } else {
                ui.label("Zuerst eine verbundene Sitzung auswählen.");
            }
        } else {
            ui.colored_label(
                tw::RED_600,
                if self.recordings.stopping {
                    "Aufzeichnung wird abgeschlossen …"
                } else {
                    "● Aufzeichnung aktiv"
                },
            );
            if ui
                .add_enabled(
                    !self.recordings.stopping,
                    egui::Button::new("Aufzeichnung stoppen"),
                )
                .clicked()
            {
                self.recordings.active.as_mut().unwrap().stop();
                self.recordings.stopping = true;
            }
            if let Some(rec) = &self.recordings.active {
                ui.small(format!(
                    "{} Bilder wegen ausgelasteter Speicherung übersprungen",
                    rec.dropped
                ));
            }
        }
        ui.add(
            egui::TextEdit::singleline(&mut self.recordings.note)
                .hint_text("Suchnotiz für die nächsten aufgenommenen Bilder")
                .desired_width(f32::INFINITY),
        );
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.recordings.query)
                    .hint_text("Bildinhalt, Titel oder Notiz suchen"),
            );
            if ui.button("Archiv aktualisieren").clicked() {
                self.refresh_recordings();
            }
        });
        let query = self.recordings.query.to_lowercase();
        let catalog = self.recordings.catalog.clone();
        for r in &catalog {
            if r.title.to_lowercase().contains(&query)
                || r.frames.iter().any(|f| {
                    f.note.to_lowercase().contains(&query) || f.ocr.to_lowercase().contains(&query)
                })
            {
                if ui
                    .selectable_label(
                        self.recordings.selected == Some(r.id),
                        format!(
                            "{} · {} · {} Bilder{}",
                            r.title,
                            r.created.format("%d.%m. %H:%M"),
                            r.frames.len(),
                            if r.finished {
                                ""
                            } else {
                                " · nicht abgeschlossen"
                            }
                        ),
                    )
                    .clicked()
                {
                    self.recordings.selected = Some(r.id);
                    self.recordings.frame = r
                        .frames
                        .iter()
                        .position(|f| {
                            f.ocr.to_lowercase().contains(&query)
                                || f.note.to_lowercase().contains(&query)
                        })
                        .unwrap_or(0);
                }
            }
        }
        if let Some(r) = catalog
            .iter()
            .find(|r| Some(r.id) == self.recordings.selected)
        {
            if !r.frames.is_empty() {
                self.recordings.frame = self.recordings.frame.min(r.frames.len() - 1);
                ui.add(
                    egui::Slider::new(&mut self.recordings.frame, 0..=r.frames.len() - 1)
                        .text("Schlüsselbild"),
                );
                let key = (r.id, self.recordings.frame);
                if self.recordings.loaded != Some(key) {
                    let result = app_data_file("recordings")
                        .and_then(|root| recording::read_frame(&root, r, self.recordings.frame))
                        .and_then(|bytes| Ok(image::load_from_memory(&bytes)?.to_rgba8()));
                    match result {
                        Ok(img) => {
                            let size = [img.width() as usize, img.height() as usize];
                            self.recordings.texture = Some(ui.ctx().load_texture(
                                "recording-playback",
                                ColorImage::from_rgba_unmultiplied(size, img.as_raw()),
                                TextureOptions::LINEAR,
                            ));
                            self.recordings.loaded = Some(key);
                        }
                        Err(e) => {
                            self.status = format!("Bild lesen: {e:#}");
                            self.recordings.texture = None;
                        }
                    }
                }
                let frame = &r.frames[self.recordings.frame];
                ui.label(format!("{} · {}", frame.at, frame.note));
                ui.collapsing("Erkannter Bildinhalt (bereinigt)", |ui| {
                    ui.label(&frame.ocr);
                });
                if let Some(texture) = &self.recordings.texture {
                    ui.add(
                        egui::Image::new(texture)
                            .max_width(ui.available_width())
                            .max_height(460.0)
                            .maintain_aspect_ratio(true),
                    );
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.recordings.path)
                        .hint_text("Absoluter Pfad für PNG-Export"),
                );
                if ui
                    .button("Dieses Bild unverschlüsselt exportieren")
                    .clicked()
                {
                    self.status = match app_data_file("recordings")
                        .and_then(|root| recording::read_frame(&root, r, self.recordings.frame))
                        .and_then(|bytes| {
                            crate::mission::export_new(Path::new(&self.recordings.path), &bytes)
                        }) {
                        Ok(p) => format!("Bild gespeichert: {}", p.display()),
                        Err(e) => format!("Export: {e:#}"),
                    };
                }
            }
        }
    }
    fn refresh_recordings(&mut self) {
        self.recordings.refreshed = true;
        match app_data_file("recordings").and_then(|p| recording::list(&p)) {
            Ok(c) => self.recordings.catalog = c,
            Err(e) => self.status = format!("Archiv nicht lesbar: {e:#}"),
        };
    }
}
