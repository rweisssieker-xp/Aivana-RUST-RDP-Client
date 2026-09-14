use super::*;
use crate::recording::{self, Mask, Recorder, Recording};
#[derive(Default)]
pub(super) struct RecordingsState {
    check_source: Option<crate::application_checks::recorded_ui::Derived>,
    check_chosen: std::collections::BTreeSet<usize>,
    check_include_procedure: bool,
    check_review: Option<crate::application_checks::recorded_ui::Review>,
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
                    self.status = format!("Recording: {e}");
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
            self.status =
                "Recording worker stopped. Check archive status; the last save may have failed."
                    .into();
        }
    }
    pub(super) fn recordings_view(&mut self, ui: &mut Ui) {
        ui.heading("Local recordings");
        ui.label("Encrypted keyframes with timestamps and search notes. At most one changed image per second, 600 images / 128 MiB per recording. Local Windows OCR redacts detected secret fields before saving and adds to the search index. OCR errors stop recording. Detection does not guarantee that all secrets are found; add manual masks. No video or audio.");
        if !self.recordings.refreshed {
            self.refresh_recordings();
        }
        if self.recordings.active.is_none() {
            ui.label(
                "Redaction before recording: coordinates as a fraction of the remote image (0 to 1).",
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
                                .prefix("Width "),
                        );
                        ui.add(
                            egui::DragValue::new(&mut m.h)
                                .speed(0.01)
                                .range(0.01..=1.0)
                                .prefix("Height "),
                        );
                        if ui.small_button("Remove").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove {
                self.recordings.masks.remove(i);
            }
            if ui.button("Add redaction area").clicked() {
                self.recordings.masks.push(Mask {
                    x: 0.0,
                    y: 0.0,
                    w: 0.25,
                    h: 0.15,
                });
            }
            if let Some(s) = self.selected_session().cloned() {
                ui.label(format!("Recording target: {}", s.title));
                if ui
                    .add_enabled(
                        s.status == SessionStatus::Connected
                            && self.latest_frames.contains_key(&s.id),
                        egui::Button::new("Start recording this session"),
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
                ui.label("Select a connected session first.");
            }
        } else {
            ui.colored_label(
                tw::RED_600,
                if self.recordings.stopping {
                    "Finalizing recording …"
                } else {
                    "● Recording active"
                },
            );
            if ui
                .add_enabled(
                    !self.recordings.stopping,
                    egui::Button::new("Stop recording"),
                )
                .clicked()
            {
                self.recordings.active.as_mut().unwrap().stop();
                self.recordings.stopping = true;
            }
            if let Some(rec) = &self.recordings.active {
                ui.small(format!(
                    "{} images skipped because storage was busy",
                    rec.dropped
                ));
            }
        }
        ui.add(
            egui::TextEdit::singleline(&mut self.recordings.note)
                .hint_text("Search note for the next recorded images")
                .desired_width(f32::INFINITY),
        );
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.recordings.query)
                    .hint_text("Search image content, title, or note"),
            );
            if ui.button("Refresh archive").clicked() {
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
                            "{} · {} · {} images{}",
                            r.title,
                            r.created.format("%m/%d %H:%M"),
                            r.frames.len(),
                            if r.finished { "" } else { " · incomplete" }
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
                self.recorded_application_checks_ui(ui, r);
                self.recordings.frame = self.recordings.frame.min(r.frames.len() - 1);
                ui.add(
                    egui::Slider::new(&mut self.recordings.frame, 0..=r.frames.len() - 1)
                        .text("Keyframe"),
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
                            self.status = format!("Read image: {e:#}");
                            self.recordings.texture = None;
                        }
                    }
                }
                let frame = &r.frames[self.recordings.frame];
                ui.label(format!("{} · {}", frame.at, frame.note));
                ui.collapsing("Recognized image content (sanitized)", |ui| {
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
                        .hint_text("Absolute path for PNG export"),
                );
                if ui.button("Export this image without encryption").clicked() {
                    self.status = match app_data_file("recordings")
                        .and_then(|root| recording::read_frame(&root, r, self.recordings.frame))
                        .and_then(|bytes| {
                            crate::mission::export_new(Path::new(&self.recordings.path), &bytes)
                        }) {
                        Ok(p) => format!("Image saved: {}", p.display()),
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
            Err(e) => self.status = format!("Cannot read archive: {e:#}"),
        };
    }

    fn recorded_application_checks_ui(&mut self, ui: &mut Ui, recording: &Recording) {
        use crate::application_checks::recorded_ui as checks;
        ui.collapsing("Application checks from this recording",|ui| {
            ui.label("Derive visible-state candidates from this finished recording's local redacted OCR. Recorded text is an observation, not proof of application success. Nothing is sent or executed.");
            if self.recordings.check_source.as_ref().is_some_and(|source|source.source.id!=recording.id) {
                self.recordings.check_source=None;self.recordings.check_review=None;self.recordings.check_chosen.clear();
            }
            if ui.add_enabled(recording.finished,egui::Button::new("Derive recorded visible checkpoints")).clicked() {
                self.recordings.check_review=None;self.recordings.check_chosen.clear();
                match checks::derive(recording) {Ok(source)=>self.recordings.check_source=Some(source),Err(error)=>{self.recordings.check_source=None;self.status=error.to_string();}}
            }
            let Some(source)=self.recordings.check_source.clone() else{return;};
            let Some(profile)=self.profiles.iter().find(|p|p.id==source.source.profile).cloned() else{ui.label("The recorded target profile is missing; restore its mapping before preparing checks.");return;};
            ui.label(format!("Recorded profile: {} · Current endpoint: {}:{} · {}",profile.id,profile.host,profile.port,profile.name));
            ui.small("Choose up to four observed words. Only a limited UI-state vocabulary is suggested; OCR with secret-field hints is omitted. Review the original images. Backend results are not inferred.");
            for (index,candidate) in source.candidates.iter().enumerate() {
                let mut selected=self.recordings.check_chosen.contains(&index);
                if ui.checkbox(&mut selected,format!("{} · frame {} · observed {}",candidate.word,candidate.frame+1,candidate.at)).changed() {
                    self.recordings.check_review=None;
                    if selected {self.recordings.check_chosen.insert(index);} else {self.recordings.check_chosen.remove(&index);}
                }
            }
            if ui.checkbox(&mut self.recordings.check_include_procedure,"Include the currently loaded demonstrated procedure before these checks").changed(){self.recordings.check_review=None;}
            let procedure=self.recordings.check_include_procedure.then(||self.teaching.teacher.procedure.clone());
            if let Some(procedure)=&procedure {
                ui.small("The demonstration is selected separately; timestamps do not align it automatically to this recording. Review every action and parameter slot for this target. Live replay uses existing native OCR and per-step approvals.");
                ui.collapsing("Demonstrated actions and assertions to review",|ui|{ui.monospace(serde_json::to_string_pretty(procedure).unwrap_or_default());});
            } else {ui.small("Select at least two observed checkpoints: an initial screen and a final screen. The workflow pauses for the operator; it does not infer login clicks.");}
            let now=chrono::Utc::now();
            if let Some(review)=&self.recordings.check_review {
                if checks::prepare(recording,&profile,&self.recordings.check_chosen,procedure.as_ref(),review,now).is_err(){self.recordings.check_review=None;}
            }
            let valid=checks::review(&source.source,&profile,&self.recordings.check_chosen,procedure.as_ref(),now);
            if let Err(error)=&valid {ui.label(error.to_string());}
            let mut reviewed=self.recordings.check_review.is_some();
            if ui.add_enabled(valid.is_ok(),egui::Checkbox::new(&mut reviewed,"I reviewed the recorded images, exact target, selected expected states, and optional demonstration. Prepare this workflow only.")).changed() {
                self.recordings.check_review=if reviewed {valid.ok()} else {None};
            }
            if ui.add_enabled(self.recordings.check_review.is_some(),egui::Button::new("Prepare recorded application-check workflow")).clicked() {
                let result=(||->anyhow::Result<()> {
                    let fresh=recording::list(&app_data_file("recordings")?)?.into_iter().find(|r|r.id==recording.id).ok_or_else(||anyhow::anyhow!("Recording is no longer available"))?;
                    let review=self.recordings.check_review.as_ref().ok_or_else(||anyhow::anyhow!("Review is missing"))?;
                    let plan=checks::prepare(&fresh,&profile,&self.recordings.check_chosen,procedure.as_ref(),review,chrono::Utc::now())?;
                    self.prepare_recorded_check_workflow(plan)
                })();
                self.recordings.check_review=None;
                self.status=match result {Ok(())=>"Recorded checks prepared in Workflows. Review and approve there before any execution.".into(),Err(error)=>error.to_string()};
            }
        });
    }
}
