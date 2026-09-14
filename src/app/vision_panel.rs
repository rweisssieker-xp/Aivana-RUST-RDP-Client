use super::*;
use crate::vision::{self, Anchor, Screen};
#[derive(Default)]
pub(super) struct VisionState {
    pub screen: Option<Screen>,
    worker: Option<std::sync::mpsc::Receiver<Result<Screen, String>>>,
    pub label: String,
    pub context: String,
    query: String,
    notice: String,
}
impl VisionState {
    pub(super) fn is_busy(&self) -> bool {
        self.worker.is_some()
    }
}
impl AivanaApp {
    pub(super) fn poll_vision(&mut self) {
        if let Some(rx) = &self.vision.worker {
            match rx.try_recv() {
                Ok(result) => {
                    self.vision.worker = None;
                    match result {
                        Ok(s) => {
                            self.vision.notice = format!("{} words recognized locally", s.words.len());
                            self.vision.screen = Some(s);
                        }
                        Err(e) => {
                            self.vision.screen = None;
                            self.vision.notice = e;
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.vision.worker = None;
                    self.vision.notice = "OCR worker stopped".into();
                }
                _ => {}
            }
        }
    }
    pub(super) fn request_vision(&mut self) {
        if self.vision.worker.is_some() {
            return;
        }
        let Some(frame) = self
            .selected_session
            .and_then(|id| self.latest_frames.get(&id))
            .cloned()
        else {
            self.vision.notice = "Select a session with an image first".into();
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        self.vision.worker = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(vision::recognize(&frame).map_err(|e| format!("Local OCR: {e:#}")));
        });
    }
    pub(super) fn vision_view(&mut self, ui: &mut Ui) {
        ui.heading("Understand the screen · locally");
        ui.label("Windows OCR recognizes visible words and their positions. Images stay local. The archive contains only keyframes with automatic and manual redactions and their sanitized search text.");
        if ui
            .add_enabled(
                self.vision.worker.is_none(),
                egui::Button::new("Read current image locally"),
            )
            .clicked()
        {
            self.request_vision();
        }
        if self.vision.worker.is_some() {
            ui.spinner();
        }
        ui.label(&self.vision.notice);
        let current = self
            .selected_session
            .and_then(|id| self.latest_frames.get(&id));
        if let Some(s) = &self.vision.screen {
            ui.label(format!(
                "{} × {} · Frame {:016x} · {}",
                s.width,
                s.height,
                s.frame_hash,
                if current.is_some_and(|f| s.matches(f)) {
                    "current"
                } else {
                    "outdated – read again before acting"
                }
            ));
            ui.add(
                egui::TextEdit::singleline(&mut self.vision.query)
                    .hint_text("Search recognized text"),
            );
            ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                for w in &s.words {
                    if w.text
                        .to_lowercase()
                        .contains(&self.vision.query.to_lowercase())
                    {
                        if ui
                            .selectable_label(
                                self.vision.label == w.text,
                                format!("{}  ({}, {})", w.text, w.bounds.x, w.bounds.y),
                            )
                            .clicked()
                        {
                            self.vision.label = w.text.clone();
                        }
                    }
                }
            });
        }
        ui.separator();
        ui.label("Semantic click for the next workflow step:");
        ui.add(
            egui::TextEdit::singleline(&mut self.vision.label)
                .char_limit(256)
                .hint_text("Exact visible word, e.g., Save"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.vision.context)
                .char_limit(256)
                .hint_text("Optional: unique nearby word"),
        );
        if let Some(s) = &self.vision.screen {
            match s.resolve(&Anchor {
                label: self.vision.label.clone(),
                context: self.vision.context.clone(),
            }) {
                Ok(b) => {
                    ui.label(format!(
                        "Unique match at {}, {}",
                        b.center().0,
                        b.center().1
                    ));
                }
                Err(e) => {
                    ui.label(e.to_string());
                }
            }
        }
        ui.small("OCR may miss secrets. Detected secret fields are broadly redacted before archiving; additional manual masks are still required. An OCR error stops recording.");
    }
}
