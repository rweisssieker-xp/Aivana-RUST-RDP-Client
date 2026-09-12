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
                            self.vision.notice = format!("{} Wörter lokal erkannt", s.words.len());
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
                    self.vision.notice = "OCR-Worker beendet".into();
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
            self.vision.notice = "Zuerst eine Sitzung mit Bild auswählen".into();
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        self.vision.worker = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(vision::recognize(&frame).map_err(|e| format!("Lokale OCR: {e:#}")));
        });
    }
    pub(super) fn vision_view(&mut self, ui: &mut Ui) {
        ui.heading("Bild verstehen · lokal");
        ui.label("Windows OCR erkennt sichtbare Wörter mit Positionen. Bilder bleiben lokal. Das Archiv enthält nur automatisch und manuell geschwärzte Schlüsselbilder und deren bereinigten Suchtext.");
        if ui
            .add_enabled(
                self.vision.worker.is_none(),
                egui::Button::new("Aktuelles Bild lokal lesen"),
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
                "{} × {} · Bild {:016x} · {}",
                s.width,
                s.height,
                s.frame_hash,
                if current.is_some_and(|f| s.matches(f)) {
                    "aktuell"
                } else {
                    "veraltet – vor Aktion neu lesen"
                }
            ));
            ui.add(
                egui::TextEdit::singleline(&mut self.vision.query)
                    .hint_text("Erkannten Text durchsuchen"),
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
        ui.label("Semantischer Klick für den nächsten Schritt im Ablauf:");
        ui.add(
            egui::TextEdit::singleline(&mut self.vision.label)
                .char_limit(256)
                .hint_text("Exaktes sichtbares Wort, z. B. Speichern"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.vision.context)
                .char_limit(256)
                .hint_text("Optional: eindeutiges Wort in der Nähe"),
        );
        if let Some(s) = &self.vision.screen {
            match s.resolve(&Anchor {
                label: self.vision.label.clone(),
                context: self.vision.context.clone(),
            }) {
                Ok(b) => {
                    ui.label(format!(
                        "Eindeutiger Treffer bei {}, {}",
                        b.center().0,
                        b.center().1
                    ));
                }
                Err(e) => {
                    ui.label(e.to_string());
                }
            }
        }
        ui.small("OCR kann Geheimnisse übersehen. Erkannte Geheimnisfelder werden vor Archivierung breit geschwärzt; zusätzliche manuelle Masken bleiben erforderlich. Ein OCR-Fehler stoppt die Aufnahme.");
    }
}
