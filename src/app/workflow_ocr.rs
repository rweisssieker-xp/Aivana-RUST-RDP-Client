use super::*;
use crate::vision::{Anchor, Screen};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

struct Pending {
    request: (String, String, String),
    session: Uuid,
    connected: DateTime<Utc>,
    activated: DateTime<Utc>,
    started: Instant,
    receiver: mpsc::Receiver<Result<Screen, String>>,
}
#[derive(Default)]
pub(super) struct WorkflowOcrState {
    pending: Option<Pending>,
    active: Option<(String, DateTime<Utc>)>,
    notice: String,
}
fn verify_current_screen(
    screen: &Screen,
    frame: &FrameUpdate,
    activated: DateTime<Utc>,
    now: DateTime<Utc>,
    expected: &str,
) -> Result<(), String> {
    let elapsed = now - frame.captured_at;
    if !screen.matches(frame)
        || frame.captured_at < activated
        || elapsed.num_seconds() < 0
        || elapsed.num_seconds() > 20
    {
        return Err(
            "A new image captured after the check started is required; image changed or outdated"
                .into(),
        );
    }
    screen
        .resolve(&Anchor {
            label: expected.into(),
            context: String::new(),
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}
impl AivanaApp {
    fn checkpoint_session(&self, target: &str) -> Option<(Uuid, DateTime<Utc>)> {
        let id = self.selected_session?;
        let session = self
            .sessions
            .iter()
            .find(|s| s.id == id && s.status == SessionStatus::Connected)?;
        let source = self.session_sources.get(&id)?;
        if source.protocol != "RDP"
            || !(source.host.eq_ignore_ascii_case(target)
                || source.profile_id.to_string() == target)
        {
            return None;
        }
        let profile = self.profiles.iter().find(|p| p.id == source.profile_id)?;
        if !source.matches(profile) {
            return None;
        }
        Some((id, session.connected_at))
    }
    pub(super) fn poll_workflow_ocr(&mut self) {
        match self.workflow_checkpoint_request() {
            Some((token, _, _))
                if self
                    .workflow_ocr
                    .active
                    .as_ref()
                    .is_none_or(|(id, _)| *id != token) =>
            {
                self.workflow_ocr.active = Some((token, Utc::now()))
            }
            None => self.workflow_ocr.active = None,
            _ => {}
        }
        let Some(p) = self.workflow_ocr.pending.as_ref() else {
            return;
        };
        if self.workflow_checkpoint_request().as_ref() != Some(&p.request)
            || p.started.elapsed() > Duration::from_secs(20)
        {
            self.workflow_ocr.pending = None;
            self.workflow_ocr.notice =
                "Check changed or OCR timed out; no evidence accepted."
                    .into();
            return;
        }
        let result = match p.receiver.try_recv() {
            Ok(r) => r,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(_) => Err("OCR worker stopped".into()),
        };
        let p = self.workflow_ocr.pending.take().unwrap();
        let result=result.and_then(|screen|{
            if self.checkpoint_session(&p.request.1)!=Some((p.session,p.connected)){return Err("Target session or profile changed".into())}
            let frame=self.latest_frames.get(&p.session).ok_or("Session image missing")?;
            verify_current_screen(&screen,frame,p.activated,Utc::now(),&p.request.2)?;
            Ok(format!("Local OCR evidence: unique expected text in the current image; session {}; connection started {}; frame {:016x}; image time {}. Visible state, not evidence of business causation.",p.session,p.connected,screen.frame_hash,screen.captured_at))
        });
        self.workflow_ocr.notice = match result {
            Ok(evidence) => {
                if self.workflow_submit_ocr_evidence(&p.request.0, evidence) {
                    "Visible state verified; job resumed.".into()
                } else {
                    "Check is no longer active; evidence discarded.".into()
                }
            }
            Err(e) => e,
        };
    }
    pub(super) fn workflow_with_proof_view(&mut self, ui: &mut Ui) {
        self.workflow_view(ui);
        let Some(request) = self.workflow_checkpoint_request() else {
            return;
        };
        ui.separator();
        ui.strong("Alternatively: verify visible state locally");
        ui.label("For OCR, the target must match the host or profile ID of the selected connected RDP session. The expected text must be an exact, visible word that occurs only once.");
        if ui
            .add_enabled(
                self.workflow_ocr.pending.is_none(),
                egui::Button::new("Check current target image with OCR and continue if matched"),
            )
            .clicked()
        {
            let result = (|| -> Result<Pending, String> {
                let (session, connected) = self
                    .checkpoint_session(&request.1)
                    .ok_or("Select a matching connected RDP session")?;
                let frame = self
                    .latest_frames
                    .get(&session)
                    .ok_or("Image missing")?
                    .clone();
                let activated = self
                    .workflow_ocr
                    .active
                    .as_ref()
                    .filter(|(token, _)| *token == request.0)
                    .map(|(_, at)| *at)
                    .ok_or("Check is initializing; try again")?;
                if frame.captured_at < activated {
                    return Err(
                        "Receive a new session image after this check started first"
                            .into(),
                    );
                }
                if frame.pixels_rgba.len() > 32 * 1024 * 1024 {
                    return Err("Image exceeds OCR limit".into());
                }
                if !crate::vision::safe_anchor_text(&request.2) {
                    return Err("Expected text is not a valid text anchor".into());
                }
                let (tx, receiver) = mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(
                        crate::vision::recognize(&frame)
                            .map_err(|_| "Local OCR failed".into()),
                    );
                });
                Ok(Pending {
                    request,
                    session,
                    connected,
                    activated,
                    started: Instant::now(),
                    receiver,
                })
            })();
            match result {
                Ok(p) => {
                    self.workflow_ocr.pending = Some(p);
                    self.workflow_ocr.notice = "Checking image locally …".into()
                }
                Err(e) => self.workflow_ocr.notice = e,
            }
        }
        ui.label(&self.workflow_ocr.notice);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn image(now: DateTime<Utc>) -> (FrameUpdate, Screen) {
        let frame = FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 10,
            height: 10,
            pixels_rgba: vec![255; 400],
            dirty_regions: vec![],
            frame_hash: 7,
            captured_at: now,
        };
        let screen = Screen {
            session: frame.session_id,
            width: 10,
            height: 10,
            frame_hash: 7,
            captured_at: now,
            words: vec![crate::vision::Word {
                text: "Ready".into(),
                bounds: crate::vision::Bounds {
                    x: 0,
                    y: 0,
                    w: 5,
                    h: 5,
                },
            }],
        };
        (frame, screen)
    }
    #[test]
    fn old_changed_and_ambiguous_screens_cannot_verify_checkpoint() {
        let now = Utc::now();
        let (mut frame, mut screen) = image(now);
        assert!(verify_current_screen(&screen, &frame, now, now, "Ready").is_ok());
        assert!(
            verify_current_screen(
                &screen,
                &frame,
                now + chrono::Duration::milliseconds(1),
                now,
                "Ready"
            )
            .is_err()
        );
        frame.frame_hash = 8;
        assert!(verify_current_screen(&screen, &frame, now, now, "Ready").is_err());
        frame.frame_hash = 7;
        assert!(
            verify_current_screen(
                &screen,
                &frame,
                now,
                now + chrono::Duration::seconds(21),
                "Ready"
            )
            .is_err()
        );
        screen.words.push(screen.words[0].clone());
        assert!(verify_current_screen(&screen, &frame, now, now, "Ready").is_err());
    }
}
