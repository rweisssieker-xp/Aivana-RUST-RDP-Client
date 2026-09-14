use super::*;
use crate::team_server::collaboration_session::{Frame as SharedFrame, Proposal};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
type CaptureResult = Result<(Uuid, SharedFrame), String>;
#[derive(Default)]
pub(super) struct CaptureState {
    pending: Option<(Instant, mpsc::Receiver<CaptureResult>)>,
    cached: Option<(Uuid, SharedFrame, Instant)>,
    last: Option<Instant>,
    used: std::collections::HashSet<Uuid>,
}
fn sanitize(frame: FrameUpdate) -> CaptureResult {
    if frame.width == 0
        || frame.height == 0
        || frame.pixels_rgba.len() != frame.width as usize * frame.height as usize * 4
        || frame.pixels_rgba.len() > 32 * 1024 * 1024
    {
        return Err("Invalid or oversized screen data".into());
    }
    let screen = crate::vision::recognize(&frame).map_err(|e| e.to_string())?;
    let (masks, _) = crate::vision::redact(&frame, &screen).map_err(|e| e.to_string())?;
    let mut pixels = frame.pixels_rgba;
    for m in masks {
        let left = (m.x * frame.width as f32).floor() as u32;
        let right = ((m.x + m.w) * frame.width as f32)
            .ceil()
            .min(frame.width as f32) as u32;
        let top = (m.y * frame.height as f32).floor() as u32;
        let bottom = ((m.y + m.h) * frame.height as f32)
            .ceil()
            .min(frame.height as f32) as u32;
        for y in top..bottom {
            for x in left..right {
                let i = (y * frame.width as u32 + x) as usize * 4;
                pixels[i..i + 4].copy_from_slice(&[0, 0, 0, 255]);
            }
        }
    }
    let image = image::RgbaImage::from_raw(frame.width as u32, frame.height as u32, pixels)
        .ok_or_else(|| "Invalid frame".to_string())?;
    let scaled = image::DynamicImage::ImageRgba8(image)
        .resize(640, 360, image::imageops::FilterType::Triangle)
        .to_rgb8();
    Ok((
        frame.session_id,
        SharedFrame {
            width: scaled.width() as u16,
            height: scaled.height() as u16,
            rgb: scaled.into_raw(),
            source_hash: frame.frame_hash,
        },
    ))
}
impl AivanaApp {
    pub(super) fn collaboration_frame(&mut self) -> Option<(Uuid, SharedFrame)> {
        if let Some((started, rx)) = &self.collaboration_capture.pending {
            match rx.try_recv() {
                Ok(Ok((id, f))) => {
                    self.collaboration_capture.cached = Some((id, f, *started));
                    self.collaboration_capture.pending = None;
                }
                Ok(Err(e)) => {
                    self.status = format!("Sharing OCR failed: {e}");
                    self.collaboration_capture.cached = None;
                    self.collaboration_capture.pending = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.collaboration_capture.pending = None,
                Err(_) => {}
            }
        }
        let id = self.selected_session?;
        if !self
            .session_sources
            .get(&id)
            .is_some_and(|t| t.protocol == "RDP")
        {
            return None;
        }
        let frame = self.latest_frames.get(&id)?;
        if frame.width == 0
            || frame.height == 0
            || frame.pixels_rgba.len() != frame.width as usize * frame.height as usize * 4
        {
            return None;
        }
        if !self
            .sessions
            .iter()
            .any(|s| s.id == id && s.status == SessionStatus::Connected)
        {
            self.collaboration_capture.cached = None;
            return None;
        }
        if self.collaboration_capture.pending.is_none()
            && self
                .collaboration_capture
                .last
                .is_none_or(|t| t.elapsed() > Duration::from_millis(200))
            && frame.pixels_rgba.len() <= 32 * 1024 * 1024
        {
            let input = frame.clone();
            let (tx, rx) = mpsc::channel();
            self.collaboration_capture.pending = Some((Instant::now(), rx));
            self.collaboration_capture.last = Some(Instant::now());
            std::thread::spawn(move || {
                let _ = tx.send(sanitize(input));
            });
        }
        self.collaboration_capture
            .cached
            .as_ref()
            .filter(|(session, _f, at)| *session == id && at.elapsed() < Duration::from_secs(2))
            .map(|(id, f, _)| (*id, f.clone()))
    }
    pub(super) fn execute_collaboration_click(&mut self, p: Proposal) {
        let identities: std::collections::HashSet<_> = p.approvals.iter().collect();
        let valid = p.consumed
            && identities.len() >= 2
            && p.x <= 10000
            && p.y <= 10000
            && self.selected_session == Some(p.session)
            && self
                .sessions
                .iter()
                .any(|s| s.id == p.session && s.status == SessionStatus::Connected)
            && self
                .latest_frames
                .get(&p.session)
                .is_some_and(|f| f.frame_hash == p.frame_hash)
            && !self.collaboration_capture.used.contains(&p.id);
        if !valid {
            self.status =
                "Shared click blocked: approval, session, or frame no longer matches."
                    .into();
            return;
        }
        let f = &self.latest_frames[&p.session];
        let action = if let Some(key) = p.key {
            InputAction::Key {
                scan_code: key.scan_code(),
                pressed: true,
            }
        } else {
            InputAction::Click {
                x: ((p.x as u32 * f.width.saturating_sub(1) as u32) / 10000) as u16,
                y: ((p.y as u32 * f.height.saturating_sub(1) as u32) / 10000) as u16,
                button: MouseButton::Left,
            }
        };
        if crate::policy::PolicyEngine.decision_for(&action) == PolicyDecision::Deny {
            self.status = "Shared click blocked by local policy".into();
            return;
        }
        if self.collaboration_capture.used.len() >= 4096 {
            self.status = "Local approval limit reached; restart the application".into();
            return;
        }
        self.collaboration_capture.used.insert(p.id);
        self.teaching
            .cancel_run("Shared input paused the RDP workflow");
        self.engine.release_inputs_except(Some(p.session));
        self.engine.release_inputs(p.session);
        let result = self.engine.send_input(p.session, action);
        let release = if let Some(key) = p.key {
            self.engine.send_input(
                p.session,
                InputAction::Key {
                    scan_code: key.scan_code(),
                    pressed: false,
                },
            )
        } else {
            Ok(())
        };
        self.engine.release_inputs(p.session);
        self.status = match result.and(release) {
            Ok(()) => "Approved shared input sent; verify its effect".into(),
            Err(e) => format!("Shared input failed: {e}"),
        };
    }
}
