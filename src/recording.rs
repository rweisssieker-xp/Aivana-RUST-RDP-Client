//! Explicit, locally protected keyframe recordings; no implicit screen collection.
use crate::{
    models::FrameUpdate,
    security::{protect_secret, redact_secret_text, unprotect_secret},
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    io::Cursor,
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};
use uuid::Uuid;
const MAX_FRAMES: usize = 600;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Mask {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}
impl Mask {
    fn valid(self) -> bool {
        [self.x, self.y, self.w, self.h]
            .iter()
            .all(|f| f.is_finite())
            && self.x >= 0.0
            && self.y >= 0.0
            && self.w > 0.0
            && self.h > 0.0
            && self.x + self.w <= 1.0001
            && self.y + self.h <= 1.0001
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Keyframe {
    pub file: String,
    pub at: DateTime<Utc>,
    pub note: String,
    #[serde(default)]
    pub ocr: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Recording {
    pub id: Uuid,
    pub profile: Uuid,
    pub title: String,
    pub created: DateTime<Utc>,
    pub finished: bool,
    pub frames: Vec<Keyframe>,
    pub masks: Vec<Mask>,
}
enum Message {
    Frame(FrameUpdate, String),
    Stop,
}
pub struct Recorder {
    pub session: Uuid,
    tx: Option<mpsc::SyncSender<Message>>,
    pub rx: mpsc::Receiver<Result<Recording, String>>,
    last: Instant,
    last_hash: Option<u64>,
    pub dropped: usize,
}
impl Recorder {
    pub fn start(
        root: PathBuf,
        session: Uuid,
        profile: Uuid,
        title: String,
        masks: Vec<Mask>,
    ) -> Result<Self> {
        if masks.len() > 16 || masks.iter().any(|m| !m.valid()) {
            bail!("Invalid redaction regions");
        }
        std::fs::create_dir_all(&root)?;
        let recording = Recording {
            id: Uuid::new_v4(),
            profile,
            title: redact_secret_text(&title),
            created: Utc::now(),
            finished: false,
            frames: vec![],
            masks,
        };
        let dir = root.join(recording.id.to_string());
        std::fs::create_dir(&dir)?;
        write_protected(&dir.join("index.dpapi"), &serde_json::to_vec(&recording)?)?;
        let (tx, rx) = mpsc::sync_channel(2);
        let (out, results) = mpsc::channel();
        std::thread::spawn(move || {
            let mut recording = recording;
            let mut bytes = 0u64;
            while let Ok(message) = rx.recv() {
                match message {
                    Message::Stop => break,
                    Message::Frame(frame, note) => {
                        let result = (|| -> Result<()> {
                            if recording.frames.len() >= MAX_FRAMES {
                                bail!("Limit of 600 keyframes reached");
                            }
                            let screen = crate::vision::recognize(&frame).context(
                                "Recording stopped: automatic OCR redaction failed",
                            )?;
                            let (mut masks, mut clean) = crate::vision::redact(&frame, &screen)?;
                            masks.extend_from_slice(&recording.masks);
                            clean.words.retain(|w| {
                                !recording.masks.iter().any(|m| {
                                    let b = w.bounds;
                                    let x = b.x as f32 / frame.width as f32;
                                    let y = b.y as f32 / frame.height as f32;
                                    let right = (u32::from(b.x) + u32::from(b.w)) as f32
                                        / frame.width as f32;
                                    let bottom = (u32::from(b.y) + u32::from(b.h)) as f32
                                        / frame.height as f32;
                                    x < m.x + m.w && right > m.x && y < m.y + m.h && bottom > m.y
                                })
                            });
                            let png = masked_png(&frame, &masks)?;
                            bytes += png.len() as u64;
                            if bytes > MAX_BYTES {
                                bail!("Recording limit of 128 MiB reached");
                            }
                            let file = format!("{:06}.dpapi", recording.frames.len());
                            write_protected(&dir.join(&file), &png)?;
                            recording.frames.push(Keyframe {
                                file,
                                at: frame.captured_at,
                                note: redact_secret_text(&note),
                                ocr: clean.text(),
                            });
                            write_protected(
                                &dir.join("index.dpapi"),
                                &serde_json::to_vec(&recording)?,
                            )?;
                            Ok(())
                        })();
                        match result {
                            Ok(()) => {
                                let _ = out.send(Ok(recording.clone()));
                            }
                            Err(e) => {
                                let _ = out.send(Err(e.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
            recording.finished = true;
            match write_protected(
                &dir.join("index.dpapi"),
                &serde_json::to_vec(&recording).unwrap_or_default(),
            ) {
                Ok(()) => {
                    let _ = out.send(Ok(recording));
                }
                Err(e) => {
                    let _ = out.send(Err(e.to_string()));
                }
            }
        });
        Ok(Self {
            session,
            tx: Some(tx),
            rx: results,
            last: Instant::now() - Duration::from_secs(2),
            last_hash: None,
            dropped: 0,
        })
    }
    pub fn capture(&mut self, frame: &FrameUpdate, note: &str) {
        if frame.session_id != self.session
            || self.last.elapsed() < Duration::from_secs(1)
            || self.last_hash == Some(frame.frame_hash)
        {
            return;
        }
        if let Some(tx) = &self.tx {
            match tx.try_send(Message::Frame(
                frame.clone(),
                note.chars().take(2048).collect(),
            )) {
                Ok(()) => {
                    self.last = Instant::now();
                    self.last_hash = Some(frame.frame_hash);
                }
                Err(mpsc::TrySendError::Full(_)) => {
                    self.dropped += 1;
                    self.last = Instant::now();
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.tx = None;
                }
            }
        }
    }
    pub fn stop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.try_send(Message::Stop); /* Dropping sender finishes even if queue was full. */
        }
    }
}
impl Drop for Recorder {
    fn drop(&mut self) {
        self.stop();
    }
}
fn write_protected(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.file_name() == Some(std::ffi::OsStr::new("index.dpapi"))
        && bytes.len() > 4 * 1024 * 1024
    {
        bail!("Recording index limit reached; recording stopped");
    }
    #[cfg(not(windows))]
    {
        let _ = (path, bytes);
        bail!("Recording protection requires Windows DPAPI");
    }
    #[cfg(windows)]
    {
        let temp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
        std::fs::write(&temp, protect_secret(bytes)?)?;
        if let Err(e) = std::fs::rename(&temp, path) {
            let _ = std::fs::remove_file(&temp);
            return Err(e.into());
        }
        Ok(())
    }
}
pub fn masked_png(frame: &FrameUpdate, masks: &[Mask]) -> Result<Vec<u8>> {
    if masks.iter().any(|m| !m.valid()) {
        bail!("Invalid redaction region");
    }
    let (w, h) = (u32::from(frame.width), u32::from(frame.height));
    if w == 0
        || h == 0
        || u64::from(w) * u64::from(h) > 32 * 1024 * 1024
        || frame.pixels_rgba.len() != w as usize * h as usize * 4
    {
        bail!("Invalid image data");
    }
    let mut img =
        image::RgbaImage::from_raw(w, h, frame.pixels_rgba.clone()).context("Image data")?;
    for m in masks {
        let (x0, y0) = (
            (m.x * w as f32).floor() as u32,
            (m.y * h as f32).floor() as u32,
        );
        let (x1, y1) = (
            ((m.x + m.w) * w as f32).ceil() as u32,
            ((m.y + m.h) * h as f32).ceil() as u32,
        );
        for y in y0..y1.min(h) {
            for x in x0..x1.min(w) {
                img.put_pixel(x, y, image::Rgba([0, 0, 0, 255]));
            }
        }
    }
    let mut bytes = Cursor::new(Vec::new());
    img.write_to(&mut bytes, image::ImageFormat::Png)?;
    Ok(bytes.into_inner())
}
pub fn list(root: &Path) -> Result<Vec<Recording>> {
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut result = vec![];
    for entry in std::fs::read_dir(root)?.take(1000) {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(id) = Uuid::parse_str(name) else {
            continue;
        };
        let p = entry.path().join("index.dpapi");
        if !p.exists() {
            continue;
        }
        if std::fs::metadata(&p)?.len() > 4 * 1024 * 1024 {
            bail!("Recording index exceeds the size limit");
        }
        let r: Recording = serde_json::from_slice(&unprotect_secret(&std::fs::read(p)?)?)?;
        if r.id != id || r.frames.len() > MAX_FRAMES {
            bail!("Invalid recording index");
        }
        result.push(r);
    }
    result.sort_by_key(|r| std::cmp::Reverse(r.created));
    Ok(result)
}
pub fn read_frame(root: &Path, recording: &Recording, index: usize) -> Result<Vec<u8>> {
    let frame = recording.frames.get(index).context("Keyframe is missing")?;
    if frame.file != format!("{index:06}.dpapi") {
        bail!("Invalid image path");
    }
    let path = root.join(recording.id.to_string()).join(&frame.file);
    if std::fs::metadata(&path)?.len() > MAX_BYTES {
        bail!("Image file exceeds the size limit");
    }
    unprotect_secret(&std::fs::read(path)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn frame() -> FrameUpdate {
        FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 4,
            height: 4,
            pixels_rgba: vec![255; 64],
            dirty_regions: vec![],
            frame_hash: 1,
            captured_at: Utc::now(),
        }
    }
    #[test]
    fn mask_applied_before_encoding() {
        let bytes = masked_png(
            &frame(),
            &[Mask {
                x: 0.0,
                y: 0.0,
                w: 0.5,
                h: 1.0,
            }],
        )
        .unwrap();
        let img = image::load_from_memory(&bytes).unwrap().to_rgba8();
        assert_eq!(img.get_pixel(0, 0).0, [0, 0, 0, 255]);
        assert_eq!(img.get_pixel(3, 0).0, [255; 4]);
    }
    #[test]
    fn rejects_malformed_frames_and_masks() {
        let mut f = frame();
        f.pixels_rgba.pop();
        assert!(masked_png(&f, &[]).is_err());
        assert!(
            masked_png(
                &frame(),
                &[Mask {
                    x: f32::NAN,
                    ..Default::default()
                }]
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_index_path_traversal() {
        let r = Recording {
            id: Uuid::new_v4(),
            profile: Uuid::new_v4(),
            title: String::new(),
            created: Utc::now(),
            finished: true,
            frames: vec![Keyframe {
                file: "../secret".into(),
                at: Utc::now(),
                note: String::new(),
                ocr: String::new(),
            }],
            masks: vec![],
        };
        assert!(read_frame(Path::new("."), &r, 0).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn recording_roundtrip_and_stop() {
        let root = std::env::temp_dir().join(format!("rec-{}", Uuid::new_v4()));
        let f = frame();
        let mut rec = Recorder::start(
            root.clone(),
            f.session_id,
            Uuid::new_v4(),
            "test".into(),
            vec![],
        )
        .unwrap();
        rec.capture(&f, "event");
        rec.stop();
        let mut done = None;
        while let Ok(Ok(r)) = rec.rx.recv_timeout(Duration::from_secs(5)) {
            if r.finished {
                done = Some(r);
                break;
            }
        }
        let r = done.unwrap();
        assert_eq!(r.frames.len(), 1);
        assert!(image::load_from_memory(&read_frame(&root, &r, 0).unwrap()).is_ok());
        assert_eq!(list(&root).unwrap().len(), 1);
        let dir = root.join(r.id.to_string());
        std::fs::remove_file(dir.join("000000.dpapi")).unwrap();
        std::fs::remove_file(dir.join("index.dpapi")).unwrap();
        std::fs::remove_dir(dir).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
