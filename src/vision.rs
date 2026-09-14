//! Local OCR, exact-frame semantic anchors and conservative pre-persistence redaction.
use crate::models::FrameUpdate;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Bounds {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}
impl Bounds {
    pub fn center(self) -> (u16, u16) {
        (self.x + self.w / 2, self.y + self.h / 2)
    }
    fn overlaps(self, b: Self) -> bool {
        u32::from(self.x) < u32::from(b.x) + u32::from(b.w)
            && u32::from(b.x) < u32::from(self.x) + u32::from(self.w)
            && u32::from(self.y) < u32::from(b.y) + u32::from(b.h)
            && u32::from(b.y) < u32::from(self.y) + u32::from(self.h)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Word {
    pub text: String,
    pub bounds: Bounds,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Screen {
    pub session: uuid::Uuid,
    pub width: u16,
    pub height: u16,
    pub frame_hash: u64,
    pub captured_at: chrono::DateTime<chrono::Utc>,
    pub words: Vec<Word>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Anchor {
    pub label: String,
    pub context: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorResolutionError {
    Missing,
    Ambiguous,
}
impl std::fmt::Display for AnchorResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "OCR target is missing; wait for the expected visible state",
            Self::Ambiguous => "OCR target is ambiguous; add unique context",
        })
    }
}
impl std::error::Error for AnchorResolutionError {}
impl Screen {
    pub fn matches(&self, f: &FrameUpdate) -> bool {
        self.session == f.session_id
            && self.width == f.width
            && self.height == f.height
            && self.frame_hash == f.frame_hash
            && self.captured_at == f.captured_at
    }
    pub fn resolve(&self, a: &Anchor) -> Result<Bounds> {
        let label = normalize(&a.label);
        let context = normalize(&a.context);
        if label.is_empty() || label.len() > 256 || context.len() > 256 {
            bail!("Invalid OCR anchor");
        }
        let found: Vec<_> = self
            .words
            .iter()
            .filter(|w| normalize(&w.text) == label)
            .filter(|w| {
                context.is_empty()
                    || self.words.iter().any(|c| {
                        normalize(&c.text) == context
                            && c.bounds.center().0.abs_diff(w.bounds.center().0) < 500
                            && c.bounds.center().1.abs_diff(w.bounds.center().1) < 120
                    })
            })
            .collect();
        match found.as_slice() {
            [w] => Ok(w.bounds),
            [] => Err(AnchorResolutionError::Missing.into()),
            _ => Err(AnchorResolutionError::Ambiguous.into()),
        }
    }
    pub fn text(&self) -> String {
        self.words
            .iter()
            .map(|w| w.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(4096)
            .collect()
    }
}
fn normalize(s: &str) -> String {
    s.trim()
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}
fn sensitive(s: &str) -> bool {
    let s = s.to_lowercase();
    [
        "key",
        "credential",
        "passphrase",
        "zugang",
        "auth",
        "password",
        "passwort",
        "kennwort",
        "secret",
        "token",
        "api-key",
        "apikey",
        "api_key",
        "bearer",
        "authorization",
        "private key",
        "recovery",
        "wiederherstellungscode",
        "pin",
        "otp",
        "cvv",
        "cvc",
    ]
    .iter()
    .any(|p| s.contains(p))
        || s.contains("sk-")
        || s.contains("eyj")
        || s.contains("-----begin")
        || (s.len() > 20
            && s.chars().any(|c| c.is_ascii_digit())
            && s.chars().any(|c| c.is_ascii_alphabetic()))
        || s.chars().filter(|c| c.is_ascii_digit()).count() >= 12
        || (s.len() >= 3 && s.chars().all(|c| matches!(c, '*' | '•' | '●')))
}
/// Automatic procedure metadata excludes likely secret values and oversized OCR tokens.
pub fn safe_anchor_text(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 256 && !sensitive(s)
}
/// Masks detected labels, the full horizontal value band and one line below.
/// This is heuristic and cannot identify every secret, image, or custom control.
pub fn redact(f: &FrameUpdate, screen: &Screen) -> Result<(Vec<crate::recording::Mask>, Screen)> {
    if !screen.matches(f) {
        bail!("Redaction blocked: OCR does not match the current image");
    }
    let mut rects = Vec::new();
    for w in &screen.words {
        let b = w.bounds;
        if b.w == 0
            || b.h == 0
            || u32::from(b.x) + u32::from(b.w) > u32::from(f.width)
            || u32::from(b.y) + u32::from(b.h) > u32::from(f.height)
        {
            bail!("Redaction blocked: invalid OCR geometry");
        }
        if sensitive(&w.text) {
            let y = b.y.saturating_sub(8);
            let end = (u32::from(b.y) + u32::from(b.h) * 3 + 20).min(u32::from(f.height)) as u16;
            rects.push(Bounds {
                x: 0,
                y,
                w: f.width,
                h: end - y,
            });
        }
    }
    let mut clean = screen.clone();
    clean
        .words
        .retain(|w| !rects.iter().any(|b| b.overlaps(w.bounds)));
    let masks = rects
        .into_iter()
        .map(|b| crate::recording::Mask {
            x: b.x as f32 / f.width as f32,
            y: b.y as f32 / f.height as f32,
            w: b.w as f32 / f.width as f32,
            h: b.h as f32 / f.height as f32,
        })
        .collect();
    Ok((masks, clean))
}
pub fn recognize(f: &FrameUpdate) -> Result<Screen> {
    if f.width == 0
        || f.height == 0
        || f.pixels_rgba.len() != usize::from(f.width) * usize::from(f.height) * 4
        || f.pixels_rgba.len() > 128 * 1024 * 1024
    {
        bail!("Invalid OCR image");
    }
    let words = native_words(f)?;
    Ok(Screen {
        session: f.session_id,
        width: f.width,
        height: f.height,
        frame_hash: f.frame_hash,
        captured_at: f.captured_at,
        words,
    })
}
#[cfg(not(windows))]
fn native_words(_: &FrameUpdate) -> Result<Vec<Word>> {
    bail!("Local OCR requires Windows 10/11 and an installed OCR language pack")
}
#[cfg(windows)]
fn keep_ocr_runtime_alive() -> Result<()> {
    // windows-core caches agile WinRT activation factories for the process lifetime.
    // Releasing the final worker apartment permits deferred COM server unloading,
    // leaving those cached factories unusable when the next OCR worker arrives.
    // Keep one MTA usage cookie for the same lifetime; Windows releases it at exit.
    // The opaque cookie is retained as an integer, never dereferenced or shared as
    // an interface pointer. Per-thread RoInitialize/RoUninitialize stay balanced.
    static MTA_USAGE: std::sync::OnceLock<std::result::Result<usize, String>> =
        std::sync::OnceLock::new();
    match MTA_USAGE.get_or_init(|| unsafe {
        windows::Win32::System::Com::CoIncrementMTAUsage()
            .map(|cookie| cookie.0 as usize)
            .map_err(|error| error.to_string())
    }) {
        Ok(_) => Ok(()),
        Err(error) => bail!("Unable to retain Windows OCR runtime: {error}"),
    }
}

#[cfg(windows)]
fn native_words(f: &FrameUpdate) -> Result<Vec<Word>> {
    use windows::{
        Graphics::Imaging::{BitmapAlphaMode, BitmapPixelFormat, SoftwareBitmap},
        Media::Ocr::OcrEngine,
        Storage::Streams::DataWriter,
        Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
    };
    keep_ocr_runtime_alive()?;
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)?;
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { RoUninitialize() }
        }
    }
    let _apartment = Apartment;
    let engine =
        OcrEngine::TryCreateFromUserProfileLanguages().context("Windows OCR language pack is missing")?;
    let max = OcrEngine::MaxImageDimension()?;
    if u32::from(f.width) > max || u32::from(f.height) > max {
        bail!("Image exceeds Windows OCR limit {max}; recording stopped");
    }
    let mut bgra = f.pixels_rgba.clone();
    for p in bgra.chunks_exact_mut(4) {
        p.swap(0, 2);
    }
    let writer = DataWriter::new()?;
    writer.WriteBytes(&bgra)?;
    let bitmap = SoftwareBitmap::CreateCopyWithAlphaFromBuffer(
        &writer.DetachBuffer()?,
        BitmapPixelFormat::Bgra8,
        i32::from(f.width),
        i32::from(f.height),
        BitmapAlphaMode::Ignore,
    )?;
    let operation = engine.RecognizeAsync(&bitmap)?;
    let started = std::time::Instant::now();
    // WinRT AsyncStatus::Started is zero. Poll on this worker, never the UI thread.
    while operation.Status()?.0 == 0 {
        if started.elapsed() > std::time::Duration::from_secs(20) {
            let _ = operation.Cancel();
            bail!("Local OCR time limit reached; recording stopped");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let result = operation.GetResults()?;
    let mut words = vec![];
    for line in result.Lines()? {
        for word in line.Words()? {
            if words.len() >= 10000 {
                bail!("OCR word limit exceeded");
            }
            let b = word.BoundingRect()?;
            let x = b.X.floor().max(0.0).min(f.width as f32) as u16;
            let y = b.Y.floor().max(0.0).min(f.height as f32) as u16;
            let right = (b.X + b.Width).ceil().min(f.width as f32) as u16;
            let bottom = (b.Y + b.Height).ceil().min(f.height as f32) as u16;
            if right > x && bottom > y {
                words.push(Word {
                    text: word.Text()?.to_string(),
                    bounds: Bounds {
                        x,
                        y,
                        w: right - x,
                        h: bottom - y,
                    },
                });
            }
        }
    }
    Ok(words)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn frame() -> FrameUpdate {
        FrameUpdate {
            session_id: uuid::Uuid::new_v4(),
            width: 800,
            height: 600,
            pixels_rgba: vec![255; 800 * 600 * 4],
            dirty_regions: vec![],
            frame_hash: 7,
            captured_at: chrono::Utc::now(),
        }
    }
    fn word(t: &str, x: u16, y: u16) -> Word {
        Word {
            text: t.into(),
            bounds: Bounds { x, y, w: 80, h: 20 },
        }
    }
    fn screen(f: &FrameUpdate, words: Vec<Word>) -> Screen {
        Screen {
            session: f.session_id,
            width: f.width,
            height: f.height,
            frame_hash: f.frame_hash,
            captured_at: f.captured_at,
            words,
        }
    }
    #[test]
    fn moved_label_resolves_but_duplicate_blocks() {
        let f = frame();
        let a = Anchor {
            label: "Save".into(),
            context: "".into(),
        };
        let mut s = screen(&f, vec![word("Save", 500, 400)]);
        assert_eq!(s.resolve(&a).unwrap().center(), (540, 410));
        s.words.push(word("Save", 0, 0));
        assert!(s.resolve(&a).is_err());
        s.words.clear();
        assert!(s.resolve(&a).is_err());
    }
    #[test]
    fn dimensions_are_not_identity() {
        let mut f = frame();
        let s = screen(&f, vec![]);
        f.frame_hash += 1;
        assert!(!s.matches(&f));
        assert!(redact(&f, &s).is_err());
    }
    #[test]
    fn redaction_removes_value_from_pixels_and_index() {
        let f = frame();
        let s = screen(
            &f,
            vec![
                word("Password", 10, 20),
                word("hunter2", 200, 20),
                word("Welcome", 10, 200),
            ],
        );
        let (m, c) = redact(&f, &s).unwrap();
        assert_eq!(c.text(), "Welcome");
        let png = crate::recording::masked_png(&f, &m).unwrap();
        let image = image::load_from_memory(&png).unwrap().to_rgba8();
        assert_eq!(image.get_pixel(230, 30).0, [0, 0, 0, 255]);
    }
}

#[cfg(all(test, windows))]
#[test]
fn native_ocr_generated_nonsecret_image() {
    let img = image::load_from_memory(include_bytes!("../tests/fixtures/ocr-nonsecret.png"))
        .unwrap()
        .to_rgba8();
    let f = FrameUpdate {
        session_id: uuid::Uuid::new_v4(),
        width: img.width() as u16,
        height: img.height() as u16,
        pixels_rgba: img.into_raw(),
        dirty_regions: vec![],
        frame_hash: 99,
        captured_at: chrono::Utc::now(),
    };
    let screen = recognize(&f).expect("Windows OCR with installed language pack");
    assert!(
        screen.text().to_lowercase().contains("save"),
        "OCR result: {}",
        screen.text()
    );
    assert!(
        screen
            .resolve(&Anchor {
                label: "Save".into(),
                context: "Settings".into()
            })
            .is_ok()
    );
}

#[cfg(all(test, windows))]
#[test]
fn native_ocr_survives_idle_worker_teardown() {
    std::thread::spawn(native_ocr_generated_nonsecret_image)
        .join()
        .unwrap();
    // Windows can unload idle COM servers after its deferred cleanup interval.
    // A fast back-to-back test does not exercise the cached factory's lifetime.
    std::thread::sleep(std::time::Duration::from_secs(35));
    std::thread::spawn(native_ocr_generated_nonsecret_image)
        .join()
        .unwrap();
}
