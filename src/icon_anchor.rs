//! Local fixed-size pixel templates. No OCR interpretation or remote image service.
use crate::{
    models::FrameUpdate,
    vision::{Bounds, Screen},
};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

pub const SIDE: u16 = 24;
const MIN_CONFIDENCE: f32 = 0.975;
const MIN_MARGIN: f32 = 0.02;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IconAnchor {
    pub rgb: Vec<u8>,
}
#[derive(Clone, Copy, Debug)]
pub struct Match {
    pub bounds: Bounds,
    pub confidence: f32,
}
impl IconAnchor {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.rgb.len() == usize::from(SIDE * SIDE) * 3,
            "Icon template must be 24×24 RGB pixels"
        );
        let min = *self.rgb.iter().min().unwrap();
        let max = *self.rgb.iter().max().unwrap();
        ensure!(
            max.saturating_sub(min) >= 64,
            "Icon template lacks contrast"
        );
        let mean = self.rgb.iter().map(|v| f64::from(*v)).sum::<f64>() / self.rgb.len() as f64;
        let variance = self
            .rgb
            .iter()
            .map(|v| (f64::from(*v) - mean).powi(2))
            .sum::<f64>()
            / self.rgb.len() as f64;
        ensure!(variance >= 200.0, "Icon template lacks distinctive detail");
        Ok(())
    }
    /// Matching OCR and redaction masks exclude detected text and sensitive bands.
    pub fn capture(frame: &FrameUpdate, screen: &Screen, x: u16, y: u16) -> Result<Self> {
        validate_frame(frame)?;
        ensure!(
            screen.matches(frame),
            "Icon capture requires OCR of this frame"
        );
        ensure!(
            x >= SIDE / 2 && y >= SIDE / 2,
            "Icon too close to frame edge"
        );
        let left = x - SIDE / 2;
        let top = y - SIDE / 2;
        ensure!(
            left + SIDE <= frame.width && top + SIDE <= frame.height,
            "Icon outside frame"
        );
        let (masks, _) = crate::vision::redact(frame, screen)?;
        ensure!(
            !masks.iter().any(|m| {
                m.x * f32::from(frame.width) < f32::from(left + SIDE)
                    && (m.x + m.w) * f32::from(frame.width) > f32::from(left)
                    && m.y * f32::from(frame.height) < f32::from(top + SIDE)
                    && (m.y + m.h) * f32::from(frame.height) > f32::from(top)
            }),
            "Icon overlaps a sensitive redaction band"
        );
        ensure!(
            !screen.words.iter().any(|w| {
                let b = w.bounds;
                u32::from(b.x) < u32::from(left + SIDE)
                    && u32::from(b.x) + u32::from(b.w) > u32::from(left)
                    && u32::from(b.y) < u32::from(top + SIDE)
                    && u32::from(b.y) + u32::from(b.h) > u32::from(top)
            }),
            "Detected text overlaps template; use a text anchor"
        );
        let mut rgb = Vec::with_capacity(usize::from(SIDE * SIDE) * 3);
        for row in top..top + SIDE {
            for col in left..left + SIDE {
                let i = (usize::from(row) * usize::from(frame.width) + usize::from(col)) * 4;
                rgb.extend_from_slice(&frame.pixels_rgba[i..i + 3]);
            }
        }
        let anchor = Self { rgb };
        anchor.validate()?;
        let found = anchor.resolve(frame)?;
        ensure!(
            found.bounds.x.abs_diff(left) <= 1 && found.bounds.y.abs_diff(top) <= 1,
            "Source icon is ambiguous"
        );
        Ok(anchor)
    }
    pub fn resolve(&self, frame: &FrameUpdate) -> Result<Match> {
        self.validate()?;
        validate_frame(frame)?;
        ensure!(
            frame.width >= SIDE && frame.height >= SIDE,
            "Frame too small for icon"
        );
        let side = usize::from(SIDE);
        let width = usize::from(frame.width);
        let mut candidates: Vec<Match> = Vec::new();
        let mut examined = 0usize;
        for y in 0..=usize::from(frame.height - SIDE) {
            for x in 0..=usize::from(frame.width - SIDE) {
                // Reject obvious mismatches before the bounded full comparison.
                let samples_match = [0usize, 5, 11, 17, 23].into_iter().all(|sy| {
                    [0usize, 5, 11, 17, 23].into_iter().all(|sx| {
                        let a = (sy * side + sx) * 3;
                        let b = ((y + sy) * width + x + sx) * 4;
                        (0..3).all(|c| self.rgb[a + c].abs_diff(frame.pixels_rgba[b + c]) <= 40)
                    })
                });
                if !samples_match {
                    continue;
                }
                examined += 1;
                ensure!(
                    examined <= 4096,
                    "Too many similar icon candidates; choose a more distinctive icon"
                );
                let mut error = 0u32;
                for sy in 0..side {
                    for sx in 0..side {
                        let a = (sy * side + sx) * 3;
                        let b = ((y + sy) * width + x + sx) * 4;
                        for c in 0..3 {
                            error += u32::from(self.rgb[a + c].abs_diff(frame.pixels_rgba[b + c]));
                        }
                    }
                }
                let confidence = 1.0 - error as f32 / (self.rgb.len() as f32 * 255.0);
                if confidence >= MIN_CONFIDENCE - MIN_MARGIN {
                    candidates.push(Match {
                        bounds: Bounds {
                            x: x as u16,
                            y: y as u16,
                            w: SIDE,
                            h: SIDE,
                        },
                        confidence,
                    });
                }
            }
        }
        candidates.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
        let best = candidates
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Icon not found at sufficient confidence"))?;
        ensure!(
            best.confidence >= MIN_CONFIDENCE,
            "Icon confidence below 97.5%"
        );
        if candidates.iter().skip(1).any(|other| {
            (other.bounds.x.abs_diff(best.bounds.x) > SIDE / 2
                || other.bounds.y.abs_diff(best.bounds.y) > SIDE / 2)
                && best.confidence - other.confidence < MIN_MARGIN
        }) {
            bail!("Icon ambiguous: another candidate is within 2 percentage points");
        }
        Ok(best)
    }
}
fn validate_frame(frame: &FrameUpdate) -> Result<()> {
    let size = usize::from(frame.width) * usize::from(frame.height) * 4;
    ensure!(
        size > 0 && size <= 32 * 1024 * 1024 && frame.pixels_rgba.len() == size,
        "Invalid or oversized icon frame"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame() -> FrameUpdate {
        FrameUpdate {
            session_id: uuid::Uuid::new_v4(),
            width: 100,
            height: 80,
            pixels_rgba: vec![220; 100 * 80 * 4],
            dirty_regions: vec![],
            frame_hash: 1,
            captured_at: chrono::Utc::now(),
        }
    }
    fn icon() -> IconAnchor {
        IconAnchor {
            rgb: (0..usize::from(SIDE * SIDE) * 3)
                .map(|i| ((i * 73 + i / 7) % 256) as u8)
                .collect(),
        }
    }
    fn paste(frame: &mut FrameUpdate, anchor: &IconAnchor, x: usize, y: usize) {
        for sy in 0..24 {
            for sx in 0..24 {
                let dst = ((y + sy) * usize::from(frame.width) + x + sx) * 4;
                let src = (sy * 24 + sx) * 3;
                frame.pixels_rgba[dst..dst + 3].copy_from_slice(&anchor.rgb[src..src + 3]);
            }
        }
    }
    #[test]
    fn translated_icon_resolves_and_duplicate_refuses() {
        let a = icon();
        let mut f = frame();
        paste(&mut f, &a, 42, 30);
        let found = a.resolve(&f).unwrap();
        assert_eq!((found.bounds.x, found.bounds.y), (42, 30));
        assert_eq!(found.confidence, 1.0);
        paste(&mut f, &a, 5, 3);
        assert!(a.resolve(&f).is_err());
    }
    #[test]
    fn changed_theme_missing_and_flat_templates_refuse() {
        let a = icon();
        assert!(a.resolve(&frame()).is_err());
        assert!(
            IconAnchor {
                rgb: vec![255; 24 * 24 * 3]
            }
            .validate()
            .is_err()
        );
        let mut f = frame();
        paste(&mut f, &a, 20, 20);
        for v in &mut f.pixels_rgba {
            *v = 255 - *v;
        }
        assert!(a.resolve(&f).is_err());
    }
}
