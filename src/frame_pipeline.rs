//! Frame data and the local presentation pipeline. Rectangles use inclusive edges.
use chrono::{DateTime, Utc};
use eframe::egui;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct FrameUpdate {
    pub session_id: Uuid,
    pub width: u16,
    pub height: u16,
    pub pixels_rgba: Vec<u8>,
    pub dirty_regions: Vec<DirtyRegion>,
    pub frame_hash: u64,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DirtyRegion {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

fn full(frame: &FrameUpdate) -> DirtyRegion {
    DirtyRegion {
        left: 0,
        top: 0,
        right: frame.width.saturating_sub(1),
        bottom: frame.height.saturating_sub(1),
    }
}

pub fn damage_bounds(frame: &FrameUpdate) -> DirtyRegion {
    if frame.dirty_regions.is_empty() {
        return full(frame);
    }
    let mut bounds = frame.dirty_regions[0];
    for r in &frame.dirty_regions {
        if r.left > r.right
            || r.top > r.bottom
            || r.right >= frame.width
            || r.bottom >= frame.height
        {
            return full(frame);
        }
        bounds.left = bounds.left.min(r.left);
        bounds.top = bounds.top.min(r.top);
        bounds.right = bounds.right.max(r.right);
        bounds.bottom = bounds.bottom.max(r.bottom);
    }
    bounds
}

/// A newer full snapshot must carry the damage of every skipped snapshot too.
pub fn merge_damage(new: &mut FrameUpdate, old: &FrameUpdate) {
    let r = if (new.width, new.height) != (old.width, old.height) {
        full(new)
    } else {
        let a = damage_bounds(new);
        let b = damage_bounds(old);
        DirtyRegion {
            left: a.left.min(b.left),
            top: a.top.min(b.top),
            right: a.right.max(b.right),
            bottom: a.bottom.max(b.bottom),
        }
    };
    new.dirty_regions = vec![r];
}

#[derive(Default)]
struct Pending {
    frame: Option<FrameUpdate>,
    published: u64,
    replaced: u64,
}

/// Latest-value slot: a slow GUI never builds an unbounded queue of desktop images.
/// Control/diagnostic events keep their existing independent ordered channel.
#[derive(Clone, Default)]
pub struct FrameMailbox(std::sync::Arc<std::sync::Mutex<Pending>>);
impl FrameMailbox {
    pub fn publish(&self, mut frame: FrameUpdate) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = state.frame.take() {
            merge_damage(&mut frame, &old);
            state.replaced += 1;
        }
        state.published += 1;
        state.frame = Some(frame);
    }
    pub fn take(&self) -> Option<FrameUpdate> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .frame
            .take()
    }
    pub fn counts(&self) -> (u64, u64) {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        (state.published, state.replaced)
    }
}

pub struct TextureUpload {
    pub origin: [usize; 2],
    pub image: egui::ColorImage,
    pub full: bool,
}

/// Convert only the damaged rectangle. The full RGBA snapshot remains available
/// to recordings, evidence and computer-use consumers, without GPU readback.
pub fn prepare_upload(
    frame: &FrameUpdate,
    previous_size: Option<[usize; 2]>,
) -> Option<TextureUpload> {
    let size = [usize::from(frame.width), usize::from(frame.height)];
    if size[0] == 0 || size[1] == 0 || frame.pixels_rgba.len() != size[0] * size[1] * 4 {
        return None;
    }
    let r = if previous_size == Some(size) {
        damage_bounds(frame)
    } else {
        full(frame)
    };
    let origin = [usize::from(r.left), usize::from(r.top)];
    let patch_size = [
        usize::from(r.right - r.left) + 1,
        usize::from(r.bottom - r.top) + 1,
    ];
    let is_full = origin == [0, 0] && patch_size == size;
    let image = if is_full {
        egui::ColorImage::from_rgba_unmultiplied(size, &frame.pixels_rgba)
    } else {
        let mut pixels = Vec::with_capacity(patch_size[0] * patch_size[1]);
        for y in origin[1]..origin[1] + patch_size[1] {
            let start = (y * size[0] + origin[0]) * 4;
            for p in frame.pixels_rgba[start..start + patch_size[0] * 4].chunks_exact(4) {
                pixels.push(egui::Color32::from_rgba_unmultiplied(
                    p[0], p[1], p[2], p[3],
                ));
            }
        }
        egui::ColorImage::new(patch_size, pixels)
    };
    Some(TextureUpload {
        origin,
        image,
        full: is_full,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(value: u8, regions: Vec<DirtyRegion>) -> FrameUpdate {
        FrameUpdate {
            session_id: Uuid::nil(),
            width: 4,
            height: 4,
            pixels_rgba: vec![value; 64],
            dirty_regions: regions,
            frame_hash: value.into(),
            captured_at: Utc::now(),
        }
    }
    #[test]
    fn skipped_frames_keep_all_damage_and_only_the_latest_pixels() {
        let slot = FrameMailbox::default();
        slot.publish(frame(
            10,
            vec![DirtyRegion {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            }],
        ));
        slot.publish(frame(
            20,
            vec![DirtyRegion {
                left: 3,
                top: 3,
                right: 3,
                bottom: 3,
            }],
        ));
        let latest = slot.take().unwrap();
        assert_eq!(latest.pixels_rgba, vec![20; 64]);
        assert_eq!(latest.dirty_regions, vec![full(&latest)]);
        assert_eq!(slot.counts(), (2, 1));
        assert!(slot.take().is_none());
    }
    #[test]
    fn partial_conversion_matches_corresponding_pixels_of_full_conversion() {
        let mut f = frame(
            255,
            vec![DirtyRegion {
                left: 1,
                top: 1,
                right: 2,
                bottom: 2,
            }],
        );
        for (i, p) in f.pixels_rgba.iter_mut().enumerate() {
            *p = (i * 3) as u8;
        }
        let expected = egui::ColorImage::from_rgba_unmultiplied([4, 4], &f.pixels_rgba);
        let patch = prepare_upload(&f, Some([4, 4])).unwrap();
        assert!(!patch.full);
        assert_eq!(patch.origin, [1, 1]);
        assert_eq!(patch.image.size, [2, 2]);
        assert_eq!(
            patch.image.pixels,
            vec![
                expected.pixels[5],
                expected.pixels[6],
                expected.pixels[9],
                expected.pixels[10]
            ]
        );
        assert!(prepare_upload(&f, None).unwrap().full);
        assert!(prepare_upload(&f, Some([8, 8])).unwrap().full);
    }
    #[test]
    fn resize_missing_damage_and_invalid_rectangles_force_full_upload() {
        let mut f = frame(255, vec![]);
        assert!(prepare_upload(&f, Some([4, 4])).unwrap().full);
        f.dirty_regions = vec![DirtyRegion {
            left: 3,
            top: 1,
            right: 2,
            bottom: 2,
        }];
        assert!(prepare_upload(&f, Some([4, 4])).unwrap().full);
        f.pixels_rgba.pop();
        assert!(prepare_upload(&f, None).is_none());
    }
    #[test]
    fn merged_patch_reconstructs_latest_image_after_skipping_frames() {
        let mut first = frame(255, vec![]);
        let mut displayed = prepare_upload(&first, None).unwrap().image;
        let slot = FrameMailbox::default();
        for (x, y, value) in [(0, 1, 10), (3, 2, 20)] {
            let index = (y * 4 + x) * 4;
            first.pixels_rgba[index..index + 3].fill(value);
            first.dirty_regions = vec![DirtyRegion {
                left: x as u16,
                top: y as u16,
                right: x as u16,
                bottom: y as u16,
            }];
            slot.publish(first.clone());
        }
        let latest = slot.take().unwrap();
        let patch = prepare_upload(&latest, Some([4, 4])).unwrap();
        for y in 0..patch.image.size[1] {
            for x in 0..patch.image.size[0] {
                displayed.pixels[(y + patch.origin[1]) * 4 + x + patch.origin[0]] =
                    patch.image.pixels[y * patch.image.size[0] + x];
            }
        }
        assert_eq!(
            displayed.pixels,
            prepare_upload(&latest, None).unwrap().image.pixels
        );
    }
    #[test]
    fn resize_while_waiting_requires_full_upload() {
        let slot = FrameMailbox::default();
        slot.publish(frame(255, vec![]));
        let mut resized = frame(
            255,
            vec![DirtyRegion {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            }],
        );
        resized.width = 2;
        resized.pixels_rgba.truncate(32);
        slot.publish(resized);
        let latest = slot.take().unwrap();
        assert_eq!(latest.dirty_regions, vec![full(&latest)]);
        assert!(prepare_upload(&latest, Some([2, 4])).unwrap().full);
    }
    #[test]
    fn stalled_consumer_retains_one_snapshot() {
        let slot = FrameMailbox::default();
        let producer = slot.clone();
        std::thread::spawn(move || {
            for _ in 0..1000 {
                producer.publish(frame(255, vec![]));
            }
        })
        .join()
        .unwrap();
        assert_eq!(slot.counts(), (1000, 999));
        assert!(slot.take().is_some());
        assert!(slot.take().is_none());
    }
}
