//! Reproducible CPU/memory microbenchmarks; not a network or end-to-end FPS test.
#[path = "../frame_pipeline.rs"]
mod frame_pipeline;
use eframe::egui;
use serde_json::json;
use std::{hint::black_box, time::Instant};

fn sample(mut action: impl FnMut(), iterations: usize) -> serde_json::Value {
    for _ in 0..3 {
        action();
    }
    let mut samples = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        action();
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    json!({"median_ms":samples[samples.len()/2],"p95_ms":samples[(samples.len()-1)*95/100],"iterations":iterations})
}

fn main() {
    let mut cases = Vec::new();
    for (width, height) in [(1920usize, 1080usize), (3840, 2160)] {
        let pixels: Vec<u8> = (0..width * height * 4)
            .map(|i| if i % 4 == 3 { 255 } else { (i % 251) as u8 })
            .collect();
        let conversion = sample(
            || {
                black_box(egui::ColorImage::from_rgba_unmultiplied(
                    [width, height],
                    black_box(&pixels),
                ));
            },
            31,
        );
        let batch = sample(
            || {
                for _ in 0..8 {
                    black_box(black_box(&pixels).clone());
                }
            },
            31,
        );
        let single_copy = sample(
            || {
                black_box(black_box(&pixels).clone());
            },
            31,
        );
        let mut frame = frame_pipeline::FrameUpdate {
            session_id: uuid::Uuid::nil(),
            width: width as u16,
            height: height as u16,
            pixels_rgba: pixels.clone(),
            dirty_regions: vec![],
            frame_hash: 0,
            captured_at: chrono::Utc::now(),
        };
        let mut patches = Vec::new();
        for (patch_width, patch_height) in [(64, 64), (width / 2, height / 2), (width, height)] {
            frame.dirty_regions = vec![frame_pipeline::DirtyRegion {
                left: 0,
                top: 0,
                right: (patch_width - 1) as u16,
                bottom: (patch_height - 1) as u16,
            }];
            let optimized = sample(
                || {
                    black_box(
                        frame_pipeline::prepare_upload(black_box(&frame), Some([width, height]))
                            .unwrap(),
                    );
                },
                31,
            );
            patches.push(
                json!({"damage_width":patch_width,"damage_height":patch_height,
                "converted_pixels":patch_width*patch_height,"optimized_conversion":optimized}),
            );
        }
        cases.push(
            json!({"width":width,"height":height,"rgba_bytes":pixels.len(),
            "legacy_full_conversion":conversion,"legacy_eight_region_copies":batch,
            "batched_single_copy":single_copy,"patches":patches,
            "legacy_eight_pending_frames_bytes":pixels.len()*8,
            "mailbox_max_pending_pixel_bytes":pixels.len()}),
        );
    }
    println!("{}", serde_json::to_string_pretty(&json!({
        "schema":"relayne.frame-pipeline-benchmark.v1", "build":if cfg!(debug_assertions){"debug"}else{"release"},
        "scope":"Local CPU conversion/copy timings and retained pixel bytes; excludes network, decoding, GPU upload, display and input latency",
        "cases":cases
    })).unwrap());
}
