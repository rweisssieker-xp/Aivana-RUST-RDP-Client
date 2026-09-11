//! Optional native renderer capture for repeatable visual verification.
use super::*;

#[derive(Default)]
pub(super) struct GuiCapture {
    path: Option<std::path::PathBuf>,
    frames: u8,
    requested: bool,
}

impl GuiCapture {
    pub fn from_args() -> Self {
        let args: Vec<_> = std::env::args_os().collect();
        let path = args
            .iter()
            .position(|arg| arg == "--gui-capture")
            .and_then(|index| args.get(index + 1))
            .map(std::path::PathBuf::from);
        Self {
            path,
            ..Default::default()
        }
    }

    pub fn tick(&mut self, ctx: &Context) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(image) = ctx.input(|input| {
            input.events.iter().find_map(|event| {
                if let egui::Event::Screenshot { image, .. } = event {
                    Some(image.clone())
                } else {
                    None
                }
            })
        }) {
            let pixels: Vec<u8> = image
                .pixels
                .iter()
                .flat_map(|pixel| pixel.to_array())
                .collect();
            let result = image::save_buffer(
                path,
                &pixels,
                image.width() as u32,
                image.height() as u32,
                image::ColorType::Rgba8,
            );
            match result {
                Ok(()) => println!("GUI capture saved: {}", path.display()),
                Err(error) => eprintln!("GUI capture failed: {error}"),
            }
            self.path = None;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        self.frames = self.frames.saturating_add(1);
        if self.frames >= 4 && !self.requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
            self.requested = true;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
