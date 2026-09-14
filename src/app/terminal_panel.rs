//! Cell-based embedded terminal; terminal keystrokes go directly to the PTY.
use crate::terminal::Terminal;
use eframe::egui::{self, Align2, Color32, FontId, Sense};

pub fn show(ui: &mut egui::Ui, terminal: &mut Terminal) {
    ui.horizontal(|ui| {
        ui.label(
            terminal
                .status
                .lock()
                .map(|s| s.clone())
                .unwrap_or_default(),
        );
        if ui.button("Disconnect").clicked() {
            terminal.close();
        }
    });
    let cell = egui::vec2(8.4, 18.0);
    let available = ui.available_size().max(egui::vec2(100.0, 80.0));
    terminal.resize((available.y / cell.y) as u16, (available.x / cell.x) as u16);
    let (rect, response) = ui.allocate_exact_size(available, Sense::click());
    if response.clicked() {
        response.request_focus();
    }
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3.0, Color32::from_rgb(10, 15, 22));
    if let Ok(parser) = terminal.parser.lock() {
        let screen = parser.screen();
        let (rows, cols) = screen.size();
        for row in 0..rows {
            for col in 0..cols {
                if let Some(c) = screen.cell(row, col) {
                    if c.is_wide_continuation() {
                        continue;
                    }
                    let pos = rect.min + egui::vec2(col as f32 * cell.x, row as f32 * cell.y);
                    let mut fg = color(c.fgcolor(), Color32::from_rgb(220, 228, 240));
                    let mut bg = color(c.bgcolor(), Color32::from_rgb(10, 15, 22));
                    if c.inverse() {
                        std::mem::swap(&mut fg, &mut bg);
                    }
                    painter.rect_filled(
                        egui::Rect::from_min_size(
                            pos,
                            egui::vec2(cell.x * if c.is_wide() { 2.0 } else { 1.0 }, cell.y),
                        ),
                        0.0,
                        bg,
                    );
                    painter.text(
                        pos,
                        Align2::LEFT_TOP,
                        c.contents(),
                        FontId::monospace(14.0),
                        fg,
                    );
                    if c.underline() {
                        painter.line_segment(
                            [pos + egui::vec2(0.0, 16.0), pos + egui::vec2(cell.x, 16.0)],
                            (1.0, fg),
                        );
                    }
                }
            }
        }
        if response.has_focus() && !screen.hide_cursor() {
            let (row, col) = screen.cursor_position();
            let pos = rect.min + egui::vec2(col as f32 * cell.x, row as f32 * cell.y);
            painter.rect_stroke(
                egui::Rect::from_min_size(pos, cell),
                0.0,
                (1.0, Color32::WHITE),
                egui::StrokeKind::Inside,
            );
        }
    }
    if response.has_focus() {
        let (events, app_cursor, bracketed) = (
            ui.input(|i| i.events.clone()),
            terminal
                .parser
                .lock()
                .map(|p| p.screen().application_cursor())
                .unwrap_or(false),
            terminal
                .parser
                .lock()
                .map(|p| p.screen().bracketed_paste())
                .unwrap_or(false),
        );
        for event in events {
            let bytes = match event {
                egui::Event::Copy => Some(vec![3]),
                egui::Event::Cut => Some(vec![24]),
                egui::Event::Text(text) => Some(text.into_bytes()),
                egui::Event::Paste(text) => Some(if bracketed {
                    format!("\x1b[200~{text}\x1b[201~").into_bytes()
                } else {
                    text.into_bytes()
                }),
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => key_bytes(key, modifiers, app_cursor),
                _ => None,
            };
            if let Some(bytes) = bytes {
                if let Err(error) = terminal.input(bytes) {
                    if let Ok(mut s) = terminal.status.lock() {
                        *s = error;
                    }
                }
            }
        }
    }
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(33));
}
fn key_bytes(key: egui::Key, modifiers: egui::Modifiers, app: bool) -> Option<Vec<u8>> {
    use egui::Key::*;
    if modifiers.ctrl {
        let name = format!("{key:?}");
        if name.len() == 1 && name.as_bytes()[0].is_ascii_uppercase() {
            return Some(vec![name.as_bytes()[0] - b'A' + 1]);
        }
    }
    let s = match key {
        Enter => "\r",
        Backspace => "\x7f",
        Tab if modifiers.shift => "\x1b[Z",
        Tab => "\t",
        Escape => "\x1b",
        ArrowUp => {
            if app {
                "\x1bOA"
            } else {
                "\x1b[A"
            }
        }
        ArrowDown => {
            if app {
                "\x1bOB"
            } else {
                "\x1b[B"
            }
        }
        ArrowRight => {
            if app {
                "\x1bOC"
            } else {
                "\x1b[C"
            }
        }
        ArrowLeft => {
            if app {
                "\x1bOD"
            } else {
                "\x1b[D"
            }
        }
        Home => "\x1b[H",
        End => "\x1b[F",
        Delete => "\x1b[3~",
        Insert => "\x1b[2~",
        PageUp => "\x1b[5~",
        PageDown => "\x1b[6~",
        F1 => "\x1bOP",
        F2 => "\x1bOQ",
        F3 => "\x1bOR",
        F4 => "\x1bOS",
        F5 => "\x1b[15~",
        F6 => "\x1b[17~",
        F7 => "\x1b[18~",
        F8 => "\x1b[19~",
        F9 => "\x1b[20~",
        F10 => "\x1b[21~",
        F11 => "\x1b[23~",
        F12 => "\x1b[24~",
        _ => return None,
    };
    Some(s.as_bytes().to_vec())
}
fn color(c: vt100::Color, default: Color32) -> Color32 {
    match c {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) => {
            const PALETTE: [[u8; 3]; 16] = [
                [0, 0, 0],
                [205, 49, 49],
                [13, 188, 121],
                [229, 229, 16],
                [36, 114, 200],
                [188, 63, 188],
                [17, 168, 205],
                [229, 229, 229],
                [102, 102, 102],
                [241, 76, 76],
                [35, 209, 139],
                [245, 245, 67],
                [59, 142, 234],
                [214, 112, 214],
                [41, 184, 219],
                [255, 255, 255],
            ];
            let [r, g, b] = if i < 16 {
                PALETTE[i as usize]
            } else if i < 232 {
                let n = i - 16;
                let v = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
                [v(n / 36), v(n / 6 % 6), v(n % 6)]
            } else {
                [8 + (i - 232) * 10; 3]
            };
            Color32::from_rgb(r, g, b)
        }
    }
}
