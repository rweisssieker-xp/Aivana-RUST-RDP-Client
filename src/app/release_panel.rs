use crate::{
    localization::{Locale, tr},
    release_readiness as release,
};
use eframe::egui;

pub(super) fn draw(ui: &mut egui::Ui, locale: Locale) {
    ui.heading(tr(locale, "Verkaufsbereitschaft"));
    ui.strong(tr(
        locale,
        "Entwicklungsversion — Verkauf noch nicht freigegeben",
    ));
    ui.label(tr(locale,"Diese Ansicht dokumentiert den Stand. Sie führt keine Verbindung, Zahlung oder Lizenzaktivierung aus."));
    ui.separator();
    if locale == Locale::EnUs {
        ui.collapsing("Operating documentation", |ui| {
            for (title, text) in release::ENGLISH_DOCUMENTS {
                ui.collapsing(*title, |ui| {
                    if ui.button("Copy document").clicked() {
                        ui.ctx().copy_text((*text).to_owned());
                    }
                    egui::ScrollArea::vertical()
                        .max_height(300.0)
                        .show(ui, |ui| {
                            ui.label(*text);
                        });
                });
            }
            if ui
                .button("Copy bundled third-party license notices")
                .clicked()
            {
                ui.ctx().copy_text(release::THIRD_PARTY_NOTICES.to_owned());
            }
        });
    }
    ui.label(release::SELLER);
    ui.label(release::CONTACT);
    ui.label(if locale == Locale::EnUs {
        "Bielefeld District Court · HRB 46421 · VAT ID DE459356027"
    } else {
        release::REGISTER
    });
    ui.hyperlink_to(release::WEBSITE, release::WEBSITE);
    ui.hyperlink_to(release::SOURCE, release::SOURCE);
    for (title, detail) in release::gates(locale) {
        ui.group(|ui| {
            ui.strong(tr(locale, title));
            ui.label(tr(locale, detail));
        });
    }
    ui.label(tr(locale,"Vor einem Verkauf müssen alle offenen Punkte belegt und die vollständige Übersetzung geprüft werden."));
    ui.add_enabled(false, egui::Button::new(tr(locale, "Kauf nicht verfügbar")));
    if ui.button(tr(locale, "Statusbericht kopieren")).clicked() {
        if let Ok(json) = serde_json::to_string_pretty(&release::report(locale)) {
            ui.ctx().copy_text(json);
        }
    }
    if ui.button(tr(locale, "Handbuch kopieren")).clicked() {
        ui.ctx().copy_text(release::guide(locale).to_owned());
    }
    ui.collapsing(tr(locale, "Handbuch und Betriebsgrenzen"), |ui| {
        for line in release::guide(locale).lines() {
            if let Some(title) = line.strip_prefix("# ").or_else(|| line.strip_prefix("## ")) {
                ui.heading(title);
            } else {
                ui.label(line);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_view_renders_in_all_locales() {
        for locale in Locale::ALL {
            for width in [640.0, 1440.0] {
                let ctx = egui::Context::default();
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 1400.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| draw(ui, locale));
                    },
                );
                assert!(!output.shapes.is_empty());
            }
        }
    }
}
