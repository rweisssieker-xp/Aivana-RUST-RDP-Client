use super::*;
use crate::{execution::impact::Report, localization::Locale};
fn t(locale: Locale, key: &str) -> &str {
    let i = match locale {
        Locale::De => 1,
        Locale::EnUs => 2,
        Locale::Fr => 3,
        Locale::It => 4,
    };
    TEXT.iter()
        .find(|r| r[0] == key)
        .map(|r| r[i])
        .unwrap_or(key)
}
const TEXT: &[[&str; 5]] = &[
    [
        "title",
        "Nachweisbare Ergebnisse",
        "Measured outcomes",
        "Résultats mesurés",
        "Risultati misurati",
    ],
    [
        "scope",
        "Abgeschlossene Ergebnisse der letzten 90 Tage für das ausgewählte Produktionsziel. Historische Daten, keine Freigabe.",
        "Completed outcomes in the last 90 days for the selected production endpoint. Historical data, not authorization.",
        "Résultats terminés des 90 derniers jours pour la cible de production sélectionnée. Données historiques, pas une autorisation.",
        "Esiti completati negli ultimi 90 giorni per l’endpoint di produzione selezionato. Dati storici, non un’autorizzazione.",
    ],
    [
        "production",
        "Produktion",
        "Production",
        "Production",
        "Produzione",
    ],
    [
        "rehearsal",
        "Testumgebung",
        "Rehearsal",
        "Environnement de test",
        "Ambiente di prova",
    ],
    [
        "repaired",
        "Belegte Reparaturen",
        "Evidenced repairs",
        "Réparations étayées",
        "Riparazioni documentate",
    ],
    ["failed", "Fehlgeschlagen", "Failed", "Échecs", "Falliti"],
    [
        "restored",
        "Zurückgesetzt",
        "Restored",
        "Restaurés",
        "Ripristinati",
    ],
    [
        "unverified",
        "Ungeklärt",
        "Unverified",
        "Non vérifiés",
        "Non verificati",
    ],
    [
        "median",
        "Median: Ausgangsbefund → erfolgreicher Funktionstest",
        "Median: initial observation → successful health check",
        "Médiane : observation initiale → contrôle réussi",
        "Mediana: osservazione iniziale → controllo riuscito",
    ],
    [
        "samples",
        "Zeitstichproben / belegte Reparaturen",
        "Timing samples / evidenced repairs",
        "Échantillons temporels / réparations étayées",
        "Campioni temporali / riparazioni documentate",
    ],
    [
        "none",
        "Nicht gemessen",
        "Not measured",
        "Non mesuré",
        "Non misurato",
    ],
    [
        "limits",
        "Das Zeitintervall umfasst nur belegte Erfolge. Es ist weder vollständige Störungsdauer noch Arbeitszeit oder Zeitersparnis. Manueller Vergleich und ROI sind nicht gemessen.",
        "The interval covers evidenced successes only. It is not total incident duration, labor time, or time saved. Manual comparison and ROI are not measured.",
        "L’intervalle couvre uniquement les réussites étayées. Il ne représente ni la durée totale d’incident, ni le travail humain, ni le temps gagné. Comparaison manuelle et ROI non mesurés.",
        "L’intervallo copre solo successi documentati. Non rappresenta durata totale dell’incidente, lavoro umano o tempo risparmiato. Confronto manuale e ROI non misurati.",
    ],
    [
        "excluded",
        "Ausgeschlossene Ergebnisse",
        "Excluded outcomes",
        "Résultats exclus",
        "Risultati esclusi",
    ],
    [
        "proof",
        "Zeitbelege (UTC)",
        "Timing evidence (UTC)",
        "Preuves temporelles (UTC)",
        "Prove temporali (UTC)",
    ],
    [
        "export",
        "Ergebnisbericht als JSON kopieren",
        "Copy outcome report as JSON",
        "Copier le rapport en JSON",
        "Copia rapporto in JSON",
    ],
    [
        "unavailable",
        "Ausführungsjournal nicht lesbar; keine Auswertung verfügbar.",
        "Execution journal unreadable; report unavailable.",
        "Journal d’exécution illisible ; rapport indisponible.",
        "Registro di esecuzione illeggibile; rapporto non disponibile.",
    ],
];
fn draw(ui: &mut Ui, locale: Locale, report: &Report) {
    ui.label(t(locale, "scope"));
    ui.label(t(locale, "limits"));
    for (key, c) in [
        ("production", &report.production),
        ("rehearsal", &report.rehearsal),
    ] {
        ui.group(|ui| {
            ui.strong(t(locale, key));
            for (label, value) in [
                ("repaired", c.repaired),
                ("failed", c.failed),
                ("restored", c.restored),
                ("unverified", c.unverified),
            ] {
                ui.label(format!("{}: {}", t(locale, label), value));
            }
            let median = c
                .median_observation_to_health_ms
                .map(|ms| {
                    let number = format!("{:.3}", ms / 1000.0);
                    format!(
                        "{} s",
                        if locale == Locale::EnUs {
                            number
                        } else {
                            number.replace('.', ",")
                        }
                    )
                })
                .unwrap_or_else(|| t(locale, "none").into());
            ui.label(format!("{}: {}", t(locale, "median"), median));
            ui.label(format!(
                "{}: {} / {}",
                t(locale, "samples"),
                c.duration_samples,
                c.repaired
            ));
        });
    }
    ui.label(format!(
        "{}: {}",
        t(locale, "excluded"),
        report.excluded_results
    ));
    ui.collapsing(t(locale, "proof"), |ui| {
        for s in &report.samples {
            ui.label(format!(
                "{} · {} · {}",
                s.run,
                s.target,
                t(
                    locale,
                    if s.rehearsal {
                        "rehearsal"
                    } else {
                        "production"
                    }
                )
            ));
            ui.monospace(format!(
                "{} → {} · {} ms",
                s.observed_at.to_rfc3339(),
                s.healthy_at.to_rfc3339(),
                s.interval_ms
            ));
        }
    });
    if ui.button(t(locale, "export")).clicked() {
        if let Ok(json) = serde_json::to_string_pretty(report) {
            ui.ctx().copy_text(json);
        }
    }
}
impl AivanaApp {
    pub(super) fn repair_impact_ui(&self, ui: &mut Ui, target: &crate::mission::Target) {
        let locale = self.desktop.locale;
        ui.collapsing(t(locale, "title"), |ui| match self.repair_impact(target) {
            Some(report) => draw(ui, locale, &report),
            None => {
                ui.label(t(locale, "unavailable"));
            }
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn impact_view_renders_all_languages_and_empty_metrics() {
        let report = crate::execution::impact::Report {
            selected_profile: Uuid::new_v4(),
            schema: "test",
            as_of: Utc::now(),
            window_days: 90,
            production: Default::default(),
            rehearsal: Default::default(),
            excluded_results: 0,
            samples: vec![],
            labor_savings_measured: false,
            roi_measured: false,
            not_execution_authorization: true,
        };
        for locale in Locale::ALL {
            for row in TEXT {
                assert_ne!(t(locale, row[0]), row[0]);
            }
            for width in [640.0, 1440.0] {
                let ctx = Context::default();
                let result = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            Pos2::ZERO,
                            egui::vec2(width, 1200.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| draw(ui, locale, &report));
                    },
                );
                assert!(!result.shapes.is_empty());
            }
        }
        assert!(report.production.median_observation_to_health_ms.is_none());
    }
}
