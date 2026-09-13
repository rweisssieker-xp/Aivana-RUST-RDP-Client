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
        "radar",
        "Frühwarnradar aus Reparaturverläufen",
        "Repair-history warning radar",
        "Alertes issues de l’historique des réparations",
        "Avvisi dallo storico delle riparazioni",
    ],
    [
        "radar_rules",
        "Nur belegte Produktionserfolge, je identischem Verfahren. Wiederholung: mindestens 3 Läufe an 2 UTC-Tagen in 7 Tagen. Verlangsamung: letzte 3 gegen vorherige 3 Erfolge in 30 Tagen, beide Gruppen an mehreren Tagen; mindestens Faktor 2 und 5 Sekunden mehr.",
        "Evidenced production successes only, per identical procedure. Repetition: at least 3 runs on 2 UTC dates in 7 days. Slowdown: latest 3 versus preceding 3 successes in 30 days, each group across multiple dates; at least 2x and 5 seconds more.",
        "Réussites de production étayées uniquement, par procédure identique. Répétition : au moins 3 exécutions sur 2 dates UTC en 7 jours. Ralentissement : 3 dernières réussites contre 3 précédentes en 30 jours, chaque groupe sur plusieurs dates ; au moins 2 fois plus et 5 secondes supplémentaires.",
        "Solo successi documentati in produzione, per procedura identica. Ripetizione: almeno 3 esecuzioni su 2 date UTC in 7 giorni. Rallentamento: ultimi 3 successi rispetto ai 3 precedenti in 30 giorni, ogni gruppo su più date; almeno 2 volte e 5 secondi in più.",
    ],
    [
        "radar_none",
        "Keine Warnschwelle erreicht. Das ist kein Nachweis eines gesunden Systems; Daten können fehlen.",
        "No warning threshold reached. This does not prove system health; data may be missing.",
        "Aucun seuil d’alerte atteint. Cela ne prouve pas le bon état du système ; des données peuvent manquer.",
        "Nessuna soglia di avviso raggiunta. Non dimostra la salute del sistema; possono mancare dati.",
    ],
    [
        "repeated",
        "Wiederholte belegte Reparaturen — dauerhafte Ursache prüfen",
        "Repeated evidenced repairs — investigate persistent causes",
        "Réparations étayées répétées — rechercher les causes persistantes",
        "Riparazioni documentate ripetute — verificare cause persistenti",
    ],
    [
        "slower",
        "Prüfintervalle deutlich länger — Verfahren und Umgebung prüfen",
        "Verification intervals substantially longer — review procedure and environment",
        "Intervalles de vérification nettement plus longs — revoir procédure et environnement",
        "Intervalli di verifica molto più lunghi — controllare procedura e ambiente",
    ],
    [
        "radar_limit",
        "Rückblickende Heuristik, keine Ausfallprognose oder automatisch ausgeführte Maßnahme. Verschiedene Vorfälle können dieselbe Reparatur benötigen.",
        "Retrospective heuristic, not an outage forecast or automatically executed action. Different incidents may require the same repair.",
        "Heuristique rétrospective, pas une prévision de panne ni une action automatique. Des incidents différents peuvent nécessiter la même réparation.",
        "Euristica retrospettiva, non una previsione di guasto o un’azione automatica. Incidenti diversi possono richiedere la stessa riparazione.",
    ],
    [
        "radar_baseline",
        "Vorheriger Median → aktueller Median (ms)",
        "Previous median → current median (ms)",
        "Médiane précédente → médiane actuelle (ms)",
        "Mediana precedente → mediana attuale (ms)",
    ],
    [
        "radar_runs",
        "Auslösende Laufkennungen",
        "Triggering run identifiers",
        "Identifiants des exécutions déclenchantes",
        "Identificativi delle esecuzioni che attivano l’avviso",
    ],
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
    ui.collapsing(t(locale, "radar"), |ui| {
        ui.label(t(locale, "radar_rules"));
        ui.label(t(locale, "radar_limit"));
        if report.signals.is_empty() {
            ui.label(t(locale, "radar_none"));
        }
        for signal in &report.signals {
            ui.group(|ui| {
                ui.strong(format!(
                    "{} · {}",
                    signal.service,
                    t(
                        locale,
                        match signal.kind {
                            crate::execution::impact::radar::Kind::RepeatedRepairs => "repeated",
                            crate::execution::impact::radar::Kind::SlowerVerification => "slower",
                        }
                    )
                ));
                if let (Some(before), Some(after)) =
                    (signal.baseline_median_ms, signal.recent_median_ms)
                {
                    ui.label(format!(
                        "{}: {:.0} → {:.0}",
                        t(locale, "radar_baseline"),
                        before,
                        after
                    ));
                }
                ui.collapsing(t(locale, "radar_runs"), |ui| {
                    for id in &signal.source_runs {
                        ui.monospace(id.to_string());
                    }
                });
            });
        }
    });
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
            signals: vec![],
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
