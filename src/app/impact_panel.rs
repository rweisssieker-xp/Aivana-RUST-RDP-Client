use super::*;
use crate::execution::impact::triage::{self, Book};
use crate::{execution::impact::Report, localization::Locale};

pub(super) struct ReviewState {
    book: Book,
    blocked: bool,
    drafts: std::collections::HashMap<String, String>,
}
impl Default for ReviewState {
    fn default() -> Self {
        let loaded = app_data_file("relayne-warning-reviews.dpapi").and_then(|p| Book::load(&p));
        let blocked = loaded.is_err();
        Self {
            book: loaded.unwrap_or_default(),
            blocked,
            drafts: Default::default(),
        }
    }
}
impl ReviewState {
    fn save(&mut self, mut next: Book) {
        match app_data_file("relayne-warning-reviews.dpapi").and_then(|p| next.save(&p)) {
            Ok(()) => self.book = next,
            Err(_) => self.blocked = true,
        }
    }
    fn signal(
        &mut self,
        ui: &mut Ui,
        locale: Locale,
        report: &Report,
        signal: &crate::execution::impact::radar::Signal,
    ) {
        let Ok(key) = triage::fingerprint(report, signal) else {
            ui.label(t(locale, "review_error"));
            return;
        };
        ui.push_id(&key, |ui| {
            if let Some(ack) = self.book.current(&key, report.as_of) {
                ui.label(format!(
                    "{} · {}",
                    t(locale, "reviewed"),
                    ack.at.to_rfc3339()
                ));
                ui.label(&ack.note);
                if ui
                    .add_enabled(!self.blocked, egui::Button::new(t(locale, "reopen")))
                    .clicked()
                {
                    let mut next = self.book.clone();
                    next.entries.remove(&key);
                    self.save(next);
                }
            } else {
                let note = self.drafts.entry(key.clone()).or_default();
                ui.add(
                    egui::TextEdit::singleline(note)
                        .hint_text(t(locale, "note"))
                        .char_limit(256),
                );
                if ui
                    .add_enabled(
                        !self.blocked && !note.trim().is_empty(),
                        egui::Button::new(t(locale, "ack")),
                    )
                    .clicked()
                {
                    let mut next = self.book.clone();
                    if next.acknowledge(key.clone(), note, report.as_of).is_ok() {
                        self.save(next);
                    } else {
                        self.blocked = true;
                    }
                }
            }
        });
    }
}
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
        "review_rules",
        "Quittierungen gelten lokal für diese Belege, höchstens 30 Tage. Geänderte Belege öffnen die Warnung wieder. Keine Reparaturfreigabe.",
        "Reviews apply locally to this evidence for at most 30 days. Changed evidence reopens the warning. No repair authorization.",
        "Les validations locales concernent ces preuves pendant 30 jours maximum. Toute modification rouvre l’alerte. Aucune autorisation de réparation.",
        "Le conferme locali valgono per queste prove per massimo 30 giorni. Prove modificate riaprono l’avviso. Nessuna autorizzazione alla riparazione.",
    ],
    [
        "reviewed",
        "Lokal geprüft",
        "Reviewed locally",
        "Vérifié localement",
        "Verificato localmente",
    ],
    [
        "note",
        "Prüfnotiz (erforderlich)",
        "Review note (required)",
        "Note de vérification (obligatoire)",
        "Nota di verifica (obbligatoria)",
    ],
    [
        "ack",
        "Diese Belege quittieren",
        "Acknowledge this evidence",
        "Valider ces preuves",
        "Conferma queste prove",
    ],
    ["reopen", "Wieder öffnen", "Reopen", "Rouvrir", "Riapri"],
    [
        "review_error",
        "Quittierung nicht verfügbar oder Speicherung fehlgeschlagen. Speicher neu laden.",
        "Review unavailable or save failed. Reload the store.",
        "Validation indisponible ou échec d’enregistrement. Rechargez le stockage.",
        "Conferma non disponibile o salvataggio non riuscito. Ricaricare l’archivio.",
    ],
    [
        "reload",
        "Quittierungen neu laden",
        "Reload reviews",
        "Recharger les validations",
        "Ricarica le conferme",
    ],
    [
        "cleanup",
        "Abgelaufene Quittierungen entfernen",
        "Remove expired reviews",
        "Supprimer les validations expirées",
        "Rimuovi le conferme scadute",
    ],
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
fn draw(ui: &mut Ui, locale: Locale, report: &Report, reviews: &mut ReviewState) {
    ui.collapsing(t(locale, "radar"), |ui| {
        ui.label(t(locale, "radar_rules"));
        ui.label(t(locale, "radar_limit"));
        ui.label(t(locale, "review_rules"));
        if reviews.blocked {
            ui.label(t(locale, "review_error"));
        }
        if ui.button(t(locale, "reload")).clicked() {
            *reviews = ReviewState::default();
        }
        if ui
            .add_enabled(!reviews.blocked, egui::Button::new(t(locale, "cleanup")))
            .clicked()
        {
            let mut next = reviews.book.clone();
            next.entries.retain(|_, a| {
                a.at > report.as_of || report.as_of - a.at < chrono::Duration::days(30)
            });
            reviews.save(next);
        }
        if report.signals.is_empty() {
            ui.label(t(locale, "radar_none"));
        }
        for signal in &report.signals {
            ui.group(|ui| {
                reviews.signal(ui, locale, report, signal);
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
    pub(super) fn repair_impact_ui(&mut self, ui: &mut Ui, target: &crate::mission::Target) {
        let locale = self.desktop.locale;
        let report = self.repair_impact(target);
        ui.collapsing(t(locale, "title"), |ui| match report {
            Some(report) => draw(ui, locale, &report, &mut self.warning_reviews),
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
                        let mut reviews = ReviewState {
                            book: Book::default(),
                            blocked: false,
                            drafts: Default::default(),
                        };
                        egui::CentralPanel::default()
                            .show(ctx, |ui| draw(ui, locale, &report, &mut reviews));
                    },
                );
                assert!(!result.shapes.is_empty());
            }
        }
        assert!(report.production.median_observation_to_health_ms.is_none());
    }
}
