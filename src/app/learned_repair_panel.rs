use super::*;
use crate::localization::Locale;
fn text(locale: Locale, key: &str) -> &str {
    let index = match locale {
        Locale::De => 1,
        Locale::EnUs => 2,
        Locale::Fr => 3,
        Locale::It => 4,
    };
    TEXT.iter()
        .find(|r| r[0] == key)
        .map(|r| r[index])
        .unwrap_or(key)
}
const TEXT: &[[&str; 5]] = &[
    [
        "gap_http",
        "Historische Lücke: HTTP-Prüfung fehlt.",
        "Historical gap: HTTP check missing.",
        "Lacune historique : contrôle HTTP absent.",
        "Lacuna storica: controllo HTTP mancante.",
    ],
    [
        "gap_baseline",
        "Historische Lücke: fehlgeschlagene Baseline nicht belegt.",
        "Historical gap: failed baseline not evidenced.",
        "Lacune historique : échec initial non étayé.",
        "Lacuna storica: errore iniziale non documentato.",
    ],
    [
        "gap_transition",
        "Historische Lücke: Zustandswechsel nicht belegt.",
        "Historical gap: state transition not evidenced.",
        "Lacune historique : transition d’état non étayée.",
        "Lacuna storica: transizione di stato non documentata.",
    ],
    [
        "gap_evidence",
        "Historische Lücke: Vorher-/Aktions-/Nachher-Belege unvollständig oder widersprüchlich.",
        "Historical gap: before/action/after evidence incomplete or contradictory.",
        "Lacune historique : preuves avant/action/après incomplètes ou contradictoires.",
        "Lacuna storica: prove prima/azione/dopo incomplete o contraddittorie.",
    ],
    [
        "title",
        "Lernende Reparaturempfehlungen",
        "Learning repair recommendations",
        "Recommandations de réparation fondées sur les résultats",
        "Raccomandazioni di riparazione basate sui risultati",
    ],
    [
        "scope",
        "Letzte 90 Tage, nur dasselbe Produktionsziel. Historische Ergebnisse belegen keine aktuelle Umgebungskompatibilität.",
        "Last 90 days, same production endpoint only. Historical results do not establish current environment compatibility.",
        "90 derniers jours, même cible de production uniquement. Les résultats historiques ne prouvent pas la compatibilité actuelle.",
        "Ultimi 90 giorni, solo lo stesso endpoint di produzione. I risultati storici non provano la compatibilità attuale.",
    ],
    [
        "select",
        "Bitte zuerst ein Zielprofil auswählen.",
        "Select a target profile first.",
        "Sélectionnez d’abord un profil cible.",
        "Selezionare prima un profilo di destinazione.",
    ],
    [
        "empty",
        "Keine gespeicherten Dienstabläufe verfügbar. Es werden keine Erfolgsbelege erzeugt oder erfunden.",
        "No stored service procedures available. No success evidence is generated or invented.",
        "Aucune procédure de service enregistrée. Aucune preuve de réussite n’est créée ni inventée.",
        "Nessuna procedura di servizio salvata. Non vengono generate o inventate prove di successo.",
    ],
    [
        "eligible",
        "Historisch gestützt — neue Prüfung erforderlich",
        "Historically supported — new verification required",
        "Étayée historiquement — nouvelle vérification requise",
        "Supportata dallo storico — nuova verifica necessaria",
    ],
    [
        "blocked",
        "Nicht empfohlen: Erfolg fehlt oder neuerer ungünstiger/ungeklärter Ausgang",
        "Not recommended: missing success or newer adverse/unverified outcome",
        "Non recommandée : réussite absente ou résultat défavorable/non vérifié plus récent",
        "Non raccomandata: successo assente o esito negativo/non verificato più recente",
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
        "Testumgebung — erhöht die Rangfolge nicht",
        "Rehearsal — does not improve rank",
        "Répétition — n’améliore pas le classement",
        "Prova — non migliora la posizione",
    ],
    [
        "success",
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
        "unknown",
        "Ungeklärt",
        "Unverified",
        "Non vérifiés",
        "Non verificati",
    ],
    [
        "excluded",
        "Ausgeschlossene Ergebnisse",
        "Excluded results",
        "Résultats exclus",
        "Risultati esclusi",
    ],
    [
        "score",
        "Rangpunkte (keine Wahrscheinlichkeit)",
        "Ranking points (not probability)",
        "Points de classement (pas une probabilité)",
        "Punti di classifica (non probabilità)",
    ],
    [
        "formula",
        "Je Kategorie höchstens fünf Ergebnisse: +5 je belegter Reparatur, −8 je Fehler/Rücksetzung, −4 je ungeklärtem Ausgang. Neuerer ungünstiger Ausgang sperrt die Empfehlung.",
        "Up to five results per category: +5 per evidenced repair, −8 per failure/restoration, −4 per unverified outcome. A newer adverse outcome blocks recommendation.",
        "Cinq résultats maximum par catégorie : +5 par réparation étayée, −8 par échec/restauration, −4 par résultat non vérifié. Un résultat défavorable plus récent bloque la recommandation.",
        "Al massimo cinque risultati per categoria: +5 per riparazione documentata, −8 per errore/ripristino, −4 per esito non verificato. Un esito negativo più recente blocca la raccomandazione.",
    ],
    [
        "proof",
        "Belegverweise",
        "Evidence references",
        "Références des preuves",
        "Riferimenti delle prove",
    ],
    [
        "prepare",
        "Als neuen Prüfplan vorbereiten",
        "Prepare as a new verification plan",
        "Préparer un nouveau plan de vérification",
        "Prepara un nuovo piano di verifica",
    ],
    ["start", "Start", "Start", "Démarrage", "Avvio"],
    ["restart", "Neustart", "Restart", "Redémarrage", "Riavvio"],
    [
        "export",
        "Empfehlungsbericht kopieren",
        "Copy recommendation report",
        "Copier le rapport de recommandation",
        "Copia rapporto delle raccomandazioni",
    ],
];
impl AivanaApp {
    pub(super) fn learned_repairs_ui(&mut self, ui: &mut Ui) {
        let locale = self.desktop.locale;
        ui.heading(text(locale, "title"));
        ui.label(text(locale, "scope"));
        let Some(profile) = self.selected_profile() else {
            ui.label(text(locale, "select"));
            return;
        };
        let target = crate::mission::Target::from_profile(profile);
        let rows = self.ranked_execution_lessons(&target);
        if rows.is_empty() {
            ui.label(text(locale, "empty"));
            return;
        }
        ui.label(text(locale, "formula"));
        for row in &rows {
            ui.push_id(&row.lesson.key, |ui| {
                ui.group(|ui| {
                    ui.strong(format!(
                        "{} · {}",
                        row.lesson.service,
                        text(
                            locale,
                            if row.lesson.restart {
                                "restart"
                            } else {
                                "start"
                            }
                        )
                    ));
                    ui.label(text(
                        locale,
                        if row.eligible() {
                            "eligible"
                        } else {
                            "blocked"
                        },
                    ));
                    ui.label(format!(
                        "{}: {} · {}: {}",
                        text(locale, "score"),
                        row.score,
                        text(locale, "excluded"),
                        row.excluded
                    ));
                    for gap in &row.gaps {
                        ui.label(text(locale, gap));
                    }
                    for (key, c) in [
                        ("production", &row.lesson.production),
                        ("rehearsal", &row.lesson.rehearsal),
                    ] {
                        ui.label(format!(
                            "{}: {} {} · {} {} · {} {} · {} {}",
                            text(locale, key),
                            c.successes,
                            text(locale, "success"),
                            c.failures,
                            text(locale, "failed"),
                            c.restored,
                            text(locale, "restored"),
                            c.unknown,
                            text(locale, "unknown")
                        ));
                    }
                    ui.collapsing(text(locale, "proof"), |ui| {
                        for e in &row.lesson.evidence {
                            ui.monospace(format!(
                                "{} · {} · {:?}",
                                e.run_id, e.target_profile_id, e.phase
                            ));
                        }
                    });
                    if ui
                        .add_enabled(row.eligible(), egui::Button::new(text(locale, "prepare")))
                        .clicked()
                    {
                        self.use_execution_lesson(&row.lesson);
                        self.view = View::Execution;
                    }
                });
            });
        }
        if ui.button(text(locale, "export")).clicked() {
            let report = serde_json::json!({"schema":"relayne-repair-learning-v1","locale":locale.tag(),"as_of":Utc::now(),"window_days":90,"not_execution_authorization":true,"same_endpoint_only":true,"rows":rows.iter().map(|r|serde_json::json!({"key":r.lesson.key,"service":r.lesson.service,"restart":r.lesson.restart,"eligible":r.eligible(),"score":r.score,"excluded":r.excluded,"production":{"success":r.lesson.production.successes,"failed":r.lesson.production.failures,"restored":r.lesson.production.restored,"unknown":r.lesson.production.unknown},"rehearsal":{"success":r.lesson.rehearsal.successes,"failed":r.lesson.rehearsal.failures,"restored":r.lesson.rehearsal.restored,"unknown":r.lesson.rehearsal.unknown},"evidence":r.lesson.evidence.iter().map(|e|serde_json::json!({"run":e.run_id,"target":e.target_profile_id,"rehearsal":e.rehearsal})).collect::<Vec<_>>()})).collect::<Vec<_>>()});
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                ui.ctx().copy_text(json);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn learning_text_is_complete() {
        let mut keys = std::collections::BTreeSet::new();
        for row in TEXT {
            assert!(keys.insert(row[0]));
            for locale in Locale::ALL {
                assert!(!text(locale, row[0]).is_empty());
                assert_ne!(text(locale, row[0]), row[0]);
            }
        }
    }
}
