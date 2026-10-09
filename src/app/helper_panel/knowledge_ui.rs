use super::{HelperCase, HelperState};
use crate::helper::{
    journal::ActionJournal,
    knowledge::{self, KnowledgeStore, LessonStatus, ReportFormat, ReviewDecision},
    verification::ReceiptStore,
};
use chrono::Utc;
use eframe::egui::{self, Ui};

fn tr(locale: crate::localization::Locale, source: &str) -> String {
    crate::localization::tr(locale, source).to_owned()
}

fn status_source(status: LessonStatus) -> &'static str {
    match status {
        LessonStatus::Candidate => "Kandidat",
        LessonStatus::Verified => "Verifiziert",
        LessonStatus::Rejected => "Abgelehnt",
        LessonStatus::Stale => "Veraltet",
        LessonStatus::Invalidated => "Widerrufen",
    }
}

pub(super) fn show(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    locale: crate::localization::Locale,
) {
    ui.separator();
    ui.heading(tr(locale, "Verifiziertes Betriebswissen"));
    ui.label(tr(locale, "Berücksichtigt werden nur Produktionsbelege aus Relaynes geschütztem Journal und Belegspeicher."));

    let path = match KnowledgeStore::path() {
        Ok(path) => path,
        Err(error) => {
            ui.label(format!(
                "{}: {error}",
                tr(locale, "Wissensspeicher nicht verfügbar")
            ));
            return;
        }
    };
    let mut store = match KnowledgeStore::load(&path) {
        Ok(store) => store,
        Err(error) => {
            ui.label(format!(
                "{}: {error}",
                tr(locale, "Wissensspeicher konnte nicht geprüft werden")
            ));
            return;
        }
    };

    if ui
        .add_enabled(
            case.resolution() == Some(crate::helper::case::CaseResolution::VerifiedRelayneRepair),
            egui::Button::new(tr(locale, "Verifizierte Produktionsbelege qualifizieren")),
        )
        .clicked()
    {
        let result = (|| -> anyhow::Result<usize> {
            let journal = ActionJournal::load(&ActionJournal::path()?)?;
            let receipts = ReceiptStore::load_checked(&ReceiptStore::path()?, &journal)?;
            let candidates = knowledge::generic_candidates(case, &journal, &receipts, Utc::now())?;
            let mut added = 0;
            for candidate in candidates {
                let duplicate = store.lessons().iter().any(|lesson| {
                    lesson.fingerprint == candidate.fingerprint
                        && lesson.evidence == candidate.evidence
                        && matches!(
                            lesson.status,
                            LessonStatus::Candidate | LessonStatus::Verified
                        )
                });
                if !duplicate {
                    store.insert(candidate, &path)?;
                    added += 1;
                }
            }
            Ok(added)
        })();
        state.notice = match result {
            Ok(0) => tr(locale, "Kein neuer Lernkandidat qualifiziert; passende Belege sind möglicherweise bereits gespeichert."),
            Ok(count) => format!("{count} {}", tr(locale, "beleggebundene Lernkandidaten gespeichert")),
            Err(error) => format!("{}: {error}", tr(locale, "Qualifizierung nicht verfügbar")),
        };
        if let Ok(updated) = KnowledgeStore::load(&path) {
            store = updated;
        }
    }

    ui.label(&state.notice);
    let lessons = store
        .lessons()
        .iter()
        .filter(|lesson| lesson.case_id == case.id())
        .cloned()
        .collect::<Vec<_>>();
    let current_snapshot = (|| -> anyhow::Result<_> {
        let journal = ActionJournal::load(&ActionJournal::path()?)?;
        let receipts = ReceiptStore::load_checked(&ReceiptStore::path()?, &journal)?;
        knowledge::generic_evidence_snapshot(case, &journal, &receipts, Utc::now())
    })();
    if let Ok(snapshot) = &current_snapshot {
        let matches = store.recommend(snapshot, Utc::now());
        ui.label(format!(
            "{}: {}",
            tr(locale, "Aktuell passende Empfehlungen"),
            matches.len()
        ));
    }

    if lessons.is_empty() {
        ui.label(tr(
            locale,
            "Für diesen Fall sind keine Lernkandidaten gespeichert.",
        ));
    }
    for lesson in lessons {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong(tr(locale, status_source(lesson.status)));
                ui.label(format!("{} {} · {} {}", tr(locale, "Revision"), lesson.revision, lesson.evidence.len(), tr(locale, "Belegreferenzen")));
            });
            ui.label(format!("{}: {}", tr(locale, "Fingerabdruck"), lesson.fingerprint));
            ui.label(format!("{} {}", tr(locale, "Gültig bis"), lesson.valid_until.to_rfc3339()));
            if let Ok(snapshot) = &current_snapshot {
                if store.recommend(snapshot, Utc::now()).iter().any(|item| item.lesson_id == lesson.id) {
                    ui.label(tr(locale, "Die aktuelle Produktionsbeleglage passt zu dieser freigegebenen Lernregel."));
                }
            }
            ui.horizontal(|ui| {
                if lesson.status == LessonStatus::Candidate {
                    if ui.button(tr(locale, "Lernregel freigeben")).clicked() {
                        state.notice = match store.review(lesson.id, lesson.revision, ReviewDecision::Approve, Utc::now(), &path) {
                            Ok(()) => tr(locale, "Lernregel freigegeben und gespeichert."),
                            Err(error) => format!("{}: {error}", tr(locale, "Prüfung wurde nicht gespeichert")),
                        };
                    }
                    if ui.button(tr(locale, "Lernregel ablehnen")).clicked() {
                        state.notice = match store.review(lesson.id, lesson.revision, ReviewDecision::Reject, Utc::now(), &path) {
                            Ok(()) => tr(locale, "Lernregel abgelehnt und gespeichert."),
                            Err(error) => format!("{}: {error}", tr(locale, "Prüfung wurde nicht gespeichert")),
                        };
                    }
                } else if lesson.status == LessonStatus::Verified {
                    if ui.button(tr(locale, "Mit aktuellen Belegen erneut prüfen")).clicked() {
                        state.notice = match &current_snapshot {
                            Ok(snapshot) => match store.revalidate(
                                lesson.id, lesson.revision, snapshot.fingerprint(), snapshot.trust(),
                                Utc::now(), &path,
                            ) {
                                Ok(()) => tr(locale, "Lernregel mit aktuellen Produktionsbelegen erneut geprüft."),
                                Err(error) => format!("{}: {error}", tr(locale, "Erneute Prüfung wurde nicht gespeichert")),
                            },
                            Err(error) => format!("{}: {error}", tr(locale, "Aktuelle Belege können nicht geprüft werden")),
                        };
                    }
                    if ui.button(tr(locale, "Als Regression endgültig invalidieren")).on_hover_text(format!(
                        "{:?}: {} ({})",
                        lesson.trust.reference.kind,
                        lesson.trust.reference.id,
                        lesson.trust.reference.digest
                    )).clicked() {
                        state.notice = match store.invalidate(
                            lesson.id,
                            lesson.revision,
                            knowledge::InvalidationReason::OperatorReportedRegression,
                            &lesson.trust.reference,
                            Utc::now(),
                            &path,
                        ) {
                            Ok(()) => tr(locale, "Lernregel als Regression endgültig invalidiert."),
                            Err(error) => format!("{}: {error}", tr(locale, "Invalidierung nicht gespeichert")),
                        };
                    }
                }
            });
        });
    }

    ui.horizontal(|ui| {
        for (format, source) in [
            (
                ReportFormat::Json,
                "JSON-Bericht zum Betriebswissen kopieren",
            ),
            (
                ReportFormat::Markdown,
                "Markdown-Bericht zum Betriebswissen kopieren",
            ),
        ] {
            let label = tr(locale, source);
            if ui.button(label).clicked() {
                match knowledge::export_report_format(case, &store.lessons(), Utc::now(), format) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(text) => {
                            ui.ctx().copy_text(text);
                            state.notice = tr(locale, "Verifizierter Wissensbericht kopiert.");
                        }
                        Err(error) => state.notice = format!("Report encoding failed: {error}"),
                    },
                    Err(error) => {
                        state.notice =
                            format!("{}: {error}", tr(locale, "Berichtsexport nicht verfügbar"))
                    }
                }
            }
        }
    });
}
