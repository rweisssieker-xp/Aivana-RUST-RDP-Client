//! Evidence inspection and local, bounded report export. No collection starts here.
use super::*;
use crate::helper::{
    evidence::{Eligibility, Origin},
    export::{ExportFormat, export_case},
    manifest::CapabilityManifest,
};
use chrono::{Duration, Utc};

pub(super) fn show(ui: &mut Ui, case: &HelperCase, store: &HelperStore) {
    ui.separator();
    ui.heading("Evidence");
    ui.label(format!(
        "{} observations · evidence revision {} · context revision {}",
        case.evidence().len(),
        case.evidence_revision(),
        case.revision()
    ));
    let now = Utc::now();
    for item in case.evidence().iter().rev().take(30) {
        let eligibility = if item.binding.case_revision != case.revision() {
            Eligibility::Stale
        } else {
            item.eligibility(now, Duration::minutes(5))
        };
        ui.collapsing(
            format!(
                "{:?} · {:?} · {:?} · {}",
                item.capability_id,
                item.origin,
                eligibility,
                item.source_observed_at.format("%Y-%m-%d %H:%M:%S UTC")
            ),
            |ui| {
                ui.label(format!("Source SHA-256: {}", item.source_id));
                ui.label(format!(
                    "Observed: {} · retrieved: {}",
                    item.source_observed_at, item.retrieved_at
                ));
                ui.label(format!(
                    "Status: {:?} · coverage: {}/{} · truncated: {}",
                    item.status,
                    item.coverage.observed,
                    item.coverage.expected,
                    item.coverage.truncated
                ));
                ui.label(format!(
                    "Origin: {:?} · eligibility: {:?}",
                    item.origin, eligibility
                ));
                ui.label(format!(
                    "Metadata retention: {:?}",
                    case.evidence_retention(item.id, now)
                ));
                for metric in &item.metrics {
                    let value = metric
                        .value
                        .map(|v| format!("{v:.2} {:?}", metric.unit))
                        .unwrap_or_else(|| format!("unknown ({:?})", metric.missing_reason));
                    ui.label(format!(
                        "{:?}: {value} · sample {} to {}",
                        metric.kind,
                        metric.sample_window.started_at.format("%H:%M:%S%.3f"),
                        metric.sample_window.ended_at.format("%H:%M:%S%.3f")
                    ));
                }
                for record in &item.records {
                    ui.label(format!(
                        "{:?}: {:?} · {:?}",
                        record.kind, record.observation, record.detail
                    ));
                }
                if item.origin != Origin::Live {
                    ui.label("Unverified import/fixture; cannot establish live proof.");
                }
                if eligibility != Eligibility::Eligible {
                    ui.label("Gap: fresh, complete, trusted live evidence is required.");
                }
            },
        );
    }
    if case.evidence().len() > 30 {
        ui.label(format!(
            "Showing newest 30 of {}; export covers the bounded history.",
            case.evidence().len()
        ));
    }
    ui.collapsing(
        "Declared checks (availability requires a registered adapter)",
        |ui| {
            for declaration in CapabilityManifest::built_in().declarations {
                ui.label(format!(
                    "{:?}: {:?} · declared only; prerequisites {:?}",
                    declaration.id, declaration.role, declaration.prerequisites
                ));
            }
        },
    );
    ui.horizontal(|ui| {
        for (format, label) in [
            (ExportFormat::Json, "Copy JSON report"),
            (ExportFormat::Markdown, "Copy Markdown report"),
        ] {
            if ui.button(label).clicked() {
                match export_case(store, case.id(), format, now) {
                    Ok(report) => ui.ctx().copy_text(report.body),
                    Err(error) => {
                        ui.label(format!("Export unavailable: {error}"));
                    }
                }
            }
        }
    });
}
