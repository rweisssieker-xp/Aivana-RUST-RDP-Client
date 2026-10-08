//! Read-only catalog and proposal review; there is intentionally no dispatch control.
use super::*;
use crate::helper::catalog::{Applicability, Catalog, CatalogEntry, CatalogTrust, ProposalParams};

fn publisher_enrollment(
    state: &mut HelperState,
    ui: &mut Ui,
    trust: &mut CatalogTrust,
    path: &std::path::Path,
) {
    ui.collapsing("Enroll a reviewed SQL recipe publisher", |ui| {
        ui.label("Paste the publisher's Ed25519 public key from a separately verified source.");
        if ui
            .text_edit_singleline(&mut state.recipe_key_input)
            .changed()
        {
            state.recipe_key_reviewed = false;
        }
        let mut candidate = CatalogTrust::default();
        match candidate.enroll(state.recipe_key_input.trim()) {
            Ok(fingerprint) => {
                ui.label(format!("Public-key SHA-256: {fingerprint}"));
                ui.checkbox(
                    &mut state.recipe_key_reviewed,
                    "I verified this key and fingerprint independently",
                );
                if ui
                    .add_enabled(
                        state.recipe_key_reviewed,
                        egui::Button::new("Enroll publisher key"),
                    )
                    .clicked()
                {
                    let mut updated = trust.clone();
                    let result = updated
                        .enroll(state.recipe_key_input.trim())
                        .and_then(|_| updated.save_protected(path));
                    state.notice = match result {
                        Ok(()) => {
                            *trust = updated;
                            state.recipe_key_reviewed = false;
                            "SQL recipe publisher enrolled securely".into()
                        }
                        Err(e) => format!("Publisher enrollment failed: {e}"),
                    };
                }
            }
            Err(_) => {
                ui.label("Enter a valid 32-byte Ed25519 public key in base64.");
            }
        }
    });
}

fn recipe_import(
    state: &mut HelperState,
    ui: &mut Ui,
    catalog: &mut Catalog,
    path: &std::path::Path,
) {
    ui.collapsing("Import a signed SQL recipe", |ui| {
        ui.label("Paste one signed recipe JSON. Its publisher must already be enrolled.");
        if ui
            .add(egui::TextEdit::multiline(&mut state.recipe_entry_input).desired_rows(4))
            .changed()
        {
            state.recipe_entry_reviewed = false;
        }
        if state.recipe_entry_input.len() > 64 * 1024 {
            ui.label("Recipe exceeds the 64 KiB import limit.");
            return;
        }
        let Ok(entry) = serde_json::from_str::<CatalogEntry>(&state.recipe_entry_input) else {
            ui.label("Paste a valid signed recipe to preview it.");
            return;
        };
        if let Err(e) = entry.verify(&catalog.trust) {
            ui.label(format!("Recipe trust gap: {e}"));
            return;
        }
        ui.label(format!(
            "{} · revision {} · {}",
            entry.body.problem_family, entry.body.revision, entry.provenance
        ));
        ui.label(format!("Publisher: {}", entry.publisher_key));
        if let Ok(identity) = entry.identity() {
            ui.label(format!("Signed recipe identity: {identity}"));
        }
        if let crate::helper::catalog::CatalogAction::Sql { action, .. } = &entry.body.action {
            ui.label(action.operation_preview());
        }
        ui.label(format!("Restoration: {:?}", entry.body.restoration));
        ui.checkbox(
            &mut state.recipe_entry_reviewed,
            "I reviewed the signed action, scope, checks and restoration limits",
        );
        if ui
            .add_enabled(
                state.recipe_entry_reviewed,
                egui::Button::new("Import reviewed recipe"),
            )
            .clicked()
        {
            let mut updated = catalog.clone();
            let result = updated
                .import_signed(entry)
                .and_then(|_| updated.save_protected(path));
            state.notice = match result {
                Ok(()) => {
                    *catalog = updated;
                    state.recipe_entry_reviewed = false;
                    "Signed SQL recipe imported securely".into()
                }
                Err(e) => format!("Recipe import failed: {e}"),
            };
        }
    });
}

pub(super) fn show(state: &mut HelperState, ui: &mut Ui, case: &HelperCase) {
    if state.statistics_ack_case != Some((case.id(), case.revision())) {
        state.statistics_limit_acknowledged = false;
        state.statistics_ack_case = None;
    }
    ui.separator();
    ui.heading("Controlled change · recipe review");
    ui.label("Catalog review prepares a proposal. Applying a change needs a separate approved authority path.");
    egui::CollapsingHeader::new("Trusted recipes and prerequisites")
        .id_salt("helper-recipe-review").show(ui, |ui| {
            let Ok(trust_path) = crate::security::app_data_file("helper-recipe-trust.dpapi") else {
                ui.label("Recipe trust storage is unavailable.");
                return;
            };
            let Ok(mut trust) = CatalogTrust::load_protected(&trust_path) else {
                ui.label("Recipe trust storage is invalid; restore or repair it before review.");
                return;
            };
            publisher_enrollment(state, ui, &mut trust, &trust_path);
            let Ok(path) = crate::security::app_data_file("helper-recipes.dpapi") else {
                ui.label("Recipe catalog storage is unavailable.");
                return;
            };
            let Ok(mut catalog) = Catalog::load_protected(&path, trust) else {
                ui.label("Signed catalog is invalid or has an unenrolled publisher. Review its publisher enrollment or restore the protected catalog.");
                return;
            };
            recipe_import(state, ui, &mut catalog, &path);
            if catalog.entries.is_empty() {
                ui.label("No signed SQL recipes imported. Enroll a reviewed publisher, then import its signed recipe above.");
            }
            for entry in &catalog.entries {
                ui.group(|ui| {
                    ui.label(format!("{} · revision {} · {}", entry.body.problem_family,
                        entry.body.revision, entry.provenance));
                    match &entry.body.action {
                        crate::helper::catalog::CatalogAction::Sql { action, .. } => {
                            ui.label(action.operation_preview());
                            ui.label("Statement deadline: 30 s; lock wait limit: 5 s. These limits are executor requirements; review does not execute them.");
                            if action.is_statistics() {
                                ui.label("Write cost: planner statistics. Locking and scan load depend on table size. Storage delta is unknown until live measurement.");
                            } else {
                                ui.label("Write cost: index build plus ongoing index maintenance. Retained storage and lock impact are unknown until live measurement; concurrent/online creation is excluded.");
                            }
                            if action.is_statistics() {
                                ui.label("Statistics maintenance changes planner data. Exact prior statistics cannot be restored.");
                            } else {
                                ui.label("Index restoration requires exact run ownership, current definition, and a verified drop precondition.");
                            }
                        }
                        crate::helper::catalog::CatalogAction::ExistingServiceRecipe { .. } => {
                            ui.label("Existing signed service package and v1 contract govern execution.");
                        }
                    }
                    ui.label("Prerequisites:");
                    for prerequisite in &entry.body.prerequisites { ui.label(format!("• {prerequisite:?}")); }
                    ui.label("Required checks:");
                    for check in &entry.body.verification.checks { ui.label(format!("• {check:?}")); }
                    match catalog.applicability(case, entry, case.evidence(), chrono::Utc::now()) {
                        Applicability::Gaps(gaps) => {
                            for gap in gaps { ui.label(format!("Gap: {gap}")); }
                        }
                        Applicability::Candidate(unverified) => {
                            ui.label("Candidate only; launch prerequisites still unverified:");
                            for prerequisite in &unverified {
                                ui.label(format!("• {prerequisite:?}"));
                            }
                            if matches!(&entry.body.action, crate::helper::catalog::CatalogAction::Sql { action, .. } if action.is_statistics()) {
                                if ui.checkbox(&mut state.statistics_limit_acknowledged,
                                    "I acknowledge exact restoration of prior statistics is unavailable").changed() {
                                    state.statistics_ack_case = state.statistics_limit_acknowledged
                                        .then_some((case.id(), case.revision()));
                                }
                            }
                            if ui.button("Prepare proposal for review").clicked() {
                                let mut evidence_ids = Vec::new();
                                if let crate::helper::catalog::CatalogAction::Sql { metadata, .. } = &entry.body.action {
                                    if let Some(source) = case.evidence().iter().find(|e|
                                        e.content_sha256 == metadata.source_evidence_sha256) {
                                        evidence_ids.push(source.id);
                                    }
                                }
                                for evidence in case.evidence().iter().rev() {
                                    if evidence_ids.len() == 16 { break; }
                                    if !evidence_ids.contains(&evidence.id) { evidence_ids.push(evidence.id); }
                                }
                                let plan = case.plan().and_then(|p|
                                    crate::helper_action::digest(b"relayne-helper-reviewed-plan-v1", p).ok());
                                let result = plan.ok_or_else(|| anyhow::anyhow!("Reviewed current plan missing"))
                                    .and_then(|plan_sha256| catalog.propose(case, entry,
                                        ProposalParams { plan_sha256,
                                            evidence_ids,
                                            statistics_limit_acknowledged: state.statistics_limit_acknowledged },
                                        ));
                                match result {
                                    Ok(proposal) => { state.reviewed_proposal = Some(proposal);
                                        state.notice = "Proposal prepared for local review only".into(); }
                                    Err(e) => state.notice = format!("Proposal unavailable: {e}"),
                                }
                            }
                        }
                    }
                });
            }
            let review_is_current = state.reviewed_proposal.as_ref().is_some_and(|proposal| {
                catalog.entry(proposal.recipe_id).is_some_and(|entry|
                    entry.identity().ok().as_deref() == Some(proposal.recipe_identity.as_str())
                        && matches!(catalog.applicability(case, entry, case.evidence(), chrono::Utc::now()),
                            Applicability::Candidate(_)))
            });
            if !review_is_current { state.reviewed_proposal = None; }
            if let Some(proposal) = &state.reviewed_proposal {
                if proposal.case_id == case.id() && proposal.case_revision == case.revision() {
                    if let Ok(digest) = proposal.review_digest() {
                        ui.label(format!("Local review digest: {digest}"));
                        ui.label("Review has no remote effect or approval request.");
                    }
                }
            }
        });
}
