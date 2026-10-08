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
        match &entry.body.action {
            crate::helper::catalog::CatalogAction::Sql { action, metadata } => {
                ui.label(format!("Action: {}", action.operation_preview()));
                ui.label(format!(
                    "Exact credential-bound change scope SHA-256: {}",
                    metadata.object.scope_sha256
                ));
                ui.label(format!(
                    "Source metadata: {:?} · {}.{}.{} · native object ID {} · base table {}",
                    metadata.object.engine,
                    metadata.object.database,
                    metadata.object.schema,
                    metadata.object.table,
                    metadata.object.object_id,
                    metadata.base_table
                ));
                ui.label(format!(
                    "Source evidence SHA-256: {}",
                    metadata.source_evidence_sha256
                ));
                for column in &metadata.columns {
                    ui.label(format!(
                        "Source column: {} · ID {} · plain {}",
                        column.name, column.column_id, column.plain
                    ));
                }
                for index in &metadata.existing_indexes {
                    ui.label(format!("Existing index: {index}"));
                }
            }
            crate::helper::catalog::CatalogAction::ExistingServiceRecipe {
                catalog_entry_id,
                signed_package_sha256,
            } => {
                ui.label(format!(
                    "Existing service recipe reference: {catalog_entry_id}"
                ));
                ui.label(format!(
                    "Signed service package SHA-256: {signed_package_sha256}"
                ));
            }
        }
        ui.label(format!(
            "Validity: {} to {}",
            entry.body.issued_at, entry.body.expires_at
        ));
        ui.label("Signed prerequisites:");
        for prerequisite in &entry.body.prerequisites {
            ui.label(format!("• {prerequisite:?}"));
        }
        ui.label("Signed required checks and exact reviewed criterion selectors:");
        for (check, criterion) in entry
            .body
            .verification
            .checks
            .iter()
            .zip(&entry.body.verification.criteria)
        {
            ui.label(format!("• {check:?} → {criterion:?}"));
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

pub(super) fn show(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    team: &super::super::team_panel::TeamState,
) {
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
    action_authority(state, ui, case, team);
}

fn action_authority(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    team: &super::super::team_panel::TeamState,
) {
    use crate::helper_approval::{
        ActionApprovalStateV2, ConsumeActionApprovalV2, CreateActionApprovalV2,
    };
    ui.separator();
    ui.heading("Generic SQL action authority · v2");
    ui.small("A proposal remains a candidate until current privileges, a reviewed isolated rehearsal, and the final local gate are proven. This screen does not run SQL.");
    let Ok((client, generation, endpoint)) = team.repair_client() else {
        ui.label("Connect as a team operator to request action consent.");
        return;
    };
    if state.action_ui.identity_generation != Some(generation)
        || state.action_ui.reviewed_endpoint.as_deref() != Some(endpoint.as_str())
    {
        state.action_ui = super::ActionUiState::default();
        state.action_ui.identity_generation = Some(generation);
        state.action_ui.reviewed_endpoint = Some(endpoint.clone());
    }
    ui.label(format!("Reviewed team endpoint: {endpoint}"));
    if ui
        .add_enabled(
            state.action_ui.pending.is_none(),
            egui::Button::new("Check team organization identity"),
        )
        .clicked()
    {
        let (tx, rx) = std::sync::mpsc::channel();
        state.action_ui.pending = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(client.helper_capabilities().and_then(|caps| {
                anyhow::ensure!(
                    caps.authority_version == 2,
                    "Unsupported team authority version"
                );
                Ok(super::ActionUiEvent::Identity(caps.organization_sha256))
            }));
        });
    }
    if let Some(org) = &state.action_ui.organization {
        ui.monospace(format!("Organization identity SHA-256: {org}"));
        ui.checkbox(
            &mut state.action_ui.organization_confirmed,
            "I verified this team endpoint and organization identity",
        );
    }
    if let Some(proposal) = state.reviewed_proposal.clone() {
        if proposal.case_id == case.id() && proposal.case_revision == case.revision() {
            ui.label(format!(
                "Reviewed proposal: {}",
                proposal.review_digest().unwrap_or_default()
            ));
            if ui
                .add_enabled(
                    state.action_ui.pending.is_none() && state.action_ui.organization_confirmed,
                    egui::Button::new("Request staged action consent"),
                )
                .clicked()
            {
                let result = (|| -> anyhow::Result<_> {
                    let org = state
                        .action_ui
                        .organization
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("Team organization missing"))?;
                    let binding = crate::helper::approval::staged_request_binding(
                        case,
                        &proposal,
                        org.clone(),
                    )?;
                    let case_path = state
                        .path
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Case store path missing"))?;
                    let journal_path = crate::helper::journal::ActionJournal::path()?;
                    crate::helper::approval::record_local_review(
                        case_path,
                        &journal_path,
                        case,
                        &proposal,
                    )?;
                    Ok((
                        CreateActionApprovalV2 {
                            request_id: Uuid::new_v4(),
                            binding,
                        },
                        org,
                    ))
                })();
                match result {
                    Ok((input, org)) => {
                        let (tx, rx) = std::sync::mpsc::channel();
                        state.action_ui.pending = Some(rx);
                        let client = team.repair_client().map(|v| v.0);
                        std::thread::spawn(move || {
                            let result = client.and_then(|client| {
                                let caps = client.helper_capabilities()?;
                                anyhow::ensure!(
                                    caps.organization_sha256 == org && caps.authority_version == 2,
                                    "Team organization identity changed"
                                );
                                client
                                    .request_action_v2(&input)
                                    .map(super::ActionUiEvent::Requested)
                            });
                            let _ = tx.send(result);
                        });
                    }
                    Err(error) => state.notice = format!("Action request unavailable: {error}"),
                }
            }
            if ui.button("Withdraw local action review").clicked() {
                state.notice = match (
                    state.path.as_ref(),
                    crate::helper::journal::ActionJournal::path(),
                ) {
                    (Some(path), Ok(journal)) => {
                        match crate::helper::approval::withdraw_local_review(
                            path,
                            &journal,
                            case.id(),
                        ) {
                            Ok(()) => {
                                "Local review withdrawn; any consumed approval cannot dispatch"
                                    .into()
                            }
                            Err(e) => format!("Review withdrawal blocked authority: {e}"),
                        }
                    }
                    _ => "Review withdrawal blocked authority: storage unavailable".into(),
                };
            }
        }
    }
    if let Some(item) = state.action_ui.approval.clone() {
        ui.label(format!(
            "Team action approval: {:?} · expires {}",
            item.state, item.expires_at
        ));
        ui.monospace(format!("Exact action fingerprint: {}", item.fingerprint));
        if ui
            .add_enabled(
                state.action_ui.pending.is_none(),
                egui::Button::new("Refresh action status"),
            )
            .clicked()
        {
            let (tx, rx) = std::sync::mpsc::channel();
            state.action_ui.pending = Some(rx);
            let id = item.id;
            let client = team.repair_client().map(|v| v.0);
            std::thread::spawn(move || {
                let _ = tx.send(
                    client.and_then(|c| c.action_v2(id).map(super::ActionUiEvent::Refreshed)),
                );
            });
        }
        if item.state == ActionApprovalStateV2::Approved
            && state.action_ui.receipt.is_none()
            && !state.action_ui.consume_attempted
            && item.expires_at > chrono::Utc::now()
        {
            if ui
                .add_enabled(
                    state.action_ui.pending.is_none(),
                    egui::Button::new("Consume approved action for final local check"),
                )
                .clicked()
            {
                state.action_ui.consume_attempted = true;
                let (tx, rx) = std::sync::mpsc::channel();
                state.action_ui.pending = Some(rx);
                let client = team.repair_client().map(|v| v.0);
                let to_consume = item.clone();
                std::thread::spawn(move || {
                    let _ = tx.send(client.and_then(|c| {
                        c.consume_action_v2(
                            to_consume.id,
                            &ConsumeActionApprovalV2 {
                                binding: to_consume.binding,
                            },
                        )
                        .map(super::ActionUiEvent::Consumed)
                    }));
                });
            }
        }
        if state.action_ui.consume_attempted && state.action_ui.receipt.is_none() {
            ui.strong("Consumption may have reached the team server. Refresh status and reconcile with an operator; no automatic retry or SQL dispatch.");
        }
        if let Some(receipt) = state.action_ui.receipt.clone() {
            ui.label(format!(
                "Consumed once: {}. A durable local intent is required before any target contact.",
                receipt.receipt().consume_id
            ));
            ui.strong("Native SQL verification is pending. This consumed approval cannot launch a change from stored evidence.");
        }
    }
    if let Some(id) = state.action_ui.intent {
        ui.label(format!(
            "Durable prepared intent {id}; awaiting executor and explicit reconciliation."
        ));
    }
    if state.action_ui.pending.is_some() {
        ui.spinner();
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));
    }
    if ui
        .button("Find consumed team approvals for this case")
        .clicked()
    {
        let result = (|| -> anyhow::Result<_> {
            let client = team.repair_client()?.0;
            let mut found = Vec::new();
            for page in 0..50 {
                let rows = client.list_actions_v2(page * 20)?;
                let done = rows.len() < 20;
                found.extend(rows.into_iter().filter(|a| {
                    a.binding.case_id == case.id() && a.state == ActionApprovalStateV2::Consumed
                }));
                if done {
                    break;
                }
            }
            Ok(found)
        })();
        match result {
            Ok(found) => state.action_ui.recovered = found,
            Err(error) => state.notice = format!("Could not load consumed approvals: {error}"),
        }
    }
    for approval in &state.action_ui.recovered {
        ui.label(format!(
            "Consumed approval {} · run {} · fingerprint {}",
            approval.id, approval.binding.run_id, approval.fingerprint
        ));
    }
    if !state.action_ui.recovered.is_empty() {
        ui.strong("Reconcile the recorded run with an operator. Consumption cannot be retried automatically.");
    }
    if let Ok(path) = crate::helper::journal::ActionJournal::path() {
        if let Ok(mut journal) = crate::helper::journal::ActionJournal::load(&path) {
            let runs = journal
                .intents()
                .iter()
                .filter(|i| i.case_id == case.id())
                .cloned()
                .collect::<Vec<_>>();
            for intent in runs {
                ui.label(format!(
                    "Run {} · {:?} · outcome reported {}",
                    intent.run_id, intent.state, intent.outcome_acknowledged
                ));
                let next = if intent.state == crate::helper::journal::IntentState::DispatchStarted
                    && ui
                        .button(format!("Mark run {} outcome unknown", intent.run_id))
                        .clicked()
                {
                    Some((
                        crate::helper::journal::IntentState::OutcomeUnknown,
                        crate::helper_approval::ActionOutcomeV2::OutcomeUnknown,
                    ))
                } else if matches!(
                    intent.state,
                    crate::helper::journal::IntentState::DispatchStarted
                        | crate::helper::journal::IntentState::OutcomeUnknown
                        | crate::helper::journal::IntentState::NeedsIntervention
                ) {
                    ui.checkbox(
                        &mut state.action_ui.outcome_observed,
                        "I independently checked this run's outcome against the target",
                    );
                    if state.action_ui.outcome_observed
                        && ui
                            .button(format!("Record verified success for {}", intent.run_id))
                            .clicked()
                    {
                        Some((
                            crate::helper::journal::IntentState::Verified,
                            crate::helper_approval::ActionOutcomeV2::Verified,
                        ))
                    } else if state.action_ui.outcome_observed
                        && ui
                            .button(format!("Record verified failure for {}", intent.run_id))
                            .clicked()
                    {
                        Some((
                            crate::helper::journal::IntentState::Failed,
                            crate::helper_approval::ActionOutcomeV2::Failed,
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some((observed, outcome)) = next {
                    let result = journal
                        .reconcile(intent.run_id, Some(observed))
                        .and_then(|_| journal.queue_outcome(intent.id, outcome));
                    state.action_ui.outcome_observed = false;
                    state.notice = match result {
                        Ok(event) => format!(
                            "Outcome event {} saved for explicit delivery",
                            event.event_id
                        ),
                        Err(error) => format!("Outcome reconciliation failed: {error}"),
                    };
                }
                if matches!(
                    intent.state,
                    crate::helper::journal::IntentState::OutcomeUnknown
                        | crate::helper::journal::IntentState::NeedsIntervention
                ) {
                    ui.strong("Requires human reconciliation; do not replay the action.");
                }
            }
            let pending = journal
                .pending_outcomes()
                .filter(|event| {
                    journal
                        .intents()
                        .iter()
                        .any(|intent| intent.case_id == case.id() && intent.run_id == event.run_id)
                })
                .cloned()
                .collect::<Vec<_>>();
            for event in pending {
                if ui
                    .button(format!(
                        "Send saved outcome event {} (sequence {})",
                        event.event_id, event.sequence
                    ))
                    .clicked()
                {
                    let result = team
                        .repair_client()
                        .map(|v| v.0)
                        .and_then(|client| client.report_action_outcome_v2(&event))
                        .and_then(|ack| journal.acknowledge_outcome(&ack));
                    state.notice = match result {
                        Ok(()) => format!("Team acknowledged outcome event {}", event.event_id),
                        Err(error) => format!(
                            "Outcome delivery/ack save failed; retry the same event: {error}"
                        ),
                    };
                }
            }
        }
    }
}
