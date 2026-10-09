//! Read-only catalog and proposal review; there is intentionally no dispatch control.
use super::*;
use crate::helper::catalog::{Applicability, Catalog, CatalogEntry, CatalogTrust, ProposalParams};
use crate::helper_approval::{
    ActionApprovalStateV2, ConsumeActionApprovalV2, CreateActionApprovalV2,
};

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
    let connection = team.repair_client();
    if let Ok((_, generation, endpoint)) = &connection {
        if state.action_ui.identity_generation != Some(*generation)
            || state.action_ui.reviewed_endpoint.as_deref() != Some(endpoint.as_str())
        {
            state.action_ui = super::ActionUiState::default();
            state.action_ui.identity_generation = Some(*generation);
            state.action_ui.reviewed_endpoint = Some(endpoint.clone());
        }
    }
    show_local_journal(state, ui, case, team);
    let Ok((client, _generation, endpoint)) = connection else {
        ui.label("Connect as a team operator to request action consent.");
        return;
    };
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
            ui.label("Isolated rehearsal change target");
            egui::ComboBox::from_id_salt("helper-staging-change-scope")
                .selected_text(if state.action_ui.staging_scope_sha256.is_empty() {
                    "Select reviewed staging scope"
                } else {
                    "Staging scope selected"
                })
                .show_ui(ui, |ui| {
                    for bound in case.scopes() {
                        if bound.credential().is_some_and(|c| {
                            c.purpose == crate::helper::scope::CredentialPurpose::ControlledChange
                        }) {
                            if let Ok(sha) = bound.digest() {
                                if let crate::helper::scope::BoundScope::Database {
                                    target,
                                    port,
                                    database,
                                    ..
                                } = bound
                                {
                                    ui.selectable_value(
                                        &mut state.action_ui.staging_scope_sha256,
                                        sha,
                                        format!("{}:{} / {}", target.host, port, database),
                                    );
                                }
                            }
                        }
                    }
                });
            ui.label("Reviewed synthetic-data coverage and disposal/rebuild limits");
            ui.text_edit_singleline(&mut state.action_ui.staging_limits);
            ui.checkbox(
                &mut state.action_ui.staging_confirmed,
                "I reviewed the isolated target, data coverage and non-restorable limits",
            );
            if ui
                .add_enabled(
                    state.action_ui.pending.is_none()
                        && state.action_ui.organization_confirmed
                        && state.action_ui.staging_confirmed
                        && !state.action_ui.staging_scope_sha256.is_empty(),
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
                    let native = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(crate::helper::approval::NativeDispatchProof::collect(
                            case,
                            &proposal,
                            tokio_util::sync::CancellationToken::new(),
                        ))?;
                    let mapping = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(crate::helper::sql::rehearsal::SqlTrialMapping::review(
                            case,
                            &proposal,
                            &native,
                            &state.action_ui.staging_scope_sha256,
                            &state.action_ui.staging_limits,
                            tokio_util::sync::CancellationToken::new(),
                        ))?;
                    let binding = crate::helper::approval::staged_request_binding(
                        case,
                        &proposal,
                        org.clone(),
                        &native,
                        &mapping,
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
                        mapping,
                    ))
                })();
                match result {
                    Ok((input, org, mapping)) => {
                        state.action_ui.staging_mapping = Some(mapping);
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
            if let Some(mapping) = state.action_ui.staging_mapping.clone() {
                ui.label(format!(
                    "Reviewed staging target {} · physical {}",
                    mapping.staging_scope_sha256(),
                    mapping.staging_physical_sha256()
                ));
                if ui
                    .add_enabled(
                        state.action_ui.pending.is_none()
                            && state.action_ui.staging_receipt.is_none()
                            && state.action_ui.intent.is_none(),
                        egui::Button::new("Run approved isolated SQL rehearsal"),
                    )
                    .clicked()
                {
                    let case = case.clone();
                    let proposal = state.reviewed_proposal.clone();
                    let binding = item.binding.clone();
                    let case_path = state.path.clone();
                    let journal_path = crate::helper::journal::ActionJournal::path();
                    let (tx, rx) = std::sync::mpsc::channel();
                    state.action_ui.pending = Some(rx);
                    std::thread::spawn(move || {
                        let result = (|| -> anyhow::Result<_> {
                            let case_path = case_path
                                .ok_or_else(|| anyhow::anyhow!("Case store path missing"))?;
                            let journal_path = journal_path?;
                            let proposal = proposal
                                .ok_or_else(|| anyhow::anyhow!("Reviewed proposal missing"))?;
                            let runtime = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?;
                            let native = runtime.block_on(
                                crate::helper::approval::NativeDispatchProof::collect(
                                    &case,
                                    &proposal,
                                    tokio_util::sync::CancellationToken::new(),
                                ),
                            )?;
                            let id = crate::helper::approval::authorize_and_record_intent(
                                &case_path,
                                &journal_path,
                                &proposal,
                                &binding,
                                &receipt,
                                &native,
                            )?;
                            let refreshed = runtime.block_on(
                                crate::helper::approval::NativeDispatchProof::collect(
                                    &case,
                                    &proposal,
                                    tokio_util::sync::CancellationToken::new(),
                                ),
                            )?;
                            let permit = crate::helper::approval::authorize_and_start_dispatch(
                                &case_path,
                                &journal_path,
                                id,
                                &proposal,
                                &binding,
                                &receipt,
                                &refreshed,
                            )?;
                            runtime
                                .block_on(crate::helper::sql::rehearsal::run_sql_rehearsal(
                                    &mapping,
                                    permit,
                                    id,
                                    &case,
                                    &proposal,
                                    &journal_path,
                                    tokio_util::sync::CancellationToken::new(),
                                ))
                                .map(super::ActionUiEvent::Rehearsed)
                        })();
                        let _ = tx.send(result);
                    });
                }
            } else {
                ui.strong("Reviewed staging mapping unavailable; reconcile consumed action.");
            }
        }
    }
    show_production_controls(state, ui, case, team);
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
    ui.horizontal(|ui| {
        ui.label("Older approval ID:");
        ui.text_edit_singleline(&mut state.action_ui.lookup_approval_id);
        if ui.button("Look up consumed approval").clicked() {
            let result = (|| -> anyhow::Result<_> {
                let id = Uuid::parse_str(state.action_ui.lookup_approval_id.trim())?;
                let item = team.repair_client()?.0.action_v2(id)?;
                anyhow::ensure!(
                    item.binding.case_id == case.id()
                        && item.state == ActionApprovalStateV2::Consumed,
                    "Approval is not a consumed action for this case"
                );
                Ok(item)
            })();
            match result {
                Ok(item) => {
                    if !state.action_ui.recovered.iter().any(|a| a.id == item.id) {
                        state.action_ui.recovered.push(item);
                    }
                }
                Err(error) => state.notice = format!("Approval lookup unavailable: {error}"),
            }
        }
    });
    for approval in state
        .action_ui
        .recovered
        .iter()
        .filter(|approval| approval.binding.case_id == case.id())
    {
        ui.label(format!(
            "Consumed approval {} · run {} · fingerprint {}",
            approval.id, approval.binding.run_id, approval.fingerprint
        ));
    }
    if state
        .action_ui
        .recovered
        .iter()
        .any(|approval| approval.binding.case_id == case.id())
    {
        ui.strong(
            "Reconcile consumed approvals with an operator; never retry consumption automatically.",
        );
    }
}

/// The protected local journal remains usable without a team connection.
fn show_production_controls(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    team: &super::super::team_panel::TeamState,
) {
    let Some(rehearsal) = state.action_ui.staging_receipt.clone() else {
        return;
    };
    ui.separator();
    ui.heading("Production SQL promotion");
    ui.label(format!(
        "Protected native rehearsal {} · original database {}",
        rehearsal.content_sha256(),
        rehearsal.production_physical_sha256()
    ));
    ui.strong("A separate current production approval and fresh native before-state are required.");
    if state.action_ui.production_approval.is_none()
        && state.action_ui.pending.is_none()
        && state.action_ui.organization_confirmed
        && ui.button("Request production SQL approval").clicked()
    {
        let case = case.clone();
        let proposal = state.reviewed_proposal.clone();
        let organization = state.action_ui.organization.clone();
        let case_path = state.path.clone();
        let rehearsal_for_request = rehearsal.clone();
        let client = team.repair_client().map(|value| value.0);
        let (tx, rx) = std::sync::mpsc::channel();
        state.action_ui.pending = Some(rx);
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<_> {
                let proposal =
                    proposal.ok_or_else(|| anyhow::anyhow!("Reviewed proposal missing"))?;
                let organization =
                    organization.ok_or_else(|| anyhow::anyhow!("Team identity missing"))?;
                let case_path = case_path.ok_or_else(|| anyhow::anyhow!("Case store missing"))?;
                let journal_path = crate::helper::journal::ActionJournal::path()?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let native =
                    runtime.block_on(crate::helper::approval::NativeDispatchProof::collect(
                        &case,
                        &proposal,
                        tokio_util::sync::CancellationToken::new(),
                    ))?;
                crate::helper::approval::record_local_review(
                    &case_path,
                    &journal_path,
                    &case,
                    &proposal,
                )?;
                let journal = crate::helper::journal::ActionJournal::load(&journal_path)?;
                let binding = crate::helper::approval::production_request_binding(
                    &case,
                    &proposal,
                    organization.clone(),
                    &native,
                    &rehearsal_for_request,
                    &journal,
                )?;
                let client = client?;
                let caps = client.helper_capabilities()?;
                anyhow::ensure!(
                    caps.organization_sha256 == organization && caps.authority_version == 2,
                    "Team organization identity changed"
                );
                client
                    .request_action_v2(&CreateActionApprovalV2 {
                        request_id: Uuid::new_v4(),
                        binding,
                    })
                    .map(super::ActionUiEvent::ProductionRequested)
            })();
            let _ = tx.send(result);
        });
    }
    if let Some(approval) = state.action_ui.production_approval.clone() {
        ui.label(format!(
            "Production approval {:?} · run {} · expires {}",
            approval.state, approval.binding.run_id, approval.expires_at
        ));
        ui.monospace(format!(
            "Exact production fingerprint: {}",
            approval.fingerprint
        ));
        if state.action_ui.pending.is_none() && ui.button("Refresh production approval").clicked() {
            let client = team.repair_client().map(|value| value.0);
            let (tx, rx) = std::sync::mpsc::channel();
            state.action_ui.pending = Some(rx);
            std::thread::spawn(move || {
                let _ = tx.send(client.and_then(|client| {
                    client
                        .action_v2(approval.id)
                        .map(super::ActionUiEvent::ProductionRefreshed)
                }));
            });
        }
        if approval.state == ActionApprovalStateV2::Approved
            && state.action_ui.production_consume.is_none()
            && !state.action_ui.production_consume_attempted
            && approval.expires_at > chrono::Utc::now()
            && state.action_ui.pending.is_none()
            && ui
                .button("Consume production approval for final native check")
                .clicked()
        {
            state.action_ui.production_consume_attempted = true;
            let client = team.repair_client().map(|value| value.0);
            let (tx, rx) = std::sync::mpsc::channel();
            state.action_ui.pending = Some(rx);
            std::thread::spawn(move || {
                let _ = tx.send(client.and_then(|client| {
                    client
                        .consume_action_v2(
                            approval.id,
                            &ConsumeActionApprovalV2 {
                                binding: approval.binding,
                            },
                        )
                        .map(super::ActionUiEvent::ProductionConsumed)
                }));
            });
        }
    }
    if state.action_ui.production_consume_attempted && state.action_ui.production_consume.is_none()
    {
        ui.strong("Production consumption may have reached team. Reconcile; never consume or run SQL twice.");
    }
    if let (Some(approval), Some(consumed)) = (
        state.action_ui.production_approval.clone(),
        state.action_ui.production_consume.clone(),
    ) {
        ui.label(format!(
            "Production consent consumed once: {}",
            consumed.receipt().consume_id
        ));
        let already_journaled = crate::helper::journal::ActionJournal::path()
            .and_then(|path| crate::helper::journal::ActionJournal::load(&path))
            .map(|journal| {
                journal
                    .intents()
                    .iter()
                    .any(|item| item.run_id == approval.binding.run_id)
            })
            .unwrap_or(true);
        if already_journaled {
            ui.strong("This production run has a durable intent or outcome. Use journal reconciliation; SQL cannot be replayed.");
        }
        if state.action_ui.pending.is_none()
            && !already_journaled
            && state.action_ui.production_receipt.is_none()
            && ui
                .button("Apply approved SQL to original production target")
                .clicked()
        {
            let case = case.clone();
            let proposal = state.reviewed_proposal.clone();
            let case_path = state.path.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            state.action_ui.pending = Some(rx);
            std::thread::spawn(move || {
                let result = (|| -> anyhow::Result<_> {
                    let proposal =
                        proposal.ok_or_else(|| anyhow::anyhow!("Reviewed proposal missing"))?;
                    let case_path =
                        case_path.ok_or_else(|| anyhow::anyhow!("Case store missing"))?;
                    let journal_path = crate::helper::journal::ActionJournal::path()?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let native =
                        runtime.block_on(crate::helper::approval::NativeDispatchProof::collect(
                            &case,
                            &proposal,
                            tokio_util::sync::CancellationToken::new(),
                        ))?;
                    let intent = crate::helper::approval::authorize_and_record_intent(
                        &case_path,
                        &journal_path,
                        &proposal,
                        &approval.binding,
                        &consumed,
                        &native,
                    )?;
                    let refreshed =
                        runtime.block_on(crate::helper::approval::NativeDispatchProof::collect(
                            &case,
                            &proposal,
                            tokio_util::sync::CancellationToken::new(),
                        ))?;
                    let permit = crate::helper::approval::authorize_and_start_dispatch(
                        &case_path,
                        &journal_path,
                        intent,
                        &proposal,
                        &approval.binding,
                        &consumed,
                        &refreshed,
                    )?;
                    let launch = crate::helper::sql::promotion::ProductionLaunch::from_authorized(
                        &case,
                        &proposal,
                        &rehearsal,
                        refreshed,
                        permit,
                        intent,
                        &journal_path,
                    )?;
                    let mut journal = crate::helper::journal::ActionJournal::load(&journal_path)?;
                    runtime
                        .block_on(crate::helper::sql::promotion::apply_sql_production(
                            launch,
                            &mut journal,
                            tokio_util::sync::CancellationToken::new(),
                        ))
                        .map(super::ActionUiEvent::Produced)
                })();
                let _ = tx.send(result);
            });
        }
    }
    if let Some(receipt) = state.action_ui.production_receipt.as_ref() {
        ui.label(format!(
            "Original production run {} · physical database {} · protected receipt {}",
            receipt.run_id(),
            receipt.physical_sha256(),
            receipt.content_sha256()
        ));
        if let Some(index) = receipt.index() {
            ui.label(format!(
                "Owned index {} · native ID {} · definition {} · marker digest {}",
                index.name, index.id, index.definition_sha256, index.marker_sha256
            ));
            if state.action_ui.pending.is_none()
                && state.action_ui.restoration_outcome.is_none()
                && ui
                    .button("Restore this exact original production index")
                    .clicked()
            {
                let run_id = receipt.run_id();
                let (tx, rx) = std::sync::mpsc::channel();
                state.action_ui.pending = Some(rx);
                std::thread::spawn(move || {
                    let result = (|| -> anyhow::Result<_> {
                        let path = crate::helper::journal::ActionJournal::path()?;
                        let mut journal = crate::helper::journal::ActionJournal::load(&path)?;
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        runtime
                            .block_on(crate::helper::sql::restoration::restore_index(
                                run_id,
                                &mut journal,
                                tokio_util::sync::CancellationToken::new(),
                            ))
                            .map(super::ActionUiEvent::Restored)
                    })();
                    let _ = tx.send(result);
                });
            }
        } else {
            ui.strong(
                "Statistics maintenance is non-restorable; the acknowledged limitation applies.",
            );
        }
    }
}

fn show_local_journal(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    team: &super::super::team_panel::TeamState,
) {
    use crate::helper::journal::{ActionJournal, IntentState};
    use crate::helper_approval::ActionOutcomeV2;
    let path = match ActionJournal::path() {
        Ok(path) => path,
        Err(error) => {
            ui.label(format!("Local action journal unavailable: {error}"));
            return;
        }
    };
    let mut journal = match ActionJournal::load(&path) {
        Ok(journal) => journal,
        Err(error) => {
            ui.label(format!("Protected action journal cannot be read: {error}"));
            return;
        }
    };
    let runs = journal
        .intents()
        .iter()
        .filter(|intent| intent.case_id == case.id())
        .cloned()
        .collect::<Vec<_>>();
    if !runs.is_empty() {
        ui.heading("Local action journal");
    }
    for intent in runs {
        ui.label(format!(
            "Run {} · {:?} · first outcome acknowledged {}",
            intent.run_id, intent.state, intent.outcome_acknowledged
        ));
        if let Ok(production) =
            crate::helper::sql::restoration::load_production_receipt(intent.run_id)
        {
            if intent.native_receipt_sha256.as_deref() == Some(production.content_sha256()) {
                ui.label(format!(
                    "Original production target {} · restoration {:?} · pending {}",
                    production.physical_sha256(),
                    intent.restoration_outcome,
                    intent.restoration_pending
                ));
                if intent.restoration_pending
                    || intent.restoration_outcome
                        == Some(
                            crate::helper::sql::restoration::RestorationOutcome::NeedsIntervention,
                        )
                {
                    ui.strong("Restoration outcome requires human reconciliation. Later SQL targets are blocked.");
                }
                if production.index().is_some()
                    && intent.restoration_outcome.is_none()
                    && !intent.restoration_pending
                    && state.action_ui.pending.is_none()
                    && ui
                        .button(format!(
                            "Restore exact owned index for run {}",
                            intent.run_id
                        ))
                        .clicked()
                {
                    let run_id = intent.run_id;
                    let (tx, rx) = std::sync::mpsc::channel();
                    state.action_ui.pending = Some(rx);
                    std::thread::spawn(move || {
                        let result = (|| -> anyhow::Result<_> {
                            let path = ActionJournal::path()?;
                            let mut journal = ActionJournal::load(&path)?;
                            let runtime = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?;
                            runtime
                                .block_on(crate::helper::sql::restoration::restore_index(
                                    run_id,
                                    &mut journal,
                                    tokio_util::sync::CancellationToken::new(),
                                ))
                                .map(super::ActionUiEvent::Restored)
                        })();
                        let _ = tx.send(result);
                    });
                }
            }
        }
        if matches!(
            intent.state,
            IntentState::DispatchStarted | IntentState::OutcomeUnknown
        ) {
            let key = (case.id(), intent.run_id);
            let note = state.action_ui.outcome_notes.entry(key).or_default();
            ui.label("Operator reference for this run (ticket or evidence ID; no SQL text):");
            ui.text_edit_singleline(note);
            let note = note.clone();
            let requested = if intent.state == IntentState::DispatchStarted
                && ui
                    .button(format!("Mark run {} outcome unknown", intent.run_id))
                    .clicked()
            {
                Some((IntentState::OutcomeUnknown, ActionOutcomeV2::OutcomeUnknown))
            } else if ui
                .button(format!("Mark run {} needs intervention", intent.run_id))
                .clicked()
            {
                Some((
                    IntentState::NeedsIntervention,
                    ActionOutcomeV2::NeedsIntervention,
                ))
            } else {
                None
            };
            if let Some((observed, outcome)) = requested {
                state.notice =
                    match journal.observe_and_queue_outcome(intent.id, observed, outcome, &note) {
                        Ok(event) => format!(
                            "Operator report {} saved; send this exact event to the team",
                            event.event_id
                        ),
                        Err(error) => format!("Outcome report was not saved: {error}"),
                    };
            }
        }
        if matches!(
            intent.state,
            IntentState::OutcomeUnknown | IntentState::NeedsIntervention
        ) {
            ui.strong("Human reconciliation required. This operator report is not protected SQL verification; never replay the action.");
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
        ui.label(format!(
            "Saved report {} · sequence {} · local reference digest {}",
            event.event_id,
            event.sequence,
            event.operator_reference_sha256.as_deref().unwrap_or("none")
        ));
        if ui
            .button(format!("Send saved outcome event {}", event.event_id))
            .clicked()
        {
            let result = team
                .repair_client()
                .map(|v| v.0)
                .and_then(|client| client.report_action_outcome_v2(&event))
                .and_then(|ack| journal.acknowledge_outcome(&ack));
            state.notice = match result {
                Ok(()) => format!("Team acknowledged outcome event {}", event.event_id),
                Err(error) => {
                    format!("Delivery or ack save failed; retry this same event: {error}")
                }
            };
        }
    }
}
