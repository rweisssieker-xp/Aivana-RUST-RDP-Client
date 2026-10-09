use super::*;
use crate::helper::{
    journal::{ActionJournal, IntentState},
    verification::{self, CheckOutcome, RunReference, VerificationPlan},
};
use crate::helper::{
    manifest::ProbeParams,
    sql::{benchmark::ReviewedWorkload, templates::ReviewedSelectTemplate},
    verification::SqlFunctionalTarget,
};
use crate::helper_action::RequiredCheck;

pub(super) fn show(state: &mut HelperState, ui: &mut Ui, case: &HelperCase) {
    ui.separator();
    ui.heading("Verify · production outcome");
    if let Some(resolution) = case.resolution() {
        ui.label(format!("Case resolution: {resolution:?}"));
        if let Some(review) = case.resolution_review() {
            ui.label(format!("{} · {}", review.reason, review.coverage));
        }
        return;
    }
    show_terminal_controls(state, ui, case);
    ui.label("Checks use the reviewed production run and each exact API or portal target. Missing coverage stays incomplete.");

    if let Some(receiver) = state.verification_ui.pending.as_ref() {
        match receiver.try_recv() {
            Ok(result) => {
                state.verification_ui.pending = None;
                match result.and_then(|receipt| {
                    let path = verification::ReceiptStore::path()?;
                    let journal = ActionJournal::load(&ActionJournal::path()?)?;
                    let mut store = verification::ReceiptStore::load_checked(&path, &journal)?;
                    store.append_functional(&journal, receipt.clone())?;
                    Ok(receipt)
                }) {
                    Ok(receipt) => {
                        state.notice = "Production functional checks recorded".into();
                        state.verification_ui.latest = Some(receipt);
                    }
                    Err(error) => state.notice = format!("Verification failed: {error}"),
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                state.verification_ui.pending = None;
                state.notice = "Verification worker stopped without a result".into();
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
    }

    let Some(proposal) = state.reviewed_proposal.clone() else {
        ui.label("Review a change and its required checks first.");
        return;
    };
    if proposal.case_id != case.id() || proposal.case_revision != case.revision() {
        ui.label("The reviewed check set is stale for this case revision.");
        return;
    }
    show_performance(state, ui, case, &proposal);
    let Some(production) = state.action_ui.production_receipt.as_ref() else {
        ui.label("A production receipt is required before post-action checks.");
        return;
    };
    let approved_check_set = state
        .action_ui
        .production_approval
        .as_ref()
        .is_some_and(|approval| {
            approval.binding.case_id == case.id()
                && approval.binding.case_revision == case.revision()
                && crate::helper_action::digest(
                    b"relayne-helper-reviewed-verification-v2",
                    &proposal.verification,
                )
                .ok()
                .as_deref()
                    == Some(approval.binding.verification_sha256.as_str())
        });
    if !approved_check_set {
        ui.label("The approved verification criteria are unavailable or changed.");
        return;
    }
    let journal = ActionJournal::path().and_then(|path| ActionJournal::load(&path));
    let Some(intent) = journal.as_ref().ok().and_then(|journal| {
        journal.intents().iter().find(|intent| {
            intent.run_id == production.run_id()
                && intent.case_id == case.id()
                && intent.state == IntentState::Verified
        })
    }) else {
        ui.label("The exact production action has not been verified in the local journal.");
        return;
    };
    let run = RunReference::GenericProduction {
        run_id: intent.run_id,
        binding_sha256: intent.binding_fingerprint.clone(),
        production_receipt_sha256: Some(production.content_sha256().to_owned()),
    };
    if state
        .verification_ui
        .latest
        .as_ref()
        .is_none_or(|receipt| receipt.case_id != case.id() || receipt.run != run)
    {
        if let Ok(path) = verification::ReceiptStore::path() {
            if let Ok(store) =
                verification::ReceiptStore::load_checked(&path, journal.as_ref().unwrap())
            {
                state.verification_ui.latest = store
                    .functional()
                    .iter()
                    .rev()
                    .find(|receipt| receipt.case_id == case.id() && receipt.run == run)
                    .cloned();
            }
        }
    }
    let sql_targets = proposal
        .verification
        .checks
        .iter()
        .filter_map(|check| {
            let RequiredCheck::SqlFunctional {
                scope_sha256,
                object_id,
                ..
            } = check
            else {
                return None;
            };
            if *object_id != production.object_id() {
                return None;
            }
            let scope = case
                .scopes()
                .iter()
                .find(|scope| scope.digest().ok().as_deref() == Some(scope_sha256.as_str()))?;
            let step = case.plan()?.steps.iter().find(|step| {
                step.scope_sha256 == *scope_sha256
                    && matches!(&step.params, ProbeParams::SqlWorkload { .. })
            })?;
            let ProbeParams::SqlWorkload {
                workload_digest,
                review_evidence_id,
                ..
            } = &step.params
            else {
                return None;
            };
            let template = ReviewedSelectTemplate::from_fingerprint(scope, workload_digest)?;
            let workload =
                ReviewedWorkload::review(case, scope, template, *review_evidence_id).ok()?;
            Some(SqlFunctionalTarget {
                scope_sha256: scope_sha256.clone(),
                object_id: *object_id,
                workload,
            })
        })
        .collect();
    let plan = VerificationPlan {
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        run: run.clone(),
        verification: proposal.verification.clone(),
        approved_verification_sha256: state
            .action_ui
            .production_approval
            .as_ref()
            .map(|approval| approval.binding.verification_sha256.clone())
            .unwrap_or_default(),
        http_scopes: case
            .scopes()
            .iter()
            .filter(|scope| matches!(scope, crate::helper::scope::BoundScope::Http { .. }))
            .cloned()
            .collect(),
        sql_targets,
        captured_at: chrono::Utc::now(),
    };
    let readiness = plan.validate(case);
    if let Err(error) = &readiness {
        ui.label(format!("Check readiness: {error}"));
    }
    if ui
        .add_enabled(
            readiness.is_ok() && state.verification_ui.pending.is_none(),
            egui::Button::new("Run production functional checks"),
        )
        .clicked()
    {
        let (tx, rx) = std::sync::mpsc::channel();
        state.verification_ui.pending = Some(rx);
        let check_run = run.clone();
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(anyhow::Error::from)
                .and_then(|runtime| {
                    runtime.block_on(verification::run_checks(
                        &plan,
                        &check_run,
                        tokio_util::sync::CancellationToken::new(),
                    ))
                });
            let _ = tx.send(result);
        });
    }
    if state.verification_ui.pending.is_some() {
        ui.spinner();
        ui.label("Checking reviewed targets…");
    }
    if let Some(receipt) = state
        .verification_ui
        .latest
        .as_ref()
        .filter(|receipt| receipt.case_id == case.id())
    {
        for result in &receipt.checks {
            let label = match result.outcome {
                CheckOutcome::Passed => "Passed",
                CheckOutcome::Failed => "Failed",
                CheckOutcome::Unknown => "Unknown",
                CheckOutcome::Incomplete => "Incomplete",
            };
            ui.label(format!(
                "{label} · {:?} · HTTP {:?} · SQL rows {:?}",
                result.check, result.observed_http_status, result.observed_row_count
            ));
        }
        if receipt.all_passed() {
            ui.label(
                "All recorded functional checks passed. Performance proof is evaluated separately.",
            );
        }
    }
    if ui.button("Resolve as verified Relayne repair").clicked() {
        let result = (|| {
            let path = state
                .path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))?
                .clone();
            let store = state
                .store
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))?;
            store.finish_verified_from_receipts(&path, case.id(), case.revision(), run.run_id())
        })();
        state.notice = match result {
            Ok(()) => "Case resolved from exact production receipts".into(),
            Err(error) => format!("Cannot verify repair: {error}"),
        };
    }
}

fn show_terminal_controls(state: &mut HelperState, ui: &mut Ui, case: &HelperCase) {
    use crate::helper::case::CaseResolution;
    ui.collapsing("Finish without a Relayne repair", |ui| {
        let choices = [
            CaseResolution::DiagnosedNoChange,
            CaseResolution::ResolvedExternally,
            CaseResolution::ClosedUnresolved,
            CaseResolution::NeedsIntervention,
        ];
        egui::ComboBox::from_id_salt("helper-terminal-outcome")
            .selected_text(
                state
                    .verification_ui
                    .resolution_kind
                    .map_or("Select outcome".into(), |v| format!("{v:?}")),
            )
            .show_ui(ui, |ui| {
                for choice in choices {
                    ui.selectable_value(
                        &mut state.verification_ui.resolution_kind,
                        Some(choice),
                        format!("{choice:?}"),
                    );
                }
            });
        ui.label("Reviewed reason");
        ui.text_edit_singleline(&mut state.verification_ui.resolution_reason);
        ui.label("Evidence coverage or gaps");
        ui.text_edit_singleline(&mut state.verification_ui.resolution_coverage);
        if ui
            .add_enabled(
                state.verification_ui.resolution_kind.is_some()
                    && state.verification_ui.resolution_reason.trim().len() >= 3
                    && !state.verification_ui.resolution_coverage.trim().is_empty(),
                egui::Button::new("Record reviewed outcome"),
            )
            .clicked()
        {
            let result = (|| {
                let path = state
                    .path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))?
                    .clone();
                let store = state
                    .store
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("Case store unavailable"))?;
                store.close_without_repair(
                    &path,
                    case.id(),
                    case.revision(),
                    state.verification_ui.resolution_kind.unwrap(),
                    &state.verification_ui.resolution_reason,
                    &state.verification_ui.resolution_coverage,
                    Vec::new(),
                )
            })();
            state.notice = match result {
                Ok(()) => "Reviewed case outcome saved".into(),
                Err(error) => format!("Cannot close case: {error}"),
            };
        }
    });
}

fn show_performance(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    proposal: &crate::helper::catalog::HelperProposal,
) {
    use crate::helper::verification::PerformancePhase;
    if let Some(receiver) = state.verification_ui.performance_pending.as_ref() {
        match receiver.try_recv() {
            Ok(result) => {
                state.verification_ui.performance_pending = None;
                state.notice = match result.and_then(|(receipt, approval, original_case)| {
                    let journal = ActionJournal::load(&ActionJournal::path()?)?;
                    let mut store = verification::ReceiptStore::load_checked(
                        &verification::ReceiptStore::path()?,
                        &journal,
                    )?;
                    match receipt.phase {
                        PerformancePhase::BeforeProduction => store.append_baseline(
                            approval
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("Baseline approval missing"))?,
                            &original_case,
                            receipt,
                        )?,
                        PerformancePhase::AfterProduction => {
                            store.append_performance(&journal, receipt)?
                        }
                    }
                    Ok(())
                }) {
                    Ok(()) => "Production performance samples recorded".into(),
                    Err(error) => format!("Performance capture failed: {error}"),
                };
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                state.verification_ui.performance_pending = None;
                state.notice = "Performance worker stopped without a result".into();
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
    }
    let Some((scope_sha256, workload_sha256)) =
        proposal
            .verification
            .checks
            .iter()
            .find_map(|check| match check {
                RequiredCheck::Performance {
                    scope_sha256,
                    workload_sha256,
                    ..
                } => Some((scope_sha256, workload_sha256)),
                _ => None,
            })
    else {
        return;
    };
    ui.label("Performance: 3 warmups and 15 measured executions per side. The baseline must finish before Apply.");
    let workload = (|| {
        let scope = case
            .scopes()
            .iter()
            .find(|scope| scope.digest().ok().as_deref() == Some(scope_sha256.as_str()))?;
        let step = case.plan()?.steps.iter().find(|step| step.scope_sha256 == *scope_sha256 && matches!(&step.params, ProbeParams::SqlWorkload { workload_digest, .. } if workload_digest == workload_sha256))?;
        let ProbeParams::SqlWorkload {
            review_evidence_id, ..
        } = &step.params
        else {
            return None;
        };
        let template = ReviewedSelectTemplate::from_fingerprint(scope, workload_sha256)?;
        ReviewedWorkload::review(case, scope, template, *review_evidence_id).ok()
    })();
    if workload.is_none() {
        ui.label("Fresh reviewed native SQL workload evidence is required.");
    }
    let journal = ActionJournal::path().and_then(|path| ActionJournal::load(&path));
    let store = journal.as_ref().ok().and_then(|journal| {
        verification::ReceiptStore::path()
            .and_then(|path| verification::ReceiptStore::load_checked(&path, journal))
            .ok()
    });
    let approval = state.action_ui.production_approval.clone();
    let baseline_run = approval
        .as_ref()
        .map(|approval| RunReference::GenericProduction {
            run_id: approval.binding.run_id,
            binding_sha256: approval.fingerprint.clone(),
            production_receipt_sha256: None,
        });
    let baseline_exists = baseline_run.as_ref().is_some_and(|run| {
        store.as_ref().is_some_and(|store| {
            store.performance().iter().any(|receipt| {
                receipt.run == *run && receipt.phase == PerformancePhase::BeforeProduction
            })
        })
    });
    if baseline_exists {
        ui.label("Exact production baseline saved.");
    }
    let pre_ready = approval.as_ref().is_some_and(|approval| {
        approval.state == crate::helper_approval::ActionApprovalStateV2::Approved
    }) && workload.is_some()
        && !baseline_exists
        && state.action_ui.production_receipt.is_none()
        && state.verification_ui.performance_pending.is_none();
    if ui
        .add_enabled(
            pre_ready,
            egui::Button::new("Capture pre-action production baseline"),
        )
        .clicked()
    {
        start_performance(
            state,
            case,
            baseline_run.as_ref().unwrap().clone(),
            PerformancePhase::BeforeProduction,
            workload.clone().unwrap(),
            approval.clone(),
        );
    }
    if let (Some(production), Some(journal), Some(workload), Some(approval)) = (
        state.action_ui.production_receipt.as_ref(),
        journal.as_ref().ok(),
        workload,
        approval.as_ref(),
    ) {
        if let Some(intent) = journal.intents().iter().find(|intent| {
            intent.case_id == case.id()
                && intent.run_id == production.run_id()
                && intent.state == IntentState::Verified
        }) {
            let run = RunReference::GenericProduction {
                run_id: intent.run_id,
                binding_sha256: intent.binding_fingerprint.clone(),
                production_receipt_sha256: Some(production.content_sha256().to_owned()),
            };
            let after_exists = store.as_ref().is_some_and(|store| {
                store.performance().iter().any(|receipt| {
                    receipt.run == run && receipt.phase == PerformancePhase::AfterProduction
                })
            });
            if after_exists {
                ui.label("Post-action production samples saved.");
            }
            if ui
                .add_enabled(
                    baseline_exists
                        && !after_exists
                        && state.verification_ui.performance_pending.is_none(),
                    egui::Button::new("Capture post-action production samples"),
                )
                .clicked()
            {
                start_performance(
                    state,
                    case,
                    run,
                    PerformancePhase::AfterProduction,
                    workload,
                    Some(approval.clone()),
                );
            }
        }
    }
    if let (Some(store), Some(run)) = (store.as_ref(), baseline_run.as_ref()) {
        let baseline = store.performance().iter().find(|receipt| {
            receipt.run == *run && receipt.phase == PerformancePhase::BeforeProduction
        });
        let after = store.performance().iter().find(|receipt| {
            receipt.run.run_id() == run.run_id()
                && receipt.phase == PerformancePhase::AfterProduction
        });
        for (label, sample) in [("Before", baseline), ("After", after)] {
            if let Some(sample) = sample {
                ui.label(format!(
                    "{label}: n={}, warmups={}, median {:.2} ms, p95 {:.2} ms, MAD {:.2} ms",
                    sample.samples_ms.len(),
                    sample.warmups,
                    sample.median_ms,
                    sample.p95_ms,
                    sample.mad_ms
                ));
            }
        }
        if let (Some(before), Some(after)) = (baseline, after) {
            if let Some((maximum_median_ms, maximum_p95_ms)) = proposal
                .verification
                .checks
                .iter()
                .find_map(|check| match check {
                    RequiredCheck::Performance {
                        maximum_median_ms,
                        maximum_p95_ms,
                        ..
                    } => Some((*maximum_median_ms, *maximum_p95_ms)),
                    _ => None,
                })
            {
                let comparison = verification::compare_performance(
                    before,
                    after,
                    &verification::ComparisonPolicy {
                        maximum_median_ms: maximum_median_ms as f64,
                        maximum_p95_ms: maximum_p95_ms as f64,
                    },
                );
                ui.label(format!("Comparison: {comparison:?} · overlapping noise or changed context stays inconclusive"));
            }
        }
    }
    if state.verification_ui.performance_pending.is_some() {
        ui.spinner();
        ui.label("Collecting bounded native SQL samples…");
    }
}

fn start_performance(
    state: &mut HelperState,
    case: &HelperCase,
    run: RunReference,
    phase: crate::helper::verification::PerformancePhase,
    workload: ReviewedWorkload,
    approval: Option<crate::helper_approval::ActionApprovalV2>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    state.verification_ui.performance_pending = Some(rx);
    let case = case.clone();
    std::thread::spawn(move || {
        let result: anyhow::Result<(
            crate::helper::verification::PerformanceReceipt,
            Option<crate::helper_approval::ActionApprovalV2>,
            HelperCase,
        )> = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| {
                runtime.block_on(verification::capture_production_performance(
                    &case,
                    &run,
                    phase,
                    &workload,
                    approval.as_ref(),
                    tokio_util::sync::CancellationToken::new(),
                ))
            })
            .map(|receipt| (receipt, approval, case));
        let _ = tx.send(result);
    });
}
