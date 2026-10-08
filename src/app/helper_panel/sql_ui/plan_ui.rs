use super::super::HelperState;
use crate::{
    helper::{
        case::HelperCase,
        evidence::{
            self, Coverage, EvidenceBinding, EvidenceEnvelope, EvidenceStatus, NormalizedRecord,
            Observation, Origin, RecordKind, TimeQuality,
        },
        manifest::{CapabilityId, ProbeParams},
        scope::{BoundScope, DatabaseEngine},
        sql::{
            artifacts::{PlanArtifact, SqlArtifact},
            plans::{self, ImportSource, PlanImportFormat},
            templates::{OrderStatus, ReviewedSelectTemplate},
        },
    },
    models::ConnectionProfile,
};
use eframe::egui;
use sha2::{Digest, Sha256};
use std::io::Read;
use uuid::Uuid;

pub(super) fn show(
    state: &mut HelperState,
    ui: &mut egui::Ui,
    case: &HelperCase,
    scope: &BoundScope,
    profiles: &[ConnectionProfile],
) {
    let Ok(digest) = scope.digest() else { return };
    ui.separator();
    ui.heading("SQL plan and workload evidence");
    if ui
        .button("Prune expired unheld SQL artifacts (90 days) and save")
        .clicked()
    {
        let result = match (&mut state.store, &state.path) {
            (Some(store), Some(path)) => {
                store.maintain_sql_artifacts(path, case.id(), chrono::Utc::now())
            }
            _ => Err(anyhow::anyhow!("Helper store unavailable")),
        };
        state.notice = result
            .map(|count| {
                format!("SQL artifact maintenance saved; {count} expired artifact(s) pruned")
            })
            .unwrap_or_else(|error| format!("SQL artifact maintenance failed: {error}"));
    }

    let path_id = egui::Id::new(("helper-plan-path", case.id(), &digest));
    let mut path = ui
        .ctx()
        .data_mut(|d| d.get_temp::<String>(path_id).unwrap_or_default());
    ui.horizontal(|ui| {
        ui.label("Local plan file");
        ui.text_edit_singleline(&mut path);
    });
    ui.ctx().data_mut(|d| d.insert_temp(path_id, path.clone()));
    ui.label("Imported plans are stored as unverified evidence for this case and scope.");
    ui.horizontal(|ui| {
        for (label, format) in [
            ("Import PostgreSQL JSON", PlanImportFormat::PostgresJson),
            (
                "Import psql export",
                PlanImportFormat::PsqlAlignedExplainJson,
            ),
            (
                "Import SQL Server XML",
                PlanImportFormat::SqlServerShowplanXml,
            ),
        ] {
            if ui.button(label).clicked() {
                let outcome = import_plan(state, case, scope, &path, format);
                state.notice = outcome
                    .map(|_| "Unverified plan attached and saved".to_owned())
                    .unwrap_or_else(|error| format!("Plan import failed: {error}"));
            }
        }
    });

    if let BoundScope::Database {
        engine: DatabaseEngine::Postgres,
        object,
        ..
    } = scope
    {
        let choice_id = egui::Id::new(("helper-plan-template", case.id(), &digest));
        let mut choice = ui
            .ctx()
            .data_mut(|d| d.get_temp::<u8>(choice_id).unwrap_or(0));
        if object.as_deref() == Some("orders") {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut choice, 0, "CustomerOrders");
                ui.selectable_value(&mut choice, 1, "StatusCount");
            });
        }
        ui.ctx().data_mut(|d| d.insert_temp(choice_id, choice));
        let template = match object.as_deref() {
            Some("orders") if choice == 0 => Some(ReviewedSelectTemplate::CustomerOrders {
                customer_id: 424242,
            }),
            Some("orders") if choice == 1 => Some(ReviewedSelectTemplate::StatusCount {
                status: OrderStatus::Pending,
            }),
            Some("spill_events") => Some(ReviewedSelectTemplate::OrderSort),
            _ => None,
        };
        if let Some(template) = template {
            ui.label(format!("Reviewed synthetic template: {}", template.label()));
            if ui.button("Collect live estimated plan").clicked() {
                let outcome = template.fingerprint(scope).and_then(|query_digest| {
                    state.try_collect_sql(
                        case.id(),
                        scope,
                        profiles,
                        CapabilityId::SqlPlan,
                        ProbeParams::SqlPlan { query_digest },
                    )
                });
                state.notice = outcome
                    .map(|_| "Estimated plan collection started".to_owned())
                    .unwrap_or_else(|error| format!("Plan collection unavailable: {error}"));
            }
            let review = case.evidence().iter().rev().find(|e| {
                e.capability_id == CapabilityId::SqlRead
                    && e.binding.scope_sha256 == digest
                    && crate::helper::sql::benchmark::ReviewedWorkload::review(
                        case, scope, template, e.id,
                    )
                    .is_ok()
            });
            if let Some(review) = review {
                if ui
                    .button("Run reviewed sandbox workload (3 warmups, 15 samples)")
                    .clicked()
                {
                    let outcome = template.fingerprint(scope).and_then(|workload_digest| {
                        state.try_collect_sql(
                            case.id(),
                            scope,
                            profiles,
                            CapabilityId::SqlWorkloadBaseline,
                            ProbeParams::SqlWorkload {
                                workload_digest,
                                review_evidence_id: review.id,
                                review_content_sha256: review.content_sha256.clone(),
                            },
                        )
                    });
                    state.notice = outcome
                        .map(|_| "Reviewed workload started".to_owned())
                        .unwrap_or_else(|error| format!("Workload unavailable: {error}"));
                }
            } else {
                ui.label("Workload needs a fresh, complete SQL read of the exact fixture object.");
            }
        } else {
            ui.label("Live collection requires an exact reviewed fixture table.");
        }
    } else if let BoundScope::Database {
        engine: DatabaseEngine::SqlServer,
        object,
        ..
    } = scope
    {
        ui.label("Native SQL Server SHOWPLAN uses a dedicated verified session. No live SQL Server fixture endpoint has been validated for this build.");
        ui.label(
            "The verified session currently supports matching SQL login and database-user names.",
        );
        let choice_id = egui::Id::new(("helper-tds-plan-template", case.id(), &digest));
        let mut choice = ui
            .ctx()
            .data_mut(|d| d.get_temp::<u8>(choice_id).unwrap_or(0));
        if object.as_deref() == Some("orders") {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut choice, 0, "CustomerOrders");
                ui.selectable_value(&mut choice, 1, "StatusCount");
            });
        }
        ui.ctx().data_mut(|d| d.insert_temp(choice_id, choice));
        let template = match object.as_deref() {
            Some("orders") if choice == 0 => Some(ReviewedSelectTemplate::CustomerOrders {
                customer_id: 424242,
            }),
            Some("orders") if choice == 1 => Some(ReviewedSelectTemplate::StatusCount {
                status: OrderStatus::Pending,
            }),
            Some("spill_events") => Some(ReviewedSelectTemplate::OrderSort),
            _ => None,
        };
        if let Some(template) =
            template.filter(|template| template.sql_server_statement(scope).is_ok())
        {
            ui.label(format!("Reviewed synthetic template: {}", template.label()));
            if ui
                .button("Collect SQL Server estimated plan (local fixture)")
                .clicked()
            {
                let outcome = template.fingerprint(scope).and_then(|query_digest| {
                    state.try_collect_sql(
                        case.id(),
                        scope,
                        profiles,
                        CapabilityId::SqlPlan,
                        ProbeParams::SqlPlan { query_digest },
                    )
                });
                state.notice = outcome
                    .map(|_| "SQL Server SHOWPLAN collection started".to_owned())
                    .unwrap_or_else(|error| format!("SQL Server SHOWPLAN unavailable: {error}"));
            }
            let review = case.evidence().iter().rev().find(|e| {
                e.capability_id == CapabilityId::SqlRead
                    && e.binding.scope_sha256 == digest
                    && crate::helper::sql::benchmark::ReviewedWorkload::review(
                        case, scope, template, e.id,
                    )
                    .is_ok()
            });
            if let Some(review) = review {
                if ui
                    .button("Run reviewed SQL Server fixture workload (3 warmups, 15 samples)")
                    .clicked()
                {
                    let outcome = template.fingerprint(scope).and_then(|workload_digest| {
                        state.try_collect_sql(
                            case.id(),
                            scope,
                            profiles,
                            CapabilityId::SqlWorkloadBaseline,
                            ProbeParams::SqlWorkload {
                                workload_digest,
                                review_evidence_id: review.id,
                                review_content_sha256: review.content_sha256.clone(),
                            },
                        )
                    });
                    state.notice = outcome
                        .map(|_| "Reviewed SQL Server workload started".to_owned())
                        .unwrap_or_else(|error| format!("Workload unavailable: {error}"));
                }
            } else {
                ui.label(
                    "Workload needs a fresh complete SQL Server read of the exact fixture object.",
                );
            }
        } else {
            ui.label("Native SHOWPLAN requires an exact disposable loopback fixture scope and read credential.");
        }
        ui.label("Imported plans remain unverified; local fixture behavior has no live endpoint validation.");
    }

    let active: Vec<_> = state
        .collect_jobs
        .iter()
        .filter(|(_, case_id)| **case_id == case.id())
        .map(|(request_id, _)| *request_id)
        .collect();
    for request_id in active {
        ui.horizontal(|ui| {
            ui.label(format!("Capture running: {request_id}"));
            if ui.button("Cancel").clicked() {
                if let Some(worker) = state.worker.as_mut() {
                    worker.cancel(request_id);
                }
            }
        });
    }
    for item in case
        .evidence()
        .iter()
        .rev()
        .filter(|e| {
            e.binding.scope_sha256 == digest
                && matches!(
                    e.capability_id,
                    CapabilityId::SqlPlan | CapabilityId::SqlWorkloadBaseline
                )
        })
        .take(12)
    {
        for artifact in &item.sql_artifacts {
            match artifact {
                SqlArtifact::Plan(plan) => {
                    ui.collapsing(
                        format!(
                            "{:?} plan · {} operators · {}",
                            item.origin, plan.operator_count, item.source_observed_at
                        ),
                        |ui| {
                            ui.label(format!("Source SHA-256: {}", plan.source_sha256));
                            ui.label(format!("Template SHA-256: {}", plan.template_sha256));
                            ui.label(format!(
                                "{} projected operators{}",
                                plan.operators.len(),
                                if plan.operators_truncated {
                                    " (truncated)"
                                } else {
                                    ""
                                }
                            ));
                        if plan.has_spill_evidence {
                            ui.label(if item.origin == Origin::ImportedUnverified {
                                "Imported spill marker; execution context remains unverified."
                            } else {
                                "Estimated spill marker; measured workload is needed to confirm a spill."
                            });
                        }
                        if plan.has_temp_io {
                            ui.label("Temporary I/O recorded; it does not identify the spilling operator by itself.");
                        }
                            for operator in plan.operators.iter().take(30) {
                                ui.label(format!(
                                    "{}{} · estimated rows {:?} · cost {:?}{}",
                                    "  ".repeat(usize::from(operator.depth).min(8)),
                                    operator.name,
                                    operator.estimated_rows,
                                    operator.estimated_cost,
                                    if operator.spill {
                                        " · spill marker"
                                    } else {
                                        ""
                                    }
                                ));
                            if let (Some(estimated), Some(actual)) =
                                (operator.estimated_rows, operator.actual_rows)
                            {
                                if estimated > 0.0 && actual > 0.0
                                    && estimated.max(actual) / estimated.min(actual) >= 10.0
                                {
                                    ui.label("Large estimate/actual row gap in imported plan; review statistics and selectivity.");
                                }
                            }
                            }
                        },
                    );
                }
                SqlArtifact::Workload(sample) => {
                    ui.collapsing(
                        format!(
                            "{:?} workload · {} samples · {}",
                            item.origin,
                            sample.milliseconds.len(),
                            item.source_observed_at
                        ),
                        |ui| {
                            ui.label(format!(
                                "Median {:.3} ms · p95 {:.3} ms · MAD {:.3} ms",
                                sample.median_ms, sample.p95_ms, sample.mad_ms
                            ));
                            ui.label(format!("Reviewed SQL read: {}", sample.review_evidence_id));
                            ui.label(format!("Result SHA-256: {}", sample.result_sha256));
                            if !sample.compatibility.is_complete() {
                                ui.label("Comparison blocked: optimizer, index, statistics, data, plan, and post-sample state are not fully verified.");
                            }
                            ui.label("One run does not establish an improvement.");
                        },
                    );
                }
            }
        }
    }
}

fn import_plan(
    state: &mut HelperState,
    case: &HelperCase,
    scope: &BoundScope,
    path: &str,
    format: PlanImportFormat,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            (scope, format),
            (
                BoundScope::Database {
                    engine: DatabaseEngine::Postgres,
                    ..
                },
                PlanImportFormat::PostgresJson | PlanImportFormat::PsqlAlignedExplainJson
            ) | (
                BoundScope::Database {
                    engine: DatabaseEngine::SqlServer,
                    ..
                },
                PlanImportFormat::SqlServerShowplanXml
            )
        ),
        "Plan format does not match reviewed database engine"
    );
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((plans::MAX_PLAN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let report = plans::parse_import(format, &bytes, ImportSource::OperatorFile)?;
    let artifact = PlanArtifact::from_report(&report, report.source_sha256.clone())?;
    let now = chrono::Utc::now();
    let content = serde_json::to_vec(&artifact)?;
    let content_sha256 = format!("{:x}", Sha256::digest(&content));
    let envelope = EvidenceEnvelope {
        schema: evidence::EVIDENCE_SCHEMA,
        id: Uuid::new_v4(),
        binding: EvidenceBinding {
            case_id: case.id(),
            case_revision: case.revision(),
            request_id: Uuid::new_v4(),
            scope_sha256: scope.digest()?,
            credential_scope_sha256: scope.credential_scope_digest()?,
            run_id: None,
        },
        request_intent_sha256: None,
        capability_id: CapabilityId::SqlPlan,
        capability_version: 1,
        parser_version: 1,
        origin: Origin::ImportedUnverified,
        source_id: evidence::source_id_digest(report.source_sha256.as_bytes()),
        source_observed_at: now,
        retrieved_at: now,
        time_quality: TimeQuality::ClockUncertain,
        status: EvidenceStatus::Complete,
        coverage: Coverage {
            observed: 1,
            expected: 1,
            truncated: artifact.operators_truncated,
        },
        content_sha256,
        records: vec![NormalizedRecord {
            kind: RecordKind::SqlPlan,
            observation: Observation::Unknown,
            subject_sha256: report.source_sha256,
        }],
        metrics: vec![],
        sql_observations: vec![],
        sql_artifacts: vec![SqlArtifact::Plan(artifact)],
        evidence_refs: vec![],
    };
    let path = state
        .path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Store path unavailable"))?;
    let mut store = state
        .store
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Store unavailable"))?
        .clone();
    evidence::import_evidence(&mut store, case.id(), envelope)?;
    store.save(path)?;
    state.store = Some(store);
    Ok(())
}
