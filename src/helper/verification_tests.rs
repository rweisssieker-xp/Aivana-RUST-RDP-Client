use super::*;

#[test]
fn service_performance_is_rejected_before_verification_dispatch() {
    use crate::helper_action::CriterionRequirement;
    let case = HelperCase::new(crate::helper::case::ProblemIntake::default()).unwrap();
    let verification = VerificationSpec {
        checks: vec![
            RequiredCheck::HttpFunctional {
                scope_sha256: digest(),
                expected_status: 200,
                body_sha256: None,
                window: "after change".into(),
            },
            RequiredCheck::Performance {
                scope_sha256: digest(),
                object_id: 1,
                workload_sha256: digest(),
                maximum_median_ms: 100,
                maximum_p95_ms: 100,
                minimum_warmups: 3,
                minimum_samples: 15,
                window: "after change".into(),
            },
        ],
        criteria: vec![
            CriterionRequirement {
                measure: "HTTP status".into(),
                comparator: CriterionComparator::Equal,
                threshold_bits: 200f64.to_bits(),
                unit: "status".into(),
                window: "after change".into(),
            },
            CriterionRequirement {
                measure: "Median latency".into(),
                comparator: CriterionComparator::AtMost,
                threshold_bits: 100f64.to_bits(),
                unit: "ms".into(),
                window: "after change".into(),
            },
        ],
    };
    verification.validate().unwrap();
    let approved_verification_sha256 = crate::helper_action::digest(
        b"relayne-helper-reviewed-verification-v2",
        &verification,
    )
    .unwrap();
    let run = RunReference::ExistingService {
        run_id: Uuid::new_v4(),
        target_index: 0,
        execution_plan_sha256: digest(),
    };
    let plan = VerificationPlan {
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        run: run.clone(),
        verification: verification.clone(),
        approved_verification_sha256: approved_verification_sha256.clone(),
        http_scopes: Vec::new(),
        sql_targets: Vec::new(),
        captured_at: Utc::now(),
    };
    assert!(
        plan.validate(&case)
            .unwrap_err()
            .to_string()
            .contains("Service performance")
    );
    let receipt = FunctionalReceipt {
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        verification_plan_sha256: digest(),
        run,
        captured_at: Utc::now(),
        verification,
        approved_verification_sha256,
        checks: Vec::new(),
    };
    assert!(
        receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("Service performance")
    );
}

#[test]
fn persisted_resolution_links_reject_missing_or_aliased_receipts() {
    let mut links = crate::helper::case::ResolutionProofLinks {
        run_id: Uuid::from_u128(1),
        intent_id: Uuid::from_u128(2),
        production_receipt_sha256: digest(),
        functional_receipt_id: Uuid::from_u128(3),
        functional_receipt_sha256: digest(),
        baseline_receipt_id: Some(Uuid::from_u128(4)),
        baseline_receipt_sha256: Some(digest()),
        after_receipt_id: Some(Uuid::from_u128(5)),
        after_receipt_sha256: Some(digest()),
    };
    links.validate().unwrap();
    links.after_receipt_sha256 = None;
    assert!(links.validate().is_err());
    links.after_receipt_sha256 = Some(digest());
    links.after_receipt_id = links.baseline_receipt_id;
    assert!(links.validate().is_err());
}

#[test]
fn performance_receipt_identity_changes_with_raw_samples() {
    let mut receipt = receipt(PerformancePhase::BeforeProduction, vec![100.0; 15]);
    let original = (receipt.id().unwrap(), receipt.content_sha256().unwrap());
    receipt.samples_ms[0] = 101.0;
    let (median, p95, mad) = summary(&receipt.samples_ms).unwrap();
    receipt.median_ms = median;
    receipt.p95_ms = p95;
    receipt.mad_ms = mad;
    assert_ne!(receipt.id().unwrap(), original.0);
    assert_ne!(receipt.content_sha256().unwrap(), original.1);
}

#[test]
fn typed_delta_requires_exact_owned_index_definition_and_marker() {
    let before = receipt(PerformancePhase::BeforeProduction, vec![100.0; 15]);
    let after = receipt(PerformancePhase::AfterProduction, vec![50.0; 15]);
    assert!(approved_typed_delta(&before, &after));
    let mut wrong_definition = after.clone();
    wrong_definition.typed_context.indexes[1].definition_sha256 = "d".repeat(64);
    assert!(!approved_typed_delta(&before, &wrong_definition));
    let mut wrong_marker = after.clone();
    wrong_marker.typed_context.indexes[1].marker_sha256 = Some("d".repeat(64));
    assert!(!approved_typed_delta(&before, &wrong_marker));
}

#[test]
fn typed_sql_server_delta_only_allows_owned_index_and_its_statistic() {
    use crate::helper::sql::benchmark::CompatibilityEngine;
    let mut before = receipt(PerformancePhase::BeforeProduction, vec![100.0; 15]);
    let mut after = receipt(PerformancePhase::AfterProduction, vec![50.0; 15]);
    before.typed_context.engine = CompatibilityEngine::SqlServer;
    after.typed_context.engine = CompatibilityEngine::SqlServer;
    let SqlAction::PostgresCreateIndex {
        object,
        index,
        columns,
    } = approved_index()
    else {
        unreachable!()
    };
    let mut object = object;
    object.engine = crate::helper_action::SqlEngine::SqlServer;
    after.approved_action = Some(SqlAction::SqlServerCreateIndex {
        object,
        index: index.clone(),
        columns,
    });
    after.typed_context.statistics.push((index, "b".repeat(64)));
    after
        .typed_context
        .statistics
        .sort_by(|left, right| left.0.cmp(&right.0));
    assert!(approved_typed_delta(&before, &after));
    let mut unrelated = after.clone();
    unrelated
        .typed_context
        .statistics
        .iter_mut()
        .find(|item| item.0 == "status")
        .unwrap()
        .1 = "d".repeat(64);
    assert!(!approved_typed_delta(&before, &unrelated));
    let mut unrelated_index = after.clone();
    unrelated_index.typed_context.indexes.push(
        crate::helper::sql::benchmark::TypedIndexDefinition {
            name: "unrelated_index".into(),
            definition_sha256: "d".repeat(64),
            marker_sha256: None,
            plain_nonunique_btree: false,
            columns: Vec::new(),
        },
    );
    assert!(!approved_typed_delta(&before, &unrelated_index));
    let mut schema_drift = after.clone();
    schema_drift.typed_context.schema_sha256 = "d".repeat(64);
    assert!(!approved_typed_delta(&before, &schema_drift));
    let mut setting_drift = after;
    setting_drift.typed_context.settings[0].1 = "changed".into();
    assert!(!approved_typed_delta(&before, &setting_drift));
}

#[test]
fn opaque_statistics_delta_cannot_prove_exact_analyze_action() {
    let before = receipt(PerformancePhase::BeforeProduction, vec![100.0; 15]);
    let mut after = receipt(PerformancePhase::AfterProduction, vec![50.0; 15]);
    let SqlAction::PostgresCreateIndex { object, .. } = approved_index() else {
        unreachable!()
    };
    after.approved_action = Some(SqlAction::PostgresAnalyze { object });
    after.typed_context.indexes = before.typed_context.indexes.clone();
    after.typed_context.statistics[0].1 = "d".repeat(64);
    after.typed_context.statistics_sha256 = "d".repeat(64);
    after.approved_index_definition_sha256 = None;
    after.approved_index_marker_sha256 = None;
    assert!(!approved_typed_delta(&before, &after));
}

fn digest() -> String {
    "a".repeat(64)
}

fn approved_index() -> SqlAction {
    use crate::helper_action::{PlainIndexColumn, SortDirection, SqlEngine, VerifiedSqlObject};
    SqlAction::PostgresCreateIndex {
        object: VerifiedSqlObject {
            engine: SqlEngine::Postgres,
            database: "fixturedb".into(),
            schema: "fixture".into(),
            table: "orders".into(),
            object_id: 10,
            scope_sha256: digest(),
        },
        index: "helper_orders_status".into(),
        columns: vec![PlainIndexColumn {
            name: "status".into(),
            direction: SortDirection::Asc,
        }],
    }
}

fn typed(phase: PerformancePhase) -> TypedCompatibilitySnapshot {
    let mut indexes = vec![crate::helper::sql::benchmark::TypedIndexDefinition {
        name: "existing_index".into(),
        definition_sha256: digest(),
        marker_sha256: None,
        plain_nonunique_btree: false,
        columns: Vec::new(),
    }];
    if phase == PerformancePhase::AfterProduction {
        let SqlAction::PostgresCreateIndex { columns, .. } = approved_index() else {
            unreachable!()
        };
        indexes.push(crate::helper::sql::benchmark::TypedIndexDefinition {
            name: "helper_orders_status".into(),
            definition_sha256: "b".repeat(64),
            marker_sha256: Some("c".repeat(64)),
            plain_nonunique_btree: true,
            columns,
        });
    }
    TypedCompatibilitySnapshot {
        engine: crate::helper::sql::benchmark::CompatibilityEngine::Postgres,
        schema_sha256: digest(),
        settings: [
            "default_statistics_target",
            "effective_cache_size",
            "enable_indexscan",
            "enable_seqscan",
            "jit",
            "max_parallel_workers_per_gather",
            "random_page_cost",
            "search_path",
            "work_mem",
        ]
        .into_iter()
        .map(|s| (s.into(), "stable".into()))
        .collect(),
        indexes,
        statistics: vec![("status".into(), digest())],
        statistics_sha256: digest(),
        data_sha256: digest(),
    }
}

fn receipt(phase: PerformancePhase, values: Vec<f64>) -> PerformanceReceipt {
    let (median_ms, p95_ms, mad_ms) = summary(&values).unwrap();
    PerformanceReceipt {
        policy_version: 1,
        case_id: Uuid::from_u128(1),
        case_revision: 1,
        evidence_revision: 1,
        run: RunReference::GenericProduction {
            run_id: Uuid::from_u128(2),
            binding_sha256: digest(),
            production_receipt_sha256: if phase == PerformancePhase::AfterProduction {
                Some(digest())
            } else {
                None
            },
        },
        phase,
        captured_at: if phase == PerformancePhase::AfterProduction {
            Utc::now()
        } else {
            Utc::now() - chrono::Duration::seconds(60)
        },
        scope_sha256: digest(),
        workload_sha256: digest(),
        result_sha256: digest(),
        host_sha256: digest(),
        engine_sha256: digest(),
        build_sha256: digest(),
        dataset_sha256: digest(),
        session_sha256: digest(),
        live_metadata_sha256: digest(),
        typed_context: typed(phase),
        approved_action: if phase == PerformancePhase::AfterProduction {
            Some(approved_index())
        } else {
            None
        },
        approved_index_definition_sha256: (phase == PerformancePhase::AfterProduction)
            .then(|| "b".repeat(64)),
        approved_index_marker_sha256: (phase == PerformancePhase::AfterProduction)
            .then(|| "c".repeat(64)),
        approved_change_sha256: if phase == PerformancePhase::AfterProduction {
            Some(digest())
        } else {
            None
        },
        warmups: 3,
        samples_ms: values,
        median_ms,
        p95_ms,
        mad_ms,
    }
}

#[test]
fn production_samples_require_complete_exact_context_and_clear_noise_bands() {
    let before = receipt(PerformancePhase::BeforeProduction, vec![100.0; 15]);
    let after = receipt(PerformancePhase::AfterProduction, vec![60.0; 15]);
    let policy = ComparisonPolicy {
        maximum_median_ms: 80.0,
        maximum_p95_ms: 80.0,
    };
    assert_eq!(
        compare_performance(&before, &after, &policy),
        Comparison::Improvement
    );
    let noisy = receipt(PerformancePhase::AfterProduction, vec![92.0; 15]);
    assert_eq!(
        compare_performance(
            &before,
            &noisy,
            &ComparisonPolicy {
                maximum_median_ms: 110.0,
                maximum_p95_ms: 110.0
            }
        ),
        Comparison::Inconclusive
    );
    let mut drift = after.clone();
    drift.dataset_sha256 = "b".repeat(64);
    assert_eq!(
        compare_performance(&before, &drift, &policy),
        Comparison::Inconclusive
    );
    let mut unrelated_index = after.clone();
    unrelated_index.typed_context.indexes.push(
        crate::helper::sql::benchmark::TypedIndexDefinition {
            name: "unrelated_index".into(),
            definition_sha256: "c".repeat(64),
            marker_sha256: None,
            plain_nonunique_btree: false,
            columns: Vec::new(),
        },
    );
    assert_eq!(
        compare_performance(&before, &unrelated_index, &policy),
        Comparison::Inconclusive
    );
    let mut schema_drift = after.clone();
    schema_drift.typed_context.schema_sha256 = "c".repeat(64);
    assert_eq!(
        compare_performance(&before, &schema_drift, &policy),
        Comparison::Inconclusive
    );
    let mut setting_drift = after.clone();
    setting_drift.typed_context.settings[0].1 = "changed".into();
    assert_eq!(
        compare_performance(&before, &setting_drift, &policy),
        Comparison::Inconclusive
    );
    let mut short = after;
    short.samples_ms.pop();
    assert_eq!(
        compare_performance(&before, &short, &policy),
        Comparison::Inconclusive
    );
}

#[test]
fn invalid_samples_and_unbound_baseline_cannot_prove_improvement() {
    let before = receipt(PerformancePhase::BeforeProduction, vec![100.0; 15]);
    let mut after = receipt(PerformancePhase::AfterProduction, vec![50.0; 15]);
    let policy = ComparisonPolicy {
        maximum_median_ms: 60.0,
        maximum_p95_ms: 60.0,
    };
    after.samples_ms[0] = f64::NAN;
    assert_eq!(
        compare_performance(&before, &after, &policy),
        Comparison::Inconclusive
    );
    after = receipt(PerformancePhase::AfterProduction, vec![50.0; 15]);
    after.run = RunReference::GenericProduction {
        run_id: Uuid::from_u128(3),
        binding_sha256: digest(),
        production_receipt_sha256: Some(digest()),
    };
    assert_eq!(
        compare_performance(&before, &after, &policy),
        Comparison::Inconclusive
    );
}

#[test]
fn reviewed_nonrepair_resolutions_cannot_become_verified_repairs() {
    use crate::helper::case::{ProblemIntake, ResolutionReview};
    for outcome in [
        CaseResolution::DiagnosedNoChange,
        CaseResolution::ResolvedExternally,
        CaseResolution::ClosedUnresolved,
        CaseResolution::NeedsIntervention,
    ] {
        let mut case = HelperCase::new(ProblemIntake::default()).unwrap();
        case.record_resolution(ResolutionReview {
            outcome,
            reason: "Operator reviewed investigation".into(),
            coverage: "No verified production effect".into(),
            evidence_refs: Vec::new(),
            proof_sha256: None,
            proof_links: None,
            reviewed_at: Utc::now(),
        })
        .unwrap();
        assert_eq!(case.resolution(), Some(outcome));
        assert_ne!(
            case.resolution(),
            Some(CaseResolution::VerifiedRelayneRepair)
        );
        assert!(case.validate().is_ok());
        assert!(case
            .record_resolution(ResolutionReview {
                outcome: CaseResolution::VerifiedRelayneRepair,
                reason: "Attempted promotion".into(),
                coverage: "No actual proof".into(),
                evidence_refs: Vec::new(),
                proof_sha256: Some(digest()),
                proof_links: None,
                reviewed_at: Utc::now(),
            })
            .is_err());
    }
}

#[test]
fn three_real_http_targets_keep_failed_portal_separate_from_api() {
    use crate::helper_action::{CriterionRequirement, VerificationSpec};
    use crate::mission::Target;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let mut scopes = Vec::new();
    let mut servers = Vec::new();
    for status in [200, 200, 503] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        servers.push(std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = socket.read(&mut buffer);
            socket
                .write_all(
                    format!("HTTP/1.1 {status} Check\r\nContent-Length: 2\r\n\r\nok").as_bytes(),
                )
                .unwrap();
        }));
        scopes.push(BoundScope::Http {
            target: Target {
                profile_id: Uuid::new_v4(),
                name: "fixture".into(),
                host: "127.0.0.1".into(),
                port,
                protocol: "RDP".into(),
                username: "fixture".into(),
                domain: String::new(),
                route: String::new(),
            },
            port,
            tls: false,
            path: "/health".into(),
        });
    }
    let mut checks = Vec::new();
    let mut criteria = Vec::new();
    for (index, scope) in scopes.iter().enumerate() {
        let window = format!("target-{index}");
        checks.push(RequiredCheck::HttpFunctional {
            scope_sha256: scope.digest().unwrap(),
            expected_status: 200,
            body_sha256: Some(format!("{:x}", Sha256::digest(b"ok"))),
            window: window.clone(),
        });
        criteria.push(CriterionRequirement {
            measure: "HTTP status".into(),
            comparator: CriterionComparator::Equal,
            threshold_bits: 200f64.to_bits(),
            unit: "status".into(),
            window,
        });
    }
    checks.push(RequiredCheck::Performance {
        scope_sha256: digest(),
        object_id: 1,
        workload_sha256: digest(),
        maximum_median_ms: 100,
        maximum_p95_ms: 100,
        minimum_warmups: 3,
        minimum_samples: 15,
        window: "workload".into(),
    });
    criteria.push(CriterionRequirement {
        measure: "Median latency".into(),
        comparator: CriterionComparator::AtMost,
        threshold_bits: 100f64.to_bits(),
        unit: "ms".into(),
        window: "workload".into(),
    });
    let verification = VerificationSpec { checks, criteria };
    verification.validate().unwrap();
    let plan = VerificationPlan {
        case_id: Uuid::new_v4(),
        case_revision: 1,
        evidence_revision: 0,
        run: RunReference::GenericProduction {
            run_id: Uuid::new_v4(),
            binding_sha256: digest(),
            production_receipt_sha256: Some(digest()),
        },
        approved_verification_sha256: crate::helper_action::digest(
            b"relayne-helper-reviewed-verification-v2",
            &verification,
        )
        .unwrap(),
        verification,
        http_scopes: scopes,
        sql_targets: Vec::new(),
        captured_at: Utc::now(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime
        .block_on(run_checks(&plan, &plan.run, CancellationToken::new()))
        .unwrap();
    for server in servers {
        server.join().unwrap();
    }
    assert_eq!(result.checks[0].observed_http_status, Some(200));
    assert_eq!(result.checks[1].observed_http_status, Some(200));
    assert_eq!(result.checks[2].observed_http_status, Some(503));
    assert_eq!(result.checks[2].outcome, CheckOutcome::Failed);
    assert!(!result.all_passed());
}
