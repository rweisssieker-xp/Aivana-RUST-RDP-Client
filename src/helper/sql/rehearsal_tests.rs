use super::*;

#[test]
fn serialized_wave14_receipt_keeps_original_integrity_but_lacks_promotion_before_proof() {
    #[derive(serde::Serialize)]
    struct Wave14Receipt<'a> {
        schema: u16,
        receipt_id: Uuid,
        run_id: Uuid,
        approval_id: Uuid,
        consume_id: Uuid,
        binding_fingerprint: &'a str,
        case_id: Uuid,
        case_revision: u64,
        mapping_sha256: &'a str,
        production_scope_sha256: &'a str,
        production_physical_sha256: &'a str,
        staging_scope_sha256: &'a str,
        staging_physical_sha256: &'a str,
        action_sha256: &'a str,
        verification_sha256: &'a str,
        before_sha256: &'a str,
        after_sha256: &'a str,
        synthetic_data_sha256: &'a str,
        workload_result_sha256: &'a str,
        workload_before_median_ms: f64,
        workload_after_median_ms: f64,
        check_outcomes: &'a [SqlCheckOutcome],
        complete_native_compatibility: bool,
        created_index_id: Option<u64>,
        created_index_definition_sha256: &'a Option<String>,
        ownership_marker_sha256: &'a Option<String>,
        statistics_nonrestorable: bool,
        reviewed_limits: &'a str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        content_sha256: &'a str,
    }
    fn old_schema<'a>(receipt: &'a SqlRehearsalReceipt, hash: &'a str) -> Wave14Receipt<'a> {
        Wave14Receipt {
            schema: receipt.schema,
            receipt_id: receipt.receipt_id,
            run_id: receipt.run_id,
            approval_id: receipt.approval_id,
            consume_id: receipt.consume_id,
            binding_fingerprint: &receipt.binding_fingerprint,
            case_id: receipt.case_id,
            case_revision: receipt.case_revision,
            mapping_sha256: &receipt.mapping_sha256,
            production_scope_sha256: &receipt.production_scope_sha256,
            production_physical_sha256: &receipt.production_physical_sha256,
            staging_scope_sha256: &receipt.staging_scope_sha256,
            staging_physical_sha256: &receipt.staging_physical_sha256,
            action_sha256: &receipt.action_sha256,
            verification_sha256: &receipt.verification_sha256,
            before_sha256: &receipt.before_sha256,
            after_sha256: &receipt.after_sha256,
            synthetic_data_sha256: &receipt.synthetic_data_sha256,
            workload_result_sha256: &receipt.workload_result_sha256,
            workload_before_median_ms: receipt.workload_before_median_ms,
            workload_after_median_ms: receipt.workload_after_median_ms,
            check_outcomes: &receipt.check_outcomes,
            complete_native_compatibility: receipt.complete_native_compatibility,
            created_index_id: receipt.created_index_id,
            created_index_definition_sha256: &receipt.created_index_definition_sha256,
            ownership_marker_sha256: &receipt.ownership_marker_sha256,
            statistics_nonrestorable: receipt.statistics_nonrestorable,
            reviewed_limits: &receipt.reviewed_limits,
            created_at: receipt.created_at,
            expires_at: receipt.expires_at,
            content_sha256: hash,
        }
    }
    let mapping = mapping();
    let current = receipt(&mapping, false);
    let old_hash = digest(
        b"relayne-helper-sql-rehearsal-receipt-v2",
        &old_schema(&current, ""),
    )
    .unwrap();
    let old_wire = serde_json::to_vec(&old_schema(&current, &old_hash)).unwrap();
    assert!(!String::from_utf8_lossy(&old_wire).contains("production_before_sha256"));
    let old: SqlRehearsalReceipt = serde_json::from_slice(&old_wire).unwrap();
    old.validate(Utc::now()).unwrap();
    assert_eq!(old.content_sha256(), old_hash);
    assert!(old.production_before_sha256.is_none());
}

// Only fixed vocabulary crosses the guest evidence boundary. Native errors
// may contain SQL or connection details and are never serialized.
fn guest_failure_classification(error: &anyhow::Error) -> (&'static str, &'static str) {
    let chain: Vec<_> = error
        .chain()
        .map(std::string::ToString::to_string)
        .collect();
    let has = |needle: &str| chain.iter().any(|part| part.contains(needle));
    let stage = if has("PostcommitJournalRecord") {
        "PostcommitJournalRecord"
    } else if has("PostcommitReceiptIntegrity") {
        "PostcommitReceiptIntegrity"
    } else if has("PostcommitRequiredChecks") {
        "PostcommitRequiredChecks"
    } else if has("PostcommitComparison") {
        "PostcommitComparison"
    } else if has("PostcommitData") {
        "PostcommitData"
    } else if has("PostcommitWorkload") {
        "PostcommitWorkload"
    } else if has("SQL committed") {
        "PostcommitUnclassified"
    } else if has("Native dispatch") || has("Native SQL action") {
        "NativeAction"
    } else {
        "Precommit"
    };
    let class = if has("workload review expired") || has("SQL Server workload review expired") {
        "ReviewExpired"
    } else if has("deadline") || has("timed out") {
        "Deadline"
    } else if has("canceled") || has("cancelled") {
        "Canceled"
    } else if has("identity changed") || has("identity unavailable") || has("binding mismatch") {
        "IdentityDrift"
    } else if has("data changed") || has("result changed") || has("digest mismatch") {
        "DataDrift"
    } else if has("coverage incomplete") || has("compatibility incomplete") {
        "CoverageIncomplete"
    } else if has("outcome uncertain") {
        "NativeOutcomeUncertain"
    } else {
        "Other"
    };
    (stage, class)
}

#[test]
fn guest_failure_classification_is_allowlisted_and_uses_inner_cause() {
    let error = anyhow::Error::msg("workload review expired; secret=do-not-emit")
        .context("SQL committed; durable outcome needs intervention");
    assert_eq!(
        guest_failure_classification(&error),
        ("PostcommitUnclassified", "ReviewExpired")
    );
    let workload = anyhow::Error::msg("workload review expired; secret=do-not-emit")
        .context("PostcommitWorkload")
        .context("SQL committed; durable outcome needs intervention");
    assert_eq!(
        guest_failure_classification(&workload),
        ("PostcommitWorkload", "ReviewExpired")
    );
    for stage in [
        "PostcommitData",
        "PostcommitComparison",
        "PostcommitRequiredChecks",
        "PostcommitReceiptIntegrity",
        "PostcommitJournalRecord",
    ] {
        let error = anyhow::Error::msg("secret=do-not-emit").context(stage);
        assert_eq!(guest_failure_classification(&error), (stage, "Other"));
    }
    let unknown = anyhow::Error::msg("server detail: secret=do-not-emit");
    let (stage, class) = guest_failure_classification(&unknown);
    assert_eq!((stage, class), ("Precommit", "Other"));
    let exported = serde_json::to_string(&serde_json::json!({
        "FailureStage": stage,
        "FailureClass": class,
    }))
    .unwrap();
    assert!(!exported.contains("do-not-emit"));
    assert!(!exported.contains("server detail"));
}

/// Read-only postmortem for a prior guest attempt. Never dispatches a SQL action.
#[tokio::test]
#[ignore = "Requires the existing isolated Windows Sandbox and its guest-only fixture credentials"]
async fn guest_prior_rehearsal_read_only_reconcile() {
    use sha2::{Digest, Sha256};
    use tokio_postgres::Config;

    assert_eq!(
        std::env::var("RELAYNE_GUEST_PG_DIAGNOSTIC").ok().as_deref(),
        Some("1")
    );
    assert_eq!(
        std::env::var("USERNAME").ok().as_deref(),
        Some("WDAGUtilityAccount")
    );
    let dir = std::path::Path::new(r"C:\RelayneHelperRehearsal\app-data");
    let files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("task14-journal-") && name.ends_with(".dpapi"))
        })
        .collect();
    assert_eq!(files.len(), 1, "Expected exactly one prior Task-14 journal");
    let journal_path = &files[0];
    let protected = std::fs::read(journal_path).unwrap();
    let journal = crate::helper::journal::ActionJournal::load(journal_path).unwrap();
    assert_eq!(
        journal.intents().len(),
        1,
        "Expected one prior Task-14 intent"
    );
    let intent = &journal.intents()[0];
    let name = journal_path.file_name().unwrap().to_str().unwrap();
    assert_eq!(name, format!("task14-journal-{}.dpapi", intent.run_id));
    let receipt_path = crate::security::app_data_file(&format!(
        "relayne-helper-sql-rehearsal-{}.dpapi",
        intent.run_id
    ))
    .unwrap();
    let receipt_protected_sha256 = receipt_path.exists().then(|| {
        format!(
            "{:x}",
            Sha256::digest(std::fs::read(&receipt_path).unwrap())
        )
    });

    async fn snapshot(port: u16, database: &str, user: &str, password: &str) -> serde_json::Value {
        use sha2::{Digest, Sha256};
        let mut config = Config::new();
        config
            .host("127.0.0.1")
            .port(port)
            .dbname(database)
            .user(user)
            .password(password)
            .application_name("task14-read-only-reconcile")
            .ssl_mode(tokio_postgres::config::SslMode::Require);
        let tls = postgres_native_tls::MakeTlsConnector::new(
            native_tls::TlsConnector::builder().build().unwrap(),
        );
        let (client, connection) = config.connect(tls).await.unwrap();
        let connection_task = tokio::spawn(async move { connection.await.unwrap() });
        client.batch_execute("BEGIN READ ONLY").await.unwrap();
        let row = client
            .query_one(
                "SELECT c.oid::bigint, s.analyze_count::bigint, s.last_analyze::text, \
             (SELECT count(*)::bigint FROM pg_index i WHERE i.indrelid = c.oid) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             JOIN pg_stat_all_tables s ON s.relid = c.oid \
             WHERE n.nspname = 'fixture' AND c.relname = 'orders'",
                &[],
            )
            .await
            .unwrap();
        let indexes = client
            .query(
                "SELECT i.indexrelid::bigint, pg_get_indexdef(i.indexrelid), \
             coalesce(obj_description(i.indexrelid, 'pg_class'), '') \
             FROM pg_index i WHERE i.indrelid = 'fixture.orders'::regclass \
             ORDER BY i.indexrelid",
                &[],
            )
            .await
            .unwrap();
        let stats = client
            .query_one(
                "SELECT count(*)::bigint, \
             max(octet_length(coalesce(most_common_vals::text, '')))::bigint, \
             max(octet_length(coalesce(histogram_bounds::text, '')))::bigint, \
             sum(octet_length(coalesce(most_common_vals::text, '')) + \
                 octet_length(coalesce(histogram_bounds::text, '')))::bigint \
             FROM pg_stats WHERE schemaname = 'fixture' AND tablename = 'orders'",
                &[],
            )
            .await
            .unwrap();
        let index_records: Vec<_> = indexes
            .iter()
            .map(|index| {
                let oid: i64 = index.get(0);
                let definition: String = index.get(1);
                let marker: String = index.get(2);
                serde_json::json!({
                    "Oid": oid,
                    "DefinitionSha256": format!("{:x}", Sha256::digest(definition.as_bytes())),
                    "MarkerSha256": format!("{:x}", Sha256::digest(marker.as_bytes())),
                    "HasMarker": !marker.is_empty()
                })
            })
            .collect();
        client.batch_execute("ROLLBACK").await.unwrap();
        drop(client);
        connection_task.await.unwrap();
        serde_json::json!({
            "Port": port,
            "ObjectOid": row.get::<_, i64>(0),
            "AnalyzeCount": row.get::<_, i64>(1),
            "LastAnalyze": row.get::<_, Option<String>>(2),
            "IndexCount": row.get::<_, i64>(3),
            "Indexes": index_records,
            "StatisticsRows": stats.get::<_, i64>(0),
            "MaxMostCommonValuesBytes": stats.get::<_, Option<i64>>(1),
            "MaxHistogramBoundsBytes": stats.get::<_, Option<i64>>(2),
            "TotalProjectedValueBytes": stats.get::<_, Option<i64>>(3)
        })
    }

    fn secret<'a>(contents: &'a str, key: &str) -> &'a str {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .expect("Guest fixture read credential unavailable")
    }
    let staging = std::fs::read_to_string(r"C:\RelayneHelperRehearsal\credentials.txt").unwrap();
    let production =
        std::fs::read_to_string(r"C:\RelayneHelperAcceptance\credentials.txt").unwrap();
    let staging_native = snapshot(
        55434,
        "relayne_helper_rehearsal",
        "relayne_rehearsal_reader",
        secret(&staging, "reader"),
    )
    .await;
    let production_native = snapshot(
        55433,
        "relayne_helper_acceptance",
        "relayne_fixture_reader",
        secret(&production, "reader"),
    )
    .await;
    let witness = serde_json::json!({
        "Stage": "task14-prior-attempt-read-only-reconciliation",
        "ProductAcceptance": false,
        "SqlMutationIssued": false,
        "PriorAction": "PostgresAnalyze",
        "RunId": intent.run_id,
        "IntentState": format!("{:?}", intent.state),
        "NativeAfterSha256": intent.native_after_sha256,
        "NativeReceiptSha256": intent.native_receipt_sha256,
        "JournalProtectedSha256": format!("{:x}", Sha256::digest(protected)),
        "ReceiptProtectedSha256": receipt_protected_sha256,
        "Staging": staging_native,
        "Production": production_native
    });
    std::fs::write(
        r"C:\FixtureEvidence\task14-prior-read-only-reconciliation-v1.json",
        serde_json::to_vec(&witness).unwrap(),
    )
    .unwrap();
}

fn d(letter: char) -> String {
    letter.to_string().repeat(64)
}

fn mapping() -> SqlTrialMapping {
    let now = Utc::now();
    SqlTrialMapping {
        case_id: Uuid::new_v4(),
        case_revision: 1,
        production_scope_sha256: d('a'),
        production_physical_sha256: d('b'),
        production_before_sha256: d('c'),
        staging_scope_sha256: d('d'),
        staging_read_scope_sha256: d('e'),
        staging_physical_sha256: d('f'),
        staging_before_sha256: d('1'),
        action_sha256: d('2'),
        verification_sha256: d('3'),
        template: ReviewedSelectTemplate::OrderSort,
        production_template_sha256: d('4'),
        staging_template_sha256: d('5'),
        synthetic_data_sha256: d('6'),
        reviewed_limits: "synthetic fixture only".into(),
        reviewed_at: now,
        expires_at: now + Duration::minutes(5),
    }
}

fn receipt(mapping: &SqlTrialMapping, statistics: bool) -> SqlRehearsalReceipt {
    let now = Utc::now();
    let check_outcomes = vec![
        SqlCheckOutcome {
            check: RequiredCheck::SqlFunctional {
                scope_sha256: d('1'),
                object_id: 1,
                expected_row_count: 100,
                window: "after change".into(),
            },
            criterion: CriterionRequirement {
                measure: "SQL row count".into(),
                comparator: CriterionComparator::Equal,
                threshold_bits: 100f64.to_bits(),
                unit: "rows".into(),
                window: "after change".into(),
            },
            observation: SqlCheckObservation::RowCount { rows: 100 },
            passed: true,
        },
        SqlCheckOutcome {
            check: RequiredCheck::Performance {
                scope_sha256: d('1'),
                object_id: 1,
                workload_sha256: d('2'),
                maximum_median_ms: 10,
                maximum_p95_ms: 20,
                minimum_warmups: 3,
                minimum_samples: 15,
                window: "after change".into(),
            },
            criterion: CriterionRequirement {
                measure: "Median latency".into(),
                comparator: CriterionComparator::AtMost,
                threshold_bits: 10f64.to_bits(),
                unit: "ms".into(),
                window: "after change".into(),
            },
            observation: SqlCheckObservation::Performance {
                median_ms: 8.0,
                p95_ms: 12.0,
                warmups: 3,
                samples: 15,
            },
            passed: true,
        },
    ];
    let mut receipt = SqlRehearsalReceipt {
        schema: RECEIPT_SCHEMA,
        receipt_id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        approval_id: Uuid::new_v4(),
        consume_id: Uuid::new_v4(),
        binding_fingerprint: d('9'),
        case_id: mapping.case_id,
        case_revision: mapping.case_revision,
        mapping_sha256: mapping.fingerprint().unwrap(),
        production_scope_sha256: mapping.production_scope_sha256.clone(),
        production_physical_sha256: mapping.production_physical_sha256.clone(),
        production_before_sha256: Some(mapping.production_before_sha256.clone()),
        staging_scope_sha256: mapping.staging_scope_sha256.clone(),
        staging_physical_sha256: mapping.staging_physical_sha256.clone(),
        action_sha256: mapping.action_sha256.clone(),
        verification_sha256: mapping.verification_sha256.clone(),
        before_sha256: mapping.staging_before_sha256.clone(),
        after_sha256: d('7'),
        synthetic_data_sha256: mapping.synthetic_data_sha256.clone(),
        workload_result_sha256: d('8'),
        workload_before_median_ms: 12.0,
        workload_after_median_ms: 8.0,
        check_outcomes,
        complete_native_compatibility: true,
        created_index_id: (!statistics).then_some(7),
        created_index_definition_sha256: (!statistics).then(|| d('9')),
        ownership_marker_sha256: (!statistics).then(|| d('a')),
        statistics_nonrestorable: statistics,
        reviewed_limits: mapping.reviewed_limits.clone(),
        created_at: now,
        expires_at: now + Duration::hours(1),
        content_sha256: String::new(),
    };
    receipt.content_sha256 = receipt.fingerprint().unwrap();
    receipt
}

#[test]
fn every_required_sql_check_uses_actual_rows_latency_and_criteria() {
    let receipt = receipt(&mapping(), false);
    let spec = VerificationSpec {
        checks: receipt
            .check_outcomes
            .iter()
            .map(|o| o.check.clone())
            .collect(),
        criteria: receipt
            .check_outcomes
            .iter()
            .map(|o| o.criterion.clone())
            .collect(),
    };
    let mut samples = benchmark::WorkloadSamples {
        policy_version: benchmark::POLICY_VERSION,
        case_id: Uuid::new_v4(),
        case_revision: 1,
        review_evidence_id: Uuid::new_v4(),
        review_content_sha256: d('a'),
        scope_sha256: d('b'),
        workload_fingerprint: d('2'),
        result_sha256: d('c'),
        environment_fingerprint: d('d'),
        live_metadata_sha256: d('e'),
        compatibility: benchmark::CompatibilityEvidence::native_complete(
            benchmark::CompatibilityEngine::Postgres,
            d('f'),
            d('f'),
        )
        .unwrap(),
        warmups: 3,
        milliseconds: vec![8.0; 15],
        median_ms: 8.0,
        p95_ms: 12.0,
        mad_ms: 0.0,
        approved_change_sha256: None,
    };
    let mut data = benchmark::FixtureDataObservation {
        sha256: d('a'),
        row_count: 100,
    };
    let evaluate = |data: &benchmark::FixtureDataObservation,
                    samples: &benchmark::WorkloadSamples,
                    spec: &VerificationSpec| {
        evaluate_required_checks(spec, &d('1'), 1, &d('2'), data, samples)
    };
    assert_eq!(evaluate(&data, &samples, &spec).unwrap().len(), 2);
    data.row_count = 99;
    assert!(evaluate(&data, &samples, &spec).is_err());
    data.row_count = 100;
    samples.p95_ms = 21.0;
    assert!(evaluate(&data, &samples, &spec).is_err());
    samples.p95_ms = 12.0;
    samples.median_ms = 11.0;
    assert!(evaluate(&data, &samples, &spec).is_err());
    samples.median_ms = 8.0;
    samples.milliseconds.truncate(14);
    assert!(evaluate(&data, &samples, &spec).is_err());
    samples.milliseconds.push(8.0);
    let mut changed_criteria = spec.clone();
    changed_criteria.criteria[1].threshold_bits = 7f64.to_bits();
    assert!(evaluate(&data, &samples, &changed_criteria).is_err());
    let mut partial = spec;
    partial.criteria.pop();
    assert!(evaluate(&data, &samples, &partial).is_err());
}

#[test]
fn mapping_requires_distinct_physical_database_and_exact_review_window() {
    let mapping = mapping();
    assert!(mapping.validate().is_ok());
    let mut alias = mapping.clone();
    alias.staging_physical_sha256 = alias.production_physical_sha256.clone();
    assert!(alias.validate().is_err());
    alias = mapping.clone();
    alias.staging_scope_sha256 = alias.production_scope_sha256.clone();
    assert!(alias.validate().is_err());
    alias = mapping.clone();
    alias.expires_at = alias.reviewed_at + Duration::minutes(6);
    assert!(alias.validate().is_err());
}

fn production_coverage_fixture() -> (SqlTrialMapping, SqlRehearsalReceipt, HelperProposal) {
    use crate::helper_action::{
        RestorationSpec, SqlAction, SqlEngine, StatisticsLimitation, VerifiedSqlColumn,
        VerifiedSqlMetadata, VerifiedSqlObject,
    };

    let mut mapping = mapping();
    let now = Utc::now();
    mapping.reviewed_at = now - Duration::minutes(6);
    mapping.expires_at = mapping.reviewed_at + Duration::minutes(5);
    let object = VerifiedSqlObject {
        engine: SqlEngine::Postgres,
        database: "fixture_db".into(),
        schema: "fixture".into(),
        table: "spill_events".into(),
        object_id: 1,
        scope_sha256: mapping.production_scope_sha256.clone(),
    };
    let action = SqlAction::PostgresAnalyze {
        object: object.clone(),
    };
    let mut checked = receipt(&mapping, true);
    let verification = VerificationSpec {
        checks: vec![
            RequiredCheck::SqlFunctional {
                scope_sha256: mapping.production_scope_sha256.clone(),
                object_id: 1,
                expected_row_count: 100,
                window: "after change".into(),
            },
            RequiredCheck::Performance {
                scope_sha256: mapping.production_scope_sha256.clone(),
                object_id: 1,
                workload_sha256: mapping.production_template_sha256.clone(),
                maximum_median_ms: 10,
                maximum_p95_ms: 20,
                minimum_warmups: 3,
                minimum_samples: 15,
                window: "after change".into(),
            },
        ],
        criteria: checked
            .check_outcomes
            .iter()
            .map(|outcome| outcome.criterion.clone())
            .collect(),
    };
    verification.validate().unwrap();
    mapping.action_sha256 = digest(b"relayne-helper-sql-action-v1", &action).unwrap();
    mapping.verification_sha256 =
        digest(b"relayne-helper-reviewed-verification-v2", &verification).unwrap();
    for (outcome, check) in checked.check_outcomes.iter_mut().zip(&verification.checks) {
        outcome.check = check.clone();
    }
    checked.mapping_sha256 = mapping.fingerprint().unwrap();
    checked.action_sha256 = mapping.action_sha256.clone();
    checked.verification_sha256 = mapping.verification_sha256.clone();
    checked.created_at = mapping.expires_at - Duration::minutes(1);
    checked.expires_at = checked.created_at + Duration::hours(1);
    checked.content_sha256 = checked.fingerprint().unwrap();
    let proposal = HelperProposal {
        case_id: mapping.case_id,
        case_revision: mapping.case_revision,
        recipe_id: Uuid::new_v4(),
        recipe_revision: 1,
        action_version: crate::helper_action::SQL_ACTION_VERSION,
        recipe_identity: d('a'),
        catalog_generation_sha256: d('b'),
        action: CatalogAction::Sql {
            action,
            metadata: VerifiedSqlMetadata {
                object,
                columns: vec![VerifiedSqlColumn {
                    name: "event_id".into(),
                    column_id: 1,
                    plain: true,
                }],
                existing_indexes: vec![],
                base_table: true,
                source_evidence_sha256: d('c'),
            },
        },
        verification,
        restoration: RestorationSpec::ManualOrUnavailable {
            limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly,
        },
        prerequisites: vec![],
        unverified_prerequisites: vec![],
        plan_sha256: d('d'),
        criteria_sha256: d('e'),
        evidence_ids: vec![],
        statistics_limit_acknowledged: true,
    };
    (mapping, checked, proposal)
}

#[test]
fn admitted_mapping_expiry_preserves_content_binding_and_receipt_hour() {
    let (mapping, checked, proposal) = production_coverage_fixture();
    let admitted_at = mapping.expires_at - Duration::milliseconds(1);
    let after_commit = mapping.expires_at + Duration::milliseconds(1);
    assert!(mapping.validate_at(admitted_at).is_ok());
    assert!(mapping.validate_at(after_commit).is_err());
    assert!(mapping.validate().is_err());
    assert_eq!(mapping.fingerprint().unwrap(), checked.mapping_sha256);
    assert!(checked.validate_for(&mapping, &proposal).is_ok());
}

#[test]
fn production_coverage_rejects_wrong_action_checks_before_and_acknowledgement() {
    use crate::helper_action::{SqlAction, VerifiedSqlObject};
    let (mapping, receipt, proposal) = production_coverage_fixture();
    let mut binding = crate::helper::journal::tests::permit().binding().clone();
    binding.case_id = mapping.case_id;
    binding.case_revision = mapping.case_revision;
    binding.scope_sha256 = mapping.production_scope_sha256.clone();
    binding.action = match &proposal.action {
        CatalogAction::Sql { action, .. } => action.clone(),
        _ => unreachable!(),
    };
    binding.verification_sha256 = receipt.verification_sha256.clone();
    binding.before_sha256 = mapping.production_before_sha256.clone();
    binding.statistics_limit_acknowledged = true;
    assert!(receipt
        .validate_production_coverage(mapping.case_id, mapping.case_revision, &proposal, &binding)
        .is_ok());

    let mut wrong_binding = binding.clone();
    wrong_binding.before_sha256 = d('9');
    assert!(receipt
        .validate_production_coverage(
            mapping.case_id,
            mapping.case_revision,
            &proposal,
            &wrong_binding
        )
        .is_err());
    wrong_binding = binding.clone();
    wrong_binding.action = SqlAction::PostgresAnalyze {
        object: VerifiedSqlObject {
            table: "another_table".into(),
            ..binding.action.object().clone()
        },
    };
    assert!(receipt
        .validate_production_coverage(
            mapping.case_id,
            mapping.case_revision,
            &proposal,
            &wrong_binding
        )
        .is_err());
    wrong_binding = binding.clone();
    wrong_binding.statistics_limit_acknowledged = false;
    assert!(receipt
        .validate_production_coverage(
            mapping.case_id,
            mapping.case_revision,
            &proposal,
            &wrong_binding
        )
        .is_err());

    let mut wrong_proposal = proposal.clone();
    wrong_proposal.verification.checks.pop();
    wrong_proposal.verification.criteria.pop();
    assert!(receipt
        .validate_production_coverage(
            mapping.case_id,
            mapping.case_revision,
            &wrong_proposal,
            &binding
        )
        .is_err());
    let mut wrong_proposal = proposal.clone();
    wrong_proposal.verification.criteria[0].threshold_bits = 101f64.to_bits();
    assert!(receipt
        .validate_production_coverage(
            mapping.case_id,
            mapping.case_revision,
            &wrong_proposal,
            &binding
        )
        .is_err());

    let mut old_receipt = receipt.clone();
    old_receipt.production_before_sha256 = None;
    old_receipt.content_sha256 = old_receipt.fingerprint().unwrap();
    assert!(old_receipt
        .validate_production_coverage(mapping.case_id, mapping.case_revision, &proposal, &binding)
        .is_err());
}

#[test]
fn receipt_rejects_partial_stale_tampered_or_wrong_action_evidence() {
    let mapping = mapping();
    let receipt = receipt(&mapping, false);
    assert!(receipt.validate(Utc::now()).is_ok());
    let mut bad = receipt.clone();
    bad.complete_native_compatibility = false;
    bad.content_sha256 = bad.fingerprint().unwrap();
    assert!(bad.validate(Utc::now()).is_err());
    bad = receipt.clone();
    bad.action_sha256 = d('b');
    assert!(bad.validate(Utc::now()).is_err());
    bad = receipt.clone();
    bad.created_index_id = None;
    bad.content_sha256 = bad.fingerprint().unwrap();
    assert!(bad.validate(Utc::now()).is_err());
    bad = receipt.clone();
    bad.statistics_nonrestorable = true;
    bad.content_sha256 = bad.fingerprint().unwrap();
    assert!(bad.validate(Utc::now()).is_err());
    assert!(receipt.validate(receipt.expires_at).is_err());
    assert!(self::receipt(&mapping, true).validate(Utc::now()).is_ok());
}

#[test]
fn protected_receipt_load_detects_tamper_and_wrong_run_path() {
    let receipt = receipt(&mapping(), false);
    let path = receipt.save().unwrap();
    assert_eq!(
        load_sql_rehearsal(&path).unwrap().content_sha256(),
        receipt.content_sha256()
    );
    let wrong_path = path.with_file_name(format!("wrong-{}.dpapi", Uuid::new_v4()));
    std::fs::copy(&path, &wrong_path).unwrap();
    assert!(load_sql_rehearsal(&wrong_path).is_err());
    std::fs::write(&path, b"tampered protected receipt").unwrap();
    assert!(load_sql_rehearsal(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&wrong_path).unwrap();
}

#[test]
fn journal_rejects_receipt_or_native_after_state_mismatch() {
    let permit = crate::helper::journal::tests::permit();
    let mut receipt = receipt(&mapping(), true);
    receipt.run_id = permit.binding().run_id;
    receipt.approval_id = permit.receipt().approval_id;
    receipt.consume_id = permit.receipt().consume_id;
    receipt.binding_fingerprint = permit.binding().fingerprint().unwrap();
    receipt.case_id = permit.binding().case_id;
    receipt.case_revision = permit.binding().case_revision;
    receipt.production_scope_sha256 = permit.binding().scope_sha256.clone();
    receipt.action_sha256 =
        digest(b"relayne-helper-sql-action-v1", &permit.binding().action).unwrap();
    receipt.before_sha256 = permit.binding().before_sha256.clone();
    receipt.content_sha256 = receipt.fingerprint().unwrap();
    let receipt_path = receipt.save().unwrap();

    let journal_path =
        std::env::temp_dir().join(format!("task14-exact-receipt-{}.dpapi", Uuid::new_v4()));
    let mut journal = ActionJournal::load(&journal_path).unwrap();
    let recorded_permit = crate::helper::approval::DispatchPermit::test_only(
        permit.binding().clone(),
        permit.receipt().clone(),
    );
    let intent_id = journal.record_intent(recorded_permit).unwrap();
    journal.mark_dispatch_started(intent_id).unwrap();
    let proof = changes::NativeActionProof::test_verified_from_permit(
        &permit,
        receipt.before_sha256.clone(),
        receipt.after_sha256.clone(),
    )
    .unwrap();
    let mut altered_receipt = receipt.clone();
    altered_receipt.consume_id = Uuid::new_v4();
    altered_receipt.content_sha256 = altered_receipt.fingerprint().unwrap();
    assert!(journal
        .record_native_outcome(intent_id, &proof, Some(&altered_receipt))
        .is_err());
    let altered_proof = changes::NativeActionProof::test_verified_from_permit(
        &permit,
        receipt.before_sha256.clone(),
        d('f'),
    )
    .unwrap();
    assert!(journal
        .record_native_outcome(intent_id, &altered_proof, Some(&receipt))
        .is_err());
    assert_eq!(
        ActionJournal::load(&journal_path).unwrap().intents()[0].state,
        IntentState::DispatchStarted
    );
    let event = journal
        .record_native_outcome(intent_id, &proof, Some(&receipt))
        .unwrap();
    assert_eq!(
        event.outcome,
        crate::helper_approval::ActionOutcomeV2::Verified
    );
    let _ = std::fs::remove_file(receipt_path);
    let _ = std::fs::remove_file(journal_path);
}

#[tokio::test]
#[ignore = "Requires isolated Windows Sandbox PostgreSQL 55433/55434 and guest-only credentials"]
async fn guest_reviewed_native_rehearsal_mints_protected_receipt() {
    use crate::helper::sql::templates::ReviewedSelectTemplate;
    use crate::helper::{
        capability::{ProbeAdapter, ProbeRequest},
        case::{CaseEdit, ProblemIntake},
        credentials::{save_scoped_at, PersistentSecretResolver},
        evidence::{EvidenceBinding, EvidenceStatus},
        manifest::{CapabilityId, ProbeParams},
        scope::CredentialScope,
        sql::{postgres::PostgresAdapter, types::SqlObservation},
    };
    use crate::helper_action::{
        CriterionComparator, CriterionRequirement, PlainIndexColumn, RestorationSpec,
        SortDirection, SqlAction, SqlEngine, VerificationSpec, VerifiedSqlColumn,
        VerifiedSqlMetadata, VerifiedSqlObject,
    };
    use crate::helper_approval::{
        ActionBindingV2, ActionProof, ConsumeReceiptV2, ACTION_BINDING_VERSION,
    };
    use crate::mission::Target;
    use crate::models::SecretCredential;

    assert_eq!(
        std::env::var("RELAYNE_GUEST_PG_NATIVE").ok().as_deref(),
        Some("1")
    );
    assert_eq!(
        std::env::var("USERNAME").ok().as_deref(),
        Some("WDAGUtilityAccount")
    );
    let production_secrets = std::fs::read_to_string(r"C:\RelayneHelperAcceptance\credentials.txt")
        .expect("Guest production credentials unavailable");
    let staging_secrets = std::fs::read_to_string(r"C:\RelayneHelperRehearsal\credentials.txt")
        .expect("Guest rehearsal credentials unavailable");
    fn secret<'a>(contents: &'a str, key: &str) -> &'a str {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .expect("Expected guest fixture role unavailable")
    }
    let vault = crate::security::app_data_file("credentials.scoped.dpapi").unwrap();
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "isolated fixture".into(),
        host: "127.0.0.1".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: "operator".into(),
        domain: String::new(),
        route: String::new(),
    };
    let make_scope =
        |port: u16, database: &str, purpose: CredentialPurpose, principal: &str, password: &str| {
            let mut scope = BoundScope::Database {
                target: target.clone(),
                engine: DatabaseEngine::Postgres,
                port,
                database: database.into(),
                schema: Some("fixture".into()),
                object: Some("orders".into()),
                credential: None,
            };
            let resource = scope.resource_digest().unwrap();
            let reference = save_scoped_at(
                &vault,
                &resource,
                purpose,
                SecretCredential {
                    username: principal.into(),
                    password: password.into(),
                    domain: String::new(),
                },
            )
            .unwrap();
            if let BoundScope::Database { credential, .. } = &mut scope {
                *credential = Some(CredentialScope {
                    reference: reference.id,
                    purpose: reference.purpose,
                    generation: reference.generation,
                    principal: reference.principal,
                    context: reference.context,
                    context_digest: reference.scope_digest,
                });
            }
            scope
        };
    let production_change = make_scope(
        55433,
        "relayne_helper_acceptance",
        CredentialPurpose::ControlledChange,
        "relayne_fixture_owner",
        secret(&production_secrets, "owner"),
    );
    let production_read = make_scope(
        55433,
        "relayne_helper_acceptance",
        CredentialPurpose::Read,
        "relayne_fixture_reader",
        secret(&production_secrets, "reader"),
    );
    let staging_change = make_scope(
        55434,
        "relayne_helper_rehearsal",
        CredentialPurpose::ControlledChange,
        "relayne_rehearsal_owner",
        secret(&staging_secrets, "owner"),
    );
    let staging_read = make_scope(
        55434,
        "relayne_helper_rehearsal",
        CredentialPurpose::Read,
        "relayne_rehearsal_reader",
        secret(&staging_secrets, "reader"),
    );
    let mut case = HelperCase::new(ProblemIntake::default()).unwrap();
    case.revise(case.revision(), CaseEdit::Profiles(vec![target.profile_id]))
        .unwrap();
    case.revise(
        case.revision(),
        CaseEdit::Scopes(vec![
            production_change.clone(),
            production_read.clone(),
            staging_change.clone(),
            staging_read.clone(),
        ]),
    )
    .unwrap();
    let request = ProbeRequest {
        binding: EvidenceBinding {
            case_id: case.id(),
            case_revision: case.revision(),
            request_id: Uuid::new_v4(),
            scope_sha256: production_read.digest().unwrap(),
            credential_scope_sha256: production_read.credential_scope_digest().unwrap(),
            run_id: None,
        },
        scope: production_read.clone(),
        capability_id: CapabilityId::SqlRead,
        capability_version: 1,
        params: ProbeParams::SqlRead {
            query_digest: crate::helper::sql::postgres::template_digest(),
        },
        requested_at: Utc::now(),
        deadline_secs: Some(15),
    };
    let output = PostgresAdapter
        .collect(
            &request,
            &PersistentSecretResolver::new().unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(output.status, EvidenceStatus::Complete);
    let evidence = crate::helper::worker::normalize(&request, output).unwrap();
    let object_id = evidence
        .sql_observations
        .iter()
        .find_map(|observation| match observation {
            SqlObservation::PostgresObject {
                schema,
                name,
                object_id,
                ..
            } if schema == "fixture" && name == "orders" => Some(*object_id),
            _ => None,
        })
        .expect("Native PostgreSQL object identity absent");
    let mut columns = evidence
        .sql_observations
        .iter()
        .filter_map(|observation| match observation {
            SqlObservation::PostgresColumn {
                object_id: id,
                column_id,
                name,
                plain,
            } if *id == object_id => Some(VerifiedSqlColumn {
                name: name.clone(),
                column_id: *column_id,
                plain: *plain,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    columns.sort_by_key(|column| column.column_id);
    let existing_indexes = evidence
        .sql_observations
        .iter()
        .filter_map(|observation| match observation {
            SqlObservation::Index { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let metadata = VerifiedSqlMetadata {
        object: VerifiedSqlObject {
            engine: SqlEngine::Postgres,
            database: "relayne_helper_acceptance".into(),
            schema: "fixture".into(),
            table: "orders".into(),
            object_id,
            scope_sha256: production_change.digest().unwrap(),
        },
        columns,
        existing_indexes,
        base_table: true,
        source_evidence_sha256: evidence.content_sha256.clone(),
    };
    let source_id = evidence.id;
    case.append_evidence(evidence).unwrap();
    let run_id = Uuid::new_v4();
    let action = SqlAction::PostgresCreateIndex {
        object: metadata.object.clone(),
        index: format!("idx_task14_receipt_{}", run_id.simple()),
        columns: vec![
            PlainIndexColumn {
                name: "customer_id".into(),
                direction: SortDirection::Asc,
            },
            PlainIndexColumn {
                name: "order_id".into(),
                direction: SortDirection::Asc,
            },
        ],
    };
    action.validate(&metadata).unwrap();
    let template = ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let functional = RequiredCheck::SqlFunctional {
        scope_sha256: production_read.digest().unwrap(),
        object_id,
        expected_row_count: 75_000,
        window: "after change".into(),
    };
    let performance = RequiredCheck::Performance {
        scope_sha256: production_read.digest().unwrap(),
        object_id,
        workload_sha256: template.fingerprint(&production_read).unwrap(),
        maximum_median_ms: 15_000,
        maximum_p95_ms: 15_000,
        minimum_warmups: 3,
        minimum_samples: 15,
        window: "after change".into(),
    };
    let verification = VerificationSpec {
        checks: vec![functional, performance],
        criteria: vec![
            CriterionRequirement {
                measure: "SQL row count".into(),
                comparator: CriterionComparator::Equal,
                threshold_bits: 75_000f64.to_bits(),
                unit: "rows".into(),
                window: "after change".into(),
            },
            CriterionRequirement {
                measure: "Median latency".into(),
                comparator: CriterionComparator::AtMost,
                threshold_bits: 15_000f64.to_bits(),
                unit: "ms".into(),
                window: "after change".into(),
            },
        ],
    };
    verification.validate().unwrap();
    let proposal = HelperProposal {
        case_id: case.id(),
        case_revision: case.revision(),
        recipe_id: Uuid::new_v4(),
        recipe_revision: 1,
        action_version: crate::helper_action::SQL_ACTION_VERSION,
        recipe_identity: d('a'),
        catalog_generation_sha256: d('b'),
        action: CatalogAction::Sql {
            action: action.clone(),
            metadata: metadata.clone(),
        },
        verification,
        restoration: RestorationSpec::VerifiedReversible {
            exact_index_sha256: digest(b"relayne-helper-exact-index-intent-v1", &action).unwrap(),
            ownership_scheme_sha256: digest(
                b"relayne-helper-index-ownership-scheme-v1",
                &"run-bound-index-comment",
            )
            .unwrap(),
        },
        prerequisites: vec![],
        unverified_prerequisites: vec![crate::helper::catalog::Prerequisite::IsolatedRehearsal],
        plan_sha256: d('c'),
        criteria_sha256: d('d'),
        evidence_ids: vec![source_id],
        statistics_limit_acknowledged: false,
    };
    let production = NativeDispatchProof::collect(&case, &proposal, CancellationToken::new())
        .await
        .unwrap();
    let mapping = SqlTrialMapping::review(
        &case,
        &proposal,
        &production,
        &staging_change.digest().unwrap(),
        "Synthetic fixture; distinct test-owned index with verified ownership marker",
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let now = Utc::now();
    let binding = ActionBindingV2 {
        version: ACTION_BINDING_VERSION,
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        run_id,
        run_kind: RunKind::Rehearsal,
        organization_sha256: d('e'),
        scope_sha256: production_change.digest().unwrap(),
        credential_scope_sha256: production_change.credential_scope_digest().unwrap(),
        action_version: crate::helper_action::SQL_ACTION_VERSION,
        action,
        metadata_sha256: production.native().metadata_sha256().to_owned(),
        before_sha256: production.native().before_sha256().to_owned(),
        plan_sha256: proposal.plan_sha256.clone(),
        verification_sha256: digest(
            b"relayne-helper-reviewed-verification-v2",
            &proposal.verification,
        )
        .unwrap(),
        proof: ActionProof::StagingReviewProof {
            review_id: Uuid::new_v4(),
            review_sha256: proposal.review_digest().unwrap(),
            mapping_sha256: mapping.fingerprint().unwrap(),
            staging_scope_sha256: mapping.staging_scope_sha256.clone(),
            staging_physical_sha256: mapping.staging_physical_sha256.clone(),
            expires_at: now + Duration::minutes(4),
        },
        restoration: proposal.restoration.clone(),
        statistics_limit_acknowledged: false,
        captured_at: now,
        expires_at: now + Duration::minutes(3),
    };
    binding.validate(Utc::now()).unwrap();
    let consume = ConsumeReceiptV2 {
        approval_id: Uuid::new_v4(),
        consume_id: Uuid::new_v4(),
        fingerprint: binding.fingerprint().unwrap(),
        organization_sha256: d('e'),
    };
    let journal_path = std::path::PathBuf::from(format!(
        r"C:\RelayneHelperRehearsal\app-data\task14-journal-{}.dpapi",
        binding.run_id
    ));
    let mut journal = ActionJournal::load(&journal_path).unwrap();
    let intent_id = journal
        .record_intent(DispatchPermit::test_only(binding.clone(), consume.clone()))
        .unwrap();
    journal.mark_dispatch_started(intent_id).unwrap();
    let run = run_sql_rehearsal(
        &mapping,
        DispatchPermit::test_only(binding, consume),
        intent_id,
        &case,
        &proposal,
        &journal_path,
        CancellationToken::new(),
    )
    .await;
    let receipt = match run {
        Ok(receipt) => receipt,
        Err(error) => {
            let (failure_stage, failure_class) = guest_failure_classification(&error);
            let journal_state = ActionJournal::load(&journal_path)
                .ok()
                .and_then(|journal| {
                    journal
                        .intents()
                        .iter()
                        .find(|intent| intent.id == intent_id)
                        .map(|intent| format!("{:?}", intent.state))
                })
                .unwrap_or_else(|| "Unavailable".into());
            let witness = serde_json::json!({
                "Stage": "task14-native-rehearsal-api-test",
                "ProductAcceptance": false,
                "TestOnlyAuthority": true,
                "ActualSqlRehearsalReceipt": false,
                "FailureStage": failure_stage,
                "FailureClass": failure_class,
                "JournalState": journal_state,
            });
            std::fs::write(
                r"C:\FixtureEvidence\task14-rehearsal-api-failure-v2.json",
                serde_json::to_vec(&witness).unwrap(),
            )
            .unwrap();
            panic!("Native rehearsal failed: {failure_stage}/{failure_class}");
        }
    };
    receipt.validate_for(&mapping, &proposal).unwrap();
    let mut changed_proposal = proposal.clone();
    if let RequiredCheck::SqlFunctional {
        expected_row_count, ..
    } = &mut changed_proposal.verification.checks[0]
    {
        *expected_row_count += 1;
    }
    assert!(receipt.validate_for(&mapping, &changed_proposal).is_err());
    let mut changed_receipt = receipt.clone();
    changed_receipt.check_outcomes[0].observation = SqlCheckObservation::RowCount { rows: 0 };
    changed_receipt.content_sha256 = changed_receipt.fingerprint().unwrap();
    assert!(changed_receipt.validate_for(&mapping, &proposal).is_err());
    let loaded = load_sql_rehearsal(&receipt.path().unwrap()).unwrap();
    assert_eq!(loaded.content_sha256(), receipt.content_sha256());
    let journal = ActionJournal::load(&journal_path).unwrap();
    assert!(journal.intents().iter().any(|intent| intent.id == intent_id
        && intent.state == IntentState::Verified
        && intent.native_receipt_sha256.as_deref() == Some(receipt.content_sha256())));
    // Bounded guest-to-host witness. No raw identifier, SQL, credential or
    // unprotected receipt leaves the guest fixture root.
    let witness = serde_json::json!({
        "Stage": "task14-native-rehearsal-api-test",
        "ProductAcceptance": false,
        "TestOnlyAuthority": true,
        "ActualSqlRehearsalReceipt": true,
        "RunId": receipt.run_id,
        "ReceiptSha256": receipt.content_sha256(),
        "JournalVerified": true,
    });
    std::fs::write(
        r"C:\FixtureEvidence\task14-rehearsal-api-witness-v2.json",
        serde_json::to_vec(&witness).unwrap(),
    )
    .unwrap();
}
