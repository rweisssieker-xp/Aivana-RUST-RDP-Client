use super::*;

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
    let mut receipt = SqlRehearsalReceipt {
        schema: RECEIPT_SCHEMA,
        receipt_id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        approval_id: Uuid::new_v4(),
        consume_id: Uuid::new_v4(),
        case_id: mapping.case_id,
        case_revision: mapping.case_revision,
        mapping_sha256: mapping.fingerprint().unwrap(),
        production_scope_sha256: mapping.production_scope_sha256.clone(),
        production_physical_sha256: mapping.production_physical_sha256.clone(),
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

#[tokio::test]
#[ignore = "Requires isolated Windows Sandbox PostgreSQL 55433/55434 and guest-only credentials"]
async fn guest_reviewed_native_rehearsal_mints_protected_receipt() {
    use crate::helper::sql::templates::ReviewedSelectTemplate;
    use crate::helper::{
        capability::{ProbeAdapter, ProbeRequest},
        case::{CaseEdit, ProblemIntake},
        credentials::{PersistentSecretResolver, save_scoped_at},
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
        ACTION_BINDING_VERSION, ActionBindingV2, ActionProof, ConsumeReceiptV2,
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
    let action = SqlAction::PostgresCreateIndex {
        object: metadata.object.clone(),
        index: "idx_task14_receipt_v1".into(),
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
        run_id: Uuid::new_v4(),
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
            let message = format!("{error:#}");
            let labels = [
                "Production native preflight changed",
                "Production synthetic data changed",
                "Staging native before-state changed",
                "Reviewed live SQL source no longer covers exact workload object",
                "Native baseline or staged data coverage incomplete",
                "Staged workload/result/coverage incomplete after action",
                "Native SQL action failed or outcome uncertain",
                "Native compatibility observations differ or are incomplete",
                "PostgreSQL index coverage incomplete",
                "PostgreSQL statistics coverage incomplete",
                "PostgreSQL fixture identity changed",
                "PostgreSQL fixture column identity changed",
                "workload review expired",
                "workload deadline exceeded",
                "workload result changed",
                "SQL committed",
            ];
            let label = labels
                .into_iter()
                .find(|label| message.contains(label))
                .unwrap_or("Other native rehearsal failure");
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
                "FailureLabel": label,
                "JournalState": journal_state,
            });
            std::fs::write(
                r"C:\FixtureEvidence\task14-rehearsal-api-failure-v1.json",
                serde_json::to_vec(&witness).unwrap(),
            )
            .unwrap();
            panic!("Native rehearsal failed: {label}");
        }
    };
    receipt.validate_for(&mapping, &proposal).unwrap();
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
        r"C:\FixtureEvidence\task14-rehearsal-api-witness-v1.json",
        serde_json::to_vec(&witness).unwrap(),
    )
    .unwrap();
}
