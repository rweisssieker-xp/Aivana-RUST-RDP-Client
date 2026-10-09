use super::*;
use crate::helper::scope::CredentialScope;
use crate::helper_action::{PlainIndexColumn, VerifiedSqlObject};
use crate::mission::Target;
use uuid::Uuid;

#[tokio::test]
async fn missing_mismatched_or_corrupt_started_intent_makes_zero_target_contacts() {
    use crate::helper_action::{RestorationSpec, SQL_ACTION_VERSION, StatisticsLimitation};
    use crate::helper_approval::{
        ACTION_BINDING_VERSION, ActionBindingV2, ActionProof, ConsumeReceiptV2,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let scope = BoundScope::Database {
        target: Target {
            profile_id: Uuid::new_v4(),
            name: "intent gate".into(),
            host: "127.0.0.1".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: "operator".into(),
            domain: String::new(),
            route: String::new(),
        },
        engine: DatabaseEngine::Postgres,
        port,
        database: "relayne_helper_rehearsal".into(),
        schema: Some("fixture".into()),
        object: Some("orders".into()),
        credential: None,
    };
    let object = VerifiedSqlObject {
        engine: SqlEngine::Postgres,
        database: "relayne_helper_rehearsal".into(),
        schema: "fixture".into(),
        table: "orders".into(),
        object_id: 1,
        scope_sha256: scope.digest().unwrap(),
    };
    let action = SqlAction::PostgresAnalyze {
        object: object.clone(),
    };
    let metadata = VerifiedSqlMetadata {
        object,
        columns: vec![],
        existing_indexes: vec![],
        base_table: true,
        source_evidence_sha256: "a".repeat(64),
    };
    let now = Utc::now();
    let binding = ActionBindingV2 {
        version: ACTION_BINDING_VERSION,
        case_id: Uuid::new_v4(),
        case_revision: 1,
        evidence_revision: 1,
        run_id: Uuid::new_v4(),
        run_kind: RunKind::Rehearsal,
        organization_sha256: "a".repeat(64),
        scope_sha256: scope.digest().unwrap(),
        credential_scope_sha256: scope.credential_scope_digest().unwrap(),
        action_version: SQL_ACTION_VERSION,
        action: action.clone(),
        metadata_sha256: digest(b"relayne-helper-sql-metadata-v2", &metadata).unwrap(),
        before_sha256: "b".repeat(64),
        plan_sha256: "c".repeat(64),
        verification_sha256: "d".repeat(64),
        proof: ActionProof::StagingReviewProof {
            review_id: Uuid::new_v4(),
            review_sha256: "e".repeat(64),
            mapping_sha256: "f".repeat(64),
            staging_scope_sha256: scope.digest().unwrap(),
            staging_physical_sha256: "1".repeat(64),
            expires_at: now + chrono::Duration::minutes(5),
        },
        restoration: RestorationSpec::ManualOrUnavailable {
            limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly,
        },
        statistics_limit_acknowledged: true,
        captured_at: now,
        expires_at: now + chrono::Duration::minutes(3),
    };
    let receipt = ConsumeReceiptV2 {
        approval_id: Uuid::new_v4(),
        consume_id: Uuid::new_v4(),
        fingerprint: binding.fingerprint().unwrap(),
        organization_sha256: binding.organization_sha256.clone(),
    };
    let trial = NativeTrialTarget {
        preflight: NativePreflight {
            state: NativeState {
                engine: SqlEngine::Postgres,
                physical_instance: "fixture".into(),
                database: "relayne_helper_rehearsal".into(),
                database_id: 1,
                schema: "fixture".into(),
                schema_id: 1,
                table: "orders".into(),
                object_id: 1,
                principal: "reader".into(),
                version: "test".into(),
                columns: vec![],
                indexes: vec![],
                statistics: String::new(),
                grants: vec![],
                configuration: vec![],
            },
            metadata_sha256: binding.metadata_sha256.clone(),
            before_sha256: binding.before_sha256.clone(),
            credential_scope_sha256: binding.credential_scope_sha256.clone(),
            observed_at: now,
        },
        action,
        metadata,
    };
    let journal_path =
        std::env::temp_dir().join(format!("task14-missing-intent-{}.dpapi", Uuid::new_v4()));
    let permit = || DispatchPermit::test_only(binding.clone(), receipt.clone());
    let missing = execute_sql_change(
        permit(),
        Uuid::new_v4(),
        &journal_path,
        &scope,
        &trial,
        CancellationToken::new(),
    )
    .await
    .err()
    .unwrap();
    assert!(missing.to_string().contains("Durable native intent"));
    let mut journal = ActionJournal::load(&journal_path).unwrap();
    let id = journal.record_intent(permit()).unwrap();
    journal.mark_dispatch_started(id).unwrap();
    let mismatch = execute_sql_change(
        permit(),
        Uuid::new_v4(),
        &journal_path,
        &scope,
        &trial,
        CancellationToken::new(),
    )
    .await
    .err()
    .unwrap();
    assert!(mismatch.to_string().contains("Durable native intent"));
    std::fs::write(&journal_path, b"corrupt protected journal").unwrap();
    assert!(
        execute_sql_change(
            permit(),
            id,
            &journal_path,
            &scope,
            &trial,
            CancellationToken::new(),
        )
        .await
        .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    let _ = std::fs::remove_file(journal_path);
}

async fn execute_with_started_test_intent(
    permit: DispatchPermit,
    scope: &BoundScope,
    trial: &NativeTrialTarget,
) -> Result<NativeActionProof> {
    let journal_path = crate::security::app_data_file(&format!(
        "task14-native-journal-{}.dpapi",
        permit.binding().run_id
    ))?;
    let mut journal = ActionJournal::load(&journal_path)?;
    let recorded = DispatchPermit::test_only(permit.binding().clone(), permit.receipt().clone());
    let intent_id = journal.record_intent(recorded)?;
    journal.mark_dispatch_started(intent_id)?;
    let proof = execute_sql_change(
        permit,
        intent_id,
        &journal_path,
        scope,
        trial,
        CancellationToken::new(),
    )
    .await?;
    journal.record_native_outcome(intent_id, &proof, None)?;
    Ok(proof)
}

#[test]
fn shared_native_failure_state_requires_ack_and_preserves_commit_ambiguity() {
    assert_eq!(
        failed_native_outcome(false, true),
        NativeActionState::Failed
    );
    assert_eq!(
        failed_native_outcome(false, false),
        NativeActionState::OutcomeUnknown
    );
    assert_eq!(
        failed_native_outcome(true, true),
        NativeActionState::OutcomeUnknown
    );
}

#[tokio::test]
#[ignore = "Runs only inside the attested isolated Windows Sandbox PostgreSQL 55434 guest"]
async fn guest_native_rehearsal_executor_rolls_back_drift_and_marks_created_index() {
    use crate::helper::credentials::save_scoped_at;
    use crate::helper_action::{RestorationSpec, SQL_ACTION_VERSION};
    use crate::helper_approval::{
        ACTION_BINDING_VERSION, ActionBindingV2, ActionProof, ConsumeReceiptV2,
    };
    use crate::models::SecretCredential;

    assert_eq!(
        std::env::var("RELAYNE_GUEST_PG_NATIVE").ok().as_deref(),
        Some("1")
    );
    assert_eq!(
        std::env::var("USERNAME").ok().as_deref(),
        Some("WDAGUtilityAccount")
    );
    let credentials = std::fs::read_to_string(r"C:\RelayneHelperRehearsal\credentials.txt")
        .expect("Guest rehearsal credentials unavailable");
    let password = credentials
        .lines()
        .find_map(|line| line.strip_prefix("owner="))
        .expect("Guest rehearsal owner unavailable");
    let mut scope = BoundScope::Database {
        target: Target {
            profile_id: Uuid::new_v4(),
            name: "isolated rehearsal".into(),
            host: "127.0.0.1".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: "operator".into(),
            domain: String::new(),
            route: String::new(),
        },
        engine: DatabaseEngine::Postgres,
        port: 55434,
        database: "relayne_helper_rehearsal".into(),
        schema: Some("fixture".into()),
        object: Some("orders".into()),
        credential: None,
    };
    let resource = scope.resource_digest().unwrap();
    let vault = crate::security::app_data_file("credentials.scoped.dpapi").unwrap();
    let reference = save_scoped_at(
        &vault,
        &resource,
        CredentialPurpose::ControlledChange,
        SecretCredential {
            username: "relayne_rehearsal_owner".into(),
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
    let (client, driver, _) = pg_connection(&scope).await.unwrap();
    let initial = pg_state(&client, &scope).await.unwrap();
    assert!(initial.physical_instance.len() <= 32);
    assert_eq!(initial.database, "relayne_helper_rehearsal");
    assert_eq!(initial.schema, "fixture");
    assert_eq!(initial.table, "orders");
    assert_eq!(initial.grants.iter().all(|granted| *granted), true);
    // Recollect both clusters through the product's native fixture reader.
    // Equal TLS certificates or equal database OIDs cannot stand in for the
    // independently observed PostgreSQL system identifiers.
    let production_credentials =
        std::fs::read_to_string(r"C:\RelayneHelperAcceptance\credentials.txt")
            .expect("Guest production fixture credentials unavailable");
    let production_password = production_credentials
        .lines()
        .find_map(|line| line.strip_prefix("reader="))
        .expect("Guest production fixture reader unavailable");
    let staging_reader_password = credentials
        .lines()
        .find_map(|line| line.strip_prefix("reader="))
        .expect("Guest staging fixture reader unavailable");
    let make_read_scope = |database: &str, port: u16, principal: &str, secret: &str| {
        let mut read_scope = scope.clone();
        if let BoundScope::Database {
            database: db,
            port: p,
            credential,
            ..
        } = &mut read_scope
        {
            *db = database.into();
            *p = port;
            *credential = None;
        }
        let resource = read_scope.resource_digest().unwrap();
        let reference = save_scoped_at(
            &vault,
            &resource,
            CredentialPurpose::Read,
            SecretCredential {
                username: principal.into(),
                password: secret.into(),
                domain: String::new(),
            },
        )
        .unwrap();
        if let BoundScope::Database { credential, .. } = &mut read_scope {
            *credential = Some(CredentialScope {
                reference: reference.id,
                purpose: reference.purpose,
                generation: reference.generation,
                principal: reference.principal,
                context: reference.context,
                context_digest: reference.scope_digest,
            });
        }
        read_scope
    };
    let production_read = make_read_scope(
        "relayne_helper_acceptance",
        55433,
        "relayne_fixture_reader",
        production_password,
    );
    let staging_read = make_read_scope(
        "relayne_helper_rehearsal",
        55434,
        "relayne_rehearsal_reader",
        staging_reader_password,
    );
    let template = crate::helper::sql::templates::ReviewedSelectTemplate::CustomerOrders {
        customer_id: 424242,
    };
    let production_session = crate::helper::sql::templates::connect_fixture(
        &production_read,
        template,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let production_system_id: String = production_session
        .client
        .query_one(
            "SELECT system_identifier::text FROM pg_control_system()",
            &[],
        )
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_ne!(production_system_id, initial.physical_instance);
    drop(production_session);
    let production_data = crate::helper::sql::benchmark::fixture_data_digest(
        &production_read,
        template,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let staging_data = crate::helper::sql::benchmark::fixture_data_digest(
        &staging_read,
        template,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(production_data, staging_data);
    let index = format!("idx_rel14_{}", &Uuid::new_v4().simple().to_string()[..8]);
    assert!(
        !initial
            .indexes
            .iter()
            .any(|existing| existing.name == index)
    );
    let object = VerifiedSqlObject {
        engine: SqlEngine::Postgres,
        database: initial.database.clone(),
        schema: initial.schema.clone(),
        table: initial.table.clone(),
        object_id: initial.object_id,
        scope_sha256: scope.digest().unwrap(),
    };
    let metadata = VerifiedSqlMetadata {
        object: object.clone(),
        columns: initial
            .columns
            .iter()
            .map(|column| VerifiedSqlColumn {
                name: column.name.clone(),
                column_id: column.id,
                plain: column.plain,
            })
            .collect(),
        existing_indexes: initial
            .indexes
            .iter()
            .map(|index| index.name.clone())
            .collect(),
        base_table: true,
        source_evidence_sha256: "a".repeat(64),
    };
    let action = SqlAction::PostgresCreateIndex {
        object,
        index: index.clone(),
        columns: vec![PlainIndexColumn {
            name: "customer_id".into(),
            direction: SortDirection::Asc,
        }],
    };
    let now = Utc::now();
    let make_permit = |action: &SqlAction, before_sha256: String| {
        let binding = ActionBindingV2 {
            version: ACTION_BINDING_VERSION,
            case_id: Uuid::new_v4(),
            case_revision: 1,
            evidence_revision: 1,
            run_id: Uuid::new_v4(),
            run_kind: RunKind::Rehearsal,
            organization_sha256: "a".repeat(64),
            scope_sha256: scope.digest().unwrap(),
            credential_scope_sha256: scope.credential_scope_digest().unwrap(),
            action_version: SQL_ACTION_VERSION,
            action: action.clone(),
            metadata_sha256: "b".repeat(64),
            before_sha256,
            plan_sha256: "c".repeat(64),
            verification_sha256: "d".repeat(64),
            proof: ActionProof::StagingReviewProof {
                review_id: Uuid::new_v4(),
                review_sha256: "e".repeat(64),
                mapping_sha256: "f".repeat(64),
                staging_scope_sha256: scope.digest().unwrap(),
                staging_physical_sha256: "1".repeat(64),
                expires_at: now + chrono::Duration::minutes(5),
            },
            restoration: RestorationSpec::VerifiedReversible {
                exact_index_sha256: "2".repeat(64),
                ownership_scheme_sha256: "3".repeat(64),
            },
            statistics_limit_acknowledged: false,
            captured_at: now,
            expires_at: now + chrono::Duration::minutes(3),
        };
        let receipt = ConsumeReceiptV2 {
            approval_id: Uuid::new_v4(),
            consume_id: Uuid::new_v4(),
            fingerprint: binding.fingerprint().unwrap(),
            organization_sha256: "a".repeat(64),
        };
        DispatchPermit::test_only(binding, receipt)
    };
    let original_sha = digest(b"relayne-helper-native-sql-before-v1", &initial).unwrap();
    let make_trial = |state: NativeState,
                      before_sha256: String,
                      action: &SqlAction,
                      metadata: &VerifiedSqlMetadata| NativeTrialTarget {
        preflight: NativePreflight {
            state,
            metadata_sha256: digest(b"relayne-helper-sql-metadata-v2", metadata).unwrap(),
            before_sha256,
            credential_scope_sha256: scope.credential_scope_digest().unwrap(),
            observed_at: Utc::now(),
        },
        action: action.clone(),
        metadata: metadata.clone(),
    };
    let drift_trial = make_trial(initial, "0".repeat(64), &action, &metadata);
    let drift = execute_with_started_test_intent(
        make_permit(&action, "0".repeat(64)),
        &scope,
        &drift_trial,
    )
    .await
    .unwrap();
    assert_eq!(drift.state, NativeActionState::Failed);
    let fresh = pg_state(&client, &scope).await.unwrap();
    assert!(!fresh.indexes.iter().any(|existing| existing.name == index));
    assert_eq!(
        digest(b"relayne-helper-native-sql-before-v1", &fresh).unwrap(),
        original_sha
    );
    let trial = make_trial(fresh, original_sha, &action, &metadata);
    arm_guest_native_fault(NativeFaultPhase::PgMarker);
    let marker_failure = execute_with_started_test_intent(
        make_permit(&action, trial.preflight.before_sha256.clone()),
        &scope,
        &trial,
    )
    .await
    .unwrap();
    assert_eq!(marker_failure.state, NativeActionState::Failed);
    let after_marker_failure = pg_state(&client, &scope).await.unwrap();
    assert!(
        !after_marker_failure
            .indexes
            .iter()
            .any(|existing| existing.name == index)
    );
    assert_eq!(
        digest(
            b"relayne-helper-native-sql-before-v1",
            &after_marker_failure
        )
        .unwrap(),
        trial.preflight.before_sha256,
    );
    let applied = execute_with_started_test_intent(
        make_permit(&action, trial.preflight.before_sha256.clone()),
        &scope,
        &trial,
    )
    .await
    .unwrap();
    assert_eq!(applied.state, NativeActionState::Verified);
    assert!(applied.created_index_id.is_some());
    assert!(applied.ownership_marker_sha256.is_some());
    let final_state = pg_state(&client, &scope).await.unwrap();
    let created = final_state
        .indexes
        .iter()
        .find(|candidate| candidate.name == index)
        .unwrap();
    assert!(
        created.valid
            && created
                .ownership
                .as_deref()
                .is_some_and(|marker| marker.starts_with("Relayne.CreatedByRunV1:"))
    );
    let unknown_index = format!(
        "idx_rel14_unknown_{}",
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let unknown_action = SqlAction::PostgresCreateIndex {
        object: metadata.object.clone(),
        index: unknown_index.clone(),
        columns: vec![PlainIndexColumn {
            name: "order_id".into(),
            direction: SortDirection::Asc,
        }],
    };
    let unknown_metadata = VerifiedSqlMetadata {
        existing_indexes: final_state
            .indexes
            .iter()
            .map(|index| index.name.clone())
            .collect(),
        ..metadata.clone()
    };
    let unknown_before_sha = digest(b"relayne-helper-native-sql-before-v1", &final_state).unwrap();
    let unknown_trial = make_trial(
        final_state,
        unknown_before_sha,
        &unknown_action,
        &unknown_metadata,
    );
    arm_guest_native_fault(NativeFaultPhase::PgCommittedReadback);
    let ambiguous_commit = execute_with_started_test_intent(
        make_permit(
            &unknown_action,
            unknown_trial.preflight.before_sha256.clone(),
        ),
        &scope,
        &unknown_trial,
    )
    .await
    .unwrap();
    assert_eq!(ambiguous_commit.state, NativeActionState::OutcomeUnknown);
    assert!(ambiguous_commit.after_sha256.is_none());
    let after_ambiguous_commit = pg_state(&client, &scope).await.unwrap();
    assert!(
        after_ambiguous_commit
            .indexes
            .iter()
            .any(|candidate| candidate.name == unknown_index
                && candidate.valid
                && candidate.ownership.is_some())
    );
    driver.abort();
}

fn fixture(engine: SqlEngine, schema: &str, table: &str) -> (BoundScope, VerifiedSqlMetadata) {
    let mut scope = BoundScope::Database {
        target: Target {
            profile_id: Uuid::new_v4(),
            name: "fixture".into(),
            host: "127.0.0.1".into(),
            port: 3389,
            protocol: "RDP".into(),
            username: "operator".into(),
            domain: String::new(),
            route: String::new(),
        },
        engine: if engine == SqlEngine::Postgres {
            DatabaseEngine::Postgres
        } else {
            DatabaseEngine::SqlServer
        },
        port: if engine == SqlEngine::Postgres {
            55434
        } else {
            1433
        },
        database: "relayne_helper_rehearsal".into(),
        schema: Some(schema.into()),
        object: Some(table.into()),
        credential: None,
    };
    let resource = scope.resource_digest().unwrap();
    if let BoundScope::Database { credential, .. } = &mut scope {
        *credential = Some(CredentialScope {
            reference: Uuid::new_v4(),
            purpose: CredentialPurpose::ControlledChange,
            generation: 1,
            principal: "owner".into(),
            context: "fixture".into(),
            context_digest: resource,
        });
    }
    let object = VerifiedSqlObject {
        engine,
        database: "relayne_helper_rehearsal".into(),
        schema: schema.into(),
        table: table.into(),
        object_id: 42,
        scope_sha256: scope.digest().unwrap(),
    };
    let metadata = VerifiedSqlMetadata {
        object,
        columns: vec![VerifiedSqlColumn {
            name: if engine == SqlEngine::Postgres {
                "col\"umn"
            } else {
                "col]umn"
            }
            .into(),
            column_id: 1,
            plain: true,
        }],
        existing_indexes: vec![],
        base_table: true,
        source_evidence_sha256: "a".repeat(64),
    };
    (scope, metadata)
}

fn create(metadata: &VerifiedSqlMetadata) -> SqlAction {
    let columns = vec![PlainIndexColumn {
        name: metadata.columns[0].name.clone(),
        direction: SortDirection::Desc,
    }];
    match metadata.object.engine {
        SqlEngine::Postgres => SqlAction::PostgresCreateIndex {
            object: metadata.object.clone(),
            index: "idx_rehearsal".into(),
            columns,
        },
        SqlEngine::SqlServer => SqlAction::SqlServerCreateIndex {
            object: metadata.object.clone(),
            index: "idx_rehearsal".into(),
            columns,
        },
    }
}

#[test]
fn closed_builders_quote_identifiers_and_cover_four_forms() {
    let (pg_scope, pg_meta) = fixture(SqlEngine::Postgres, "fi\"xture", "ord\"ers");
    let pg = prepare_sql_change(&create(&pg_meta), &pg_scope, &pg_meta).unwrap();
    let PreparedOperation::PgCreate { statement, .. } = pg.operation else {
        panic!("wrong form")
    };
    assert_eq!(
        statement,
        "CREATE INDEX \"idx_rehearsal\" ON \"fi\"\"xture\".\"ord\"\"ers\" USING btree (\"col\"\"umn\" DESC)"
    );
    let analyze = SqlAction::PostgresAnalyze {
        object: pg_meta.object.clone(),
    };
    let PreparedOperation::PgAnalyze { statement } =
        prepare_sql_change(&analyze, &pg_scope, &pg_meta)
            .unwrap()
            .operation
    else {
        panic!("wrong form")
    };
    assert_eq!(statement, "ANALYZE \"fi\"\"xture\".\"ord\"\"ers\"");

    let (tds_scope, tds_meta) = fixture(SqlEngine::SqlServer, "fi]xture", "ord]ers");
    let PreparedOperation::TdsCreate { statement, .. } =
        prepare_sql_change(&create(&tds_meta), &tds_scope, &tds_meta)
            .unwrap()
            .operation
    else {
        panic!("wrong form")
    };
    assert_eq!(
        statement,
        "CREATE NONCLUSTERED INDEX [idx_rehearsal] ON [fi]]xture].[ord]]ers] ([col]]umn] DESC)"
    );
    let update = SqlAction::SqlServerUpdateStatistics {
        object: tds_meta.object.clone(),
    };
    let PreparedOperation::TdsUpdate { statement } =
        prepare_sql_change(&update, &tds_scope, &tds_meta)
            .unwrap()
            .operation
    else {
        panic!("wrong form")
    };
    assert_eq!(statement, "UPDATE STATISTICS [fi]]xture].[ord]]ers]");
}

#[test]
fn builder_rejects_unreviewed_target_grant_shape_and_index_collision() {
    let (scope, metadata) = fixture(SqlEngine::Postgres, "fixture", "orders");
    let action = create(&metadata);
    let mut bad = metadata.clone();
    bad.columns.clear();
    assert!(prepare_sql_change(&action, &scope, &bad).is_err());
    bad = metadata.clone();
    bad.columns.extend((2..=6).map(|id| VerifiedSqlColumn {
        name: format!("extra{id}"),
        column_id: id,
        plain: true,
    }));
    let mut five_keys = create(&bad);
    if let SqlAction::PostgresCreateIndex { columns, .. } = &mut five_keys {
        columns.extend((2..=5).map(|id| PlainIndexColumn {
            name: format!("extra{id}"),
            direction: SortDirection::Asc,
        }));
    }
    assert!(prepare_sql_change(&five_keys, &scope, &bad).is_err());
    bad = metadata.clone();
    bad.existing_indexes.push("idx_rehearsal".into());
    assert!(prepare_sql_change(&action, &scope, &bad).is_err());

    let mut wrong = scope.clone();
    if let BoundScope::Database { database, .. } = &mut wrong {
        *database = "other_database".into();
    }
    assert!(prepare_sql_change(&action, &wrong, &metadata).is_err());
    wrong = scope.clone();
    if let BoundScope::Database {
        credential: Some(credential),
        ..
    } = &mut wrong
    {
        credential.purpose = CredentialPurpose::Read;
    }
    assert!(prepare_sql_change(&action, &wrong, &metadata).is_err());

    let mut hostile = create(&metadata);
    if let SqlAction::PostgresCreateIndex { index, .. } = &mut hostile {
        *index = "bad\0name".into();
    }
    assert!(prepare_sql_change(&hostile, &scope, &metadata).is_err());
    if let SqlAction::PostgresCreateIndex { index, .. } = &mut hostile {
        *index = "x".repeat(64);
    }
    assert!(prepare_sql_change(&hostile, &scope, &metadata).is_err());
}
