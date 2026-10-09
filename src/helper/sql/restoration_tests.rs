use super::*;
use crate::helper::scope::DatabaseEngine;
use crate::helper_action::{PlainIndexColumn, SortDirection, SqlEngine, VerifiedSqlObject};
use crate::mission::Target;

fn d(value: char) -> String {
    value.to_string().repeat(64)
}

fn observed<'a>(
    id: u64,
    name: &'a str,
    definition: &'a str,
    marker: Option<&'a str>,
) -> ObservedIndex<'a> {
    ObservedIndex {
        id,
        name,
        definition,
        valid: true,
        marker,
    }
}

fn production_index(engine: SqlEngine) -> (ProductionReceipt, String) {
    let scope = BoundScope::Database {
        target: Target {
            profile_id: Uuid::new_v4(),
            name: "original target".into(),
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
        port: 55433,
        database: "original_database".into(),
        schema: Some("public".into()),
        object: Some("orders".into()),
        credential: None,
    };
    let object = VerifiedSqlObject {
        engine,
        database: "original_database".into(),
        schema: "public".into(),
        table: "orders".into(),
        object_id: 42,
        scope_sha256: scope.digest().unwrap(),
    };
    let columns = vec![PlainIndexColumn {
        name: "id".into(),
        direction: SortDirection::Asc,
    }];
    let action = if engine == SqlEngine::Postgres {
        SqlAction::PostgresCreateIndex {
            object,
            index: "idx_run".into(),
            columns,
        }
    } else {
        SqlAction::SqlServerCreateIndex {
            object,
            index: "idx_run".into(),
            columns,
        }
    };
    let marker = format!("Relayne.CreatedByRunV1:{}", d('a'));
    let definition = "native normalized index definition".to_string();
    let mut receipt = ProductionReceipt {
        schema: RECEIPT_SCHEMA,
        run_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        approval_id: Uuid::new_v4(),
        consume_id: Uuid::new_v4(),
        binding_fingerprint: d('b'),
        rehearsal_sha256: d('c'),
        scope,
        physical_sha256: d('d'),
        database_id: 7,
        object_id: 42,
        restoration_guard_sha256: d('e'),
        action,
        before_sha256: d('f'),
        after_sha256: d('0'),
        index: Some(OwnedProductionIndex {
            id: 99,
            name: "idx_run".into(),
            definition_sha256: digest(b"relayne-helper-created-index-definition-v1", &definition)
                .unwrap(),
            marker_sha256: digest(b"relayne-helper-created-index-marker-v1", &marker).unwrap(),
            marker,
        }),
        created_at: Utc::now(),
        content_sha256: String::new(),
    };
    receipt.content_sha256 = receipt.fingerprint().unwrap();
    receipt.validate().unwrap();
    (receipt, definition)
}

#[test]
fn production_receipt_rejects_rehashed_wrong_index_action_and_future_time() {
    for engine in [SqlEngine::Postgres, SqlEngine::SqlServer] {
        let (receipt, _) = production_index(engine);

        let mut wrong_index = receipt.clone();
        wrong_index.index.as_mut().unwrap().name = "another_index".into();
        wrong_index.content_sha256 = wrong_index.fingerprint().unwrap();
        assert!(wrong_index.validate().is_err());

        let mut wrong_action = receipt.clone();
        wrong_action.action = match &receipt.action {
            SqlAction::PostgresCreateIndex {
                object, columns, ..
            } => SqlAction::PostgresCreateIndex {
                object: object.clone(),
                index: "another_index".into(),
                columns: columns.clone(),
            },
            SqlAction::SqlServerCreateIndex {
                object, columns, ..
            } => SqlAction::SqlServerCreateIndex {
                object: object.clone(),
                index: "another_index".into(),
                columns: columns.clone(),
            },
            _ => unreachable!(),
        };
        wrong_action.content_sha256 = wrong_action.fingerprint().unwrap();
        assert!(wrong_action.validate().is_err());

        let mut future = receipt.clone();
        future.created_at = Utc::now() + chrono::Duration::minutes(1);
        future.content_sha256 = future.fingerprint().unwrap();
        assert!(future.validate().is_err());

        let mut tampered = receipt;
        tampered.before_sha256 = d('9');
        assert!(tampered.validate().is_err());
    }
}

#[test]
fn exact_original_index_requires_original_identity_definition_and_random_marker() {
    for engine in [SqlEngine::Postgres, SqlEngine::SqlServer] {
        let (receipt, definition) = production_index(engine);
        let original = receipt.index.as_ref().unwrap();
        let exact = observed(
            original.id,
            &original.name,
            &definition,
            Some(&original.marker),
        );
        verify_original_index(&receipt, &d('d'), 7, 42, &d('e'), &[exact]).unwrap();
        for (id, name, def, marker) in [
            (
                original.id,
                original.name.as_str(),
                definition.as_str(),
                None,
            ),
            (
                original.id,
                original.name.as_str(),
                definition.as_str(),
                Some("replacement"),
            ),
            (
                original.id,
                original.name.as_str(),
                "changed definition",
                Some(original.marker.as_str()),
            ),
            (
                original.id + 1,
                original.name.as_str(),
                definition.as_str(),
                Some(original.marker.as_str()),
            ),
            (
                original.id,
                "replacement_name",
                definition.as_str(),
                Some(original.marker.as_str()),
            ),
        ] {
            assert!(verify_original_index(
                &receipt,
                &d('d'),
                7,
                42,
                &d('e'),
                &[observed(id, name, def, marker)]
            )
            .is_err());
        }
        let duplicate = [
            observed(
                original.id,
                &original.name,
                &definition,
                Some(&original.marker),
            ),
            observed(
                original.id + 1,
                &original.name,
                &definition,
                Some(&original.marker),
            ),
        ];
        assert!(verify_original_index(&receipt, &d('d'), 7, 42, &d('e'), &duplicate).is_err());
        assert!(verify_original_index(&receipt, &d('a'), 7, 42, &d('e'), &duplicate[..1]).is_err());
        assert!(verify_original_index(&receipt, &d('d'), 8, 42, &d('e'), &duplicate[..1]).is_err());
        assert!(verify_original_index(&receipt, &d('d'), 7, 43, &d('e'), &duplicate[..1]).is_err());
        assert!(verify_original_index(&receipt, &d('d'), 7, 42, &d('f'), &duplicate[..1]).is_err());
    }
}

#[test]
fn restoration_record_is_one_shot_and_protected_receipt_bound() {
    let (receipt, _) = production_index(SqlEngine::Postgres);
    let mut record = RestorationRecord::new(&receipt).unwrap();
    record.validate_for(&receipt).unwrap();
    record.finish(RestorationOutcome::Restored).unwrap();
    assert!(record.finish(RestorationOutcome::Restored).is_err());
    let mut altered = receipt.clone();
    altered.run_id = Uuid::new_v4();
    assert!(record.validate_for(&altered).is_err());
    record.production_receipt_sha256 = d('e');
    assert!(record.validate_for(&receipt).is_err());
}

fn seeded_production() -> (ProductionReceipt, ActionJournal) {
    let (receipt, _) = production_index(SqlEngine::Postgres);
    seeded_receipt(receipt)
}

fn seeded_receipt(receipt: ProductionReceipt) -> (ProductionReceipt, ActionJournal) {
    receipt.save().unwrap();
    let path = ActionJournal::path().unwrap();
    let mut journal = ActionJournal::load(&path).unwrap();
    journal
        .test_seed_verified_production(
            receipt.run_id,
            receipt.case_id,
            receipt.approval_id,
            receipt.consume_id,
            receipt.binding_fingerprint.clone(),
            receipt.content_sha256.clone(),
            receipt.after_sha256.clone(),
        )
        .unwrap();
    (receipt, journal)
}

#[tokio::test]
async fn missing_or_tampered_verified_production_proof_persists_original_run_barrier() {
    for tamper in [false, true] {
        let (receipt, mut journal) = seeded_production();
        let path = receipt_path(receipt.run_id()).unwrap();
        if tamper {
            std::fs::write(&path, b"invalid protected production receipt").unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        super::super::changes::set_restore_test_delay(0);
        let later_run = Uuid::new_v4();
        assert!(journal.has_open_intervention(receipt.case_id, later_run));
        assert_eq!(
            restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
                .await
                .unwrap(),
            RestorationOutcome::NeedsIntervention
        );
        let reloaded = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
        let original = reloaded
            .intents()
            .iter()
            .find(|i| i.run_id == receipt.run_id())
            .unwrap();
        assert_eq!(original.state, IntentState::Verified);
        assert_eq!(original.case_id, receipt.case_id);
        assert_eq!(
            original.restoration_outcome,
            Some(RestorationOutcome::NeedsIntervention)
        );
        assert!(reloaded.has_open_intervention(receipt.case_id, later_run));
        assert_eq!(super::super::changes::restore_test_attempts(), 0);
    }
}

#[tokio::test]
async fn terminal_restoration_survives_unavailable_production_proof() {
    for outcome in [
        RestorationOutcome::Restored,
        RestorationOutcome::NotRestorable,
    ] {
        for tamper in [false, true] {
            let (receipt, mut journal) = if outcome == RestorationOutcome::Restored {
                seeded_production()
            } else {
                let (mut receipt, _) = production_index(SqlEngine::Postgres);
                receipt.action = SqlAction::PostgresAnalyze {
                    object: receipt.action.object().clone(),
                };
                receipt.index = None;
                receipt.content_sha256 = receipt.fingerprint().unwrap();
                seeded_receipt(receipt)
            };
            let record_path = restoration_path(receipt.run_id()).unwrap();
            journal.record_restoration_intent(&receipt).unwrap();
            let mut record = RestorationRecord::new(&receipt).unwrap();
            write_restoration(&record_path, &record, &receipt).unwrap();
            record.finish(outcome).unwrap();
            write_restoration(&record_path, &record, &receipt).unwrap();
            journal
                .record_restoration_outcome(&receipt, outcome)
                .unwrap();

            let receipt_file = receipt_path(receipt.run_id()).unwrap();
            let receipt_bytes = std::fs::read(&receipt_file).unwrap();
            if tamper {
                std::fs::write(&receipt_file, b"invalid protected production receipt").unwrap();
            } else {
                std::fs::remove_file(&receipt_file).unwrap();
            }
            super::super::changes::set_restore_test_delay(0);
            let later_run = Uuid::new_v4();
            assert!(journal.has_open_intervention(receipt.case_id, later_run));
            assert_eq!(
                restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
                    .await
                    .unwrap(),
                RestorationOutcome::NeedsIntervention
            );
            let reloaded = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
            let original = reloaded
                .intents()
                .iter()
                .find(|item| item.run_id == receipt.run_id())
                .unwrap();
            assert_eq!(original.restoration_outcome, Some(outcome));
            assert!(!original.restoration_pending);
            assert!(reloaded.has_open_intervention(receipt.case_id, later_run));
            assert_eq!(super::super::changes::restore_test_attempts(), 0);

            std::fs::write(&receipt_file, receipt_bytes).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
                        .await
                        .unwrap(),
                    outcome
                );
            }
            let reloaded = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
            let original = reloaded
                .intents()
                .iter()
                .find(|item| item.run_id == receipt.run_id())
                .unwrap();
            assert_eq!(original.restoration_outcome, Some(outcome));
            assert!(!original.restoration_pending);
            assert_eq!(
                read_restoration(&record_path, &receipt)
                    .unwrap()
                    .unwrap()
                    .outcome,
                Some(outcome)
            );
            assert_eq!(
                reloaded.has_open_intervention(receipt.case_id, later_run),
                outcome == RestorationOutcome::NotRestorable
            );
            assert_eq!(super::super::changes::restore_test_attempts(), 0);
        }
    }
}

#[tokio::test]
async fn unavailable_production_proof_save_failure_still_denies_later_dispatch() {
    let (receipt, mut journal) = seeded_production();
    std::fs::remove_file(receipt_path(receipt.run_id()).unwrap()).unwrap();
    super::super::changes::set_restore_test_delay(0);
    crate::helper::journal::arm_unavailable_receipt_save_fault();
    assert!(
        restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
            .await
            .is_err()
    );
    let reloaded = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
    let original = reloaded
        .intents()
        .iter()
        .find(|i| i.run_id == receipt.run_id())
        .unwrap();
    assert_eq!(original.restoration_outcome, None);
    assert!(reloaded.has_open_intervention(receipt.case_id, Uuid::new_v4()));
    assert_eq!(super::super::changes::restore_test_attempts(), 0);
}

#[tokio::test]
async fn requested_nonrestorable_statistics_halts_later_targets_for_both_engines() {
    for engine in [SqlEngine::Postgres, SqlEngine::SqlServer] {
        let (mut receipt, _) = production_index(engine);
        let object = receipt.action.object().clone();
        receipt.action = match engine {
            SqlEngine::Postgres => SqlAction::PostgresAnalyze { object },
            SqlEngine::SqlServer => SqlAction::SqlServerUpdateStatistics { object },
        };
        receipt.index = None;
        receipt.content_sha256 = receipt.fingerprint().unwrap();
        let (receipt, mut journal) = seeded_receipt(receipt);
        super::super::changes::set_restore_test_delay(0);
        assert_eq!(
            restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
                .await
                .unwrap(),
            RestorationOutcome::NotRestorable
        );
        let reloaded = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
        let original = reloaded
            .intents()
            .iter()
            .find(|i| i.run_id == receipt.run_id())
            .unwrap();
        assert_eq!(
            original.restoration_outcome,
            Some(RestorationOutcome::NotRestorable)
        );
        assert!(!original.restoration_pending);
        assert!(reloaded.has_open_intervention(receipt.case_id, Uuid::new_v4()));
        assert_eq!(super::super::changes::restore_test_attempts(), 0);
    }
}

#[tokio::test]
async fn concurrent_restore_claim_and_later_dispatch_gate_make_one_native_attempt() {
    let (receipt, mut first) = seeded_production();
    let mut second = ActionJournal::load(first.storage_path()).unwrap();
    super::super::changes::set_restore_test_delay(120);
    let run_id = receipt.run_id();
    let case_id = receipt.case_id;
    let later = async {
        for _ in 0..100 {
            if super::super::changes::restore_test_attempts() > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(super::super::changes::restore_test_attempts(), 1);
        let path = HelperStore::path().unwrap();
        HelperStore::inspect_locked(&path, |_store| {
            let current = ActionJournal::load(&ActionJournal::path()?)?;
            assert!(current.has_open_intervention(case_id, Uuid::new_v4()));
            Ok(())
        })
        .unwrap();
    };
    let (left, right, _) = tokio::join!(
        restore_index(run_id, &mut first, CancellationToken::new()),
        restore_index(run_id, &mut second, CancellationToken::new()),
        later,
    );
    assert_eq!(left.unwrap(), RestorationOutcome::NeedsIntervention);
    assert_eq!(right.unwrap(), RestorationOutcome::NeedsIntervention);
    assert_eq!(super::super::changes::restore_test_attempts(), 1);
    super::super::changes::set_restore_test_delay(0);
    let mut replay = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
    assert_eq!(
        restore_index(run_id, &mut replay, CancellationToken::new())
            .await
            .unwrap(),
        RestorationOutcome::NeedsIntervention
    );
    assert_eq!(super::super::changes::restore_test_attempts(), 0);
}

#[tokio::test]
async fn partial_claim_writes_remain_pending_and_never_contact_target() {
    for phase in [1, 2] {
        let (receipt, mut journal) = seeded_production();
        super::super::changes::set_restore_test_delay(0);
        arm_restoration_test_fault(phase);
        assert!(
            restore_index(receipt.run_id(), &mut journal, CancellationToken::new())
                .await
                .is_err()
        );
        assert_eq!(super::super::changes::restore_test_attempts(), 0);
        let mut reloaded = ActionJournal::load(&ActionJournal::path().unwrap()).unwrap();
        let original = reloaded
            .intents()
            .iter()
            .find(|item| item.run_id == receipt.run_id())
            .unwrap();
        assert!(original.restoration_pending);
        assert!(reloaded.has_open_intervention(receipt.case_id, Uuid::new_v4()));
        assert_eq!(
            restore_index(receipt.run_id(), &mut reloaded, CancellationToken::new())
                .await
                .unwrap(),
            RestorationOutcome::NeedsIntervention
        );
        assert_eq!(super::super::changes::restore_test_attempts(), 0);
    }
}
