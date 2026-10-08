use super::*;
use crate::helper_action::{
    RestorationSpec, SqlAction, SqlEngine, StatisticsLimitation, VerifiedSqlObject,
};
use crate::helper_approval::{ActionBindingV2, ActionProof, ConsumeReceiptV2, RunKind};
use chrono::Duration;

fn d() -> String {
    "a".repeat(64)
}
fn permit() -> DispatchPermit {
    let now = Utc::now();
    let run = Uuid::new_v4();
    let binding = ActionBindingV2 {
        version: 2,
        case_id: Uuid::new_v4(),
        case_revision: 1,
        evidence_revision: 1,
        run_id: run,
        run_kind: RunKind::Rehearsal,
        organization_sha256: d(),
        scope_sha256: d(),
        credential_scope_sha256: d(),
        action_version: 1,
        action: SqlAction::PostgresAnalyze {
            object: VerifiedSqlObject {
                engine: SqlEngine::Postgres,
                database: "db".into(),
                schema: "public".into(),
                table: "orders".into(),
                object_id: 1,
                scope_sha256: d(),
            },
        },
        metadata_sha256: d(),
        before_sha256: d(),
        plan_sha256: d(),
        verification_sha256: d(),
        proof: ActionProof::StagingReviewProof {
            review_id: Uuid::new_v4(),
            review_sha256: d(),
            expires_at: now + Duration::minutes(5),
        },
        restoration: RestorationSpec::ManualOrUnavailable {
            limitation: StatisticsLimitation::PriorStatisticsCannotBeRestoredExactly,
        },
        statistics_limit_acknowledged: true,
        captured_at: now,
        expires_at: now + Duration::minutes(3),
    };
    let receipt = ConsumeReceiptV2 {
        approval_id: Uuid::new_v4(),
        consume_id: Uuid::new_v4(),
        fingerprint: binding.fingerprint().unwrap(),
        organization_sha256: d(),
    };
    DispatchPermit::test_only(binding, receipt)
}
fn path() -> PathBuf {
    std::env::temp_dir().join(format!("relayne-action-journal-{}.dpapi", Uuid::new_v4()))
}

#[test]
fn intent_is_durable_before_dispatch_and_never_replayed_on_load() {
    let path = path();
    let mut journal = ActionJournal::load(&path).unwrap();
    let permit = permit();
    let run = permit.binding().run_id;
    let id = journal.record_intent(permit).unwrap();
    let mut reloaded = ActionJournal::load(&path).unwrap();
    assert_eq!(
        reloaded.reconcile(run, None).unwrap(),
        Reconciliation::PreparedNoEffect
    );
    reloaded.mark_dispatch_started(id).unwrap();
    assert_eq!(
        ActionJournal::load(&path)
            .unwrap()
            .reconcile(run, None)
            .unwrap(),
        Reconciliation::AwaitingObservation
    );
    assert!(reloaded.mark_dispatch_started(id).is_err());
    reloaded
        .reconcile(run, Some(IntentState::OutcomeUnknown))
        .unwrap();
    let event = reloaded
        .queue_outcome(id, ActionOutcomeV2::OutcomeUnknown)
        .unwrap();
    assert_eq!(
        ActionJournal::load(&path)
            .unwrap()
            .pending_outcomes()
            .next()
            .unwrap(),
        &event
    );
    reloaded
        .acknowledge_outcome(&ActionOutcomeAckV2 {
            event_id: event.event_id,
            accepted: true,
        })
        .unwrap();
    assert_eq!(
        ActionJournal::load(&path)
            .unwrap()
            .pending_outcomes()
            .count(),
        0
    );
}

#[test]
fn failed_intent_write_returns_no_launch_id() {
    let path = path();
    let mut journal = ActionJournal::load(&path).unwrap();
    std::fs::write(&path, b"conflicting file").unwrap();
    assert!(journal.record_intent(permit()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"conflicting file");
}

#[test]
fn ack_save_failure_keeps_exact_event_for_retry() {
    let path = path();
    let mut journal = ActionJournal::load(&path).unwrap();
    let permit = permit();
    let run = permit.binding().run_id;
    let id = journal.record_intent(permit).unwrap();
    journal.mark_dispatch_started(id).unwrap();
    journal.reconcile(run, Some(IntentState::Failed)).unwrap();
    let event = journal.queue_outcome(id, ActionOutcomeV2::Failed).unwrap();
    let saved = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"conflict").unwrap();
    assert!(
        journal
            .acknowledge_outcome(&ActionOutcomeAckV2 {
                event_id: event.event_id,
                accepted: true
            })
            .is_err()
    );
    std::fs::write(&path, saved).unwrap();
    let mut recovered = ActionJournal::load(&path).unwrap();
    assert_eq!(
        recovered.pending_outcomes().next().unwrap().event_id,
        event.event_id
    );
    assert_eq!(
        recovered
            .queue_outcome(id, ActionOutcomeV2::Failed)
            .unwrap()
            .event_id,
        event.event_id
    );
    recovered
        .acknowledge_outcome(&ActionOutcomeAckV2 {
            event_id: event.event_id,
            accepted: true,
        })
        .unwrap();
}
