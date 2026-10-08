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
        .reconcile_inner(run, Some(IntentState::OutcomeUnknown), true)
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
    journal
        .reconcile_inner(run, Some(IntentState::Failed), true)
        .unwrap();
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

#[test]
fn acknowledged_unknown_can_be_corrected_once_with_a_linked_event() {
    let path = path();
    let mut journal = ActionJournal::load(&path).unwrap();
    let permit = permit();
    let run = permit.binding().run_id;
    let id = journal.record_intent(permit).unwrap();
    journal.mark_dispatch_started(id).unwrap();
    journal
        .reconcile_inner(run, Some(IntentState::OutcomeUnknown), true)
        .unwrap();
    let unknown = journal
        .queue_outcome(id, ActionOutcomeV2::OutcomeUnknown)
        .unwrap();
    assert!(
        journal
            .reconcile_inner(run, Some(IntentState::Verified), true)
            .is_err()
    );
    journal
        .acknowledge_outcome(&ActionOutcomeAckV2 {
            event_id: unknown.event_id,
            accepted: true,
        })
        .unwrap();
    journal
        .reconcile_inner(run, Some(IntentState::Verified), true)
        .unwrap();
    let verified = journal
        .queue_outcome(id, ActionOutcomeV2::Verified)
        .unwrap();
    assert_eq!(verified.sequence, 2);
    assert_eq!(verified.previous_event_id, Some(unknown.event_id));
    assert_eq!(
        journal
            .queue_outcome(id, ActionOutcomeV2::Verified)
            .unwrap()
            .event_id,
        verified.event_id
    );
    assert_eq!(
        ActionJournal::load(&path)
            .unwrap()
            .pending_outcomes()
            .next()
            .unwrap(),
        &verified
    );
}

#[test]
fn atomic_operator_report_survives_save_fault_restart_and_intervention_correction() {
    let path = path();
    let mut journal = ActionJournal::load(&path).unwrap();
    let permit = permit();
    let run = permit.binding().run_id;
    let id = journal.record_intent(permit).unwrap();
    journal.mark_dispatch_started(id).unwrap();
    let saved = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"conflicting protected file").unwrap();
    assert!(
        journal
            .observe_and_queue_outcome(
                id,
                IntentState::OutcomeUnknown,
                ActionOutcomeV2::OutcomeUnknown,
                "TICKET-101"
            )
            .is_err()
    );
    std::fs::write(&path, saved).unwrap();
    let mut recovered = ActionJournal::load(&path).unwrap();
    assert_eq!(
        recovered
            .intents()
            .iter()
            .find(|i| i.id == id)
            .unwrap()
            .state,
        IntentState::DispatchStarted
    );
    assert_eq!(recovered.pending_outcomes().count(), 0);
    assert!(
        recovered
            .observe_and_queue_outcome(
                id,
                IntentState::Verified,
                ActionOutcomeV2::Verified,
                "TICKET-101"
            )
            .is_err()
    );
    let unknown = recovered
        .observe_and_queue_outcome(
            id,
            IntentState::OutcomeUnknown,
            ActionOutcomeV2::OutcomeUnknown,
            "TICKET-101",
        )
        .unwrap();
    let mut restarted = ActionJournal::load(&path).unwrap();
    assert_eq!(
        restarted
            .intents()
            .iter()
            .find(|i| i.id == id)
            .unwrap()
            .state,
        IntentState::OutcomeUnknown
    );
    assert_eq!(
        restarted.pending_outcomes().next().unwrap().event_id,
        unknown.event_id
    );
    assert_eq!(
        restarted
            .pending_outcomes()
            .next()
            .unwrap()
            .operator_reference
            .as_deref(),
        Some("TICKET-101")
    );
    assert!(
        restarted
            .observe_and_queue_outcome(
                id,
                IntentState::NeedsIntervention,
                ActionOutcomeV2::NeedsIntervention,
                "TICKET-102"
            )
            .is_err()
    );
    restarted
        .acknowledge_outcome(&ActionOutcomeAckV2 {
            event_id: unknown.event_id,
            accepted: true,
        })
        .unwrap();
    let intervention = restarted
        .observe_and_queue_outcome(
            id,
            IntentState::NeedsIntervention,
            ActionOutcomeV2::NeedsIntervention,
            "TICKET-102",
        )
        .unwrap();
    assert_eq!(intervention.sequence, 2);
    assert_eq!(intervention.previous_event_id, Some(unknown.event_id));
    assert_eq!(
        ActionJournal::load(&path)
            .unwrap()
            .pending_outcomes()
            .next()
            .unwrap()
            .event_id,
        intervention.event_id
    );
    assert_eq!(
        restarted.reconcile(run, None).unwrap(),
        Reconciliation::NeedsIntervention
    );
}
