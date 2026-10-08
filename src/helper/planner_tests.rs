use super::*;
use crate::helper::{case::CaseEdit, evidence::*, scope::BoundScope, store::HelperStore};
use crate::helper::{case::ProblemIntake, manifest::CapabilityManifest};
use crate::mission::Target;

pub(crate) fn observed_case() -> (HelperStore, HelperCase, EvidenceEnvelope) {
    let mut store = HelperStore::default();
    let id = store.create(ProblemIntake::default()).unwrap();
    let profile_id = Uuid::new_v4();
    let other_profile_id = Uuid::new_v4();
    store
        .revise(
            id,
            1,
            CaseEdit::Profiles(vec![profile_id, other_profile_id]),
        )
        .unwrap();
    let scope = BoundScope::Http {
        target: Target {
            profile_id,
            name: "web".into(),
            host: "example.test".into(),
            port: 443,
            protocol: "RDP".into(),
            username: "operator".into(),
            domain: "example".into(),
            route: "gateway:443".into(),
        },
        port: 443,
        tls: true,
        path: "/health".into(),
    };
    let scope_digest = scope.digest().unwrap();
    let other_scope = BoundScope::Http {
        target: Target {
            profile_id: other_profile_id,
            name: "other".into(),
            host: "other.test".into(),
            port: 443,
            protocol: "RDP".into(),
            username: "operator".into(),
            domain: "other".into(),
            route: "gateway:443".into(),
        },
        port: 443,
        tls: true,
        path: "/health".into(),
    };
    store
        .revise(id, 2, CaseEdit::Scopes(vec![scope, other_scope]))
        .unwrap();
    let binding = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope_digest,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    let now = Utc::now();
    let envelope = EvidenceEnvelope {
        schema: EVIDENCE_SCHEMA,
        id: Uuid::new_v4(),
        binding,
        capability_id: CapabilityId::NetworkReachability,
        capability_version: 1,
        parser_version: 1,
        origin: Origin::Live,
        source_id: source_id_digest(b"fixture"),
        source_observed_at: now,
        retrieved_at: now,
        time_quality: TimeQuality::Trusted,
        status: EvidenceStatus::Complete,
        coverage: Coverage {
            observed: 5,
            expected: 5,
            truncated: false,
        },
        content_sha256: "a".repeat(64),
        records: vec![
            (RecordKind::Network, Observation::Healthy),
            (RecordKind::Service, Observation::Unavailable),
            (RecordKind::System, Observation::Degraded),
            (RecordKind::SqlRead, Observation::Unavailable),
            (RecordKind::SqlRead, Observation::Healthy),
        ]
        .into_iter()
        .map(|(kind, observation)| NormalizedRecord {
            kind,
            observation,
            subject_sha256: "b".repeat(64),
        })
        .collect(),
        metrics: vec![],
        evidence_refs: vec![],
    };
    store.attach_evidence(id, envelope.clone()).unwrap();
    (store.clone(), store.case(id).unwrap().clone(), envelope)
}

#[test]
fn empty_case_has_explicit_gaps_and_no_confirmed_cause() {
    let case = HelperCase::new(ProblemIntake::default()).unwrap();
    let plan = plan_local(&case, &[], &CapabilityManifest::built_in(), Utc::now()).unwrap();
    assert_eq!(plan.case_id, case.id());
    assert!(plan.hypotheses.iter().all(|h| h.confirmation.is_none()));
    assert!(plan.hypotheses.iter().all(|h| !h.gaps.is_empty()));
    assert!(plan.steps.is_empty());
    let checkpoint = mission_checkpoint(&plan).unwrap();
    assert_eq!(checkpoint.kind, crate::mission::StepKind::Operator);
    assert!(checkpoint.command.is_empty());
}

#[test]
fn mixed_faults_preserve_contradiction_and_tcp_limit() {
    let (_, case, envelope) = observed_case();
    let plan = plan_local(
        &case,
        &[envelope.clone()],
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    let network = plan
        .hypotheses
        .iter()
        .find(|h| h.kind == HypothesisKind::NetworkTransport)
        .unwrap();
    assert!(network.support.is_empty());
    assert_eq!(network.counterevidence, vec![envelope.id]);
    assert!(
        network
            .gaps
            .iter()
            .any(|g| g.contains("TCP reachability alone"))
    );
    for kind in [
        HypothesisKind::ServiceHealth,
        HypothesisKind::ResourcePressure,
        HypothesisKind::SqlHealth,
    ] {
        assert_eq!(
            plan.hypotheses
                .iter()
                .find(|h| h.kind == kind)
                .unwrap()
                .support,
            vec![envelope.id]
        );
    }
    assert_eq!(
        plan.hypotheses
            .iter()
            .find(|h| h.kind == HypothesisKind::SqlHealth)
            .unwrap()
            .counterevidence,
        vec![envelope.id]
    );
    assert!(plan.hypotheses.iter().all(|h| h.confirmation.is_none()));
    assert!(plan.steps.iter().all(|s| !matches!(
        s.params,
        ProbeParams::SqlRead { .. } | ProbeParams::SqlPlan { .. }
    )));
}

#[test]
fn stale_or_altered_evidence_cannot_support_a_plan() {
    let (_, case, mut envelope) = observed_case();
    envelope.source_observed_at -= Duration::minutes(6);
    let plan = plan_local(
        &case,
        &[envelope],
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    assert!(
        plan.hypotheses
            .iter()
            .all(|h| h.support.is_empty() && h.counterevidence.is_empty())
    );
}

#[test]
fn derived_refresh_does_not_edit_context_but_adoption_does() {
    let (mut store, case, envelope) = observed_case();
    let plan = plan_local(
        &case,
        &[envelope],
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    assert_eq!(plan.case_revision, case.revision());
    assert_eq!(plan.evidence_revision, case.evidence_revision());
    store.refresh_derived_plan(case.id(), plan.clone()).unwrap();
    assert_eq!(store.case(case.id()).unwrap().revision(), case.revision());
    assert_eq!(
        store
            .case(case.id())
            .unwrap()
            .plan()
            .unwrap()
            .evidence_revision,
        case.evidence_revision()
    );
    store
        .revise(case.id(), case.revision(), CaseEdit::PlanIntent(plan))
        .unwrap();
    assert_eq!(
        store.case(case.id()).unwrap().revision(),
        case.revision() + 1
    );
    assert_eq!(
        store.case(case.id()).unwrap().plan().unwrap().case_revision,
        case.revision() + 1
    );
    assert!(
        store
            .case(case.id())
            .unwrap()
            .plan()
            .unwrap()
            .hypotheses
            .iter()
            .all(|h| h.support.is_empty() && h.counterevidence.is_empty())
    );
    assert!(
        store
            .case(case.id())
            .unwrap()
            .plan()
            .unwrap()
            .steps
            .iter()
            .all(|s| s.evidence_refs.is_empty())
    );
}

#[test]
fn confirmation_requires_human_actor_time_and_supporting_live_refs() {
    let (mut store, case, envelope) = observed_case();
    let plan = plan_local(
        &case,
        &[envelope.clone()],
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    store.refresh_derived_plan(case.id(), plan).unwrap();
    let confirmation = HumanConfirmation {
        actor: "operator-1".into(),
        confirmed_at: Utc::now(),
        rationale: "Observed service failure on reviewed scope".into(),
        evidence_refs: vec![envelope.id],
        case_revision: case.revision(),
    };
    assert!(
        store
            .confirm_hypothesis(
                case.id(),
                case.revision(),
                HypothesisKind::NetworkTransport,
                confirmation.clone()
            )
            .is_err()
    );
    assert_eq!(store.case(case.id()).unwrap().revision(), case.revision());
    let rev = store
        .confirm_hypothesis(
            case.id(),
            case.revision(),
            HypothesisKind::ServiceHealth,
            confirmation,
        )
        .unwrap();
    assert_eq!(rev, case.revision() + 1);
    let saved = store.case(case.id()).unwrap().plan().unwrap();
    assert!(
        saved
            .hypotheses
            .iter()
            .find(|h| h.kind == HypothesisKind::ServiceHealth)
            .unwrap()
            .confirmation
            .is_some()
    );
    assert!(saved.hypotheses.iter().all(|h| h.support.is_empty()));
    let current = store.case(case.id()).unwrap().clone();
    let refreshed = plan_local(
        &current,
        current.evidence(),
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    store.refresh_derived_plan(case.id(), refreshed).unwrap();
    assert!(
        store
            .case(case.id())
            .unwrap()
            .plan()
            .unwrap()
            .hypotheses
            .iter()
            .find(|h| h.kind == HypothesisKind::ServiceHealth)
            .unwrap()
            .confirmation
            .is_some()
    );
}

#[test]
fn plan_artifact_expires_at_ninety_days_without_erasing_case_evidence() {
    let (mut store, case, envelope) = observed_case();
    let mut plan = plan_local(
        &case,
        &[envelope.clone()],
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    plan.generated_at -= Duration::days(91);
    store.refresh_derived_plan(case.id(), plan).unwrap();
    assert_eq!(
        store.case(case.id()).unwrap().plan_retention(Utc::now()),
        Some(RetentionState::ExpiredUnheld)
    );
    assert!(store.prune_expired_plan(case.id(), Utc::now()).unwrap());
    assert!(store.case(case.id()).unwrap().plan().is_none());
    assert_eq!(store.case(case.id()).unwrap().evidence().len(), 1);
}

#[test]
fn backdated_future_and_stale_confirmation_times_are_rejected() {
    let (mut store, case, envelope) = observed_case();
    let scope = case.scopes()[0].digest().unwrap();
    let binding = store
        .register_pending_capture(
            case.id(),
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    let mut stale = envelope.clone();
    stale.id = Uuid::new_v4();
    stale.binding = binding;
    stale.source_observed_at = Utc::now() - Duration::minutes(6);
    stale.retrieved_at = Utc::now();
    store.attach_evidence(case.id(), stale.clone()).unwrap();
    let current = store.case(case.id()).unwrap().clone();
    let mut plan = plan_local(
        &current,
        current.evidence(),
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    plan.hypotheses
        .iter_mut()
        .find(|h| h.kind == HypothesisKind::ServiceHealth)
        .unwrap()
        .support
        .push(stale.id);
    store.refresh_derived_plan(case.id(), plan).unwrap();
    let decision = |at| HumanConfirmation {
        actor: "operator-1".into(),
        confirmed_at: at,
        rationale: "Reviewed observation".into(),
        evidence_refs: vec![stale.id],
        case_revision: case.revision(),
    };
    assert!(
        store
            .confirm_hypothesis(
                case.id(),
                case.revision(),
                HypothesisKind::ServiceHealth,
                decision(stale.source_observed_at)
            )
            .is_err()
    );
    assert!(
        store
            .confirm_hypothesis(
                case.id(),
                case.revision(),
                HypothesisKind::ServiceHealth,
                decision(Utc::now() + Duration::seconds(10))
            )
            .is_err()
    );
    assert!(
        store
            .confirm_hypothesis(
                case.id(),
                case.revision(),
                HypothesisKind::ServiceHealth,
                decision(Utc::now())
            )
            .is_err()
    );
    assert_eq!(store.case(case.id()).unwrap().revision(), case.revision());
}

#[test]
fn mixed_scope_next_check_cites_only_its_exact_scope_and_credential() {
    let (mut store, case, first) = observed_case();
    let other_digest = case.scopes()[1].digest().unwrap();
    let binding = store
        .register_pending_capture(
            case.id(),
            Uuid::new_v4(),
            &other_digest,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    let mut other = first.clone();
    other.id = Uuid::new_v4();
    other.binding = binding;
    other.content_sha256 = "c".repeat(64);
    store.attach_evidence(case.id(), other.clone()).unwrap();
    let current = store.case(case.id()).unwrap();
    let plan = plan_local(
        current,
        current.evidence(),
        &CapabilityManifest::built_in(),
        Utc::now(),
    )
    .unwrap();
    let step = plan
        .steps
        .iter()
        .find(|s| s.capability_id == CapabilityId::ServiceStatus)
        .unwrap();
    assert_eq!(step.evidence_refs.len(), 1);
    let cited = current
        .evidence()
        .iter()
        .find(|e| e.id == step.evidence_refs[0])
        .unwrap();
    assert_eq!(cited.binding.scope_sha256, step.scope_sha256);
    assert_eq!(
        cited.binding.credential_scope_sha256,
        current
            .scopes()
            .iter()
            .find(|s| s.digest().unwrap() == step.scope_sha256)
            .unwrap()
            .credential_scope_digest()
            .unwrap()
    );
    let mut forged = plan.clone();
    forged
        .steps
        .iter_mut()
        .find(|s| s.capability_id == CapabilityId::ServiceStatus)
        .unwrap()
        .evidence_refs = vec![if cited.id == first.id {
        other.id
    } else {
        first.id
    }];
    assert!(
        forged
            .validate(current, &CapabilityManifest::built_in())
            .is_err()
    );
}
