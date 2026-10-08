use super::*;
use crate::helper::{
    case::{CaseEdit, ProblemIntake},
    scope::BoundScope,
    store::HelperStore,
};
use crate::mission::Target;

fn fixture() -> (HelperStore, Uuid, String) {
    let mut store = HelperStore::default();
    let id = store.create(ProblemIntake::default()).unwrap();
    let profile_id = Uuid::new_v4();
    store
        .revise(id, 1, CaseEdit::Profiles(vec![profile_id]))
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
    let digest = scope.digest().unwrap();
    store.revise(id, 2, CaseEdit::Scopes(vec![scope])).unwrap();
    (store, id, digest)
}

fn envelope(binding: EvidenceBinding) -> EvidenceEnvelope {
    let now = Utc::now();
    EvidenceEnvelope {
        schema: EVIDENCE_SCHEMA,
        id: Uuid::new_v4(),
        binding,
        capability_id: CapabilityId::NetworkReachability,
        capability_version: 1,
        parser_version: 1,
        origin: Origin::Live,
        source_id: "worker-1".into(),
        source_observed_at: now,
        retrieved_at: now,
        time_quality: TimeQuality::Trusted,
        status: EvidenceStatus::Complete,
        coverage: Coverage {
            observed: 1,
            expected: 1,
            truncated: false,
        },
        content_sha256: "a".repeat(64),
        records: vec![NormalizedRecord {
            kind: RecordKind::Network,
            observation: Observation::Healthy,
            subject_sha256: "b".repeat(64),
        }],
        metrics: vec![],
        evidence_refs: vec![],
    }
}

#[test]
fn rejects_every_wrong_binding_component() {
    let (mut store, id, scope) = fixture();
    let expected = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            Some(Uuid::new_v4()),
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    for edit in 0..6 {
        let mut response = envelope(expected.clone());
        match edit {
            0 => response.binding.case_id = Uuid::new_v4(),
            1 => response.binding.case_revision += 1,
            2 => response.binding.request_id = Uuid::new_v4(),
            3 => response.binding.scope_sha256 = "b".repeat(64),
            4 => response.binding.credential_scope_sha256 = "b".repeat(64),
            _ => response.binding.run_id = Some(Uuid::new_v4()),
        }
        assert!(
            attach_evidence(&mut store, id, response).is_err(),
            "component {edit}"
        );
    }
    assert_eq!(store.case(id).unwrap().evidence_revision(), 0);
    attach_evidence(&mut store, id, envelope(expected)).unwrap();
    assert_eq!(store.case(id).unwrap().revision(), 3);
    assert_eq!(store.case(id).unwrap().evidence_revision(), 1);
}

#[test]
fn origin_time_coverage_and_limits_are_ineligible_or_rejected() {
    let (mut store, id, scope) = fixture();
    let binding = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    let now = Utc::now() + Duration::seconds(2);
    let mut e = envelope(binding.clone());
    assert_eq!(
        e.eligibility(now + Duration::seconds(1), Duration::minutes(5)),
        Eligibility::Eligible
    );
    e.origin = Origin::ImportedUnverified;
    assert_eq!(
        e.eligibility(now, Duration::minutes(5)),
        Eligibility::Imported
    );
    e.origin = Origin::SimulationFixture;
    assert_eq!(
        e.eligibility(now, Duration::minutes(5)),
        Eligibility::Simulation
    );
    e.origin = Origin::Live;
    e.time_quality = TimeQuality::ClockUncertain;
    assert_eq!(
        e.eligibility(now, Duration::minutes(5)),
        Eligibility::ClockUncertain
    );
    e.time_quality = TimeQuality::Trusted;
    e.source_observed_at = now + Duration::seconds(1);
    assert_eq!(
        e.eligibility(now, Duration::minutes(5)),
        Eligibility::Future
    );
    e.source_observed_at = now - Duration::minutes(6);
    assert_eq!(e.eligibility(now, Duration::minutes(5)), Eligibility::Stale);
    e.source_observed_at = now;
    e.coverage.observed = 0;
    assert_eq!(
        e.eligibility(now, Duration::minutes(5)),
        Eligibility::Incomplete
    );
    e.coverage.observed = 1;
    e.status = EvidenceStatus::Denied;
    assert_eq!(
        e.eligibility(now, Duration::minutes(5)),
        Eligibility::Incomplete
    );
    e.status = EvidenceStatus::Complete;
    e.evidence_refs = vec![Uuid::new_v4(); MAX_EVIDENCE_REFS + 1];
    assert!(e.validate_shape().is_err());
    e.evidence_refs.clear();
    e.metrics = (0..MAX_METRICS + 1)
        .map(|_| NormalizedMetric {
            kind: MetricKind::Rows,
            value: 1.0,
        })
        .collect();
    assert!(e.validate_shape().is_err());
    e.metrics.clear();
    e.records = (0..MAX_RECORDS + 1)
        .map(|_| NormalizedRecord {
            kind: RecordKind::Network,
            observation: Observation::Healthy,
            subject_sha256: "a".repeat(64),
        })
        .collect();
    assert!(e.validate_shape().is_err());
    e.records.clear();
    e.source_id = "x".repeat(MAX_ENVELOPE_BYTES);
    assert!(e.validate_shape().is_err());
    e.source_id = "worker-1".into();
    e.schema += 1;
    assert!(e.validate_shape().is_err());
}

#[test]
fn self_consistent_live_import_has_no_authority_and_same_context_remains_current() {
    let (mut store, id, scope) = fixture();
    let credential = store.case(id).unwrap().scopes()[0]
        .credential_scope_digest()
        .unwrap();
    let fake = EvidenceBinding {
        case_id: id,
        case_revision: 3,
        request_id: Uuid::new_v4(),
        scope_sha256: scope.clone(),
        credential_scope_sha256: credential,
        run_id: None,
    };
    assert!(attach_evidence(&mut store, id, envelope(fake.clone())).is_err());
    let first = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    let second = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    attach_evidence(&mut store, id, envelope(first)).unwrap();
    attach_evidence(&mut store, id, envelope(second)).unwrap();
    assert_eq!(store.case(id).unwrap().evidence().len(), 2);
    assert_eq!(store.case(id).unwrap().revision(), 3);
    assert_eq!(store.case(id).unwrap().evidence_revision(), 2);
    let mut imported = envelope(fake);
    imported.origin = Origin::ImportedUnverified;
    attach_evidence(&mut store, id, imported).unwrap();
    assert_eq!(store.case(id).unwrap().evidence().len(), 3);
}

#[test]
fn expired_held_history_is_preserved_and_capacity_rejects_without_eviction() {
    use crate::helper::case::HelperCase;
    assert_eq!(PLAN_ARTIFACT_RETENTION_DAYS, 90);
    assert_eq!(METADATA_RETENTION_DAYS, 365);
    let case = HelperCase::new(ProblemIntake::default()).unwrap();
    let id = case.id();
    let mut entries = Vec::with_capacity(MAX_ENVELOPES_PER_CASE);
    for _ in 0..MAX_ENVELOPES_PER_CASE {
        let mut e = envelope(EvidenceBinding {
            case_id: id,
            case_revision: 1,
            request_id: Uuid::new_v4(),
            scope_sha256: "a".repeat(64),
            credential_scope_sha256: "b".repeat(64),
            run_id: None,
        });
        e.source_observed_at -= Duration::days(366);
        e.retrieved_at -= Duration::days(366);
        entries.push(e);
    }
    let held_id = entries[0].id;
    let mut value = serde_json::to_value(&case).unwrap();
    value["evidence"] = serde_json::to_value(entries).unwrap();
    value["evidence_revision"] = serde_json::json!(MAX_ENVELOPES_PER_CASE);
    let mut full: HelperCase = serde_json::from_value(value).unwrap();
    full.validate().unwrap();
    full.set_evidence_hold(EvidenceHold {
        run_id: Uuid::new_v4(),
        reason: HoldReason::AmbiguousOutcome,
        evidence_ids: vec![held_id],
    })
    .unwrap();
    assert_eq!(
        full.evidence_retention(held_id, Utc::now()),
        Some(RetentionState::ExpiredHeld)
    );
    assert_eq!(
        full.evidence_retention(full.evidence()[1].id, Utc::now()),
        Some(RetentionState::ExpiredUnheld)
    );
    let next = envelope(EvidenceBinding {
        case_id: id,
        case_revision: 1,
        request_id: Uuid::new_v4(),
        scope_sha256: "a".repeat(64),
        credential_scope_sha256: "b".repeat(64),
        run_id: None,
    });
    assert!(full.append_evidence(next).is_err());
    assert_eq!(full.evidence().len(), MAX_ENVELOPES_PER_CASE);
    assert_eq!(full.evidence()[0].id, held_id);
    assert_eq!(
        full.prune_expired_evidence_metadata(Utc::now()).unwrap(),
        MAX_ENVELOPES_PER_CASE - 1
    );
    assert_eq!(full.evidence().len(), 1);
    assert_eq!(full.evidence()[0].id, held_id);
}

#[test]
fn credential_binding_distinguishes_purpose_for_identical_resource() {
    use crate::helper::scope::{CredentialPurpose, CredentialScope, DatabaseEngine};
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "db".into(),
        host: "db.test".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: "operator".into(),
        domain: "example".into(),
        route: "gateway:443".into(),
    };
    let credential = CredentialScope {
        reference: Uuid::new_v4(),
        purpose: CredentialPurpose::Read,
        generation: 1,
        principal: "reader".into(),
        context: "db.test".into(),
        context_digest: String::new(),
    };
    let read = BoundScope::Database {
        target,
        engine: DatabaseEngine::Postgres,
        port: 5432,
        database: "Sales".into(),
        schema: None,
        object: None,
        credential: Some(credential),
    }
    .bind_credential_context()
    .unwrap();
    let mut changed = serde_json::to_value(&read).unwrap();
    changed["credential"]["purpose"] = serde_json::json!("controlled_change");
    let change: BoundScope = serde_json::from_value(changed).unwrap();
    assert_eq!(
        read.resource_digest().unwrap(),
        change.resource_digest().unwrap()
    );
    assert_ne!(
        read.credential_scope_digest().unwrap(),
        change.credential_scope_digest().unwrap()
    );
    assert_ne!(read.digest().unwrap(), change.digest().unwrap());
}

#[test]
fn context_edit_rejects_late_response_without_losing_history() {
    let (mut store, id, scope) = fixture();
    let first = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    let late = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    attach_evidence(&mut store, id, envelope(first)).unwrap();
    store
        .revise(
            id,
            3,
            CaseEdit::Impact(crate::helper::case::Answer::Known("changed".into())),
        )
        .unwrap();
    assert!(attach_evidence(&mut store, id, envelope(late)).is_err());
    let case = store.case(id).unwrap();
    assert_eq!(case.revision(), 4);
    assert_eq!(case.evidence_revision(), 1);
    assert_eq!(case.evidence().len(), 1);
    assert_eq!(case.evidence()[0].binding.case_revision, 3);
}

#[test]
fn evidence_survives_restart_and_stale_writer_cannot_overwrite_it() {
    let dir = std::env::temp_dir().join(format!("relayne-evidence-{}", Uuid::new_v4()));
    let path = dir.join("cases.dpapi");
    let (mut store, id, scope) = fixture();
    store.save(&path).unwrap();
    let mut stale = HelperStore::load(&path).unwrap();
    let binding = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    attach_evidence(&mut store, id, envelope(binding)).unwrap();
    store.save(&path).unwrap();
    stale
        .revise(
            id,
            3,
            CaseEdit::Impact(crate::helper::case::Answer::Unknown),
        )
        .unwrap();
    assert!(stale.save(&path).is_err());
    let loaded = HelperStore::load(&path).unwrap();
    assert_eq!(loaded.case(id).unwrap().revision(), 3);
    assert_eq!(loaded.case(id).unwrap().evidence_revision(), 1);
    assert_eq!(loaded.case(id).unwrap().evidence().len(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn declarative_manifest_cannot_serialize_executable_readiness() {
    use crate::helper::manifest::{CapabilityDeclaration, CapabilityManifest};
    let manifest = CapabilityManifest::built_in();
    let text = serde_json::to_string(&manifest).unwrap();
    assert!(!text.contains("ready"));
    assert!(!text.contains("executable"));
    let mut value = serde_json::to_value(&manifest.declarations[0]).unwrap();
    value["ready"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CapabilityDeclaration>(value).is_err());
}

#[test]
fn import_force_downgrades_even_matching_pending_live_capture() {
    let (mut store, id, scope) = fixture();
    let binding = store
        .register_pending_capture(
            id,
            Uuid::new_v4(),
            &scope,
            None,
            CapabilityId::NetworkReachability,
            1,
        )
        .unwrap();
    import_evidence(&mut store, id, envelope(binding.clone())).unwrap();
    assert_eq!(
        store.case(id).unwrap().evidence()[0].origin,
        Origin::ImportedUnverified
    );
    assert_eq!(
        store.case(id).unwrap().evidence()[0].eligibility(Utc::now(), Duration::minutes(5)),
        Eligibility::Imported
    );
    attach_evidence(&mut store, id, envelope(binding)).unwrap();
    assert_eq!(store.case(id).unwrap().evidence()[1].origin, Origin::Live);
}
