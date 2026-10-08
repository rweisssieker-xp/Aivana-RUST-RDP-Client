use super::*;
use crate::helper::{
    case::{CaseEdit, ProblemIntake},
    evidence::{
        Coverage, EVIDENCE_SCHEMA, EvidenceBinding, EvidenceEnvelope, EvidenceStatus, Origin,
        TimeQuality, attach_evidence,
    },
    manifest::CapabilityId,
    scope::BoundScope,
};
use crate::mission::Target;

fn fixture() -> (HelperStore, Uuid) {
    let mut store = HelperStore::default();
    let id = store.create(ProblemIntake::default()).unwrap();
    let profile_id = Uuid::new_v4();
    store
        .revise(id, 1, CaseEdit::Profiles(vec![profile_id]))
        .unwrap();
    let scope = BoundScope::Http {
        target: Target {
            profile_id,
            name: "display".into(),
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
    let scope_sha256 = scope.digest().unwrap();
    let credential_scope_sha256 = scope.credential_scope_digest().unwrap();
    store.revise(id, 2, CaseEdit::Scopes(vec![scope])).unwrap();
    let now = Utc::now();
    let envelope = EvidenceEnvelope {
        schema: EVIDENCE_SCHEMA,
        id: Uuid::new_v4(),
        binding: EvidenceBinding {
            case_id: id,
            case_revision: 3,
            request_id: Uuid::new_v4(),
            scope_sha256,
            credential_scope_sha256,
            run_id: None,
        },
        capability_id: CapabilityId::NetworkReachability,
        capability_version: 1,
        parser_version: 1,
        origin: Origin::ImportedUnverified,
        source_id: "SENTINELSECRET123".into(),
        source_observed_at: now,
        retrieved_at: now,
        time_quality: TimeQuality::Trusted,
        status: EvidenceStatus::Partial,
        coverage: Coverage {
            observed: 0,
            expected: 1,
            truncated: false,
        },
        content_sha256: "a".repeat(64),
        records: vec![],
        metrics: vec![],
        evidence_refs: vec![],
    };
    attach_evidence(&mut store, id, envelope).unwrap();
    (store, id)
}

#[test]
fn exports_are_deterministic_bounded_and_omit_source_secret() {
    let (store, id) = fixture();
    let now = Utc::now();
    for format in [ExportFormat::Json, ExportFormat::Markdown] {
        let a = export_case(&store, id, format, now).unwrap();
        let b = export_case(&store, id, format, now).unwrap();
        assert_eq!(a.body, b.body);
        assert!(a.body.len() <= MAX_EXPORT_BYTES);
        assert!(!a.body.contains("SENTINELSECRET123"));
        assert!(a.body.contains("imported_unverified"));
        assert!(a.body.contains("source_observed_at") || a.body.contains("observed"));
        assert!(a.body.contains("coverage") || a.body.contains("Coverage"));
        assert_eq!(a.included_envelopes, 1);
        assert!(!a.truncated);
    }
}

#[test]
fn legacy_case_without_evidence_fields_loads_with_defaults() {
    let (store, id) = fixture();
    let mut value = serde_json::to_value(&store).unwrap();
    let case = &mut value["cases"][0];
    case.as_object_mut().unwrap().remove("evidence");
    case.as_object_mut().unwrap().remove("evidence_holds");
    case["evidence_revision"] = serde_json::json!(0);
    value.as_object_mut().unwrap().remove("pending_captures");
    let legacy: HelperStore = serde_json::from_value(value).unwrap();
    assert!(legacy.case(id).unwrap().evidence().is_empty());
    assert_eq!(legacy.case(id).unwrap().evidence_revision(), 0);
    assert!(export_case(&legacy, id, ExportFormat::Json, Utc::now()).is_ok());
}
