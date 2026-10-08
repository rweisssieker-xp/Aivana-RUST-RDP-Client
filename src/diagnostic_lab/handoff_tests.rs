use super::*;
use crate::incident::{Kind, Record, Source};
use crate::models::ConnectionProfile;

fn profile() -> ConnectionProfile {
    ConnectionProfile::sample("Affected", "affected.example.test", "", false)
}

fn config(profile: &ConnectionProfile) -> Config {
    Config {
        mode: Mode::ReadOnly,
        scenario: None,
        target: Some(Target::from_profile(profile)),
        incident: "Application unavailable".into(),
        service: "AppService".into(),
        application: "https://app.example.test/health".into(),
        dependency: "https://dependency.example.test/health".into(),
    }
}

fn failure(profile: &ConnectionProfile, at: DateTime<Utc>) -> Record {
    let target = Target::from_profile(profile);
    Record {
        id: "telemetry:failure-123".into(),
        profile: Some(profile.id),
        endpoint: Some(crate::incident::endpoint_key(&target)),
        at,
        kind: Kind::Failure,
        title: "Application unavailable".into(),
        evidence: vec!["capture-7".into(), "job-8".into()],
    }
}

#[test]
fn incident_source_requires_the_exact_selected_endpoint_and_failure() {
    let profile = profile();
    let target = Target::from_profile(&profile);
    let now = Utc::now();
    let record = failure(&profile, now);
    let source = Source::from_failure(&record, &target).unwrap();
    assert_eq!(source.record_id, record.id);
    assert_eq!(source.evidence, record.evidence);
    let mut changed = target.clone();
    changed.host = "another.example.test".into();
    assert!(Source::from_failure(&record, &changed).is_err());
    let mut unrelated = record;
    unrelated.kind = Kind::Observation;
    assert!(Source::from_failure(&unrelated, &target).is_err());
}

#[test]
fn incident_case_binds_source_and_preserves_legacy_case_binding() {
    let profile = profile();
    let now = Utc::now();
    let source =
        Source::from_failure(&failure(&profile, now), &Target::from_profile(&profile)).unwrap();
    let mut legacy = Case::new(config(&profile), now).unwrap();
    let request = legacy.request(Probe::Service, now).unwrap();
    legacy.record(&request, Value::Pass, now).unwrap();
    let old_binding = hash(&(legacy.id, &legacy.config, legacy.created)).unwrap();
    assert_eq!(legacy.binding().unwrap(), old_binding);
    let restored: Case = serde_json::from_value({
        let mut value = serde_json::to_value(&legacy).unwrap();
        value.as_object_mut().unwrap().remove("source");
        value
    })
    .unwrap();
    assert_eq!(restored.binding().unwrap(), old_binding);
    restored.validate().unwrap();
    let mut case = Case::new_from_incident(config(&profile), source, now).unwrap();
    let reloaded: Case = serde_json::from_value(serde_json::to_value(&case).unwrap()).unwrap();
    assert_eq!(
        reloaded.source.as_ref().unwrap().evidence,
        vec!["capture-7", "job-8"]
    );
    assert_eq!(reloaded.binding().unwrap(), case.binding().unwrap());
    let before = case.binding().unwrap();
    case.source
        .as_mut()
        .unwrap()
        .evidence
        .push("another-evidence-id".into());
    assert_ne!(case.binding().unwrap(), before);
    let mut changed = config(&profile);
    changed.target.as_mut().unwrap().host = "another.example.test".into();
    assert!(Case::new_from_incident(changed, case.source.unwrap(), now).is_err());
}

#[test]
fn verification_handoff_excludes_simulation_and_changed_profile() {
    let profile = profile();
    let now = Utc::now();
    let source =
        Source::from_failure(&failure(&profile, now), &Target::from_profile(&profile)).unwrap();
    let case = Case::new_from_incident(config(&profile), source, now).unwrap();
    let handoff = case.verification_handoff(&profile).unwrap();
    assert_eq!(handoff.case_id, case.id);
    assert_eq!(handoff.binding, case.binding().unwrap());
    assert_eq!(
        handoff.source_record.as_deref(),
        Some("telemetry:failure-123")
    );
    assert_eq!(handoff.source_evidence, vec!["capture-7", "job-8"]);
    let mut changed = profile.clone();
    changed.host = "changed.example.test".into();
    assert!(case.verification_handoff(&changed).is_err());
    let simulated = Case::new(
        Config {
            mode: Mode::Simulation,
            scenario: Some(Scenario::Service),
            target: None,
            ..config(&profile)
        },
        now,
    )
    .unwrap();
    assert!(simulated.verification_handoff(&profile).is_err());
}

#[test]
fn stale_and_missing_checks_cannot_become_functional_success() {
    let profile = profile();
    let now = Utc::now();
    let mut case = Case::new(config(&profile), now).unwrap();
    let request = case.request(Probe::Service, now).unwrap();
    case.record(&request, Value::Fail, now).unwrap();
    let stale = case.assess(now + chrono::Duration::minutes(6));
    assert_eq!(stale.known, 0);
    assert_eq!(stale.candidates[0].missing.len(), 4);

    let mut complete = Case::new(config(&profile), now).unwrap();
    for probe in Probe::ALL {
        let request = complete.request(probe, now).unwrap();
        complete
            .record(
                &request,
                if probe == Probe::Service {
                    Value::Fail
                } else {
                    Value::Pass
                },
                now,
            )
            .unwrap();
    }
    assert_eq!(complete.assess(now).known, 4);
    assert!(complete.assess(now).conclusion().contains("does not prove"));
    // The handoff carries context only; it cannot contain a functional success state.
    let handoff = complete.verification_handoff(&profile).unwrap();
    assert_eq!(handoff.case_id, complete.id);
}
