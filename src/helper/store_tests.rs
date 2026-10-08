use super::*;
use crate::helper::case::{Answer, CaseEdit, MAX_DESCRIPTION, MAX_LIST, MAX_PROFILES};

#[test]
fn unknown_answer_round_trips() {
    let dir = std::env::temp_dir().join(format!("relayne-helper-{}", Uuid::new_v4()));
    let path = dir.join("cases.dpapi");
    let mut store = HelperStore::load(&path).unwrap();
    let id = store.create(ProblemIntake::default()).unwrap();
    store
        .revise(id, 1, CaseEdit::OnsetFrequency(Answer::Unknown))
        .unwrap();
    store.save(&path).unwrap();
    let again = HelperStore::load(&path).unwrap();
    assert!(matches!(
        again.cases()[0].intake().onset_frequency,
        Answer::Unknown
    ));
    assert_eq!(again.cases()[0].revision(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn stale_revision_and_corrupt_store_rejected() {
    let dir = std::env::temp_dir().join(format!("relayne-helper-{}", Uuid::new_v4()));
    let path = dir.join("cases.dpapi");
    let mut a = HelperStore::load(&path).unwrap();
    let id = a.create(ProblemIntake::default()).unwrap();
    a.save(&path).unwrap();
    let mut b = HelperStore::load(&path).unwrap();
    assert!(b.revise(id, 0, CaseEdit::Impact(Answer::Unknown)).is_err());
    a.revise(id, 1, CaseEdit::Impact(Answer::Unknown)).unwrap();
    a.save(&path).unwrap();
    b.revise(id, 1, CaseEdit::Description(Answer::Unknown))
        .unwrap();
    assert!(b.save(&path).is_err());
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(HelperStore::load(&path).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn fixed_case_and_intake_caps() {
    let mut store = HelperStore::default();
    assert!(
        store
            .create(ProblemIntake {
                description: Answer::Known("x".repeat(MAX_DESCRIPTION + 1)),
                ..Default::default()
            })
            .is_err()
    );
    assert!(
        store
            .create(ProblemIntake {
                constraints: vec!["x".into(); MAX_LIST + 1],
                ..Default::default()
            })
            .is_err()
    );
    for _ in 0..MAX_CASES {
        store.create(ProblemIntake::default()).unwrap();
    }
    assert!(store.create(ProblemIntake::default()).is_err());
    let id = store.cases()[0].id();
    let many = (0..=MAX_PROFILES).map(|_| Uuid::new_v4()).collect();
    assert!(store.revise(id, 1, CaseEdit::Profiles(many)).is_err());
    assert_eq!(store.cases()[0].revision(), 1);
}

#[test]
fn read_only_case_copy_cannot_bypass_revision_or_persist_claimed_resolution() {
    let dir = std::env::temp_dir().join(format!("relayne-helper-{}", Uuid::new_v4()));
    let path = dir.join("cases.dpapi");
    let mut store = HelperStore::load(&path).unwrap();
    let id = store.create(ProblemIntake::default()).unwrap();
    store.save(&path).unwrap();

    let mut detached = store.case(id).unwrap().clone();
    detached
        .revise(
            1,
            CaseEdit::AffectedScope(Answer::Known("another host".into())),
        )
        .unwrap();
    assert_eq!(detached.revision(), 2);
    assert_eq!(store.case(id).unwrap().revision(), 1);
    assert!(matches!(
        store.case(id).unwrap().intake().affected_scope,
        Answer::Unanswered
    ));
    assert!(store.case(id).unwrap().resolution().is_none());

    assert!(
        store
            .revise(id, 0, CaseEdit::AffectedScope(Answer::Unknown))
            .is_err()
    );
    assert_eq!(
        store
            .revise(id, 1, CaseEdit::AffectedScope(Answer::Unknown))
            .unwrap(),
        2
    );
    assert!(
        store
            .revise(
                id,
                1,
                CaseEdit::AffectedScope(Answer::Known("stale".into()))
            )
            .is_err()
    );
    store.save(&path).unwrap();
    let loaded = HelperStore::load(&path).unwrap();
    assert_eq!(loaded.case(id).unwrap().revision(), 2);
    assert!(matches!(
        loaded.case(id).unwrap().intake().affected_scope,
        Answer::Unknown
    ));
    assert!(loaded.case(id).unwrap().resolution().is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn deserialized_store_cannot_become_a_new_persistence_authority() {
    let mut store = HelperStore::default();
    store.create(ProblemIntake::default()).unwrap();
    let raw = serde_json::to_vec(&store).unwrap();
    let mut detached: HelperStore = serde_json::from_slice(&raw).unwrap();
    let dir = std::env::temp_dir().join(format!("relayne-helper-{}", Uuid::new_v4()));
    let path = dir.join("cases.dpapi");
    assert!(detached.save(&path).is_err());
    assert!(!path.exists());
}
