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
        again.cases[0].intake.onset_frequency,
        Answer::Unknown
    ));
    assert_eq!(again.cases[0].revision, 2);
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
    let id = store.cases[0].id;
    let many = (0..=MAX_PROFILES).map(|_| Uuid::new_v4()).collect();
    assert!(store.revise(id, 1, CaseEdit::Profiles(many)).is_err());
    assert_eq!(store.cases[0].revision, 1);
}
