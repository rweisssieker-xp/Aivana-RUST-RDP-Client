use super::*;
use crate::helper::case::ProblemIntake;

#[test]
fn withdrawal_persistence_failure_blocks_existing_authority_in_process() {
    let dir = std::env::temp_dir().join(format!("relayne-authority-gate-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let case_path = dir.join("cases.dpapi");
    let journal_path = dir.join("journal.dpapi");
    let mut store = HelperStore::load(&case_path).unwrap();
    let id = store.create(ProblemIntake::default()).unwrap();
    store.save(&case_path).unwrap();
    std::fs::write(&journal_path, b"corrupt journal").unwrap();
    assert!(withdraw_local_review(&case_path, &journal_path, id).is_err());
    assert!(is_blocked(id).unwrap());
    // The user edit must not proceed after the failed withdrawal; persisted case
    // remains at the original revision and no launch can pass this process gate.
    assert_eq!(
        HelperStore::load(&case_path)
            .unwrap()
            .case(id)
            .unwrap()
            .revision(),
        1
    );
}
