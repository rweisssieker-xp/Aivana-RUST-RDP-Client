use super::*;
use crate::{
    models::ConnectionProfile,
    security::{CredentialStore, PersistentCredentialStore},
};

fn secret(name: &str, password: &str) -> SecretCredential {
    SecretCredential {
        username: name.into(),
        password: password.into(),
        domain: String::new(),
    }
}
fn scope(reference: &ScopedCredentialRef) -> CredentialScope {
    CredentialScope {
        reference: reference.id,
        purpose: reference.purpose,
        generation: reference.generation,
        principal: reference.principal.clone(),
        context: reference.context.clone(),
        context_digest: reference.scope_digest.clone(),
    }
}

#[test]
fn scoped_rotation_revoke_and_exact_purpose_fail_closed() {
    let dir = std::env::temp_dir().join(format!("relayne-scoped-{}", Uuid::new_v4()));
    let mut store = PersistentCredentialStore::at(dir.join("credentials.json")).unwrap();
    let digest = "a".repeat(64);
    let first = store
        .save_scoped(
            &digest,
            CredentialPurpose::Read,
            secret("alice", "sentinel-1"),
        )
        .unwrap();
    let resolver = PersistentSecretResolver::at(dir.join("credentials.scoped.dpapi"));
    assert_eq!(
        resolver
            .resolve(&scope(&first), CredentialPurpose::Read)
            .unwrap()
            .password(),
        "sentinel-1"
    );
    assert!(
        resolver
            .resolve(&scope(&first), CredentialPurpose::Diagnose)
            .is_err()
    );
    let mut wrong = scope(&first);
    wrong.context = "other-context".into();
    assert!(resolver.resolve(&wrong, CredentialPurpose::Read).is_err());
    wrong = scope(&first);
    wrong.context_digest = "b".repeat(64);
    assert!(resolver.resolve(&wrong, CredentialPurpose::Read).is_err());
    let second = store
        .save_scoped(
            &digest,
            CredentialPurpose::Read,
            secret("alice", "sentinel-2"),
        )
        .unwrap();
    assert_eq!(second.generation, first.generation + 1);
    assert_ne!(second.id, first.id);
    assert!(
        resolver
            .resolve(&scope(&first), CredentialPurpose::Read)
            .is_err()
    );
    assert_eq!(
        resolver
            .resolve(&scope(&second), CredentialPurpose::Read)
            .unwrap()
            .password(),
        "sentinel-2"
    );
    store.revoke_scoped(second.id).unwrap();
    assert!(
        resolver
            .resolve(&scope(&second), CredentialPurpose::Read)
            .is_err()
    );
    let bytes = fs::read(dir.join("credentials.scoped.dpapi")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("sentinel"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn legacy_profile_secret_survives_scoped_vault_use() {
    let dir = std::env::temp_dir().join(format!("relayne-legacy-{}", Uuid::new_v4()));
    let path = dir.join("credentials.json");
    let mut store = PersistentCredentialStore::at(path.clone()).unwrap();
    let mut profile = ConnectionProfile::sample("test", "example.invalid", "Default", false);
    let legacy = store
        .save(&mut profile, secret("legacy", "legacy-sentinel"))
        .unwrap();
    store
        .save_scoped(
            &"c".repeat(64),
            CredentialPurpose::Diagnose,
            secret("helper", "helper-sentinel"),
        )
        .unwrap();
    let reopened = PersistentCredentialStore::at(path).unwrap();
    assert_eq!(
        reopened.get(legacy.id).unwrap().unwrap().password,
        "legacy-sentinel"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn legacy_store_rejects_stale_saves_and_scoped_store_rejects_corruption() {
    let dir = std::env::temp_dir().join(format!("relayne-credential-cas-{}", Uuid::new_v4()));
    let path = dir.join("credentials.json");
    let mut first = PersistentCredentialStore::at(path.clone()).unwrap();
    let mut stale = PersistentCredentialStore::at(path.clone()).unwrap();
    let mut p1 = ConnectionProfile::sample("first", "one.invalid", "Default", false);
    let id = first
        .save(&mut p1, secret("first", "first-sentinel"))
        .unwrap()
        .id;
    let mut p2 = ConnectionProfile::sample("stale", "two.invalid", "Default", false);
    assert!(
        stale
            .save(&mut p2, secret("stale", "second-sentinel"))
            .is_err()
    );
    assert_eq!(
        PersistentCredentialStore::at(path)
            .unwrap()
            .get(id)
            .unwrap()
            .unwrap()
            .password,
        "first-sentinel"
    );

    let scoped_path = dir.join("credentials.scoped.dpapi");
    fs::write(&scoped_path, b"unknown-or-corrupt").unwrap();
    let resolver = PersistentSecretResolver::at(scoped_path.clone());
    let missing = CredentialScope {
        reference: Uuid::new_v4(),
        purpose: CredentialPurpose::Read,
        generation: 1,
        principal: "first".into(),
        context: "a".repeat(64),
        context_digest: "a".repeat(64),
    };
    assert!(resolver.resolve(&missing, CredentialPurpose::Read).is_err());
    assert!(
        save_scoped_at(
            &scoped_path,
            &"a".repeat(64),
            CredentialPurpose::Read,
            secret("first", "new-sentinel")
        )
        .is_err()
    );
    assert_eq!(fs::read(scoped_path).unwrap(), b"unknown-or-corrupt");
    fs::remove_dir_all(dir).unwrap();
}
