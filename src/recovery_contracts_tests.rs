use super::*;
use crate::{
    execution::{HealthCheck, Mapping},
    intelligence::ServiceState,
    mission::Target,
};
use chrono::Duration;
fn fixture() -> (Contract, DateTime<Utc>) {
    let now = Utc::now() - Duration::minutes(5);
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "Production".into(),
        host: "prod.example.invalid".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: String::new(),
        domain: String::new(),
        route: String::new(),
    };
    let mut lab = target.clone();
    lab.profile_id = Uuid::new_v4();
    lab.host = Uuid::new_v4().to_string();
    lab.port = 0;
    lab.protocol = "Hyper-V".into();
    lab.route = "PowerShellDirect/private-switch".into();
    let plan = ExecutionPlan {
        restart: false,
        service: "Spooler".into(),
        desired: ServiceState::Running,
        health: HealthCheck::Http {
            port: 8080,
            tls: false,
            path: "/health".into(),
            status: 200,
            contains: "ready".into(),
            followups: vec![],
        },
        mappings: vec![Mapping {
            production: target,
            staging: lab,
        }],
    };
    let fp = Fingerprint {
        os_version: "Windows".into(),
        os_build: "1".into(),
        architecture: "64".into(),
        executable_hash: "a".repeat(64),
        executable_version: "1".into(),
        configuration_hash: "b".repeat(64),
        start_mode: "Auto".into(),
        dependencies: vec![],
    };
    let baseline = RehearsalBaseline {
        observed_at: now - Duration::minutes(1),
        rehearsed_at: now,
        fingerprints: vec![fp],
    };
    (
        Contract::new("Test".into(), plan, vec!["proof-one".into()], baseline, now).unwrap(),
        now,
    )
}
fn check(c: &Contract, at: DateTime<Utc>) -> Check {
    Check {
        started: at,
        finished: at,
        fingerprints: c.baseline.fingerprints.clone(),
        error: None,
    }
}
#[test]
fn independent_deadlines() {
    let (mut c, now) = fixture();
    assert_eq!(c.readiness(now), Readiness::Ready);
    assert_eq!(c.readiness(c.next_check_at()), Readiness::CheckDue);
    let at = now + Duration::hours(23);
    c.apply_check(c.revision, check(&c, at), at).unwrap();
    assert_eq!(c.readiness(at), Readiness::Ready);
    assert_eq!(
        c.readiness(now + Duration::hours(24)),
        Readiness::RehearsalDue
    );
}
#[test]
fn drift_is_sticky_and_revokes_guard_even_paused() {
    let (mut c, now) = fixture();
    let at = now + Duration::minutes(1);
    let mut changed = check(&c, at);
    changed.fingerprints[0].os_build = "2".into();
    c.apply_check(c.revision, changed, at).unwrap();
    assert_eq!(c.readiness(at), Readiness::Changed);
    c.apply_check(c.revision, check(&c, at), at).unwrap();
    c.set_settings(60, 24, false).unwrap();
    assert_eq!(c.readiness(at), Readiness::Changed);
    let book = Book {
        contracts: vec![c.clone()],
        ..Default::default()
    };
    assert!(book.ensure_allowed(&c.plan, &c.references, at).is_err());
    assert!(c.invalidated.unwrap().contains("OS-Build"));
}
#[test]
fn errors_are_unknown_and_retry_is_bounded() {
    let (mut c, now) = fixture();
    let at = now + Duration::minutes(1);
    let mut failed = check(&c, at);
    failed.error = Some("password=secret".into());
    failed.fingerprints.clear();
    c.apply_check(c.revision, failed, at).unwrap();
    assert_eq!(c.readiness(at), Readiness::Unknown);
    assert!(!c.check_due(at));
    assert!(c.check_due(at + Duration::hours(1)));
    let mut missing = check(&c, at);
    missing.fingerprints.clear();
    assert!(c.apply_check(c.revision, missing, at).is_err());
}
#[test]
fn stale_workers_and_settings_are_rejected() {
    let (mut c, now) = fixture();
    let revision = c.revision;
    c.set_settings(5, 1, true).unwrap();
    assert!(c.apply_check(revision, check(&c, now), now).is_err());
    for (minutes, hours) in [(4, 1), (1441, 1), (5, 0), (5, 721)] {
        assert!(c.set_settings(minutes, hours, true).is_err());
    }
    let mut future = check(&c, now + Duration::seconds(1));
    assert!(c.apply_check(c.revision, future.clone(), now).is_err());
    future.started = now - Duration::hours(1);
    future.finished = now;
    assert!(c.apply_check(c.revision, future, now).is_err());
}
#[test]
fn renewal_requires_new_rehearsal_and_references_and_revokes_old_proofs() {
    let (mut c, now) = fixture();
    let old = c.references.clone();
    c.invalidate_at("Drift", now);
    let mut fresh = c.baseline.clone();
    assert!(
        c.renew(c.plan.clone(), vec!["proof-two".into()], fresh.clone(), now)
            .is_err()
    );
    fresh.observed_at = now + Duration::minutes(1);
    fresh.rehearsed_at = now + Duration::minutes(2);
    let at = fresh.rehearsed_at;
    assert!(
        c.renew(c.plan.clone(), old.clone(), fresh.clone(), at)
            .is_err()
    );
    c.renew(c.plan.clone(), vec!["proof-two".into()], fresh, at)
        .unwrap();
    assert_eq!(c.readiness(at), Readiness::Ready);
    let book = Book {
        contracts: vec![c.clone()],
        ..Default::default()
    };
    assert!(book.ensure_allowed(&c.plan, &old, at).is_err());
    assert!(book.ensure_allowed(&c.plan, &c.references, at).is_ok());
}
#[test]
fn pause_does_not_bypass_expiry_or_failed_checks() {
    let (mut c, now) = fixture();
    c.set_settings(60, 24, false).unwrap();
    assert_eq!(c.readiness(now), Readiness::Paused);
    assert!(!c.check_due(now + Duration::days(2)));
    let book = Book {
        contracts: vec![c.clone()],
        ..Default::default()
    };
    assert!(
        book.ensure_allowed(&c.plan, &c.references, now + Duration::hours(1))
            .is_err()
    );
}
#[test]
fn encrypted_store_rejects_corruption_and_duplicate_ids() {
    let (c, _) = fixture();
    let path = std::env::temp_dir().join(format!("contract-{}.dpapi", Uuid::new_v4()));
    let book = Book {
        contracts: vec![c.clone()],
        ..Default::default()
    };
    let mut book = book;
    book.save(&path).unwrap();
    assert_eq!(Book::load(&path).unwrap().contracts.len(), 1);
    assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("Spooler"));
    assert!(
        Book {
            contracts: vec![c.clone(), c],
            ..Default::default()
        }
        .save(&path)
        .is_err()
    );
    std::fs::write(&path, b"broken").unwrap();
    assert!(Book::load(&path).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn optimistic_save_prevents_parallel_revocation_loss() {
    let (c, _) = fixture();
    let path = std::env::temp_dir().join(format!("contract-cas-{}.dpapi", Uuid::new_v4()));
    let mut first = Book {
        contracts: vec![c],
        ..Default::default()
    };
    first.save(&path).unwrap();
    let mut stale = Book::load(&path).unwrap();
    first.contracts[0].invalidate("Drift");
    first.save(&path).unwrap();
    stale.contracts[0].set_settings(10, 24, true).unwrap();
    assert!(stale.save(&path).is_err());
    assert!(
        Book::load(&path).unwrap().contracts[0]
            .invalidated
            .is_some()
    );
    assert!(Book::default().save(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(path.with_extension("lock")).unwrap();
}
#[test]
fn all_fingerprint_fields_invalidate_without_exposing_values() {
    for field in 0..8 {
        let (mut c, now) = fixture();
        let mut changed = check(&c, now);
        let fp = &mut changed.fingerprints[0];
        match field {
            0 => fp.os_version = "sensitive-value".into(),
            1 => fp.os_build = "sensitive-value".into(),
            2 => fp.architecture = "sensitive-value".into(),
            3 => fp.executable_hash = "c".repeat(64),
            4 => fp.executable_version = "sensitive-value".into(),
            5 => fp.configuration_hash = "c".repeat(64),
            6 => fp.start_mode = "Manual".into(),
            _ => fp.dependencies = vec!["sensitive-value".into()],
        }
        c.apply_check(c.revision, changed, now).unwrap();
        assert_eq!(c.readiness(now), Readiness::Changed);
        assert!(!c.invalidated.unwrap().contains("sensitive-value"));
    }
}
#[test]
fn invalid_evidence_and_store_bounds_fail_closed() {
    let (c, now) = fixture();
    let mut bad = c.baseline.clone();
    bad.observed_at = now + Duration::seconds(1);
    assert!(
        Contract::new(
            c.name.clone(),
            c.plan.clone(),
            c.references.clone(),
            bad,
            now
        )
        .is_err()
    );
    let mut bad = c.baseline.clone();
    bad.fingerprints.clear();
    assert!(
        Contract::new(
            c.name.clone(),
            c.plan.clone(),
            c.references.clone(),
            bad,
            now
        )
        .is_err()
    );
    assert!(
        Contract::new(
            c.name.clone(),
            c.plan.clone(),
            vec![],
            c.baseline.clone(),
            now
        )
        .is_err()
    );
    let mut book = Book::default();
    for _ in 0..129 {
        let mut clone = c.clone();
        clone.id = Uuid::new_v4();
        book.contracts.push(clone);
    }
    assert!(book.validate().is_err());
    let mut c = c;
    c.revoked_references = (0..MAX_REVOKED).map(|i| format!("old-{i}")).collect();
    let mut baseline = c.baseline.clone();
    baseline.observed_at = now + Duration::minutes(1);
    baseline.rehearsed_at = now + Duration::minutes(2);
    assert!(
        c.renew(
            c.plan.clone(),
            vec!["new".into()],
            baseline,
            now + Duration::minutes(2)
        )
        .is_err()
    );
}
#[test]
fn untracked_plans_allowed_but_matching_hash_and_overlap_are_protected() {
    let (mut c, now) = fixture();
    assert!(
        Book::default()
            .ensure_allowed(&c.plan, &c.references, now)
            .is_ok()
    );
    c.invalidate_at("Drift", now);
    let book = Book {
        contracts: vec![c.clone()],
        ..Default::default()
    };
    assert!(
        book.ensure_allowed(&c.plan, &["fresh-reference".into()], now)
            .is_err()
    );
    let mut changed = c.plan.clone();
    changed.service = "Other".into();
    assert!(book.ensure_allowed(&changed, &c.references, now).is_err());
    assert!(
        book.ensure_allowed(&changed, &["untracked".into()], now)
            .is_ok()
    );
}
#[test]
fn renewal_must_postdate_local_invalidation() {
    let (mut c, now) = fixture();
    c.invalidate_at("Profil geändert", now + Duration::minutes(3));
    let mut baseline = c.baseline.clone();
    baseline.observed_at = now + Duration::minutes(1);
    baseline.rehearsed_at = now + Duration::minutes(2);
    assert!(
        c.renew(
            c.plan.clone(),
            vec!["next".into()],
            baseline.clone(),
            now + Duration::minutes(4)
        )
        .is_err()
    );
    baseline.observed_at = now + Duration::minutes(3);
    baseline.rehearsed_at = now + Duration::minutes(4);
    c.renew(
        c.plan.clone(),
        vec!["next".into()],
        baseline,
        now + Duration::minutes(4),
    )
    .unwrap();
    assert!(c.invalidated_at.is_none());
}
#[test]
fn settings_first_cannot_discard_later_drift_or_failed_check() {
    for failed in [false, true] {
        let (c, now) = fixture();
        let path =
            std::env::temp_dir().join(format!("contract-restrictive-{}.dpapi", Uuid::new_v4()));
        let mut initial = Book {
            contracts: vec![c],
            ..Default::default()
        };
        initial.save(&path).unwrap();
        let mut settings = Book::load(&path).unwrap();
        let mut worker = Book::load(&path).unwrap();
        settings.contracts[0].set_settings(15, 24, true).unwrap();
        settings.save(&path).unwrap();
        let c = &mut worker.contracts[0];
        let mut observation = check(c, now);
        if failed {
            observation.error = Some("failure".into());
            observation.fingerprints.clear();
        } else {
            observation.fingerprints[0].os_build = "changed".into();
        }
        c.apply_check(c.revision, observation, now).unwrap();
        assert!(worker.save(&path).is_err());
        let loaded = Book::load(&path).unwrap();
        assert_eq!(loaded.contracts[0].check_minutes, 15);
        assert_eq!(
            loaded.contracts[0].readiness(now),
            if failed {
                Readiness::Unknown
            } else {
                Readiness::Changed
            }
        );
        assert!(
            loaded
                .ensure_allowed(
                    &loaded.contracts[0].plan,
                    &loaded.contracts[0].references,
                    now
                )
                .is_err()
        );
        std::fs::remove_file(&path).unwrap();
    }
}
#[test]
fn lock_contention_keeps_restrictive_evidence_across_reload() {
    let (c, now) = fixture();
    let path = std::env::temp_dir().join(format!("contract-pending-{}.dpapi", Uuid::new_v4()));
    let mut book = Book {
        contracts: vec![c],
        ..Default::default()
    };
    book.save(&path).unwrap();
    let held = lock_store(&path).unwrap();
    book.contracts[0].invalidate_at("Drift", now);
    assert!(book.save(&path).is_err());
    assert!(Book::load(&path).is_err());
    drop(held);
    let mut reloaded = Book::load(&path).unwrap();
    assert_eq!(reloaded.contracts[0].readiness(now), Readiness::Changed);
    reloaded.save(&path).unwrap();
    assert_eq!(
        Book::load(&path).unwrap().contracts[0].readiness(now),
        Readiness::Changed
    );
    std::fs::remove_file(&path).unwrap();
}
#[test]
fn pending_drift_can_only_be_cleared_by_a_later_rehearsal() {
    let (c, now) = fixture();
    let path =
        std::env::temp_dir().join(format!("contract-pending-renew-{}.dpapi", Uuid::new_v4()));
    let mut book = Book {
        contracts: vec![c],
        ..Default::default()
    };
    book.save(&path).unwrap();
    book.contracts[0].invalidate_at("Drift", now);
    book.persist_restrictions(&path).unwrap();
    let mut loaded = Book::load(&path).unwrap();
    let c = &mut loaded.contracts[0];
    let mut baseline = c.baseline.clone();
    baseline.observed_at = now + Duration::minutes(1);
    baseline.rehearsed_at = now + Duration::minutes(2);
    c.renew(
        c.plan.clone(),
        vec!["new-proof".into()],
        baseline,
        now + Duration::minutes(2),
    )
    .unwrap();
    loaded.save(&path).unwrap();
    let current = Book::load(&path).unwrap();
    assert_eq!(
        current.contracts[0].readiness(now + Duration::minutes(2)),
        Readiness::Ready
    );
    assert!(
        current.contracts[0]
            .revoked_references
            .contains(&"proof-one".to_string())
    );
    std::fs::remove_file(path).unwrap();
}
#[test]
fn journal_write_failure_leaves_durable_block_and_clean_conflict_still_rejects() {
    let (c, now) = fixture();
    let path = std::env::temp_dir().join(format!("contract-blocked-{}.dpapi", Uuid::new_v4()));
    let mut book = Book {
        contracts: vec![c],
        ..Default::default()
    };
    book.save(&path).unwrap();
    book.contracts[0].invalidate_at("Drift", now);
    std::fs::write(path.with_extension("pending"), b"not a directory").unwrap();
    assert!(book.save(&path).is_err());
    assert!(path.with_extension("blocked").exists());
    std::fs::remove_file(path.with_extension("pending")).unwrap();
    assert!(Book::load(&path).is_err());
    std::fs::remove_file(path.with_extension("blocked")).unwrap();
    book.persist_restrictions(&path).unwrap();
    assert_eq!(
        Book::load(&path).unwrap().contracts[0].readiness(now),
        Readiness::Changed
    );
    book.save(&path).unwrap();
    let mut stale = Book::load(&path).unwrap();
    book.contracts[0].set_settings(10, 24, true).unwrap();
    book.save(&path).unwrap();
    stale.contracts[0].set_settings(20, 24, true).unwrap();
    assert!(stale.save(&path).is_err());
    std::fs::remove_file(path).unwrap();
}
#[test]
fn stale_renewal_only_publishes_revocations_and_reports_conflict() {
    let (c, now) = fixture();
    let path = std::env::temp_dir().join(format!("contract-stale-renew-{}.dpapi", Uuid::new_v4()));
    let mut book = Book {
        contracts: vec![c],
        ..Default::default()
    };
    book.save(&path).unwrap();
    let mut stale = Book::load(&path).unwrap();
    book.contracts[0].set_settings(10, 24, true).unwrap();
    book.save(&path).unwrap();
    let c = &mut stale.contracts[0];
    let mut baseline = c.baseline.clone();
    baseline.observed_at = now + Duration::minutes(1);
    baseline.rehearsed_at = now + Duration::minutes(2);
    c.renew(
        c.plan.clone(),
        vec!["new-proof".into()],
        baseline,
        now + Duration::minutes(2),
    )
    .unwrap();
    assert!(stale.save(&path).is_err());
    let loaded = Book::load(&path).unwrap();
    assert_eq!(loaded.contracts[0].references, vec!["proof-one"]);
    assert_eq!(loaded.contracts[0].check_minutes, 10);
    assert_eq!(
        loaded.contracts[0].readiness(Utc::now()),
        Readiness::Changed
    );
    std::fs::remove_file(path).unwrap();
}
