use super::*;
use chrono::TimeZone;

#[test]
fn exact_fingerprint_is_domain_separated_and_deterministic() {
    let a=exact_fingerprint(b"same");
    assert_eq!(a,exact_fingerprint(b"same"));
    assert_ne!(a,format!("{:x}",sha2::Sha256::digest(b"same")));
    assert_ne!(a,exact_fingerprint(b"different"));
}

#[test]
fn generic_and_rehearsal_only_evidence_never_qualifies() {
    let now=Utc.timestamp_opt(1_800_000_000,0).unwrap();
    let case=crate::helper::case::HelperCase::new(crate::helper::case::ProblemIntake::default()).unwrap();
    let path=std::env::temp_dir().join(format!("knowledge-test-{}.json",Uuid::new_v4()));
    let journal=crate::helper::journal::ActionJournal::load(&path).unwrap();
    let receipts=crate::helper::verification::ReceiptStore::load(&path).unwrap();
    assert!(generic_candidates(&case,&journal,&receipts,now).is_err());
    let _=std::fs::remove_file(path);
}

#[test]
fn report_allowlist_does_not_serialize_intake_or_scope() {
    let mut intake=crate::helper::case::ProblemIntake::default();
    intake.description=crate::helper::case::Answer::Known("SECRET_SENTINEL_17 SELECT * FROM customers".into());
    let case=crate::helper::case::HelperCase::new(intake).unwrap();
    let bytes=export_report(&case,&[],Utc::now()).unwrap();
    let out=String::from_utf8(bytes).unwrap();
    assert!(!out.contains("SECRET_SENTINEL_17"));
    assert!(!out.contains("SELECT *"));
    assert!(out.contains(&case.id().to_string()));
}

#[test]
fn report_marks_bounded_reference_truncation() {
    let now=Utc::now();
    let case=crate::helper::case::HelperCase::new(crate::helper::case::ProblemIntake::default()).unwrap();
    let lessons=(0..300).map(|_| Lesson {id:Uuid::new_v4(),revision:1,case_id:case.id(),fingerprint:exact_fingerprint(b"scope"),
        status:LessonStatus::Candidate,evidence:vec![EvidenceRef{kind:EvidenceKind::ServiceRun,id:Uuid::new_v4(),digest:exact_fingerprint(b"run")}],
        created_at:now,reviewed_at:None,valid_until:now+Duration::days(90),history:vec![]}).collect::<Vec<_>>();
    let bytes=export_report(&case,&lessons,now).unwrap();
    let report:CaseExport=serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report.evidence.len(),256);
    assert_eq!(report.evidence_total,300);
    assert_eq!(report.evidence_omitted,44);
    assert!(report.truncated);
}

#[test]
fn stale_store_cannot_overwrite_review_and_revocation_is_terminal() {
    let path=std::env::temp_dir().join(format!("knowledge-store-{}.dat",Uuid::new_v4()));
    let now=Utc.timestamp_opt(1_800_000_000,0).unwrap();
    let mut store=KnowledgeStore::default();
    let lesson=Lesson { id:Uuid::new_v4(), revision:1, case_id:Uuid::new_v4(), fingerprint:exact_fingerprint(b"scope"), status:LessonStatus::Candidate,
        evidence:vec![EvidenceRef {kind:EvidenceKind::ServiceRun,id:Uuid::new_v4(),digest:exact_fingerprint(b"run")}], created_at:now, reviewed_at:None,
        valid_until:now+Duration::days(90), history:vec![] };
    let id=lesson.id;
    store.insert(lesson,&path).unwrap();
    let mut stale=KnowledgeStore::load(&path).unwrap();
    store.review(id,1,ReviewDecision::Approve,now,&path).unwrap();
    assert!(stale.review(id,1,ReviewDecision::Approve,now,&path).is_err());
    assert!(stale.recommend(&exact_fingerprint(b"scope"),now).is_empty());
    let mut reviewed=KnowledgeStore::load(&path).unwrap();
    assert_eq!(reviewed.recommend(&exact_fingerprint(b"scope"),now).len(),1);
    reviewed.revalidate(id,2,&exact_fingerprint(b"scope"),true,true,now,&path).unwrap();
    assert!(reviewed.recommend(&exact_fingerprint(b"scope"),now).is_empty());
    assert!(reviewed.revalidate(id,3,&exact_fingerprint(b"scope"),false,true,now,&path).is_err());
    let _=std::fs::remove_file(&path);
    let _=std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn drift_expiry_and_revoked_trust_only_make_a_lesson_stale() {
    let path=std::env::temp_dir().join(format!("knowledge-revalidation-{}.dat",Uuid::new_v4()));
    let now=Utc.timestamp_opt(1_800_000_000,0).unwrap();
    let fingerprint=exact_fingerprint(b"same-scope");
    let mut store=KnowledgeStore::default();
    let mut ids=Vec::new();
    for _ in 0..3 {
        let id=Uuid::new_v4(); ids.push(id);
        store.insert(Lesson {id,revision:1,case_id:Uuid::new_v4(),fingerprint:fingerprint.clone(),status:LessonStatus::Candidate,
            evidence:vec![EvidenceRef{kind:EvidenceKind::ServiceRun,id:Uuid::new_v4(),digest:exact_fingerprint(b"evidence")}],
            created_at:now,reviewed_at:None,valid_until:now+Duration::days(90),history:vec![]},&path).unwrap();
    }
    for id in &ids { store.review(*id,1,ReviewDecision::Approve,now,&path).unwrap(); }
    store.revalidate(ids[0],2,&exact_fingerprint(b"drifted-scope"),false,true,now,&path).unwrap();
    store.revalidate(ids[1],2,&fingerprint,false,false,now,&path).unwrap();
    store.revalidate(ids[2],2,&fingerprint,false,true,now+Duration::days(91),&path).unwrap();
    assert!(store.recommend(&fingerprint,now).is_empty());
    assert!(store.revalidate(ids[0],3,&fingerprint,false,true,now,&path).is_err());
    assert!(store.revalidate(ids[1],3,&fingerprint,false,true,now,&path).is_err());
    assert!(store.revalidate(ids[2],3,&fingerprint,false,true,now,&path).is_err());
    let _=std::fs::remove_file(&path);
    let _=std::fs::remove_file(path.with_extension("lock"));
}
