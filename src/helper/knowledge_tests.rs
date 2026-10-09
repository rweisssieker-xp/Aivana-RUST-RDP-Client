use super::*;
use chrono::TimeZone;

fn candidate(case_id:Uuid,fingerprint:String,now:DateTime<Utc>)->Lesson {
    let evidence=vec![EvidenceRef{kind:EvidenceKind::ServiceRun,id:Uuid::new_v4(),digest:exact_fingerprint(Uuid::new_v4().as_bytes())}];
    let trust=TrustRevision{revision:1,reference:evidence[0].clone()};
    let mut lesson=Lesson{id:Uuid::new_v4(),revision:1,case_id,fingerprint,status:LessonStatus::Candidate,evidence,
        created_at:now,reviewed_at:None,valid_until:now+Duration::days(90),trust,history:vec![]};
    lesson.history.push(event(&lesson,now,&lesson.trust,None)); lesson
}

fn verified(case_id:Uuid,fingerprint:String,now:DateTime<Utc>)->Lesson {
    let mut lesson=candidate(case_id,fingerprint,now);
    lesson.status=LessonStatus::Verified; lesson.revision=2; lesson.reviewed_at=Some(now);
    lesson.history.push(event(&lesson,now,&lesson.trust,None)); lesson
}
fn snapshot(lesson:&Lesson)->VerifiedEvidenceSnapshot { snapshot_from_candidate(lesson) }

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
    let sentinel = "PRIVATE_SENTINEL_17";
    intake.description=crate::helper::case::Answer::Known(format!("{sentinel} SELECT * FROM customers"));
    intake.affected_scope=crate::helper::case::Answer::Known(format!("{sentinel} production-db"));
    intake.impact=crate::helper::case::Answer::Known(format!("{sentinel} customer outage"));
    intake.onset_frequency=crate::helper::case::Answer::Known(format!("{sentinel} recurring"));
    intake.permission=crate::helper::case::Answer::Known(format!("{sentinel} credential-scope"));
    intake.recent_changes.push(format!("{sentinel} deploy"));
    intake.attempted_remedies.push(format!("{sentinel} manual SQL"));
    intake.constraints.push(format!("{sentinel} ticket INC-1842"));
    let case=crate::helper::case::HelperCase::new(intake).unwrap();
    let bytes=export_report(&case,&[],Utc::now()).unwrap();
    let out=String::from_utf8(bytes).unwrap();
    assert!(!out.contains(sentinel));
    assert!(!out.contains("SELECT *"));
    assert!(!out.contains("INC-1842"));
    assert!(!out.contains("credential-scope"));
    assert!(out.contains(&case.id().to_string()));
}

#[test]
fn report_validates_malformed_lessons_even_when_they_belong_to_another_case() {
    let now=Utc.timestamp_opt(1_800_000_000,0).unwrap();
    let case=crate::helper::case::HelperCase::new(crate::helper::case::ProblemIntake::default()).unwrap();
    let mut foreign=candidate(Uuid::new_v4(),exact_fingerprint(b"foreign"),now);
    foreign.fingerprint="not-a-digest".into();
    assert!(export_report(&case,&[foreign],now).is_err());
}

#[test]
fn load_rejects_modified_persisted_event_history() {
    let path=std::env::temp_dir().join(format!("knowledge-history-{}.dat",Uuid::new_v4()));
    let now=Utc.timestamp_opt(1_800_000_000,0).unwrap();
    let mut store=KnowledgeStore::default();
    store.insert(candidate(Uuid::new_v4(),exact_fingerprint(b"history-scope"),now),&path).unwrap();
    let clear=crate::security::unprotect_secret(&std::fs::read(&path).unwrap()).unwrap();
    let mut value:serde_json::Value=serde_json::from_slice(&clear).unwrap();
    value["lessons"][0]["history"][0]["event_sha256"]=serde_json::Value::String("0".repeat(64));
    let protected=crate::security::protect_secret(&serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::write(&path,protected).unwrap();
    assert!(KnowledgeStore::load(&path).is_err());
    let _=std::fs::remove_file(&path);
    let _=std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn report_marks_bounded_reference_truncation() {
    let now=Utc::now();
    let case=crate::helper::case::HelperCase::new(crate::helper::case::ProblemIntake::default()).unwrap();
    let lessons=(0..300).map(|_| verified(case.id(),exact_fingerprint(b"scope"),now)).collect::<Vec<_>>();
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
    let lesson=candidate(Uuid::new_v4(),exact_fingerprint(b"scope"),now);
    let id=lesson.id;
    let proof=snapshot(&lesson); let trust=lesson.trust.clone();
    store.insert(lesson,&path).unwrap();
    let mut stale=KnowledgeStore::load(&path).unwrap();
    store.review(id,1,ReviewDecision::Approve,now,&path).unwrap();
    assert!(stale.review(id,1,ReviewDecision::Approve,now,&path).is_err());
    assert!(stale.recommend(&proof,now).is_empty());
    let mut reviewed=KnowledgeStore::load(&path).unwrap();
    assert_eq!(reviewed.recommend(&proof,now).len(),1);
    reviewed.invalidate(id,2,InvalidationReason::OperatorReportedRegression,&trust.reference,now,&path).unwrap();
    let invalidated=KnowledgeStore::load(&path).unwrap();
    assert!(invalidated.recommend(&proof,now).is_empty());
    let event=invalidated.lessons()[0].history.last().unwrap();
    assert_eq!(event.invalidation_reason,Some(InvalidationReason::OperatorReportedRegression));
    assert_eq!(event.invalidation_evidence.as_ref(),Some(&trust.reference));
    // A recovered snapshot with the same fingerprint and trust revision cannot revive a terminal invalidation.
    assert!(reviewed.revalidate(id,3,&exact_fingerprint(b"scope"),&trust,now,&path).is_err());
    let _=std::fs::remove_file(&path);
    let _=std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn drift_expiry_and_revoked_trust_only_make_a_lesson_stale() {
    let path=std::env::temp_dir().join(format!("knowledge-revalidation-{}.dat",Uuid::new_v4()));
    let now=Utc.timestamp_opt(1_800_000_000,0).unwrap();
    let fingerprint=exact_fingerprint(b"same-scope");
    let mut store=KnowledgeStore::default();
    let mut ids=Vec::new(); let mut trusts=Vec::new(); let mut proofs=Vec::new();
    for _ in 0..3 {
        let lesson=candidate(Uuid::new_v4(),fingerprint.clone(),now); ids.push(lesson.id); trusts.push(lesson.trust.clone()); proofs.push(snapshot(&lesson));
        store.insert(lesson,&path).unwrap();
    }
    for id in &ids { store.review(*id,1,ReviewDecision::Approve,now,&path).unwrap(); }
    let revoked=TrustRevision{revision:trusts[1].revision+1,reference:trusts[1].reference.clone()};
    store.revalidate(ids[0],2,&exact_fingerprint(b"drifted-scope"),&trusts[0],now,&path).unwrap();
    store.revalidate(ids[1],2,&fingerprint,&revoked,now,&path).unwrap();
    store.revalidate(ids[2],2,&fingerprint,&trusts[2],now+Duration::days(91),&path).unwrap();
    assert!(store.recommend(&proofs[0],now).is_empty());
    assert!(store.revalidate(ids[0],3,&fingerprint,&trusts[0],now,&path).is_err());
    assert!(store.revalidate(ids[1],3,&fingerprint,&trusts[1],now,&path).is_err());
    assert!(store.revalidate(ids[2],3,&fingerprint,&trusts[2],now,&path).is_err());
    let _=std::fs::remove_file(&path);
    let _=std::fs::remove_file(path.with_extension("lock"));
}
