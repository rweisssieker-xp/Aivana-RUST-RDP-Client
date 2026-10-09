//! Reviewed, bounded operating knowledge. Raw case/journal text never crosses the report boundary.
use super::{case::{CaseResolution, HelperCase}, journal::{ActionJournal, IntentState}, verification::{PerformancePhase, ReceiptStore}};
use crate::execution::{self, Journal as ServiceJournal};
use crate::mission::Target;
use anyhow::{ensure, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const MAX_LESSONS: usize = 4096;
pub const MAX_REPORT_BYTES: usize = 128 * 1024;
const DOMAIN: &[u8] = b"relayne-helper-lesson-fingerprint-v1\0";
const EVENT_DOMAIN: &[u8] = b"relayne-helper-lesson-event-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum ReviewDecision { Approve, Reject }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum LessonStatus { Candidate, Verified, Rejected, Stale, Invalidated }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum InvalidationReason { OperatorReportedRegression, AdverseProductionEvidence, SecurityOrPolicyChange }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef { pub kind: EvidenceKind, pub id: Uuid, pub digest: String }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRevision { pub revision: u64, pub reference: EvidenceRef }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum EvidenceKind { ServiceRun, GenericIntent, FunctionalReceipt, PerformanceReceipt }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lesson {
    pub id: Uuid, pub revision: u64, pub case_id: Uuid, pub fingerprint: String,
    pub status: LessonStatus, pub evidence: Vec<EvidenceRef>, pub created_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>, pub valid_until: DateTime<Utc>,
    pub trust: TrustRevision, pub history: Vec<LessonEvent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The hash chain detects accidental or partial history corruption. Its trust boundary remains the
/// DPAPI-protected store and fresh receipt verification; the chain is not a keyed MAC.
pub struct LessonEvent {
    pub revision: u64, pub status: LessonStatus, pub at: DateTime<Utc>,
    pub evidence_digest: String, pub trust_revision: u64, pub trust_digest: String,
    pub trust_reference_id: Uuid, pub trust_reference_kind: EvidenceKind,
    pub invalidation_reason: Option<InvalidationReason>, pub invalidation_evidence: Option<EvidenceRef>,
    pub prior_event_sha256: Option<String>, pub event_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonMatch { pub lesson_id: Uuid, pub fingerprint: String, pub evidence: Vec<EvidenceRef> }
#[derive(Clone, Debug)]
pub struct VerifiedEvidenceSnapshot { fingerprint: String, trust: TrustRevision, evidence: Vec<EvidenceRef> }
impl VerifiedEvidenceSnapshot {
    pub fn fingerprint(&self)->&str { &self.fingerprint }
    pub fn trust(&self)->&TrustRevision { &self.trust }
    pub fn evidence(&self)->&[EvidenceRef] { &self.evidence }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseExport {
    pub schema: u16, pub case_id: Uuid, pub case_revision: u64, pub status: Option<CaseResolution>,
    pub evidence: Vec<EvidenceRef>, pub evidence_total: usize, pub evidence_omitted: usize,
    pub lesson_count: usize, pub lessons_omitted: usize, pub truncated: bool,
    pub generated_at: DateTime<Utc>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFormat { Json, Markdown }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeStore { schema: u16, lessons: Vec<Lesson>, #[serde(skip)] source_digest: Option<[u8;32]> }
impl Default for KnowledgeStore { fn default()->Self { Self { schema:1, lessons:Vec::new(), source_digest:None } } }

pub fn exact_fingerprint(bytes: &[u8]) -> String {
    let mut hash = Sha256::new(); hash.update(DOMAIN); hash.update(bytes); format!("{:x}", hash.finalize())
}
fn valid_digest(s: &str) -> bool { s.len()==64 && s.bytes().all(|b| b.is_ascii_hexdigit()) }
fn refs_digest(refs: &[EvidenceRef]) -> String { exact_fingerprint(&serde_json::to_vec(refs).unwrap_or_default()) }

/// Service lessons follow the accepted historical qualifier, then retain only opaque run references.
pub fn service_candidates(case: &HelperCase, journal: &ServiceJournal, target: &Target, now: DateTime<Utc>) -> Result<Vec<Lesson>> {
    ensure!(case.resolution()==Some(CaseResolution::VerifiedRelayneRepair), "case is not a verified Relayne repair");
    let linked_runs=journal.runs.iter().filter(|r| r.diagnostic.as_ref().is_some_and(|d|d.case_id==case.id()))
        .map(|r|r.id).collect::<std::collections::BTreeSet<_>>();
    let ranked=execution::learning::rank(journal,target,now);
    let mut out=Vec::new();
    for row in ranked.into_iter().filter(|r| r.eligible()) {
        let refs=row.lesson.evidence.iter().filter(|e| linked_runs.contains(&e.run_id) && !e.rehearsal && e.phase==execution::Phase::Passed)
            .map(|e| EvidenceRef { kind: EvidenceKind::ServiceRun, id:e.run_id, digest: exact_fingerprint(e.run_id.as_bytes()) }).collect::<Vec<_>>();
        if refs.is_empty() { continue; }
        ensure!(case.evidence_revision()>0,"Verified service case has no evidence revision");
        let trust=TrustRevision {revision:case.evidence_revision(),reference:refs[0].clone()};
        let fingerprint=exact_fingerprint(row.lesson.key.as_bytes());
        let mut lesson=Lesson { id:Uuid::new_v4(), revision:1, case_id:case.id(), fingerprint, status:LessonStatus::Candidate, evidence:refs, created_at:now, reviewed_at:None, valid_until:now+Duration::days(90), trust, history:vec![] };
 lesson.history.push(event(&lesson,now,&lesson.trust,None)); out.push(lesson);
    }
    Ok(out)
}

/// Generic lessons require the persisted closed-case proof and exact checked receipt membership.
pub fn generic_candidates(case:&HelperCase, journal:&ActionJournal, receipts:&ReceiptStore, now:DateTime<Utc>) -> Result<Vec<Lesson>> {
    ensure!(case.resolution()==Some(CaseResolution::VerifiedRelayneRepair), "case is not a verified Relayne repair");
    receipts.verify_resolution_from_store(case,journal)?;
    let links=case.resolution_review().and_then(|review|review.proof_links.as_ref())
        .ok_or_else(||anyhow::anyhow!("Verified repair lacks receipt links"))?;
    let intent=journal.intents().iter().find(|i|i.id==links.intent_id && i.run_id==links.run_id && i.case_id==case.id())
        .ok_or_else(||anyhow::anyhow!("Exact production intent is missing"))?;
    ensure!(intent.state==IntentState::Verified && !intent.restoration_pending && intent.restoration_outcome.is_none(),
        "Production intent is no longer verified or has restoration evidence");
    ensure!(!journal.intents().iter().any(|later| later.case_id==case.id()
        && later.binding_fingerprint==intent.binding_fingerprint && later.updated_at>intent.updated_at
        && (later.state!=IntentState::Verified || later.restoration_pending || later.restoration_outcome.is_some())),
        "Later adverse action evidence prevents qualification");
    let functional=receipts.functional().iter().find(|r|r.id().ok()==Some(links.functional_receipt_id)
        && r.content_sha256().ok().as_deref()==Some(links.functional_receipt_sha256.as_str()))
        .ok_or_else(||anyhow::anyhow!("Exact functional receipt is missing"))?;
    ensure!(functional.all_passed(),"Functional checks are not all passing");
    let intent_ref=EvidenceRef {kind:EvidenceKind::GenericIntent,id:intent.id,digest:exact_fingerprint(intent.binding_fingerprint.as_bytes())};
    ensure!(case.evidence_revision()>0,"Verified production case has no evidence revision");
    let trust=TrustRevision {revision:case.evidence_revision(),reference:intent_ref.clone()};
    let mut refs=vec![
        intent_ref,
        EvidenceRef {kind:EvidenceKind::FunctionalReceipt,id:links.functional_receipt_id,digest:links.functional_receipt_sha256.clone()},
    ];
    if let (Some(id),Some(hash))=(links.baseline_receipt_id,links.baseline_receipt_sha256.as_deref()) {
        let receipt=receipts.performance().iter().find(|r|r.phase==PerformancePhase::BeforeProduction
            && r.id().ok()==Some(id) && r.content_sha256().ok().as_deref()==Some(hash))
            .ok_or_else(||anyhow::anyhow!("Exact baseline receipt is missing"))?;
        refs.push(EvidenceRef {kind:EvidenceKind::PerformanceReceipt,id,digest:receipt.content_sha256()?});
    }
    if let (Some(id),Some(hash))=(links.after_receipt_id,links.after_receipt_sha256.as_deref()) {
        let receipt=receipts.performance().iter().find(|r|r.phase==PerformancePhase::AfterProduction
            && r.id().ok()==Some(id) && r.content_sha256().ok().as_deref()==Some(hash))
            .ok_or_else(||anyhow::anyhow!("Exact after receipt is missing"))?;
        refs.push(EvidenceRef {kind:EvidenceKind::PerformanceReceipt,id,digest:receipt.content_sha256()?});
    }
    let fingerprint=exact_fingerprint(intent.binding_fingerprint.as_bytes());
    let mut lesson=Lesson {id:Uuid::new_v4(),revision:1,case_id:case.id(),fingerprint,status:LessonStatus::Candidate,
        evidence:refs,created_at:now,reviewed_at:None,valid_until:now+Duration::days(90),trust,history:vec![]};
 lesson.history.push(event(&lesson,now,&lesson.trust,None));
    Ok(vec![lesson])
}

pub fn generic_evidence_snapshot(case:&HelperCase,journal:&ActionJournal,receipts:&ReceiptStore,now:DateTime<Utc>)->Result<VerifiedEvidenceSnapshot> {
    let candidate=generic_candidates(case,journal,receipts,now)?.into_iter().next().ok_or_else(||anyhow::anyhow!("No qualifying generic evidence"))?;
    Ok(snapshot_from_candidate(&candidate))
}

pub fn service_evidence_snapshots(case:&HelperCase,journal:&ServiceJournal,target:&Target,now:DateTime<Utc>)->Result<Vec<VerifiedEvidenceSnapshot>> {
    Ok(service_candidates(case,journal,target,now)?.iter().map(snapshot_from_candidate).collect())
}

fn snapshot_from_candidate(candidate:&Lesson)->VerifiedEvidenceSnapshot {
    VerifiedEvidenceSnapshot {fingerprint:candidate.fingerprint.clone(),trust:candidate.trust.clone(),evidence:candidate.evidence.clone()}
}

fn event_hash(event:&LessonEvent)->String {
    let payload=serde_json::to_vec(&(event.revision,event.status,event.at,event.evidence_digest.as_str(),event.trust_revision,
        event.trust_digest.as_str(),event.trust_reference_id,event.trust_reference_kind,event.invalidation_reason,
        event.invalidation_evidence.as_ref(),event.prior_event_sha256.as_deref())).unwrap_or_default();
    let mut hash=Sha256::new(); hash.update(EVENT_DOMAIN); hash.update(payload); format!("{:x}",hash.finalize())
}
fn event(l:&Lesson,at:DateTime<Utc>,trust:&TrustRevision,invalidation:Option<(InvalidationReason,EvidenceRef)>)->LessonEvent {
    let mut item=LessonEvent {revision:l.revision,status:l.status,at,evidence_digest:refs_digest(&l.evidence),trust_revision:trust.revision,
        trust_digest:trust.reference.digest.clone(),trust_reference_id:trust.reference.id,trust_reference_kind:trust.reference.kind,
        invalidation_reason:invalidation.as_ref().map(|(reason,_)|*reason),invalidation_evidence:invalidation.map(|(_,reference)|reference),
        prior_event_sha256:l.history.last().map(|e|e.event_sha256.clone()),event_sha256:String::new()};
    item.event_sha256=event_hash(&item); item
}
fn validate_lesson(lesson:&Lesson)->Result<()> {
    ensure!(!lesson.id.is_nil() && !lesson.case_id.is_nil() && lesson.revision>0,"Invalid lesson identity/revision");
    ensure!(valid_digest(&lesson.fingerprint) && lesson.valid_until>lesson.created_at,"Invalid lesson fingerprint or expiry");
    ensure!(lesson.valid_until<=lesson.created_at+Duration::days(90),"Lesson expiry exceeds policy");
    ensure!(lesson.evidence.len()>0 && lesson.evidence.len()<=16,"Invalid lesson evidence count");
    let mut refs=std::collections::BTreeSet::new();
    for reference in &lesson.evidence {
        ensure!(!reference.id.is_nil() && valid_digest(&reference.digest) && refs.insert((reference.kind as u8,reference.id)),"Invalid/duplicate lesson evidence reference");
    }
    ensure!(lesson.trust.revision>0 && valid_digest(&lesson.trust.reference.digest)
        && lesson.evidence.contains(&lesson.trust.reference),"Lesson trust revision is not evidence-bound");
    ensure!(lesson.history.len()==lesson.revision as usize && !lesson.history.is_empty(),"Lesson history/revision mismatch");
    for (index,item) in lesson.history.iter().enumerate() {
        ensure!(item.revision==index as u64+1 && item.trust_revision>0 && !item.trust_reference_id.is_nil()
            && valid_digest(&item.trust_digest) && item.evidence_digest==refs_digest(&lesson.evidence)
            && valid_digest(&item.event_sha256) && item.event_sha256==event_hash(item),"Invalid lesson history event");
        ensure!(if item.status==LessonStatus::Invalidated {
            item.invalidation_reason.is_some() && item.invalidation_evidence.as_ref().is_some_and(|e|lesson.evidence.contains(e))
        } else { item.invalidation_reason.is_none() && item.invalidation_evidence.is_none() },"Invalid lesson event lacks typed invalidation reason/evidence");
        let expected_prior=index.checked_sub(1).map(|previous|lesson.history[previous].event_sha256.as_str());
        ensure!(item.prior_event_sha256.as_deref()==expected_prior,"Lesson history chain is broken");
        if index==0 { ensure!(item.status==LessonStatus::Candidate && item.trust_revision==lesson.trust.revision
            && item.trust_reference_id==lesson.trust.reference.id && item.trust_reference_kind==lesson.trust.reference.kind
            && item.trust_digest==lesson.trust.reference.digest,"Lesson history must begin as candidate"); }
        else {
            let previous=lesson.history[index-1].status;
            ensure!(item.at>=lesson.history[index-1].at,"Lesson history time moved backwards");
            ensure!(matches!((previous,item.status),(LessonStatus::Candidate,LessonStatus::Verified|LessonStatus::Rejected)
                |(LessonStatus::Verified,LessonStatus::Stale|LessonStatus::Invalidated)),"Invalid lesson status transition");
        }
    }
    ensure!(lesson.history.last().is_some_and(|e|e.status==lesson.status && e.revision==lesson.revision),"Current lesson status lacks terminal history event");
    ensure!(if lesson.status==LessonStatus::Candidate {lesson.reviewed_at.is_none()} else {lesson.reviewed_at==lesson.history.get(1).map(|e|e.at)},
        "Lesson review timestamp differs from history");
    Ok(())
}
impl KnowledgeStore {
    pub fn path()->Result<std::path::PathBuf> { crate::security::app_data_file("relayne-helper-knowledge.dpapi") }
    pub fn lessons(&self)->&[Lesson] { &self.lessons }
    fn validate(&self)->Result<()> {
        ensure!(self.schema==1 && self.lessons.len()<=MAX_LESSONS,"Unsupported knowledge store or capacity");
        let mut ids=std::collections::BTreeSet::new();
        for lesson in &self.lessons { validate_lesson(lesson)?; ensure!(ids.insert(lesson.id),"Duplicate lesson ID"); }
        Ok(())
    }
    pub fn load(path:&std::path::Path)->Result<Self> {
        if let Ok(metadata)=std::fs::metadata(path) { ensure!(metadata.len()<=MAX_REPORT_BYTES as u64*16+4096,"Knowledge store exceeds capacity"); }
        let protected=match std::fs::read(path) { Ok(bytes)=>bytes, Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(Self::default()), Err(e)=>return Err(e.into()) };
        let raw=crate::security::unprotect_secret(&protected)?;
        ensure!(raw.len()<=MAX_REPORT_BYTES*16,"Knowledge store exceeds capacity");
        let mut store:Self=serde_json::from_slice(&raw)?; store.validate()?; store.source_digest=Some(Sha256::digest(&protected).into()); Ok(store)
    }
    fn save(&mut self,path:&std::path::Path)->Result<()> {
        self.validate()?;
        let raw=serde_json::to_vec(self)?; ensure!(raw.len()<=MAX_REPORT_BYTES*16,"Knowledge store exceeds capacity");
        if let Some(parent)=path.parent() { std::fs::create_dir_all(parent)?; }
        let _guard=knowledge_lock(path)?;
        let current=match std::fs::read(path) { Ok(bytes)=>Some(<[u8;32]>::from(Sha256::digest(&bytes))), Err(e) if e.kind()==std::io::ErrorKind::NotFound=>None, Err(e)=>return Err(e.into()) };
        ensure!(current==self.source_digest,"Knowledge store changed concurrently; reload before saving");
        let protected=crate::security::protect_secret(&raw)?;
        crate::security::atomic_write(path,&protected)?;
        self.source_digest=Some(Sha256::digest(&protected).into()); Ok(())
    }
    pub fn insert(&mut self,lesson:Lesson,path:&std::path::Path)->Result<()> {
        ensure!(lesson.status==LessonStatus::Candidate && lesson.revision==1,"Only new candidate lessons may be inserted");
        ensure!(valid_digest(&lesson.fingerprint) && !lesson.evidence.is_empty() && lesson.evidence.iter().all(|r|valid_digest(&r.digest)),"Invalid lesson evidence");
        ensure!(self.lessons.len()<MAX_LESSONS && !self.lessons.iter().any(|l|l.id==lesson.id),"Duplicate or full knowledge store");
        let previous=self.clone(); self.lessons.push(lesson);
        if let Err(error)=self.save(path) { *self=previous; return Err(error); }
        Ok(())
    }
    pub fn review(&mut self,id:Uuid,expected_revision:u64,decision:ReviewDecision,at:DateTime<Utc>,path:&std::path::Path)->Result<()> {
        let previous=self.clone();
        let l=self.lessons.iter_mut().find(|l|l.id==id).ok_or_else(||anyhow::anyhow!("Lesson not found"))?;
        ensure!(l.revision==expected_revision,"Stale lesson revision");
        ensure!(l.status==LessonStatus::Candidate,"Only candidates can be reviewed");
        l.status=match decision {ReviewDecision::Approve=>LessonStatus::Verified,ReviewDecision::Reject=>LessonStatus::Rejected};
        l.revision+=1; l.reviewed_at=Some(at); let record=event(l,at,&l.trust,None); l.history.push(record);
        if let Err(error)=self.save(path) { *self=previous; return Err(error); } Ok(())
    }
    pub fn revalidate(&mut self,id:Uuid,expected_revision:u64,fingerprint:&str,current_trust:&TrustRevision,at:DateTime<Utc>,path:&std::path::Path)->Result<()> {
        let previous=self.clone();
        let l=self.lessons.iter_mut().find(|l|l.id==id).ok_or_else(||anyhow::anyhow!("Lesson not found"))?;
        ensure!(l.revision==expected_revision,"Stale lesson revision"); ensure!(l.status==LessonStatus::Verified,"Stale or invalidated lessons require new production evidence");
        ensure!(current_trust.revision>0 && !current_trust.reference.id.is_nil() && valid_digest(&current_trust.reference.digest),"Invalid current trust evidence");
        l.status=if at>l.valid_until || fingerprint!=l.fingerprint || *current_trust!=l.trust {LessonStatus::Stale} else {LessonStatus::Verified};
        l.revision+=1; let record=event(l,at,current_trust,None); l.history.push(record);
        if let Err(error)=self.save(path) { *self=previous; return Err(error); } Ok(())
    }
    pub fn invalidate(&mut self,id:Uuid,expected_revision:u64,reason:InvalidationReason,evidence:&EvidenceRef,at:DateTime<Utc>,path:&std::path::Path)->Result<()> {
        let previous=self.clone();
        let l=self.lessons.iter_mut().find(|l|l.id==id).ok_or_else(||anyhow::anyhow!("Lesson not found"))?;
        ensure!(l.revision==expected_revision,"Stale lesson revision");
        ensure!(l.status==LessonStatus::Verified,"Only verified lessons can be invalidated");
        ensure!(l.evidence.contains(evidence),"Invalidation evidence is not linked to this lesson");
        ensure!(valid_digest(&evidence.digest) && !evidence.id.is_nil(),"Invalid invalidation evidence");
        l.status=LessonStatus::Invalidated; l.revision+=1;
        let record=event(l,at,&l.trust,Some((reason,evidence.clone()))); l.history.push(record);
        if let Err(error)=self.save(path) { *self=previous; return Err(error); } Ok(())
    }
    pub fn recommend(&self,snapshot:&VerifiedEvidenceSnapshot,now:DateTime<Utc>)->Vec<LessonMatch> {
        if self.validate().is_err() { return Vec::new(); }
        self.lessons.iter().filter(|l|l.status==LessonStatus::Verified && l.fingerprint==snapshot.fingerprint
            && l.trust==snapshot.trust && l.evidence.iter().all(|r|snapshot.evidence.contains(r)) && now<=l.valid_until)
            .map(|l|LessonMatch{lesson_id:l.id,fingerprint:l.fingerprint.clone(),evidence:l.evidence.clone()}).collect()
    }
}

fn knowledge_lock(path:&std::path::Path)->Result<std::fs::File> {
    let mut options=std::fs::OpenOptions::new(); options.create(true).read(true).write(true).truncate(false);
    #[cfg(windows)] { use std::os::windows::fs::OpenOptionsExt; options.share_mode(0); }
    Ok(options.open(path.with_extension("lock"))?)
}

pub fn export_report(case:&HelperCase,lessons:&[Lesson],now:DateTime<Utc>)->Result<Vec<u8>> {
    for lesson in lessons { validate_lesson(lesson)?; }
    let verified=lessons.iter().filter(|l|l.case_id==case.id() && l.status==LessonStatus::Verified && now<=l.valid_until).collect::<Vec<_>>();
    let refs=verified.iter().flat_map(|l|l.evidence.iter().cloned()).collect::<Vec<_>>();
    let mut unique=BTreeMap::new(); for r in refs { unique.insert((r.kind as u8,r.id),r); }
    let mut all=unique.into_values().collect::<Vec<_>>();
    let evidence_total=all.len();
    let evidence_omitted=evidence_total.saturating_sub(256);
    all.truncate(256);
    let lesson_total=verified.len();
    let report=CaseExport {schema:1,case_id:case.id(),case_revision:case.revision(),status:case.resolution(),evidence:all,
        evidence_total,evidence_omitted,lesson_count:lesson_total.min(4096),lessons_omitted:lesson_total.saturating_sub(4096),
        truncated:evidence_omitted>0 || lesson_total>4096,generated_at:now};
    let bytes=serde_json::to_vec(&report)?; ensure!(bytes.len()<=MAX_REPORT_BYTES,"Case report exceeds capacity"); Ok(bytes)
}

pub fn export_report_format(case:&HelperCase,lessons:&[Lesson],now:DateTime<Utc>,format:ReportFormat)->Result<Vec<u8>> {
    let json=export_report(case,lessons,now)?;
    if format==ReportFormat::Json { return Ok(json); }
    let report:CaseExport=serde_json::from_slice(&json)?;
    let mut text=format!("# Relayne case report\n\n- Case: `{}`\n- Revision: {}\n- Status: {}\n- Verified evidence references: {} of {} ({} omitted)\n- Verified lessons: {} ({} omitted); truncated: {}\n- Generated: {}\n",
        report.case_id,report.case_revision,report.status.map(|s|format!("{s:?}")).unwrap_or_else(||"open".into()),
        report.evidence.len(),report.evidence_total,report.evidence_omitted,report.lesson_count,report.lessons_omitted,report.truncated,
        report.generated_at.to_rfc3339());
    for r in report.evidence { text.push_str(&format!("- {:?}: `{}` ({})\n",r.kind,r.id,r.digest)); }
    ensure!(text.len()<=MAX_REPORT_BYTES,"Case report exceeds capacity"); Ok(text.into_bytes())
}

#[cfg(test)]
#[path = "knowledge_tests.rs"]
mod tests;
