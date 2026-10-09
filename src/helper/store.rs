//! Bounded protected case persistence with optimistic concurrency.
use super::case::{CaseEdit, HelperCase, ProblemIntake, TicketReference};
use super::evidence::{EvidenceBinding, EvidenceEnvelope, EvidenceHold, Origin, PendingCapture};
use super::manifest::CapabilityId;
use super::scope::CredentialPurpose;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
use uuid::Uuid;

const STORE_SCHEMA: u16 = 1;
pub const MAX_CASES: usize = 128;
pub const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperStore {
    schema: u16,
    cases: Vec<HelperCase>,
    #[serde(default)]
    pending_captures: Vec<PendingCapture>,
    #[serde(skip)]
    source_digest: Option<[u8; 32]>,
    // Deserializing a value is not the same as loading it under the store's CAS discipline.
    #[serde(skip)]
    opened: bool,
}

impl Default for HelperStore {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA,
            cases: vec![],
            pending_captures: vec![],
            source_digest: None,
            opened: true,
        }
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_STORE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_STORE_BYTES,
        "Helper store capacity reached; archive or export cases"
    );
    Ok(Some(bytes))
}

fn lock(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    Ok(options.open(path.with_extension("lock"))?)
}

impl HelperStore {
    /// Closes only from protected receipts that still match the exact durable
    /// production journal. The case transition is persisted with the same
    /// optimistic store check as other edits.
    pub fn finish_verified_from_receipts(
        &mut self,
        path: &Path,
        case_id: Uuid,
        expected_revision: u64,
        run_id: Uuid,
    ) -> Result<()> {
        use super::case::{CaseResolution, ResolutionProofLinks, ResolutionReview};
        use super::verification::{ComparisonPolicy, PerformancePhase, ReceiptStore, resolve_case};
        let journal = super::journal::ActionJournal::load(&super::journal::ActionJournal::path()?)?;
        let receipts = ReceiptStore::load_checked(&ReceiptStore::path()?, &journal)?;
        let mut next = self.clone();
        let case = next
            .cases
            .iter_mut()
            .find(|case| case.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        ensure!(
            case.revision() == expected_revision && case.resolution().is_none(),
            "Stale or closed case"
        );
        let functional = receipts
            .functional()
            .iter()
            .rev()
            .find(|receipt| {
                receipt.case_id == case_id
                    && receipt.case_revision == expected_revision
                    && receipt.run.run_id() == run_id
            })
            .ok_or_else(|| anyhow::anyhow!("Functional production receipt missing"))?;
        let needs_performance = functional.verification.checks.iter().any(|check| {
            matches!(
                check,
                crate::helper_action::RequiredCheck::Performance { .. }
            )
        });
        let baseline = receipts.performance().iter().find(|receipt| {
            receipt.case_id == case_id
                && receipt.run.run_id() == run_id
                && receipt.phase == PerformancePhase::BeforeProduction
        });
        let after = receipts.performance().iter().find(|receipt| {
            receipt.case_id == case_id
                && receipt.run.run_id() == run_id
                && receipt.phase == PerformancePhase::AfterProduction
        });
        let thresholds = functional
            .verification
            .checks
            .iter()
            .filter_map(|check| match check {
                crate::helper_action::RequiredCheck::Performance {
                    maximum_median_ms,
                    maximum_p95_ms,
                    ..
                } => Some((*maximum_median_ms, *maximum_p95_ms)),
                _ => None,
            })
            .reduce(|left, right| (left.0.min(right.0), left.1.min(right.1)));
        let policy = thresholds.map(|(median, p95)| ComparisonPolicy {
            maximum_median_ms: median as f64,
            maximum_p95_ms: p95 as f64,
        });
        let performance = if needs_performance {
            Some((
                baseline
                    .ok_or_else(|| anyhow::anyhow!("Pre-effect production baseline missing"))?,
                after.ok_or_else(|| anyhow::anyhow!("Post-effect production samples missing"))?,
                policy
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Reviewed performance threshold missing"))?,
            ))
        } else {
            None
        };
        ensure!(
            resolve_case(case, &journal, functional, performance)?
                == CaseResolution::VerifiedRelayneRepair,
            "Repair proof incomplete"
        );
        let intent = journal
            .intents()
            .iter()
            .find(|item| item.run_id == run_id && item.case_id == case_id)
            .ok_or_else(|| anyhow::anyhow!("Exact production intent absent"))?;
        let functional_sha256 = functional.content_sha256()?;
        let baseline_sha256 = performance
            .map(|(before, _, _)| before.content_sha256())
            .transpose()?;
        let after_sha256 = performance
            .map(|(_, after, _)| after.content_sha256())
            .transpose()?;
        let proof_links = ResolutionProofLinks {
            run_id,
            intent_id: intent.id,
            production_receipt_sha256: intent
                .production_receipt_sha256
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Production receipt link missing"))?,
            functional_receipt_id: functional.id()?,
            functional_receipt_sha256: functional_sha256.clone(),
            baseline_receipt_id: performance.map(|(before, _, _)| before.id()).transpose()?,
            baseline_receipt_sha256: baseline_sha256.clone(),
            after_receipt_id: performance.map(|(_, after, _)| after.id()).transpose()?,
            after_receipt_sha256: after_sha256.clone(),
        };
        proof_links.validate()?;
        let production = super::sql::restoration::load_production_receipt(run_id)?;
        ensure!(
            intent.production_receipt_sha256.as_deref() == Some(production.content_sha256()),
            "Production proof changed before closure"
        );
        let evidence_refs: Vec<_> = case
            .evidence()
            .iter()
            .filter(|evidence| {
                (evidence.binding.run_id == Some(run_id) || evidence.binding.run_id.is_none())
                    && functional
                        .verification
                        .checks
                        .iter()
                        .any(|check| match check {
                            crate::helper_action::RequiredCheck::HttpFunctional {
                                scope_sha256,
                                ..
                            }
                            | crate::helper_action::RequiredCheck::SqlFunctional {
                                scope_sha256,
                                ..
                            }
                            | crate::helper_action::RequiredCheck::Performance {
                                scope_sha256,
                                ..
                            } => *scope_sha256 == evidence.binding.scope_sha256,
                        })
            })
            .take(16)
            .map(|evidence| evidence.id)
            .collect();
        ensure!(
            !evidence_refs.is_empty(),
            "No case evidence supports the reviewed verification scopes"
        );
        let evidence_content: Vec<_> = evidence_refs
            .iter()
            .filter_map(|id| {
                case.evidence()
                    .iter()
                    .find(|evidence| evidence.id == *id)
                    .map(|evidence| (*id, evidence.content_sha256.as_str()))
            })
            .collect();
        let proof_sha256 = super::verification::resolution_proof_sha256(
            case,
            intent,
            &production,
            functional,
            performance.map(|(before, _, _)| before),
            performance.map(|(_, after, _)| after),
            &proof_links,
            &evidence_content,
        )?;
        case.record_resolution(ResolutionReview {
            outcome: CaseResolution::VerifiedRelayneRepair,
            reason: "Verified production action and reviewed checks passed".into(),
            coverage: if let Some((_, after, _)) = performance {
                format!(
                    "{} reviewed checks; 3 warmups and {} measured samples per side",
                    functional.checks.len(),
                    after.samples_ms.len()
                )
            } else {
                format!("{} reviewed functional checks", functional.checks.len())
            },
            evidence_refs,
            proof_sha256: Some(proof_sha256),
            proof_links: Some(proof_links),
            reviewed_at: chrono::Utc::now(),
        })?;
        receipts.verify_resolution_from_store(case, &journal)?;
        next.validate()?;
        next.save(path)?;
        *self = next;
        Ok(())
    }

    pub fn close_without_repair(
        &mut self,
        path: &Path,
        case_id: Uuid,
        expected_revision: u64,
        outcome: super::case::CaseResolution,
        reason: &str,
        coverage: &str,
        evidence_refs: Vec<Uuid>,
    ) -> Result<()> {
        use super::case::{CaseResolution, ResolutionReview};
        ensure!(
            matches!(
                outcome,
                CaseResolution::DiagnosedNoChange
                    | CaseResolution::ResolvedExternally
                    | CaseResolution::ClosedUnresolved
                    | CaseResolution::NeedsIntervention
            ),
            "Verified repair requires production receipts"
        );
        let mut next = self.clone();
        let case = next
            .cases
            .iter_mut()
            .find(|case| case.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        ensure!(
            case.revision() == expected_revision && case.resolution().is_none(),
            "Stale or closed case"
        );
        case.record_resolution(ResolutionReview {
            outcome,
            reason: crate::security::redact_secret_text(reason),
            coverage: crate::security::redact_secret_text(coverage),
            evidence_refs,
            proof_sha256: None,
            proof_links: None,
            reviewed_at: chrono::Utc::now(),
        })?;
        next.validate()?;
        next.save(path)?;
        *self = next;
        Ok(())
    }
    /// Holds the same OS lock as case saves while the caller inspects the current
    /// protected on-disk state and durably records a dispatch intent.
    pub fn inspect_locked<T>(path: &Path, inspect: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = lock(path)?;
        let current = Self::load(path)?;
        inspect(&current)
    }
    pub fn cases(&self) -> &[HelperCase] {
        &self.cases
    }
    pub fn case(&self, id: Uuid) -> Option<&HelperCase> {
        self.cases.iter().find(|case| case.id() == id)
    }
    pub fn path() -> Result<std::path::PathBuf> {
        crate::security::app_data_file("relayne-helper-cases.dpapi")
    }
    pub fn load(path: &Path) -> Result<Self> {
        let Some(bytes) = read_bounded(path)? else {
            return Ok(Self::default());
        };
        let raw = crate::security::unprotect_secret(&bytes)?;
        ensure!(
            raw.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached; archive or export cases"
        );
        let mut store: Self = serde_json::from_slice(&raw)?;
        store.validate()?;
        if store
            .cases
            .iter()
            .any(|case| case.resolution() == Some(super::case::CaseResolution::VerifiedRelayneRepair))
        {
            let journal = super::journal::ActionJournal::load(&super::journal::ActionJournal::path()?)?;
            let receipts = super::verification::ReceiptStore::load_checked(
                &super::verification::ReceiptStore::path()?,
                &journal,
            )?;
            for case in &store.cases {
                if case.resolution() == Some(super::case::CaseResolution::VerifiedRelayneRepair) {
                    receipts.verify_resolution_from_store(case, &journal)?;
                }
            }
        }
        store.source_digest = Some(digest(&bytes));
        store.opened = true;
        Ok(store)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == STORE_SCHEMA,
            "Unsupported helper store schema"
        );
        ensure!(
            self.cases.len() <= MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        ensure!(
            self.pending_captures.len() <= 128,
            "Pending capture capacity reached"
        );
        for pending in &self.pending_captures {
            pending.binding.validate()?;
            ensure!(
                pending
                    .request_intent_sha256
                    .as_deref()
                    .is_none_or(super::evidence::is_digest),
                "Invalid pending request intent digest"
            );
            ensure!(
                pending.capability_version > 0,
                "Invalid pending capture version"
            );
            ensure!(
                self.case(pending.binding.case_id).is_some(),
                "Orphan pending capture"
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            ensure!(ids.insert(case.id()), "Duplicate helper case ID");
        }
        Ok(())
    }
    pub fn create(&mut self, intake: ProblemIntake) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::new(intake)?;
        let id = case.id();
        self.cases.push(case);
        Ok(id)
    }
    pub fn adopt_incident(&mut self, source: crate::incident::Source) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::from_incident(source)?;
        let id = case.id();
        self.cases.push(case);
        Ok(id)
    }
    pub fn adopt_ticket(
        &mut self,
        reference: TicketReference,
        title: &str,
        description: &str,
    ) -> Result<Uuid> {
        ensure!(
            self.cases.len() < MAX_CASES,
            "Helper case capacity reached; archive or export cases"
        );
        let case = HelperCase::from_ticket(reference, title, description)?;
        let id = case.id();
        self.cases.push(case);
        Ok(id)
    }
    pub fn revise(&mut self, id: Uuid, expected_revision: u64, edit: CaseEdit) -> Result<u64> {
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id() == id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        case.revise(expected_revision, edit)
    }
    pub fn refresh_derived_plan(
        &mut self,
        id: Uuid,
        plan: super::planner::HelperPlan,
    ) -> Result<()> {
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id() == id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        case.refresh_plan(plan)
    }
    pub fn prune_expired_plan(
        &mut self,
        id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id() == id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        case.prune_expired_plan(now)
    }
    pub fn confirm_hypothesis(
        &mut self,
        id: Uuid,
        expected_revision: u64,
        kind: super::planner::HypothesisKind,
        confirmation: super::planner::HumanConfirmation,
    ) -> Result<u64> {
        let case = self
            .cases
            .iter_mut()
            .find(|case| case.id() == id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        case.confirm_hypothesis(expected_revision, kind, confirmation)
    }
    /// Called by the worker after a real request has been accepted. UI/import paths cannot
    /// create a live observation by simply supplying a self-consistent envelope.
    fn register_pending_capture_inner(
        &mut self,
        case_id: Uuid,
        request_id: Uuid,
        scope_sha256: &str,
        run_id: Option<Uuid>,
        capability_id: CapabilityId,
        capability_version: u16,
    ) -> Result<EvidenceBinding> {
        ensure!(
            self.opened && self.pending_captures.len() < 128,
            "Pending capture unavailable/full"
        );
        ensure!(
            capability_version > 0 && !request_id.is_nil(),
            "Invalid capture request"
        );
        ensure!(
            !self
                .pending_captures
                .iter()
                .any(|p| p.binding.request_id == request_id),
            "Duplicate capture request"
        );
        let case = self
            .case(case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        let scope = case
            .scopes()
            .iter()
            .find(|s| s.digest().ok().as_deref() == Some(scope_sha256))
            .ok_or_else(|| anyhow::anyhow!("Capture scope is not reviewed in case"))?;
        ensure!(
            scope
                .credential()
                .is_none_or(|c| c.purpose != CredentialPurpose::ControlledChange),
            "Controlled-change credential cannot authorize diagnostic capture"
        );
        let binding = EvidenceBinding {
            case_id,
            case_revision: case.revision(),
            request_id,
            scope_sha256: scope.digest()?,
            credential_scope_sha256: scope.credential_scope_digest()?,
            run_id,
        };
        binding.validate()?;
        self.pending_captures.push(PendingCapture {
            binding: binding.clone(),
            request_intent_sha256: None,
            capability_id,
            capability_version,
            registered_at: chrono::Utc::now(),
        });
        Ok(binding)
    }

    /// Production registration takes the exact accepted typed registry request.
    pub(crate) fn register_accepted_capture(
        &mut self,
        registry: &super::capability::CapabilityRegistry,
        request: &super::capability::ProbeRequest,
    ) -> Result<EvidenceBinding> {
        let case = self
            .case(request.binding.case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        registry.validate_request(case, request)?;
        let binding = self.register_pending_capture_inner(
            request.binding.case_id,
            request.binding.request_id,
            &request.binding.scope_sha256,
            request.binding.run_id,
            request.capability_id,
            request.capability_version,
        )?;
        ensure!(
            binding == request.binding,
            "Accepted request binding changed"
        );
        self.pending_captures
            .last_mut()
            .expect("capture registered")
            .request_intent_sha256 = Some(request.intent_sha256()?);
        Ok(binding)
    }

    #[cfg(test)]
    pub(crate) fn register_pending_capture(
        &mut self,
        case_id: Uuid,
        request_id: Uuid,
        scope_sha256: &str,
        run_id: Option<Uuid>,
        capability_id: CapabilityId,
        capability_version: u16,
    ) -> Result<EvidenceBinding> {
        self.register_pending_capture_inner(
            case_id,
            request_id,
            scope_sha256,
            run_id,
            capability_id,
            capability_version,
        )
    }

    /// Remove durable intent when a submitted capture is canceled, rejected, or times out.
    pub(crate) fn cancel_pending_capture(&mut self, request_id: Uuid) -> Result<()> {
        ensure!(self.opened, "Helper store unavailable");
        self.pending_captures
            .retain(|pending| pending.binding.request_id != request_id);
        Ok(())
    }

    pub(crate) fn cancel_abandoned_pending_captures(&mut self) -> bool {
        let had_pending = !self.pending_captures.is_empty();
        self.pending_captures.clear();
        had_pending
    }
    pub fn attach_evidence(&mut self, case_id: Uuid, envelope: EvidenceEnvelope) -> Result<()> {
        ensure!(
            self.opened,
            "Load or create a helper store before attaching evidence"
        );
        envelope.validate_shape()?;
        let case = self
            .case(case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        ensure!(
            envelope.binding.case_id == case_id
                && envelope.binding.case_revision == case.revision(),
            "Stale or wrong case evidence"
        );
        let scope = case
            .scopes()
            .iter()
            .find(|s| s.digest().ok().as_deref() == Some(&envelope.binding.scope_sha256))
            .ok_or_else(|| anyhow::anyhow!("Evidence scope not reviewed in case"))?;
        let authoritative = EvidenceBinding {
            case_id,
            case_revision: case.revision(),
            request_id: envelope.binding.request_id,
            scope_sha256: scope.digest()?,
            credential_scope_sha256: scope.credential_scope_digest()?,
            run_id: envelope.binding.run_id,
        };
        envelope.validate_ingest(&authoritative)?;
        if envelope.origin == Origin::Live {
            for artifact in &envelope.sql_artifacts {
                if let super::sql::artifacts::SqlArtifact::Workload(workload) = artifact {
                    let reviewed = case
                        .evidence()
                        .iter()
                        .find(|item| item.id == workload.review_evidence_id)
                        .ok_or_else(|| anyhow::anyhow!("Workload review evidence missing"))?;
                    ensure!(
                        reviewed.capability_id == CapabilityId::SqlRead
                            && reviewed.origin == Origin::Live
                            && reviewed.binding.case_revision == case.revision()
                            && reviewed.binding.scope_sha256 == envelope.binding.scope_sha256
                            && reviewed.binding.credential_scope_sha256
                                == envelope.binding.credential_scope_sha256
                            && reviewed.content_sha256 == workload.review_content_sha256,
                        "Workload review evidence changed"
                    );
                }
            }
        }
        if envelope.origin == Origin::Live {
            let pending = self
                .pending_captures
                .iter()
                .find(|p| p.binding.request_id == envelope.binding.request_id)
                .ok_or_else(|| anyhow::anyhow!("No trusted pending live capture"))?;
            envelope.validate_ingest(&pending.binding)?;
            ensure!(
                pending.request_intent_sha256 == envelope.request_intent_sha256,
                "Capture request intent mismatch"
            );
            ensure!(
                pending.capability_id == envelope.capability_id
                    && pending.capability_version == envelope.capability_version,
                "Capture capability/version mismatch"
            );
            ensure!(
                envelope.retrieved_at >= pending.registered_at - chrono::Duration::seconds(30),
                "Response predates capture request"
            );
        }
        ensure!(
            !case.evidence().iter().any(|e| e.id == envelope.id
                || (e.binding.request_id == envelope.binding.request_id
                    && e.origin == Origin::Live)),
            "Duplicate evidence/request"
        );
        let mut next = self.clone();
        next.cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .unwrap()
            .append_evidence(envelope.clone())?;
        if envelope.origin == Origin::Live {
            next.pending_captures
                .retain(|p| p.binding.request_id != envelope.binding.request_id);
        }
        next.validate()?;
        ensure!(
            serde_json::to_vec(&next)?.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached"
        );
        *self = next;
        Ok(())
    }
    pub(crate) fn set_evidence_hold(&mut self, case_id: Uuid, hold: EvidenceHold) -> Result<()> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        next.cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?
            .set_evidence_hold(hold)?;
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub(crate) fn clear_evidence_hold(&mut self, case_id: Uuid, run_id: Uuid) -> Result<()> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        next.cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?
            .clear_evidence_hold(run_id)?;
        next.validate()?;
        *self = next;
        Ok(())
    }
    /// Deliberate metadata retention maintenance, never called implicitly at capacity/save.
    pub fn prune_expired_evidence_metadata(
        &mut self,
        case_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        let removed = next
            .cases
            .iter_mut()
            .find(|c| c.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?
            .prune_expired_evidence_metadata(now)?;
        next.validate()?;
        *self = next;
        Ok(removed)
    }
    /// Explicit retention maintenance keeps the envelope and source digest after clearing
    /// expired SQL projections. Holds and evidence references protect referenced artifacts.
    pub fn prune_expired_sql_artifacts(
        &mut self,
        case_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        ensure!(self.opened, "Store not opened");
        let mut next = self.clone();
        let case = next
            .cases
            .iter_mut()
            .find(|case| case.id() == case_id)
            .ok_or_else(|| anyhow::anyhow!("Helper case missing"))?;
        let removed = case.prune_expired_sql_artifacts(now)?;
        next.validate()?;
        *self = next;
        Ok(removed)
    }

    /// Explicit maintenance persists the pruned projection atomically. A failed
    /// save leaves the in-memory case and every protected reference untouched.
    pub fn maintain_sql_artifacts(
        &mut self,
        path: &Path,
        case_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        let mut next = self.clone();
        let removed = next.prune_expired_sql_artifacts(case_id, now)?;
        if removed > 0 {
            next.save(path)?;
            *self = next;
        }
        Ok(removed)
    }
    pub fn save(&mut self, path: &Path) -> Result<()> {
        ensure!(self.opened, "Load or create a helper store before saving");
        self.validate()?;
        let raw = serde_json::to_vec(self)?;
        ensure!(
            raw.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached; archive or export cases"
        );
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = lock(path)?;
        let current = read_bounded(path)?.as_deref().map(digest);
        ensure!(
            current == self.source_digest,
            "Helper store changed concurrently; reload"
        );
        let protected = crate::security::protect_secret(&raw)?;
        ensure!(
            protected.len() <= MAX_STORE_BYTES,
            "Helper store capacity reached; archive or export cases"
        );
        crate::security::atomic_write(path, &protected)?;
        self.source_digest = Some(digest(&protected));
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
