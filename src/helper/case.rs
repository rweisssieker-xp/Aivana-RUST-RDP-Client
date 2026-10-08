//! Reviewed problem facts. Unknown is an explicit answer, distinct from unanswered.
use super::evidence::{
    EvidenceEnvelope, EvidenceHold, MAX_ENVELOPES_PER_CASE, METADATA_RETENTION_DAYS, RetentionState,
};
use super::planner::{HelperPlan, HumanConfirmation, HypothesisKind};
use super::scope::BoundScope;
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CASE_SCHEMA: u16 = 1;
pub const MAX_DESCRIPTION: usize = 4096;
pub const MAX_FIELD: usize = 512;
pub const MAX_LIST: usize = 16;
pub const MAX_PROFILES: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "answer",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Answer<T> {
    #[default]
    Unanswered,
    Unknown,
    Known(T),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Production,
    Sandbox,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    AtMost,
    AtLeast,
    Equal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessCriterion {
    pub measure: String,
    pub comparator: Comparator,
    pub threshold: f64,
    pub unit: String,
    pub window: String,
    pub reviewed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProblemIntake {
    pub description: Answer<String>,
    pub affected_scope: Answer<String>,
    pub impact: Answer<String>,
    pub onset_frequency: Answer<String>,
    pub environment: Answer<Environment>,
    pub permission: Answer<String>,
    pub recent_changes: Vec<String>,
    pub attempted_remedies: Vec<String>,
    pub constraints: Vec<String>,
    pub success_criteria: Vec<SuccessCriterion>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clarification {
    Description,
    AffectedScope,
    Environment,
    Permission,
    SuccessCriterion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Descriptive context only. This never authorizes a probe, credential, or change.
pub struct IntakeReadiness {
    pub ready_for_action: bool,
    pub missing: Vec<Clarification>,
}

pub fn next_questions(intake: &ProblemIntake, scope_confirmed: bool) -> Vec<Clarification> {
    let mut q = Vec::new();
    if !matches!(&intake.description, Answer::Known(v) if !v.trim().is_empty()) {
        q.push(Clarification::Description);
    }
    if !scope_confirmed
        || !matches!(&intake.affected_scope, Answer::Known(v) if !v.trim().is_empty())
    {
        q.push(Clarification::AffectedScope);
    }
    if !matches!(intake.environment, Answer::Known(_)) {
        q.push(Clarification::Environment);
    }
    if !matches!(&intake.permission, Answer::Known(v) if !v.trim().is_empty()) {
        q.push(Clarification::Permission);
    }
    if !intake
        .success_criteria
        .iter()
        .any(SuccessCriterion::complete)
    {
        q.push(Clarification::SuccessCriterion);
    }
    q
}

pub fn validate_intake(intake: &ProblemIntake, scope_confirmed: bool) -> IntakeReadiness {
    let missing = next_questions(intake, scope_confirmed);
    IntakeReadiness {
        ready_for_action: missing.is_empty(),
        missing,
    }
}

impl SuccessCriterion {
    pub fn complete(&self) -> bool {
        self.reviewed
            && self.threshold.is_finite()
            && !self.measure.trim().is_empty()
            && !self.unit.trim().is_empty()
            && !self.window.trim().is_empty()
    }
    fn validate(&self) -> Result<()> {
        for v in [&self.measure, &self.unit, &self.window] {
            validate_text(v, MAX_FIELD)?;
        }
        ensure!(
            self.threshold.is_finite(),
            "Criterion threshold must be finite"
        );
        Ok(())
    }
}

fn validate_text(value: &str, cap: usize) -> Result<()> {
    ensure!(
        value.chars().count() <= cap,
        "Intake field exceeds {cap} characters"
    );
    ensure!(
        !value.chars().any(char::is_control),
        "Intake contains control characters"
    );
    Ok(())
}

fn validate_answer(value: &Answer<String>, cap: usize) -> Result<()> {
    if let Answer::Known(value) = value {
        validate_text(value, cap)?;
    }
    Ok(())
}

impl ProblemIntake {
    pub fn validate(&self) -> Result<()> {
        validate_answer(&self.description, MAX_DESCRIPTION)?;
        for value in [
            &self.affected_scope,
            &self.impact,
            &self.onset_frequency,
            &self.permission,
        ] {
            validate_answer(value, MAX_FIELD)?;
        }
        for list in [
            &self.recent_changes,
            &self.attempted_remedies,
            &self.constraints,
        ] {
            ensure!(
                list.len() <= MAX_LIST,
                "Intake list exceeds {MAX_LIST} entries"
            );
            for value in list {
                validate_text(value, MAX_FIELD)?;
            }
        }
        ensure!(
            self.success_criteria.len() <= MAX_LIST,
            "Too many success criteria"
        );
        for criterion in &self.success_criteria {
            criterion.validate()?;
        }
        Ok(())
    }
    pub fn sanitized(mut self) -> Result<Self> {
        fn clean(a: &mut Answer<String>) {
            if let Answer::Known(v) = a {
                *v = crate::security::redact_secret_text(v);
            }
        }
        for a in [
            &mut self.description,
            &mut self.affected_scope,
            &mut self.impact,
            &mut self.onset_frequency,
            &mut self.permission,
        ] {
            clean(a);
        }
        for list in [
            &mut self.recent_changes,
            &mut self.attempted_remedies,
            &mut self.constraints,
        ] {
            for v in list {
                *v = crate::security::redact_secret_text(v);
            }
        }
        for c in &mut self.success_criteria {
            for v in [&mut c.measure, &mut c.unit, &mut c.window] {
                *v = crate::security::redact_secret_text(v);
            }
        }
        self.validate()?;
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketReference {
    pub origin: String,
    pub source_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseResolution {
    VerifiedRelayneRepair,
    DiagnosedNoChange,
    ResolvedExternally,
    ClosedUnresolved,
    NeedsIntervention,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperCase {
    schema: u16,
    id: Uuid,
    revision: u64,
    evidence_revision: u64,
    intake: ProblemIntake,
    profile_ids: Vec<Uuid>,
    #[serde(default)]
    scopes: Vec<BoundScope>,
    #[serde(default)]
    evidence: Vec<EvidenceEnvelope>,
    #[serde(default)]
    evidence_holds: Vec<EvidenceHold>,
    #[serde(default)]
    plan: Option<HelperPlan>,
    source: Option<crate::incident::Source>,
    mission_id: Option<Uuid>,
    ticket_ref: Option<TicketReference>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    resolution: Option<CaseResolution>,
}

#[derive(Clone, Debug)]
pub enum CaseEdit {
    Description(Answer<String>),
    AffectedScope(Answer<String>),
    Impact(Answer<String>),
    OnsetFrequency(Answer<String>),
    Environment(Answer<Environment>),
    Permission(Answer<String>),
    RecentChange(usize, Option<String>),
    AttemptedRemedy(usize, Option<String>),
    Constraint(usize, Option<String>),
    SuccessCriterion(usize, Option<SuccessCriterion>),
    Profiles(Vec<Uuid>),
    Scopes(Vec<BoundScope>),
    PlanIntent(HelperPlan),
}

fn edit_list(list: &mut Vec<String>, index: usize, value: Option<String>) -> Result<()> {
    ensure!(index <= list.len(), "Invalid intake item index");
    if let Some(value) = value {
        ensure!(index < MAX_LIST, "Intake list full");
        if index == list.len() {
            list.push(value);
        } else {
            list[index] = value;
        }
    } else {
        ensure!(index < list.len(), "Invalid intake item index");
        list.remove(index);
    }
    Ok(())
}

impl HelperCase {
    pub fn schema(&self) -> u16 {
        self.schema
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn evidence_revision(&self) -> u64 {
        self.evidence_revision
    }
    pub fn intake(&self) -> &ProblemIntake {
        &self.intake
    }
    pub fn profile_ids(&self) -> &[Uuid] {
        &self.profile_ids
    }
    pub fn scopes(&self) -> &[BoundScope] {
        &self.scopes
    }
    pub fn evidence(&self) -> &[EvidenceEnvelope] {
        &self.evidence
    }
    pub fn evidence_holds(&self) -> &[EvidenceHold] {
        &self.evidence_holds
    }
    pub fn plan(&self) -> Option<&HelperPlan> {
        self.plan.as_ref()
    }
    pub fn plan_retention(&self, now: DateTime<Utc>) -> Option<RetentionState> {
        let plan = self.plan.as_ref()?;
        if now.signed_duration_since(plan.generated_at)
            <= chrono::Duration::days(super::evidence::PLAN_ARTIFACT_RETENTION_DAYS)
        {
            Some(RetentionState::WithinWindow)
        } else if !self.evidence_holds.is_empty() {
            Some(RetentionState::ExpiredHeld)
        } else {
            Some(RetentionState::ExpiredUnheld)
        }
    }
    pub fn evidence_retention(&self, id: Uuid, now: DateTime<Utc>) -> Option<RetentionState> {
        let item = self.evidence.iter().find(|e| e.id == id)?;
        if now.signed_duration_since(item.retrieved_at)
            <= chrono::Duration::days(METADATA_RETENTION_DAYS)
        {
            return Some(RetentionState::WithinWindow);
        }
        if self
            .evidence_holds
            .iter()
            .any(|h| h.evidence_ids.contains(&id))
        {
            Some(RetentionState::ExpiredHeld)
        } else if self.evidence.iter().any(|e| e.evidence_refs.contains(&id)) {
            Some(RetentionState::ExpiredReferenced)
        } else {
            Some(RetentionState::ExpiredUnheld)
        }
    }
    /// Explicit maintenance only. Collection/save never evicts evidence to make room.
    pub(super) fn prune_expired_evidence_metadata(&mut self, now: DateTime<Utc>) -> Result<usize> {
        ensure!(now >= self.created_at, "Retention time predates case");
        let before = self.evidence.len();
        let remove: std::collections::BTreeSet<_> = self
            .evidence
            .iter()
            .filter(|e| self.evidence_retention(e.id, now) == Some(RetentionState::ExpiredUnheld))
            .map(|e| e.id)
            .collect();
        if remove.is_empty() {
            return Ok(0);
        }
        let mut next = self.clone();
        next.evidence.retain(|e| !remove.contains(&e.id));
        next.evidence_revision = next
            .evidence_revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Evidence revision exhausted"))?;
        next.updated_at = now;
        next.validate()?;
        *self = next;
        Ok(before - self.evidence.len())
    }
    pub fn source(&self) -> Option<&crate::incident::Source> {
        self.source.as_ref()
    }
    pub fn mission_id(&self) -> Option<Uuid> {
        self.mission_id
    }
    pub fn ticket_ref(&self) -> Option<&TicketReference> {
        self.ticket_ref.as_ref()
    }
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    pub fn resolution(&self) -> Option<CaseResolution> {
        self.resolution
    }
    pub fn new(intake: ProblemIntake) -> Result<Self> {
        let intake = intake.sanitized()?;
        let now = Utc::now();
        Ok(Self {
            schema: CASE_SCHEMA,
            id: Uuid::new_v4(),
            revision: 1,
            evidence_revision: 0,
            intake,
            profile_ids: vec![],
            scopes: vec![],
            evidence: vec![],
            evidence_holds: vec![],
            plan: None,
            source: None,
            mission_id: None,
            ticket_ref: None,
            created_at: now,
            updated_at: now,
            resolution: None,
        })
    }
    pub fn from_incident(mut source: crate::incident::Source) -> Result<Self> {
        source.record_id = bounded_redacted(&source.record_id, MAX_FIELD);
        source.endpoint = bounded_redacted(&source.endpoint, MAX_FIELD);
        source.title = bounded_redacted(&source.title, MAX_FIELD);
        source.evidence = source
            .evidence
            .into_iter()
            .take(MAX_LIST)
            .map(|v| bounded_redacted(&v, MAX_FIELD))
            .collect();
        let mut case = Self::new(ProblemIntake {
            description: Answer::Known(source.title.clone()),
            ..Default::default()
        })?;
        case.profile_ids.push(source.profile_id);
        case.source = Some(source);
        case.validate()?;
        Ok(case)
    }
    pub fn from_ticket(reference: TicketReference, title: &str, description: &str) -> Result<Self> {
        let reference = TicketReference {
            origin: bounded_redacted(&reference.origin, MAX_FIELD),
            source_id: bounded_redacted(&reference.source_id, MAX_FIELD),
        };
        let text = format!("{}\n{}", title, description);
        let mut case = Self::new(ProblemIntake {
            description: Answer::Known(bounded_redacted(&text, MAX_DESCRIPTION)),
            ..Default::default()
        })?;
        case.ticket_ref = Some(reference);
        case.validate()?;
        Ok(case)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == CASE_SCHEMA, "Unsupported helper case schema");
        ensure!(
            !self.id.is_nil() && self.revision > 0 && self.updated_at >= self.created_at,
            "Invalid helper case identity/revision/time"
        );
        ensure!(
            self.profile_ids.len() <= MAX_PROFILES,
            "Too many case targets"
        );
        let unique: std::collections::BTreeSet<_> = self.profile_ids.iter().collect();
        ensure!(
            unique.len() == self.profile_ids.len() && !self.profile_ids.iter().any(Uuid::is_nil),
            "Invalid case target IDs"
        );
        self.intake.validate()?;
        ensure!(
            self.evidence.len() <= MAX_ENVELOPES_PER_CASE,
            "Evidence capacity reached"
        );
        let mut evidence_ids = std::collections::BTreeSet::new();
        for item in &self.evidence {
            item.validate_shape()?;
            ensure!(
                item.binding.case_id == self.id
                    && item.binding.case_revision <= self.revision
                    && evidence_ids.insert(item.id),
                "Invalid case evidence reference"
            );
        }
        ensure!(
            self.evidence_revision >= self.evidence.len() as u64,
            "Invalid evidence revision"
        );
        for hold in &self.evidence_holds {
            hold.validate()?;
            ensure!(
                hold.evidence_ids.iter().all(|id| evidence_ids.contains(id)),
                "Missing held evidence"
            );
        }
        if let Some(plan) = &self.plan {
            ensure!(
                plan.case_id == self.id
                    && plan.case_revision <= self.revision
                    && plan.evidence_revision <= self.evidence_revision
                    && plan.hypotheses.len() <= 16
                    && plan.steps.len() <= 16,
                "Invalid stored plan binding"
            );
            if plan.case_revision == self.revision
                && plan.evidence_revision == self.evidence_revision
            {
                plan.validate(self, &super::manifest::CapabilityManifest::built_in())?;
            }
        }
        ensure!(
            self.scopes.len() <= MAX_PROFILES,
            "Too many reviewed scopes"
        );
        let mut digests = std::collections::BTreeSet::new();
        for scope in &self.scopes {
            let digest = scope.digest()?;
            ensure!(digests.insert(digest), "Duplicate reviewed scope");
            if let Some(target) = scope.target() {
                ensure!(
                    self.profile_ids.contains(&target.profile_id),
                    "Scope profile must be selected in case"
                );
            }
        }
        // Task 16 will add a receipt-backed transition; intake edits cannot claim repair.
        ensure!(
            self.resolution.is_none(),
            "Case resolution requires a verified result"
        );
        if let Some(t) = &self.ticket_ref {
            validate_text(&t.origin, MAX_FIELD)?;
            validate_text(&t.source_id, MAX_FIELD)?;
        }
        if let Some(s) = &self.source {
            for v in [&s.record_id, &s.endpoint, &s.title] {
                validate_text(v, MAX_FIELD)?;
            }
            ensure!(s.evidence.len() <= MAX_LIST, "Too many incident source IDs");
            for v in &s.evidence {
                validate_text(v, MAX_FIELD)?;
            }
        }
        Ok(())
    }
    pub fn revise(&mut self, expected_revision: u64, edit: CaseEdit) -> Result<u64> {
        ensure!(
            self.revision == expected_revision,
            "Stale case revision; reload"
        );
        let mut next = self.clone();
        match edit {
            CaseEdit::Description(v) => next.intake.description = v,
            CaseEdit::AffectedScope(v) => next.intake.affected_scope = v,
            CaseEdit::Impact(v) => next.intake.impact = v,
            CaseEdit::OnsetFrequency(v) => next.intake.onset_frequency = v,
            CaseEdit::Environment(v) => next.intake.environment = v,
            CaseEdit::Permission(v) => next.intake.permission = v,
            CaseEdit::RecentChange(i, v) => edit_list(&mut next.intake.recent_changes, i, v)?,
            CaseEdit::AttemptedRemedy(i, v) => {
                edit_list(&mut next.intake.attempted_remedies, i, v)?
            }
            CaseEdit::Constraint(i, v) => edit_list(&mut next.intake.constraints, i, v)?,
            CaseEdit::SuccessCriterion(i, v) => {
                ensure!(
                    i <= next.intake.success_criteria.len(),
                    "Invalid criterion index"
                );
                if let Some(v) = v {
                    ensure!(i < MAX_LIST, "Criterion list full");
                    if i == next.intake.success_criteria.len() {
                        next.intake.success_criteria.push(v);
                    } else {
                        next.intake.success_criteria[i] = v;
                    }
                } else {
                    ensure!(
                        i < next.intake.success_criteria.len(),
                        "Invalid criterion index"
                    );
                    next.intake.success_criteria.remove(i);
                }
            }
            CaseEdit::Profiles(v) => next.profile_ids = v,
            CaseEdit::Scopes(v) => next.scopes = v,
            CaseEdit::PlanIntent(mut plan) => {
                ensure!(
                    plan.case_id == next.id
                        && plan.case_revision == next.revision
                        && plan.evidence_revision == next.evidence_revision,
                    "Stale plan intent"
                );
                plan.validate(&next, &super::manifest::CapabilityManifest::built_in())?;
                plan.case_revision = next
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("Revision exhausted"))?;
                for hypothesis in &mut plan.hypotheses {
                    hypothesis.confirmation = None;
                    if !hypothesis.support.is_empty() || !hypothesis.counterevidence.is_empty() {
                        hypothesis
                            .gaps
                            .push("Recollect evidence under the adopted plan revision".into());
                    }
                    hypothesis.support.clear();
                    hypothesis.counterevidence.clear();
                }
                for step in &mut plan.steps {
                    step.evidence_refs.clear();
                }
                plan.rationale =
                    "Reviewed plan intent; earlier evidence needs recollection under this revision"
                        .into();
                next.plan = Some(plan);
            }
        }
        next.intake = next.intake.sanitized()?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Revision exhausted"))?;
        next.updated_at = Utc::now();
        next.validate()?;
        *self = next;
        Ok(self.revision)
    }
    /// Recompute derived assessment after evidence arrival without pretending the user edited intent.
    pub(super) fn refresh_plan(&mut self, mut plan: HelperPlan) -> Result<()> {
        if let Some(previous) = &self.plan
            && previous.case_revision == self.revision
        {
            for hypothesis in &mut plan.hypotheses {
                hypothesis.confirmation = previous
                    .hypotheses
                    .iter()
                    .find(|h| h.kind == hypothesis.kind)
                    .and_then(|h| h.confirmation.clone());
            }
        }
        plan.validate(self, &super::manifest::CapabilityManifest::built_in())?;
        let mut next = self.clone();
        next.plan = Some(plan);
        next.updated_at = Utc::now();
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub(super) fn prune_expired_plan(&mut self, now: DateTime<Utc>) -> Result<bool> {
        if self.plan_retention(now) != Some(RetentionState::ExpiredUnheld) {
            return Ok(false);
        }
        let mut next = self.clone();
        next.plan = None;
        next.updated_at = Utc::now();
        next.validate()?;
        *self = next;
        Ok(true)
    }

    /// A human decision is recorded separately from an inferred hypothesis.
    pub(super) fn confirm_hypothesis(
        &mut self,
        expected_revision: u64,
        kind: HypothesisKind,
        confirmation: HumanConfirmation,
    ) -> Result<u64> {
        ensure!(
            self.revision == expected_revision && confirmation.case_revision == expected_revision,
            "Stale confirmation context"
        );
        ensure!(
            confirmation.confirmed_at <= Utc::now() + chrono::Duration::seconds(5),
            "Invalid confirmation time"
        );
        ensure!(
            !confirmation.evidence_refs.is_empty()
                && confirmation
                    .evidence_refs
                    .iter()
                    .all(|id| self.evidence.iter().any(|e| e.id == *id
                        && e.binding.case_revision == expected_revision
                        && e.eligibility(
                            confirmation.confirmed_at,
                            chrono::Duration::seconds(super::evidence::MAX_FRESHNESS_SECS)
                        ) == super::evidence::Eligibility::Eligible)),
            "Confirmation requires current live evidence"
        );
        let mut next = self.clone();
        let plan = next
            .plan
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No reviewed plan"))?;
        ensure!(
            plan.case_revision == expected_revision
                && plan.evidence_revision == next.evidence_revision,
            "Plan needs refresh before confirmation"
        );
        let hypothesis = plan
            .hypotheses
            .iter_mut()
            .find(|h| h.kind == kind)
            .ok_or_else(|| anyhow::anyhow!("Unknown hypothesis"))?;
        ensure!(
            hypothesis.confirmation.is_none(),
            "Hypothesis already confirmed"
        );
        ensure!(
            confirmation
                .evidence_refs
                .iter()
                .all(|id| hypothesis.support.contains(id)),
            "Confirmation needs supporting plan evidence"
        );
        hypothesis.confirmation = Some(confirmation);
        for h in &mut plan.hypotheses {
            h.support.clear();
            h.counterevidence.clear();
        }
        for step in &mut plan.steps {
            step.evidence_refs.clear();
        }
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Revision exhausted"))?;
        plan.case_revision = next.revision;
        next.updated_at = Utc::now();
        next.validate()?;
        *self = next;
        Ok(self.revision)
    }

    pub(super) fn append_evidence(&mut self, envelope: EvidenceEnvelope) -> Result<()> {
        ensure!(
            self.evidence.len() < MAX_ENVELOPES_PER_CASE,
            "Evidence capacity reached; export or archive before collecting more"
        );
        let mut next = self.clone();
        next.evidence.push(envelope);
        next.evidence_revision = next
            .evidence_revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Evidence revision exhausted"))?;
        next.updated_at = Utc::now();
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub(super) fn set_evidence_hold(&mut self, hold: EvidenceHold) -> Result<()> {
        let mut next = self.clone();
        if let Some(old) = next
            .evidence_holds
            .iter_mut()
            .find(|h| h.run_id == hold.run_id)
        {
            *old = hold;
        } else {
            ensure!(
                next.evidence_holds.len() < 64,
                "Evidence hold capacity reached"
            );
            next.evidence_holds.push(hold);
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub(super) fn clear_evidence_hold(&mut self, run_id: Uuid) -> Result<()> {
        ensure!(!run_id.is_nil(), "Invalid run identity");
        let mut next = self.clone();
        next.evidence_holds.retain(|h| h.run_id != run_id);
        next.validate()?;
        *self = next;
        Ok(())
    }
}

fn bounded_redacted(value: &str, max: usize) -> String {
    crate::security::redact_secret_text(value)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect()
}

#[cfg(test)]
#[path = "case_tests.rs"]
mod tests;
