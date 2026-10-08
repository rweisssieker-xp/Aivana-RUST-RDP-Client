//! Reviewed problem facts. Unknown is an explicit answer, distinct from unanswered.
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
    pub schema: u16,
    pub id: Uuid,
    pub revision: u64,
    pub evidence_revision: u64,
    pub intake: ProblemIntake,
    pub profile_ids: Vec<Uuid>,
    pub source: Option<crate::incident::Source>,
    pub mission_id: Option<Uuid>,
    pub ticket_ref: Option<TicketReference>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolution: Option<CaseResolution>,
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
