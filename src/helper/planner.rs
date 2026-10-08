//! Inert, evidence-linked investigation plans. A plan never dispatches a check.

use super::{
    case::HelperCase,
    evidence::{Eligibility, EvidenceEnvelope, MAX_FRESHNESS_SECS, Observation, RecordKind},
    manifest::{CapabilityId, CapabilityManifest, CheckRole, Prerequisite, ProbeParams},
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisKind {
    NetworkTransport,
    ServiceHealth,
    ResourcePressure,
    SqlHealth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanConfirmation {
    pub actor: String,
    pub confirmed_at: DateTime<Utc>,
    pub rationale: String,
    pub evidence_refs: Vec<Uuid>,
    pub case_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub kind: HypothesisKind,
    pub explanation: String,
    pub support: Vec<Uuid>,
    pub counterevidence: Vec<Uuid>,
    pub gaps: Vec<String>,
    pub confirmation: Option<HumanConfirmation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperPlanStep {
    pub capability_id: CapabilityId,
    pub version: u16,
    pub params: ProbeParams,
    pub scope_sha256: String,
    pub evidence_refs: Vec<Uuid>,
    pub prerequisites: Vec<Prerequisite>,
    pub role: CheckRole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperPlan {
    pub case_id: Uuid,
    pub case_revision: u64,
    pub evidence_revision: u64,
    pub generated_at: DateTime<Utc>,
    pub hypotheses: Vec<Hypothesis>,
    pub steps: Vec<HelperPlanStep>,
    pub rationale: String,
}

impl HelperPlan {
    pub fn validate(&self, case: &HelperCase, manifest: &CapabilityManifest) -> Result<()> {
        ensure!(
            self.case_id == case.id() && self.case_revision == case.revision(),
            "Stale plan context"
        );
        ensure!(
            self.evidence_revision == case.evidence_revision(),
            "Stale plan evidence"
        );
        ensure!(
            self.hypotheses.len() <= 16 && self.steps.len() <= 16,
            "Plan exceeds limits"
        );
        ensure!(safe_text(&self.rationale, 512), "Invalid plan rationale");
        let supplied: BTreeSet<_> = case
            .evidence()
            .iter()
            .filter(|e| e.binding.case_revision == case.revision())
            .map(|e| e.id)
            .collect();
        for h in &self.hypotheses {
            ensure!(
                safe_text(&h.explanation, 512) && h.gaps.len() <= 16,
                "Invalid hypothesis"
            );
            ensure!(h.gaps.iter().all(|s| safe_text(s, 256)), "Invalid gap");
            ensure!(
                h.support
                    .iter()
                    .chain(&h.counterevidence)
                    .all(|id| supplied.contains(id)),
                "Unknown evidence citation"
            );
            if let Some(c) = &h.confirmation {
                ensure!(
                    c.case_revision <= case.revision()
                        && c.confirmed_at >= case.created_at()
                        && safe_text(&c.actor, 128)
                        && !c.actor.trim().is_empty(),
                    "Invalid confirmation actor/context"
                );
                ensure!(
                    safe_text(&c.rationale, 512) && !c.rationale.trim().is_empty(),
                    "Invalid confirmation rationale"
                );
                ensure!(
                    !c.evidence_refs.is_empty()
                        && c.evidence_refs.iter().all(|id| case
                            .evidence()
                            .iter()
                            .any(|e| e.id == *id && e.binding.case_revision == c.case_revision)),
                    "Invalid confirmation references"
                );
            }
        }
        for step in &self.steps {
            let declaration = manifest
                .declarations
                .iter()
                .find(|d| {
                    d.id == step.capability_id && d.version == step.version && d.role == step.role
                })
                .ok_or_else(|| anyhow::anyhow!("Unknown capability declaration"))?;
            ensure!(
                step.prerequisites == declaration.prerequisites,
                "Capability prerequisites changed"
            );
            ensure!(
                params_match(step.capability_id, &step.params),
                "Capability parameters mismatch"
            );
            let scope = case
                .scopes()
                .iter()
                .find(|s| s.digest().ok().as_deref() == Some(step.scope_sha256.as_str()))
                .ok_or_else(|| anyhow::anyhow!("Step scope no longer reviewed"))?;
            let credential_digest = scope.credential_scope_digest()?;
            ensure!(
                step.evidence_refs.len() <= 16
                    && step.evidence_refs.iter().all(|id| supplied.contains(id)
                        && case.evidence().iter().any(|e| e.id == *id
                            && e.binding.scope_sha256 == step.scope_sha256
                            && e.binding.credential_scope_sha256 == credential_digest)),
                "Step citation scope/credential mismatch"
            );
        }
        Ok(())
    }
}

pub fn params_match(id: CapabilityId, params: &ProbeParams) -> bool {
    let shape = matches!(
        (id, params),
        (
            CapabilityId::NetworkReachability,
            ProbeParams::Network { port: 1..=u16::MAX }
        ) | (CapabilityId::SystemResources, ProbeParams::System)
            | (CapabilityId::ServiceStatus, ProbeParams::Service { .. })
            | (CapabilityId::SqlRead, ProbeParams::SqlRead { .. })
            | (CapabilityId::SqlPlan, ProbeParams::SqlPlan { .. })
            | (
                CapabilityId::SqlWorkloadBaseline | CapabilityId::SqlWorkloadRehearsal,
                ProbeParams::SqlWorkload { .. }
            )
            | (CapabilityId::ContainerStatus, ProbeParams::Container)
            | (
                CapabilityId::CloudInstanceStatus
                    | CapabilityId::AzureVmIdentity
                    | CapabilityId::AzureVmResourceHealth
                    | CapabilityId::AwsEc2Inventory
                    | CapabilityId::AwsEc2Status,
                ProbeParams::CloudInstance
            )
    );
    let digest = match params {
        ProbeParams::Service { service_digest } => Some(service_digest.as_str()),
        ProbeParams::SqlRead { query_digest } | ProbeParams::SqlPlan { query_digest } => {
            Some(query_digest.as_str())
        }
        ProbeParams::SqlWorkload { workload_digest } => Some(workload_digest.as_str()),
        _ => None,
    };
    shape && digest.is_none_or(super::evidence::is_digest)
}

pub(crate) fn safe_text(s: &str, max: usize) -> bool {
    let lower = s.to_ascii_lowercase();
    s.chars().count() <= max
        && !s.chars().any(char::is_control)
        && !s.contains("<|")
        && !s.contains("|>")
        && !s.contains("```")
        && !s.contains("${")
        && !s.contains("$ (")
        && !lower.contains("ignore previous")
        && !lower.contains("system prompt")
        && !lower.contains("developer message")
        && !lower.contains("run this command")
}

pub fn plan_local(
    case: &HelperCase,
    evidence: &[EvidenceEnvelope],
    manifest: &CapabilityManifest,
    now: DateTime<Utc>,
) -> Result<HelperPlan> {
    case.validate()?;
    let mut hypotheses = Vec::new();
    let families = [
        (
            HypothesisKind::NetworkTransport,
            RecordKind::Network,
            "Network transport may be unavailable",
        ),
        (
            HypothesisKind::ServiceHealth,
            RecordKind::Service,
            "Service health may contribute",
        ),
        (
            HypothesisKind::ResourcePressure,
            RecordKind::System,
            "Resource pressure may contribute",
        ),
        (
            HypothesisKind::SqlHealth,
            RecordKind::SqlRead,
            "SQL behavior may contribute",
        ),
    ];
    let mut steps = Vec::new();
    for (kind, record_kind, explanation) in families {
        let mut support = BTreeSet::new();
        let mut counterevidence = BTreeSet::new();
        let mut gaps = Vec::new();
        for e in evidence {
            if e.binding.case_id != case.id()
                || e.binding.case_revision != case.revision()
                || !case.evidence().iter().any(|stored| {
                    stored.id == e.id
                        && serde_json::to_vec(stored).ok() == serde_json::to_vec(e).ok()
                })
                || e.eligibility(now, Duration::seconds(MAX_FRESHNESS_SECS))
                    != Eligibility::Eligible
            {
                continue;
            }
            for r in &e.records {
                if r.kind != record_kind {
                    continue;
                }
                match r.observation {
                    Observation::Degraded | Observation::Unavailable => {
                        support.insert(e.id);
                    }
                    Observation::Healthy => {
                        counterevidence.insert(e.id);
                    }
                    Observation::Unknown => {}
                }
            }
        }
        if support.is_empty() && counterevidence.is_empty() {
            gaps.push("No current complete live observation for this system layer".into());
        }
        if !support.is_empty() && !counterevidence.is_empty() {
            gaps.push("Conflicting observations need a distinguishing check".into());
        }
        if kind == HypothesisKind::NetworkTransport {
            gaps.push(
                "TCP reachability alone cannot establish application or authentication health"
                    .into(),
            );
        }
        let refs: Vec<_> = support.iter().chain(&counterevidence).copied().collect();
        hypotheses.push(Hypothesis {
            kind,
            explanation: explanation.into(),
            support: support.into_iter().collect(),
            counterevidence: counterevidence.into_iter().collect(),
            gaps,
            confirmation: None,
        });
        if let Some(e) = evidence.iter().find(|e| refs.contains(&e.id)) {
            let (id, params) = match kind {
                HypothesisKind::ServiceHealth => e
                    .records
                    .iter()
                    .find(|r| r.kind == RecordKind::Service)
                    .map(|r| {
                        (
                            CapabilityId::ServiceStatus,
                            ProbeParams::Service {
                                service_digest: r.subject_sha256.clone(),
                            },
                        )
                    }),
                HypothesisKind::ResourcePressure => {
                    Some((CapabilityId::SystemResources, ProbeParams::System))
                }
                // A TCP observation is not a reviewed application endpoint or port declaration.
                HypothesisKind::NetworkTransport | HypothesisKind::SqlHealth => None,
            }
            .unwrap_or((CapabilityId::SystemResources, ProbeParams::System));
            if kind == HypothesisKind::ServiceHealth || kind == HypothesisKind::ResourcePressure {
                if let Some(d) = manifest
                    .declarations
                    .iter()
                    .find(|d| d.id == id && d.role == CheckRole::Diagnostic)
                {
                    let scoped_refs = refs
                        .iter()
                        .copied()
                        .filter(|id| {
                            case.evidence().iter().any(|candidate| {
                                candidate.id == *id
                                    && candidate.binding.scope_sha256 == e.binding.scope_sha256
                                    && candidate.binding.credential_scope_sha256
                                        == e.binding.credential_scope_sha256
                            })
                        })
                        .collect();
                    steps.push(HelperPlanStep {
                        capability_id: id,
                        version: d.version,
                        params,
                        scope_sha256: e.binding.scope_sha256.clone(),
                        evidence_refs: scoped_refs,
                        prerequisites: d.prerequisites.clone(),
                        role: d.role,
                    });
                }
            }
        }
    }
    let plan = HelperPlan {
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        generated_at: now,
        hypotheses,
        steps,
        rationale: "Local layer-specific assessment; hypotheses remain unconfirmed".into(),
    };
    plan.validate(case, manifest)?;
    Ok(plan)
}

pub fn mission_checkpoint(plan: &HelperPlan) -> Result<crate::mission::Step> {
    ensure!(
        !plan.case_id.is_nil() && plan.case_revision > 0,
        "Invalid plan checkpoint"
    );
    Ok(crate::mission::Step {
        title: "Review Relayne helper plan".into(),
        kind: crate::mission::StepKind::Operator,
        expectation: format!(
            "Review case {} revision {} evidence revision {}",
            plan.case_id, plan.case_revision, plan.evidence_revision
        ),
        recovery: "Return to the helper case and collect a selected check deliberately".into(),
        command: String::new(),
    })
}

#[cfg(test)]
#[path = "planner_tests.rs"]
pub(crate) mod tests;
