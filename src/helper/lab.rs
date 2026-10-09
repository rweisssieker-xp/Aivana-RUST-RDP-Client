//! Bounded Task 18 acceptance report contract and dependency-aware preflight.
//!
//! This module deliberately does not execute SQL changes or manufacture product
//! receipts. Scenario execution is admitted only through the corresponding
//! product adapters and receipt APIs once their native prerequisites are present.

use super::case::HelperCase;
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

pub const ACCEPTANCE_SCHEMA: u16 = 1;
pub const MAX_REPORT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureLabel {
    SimulationFixture,
    GuestAcceptancePreflight,
    MeasuredGuestFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    NotRun,
    Passed,
    Failed,
    Blocked,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioResult {
    pub id: u8,
    pub status: ScenarioStatus,
    pub summary: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReference {
    pub state: CaptureState,
    pub status: ScenarioStatus,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Requested,
    Approved,
    Consumed,
    Verified,
    Intervention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceReport {
    pub schema: u16,
    pub run_id: Uuid,
    pub case_id: Uuid,
    pub case_revision: u64,
    pub evidence_revision: u64,
    pub fixture: FixtureLabel,
    pub product_acceptance: bool,
    pub created_at: DateTime<Utc>,
    pub scenarios: Vec<ScenarioResult>,
    pub captures: Vec<CaptureReference>,
}

impl AcceptanceReport {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == ACCEPTANCE_SCHEMA,
            "Unsupported acceptance report schema"
        );
        ensure!(
            !self.run_id.is_nil() && !self.case_id.is_nil(),
            "Invalid acceptance identity"
        );
        ensure!(self.case_revision > 0, "Invalid case revision");
        ensure!(
            self.scenarios.len() == 7,
            "Acceptance report must contain seven scenarios"
        );
        ensure!(
            self.scenarios
                .iter()
                .enumerate()
                .all(|(i, item)| item.id == i as u8 + 1
                    && !item.summary.is_empty()
                    && item.summary.len() <= 512
                    && item.evidence_refs.len() <= 16
                    && item.evidence_refs.iter().all(|value| value.len() <= 128)),
            "Invalid scenario report"
        );
        ensure!(
            self.captures.len() == 5,
            "Acceptance report must contain five capture states"
        );
        ensure!(
            self.captures
                .iter()
                .enumerate()
                .all(|(i, item)| item.state as usize == i
                    && item.evidence_refs.len() <= 16
                    && item.evidence_refs.iter().all(|value| value.len() <= 128)),
            "Invalid capture report"
        );
        ensure!(
            !self.product_acceptance,
            "This preflight-only report cannot establish product acceptance"
        );
        ensure!(
            self.fixture != FixtureLabel::MeasuredGuestFixture
                && self.scenarios.iter().all(|item| !matches!(
                    item.status,
                    ScenarioStatus::Passed | ScenarioStatus::Failed
                ))
                && self.captures.iter().all(|item| {
                    item.status == ScenarioStatus::NotRun && item.evidence_refs.is_empty()
                }),
            "Preflight reports cannot claim measured outcomes or captures"
        );
        Ok(())
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() <= MAX_REPORT_BYTES,
            "Acceptance report exceeds size limit"
        );
        Ok(bytes)
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_REPORT_BYTES,
            "Acceptance report exceeds size limit"
        );
        let report: Self = serde_json::from_slice(bytes)?;
        report.validate()?;
        Ok(report)
    }
}

/// Runs a local, non-mutating acceptance preflight for one persisted case.
/// It records concrete blockers and never represents a component test as a
/// measured scenario result.
pub fn run_acceptance(case: &HelperCase, fixture: FixtureLabel) -> Result<AcceptanceReport> {
    case.validate()?;
    let has_postgres = case.scopes().iter().any(|scope| {
        matches!(
            scope,
            super::scope::BoundScope::Database {
                engine: super::scope::DatabaseEngine::Postgres,
                ..
            }
        )
    });
    let has_http = case
        .scopes()
        .iter()
        .filter(|scope| matches!(scope, super::scope::BoundScope::Http { .. }))
        .count();
    let verified = case.resolution() == Some(super::case::CaseResolution::VerifiedRelayneRepair);
    let scenarios = vec![
        scenario(
            1,
            ScenarioStatus::Incomplete,
            "Persisted case loaded; save/reload zero-call instrumentation has not run.",
        ),
        scenario(
            2,
            if has_postgres {
                ScenarioStatus::Incomplete
            } else {
                ScenarioStatus::Blocked
            },
            if has_postgres {
                "Reviewed PostgreSQL scope exists; native collection, blocker, import and workload receipts are required."
            } else {
                "A reviewed PostgreSQL scope is required for native reads."
            },
        ),
        scenario(
            3,
            ScenarioStatus::Blocked,
            "Requires accepted Task 14 protected rehearsal and Task 15 native production action, intent and verification receipts.",
        ),
        scenario(
            4,
            ScenarioStatus::Blocked,
            "Requires accepted Task 14 protected rehearsal and Task 15 exact-index production and restoration receipts.",
        ),
        scenario(
            5,
            if has_http >= 3 {
                ScenarioStatus::Incomplete
            } else {
                ScenarioStatus::Blocked
            },
            if has_http >= 3 {
                "Three reviewed HTTP scopes exist; separate DB-backed API and portal functional receipts are still required."
            } else {
                "Three separately reviewed API/portal HTTP scopes are required."
            },
        ),
        scenario(
            6,
            ScenarioStatus::Incomplete,
            "Pre-dispatch edit and post-launch reconciliation witnesses have not been collected for this run.",
        ),
        scenario(
            7,
            if verified {
                ScenarioStatus::Incomplete
            } else {
                ScenarioStatus::Blocked
            },
            if verified {
                "Case is marked verified; exact lesson evidence, restart invalidation and export receipts are still required."
            } else {
                "Requires an independently verified product outcome before lesson creation."
            },
        ),
    ];
    let captures = [
        CaptureState::Requested,
        CaptureState::Approved,
        CaptureState::Consumed,
        CaptureState::Verified,
        CaptureState::Intervention,
    ]
    .into_iter()
    .map(|state| CaptureReference {
        state,
        status: ScenarioStatus::NotRun,
        evidence_refs: Vec::new(),
    })
    .collect();
    let report = AcceptanceReport {
        schema: ACCEPTANCE_SCHEMA,
        run_id: Uuid::new_v4(),
        case_id: case.id(),
        case_revision: case.revision(),
        evidence_revision: case.evidence_revision(),
        fixture,
        product_acceptance: false,
        created_at: Utc::now(),
        scenarios,
        captures,
    };
    report.validate()?;
    Ok(report)
}

pub fn save_report(path: &Path, report: &AcceptanceReport) -> Result<()> {
    let bytes = report.to_bounded_json()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::security::atomic_write(path, &bytes)?;
    Ok(())
}

pub fn load_report(path: &Path) -> Result<AcceptanceReport> {
    let metadata = std::fs::metadata(path)?;
    ensure!(
        metadata.len() as usize <= MAX_REPORT_BYTES,
        "Acceptance report exceeds size limit"
    );
    AcceptanceReport::from_bounded_json(&std::fs::read(path)?)
}

fn scenario(id: u8, status: ScenarioStatus, summary: &str) -> ScenarioResult {
    ScenarioResult {
        id,
        status,
        summary: summary.to_owned(),
        evidence_refs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::case::{HelperCase, ProblemIntake};

    #[test]
    fn preflight_keeps_native_changes_blocked_and_acceptance_false() {
        let case = HelperCase::new(ProblemIntake::default()).unwrap();
        let report = run_acceptance(&case, FixtureLabel::SimulationFixture).unwrap();
        assert_eq!(report.scenarios.len(), 7);
        assert_eq!(report.scenarios[2].status, ScenarioStatus::Blocked);
        assert_eq!(report.scenarios[3].status, ScenarioStatus::Blocked);
        assert!(!report.product_acceptance);
        AcceptanceReport::from_bounded_json(&report.to_bounded_json().unwrap()).unwrap();
    }

    #[test]
    fn acceptance_flag_cannot_be_set_for_simulation_or_partial_results() {
        let case = HelperCase::new(ProblemIntake::default()).unwrap();
        let mut report = run_acceptance(&case, FixtureLabel::SimulationFixture).unwrap();
        report.product_acceptance = true;
        assert!(report.validate().is_err());
        report.product_acceptance = false;
        report.scenarios.pop();
        assert!(report.validate().is_err());
    }

    #[test]
    fn preflight_cannot_claim_a_measured_fixture_or_successful_scenario() {
        let case = HelperCase::new(ProblemIntake::default()).unwrap();
        let mut report = run_acceptance(&case, FixtureLabel::SimulationFixture).unwrap();
        report.fixture = FixtureLabel::MeasuredGuestFixture;
        assert!(report.validate().is_err());
        report.fixture = FixtureLabel::SimulationFixture;
        report.scenarios[0].status = ScenarioStatus::Passed;
        assert!(report.validate().is_err());
    }
}
