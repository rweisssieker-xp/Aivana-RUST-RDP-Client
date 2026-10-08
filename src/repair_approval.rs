//! Metadata-only, versioned wire contract for team-controlled service repair.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairState {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairDecision {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairServiceState {
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    Rehearsal,
    Lab,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairProof {
    pub kind: ProofKind,
    pub reference_id: Uuid,
    pub sha256: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairBinding {
    pub version: u8,
    pub run_id: Uuid,
    pub target_index: u8,
    pub profile_id: Uuid,
    pub plan_sha256: String,
    pub target_sha256: String,
    pub service: String,
    pub before: RepairServiceState,
    pub desired: RepairServiceState,
    pub captured_at: DateTime<Utc>,
    pub baseline_passed: bool,
    pub baseline_sha256: String,
    pub health_sha256: String,
    pub proof: RepairProof,
}

pub fn digest(domain: &[u8], value: &impl Serialize) -> anyhow::Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(serde_json::to_vec(value)?);
    Ok(format!("{:x}", hash.finalize()))
}

impl RepairBinding {
    pub fn validate(&self, now: DateTime<Utc>) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == 1 && self.run_id != Uuid::nil() && self.profile_id != Uuid::nil(),
            "Invalid repair binding version or identity"
        );
        anyhow::ensure!(self.target_index < 32, "Invalid repair target index");
        anyhow::ensure!(
            !self.service.is_empty()
                && self.service.len() <= 128
                && self
                    .service
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "Invalid repair service"
        );
        for hash in [
            &self.plan_sha256,
            &self.target_sha256,
            &self.baseline_sha256,
            &self.health_sha256,
            &self.proof.sha256,
        ] {
            anyhow::ensure!(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "Invalid repair digest"
            );
        }
        anyhow::ensure!(
            self.proof.reference_id != Uuid::nil(),
            "Invalid proof reference"
        );
        anyhow::ensure!(
            self.captured_at <= now
                && (now - self.captured_at).num_seconds() < 120
                && self.proof.expires_at > now,
            "Stale repair evidence"
        );
        Ok(())
    }
    pub fn fingerprint(&self) -> anyhow::Result<String> {
        digest(b"relayne-repair-binding-v1", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRepairApproval {
    pub request_id: Uuid,
    pub binding: RepairBinding,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideRepairApproval {
    pub decision: RepairDecision,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeRepairApproval {
    pub binding: RepairBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairApproval {
    pub id: Uuid,
    pub request_id: Uuid,
    pub binding: RepairBinding,
    pub fingerprint: String,
    pub requester: String,
    pub approver: Option<String>,
    pub state: RepairState,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsumeReceipt {
    pub approval_id: Uuid,
    pub consume_id: Uuid,
    pub fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairOutcome {
    Passed,
    Failed,
    Restored,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairOutcomeEvent {
    pub event_id: Uuid,
    pub approval_id: Uuid,
    pub run_id: Uuid,
    pub target_index: u8,
    pub outcome: RepairOutcome,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairOutcomeAck {
    pub event_id: Uuid,
    pub accepted: bool,
}
