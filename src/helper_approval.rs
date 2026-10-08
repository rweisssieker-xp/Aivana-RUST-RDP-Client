//! Portable, metadata-only authority wire for generic helper SQL actions.
//! This module is compiled into both binaries; it has no desktop or executor dependency.
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::helper_action::{Digest, RestorationSpec, SqlAction, digest, valid_digest};

pub const ACTION_BINDING_VERSION: u16 = 2;
const DOMAIN: &[u8] = b"relayne-helper-action-binding-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    Rehearsal,
    Production,
}

/// A staged run is authorized by an explicit local review. Production requires an
/// actual protected receipt produced by the SQL rehearsal executor in Wave 14.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionProof {
    StagingReviewProof {
        review_id: Uuid,
        review_sha256: Digest,
        expires_at: DateTime<Utc>,
    },
    SqlRehearsalReceipt {
        receipt_id: Uuid,
        receipt_sha256: Digest,
        expires_at: DateTime<Utc>,
    },
}

impl ActionProof {
    pub fn digest(&self) -> &str {
        match self {
            Self::StagingReviewProof { review_sha256, .. } => review_sha256,
            Self::SqlRehearsalReceipt { receipt_sha256, .. } => receipt_sha256,
        }
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        match self {
            Self::StagingReviewProof { expires_at, .. }
            | Self::SqlRehearsalReceipt { expires_at, .. } => *expires_at,
        }
    }
    fn validate(&self, run_kind: RunKind, now: DateTime<Utc>) -> Result<()> {
        match (run_kind, self) {
            (
                RunKind::Rehearsal,
                Self::StagingReviewProof {
                    review_id,
                    review_sha256,
                    ..
                },
            ) => ensure!(
                *review_id != Uuid::nil() && valid_digest(review_sha256),
                "Invalid staged review proof"
            ),
            (
                RunKind::Production,
                Self::SqlRehearsalReceipt {
                    receipt_id,
                    receipt_sha256,
                    ..
                },
            ) => ensure!(
                *receipt_id != Uuid::nil() && valid_digest(receipt_sha256),
                "Invalid SQL rehearsal receipt reference"
            ),
            _ => anyhow::bail!("Proof type does not authorize this run kind"),
        }
        ensure!(self.expires_at() > now, "Action proof expired");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBindingV2 {
    pub version: u16,
    pub case_id: Uuid,
    pub case_revision: u64,
    pub evidence_revision: u64,
    pub run_id: Uuid,
    pub run_kind: RunKind,
    pub organization_sha256: Digest,
    pub scope_sha256: Digest,
    pub credential_scope_sha256: Digest,
    pub action_version: u16,
    pub action: SqlAction,
    pub metadata_sha256: Digest,
    pub before_sha256: Digest,
    pub plan_sha256: Digest,
    pub verification_sha256: Digest,
    pub proof: ActionProof,
    pub restoration: RestorationSpec,
    pub statistics_limit_acknowledged: bool,
    pub captured_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ActionBindingV2 {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.version == ACTION_BINDING_VERSION
                && self.action_version == crate::helper_action::SQL_ACTION_VERSION,
            "Unsupported action binding version"
        );
        ensure!(
            self.case_id != Uuid::nil()
                && self.run_id != Uuid::nil()
                && self.case_revision > 0
                && self.evidence_revision > 0,
            "Invalid case/run identity"
        );
        for value in [
            &self.organization_sha256,
            &self.scope_sha256,
            &self.credential_scope_sha256,
            &self.metadata_sha256,
            &self.before_sha256,
            &self.plan_sha256,
            &self.verification_sha256,
        ] {
            ensure!(valid_digest(value), "Invalid action digest");
        }
        ensure!(
            self.action.object().scope_sha256 == self.scope_sha256,
            "Action scope differs from binding"
        );
        self.restoration.validate_for(&self.action)?;
        ensure!(
            !self.action.is_statistics() || self.statistics_limit_acknowledged,
            "Statistics restoration limitation not acknowledged"
        );
        self.proof.validate(self.run_kind, now)?;
        ensure!(
            self.captured_at <= now
                && now.signed_duration_since(self.captured_at) < Duration::seconds(120),
            "Stale action preconditions"
        );
        ensure!(
            self.expires_at > now && self.expires_at <= self.captured_at + Duration::minutes(10),
            "Invalid action expiry"
        );
        ensure!(
            self.proof.expires_at() >= self.expires_at,
            "Proof expires before action binding"
        );
        Ok(())
    }
    pub fn fingerprint(&self) -> Result<Digest> {
        digest(DOMAIN, self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateActionApprovalV2 {
    pub request_id: Uuid,
    pub binding: ActionBindingV2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDecisionV2 {
    Approve,
    Deny,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideActionApprovalV2 {
    pub decision: ActionDecisionV2,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeActionApprovalV2 {
    pub binding: ActionBindingV2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionApprovalStateV2 {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionApprovalV2 {
    pub id: Uuid,
    pub request_id: Uuid,
    pub binding: ActionBindingV2,
    pub fingerprint: Digest,
    pub requester: String,
    pub approver: Option<String>,
    pub state: ActionApprovalStateV2,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeReceiptV2 {
    pub approval_id: Uuid,
    pub consume_id: Uuid,
    pub fingerprint: Digest,
    pub organization_sha256: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcomeV2 {
    Verified,
    Failed,
    NeedsIntervention,
    OutcomeUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionOutcomeEventV2 {
    pub event_id: Uuid,
    /// Starts at one. Each correction references the immediately preceding event.
    pub sequence: u32,
    pub previous_event_id: Option<Uuid>,
    pub approval_id: Uuid,
    pub consume_id: Uuid,
    pub run_id: Uuid,
    pub fingerprint: Digest,
    pub outcome: ActionOutcomeV2,
    pub occurred_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionOutcomeAckV2 {
    pub event_id: Uuid,
    pub accepted: bool,
}
