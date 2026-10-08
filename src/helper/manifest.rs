//! Declarative capability vocabulary. A manifest entry never registers an executable adapter.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    NetworkReachability,
    SystemResources,
    ServiceStatus,
    SqlRead,
    SqlPlan,
    ContainerStatus,
    CloudInstanceStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckRole {
    Diagnostic,
    Functional,
    Performance,
    Rehearsal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prerequisite {
    ReviewedScope,
    ReadCredential,
    NetworkAccess,
    DeclaredWorkload,
    IsolatedRehearsal,
}

/// Closed parameters; digests refer to reviewed, separately stored declarations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeParams {
    Network { port: u16 },
    System,
    Service { service_digest: String },
    SqlRead { query_digest: String },
    SqlPlan { query_digest: String },
    Container,
    CloudInstance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDeclaration {
    pub id: CapabilityId,
    pub version: u16,
    pub role: CheckRole,
    pub prerequisites: Vec<Prerequisite>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub declarations: Vec<CapabilityDeclaration>,
}

impl CapabilityManifest {
    pub fn built_in() -> Self {
        use CapabilityId::*;
        let declarations = [
            NetworkReachability,
            SystemResources,
            ServiceStatus,
            SqlRead,
            SqlPlan,
            ContainerStatus,
            CloudInstanceStatus,
        ]
        .into_iter()
        .map(|id| CapabilityDeclaration {
            id,
            version: 1,
            role: CheckRole::Diagnostic,
            prerequisites: vec![Prerequisite::ReviewedScope],
        })
        .collect();
        Self { declarations }
    }
}
