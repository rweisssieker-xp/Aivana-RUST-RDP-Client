//! Declarative capability vocabulary. A manifest entry never registers an executable adapter.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    NetworkReachability,
    HttpHealth,
    SystemResources,
    ServiceStatus,
    SqlRead,
    SqlPlan,
    SqlWorkloadBaseline,
    SqlWorkloadRehearsal,
    ContainerStatus,
    CloudInstanceStatus,
    AzureVmIdentity,
    AzureVmResourceHealth,
    AwsEc2Inventory,
    AwsEc2Status,
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
    Http,
    System,
    Service { service_digest: String },
    SqlRead { query_digest: String },
    SqlPlan { query_digest: String },
    SqlWorkload { workload_digest: String },
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
        use CheckRole::{Diagnostic, Performance, Rehearsal};
        use Prerequisite::{
            DeclaredWorkload, IsolatedRehearsal, NetworkAccess, ReadCredential, ReviewedScope,
        };
        let declaration = |id, role, prerequisites| CapabilityDeclaration {
            id,
            version: 1,
            role,
            prerequisites,
        };
        let declarations = vec![
            declaration(
                NetworkReachability,
                Diagnostic,
                vec![ReviewedScope, NetworkAccess],
            ),
            declaration(HttpHealth, Diagnostic, vec![ReviewedScope, NetworkAccess]),
            declaration(
                SystemResources,
                Diagnostic,
                vec![ReviewedScope, ReadCredential],
            ),
            declaration(
                ServiceStatus,
                Diagnostic,
                vec![ReviewedScope, ReadCredential],
            ),
            declaration(
                SqlRead,
                Diagnostic,
                vec![ReviewedScope, ReadCredential, NetworkAccess],
            ),
            declaration(
                SqlPlan,
                Diagnostic,
                vec![
                    ReviewedScope,
                    ReadCredential,
                    NetworkAccess,
                    DeclaredWorkload,
                ],
            ),
            declaration(
                SqlWorkloadBaseline,
                Performance,
                vec![
                    ReviewedScope,
                    ReadCredential,
                    NetworkAccess,
                    DeclaredWorkload,
                ],
            ),
            declaration(
                SqlWorkloadRehearsal,
                Rehearsal,
                vec![
                    ReviewedScope,
                    ReadCredential,
                    NetworkAccess,
                    DeclaredWorkload,
                    IsolatedRehearsal,
                ],
            ),
            declaration(
                ContainerStatus,
                Diagnostic,
                vec![ReviewedScope, ReadCredential],
            ),
            declaration(
                CloudInstanceStatus,
                Diagnostic,
                vec![ReviewedScope, ReadCredential, NetworkAccess],
            ),
            declaration(
                AzureVmIdentity,
                Diagnostic,
                vec![ReviewedScope, ReadCredential, NetworkAccess],
            ),
            declaration(
                AzureVmResourceHealth,
                Diagnostic,
                vec![ReviewedScope, ReadCredential, NetworkAccess],
            ),
            declaration(
                AwsEc2Inventory,
                Diagnostic,
                vec![ReviewedScope, ReadCredential, NetworkAccess],
            ),
            declaration(
                AwsEc2Status,
                Diagnostic,
                vec![ReviewedScope, ReadCredential, NetworkAccess],
            ),
        ];
        Self { declarations }
    }
}
