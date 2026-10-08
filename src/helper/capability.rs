//! Only a registered adapter can turn a typed capability into executable collection.
use super::{
    case::HelperCase,
    evidence::{Coverage, EvidenceBinding, EvidenceStatus, NormalizedMetric, NormalizedRecord},
    manifest::{CapabilityDeclaration, CapabilityId, Prerequisite, ProbeParams},
    scope::BoundScope,
};
use crate::helper::credentials::SecretResolver;
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio_util::sync::CancellationToken;

pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + 'a>>;

#[derive(Clone)]
pub struct ProbeRequest {
    pub binding: EvidenceBinding,
    pub scope: BoundScope,
    pub capability_id: CapabilityId,
    pub capability_version: u16,
    pub params: ProbeParams,
    pub requested_at: DateTime<Utc>,
    pub deadline_secs: Option<u64>,
}

pub struct ProbeOutput {
    pub status: EvidenceStatus,
    pub coverage: Coverage,
    pub records: Vec<NormalizedRecord>,
    pub metrics: Vec<NormalizedMetric>,
    pub sql_observations: Vec<super::sql::types::SqlObservation>,
    pub evidence_refs: Vec<uuid::Uuid>,
    /// Raw source identity is hashed before the envelope is persisted.
    pub source_id: Vec<u8>,
    pub source_observed_at: DateTime<Utc>,
    pub parser_version: u16,
}

pub trait ProbeAdapter: Send + Sync {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        secrets: &'a dyn SecretResolver,
        cancel: CancellationToken,
    ) -> ProbeFuture<'a>;
}

pub struct CapabilityRegistry {
    entries: HashMap<CapabilityId, (CapabilityDeclaration, Arc<dyn ProbeAdapter>)>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        descriptor: CapabilityDeclaration,
        adapter: Arc<dyn ProbeAdapter>,
    ) -> Result<()> {
        ensure!(descriptor.version > 0, "Invalid capability version");
        ensure!(
            !self.entries.contains_key(&descriptor.id),
            "Duplicate executable capability"
        );
        self.entries.insert(descriptor.id, (descriptor, adapter));
        Ok(())
    }

    pub fn descriptor(&self, id: CapabilityId) -> Option<&CapabilityDeclaration> {
        self.entries.get(&id).map(|entry| &entry.0)
    }

    pub fn adapter(&self, id: CapabilityId) -> Option<Arc<dyn ProbeAdapter>> {
        self.entries.get(&id).map(|entry| Arc::clone(&entry.1))
    }

    pub fn validate_request(&self, case: &HelperCase, request: &ProbeRequest) -> Result<()> {
        let (descriptor, _) = self
            .entries
            .get(&request.capability_id)
            .ok_or_else(|| anyhow::anyhow!("Capability has no executable adapter"))?;
        ensure!(
            descriptor.version == request.capability_version,
            "Capability version changed"
        );
        ensure!(
            request.binding.case_id == case.id()
                && request.binding.case_revision == case.revision(),
            "Case binding changed"
        );
        ensure!(
            request.binding.request_id != uuid::Uuid::nil(),
            "Invalid request ID"
        );
        request.scope.validate()?;
        ensure!(
            request.binding.scope_sha256 == request.scope.digest()?
                && request.binding.credential_scope_sha256
                    == request.scope.credential_scope_digest()?,
            "Scope binding changed"
        );
        ensure!(
            case.scopes()
                .iter()
                .any(|scope| scope.digest().ok() == Some(request.binding.scope_sha256.clone())),
            "Scope is not reviewed"
        );
        ensure!(
            request.deadline_secs.unwrap_or(15) > 0 && request.deadline_secs.unwrap_or(15) <= 30,
            "Probe deadline outside 1..=30 seconds"
        );
        if let Some(credential) = request.scope.credential() {
            ensure!(
                credential.purpose != super::scope::CredentialPurpose::ControlledChange,
                "Change credential cannot collect diagnostic evidence"
            );
        }
        if descriptor
            .prerequisites
            .contains(&Prerequisite::ReadCredential)
        {
            ensure!(
                request.scope.credential().is_some(),
                "Read credential missing"
            );
        }
        match (&request.capability_id, &request.params, &request.scope) {
            (CapabilityId::NetworkReachability, ProbeParams::Network { port }, scope) => {
                let expected = match scope {
                    BoundScope::Http { port, .. } | BoundScope::Database { port, .. } => *port,
                    _ => scope.target().map(|target| target.port).unwrap_or(0),
                };
                ensure!(
                    *port > 0 && *port == expected,
                    "Network port differs from reviewed endpoint"
                );
            }
            (CapabilityId::HttpHealth, ProbeParams::Http, BoundScope::Http { .. }) => {}
            (
                CapabilityId::SystemResources,
                ProbeParams::System,
                BoundScope::Windows { .. } | BoundScope::Linux { .. },
            ) => {}
            (
                CapabilityId::ServiceStatus,
                ProbeParams::Service { service_digest },
                BoundScope::Windows { .. } | BoundScope::Linux { .. },
            ) if super::evidence::is_digest(service_digest) => {}
            (
                CapabilityId::SqlRead,
                ProbeParams::SqlRead { query_digest },
                BoundScope::Database {
                    engine: super::scope::DatabaseEngine::Postgres,
                    credential: Some(credential),
                    ..
                },
            ) if query_digest == &super::sql::postgres::template_digest()
                && credential.purpose == super::scope::CredentialPurpose::Read => {}
            (
                CapabilityId::SqlRead,
                ProbeParams::SqlRead { query_digest },
                BoundScope::Database {
                    engine: super::scope::DatabaseEngine::SqlServer,
                    credential: Some(credential),
                    ..
                },
            ) if query_digest == &super::sql::sql_server::template_digest()
                && credential.purpose == super::scope::CredentialPurpose::Read => {}
            (
                CapabilityId::SqlPlan,
                ProbeParams::SqlPlan { query_digest },
                BoundScope::Database { .. },
            ) if super::evidence::is_digest(query_digest) => {}
            (
                CapabilityId::SqlWorkloadBaseline | CapabilityId::SqlWorkloadRehearsal,
                ProbeParams::SqlWorkload { workload_digest },
                BoundScope::Database { .. },
            ) if super::evidence::is_digest(workload_digest) => {}
            (
                CapabilityId::ContainerStatus,
                ProbeParams::Container,
                BoundScope::Docker { .. } | BoundScope::Kubernetes { .. },
            ) => {}
            (
                CapabilityId::CloudInstanceStatus
                | CapabilityId::AzureVmIdentity
                | CapabilityId::AzureVmResourceHealth
                | CapabilityId::AwsEc2Inventory
                | CapabilityId::AwsEc2Status,
                ProbeParams::CloudInstance,
                BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. },
            ) => {}
            _ => anyhow::bail!("Capability parameters or scope mismatch"),
        }
        ensure!(
            match request.capability_id {
                CapabilityId::AzureVmIdentity | CapabilityId::AzureVmResourceHealth =>
                    matches!(request.scope, BoundScope::AzureVm { .. }),
                CapabilityId::AwsEc2Inventory | CapabilityId::AwsEc2Status =>
                    matches!(request.scope, BoundScope::AwsEc2 { .. }),
                _ => true,
            },
            "Cloud capability/scope mismatch"
        );
        if matches!(
            request.capability_id,
            CapabilityId::AzureVmIdentity
                | CapabilityId::AzureVmResourceHealth
                | CapabilityId::AwsEc2Inventory
                | CapabilityId::AwsEc2Status
        ) {
            ensure!(
                request.scope.credential().is_some_and(
                    |credential| credential.purpose == super::scope::CredentialPurpose::Read
                ),
                "Cloud read credential required"
            );
        }
        ensure!(descriptor.version > 0, "Capability version unavailable");
        Ok(())
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}
