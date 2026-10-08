//! Explicit review of scope identities; controls here never dispatch work.
use super::*;
use crate::{
    helper::{
        inventory::{InventoryEntry, derive_inventory},
        scope::{BoundScope, CredentialPurpose, CredentialScope, DatabaseEngine},
    },
    mission::Target,
    models::ConnectionProfile,
    telemetry,
};

const KINDS: [&str; 8] = [
    "Windows",
    "Linux",
    "Database",
    "HTTP",
    "Docker",
    "Kubernetes",
    "Azure VM",
    "AWS EC2",
];

#[derive(Default)]
pub(super) struct Editor {
    kind: usize,
    profile: Option<Uuid>,
    engine: usize,
    port: String,
    database: String,
    schema: String,
    object: String,
    tls: bool,
    path: String,
    daemon_context: String,
    container_id: String,
    context: String,
    cluster_fingerprint: String,
    namespace: String,
    resource_kind: String,
    resource_name: String,
    tenant: String,
    subscription: String,
    resource_id: String,
    account: String,
    region: String,
    instance_id: String,
    credential_ref: String,
    credential_purpose: usize,
    credential_generation: String,
    credential_principal: String,
    credential_context: String,
}

fn optional(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
impl Editor {
    fn credential(&self) -> anyhow::Result<Option<CredentialScope>> {
        if self.credential_ref.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(CredentialScope {
            reference: Uuid::parse_str(self.credential_ref.trim())?,
            purpose: [
                CredentialPurpose::Read,
                CredentialPurpose::Diagnose,
                CredentialPurpose::ControlledChange,
            ][self.credential_purpose],
            generation: self.credential_generation.parse()?,
            principal: self.credential_principal.clone(),
            context: self.credential_context.clone(),
            context_digest: String::new(),
        }))
    }
    fn build(&self, profiles: &[ConnectionProfile]) -> anyhow::Result<BoundScope> {
        let credential = self.credential()?;
        let target = || -> anyhow::Result<Target> {
            let id = self
                .profile
                .ok_or_else(|| anyhow::anyhow!("Select an exact saved profile"))?;
            let profile = profiles
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| anyhow::anyhow!("Selected profile missing"))?;
            Ok(Target::from_profile(profile))
        };
        let scope = match self.kind {
            0 => BoundScope::Windows {
                target: target()?,
                credential,
            },
            1 => BoundScope::Linux {
                target: target()?,
                credential,
            },
            2 => BoundScope::Database {
                target: target()?,
                engine: if self.engine == 0 {
                    DatabaseEngine::Postgres
                } else {
                    DatabaseEngine::SqlServer
                },
                port: self.port.parse()?,
                database: self.database.clone(),
                schema: optional(&self.schema),
                object: optional(&self.object),
                credential,
            },
            3 => BoundScope::Http {
                target: target()?,
                port: self.port.parse()?,
                tls: self.tls,
                path: self.path.clone(),
            },
            4 => BoundScope::Docker {
                daemon_context: self.daemon_context.clone(),
                container_id: self.container_id.clone(),
                credential,
            },
            5 => BoundScope::Kubernetes {
                context: self.context.clone(),
                cluster_fingerprint: self.cluster_fingerprint.clone(),
                namespace: self.namespace.clone(),
                resource_kind: self.resource_kind.clone(),
                resource_name: self.resource_name.clone(),
                credential,
            },
            6 => BoundScope::AzureVm {
                tenant: self.tenant.clone(),
                subscription: self.subscription.clone(),
                resource_id: self.resource_id.clone(),
                credential,
            },
            _ => BoundScope::AwsEc2 {
                account: self.account.clone(),
                region: self.region.clone(),
                instance_id: self.instance_id.clone(),
                credential,
            },
        };
        scope.bind_credential_context()
    }
}

pub(super) fn show(
    state: &mut HelperState,
    ui: &mut Ui,
    case: &HelperCase,
    profiles: &[ConnectionProfile],
    telemetry: &telemetry::Store,
) {
    ui.separator();
    ui.heading("Reviewed system scopes");
    ui.label("Choose an exact saved profile or enter an explicit resource identity. Review records intent only; no connection or check starts here.");
    for (index, scope) in case.scopes().iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!(
                "{} · resource {} · review {}",
                scope_kind(scope),
                scope
                    .resource_digest()
                    .unwrap_or_else(|_| "invalid".into())
                    .chars()
                    .take(12)
                    .collect::<String>(),
                scope
                    .digest()
                    .unwrap_or_else(|_| "invalid".into())
                    .chars()
                    .take(12)
                    .collect::<String>()
            ));
            if let Some(target) = scope.target() {
                let current = profiles.iter().find(|p| p.id == target.profile_id);
                ui.label(match current {
                    Some(p) if scope.matches_profile(p) => "Exact profile bound",
                    _ => "Profile changed or missing · review again",
                });
            }
            if ui.button("Remove reviewed scope").clicked() {
                let mut scopes = case.scopes().to_vec();
                scopes.remove(index);
                state.revise(CaseEdit::Scopes(scopes));
            }
        });
    }
    let mut pending_profile_ids = None;
    let editor = &mut state.scope_editor;
    egui::ComboBox::from_id_salt("helper-scope-kind")
        .selected_text(KINDS[editor.kind])
        .show_ui(ui, |ui| {
            for (i, kind) in KINDS.iter().enumerate() {
                ui.selectable_value(&mut editor.kind, i, *kind);
            }
        });
    if editor.kind <= 3 {
        let label = editor
            .profile
            .and_then(|id| profiles.iter().find(|p| p.id == id))
            .map(|p| {
                format!(
                    "{} · {}:{} · {}",
                    p.name,
                    p.host,
                    p.port,
                    p.protocol.label()
                )
            })
            .unwrap_or_else(|| "Select exact saved profile".into());
        egui::ComboBox::from_id_salt("helper-scope-profile")
            .selected_text(label)
            .show_ui(ui, |ui| {
                for profile in profiles {
                    ui.selectable_value(
                        &mut editor.profile,
                        Some(profile.id),
                        format!(
                            "{} · {}:{} · {}",
                            profile.name,
                            profile.host,
                            profile.port,
                            profile.protocol.label()
                        ),
                    );
                }
            });
        if let Some(id) = editor.profile {
            if !case.profile_ids().contains(&id) && ui.button("Add profile to case").clicked() {
                let mut ids = case.profile_ids().to_vec();
                ids.push(id);
                pending_profile_ids = Some(ids);
            }
            if !case.profile_ids().contains(&id) {
                ui.label("Add this profile to the case before reviewing its scope.");
            }
        }
    }
    match editor.kind {
        2 => {
            egui::ComboBox::from_id_salt("helper-db-engine")
                .selected_text(if editor.engine == 0 {
                    "PostgreSQL"
                } else {
                    "SQL Server"
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut editor.engine, 0, "PostgreSQL");
                    ui.selectable_value(&mut editor.engine, 1, "SQL Server");
                });
            ui.label("Database port is separate from the profile's RDP/SSH port.");
            field(ui, "Database port", &mut editor.port);
            field(ui, "Database", &mut editor.database);
            field(ui, "Schema (optional)", &mut editor.schema);
            field(ui, "Object (optional)", &mut editor.object);
        }
        3 => {
            field(ui, "HTTP port", &mut editor.port);
            ui.checkbox(&mut editor.tls, "TLS");
            field(ui, "Path", &mut editor.path);
        }
        4 => {
            field(ui, "Daemon context", &mut editor.daemon_context);
            field(ui, "Container ID", &mut editor.container_id);
        }
        5 => {
            field(ui, "Context", &mut editor.context);
            field(ui, "Cluster fingerprint", &mut editor.cluster_fingerprint);
            field(ui, "Namespace", &mut editor.namespace);
            field(ui, "Resource kind", &mut editor.resource_kind);
            field(ui, "Resource name", &mut editor.resource_name);
        }
        6 => {
            field(ui, "Tenant UUID", &mut editor.tenant);
            field(ui, "Subscription UUID", &mut editor.subscription);
            field(ui, "VM resource ID", &mut editor.resource_id);
        }
        7 => {
            field(ui, "Account ID", &mut editor.account);
            field(ui, "Region", &mut editor.region);
            field(ui, "Instance ID", &mut editor.instance_id);
        }
        _ => {}
    }
    if editor.kind != 3 {
        ui.collapsing("Credential reference (metadata only)", |ui| {
            field(ui, "Reference UUID (optional)", &mut editor.credential_ref);
            if !editor.credential_ref.is_empty() {
                egui::ComboBox::from_id_salt("helper-credential-purpose")
                    .selected_text(
                        ["Read", "Diagnose", "Controlled change"][editor.credential_purpose],
                    )
                    .show_ui(ui, |ui| {
                        for (i, label) in
                            ["Read", "Diagnose", "Controlled change"].iter().enumerate()
                        {
                            ui.selectable_value(&mut editor.credential_purpose, i, *label);
                        }
                    });
                field(ui, "Generation", &mut editor.credential_generation);
                field(ui, "Principal", &mut editor.credential_principal);
                field(ui, "Context", &mut editor.credential_context);
            }
        });
    }
    if ui.button("Review and add scope").clicked() {
        match editor.build(profiles) {
            Ok(scope) => {
                let mut scopes = case.scopes().to_vec();
                scopes.push(scope);
                state.revise(CaseEdit::Scopes(scopes));
            }
            Err(error) => state.notice = format!("Scope review failed: {error}"),
        }
    }
    if let Some(ids) = pending_profile_ids {
        state.revise(CaseEdit::Profiles(ids));
    }
    ui.label("Telemetry and connector readiness remain unknown until separately checked.");
    ui.collapsing("Recorded inventory and network links", |ui| {
        for entry in derive_inventory(profiles, telemetry, chrono::Utc::now()) {
            match entry {
                InventoryEntry::SavedProfile { target }
                    if case.profile_ids().contains(&target.profile_id) =>
                {
                    ui.label(format!(
                        "Saved profile · {}:{} · {}",
                        target.host, target.port, target.protocol
                    ));
                }
                InventoryEntry::DirectCapture {
                id,
                    target,
                    freshness,
                    partial,
                } if case.profile_ids().contains(&target.profile_id) => {
                    ui.label(format!(
                    "Direct capture {} · {} · {:?}{}",
                    id,
                        target.host,
                        freshness,
                        if partial { " · partial/unknown" } else { "" }
                    ));
                }
                InventoryEntry::InferredNetwork {
                    source,
                    destination,
                address,
                    port,
                    freshness,
                    profile_drift,
                evidence,
                } if case.profile_ids().contains(&source.profile_id)
                    || case.profile_ids().contains(&destination.profile_id) =>
                {
                    ui.label(format!(
                    "Inferred TCP link · {} → {} ({}:{}) · {:?}{} · {} captures · service identity unknown",
                        source.host,
                        destination.host,
                    address,
                        port,
                        freshness,
                        if profile_drift {
                            " · profile changed"
                        } else {
                            ""
                    },
                    evidence.len()
                    ));
                }
                _ => {}
            }
        }
    });
}

fn field(ui: &mut Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.text_edit_singleline(value);
    });
}
fn scope_kind(scope: &BoundScope) -> &'static str {
    match scope {
        BoundScope::Windows { .. } => "Windows",
        BoundScope::Linux { .. } => "Linux",
        BoundScope::Database { .. } => "Database",
        BoundScope::Http { .. } => "HTTP",
        BoundScope::Docker { .. } => "Docker",
        BoundScope::Kubernetes { .. } => "Kubernetes",
        BoundScope::AzureVm { .. } => "Azure VM",
        BoundScope::AwsEc2 { .. } => "AWS EC2",
    }
}
