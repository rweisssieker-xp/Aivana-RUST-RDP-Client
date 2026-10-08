//! Explicit review of scope identities; controls here never dispatch work.
use super::*;
use crate::{
    helper::{
        cloud,
        inventory::{InventoryEntry, derive_inventory},
        scope::{BoundScope, CredentialPurpose, CredentialScope, DatabaseEngine},
    },
    mission::Target,
    models::{ConnectionProfile, SecretCredential},
    security::PersistentCredentialStore,
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
    cloud_case: Option<Uuid>,
    cloud_scope_digest: String,
    cloud_principal: String,
    cloud_secret: String,
    cloud_access_key: String,
    cloud_session_token: String,
}

fn optional(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
impl Editor {
    pub(super) fn clear_cloud_draft(&mut self) {
        self.cloud_case = None;
        self.cloud_scope_digest.clear();
        self.cloud_principal.clear();
        self.cloud_secret.clear();
        self.cloud_access_key.clear();
        self.cloud_session_token.clear();
    }

    fn prepare_cloud(&mut self, case_id: Uuid, scope: &BoundScope) -> anyhow::Result<()> {
        self.clear_cloud_draft();
        anyhow::ensure!(
            matches!(
                scope,
                BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
            ),
            "Cloud scope required"
        );
        self.cloud_case = Some(case_id);
        self.cloud_scope_digest = scope.digest()?;
        self.cloud_principal = scope
            .credential()
            .map(|credential| credential.principal.clone())
            .unwrap_or_default();
        Ok(())
    }

    fn provision_cloud(
        &mut self,
        case_id: Uuid,
        scope: &BoundScope,
        store: &mut PersistentCredentialStore,
    ) -> anyhow::Result<BoundScope> {
        anyhow::ensure!(
            self.cloud_case == Some(case_id) && self.cloud_scope_digest == scope.digest()?,
            "Cloud scope changed"
        );
        let principal = std::mem::take(&mut self.cloud_principal);
        let password = std::mem::take(&mut self.cloud_secret);
        let access_key = std::mem::take(&mut self.cloud_access_key);
        let session_token = std::mem::take(&mut self.cloud_session_token);
        anyhow::ensure!(
            !password.is_empty() && password.len() <= 16 * 1024,
            "Invalid cloud secret"
        );
        let domain = match scope {
            BoundScope::AzureVm { tenant, .. } => {
                cloud::token_tenant(&password, tenant, &principal)?;
                String::new()
            }
            BoundScope::AwsEc2 {
                account, region, ..
            } => {
                anyhow::ensure!(
                    password.len() <= 4096 && !password.chars().any(char::is_control),
                    "Invalid AWS secret access key"
                );
                let partition = if region.starts_with("cn-") {
                    "arn:aws-cn:"
                } else if region.starts_with("us-gov-") {
                    "arn:aws-us-gov:"
                } else {
                    "arn:aws:"
                };
                anyhow::ensure!(
                    principal.starts_with(partition)
                        && principal.contains(&format!("::{account}:")),
                    "Invalid reviewed AWS principal"
                );
                let material = if session_token.is_empty() {
                    access_key
                } else {
                    format!("{access_key}|{session_token}")
                };
                cloud::aws_key_material(&material)?;
                material
            }
            _ => anyhow::bail!("Cloud scope required"),
        };
        let resource_digest = scope.resource_digest()?;
        let reference = store.save_scoped(
            &resource_digest,
            CredentialPurpose::Read,
            SecretCredential {
                username: principal,
                password,
                domain,
            },
        )?;
        let credential = CredentialScope {
            reference: reference.id,
            purpose: reference.purpose,
            generation: reference.generation,
            principal: reference.principal,
            context: reference.context,
            context_digest: reference.scope_digest,
        };
        let mut updated = scope.clone();
        match &mut updated {
            BoundScope::AzureVm {
                credential: slot, ..
            }
            | BoundScope::AwsEc2 {
                credential: slot, ..
            } => *slot = Some(credential),
            _ => unreachable!("validated cloud scope"),
        }
        updated.validate()?;
        self.clear_cloud_draft();
        Ok(updated)
    }

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
            if scope.target().is_some() {
                ui.label(profile_review_status(scope, profiles));
            }
            if ui.button("Remove reviewed scope").clicked() {
                let mut scopes = case.scopes().to_vec();
                scopes.remove(index);
                state.revise(CaseEdit::Scopes(scopes));
            }
        });
        ui.push_id(("reviewed-scope", index), |ui| {
            ui.collapsing("Inspect exact reviewed identity", |ui| {
                for line in review_details(scope) {
                    ui.monospace(line);
                }
            });
            if matches!(
                scope,
                BoundScope::AzureVm { .. } | BoundScope::AwsEc2 { .. }
            ) && ui
                .button("Set up or rotate protected cloud read credential")
                .clicked()
            {
                if state.scope_editor.prepare_cloud(case.id(), scope).is_err() {
                    state.notice = "Cloud scope unavailable".into();
                }
            }
        });
    }
    if let Some(index) = case.scopes().iter().position(|scope| {
        state.scope_editor.cloud_case == Some(case.id())
            && scope.digest().ok().as_deref() == Some(&state.scope_editor.cloud_scope_digest)
    }) {
        let is_aws = matches!(case.scopes()[index], BoundScope::AwsEc2 { .. });
        ui.group(|ui| {
            ui.label("Protected read credential for this exact reviewed cloud resource");
            field(
                ui,
                if is_aws {
                    "Exact STS principal ARN"
                } else {
                    "Token principal ID or name"
                },
                &mut state.scope_editor.cloud_principal,
            );
            ui.horizontal(|ui| {
                ui.label(if is_aws {
                    "Secret access key"
                } else {
                    "ARM bearer token"
                });
                ui.add(
                    egui::TextEdit::singleline(&mut state.scope_editor.cloud_secret).password(true),
                );
            });
            if is_aws {
                ui.horizontal(|ui| {
                    ui.label("Access key ID");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.scope_editor.cloud_access_key)
                            .password(true),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Session token (optional)");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.scope_editor.cloud_session_token)
                            .password(true),
                    );
                });
            }
            if ui
                .button("Protect credential and update reviewed scope")
                .clicked()
            {
                let result = PersistentCredentialStore::new().and_then(|mut store| {
                    state
                        .scope_editor
                        .provision_cloud(case.id(), &case.scopes()[index], &mut store)
                });
                match result {
                    Ok(updated) => {
                        let mut scopes = case.scopes().to_vec();
                        scopes[index] = updated;
                        state.revise(CaseEdit::Scopes(scopes));
                        if state.notice.starts_with("Answer recorded") {
                            state.save();
                            if state.notice == "Case workspace saved securely" {
                                state.notice =
                                    "Protected cloud credential and reviewed scope saved".into();
                            } else {
                                state.notice = "Cloud credential protected, but case save failed; retry saving the case".into();
                            }
                        }
                    }
                    Err(_) => {
                        state.scope_editor.clear_cloud_draft();
                        state.notice =
                            "Cloud credential could not be protected for this scope".into();
                    }
                }
            }
            if ui.button("Cancel credential entry").clicked() {
                state.scope_editor.clear_cloud_draft();
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
        review_from_editor(state, case, profiles);
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

fn review_details(scope: &BoundScope) -> Vec<String> {
    let mut details = vec![format!("Scope: {}", scope_kind(scope))];
    if let Some(target) = scope.target() {
        details.extend([
            format!("Saved profile ID: {}", target.profile_id),
            format!("Display name: {} (not identity)", target.name),
            format!("Endpoint: {}:{}", target.host, target.port),
            format!("Protocol: {}", target.protocol),
            format!("Login: {}", target.username),
            format!("Domain: {}", target.domain),
            format!(
                "Route: {}",
                if target.route.is_empty() {
                    "<direct>"
                } else {
                    &target.route
                }
            ),
        ]);
    }
    match scope {
        BoundScope::Database {
            engine,
            port,
            database,
            schema,
            object,
            ..
        } => details.extend([
            format!("Database engine: {engine:?}"),
            format!("Database port: {port}"),
            format!("Database: {database}"),
            format!("Schema: {}", schema.as_deref().unwrap_or("<none>")),
            format!("Object: {}", object.as_deref().unwrap_or("<none>")),
        ]),
        BoundScope::Http {
            port, tls, path, ..
        } => details.extend([
            format!("HTTP port: {port}"),
            format!("TLS: {tls}"),
            format!("Path: {path}"),
        ]),
        BoundScope::Docker {
            daemon_context,
            container_id,
            ..
        } => details.extend([
            format!("Daemon context: {daemon_context}"),
            format!("Container ID: {container_id}"),
        ]),
        BoundScope::Kubernetes {
            context,
            cluster_fingerprint,
            namespace,
            resource_kind,
            resource_name,
            ..
        } => details.extend([
            format!("Kubernetes context: {context}"),
            format!("Cluster fingerprint: {cluster_fingerprint}"),
            format!("Namespace: {namespace}"),
            format!("Resource kind: {resource_kind}"),
            format!("Resource name: {resource_name}"),
        ]),
        BoundScope::AzureVm {
            tenant,
            subscription,
            resource_id,
            ..
        } => details.extend([
            format!("Tenant: {tenant}"),
            format!("Subscription: {subscription}"),
            format!("Resource ID: {resource_id}"),
        ]),
        BoundScope::AwsEc2 {
            account,
            region,
            instance_id,
            ..
        } => details.extend([
            format!("Account: {account}"),
            format!("Region: {region}"),
            format!("Instance ID: {instance_id}"),
        ]),
        BoundScope::Windows { .. } | BoundScope::Linux { .. } => {}
    }
    if let Some(credential) = scope.credential() {
        details.extend([
            format!("Credential reference: {}", credential.reference),
            format!("Credential purpose: {:?}", credential.purpose),
            format!("Credential generation: {}", credential.generation),
            format!("Credential principal: {}", credential.principal),
            format!("Credential context: {}", credential.context),
            format!("Credential resource digest: {}", credential.context_digest),
        ]);
    } else if !matches!(scope, BoundScope::Http { .. }) {
        details.push("Credential reference: <none>".into());
    }
    details
}

fn profile_review_status(scope: &BoundScope, profiles: &[ConnectionProfile]) -> &'static str {
    match scope
        .target()
        .and_then(|t| profiles.iter().find(|p| p.id == t.profile_id))
    {
        Some(profile) if scope.matches_profile(profile) => "Exact profile bound",
        _ => "Profile changed or missing · review again",
    }
}

fn review_from_editor(state: &mut HelperState, case: &HelperCase, profiles: &[ConnectionProfile]) {
    match state.scope_editor.build(profiles) {
        Ok(scope) => {
            let mut scopes = case.scopes().to_vec();
            scopes.push(scope);
            state.revise(CaseEdit::Scopes(scopes));
        }
        Err(error) => state.notice = format!("Scope review failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::credentials::{PersistentSecretResolver, SecretResolver};
    use base64::Engine;

    #[test]
    fn azure_token_provisioning_is_bound_to_reviewed_vm_and_protected_vault() {
        let dir = std::env::temp_dir().join(format!("relayne-azure-authoring-{}", Uuid::new_v4()));
        let tenant = Uuid::new_v4().to_string();
        let subscription = Uuid::new_v4().to_string();
        let resource_id = format!(
            "/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
        );
        let scope = BoundScope::AzureVm {
            tenant: tenant.clone(),
            subscription,
            resource_id,
            credential: None,
        };
        let payload = serde_json::json!({"tid":tenant,"aud":"https://management.azure.com/","oid":"reviewed-principal","exp":chrono::Utc::now().timestamp()+600});
        let token = format!(
            "e30.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let mut editor = Editor::default();
        let case_id = Uuid::new_v4();
        editor.prepare_cloud(case_id, &scope).unwrap();
        editor.cloud_principal = "reviewed-principal".into();
        editor.cloud_secret = token.clone();
        let mut vault = PersistentCredentialStore::at(dir.join("credentials.json")).unwrap();
        let updated = editor.provision_cloud(case_id, &scope, &mut vault).unwrap();
        let resolver = PersistentSecretResolver::at(dir.join("credentials.scoped.dpapi"));
        assert!(super::super::connectors_ui::collect_enabled(
            &updated,
            &[],
            Some(&resolver)
        ));
        assert_eq!(
            resolver
                .resolve(updated.credential().unwrap(), CredentialPurpose::Read)
                .unwrap()
                .password(),
            token
        );
        assert!(editor.cloud_secret.is_empty());
        let bytes = std::fs::read(dir.join("credentials.scoped.dpapi")).unwrap();
        assert!(
            !bytes
                .windows(token.len())
                .any(|part| part == token.as_bytes())
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protected_cloud_provisioning_and_rotation_enable_only_current_vault_reference() {
        let dir = std::env::temp_dir().join(format!("relayne-cloud-authoring-{}", Uuid::new_v4()));
        let mut state = HelperState::at_path(dir.join("cases.dpapi"));
        state.create();
        let case_id = state.current().unwrap().id();
        let scope = BoundScope::AwsEc2 {
            account: "123456789012".into(),
            region: "eu-central-1".into(),
            instance_id: "i-0123456789abcdef0".into(),
            credential: None,
        };
        state.revise(CaseEdit::Scopes(vec![scope.clone()]));
        state.save();
        let mut vault = PersistentCredentialStore::at(dir.join("credentials.json")).unwrap();
        let resolver = PersistentSecretResolver::at(dir.join("credentials.scoped.dpapi"));
        assert!(!super::super::connectors_ui::collect_enabled(
            &scope,
            &[],
            Some(&resolver)
        ));
        let mut metadata_only = scope.clone();
        let digest = scope.resource_digest().unwrap();
        if let BoundScope::AwsEc2 { credential, .. } = &mut metadata_only {
            *credential = Some(CredentialScope {
                reference: Uuid::new_v4(),
                purpose: CredentialPurpose::Read,
                generation: 1,
                principal: "arn:aws:iam::123456789012:user/read".into(),
                context: digest.clone(),
                context_digest: digest,
            });
        }
        metadata_only.validate().unwrap();
        assert!(!super::super::connectors_ui::collect_enabled(
            &metadata_only,
            &[],
            Some(&resolver)
        ));
        state.scope_editor.prepare_cloud(case_id, &scope).unwrap();
        state.scope_editor.cloud_principal = "arn:aws:iam::123456789012:user/read".into();
        state.scope_editor.cloud_access_key = "AKIA1234567890123456".into();
        state.scope_editor.cloud_secret = "secret-sentinel-1".into();
        let first = state
            .scope_editor
            .provision_cloud(case_id, &scope, &mut vault)
            .unwrap();
        let first_ref = first.credential().unwrap().clone();
        assert!(state.scope_editor.cloud_secret.is_empty());
        assert!(
            resolver
                .resolve(&first_ref, CredentialPurpose::Read)
                .is_ok()
        );
        assert!(super::super::connectors_ui::collect_enabled(
            &first,
            &[],
            Some(&resolver)
        ));
        assert!(!super::super::connectors_ui::collect_enabled(
            &first,
            &[],
            None
        ));
        let missing = PersistentSecretResolver::at(dir.join("missing.scoped.dpapi"));
        assert!(!super::super::connectors_ui::collect_enabled(
            &first,
            &[],
            Some(&missing)
        ));
        state.scope_editor.prepare_cloud(case_id, &first).unwrap();
        state.scope_editor.cloud_access_key = "AKIA1234567890123456".into();
        state.scope_editor.cloud_secret = "secret-sentinel-2".into();
        let second = state
            .scope_editor
            .provision_cloud(case_id, &first, &mut vault)
            .unwrap();
        assert_eq!(
            second.credential().unwrap().generation,
            first_ref.generation + 1
        );
        assert!(
            resolver
                .resolve(&first_ref, CredentialPurpose::Read)
                .is_err()
        );
        assert_eq!(
            resolver
                .resolve(second.credential().unwrap(), CredentialPurpose::Read)
                .unwrap()
                .password(),
            "secret-sentinel-2"
        );
        state.revise(CaseEdit::Scopes(vec![second]));
        assert!(state.notice.starts_with("Answer recorded"));
        state.save();
        let reloaded = crate::helper::store::HelperStore::load(&dir.join("cases.dpapi")).unwrap();
        assert_eq!(
            reloaded.case(case_id).unwrap().scopes()[0]
                .credential()
                .unwrap()
                .generation,
            first_ref.generation + 1
        );
        let stored = std::fs::read(dir.join("cases.dpapi")).unwrap();
        assert!(
            !stored
                .windows("secret-sentinel".len())
                .any(|part| part == b"secret-sentinel")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn all_editor_variants_are_reviewable_inspectable_persisted_and_inert() {
        let ctx = egui::Context::default();
        let mut app = AivanaApp::from_context(&ctx);
        let dir = std::env::temp_dir().join(format!("relayne-scope-editor-{}", Uuid::new_v4()));
        app.helper = HelperState::at_path(dir.join("cases.dpapi"));
        app.helper.create();
        let mut rdp = ConnectionProfile::sample("RDP", "rdp.local", "", false);
        rdp.options.gateway.enabled = true;
        rdp.options.gateway.host = "gateway.example".into();
        rdp.options.gateway.port = 444;
        let mut ssh = ConnectionProfile::sample("SSH", "ssh.local", "", false);
        ssh.protocol = crate::models::Protocol::Ssh;
        ssh.port = 22;
        app.profiles.extend([rdp.clone(), ssh.clone()]);
        app.helper.revise(CaseEdit::Profiles(vec![rdp.id, ssh.id]));
        let subscription = Uuid::new_v4().to_string();
        let mut scopes = Vec::new();
        for kind in 0..8 {
            let mut editor = Editor {
                kind,
                profile: Some(if kind == 1 { ssh.id } else { rdp.id }),
                port: "5432".into(),
                database: "CaseDB".into(),
                schema: "Public".into(),
                object: "Orders".into(),
                tls: true,
                path: "/Health".into(),
                daemon_context: "daemon-A".into(),
                container_id: "Container-A".into(),
                context: "cluster-A".into(),
                cluster_fingerprint: "fingerprint-A".into(),
                namespace: "NS-A".into(),
                resource_kind: "Deployment".into(),
                resource_name: "API-A".into(),
                tenant: Uuid::new_v4().to_string(),
                subscription: subscription.clone(),
                resource_id: format!(
                    "/subscriptions/{subscription}/resourceGroups/Group-A/providers/Microsoft.Compute/virtualMachines/VM-A"
                ),
                account: "123456789012".into(),
                region: "us-gov-west-1".into(),
                instance_id: "i-12345678".into(),
                credential_ref: Uuid::new_v4().to_string(),
                credential_purpose: 1,
                credential_generation: "7".into(),
                credential_principal: "principal-A".into(),
                credential_context: "tenant-A".into(),
                ..Default::default()
            };
            if kind == 3 {
                editor.credential_ref.clear();
            }
            let scope = editor.build(&app.profiles).unwrap();
            let details = review_details(&scope).join("\n");
            if kind != 3 {
                for expected in [
                    format!("Credential reference: {}", editor.credential_ref),
                    "Credential purpose: Diagnose".into(),
                    "Credential generation: 7".into(),
                    "Credential principal: principal-A".into(),
                    "Credential context: tenant-A".into(),
                ] {
                    assert!(
                        details.contains(&expected),
                        "kind {kind} missing {expected}"
                    );
                }
            }
            if kind <= 3 {
                assert!(details.contains("Saved profile ID:"));
                assert!(details.contains("Endpoint:"));
                assert!(details.contains(if kind == 1 {
                    "Route: <direct>"
                } else {
                    "Route: gateway.example:444"
                }));
                assert_eq!(
                    profile_review_status(&scope, &app.profiles),
                    "Exact profile bound"
                );
                let mut drifted = app.profiles.clone();
                let profile = drifted
                    .iter_mut()
                    .find(|p| p.id == scope.target().unwrap().profile_id)
                    .unwrap();
                profile.host.push_str("-changed");
                assert_eq!(
                    profile_review_status(&scope, &drifted),
                    "Profile changed or missing · review again"
                );
            }
            for expected in match kind {
                0 => vec!["rdp.local", "RDP", "principal-A", "generation: 7"],
                1 => vec!["ssh.local", "SSH", "principal-A", "generation: 7"],
                2 => vec!["CaseDB", "Public", "Orders", "5432"],
                3 => vec!["/Health", "TLS", "5432"],
                4 => vec!["daemon-A", "Container-A"],
                5 => vec!["cluster-A", "fingerprint-A", "NS-A", "API-A"],
                6 => vec!["Group-A", "VM-A", &subscription],
                _ => vec!["123456789012", "us-gov-west-1", "i-12345678"],
            } {
                assert!(details.contains(expected), "kind {kind} missing {expected}");
            }
            scopes.push(scope);
        }
        let mut invalid = Editor {
            kind: 7,
            account: "123456789012".into(),
            region: "---".into(),
            instance_id: "i-12345678".into(),
            ..Default::default()
        };
        assert!(invalid.build(&app.profiles).is_err());
        invalid.region = "eu-central-1".into();
        assert!(invalid.build(&app.profiles).is_ok());
        invalid.region = "---".into();
        app.helper.scope_editor = invalid;
        let case = app.helper.current().unwrap().clone();
        review_from_editor(&mut app.helper, &case, &app.profiles);
        assert!(app.helper.notice.starts_with("Scope review failed:"));
        assert!(app.helper.current().unwrap().scopes().is_empty());
        app.helper.revise(CaseEdit::Scopes(scopes));
        app.helper.save();
        app.helper.reload();
        assert_eq!(app.helper.current().unwrap().scopes().len(), 8);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.helper_view(ui));
        });
        app.poll_helper();
        assert!(app.operations.queue.jobs.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
