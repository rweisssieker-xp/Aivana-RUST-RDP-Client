use super::*;

#[test]
fn http_scope_rejects_reinterpreted_authority_and_preserves_ipv6_idna() {
    let mut endpoint = target("RDP");
    endpoint.route.clear();
    for host in [
        "good.example@bad.example",
        "good.example:81",
        "good.example/path",
        "good.example#evil",
        "0x7f000001",
    ] {
        endpoint.host = host.into();
        let scope = BoundScope::Http {
            target: endpoint.clone(),
            port: 8443,
            tls: true,
            path: "/health".into(),
        };
        assert!(scope.validate().is_err(), "accepted {host}");
    }
    endpoint.host = "::1".into();
    let ipv6 = reviewed_http_url(&endpoint, 8443, true, "/health").unwrap();
    assert_eq!(ipv6.host_str().unwrap().trim_matches(['[', ']']), "::1");
    assert_eq!(ipv6.port_or_known_default(), Some(8443));
    endpoint.host = "bücher.example".into();
    let idna = reviewed_http_url(&endpoint, 8443, true, "/health").unwrap();
    assert_eq!(idna.host_str(), Some("xn--bcher-kva.example"));
    endpoint.route = "proxy:443".into();
    assert!(reviewed_http_url(&endpoint, 8443, true, "/health").is_ok());
    endpoint.route.clear();
    let with_query = reviewed_http_url(&endpoint, 8443, true, "/health?next=ok%20value").unwrap();
    assert_eq!(with_query.path(), "/health");
    assert_eq!(with_query.query(), Some("next=ok%20value"));
    for path in ["/health#fragment", "/foo/../bar"] {
        assert!(reviewed_http_url(&endpoint, 8443, true, path).is_err());
    }
}
use crate::helper::case::{CaseEdit, HelperCase, ProblemIntake};

fn target(protocol: &str) -> Target {
    Target {
        profile_id: Uuid::new_v4(),
        name: "Display".into(),
        host: "host".into(),
        port: 3389,
        protocol: protocol.into(),
        username: "operator".into(),
        domain: "realm".into(),
        route: "gateway:443".into(),
    }
}
fn cred() -> CredentialScope {
    CredentialScope {
        reference: Uuid::new_v4(),
        purpose: CredentialPurpose::Read,
        generation: 1,
        principal: "alice".into(),
        context: "host".into(),
        context_digest: String::new(),
    }
}

#[test]
#[cfg(windows)]
fn winrm_review_binds_separate_wsman_port_and_current_identity() {
    let mut direct = target("RDP");
    direct.route.clear();
    let scope = BoundScope::WindowsWinRm {
        target: direct,
        winrm_port: 5985,
        identity: current_windows_identity().unwrap(),
        credential: None,
    };
    scope.validate().unwrap();
    let digest = scope.digest().unwrap();
    let other = BoundScope::WindowsWinRm {
        target: scope.target().unwrap().clone(),
        winrm_port: 5986,
        identity: current_windows_identity().unwrap(),
        credential: None,
    };
    assert_ne!(digest, other.digest().unwrap());
    let changed_identity = BoundScope::WindowsWinRm {
        target: scope.target().unwrap().clone(),
        winrm_port: 5985,
        identity: "OTHER\\operator".into(),
        credential: None,
    };
    assert_ne!(digest, changed_identity.digest().unwrap());
    assert!(
        BoundScope::WindowsWinRm {
            target: scope.target().unwrap().clone(),
            winrm_port: 3389,
            identity: current_windows_identity().unwrap(),
            credential: None
        }
        .validate()
        .is_err()
    );
    assert!(
        BoundScope::WindowsWinRm {
            target: scope.target().unwrap().clone(),
            winrm_port: 5985,
            identity: current_windows_identity().unwrap(),
            credential: Some(cred())
        }
        .bind_credential_context()
        .is_err()
    );
}

#[test]
fn digest_binds_exact_identity_and_credential_metadata() {
    let scope = BoundScope::Database {
        target: target("RDP"),
        engine: DatabaseEngine::Postgres,
        port: 5432,
        database: "Sales".into(),
        schema: Some("Public".into()),
        object: Some("Orders".into()),
        credential: Some(cred()),
    }
    .bind_credential_context()
    .unwrap();
    let base = scope.digest().unwrap();
    let resource = scope.resource_digest().unwrap();
    let mut value = serde_json::to_value(&scope).unwrap();
    let edits = [
        ("target.profile_id", serde_json::json!(Uuid::new_v4())),
        ("target.host", serde_json::json!("other")),
        ("target.port", serde_json::json!(3390)),
        ("target.protocol", serde_json::json!("SSH")),
        ("target.username", serde_json::json!("bob")),
        ("target.domain", serde_json::json!("other")),
        ("target.route", serde_json::json!("other:443")),
        ("engine", serde_json::json!("sql_server")),
        ("port", serde_json::json!(1433)),
        ("database", serde_json::json!("sales")),
        ("schema", serde_json::json!("public")),
        ("object", serde_json::json!("orders")),
        ("credential.reference", serde_json::json!(Uuid::new_v4())),
        ("credential.purpose", serde_json::json!("diagnose")),
        ("credential.generation", serde_json::json!(2)),
        ("credential.principal", serde_json::json!("bob")),
        ("credential.context", serde_json::json!("other")),
    ];
    for (path, replacement) in edits {
        let mut changed = value.clone();
        let mut node = &mut changed;
        let parts: Vec<_> = path.split('.').collect();
        for key in &parts[..parts.len() - 1] {
            node = node.get_mut(*key).unwrap();
        }
        node[parts[parts.len() - 1]] = replacement;
        let altered: BoundScope = serde_json::from_value(changed).unwrap();
        if path.starts_with("credential.") {
            assert_ne!(altered.digest().unwrap(), base, "{path}");
            assert_eq!(altered.resource_digest().unwrap(), resource, "{path}");
        } else {
            assert!(
                altered.digest().is_err(),
                "resource change must stale credential context: {path}"
            );
            assert_ne!(
                altered.unchecked_resource_digest().unwrap(),
                resource,
                "{path}"
            );
        }
    }
    value["target"]["name"] = serde_json::json!("Renamed");
    assert_eq!(
        serde_json::from_value::<BoundScope>(value)
            .unwrap()
            .digest()
            .unwrap(),
        base
    );
    let mut wrong_context = serde_json::to_value(&scope).unwrap();
    wrong_context["credential"]["context_digest"] = serde_json::json!("0".repeat(64));
    assert!(
        serde_json::from_value::<BoundScope>(wrong_context)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn scope_variants_validate_and_bind_without_port_inference() {
    let db = BoundScope::Database {
        target: target("RDP"),
        engine: DatabaseEngine::SqlServer,
        port: 5432,
        database: "DB".into(),
        schema: None,
        object: None,
        credential: None,
    };
    assert!(db.validate().is_ok()); // Port 5432 does not turn SQL Server into PostgreSQL.
    assert!(matches!(
        db,
        BoundScope::Database {
            engine: DatabaseEngine::SqlServer,
            ..
        }
    ));
    assert!(
        BoundScope::Windows {
            target: target("SSH"),
            credential: None
        }
        .validate()
        .is_err()
    );
    assert!(
        BoundScope::Linux {
            target: target("RDP"),
            credential: None
        }
        .validate()
        .is_err()
    );
    assert!(
        BoundScope::AwsEc2 {
            account: "bad".into(),
            region: "eu-central-1".into(),
            instance_id: "i-12345678".into(),
            credential: None
        }
        .validate()
        .is_err()
    );
    assert!(
        BoundScope::AzureVm {
            tenant: "bad".into(),
            subscription: Uuid::new_v4().to_string(),
            resource_id:
                "/subscriptions/x/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/v"
                    .into(),
            credential: None
        }
        .validate()
        .is_err()
    );
    for region in ["---", "us--1", "us-east-x", "x-east-1"] {
        assert!(
            BoundScope::AwsEc2 {
                account: "123456789012".into(),
                region: region.into(),
                instance_id: "i-12345678".into(),
                credential: None
            }
            .validate()
            .is_err(),
            "{region}"
        );
    }
    for region in [
        "eu-central-1",
        "us-gov-west-1",
        "us-iso-east-1",
        "us-isob-east-1",
        "eu-isoe-west-1",
    ] {
        assert!(
            BoundScope::AwsEc2 {
                account: "123456789012".into(),
                region: region.into(),
                instance_id: "i-12345678".into(),
                credential: None
            }
            .validate()
            .is_ok(),
            "{region}"
        );
    }
}

#[test]
fn reviewed_scope_is_revisioned_and_requires_selected_profile() {
    let mut case = HelperCase::new(ProblemIntake::default()).unwrap();
    let scope = BoundScope::Windows {
        target: target("RDP"),
        credential: None,
    };
    assert!(review_scopes(&mut case, vec![scope.clone()]).is_err());
    assert_eq!(case.revision(), 1);
    case.revise(
        1,
        CaseEdit::Profiles(vec![scope.target().unwrap().profile_id]),
    )
    .unwrap();
    review_scopes(&mut case, vec![scope]).unwrap();
    assert_eq!(case.revision(), 3);
    assert!(case.revise(2, CaseEdit::Scopes(vec![])).is_err());
}

#[test]
fn inventory_requires_two_captures_and_exact_current_profiles() {
    use crate::{
        helper::inventory::{InventoryEntry, InventoryFreshness, derive_inventory},
        models::ConnectionProfile,
        telemetry::{Edge, Observation, Payload, Store},
    };
    let now = chrono::Utc::now();
    let source = ConnectionProfile::sample("source", "source.local", "", false);
    let destination = ConnectionProfile::sample("destination", "destination.local", "", false);
    let src = Target::from_profile(&source);
    let dst = Target::from_profile(&destination);
    let payload = |address: &str| Payload {
        machine: "host".into(),
        os_version: "Windows".into(),
        observed_at: now.to_rfc3339(),
        addresses: vec![address.into()],
        services: vec![],
        sockets: vec![],
        events: vec![],
        events_available: true,
        truncated: false,
    };
    let a = Observation {
        id: Uuid::new_v4(),
        target: src.clone(),
        received: now,
        payload: payload("10.0.0.1"),
    };
    let b = Observation {
        id: Uuid::new_v4(),
        target: dst.clone(),
        received: now,
        payload: payload("10.0.0.2"),
    };
    let edge = Edge {
        source: src,
        destination: dst,
        address: "10.0.0.2".into(),
        port: 5432,
        services: vec![],
        evidence: vec![a.id, b.id],
        observed: now,
    };
    let mut telemetry = Store::default();
    telemetry.observations.push(a);
    telemetry.edges.push(edge);
    let read = |profiles: &[ConnectionProfile], store: &Store| {
        derive_inventory(profiles, store, now)
            .into_iter()
            .find_map(|entry| match entry {
                InventoryEntry::InferredNetwork {
                    freshness,
                    profile_drift,
                    ..
                } => Some((freshness, profile_drift)),
                _ => None,
            })
            .unwrap()
    };
    assert_eq!(
        read(&[source.clone(), destination.clone()], &telemetry),
        (InventoryFreshness::Unknown, false)
    );
    telemetry.observations.push(b);
    assert_eq!(
        read(&[source.clone(), destination.clone()], &telemetry),
        (InventoryFreshness::Recent, false)
    );
    // A newer complete capture must not hide a partial capture referenced by this edge.
    telemetry.observations[0].payload.truncated = true;
    telemetry.observations.push(Observation {
        id: Uuid::new_v4(),
        target: telemetry.observations[0].target.clone(),
        received: now,
        payload: payload("10.0.0.1"),
    });
    assert_eq!(
        read(&[source.clone(), destination.clone()], &telemetry),
        (InventoryFreshness::Unknown, false)
    );
    telemetry.observations[0].payload.truncated = false;
    telemetry.observations[1].payload.events_available = false;
    assert_eq!(
        read(&[source.clone(), destination.clone()], &telemetry),
        (InventoryFreshness::Unknown, false)
    );
    telemetry.observations[1].payload.events_available = true;
    let mut changed = destination.clone();
    changed.host = "replacement.local".into();
    assert_eq!(
        read(&[source, changed], &telemetry),
        (InventoryFreshness::Unknown, true)
    );
}

#[test]
fn all_variant_resource_fields_change_digest() {
    let tenant = Uuid::new_v4().to_string();
    let subscription = Uuid::new_v4().to_string();
    let cases: Vec<(BoundScope, Vec<(&str, serde_json::Value)>)> = vec![
        (
            BoundScope::Windows {
                target: target("RDP"),
                credential: Some(cred()),
            },
            vec![
                ("target.profile_id", serde_json::json!(Uuid::new_v4())),
                ("target.host", serde_json::json!("other")),
                ("target.port", serde_json::json!(3390)),
                ("target.username", serde_json::json!("other-user")),
                ("target.domain", serde_json::json!("other-domain")),
                ("target.route", serde_json::json!("other-gateway:443")),
            ],
        ),
        (
            BoundScope::Linux {
                target: target("SSH"),
                credential: Some(cred()),
            },
            vec![
                ("target.profile_id", serde_json::json!(Uuid::new_v4())),
                ("target.host", serde_json::json!("other")),
                ("target.port", serde_json::json!(23)),
                ("target.username", serde_json::json!("other-user")),
                ("target.domain", serde_json::json!("other-domain")),
                ("target.route", serde_json::json!("other-gateway:443")),
            ],
        ),
        (
            BoundScope::Http {
                target: target("RDP"),
                port: 443,
                tls: true,
                path: "/Health".into(),
            },
            vec![
                ("target.profile_id", serde_json::json!(Uuid::new_v4())),
                ("target.host", serde_json::json!("other")),
                ("target.port", serde_json::json!(3390)),
                ("target.protocol", serde_json::json!("SSH")),
                ("target.username", serde_json::json!("other-user")),
                ("target.domain", serde_json::json!("other-domain")),
                ("target.route", serde_json::json!("other-gateway:443")),
                ("port", serde_json::json!(8443)),
                ("tls", serde_json::json!(false)),
                ("path", serde_json::json!("/health")),
            ],
        ),
        (
            BoundScope::Docker {
                daemon_context: "prod".into(),
                container_id: "ABC".into(),
                credential: Some(cred()),
            },
            vec![
                ("daemon_context", serde_json::json!("test")),
                ("container_id", serde_json::json!("abc")),
            ],
        ),
        (
            BoundScope::Kubernetes {
                context: "prod".into(),
                cluster_fingerprint: "fingerprint".into(),
                namespace: "NS".into(),
                resource_kind: "Deployment".into(),
                resource_name: "API".into(),
                credential: Some(cred()),
            },
            vec![
                ("context", serde_json::json!("test")),
                ("cluster_fingerprint", serde_json::json!("other")),
                ("namespace", serde_json::json!("ns")),
                ("resource_kind", serde_json::json!("Pod")),
                ("resource_name", serde_json::json!("api")),
            ],
        ),
        (
            BoundScope::AzureVm {
                tenant: tenant.clone(),
                subscription: subscription.clone(),
                resource_id: format!(
                    "/subscriptions/{subscription}/resourceGroups/Group/providers/Microsoft.Compute/virtualMachines/VM"
                ),
                credential: Some(cred()),
            },
            vec![
                ("tenant", serde_json::json!(Uuid::new_v4().to_string())),
                (
                    "resource_id",
                    serde_json::json!(format!(
                        "/subscriptions/{subscription}/resourceGroups/Group/providers/Microsoft.Compute/virtualMachines/vm"
                    )),
                ),
            ],
        ),
        (
            BoundScope::AwsEc2 {
                account: "123456789012".into(),
                region: "eu-central-1".into(),
                instance_id: "i-12345678".into(),
                credential: Some(cred()),
            },
            vec![
                ("account", serde_json::json!("123456789013")),
                ("region", serde_json::json!("eu-west-1")),
                ("instance_id", serde_json::json!("i-12345679")),
            ],
        ),
    ];
    for (scope, edits) in cases {
        let scope = scope.bind_credential_context().unwrap();
        let digest = scope.digest().unwrap();
        let resource_digest = scope.resource_digest().unwrap();
        for (path, replacement) in edits {
            let mut value = serde_json::to_value(&scope).unwrap();
            let mut node = &mut value;
            let parts: Vec<_> = path.split('.').collect();
            for key in &parts[..parts.len() - 1] {
                node = node.get_mut(*key).unwrap();
            }
            node[parts[parts.len() - 1]] = replacement;
            let altered: BoundScope = serde_json::from_value(value).unwrap();
            if altered.credential().is_some() && !path.starts_with("credential.") {
                assert!(
                    altered.digest().is_err(),
                    "resource edit must stale credential context: {path}"
                );
                let rebound = altered.bind_credential_context().unwrap();
                assert_ne!(
                    rebound.resource_digest().unwrap(),
                    resource_digest,
                    "{path}"
                );
                assert_ne!(rebound.digest().unwrap(), digest, "{path}");
            } else if path.starts_with("credential.") {
                assert_eq!(
                    altered.resource_digest().unwrap(),
                    resource_digest,
                    "{path}"
                );
                assert_ne!(altered.digest().unwrap(), digest, "{path}");
            } else {
                assert_ne!(
                    altered.resource_digest().unwrap(),
                    resource_digest,
                    "{path}"
                );
                assert_ne!(altered.digest().unwrap(), digest, "{path}");
            }
        }
        if scope.credential().is_some() {
            for (field, replacement) in [
                ("reference", serde_json::json!(Uuid::new_v4())),
                ("purpose", serde_json::json!("controlled_change")),
                ("generation", serde_json::json!(17)),
                ("principal", serde_json::json!("other-principal")),
                ("context", serde_json::json!("other-context")),
            ] {
                let mut value = serde_json::to_value(&scope).unwrap();
                value["credential"][field] = replacement;
                let altered: BoundScope = serde_json::from_value(value).unwrap();
                assert_eq!(
                    altered.resource_digest().unwrap(),
                    resource_digest,
                    "{field}"
                );
                assert_ne!(altered.digest().unwrap(), digest, "{field}");
            }
            let mut value = serde_json::to_value(&scope).unwrap();
            value["credential"] = serde_json::Value::Null;
            let without: BoundScope = serde_json::from_value(value).unwrap();
            assert_eq!(without.resource_digest().unwrap(), resource_digest);
            assert_ne!(without.digest().unwrap(), digest);
        }
    }
    let old = BoundScope::AzureVm {
        tenant,
        subscription: subscription.clone(),
        resource_id: format!(
            "/subscriptions/{subscription}/resourceGroups/Group/providers/Microsoft.Compute/virtualMachines/VM"
        ),
        credential: None,
    };
    let replacement_subscription = Uuid::new_v4().to_string();
    let changed = BoundScope::AzureVm {
        tenant: match &old {
            BoundScope::AzureVm { tenant, .. } => tenant.clone(),
            _ => unreachable!(),
        },
        subscription: replacement_subscription.clone(),
        resource_id: format!(
            "/subscriptions/{replacement_subscription}/resourceGroups/Group/providers/Microsoft.Compute/virtualMachines/VM"
        ),
        credential: None,
    };
    assert_ne!(
        old.resource_digest().unwrap(),
        changed.resource_digest().unwrap()
    );
}

#[test]
fn ambiguous_address_does_not_create_inferred_relationship() {
    use crate::telemetry::{Observation, Payload, Socket, discover};
    let now = chrono::Utc::now();
    let capture = |host: Target, address: &str, sockets: Vec<Socket>| Observation {
        id: Uuid::new_v4(),
        target: host,
        received: now,
        payload: Payload {
            machine: "host".into(),
            os_version: "Windows".into(),
            observed_at: now.to_rfc3339(),
            addresses: vec![address.into()],
            services: vec![],
            sockets,
            events: vec![],
            events_available: true,
            truncated: false,
        },
    };
    let outgoing = Socket {
        local: "10.0.0.1".into(),
        local_port: 49000,
        remote: "10.0.0.2".into(),
        remote_port: 5432,
        state: "Established".into(),
        pid: 1,
    };
    let captures = [
        capture(target("RDP"), "10.0.0.1", vec![outgoing]),
        capture(target("RDP"), "10.0.0.2", vec![]),
        capture(target("RDP"), "10.0.0.2", vec![]),
    ];
    assert!(discover(&captures).is_empty());
}

#[test]
fn persisted_scope_with_stale_credential_context_is_rejected_on_load() {
    let mut store = crate::helper::store::HelperStore::default();
    let id = store.create(ProblemIntake::default()).unwrap();
    let scoped = BoundScope::Windows {
        target: target("RDP"),
        credential: Some(cred()),
    }
    .bind_credential_context()
    .unwrap();
    store
        .revise(
            id,
            1,
            CaseEdit::Profiles(vec![scoped.target().unwrap().profile_id]),
        )
        .unwrap();
    store.revise(id, 2, CaseEdit::Scopes(vec![scoped])).unwrap();
    let mut value = serde_json::to_value(&store).unwrap();
    value["cases"][0]["scopes"][0]["target"]["host"] = serde_json::json!("replacement.local");
    let dir = std::env::temp_dir().join(format!("relayne-stale-scope-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cases.dpapi");
    let bytes = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, crate::security::protect_secret(&bytes).unwrap()).unwrap();
    assert!(crate::helper::store::HelperStore::load(&path).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
