use super::*;
use crate::{
    helper::{
        credentials::{PersistentSecretResolver, save_scoped_at},
        evidence::EvidenceBinding,
        scope::CredentialScope,
    },
    mission::Target,
    models::SecretCredential,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[test]
fn fixed_queries_are_bounded_and_current_database_scoped() {
    assert_eq!(SqlServerReadProbe::ALL.len(), 8);
    for probe in SqlServerReadProbe::ALL {
        let sql = probe.sql();
        assert!(!sql.contains("SELECT *"));
        if probe != SqlServerReadProbe::Identity {
            assert!(sql.contains("TOP ("));
        }
        if matches!(
            probe,
            SqlServerReadProbe::Requests | SqlServerReadProbe::Waits | SqlServerReadProbe::Blocking
        ) {
            assert!(sql.contains("DB_ID()"));
        }
        if probe.needs_object() {
            assert!(sql.contains("@P1") && sql.contains("@P2"));
        }
    }
    assert_eq!(template_digest().len(), 64);
    let permissions = SqlServerReadProbe::Permissions.sql();
    assert!(permissions.contains("QUOTENAME(@P1) + '.' + QUOTENAME(@P2)"));
    assert!(permissions.contains("HAS_PERMS_BY_NAME(QUOTENAME(@P1), 'SCHEMA'"));
    assert!(!permissions.contains("@P1 + '.' + @P2"));
    // Parameterized QUOTENAME covers valid names such as Order.Detail and end]bracket.
    assert!(!permissions.contains("Order.Detail") && !permissions.contains("end]bracket"));
}

#[test]
fn sql_server_tokens_do_not_masquerade_as_postgres_tokens() {
    assert!(SqlObservation::tds_state("suspended"));
    assert!(!SqlObservation::pg_state("suspended"));
    assert!(SqlObservation::version_token("16.0.1000.6"));
    assert!(!SqlObservation::version_token("PostgreSQL 16"));
    let identity = SqlObservation::SqlServerIdentity {
        database: "fixture".into(),
        principal: "reader".into(),
        effective_principal: "reader".into(),
        database_principal: "reader".into(),
        product_version: "16.0.1000.6".into(),
        server_ip: "127.0.0.1".into(),
        server_port: 1433,
        tls_required: true,
        server_state_access: Some(false),
        server_performance_access: None,
    };
    assert!(identity.bounded());
    for kind in [
        "CLUSTERED COLUMNSTORE",
        "NONCLUSTERED COLUMNSTORE",
        "NONCLUSTERED HASH",
    ] {
        let parsed = SqlServerIndexKind::from_type_desc(kind).unwrap();
        assert_eq!(parsed.label(), kind);
        assert!(
            SqlObservation::SqlServerIndex {
                name: "IX_fixture".into(),
                index_kind: parsed,
                enabled: true,
                usage_count: Some(3),
            }
            .bounded()
        );
        assert!(
            !SqlObservation::Index {
                name: "IX_fixture".into(),
                method: kind.into(),
                valid: true,
                scans: Some(3),
            }
            .bounded()
        );
    }
    assert!(SqlServerIndexKind::from_type_desc("FUTURE INDEX TYPE").is_none());
}

#[test]
fn denied_visibility_and_nulls_never_become_healthy() {
    assert_eq!(
        classify(
            SqlServerReadProbe::Requests,
            &[SqlObservation::SqlServerRequest {
                session_id: 42,
                state: None,
                wait_type: None,
                elapsed_ms: None
            }]
        ),
        ReadState::Unknown
    );
    assert_eq!(
        classify(
            SqlServerReadProbe::Permissions,
            &[SqlObservation::SqlServerPermission {
                database_connect: Some(false),
                schema_select: None,
                object_select: None,
                object_alter: None,
                object_control: None
            }]
        ),
        ReadState::Denied
    );
    assert_eq!(
        classify(SqlServerReadProbe::Objects, &[]),
        ReadState::Unknown
    );
    assert!(
        !SqlObservation::SqlServerRequest {
            session_id: 0,
            state: Some("running".into()),
            wait_type: None,
            elapsed_ms: Some(1),
        }
        .bounded()
    );
}

#[test]
fn identity_must_match_database_login_endpoint_and_tls() {
    let mut value = SqlObservation::SqlServerIdentity {
        database: "fixture".into(),
        principal: "reader".into(),
        effective_principal: "reader".into(),
        database_principal: "reader".into(),
        product_version: "16.0.1000.6".into(),
        server_ip: "127.0.0.1".into(),
        server_port: 1433,
        tls_required: true,
        server_state_access: Some(true),
        server_performance_access: None,
    };
    assert_eq!(
        verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.1", 1433).unwrap(),
        true
    );
    let mut switched_login = value.clone();
    if let SqlObservation::SqlServerIdentity {
        effective_principal,
        ..
    } = &mut switched_login
    {
        *effective_principal = "impersonated".into();
    }
    assert!(verify_identity(&[switched_login], "fixture", "reader", "127.0.0.1", 1433).is_err());
    let mut remapped_user = value.clone();
    if let SqlObservation::SqlServerIdentity {
        database_principal, ..
    } = &mut remapped_user
    {
        *database_principal = "dbo".into();
    }
    assert!(verify_identity(&[remapped_user], "fixture", "reader", "127.0.0.1", 1433).is_err());
    if let SqlObservation::SqlServerIdentity {
        server_state_access,
        ..
    } = &mut value
    {
        *server_state_access = Some(false);
    }
    assert!(!verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.1", 1433).unwrap());
    assert!(verify_identity(&[value.clone()], "other", "reader", "127.0.0.1", 1433).is_err());
    assert!(verify_identity(&[value.clone()], "fixture", "other", "127.0.0.1", 1433).is_err());
    assert!(verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.1", 1444).is_err());
    assert!(verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.2", 1433).is_err());
    if let SqlObservation::SqlServerIdentity { tls_required, .. } = &mut value {
        *tls_required = false;
    }
    assert!(verify_identity(&[value], "fixture", "reader", "127.0.0.1", 1433).is_err());
}

#[test]
fn cancellation_and_deadline_interrupt_stalled_tds_operations() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let canceled = CancellationToken::new();
        canceled.cancel();
        let stalled: TdsFuture<'_, ()> = Box::pin(std::future::pending());
        assert_eq!(
            gated(&canceled, Instant::now() + Duration::from_secs(1), stalled).await,
            Err(Failure::Canceled)
        );
        let stalled: TdsFuture<'_, ()> = Box::pin(std::future::pending());
        assert_eq!(
            gated(&CancellationToken::new(), Instant::now(), stalled).await,
            Err(Failure::TimedOut)
        );
    });
}

struct IdentityOnlyTransport {
    calls: Arc<Mutex<Vec<SqlServerReadProbe>>>,
    identity: SqlObservation,
    index_projection_error: bool,
}
struct IdentityOnlySession {
    calls: Arc<Mutex<Vec<SqlServerReadProbe>>>,
    identity: SqlObservation,
    index_projection_error: bool,
}
impl Transport for IdentityOnlyTransport {
    fn open<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
        _database: &'a str,
        principal: &'a str,
        password: &'a str,
    ) -> TdsFuture<'a, Box<dyn Session>> {
        Box::pin(async move {
            assert_eq!(principal, "reader");
            assert_eq!(password, "secret-marker");
            Ok(Box::new(IdentityOnlySession {
                calls: self.calls.clone(),
                identity: self.identity.clone(),
                index_projection_error: self.index_projection_error,
            }) as Box<dyn Session>)
        })
    }
}
impl Session for IdentityOnlySession {
    fn read<'a>(
        &'a mut self,
        probe: SqlServerReadProbe,
        _schema: &'a str,
        _object: &'a str,
    ) -> TdsFuture<'a, Vec<SqlObservation>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(probe);
            match probe {
                SqlServerReadProbe::Identity => Ok(vec![self.identity.clone()]),
                SqlServerReadProbe::Objects if self.index_projection_error => Ok(vec![
                    SqlObservation::SqlServerObject {
                        schema: "sales.eu".into(),
                        name: "Order.]Detail".into(),
                        object_id: 42,
                        column_count: 1,
                    },
                    SqlObservation::SqlServerColumn {
                        object_id: 42,
                        column_id: 1,
                        name: "Order]Id".into(),
                        plain: true,
                    },
                ]),
                SqlServerReadProbe::Indexes if self.index_projection_error => {
                    Err(Failure::InvalidProjection)
                }
                _ => Ok(Vec::new()),
            }
        })
    }
}
fn scoped_request() -> (ProbeRequest, PersistentSecretResolver, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("relayne-tds-test-{}.dpapi", Uuid::new_v4()));
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "fixture".into(),
        host: "localhost".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: "operator".into(),
        domain: String::new(),
        route: String::new(),
    };
    let mut scope = BoundScope::Database {
        target,
        engine: DatabaseEngine::SqlServer,
        port: 1433,
        database: "fixture".into(),
        schema: Some("sales.eu".into()),
        object: Some("Order.]Detail".into()),
        credential: None,
    };
    let resource = scope.resource_digest().unwrap();
    let reference = save_scoped_at(
        &path,
        &resource,
        CredentialPurpose::Read,
        SecretCredential {
            username: "reader".into(),
            password: "secret-marker".into(),
            domain: String::new(),
        },
    )
    .unwrap();
    let BoundScope::Database { credential, .. } = &mut scope else {
        unreachable!()
    };
    *credential = Some(CredentialScope {
        reference: reference.id,
        purpose: reference.purpose,
        generation: reference.generation,
        principal: reference.principal,
        context: reference.context,
        context_digest: reference.scope_digest,
    });
    scope.validate().unwrap();
    let request = ProbeRequest {
        binding: EvidenceBinding {
            case_id: Uuid::new_v4(),
            case_revision: 1,
            request_id: Uuid::new_v4(),
            scope_sha256: scope.digest().unwrap(),
            credential_scope_sha256: scope.credential_scope_digest().unwrap(),
            run_id: None,
        },
        scope,
        capability_id: CapabilityId::SqlRead,
        capability_version: 1,
        params: ProbeParams::SqlRead {
            query_digest: template_digest(),
        },
        requested_at: Utc::now(),
        deadline_secs: Some(5),
    };
    (request, PersistentSecretResolver::at(path.clone()), path)
}

#[test]
fn changed_effective_context_stops_before_any_followup() {
    let (request, secrets, path) = scoped_request();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = IdentityOnlyTransport {
        calls: calls.clone(),
        index_projection_error: false,
        identity: SqlObservation::SqlServerIdentity {
            database: "fixture".into(),
            principal: "reader".into(),
            effective_principal: "impersonated".into(),
            database_principal: "reader".into(),
            product_version: "16.0.1000.6".into(),
            server_ip: "127.0.0.1".into(),
            server_port: 1433,
            tls_required: true,
            server_state_access: Some(true),
            server_performance_access: None,
        },
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(collect_with(
        &transport,
        &request,
        &secrets,
        CancellationToken::new(),
    ));
    assert!(result.is_err());
    assert_eq!(*calls.lock().unwrap(), vec![SqlServerReadProbe::Identity]);
    let mut remapped = transport;
    if let SqlObservation::SqlServerIdentity {
        effective_principal,
        database_principal,
        ..
    } = &mut remapped.identity
    {
        *effective_principal = "reader".into();
        *database_principal = "dbo".into();
    }
    calls.lock().unwrap().clear();
    let result = runtime.block_on(collect_with(
        &remapped,
        &request,
        &secrets,
        CancellationToken::new(),
    ));
    assert!(result.is_err());
    assert_eq!(*calls.lock().unwrap(), vec![SqlServerReadProbe::Identity]);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unknown_index_projection_is_partial_and_later_probes_continue() {
    let (request, secrets, path) = scoped_request();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = IdentityOnlyTransport {
        calls: calls.clone(),
        index_projection_error: true,
        identity: SqlObservation::SqlServerIdentity {
            database: "fixture".into(),
            principal: "reader".into(),
            effective_principal: "reader".into(),
            database_principal: "reader".into(),
            product_version: "16.0.1000.6".into(),
            server_ip: "127.0.0.1".into(),
            server_port: 1433,
            tls_required: true,
            server_state_access: Some(true),
            server_performance_access: None,
        },
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let output = runtime
        .block_on(collect_with(
            &transport,
            &request,
            &secrets,
            CancellationToken::new(),
        ))
        .unwrap();
    assert_eq!(output.status, EvidenceStatus::Partial);
    assert!(
        calls
            .lock()
            .unwrap()
            .contains(&SqlServerReadProbe::Statistics)
    );
    let resource = request.scope.resource_digest().unwrap();
    assert_eq!(
        output
            .records
            .iter()
            .find(|r| r.subject_sha256
                == probe_subject_digest(&resource, SqlServerReadProbe::Indexes))
            .unwrap()
            .observation,
        Observation::Unknown
    );
    std::fs::remove_file(path).unwrap();
}
