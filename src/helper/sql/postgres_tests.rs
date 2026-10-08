use super::*;
use crate::{
    helper::{
        case::{CaseEdit, HelperCase, ProblemIntake},
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
fn fixed_queries_never_project_sql_text_and_bind_only_object_names() {
    assert_eq!(PgReadProbe::ALL.len(), 7);
    for probe in PgReadProbe::ALL {
        let sql = probe.sql().to_ascii_lowercase();
        assert!(sql.starts_with("select "));
        assert!(
            !sql.contains(".query") && !sql.contains("query_id") && !sql.contains("query_text")
        );
        assert!(!sql.contains("pg_stat_statements") && !sql.contains("pg_get_indexdef"));
        assert_eq!(sql.contains("$1"), probe.needs_object());
        assert_eq!(sql.contains("$2"), probe.needs_object());
        assert!(!sql.contains(";"));
    }
    assert!(PgReadProbe::Activity.sql().contains("LIMIT 21"));
    assert!(PgReadProbe::Blocking.sql().contains("LIMIT 21"));
    assert!(PgReadProbe::Indexes.sql().contains("LIMIT 21"));
    assert_eq!(template_digest().len(), 64);
}

struct FakeTransport {
    calls: Arc<Mutex<Vec<String>>>,
    database: String,
    server_port: u16,
    delay: Duration,
}
struct FakeSession {
    calls: Arc<Mutex<Vec<String>>>,
    database: String,
    server_port: u16,
    delay: Duration,
}
impl PgTransport for FakeTransport {
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        database: &'a str,
        principal: &'a str,
        password: &'a str,
    ) -> PgFuture<'a, Box<dyn PgSession>> {
        Box::pin(async move {
            assert_eq!(
                (host, port, database, principal, password),
                (
                    "localhost",
                    55433,
                    "relayne_helper_acceptance",
                    "reader",
                    "secret-marker"
                )
            );
            self.calls.lock().unwrap().push("open".into());
            Ok(Box::new(FakeSession {
                calls: self.calls.clone(),
                database: self.database.clone(),
                server_port: self.server_port,
                delay: self.delay,
            }) as Box<dyn PgSession>)
        })
    }
}
impl PgSession for FakeSession {
    fn begin<'a>(&'a mut self, timeout_ms: u64) -> PgFuture<'a, ()> {
        Box::pin(async move {
            assert!(timeout_ms > 0 && timeout_ms <= 30_000);
            self.calls.lock().unwrap().push("begin_read_only".into());
            Ok(())
        })
    }
    fn read<'a>(
        &'a mut self,
        probe: PgReadProbe,
        schema: &'a str,
        object: &'a str,
    ) -> PgFuture<'a, Vec<SqlObservation>> {
        Box::pin(async move {
            assert_eq!((schema, object), ("fixture", "orders"));
            self.calls.lock().unwrap().push(probe.label().into());
            if self.delay > Duration::ZERO {
                tokio::time::sleep(self.delay).await;
            }
            Ok(match probe {
                PgReadProbe::Identity => vec![SqlObservation::Identity {
                    database: self.database.clone(),
                    principal: "reader".into(),
                    version: 180000,
                    tls: true,
                    server_ip: "127.0.0.1".into(),
                    server_port: self.server_port,
                }],
                PgReadProbe::Objects => vec![SqlObservation::Object {
                    schema: "fixture".into(),
                    name: "orders".into(),
                    columns: 5,
                    estimated_rows: Some(12000.0),
                }],
                PgReadProbe::Statistics => vec![SqlObservation::Statistics {
                    live_rows: Some(12000),
                    dead_rows: Some(0),
                    analyze_count: Some(1),
                }],
                PgReadProbe::Permissions => vec![SqlObservation::Permission {
                    database_connect: Some(true),
                    schema_usage: Some(true),
                    table_select: Some(true),
                }],
                _ => Vec::new(),
            })
        })
    }
    fn rollback<'a>(&'a mut self) -> PgFuture<'a, ()> {
        Box::pin(async move {
            self.calls.lock().unwrap().push("rollback".into());
            Ok(())
        })
    }
    fn cancel<'a>(&'a mut self) -> PgFuture<'a, ()> {
        Box::pin(async move {
            self.calls.lock().unwrap().push("cancel".into());
            Ok(())
        })
    }
}

fn setup() -> (ProbeRequest, PersistentSecretResolver, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("relayne-pg-test-{}.dpapi", Uuid::new_v4()));
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
        engine: DatabaseEngine::Postgres,
        port: 55433,
        database: "relayne_helper_acceptance".into(),
        schema: Some("fixture".into()),
        object: Some("orders".into()),
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
    let credential = CredentialScope {
        reference: reference.id,
        purpose: reference.purpose,
        generation: reference.generation,
        principal: reference.principal,
        context: reference.context,
        context_digest: reference.scope_digest,
    };
    if let BoundScope::Database {
        credential: current,
        ..
    } = &mut scope
    {
        *current = Some(credential);
    }
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

#[tokio::test]
async fn native_adapter_orchestration_verifies_identity_and_rolls_back() {
    let (request, secrets, path) = setup();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        calls: calls.clone(),
        database: "relayne_helper_acceptance".into(),
        server_port: 55433,
        delay: Duration::ZERO,
    };
    let output = collect_with(&transport, &request, &secrets, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(output.status, EvidenceStatus::Complete);
    assert_eq!(output.coverage.observed, PROBE_COUNT);
    assert_eq!(output.records.len(), PROBE_COUNT as usize);
    assert_eq!(output.sql_observations.len(), 4);
    assert!(output.sql_observations.iter().any(|o| matches!(
        o,
        SqlObservation::Statistics {
            live_rows: Some(12000),
            ..
        }
    )));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [
            "open",
            "begin_read_only",
            "identity",
            "activity",
            "blocking",
            "objects",
            "indexes",
            "statistics",
            "permissions",
            "rollback"
        ]
    );
    assert!(!format!("{:?}", output.source_id).contains("secret-marker"));
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn identity_mismatch_prevents_other_queries_and_rolls_back() {
    let (request, secrets, path) = setup();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        calls: calls.clone(),
        database: "other".into(),
        server_port: 55433,
        delay: Duration::ZERO,
    };
    assert!(
        collect_with(&transport, &request, &secrets, CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["open", "begin_read_only", "identity", "rollback"]
    );
    calls.lock().unwrap().clear();
    let wrong_server = FakeTransport {
        calls: calls.clone(),
        database: "relayne_helper_acceptance".into(),
        server_port: 55434,
        delay: Duration::ZERO,
    };
    assert!(
        collect_with(&wrong_server, &request, &secrets, CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["open", "begin_read_only", "identity", "rollback"]
    );
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn canceled_query_attempts_server_cancel_then_rollback() {
    let (request, secrets, path) = setup();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        calls: calls.clone(),
        database: "relayne_helper_acceptance".into(),
        server_port: 55433,
        delay: Duration::from_millis(300),
    };
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        trigger.cancel();
    });
    assert!(
        collect_with(&transport, &request, &secrets, cancel)
            .await
            .is_err()
    );
    let calls = calls.lock().unwrap();
    assert!(calls.contains(&"cancel".into()));
    assert_eq!(calls.last().unwrap(), "rollback");
    let _ = std::fs::remove_file(path);
}

#[test]
fn row_projection_rejects_unbounded_names_and_non_finite_estimates() {
    assert_eq!(
        canonical_server("127.0.0.1/32", 55433).unwrap(),
        ("127.0.0.1".into(), 55433)
    );
    assert_eq!(
        canonical_server("not-an-ip", 55433),
        Err(PgFailure::InvalidProjection)
    );
    assert_eq!(
        canonical_server("127.0.0.1", 0),
        Err(PgFailure::InvalidProjection)
    );
    assert_eq!(
        verified_principal("reader".into(), "reader".into()).unwrap(),
        "reader"
    );
    assert_eq!(
        verified_principal("reader".into(), "admin".into()),
        Err(PgFailure::InvalidProjection)
    );
    assert!(
        !SqlObservation::Index {
            name: "x".repeat(257),
            method: "btree".into(),
            valid: true,
            scans: None
        }
        .bounded()
    );
    assert!(
        !SqlObservation::Object {
            schema: "public".into(),
            name: "orders".into(),
            columns: 1,
            estimated_rows: Some(f64::NAN)
        }
        .bounded()
    );
}

#[test]
fn registry_rejects_other_engine_and_unreviewed_template() {
    fn reviewed(mut request: ProbeRequest) -> (HelperCase, ProbeRequest) {
        let mut case = HelperCase::new(ProblemIntake::default()).unwrap();
        let profile = request.scope.target().unwrap().profile_id;
        case.revise(case.revision(), CaseEdit::Profiles(vec![profile]))
            .unwrap();
        case.revise(
            case.revision(),
            CaseEdit::Scopes(vec![request.scope.clone()]),
        )
        .unwrap();
        request.binding.case_id = case.id();
        request.binding.case_revision = case.revision();
        (case, request)
    }
    let (request, _, path) = setup();
    let registry = crate::helper::worker::built_in_registry().unwrap();
    let (case, mut request) = reviewed(request);
    assert!(registry.validate_request(&case, &request).is_ok());
    request.params = ProbeParams::SqlRead {
        query_digest: "a".repeat(64),
    };
    assert!(registry.validate_request(&case, &request).is_err());
    let mut diagnose = request.clone();
    if let BoundScope::Database {
        credential: Some(credential),
        ..
    } = &mut diagnose.scope
    {
        credential.purpose = CredentialPurpose::Diagnose;
    }
    diagnose.binding.scope_sha256 = diagnose.scope.digest().unwrap();
    diagnose.binding.credential_scope_sha256 = diagnose.scope.credential_scope_digest().unwrap();
    diagnose.params = ProbeParams::SqlRead {
        query_digest: template_digest(),
    };
    let (case, diagnose) = reviewed(diagnose);
    assert!(registry.validate_request(&case, &diagnose).is_err());
    let mut other = request.scope.clone();
    if let BoundScope::Database { engine, .. } = &mut other {
        *engine = DatabaseEngine::SqlServer;
    }
    let other = other.bind_credential_context().unwrap();
    request.scope = other;
    request.binding.scope_sha256 = request.scope.digest().unwrap();
    request.binding.credential_scope_sha256 = request.scope.credential_scope_digest().unwrap();
    request.params = ProbeParams::SqlRead {
        query_digest: template_digest(),
    };
    let (case, request) = reviewed(request);
    assert!(registry.validate_request(&case, &request).is_err());
    let _ = std::fs::remove_file(path);
}

struct SlowOpen {
    calls: Arc<Mutex<u32>>,
}
impl PgTransport for SlowOpen {
    fn open<'a>(
        &'a self,
        _: &'a str,
        _: u16,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> PgFuture<'a, Box<dyn PgSession>> {
        Box::pin(async move {
            *self.calls.lock().unwrap() += 1;
            tokio::time::sleep(Duration::from_secs(2)).await;
            Err(PgFailure::Unavailable)
        })
    }
}

#[tokio::test]
async fn cancel_during_connect_never_starts_transaction_or_retries_without_tls() {
    let (request, secrets, path) = setup();
    let calls = Arc::new(Mutex::new(0));
    let transport = SlowOpen {
        calls: calls.clone(),
    };
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        trigger.cancel();
    });
    assert!(
        collect_with(&transport, &request, &secrets, cancel)
            .await
            .is_err()
    );
    assert_eq!(*calls.lock().unwrap(), 1);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn connect_deadline_is_bounded_and_sanitizes_error() {
    let (mut request, secrets, path) = setup();
    request.deadline_secs = Some(1);
    let calls = Arc::new(Mutex::new(0));
    let started = Instant::now();
    let error = collect_with(
        &SlowOpen {
            calls: calls.clone(),
        },
        &request,
        &secrets,
        CancellationToken::new(),
    )
    .await
    .err()
    .expect("connection deadline must fail");
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert_eq!(*calls.lock().unwrap(), 1);
    assert!(!format!("{error:?}").contains("secret-marker"));
    let _ = std::fs::remove_file(path);
}

/// Run only inside the existing disposable Windows Sandbox. The role password
/// is loaded and used in the guest; it never appears in arguments or output.
#[test]
#[ignore]
fn guest_native_pg18_tls_scram_product_adapter() {
    assert_eq!(
        std::env::var("RELAYNE_GUEST_PG_NATIVE").ok().as_deref(),
        Some("1")
    );
    assert_eq!(
        std::env::var("USERNAME").ok().as_deref(),
        Some("WDAGUtilityAccount")
    );
    let secret_path = std::path::Path::new(r"C:\RelayneHelperAcceptance\credentials.txt");
    let contents =
        std::fs::read_to_string(secret_path).expect("guest fixture credential unavailable");
    let password = contents
        .lines()
        .find_map(|line| line.strip_prefix("reader="))
        .expect("guest reader credential unavailable");
    let vault =
        std::path::Path::new(r"C:\RelayneHelperAcceptance\app-data\native-probe-test.dpapi");
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "guest fixture".into(),
        host: "127.0.0.1".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: "operator".into(),
        domain: String::new(),
        route: String::new(),
    };
    let mut scope = BoundScope::Database {
        target,
        engine: DatabaseEngine::Postgres,
        port: 55433,
        database: "relayne_helper_acceptance".into(),
        schema: Some("fixture".into()),
        object: Some("orders".into()),
        credential: None,
    };
    let resource = scope.resource_digest().unwrap();
    let reference = save_scoped_at(
        vault,
        &resource,
        CredentialPurpose::Read,
        SecretCredential {
            username: "relayne_fixture_reader".into(),
            password: password.into(),
            domain: String::new(),
        },
    )
    .expect("guest scoped credential unavailable");
    let credential = CredentialScope {
        reference: reference.id,
        purpose: reference.purpose,
        generation: reference.generation,
        principal: reference.principal,
        context: reference.context,
        context_digest: reference.scope_digest,
    };
    if let BoundScope::Database {
        credential: current,
        ..
    } = &mut scope
    {
        *current = Some(credential);
    }
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
        deadline_secs: Some(15),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let output = runtime
        .block_on(PostgresAdapter.collect(
            &request,
            &PersistentSecretResolver::at(vault.to_owned()),
            CancellationToken::new(),
        ))
        .expect("native PostgreSQL read failed");
    assert_eq!(output.status, EvidenceStatus::Complete);
    assert_eq!(output.coverage.observed, PROBE_COUNT);
    assert_eq!(output.records.len(), PROBE_COUNT as usize);
    assert!(output.sql_observations.iter().any(|o| matches!(
        o,
        SqlObservation::Permission {
            table_select: Some(true),
            ..
        }
    )));
}
