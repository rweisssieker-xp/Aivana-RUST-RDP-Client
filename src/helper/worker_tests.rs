use super::*;
use crate::{
    helper::{
        capability::{ProbeFuture, ProbeRequest},
        case::{CaseEdit, HelperCase, ProblemIntake},
        credentials::{ResolvedSecret, SecretResolver},
        manifest::{CapabilityDeclaration, CheckRole},
        scope::{BoundScope, CredentialPurpose, CredentialScope},
    },
    mission::Target,
};
use std::{
    net::TcpListener,
    sync::atomic::{AtomicUsize, Ordering},
};

fn current_profile(scope: &BoundScope) -> crate::models::ConnectionProfile {
    let target = scope.target().unwrap();
    let mut profile =
        crate::models::ConnectionProfile::sample("current", &target.host, "Default", false);
    profile.id = target.profile_id;
    profile.name = target.name.clone();
    profile.port = target.port;
    profile.username = target.username.clone();
    profile.domain = target.domain.clone();
    profile
}

fn authority_for(case: &HelperCase, scope: &BoundScope) -> Arc<SnapshotProbeAuthority> {
    let authority = Arc::new(SnapshotProbeAuthority::default());
    authority.publish(&[case.clone()], &[current_profile(scope)]);
    authority
}

fn wait_for_adapter_calls(calls: &AtomicUsize, expected: usize) {
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while calls.load(Ordering::SeqCst) < expected && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(calls.load(Ordering::SeqCst), expected);
}

#[test]
fn queued_profile_edit_rejects_before_adapter_contact() {
    let (case, scope) = setup(9999, false);
    let calls = Arc::new(AtomicUsize::new(0));
    let authority = Arc::new(SnapshotProbeAuthority::default());
    let current = current_profile(&scope);
    authority.publish(&[case.clone()], &[current.clone()]);
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(SlowProbe {
                calls: calls.clone(),
                delay: Duration::from_millis(200),
                large: false,
            }),
        )
        .unwrap();
    let mut worker =
        HelperWorker::new(Arc::new(registry), Arc::new(NoSecrets), authority.clone()).unwrap();
    for _ in 0..4 {
        worker.submit(request(&case, &scope, false)).unwrap();
    }
    wait_for_adapter_calls(&calls, MAX_ACTIVE);
    let queued = worker.submit(request(&case, &scope, false)).unwrap();
    let mut edited = current;
    edited.host = "edited.invalid".into();
    authority.publish(&[case], &[edited]);
    std::thread::sleep(Duration::from_millis(250));
    let mut rejected = false;
    for _ in 0..100 {
        for event in worker.poll() {
            if event.request_id == queued {
                rejected = matches!(
                    event.outcome,
                    WorkerOutcome::Failed(WorkerFailure::AuthorityChanged)
                );
            }
        }
        if rejected {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(rejected);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "queued adapter reached old endpoint"
    );
}

#[test]
fn queued_case_withdrawal_rejects_before_adapter_contact() {
    let (case, scope) = setup(9999, false);
    let calls = Arc::new(AtomicUsize::new(0));
    let authority = authority_for(&case, &scope);
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(SlowProbe {
                calls: calls.clone(),
                delay: Duration::from_millis(200),
                large: false,
            }),
        )
        .unwrap();
    let mut worker =
        HelperWorker::new(Arc::new(registry), Arc::new(NoSecrets), authority.clone()).unwrap();
    for _ in 0..MAX_ACTIVE {
        worker.submit(request(&case, &scope, false)).unwrap();
    }
    wait_for_adapter_calls(&calls, MAX_ACTIVE);
    let queued = worker.submit(request(&case, &scope, false)).unwrap();
    authority.publish(&[], &[current_profile(&scope)]);
    let mut rejected = false;
    for _ in 0..100 {
        for event in worker.poll() {
            if event.request_id == queued {
                rejected = matches!(
                    event.outcome,
                    WorkerOutcome::Failed(WorkerFailure::AuthorityChanged)
                );
            }
        }
        if rejected {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(rejected);
    assert_eq!(calls.load(Ordering::SeqCst), MAX_ACTIVE);
}

#[test]
fn canceled_queued_intent_never_contacts_adapter() {
    let (case, scope) = setup(9999, false);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(SlowProbe {
                calls: calls.clone(),
                delay: Duration::from_millis(200),
                large: false,
            }),
        )
        .unwrap();
    let mut worker = HelperWorker::new(
        Arc::new(registry),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    for _ in 0..MAX_ACTIVE {
        worker.submit(request(&case, &scope, false)).unwrap();
    }
    wait_for_adapter_calls(&calls, MAX_ACTIVE);
    let queued = worker.submit(request(&case, &scope, false)).unwrap();
    assert!(worker.cancel(queued));
    let event = poll_one(&mut worker);
    assert_eq!(event.request_id, queued);
    assert!(matches!(event.outcome, WorkerOutcome::Canceled));
    std::thread::sleep(Duration::from_millis(250));
    let _ = worker.poll();
    assert_eq!(calls.load(Ordering::SeqCst), MAX_ACTIVE);
}

struct NoSecrets;
impl SecretResolver for NoSecrets {
    fn resolve(&self, _: &CredentialScope, _: CredentialPurpose) -> Result<ResolvedSecret> {
        anyhow::bail!("no secret")
    }
}
struct SlowProbe {
    calls: Arc<AtomicUsize>,
    delay: Duration,
    large: bool,
}
impl ProbeAdapter for SlowProbe {
    fn collect<'a>(
        &'a self,
        request: &'a ProbeRequest,
        _: &'a dyn SecretResolver,
        _: CancellationToken,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            let record = NormalizedRecord {
                kind: RecordKind::Network,
                observation: Observation::Healthy,
                subject_sha256: request.scope.resource_digest()?,
                detail: None,
            };
            Ok(ProbeOutput {
                status: EvidenceStatus::Complete,
                coverage: Coverage {
                    observed: 1,
                    expected: 1,
                    truncated: false,
                },
                records: vec![record; if self.large { 101 } else { 1 }],
                metrics: Vec::new(),
                sql_observations: Vec::new(),
                sql_artifacts: Vec::new(),
                evidence_refs: Vec::new(),
                source_id: b"fixture".to_vec(),
                source_observed_at: Utc::now(),
                parser_version: 1,
            })
        })
    }
}
fn setup(port: u16, http: bool) -> (HelperCase, BoundScope) {
    let target = Target {
        profile_id: Uuid::new_v4(),
        name: "loopback".into(),
        host: "127.0.0.1".into(),
        port,
        protocol: "RDP".into(),
        username: "tester".into(),
        domain: String::new(),
        route: String::new(),
    };
    let scope = if http {
        BoundScope::Http {
            target: target.clone(),
            port,
            tls: false,
            path: "/".into(),
        }
    } else {
        BoundScope::Windows {
            target: target.clone(),
            credential: None,
        }
    };
    let mut case = HelperCase::new(ProblemIntake::default()).unwrap();
    case.revise(1, CaseEdit::Profiles(vec![target.profile_id]))
        .unwrap();
    case.revise(2, CaseEdit::Scopes(vec![scope.clone()]))
        .unwrap();
    (case, scope)
}

#[tokio::test]
async fn malformed_http_authority_causes_zero_dns_tls_and_http_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (case, scope) = setup(port, true);
    let mut probe = request(&case, &scope, true);
    if let BoundScope::Http { target, .. } = &mut probe.scope {
        target.host = "good.example@127.0.0.1".into();
    }
    assert!(
        HttpProbe
            .collect(&probe, &NoSecrets, CancellationToken::new())
            .await
            .is_err()
    );
    probe.capability_id = CapabilityId::NetworkDns;
    probe.params = ProbeParams::Dns;
    assert!(
        crate::helper::adapters::NetworkAdapter
            .collect(&probe, &NoSecrets, CancellationToken::new())
            .await
            .is_err()
    );
    probe.capability_id = CapabilityId::NetworkTls;
    probe.params = ProbeParams::Tls;
    if let BoundScope::Http { tls, .. } = &mut probe.scope {
        *tls = true;
    }
    assert!(
        crate::helper::adapters::NetworkAdapter
            .collect(&probe, &NoSecrets, CancellationToken::new())
            .await
            .is_err()
    );
    if let BoundScope::Http { target, .. } = &mut probe.scope {
        target.host = "127.0.0.1".into();
        target.route = "proxy:443".into();
    }
    assert!(
        crate::helper::adapters::NetworkAdapter
            .collect(&probe, &NoSecrets, CancellationToken::new())
            .await
            .is_err()
    );
    probe.capability_id = CapabilityId::HttpHealth;
    probe.params = ProbeParams::Http;
    assert!(
        HttpProbe
            .collect(&probe, &NoSecrets, CancellationToken::new())
            .await
            .is_err()
    );
    assert!(listener.accept().is_err());
}
fn request(case: &HelperCase, scope: &BoundScope, http: bool) -> ProbeRequest {
    let id = Uuid::new_v4();
    ProbeRequest {
        binding: evidence::EvidenceBinding {
            case_id: case.id(),
            case_revision: case.revision(),
            request_id: id,
            scope_sha256: scope.digest().unwrap(),
            credential_scope_sha256: scope.credential_scope_digest().unwrap(),
            run_id: None,
        },
        scope: scope.clone(),
        capability_id: if http {
            CapabilityId::HttpHealth
        } else {
            CapabilityId::NetworkReachability
        },
        capability_version: 1,
        params: if http {
            ProbeParams::Http
        } else {
            ProbeParams::Network {
                port: scope.target().unwrap().port,
            }
        },
        requested_at: Utc::now(),
        deadline_secs: None,
    }
}

#[test]
fn sql_projection_is_persisted_and_unbounded_metadata_rejected() {
    let (case, scope) = setup(5432, false);
    let mut request = request(&case, &scope, false);
    request.capability_id = CapabilityId::SqlRead;
    request.params = ProbeParams::SqlRead {
        query_digest: "a".repeat(64),
    };
    let observation = crate::helper::sql::types::SqlObservation::Statistics {
        live_rows: Some(12000),
        dead_rows: Some(5),
        analyze_count: Some(1),
    };
    let output = ProbeOutput {
        status: EvidenceStatus::Complete,
        coverage: Coverage {
            observed: 1,
            expected: 1,
            truncated: false,
        },
        records: vec![NormalizedRecord {
            kind: RecordKind::SqlRead,
            observation: Observation::Healthy,
            subject_sha256: "b".repeat(64),
                detail: None,
        }],
        metrics: vec![],
        sql_observations: vec![observation.clone()],
        sql_artifacts: vec![],
        evidence_refs: vec![],
        source_id: b"postgres-fixture".to_vec(),
        source_observed_at: Utc::now(),
        parser_version: 1,
    };
    let envelope = normalize(&request, output).unwrap();
    assert_eq!(envelope.sql_observations, vec![observation]);
    assert!(
        serde_json::to_string(&envelope)
            .unwrap()
            .contains("live_rows")
    );
    let invalid = ProbeOutput {
        sql_observations: vec![crate::helper::sql::types::SqlObservation::Index {
            name: "x".repeat(257),
            method: "btree".into(),
            valid: true,
            scans: None,
        }],
        ..ProbeOutput {
            status: EvidenceStatus::Complete,
            coverage: Coverage {
                observed: 1,
                expected: 1,
                truncated: false,
            },
            records: vec![],
            metrics: vec![],
            sql_observations: vec![],
            sql_artifacts: vec![],
            evidence_refs: vec![],
            source_id: b"postgres-fixture".to_vec(),
            source_observed_at: Utc::now(),
            parser_version: 1,
        }
    };
    assert!(normalize(&request, invalid).is_err());
}
fn poll_one(worker: &mut HelperWorker) -> WorkerEvent {
    for _ in 0..300 {
        if let Some(event) = worker.poll().into_iter().next() {
            return event;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("worker did not finish")
}

#[test]
fn queue_limits_are_explicit() {
    assert_eq!(MAX_ACTIVE, 4);
    assert_eq!(MAX_QUEUED, 32);
    assert_eq!(DEFAULT_DEADLINE_SECS, 15);
    assert_eq!(MAX_DEADLINE_SECS, 30);
}

#[test]
fn declared_manifest_alone_cannot_dispatch_and_exact_binding_is_checked() {
    let (mut case, scope) = setup(9999, false);
    let registry = built_in_registry().unwrap();
    let mut probe = request(&case, &scope, false);
    registry.validate_request(&case, &probe).unwrap();
    probe.capability_id = CapabilityId::SqlPlan;
    assert!(registry.validate_request(&case, &probe).is_err());
    probe.capability_id = CapabilityId::NetworkReachability;
    probe.capability_version = 2;
    assert!(registry.validate_request(&case, &probe).is_err());
    probe.capability_version = 1;
    probe.params = ProbeParams::Network { port: 9998 };
    assert!(registry.validate_request(&case, &probe).is_err());
    probe.params = ProbeParams::Network { port: 9999 };
    case.revise(
        3,
        CaseEdit::Description(crate::helper::case::Answer::Unknown),
    )
    .unwrap();
    assert!(registry.validate_request(&case, &probe).is_err());
}

#[test]
fn pending_live_intent_requires_executable_registry_acceptance() {
    let (_, scope) = setup(9999, false);
    let mut store = crate::helper::store::HelperStore::default();
    let id = store.create(ProblemIntake::default()).unwrap();
    store
        .revise(
            id,
            1,
            CaseEdit::Profiles(vec![scope.target().unwrap().profile_id]),
        )
        .unwrap();
    store
        .revise(id, 2, CaseEdit::Scopes(vec![scope.clone()]))
        .unwrap();
    let request = request(store.case(id).unwrap(), &scope, false);
    assert!(
        store
            .register_accepted_capture(&CapabilityRegistry::new(), &request)
            .is_err()
    );
    let accepted = store
        .register_accepted_capture(&built_in_registry().unwrap(), &request)
        .unwrap();
    assert_eq!(accepted, request.binding);
    assert!(
        store
            .register_accepted_capture(&built_in_registry().unwrap(), &request)
            .is_err()
    );
}

#[test]
fn four_active_thirty_two_queued_and_typed_cancel() {
    let (case, scope) = setup(9999, false);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(SlowProbe {
                calls: calls.clone(),
                delay: Duration::from_millis(500),
                large: false,
            }),
        )
        .unwrap();
    let mut worker = HelperWorker::new(
        Arc::new(registry),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    let mut ids = Vec::new();
    for _ in 0..MAX_ACTIVE + MAX_QUEUED {
        ids.push(worker.submit(request(&case, &scope, false)).unwrap());
    }
    assert_eq!(worker.active_count(), 4);
    assert_eq!(worker.queued_count(), 32);
    assert!(worker.submit(request(&case, &scope, false)).is_err());
    assert!(worker.cancel(ids[MAX_ACTIVE]));
    let event = poll_one(&mut worker);
    assert_eq!(event.request_id, ids[MAX_ACTIVE]);
    assert!(matches!(event.outcome, WorkerOutcome::Canceled));
    assert_eq!(worker.queued_count(), 31);
    assert!(worker.cancel(ids[0]));
    let canceled = poll_one(&mut worker);
    assert_eq!(canceled.request_id, ids[0]);
    assert!(matches!(canceled.outcome, WorkerOutcome::Canceled));
    assert!(calls.load(Ordering::SeqCst) <= 5);
}

#[test]
fn real_loopback_tcp_and_http_produce_schema_two_evidence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (case, scope) = setup(port, false);
    let authority = authority_for(&case, &scope);
    let mut worker = HelperWorker::new(
        Arc::new(built_in_registry().unwrap()),
        Arc::new(NoSecrets),
        authority.clone(),
    )
    .unwrap();
    let probe = request(&case, &scope, false);
    worker.registry().validate_request(&case, &probe).unwrap();
    worker.submit(probe).unwrap();
    let event = poll_one(&mut worker);
    let WorkerOutcome::Complete(envelope) = event.outcome else {
        panic!("TCP did not yield evidence")
    };
    assert_eq!(envelope.schema, 2);
    assert_eq!(envelope.status, EvidenceStatus::Complete);
    assert_eq!(envelope.records[0].observation, Observation::Healthy);
    drop(listener);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .unwrap();
    });
    let (case, scope) = setup(port, true);
    authority.publish(&[case.clone()], &[current_profile(&scope)]);
    let probe = request(&case, &scope, true);
    worker.registry().validate_request(&case, &probe).unwrap();
    worker.submit(probe).unwrap();
    let event = poll_one(&mut worker);
    let WorkerOutcome::Complete(envelope) = event.outcome else {
        panic!("HTTP did not yield evidence")
    };
    assert_eq!(envelope.records[0].observation, Observation::Healthy);
    server.join().unwrap();
}

#[test]
fn http_assertion_distinguishes_status_and_body_from_transport() {
    use sha2::{Digest, Sha256};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\n\r\nOK")
            .unwrap();
    });
    let (case, scope) = setup(port, true);
    let mut probe = request(&case, &scope, true);
    probe.params = ProbeParams::HttpAssert {
        expected_status: 503,
        body_sha256: Some(format!("{:x}", Sha256::digest(b"OK"))),
    };
    let mut worker = HelperWorker::new(
        Arc::new(built_in_registry().unwrap()),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    worker.registry().validate_request(&case, &probe).unwrap();
    worker.submit(probe).unwrap();
    let event = poll_one(&mut worker);
    let WorkerOutcome::Complete(envelope) = event.outcome else {
        panic!("HTTP assertion failed")
    };
    assert_eq!(envelope.records[0].observation, Observation::Healthy);
    server.join().unwrap();
}

#[test]
fn dns_check_resolves_only_reviewed_http_host() {
    let (case, scope) = setup(443, true);
    let mut probe = request(&case, &scope, true);
    probe.capability_id = CapabilityId::NetworkDns;
    probe.params = ProbeParams::Dns;
    let mut worker = HelperWorker::new(
        Arc::new(built_in_registry().unwrap()),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    worker.registry().validate_request(&case, &probe).unwrap();
    worker.submit(probe).unwrap();
    let event = poll_one(&mut worker);
    let WorkerOutcome::Complete(envelope) = event.outcome else {
        panic!("DNS check failed")
    };
    assert_eq!(envelope.status, EvidenceStatus::Complete);
    assert_eq!(envelope.records[0].observation, Observation::Healthy);
}

#[test]
fn oversized_output_and_deadline_are_terminal_without_raw_error() {
    let (case, scope) = setup(9999, false);
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(SlowProbe {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::from_millis(0),
                large: true,
            }),
        )
        .unwrap();
    let mut worker = HelperWorker::new(
        Arc::new(registry),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    worker.submit(request(&case, &scope, false)).unwrap();
    assert!(matches!(
        poll_one(&mut worker).outcome,
        WorkerOutcome::Failed(WorkerFailure::InvalidOutput)
    ));
    let mut invalid = request(&case, &scope, false);
    invalid.deadline_secs = Some(31);
    assert!(worker.submit(invalid).is_err());
    let mut stale = request(&case, &scope, false);
    stale.requested_at = Utc::now() - chrono::Duration::seconds(31);
    assert!(worker.submit(stale).is_err());
}

#[test]
fn running_deadline_and_adapter_error_have_closed_terminal_status() {
    struct RawErrorProbe;
    impl ProbeAdapter for RawErrorProbe {
        fn collect<'a>(
            &'a self,
            _: &'a ProbeRequest,
            _: &'a dyn SecretResolver,
            _: CancellationToken,
        ) -> ProbeFuture<'a> {
            Box::pin(async { anyhow::bail!("password=secret-sentinel native process text") })
        }
    }
    let (case, scope) = setup(9999, false);
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(SlowProbe {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::from_secs(2),
                large: false,
            }),
        )
        .unwrap();
    let mut worker = HelperWorker::new(
        Arc::new(registry),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    let mut probe = request(&case, &scope, false);
    probe.deadline_secs = Some(1);
    worker.submit(probe).unwrap();
    assert!(matches!(
        poll_one(&mut worker).outcome,
        WorkerOutcome::TimedOut
    ));
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            CapabilityDeclaration {
                id: CapabilityId::NetworkReachability,
                version: 1,
                role: CheckRole::Diagnostic,
                prerequisites: Vec::new(),
            },
            Arc::new(RawErrorProbe),
        )
        .unwrap();
    let mut worker = HelperWorker::new(
        Arc::new(registry),
        Arc::new(NoSecrets),
        authority_for(&case, &scope),
    )
    .unwrap();
    worker.submit(request(&case, &scope, false)).unwrap();
    let event = poll_one(&mut worker);
    assert!(matches!(
        event.outcome,
        WorkerOutcome::Failed(WorkerFailure::AdapterUnavailable)
    ));
}
