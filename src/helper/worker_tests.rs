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
    let mut worker = HelperWorker::new(Arc::new(registry), Arc::new(NoSecrets)).unwrap();
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
    let mut worker =
        HelperWorker::new(Arc::new(built_in_registry().unwrap()), Arc::new(NoSecrets)).unwrap();
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
    let mut worker = HelperWorker::new(Arc::new(registry), Arc::new(NoSecrets)).unwrap();
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
    let mut worker = HelperWorker::new(Arc::new(registry), Arc::new(NoSecrets)).unwrap();
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
    let mut worker = HelperWorker::new(Arc::new(registry), Arc::new(NoSecrets)).unwrap();
    worker.submit(request(&case, &scope, false)).unwrap();
    let event = poll_one(&mut worker);
    assert!(matches!(
        event.outcome,
        WorkerOutcome::Failed(WorkerFailure::AdapterUnavailable)
    ));
}
