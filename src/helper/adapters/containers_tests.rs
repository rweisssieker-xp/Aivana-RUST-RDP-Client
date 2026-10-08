use super::{containers::*, docker_native, kube_native};
use crate::helper::{
    capability::ProbeRequest,
    credentials::{ResolvedSecret, SecretResolver},
    evidence::EvidenceBinding,
    evidence::{EvidenceStatus, MetricSourceCounter, Observation},
    manifest::{CapabilityId, ProbeParams},
    scope::{BoundScope, CredentialPurpose, CredentialScope},
    worker::built_in_registry,
};

struct NoCredential;
impl SecretResolver for NoCredential {
    fn resolve(&self, _: &CredentialScope, _: CredentialPurpose) -> anyhow::Result<ResolvedSecret> {
        panic!("preflight must fail before credential or provider contact")
    }
}
struct FixtureCredential;
impl SecretResolver for FixtureCredential {
    fn resolve(
        &self,
        scope: &CredentialScope,
        _: CredentialPurpose,
    ) -> anyhow::Result<ResolvedSecret> {
        Ok(ResolvedSecret::fixture(
            scope.principal.clone(),
            "fixture-token".into(),
        ))
    }
}
use base64::Engine;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!("relayne-containers-{}", Uuid::new_v4()));
    fs::create_dir_all(&path).unwrap();
    path
}
fn pem_der(pem: &str) -> Vec<u8> {
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap()
}
fn fixture_tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    let cert = CertificateDer::from(pem_der(include_str!("fixtures/server-cert.pem")));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_der(include_str!(
        "fixtures/server-key.pem"
    ))));
    let server = ServerConfig::builder_with_provider(std::sync::Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server))
}
fn fingerprint(server: &str, ca: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"relayne-kubernetes-cluster-v1\0");
    hash.update(server.as_bytes());
    hash.update(b"\0");
    hash.update(ca.as_bytes());
    format!("{:x}", hash.finalize())
}
fn kube_config(extra: &str) -> String {
    format!(
        r#"contexts:
  - name: reviewed
    context:
      cluster: cluster-a
      user: read-user
clusters:
  - name: cluster-a
    cluster:
      server: https://cluster.example/
      certificate-authority-data: Y2E=
      {extra}
users:
  - name: read-user
    user: {{}}
"#
    )
}

#[test]
fn registry_has_only_executable_closed_container_ids() {
    let registry = built_in_registry().unwrap();
    assert!(registry.adapter(CapabilityId::ContainerStatus).is_none());
    for id in [
        CapabilityId::DockerContainerInspect,
        CapabilityId::DockerContainerStats,
        CapabilityId::KubernetesWorkloadStatus,
        CapabilityId::KubernetesEvents,
    ] {
        assert!(registry.adapter(id).is_some());
    }
    let scope = BoundScope::Docker {
        daemon_context: "--current".into(),
        container_id: "a".repeat(64),
        credential: None,
    };
    assert!(validate_scoped_operation(&scope, CapabilityId::DockerContainerInspect).is_err());
    let scope = BoundScope::Kubernetes {
        context: "reviewed".into(),
        cluster_fingerprint: "x".into(),
        namespace: "prod".into(),
        resource_kind: "secret".into(),
        resource_name: "web".into(),
        credential: None,
    };
    assert!(validate_scoped_operation(&scope, CapabilityId::KubernetesWorkloadStatus).is_err());
}

#[test]
fn kube_tls_and_dynamic_auth_are_rejected_before_transport() {
    let dir = scratch();
    let path = dir.join("config");
    let fp = fingerprint("https://cluster.example/", "Y2E=");
    fs::write(&path, kube_config("")).unwrap();
    assert!(kube_native::load_endpoint(&path, "reviewed", &fp).is_ok());
    for extra in [
        "insecure-skip-tls-verify: true",
        "tls-server-name: attacker.example",
        "proxy-url: http://attacker.example",
        "certificate-authority: C:\\attacker.pem",
    ] {
        fs::write(&path, kube_config(extra)).unwrap();
        assert!(
            kube_native::load_endpoint(&path, "reviewed", &fp).is_err(),
            "accepted {extra}"
        );
    }
    fs::write(&path, kube_config("")).unwrap();
    assert!(kube_native::load_endpoint(&path, "other", &fp).is_err());
    assert!(kube_native::load_endpoint(&path, "reviewed", &"0".repeat(64)).is_err());
    let dynamic = kube_config("").replace(
        "user: {}",
        "user:\n      exec:\n        command: powershell.exe",
    );
    fs::write(&path, dynamic).unwrap();
    assert!(kube_native::load_endpoint(&path, "reviewed", &fp).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unsafe_kube_preflight_causes_zero_provider_contact() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().unwrap().port()
    );
    let dir = scratch();
    let path = dir.join("config");
    fs::write(
        &path,
        kube_config("insecure-skip-tls-verify: true").replace("https://cluster.example/", &server),
    )
    .unwrap();
    let scope = BoundScope::Kubernetes {
        context: "reviewed".into(),
        cluster_fingerprint: fingerprint(&server, "Y2E="),
        namespace: "prod".into(),
        resource_kind: "pod".into(),
        resource_name: "web".into(),
        credential: Some(CredentialScope {
            reference: Uuid::new_v4(),
            purpose: CredentialPurpose::Read,
            generation: 1,
            principal: "alice".into(),
            context: "reviewed".into(),
            context_digest: String::new(),
        }),
    }
    .bind_credential_context()
    .unwrap();
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
        capability_id: CapabilityId::KubernetesWorkloadStatus,
        capability_version: 1,
        params: ProbeParams::KubernetesStatus,
        requested_at: chrono::Utc::now(),
        deadline_secs: Some(1),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let output = runtime
        .block_on(kube_native::collect_from_path(
            &request,
            &NoCredential,
            CancellationToken::new(),
            &path,
        ))
        .unwrap();
    assert_eq!(output.status, EvidenceStatus::Unavailable);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn changed_docker_context_causes_zero_pipe_contact() {
    use tokio::net::windows::named_pipe::ServerOptions;
    let pipe_name = format!("relayne-fixture-{}", Uuid::new_v4());
    let path = format!(r"\\.\pipe\{pipe_name}");
    let dir = scratch();
    let folder = dir.join("one");
    fs::create_dir_all(&folder).unwrap();
    fs::write(
        folder.join("meta.json"),
        r#"{"Name":"reviewed","Endpoints":{"docker":{"Host":"npipe:////./pipe/changed"}}}"#,
    )
    .unwrap();
    let scope = BoundScope::Docker {
        daemon_context: "reviewed".into(),
        container_id: "a".repeat(64),
        credential: Some(CredentialScope {
            reference: Uuid::new_v4(),
            purpose: CredentialPurpose::Read,
            generation: 1,
            principal: "a".repeat(64),
            context: format!("npipe:////./pipe/{pipe_name}|daemon-a"),
            context_digest: String::new(),
        }),
    }
    .bind_credential_context()
    .unwrap();
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
        capability_id: CapabilityId::DockerContainerInspect,
        capability_version: 1,
        params: ProbeParams::DockerInspect,
        requested_at: chrono::Utc::now(),
        deadline_secs: Some(1),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut server = ServerOptions::new().create(&path).unwrap();
        let output = docker_native::collect_from_root(
            &request,
            &NoCredential,
            CancellationToken::new(),
            &dir,
            &"a".repeat(64),
        )
        .await
        .unwrap();
        assert_eq!(output.status, EvidenceStatus::Unavailable);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), server.connect())
                .await
                .is_err()
        );
    });
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn native_https_fixture_uses_vault_token_and_selected_resource() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = format!("https://127.0.0.1:{}/", listener.local_addr().unwrap().port());
        let ca = base64::engine::general_purpose::STANDARD.encode(include_str!("fixtures/ca-cert.pem"));
        let dir = scratch(); let path = dir.join("config");
        fs::write(&path, kube_config("").replace("https://cluster.example/", &server).replace("Y2E=", &ca)).unwrap();
        let scope = BoundScope::Kubernetes { context: "reviewed".into(), cluster_fingerprint: fingerprint(&server, &ca),
            namespace: "prod".into(), resource_kind: "pod".into(), resource_name: "web".into(),
            credential: Some(CredentialScope { reference: Uuid::new_v4(), purpose: CredentialPurpose::Read,
                generation: 1, principal: "alice".into(), context: "reviewed".into(), context_digest: String::new() })
        }.bind_credential_context().unwrap();
        let request = ProbeRequest { binding: EvidenceBinding { case_id: Uuid::new_v4(), case_revision: 1,
            request_id: Uuid::new_v4(), scope_sha256: scope.digest().unwrap(),
            credential_scope_sha256: scope.credential_scope_digest().unwrap(), run_id: None },
            scope, capability_id: CapabilityId::KubernetesEvents, capability_version: 1,
            params: ProbeParams::KubernetesEvents, requested_at: chrono::Utc::now(), deadline_secs: Some(3) };
        let acceptor = fixture_tls_acceptor();
        let fixture = tokio::spawn(async move {
            let responses = [
                ("POST /apis/authentication.k8s.io/v1/selfsubjectreviews", r#"{"kind":"SelfSubjectReview","status":{"userInfo":{"username":"alice"}}}"#),
                ("GET /api/v1/namespaces/prod/pods/web", r#"{"kind":"Pod","metadata":{"name":"web","namespace":"prod","uid":"uid-pod","generation":1},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"ready":true}]}}"#),
                ("GET /api/v1/namespaces/prod/events?", r#"{"kind":"EventList","items":[{"type":"Warning","reason":"BackOff","message":"canary-secret","involvedObject":{"uid":"uid-pod","kind":"Pod","name":"web"}}]}"#),
            ];
            for (expected, body) in responses {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(socket).await.unwrap();
                let mut bytes = Vec::new(); let mut chunk = [0_u8; 4096];
                while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = tls.read(&mut chunk).await.unwrap(); assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]); assert!(bytes.len() < 8192);
                }
                let headers = std::str::from_utf8(&bytes).unwrap().to_ascii_lowercase();
                assert!(headers.starts_with(&expected.to_ascii_lowercase()), "unexpected request path");
                assert!(headers.contains("authorization: bearer fixture-token"));
                tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            }
        });
        let output = tokio::time::timeout(std::time::Duration::from_secs(5),
            kube_native::collect_from_path(&request, &FixtureCredential, CancellationToken::new(), &path)).await.unwrap().unwrap();
        assert_eq!(output.status, EvidenceStatus::Complete);
        assert_eq!(output.records[0].observation, Observation::Degraded);
        assert!(!format!("{:?}", output.records).contains("canary-secret"));
        fixture.await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    });
}

#[test]
fn kubernetes_identity_mismatch_stops_before_resource_read() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = format!("https://127.0.0.1:{}/", listener.local_addr().unwrap().port());
        let ca = base64::engine::general_purpose::STANDARD.encode(include_str!("fixtures/ca-cert.pem"));
        let dir = scratch();
        let path = dir.join("config");
        fs::write(&path, kube_config("").replace("https://cluster.example/", &server).replace("Y2E=", &ca)).unwrap();
        let scope = BoundScope::Kubernetes {
            context: "reviewed".into(),
            cluster_fingerprint: fingerprint(&server, &ca),
            namespace: "prod".into(),
            resource_kind: "pod".into(),
            resource_name: "web".into(),
            credential: Some(CredentialScope {
                reference: Uuid::new_v4(),
                purpose: CredentialPurpose::Read,
                generation: 1,
                principal: "alice".into(),
                context: "reviewed".into(),
                context_digest: String::new(),
            }),
        }.bind_credential_context().unwrap();
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
            capability_id: CapabilityId::KubernetesWorkloadStatus,
            capability_version: 1,
            params: ProbeParams::KubernetesStatus,
            requested_at: chrono::Utc::now(),
            deadline_secs: Some(3),
        };
        let acceptor = fixture_tls_acceptor();
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tls.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            let headers = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            assert!(headers.starts_with("post /apis/authentication.k8s.io/v1/selfsubjectreviews"));
            assert!(headers.contains("authorization: bearer fixture-token"));
            let body = r#"{"kind":"SelfSubjectReview","status":{"userInfo":{"username":"mallory"}}}"#;
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
            assert!(tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await.is_err(), "resource read followed identity mismatch");
        });
        let output = tokio::time::timeout(std::time::Duration::from_secs(5), kube_native::collect_from_path(&request, &FixtureCredential, CancellationToken::new(), &path)).await.unwrap().unwrap();
        assert_eq!(output.status, EvidenceStatus::Unavailable);
        fixture.await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    });
}

#[test]
fn docker_capture_keeps_one_pipe_when_context_changes() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ServerOptions,
    };
    let name = format!("relayne-fixture-{}", Uuid::new_v4());
    let pipe_path = format!(r"\\.\pipe\{name}");
    let uri = format!("npipe:////./pipe/{name}");
    let dir = scratch();
    let folder = dir.join("one");
    fs::create_dir_all(&folder).unwrap();
    let meta = folder.join("meta.json");
    fs::write(
        &meta,
        format!(r#"{{"Name":"reviewed","Endpoints":{{"docker":{{"Host":"{uri}"}}}}}}"#),
    )
    .unwrap();
    let sid = docker_native::process_sid_digest().unwrap();
    let id = "a".repeat(64);
    let scope = BoundScope::Docker {
        daemon_context: "reviewed".into(),
        container_id: id.clone(),
        credential: Some(CredentialScope {
            reference: Uuid::new_v4(),
            purpose: CredentialPurpose::Read,
            generation: 1,
            principal: sid.clone(),
            context: format!("{uri}|daemon-a"),
            context_digest: String::new(),
        }),
    }
    .bind_credential_context()
    .unwrap();
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
        capability_id: CapabilityId::DockerContainerInspect,
        capability_version: 1,
        params: ProbeParams::DockerInspect,
        requested_at: chrono::Utc::now(),
        deadline_secs: Some(3),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut server = ServerOptions::new().create(&pipe_path).unwrap();
        let fixture = tokio::spawn(async move {
            server.connect().await.unwrap();
            for (path, body) in [
                ("/info".to_string(), r#"{"ID":"daemon-a"}"#.to_string()),
                (format!("/containers/{id}/json"), format!(r#"{{"Id":"{id}","State":{{"Status":"running","Health":{{"Status":"healthy"}}}}}}"#)),
                ("/info".to_string(), r#"{"ID":"daemon-a"}"#.to_string()),
            ] {
                let mut request = [0_u8; 1024]; let n = server.read(&mut request).await.unwrap();
                assert!(std::str::from_utf8(&request[..n]).unwrap().starts_with(&format!("GET {path} HTTP/1.1")));
                if path == "/info" {
                    fs::write(&meta, r#"{"Name":"reviewed","Endpoints":{"docker":{"Host":"npipe:////./pipe/changed"}}}"#).unwrap();
                }
                server.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let output = docker_native::collect_from_root(&request, &FixtureCredential,
            CancellationToken::new(), &dir, &sid).await.unwrap();
        assert_eq!(output.status, EvidenceStatus::Partial);
        assert_eq!(output.records[0].observation, Observation::Healthy);
        fixture.await.unwrap();
    });
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn docker_context_is_pinned_to_reviewed_local_pipe() {
    let dir = scratch();
    let folder = dir.join("one");
    fs::create_dir_all(&folder).unwrap();
    fs::write(
        folder.join("meta.json"),
        r#"{"Name":"reviewed","Endpoints":{"docker":{"Host":"npipe:////./pipe/docker_engine"}}}"#,
    )
    .unwrap();
    assert_eq!(
        docker_native::load_context(&dir, "reviewed").unwrap(),
        "npipe:////./pipe/docker_engine"
    );
    assert_eq!(
        docker_native::pipe_path("npipe:////./pipe/docker_engine").unwrap(),
        r"\\.\pipe\docker_engine"
    );
    assert!(docker_native::pipe_path("tcp://remote:2376").is_err());
    assert!(docker_native::pipe_path("npipe:////./pipe/../other").is_err());
    assert!(docker_native::load_context(&dir, "other").is_err());
    assert!(crate::helper::evidence::is_digest(
        &docker_native::process_sid_digest().unwrap()
    ));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn docker_parsers_whitelist_sensitive_fields_and_preserve_multicore_cpu() {
    let id = "a".repeat(64);
    let inspect = format!(
        r#"{{"Id":"{id}","State":{{"Status":"running","Health":{{"Status":"healthy"}}}},"Config":{{"Env":["TOKEN=canary-secret"]}}}}"#
    );
    let out = parse_docker_inspect(inspect.as_bytes(), &id).unwrap();
    assert_eq!(out.records[0].observation, Observation::Healthy);
    assert!(!format!("{:?}", out.records).contains("canary-secret"));
    assert!(parse_docker_inspect(inspect.as_bytes(), "wrong").is_err());
    assert!(parse_docker_inspect(b"{}{}", &id).is_err());
    let stats = format!(
        r#"{{"id":"{id}","read":"2026-01-01T00:00:01Z","preread":"2026-01-01T00:00:00Z","cpu_stats":{{"cpu_usage":{{"total_usage":300}},"system_cpu_usage":200,"online_cpus":2}},"precpu_stats":{{"cpu_usage":{{"total_usage":100}},"system_cpu_usage":100}},"memory_stats":{{"usage":50,"limit":100}},"name":"canary-secret"}}"#
    );
    let out = parse_docker_stats(stats.as_bytes(), &id).unwrap();
    assert_eq!(out.status, EvidenceStatus::Complete);
    assert_eq!(out.records[0].observation, Observation::Unknown);
    assert_eq!(out.metrics[0].value, Some(400.0));
    assert_eq!(
        out.metrics[0].source_counter,
        MetricSourceCounter::DockerCpu
    );
    assert_eq!(
        out.metrics[1].source_counter,
        MetricSourceCounter::DockerMemory
    );
    assert!(out.metrics[0].sample_window.started_at < out.metrics[0].sample_window.ended_at);
    assert!(!format!("{:?}", out.metrics).contains("canary-secret"));
}

#[test]
fn workload_health_requires_current_readiness_and_completion() {
    let ready = br#"{"kind":"Pod","metadata":{"name":"web","namespace":"prod","uid":"uid-pod","generation":1},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"ready":true}]}}"#;
    assert_eq!(
        parse_kube_status(ready, "prod", "pod", "web")
            .unwrap()
            .0
            .records[0]
            .observation,
        Observation::Healthy
    );
    let pod = br#"{"kind":"Pod","metadata":{"name":"web","namespace":"prod","uid":"uid-pod"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}]}}"#;
    assert_ne!(
        parse_kube_status(pod, "prod", "pod", "web")
            .unwrap()
            .0
            .records[0]
            .observation,
        Observation::Healthy
    );
    let job = br#"{"kind":"Job","metadata":{"name":"job","namespace":"prod","uid":"uid-job"},"spec":{"completions":4},"status":{"succeeded":1,"conditions":[{"type":"Complete","status":"False"}]}}"#;
    assert_ne!(
        parse_kube_status(job, "prod", "job", "job")
            .unwrap()
            .0
            .records[0]
            .observation,
        Observation::Healthy
    );
    let stale = br#"{"kind":"Deployment","metadata":{"name":"web","namespace":"prod","uid":"uid-dep","generation":3},"spec":{"replicas":2},"status":{"observedGeneration":2,"readyReplicas":2,"updatedReplicas":2}}"#;
    assert_ne!(
        parse_kube_status(stale, "prod", "deployment", "web")
            .unwrap()
            .0
            .records[0]
            .observation,
        Observation::Healthy
    );
    let ds = br#"{"kind":"DaemonSet","metadata":{"name":"agents","namespace":"prod","uid":"uid-ds","generation":3},"status":{"observedGeneration":3,"desiredNumberScheduled":2,"numberReady":2,"updatedNumberScheduled":2}}"#;
    assert_eq!(
        parse_kube_status(ds, "prod", "daemonset", "agents")
            .unwrap()
            .0
            .records[0]
            .observation,
        Observation::Healthy
    );
    assert!(parse_kube_status(ds, "other", "daemonset", "agents").is_err());
}

#[test]
fn named_pipe_fixture_exercises_real_framing_cancel_and_limits() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::windows::named_pipe::ServerOptions,
        };
        let path = format!(r"\\.\pipe\relayne-fixture-{}", Uuid::new_v4());
        let mut server = ServerOptions::new().create(&path).unwrap();
        let fixture = tokio::spawn(async move {
            server.connect().await.unwrap();
            for body in [b"{}".as_slice(), b"{}".as_slice()] {
                let mut request = [0_u8; 1024];
                let n = server.read(&mut request).await.unwrap();
                assert!(n > 0 && request[..n].starts_with(b"GET /info HTTP/1.1\r\n"));
                server
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                server.write_all(body).await.unwrap();
            }
        });
        let mut client = docker_native::PipeHttp::open(&path).await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                client
                    .get("/info", &CancellationToken::new())
                    .await
                    .unwrap(),
                (200, b"{}".to_vec())
            );
        }
        fixture.await.unwrap();
        let path = format!(r"\\.\pipe\relayne-fixture-{}", Uuid::new_v4());
        let mut server = ServerOptions::new().create(&path).unwrap();
        let fixture = tokio::spawn(async move {
            server.connect().await.unwrap();
            let mut request = [0_u8; 1024];
            server.read(&mut request).await.unwrap();
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
                .await
                .unwrap();
        });
        let mut client = docker_native::PipeHttp::open(&path).await.unwrap();
        assert!(
            client
                .get("/info", &CancellationToken::new())
                .await
                .is_err()
        );
        fixture.await.unwrap();
        let path = format!(r"\\.\pipe\relayne-fixture-{}", Uuid::new_v4());
        let mut server = ServerOptions::new().create(&path).unwrap();
        let fixture = tokio::spawn(async move {
            server.connect().await.unwrap();
            let mut b = [0_u8; 1024];
            server.read(&mut b).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });
        let mut client = docker_native::PipeHttp::open(&path).await.unwrap();
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            trigger.cancel();
        });
        assert!(client.get("/info", &cancel).await.is_err());
        fixture.await.unwrap();
        let path = format!(r"\\.\pipe\relayne-fixture-{}", Uuid::new_v4());
        let mut server = ServerOptions::new().create(&path).unwrap();
        let fixture = tokio::spawn(async move {
            server.connect().await.unwrap();
            let mut b = [0_u8; 1024];
            server.read(&mut b).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let mut client = docker_native::PipeHttp::open(&path).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(25),
                client.get("/info", &CancellationToken::new())
            )
            .await
            .is_err()
        );
        fixture.await.unwrap();
    });
}
