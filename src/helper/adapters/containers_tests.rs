use super::containers::*;
use crate::helper::{
    evidence::{EvidenceStatus, Observation},
    manifest::CapabilityId,
    process::FixedToolOperation,
    scope::BoundScope,
    worker::built_in_registry,
};
use sha2::{Digest, Sha256};

#[test]
fn container_argv_is_explicit_and_closed() {
    let (program, args) = FixedToolOperation::DockerContainerInspect {
        context: "reviewed".into(),
        container_id: "abc123".into(),
    }
    .argv()
    .unwrap();
    assert_eq!(program.to_string_lossy(), "docker.exe");
    assert_eq!(
        args.iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        [
            "--context",
            "reviewed",
            "inspect",
            "--type",
            "container",
            "--format",
            "{{json .}}",
            "abc123"
        ]
    );
    let (_, args) = FixedToolOperation::KubernetesEvents {
        context: "reviewed".into(),
        namespace: "prod".into(),
        uid: "uid-123".into(),
    }
    .argv()
    .unwrap();
    assert_eq!(
        args.iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        [
            "--context",
            "reviewed",
            "--namespace",
            "prod",
            "get",
            "events",
            "--field-selector",
            "involvedObject.uid=uid-123",
            "-o",
            "json",
            "--chunk-size=50"
        ]
    );
    assert!(
        FixedToolOperation::DockerContainerStats {
            context: "-bad".into(),
            container_id: "abc".into()
        }
        .argv()
        .is_err()
    );
    assert!(
        FixedToolOperation::DockerContainerInspect {
            context: "reviewed".into(),
            container_id: "--all".into()
        }
        .argv()
        .is_err()
    );
}

#[test]
fn only_implemented_container_operations_are_executable() {
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
}

#[test]
fn unsafe_or_unreviewed_scope_is_rejected_before_dispatch() {
    let scope = BoundScope::Docker {
        daemon_context: "-ambient".into(),
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
fn docker_json_whitelists_secrets_and_rejects_mismatch() {
    let raw = br#"{"Id":"abc123","State":{"Status":"running","Health":{"Status":"healthy"}},"Config":{"Env":["TOKEN=canary-secret"]},"Mounts":[{"Source":"canary-secret"}]}"#;
    let out = parse_docker_inspect(raw, "abc123").unwrap();
    assert_eq!(out.status, EvidenceStatus::Complete);
    assert_eq!(out.records[0].observation, Observation::Healthy);
    assert!(!format!("{:?}", out.records).contains("canary-secret"));
    assert!(parse_docker_inspect(raw, "wrong").is_err());
    assert!(parse_docker_inspect(b"{}{}", "abc123").is_err());
    assert!(parse_docker_inspect(b"", "abc123").is_err());
    let stats = br#"{"ID":"abc123","CPUPerc":"12.4%","MemPerc":"99.2%","Name":"canary-secret"}"#;
    let out = parse_docker_stats(stats, "abc123").unwrap();
    assert_eq!(out.records[0].observation, Observation::Degraded);
    assert_eq!(out.metrics.len(), 2);
    assert!(
        parse_docker_stats(
            br#"{"ID":"abc123","CPUPerc":"NaN%","MemPerc":"1%"}"#,
            "abc123"
        )
        .is_err()
    );
}

#[test]
fn kubernetes_identity_status_and_events_are_scoped() {
    let workload = br#"{"kind":"Pod","metadata":{"name":"web","namespace":"prod","uid":"uid-123","annotations":{"token":"canary-secret"}},"status":{"phase":"Running"}}"#;
    let (out, uid) = parse_kube_status(workload, "prod", "pod", "web").unwrap();
    assert_eq!(out.records[0].observation, Observation::Healthy);
    assert_eq!(uid, "uid-123");
    assert!(parse_kube_status(workload, "other", "pod", "web").is_err());
    let events = br#"{"kind":"EventList","items":[{"type":"Warning","reason":"BackOff","message":"canary-secret","involvedObject":{"uid":"uid-123","kind":"Pod","name":"web"}}]}"#;
    let out = parse_kube_events(events, &uid).unwrap();
    assert_eq!(out.records[0].observation, Observation::Degraded);
    assert!(!format!("{:?}", out.records).contains("canary-secret"));
    assert!(parse_kube_events(events, "other").is_err());
    let empty = parse_kube_events(br#"{"kind":"EventList","items":[]}"#, &uid).unwrap();
    assert_eq!(empty.records[0].observation, Observation::Unknown);
}

#[test]
fn daemon_identity_must_match() {
    assert!(docker_identity(br#"{"ID":"daemon-a"}"#, "daemon-a").is_ok());
    assert!(docker_identity(br#"{"ID":"daemon-b"}"#, "daemon-a").is_err());
    assert!(docker_identity(br#"{}"#, "daemon-a").is_err());
    let local =
        br#"{"Name":"reviewed","Endpoints":{"docker":{"Host":"npipe:////./pipe/docker_engine"}}}"#;
    assert!(docker_local_context(local, "reviewed").is_ok());
    assert!(docker_local_context(local, "other").is_err());
    assert!(
        docker_local_context(
            br#"{"Name":"reviewed","Endpoints":{"docker":{"Host":"tcp://remote:2376"}}}"#,
            "reviewed"
        )
        .is_err()
    );
    assert!(local_principal(b"DOMAIN\\alice\r\n", "domain\\Alice").is_ok());
    assert!(local_principal(b"DOMAIN\\bob\r\n", "domain\\Alice").is_err());
    assert!(
        kube_principal(
            br#"{"kind":"SelfSubjectReview","status":{"userInfo":{"username":"alice"}}}"#,
            "alice"
        )
        .is_ok()
    );
    assert!(
        kube_principal(
            br#"{"kind":"SelfSubjectReview","status":{"userInfo":{"username":"bob"}}}"#,
            "alice"
        )
        .is_err()
    );
}

#[test]
fn kube_context_and_cluster_fingerprint_must_match() {
    let mut hash = Sha256::new();
    hash.update(b"relayne-kubernetes-cluster-v1\0");
    hash.update(b"https://cluster.example");
    hash.update(b"\0");
    hash.update(b"Y2E=");
    let fingerprint = format!("{:x}", hash.finalize());
    let view = br#"{"current-context":"reviewed","contexts":[{"name":"reviewed","context":{"cluster":"cluster-a","user":"reviewed-user"}}],"clusters":[{"name":"cluster-a","cluster":{"server":"https://cluster.example","certificate-authority-data":"Y2E="}}],"users":[{"name":"reviewed-user","user":{"token":"canary-secret"}}]}"#;
    assert!(kube_identity(view, "reviewed", &fingerprint).is_ok());
    assert!(kube_identity(view, "other", &fingerprint).is_err());
    assert!(kube_identity(view, "reviewed", &"0".repeat(64)).is_err());
    let dynamic = br#"{"current-context":"reviewed","contexts":[{"name":"reviewed","context":{"cluster":"cluster-a","user":"reviewed-user"}}],"clusters":[{"name":"cluster-a","cluster":{"server":"https://cluster.example","certificate-authority-data":"Y2E="}}],"users":[{"name":"reviewed-user","user":{"exec":{"command":"powershell.exe"}}}]}"#;
    assert!(kube_identity(dynamic, "reviewed", &fingerprint).is_err());
}
