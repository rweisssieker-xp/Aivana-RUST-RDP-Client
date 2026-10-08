use super::*;
use crate::{
    helper::{evidence::EvidenceBinding, manifest::CapabilityId},
    mission::Target,
};
use chrono::Duration;
use uuid::Uuid;

fn sample_request() -> ProbeRequest {
    let scope = BoundScope::Linux {
        target: Target {
            profile_id: Uuid::new_v4(),
            name: "test".into(),
            host: "linux.example".into(),
            port: 22,
            protocol: "SSH".into(),
            username: "operator".into(),
            domain: String::new(),
            route: String::new(),
        },
        credential: None,
    };
    let binding = EvidenceBinding {
        case_id: Uuid::new_v4(),
        case_revision: 1,
        request_id: Uuid::new_v4(),
        scope_sha256: scope.digest().unwrap(),
        credential_scope_sha256: scope.credential_scope_digest().unwrap(),
        run_id: None,
    };
    ProbeRequest {
        binding,
        scope,
        capability_id: CapabilityId::SystemResources,
        capability_version: 1,
        params: ProbeParams::System,
        requested_at: Utc::now(),
        deadline_secs: None,
    }
}

#[test]
fn sample_normalization_keeps_rates_and_unknown_gaps() {
    let request = sample_request();
    let end = Utc::now().timestamp_millis();
    let make = |rx_after| RawSnapshot {
        schema: 1,
        start_ms: end - 250,
        end_ms: end,
        cpu_before: Some(vec![100.0, 200.0]),
        cpu_after: Some(vec![110.0, 250.0]),
        interface_before: Some(vec![1000.0, 2000.0]),
        interface_after: Some(vec![rx_after, 2250.0]),
        memory: Some(vec![40.0, 100.0]),
        commit: Some(vec![80.0, 100.0]),
        disk: Some(vec![50.0, 100.0]),
        error_count: None,
        events_truncated: false,
        process_count: Some(9.0),
        service_state: None,
        ..RawSnapshot::default()
    };
    let output = normalize_snapshot(make(1100.0), &request, None, Some("/"), Some("eth0")).unwrap();
    assert_eq!(output.status, EvidenceStatus::Partial);
    assert_eq!(
        output
            .metrics
            .iter()
            .find(|m| m.kind == MetricKind::CpuPercent)
            .unwrap()
            .value,
        Some(80.0)
    );
    assert_eq!(
        output
            .metrics
            .iter()
            .find(|m| m.kind == MetricKind::InterfaceRxBytesPerSecond)
            .unwrap()
            .value,
        Some(400.0)
    );
    assert_eq!(
        output
            .metrics
            .iter()
            .find(|m| m.kind == MetricKind::ErrorCount)
            .unwrap()
            .missing_reason,
        Some(MissingReason::Unsupported)
    );
    let reset = normalize_snapshot(make(999.0), &request, None, Some("/"), Some("eth0")).unwrap();
    let reset_rx = reset
        .metrics
        .iter()
        .find(|m| m.kind == MetricKind::InterfaceRxBytesPerSecond)
        .unwrap();
    assert_eq!(reset_rx.value, None);
    assert_eq!(reset_rx.missing_reason, Some(MissingReason::NoSamples));
    assert_eq!(
        reset_rx
            .sample_window
            .ended_at
            .signed_duration_since(reset_rx.sample_window.started_at),
        Duration::milliseconds(250)
    );
    let unselected = normalize_snapshot(make(1100.0), &request, None, Some("/"), None).unwrap();
    let unselected_rx = unselected
        .metrics
        .iter()
        .find(|m| m.kind == MetricKind::InterfaceRxBytesPerSecond)
        .unwrap();
    assert_eq!(unselected_rx.value, None);
    assert_eq!(
        unselected_rx.missing_reason,
        Some(MissingReason::Unsupported)
    );
    let mut capped = make(1100.0);
    capped.events_truncated = true;
    let capped = normalize_snapshot(capped, &request, None, Some("/"), Some("eth0")).unwrap();
    assert_eq!(capped.status, EvidenceStatus::Truncated);
    assert!(capped.coverage.truncated);
}

#[test]
fn bounded_system_details_keep_resources_and_hide_provider_names() {
    let request = sample_request();
    let end = Utc::now().timestamp_millis();
    let raw = RawSnapshot {
        schema: 1,
        start_ms: end - 250,
        end_ms: end,
        os_version: Some("22.04".into()),
        os_name: Some("secret-host".into()),
        uptime_seconds: Some(1000.0),
        load_one: Some(0.25),
        processes: Some(vec![RawProcess {
            name: "secret-process".into(),
            memory_bytes: Some(4096.0),
            cpu_seconds: Some(4.0),
        }]),
        service_state: Some("active".into()),
        service_dependencies: Some(vec!["secret-dependency".into()]),
        interface_extra: Some(vec![1.0, 2.0, 3.0, 4.0]),
        tcp_before: Some(vec![2.0, 100.0]),
        tcp_after: Some(vec![3.0, 102.0]),
        listening_tcp: Some(5.0),
        ..RawSnapshot::default()
    };
    let output = normalize_snapshot(raw, &request, Some("sshd"), Some("/"), Some("eth0")).unwrap();
    assert!(output.records.iter().any(|r| matches!(
        r.detail.as_ref(),
        Some(SystemDetail::Process {
            memory_bytes: Some(4096),
            ..
        })
    )));
    assert!(output.records.iter().any(|r| matches!(r.detail.as_ref(), Some(SystemDetail::Tcp { established: Some(3), retransmits_per_second: Some(v), .. }) if (*v - 8.0).abs() < 0.01)));
    assert!(output.records.iter().any(|r| matches!(
        r.detail.as_ref(),
        Some(SystemDetail::ServiceDependencies { count: Some(1), .. })
    )));
    let evidence = serde_json::to_string(&output.records).unwrap();
    assert!(!evidence.contains("secret-process"));
    assert!(!evidence.contains("secret-dependency"));
    assert!(!evidence.contains("secret-host"));
}

#[test]
fn collector_failures_preserve_denied_truncated_and_unavailable() {
    let request = sample_request();
    assert_eq!(
        permission_gap(&request).unwrap().status,
        EvidenceStatus::Denied
    );
    let truncated = tool_gap(&request, ProcessFailure::OutputLimit).unwrap();
    assert_eq!(truncated.status, EvidenceStatus::Truncated);
    assert!(truncated.coverage.truncated);
    assert_eq!(
        tool_gap(&request, ProcessFailure::Spawn).unwrap().status,
        EvidenceStatus::Unavailable
    );
    assert!(tool_gap(&request, ProcessFailure::Canceled).is_err());
}

#[test]
fn counter_delta_requires_two_monotonic_samples_and_real_window() {
    let at = Utc::now();
    let before = CounterSample {
        value: Some(100.0),
        at,
        missing_reason: None,
    };
    let after = CounterSample {
        value: Some(140.0),
        at: at + Duration::seconds(2),
        missing_reason: None,
    };
    assert_eq!(counter_delta(&before, &after).value, Some(20.0));
    assert_eq!(
        counter_delta(
            &before,
            &CounterSample {
                value: Some(100.0),
                ..after.clone()
            }
        )
        .value,
        Some(0.0)
    );
    assert!(
        counter_delta(
            &before,
            &CounterSample {
                value: Some(99.0),
                ..after.clone()
            }
        )
        .value
        .is_none()
    );
    assert!(
        counter_delta(
            &before,
            &CounterSample {
                at,
                ..after.clone()
            }
        )
        .value
        .is_none()
    );
    assert!(
        counter_delta(
            &before,
            &CounterSample {
                value: None,
                ..after.clone()
            }
        )
        .value
        .is_none()
    );
    let denied = CounterSample {
        value: None,
        missing_reason: Some(MissingReason::PermissionDenied),
        ..after.clone()
    };
    assert_eq!(
        counter_delta(&before, &denied).missing_reason,
        Some(MissingReason::PermissionDenied)
    );
    let contradictory = CounterSample {
        value: Some(140.0),
        ..denied
    };
    assert_eq!(counter_delta(&before, &contradictory).value, None);
    assert!(
        counter_delta(
            &before,
            &CounterSample {
                value: Some(f64::NAN),
                ..after
            }
        )
        .value
        .is_none()
    );
}

#[test]
fn selectors_reject_shell_and_option_injection() {
    for value in ["$(id)", "foo;true", "a'\necho", "--help", "x/y"] {
        assert!(safe_identifier(Some(value), true).is_err());
    }
    for value in ["-host", "host;id", "user@host", "$(id)"] {
        assert!(safe_host(value).is_err());
    }
    for value in ["-a", "/tmp/../etc", "/tmp';id", "/x\ny"] {
        assert!(safe_mount(Some(value)).is_err());
    }
    assert_eq!(safe_mount(Some("/var/lib/data")).unwrap(), "/var/lib/data");
    assert!(safe_linux_mount(Some("relative/path")).is_err());
    assert!(safe_windows_mount(Some("/var/lib/data")).is_err());
    assert_eq!(safe_windows_mount(Some("C:")).unwrap(), "C:");
    assert_eq!(safe_identifier(Some("eth0"), true).unwrap(), "eth0");
    assert_eq!(
        safe_service(Some("postgresql@16-main.service")).unwrap(),
        "postgresql@16-main.service"
    );
    assert!(safe_service(Some("foo';id")).is_err());
}

#[test]
fn linux_parser_rejects_unknown_partial_and_raw_data() {
    let fixture = b"schema=1\nstart_ms=1000\nend_ms=1250\ncpu_before=10 100\ncpu_after=20 150\ninterface_before=100 200\ninterface_after=150 250\nmemory=40 100\ncommit=30 100\ndisk=50 100\nerror_count=\nevents_truncated=false\nevents_metadata_truncated=false\nprocess_count=5\nservice_state=active\nos_version=22.04\nos_name=fixture-host\nuptime_seconds=100\nload_one=0.5\nprocesses=init,1024,3;\nservice_dependencies=-\nservice_dependencies_truncated=false\nevents=\ninterface_extra=0 0 0 0\ntcp_before=1 2\ntcp_after=1 3\nlistening_tcp=4\n";
    let sample = linux::parse_snapshot(fixture).unwrap();
    assert_eq!(pair(sample.cpu_before.as_ref()), Some((10.0, 100.0)));
    assert!(linux::parse_snapshot(&fixture[..fixture.len() - 20]).is_err());
    let bad =
        String::from_utf8_lossy(fixture).replace("service_state=active", "command_line=secret");
    assert!(linux::parse_snapshot(bad.as_bytes()).is_err());
}

#[cfg(windows)]
#[tokio::test]
async fn fixed_linux_script_executes_through_bounded_child_and_closed_parser() {
    let shell = std::path::PathBuf::from(r"C:\Program Files\Git\usr\bin\sh.exe");
    if !shell.is_file() {
        return;
    }
    let output = crate::helper::process::run_fixed_tool(
        crate::helper::process::FixedToolOperation::TestLocalLinuxScript {
            shell: shell.clone(),
        },
        tokio_util::sync::CancellationToken::new(),
        std::time::Duration::from_secs(8),
    )
    .await
    .unwrap();
    let parsed = linux::parse_snapshot(&output.stdout).unwrap();
    assert_eq!(parsed.schema, 1);
    assert!(parsed.end_ms >= parsed.start_ms);
    assert!(output.stdout.len() <= 16384);
    let canceled = tokio_util::sync::CancellationToken::new();
    canceled.cancel();
    assert_eq!(
        crate::helper::process::run_fixed_tool(
            crate::helper::process::FixedToolOperation::TestLocalLinuxScript { shell },
            canceled,
            std::time::Duration::from_secs(8),
        )
        .await
        .err()
        .unwrap(),
        ProcessFailure::Canceled
    );
}

#[cfg(windows)]
#[tokio::test]
async fn fixed_windows_script_executes_guarded_fixture_and_denial_shape() {
    let output = crate::helper::process::run_fixed_tool(
        crate::helper::process::FixedToolOperation::TestLocalWindowsScript { denied: false },
        tokio_util::sync::CancellationToken::new(),
        std::time::Duration::from_secs(8),
    )
    .await
    .unwrap();
    let raw: RawSnapshot = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(raw.schema, 1);
    assert_eq!(raw.processes.as_ref().unwrap().len(), 1);
    assert_eq!(raw.service_dependencies.as_ref().unwrap().len(), 1);
    assert_eq!(raw.events.as_ref().unwrap().len(), 1);
    assert_eq!(raw.interface_extra.as_ref().unwrap().len(), 4);
    let normalized = normalize_snapshot(
        raw,
        &sample_request(),
        Some("FixtureService"),
        Some("/"),
        Some("FixtureInterface"),
    )
    .unwrap();
    let serialized = serde_json::to_string(&normalized.records).unwrap();
    assert!(!serialized.contains("secret-process"));
    assert!(!serialized.contains("secret-provider"));
    let denied = crate::helper::process::run_fixed_tool(
        crate::helper::process::FixedToolOperation::TestLocalWindowsScript { denied: true },
        tokio_util::sync::CancellationToken::new(),
        std::time::Duration::from_secs(8),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&denied.stdout).unwrap()["collector_status"],
        "denied"
    );
}

#[test]
fn fixed_scripts_exclude_command_lines_and_event_bodies() {
    let windows = include_str!("windows.ps1");
    let linux = include_str!("linux.sh");
    for script in [windows, linux] {
        assert!(!script.contains("CommandLine"));
        assert!(!script.contains("Message"));
        assert!(!script.contains("eval "));
    }
    assert!(windows.contains("Invoke-Command -ConnectionUri"));
    assert!(linux.contains("/proc/stat"));
}
