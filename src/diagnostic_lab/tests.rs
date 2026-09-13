use super::*;
use crate::operations::{JobResult, JobStatus};
use std::io::Write;

#[test]
fn diagnostic_preview_explains_three_outcomes_without_mutating_real_case() {
    let now = Utc::now();
    let case = real(now);
    let before = serde_json::to_value(&case).unwrap();
    let branches = case.preview(Probe::Service, now).unwrap();
    assert_eq!(branches.len(), 3);
    assert_eq!(branches[0].assumed, Value::Pass);
    assert_eq!(
        branches[0].compatible,
        vec![Probe::Dns, Probe::Tls, Probe::Dependency]
    );
    assert_eq!(branches[1].assumed, Value::Fail);
    assert_eq!(branches[1].compatible, vec![Probe::Service]);
    assert_eq!(branches[1].known, 1);
    assert_eq!(branches[1].next, Some(Probe::Dns));
    assert!(!branches[1].conclusion.starts_with("Alle vier"));
    assert_eq!(branches[2].assumed, Value::Unknown);
    assert_eq!(branches[2].compatible, Probe::ALL);
    assert_eq!(branches[2].known, 0);
    assert_eq!(branches[2].next, Some(Probe::Service));
    assert_eq!(serde_json::to_value(&case).unwrap(), before);
}

#[test]
fn diagnostic_preview_models_contradiction_and_attempt_exhaustion() {
    let now = Utc::now();
    let mut case = real(now);
    let request = case.request(Probe::Service, now).unwrap();
    case.record(&request, Value::Fail, now).unwrap();
    let branches = case.preview(Probe::Dns, now).unwrap();
    assert_eq!(branches[0].compatible, vec![Probe::Service]);
    assert!(branches[1].compatible.is_empty());
    assert_eq!(branches[1].next, None);
    assert!(branches[1].conclusion.starts_with("Keine Hypothese"));
    assert!(case.preview(Probe::Service, now).is_err());

    let mut unavailable = Case::new(config(Scenario::Unavailable), now).unwrap();
    for _ in 0..2 {
        unavailable.simulate(Probe::Service, now).unwrap();
    }
    let branches = unavailable.preview(Probe::Service, now).unwrap();
    assert_eq!(branches[2].next, Some(Probe::Dns));
    assert_eq!(unavailable.observations.len(), 2);
    unavailable.simulate(Probe::Service, now).unwrap();
    assert!(unavailable.preview(Probe::Service, now).is_err());
}

#[test]
fn diagnostic_preview_respects_expiry_and_requires_all_confirmations() {
    let now = Utc::now();
    let mut case = Case::new(config(Scenario::Dns), now).unwrap();
    for probe in [Probe::Service, Probe::Dns, Probe::Tls] {
        case.simulate(probe, now).unwrap();
    }
    let branches = case.preview(Probe::Dependency, now).unwrap();
    assert_eq!(branches[0].known, 4);
    assert_eq!(branches[0].compatible, vec![Probe::Dns]);
    assert!(branches[0].conclusion.contains("kein Nachweis"));
    assert_eq!(branches[1].compatible.len(), 0);
    assert_eq!(branches[2].known, 3);
    assert_eq!(branches[2].next, Some(Probe::Dependency));
    let later = now + chrono::Duration::seconds(301);
    let expired = case.preview(Probe::Service, later).unwrap();
    assert_eq!(expired[2].known, 0);
    assert_eq!(expired[2].compatible, Probe::ALL);
    assert!(
        case.preview(Probe::Dependency, now - chrono::Duration::seconds(1))
            .is_err()
    );
}

fn config(scenario: Scenario) -> Config {
    Config {
        mode: Mode::Simulation,
        scenario: Some(scenario),
        target: None,
        incident: "Application unavailable".into(),
        service: "ExampleSvc".into(),
        application: "https://app.example.invalid/".into(),
        dependency: "https://dependency.example.invalid/health".into(),
    }
}
fn real(now: DateTime<Utc>) -> Case {
    let mut c = config(Scenario::Service);
    c.mode = Mode::ReadOnly;
    c.scenario = None;
    c.target = Some(Target {
        profile_id: Uuid::new_v4(),
        name: "fixture".into(),
        host: "fixture.invalid".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: String::new(),
        domain: String::new(),
        route: String::new(),
    });
    Case::new(c, now).unwrap()
}
#[test]
fn diagnostic_single_fault_requires_all_four_confirmations() {
    for (scenario, cause) in [
        (Scenario::Service, Probe::Service),
        (Scenario::Dns, Probe::Dns),
        (Scenario::Tls, Probe::Tls),
        (Scenario::Dependency, Probe::Dependency),
    ] {
        let now = Utc::now();
        let mut c = Case::new(config(scenario), now).unwrap();
        for index in 0..4 {
            let a = c.assess(now);
            assert_eq!(a.known, index);
            assert!(!a.conclusion().starts_with("Alle vier"));
            c.simulate(a.next.unwrap(), now).unwrap();
        }
        let a = c.assess(now);
        assert_eq!(a.known, 4);
        assert_eq!(a.compatible().len(), 1);
        assert_eq!(a.compatible()[0].cause, cause);
        assert!(a.next.is_none());
        assert!(a.conclusion().contains("kein Nachweis"));
    }
}
#[test]
fn diagnostic_next_check_separates_surviving_pairs() {
    let now = Utc::now();
    let mut c = Case::new(config(Scenario::Dependency), now).unwrap();
    assert_eq!(c.assess(now).pairs, 3);
    c.simulate(Probe::Service, now).unwrap();
    let a = c.assess(now);
    assert_eq!(a.compatible().len(), 3);
    assert_eq!(a.next, Some(Probe::Dns));
    assert_eq!(a.pairs, 2);
}
#[test]
fn diagnostic_multiple_faults_and_healthy_checks_expose_model_gaps() {
    for scenario in [Scenario::Multiple, Scenario::Healthy] {
        let now = Utc::now();
        let mut c = Case::new(config(scenario), now).unwrap();
        while let Some(probe) = c.assess(now).next {
            c.simulate(probe, now).unwrap();
        }
        let a = c.assess(now);
        assert!(a.compatible().is_empty());
        assert!(a.conclusion().contains("Keine Hypothese"));
    }
}
#[test]
fn diagnostic_unknown_attempts_never_count_as_passes() {
    let now = Utc::now();
    let mut c = Case::new(config(Scenario::Unavailable), now).unwrap();
    for _ in 0..12 {
        let next = c.assess(now).next.unwrap();
        c.simulate(next, now).unwrap();
    }
    let a = c.assess(now);
    assert_eq!(a.known, 0);
    assert_eq!(a.compatible().len(), 4);
    assert!(a.next.is_none());
    assert!(a.conclusion().contains("unzureichend"));
    assert!(c.request(Probe::Service, now).is_err());
    assert!(
        c.assess(now + chrono::Duration::seconds(301))
            .next
            .is_some()
    );
}
#[test]
fn diagnostic_freshness_rejects_future_and_expired_evidence() {
    let now = Utc::now();
    let mut c = Case::new(config(Scenario::Service), now).unwrap();
    c.simulate(Probe::Service, now).unwrap();
    assert_eq!(c.assess(now).known, 1);
    assert_eq!(c.assess(now - chrono::Duration::milliseconds(1)).known, 0);
    assert_eq!(
        c.assess(now + chrono::Duration::milliseconds(300001)).known,
        0
    );
    let request = c.request(Probe::Dns, now).unwrap();
    assert!(
        c.record(
            &request,
            Value::Pass,
            now - chrono::Duration::milliseconds(1)
        )
        .is_err()
    );
    assert!(
        c.record(
            &request,
            Value::Pass,
            now + chrono::Duration::milliseconds(180001)
        )
        .is_err()
    );
}
#[test]
fn diagnostic_binding_duplicate_and_origin_guards() {
    let now = Utc::now();
    let mut c = Case::new(config(Scenario::Service), now).unwrap();
    let r = c.request(Probe::Service, now).unwrap();
    c.record(&r, Value::Fail, now).unwrap();
    assert!(c.record(&r, Value::Pass, now).is_err());
    let mut other = Case::new(config(Scenario::Service), now).unwrap();
    assert!(other.record(&r, Value::Fail, now).is_err());
    let mut live = real(now);
    assert!(live.simulate(Probe::Service, now).is_err());
    assert!(live.record(&r, Value::Fail, now).is_err());
    assert!(adapter::build(&c, &r).is_err());
    c.config.scenario = Some(Scenario::Dns);
    assert!(c.validate().is_err());
}
#[test]
fn diagnostic_old_completion_cannot_replace_newer_observation() {
    let now = Utc::now();
    let mut c = Case::new(config(Scenario::Unavailable), now).unwrap();
    let old = c.request(Probe::Service, now).unwrap();
    let new = c
        .request(Probe::Service, now + chrono::Duration::seconds(1))
        .unwrap();
    c.record(&new, Value::Pass, now + chrono::Duration::seconds(2))
        .unwrap();
    c.record(&old, Value::Fail, now + chrono::Duration::seconds(1))
        .unwrap();
    assert_eq!(
        c.fresh(now + chrono::Duration::seconds(3))[&Probe::Service].value,
        Value::Pass
    );
}
#[test]
fn diagnostic_ai_cannot_supply_evidence_commands_or_stale_choices() {
    let now = Utc::now();
    let mut c = Case::new(config(Scenario::Service), now).unwrap();
    let mut p = serde_json::json!({"binding":c.state_binding().unwrap(),"as_of":now,"probe":"Service","rationale":"Unterscheidet die Diensthypothese"});
    let raw = p.to_string();
    assert_eq!(c.proposal(&raw, now).unwrap().probe, Probe::Service);
    assert!(
        c.proposal(&raw, now + chrono::Duration::seconds(121))
            .is_err()
    );
    p["evidence"] = serde_json::json!({"value":"Pass"});
    assert!(c.proposal(&p.to_string(), now).is_err());
    p.as_object_mut().unwrap().remove("evidence");
    p["command"] = "Stop-Service".into();
    assert!(c.proposal(&p.to_string(), now).is_err());
    c.simulate(Probe::Service, now).unwrap();
    assert!(c.proposal(&raw, now).is_err());
    let prompt = c.ai_prompt(now).unwrap();
    assert!(!prompt.contains("fixture.invalid"));
    assert!(!prompt.contains("dependency.example.invalid"));
}
#[test]
fn diagnostic_configuration_rejects_secret_urls_and_code() {
    let mut c = config(Scenario::Service);
    c.validate().unwrap();
    c.dependency = "https://user:secret@example.invalid/".into();
    assert!(c.validate().is_err());
    c.dependency = "https://example.invalid/?token=secret".into();
    assert!(c.validate().is_err());
    c.dependency = "https://example.invalid/".into();
    c.service = "Foo'; Stop-Service Bar".into();
    assert!(c.validate().is_err());
    c.service = "ExampleSvc".into();
    c.application = "https://127.0.0.1/".into();
    assert!(c.validate().is_err());
}
#[test]
fn diagnostic_adapter_rejects_foreign_truncated_and_late_responses() {
    let now = Utc::now();
    let c = real(now);
    let request = c.request(Probe::Service, now).unwrap();
    let mut r=JobResult{status:JobStatus::Completed,stdout:serde_json::json!({"request":request.id,"binding":request.binding,"probe":"Service","value":"Pass"}).to_string(),stderr:String::new(),truncated:false,finished:now.into()};
    assert_eq!(adapter::value(&request, &r).unwrap(), Value::Pass);
    r.truncated = true;
    assert!(adapter::value(&request, &r).is_err());
    r.truncated = false;
    r.finished = (now + chrono::Duration::seconds(181)).into();
    assert!(adapter::value(&request, &r).is_err());
    r.finished = now.into();
    r.stdout = r
        .stdout
        .replace(&request.id.to_string(), &Uuid::new_v4().to_string());
    assert!(adapter::value(&request, &r).is_err());
}
#[test]
#[cfg(windows)]
fn diagnostic_store_roundtrip_corruption_and_concurrent_updates() {
    let dir = std::env::temp_dir().join(format!("relayne-diagnostic-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("book.dpapi");
    let now = Utc::now();
    let mut b = Book::default();
    b.cases
        .push(Case::new(config(Scenario::Service), now).unwrap());
    b.save(&path).unwrap();
    let mut stale = Book::load(&path).unwrap();
    assert_eq!(stale.cases[0].config.mode, Mode::Simulation);
    b.cases[0].simulate(Probe::Service, now).unwrap();
    b.save(&path).unwrap();
    assert!(stale.save(&path).is_err());
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(Book::load(&path).is_err());
    assert!(b.save(&path).is_err());
    std::fs::File::create(&path)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    assert!(Book::load(&path).is_err());
    assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(windows)]
fn execute_fixture(case: &Case, probe: Probe, prefix: &str) -> (Request, JobResult) {
    execute_fixture_with(case, probe, prefix, &[])
}
#[cfg(windows)]
fn execute_fixture_with(
    case: &Case,
    probe: Probe,
    prefix: &str,
    replacements: &[(&str, &str)],
) -> (Request, JobResult) {
    use std::process::{Command, Stdio};
    let request = case.request(probe, Utc::now()).unwrap();
    let mut spec = adapter::build(case, &request).unwrap();
    let transport = r#"
function New-PSSessionOption {param($OpenTimeout,$OperationTimeout) $null}
function Invoke-Command {param($ComputerName,$Authentication,$SessionOption,$ScriptBlock,$ErrorAction) if($ComputerName -ne 'fixture.invalid'){throw 'Unexpected host'}; & $ScriptBlock}
"#;
    for (source, replacement) in replacements {
        assert_eq!(spec.stdin.matches(source).count(), 1);
        spec.stdin = spec.stdin.replace(source, replacement);
    }
    spec.stdin = format!("{transport}\n{prefix}\n{}", spec.stdin);
    let mut child = Command::new(&spec.program)
        .args(&spec.args)
        .env_remove("PSModulePath")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(spec.stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        request,
        JobResult {
            status: JobStatus::Completed,
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::new(),
            truncated: false,
            finished: std::time::SystemTime::now(),
        },
    )
}

#[test]
#[cfg(windows)]
fn diagnostic_dns_and_tls_failures_remain_distinct_from_unavailable_probes() {
    for (scenario, want) in [
        ("success", Value::Pass),
        ("missing", Value::Fail),
        ("timeout", Value::Unknown),
    ] {
        let prefix = format!(
            r#"
$global:scenario='{scenario}'
function New-FixtureDnsTask {{
    if($global:scenario -eq 'missing'){{throw [Net.Sockets.SocketException]::new(11001)}}
    $task=[pscustomobject]@{{Result=@('127.0.0.1')}}
    $task|Add-Member ScriptMethod Wait {{param($timeout) return ($global:scenario -ne 'timeout')}}
    return $task
}}
"#
        );
        let (r, result) = execute_fixture_with(
            &real(Utc::now()),
            Probe::Dns,
            &prefix,
            &[(
                "[Net.Dns]::GetHostAddressesAsync([string]$p.host)",
                "New-FixtureDnsTask",
            )],
        );
        assert_eq!(adapter::value(&r, &result).unwrap(), want, "{scenario}");
    }
    for (scenario, want) in [
        ("success", Value::Pass),
        ("untrusted", Value::Fail),
        ("timeout", Value::Unknown),
        ("unreachable", Value::Unknown),
    ] {
        let prefix = format!(
            r#"
$global:scenario='{scenario}'
function New-FixtureTask {{
    $task=[pscustomobject]@{{}}
    $task|Add-Member ScriptMethod Wait {{param($timeout) return ($global:scenario -ne 'timeout')}}
    return $task
}}
function New-FixtureClient {{
    $client=[pscustomobject]@{{Connected=($global:scenario -ne 'unreachable')}}
    $client|Add-Member ScriptMethod ConnectAsync {{param($server,$port) return (New-FixtureTask)}}
    $client|Add-Member ScriptMethod Dispose {{}}
    return $client
}}
function New-FixtureSsl {{
    $stream=[pscustomobject]@{{IsAuthenticated=$true}}
    $stream|Add-Member ScriptMethod AuthenticateAsClientAsync {{param($server) if($global:scenario -eq 'untrusted'){{throw [Security.Authentication.AuthenticationException]::new('fixture',[Exception]::new('inner'))}};return (New-FixtureTask)}}
    $stream|Add-Member ScriptMethod Dispose {{}}
    return $stream
}}
"#
        );
        let (r, result) = execute_fixture_with(
            &real(Utc::now()),
            Probe::Tls,
            &prefix,
            &[
                ("[Net.Sockets.TcpClient]::new()", "New-FixtureClient"),
                (
                    "[Net.Security.SslStream]::new($client.GetStream(),$false)",
                    "New-FixtureSsl",
                ),
            ],
        );
        assert_eq!(adapter::value(&r, &result).unwrap(), want, "{scenario}");
    }
}
#[test]
#[cfg(windows)]
fn diagnostic_service_adapter_distinguishes_stopped_transient_and_missing() {
    for (state, want) in [
        ("Running", Value::Pass),
        ("Stopped", Value::Fail),
        ("StartPending", Value::Unknown),
        ("Missing", Value::Unknown),
    ] {
        let c = real(Utc::now());
        let prefix = format!(
            "function Get-Service {{ param($Name,$ErrorAction) if($Name -ne 'ExampleSvc'){{throw 'Unexpected service'}};if('{state}' -eq 'Missing'){{throw 'Not available'}};$s=[pscustomobject]@{{Status='{state}'}};$s|Add-Member ScriptMethod Refresh {{}};$s }}"
        );
        let (r, result) = execute_fixture(&c, Probe::Service, &prefix);
        assert_eq!(adapter::value(&r, &result).unwrap(), want);
    }
}
#[test]
#[cfg(windows)]
fn diagnostic_http_adapter_checks_status_without_following_redirects() {
    for (status, want) in [
        (200, Value::Pass),
        (204, Value::Pass),
        (302, Value::Unknown),
        (401, Value::Unknown),
        (503, Value::Fail),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut calls = 0;
            while start.elapsed() < std::time::Duration::from_secs(8) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                            .unwrap();
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf);
                        calls += 1;
                        let response = format!(
                            "HTTP/1.1 {status} Status\r\nLocation: http://127.0.0.1:{}/unexpected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            address.port()
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if calls > 0 && start.elapsed() > std::time::Duration::from_secs(2) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            calls
        });
        let mut c = real(Utc::now());
        c.config.dependency = format!("http://{address}/health");
        let (request, result) = execute_fixture(&c, Probe::Dependency, "");
        assert_eq!(adapter::value(&request, &result).unwrap(), want);
        assert_eq!(
            server.join().unwrap(),
            1,
            "Redirect must not issue a second request"
        );
    }
}
