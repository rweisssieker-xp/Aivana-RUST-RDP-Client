//! Tests run generated service code only against in-process PowerShell fakes.
//! The WinRM wrapper is never executed; no real service cmdlet is invoked.
use crate::intelligence::{self as intel, Knowledge, Repair, ServiceState};
use crate::mission::Target;
use uuid::Uuid;
fn target() -> Target {
    Target {
        profile_id: Uuid::new_v4(),
        name: "fixture".into(),
        host: "example.invalid".into(),
        port: 3389,
        protocol: "RDP".into(),
        username: String::new(),
        domain: String::new(),
        route: String::new(),
    }
}
fn repair(status: &str) -> Repair {
    Repair {
        id: Uuid::new_v4(),
        target: target(),
        service: "RelayneFixture".into(),
        before: ServiceState::Stopped,
        desired: ServiceState::Running,
        captured: chrono::Utc::now(),
        status: status.into(),
        evidence: None,
    }
}
#[cfg(windows)]
fn fake_service_run(scenario: &str) -> serde_json::Value {
    use base64::Engine;
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    assert!(
        [
            "success",
            "changed",
            "apply_failure",
            "restore_failure",
            "dependent",
            "prerequisite"
        ]
        .contains(&scenario)
    );
    let spec = intel::service_spec(
        &target(),
        "RelayneFixture",
        Some((ServiceState::Stopped, ServiceState::Running)),
    )
    .unwrap();
    let body = spec
        .stdin
        .split_once("-ScriptBlock { $ErrorActionPreference='Stop'; ")
        .expect("known wrapper")
        .1
        .rsplit_once(" } -ErrorAction Stop | ConvertTo-Json")
        .expect("known wrapper end")
        .0;
    assert!(!body.contains("Invoke-Command"));
    let fixture = r#"
$ErrorActionPreference='Stop'
$global:Calls=[System.Collections.Generic.List[string]]::new()
$global:FakeService=[pscustomobject]@{Name='RelayneFixture';Status='Stopped';DependentServices=@();ServicesDependedOn=@()}
if($global:Scenario -eq 'changed'){$global:FakeService.Status='Running'}
if($global:Scenario -eq 'dependent'){$global:FakeService.DependentServices=@([pscustomobject]@{Name='Dependent';Status='Running'})}
if($global:Scenario -eq 'prerequisite'){$global:FakeService.ServicesDependedOn=@([pscustomobject]@{Name='Dependency';Status='Stopped'})}
$global:FakeService | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
$global:FakeService | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {param($wanted,$timeout) if($this.Status -ne $wanted){throw 'fixture wait mismatch'}}
function Get-Service {param($Name,$ErrorAction) if($Name -ne 'RelayneFixture'){throw 'invalid fixture name'};return $global:FakeService}
function Start-Service {param($InputObject,$ErrorAction) $global:Calls.Add('Start');$InputObject.Status='Running';if($global:Scenario -in @('apply_failure','restore_failure')){throw 'fixture partial apply failure'}}
function Stop-Service {param($InputObject,$ErrorAction) $global:Calls.Add('Stop');if($global:Scenario -eq 'restore_failure'){throw 'fixture restore failure'};$InputObject.Status='Stopped'}
foreach($name in @('Get-Service','Start-Service','Stop-Service')) {if((Get-Command $name).CommandType -ne 'Function'){throw 'fake service guard failed'}}
"#;
    let script = format!(
        "$global:Scenario='{scenario}'\n{fixture}\ntry {{$result=& {{ {body} }};[pscustomobject]@{{result=$result;calls=@($global:Calls.ToArray());state=$global:FakeService.Status;error=''}}|ConvertTo-Json -Depth 6 -Compress}}catch{{[pscustomobject]@{{result=$null;calls=@($global:Calls.ToArray());state=$global:FakeService.Status;error=$_.Exception.Message}}|ConvertTo-Json -Depth 6 -Compress}}"
    );
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut child = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded,
        ])
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("local PowerShell fixture");
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fixture timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}
#[cfg(windows)]
#[test]
fn generated_service_script_executes_success_and_both_failure_paths() {
    let success = fake_service_run("success");
    assert_eq!(success["calls"], serde_json::json!(["Start"]));
    assert_eq!(success["result"]["verified"], true);
    assert_eq!(success["state"], "Running");
    let restored = fake_service_run("apply_failure");
    assert_eq!(restored["calls"], serde_json::json!(["Start", "Stop"]));
    assert_eq!(restored["result"]["rollbackVerified"], true);
    assert_eq!(restored["state"], "Stopped");
    let mut r = repair("Läuft");
    r.assess(&restored["result"].to_string()).unwrap();
    assert!(r.status.contains("restored"));
    let failed = fake_service_run("restore_failure");
    assert_eq!(failed["calls"], serde_json::json!(["Start", "Stop"]));
    assert_eq!(failed["result"]["rollbackVerified"], false);
    r.assess(&failed["result"].to_string()).unwrap();
    assert!(r.status.starts_with("Unresolved"));
}
#[cfg(windows)]
#[test]
fn generated_preconditions_block_all_mutations() {
    for scenario in ["changed", "dependent", "prerequisite"] {
        let result = fake_service_run(scenario);
        assert_eq!(result["calls"], serde_json::json!([]));
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("no mutation attempted"),
            "{result}"
        );
    }
}
#[cfg(windows)]
#[test]
fn restart_invalidates_running_and_preflight_journals() {
    let path =
        std::env::temp_dir().join(format!("relayne-repair-fixture-{}.dpapi", Uuid::new_v4()));
    let k = Knowledge {
        repairs: vec![
            repair("Läuft"),
            repair("Vorprüfung bestätigt"),
            repair("Zustand technisch bestätigt"),
        ],
        ..Default::default()
    };
    k.save(&path).unwrap();
    let loaded = Knowledge::load(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(loaded.repairs[0].status.contains("Unresolved"));
    assert!(loaded.repairs[1].status.contains("Unresolved"));
    assert_eq!(loaded.repairs[2].status, "Zustand technisch bestätigt");
}
#[test]
fn dependency_hypothesis_requires_two_failures_with_evidence() {
    use crate::mission::{Evidence, Mission, MissionBook, Status, Step};
    let a = target();
    let b = target();
    let dep = intel::Dependency {
        dependent: a.profile_id,
        prerequisite: b.profile_id,
        reason: "Application needs database".into(),
    };
    let mut m = Mission::new("fixture", vec![a.clone(), b.clone()], vec![Step::default()]).unwrap();
    let ea = Evidence::new(a, "fixture", Default::default(), "A failed");
    let eb = Evidence::new(b, "fixture", Default::default(), "B failed");
    m.outcomes[0].status = Status::Failed;
    m.outcomes[1].status = Status::Failed;
    let mut book = MissionBook {
        missions: vec![m],
        ..Default::default()
    };
    assert!(intel::candidates(&book, &[dep.clone()]).is_empty());
    book.missions[0].outcomes[0].evidence.push(ea.id);
    book.missions[0].evidence.push(ea);
    assert!(intel::candidates(&book, &[dep.clone()]).is_empty());
    book.missions[0].outcomes[1].evidence.push(eb.id);
    book.missions[0].evidence.push(eb);
    let c = intel::candidates(&book, &[dep.clone()]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].evidence.len(), 2);
    assert!(c[0].explanation.contains("Hypothesis"));
    book.missions[0].outcomes[1].status = Status::Passed;
    assert!(intel::candidates(&book, &[dep]).is_empty());
}
