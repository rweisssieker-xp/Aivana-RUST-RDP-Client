use super::*;
fn request() -> Request {
    Request {
        id: Uuid::new_v4(),
        lab_id: Uuid::new_v4().to_string(),
        vm_id: Uuid::new_v4().to_string(),
        started: Utc::now(),
        spec: Spec {
            service: "ExampleSvc".into(),
            startup: Startup::Manual,
            health: HealthProbe {
                url: "http://127.0.0.1:8080/health".into(),
                expected_status: 200,
                ..Default::default()
            },
        },
    }
}
#[test]
fn trial_spec_rejects_system_services_and_remote_health() {
    let mut r = request();
    r.spec.validate().unwrap();
    r.spec.service = "vmicvmsession".into();
    assert!(r.spec.validate().is_err());
    r.spec.service = "ExampleSvc;Stop-VM".into();
    assert!(r.spec.validate().is_err());
    r.spec.service = "ExampleSvc".into();
    r.spec.health.url = "https://example.com/health".into();
    assert!(r.spec.validate().is_err());
}
#[test]
fn trial_success_requires_fault_and_return_and_deletion() {
    let r = request();
    let p = Proof {
        request_hash: r.hash().unwrap(),
        baseline: true,
        changed: true,
        fault_observed: true,
        repaired: true,
        returned: true,
        checkpoint_removed: true,
        baseline_mode: "Auto".into(),
        stage: "complete".into(),
        ..Default::default()
    };
    p.validate(&r).unwrap();
    assert!(p.passed());
    let mut failed = p.clone();
    failed.returned = false;
    assert!(!failed.passed());
    assert!(failed.validate(&r).is_err());
    failed = p.clone();
    failed.fault_observed = false;
    assert!(failed.validate(&r).is_err());
    failed = p.clone();
    failed.checkpoint_removed = false;
    assert!(!failed.passed());
    assert!(!failed.settled());
    failed = p;
    failed.untouched = true;
    assert!(failed.validate(&r).is_err());
}
#[test]
fn trial_binding_covers_target_change_and_health() {
    let mut r = request();
    let hash = r.hash().unwrap();
    r.spec.startup = Startup::Automatic;
    assert_ne!(hash, r.hash().unwrap());
    let hash = r.hash().unwrap();
    r.vm_id = Uuid::new_v4().to_string();
    assert_ne!(hash, r.hash().unwrap());
    let hash = r.hash().unwrap();
    r.spec.health.body_marker = "ready".into();
    assert_ne!(hash, r.hash().unwrap());
}
#[test]
fn trial_interruption_never_counts_as_success_or_settlement() {
    let r = request();
    let mut record = Record {
        request: r.clone(),
        proof: None,
        recovered: false,
    };
    assert!(record.unresolved());
    record.proof = Some(Proof {
        request_hash: r.hash().unwrap(),
        stage: "baseline".into(),
        untouched: true,
        ..Default::default()
    });
    assert!(!record.unresolved());
    assert!(!record.proof.as_ref().unwrap().passed());
    record.proof.as_mut().unwrap().untouched = false;
    assert!(record.unresolved());
    record.recovered = true;
    assert!(!record.unresolved());
}

// Doubles replace only external VM/guest calls. The actual checkpoint lifecycle,
// exception handling, DPAPI baseline and receipt serialization run in PowerShell.
#[cfg(windows)]
const DOUBLES: &str = r#"
function Owned-VM { [pscustomobject]@{CheckpointType='Standard';State='Running'} }
function Get-VMSnapshot { param([Parameter(ValueFromPipeline=$true)]$InputObject) process {if($global:trialSnapshot){$global:trialSnapshot}} }
function Checkpoint-VM {param([Parameter(ValueFromPipeline=$true)]$InputObject,$SnapshotName) process {$global:trialSnapshot=[pscustomobject]@{Name=$SnapshotName};$global:restored=$false} }
function Restore-VMSnapshot {param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm) process {if($p.scenario -eq 'return-failure'){throw 'synthetic restore failure'};$global:restored=$true} }
function Remove-VMSnapshot {param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm) process {if(!$global:restored){throw 'Cannot remove before restore'};if($p.scenario -eq 'delete-failure'){throw 'synthetic deletion failure'};$global:trialSnapshot=$null} }
function Guest-Step($mode,$original){
    if($p.scenario -eq $mode){throw 'synthetic guest failure'}
    if($mode -eq 'return' -and (!$global:restored -or $original -ne 'Auto')){throw 'Incorrect return'}
    [pscustomobject]@{ok=$true;startup='Auto'}
}
if($p.recover){$global:trialSnapshot=[pscustomobject]@{Name=[string]$p.checkpoint};$global:restored=$false}
"#;

#[test]
#[cfg(windows)]
fn trial_adapter_records_actual_stages_and_always_attempts_return() {
    for scenario in [
        "success",
        "baseline",
        "change",
        "fault",
        "repair",
        "return-failure",
        "delete-failure",
    ] {
        let r = request();
        let dir = std::env::temp_dir().join(format!("relayne-trial-fixture-{}", r.id));
        std::fs::create_dir_all(dir.join("receipts/change-trials")).unwrap();
        let script = include_str!("change_trial.ps1").replace(
            "try {\n    if($r.vm_id",
            &format!("{DOUBLES}\ntry {{\n    if($r.vm_id"),
        );
        let script = script.replace("# Persist only a bounded stage, never raw guest errors, credentials or response bodies.", "if($p.scenario -eq 'success'){throw}");
        assert!(script.contains("function Guest-Step($mode,$original){\n    if($p.scenario"));
        let payload = serde_json::json!({"lab":{"id":r.lab_id,"vm_id":r.vm_id,"directory":dir},"request":r,"hash":r.hash().unwrap(),"checkpoint":r.checkpoint_name(),"user":"fixture-user","password":"fixture-secret","recover":false,"scenario":scenario});
        let output = run_script(&script, payload).unwrap();
        assert!(!output.contains("fixture-secret"));
        let proof: Proof = serde_json::from_str(&output).unwrap();
        proof.validate(&r).unwrap();
        assert_eq!(
            proof.passed(),
            scenario == "success",
            "{scenario}: {output}"
        );
        match scenario {
            "baseline" => assert!(proof.untouched && !proof.baseline),
            "change" => assert!(!proof.changed && proof.returned && proof.checkpoint_removed),
            "fault" => assert!(proof.changed && !proof.fault_observed && proof.returned),
            "repair" => assert!(proof.fault_observed && !proof.repaired && proof.returned),
            "return-failure" => {
                assert!(proof.repaired && !proof.returned && !proof.checkpoint_removed)
            }
            "delete-failure" => {
                assert!(proof.returned && !proof.checkpoint_removed && !proof.settled())
            }
            _ => assert!(proof.settled()),
        }
        if scenario == "return-failure" {
            let restored: Proof = serde_json::from_str(&run_script(&script,serde_json::json!({"lab":{"id":r.lab_id,"vm_id":r.vm_id,"directory":dir},"request":r,"hash":r.hash().unwrap(),"checkpoint":r.checkpoint_name(),"user":"fixture-user","password":"fixture-secret","recover":true,"scenario":"success"})).unwrap()).unwrap();
            restored.validate(&r).unwrap();
            assert!(restored.returned && restored.checkpoint_removed);
            assert!(
                !restored.passed(),
                "A separate return cannot turn a failed trial into a passed trial"
            );
        }
        // Exact UUID-owned temporary fixture only.
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
#[cfg(windows)]
fn trial_history_fails_closed_on_corruption_and_binds_restore_to_request() {
    let mut r = request();
    let dir = root().unwrap().join(&r.lab_id);
    std::fs::create_dir_all(&dir).unwrap();
    let j = Journal {
        id: r.lab_id.clone(),
        name: format!("Relayne-Lab-{}", r.lab_id),
        template: "fixture.vhdx".into(),
        directory: dir.to_string_lossy().into(),
        vm_id: r.vm_id.clone(),
        switch_id: Uuid::new_v4().to_string(),
        phase: "running".into(),
        detail: String::new(),
    };
    write_immutable(&dir.join("journal.dpapi"), &j).unwrap();
    let store = directory(&r.lab_id).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    let request_path = store.join(format!("{}.request.dpapi", r.id));
    write_immutable(&request_path, &r).unwrap();
    assert!(history(&r.lab_id).unwrap()[0].unresolved());
    // A pending run blocks execution before any PowerShell process can start.
    assert!(
        run(
            j.clone(),
            r.spec.clone(),
            "fixture".into(),
            "fixture".into()
        )
        .unwrap_err()
        .to_string()
        .contains("Offenen Versuch")
    );
    let restore_path = store.join(format!("{}.restore.dpapi", r.id));
    r.spec.startup = Startup::Automatic;
    write_immutable(
        &restore_path,
        &Restoration {
            request_hash: r.hash().unwrap(),
            finished: Utc::now(),
        },
    )
    .unwrap();
    assert!(history(&r.lab_id).is_err());
    std::fs::remove_file(restore_path).unwrap();
    std::fs::write(request_path, b"corrupt").unwrap();
    assert!(history(&r.lab_id).is_err());
    assert_eq!(dir.parent(), Some(root().unwrap().as_path()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[cfg(windows)]
fn trial_guest_runs_real_http_and_service_state_verification() {
    const GUEST_DOUBLES: &str = r#"
$global:fakeMode='Auto'
$global:fakeService=[pscustomobject]@{Name='ExampleSvc';Status='Running';DependentServices=@();ServicesDependedOn=@()}
$global:fakeService|Add-Member ScriptMethod Refresh {}
$global:fakeService|Add-Member ScriptMethod WaitForStatus {param($wanted,$timeout) if([string]$this.Status -ne [string]$wanted){throw 'Wrong fixture service state'}}
function Get-Service {param($Name) if($Name -ne 'ExampleSvc'){throw 'Unexpected service'};$global:fakeService}
function Get-CimInstance {param($ClassName,$Filter) [pscustomobject]@{StartMode=$global:fakeMode}}
function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction) [pscustomobject]@{DelayedAutoStart=0}}
function Set-Service {param($Name,$StartupType) $global:fakeMode=if($StartupType -eq 'Automatic'){'Auto'}else{'Manual'}}
function Stop-Service {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$InputObject.Status='Stopped'}}
function Start-Service {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$InputObject.Status='Running'}}
function Invoke-Command {param($VMId,$Credential,$ScriptBlock,$ArgumentList) & $ScriptBlock @ArgumentList}
function Guest-Step($mode,$original){
    $result=Invoke-Command -VMId ([guid]$j.vm_id) -Credential $credential -ScriptBlock $guest -ArgumentList $r.spec.service,$r.spec.health,$mode,$r.spec.startup,$original
    if(!$result.ok){throw 'Missing actual guest result'};return $result
}
function Restore-VMSnapshot {param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm) process {$global:fakeMode='Auto';$global:fakeService.Status='Running';$global:restored=$true}}
"#;
    for (fault_healthy, return_unhealthy) in [(false, false), (true, false), (false, true)] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let server_running = running.clone();
        let server = std::thread::spawn(move || {
            let mut calls = 0;
            let started = Instant::now();
            while server_running.load(std::sync::atomic::Ordering::Relaxed)
                && started.elapsed() < Duration::from_secs(60)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf);
                        let status =
                            if (calls == 2 && !fault_healthy) || (calls >= 4 && return_unhealthy) {
                                "503 Unavailable"
                            } else {
                                "200 OK"
                            };
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        calls += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            calls
        });
        let mut r = request();
        r.spec.health.url = format!("http://{addr}/health");
        let dir = std::env::temp_dir().join(format!("relayne-trial-guest-{}", r.id));
        std::fs::create_dir_all(dir.join("receipts/change-trials")).unwrap();
        let script = include_str!("change_trial.ps1").replace(
            "try {\n    if($r.vm_id",
            &format!("{DOUBLES}\n{GUEST_DOUBLES}\ntry {{\n    if($r.vm_id"),
        );
        let script = if !fault_healthy && !return_unhealthy {
            script.replace("# Persist only a bounded stage, never raw guest errors, credentials or response bodies.", "throw")
        } else {
            script
        };
        let output = run_script(
            &script,
            serde_json::json!({"lab":{"id":r.lab_id,"vm_id":r.vm_id,"directory":dir},"request":r,"hash":r.hash().unwrap(),"checkpoint":r.checkpoint_name(),"user":"fixture-user","password":"fixture-secret","recover":false}),
        );
        running.store(false, std::sync::atomic::Ordering::Relaxed);
        let calls = server.join().unwrap();
        let output = output.unwrap();
        let proof: Proof = serde_json::from_str(&output).unwrap();
        proof.validate(&r).unwrap();
        assert_eq!(
            proof.passed(),
            !fault_healthy && !return_unhealthy,
            "{output}"
        );
        assert_eq!(
            calls,
            if return_unhealthy {
                9
            } else if fault_healthy {
                4
            } else {
                5
            },
            "{output}"
        );
        assert_eq!(proof.returned, !return_unhealthy, "{output}");
        assert_eq!(proof.checkpoint_removed, !return_unhealthy, "{output}");
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
#[cfg(windows)]
fn trial_rejects_foreign_topology_before_guest_or_checkpoint_actions() {
    const TOPOLOGY: &str = r#"
function Get-VM {param($Id) [pscustomobject]@{Name=$(if($p.scenario -eq 'name'){'Foreign'}else{$j.name});Notes=$j.id;State='Running';CheckpointType=$(if($p.scenario -eq 'production'){'Production'}else{'Standard'})}}
function Get-VMNetworkAdapter {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {[pscustomobject]@{SwitchId=$j.switch_id;VMId=$j.vm_id};if($p.scenario -eq 'adapter'){[pscustomobject]@{SwitchId=$j.switch_id;VMId=$j.vm_id}}}}
function Get-VMSwitch {param($Id) [pscustomobject]@{Name=$j.name;SwitchType=$(if($p.scenario -eq 'switch'){'External'}else{'Private'})}}
function Get-VMHardDiskDrive {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {[pscustomobject]@{Path=$(if($p.scenario -eq 'disk'){'C:\foreign.vhdx'}else{Join-Path $j.directory 'child.vhdx'})}}}
function Get-VHD {param($Path) [pscustomobject]@{ParentPath=$(if($p.scenario -eq 'template'){'foreign.vhdx'}else{$j.template})}}
function Guest-Step($mode,$original){$global:forbiddenCall=$true;throw 'Guest must not run for rejected topology'}
function Checkpoint-VM {$global:forbiddenCall=$true;throw 'Checkpoint must not run for rejected topology'}
"#;
    for scenario in [
        "name",
        "adapter",
        "switch",
        "disk",
        "template",
        "production",
    ] {
        let r = request();
        let dir = std::env::temp_dir().join(format!("relayne-trial-topology-{}", r.id));
        std::fs::create_dir_all(dir.join("receipts/change-trials")).unwrap();
        std::fs::write(dir.join("child.vhdx"), b"fixture").unwrap();
        let doubles = DOUBLES.replace(
            "function Owned-VM { [pscustomobject]@{CheckpointType='Standard';State='Running'} }",
            "",
        );
        let script=include_str!("change_trial.ps1").replace("try {\n    if($r.vm_id",&format!("{doubles}\n{TOPOLOGY}\ntry {{\n    if($r.vm_id")).replace("$proof|ConvertTo-Json -Compress", "if($global:forbiddenCall){throw 'Guard allowed forbidden call'}\n$proof|ConvertTo-Json -Compress");
        let output=run_script(&script,serde_json::json!({"lab":{"id":r.lab_id,"vm_id":r.vm_id,"directory":dir,"name":"Owned","switch_id":Uuid::new_v4(),"template":"fixture.vhdx"},"request":r,"hash":r.hash().unwrap(),"checkpoint":r.checkpoint_name(),"user":"fixture","password":"fixture","recover":false,"scenario":scenario})).unwrap();
        let proof: Proof = serde_json::from_str(&output).unwrap();
        proof.validate(&r).unwrap();
        assert!(
            proof.untouched && !proof.baseline && !proof.passed(),
            "{scenario}: {output}"
        );
        assert!(
            !dir.join(format!("receipts/change-trials/{}.baseline.dpapi", r.id))
                .exists()
        );
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
