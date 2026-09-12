mod ai;
mod app;
mod autopilot;
mod certificate;
mod change_history;
mod computer_use;
mod connection_options;
mod diagnostics;
mod equivalence;
mod execution;
mod incident;
mod integrations;
mod intelligence;
#[cfg(test)]
mod intelligence_tests;
mod ironrdp_client;
mod legacy_rdp;
mod memory;
mod mission;
mod models;
#[cfg(windows)]
mod native_remoteapp;
mod operations;
mod package_trust;
mod policy;
mod profile_exchange;
mod promotion;
mod rd_gateway;
mod rdp_audio_input;
mod rdp_audio_output;
mod rdp_channels;
mod rdp_drives;
mod recommendations;
mod recording;
mod recovery;
mod remoteapp;
mod runbook;
mod security;
mod services;
mod teaching;
mod team_client;
mod team_server;
mod telemetry;
mod terminal;
mod test_lab;
mod timeline;
mod transferable;
mod vision;
mod workflow;
mod workspace;

use app::AivanaApp;

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn build_cli_help() -> &'static str {
    r#"Relayne

Usage:
  cargo run                       Launch the GUI
  cargo run -- <command>          Run a headless operator command

Headless KI / RDP commands:
  --save-ki-preferences           Persist current/default KI preferences for headless readiness
  --ki-readiness-report           Print and save OpenAI/RDP/KI readiness JSON
  --command-index                 Print a machine-readable JSON command catalog
  --ai-brief-pack                 Print and save redacted AI/KI brief pack JSON
  --ki-evidence-bundle            Print and save redacted readiness and evidence bundle JSON
  --completion-audit              Print and save prompt-to-artifact completion audit JSON
  --goal-evidence-matrix          Print and save requirement-to-artifact evidence matrix JSON
  --goal-evidence-check           Print final goal evidence check JSON and fail while blocked
  --next-live-gate                Print the first blocking live gate and exact next commands
  --next-live-gate-json           Print the first blocking live gate as structured JSON
  --live-gate-sequence            Print the ordered live-gate command sequence
  --live-gate-doctor              Print and save env/preflight/smoke/handoff ladder JSON
  --live-gate-operator-brief      Print and save concise live-gate operator brief Markdown
  --rdp-proof-check               Print and save direct RDP proof checklist JSON
  --rdp-proof-prompt              Print and save no-secrets RDP proof prompt Markdown
  --rdp-proof-recovery-plan       Print and save RDP proof recovery plan Markdown
  --live-gate-runbook             Print and save the live-gate operator runbook Markdown
  --llm-review-prompt             Print and save the LLM reviewer prompt Markdown
  --llm-live-gate-plan            Print and save LLM/CI live-gate instruction plan Markdown
  --llm-action-contract           Print and save machine-readable LLM next-action contract JSON
  --rdp-env-fill-guide            Print and save local rdp-live.env fill guide Markdown
  --gui-operator-actions          Print and save GUI operator action checklist Markdown
  --operator-handoff-pack         Save readiness, audit, runbook, env template, LLM prompt, summary, and manifest
  --operator-handoff-check        Validate the latest operator handoff pack JSON
  --operator-handoff-risk-summary Print and save compact live-gate/handoff risk JSON
  --verification-snapshot         Print and save compact GUI/live-gate/handoff snapshot JSON
  --live-gate                     Run preflight, optional smoke test, readiness, audit, and live-gate report
  --rdp-env-template              Print a redacted AIVANA_RDP_TEST_* environment starter
  --save-rdp-env-template <path>  Save a redacted RDP .env starter without overwriting an existing file
  --rdp-env-file-check            Validate --rdp-env-file values without DNS/TCP or RDP connect
  --rdp-preflight                 Validate AIVANA_RDP_TEST_* environment, DNS/TCP, and timeout readiness
  --rdp-smoke-test                Connect to the configured RDP host and persist framebuffer/input evidence

Options:
  --rdp-smoke-timeout <seconds>   Override smoke/preflight timeout, clamped to 5-600 seconds
  --rdp-env-file <path>           Read AIVANA_RDP_TEST_* values from a .env file for readiness and live RDP checks
  --help, --ai-help               Show this command reference

Live gate requirement:
  Completion stays false until persisted RDP smoke evidence shows connected=true against a reachable host."#
}

fn cli_arg_value(args: &[String], name: &str) -> Option<String> {
    for index in 0..args.len() {
        let arg = &args[index];
        if arg == name {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
}

fn main() -> eframe::Result<()> {
    install_rustls_crypto_provider();

    let args = std::env::args().collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "--ai-help") {
        println!("{}", build_cli_help());
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--command-index") {
        println!(
            "{}",
            serde_json::to_string_pretty(&app::build_command_index())
                .expect("serialize command index")
        );
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--save-ki-preferences") {
        match app::save_ki_preferences_headless() {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("serialize KI preferences save report")
                );
                return Ok(());
            }
            Err(err) => {
                eprintln!("KI preferences save failed: {err}");
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|arg| arg == "--ai-brief-pack") {
        match app::build_ai_brief_pack_report() {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("serialize AI brief pack report")
                );
                return Ok(());
            }
            Err(err) => {
                eprintln!("AI brief pack export failed: {err}");
                std::process::exit(1);
            }
        }
    }

    if let Some(path) = cli_arg_value(&args, "--save-rdp-env-template") {
        match app::save_rdp_live_gate_env_template_to(std::path::Path::new(&path)) {
            Ok(path) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema": "aivana.rdp-env-template-save.v1",
                        "path": path.display().to_string(),
                        "created": true,
                        "redacted": true,
                        "overwrote_existing_file": false
                    }))
                    .expect("serialize rdp env template save report")
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema": "aivana.rdp-env-template-save.v1",
                        "path": path,
                        "created": false,
                        "redacted": true,
                        "overwrote_existing_file": false,
                        "error": error.to_string()
                    }))
                    .expect("serialize rdp env template save error")
                );
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|arg| arg == "--rdp-env-template") {
        println!("{}", app::build_rdp_live_gate_env_template());
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--rdp-env-fill-guide") {
        let mut guide = app::build_rdp_env_fill_guide();
        if let Ok(path) = app::save_rdp_env_fill_guide() {
            guide.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{guide}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--rdp-env-file-check") {
        let timeout_secs = ironrdp_client::rdp_smoke_timeout_secs_from_args(&args);
        let mut report = ironrdp_client::rdp_env_file_check_report_from_args(&args, timeout_secs);
        if let Ok(path) = ironrdp_client::save_rdp_env_file_check_report(&report) {
            report.evidence_path = Some(path.display().to_string());
            let _ = ironrdp_client::save_rdp_env_file_check_report(&report);
        }
        let json = serde_json::to_string_pretty(&report).expect("serialize rdp env file check");
        if report.ok {
            println!("{json}");
            return Ok(());
        }
        eprintln!("{json}");
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--next-live-gate-json") {
        let report = app::build_completion_audit_report_from_args(&args);
        println!(
            "{}",
            serde_json::to_string_pretty(&app::build_next_live_gate_report_from_args(
                &report, &args
            ))
            .expect("serialize next live gate report")
        );
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--live-gate-sequence") {
        let report = app::build_completion_audit_report_from_args(&args);
        println!("{}", app::build_live_gate_command_sequence(&report));
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--live-gate-doctor") {
        let mut report = app::build_live_gate_doctor_report_from_args(&args);
        if let Ok(path) = app::save_live_gate_doctor_report(&report) {
            report.evidence_path = Some(path.display().to_string());
            let _ = app::save_live_gate_doctor_report(&report);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize live gate doctor")
        );
        if report.achieved {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--live-gate-operator-brief") {
        let audit = app::build_completion_audit_report_from_args(&args);
        let doctor = app::build_live_gate_doctor_report_from_args(&args);
        let mut brief = app::build_live_gate_operator_brief(&audit, &doctor);
        if let Ok(path) = app::save_live_gate_operator_brief(&audit, &brief) {
            brief.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{brief}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--rdp-proof-prompt") {
        let audit = app::build_completion_audit_report_from_args(&args);
        let doctor = app::build_live_gate_doctor_report_from_args(&args);
        let snapshot = app::build_verification_snapshot_from_args(&args);
        let mut prompt = app::build_rdp_proof_prompt(&audit, &doctor, &snapshot);
        if let Ok(path) = app::save_rdp_proof_prompt(&audit, &prompt) {
            prompt.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{prompt}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--rdp-proof-recovery-plan") {
        let audit = app::build_completion_audit_report_from_args(&args);
        let doctor = app::build_live_gate_doctor_report_from_args(&args);
        let proof_check = app::build_rdp_proof_check_from_args(&args);
        let mut plan = app::build_rdp_proof_recovery_plan(&audit, &doctor, &proof_check);
        if let Ok(path) = app::save_rdp_proof_recovery_plan(&audit, &plan) {
            plan.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{plan}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--rdp-proof-check") {
        let check = app::build_rdp_proof_check_from_args(&args);
        let path = app::save_rdp_proof_check(&check).ok();
        let ok = check
            .get("ok")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let mut json = check;
        if let Some(path) = path {
            json["evidence_path"] = serde_json::Value::String(path.display().to_string());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialize rdp proof check")
        );
        if ok {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--next-live-gate") {
        let report = app::build_completion_audit_report_from_args(&args);
        let mut summary = app::build_next_live_gate_summary(&report);
        if let Ok(path) = app::save_next_live_gate_summary(&report) {
            summary.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{summary}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--live-gate-runbook") {
        let report = app::build_completion_audit_report_from_args(&args);
        let path = app::save_live_gate_runbook(&report).ok();
        let mut runbook = app::build_live_gate_runbook(&report);
        if let Some(path) = path {
            runbook.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{runbook}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--llm-review-prompt") {
        let readiness = app::build_ki_readiness_cli_report();
        let audit = app::build_completion_audit_report_from_args(&args);
        let runbook = app::build_live_gate_runbook(&audit);
        let mut prompt = app::build_operator_llm_review_prompt(&readiness, &audit, &runbook);
        if let Ok(path) = app::save_operator_llm_review_prompt(&audit, &prompt) {
            prompt.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{prompt}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--llm-live-gate-plan") {
        let audit = app::build_completion_audit_report_from_args(&args);
        let doctor = app::build_live_gate_doctor_report_from_args(&args);
        let runbook = app::build_live_gate_runbook(&audit);
        let mut plan = app::build_live_gate_llm_plan(&audit, &doctor, &runbook);
        if let Ok(path) = app::save_live_gate_llm_plan(&audit, &plan) {
            plan.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{plan}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--llm-action-contract") {
        let contract = app::build_llm_action_contract_from_args(&args);
        let path = app::save_llm_action_contract(&contract).ok();
        let ok = contract
            .get("ok")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let mut json = contract;
        if let Some(path) = path {
            json["evidence_path"] = serde_json::Value::String(path.display().to_string());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialize LLM action contract")
        );
        if ok {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--gui-operator-actions") {
        let audit = app::build_completion_audit_report_from_args(&args);
        let mut actions = app::build_gui_operator_actions(&audit);
        if let Ok(path) = app::save_gui_operator_actions(&audit, &actions) {
            actions.push_str(&format!("\nSaved: {}\n", path.display()));
        }
        println!("{actions}");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--operator-handoff-pack") {
        match app::build_operator_handoff_pack_report_from_args(&args) {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("serialize operator handoff pack report")
                );
                return Ok(());
            }
            Err(err) => {
                eprintln!("operator handoff pack failed: {err}");
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|arg| arg == "--operator-handoff-check") {
        let check = app::build_operator_handoff_pack_check();
        println!(
            "{}",
            serde_json::to_string_pretty(&check).expect("serialize operator handoff check")
        );
        if !check.ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args
        .iter()
        .any(|arg| arg == "--operator-handoff-risk-summary")
    {
        let summary = app::build_operator_handoff_risk_summary_from_args(&args);
        let path = app::save_operator_handoff_risk_summary(&summary).ok();
        let ok = summary.ok;
        let mut json =
            serde_json::to_value(summary).expect("serialize operator handoff risk summary value");
        if let Some(path) = path {
            json["evidence_path"] = serde_json::Value::String(path.display().to_string());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialize operator handoff risk summary")
        );
        if ok {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--verification-snapshot") {
        let snapshot = app::build_verification_snapshot_from_args(&args);
        let path = app::save_verification_snapshot(&snapshot).ok();
        let ok = snapshot
            .get("ok")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let mut json =
            serde_json::to_value(snapshot).expect("serialize verification snapshot value");
        if let Some(path) = path {
            json["evidence_path"] = serde_json::Value::String(path.display().to_string());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialize verification snapshot")
        );
        if ok {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--live-gate") {
        let timeout_secs = ironrdp_client::rdp_smoke_timeout_secs_from_args(&args);
        let mut report = app::run_live_gate_report_from_profile_result_with_args(
            timeout_secs,
            ironrdp_client::rdp_test_profile_from_args(&args),
            &args,
        );
        if let Ok(path) = app::save_live_gate_report(&report) {
            report.evidence_path = Some(path.display().to_string());
            let _ = app::save_live_gate_report(&report);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize live gate report")
        );
        if report.achieved {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--completion-audit") {
        let mut report = app::build_completion_audit_report_from_args(&args);
        if let Ok(path) = app::save_completion_audit_report(&report) {
            report.audit_path = Some(path.display().to_string());
            let _ = app::save_completion_audit_report(&report);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize completion audit report")
        );
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--goal-evidence-matrix") {
        let report = app::build_completion_audit_report_from_args(&args);
        let matrix = app::build_goal_evidence_matrix_from_args(&report, &args);
        let path = app::save_goal_evidence_matrix_from_args(&report, &args).ok();
        let mut json = serde_json::to_value(matrix).expect("serialize goal evidence matrix value");
        if let Some(path) = path {
            json["evidence_path"] = serde_json::Value::String(path.display().to_string());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialize goal evidence matrix")
        );
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--goal-evidence-check") {
        let report = app::build_completion_audit_report_from_args(&args);
        let check = app::build_goal_evidence_check_from_args(&report, &args);
        let path = app::save_goal_evidence_check_from_args(&report, &args).ok();
        let ok = check
            .get("ok")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let mut json = serde_json::to_value(check).expect("serialize goal evidence check value");
        if let Some(path) = path {
            json["evidence_path"] = serde_json::Value::String(path.display().to_string());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialize goal evidence check")
        );
        if ok {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--ki-evidence-bundle") {
        let mut report = app::build_ki_evidence_bundle_report_from_args(&args);
        if let Ok(path) = app::save_ki_evidence_bundle_report(&report) {
            report.bundle_path = Some(path.display().to_string());
            let _ = app::save_ki_evidence_bundle_report(&report);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize KI evidence bundle report")
        );
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--ki-readiness-report") {
        let mut report = app::build_ki_readiness_cli_report_from_args(&args);
        if let Ok(path) = app::save_ki_readiness_cli_report(&report) {
            report.evidence_path = Some(path.display().to_string());
            let _ = app::save_ki_readiness_cli_report(&report);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize KI readiness report")
        );
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--rdp-preflight") {
        let timeout_secs = ironrdp_client::rdp_smoke_timeout_secs_from_args(&args);
        let mut report = match ironrdp_client::rdp_test_profile_from_args(&args) {
            Ok(profile) => diagnostics::build_rdp_preflight_evidence(&profile, timeout_secs),
            Err(err) => diagnostics::rdp_preflight_env_failure(&err, timeout_secs),
        };
        if let Ok(path) = diagnostics::save_rdp_preflight_evidence(&report) {
            report.evidence_path = Some(path.display().to_string());
            let _ = diagnostics::save_rdp_preflight_evidence(&report);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize RDP preflight report")
        );
        if report.connect_recommended {
            return Ok(());
        }
        std::process::exit(1);
    }

    if args.iter().any(|arg| arg == "--rdp-smoke-test") {
        let timeout_secs = ironrdp_client::rdp_smoke_timeout_secs_from_args(&args);
        match ironrdp_client::rdp_test_profile_from_args(&args)
            .and_then(|profile| ironrdp_client::rdp_smoke_test(profile, timeout_secs))
        {
            Ok(mut report) => {
                if let Ok(path) = ironrdp_client::save_rdp_smoke_report(&report) {
                    report.evidence_path = Some(path.display().to_string());
                    let _ = ironrdp_client::save_rdp_smoke_report(&report);
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("serialize smoke report")
                );
                return Ok(());
            }
            Err(err) => {
                let mut report = ironrdp_client::rdp_smoke_failure_report(&err, timeout_secs);
                if let Ok(path) = ironrdp_client::save_rdp_smoke_failure_report(&report) {
                    report.evidence_path = Some(path.display().to_string());
                    let _ = ironrdp_client::save_rdp_smoke_failure_report(&report);
                }
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("serialize smoke failure report")
                );
                std::process::exit(1);
            }
        }
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(if args.iter().any(|arg| arg == "--gui-capture") {
                [1440.0, 1024.0]
            } else {
                [1280.0, 820.0]
            })
            .with_min_inner_size([640.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Relayne",
        options,
        Box::new(|cc| Ok(Box::new(AivanaApp::new(cc)))),
    )
}

#[cfg(test)]
mod tests {
    use super::build_cli_help;

    #[test]
    fn cli_help_lists_operator_and_live_gate_commands() {
        let help = build_cli_help();

        assert!(help.contains("--save-ki-preferences"));
        assert!(help.contains("--ki-readiness-report"));
        assert!(help.contains("--command-index"));
        assert!(help.contains("--ai-brief-pack"));
        assert!(help.contains("--completion-audit"));
        assert!(help.contains("--goal-evidence-matrix"));
        assert!(help.contains("--goal-evidence-check"));
        assert!(help.contains("--next-live-gate"));
        assert!(help.contains("--next-live-gate-json"));
        assert!(help.contains("--live-gate-sequence"));
        assert!(help.contains("--live-gate-doctor"));
        assert!(help.contains("--live-gate-operator-brief"));
        assert!(help.contains("--rdp-proof-check"));
        assert!(help.contains("--rdp-proof-prompt"));
        assert!(help.contains("--rdp-proof-recovery-plan"));
        assert!(help.contains("--llm-review-prompt"));
        assert!(help.contains("--llm-live-gate-plan"));
        assert!(help.contains("--llm-action-contract"));
        assert!(help.contains("--gui-operator-actions"));
        assert!(help.contains("--operator-handoff-pack"));
        assert!(help.contains("--operator-handoff-check"));
        assert!(help.contains("--operator-handoff-risk-summary"));
        assert!(help.contains("--verification-snapshot"));
        assert!(help.contains("--live-gate"));
        assert!(help.contains("--rdp-env-file"));
        assert!(help.contains("--rdp-env-file-check"));
        assert!(help.contains("--rdp-env-fill-guide"));
        assert!(help.contains("--save-rdp-env-template"));
        assert!(help.contains("--rdp-smoke-test"));
        assert!(help.contains("connected=true"));
    }

    #[test]
    fn command_index_lists_machine_readable_live_gate_commands() {
        let index = crate::app::build_command_index();
        let commands = index["commands"].as_array().expect("commands array");
        let names = commands
            .iter()
            .filter_map(|command| command["name"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(index["schema"], "aivana.command-index.v1");
        assert_eq!(
            index["recommended_live_gate_sequence"][0]["command"],
            "cargo run -- --save-rdp-env-template .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][1]["command"],
            "cargo run -- --rdp-env-fill-guide"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][2]["command"],
            "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][3]["command"],
            "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][4]["command"],
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][5]["command"],
            "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][6]["command"],
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"
        );
        assert!(
            index["recommended_live_gate_sequence"][6]["expect"]
                .as_str()
                .expect("recovery plan expect")
                .contains("failed proof checks")
        );
        assert!(
            index["recommended_live_gate_sequence"][6]["expect"]
                .as_str()
                .expect("recovery plan expect")
                .contains("direct live evidence")
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][7]["command"],
            "cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env"
        );
        assert!(
            index["recommended_live_gate_sequence"][7]["expect"]
                .as_str()
                .expect("doctor expect")
                .contains("operator_stage")
        );
        assert!(
            index["recommended_live_gate_sequence"][7]["expect"]
                .as_str()
                .expect("doctor expect")
                .contains("rdp_proof_recovery_plan_command")
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][8]["command"],
            "cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env"
        );
        assert!(
            index["recommended_live_gate_sequence"][8]["expect"]
                .as_str()
                .expect("operator brief expect")
                .contains("RDP proof recovery-plan command")
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][9]["command"],
            "cargo run -- --llm-review-prompt"
        );
        assert!(
            index["recommended_live_gate_sequence"][9]["expect"]
                .as_str()
                .expect("llm review prompt expect")
                .contains("operator-handoff-risk-summary.json")
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][10]["command"],
            "cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env"
        );
        assert!(
            index["recommended_live_gate_sequence"][10]["expect"]
                .as_str()
                .expect("llm plan expect")
                .contains("RDP proof recovery-plan command")
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][11]["command"],
            "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env"
        );
        let llm_contract_expect = index["recommended_live_gate_sequence"][11]["expect"]
            .as_str()
            .expect("llm action contract expect");
        assert!(llm_contract_expect.contains("direct_live_evidence_requirements"));
        assert!(llm_contract_expect.contains("direct live evidence"));
        assert_eq!(
            index["recommended_live_gate_sequence"][12]["command"],
            "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][13]["command"],
            "cargo run -- --goal-evidence-matrix --rdp-env-file .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][14]["command"],
            "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][16]["command"],
            "cargo run -- --operator-handoff-check"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][16]["expect"],
            "ok=true for schema, expected files, file roles, recommended inspection order, machine-readable JSON schemas, and cross-artifact consistency."
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][17]["command"],
            "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env"
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][17]["expect"],
            "ok=true only when the handoff pack, live-gate doctor, and real RDP goal evidence are all valid; exposes LLM triage entrypoint, required evidence files, and early_triage_artifacts."
        );
        assert_eq!(
            index["recommended_live_gate_sequence"][18]["command"],
            "cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env"
        );
        assert!(names.contains(&"--completion-audit"));
        assert!(names.contains(&"--save-ki-preferences"));
        assert!(names.contains(&"--ai-brief-pack"));
        assert!(names.contains(&"--goal-evidence-matrix"));
        assert!(names.contains(&"--goal-evidence-check"));
        assert!(names.contains(&"--next-live-gate"));
        assert!(names.contains(&"--next-live-gate-json"));
        assert!(names.contains(&"--live-gate-sequence"));
        assert!(names.contains(&"--live-gate-doctor"));
        assert!(names.contains(&"--live-gate-operator-brief"));
        assert!(names.contains(&"--rdp-proof-check"));
        assert!(names.contains(&"--rdp-proof-prompt"));
        assert!(names.contains(&"--rdp-proof-recovery-plan"));
        assert!(names.contains(&"--llm-live-gate-plan"));
        assert!(names.contains(&"--llm-action-contract"));
        assert!(names.contains(&"--gui-operator-actions"));
        assert!(names.contains(&"--operator-handoff-pack"));
        assert!(names.contains(&"--operator-handoff-risk-summary"));
        assert!(names.contains(&"--verification-snapshot"));
        assert!(names.contains(&"--save-rdp-env-template <path>"));
        assert!(names.contains(&"--rdp-env-fill-guide"));
        assert!(names.contains(&"--rdp-env-file-check"));
        assert!(names.contains(&"--operator-handoff-check"));
        assert!(names.contains(&"--rdp-smoke-test"));
        assert!(
            commands
                .iter()
                .any(|command| command["name"] == "--rdp-smoke-test"
                    && command["success_condition"] == "connected == true")
        );
        let smoke = commands
            .iter()
            .find(|command| command["name"] == "--rdp-smoke-test")
            .expect("smoke command");
        let save_preferences = commands
            .iter()
            .find(|command| command["name"] == "--save-ki-preferences")
            .expect("save KI preferences command");
        let gui_actions = commands
            .iter()
            .find(|command| command["name"] == "--gui-operator-actions")
            .expect("gui operator actions command");
        let ai_brief_pack = commands
            .iter()
            .find(|command| command["name"] == "--ai-brief-pack")
            .expect("ai brief pack command");
        let handoff_pack = commands
            .iter()
            .find(|command| command["name"] == "--operator-handoff-pack")
            .expect("operator handoff pack command");
        let evidence_matrix = commands
            .iter()
            .find(|command| command["name"] == "--goal-evidence-matrix")
            .expect("goal evidence matrix command");
        let evidence_check = commands
            .iter()
            .find(|command| command["name"] == "--goal-evidence-check")
            .expect("goal evidence check command");
        let handoff_check = commands
            .iter()
            .find(|command| command["name"] == "--operator-handoff-check")
            .expect("operator handoff check command");
        let risk_summary = commands
            .iter()
            .find(|command| command["name"] == "--operator-handoff-risk-summary")
            .expect("operator handoff risk summary command");
        let verification_snapshot = commands
            .iter()
            .find(|command| command["name"] == "--verification-snapshot")
            .expect("verification snapshot command");
        let live_gate_doctor = commands
            .iter()
            .find(|command| command["name"] == "--live-gate-doctor")
            .expect("live gate doctor command");
        let live_gate_operator_brief = commands
            .iter()
            .find(|command| command["name"] == "--live-gate-operator-brief")
            .expect("live gate operator brief command");
        let rdp_proof_check = commands
            .iter()
            .find(|command| command["name"] == "--rdp-proof-check")
            .expect("rdp proof check command");
        let rdp_proof_prompt = commands
            .iter()
            .find(|command| command["name"] == "--rdp-proof-prompt")
            .expect("rdp proof prompt command");
        let rdp_proof_recovery_plan = commands
            .iter()
            .find(|command| command["name"] == "--rdp-proof-recovery-plan")
            .expect("rdp proof recovery plan command");
        let live_gate_sequence = commands
            .iter()
            .find(|command| command["name"] == "--live-gate-sequence")
            .expect("live gate sequence command");
        let llm_live_gate_plan = commands
            .iter()
            .find(|command| command["name"] == "--llm-live-gate-plan")
            .expect("llm live gate plan command");
        let llm_review_prompt = commands
            .iter()
            .find(|command| command["name"] == "--llm-review-prompt")
            .expect("llm review prompt command");
        let llm_action_contract = commands
            .iter()
            .find(|command| command["name"] == "--llm-action-contract")
            .expect("llm action contract command");
        let env_file_check = commands
            .iter()
            .find(|command| command["name"] == "--rdp-env-file-check")
            .expect("rdp env file check command");
        let env_fill_guide = commands
            .iter()
            .find(|command| command["name"] == "--rdp-env-fill-guide")
            .expect("rdp env fill guide command");
        assert_eq!(gui_actions["output"], "markdown");
        assert_eq!(save_preferences["output"], "json");
        assert_eq!(save_preferences["persists"], true);
        assert_eq!(
            save_preferences["success_condition"],
            "preferences_saved == true in --ki-readiness-report"
        );
        assert_eq!(gui_actions["persists"], true);
        assert_eq!(ai_brief_pack["output"], "json");
        assert_eq!(ai_brief_pack["persists"], true);
        assert_eq!(evidence_matrix["output"], "json");
        assert_eq!(
            evidence_matrix["success_condition"],
            "achieved == true and uncovered_requirements is empty"
        );
        assert_eq!(evidence_check["output"], "json");
        assert_eq!(evidence_check["success_condition"], "ok == true");
        assert_eq!(evidence_check["failure_exit"], 1);
        assert_eq!(handoff_check["output"], "json");
        assert_eq!(handoff_check["persists"], false);
        assert_eq!(handoff_check["success_condition"], "ok == true");
        assert_eq!(risk_summary["output"], "json");
        assert_eq!(risk_summary["persists"], true);
        assert_eq!(risk_summary["success_condition"], "ok == true");
        assert_eq!(risk_summary["failure_exit"], 1);
        assert_eq!(verification_snapshot["output"], "json");
        assert_eq!(verification_snapshot["persists"], true);
        assert_eq!(verification_snapshot["failure_exit"], 1);
        assert_eq!(live_gate_doctor["output"], "json");
        assert_eq!(live_gate_doctor["persists"], true);
        assert_eq!(live_gate_doctor["success_condition"], "achieved == true");
        assert_eq!(live_gate_doctor["failure_exit"], 1);
        assert_eq!(live_gate_operator_brief["output"], "markdown");
        assert_eq!(live_gate_operator_brief["persists"], true);
        assert_eq!(rdp_proof_check["output"], "json");
        assert_eq!(rdp_proof_check["persists"], true);
        assert_eq!(rdp_proof_check["success_condition"], "ok == true");
        assert_eq!(rdp_proof_check["failure_exit"], 1);
        assert_eq!(rdp_proof_prompt["output"], "markdown");
        assert_eq!(rdp_proof_prompt["persists"], true);
        assert_eq!(rdp_proof_recovery_plan["output"], "markdown");
        assert_eq!(rdp_proof_recovery_plan["persists"], true);
        assert_eq!(live_gate_sequence["output"], "text");
        assert_eq!(live_gate_sequence["persists"], false);
        assert_eq!(llm_live_gate_plan["output"], "markdown");
        assert_eq!(llm_live_gate_plan["persists"], true);
        assert_eq!(llm_review_prompt["output"], "markdown");
        assert_eq!(llm_review_prompt["persists"], true);
        assert_eq!(llm_action_contract["output"], "json");
        assert_eq!(llm_action_contract["persists"], true);
        assert_eq!(llm_action_contract["success_condition"], "ok == true");
        assert_eq!(llm_action_contract["failure_exit"], 1);
        let llm_review_prompt_purpose = llm_review_prompt["purpose"]
            .as_str()
            .expect("llm review prompt purpose");
        assert!(llm_review_prompt_purpose.contains("summary.md Early LLM Triage"));
        assert!(llm_review_prompt_purpose.contains("operator-handoff-risk-summary.json"));
        assert!(llm_review_prompt_purpose.contains("LLM triage entrypoint"));
        assert!(llm_review_prompt_purpose.contains("required evidence files"));
        assert!(llm_review_prompt_purpose.contains("early_triage_artifacts"));
        assert!(llm_review_prompt_purpose.contains("proxy-evidence rejection"));
        let risk_summary_purpose = risk_summary["purpose"]
            .as_str()
            .expect("risk summary purpose");
        assert!(risk_summary_purpose.contains("LLM triage entrypoint"));
        assert!(risk_summary_purpose.contains("required evidence files"));
        assert!(risk_summary_purpose.contains("early_triage_artifacts"));
        assert!(
            llm_action_contract["purpose"]
                .as_str()
                .expect("llm action contract purpose")
                .contains("summary.md Early LLM Triage")
        );
        assert!(
            llm_action_contract["purpose"]
                .as_str()
                .expect("llm action contract purpose")
                .contains("early_triage_artifacts")
        );
        assert!(
            llm_action_contract["purpose"]
                .as_str()
                .expect("llm action contract purpose")
                .contains("success signals")
        );
        assert!(
            llm_action_contract["purpose"]
                .as_str()
                .expect("llm action contract purpose")
                .contains("direct_live_evidence_requirements")
        );
        assert!(
            llm_action_contract["purpose"]
                .as_str()
                .expect("llm action contract purpose")
                .contains("direct live evidence")
        );
        assert!(
            llm_action_contract["purpose"]
                .as_str()
                .expect("llm action contract purpose")
                .contains("proxy-evidence rejection rules")
        );
        assert_eq!(env_file_check["output"], "json");
        assert_eq!(env_file_check["persists"], true);
        assert_eq!(env_file_check["success_condition"], "ok == true");
        assert_eq!(env_file_check["failure_exit"], 1);
        assert_eq!(env_fill_guide["output"], "markdown");
        assert_eq!(env_fill_guide["persists"], true);
        let handoff_purpose = handoff_pack["purpose"]
            .as_str()
            .expect("handoff pack purpose");
        assert!(handoff_purpose.contains("summary.md Early LLM Triage"));
        assert!(handoff_purpose.contains("verification-snapshot.json"));
        assert!(handoff_purpose.contains("llm-action-contract.json"));
        let handoff_artifacts = handoff_pack["artifacts"]
            .as_array()
            .expect("handoff artifacts");
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/gui-operator-actions.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/next-live-gate.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/goal-evidence-matrix.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/goal-evidence-check.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/verification-snapshot.json")
        );
        assert!(
            handoff_artifacts.iter().any(|path| path
                == "operator-handoff-packs/<pack-id>/operator-handoff-risk-summary.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/rdp-env-file-check.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/rdp-proof-check.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/live-gate-doctor.json")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/live-gate-operator-brief.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/llm-review-prompt.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/rdp-proof-prompt.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/rdp-proof-recovery-plan.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/rdp-env-fill-guide.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/llm-live-gate-plan.md")
        );
        assert!(
            handoff_artifacts
                .iter()
                .any(|path| path == "operator-handoff-packs/<pack-id>/llm-action-contract.json")
        );
        assert!(
            smoke["requires_env"]
                .as_array()
                .expect("requires env")
                .iter()
                .any(|name| name == "AIVANA_RDP_TEST_PASSWORD")
        );
        assert!(
            smoke["artifacts"]
                .as_array()
                .expect("artifacts")
                .iter()
                .any(|path| path == "rdp-smoke-tests/*.json")
        );
    }
}
