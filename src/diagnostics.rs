use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::models::{
    ConnectionProfile, DiagnosticClass, DiagnosticFinding, DiagnosticSeverity, PreflightReport,
};
use crate::security::{app_data_file, redact_secret_text};

pub trait PreflightService {
    fn run(&self, profile: &ConnectionProfile) -> PreflightReport;
}

#[derive(Default)]
pub struct LocalPreflightService;

#[derive(Clone, Debug, Serialize)]
pub struct RdpPreflightEvidenceReport {
    pub report_id: Uuid,
    pub generated_at: chrono::DateTime<Utc>,
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub username_set: bool,
    pub password_set: bool,
    pub connect_recommended: bool,
    pub env_error: Option<String>,
    pub expected_environment: Vec<&'static str>,
    pub findings: Vec<DiagnosticFinding>,
    pub evidence_path: Option<String>,
}

pub fn build_rdp_preflight_evidence(
    profile: &ConnectionProfile,
    timeout_secs: u64,
) -> RdpPreflightEvidenceReport {
    let report = LocalPreflightService.run(profile);
    RdpPreflightEvidenceReport {
        report_id: Uuid::new_v4(),
        generated_at: Utc::now(),
        host: redact_secret_text(&profile.host),
        port: profile.port,
        timeout_secs,
        username_set: !profile.username.trim().is_empty(),
        password_set: !profile.password.trim().is_empty() || profile.credential_id.is_some(),
        connect_recommended: report.connect_recommended,
        env_error: None,
        expected_environment: rdp_preflight_expected_environment(),
        findings: report.findings,
        evidence_path: None,
    }
}

pub fn rdp_preflight_env_failure(
    error: &anyhow::Error,
    timeout_secs: u64,
) -> RdpPreflightEvidenceReport {
    RdpPreflightEvidenceReport {
        report_id: Uuid::new_v4(),
        generated_at: Utc::now(),
        host: "unknown-host".to_owned(),
        port: 3389,
        timeout_secs,
        username_set: false,
        password_set: false,
        connect_recommended: false,
        env_error: Some(redact_secret_text(&format!("{error:#}"))),
        expected_environment: rdp_preflight_expected_environment(),
        findings: Vec::new(),
        evidence_path: None,
    }
}

pub fn save_rdp_preflight_evidence(
    report: &RdpPreflightEvidenceReport,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-preflight")?;
    std::fs::create_dir_all(&dir)?;
    let suffix = if report.connect_recommended {
        "ready"
    } else {
        "blocked"
    };
    let path = dir.join(format!("{}-{suffix}.json", report.report_id));
    std::fs::write(&path, serde_json::to_string_pretty(report)?)?;
    Ok(path)
}

fn rdp_preflight_expected_environment() -> Vec<&'static str> {
    vec![
        "AIVANA_RDP_TEST_HOST",
        "AIVANA_RDP_TEST_USER",
        "AIVANA_RDP_TEST_PASSWORD",
        "AIVANA_RDP_TEST_PORT (optional)",
        "AIVANA_RDP_TEST_DOMAIN (optional)",
        "AIVANA_RDP_TEST_TIMEOUT_SECS (optional, 5-600)",
    ]
}

impl PreflightService for LocalPreflightService {
    fn run(&self, profile: &ConnectionProfile) -> PreflightReport {
        let mut findings = Vec::new();

        if profile.host.trim().is_empty() {
            findings.push(finding(
                DiagnosticClass::Dns,
                DiagnosticSeverity::Error,
                "Host fehlt",
                "Das Profil hat keinen Hostnamen oder keine IP-Adresse.",
                "Host im Profil eintragen.",
            ));
        } else {
            match (profile.host.as_str(), profile.port).to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        findings.push(finding(
                            DiagnosticClass::Dns,
                            DiagnosticSeverity::Info,
                            "DNS aufgeloest",
                            &format!("{} wurde zu {} aufgeloest.", profile.host, addr),
                            "Keine Aktion erforderlich.",
                        ));
                        if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_err() {
                            findings.push(finding(
                                DiagnosticClass::Tcp,
                                DiagnosticSeverity::Error,
                                "TCP-Port nicht erreichbar",
                                "Der Zielhost antwortet nicht auf dem RDP-Port.",
                                "Firewall, VPN, Routing und RDP-Port pruefen.",
                            ));
                        }
                    } else {
                        findings.push(finding(
                            DiagnosticClass::Dns,
                            DiagnosticSeverity::Error,
                            "Keine Adresse gefunden",
                            "DNS lieferte keine nutzbare Zieladresse.",
                            "Hostnamen oder DNS-Konfiguration pruefen.",
                        ));
                    }
                }
                Err(err) => findings.push(finding(
                    DiagnosticClass::Dns,
                    DiagnosticSeverity::Error,
                    "DNS-Fehler",
                    &err.to_string(),
                    "Hostnamen, DNS-Server oder Netzwerk pruefen.",
                )),
            }
        }

        if profile.credential_id.is_none() && profile.password.is_empty() {
            findings.push(finding(
                DiagnosticClass::Credential,
                DiagnosticSeverity::Warning,
                "Keine gespeicherten Credentials",
                "Das Profil hat weder Credential-Referenz noch ein temporaeres Passwort.",
                "Credential speichern oder Passwort fuer die Session eingeben.",
            ));
        }

        let connect_recommended = !findings
            .iter()
            .any(|f| matches!(f.severity, DiagnosticSeverity::Error));

        PreflightReport {
            profile_id: profile.id,
            checked_at: Utc::now(),
            findings,
            connect_recommended,
        }
    }
}

pub fn classify_error(message: &str) -> DiagnosticClass {
    let lower = message.to_lowercase();
    // Security failures may be wrapped in generic "connection finalize" text.
    // Classify the specific cause before transport context to avoid unsafe retries.
    if lower.contains("logon_failure")
        || lower.contains("0xc000006d")
        || lower.contains("account_locked")
        || lower.contains("password")
        || lower.contains("authentication")
    {
        DiagnosticClass::Auth
    } else if lower.contains("certificate") || lower.contains("cert") {
        DiagnosticClass::Certificate
    } else if lower.contains("credssp") || lower.contains("nla") {
        DiagnosticClass::CredSspNla
    } else if lower.contains("standard rdp security") || lower.contains("negotiation failure") {
        DiagnosticClass::Protocol
    } else if lower.contains("tls") {
        DiagnosticClass::Tls
    } else if lower.contains("auth") {
        DiagnosticClass::Auth
    } else if lower.contains("dns") || lower.contains("socket address") {
        DiagnosticClass::Dns
    } else if lower.contains("timeout") || lower.contains("timed out") {
        DiagnosticClass::Timeout
    } else if lower.contains("tcp") || lower.contains("connect") {
        DiagnosticClass::Tcp
    } else {
        DiagnosticClass::Unknown
    }
}

pub fn finding(
    class: DiagnosticClass,
    severity: DiagnosticSeverity,
    title: &str,
    detail: &str,
    fix: &str,
) -> DiagnosticFinding {
    DiagnosticFinding {
        class,
        severity,
        title: title.to_owned(),
        detail: detail.to_owned(),
        fix: fix.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_logon_and_certificate_failures_are_not_transport_errors() {
        assert_eq!(
            classify_error(
                "connection finalize: [CredSSP] InvalidToken: STATUS_LOGON_FAILURE [0xc000006d]"
            ),
            DiagnosticClass::Auth
        );
        assert_eq!(
            classify_error("connection finalize: invalid certificate"),
            DiagnosticClass::Certificate
        );
        assert_eq!(
            classify_error("TCP connect timed out"),
            DiagnosticClass::Timeout
        );
    }

    #[test]
    fn classifies_common_error_text() {
        assert_eq!(classify_error("TLS upgrade failed"), DiagnosticClass::Tls);
        assert_eq!(
            classify_error("CredSSP failure"),
            DiagnosticClass::CredSspNla
        );
        assert_eq!(
            classify_error("negotiation failure: server only supports Standard RDP Security"),
            DiagnosticClass::Protocol
        );
    }

    #[test]
    fn rdp_preflight_env_failure_redacts_and_lists_requirements() {
        let err = anyhow::anyhow!("missing password=hunter2");
        let report = rdp_preflight_env_failure(&err, 90);
        let json = serde_json::to_string(&report).expect("serialized preflight failure");

        assert!(!report.connect_recommended);
        assert_eq!(report.timeout_secs, 90);
        assert!(json.contains("AIVANA_RDP_TEST_HOST"));
        assert!(json.contains("AIVANA_RDP_TEST_TIMEOUT_SECS"));
        assert!(json.contains("password=[REDACTED]"));
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn rdp_preflight_evidence_reports_missing_host_without_secret_leak() {
        let mut profile = ConnectionProfile::sample("preflight", "", "Manual", false);
        profile.username = "user".to_owned();
        profile.password = "password=hunter2".to_owned();

        let report = build_rdp_preflight_evidence(&profile, 45);
        let json = serde_json::to_string(&report).expect("serialized preflight evidence");

        assert!(!report.connect_recommended);
        assert_eq!(report.timeout_secs, 45);
        assert!(report.username_set);
        assert!(report.password_set);
        assert!(json.contains("Host fehlt"));
        assert!(!json.contains("hunter2"));
    }
}
