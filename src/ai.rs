use uuid::Uuid;

use crate::models::{
    AiAction, AiEvidence, AiExplanation, ChangeSummary, DiagnosticFinding, IncidentDraft,
    InputAction, PolicyDecision, PreflightReport, RiskLevel, RunbookRecommendation,
    ScreenObservation, SessionSummary,
};

pub trait AiProvider {
    fn explain_failure(&self, report: &PreflightReport) -> AiExplanation;
    fn summarize_session(&self, events: &[String]) -> SessionSummary;
    fn plan_action(&self, observation: &ScreenObservation, goal: &str) -> AiAction;
    fn classify_risk(&self, action: &InputAction) -> RiskLevel;
    fn recommend_runbook(&self, context: &str) -> RunbookRecommendation;
    fn write_incident_report(&self, events: &[String]) -> IncidentDraft;
    fn compare_sessions(&self, current: &[String], previous: &[String]) -> ChangeSummary;
}

#[derive(Default)]
pub struct LocalAiProvider;

impl AiProvider for LocalAiProvider {
    fn explain_failure(&self, report: &PreflightReport) -> AiExplanation {
        if report.findings.is_empty() {
            return AiExplanation {
                title: "Keine lokalen Fehler gefunden".to_owned(),
                likely_root_cause: "Preflight hat keine blockierenden lokalen Probleme erkannt."
                    .to_owned(),
                evidence: vec![AiEvidence {
                    source: "preflight".to_owned(),
                    detail: "Keine Findings vorhanden.".to_owned(),
                }],
                next_safe_step: "Verbindung starten und Timeline beobachten.".to_owned(),
                risk: RiskLevel::ReadOnly,
                confidence: 0.72,
            };
        }

        let most_important = report
            .findings
            .iter()
            .find(|f| matches!(f.severity, crate::models::DiagnosticSeverity::Error))
            .or_else(|| report.findings.first())
            .expect("checked non-empty");

        AiExplanation {
            title: most_important.title.clone(),
            likely_root_cause: most_important.detail.clone(),
            evidence: report
                .findings
                .iter()
                .map(|finding| AiEvidence {
                    source: format!("{:?}", finding.class),
                    detail: finding_to_sentence(finding),
                })
                .collect(),
            next_safe_step: most_important.fix.clone(),
            risk: RiskLevel::ReadOnly,
            confidence: if report.connect_recommended {
                0.66
            } else {
                0.86
            },
        }
    }

    fn summarize_session(&self, events: &[String]) -> SessionSummary {
        let errors = events
            .iter()
            .filter(|event| event.to_lowercase().contains("error"))
            .count();
        SessionSummary {
            headline: format!(
                "Session enthaelt {} Ereignisse, davon {} Fehlerhinweise.",
                events.len(),
                errors
            ),
            details: events.iter().rev().take(5).cloned().collect(),
        }
    }

    fn plan_action(&self, observation: &ScreenObservation, goal: &str) -> AiAction {
        let action = InputAction::Verify {
            expectation: format!("{} | observed frame {}", goal, observation.frame_hash),
        };
        let risk = self.classify_risk(&action);
        AiAction {
            id: Uuid::new_v4(),
            session_id: Some(observation.session_id),
            description: format!("Verify goal against current screen: {goal}"),
            action,
            risk,
            decision: PolicyDecision::Allow,
        }
    }

    fn classify_risk(&self, action: &InputAction) -> RiskLevel {
        match action {
            InputAction::Screenshot | InputAction::Verify { .. } | InputAction::Wait { .. } => {
                RiskLevel::ReadOnly
            }
            InputAction::MovePointer { .. }
            | InputAction::Scroll { .. }
            | InputAction::Resize { .. }
            | InputAction::ClipboardFocus { .. } => RiskLevel::LowRisk,
            InputAction::Click { .. }
            | InputAction::Key { .. }
            | InputAction::PointerButton { .. }
            | InputAction::ClipboardFiles { .. }
            | InputAction::ClipboardDownload { .. }
            | InputAction::DoubleClick { .. }
            | InputAction::Hotkey { .. }
            | InputAction::TypeText { .. } => RiskLevel::ElevatedRisk,
        }
    }

    fn recommend_runbook(&self, context: &str) -> RunbookRecommendation {
        let lower = context.to_lowercase();
        let (name, reason) = if lower.contains("credssp") || lower.contains("nla") {
            (
                "NLA/CredSSP Problem",
                "Credential- oder NLA-Hinweise im Kontext erkannt.",
            )
        } else if lower.contains("certificate") || lower.contains("cert") {
            (
                "Certificate Changed Investigation",
                "Zertifikatsrisiko im Kontext erkannt.",
            )
        } else if lower.contains("disconnect") {
            (
                "Repeated Disconnects",
                "Wiederholte Trennungen im Kontext erkannt.",
            )
        } else if lower.contains("black") || lower.contains("slow") {
            (
                "Slow Login / Black Screen",
                "Langsamer Login oder schwarzer Bildschirm erkannt.",
            )
        } else {
            (
                "DNS/TCP/RDP-Port Diagnose",
                "Sicherer Netzwerk-Preflight ist der beste erste Schritt.",
            )
        };

        RunbookRecommendation {
            runbook_id: Uuid::new_v4(),
            name: name.to_owned(),
            reason: reason.to_owned(),
            confidence: 0.78,
        }
    }

    fn write_incident_report(&self, events: &[String]) -> IncidentDraft {
        IncidentDraft {
            title: "Relayne RDP Incident".to_owned(),
            root_cause: events
                .iter()
                .find(|event| event.to_lowercase().contains("error"))
                .cloned()
                .unwrap_or_else(|| "Keine eindeutige Root Cause gefunden.".to_owned()),
            customer_text: format!(
                "Die Remote-Session wurde analysiert. Es wurden {} Ereignisse ausgewertet und sichere Diagnosebeweise gesammelt.",
                events.len()
            ),
            internal_note: "Timeline, KI-Beobachtungen und Policy-Entscheidungen pruefen."
                .to_owned(),
            open_tasks: vec!["Bei Bedarf mutierende Schritte separat freigeben.".to_owned()],
        }
    }

    fn compare_sessions(&self, current: &[String], previous: &[String]) -> ChangeSummary {
        ChangeSummary {
            headline: format!(
                "Aktuelle Session: {} Events, vorherige Referenz: {} Events.",
                current.len(),
                previous.len()
            ),
            changes: current
                .iter()
                .filter(|event| !previous.contains(event))
                .take(5)
                .cloned()
                .collect(),
        }
    }
}

fn finding_to_sentence(finding: &DiagnosticFinding) -> String {
    format!("{}: {} Fix: {}", finding.title, finding.detail, finding.fix)
}

#[derive(Default)]
#[allow(dead_code)]
pub struct OptionalCloudAiProvider {
    api_key: Option<String>,
    local: LocalAiProvider,
}

#[allow(dead_code)]
impl OptionalCloudAiProvider {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            local: LocalAiProvider,
        }
    }

    pub fn cloud_enabled(&self) -> bool {
        self.api_key
            .as_ref()
            .is_some_and(|key| !key.trim().is_empty())
    }
}

impl AiProvider for OptionalCloudAiProvider {
    fn explain_failure(&self, report: &PreflightReport) -> AiExplanation {
        self.local.explain_failure(report)
    }

    fn summarize_session(&self, events: &[String]) -> SessionSummary {
        self.local.summarize_session(events)
    }

    fn plan_action(&self, observation: &ScreenObservation, goal: &str) -> AiAction {
        self.local.plan_action(observation, goal)
    }

    fn classify_risk(&self, action: &InputAction) -> RiskLevel {
        self.local.classify_risk(action)
    }

    fn recommend_runbook(&self, context: &str) -> RunbookRecommendation {
        self.local.recommend_runbook(context)
    }

    fn write_incident_report(&self, events: &[String]) -> IncidentDraft {
        self.local.write_incident_report(events)
    }

    fn compare_sessions(&self, current: &[String], previous: &[String]) -> ChangeSummary {
        self.local.compare_sessions(current, previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::models::{DiagnosticClass, DiagnosticFinding, DiagnosticSeverity, PreflightReport};

    #[test]
    fn explanation_contains_evidence_and_next_step() {
        let provider = LocalAiProvider;
        let report = PreflightReport {
            profile_id: Uuid::new_v4(),
            checked_at: Utc::now(),
            findings: vec![DiagnosticFinding {
                class: DiagnosticClass::Tcp,
                severity: DiagnosticSeverity::Error,
                title: "Port closed".to_owned(),
                detail: "RDP port unreachable".to_owned(),
                fix: "Check firewall".to_owned(),
            }],
            connect_recommended: false,
        };

        let explanation = provider.explain_failure(&report);
        assert_eq!(explanation.next_safe_step, "Check firewall");
        assert!(!explanation.evidence.is_empty());
    }
}
