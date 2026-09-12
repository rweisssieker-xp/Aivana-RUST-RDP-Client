use crate::models::{InputAction, PolicyDecision, RiskLevel};

#[derive(Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn classify_action(&self, action: &InputAction) -> RiskLevel {
        match action {
            InputAction::Screenshot | InputAction::Verify { .. } | InputAction::Wait { .. } => {
                RiskLevel::ReadOnly
            }
            InputAction::MovePointer { .. }
            | InputAction::Scroll { .. }
            | InputAction::Resize { .. }
            | InputAction::ClipboardFocus { .. } => RiskLevel::LowRisk,
            InputAction::TypeText { text } if contains_blocked_intent(text) => {
                RiskLevel::Destructive
            }
            InputAction::Hotkey { keys }
                if keys.iter().any(|key| key.eq_ignore_ascii_case("del")) =>
            {
                RiskLevel::ElevatedRisk
            }
            InputAction::Click { .. }
            | InputAction::ClipboardFiles { .. }
            | InputAction::ClipboardDownload { .. }
            | InputAction::Key { .. }
            | InputAction::PointerButton { .. }
            | InputAction::DoubleClick { .. }
            | InputAction::Hotkey { .. }
            | InputAction::TypeText { .. } => RiskLevel::ElevatedRisk,
        }
    }

    pub fn decision_for(&self, action: &InputAction) -> PolicyDecision {
        match self.classify_action(action) {
            RiskLevel::ReadOnly | RiskLevel::LowRisk => PolicyDecision::Allow,
            RiskLevel::ElevatedRisk => PolicyDecision::RequireApproval,
            RiskLevel::Destructive => PolicyDecision::Deny,
        }
    }

    #[allow(dead_code)]
    pub fn requires_approval(&self, action: &InputAction) -> bool {
        self.decision_for(action) == PolicyDecision::RequireApproval
    }

    #[allow(dead_code)]
    pub fn deny_reason(&self, action: &InputAction) -> Option<String> {
        (self.decision_for(action) == PolicyDecision::Deny)
            .then(|| "Action is blocked by Relayne safety policy.".to_owned())
    }

    #[allow(dead_code)]
    pub fn explain_decision(&self, action: &InputAction) -> String {
        match self.decision_for(action) {
            PolicyDecision::Allow => "Allowed: read-only or low-risk action.".to_owned(),
            PolicyDecision::RequireApproval => {
                "Approval required: action can change remote UI state.".to_owned()
            }
            PolicyDecision::Deny => {
                "Denied: action resembles destructive or security-sensitive automation.".to_owned()
            }
        }
    }
}

fn contains_blocked_intent(text: &str) -> bool {
    let lower = text.to_lowercase();
    [
        "format ",
        "del /s",
        "remove-item -recurse",
        "disable-defender",
        "shutdown /r",
        "reg delete",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_requires_approval() {
        let policy = PolicyEngine;
        assert!(policy.requires_approval(&InputAction::TypeText {
            text: "restart service".to_owned()
        }));
    }

    #[test]
    fn destructive_text_is_denied() {
        let policy = PolicyEngine;
        assert_eq!(
            policy.decision_for(&InputAction::TypeText {
                text: "Remove-Item -Recurse C:\\data".to_owned()
            }),
            PolicyDecision::Deny
        );
    }
}
