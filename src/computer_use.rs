use uuid::Uuid;

use crate::ai::{AiProvider, LocalAiProvider};
use crate::models::{
    AiAction, ApprovalRequest, ApprovalStatus, DialogKind, DialogObservation, FrameUpdate,
    InputAction, OcrResult, PolicyDecision, ScreenObservation, VerificationResult,
};
use crate::policy::PolicyEngine;

#[derive(Default)]
pub struct ScreenObserver;

impl ScreenObserver {
    pub fn observe(&self, frame: &FrameUpdate) -> ScreenObservation {
        let ocr = self.extract_text(frame);
        let dialogs = self.detect_dialogs(frame);
        let mut hypotheses = vec!["remote-desktop-framebuffer".to_owned()];
        hypotheses.extend(dialogs.iter().map(|dialog| format!("{:?}", dialog.kind)));

        ScreenObservation {
            session_id: frame.session_id,
            frame_hash: frame.frame_hash,
            summary: format!(
                "Framebuffer {}x{} with {} dirty regions. {} screen signal(s) detected.",
                frame.width,
                frame.height,
                frame.dirty_regions.len(),
                hypotheses.len()
            ),
            detected_text: ocr.text.clone(),
            ui_hypotheses: hypotheses,
            dialogs,
            ocr,
            captured_at: frame.captured_at,
        }
    }

    pub fn detect_dialogs(&self, frame: &FrameUpdate) -> Vec<DialogObservation> {
        let brightness = average_brightness(&frame.pixels_rgba);
        let mut dialogs = Vec::new();
        if brightness < 8.0 {
            dialogs.push(DialogObservation {
                title: "Possible black screen".to_owned(),
                kind: DialogKind::BlackScreen,
                confidence: 0.82,
            });
        }
        if frame.dirty_regions.is_empty() {
            dialogs.push(DialogObservation {
                title: "Possibly frozen or idle screen".to_owned(),
                kind: DialogKind::Unknown,
                confidence: 0.45,
            });
        }
        dialogs
    }

    pub fn extract_text(&self, frame: &FrameUpdate) -> OcrResult {
        let brightness = average_brightness(&frame.pixels_rgba);
        let text = if brightness < 8.0 {
            vec!["black screen".to_owned()]
        } else if frame.width >= 1000 && frame.height >= 700 {
            vec!["remote desktop framebuffer".to_owned()]
        } else {
            vec!["small remote desktop framebuffer".to_owned()]
        };

        OcrResult {
            text,
            confidence: 0.35,
        }
    }
}

pub struct ComputerUseAgent<P: AiProvider = LocalAiProvider> {
    observer: ScreenObserver,
    planner: P,
    policy: PolicyEngine,
}

impl Default for ComputerUseAgent<LocalAiProvider> {
    fn default() -> Self {
        Self {
            observer: ScreenObserver,
            planner: LocalAiProvider,
            policy: PolicyEngine,
        }
    }
}

impl<P: AiProvider> ComputerUseAgent<P> {
    pub fn observe(&self, frame: &FrameUpdate) -> ScreenObservation {
        self.observer.observe(frame)
    }

    pub fn plan_next_step(&self, observation: &ScreenObservation, goal: &str) -> AiAction {
        let mut action = self.planner.plan_action(observation, goal);
        action.risk = self.policy.classify_action(&action.action);
        action.decision = self.policy.decision_for(&action.action);
        action
    }

    pub fn execute_step(&self, action: &AiAction) -> Result<InputAction, String> {
        match action.decision {
            PolicyDecision::Allow => Ok(action.action.clone()),
            PolicyDecision::RequireApproval => Err("approval required".to_owned()),
            PolicyDecision::Deny => Err("action denied".to_owned()),
        }
    }

    pub fn request_approval(&self, action: &AiAction, reason: String) -> ApprovalRequest {
        ApprovalRequest {
            id: Uuid::new_v4(),
            action_id: action.id,
            session_id: action.session_id,
            description: action.description.clone(),
            action: action.action.clone(),
            actions: vec![action.action.clone()],
            reason,
            expected_result: "Relayne verifies the next framebuffer after execution.".to_owned(),
            risk: action.risk,
            status: ApprovalStatus::Pending,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn verify_step(
        &self,
        session_id: Uuid,
        frame_hash_before: u64,
        frame: &FrameUpdate,
    ) -> VerificationResult {
        let success = frame.session_id == session_id && frame.frame_hash != frame_hash_before;
        VerificationResult {
            success,
            frame_hash_before,
            frame_hash_after: frame.frame_hash,
            evidence: if success {
                "Framebuffer changed after action.".to_owned()
            } else {
                "No framebuffer change detected.".to_owned()
            },
        }
    }
}

fn average_brightness(pixels: &[u8]) -> f32 {
    let mut total = 0_u64;
    let mut count = 0_u64;
    for rgba in pixels.chunks_exact(4).step_by(512) {
        total += (u64::from(rgba[0]) + u64::from(rgba[1]) + u64::from(rgba[2])) / 3;
        count += 1;
    }
    if count == 0 {
        0.0
    } else {
        total as f32 / count as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::models::DirtyRegion;

    #[test]
    fn black_frame_is_detected_as_black_screen() {
        let frame = FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 640,
            height: 480,
            pixels_rgba: vec![0; 640 * 480 * 4],
            dirty_regions: vec![DirtyRegion {
                left: 0,
                top: 0,
                right: 640,
                bottom: 480,
            }],
            frame_hash: 42,
            captured_at: Utc::now(),
        };

        let observation = ScreenObserver.observe(&frame);
        assert!(
            observation
                .dialogs
                .iter()
                .any(|d| d.kind == DialogKind::BlackScreen)
        );
    }

    #[test]
    fn approval_request_preserves_executable_action_list() {
        let agent = ComputerUseAgent::default();
        let action = AiAction {
            id: Uuid::new_v4(),
            session_id: Some(Uuid::new_v4()),
            description: "type text".to_owned(),
            action: InputAction::TypeText {
                text: "hello".to_owned(),
            },
            risk: crate::models::RiskLevel::ElevatedRisk,
            decision: PolicyDecision::RequireApproval,
        };

        let approval = agent.request_approval(&action, "needs approval".to_owned());

        assert_eq!(approval.actions, vec![action.action]);
    }
}
