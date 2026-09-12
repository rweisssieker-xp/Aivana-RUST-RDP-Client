use std::io::Cursor;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use image::{ImageBuffer, ImageFormat, Rgba};
use serde::{Deserialize, Serialize};

use crate::computer_use::ComputerUseAgent;
use crate::models::{
    FrameUpdate, InputAction, MouseButton, PolicyDecision, RiskLevel, ScreenObservation,
    VerificationResult,
};
use crate::policy::PolicyEngine;
use crate::security::redact_secret_text;

const OPENAI_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum AutopilotProviderKind {
    Local,
    OpenAiComputerUse,
}

impl AutopilotProviderKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::OpenAiComputerUse => "OpenAI CUA",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutopilotSettings {
    pub provider: AutopilotProviderKind,
    pub max_steps: usize,
    pub step_delay_millis: u64,
    pub require_approval_for_every_mutation: bool,
    pub agentic_runbook_mode: bool,
    pub openai_model: String,
}

impl Default for AutopilotSettings {
    fn default() -> Self {
        Self {
            provider: AutopilotProviderKind::Local,
            max_steps: 12,
            step_delay_millis: 800,
            require_approval_for_every_mutation: true,
            agentic_runbook_mode: false,
            openai_model: "gpt-5.5".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum AutopilotStatus {
    Idle,
    Running,
    WaitingForApproval,
    WaitingForSafetyAck,
    Paused,
    Completed,
    Failed,
    Aborted,
}

impl AutopilotStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Running => "Running",
            Self::WaitingForApproval => "Waiting approval",
            Self::WaitingForSafetyAck => "Waiting safety ack",
            Self::Paused => "Paused",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Aborted => "Aborted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OpenAiSafetyCheck {
    pub id: String,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutopilotStep {
    pub index: usize,
    pub captured_at: DateTime<Utc>,
    pub observation: String,
    pub model_summary: String,
    pub action_description: String,
    pub action: Option<InputAction>,
    pub actions: Vec<InputAction>,
    pub risk: RiskLevel,
    pub decision: PolicyDecision,
    pub verification: Option<VerificationResult>,
    pub safety_checks: Vec<OpenAiSafetyCheck>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AutopilotPlan {
    pub response_id: Option<String>,
    pub call_id: Option<String>,
    pub summary: String,
    pub action: Option<InputAction>,
    pub actions: Vec<InputAction>,
    pub action_description: String,
    pub safety_checks: Vec<OpenAiSafetyCheck>,
    pub completed: bool,
}

#[derive(Clone, Debug)]
pub struct AutopilotController {
    pub goal: String,
    pub status: AutopilotStatus,
    pub settings: AutopilotSettings,
    pub steps: Vec<AutopilotStep>,
    pub previous_response_id: Option<String>,
    pub last_call_id: Option<String>,
    pub pending_safety_checks: Vec<OpenAiSafetyCheck>,
    pub acknowledged_safety_checks: Vec<OpenAiSafetyCheck>,
    pub pending_safety_plan: Option<AutopilotPlan>,
    pub last_step_at: Option<DateTime<Utc>>,
    pub no_change_verifications: usize,
}

impl Default for AutopilotController {
    fn default() -> Self {
        Self {
            goal: "Diagnose den Remote-Desktop und fuehre den naechsten sicheren Schritt aus."
                .to_owned(),
            status: AutopilotStatus::Idle,
            settings: AutopilotSettings::default(),
            steps: Vec::new(),
            previous_response_id: None,
            last_call_id: None,
            pending_safety_checks: Vec::new(),
            acknowledged_safety_checks: Vec::new(),
            pending_safety_plan: None,
            last_step_at: None,
            no_change_verifications: 0,
        }
    }
}

impl AutopilotController {
    pub fn start(&mut self, goal: String) {
        self.goal = redact_secret_text(&goal);
        self.status = AutopilotStatus::Running;
        self.steps.clear();
        self.previous_response_id = None;
        self.last_call_id = None;
        self.pending_safety_checks.clear();
        self.acknowledged_safety_checks.clear();
        self.pending_safety_plan = None;
        self.last_step_at = None;
        self.no_change_verifications = 0;
    }

    pub fn pause(&mut self) {
        if matches!(
            self.status,
            AutopilotStatus::Running
                | AutopilotStatus::WaitingForApproval
                | AutopilotStatus::WaitingForSafetyAck
        ) {
            self.status = AutopilotStatus::Paused;
        }
    }

    pub fn resume(&mut self) {
        if self.status == AutopilotStatus::Paused {
            self.status = AutopilotStatus::Running;
        }
    }

    pub fn abort(&mut self) {
        self.status = AutopilotStatus::Aborted;
    }

    pub fn acknowledge_safety_checks(&mut self) {
        self.acknowledged_safety_checks
            .extend(self.pending_safety_checks.drain(..));
        if self.status == AutopilotStatus::WaitingForSafetyAck {
            self.status = AutopilotStatus::Running;
        }
    }

    pub fn take_pending_safety_plan(&mut self) -> Option<AutopilotPlan> {
        self.pending_safety_plan.take()
    }

    pub fn can_step(&self) -> bool {
        if self.status != AutopilotStatus::Running || self.steps.len() >= self.settings.max_steps {
            return false;
        }
        let Some(last_step_at) = self.last_step_at else {
            return true;
        };
        let elapsed = Utc::now()
            .signed_duration_since(last_step_at)
            .to_std()
            .unwrap_or_default();
        elapsed >= Duration::from_millis(self.settings.step_delay_millis)
    }

    pub fn record_step(&mut self, step: AutopilotStep) {
        if step
            .verification
            .as_ref()
            .is_some_and(|verification| !verification.success)
        {
            self.no_change_verifications += 1;
        } else if step.verification.is_some() {
            self.no_change_verifications = 0;
        }
        self.steps.push(step);
        self.last_step_at = Some(Utc::now());
        if self.steps.len() >= self.settings.max_steps {
            self.status = AutopilotStatus::Completed;
        } else if self.no_change_verifications >= 2 {
            self.status = AutopilotStatus::Failed;
        }
    }
}

pub trait AutopilotProvider {
    fn plan(&self, request: &AutopilotRequest<'_>) -> Result<AutopilotPlan>;
}

pub struct AutopilotRequest<'a> {
    pub goal: &'a str,
    pub frame: &'a FrameUpdate,
    pub observation: &'a ScreenObservation,
    pub settings: &'a AutopilotSettings,
    pub previous_response_id: Option<&'a str>,
    pub last_call_id: Option<&'a str>,
    pub acknowledged_safety_checks: &'a [OpenAiSafetyCheck],
}

#[derive(Default)]
pub struct LocalAutopilotProvider;

impl AutopilotProvider for LocalAutopilotProvider {
    fn plan(&self, request: &AutopilotRequest<'_>) -> Result<AutopilotPlan> {
        let agent = ComputerUseAgent::default();
        let action = agent.plan_next_step(request.observation, request.goal);
        Ok(AutopilotPlan {
            response_id: None,
            call_id: None,
            summary: format!("Local planner: {}", request.observation.summary),
            action: Some(action.action.clone()),
            actions: vec![action.action],
            action_description: action.description,
            safety_checks: Vec::new(),
            completed: false,
        })
    }
}

pub struct OpenAiComputerUseProvider {
    api_key: String,
    client: reqwest::blocking::Client,
}

impl OpenAiComputerUseProvider {
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow!("OPENAI_API_KEY is not set for OpenAI Computer Use"))?;
        if api_key.trim().is_empty() {
            anyhow::bail!("OPENAI_API_KEY is empty");
        }
        Ok(Self {
            api_key,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn create_response(&self, body: serde_json::Value) -> Result<OpenAiResponse> {
        let response = self
            .client
            .post(OPENAI_RESPONSES_URL)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .context("send OpenAI computer-use request")?;
        let status = response.status();
        let text = response.text().context("read OpenAI response")?;
        if !status.is_success() {
            anyhow::bail!(
                "OpenAI API returned {status}: {}",
                redact_secret_text(&text)
            );
        }
        parse_openai_response(&text)
    }
}

impl AutopilotProvider for OpenAiComputerUseProvider {
    fn plan(&self, request: &AutopilotRequest<'_>) -> Result<AutopilotPlan> {
        let screenshot = encode_frame_png_data_url(request.frame)?;
        let tool = if request.settings.openai_model == "computer-use-preview" {
            serde_json::json!({
                "type": "computer_use_preview",
                "display_width": request.frame.width,
                "display_height": request.frame.height,
                "environment": "browser"
            })
        } else {
            serde_json::json!({ "type": "computer" })
        };

        let mut body = serde_json::json!({
            "model": request.settings.openai_model,
            "tools": [tool],
            "reasoning": { "summary": "concise" },
            "truncation": "auto"
        });

        if let (Some(previous_response_id), Some(call_id)) =
            (request.previous_response_id, request.last_call_id)
        {
            body["previous_response_id"] =
                serde_json::Value::String(previous_response_id.to_owned());
            body["input"] = serde_json::json!([{
                "type": "computer_call_output",
                "call_id": call_id,
                "acknowledged_safety_checks": request.acknowledged_safety_checks,
                "output": {
                    "type": "computer_screenshot",
                    "image_url": screenshot
                }
            }]);
        } else {
            body["input"] = serde_json::json!([{
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": format!(
                            "Goal: {}\nYou are controlling a remote Windows desktop through Relayne RDP. Avoid destructive or security-sensitive actions. Return the next computer action only when it advances the goal.",
                            redact_secret_text(request.goal)
                        )
                    },
                    {
                        "type": "input_image",
                        "image_url": screenshot
                    }
                ]
            }]);
        }

        openai_response_to_plan(self.create_response(body)?)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct OpenAiResponse {
    id: Option<String>,
    #[serde(default)]
    output: Vec<OpenAiOutputItem>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
enum OpenAiOutputItem {
    #[serde(rename = "computer_call")]
    ComputerCall {
        call_id: Option<String>,
        action: Option<OpenAiComputerAction>,
        #[serde(default)]
        actions: Vec<OpenAiComputerAction>,
        #[serde(default)]
        pending_safety_checks: Vec<OpenAiSafetyCheck>,
    },
    #[serde(rename = "message")]
    Message { content: Option<serde_json::Value> },
    #[serde(rename = "reasoning")]
    Reasoning { summary: Option<serde_json::Value> },
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpenAiComputerAction {
    Click {
        x: u16,
        y: u16,
        button: Option<String>,
    },
    DoubleClick {
        x: u16,
        y: u16,
        button: Option<String>,
    },
    Move {
        x: u16,
        y: u16,
    },
    Scroll {
        x: u16,
        y: u16,
        #[serde(default, alias = "scrollX")]
        scroll_x: Option<i16>,
        #[serde(default, alias = "scrollY")]
        scroll_y: Option<i16>,
        #[serde(default, alias = "deltaY")]
        delta_y: Option<i16>,
    },
    Type {
        text: String,
    },
    Keypress {
        keys: Vec<String>,
    },
    Wait {
        ms: Option<u64>,
    },
    Screenshot,
    #[serde(other)]
    Unsupported,
}

fn parse_openai_response(json: &str) -> Result<OpenAiResponse> {
    serde_json::from_str(json).context("parse OpenAI computer-use response")
}

fn openai_response_to_plan(response: OpenAiResponse) -> Result<AutopilotPlan> {
    let mut summary = Vec::new();
    let mut final_text = Vec::new();
    let mut computer_call = None;

    for item in response.output {
        match item {
            OpenAiOutputItem::ComputerCall {
                call_id,
                action,
                actions,
                pending_safety_checks,
            } => {
                let mut planned_actions = Vec::new();
                if let Some(action) = action {
                    planned_actions.push(action);
                }
                planned_actions.extend(actions);
                if !planned_actions.is_empty() {
                    computer_call = Some((call_id, planned_actions, pending_safety_checks));
                }
            }
            OpenAiOutputItem::Reasoning {
                summary: Some(value),
            } => collect_text(&value, &mut summary),
            OpenAiOutputItem::Message {
                content: Some(value),
            } => collect_text(&value, &mut final_text),
            _ => {}
        }
    }

    if let Some((call_id, actions, safety_checks)) = computer_call {
        let mapped = actions
            .into_iter()
            .map(map_openai_action)
            .collect::<Result<Vec<_>>>()?;
        let first = mapped.first().cloned();
        return Ok(AutopilotPlan {
            response_id: response.id,
            call_id,
            summary: if summary.is_empty() {
                "OpenAI Computer Use proposed a remote action.".to_owned()
            } else {
                summary.join(" ")
            },
            action_description: describe_actions(&mapped),
            action: first,
            actions: mapped,
            safety_checks,
            completed: false,
        });
    }

    Ok(AutopilotPlan {
        response_id: response.id,
        call_id: None,
        summary: if final_text.is_empty() {
            "OpenAI Computer Use returned no computer action.".to_owned()
        } else {
            final_text.join(" ")
        },
        action_description: "No further action".to_owned(),
        action: None,
        actions: Vec::new(),
        safety_checks: Vec::new(),
        completed: true,
    })
}

pub fn map_openai_action(action: OpenAiComputerAction) -> Result<InputAction> {
    Ok(match action {
        OpenAiComputerAction::Click { x, y, button } => InputAction::Click {
            x,
            y,
            button: map_button(button.as_deref()),
        },
        OpenAiComputerAction::DoubleClick { x, y, button } => InputAction::DoubleClick {
            x,
            y,
            button: map_button(button.as_deref()),
        },
        OpenAiComputerAction::Move { x, y } => InputAction::MovePointer { x, y },
        OpenAiComputerAction::Scroll {
            x,
            y,
            scroll_x,
            scroll_y,
            delta_y,
        } => InputAction::Scroll {
            x,
            y,
            delta: scroll_y.or(delta_y).unwrap_or_else(|| {
                if scroll_x.unwrap_or_default() == 0 {
                    -480
                } else {
                    0
                }
            }),
        },
        OpenAiComputerAction::Type { text } => InputAction::TypeText { text },
        OpenAiComputerAction::Keypress { keys } => InputAction::Hotkey { keys },
        OpenAiComputerAction::Wait { ms } => InputAction::Wait {
            millis: ms.unwrap_or(1000),
        },
        OpenAiComputerAction::Screenshot => InputAction::Screenshot,
        OpenAiComputerAction::Unsupported => anyhow::bail!("unsupported OpenAI computer action"),
    })
}

pub fn encode_frame_png_data_url(frame: &FrameUpdate) -> Result<String> {
    let image: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_raw(
        u32::from(frame.width),
        u32::from(frame.height),
        frame.pixels_rgba.clone(),
    )
    .context("frame pixels do not match dimensions")?;
    let mut bytes = Cursor::new(Vec::new());
    image
        .write_to(&mut bytes, ImageFormat::Png)
        .context("encode frame as PNG")?;
    Ok(format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes.into_inner())
    ))
}

pub fn classify_plan_action(
    action: &InputAction,
    settings: &AutopilotSettings,
) -> (RiskLevel, PolicyDecision) {
    let policy = PolicyEngine;
    let risk = policy.classify_action(action);
    let mut decision = policy.decision_for(action);
    if settings.require_approval_for_every_mutation
        && !settings.agentic_runbook_mode
        && !matches!(risk, RiskLevel::ReadOnly | RiskLevel::LowRisk)
        && decision == PolicyDecision::Allow
    {
        decision = PolicyDecision::RequireApproval;
    }
    if settings.require_approval_for_every_mutation
        && !settings.agentic_runbook_mode
        && matches!(risk, RiskLevel::ElevatedRisk)
    {
        decision = PolicyDecision::RequireApproval;
    }
    (risk, decision)
}

fn map_button(button: Option<&str>) -> MouseButton {
    match button.unwrap_or("left").to_ascii_lowercase().as_str() {
        "right" => MouseButton::Right,
        "middle" => MouseButton::Middle,
        _ => MouseButton::Left,
    }
}

fn describe_action(action: &InputAction) -> String {
    match action {
        InputAction::ClipboardFocus { active } => format!("clipboard focus {active}"),
        InputAction::Key { scan_code, pressed } => format!(
            "key {scan_code:#x} {}",
            if *pressed { "down" } else { "up" }
        ),
        InputAction::PointerButton {
            x,
            y,
            button,
            pressed,
        } => format!(
            "{button:?} {} at {x},{y}",
            if *pressed { "down" } else { "up" }
        ),
        InputAction::Resize { width, height } => format!("resize desktop to {width}x{height}"),
        InputAction::ClipboardFiles { paths } => {
            format!("share {} file(s) via clipboard", paths.len())
        }
        InputAction::ClipboardDownload { .. } => "download clipboard files".to_owned(),
        InputAction::MovePointer { x, y } => format!("move pointer to {x},{y}"),
        InputAction::Click { x, y, button } => format!("click {button:?} at {x},{y}"),
        InputAction::DoubleClick { x, y, button } => format!("double-click {button:?} at {x},{y}"),
        InputAction::Scroll { x, y, delta } => format!("scroll {delta} at {x},{y}"),
        InputAction::TypeText { text } => {
            format!("type {} character(s)", text.chars().count())
        }
        InputAction::Hotkey { keys } => format!("keypress {}", keys.join("+")),
        InputAction::Wait { millis } => format!("wait {millis}ms"),
        InputAction::Screenshot => "screenshot".to_owned(),
        InputAction::Verify { expectation } => format!("verify {expectation}"),
    }
}

fn describe_actions(actions: &[InputAction]) -> String {
    match actions {
        [] => "No further action".to_owned(),
        [single] => describe_action(single),
        many => format!(
            "{} batched actions: {}",
            many.len(),
            many.iter()
                .map(describe_action)
                .collect::<Vec<_>>()
                .join("; ")
        ),
    }
}

fn collect_text(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_text(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(|value| value.as_str()) {
                out.push(text.to_owned());
            }
            if let Some(text) = map.get("summary_text").and_then(|value| value.as_str()) {
                out.push(text.to_owned());
            }
            if let Some(content) = map.get("content") {
                collect_text(content, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DirtyRegion;
    use uuid::Uuid;

    fn frame() -> FrameUpdate {
        FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 2,
            height: 2,
            pixels_rgba: vec![
                255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255,
            ],
            dirty_regions: vec![DirtyRegion {
                left: 0,
                top: 0,
                right: 2,
                bottom: 2,
            }],
            frame_hash: 7,
            captured_at: Utc::now(),
        }
    }

    #[test]
    fn screenshot_encoding_produces_png_data_url() {
        let encoded = encode_frame_png_data_url(&frame()).expect("encoded frame");

        assert!(encoded.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn maps_openai_click_to_input_action() {
        let action = map_openai_action(OpenAiComputerAction::Click {
            x: 10,
            y: 20,
            button: Some("right".to_owned()),
        })
        .expect("mapped action");

        assert_eq!(
            action,
            InputAction::Click {
                x: 10,
                y: 20,
                button: MouseButton::Right
            }
        );
    }

    #[test]
    fn parses_computer_call_response() {
        let json = r#"{
            "id": "resp_1",
            "output": [
                {
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "Need to click Start."}]
                },
                {
                    "type": "computer_call",
                    "call_id": "call_1",
                    "action": {"type": "click", "x": 40, "y": 50, "button": "left"},
                    "pending_safety_checks": []
                }
            ]
        }"#;

        let plan =
            openai_response_to_plan(parse_openai_response(json).expect("response")).expect("plan");

        assert_eq!(plan.response_id.as_deref(), Some("resp_1"));
        assert_eq!(plan.call_id.as_deref(), Some("call_1"));
        assert!(matches!(
            plan.action,
            Some(InputAction::Click { x: 40, y: 50, .. })
        ));
    }

    #[test]
    fn parses_safety_checks() {
        let json = r#"{
            "id": "resp_1",
            "output": [{
                "type": "computer_call",
                "call_id": "call_1",
                "action": {"type": "type", "text": "hello"},
                "pending_safety_checks": [{
                    "id": "safe_1",
                    "code": "malicious_instructions",
                    "message": "warning"
                }]
            }]
        }"#;

        let plan =
            openai_response_to_plan(parse_openai_response(json).expect("response")).expect("plan");

        assert_eq!(plan.safety_checks.len(), 1);
        assert_eq!(plan.safety_checks[0].code, "malicious_instructions");
    }

    #[test]
    fn parses_ga_batched_computer_actions() {
        let json = r#"{
            "id": "resp_2",
            "output": [{
                "type": "computer_call",
                "call_id": "call_2",
                "actions": [
                    {"type": "click", "x": 405, "y": 157, "button": "left"},
                    {"type": "type", "text": "penguin"}
                ]
            }]
        }"#;

        let plan =
            openai_response_to_plan(parse_openai_response(json).expect("response")).expect("plan");

        assert_eq!(plan.response_id.as_deref(), Some("resp_2"));
        assert!(matches!(
            plan.action,
            Some(InputAction::Click { x: 405, y: 157, .. })
        ));
        assert_eq!(plan.actions.len(), 2);
        assert!(matches!(
            plan.actions[1],
            InputAction::TypeText { ref text } if text == "penguin"
        ));
    }

    #[test]
    fn controller_stops_after_max_steps() {
        let mut controller = AutopilotController::default();
        controller.settings.max_steps = 1;
        controller.start("goal".to_owned());
        controller.record_step(AutopilotStep {
            index: 1,
            captured_at: Utc::now(),
            observation: "obs".to_owned(),
            model_summary: "summary".to_owned(),
            action_description: "wait".to_owned(),
            action: Some(InputAction::Wait { millis: 1 }),
            actions: vec![InputAction::Wait { millis: 1 }],
            risk: RiskLevel::ReadOnly,
            decision: PolicyDecision::Allow,
            verification: None,
            safety_checks: Vec::new(),
            error: None,
        });

        assert_eq!(controller.status, AutopilotStatus::Completed);
    }
}
