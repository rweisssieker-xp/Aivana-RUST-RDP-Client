use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Rdp,
    Ssh,
    Vnc,
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Rdp => "RDP",
            Self::Ssh => "SSH",
            Self::Vnc => "VNC",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::Rdp => 3389,
            Self::Ssh => 22,
            Self::Vnc => 5900,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConnectionProfile {
    pub id: Uuid,
    #[serde(default)]
    pub workspace_id: Option<Uuid>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub credential_id: Option<Uuid>,
    #[serde(default, skip_serializing)]
    pub password: String,
    pub domain: String,
    pub protocol: Protocol,
    pub group: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    #[serde(default)]
    pub options: crate::connection_options::ProfileOptions,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ConnectionProfile {
    pub fn sample(name: &str, host: &str, group: &str, favorite: bool) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            workspace_id: None,
            name: name.to_owned(),
            host: host.to_owned(),
            port: Protocol::Rdp.default_port(),
            username: "Administrator".to_owned(),
            credential_id: None,
            password: String::new(),
            domain: String::new(),
            protocol: Protocol::Rdp,
            group: group.to_owned(),
            tags: vec!["windows".to_owned(), "rdp".to_owned()],
            favorite,
            options: Default::default(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RemoteSession {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub title: String,
    pub status: SessionStatus,
    pub connected_at: DateTime<Utc>,
    pub metrics: PerformanceMetrics,
    pub last_error: Option<String>,
    pub frame_size: Option<(u16, u16)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SessionStatus {
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
    Suspended,
    Disconnected,
    Failed,
}

impl SessionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "Connecting",
            Self::Authenticating => "Authenticating",
            Self::Connected => "Connected",
            Self::Reconnecting => "Reconnecting",
            Self::Suspended => "Suspended",
            Self::Disconnected => "Disconnected",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PerformanceMetrics {
    pub latency_ms: f32,
    pub bandwidth_mbps: f32,
    pub frame_rate: f32,
    pub packet_loss_pct: f32,
    pub quality_score: u8,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            latency_ms: 0.0,
            bandwidth_mbps: 0.0,
            frame_rate: 0.0,
            packet_loss_pct: 0.0,
            quality_score: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DraftProfile {
    pub protocol: Protocol,
    pub name: String,
    pub host: String,
    pub port: String,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub group: String,
    pub tags: String,
    pub favorite: bool,
    pub options: crate::connection_options::ProfileOptions,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialRef {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub username: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretCredential {
    pub username: String,
    pub password: String,
    pub domain: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum CertificateTrustStatus {
    Unknown,
    Trusted,
    Rejected,
    Changed,
}

#[derive(Clone, Debug)]
pub struct FrameUpdate {
    pub session_id: Uuid,
    pub width: u16,
    pub height: u16,
    pub pixels_rgba: Vec<u8>,
    pub dirty_regions: Vec<DirtyRegion>,
    pub frame_hash: u64,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DirtyRegion {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum InputAction {
    ClipboardFocus {
        active: bool,
    },
    ClipboardFiles {
        paths: Vec<String>,
    },
    ClipboardDownload {
        directory: String,
    },
    Resize {
        width: u16,
        height: u16,
    },
    /// PC set-1 scan code; bit 8 denotes an extended (E0) key.
    Key {
        scan_code: u16,
        pressed: bool,
    },
    PointerButton {
        x: u16,
        y: u16,
        button: MouseButton,
        pressed: bool,
    },
    MovePointer {
        x: u16,
        y: u16,
    },
    Click {
        x: u16,
        y: u16,
        button: MouseButton,
    },
    DoubleClick {
        x: u16,
        y: u16,
        button: MouseButton,
    },
    Scroll {
        x: u16,
        y: u16,
        delta: i16,
    },
    TypeText {
        text: String,
    },
    Hotkey {
        keys: Vec<String>,
    },
    Wait {
        millis: u64,
    },
    Screenshot,
    Verify {
        expectation: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum EngineEvent {
    GatewayMessage {
        session_id: Uuid,
        message: String,
    },
    StatusChanged {
        session_id: Uuid,
        status: SessionStatus,
    },
    Frame(FrameUpdate),
    Error {
        session_id: Uuid,
        class: DiagnosticClass,
        message: String,
    },
    Diagnostic {
        session_id: Uuid,
        message: String,
    },
    Disconnected {
        session_id: Uuid,
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum DiagnosticClass {
    Dns,
    Tcp,
    Tls,
    CredSspNla,
    Auth,
    Certificate,
    Protocol,
    Timeout,
    Display,
    Input,
    Credential,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiagnosticFinding {
    pub class: DiagnosticClass,
    pub severity: DiagnosticSeverity,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightReport {
    pub profile_id: Uuid,
    pub checked_at: DateTime<Utc>,
    pub findings: Vec<DiagnosticFinding>,
    pub connect_recommended: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SessionEventKind {
    ConnectionStage,
    Diagnostic,
    UserAction,
    AiObservation,
    AiAction,
    Approval,
    Error,
    Screenshot,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionEvent {
    pub id: Uuid,
    pub session_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub kind: SessionEventKind,
    pub message: String,
    pub redacted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RiskLevel {
    ReadOnly,
    LowRisk,
    ElevatedRisk,
    Destructive,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireApproval,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AiAction {
    pub id: Uuid,
    pub session_id: Option<Uuid>,
    pub description: String,
    pub action: InputAction,
    pub risk: RiskLevel,
    pub decision: PolicyDecision,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub action_id: Uuid,
    pub session_id: Option<Uuid>,
    pub description: String,
    pub action: InputAction,
    #[serde(default)]
    pub actions: Vec<InputAction>,
    pub reason: String,
    pub expected_result: String,
    pub risk: RiskLevel,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    AllowedOnce,
    AllowedForRunbook,
    Denied,
    Aborted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ScreenObservation {
    pub session_id: Uuid,
    pub frame_hash: u64,
    pub summary: String,
    pub detected_text: Vec<String>,
    pub ui_hypotheses: Vec<String>,
    pub dialogs: Vec<DialogObservation>,
    pub ocr: OcrResult,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AiExplanation {
    pub title: String,
    pub likely_root_cause: String,
    pub evidence: Vec<AiEvidence>,
    pub next_safe_step: String,
    pub risk: RiskLevel,
    pub confidence: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AiEvidence {
    pub source: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OcrResult {
    pub text: Vec<String>,
    pub confidence: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DialogObservation {
    pub title: String,
    pub kind: DialogKind,
    pub confidence: f32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum DialogKind {
    Login,
    WindowsSecurity,
    Uac,
    Error,
    EventViewer,
    Services,
    TaskManager,
    Settings,
    Locked,
    BlackScreen,
    Rebooting,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionSummary {
    pub headline: String,
    pub details: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunbookRecommendation {
    pub runbook_id: Uuid,
    pub name: String,
    pub reason: String,
    pub confidence: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncidentDraft {
    pub title: String,
    pub root_cause: String,
    pub customer_text: String,
    pub internal_note: String,
    pub open_tasks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChangeSummary {
    pub headline: String,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationResult {
    pub success: bool,
    pub frame_hash_before: u64,
    pub frame_hash_after: u64,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlackboxSnapshot {
    pub id: Uuid,
    pub session_id: Uuid,
    pub reason: String,
    pub frame_hash: u64,
    pub width: u16,
    pub height: u16,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMemory {
    pub id: Uuid,
    pub host: String,
    pub workspace_id: Option<Uuid>,
    pub known_issues: Vec<String>,
    pub successful_fixes: Vec<String>,
    pub certificate_changes: Vec<String>,
    pub login_notes: Vec<String>,
    pub disconnect_patterns: Vec<String>,
    pub maintenance_notes: Vec<String>,
    pub runbook_results: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkspaceMemory {
    pub workspace_id: Uuid,
    pub notes: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Runbook {
    pub id: Uuid,
    pub name: String,
    pub category: RunbookCategory,
    pub risk: RiskLevel,
    pub steps: Vec<RunbookStep>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RunbookCategory {
    Connectivity,
    Authentication,
    Certificate,
    Performance,
    Evidence,
    Services,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunbookStep {
    pub id: Uuid,
    pub title: String,
    pub action: InputAction,
    pub risk: RiskLevel,
    pub requires_approval: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunbookExecution {
    pub id: Uuid,
    pub session_id: Uuid,
    pub runbook_id: Uuid,
    pub current_step: usize,
    pub status: RunbookStatus,
    pub started_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RunbookStatus {
    Running,
    Paused,
    WaitingForApproval,
    Completed,
    Aborted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateIdentity {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub status: CertificateTrustStatus,
}

impl From<&ConnectionProfile> for DraftProfile {
    fn from(profile: &ConnectionProfile) -> Self {
        Self {
            protocol: profile.protocol.clone(),
            name: profile.name.clone(),
            host: profile.host.clone(),
            port: profile.port.to_string(),
            username: profile.username.clone(),
            password: String::new(),
            domain: profile.domain.clone(),
            group: profile.group.clone(),
            tags: profile.tags.join(", "),
            favorite: profile.favorite,
            options: profile.options.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_default_ports_match_common_remote_desktop_ports() {
        assert_eq!(Protocol::Rdp.default_port(), 3389);
        assert_eq!(Protocol::Ssh.default_port(), 22);
        assert_eq!(Protocol::Vnc.default_port(), 5900);
    }

    #[test]
    fn draft_profile_preserves_editable_profile_fields() {
        let mut profile = ConnectionProfile::sample("Prod", "10.0.0.5", "Ops", true);
        profile.username = "admin".to_owned();
        profile.password = "secret".to_owned();
        profile.domain = "corp".to_owned();
        profile.tags = vec!["windows".to_owned(), "critical".to_owned()];

        let draft = DraftProfile::from(&profile);

        assert_eq!(draft.name, "Prod");
        assert_eq!(draft.host, "10.0.0.5");
        assert_eq!(draft.port, "3389");
        assert_eq!(draft.username, "admin");
        assert_eq!(draft.password, "");
        assert_eq!(draft.domain, "corp");
        assert_eq!(draft.group, "Ops");
        assert_eq!(draft.tags, "windows, critical");
        assert!(draft.favorite);
    }
}
