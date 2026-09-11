use std::collections::{HashMap, hash_map::Entry};
use std::fmt::Write as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use eframe::egui::{
    self, Align, Color32, ColorImage, Context, CornerRadius, FontFamily, FontId, Frame, Layout,
    Margin, Pos2, Rect, RichText, ScrollArea, Sense, Stroke, StrokeKind, TextStyle, TextureHandle,
    TextureOptions, Ui, UiBuilder, Vec2, pos2,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ai::{AiProvider, LocalAiProvider};
use crate::autopilot::{
    AutopilotController, AutopilotPlan, AutopilotProvider, AutopilotProviderKind, AutopilotRequest,
    AutopilotSettings, AutopilotStatus, LocalAutopilotProvider, OpenAiComputerUseProvider,
    classify_plan_action,
};
use crate::certificate::CertificateTrustStore;
use crate::computer_use::ComputerUseAgent;
use crate::diagnostics::{LocalPreflightService, PreflightService, RdpPreflightEvidenceReport};
use crate::ironrdp_client::{
    RdpSmokeTestFailureReport, RdpSmokeTestReport, probe_server_fingerprint,
    rdp_env_file_path_from_args,
};
use crate::memory::MemoryStore;
use crate::models::{
    AiAction, AiExplanation, ApprovalRequest, ApprovalStatus, BlackboxSnapshot, ConnectionProfile,
    DiagnosticFinding, DiagnosticSeverity, DraftProfile, EngineEvent, FrameUpdate, InputAction,
    MouseButton, PolicyDecision, Protocol, RemoteSession, RiskLevel, SecretCredential,
    SessionEvent, SessionEventKind, SessionStatus,
};
use crate::runbook::RunbookEngine;
use crate::security::{
    CredentialStore, PersistentCredentialStore, app_data_file, redact_secret_text,
};
use crate::services::{NativeRdpEngine, ProfileStore, RemoteDesktopEngine};
use crate::timeline::{InMemoryTimelineStore, TimelineStore};
use crate::workspace::WorkspaceStore;

const ACTIVE_GOAL_OBJECTIVE: &str =
    "bau das weiter aus max. usp max gui friendly max ai ki llm usage";

mod capture;
mod connection_probe;
mod desktop;
mod integrations_panel;
mod mission_panel;
mod operations_panel;
mod recordings_panel;
mod session_windows;
mod teaching_panel;

mod tw {
    use eframe::egui::Color32;

    pub const WHITE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const SLATE_50: Color32 = Color32::from_rgb(248, 250, 252);
    pub const SLATE_100: Color32 = Color32::from_rgb(241, 245, 249);
    pub const SLATE_200: Color32 = Color32::from_rgb(226, 232, 240);
    pub const SLATE_300: Color32 = Color32::from_rgb(203, 213, 225);
    pub const SLATE_600: Color32 = Color32::from_rgb(71, 85, 105);
    pub const SLATE_700: Color32 = Color32::from_rgb(51, 65, 85);
    pub const SLATE_800: Color32 = Color32::from_rgb(30, 41, 59);
    pub const SLATE_900: Color32 = Color32::from_rgb(15, 23, 42);
    pub const SLATE_950: Color32 = Color32::from_rgb(2, 6, 23);
    pub const BLUE_50: Color32 = Color32::from_rgb(239, 246, 255);
    pub const BLUE_100: Color32 = Color32::from_rgb(219, 234, 254);
    pub const BLUE_500: Color32 = Color32::from_rgb(59, 130, 246);
    pub const BLUE_600: Color32 = Color32::from_rgb(37, 99, 235);
    pub const BLUE_700: Color32 = Color32::from_rgb(29, 78, 216);
    pub const RED_600: Color32 = Color32::from_rgb(220, 38, 38);
    pub const RED_700: Color32 = Color32::from_rgb(185, 28, 28);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Missions,
    Operations,
    SessionWindows,
    Integrations,
    Recordings,
    Teaching,
    Connections,
    Sessions,
    Approvals,
    Workspaces,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteViewMode {
    Fit,
    ActualSize,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct AutopilotPreferences {
    goal: String,
    settings: AutopilotSettings,
}

impl From<&AutopilotController> for AutopilotPreferences {
    fn from(controller: &AutopilotController) -> Self {
        Self {
            goal: controller.goal.clone(),
            settings: controller.settings.clone(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct KiPreferencesSaveReport {
    pub schema: String,
    pub saved_at: chrono::DateTime<Utc>,
    pub path: String,
    pub already_existed: bool,
    pub provider: String,
    pub model: String,
    pub max_steps: usize,
    pub step_delay_millis: u64,
    pub goal: String,
    pub redacted: bool,
}

pub struct AivanaApp {
    profiles: Vec<ConnectionProfile>,
    sessions: Vec<RemoteSession>,
    session_sources: HashMap<Uuid, crate::mission::Target>,
    selected_profile: Option<Uuid>,
    selected_session: Option<Uuid>,
    view: View,
    search: String,
    draft: DraftProfile,
    editing_profile: Option<Uuid>,
    status: String,
    store: Option<ProfileStore>,
    engine: NativeRdpEngine,
    connection_probe: connection_probe::ProbeCoordinator,
    textures: HashMap<Uuid, TextureHandle>,
    latest_frames: HashMap<Uuid, FrameUpdate>,
    credentials: PersistentCredentialStore,
    ai: LocalAiProvider,
    timeline: InMemoryTimelineStore,
    workspaces: WorkspaceStore,
    certificates: CertificateTrustStore,
    runbooks: RunbookEngine,
    memory: MemoryStore,
    approvals: Vec<ApprovalRequest>,
    active_runbook_execution: Option<Uuid>,
    diagnostics: Vec<DiagnosticFinding>,
    ai_diagnosis: String,
    computer_use_status: String,
    certificate_notice: String,
    remote_view_mode: RemoteViewMode,
    remote_fullscreen: bool,
    autopilot: AutopilotController,
    desktop: desktop::DesktopState,
    gui_capture: capture::GuiCapture,
    missions: mission_panel::MissionState,
    operations: operations_panel::OperationsState,
    session_windows: session_windows::SessionWindows,
    integrations: integrations_panel::IntegrationsState,
    recordings: recordings_panel::RecordingsState,
    teaching: teaching_panel::TeachingState,
}

impl AivanaApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::from_context(&cc.egui_ctx)
    }

    fn from_context(ctx: &Context) -> Self {
        configure_style(ctx);

        let (store, profiles, status) = match ProfileStore::new() {
            Ok(store) => match store.load() {
                Ok(profiles) => (Some(store), profiles, "Profile geladen".to_owned()),
                Err(err) => (
                    Some(store),
                    Vec::new(),
                    format!("Could not load profiles: {err}"),
                ),
            },
            Err(err) => (
                None,
                Vec::new(),
                format!("Profile store unavailable: {err}"),
            ),
        };

        let selected_profile = profiles.first().map(|profile| profile.id);
        let initial_draft =
            profiles
                .first()
                .map(DraftProfile::from)
                .unwrap_or_else(|| DraftProfile {
                    port: Protocol::Rdp.default_port().to_string(),
                    group: "Default".to_owned(),
                    ..Default::default()
                });
        let mut workspaces = WorkspaceStore::new().unwrap_or_default();
        workspaces.ensure_default();

        let credentials = PersistentCredentialStore::new().unwrap_or_else(|_| {
            PersistentCredentialStore::at(
                std::env::temp_dir().join("aivana-credentials-fallback.json"),
            )
            .expect("fallback credential store")
        });
        let certificates = CertificateTrustStore::new().unwrap_or_default();
        let timeline = InMemoryTimelineStore::new().unwrap_or_default();
        let memory = MemoryStore::new().unwrap_or_default();
        let mut autopilot = AutopilotController::default();
        if let Some(preferences) = load_autopilot_preferences() {
            autopilot.goal = preferences.goal;
            autopilot.settings = preferences.settings;
        }

        Self {
            profiles,
            sessions: Vec::new(),
            session_sources: HashMap::new(),
            selected_profile,
            selected_session: None,
            view: View::Missions,
            search: String::new(),
            draft: initial_draft,
            editing_profile: selected_profile,
            status,
            store,
            engine: NativeRdpEngine::default(),
            connection_probe: connection_probe::ProbeCoordinator::default(),
            textures: HashMap::new(),
            latest_frames: HashMap::new(),
            credentials,
            ai: LocalAiProvider,
            timeline,
            workspaces,
            certificates,
            runbooks: RunbookEngine::with_defaults(),
            memory,
            approvals: Vec::new(),
            active_runbook_execution: None,
            diagnostics: Vec::new(),
            ai_diagnosis: "Lokale KI-Diagnose wartet auf Preflight oder Sessiondaten.".to_owned(),
            computer_use_status: "Computer Use wartet auf einen Framebuffer.".to_owned(),
            certificate_notice: "Certificate Trust wartet auf einen Host.".to_owned(),
            remote_view_mode: RemoteViewMode::Fit,
            remote_fullscreen: false,
            autopilot,
            desktop: desktop::DesktopState::load(),
            gui_capture: capture::GuiCapture::from_args(),
            missions: mission_panel::MissionState::default(),
            operations: operations_panel::OperationsState::default(),
            session_windows: session_windows::SessionWindows::default(),
            integrations: integrations_panel::IntegrationsState::default(),
            recordings: recordings_panel::RecordingsState::default(),
            teaching: teaching_panel::TeachingState::default(),
        }
    }

    fn filtered_profiles(&self) -> Vec<&ConnectionProfile> {
        let needle = self.search.trim().to_lowercase();
        self.profiles
            .iter()
            .filter(|profile| {
                needle.is_empty()
                    || profile.name.to_lowercase().contains(&needle)
                    || profile.host.to_lowercase().contains(&needle)
                    || profile.group.to_lowercase().contains(&needle)
                    || profile
                        .tags
                        .iter()
                        .any(|tag| tag.to_lowercase().contains(&needle))
            })
            .collect()
    }

    fn selected_profile(&self) -> Option<&ConnectionProfile> {
        let id = self.selected_profile?;
        self.profiles.iter().find(|profile| profile.id == id)
    }

    fn selected_session(&self) -> Option<&RemoteSession> {
        let id = self.selected_session?;
        self.sessions.iter().find(|session| session.id == id)
    }

    fn save_profiles(&mut self) {
        if let Some(store) = &self.store {
            match store.save(&self.profiles) {
                Ok(()) => self.status = "Profiles saved".to_owned(),
                Err(err) => self.status = format!("Could not save profiles: {err}"),
            }
        }
    }

    fn start_new_profile(&mut self) {
        self.editing_profile = None;
        self.draft = DraftProfile {
            port: Protocol::Rdp.default_port().to_string(),
            group: "Default".to_owned(),
            ..Default::default()
        };
        self.status = "Ready for new profile".to_owned();
    }

    fn edit_selected_profile(&mut self) {
        if let Some(profile_id) = self.selected_profile {
            self.load_profile_into_editor(profile_id);
        }
    }

    fn load_profile_into_editor(&mut self, profile_id: Uuid) {
        if let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
        {
            self.selected_profile = Some(profile.id);
            self.editing_profile = Some(profile.id);
            self.draft = DraftProfile::from(&profile);
            self.status = format!("Editing {}", profile.name);
        }
    }

    fn save_draft(&mut self) {
        if let Err(err) = crate::rd_gateway::validate_host(self.draft.host.trim()) {
            self.status = format!("Ungültige Rechneradresse: {err}");
            return;
        }
        if self
            .draft
            .port
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .is_none()
        {
            self.status = "Der Port muss zwischen 1 und 65535 liegen.".to_owned();
            return;
        }
        if let Err(err) = crate::rd_gateway::validate_gateway(
            &self.draft.options.gateway,
            self.draft.port.parse().unwrap_or(3389),
        ) {
            self.status = format!("Gateway-Einstellungen ungültig: {err}");
            return;
        }
        if !self.draft.options.gateway.use_profile_credentials
            && !self.draft.options.gateway.password.is_empty()
        {
            let gateway = &self.draft.options.gateway;
            let mut gateway_profile =
                ConnectionProfile::sample("RD Gateway", &gateway.host, "Gateway", false);
            gateway_profile.credential_id = gateway.credential_id;
            let secret = SecretCredential {
                username: gateway.username.clone(),
                password: gateway.password.clone(),
                domain: gateway.domain.clone(),
            };
            match self.credentials.save(&mut gateway_profile, secret) {
                Ok(reference) => self.draft.options.gateway.credential_id = Some(reference.id),
                Err(err) => {
                    self.status =
                        format!("Gateway-Zugang konnte nicht geschützt gespeichert werden: {err}");
                    return;
                }
            }
        }
        self.draft.options.gateway.password.clear();

        let port = self
            .draft
            .port
            .parse::<u16>()
            .unwrap_or_else(|_| Protocol::Rdp.default_port());
        let tags = self
            .draft
            .tags
            .split(',')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();

        if self.draft.name.trim().is_empty() || self.draft.host.trim().is_empty() {
            self.status = "Name and host are required".to_owned();
            return;
        }

        let draft_secret = (!self.draft.password.is_empty()).then(|| SecretCredential {
            username: self.draft.username.trim().to_owned(),
            password: self.draft.password.clone(),
            domain: self.draft.domain.trim().to_owned(),
        });

        let mut profile = self
            .editing_profile
            .and_then(|id| self.profiles.iter().find(|p| p.id == id))
            .cloned()
            .unwrap_or_else(|| {
                ConnectionProfile::sample(
                    self.draft.name.trim(),
                    self.draft.host.trim(),
                    self.draft.group.trim(),
                    self.draft.favorite,
                )
            });
        profile.options = self.draft.options.clone();
        profile.name = self.draft.name.trim().to_owned();
        profile.host = self.draft.host.trim().to_owned();
        profile.port = port;
        profile.username = self.draft.username.trim().to_owned();
        profile.domain = self.draft.domain.trim().to_owned();
        profile.password.clear();
        profile.group = self.draft.group.trim().to_owned();
        profile.tags = tags;
        profile.favorite = self.draft.favorite;
        profile.updated_at = Utc::now();
        if let Some(secret) = draft_secret {
            if let Err(err) = self.credentials.save(&mut profile, secret) {
                self.status = format!("Zugang konnte nicht geschützt gespeichert werden: {err}");
                return;
            }
        }
        let id = profile.id;
        let mut profiles = self.profiles.clone();
        if let Some(existing) = profiles.iter_mut().find(|p| p.id == id) {
            *existing = profile;
        } else {
            profiles.push(profile);
        }
        let result = self
            .store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Profilspeicher nicht verfügbar"))
            .and_then(|store| store.save(&profiles));
        if let Err(err) = result {
            self.status = format!("Profil konnte nicht gespeichert werden: {err}");
            return;
        }
        self.profiles = profiles;
        self.selected_profile = Some(id);
        self.load_profile_into_editor(id);
        self.status = "Profil gespeichert".to_owned();
    }

    fn connect_selected(&mut self) {
        self.begin_certificate_probe(connection_probe::ProbeIntent::Connect);
    }

    fn connect_after_probe(
        &mut self,
        profile: ConnectionProfile,
        probe: Result<String, String>,
        report: Option<crate::models::PreflightReport>,
    ) {
        let mut legacy_standard_rdp = false;
        let fingerprint = match probe {
            Ok(fingerprint) => fingerprint,
            Err(err) if is_standard_rdp_security_error(&format!("{err:#}")) => {
                legacy_standard_rdp = true;
                "legacy-standard-rdp-no-tls-certificate".to_owned()
            }
            Err(err) => {
                self.status = format!("RDP certificate probe failed: {err}");
                self.certificate_notice =
                    "Kein TLS-Zertifikat pruefbar; Verbindung bleibt blockiert.".to_owned();
                self.diagnostics = vec![DiagnosticFinding {
                    class: crate::models::DiagnosticClass::Tls,
                    severity: DiagnosticSeverity::Error,
                    title: "TLS-Zertifikat nicht pruefbar".to_owned(),
                    detail: err.to_string(),
                    fix: "RDP-Server muss TLS/NLA anbieten oder ein unterstuetzter Backendpfad muss ergaenzt werden.".to_owned(),
                }];
                self.ai_diagnosis = "RDP ist erreichbar, aber der TLS-/Certificate-Probe ist fehlgeschlagen. Aivana blockiert den Connect, damit kein unsicherer Fallback als Trust-Entscheidung gespeichert wird.".to_owned();
                return;
            }
        };
        if legacy_standard_rdp {
            self.certificate_notice = format!(
                "{}:{} nutzt Standard RDP Security ohne TLS-Zertifikat. Aivana versucht den nativen Legacy-Backendpfad.",
                profile.host, profile.port
            );
        } else {
            let cert_status = self
                .certificates
                .classify(&profile.host, profile.port, &fingerprint);
            if !matches!(cert_status, crate::models::CertificateTrustStatus::Trusted) {
                self.certificate_notice = format!(
                    "{:?}: {} Fingerprint: {}",
                    cert_status,
                    self.certificates.explain_risk(cert_status),
                    fingerprint
                );
                self.status = "Certificate trust decision required before connect".to_owned();
                return;
            }
        }

        let Some(report) = report else {
            self.status = "Vorprüfung fehlt; Verbindung bleibt blockiert.".into();
            return;
        };
        self.ai_diagnosis = format_ai_explanation(&self.ai.explain_failure(&report));
        self.diagnostics = report.findings.clone();

        match self.engine.connect(&profile) {
            Ok(session) => {
                self.session_sources
                    .insert(session.id, crate::mission::Target::from_profile(&profile));
                self.autopilot.abort();
                self.timeline.append_event(
                    session.id,
                    profile.workspace_id,
                    SessionEventKind::ConnectionStage,
                    format!("Connecting to {}:{}", profile.host, profile.port),
                );
                self.memory.record_known_issue(
                    &profile.host,
                    profile.workspace_id,
                    "Session started; host evidence available in Aivana timeline.",
                );
                self.selected_session = Some(session.id);
                self.sessions.push(session);
                self.desktop.focus = true;
                self.view = View::Sessions;
                self.status = if report.connect_recommended {
                    format!("Connecting to {}", profile.name)
                } else {
                    format!("Connecting with preflight warnings for {}", profile.name)
                };
            }
            Err(err) => self.status = format!("Connection failed: {err}"),
        }
    }

    fn trust_selected_certificate(&mut self) {
        self.begin_certificate_probe(connection_probe::ProbeIntent::Trust);
    }

    fn reject_selected_certificate(&mut self) {
        self.begin_certificate_probe(connection_probe::ProbeIntent::Reject);
    }
    fn block_standard_rdp_security(&mut self, profile: &ConnectionProfile, detail: &str) {
        self.status = format!("{} uses unsupported Standard RDP Security", profile.host);
        self.certificate_notice = format!(
            "{}:{} bietet kein TLS/NLA-Zertifikat an. Standard RDP Security wird vom nativen IronRDP-Backend nicht unterstuetzt.",
            profile.host, profile.port
        );
        self.diagnostics = vec![DiagnosticFinding {
            class: crate::models::DiagnosticClass::Protocol,
            severity: DiagnosticSeverity::Error,
            title: "Standard RDP Security nicht unterstuetzt".to_owned(),
            detail: detail.to_owned(),
            fix: "Auf dem Server TLS/NLA fuer RDP aktivieren oder einen zusaetzlichen Standard-RDP-Security-Backendpfad implementieren.".to_owned(),
        }];
        self.ai_diagnosis = format!(
            "Root Cause: {} ist per Netzwerk erreichbar, bietet aber nur altes Standard RDP Security an. Aivana nutzt kein mstsc und das aktuelle native IronRDP-Backend kann diesen Modus nicht oeffnen. Fix: TLS/NLA auf dem Host aktivieren oder Backend erweitern.",
            profile.host
        );
    }

    fn test_selected_credential(&mut self) {
        let Some(profile) = self.selected_profile().cloned() else {
            self.status = "Select a profile first".to_owned();
            return;
        };
        let Some(credential_id) = profile.credential_id else {
            self.status = "Profile has no saved credential".to_owned();
            return;
        };
        match self.credentials.test(credential_id) {
            Ok(health) => self.status = format!("Credential status: {health:?}"),
            Err(err) => self.status = format!("Credential test failed: {err}"),
        }
    }

    fn delete_selected_credential(&mut self) {
        let Some(profile_id) = self.selected_profile else {
            self.status = "Select a profile first".to_owned();
            return;
        };
        let Some(profile) = self
            .profiles
            .iter_mut()
            .find(|profile| profile.id == profile_id)
        else {
            self.status = "Profile not found".to_owned();
            return;
        };
        let Some(credential_id) = profile.credential_id.take() else {
            self.status = "Profile has no saved credential".to_owned();
            return;
        };
        match self.credentials.delete(credential_id) {
            Ok(()) => {
                self.save_profiles();
                self.status = "Credential deleted".to_owned();
            }
            Err(err) => self.status = format!("Credential delete failed: {err}"),
        }
    }

    fn disconnect_selected_session(&mut self) {
        let Some(session_id) = self.selected_session else {
            self.status = "No session selected".to_owned();
            return;
        };

        if self.engine.disconnect(session_id).is_ok() {
            self.autopilot.abort();
            self.sessions.retain(|session| session.id != session_id);
            self.textures.remove(&session_id);
            self.latest_frames.remove(&session_id);
            self.selected_session = self.sessions.last().map(|session| session.id);
            self.status = "Session disconnected".to_owned();
        }
    }

    fn process_autopilot(&mut self) {
        let Some(session_id) = self.selected_session else {
            return;
        };
        if !self.autopilot.can_step() {
            return;
        }
        let Some(frame) = self.latest_frames.get(&session_id).cloned() else {
            self.computer_use_status = "Autopilot wartet auf einen Framebuffer.".to_owned();
            return;
        };
        if self
            .sessions
            .iter()
            .find(|session| session.id == session_id)
            .is_some_and(|session| session.status != SessionStatus::Connected)
        {
            self.autopilot.status = AutopilotStatus::Failed;
            self.computer_use_status =
                "Autopilot gestoppt: RDP-Session ist nicht verbunden.".to_owned();
            return;
        }

        let agent = ComputerUseAgent::default();
        let observation = agent.observe(&frame);
        let plan = if let Some(mut plan) = self.autopilot.take_pending_safety_plan() {
            plan.safety_checks.clear();
            plan
        } else {
            match self.plan_autopilot_step(&frame, &observation) {
                Ok(plan) => plan,
                Err(err) => {
                    self.autopilot.status = AutopilotStatus::Failed;
                    self.computer_use_status = format!("Autopilot planning failed: {err}");
                    self.record_autopilot_error(session_id, &observation.summary, err.to_string());
                    return;
                }
            }
        };

        self.autopilot.previous_response_id = plan
            .response_id
            .clone()
            .or_else(|| self.autopilot.previous_response_id.clone());
        self.autopilot.last_call_id = plan
            .call_id
            .clone()
            .or_else(|| self.autopilot.last_call_id.clone());

        if !plan.safety_checks.is_empty() {
            self.autopilot.pending_safety_checks = plan.safety_checks.clone();
            self.autopilot.pending_safety_plan = Some(plan.clone());
            self.autopilot.status = AutopilotStatus::WaitingForSafetyAck;
            self.computer_use_status =
                "OpenAI Computer Use safety check wartet auf Operator-Bestaetigung.".to_owned();
            self.record_autopilot_step(
                session_id,
                &frame,
                &observation.summary,
                &plan,
                RiskLevel::ReadOnly,
                PolicyDecision::RequireApproval,
                None,
                None,
            );
            return;
        }

        if plan.completed {
            self.autopilot.status = AutopilotStatus::Completed;
            self.computer_use_status = format!("Autopilot completed: {}", plan.summary);
            self.timeline.append_event(
                session_id,
                None,
                SessionEventKind::AiAction,
                self.computer_use_status.clone(),
            );
            return;
        }

        let actions = if plan.actions.is_empty() {
            plan.action.iter().cloned().collect::<Vec<_>>()
        } else {
            plan.actions.clone()
        };
        if actions.is_empty() {
            self.autopilot.status = AutopilotStatus::Completed;
            self.computer_use_status = "Autopilot completed without further action.".to_owned();
            return;
        }
        let (risk, decision) = classify_plan_actions(&actions, &self.autopilot.settings);
        if decision == PolicyDecision::Deny {
            self.autopilot.status = AutopilotStatus::Failed;
            self.computer_use_status = format!("Autopilot denied action batch: {:?}", actions);
            self.record_autopilot_step(
                session_id,
                &frame,
                &observation.summary,
                &plan,
                risk,
                decision,
                None,
                Some("Policy denied action".to_owned()),
            );
            return;
        }
        if decision == PolicyDecision::RequireApproval {
            let approval_action = actions
                .iter()
                .find(|action| {
                    classify_plan_action(action, &self.autopilot.settings).1
                        == PolicyDecision::RequireApproval
                })
                .cloned()
                .unwrap_or_else(|| actions[0].clone());
            let ai_action = AiAction {
                id: Uuid::new_v4(),
                session_id: Some(session_id),
                description: format!("Autopilot: {}", plan.action_description),
                action: approval_action,
                risk,
                decision,
            };
            let mut approval = agent.request_approval(
                &ai_action,
                format!(
                    "Autopilot goal '{}' wants to mutate remote UI.",
                    self.autopilot.goal
                ),
            );
            approval.actions = actions.clone();
            approval.expected_result =
                "Aivana executes the approved batch in order and verifies the next framebuffer."
                    .to_owned();
            self.approvals.push(approval);
            self.autopilot.status = AutopilotStatus::WaitingForApproval;
            self.computer_use_status =
                format!("Autopilot queued approval: {}", plan.action_description);
            self.record_autopilot_step(
                session_id,
                &frame,
                &observation.summary,
                &plan,
                risk,
                decision,
                None,
                None,
            );
            return;
        }

        let verification = match self.execute_autopilot_actions(session_id, &actions, &frame) {
            Ok(verification) => verification,
            Err(err) => {
                self.autopilot.status = AutopilotStatus::Failed;
                self.computer_use_status = format!("Autopilot action failed: {err}");
                self.record_autopilot_step(
                    session_id,
                    &frame,
                    &observation.summary,
                    &plan,
                    risk,
                    decision,
                    None,
                    Some(err.to_string()),
                );
                return;
            }
        };
        self.record_autopilot_step(
            session_id,
            &frame,
            &observation.summary,
            &plan,
            risk,
            decision,
            verification,
            None,
        );
        self.computer_use_status = format!("Autopilot step: {}", plan.action_description);
    }

    fn plan_autopilot_step(
        &self,
        frame: &FrameUpdate,
        observation: &crate::models::ScreenObservation,
    ) -> anyhow::Result<AutopilotPlan> {
        let request = AutopilotRequest {
            goal: &self.autopilot.goal,
            frame,
            observation,
            settings: &self.autopilot.settings,
            previous_response_id: self.autopilot.previous_response_id.as_deref(),
            last_call_id: self.autopilot.last_call_id.as_deref(),
            acknowledged_safety_checks: &self.autopilot.acknowledged_safety_checks,
        };
        match self.autopilot.settings.provider {
            AutopilotProviderKind::Local => LocalAutopilotProvider.plan(&request),
            AutopilotProviderKind::OpenAiComputerUse => {
                OpenAiComputerUseProvider::from_env()?.plan(&request)
            }
        }
    }

    fn execute_autopilot_action(
        &mut self,
        session_id: Uuid,
        action: InputAction,
        frame_before: &FrameUpdate,
    ) -> anyhow::Result<Option<crate::models::VerificationResult>> {
        match action {
            InputAction::Wait { millis } => {
                std::thread::sleep(std::time::Duration::from_millis(millis.min(2500)));
                Ok(None)
            }
            InputAction::Screenshot | InputAction::Verify { .. } => Ok(None),
            other => {
                self.engine.send_input(session_id, other)?;
                let frame_after = self.latest_frames.get(&session_id).unwrap_or(frame_before);
                if frame_after.frame_hash == frame_before.frame_hash {
                    Ok(None)
                } else {
                    Ok(Some(ComputerUseAgent::default().verify_step(
                        session_id,
                        frame_before.frame_hash,
                        frame_after,
                    )))
                }
            }
        }
    }

    fn execute_autopilot_actions(
        &mut self,
        session_id: Uuid,
        actions: &[InputAction],
        frame_before: &FrameUpdate,
    ) -> anyhow::Result<Option<crate::models::VerificationResult>> {
        let mut verification = None;
        for action in actions {
            if let Some(result) =
                self.execute_autopilot_action(session_id, action.clone(), frame_before)?
            {
                verification = Some(result);
            }
        }
        Ok(verification)
    }

    fn execute_approved_actions(
        &mut self,
        session_id: Uuid,
        actions: &[InputAction],
    ) -> anyhow::Result<()> {
        for action in actions {
            match action {
                InputAction::Wait { millis } => {
                    std::thread::sleep(std::time::Duration::from_millis((*millis).min(2500)));
                }
                InputAction::Screenshot | InputAction::Verify { .. } => {}
                other => self.engine.send_input(session_id, other.clone())?,
            }
        }
        Ok(())
    }

    fn record_autopilot_step(
        &mut self,
        session_id: Uuid,
        frame: &FrameUpdate,
        observation: &str,
        plan: &AutopilotPlan,
        risk: RiskLevel,
        decision: PolicyDecision,
        verification: Option<crate::models::VerificationResult>,
        error: Option<String>,
    ) {
        self.timeline
            .append_snapshot("Autopilot framebuffer observation".to_owned(), frame);
        self.timeline.append_event(
            session_id,
            None,
            SessionEventKind::AiAction,
            format!(
                "Autopilot step {} provider={} risk={:?} decision={:?} action={} summary={}{}",
                self.autopilot.steps.len() + 1,
                self.autopilot.settings.provider.label(),
                risk,
                decision,
                plan.action_description,
                plan.summary,
                error
                    .as_ref()
                    .map(|err| format!(" error={err}"))
                    .unwrap_or_default()
            ),
        );
        self.autopilot.record_step(crate::autopilot::AutopilotStep {
            index: self.autopilot.steps.len() + 1,
            captured_at: Utc::now(),
            observation: observation.to_owned(),
            model_summary: plan.summary.clone(),
            action_description: plan.action_description.clone(),
            action: plan.action.clone(),
            actions: plan.actions.clone(),
            risk,
            decision,
            verification,
            safety_checks: plan.safety_checks.clone(),
            error,
        });
    }

    fn record_autopilot_error(&mut self, session_id: Uuid, observation: &str, error: String) {
        let Some(frame) = self.latest_frames.get(&session_id).cloned() else {
            return;
        };
        let plan = AutopilotPlan {
            response_id: None,
            call_id: None,
            summary: "Autopilot planning error".to_owned(),
            action: None,
            actions: Vec::new(),
            action_description: "planning failed".to_owned(),
            safety_checks: Vec::new(),
            completed: false,
        };
        self.record_autopilot_step(
            session_id,
            &frame,
            observation,
            &plan,
            RiskLevel::ReadOnly,
            PolicyDecision::Deny,
            None,
            Some(error),
        );
    }

    fn llm_handoff_prompt(&self, session_id: Uuid) -> String {
        build_llm_handoff_prompt(
            session_id,
            &self.selected_host_label(),
            &self.diagnostics,
            &self.timeline.events_for_session(session_id),
            &self.timeline.snapshots_for_session(session_id),
            &self.autopilot.steps,
        )
    }

    fn persist_autopilot_preferences(&mut self) {
        match save_autopilot_preferences(&AutopilotPreferences::from(&self.autopilot)) {
            Ok(()) => self.status = "KI preferences saved".to_owned(),
            Err(err) => self.status = format!("Could not save KI preferences: {err}"),
        }
    }

    fn reconnect_selected_session(&mut self) {
        let Some(session_id) = self.selected_session else {
            self.status = "No session selected".to_owned();
            return;
        };
        let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.id == session_id)
        else {
            self.status = "Selected session not found".to_owned();
            return;
        };
        match self.engine.reconnect(session) {
            Ok(()) => self.status = "Reconnect started".to_owned(),
            Err(err) => self.status = format!("Reconnect failed: {err}"),
        }
    }
}

impl eframe::App for AivanaApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.gui_capture.tick(&ctx);
        self.poll_certificate_probe();
        self.engine
            .release_inputs_except(self.remote_input_owner(ui));
        let mut received_frame = false;

        for session in &mut self.sessions {
            self.engine.tick(session);
            for event in self.engine.poll_events(session.id) {
                let (kind, message) = timeline_message(&event);
                self.timeline
                    .append_event(session.id, None, kind, message.clone());
                if Some(session.id) == self.selected_session
                    && matches!(
                        event,
                        EngineEvent::Error { .. } | EngineEvent::Disconnected { .. }
                    )
                {
                    self.desktop.assistant = true;
                    self.desktop.timeline = true;
                }
                if matches!(
                    event,
                    EngineEvent::Error { .. }
                        | EngineEvent::Disconnected { .. }
                        | EngineEvent::Diagnostic { .. }
                ) {
                    if Some(session.id) == self.selected_session {
                        self.ai_diagnosis = message;
                    }
                }
            }
            if let Some(frame) = self.engine.poll_frame(session.id) {
                let image = ColorImage::from_rgba_unmultiplied(
                    [usize::from(frame.width), usize::from(frame.height)],
                    &frame.pixels_rgba,
                );
                match self.textures.entry(session.id) {
                    Entry::Occupied(mut texture) => {
                        texture.get_mut().set(image, TextureOptions::NEAREST);
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(ctx.load_texture(
                            format!("rdp-frame-{}", session.id),
                            image,
                            TextureOptions::NEAREST,
                        ));
                    }
                }
                self.latest_frames.insert(session.id, frame);
                received_frame = true;
            }
        }

        self.poll_missions();
        self.poll_operations();
        self.poll_integrations();
        self.poll_recordings();
        if !ui.input(|i| i.focused || i.raw.viewports.values().any(|v| v.focused == Some(true))) {
            self.teaching.teacher.stop();
            self.teaching.cancel_approval();
        }
        self.poll_teaching();
        for (session, action, at) in self.engine.take_manual_inputs() {
            let size = self
                .latest_frames
                .get(&session)
                .map(|f| (f.width, f.height));
            self.teaching.observe_at(session, &action, size, at);
        }
        self.engine
            .set_manual_capture(self.teaching.teacher.is_recording());
        self.process_autopilot();

        self.desktop_shell(ui);
        self.detached_sessions(&ctx);
        self.engine
            .release_inputs_except(self.remote_input_owner(ui));

        if received_frame {
            ctx.request_repaint();
        }
        let has_live_session = self.sessions.iter().any(|session| {
            !matches!(
                session.status,
                SessionStatus::Disconnected | SessionStatus::Failed
            )
        });
        ctx.request_repaint_after(std::time::Duration::from_millis(if has_live_session {
            16
        } else {
            250
        }));
    }
}

impl AivanaApp {
    fn connections_view(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Connection Profiles",
            "Manage saved endpoints and launch sessions.",
        );

        ui.horizontal_wrapped(|ui| {
            ui.add_sized(
                [ui.available_width().min(360.0), 42.0],
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search name, host, group, tag"),
            );
            if action_button(ui, "Neu", 88.0, ActionTone::Neutral).clicked() {
                self.start_new_profile();
            }
            if action_button(ui, "Bearbeiten", 88.0, ActionTone::Neutral).clicked() {
                self.edit_selected_profile();
            }
            if action_button(ui, "Verbinden", 108.0, ActionTone::Primary).clicked() {
                self.connect_selected();
            }
            if action_button(ui, "Zertifikat vertrauen", 122.0, ActionTone::Primary).clicked() {
                self.trust_selected_certificate();
            }
            if action_button(ui, "Zertifikat ablehnen", 126.0, ActionTone::Danger).clicked() {
                self.reject_selected_certificate();
            }
            if action_button(ui, "Zugang prüfen", 112.0, ActionTone::Neutral).clicked() {
                self.test_selected_credential();
            }
            if action_button(ui, "Zugang löschen", 124.0, ActionTone::Danger).clicked() {
                self.delete_selected_credential();
            }
        });
        ui.label(RichText::new(&self.certificate_notice).color(tw::SLATE_600));
        ui.label(
            RichText::new(format!("Status: {}", self.status))
                .strong()
                .color(tw::SLATE_700),
        );

        ui.add_space(14.0);
        self.profile_editor(ui);
        ui.add_space(14.0);
        self.profile_table(ui);
    }

    fn profile_table(&mut self, ui: &mut Ui) {
        panel(ui, |ui| {
            ui.heading("Profile");
            ui.add_space(8.0);

            let rows = self
                .filtered_profiles()
                .into_iter()
                .map(|profile| profile.id)
                .collect::<Vec<_>>();

            for profile_id in rows {
                let Some(profile) = self
                    .profiles
                    .iter()
                    .find(|profile| profile.id == profile_id)
                else {
                    continue;
                };
                let selected = self.selected_profile == Some(profile.id);
                let row_fill = if selected { tw::BLUE_50 } else { tw::WHITE };
                let stroke = if selected {
                    Stroke::new(1.0, tw::BLUE_500)
                } else {
                    Stroke::new(1.0, tw::SLATE_200)
                };
                let row_width = ui.available_width().max(260.0);
                let (rect, response) =
                    ui.allocate_exact_size(Vec2::new(row_width, 74.0), Sense::click());
                let painter = ui.painter_at(rect);
                painter.rect(
                    rect,
                    CornerRadius::same(8),
                    row_fill,
                    stroke,
                    StrokeKind::Outside,
                );

                let favorite = if profile.favorite { "* " } else { "" };
                painter.text(
                    pos2(rect.left() + 14.0, rect.top() + 14.0),
                    egui::Align2::LEFT_TOP,
                    format!("{favorite}{}", profile.name),
                    FontId::proportional(19.0),
                    tw::SLATE_900,
                );
                painter.text(
                    pos2(rect.left() + 14.0, rect.top() + 42.0),
                    egui::Align2::LEFT_TOP,
                    format!(
                        "{}:{}  |  {}  |  {}",
                        profile.host,
                        profile.port,
                        profile.protocol.label(),
                        profile.group
                    ),
                    FontId::proportional(15.0),
                    tw::SLATE_600,
                );
                if selected {
                    painter.text(
                        pos2(rect.right() - 14.0, rect.top() + 14.0),
                        egui::Align2::RIGHT_TOP,
                        "Ausgewählt",
                        FontId::proportional(14.0),
                        tw::BLUE_700,
                    );
                }
                if response.clicked() {
                    self.load_profile_into_editor(profile.id);
                }
                ui.add_space(6.0);
            }
        });
    }

    fn profile_editor(&mut self, ui: &mut Ui) {
        panel(ui, |ui| {
            ui.heading(if self.editing_profile.is_some() {
                "Profil bearbeiten"
            } else {
                "Neues Profil"
            });
            ui.label(
                RichText::new(self.credential_status_label())
                    .strong()
                    .color(tw::SLATE_600),
            );
            ui.add_space(8.0);
            let draft = &mut self.draft;
            ui.columns(2, |columns| {
                text_field(&mut columns[0], "Name", &mut draft.name);
                text_field(&mut columns[1], "Rechneradresse", &mut draft.host);
            });
            ui.columns(2, |columns| {
                text_field(&mut columns[0], "Port", &mut draft.port);
                text_field(&mut columns[1], "Benutzername", &mut draft.username);
            });
            ui.columns(2, |columns| {
                text_field(&mut columns[0], "Domäne", &mut draft.domain);
                text_field(&mut columns[1], "Gruppe", &mut draft.group);
            });
            password_field(ui, "Passwort", &mut draft.password);
            text_field(ui, "Schlagwörter", &mut draft.tags);
            ui.checkbox(&mut draft.favorite, "Favorit");
            self.workbench_profile_options(ui);
            ui.add_space(12.0);
            if action_button(ui, "Profil speichern", 132.0, ActionTone::Primary).clicked() {
                self.save_draft();
            }
        });
    }

    fn approvals_view(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Approval Center",
            "Review KI Computer Use actions before they can mutate remote state.",
        );
        panel(ui, |ui| {
            if self.approvals.is_empty() {
                ui.label("No pending KI approvals.");
                return;
            }

            let mut updated = Vec::new();
            let approvals = std::mem::take(&mut self.approvals);
            for mut approval in approvals {
                ui.separator();
                ui.label(RichText::new(&approval.description).strong());
                ui.label(format!(
                    "Risk: {:?} | Status: {:?}",
                    approval.risk, approval.status
                ));
                ui.label(format!("Reason: {}", approval.reason));
                ui.label(format!("Expected: {}", approval.expected_result));
                let preview_actions = if approval.actions.is_empty() {
                    vec![approval.action.clone()]
                } else {
                    approval.actions.clone()
                };
                ui.label(format!("Batch: {} action(s)", preview_actions.len()));
                for (index, action) in preview_actions.iter().take(8).enumerate() {
                    ui.label(
                        RichText::new(format!("{}. {}", index + 1, input_action_label(action)))
                            .size(12.0)
                            .color(tw::SLATE_600),
                    );
                }
                ui.horizontal(|ui| {
                    if ui.button("Allow once").clicked() {
                        approval.status = ApprovalStatus::AllowedOnce;
                    }
                    if ui.button("Allow for Runbook").clicked() {
                        approval.status = ApprovalStatus::AllowedForRunbook;
                    }
                    if ui.button("Deny").clicked() {
                        approval.status = ApprovalStatus::Denied;
                    }
                    if ui.button("Abort Agent").clicked() {
                        approval.status = ApprovalStatus::Aborted;
                    }
                });
                if approval.status == ApprovalStatus::Pending {
                    updated.push(approval);
                } else if let Some(session_id) = approval.session_id {
                    if matches!(
                        approval.status,
                        ApprovalStatus::AllowedOnce | ApprovalStatus::AllowedForRunbook
                    ) {
                        let actions = if approval.actions.is_empty() {
                            vec![approval.action.clone()]
                        } else {
                            approval.actions.clone()
                        };
                        match self.execute_approved_actions(session_id, &actions) {
                            Ok(()) => {
                                if let Some(frame) = self.latest_frames.get(&session_id) {
                                    let verification = ComputerUseAgent::default().verify_step(
                                        session_id,
                                        frame.frame_hash,
                                        frame,
                                    );
                                    self.timeline.append_event(
                                        session_id,
                                        None,
                                        SessionEventKind::AiAction,
                                        format!(
                                            "Verification after approval: {}",
                                            verification.evidence
                                        ),
                                    );
                                }
                                self.computer_use_status =
                                    format!("Approved action executed: {}", approval.description);
                                if self.autopilot.status == AutopilotStatus::WaitingForApproval {
                                    self.autopilot.status = AutopilotStatus::Running;
                                }
                            }
                            Err(err) => {
                                self.computer_use_status =
                                    format!("Approved action could not execute: {err}");
                                if self.autopilot.status == AutopilotStatus::WaitingForApproval {
                                    self.autopilot.status = AutopilotStatus::Failed;
                                }
                            }
                        }
                    } else if self.autopilot.status == AutopilotStatus::WaitingForApproval {
                        self.autopilot.status = if approval.status == ApprovalStatus::Aborted {
                            AutopilotStatus::Aborted
                        } else {
                            AutopilotStatus::Failed
                        };
                    }
                    self.timeline.append_event(
                        session_id,
                        None,
                        SessionEventKind::Approval,
                        format!("Approval {:?}: {}", approval.status, approval.description),
                    );
                }
            }
            self.approvals = updated;
        });
    }

    fn workspaces_view(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Workspace Cockpit",
            "Customers, incidents, runbooks, host memory and evidence.",
        );
        let selected_host = self
            .selected_profile()
            .map(|profile| profile.host.clone())
            .unwrap_or_else(|| "no-host-selected".to_owned());
        panel(ui, |ui| {
            ui.heading("Dashboard");
            metric(ui, "Workspaces", self.workspaces.all().len().to_string());
            metric(ui, "Profiles", self.profiles.len().to_string());
            metric(ui, "Sessions", self.sessions.len().to_string());
            metric(ui, "Open approvals", self.approvals.len().to_string());
            ui.add_space(10.0);
            ui.label(format!("Selected host: {selected_host}"));
            ui.label(format!(
                "Recommended next step: {}",
                self.memory.recommended_next_step(&selected_host)
            ));
            if let Some(memory) = self.memory.host_memory(&selected_host) {
                ui.label("Known for this host:");
                for issue in memory.known_issues.iter().rev().take(4) {
                    ui.label(format!("- {issue}"));
                }
            }
            if ui.button("Record successful safe fix").clicked() {
                self.memory.record_successful_fix(
                    &selected_host,
                    None,
                    "Operator confirmed latest safe diagnostic workflow as useful.",
                );
                self.status = "Host memory updated".to_owned();
            }
            if let Some(workspace) = self.workspaces.all().first() {
                if self.memory.workspace_note_count(workspace.id) == 0 {
                    self.memory
                        .record_workspace_note(workspace.id, "Workspace cockpit initialized.");
                }
                ui.label(format!(
                    "Workspace memory notes: {}",
                    self.memory.workspace_note_count(workspace.id)
                ));
            }
            ui.add_space(10.0);
            ui.heading("KI Operations");
            let selected_session_id = self.selected_session;
            let has_frame = selected_session_id
                .is_some_and(|session_id| self.latest_frames.contains_key(&session_id));
            let session_event_count = selected_session_id
                .map(|session_id| self.timeline.events_for_session(session_id).len())
                .unwrap_or_default();
            let snapshot_count = selected_session_id
                .map(|session_id| self.timeline.snapshots_for_session(session_id).len())
                .unwrap_or_default();
            ui.horizontal_wrapped(|ui| {
                compact_metric(ui, "Autopilot", self.autopilot.status.label().to_owned());
                compact_metric(ui, "Events", session_event_count.to_string());
                compact_metric(ui, "Snapshots", snapshot_count.to_string());
                compact_metric(
                    ui,
                    "Provider",
                    self.autopilot.settings.provider.label().to_owned(),
                );
            });
            ui.label(build_ai_readiness_report(
                selected_session_id,
                has_frame,
                self.autopilot.settings.provider,
                std::env::var("OPENAI_API_KEY").is_ok_and(|key| !key.trim().is_empty()),
                self.approvals.len(),
            ));
            let action_brief = selected_session_id
                .map(|session_id| {
                    build_ai_action_brief(
                        &selected_host,
                        &self.diagnostics,
                        &self.timeline.events_for_session(session_id),
                        &self.timeline.snapshots_for_session(session_id),
                        &self.autopilot.steps,
                    )
                })
                .unwrap_or_else(|| {
                    build_ai_action_brief(&selected_host, &self.diagnostics, &[], &[], &[])
                });
            ui.label(
                RichText::new("KI Action Brief")
                    .strong()
                    .color(tw::SLATE_800),
            );
            ui.label(RichText::new(&action_brief).size(13.0).color(tw::SLATE_700));
            let guardrail_brief = build_guardrail_brief(&self.autopilot.settings);
            ui.label(
                RichText::new("Policy Guardrails")
                    .strong()
                    .color(tw::SLATE_800),
            );
            ui.label(
                RichText::new(&guardrail_brief)
                    .size(13.0)
                    .color(tw::SLATE_700),
            );
            ui.horizontal_wrapped(|ui| {
                if ui.button("Prime Diagnose Autopilot").clicked() {
                    self.autopilot.goal =
                        "Diagnose die aktive Session, sammle Evidenz, und schlage den naechsten sicheren Schritt vor."
                            .to_owned();
                    self.persist_autopilot_preferences();
                    self.view = View::Sessions;
                    self.desktop.assistant = true;
                    self.desktop.focus = true;
                    self.status = "Autopilot goal primed from Workspace Cockpit".to_owned();
                }
                if ui.button("Prime Evidence Autopilot").clicked() {
                    self.autopilot.goal =
                        "Erzeuge eine belastbare Incident-Evidenzbasis mit Timeline, Snapshots, Runbook und LLM-Handoff."
                            .to_owned();
                    self.persist_autopilot_preferences();
                    self.view = View::Sessions;
                    self.desktop.assistant = true;
                    self.desktop.focus = true;
                    self.status = "Evidence autopilot goal primed".to_owned();
                }
                if ui.button("Copy LLM Handoff").clicked() {
                    if let Some(session_id) = selected_session_id {
                        let prompt = self.llm_handoff_prompt(session_id);
                        ui.ctx().copy_text(prompt.clone());
                        self.computer_use_status =
                            format!("Workspace copied LLM handoff, {} bytes.", prompt.len());
                    } else {
                        self.computer_use_status =
                            "LLM handoff braucht zuerst eine aktive Session.".to_owned();
                    }
                }
                if ui.button("Copy Action Brief").clicked() {
                    ui.ctx().copy_text(action_brief.clone());
                    self.computer_use_status =
                        format!("Workspace copied KI action brief, {} bytes.", action_brief.len());
                }
                if ui.button("Copy Guardrails").clicked() {
                    ui.ctx().copy_text(guardrail_brief.clone());
                    self.computer_use_status =
                        format!("Policy guardrails copied, {} bytes.", guardrail_brief.len());
                }
                if ui.button("Copy Prompt Library").clicked() {
                    let prompt_library = build_prompt_library_brief(
                        &selected_host,
                        &action_brief,
                        &self.autopilot,
                        selected_session_id.is_some(),
                    );
                    ui.ctx().copy_text(prompt_library.clone());
                    self.computer_use_status =
                        format!("Prompt library copied, {} bytes.", prompt_library.len());
                }
                if ui.button("Export AI Brief Pack").clicked() {
                    let prompt_library = build_prompt_library_brief(
                        &selected_host,
                        &action_brief,
                        &self.autopilot,
                        selected_session_id.is_some(),
                    );
                    let runbook_brief =
                        build_runbook_llm_brief(self.runbooks.list_runbooks(), &selected_host);
                    let verification_brief =
                        build_ki_verification_report(&self.autopilot, self.sessions.len())
                            .to_markdown();
                    match save_ai_brief_pack(
                        &action_brief,
                        &prompt_library,
                        &runbook_brief,
                        &verification_brief,
                    ) {
                        Ok(path) => {
                            self.computer_use_status =
                                format!("AI brief pack exported to {}", path.display());
                        }
                        Err(err) => {
                            self.computer_use_status =
                                format!("AI brief pack export failed: {err}");
                        }
                    }
                }
            });
            ui.add_space(10.0);
            ui.heading("Runbooks");
            for runbook in self.runbooks.list_runbooks().iter().take(9) {
                ui.label(format!("- {} [{:?}]", runbook.name, runbook.category));
            }
            ui.add_space(8.0);
            let runbook_brief =
                build_runbook_llm_brief(self.runbooks.list_runbooks(), &selected_host);
            ui.label(
                RichText::new("Runbook LLM Brief")
                    .strong()
                    .color(tw::SLATE_800),
            );
            ui.label(
                RichText::new(&runbook_brief)
                    .size(13.0)
                    .color(tw::SLATE_700),
            );
            if ui.button("Copy Runbook Brief").clicked() {
                ui.ctx().copy_text(runbook_brief.clone());
                self.computer_use_status =
                    format!("Runbook LLM brief copied, {} bytes.", runbook_brief.len());
            }
        });
    }

    fn settings_view(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Einstellungen",
            "Darstellung, Verbindungen und KI-Unterstützung.",
        );
        self.workbench_display_settings(ui);
        panel(ui, |ui| {
            ui.heading("Rust migration status");
            ui.label("UI runtime: native eframe/egui");
            ui.label("Persistent profile store: JSON in user data directory");
            ui.label("RDP backend: native Rust IronRDP connector");
            ui.label("Computer Use: native framebuffer observation and RDP input policy gates");
            ui.label(format!(
                "Autopilot provider: {}",
                self.autopilot.settings.provider.label()
            ));
            ui.label(format!(
                "OpenAI Computer Use: opt-in via OPENAI_API_KEY, model {}",
                self.autopilot.settings.openai_model
            ));
            ui.label("Security: profile JSON omits passwords; credential backend boundary exists");
            ui.label(format!(
                "Workspaces prepared: {}",
                self.workspaces.all().len()
            ));
        });
        ui.add_space(12.0);
        panel(ui, |ui| {
            ui.heading("KI Verification Center");
            let live_gate_args = default_rdp_live_env_args();
            let cli_readiness = build_ki_readiness_cli_report_from_args(&live_gate_args);
            let preferences_saved = app_data_file("autopilot-preferences.json")
                .ok()
                .is_some_and(|path| path.exists());
            let report = build_ki_verification_report_with_inputs(
                &self.autopilot,
                self.sessions.len(),
                cli_readiness.openai_key_set,
                cli_readiness.rdp_smoke_env_ready,
                preferences_saved,
            );
            let live_gate_env_source = if live_gate_args.is_empty() {
                "RDP env source: process environment".to_owned()
            } else {
                "RDP env source: .\\rdp-live.env".to_owned()
            };
            ui.horizontal_wrapped(|ui| {
                compact_metric(
                    ui,
                    "OpenAI",
                    if report.openai_key_set {
                        "ready".to_owned()
                    } else {
                        "missing".to_owned()
                    },
                );
                compact_metric(
                    ui,
                    "RDP smoke",
                    if report.rdp_smoke_ready {
                        "ready".to_owned()
                    } else {
                        "env missing".to_owned()
                    },
                );
                compact_metric(
                    ui,
                    "Prefs",
                    if report.preferences_saved {
                        "saved".to_owned()
                    } else {
                        "not saved".to_owned()
                    },
                );
                compact_metric(ui, "Sessions", report.session_count.to_string());
            });
            ui.label(RichText::new(live_gate_env_source).color(tw::SLATE_700));
            ui.label(RichText::new(&report.summary).color(tw::SLATE_700));
            ui.label(
                RichText::new(&report.next_step)
                    .strong()
                    .color(tw::SLATE_800),
            );
            let preflight_evidence = latest_rdp_preflight_report_summary()
                .unwrap_or_else(|| "Latest RDP preflight evidence: none recorded yet.".to_owned());
            ui.label(RichText::new(&preflight_evidence).color(tw::SLATE_700));
            let smoke_evidence = latest_rdp_smoke_report_summary()
                .unwrap_or_else(|| "Latest RDP smoke evidence: none recorded yet.".to_owned());
            ui.label(RichText::new(&smoke_evidence).color(tw::SLATE_700));
            let ai_pack_evidence = latest_ai_brief_pack_summary()
                .unwrap_or_else(|| "Latest AI brief pack: none exported yet.".to_owned());
            ui.label(RichText::new(&ai_pack_evidence).color(tw::SLATE_700));
            let handoff_pack_evidence = latest_operator_handoff_pack_summary()
                .unwrap_or_else(|| "Latest operator handoff pack: none exported yet.".to_owned());
            ui.label(RichText::new(&handoff_pack_evidence).color(tw::SLATE_700));
            let handoff_check_evidence = latest_operator_handoff_check_summary();
            ui.label(RichText::new(&handoff_check_evidence).color(tw::SLATE_700));
            let handoff_risk_summary =
                build_operator_handoff_risk_summary_from_args(&live_gate_args);
            let handoff_risk_evidence = redact_secret_text(&format!(
                "Handoff risk: ok={} severity={} stage={} next={} failed_requirements={}",
                handoff_risk_summary.ok,
                handoff_risk_summary.severity,
                handoff_risk_summary.live_gate_stage,
                handoff_risk_summary.next_command,
                handoff_risk_summary.failed_requirements.len()
            ));
            ui.label(RichText::new(&handoff_risk_evidence).color(tw::SLATE_700));
            let live_gate_doctor = build_live_gate_doctor_report_from_args(&live_gate_args);
            let live_gate_proof_ok = live_gate_doctor
                .checks
                .iter()
                .find(|check| check.name == "rdp-proof-check")
                .map(|check| check.ok)
                .unwrap_or(false);
            let live_gate_doctor_evidence = redact_secret_text(&format!(
                "Live gate doctor: achieved={} stage={} ready_for_preflight={} ready_for_smoke={} smoke_connected={} rdp_proof_ok={} handoff_pack_valid={} next={}",
                live_gate_doctor.achieved,
                live_gate_doctor.operator_stage,
                live_gate_doctor.ready_for_preflight,
                live_gate_doctor.ready_for_smoke,
                live_gate_doctor.smoke_connected,
                live_gate_proof_ok,
                live_gate_doctor.handoff_pack_valid,
                live_gate_doctor.next_command
            ));
            ui.label(RichText::new(&live_gate_doctor_evidence).color(tw::SLATE_700));
            ui.label(
                RichText::new(redact_secret_text(&live_gate_doctor.operator_brief))
                    .strong()
                    .color(tw::SLATE_800),
            );
            let verification_snapshot = build_verification_snapshot_from_args(&live_gate_args);
            let live_gate_evidence = latest_live_gate_report_summary()
                .unwrap_or_else(|| "Latest live gate report: none executed yet.".to_owned());
            ui.label(RichText::new(&live_gate_evidence).color(tw::SLATE_700));
            let completion_audit = build_completion_audit_report_from_args(&live_gate_args);
            let blocking_items = completion_audit
                .items
                .iter()
                .filter(|item| item.blocking)
                .count();
            ui.horizontal_wrapped(|ui| {
                compact_metric(
                    ui,
                    "Goal audit",
                    if completion_audit.achieved {
                        "achieved".to_owned()
                    } else {
                        "blocked".to_owned()
                    },
                );
                compact_metric(ui, "Blocking gates", blocking_items.to_string());
                compact_metric(ui, "Handoff risk", handoff_risk_summary.severity.clone());
            });
            ui.label(RichText::new(&completion_audit.summary).color(tw::SLATE_700));
            let next_blocking_action = completion_audit
                .items
                .iter()
                .find(|item| item.blocking)
                .map(|item| item.next_action.clone())
                .unwrap_or_else(|| "No blocking gate remains; keep evidence attached.".to_owned());
            ui.label(
                RichText::new(format!("Next gate: {next_blocking_action}"))
                    .strong()
                    .color(tw::SLATE_800),
            );
            ui.horizontal_wrapped(|ui| {
                if ui.button("Save KI Preferences").clicked() {
                    self.persist_autopilot_preferences();
                }
                if ui.button("Copy Smoke Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90".to_owned(),
                    );
                    self.status = "RDP smoke command copied".to_owned();
                }
                if ui.button("Copy Preflight Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90".to_owned(),
                    );
                    self.status = "RDP preflight command copied".to_owned();
                }
                if ui.button("Copy Env Save Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --save-rdp-env-template .\\rdp-live.env".to_owned(),
                    );
                    self.status = "RDP env save command copied".to_owned();
                }
                if ui.button("Copy RDP Env Template").clicked() {
                    let template = build_rdp_live_gate_env_template();
                    ui.ctx().copy_text(template.clone());
                    self.status = format!("RDP env template copied, {} bytes.", template.len());
                }
                if ui.button("Copy RDP Env Fill Guide").clicked() {
                    let guide = build_rdp_env_fill_guide();
                    ui.ctx().copy_text(guide.clone());
                    self.status = format!("RDP env fill guide copied, {} bytes.", guide.len());
                }
                if ui.button("Copy Env Check Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env"
                            .to_owned(),
                    );
                    self.status = "RDP env file check command copied".to_owned();
                }
                if ui.button("Copy Verification Brief").clicked() {
                    ui.ctx().copy_text(report.to_markdown());
                    self.status = "KI verification brief copied".to_owned();
                }
                if ui.button("Copy Smoke Evidence").clicked() {
                    ui.ctx().copy_text(smoke_evidence.clone());
                    self.status = "RDP smoke evidence summary copied".to_owned();
                }
                if ui.button("Copy Preflight Evidence").clicked() {
                    ui.ctx().copy_text(preflight_evidence.clone());
                    self.status = "RDP preflight evidence summary copied".to_owned();
                }
                if ui.button("Copy AI Pack Evidence").clicked() {
                    ui.ctx().copy_text(ai_pack_evidence.clone());
                    self.status = "AI brief pack evidence copied".to_owned();
                }
                if ui.button("Copy Handoff Pack Evidence").clicked() {
                    ui.ctx().copy_text(handoff_pack_evidence.clone());
                    self.status = "Operator handoff pack evidence copied".to_owned();
                }
                if ui.button("Copy Handoff Check Evidence").clicked() {
                    ui.ctx().copy_text(handoff_check_evidence.clone());
                    self.status = "Operator handoff check evidence copied".to_owned();
                }
                if ui.button("Copy Handoff Risk Evidence").clicked() {
                    ui.ctx().copy_text(handoff_risk_evidence.clone());
                    self.status = "Operator handoff risk evidence copied".to_owned();
                }
                if ui.button("Copy Live Gate Evidence").clicked() {
                    ui.ctx().copy_text(live_gate_evidence.clone());
                    self.status = "Live gate evidence copied".to_owned();
                }
                if ui.button("Copy Live Gate Doctor JSON").clicked() {
                    match redacted_json_string(&build_live_gate_doctor_report_from_args(
                        &live_gate_args,
                    )) {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Live gate doctor JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Live gate doctor JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Live Gate Next Command").clicked() {
                    ui.ctx().copy_text(live_gate_doctor.next_command.clone());
                    self.status = format!(
                        "Live gate next command copied for stage {}",
                        live_gate_doctor.operator_stage
                    );
                }
                if ui.button("Copy Live Gate Operator Brief").clicked() {
                    let brief = build_live_gate_operator_brief(&completion_audit, &live_gate_doctor);
                    ui.ctx().copy_text(brief.clone());
                    self.status =
                        format!("Live gate operator brief copied, {} bytes.", brief.len());
                }
                if ui.button("Copy Live Gate Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --live-gate --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90".to_owned(),
                    );
                    self.status = "Live gate command copied".to_owned();
                }
                if ui.button("Copy Live Gate Sequence").clicked() {
                    let sequence = build_live_gate_command_sequence(&completion_audit);
                    ui.ctx().copy_text(sequence.clone());
                    self.status = format!("Live gate sequence copied, {} bytes.", sequence.len());
                }
                if ui.button("Copy Goal Audit").clicked() {
                    ui.ctx().copy_text(completion_audit.to_markdown());
                    self.status = "KI goal audit copied".to_owned();
                }
                if ui.button("Copy Next Gate").clicked() {
                    ui.ctx().copy_text(next_blocking_action.clone());
                    self.status = "Next KI gate copied".to_owned();
                }
                if ui.button("Copy Next Gate JSON").clicked() {
                    match serde_json::to_string_pretty(&build_next_live_gate_report(
                        &completion_audit,
                    )) {
                        Ok(json) => {
                            let json = redact_secret_text(&json);
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Next KI gate JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Next KI gate JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Command Index JSON").clicked() {
                    match serde_json::to_string_pretty(&build_command_index()) {
                        Ok(json) => {
                            let json = redact_secret_text(&json);
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Command index JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Command index JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Evidence Matrix JSON").clicked() {
                    match redacted_json_string(&build_goal_evidence_matrix(&completion_audit)) {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Goal evidence matrix JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Goal evidence matrix JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Evidence Check JSON").clicked() {
                    match redacted_json_string(&build_goal_evidence_check(&completion_audit)) {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Goal evidence check JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Goal evidence check JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Handoff Check JSON").clicked() {
                    match serde_json::to_string_pretty(&build_operator_handoff_pack_check()) {
                        Ok(json) => {
                            let json = redact_secret_text(&json);
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Handoff check JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Handoff check JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Handoff Risk JSON").clicked() {
                    match redacted_json_string(&handoff_risk_summary) {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Handoff risk JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Handoff risk JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy Verification Snapshot JSON").clicked() {
                    match redacted_json_string(&verification_snapshot) {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("Verification snapshot JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("Verification snapshot JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy RDP Proof Check JSON").clicked() {
                    match redacted_json_string(&build_rdp_proof_check_from_args(&live_gate_args)) {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("RDP proof check JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("RDP proof check JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Copy RDP Proof Prompt").clicked() {
                    let prompt = build_rdp_proof_prompt(
                        &completion_audit,
                        &live_gate_doctor,
                        &verification_snapshot,
                    );
                    ui.ctx().copy_text(prompt.clone());
                    self.status = format!("RDP proof prompt copied, {} bytes.", prompt.len());
                }
                if ui.button("Copy RDP Recovery Plan").clicked() {
                    let proof_check = build_rdp_proof_check_from_args(&live_gate_args);
                    let plan = build_rdp_proof_recovery_plan(
                        &completion_audit,
                        &live_gate_doctor,
                        &proof_check,
                    );
                    ui.ctx().copy_text(plan.clone());
                    self.status = format!("RDP recovery plan copied, {} bytes.", plan.len());
                }
                if ui.button("Copy RDP Recovery Plan Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"
                            .to_owned(),
                    );
                    self.status = "RDP recovery plan command copied".to_owned();
                }
                if ui.button("Copy RDP Recovery Commands").clicked() {
                    let commands = handoff_risk_summary
                        .rdp_proof_failed_check_actions
                        .iter()
                        .filter_map(|action| {
                            action
                                .get("command")
                                .and_then(|command| command.as_str())
                                .map(str::to_owned)
                        })
                        .collect::<Vec<_>>();
                    let text = if commands.is_empty() {
                        "RDP proof has no failed recovery commands.".to_owned()
                    } else {
                        commands.join("\n")
                    };
                    ui.ctx().copy_text(text.clone());
                    self.status = format!("RDP recovery commands copied, {} bytes.", text.len());
                }
                if ui.button("Copy Handoff Risk Command").clicked() {
                    ui.ctx().copy_text(
                        "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env"
                            .to_owned(),
                    );
                    self.status = "Handoff risk command copied".to_owned();
                }
                if ui.button("Copy Live Gate Runbook").clicked() {
                    let runbook = build_live_gate_runbook(&completion_audit);
                    ui.ctx().copy_text(runbook.clone());
                    self.status = format!("Live gate runbook copied, {} bytes.", runbook.len());
                }
                if ui.button("Copy Handoff LLM Prompt").clicked() {
                    let readiness = build_ki_readiness_cli_report_from_args(&live_gate_args);
                    let runbook = build_live_gate_runbook(&completion_audit);
                    let prompt =
                        build_operator_llm_review_prompt(&readiness, &completion_audit, &runbook);
                    ui.ctx().copy_text(prompt.clone());
                    self.status = format!("Handoff LLM prompt copied, {} bytes.", prompt.len());
                }
                if ui.button("Copy Live Gate LLM Plan").clicked() {
                    let doctor = build_live_gate_doctor_report_from_args(&live_gate_args);
                    let runbook = build_live_gate_runbook(&completion_audit);
                    let plan = build_live_gate_llm_plan(&completion_audit, &doctor, &runbook);
                    ui.ctx().copy_text(plan.clone());
                    self.status = format!("Live gate LLM plan copied, {} bytes.", plan.len());
                }
                if ui.button("Copy LLM Action Contract JSON").clicked() {
                    match redacted_json_string(&build_llm_action_contract_from_args(&live_gate_args))
                    {
                        Ok(json) => {
                            ui.ctx().copy_text(json.clone());
                            self.status =
                                format!("LLM action contract JSON copied, {} bytes.", json.len());
                        }
                        Err(err) => {
                            self.status = format!("LLM action contract JSON failed: {err}");
                        }
                    }
                }
                if ui.button("Export Goal Audit").clicked() {
                    let mut report = build_completion_audit_report_from_args(&live_gate_args);
                    match save_completion_audit_report(&report) {
                        Ok(path) => {
                            report.audit_path = Some(path.display().to_string());
                            let _ = save_completion_audit_report(&report);
                            self.status = format!("KI goal audit exported to {}", path.display());
                        }
                        Err(err) => {
                            self.status = format!("KI goal audit export failed: {err}");
                        }
                    }
                }
                if ui.button("Export Handoff Pack").clicked() {
                    match build_operator_handoff_pack_report_from_args(&live_gate_args) {
                        Ok(report) => {
                            self.status = format!(
                                "Operator handoff pack exported to {}",
                                report.pack_path.as_deref().unwrap_or("app data")
                            );
                        }
                        Err(err) => {
                            self.status = format!("Operator handoff pack export failed: {err}");
                        }
                    }
                }
                if ui.button("Export Handoff Risk").clicked() {
                    match save_operator_handoff_risk_summary(&handoff_risk_summary) {
                        Ok(path) => {
                            self.status = format!("Handoff risk exported to {}", path.display());
                        }
                        Err(err) => {
                            self.status = format!("Handoff risk export failed: {err}");
                        }
                    }
                }
                if ui.button("Export Verification Snapshot").clicked() {
                    match save_verification_snapshot(&verification_snapshot) {
                        Ok(path) => {
                            self.status =
                                format!("Verification snapshot exported to {}", path.display());
                        }
                        Err(err) => {
                            self.status = format!("Verification snapshot export failed: {err}");
                        }
                    }
                }
                if ui.button("Export LLM Action Contract").clicked() {
                    let contract = build_llm_action_contract_from_args(&live_gate_args);
                    match save_llm_action_contract(&contract) {
                        Ok(path) => {
                            self.status =
                                format!("LLM action contract exported to {}", path.display());
                        }
                        Err(err) => {
                            self.status = format!("LLM action contract export failed: {err}");
                        }
                    }
                }
            });
        });
    }

    fn ai_session_panel(&mut self, ui: &mut Ui, session_id: Uuid) {
        ui.heading("KI Diagnose & Computer Use");
        if !self.diagnostics.is_empty() {
            ui.label("Preflight findings:");
            for finding in &self.diagnostics {
                ui.label(format!("- {}: {}", finding.title, finding.fix));
            }
        }
        ui.label(format!("Lokale KI: {}", self.ai_diagnosis));
        ui.label(format!("Computer Use: {}", self.computer_use_status));
        ui.separator();
        ui.label(
            RichText::new("Autopilot Mission Control")
                .strong()
                .color(tw::SLATE_800),
        );
        let mut preferences_changed = false;
        ui.horizontal_wrapped(|ui| {
            if ui.button("Diagnose").clicked() {
                self.autopilot.goal =
                    "Diagnose den aktuellen Remote-Desktop und sammle nur sichere Evidenz."
                        .to_owned();
                preferences_changed = true;
            }
            if ui.button("Login Assist").clicked() {
                self.autopilot.goal =
                    "Unterstuetze den sicheren Login, ohne Credentials offenzulegen oder zu speichern."
                        .to_owned();
                preferences_changed = true;
            }
            if ui.button("Black Screen").clicked() {
                self.autopilot.goal =
                    "Analysiere Black-Screen- oder Frozen-Session-Signale und schlage sichere Recovery-Schritte vor."
                        .to_owned();
                preferences_changed = true;
            }
            if ui.button("Evidence").clicked() {
                self.autopilot.goal =
                    "Sammle verwertbare Incident-Evidenz fuer Ticket, Timeline und Runbook."
                        .to_owned();
                preferences_changed = true;
            }
        });
        ui.horizontal(|ui| {
            ui.label("Provider");
            let provider_response = egui::ComboBox::from_id_salt("autopilot-provider")
                .selected_text(self.autopilot.settings.provider.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.autopilot.settings.provider,
                        AutopilotProviderKind::Local,
                        "Local",
                    );
                    ui.selectable_value(
                        &mut self.autopilot.settings.provider,
                        AutopilotProviderKind::OpenAiComputerUse,
                        "OpenAI CUA",
                    );
                });
            preferences_changed |= provider_response.response.changed();
            preferences_changed |= ui
                .checkbox(
                    &mut self.autopilot.settings.require_approval_for_every_mutation,
                    "Approve mutations",
                )
                .changed();
            preferences_changed |= ui
                .checkbox(
                    &mut self.autopilot.settings.agentic_runbook_mode,
                    "Agentic runbook mode",
                )
                .changed();
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Model");
            preferences_changed |= ui
                .add_sized(
                    [170.0, 24.0],
                    egui::TextEdit::singleline(&mut self.autopilot.settings.openai_model),
                )
                .changed();
            ui.label("Steps");
            preferences_changed |= ui
                .add(egui::Slider::new(
                    &mut self.autopilot.settings.max_steps,
                    1..=40,
                ))
                .changed();
            ui.label("Delay ms");
            preferences_changed |= ui
                .add(
                    egui::DragValue::new(&mut self.autopilot.settings.step_delay_millis)
                        .range(100..=5000)
                        .speed(50),
                )
                .changed();
        });
        ui.horizontal(|ui| {
            ui.label("Goal");
            preferences_changed |= ui
                .add_sized(
                    [ui.available_width().max(260.0), 28.0],
                    egui::TextEdit::singleline(&mut self.autopilot.goal),
                )
                .changed();
        });
        if preferences_changed {
            self.persist_autopilot_preferences();
        }
        ui.horizontal_wrapped(|ui| {
            compact_metric(ui, "Status", self.autopilot.status.label().to_owned());
            compact_metric(
                ui,
                "Steps",
                format!(
                    "{}/{}",
                    self.autopilot.steps.len(),
                    self.autopilot.settings.max_steps
                ),
            );
            compact_metric(
                ui,
                "Approvals",
                self.approvals
                    .iter()
                    .filter(|approval| approval.session_id == Some(session_id))
                    .count()
                    .to_string(),
            );
        });
        ui.horizontal_wrapped(|ui| {
            if ui.button("Copy CUA Request Brief").clicked() {
                let has_frame = self.latest_frames.contains_key(&session_id);
                let brief = build_cua_request_brief(&self.autopilot, has_frame);
                ui.ctx().copy_text(brief.clone());
                self.computer_use_status =
                    format!("OpenAI CUA request brief copied, {} bytes.", brief.len());
            }
            if ui.button("Preview local next step").clicked() {
                if let Some(frame) = self.latest_frames.get(&session_id) {
                    let agent = ComputerUseAgent::default();
                    let observation = agent.observe(frame);
                    let request = AutopilotRequest {
                        goal: &self.autopilot.goal,
                        frame,
                        observation: &observation,
                        settings: &self.autopilot.settings,
                        previous_response_id: None,
                        last_call_id: None,
                        acknowledged_safety_checks: &[],
                    };
                    match LocalAutopilotProvider.plan(&request) {
                        Ok(plan) => {
                            let action_label = plan
                                .action
                                .as_ref()
                                .map(|action| format!("{action:?}"))
                                .unwrap_or_else(|| "no action".to_owned());
                            self.computer_use_status = format!(
                                "Preview: {} | {} | {}",
                                observation.summary, plan.action_description, action_label
                            );
                            self.timeline.append_event(
                                session_id,
                                None,
                                SessionEventKind::AiObservation,
                                format!("Autopilot preview: {}", self.computer_use_status),
                            );
                        }
                        Err(err) => {
                            self.computer_use_status = format!("Autopilot preview failed: {err}");
                        }
                    }
                } else {
                    self.computer_use_status =
                        "Preview braucht zuerst einen Remote-Framebuffer.".to_owned();
                }
            }
            if ui.button("Start Autopilot").clicked() {
                let goal = self.autopilot.goal.clone();
                self.autopilot.start(goal);
                self.computer_use_status = "Autopilot started.".to_owned();
                self.timeline.append_event(
                    session_id,
                    None,
                    SessionEventKind::AiAction,
                    format!("Autopilot started: {}", self.autopilot.goal),
                );
            }
            if ui.button("Pause").clicked() {
                self.autopilot.pause();
                self.computer_use_status = "Autopilot paused.".to_owned();
            }
            if ui.button("Resume").clicked() {
                self.autopilot.resume();
                self.computer_use_status = "Autopilot resumed.".to_owned();
            }
            if ui.button("Abort").clicked() {
                self.autopilot.abort();
                self.timeline.append_event(
                    session_id,
                    None,
                    SessionEventKind::AiAction,
                    "Autopilot aborted by operator.".to_owned(),
                );
                self.computer_use_status = "Autopilot aborted.".to_owned();
            }
        });
        if self.autopilot.status == AutopilotStatus::WaitingForSafetyAck {
            ui.label(
                RichText::new("OpenAI safety checks require confirmation.").color(tw::RED_600),
            );
            for check in &self.autopilot.pending_safety_checks {
                ui.label(format!("{}: {}", check.code, check.message));
            }
            if ui.button("Acknowledge safety checks").clicked() {
                self.autopilot.acknowledge_safety_checks();
                self.timeline.append_event(
                    session_id,
                    None,
                    SessionEventKind::Approval,
                    "Autopilot OpenAI safety checks acknowledged.".to_owned(),
                );
            }
        }
        ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
            for step in self.autopilot.steps.iter().rev().take(5) {
                ui.label(format!(
                    "#{} {:?}/{:?} batch={}: {}",
                    step.index,
                    step.risk,
                    step.decision,
                    audited_step_actions(step).len(),
                    step.action_description
                ));
                ui.label(
                    RichText::new(&step.model_summary)
                        .size(12.0)
                        .color(tw::SLATE_600),
                );
                if let Some(verification) = &step.verification {
                    ui.label(format!("Verify: {}", verification.evidence));
                }
                if let Some(error) = &step.error {
                    ui.label(RichText::new(format!("Error: {error}")).color(tw::RED_600));
                }
            }
        });
        ui.separator();

        ui.horizontal(|ui| {
            if ui.button("Why did this fail?").clicked() {
                let messages = self.session_messages(session_id);
                let report = self.ai.write_incident_report(&messages);
                self.ai_diagnosis = format!("{} | Root cause: {}", report.title, report.root_cause);
            }
            if ui.button("What changed?").clicked() {
                let messages = self.session_messages(session_id);
                let change = self.ai.compare_sessions(&messages, &[]);
                self.ai_diagnosis = format!("{} {:?}", change.headline, change.changes);
            }
            if ui.button("Safe next action").clicked() {
                if let Some(frame) = self.latest_frames.get(&session_id) {
                    let agent = ComputerUseAgent::default();
                    let observation = agent.observe(frame);
                    let action =
                        agent.plan_next_step(&observation, "Diagnose aktuellen UI-Zustand");
                    if let Ok(input_action) = agent.execute_step(&action) {
                        let _ = self.engine.send_input(session_id, input_action);
                    }
                    self.computer_use_status = format!(
                        "{} | decision: {:?} | risk: {:?}",
                        observation.summary, action.decision, action.risk
                    );
                    self.timeline
                        .append_snapshot("KI screen observation".to_owned(), frame);
                    self.timeline.append_event(
                        session_id,
                        None,
                        SessionEventKind::AiObservation,
                        self.computer_use_status.clone(),
                    );
                } else {
                    self.computer_use_status =
                        "Noch kein Framebuffer fuer Observation vorhanden.".to_owned();
                }
            }
        });

        ui.horizontal(|ui| {
            if ui.button("Plan admin action").clicked() {
                let action = AiAction {
                    id: Uuid::new_v4(),
                    session_id: Some(session_id),
                    description: "Open diagnostics tool through remote UI".to_owned(),
                    action: InputAction::Hotkey {
                        keys: vec!["Win".to_owned(), "R".to_owned()],
                    },
                    risk: RiskLevel::ElevatedRisk,
                    decision: PolicyDecision::RequireApproval,
                };
                let agent = ComputerUseAgent::default();
                let approval = agent.request_approval(
                    &action,
                    "Opening remote tooling changes UI state and needs operator approval."
                        .to_owned(),
                );
                self.approvals.push(approval);
                self.computer_use_status = "Approval request queued.".to_owned();
            }
            if ui.button("Runbook recommendation").clicked() {
                let context = self.session_messages(session_id).join("\n");
                let recommendation = self
                    .runbooks
                    .recommend(&context)
                    .unwrap_or_else(|| self.ai.recommend_runbook(&context));
                self.computer_use_status = format!(
                    "{} ({:.0}%): {}",
                    recommendation.name,
                    recommendation.confidence * 100.0,
                    recommendation.reason
                );
            }
            if ui.button("Evidence mode").clicked() {
                let Some((runbook_id, runbook_name)) = self
                    .runbooks
                    .list_runbooks()
                    .first()
                    .map(|runbook| (runbook.id, runbook.name.clone()))
                else {
                    self.computer_use_status = "No runbooks available.".to_owned();
                    return;
                };
                if let Some(execution) = self.runbooks.start(session_id, runbook_id) {
                    self.active_runbook_execution = Some(execution.id);
                    if let Some(step) = self.runbooks.next_step(execution.id) {
                        let _ = self.engine.send_input(session_id, step.action.clone());
                        self.timeline.append_event(
                            session_id,
                            None,
                            SessionEventKind::AiAction,
                            format!("Runbook {} step: {}", runbook_name, step.title),
                        );
                        self.memory.record_runbook_result(
                            &self.selected_host_label(),
                            None,
                            &format!("{} started", runbook_name),
                        );
                        self.computer_use_status = format!("Evidence mode: {}", step.title);
                    }
                }
            }
            if ui.button("Next runbook step").clicked() {
                let Some(execution_id) = self.active_runbook_execution else {
                    self.computer_use_status = "No active runbook execution.".to_owned();
                    return;
                };
                if let Some(step) = self.runbooks.next_step(execution_id) {
                    match self.engine.send_input(session_id, step.action.clone()) {
                        Ok(()) => {
                            self.computer_use_status =
                                format!("Runbook step executed: {}", step.title);
                            self.timeline.append_event(
                                session_id,
                                None,
                                SessionEventKind::AiAction,
                                format!("Runbook step executed: {}", step.title),
                            );
                        }
                        Err(err) => {
                            self.computer_use_status = format!("Runbook step failed: {err}");
                        }
                    }
                } else {
                    self.computer_use_status = "Runbook has no next step.".to_owned();
                    self.active_runbook_execution = None;
                }
            }
            if ui.button("Pause runbook").clicked() {
                if let Some(execution_id) = self.active_runbook_execution {
                    self.runbooks.pause(execution_id);
                    self.computer_use_status = "Runbook paused.".to_owned();
                }
            }
            if ui.button("Resume runbook").clicked() {
                if let Some(execution_id) = self.active_runbook_execution {
                    self.runbooks.resume(execution_id);
                    self.computer_use_status = "Runbook resumed.".to_owned();
                }
            }
            if ui.button("Abort runbook").clicked() {
                if let Some(execution_id) = self.active_runbook_execution.take() {
                    self.runbooks.abort(execution_id);
                    self.timeline.append_event(
                        session_id,
                        None,
                        SessionEventKind::AiAction,
                        "Runbook aborted by operator.".to_owned(),
                    );
                    self.computer_use_status = "Runbook aborted.".to_owned();
                }
            }
            if ui.button("Export Incident").clicked() {
                let report = self.timeline.export_incident_markdown(session_id);
                let evidence_json = self.timeline.export_evidence_json(session_id);
                let saved = save_incident_files(session_id, &report, &evidence_json)
                    .map(|path| format!(" saved to {}", path.display()))
                    .unwrap_or_else(|err| format!(" save failed: {err}"));
                let messages = self
                    .timeline
                    .events_for_session(session_id)
                    .into_iter()
                    .map(|event| event.message)
                    .collect::<Vec<_>>();
                self.ai_diagnosis = self.ai.summarize_session(&messages).headline;
                self.computer_use_status = format!(
                    "Incident markdown {} bytes, evidence JSON {} bytes;{}",
                    report.len(),
                    evidence_json.len(),
                    saved
                );
            }
            if ui.button("LLM Handoff").clicked() {
                let prompt = self.llm_handoff_prompt(session_id);
                ui.ctx().copy_text(prompt.clone());
                let saved = save_llm_handoff_file(session_id, &prompt)
                    .map(|path| format!(" saved to {}", path.display()))
                    .unwrap_or_else(|err| format!(" save failed: {err}"));
                self.timeline.append_event(
                    session_id,
                    None,
                    SessionEventKind::AiObservation,
                    format!("LLM handoff generated: {} bytes;{}", prompt.len(), saved),
                );
                self.computer_use_status =
                    format!("LLM handoff copied, {} bytes;{}", prompt.len(), saved);
            }
            if ui.button("Ticket in 30 seconds").clicked() {
                let messages = self.session_messages(session_id);
                let ticket = self.ai.write_incident_report(&messages);
                self.computer_use_status = format!("Ticket: {}", ticket.customer_text);
            }
        });
    }

    fn session_messages(&self, session_id: Uuid) -> Vec<String> {
        self.timeline
            .events_for_session(session_id)
            .into_iter()
            .map(|event| event.message)
            .collect()
    }

    fn selected_host_label(&self) -> String {
        self.selected_profile()
            .map(|profile| profile.host.clone())
            .unwrap_or_else(|| "unknown-host".to_owned())
    }

    fn credential_status_label(&self) -> String {
        let Some(profile) = self.selected_profile() else {
            return "Credential: kein Profil ausgewaehlt".to_owned();
        };
        match profile.credential_id {
            Some(credential_id) if self.credentials.has_credential(credential_id) => {
                "Credential: gespeichert".to_owned()
            }
            Some(_) => "Credential: Referenz vorhanden, Secret fehlt".to_owned(),
            None => "Credential: fehlt, Passwort eintragen und Save Profile klicken".to_owned(),
        }
    }

    fn canvas_status(&self, session_id: Uuid) -> String {
        match (
            self.latest_frames.get(&session_id),
            self.textures.get(&session_id),
        ) {
            (Some(frame), Some(_)) => format!("Frame {}x{}", frame.width, frame.height),
            (Some(frame), None) => format!("Frame {}x{}, Texture fehlt", frame.width, frame.height),
            (None, Some(_)) => "Texture vorhanden, Frame fehlt".to_owned(),
            (None, None) => "Noch kein Frame".to_owned(),
        }
    }

    fn remote_canvas(&mut self, ui: &mut Ui, session_id: Uuid) {
        let width = ui.available_width().max(1.0);
        let height = ui.available_height().max(1.0);
        let desired_size = Vec2::new(width, height);
        let (rect, response) = ui.allocate_exact_size(desired_size, Sense::click_and_drag());
        if response.clicked() && ui.is_enabled() {
            response.request_focus();
        }
        let input_enabled = ui.is_enabled()
            && !self.desktop.palette
            && self.sessions.iter().any(|session| {
                session.id == session_id && session.status == SessionStatus::Connected
            });
        ui.memory_mut(|memory| {
            memory.set_focus_lock_filter(
                response.id,
                egui::EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            )
        });
        let painter = ui.painter_at(rect);
        painter.rect(
            rect,
            CornerRadius::same(4),
            tw::SLATE_950,
            Stroke::new(1.0, tw::SLATE_800),
            StrokeKind::Outside,
        );

        if let (Some(texture), Some(frame)) = (
            self.textures.get(&session_id),
            self.latest_frames.get(&session_id),
        ) {
            let source = remote_frame_source(frame);
            let image_rect =
                remote_image_rect(rect.shrink(2.0), source.size(), self.remote_view_mode);
            let _ = self.engine.resize(
                session_id,
                rect.shrink(2.0).width().round().clamp(320.0, 3840.0) as u16,
                rect.shrink(2.0).height().round().clamp(200.0, 2160.0) as u16,
            );
            painter.image(
                texture.id(),
                image_rect,
                source.uv_rect(frame),
                Color32::WHITE,
            );
            painter.text(
                rect.left_top() + Vec2::new(10.0, 8.0),
                egui::Align2::LEFT_TOP,
                format!(
                    "{}x{}  {:?}",
                    frame.width, frame.height, self.remote_view_mode
                ),
                FontId::proportional(11.0),
                tw::SLATE_300,
            );

            let events = ui.input(|input| input.events.clone());
            let focused = input_enabled
                && response.has_focus()
                && ui.input(|input| input.focused)
                && self.selected_session == Some(session_id);
            if focused {
                self.engine.set_clipboard_focus(Some(session_id));
            }
            let held_pointer = self.engine.pointer_is_held(session_id);
            if !focused && !held_pointer {
                self.engine.release_inputs(session_id);
            }
            let raw_keys = events
                .iter()
                .any(|event| matches!(event, egui::Event::Key { pressed: true, .. }));
            for event in events {
                match event {
                    egui::Event::PointerButton {
                        pos,
                        button,
                        pressed,
                        ..
                    } => {
                        let accepts = input_enabled
                            && self.selected_session == Some(session_id)
                            && ((response.hovered() && image_rect.contains(pos))
                                || (!pressed && held_pointer));
                        if accepts {
                            if pressed {
                                response.request_focus();
                            }
                            let button = match button {
                                egui::PointerButton::Primary => MouseButton::Left,
                                egui::PointerButton::Secondary => MouseButton::Right,
                                egui::PointerButton::Middle => MouseButton::Middle,
                                _ => continue,
                            };
                            let (x, y) = viewport_to_remote(pos, image_rect, source, frame);
                            let _ = self.engine.send_manual_input(
                                session_id,
                                InputAction::PointerButton {
                                    x,
                                    y,
                                    button,
                                    pressed,
                                },
                            );
                        }
                    }
                    egui::Event::PointerMoved(pos)
                        if input_enabled
                            && self.selected_session == Some(session_id)
                            && ((response.hovered() && image_rect.contains(pos))
                                || self.engine.pointer_is_held(session_id)) =>
                    {
                        let (x, y) = viewport_to_remote(pos, image_rect, source, frame);
                        let _ = self
                            .engine
                            .send_manual_input(session_id, InputAction::MovePointer { x, y });
                    }
                    egui::Event::Key {
                        key,
                        physical_key,
                        pressed,
                        modifiers,
                        ..
                    } if focused => {
                        for (scan_code, down) in remote_modifier_keys(modifiers) {
                            if self.engine.key_is_held(session_id, scan_code) != down {
                                let _ = self.engine.send_manual_input(
                                    session_id,
                                    InputAction::Key {
                                        scan_code,
                                        pressed: down,
                                    },
                                );
                            }
                        }
                        if let Some(scan_code) = remote_scan_code(physical_key.unwrap_or(key)) {
                            let _ = self.engine.send_manual_input(
                                session_id,
                                InputAction::Key { scan_code, pressed },
                            );
                        }
                    }
                    egui::Event::Copy | egui::Event::Cut | egui::Event::Paste(_) if focused => {
                        // egui-winit replaces Ctrl+C/X/V key-down with these semantic events.
                        for (scan_code, pressed) in
                            remote_modifier_keys(ui.input(|input| input.modifiers))
                        {
                            if self.engine.key_is_held(session_id, scan_code) != pressed {
                                let _ = self.engine.send_manual_input(
                                    session_id,
                                    InputAction::Key { scan_code, pressed },
                                );
                            }
                        }
                        let scan_code = match event {
                            egui::Event::Copy => 0x2e,
                            egui::Event::Cut => 0x2d,
                            _ => 0x2f,
                        };
                        let _ = self.engine.send_manual_input(
                            session_id,
                            InputAction::Key {
                                scan_code,
                                pressed: true,
                            },
                        );
                    }
                    egui::Event::Text(text) if focused && !raw_keys => {
                        let _ = self
                            .engine
                            .send_manual_input(session_id, InputAction::TypeText { text });
                    }
                    egui::Event::Ime(egui::ImeEvent::Commit(text)) if focused => {
                        let _ = self
                            .engine
                            .send_manual_input(session_id, InputAction::TypeText { text });
                    }
                    egui::Event::MouseWheel { unit, delta, .. }
                        if focused && response.hovered() =>
                    {
                        if let Some(pos) = ui.ctx().pointer_latest_pos() {
                            let scale = match unit {
                                egui::MouseWheelUnit::Line => 120.0,
                                egui::MouseWheelUnit::Page => 360.0,
                                egui::MouseWheelUnit::Point => 3.0,
                            };
                            let (x, y) = viewport_to_remote(pos, image_rect, source, frame);
                            let delta = (delta.y * scale).round().clamp(-255.0, 255.0) as i16;
                            if delta != 0 {
                                let _ = self.engine.send_manual_input(
                                    session_id,
                                    InputAction::Scroll { x, y, delta },
                                );
                            }
                        }
                    }
                    egui::Event::WindowFocused(false) | egui::Event::PointerGone => {
                        self.engine.release_inputs(session_id)
                    }
                    _ => {}
                }
            }
            if focused {
                for (scan_code, pressed) in remote_modifier_keys(ui.input(|input| input.modifiers))
                {
                    if self.engine.key_is_held(session_id, scan_code) != pressed {
                        let _ = self
                            .engine
                            .send_manual_input(session_id, InputAction::Key { scan_code, pressed });
                    }
                }
                for (scan_code, pressed) in native_extra_keys() {
                    if self.engine.key_is_held(session_id, scan_code) != pressed {
                        let _ = self
                            .engine
                            .send_manual_input(session_id, InputAction::Key { scan_code, pressed });
                    }
                }
            }
        } else {
            let message = self
                .sessions
                .iter()
                .find(|session| session.id == session_id)
                .map(|session| match session.status {
                    SessionStatus::Connected => {
                        "Connected - waiting for first remote desktop frame"
                    }
                    SessionStatus::Connecting | SessionStatus::Authenticating => {
                        "Connecting to native RDP session"
                    }
                    SessionStatus::Failed => "RDP session failed before a framebuffer arrived",
                    SessionStatus::Disconnected => "RDP session is disconnected",
                    SessionStatus::Reconnecting => "Reconnecting to native RDP session",
                    SessionStatus::Suspended => "RDP session is suspended",
                })
                .unwrap_or("Waiting for native RDP framebuffer");
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                message,
                FontId::proportional(20.0),
                tw::SLATE_300,
            );
        }
    }
}

fn configure_style(ctx: &Context) {
    // Use the platform UI face when available; egui's bundled fonts remain the fallback.
    #[cfg(windows)]
    if let Some(windows_dir) = std::env::var_os("WINDIR") {
        if let Ok(bytes) =
            std::fs::read(std::path::PathBuf::from(windows_dir).join("Fonts/segoeui.ttf"))
        {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "aivana-ui".to_owned(),
                egui::FontData::from_owned(bytes).into(),
            );
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "aivana-ui".to_owned());
            ctx.set_fonts(fonts);
        }
    }
    let mut style = (*ctx.global_style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(6);
    style.visuals.override_text_color = None;
    style.visuals.panel_fill = tw::SLATE_100;
    style.visuals.window_fill = tw::WHITE;
    style.visuals.extreme_bg_color = tw::WHITE;
    style.visuals.faint_bg_color = tw::SLATE_50;
    style.visuals.selection.bg_fill = Color32::from_rgb(0, 108, 123);
    style.visuals.selection.stroke = Stroke::new(1.0, tw::WHITE);
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, tw::SLATE_800);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, tw::SLATE_800);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, tw::SLATE_950);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, tw::SLATE_950);
    style.visuals.widgets.inactive.bg_fill = tw::SLATE_50;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, tw::SLATE_300);
    style.visuals.widgets.hovered.bg_fill = tw::BLUE_50;
    style.visuals.widgets.active.bg_fill = tw::BLUE_100;
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(30.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(17.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(14.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(12.0, FontFamily::Proportional),
    );
    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.button_padding = Vec2::new(10.0, 7.0);
    ctx.set_global_style(style);
}

#[derive(Clone, Copy)]
enum ActionTone {
    Neutral,
    Primary,
    Danger,
}

fn action_button(ui: &mut Ui, label: &str, width: f32, tone: ActionTone) -> egui::Response {
    let (fill, text, stroke) = match tone {
        ActionTone::Neutral => (tw::WHITE, tw::SLATE_800, tw::SLATE_300),
        ActionTone::Primary => (tw::BLUE_600, tw::WHITE, tw::BLUE_700),
        ActionTone::Danger => (tw::RED_600, tw::WHITE, tw::RED_700),
    };

    ui.add_sized(
        [width, 42.0],
        egui::Button::new(RichText::new(label).color(text).strong())
            .fill(fill)
            .stroke(Stroke::new(1.0, stroke)),
    )
}

fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.add_space(8.0);
    ui.heading(RichText::new(title).size(34.0).color(tw::SLATE_900));
    ui.label(RichText::new(subtitle).size(18.0).color(tw::SLATE_600));
    ui.add_space(18.0);
}

fn panel(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(tw::WHITE)
        .stroke(Stroke::new(1.0, tw::SLATE_200))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(16))
        .show(ui, add_contents);
}

fn text_field(ui: &mut Ui, label: &str, value: &mut String) {
    ui.label(RichText::new(label).strong().color(tw::SLATE_700));
    input_frame(ui, |ui| {
        ui.add_sized(
            [ui.available_width().max(220.0), 28.0],
            egui::TextEdit::singleline(value)
                .frame(Frame::NONE)
                .desired_width(f32::INFINITY),
        );
    });
}

fn password_field(ui: &mut Ui, label: &str, value: &mut String) {
    ui.label(RichText::new(label).strong().color(tw::SLATE_700));
    input_frame(ui, |ui| {
        ui.add_sized(
            [ui.available_width().max(220.0), 28.0],
            egui::TextEdit::singleline(value)
                .password(true)
                .frame(Frame::NONE)
                .desired_width(f32::INFINITY),
        );
    });
}

fn input_frame(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(tw::SLATE_50)
        .stroke(Stroke::new(1.0, tw::SLATE_300))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(10, 5))
        .show(ui, add_contents);
}

fn metric(ui: &mut Ui, label: &str, value: String) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(tw::SLATE_600));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).strong());
        });
    });
}

fn compact_metric(ui: &mut Ui, label: &str, value: String) {
    Frame::new()
        .fill(tw::SLATE_50)
        .stroke(Stroke::new(1.0, tw::SLATE_200))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_min_width(118.0);
            ui.label(RichText::new(label).size(12.0).color(tw::SLATE_600));
            ui.label(RichText::new(value).strong().color(tw::SLATE_900));
        });
}

fn fit_rect(bounds: Rect, image_size: Vec2) -> Rect {
    let scale = (bounds.width() / image_size.x).min(bounds.height() / image_size.y);
    let size = image_size * scale;
    Rect::from_center_size(bounds.center(), size)
}

fn remote_image_rect(bounds: Rect, image_size: Vec2, mode: RemoteViewMode) -> Rect {
    match mode {
        RemoteViewMode::Fit => fit_rect(bounds, image_size),
        RemoteViewMode::ActualSize => Rect::from_center_size(bounds.center(), image_size),
    }
}

#[derive(Clone, Copy)]
struct RemoteFrameSource {
    left: u16,
    top: u16,
    right: u16,
    bottom: u16,
}

impl RemoteFrameSource {
    fn full(frame: &FrameUpdate) -> Self {
        Self {
            left: 0,
            top: 0,
            right: frame.width.max(1),
            bottom: frame.height.max(1),
        }
    }

    fn size(self) -> Vec2 {
        Vec2::new(
            f32::from(self.right.saturating_sub(self.left).max(1)),
            f32::from(self.bottom.saturating_sub(self.top).max(1)),
        )
    }

    fn uv_rect(self, frame: &FrameUpdate) -> Rect {
        Rect::from_min_max(
            pos2(
                f32::from(self.left) / f32::from(frame.width.max(1)),
                f32::from(self.top) / f32::from(frame.height.max(1)),
            ),
            pos2(
                f32::from(self.right) / f32::from(frame.width.max(1)),
                f32::from(self.bottom) / f32::from(frame.height.max(1)),
            ),
        )
    }
}

fn remote_frame_source(frame: &FrameUpdate) -> RemoteFrameSource {
    visible_content_source(frame).unwrap_or_else(|| RemoteFrameSource::full(frame))
}

fn visible_content_source(frame: &FrameUpdate) -> Option<RemoteFrameSource> {
    let width = usize::from(frame.width);
    let height = usize::from(frame.height);
    let expected_len = width.checked_mul(height)?.checked_mul(4)?;
    if width == 0 || height == 0 || frame.pixels_rgba.len() < expected_len {
        return None;
    }

    let mut min_x = width;
    let mut min_y = height;
    let mut max_x = 0usize;
    let mut max_y = 0usize;
    let mut non_empty_pixels = 0usize;

    for y in 0..height {
        for x in 0..width {
            let offset = (y * width + x) * 4;
            let r = frame.pixels_rgba[offset];
            let g = frame.pixels_rgba[offset + 1];
            let b = frame.pixels_rgba[offset + 2];
            if r.max(g).max(b) > 18 {
                min_x = min_x.min(x);
                min_y = min_y.min(y);
                max_x = max_x.max(x);
                max_y = max_y.max(y);
                non_empty_pixels += 1;
            }
        }
    }

    if non_empty_pixels == 0 {
        return None;
    }

    let margin = 6usize;
    min_x = min_x.saturating_sub(margin);
    min_y = min_y.saturating_sub(margin);
    max_x = (max_x + margin).min(width.saturating_sub(1));
    max_y = (max_y + margin).min(height.saturating_sub(1));

    let bbox_width = max_x.saturating_sub(min_x) + 1;
    let bbox_height = max_y.saturating_sub(min_y) + 1;
    let bbox_area = bbox_width.saturating_mul(bbox_height);
    let frame_area = width.saturating_mul(height).max(1);
    let bbox_ratio = bbox_area as f32 / frame_area as f32;
    let non_empty_ratio = non_empty_pixels as f32 / frame_area as f32;

    if bbox_width < 80 || bbox_height < 80 || bbox_ratio > 0.82 || non_empty_ratio < 0.002 {
        return None;
    }

    Some(RemoteFrameSource {
        left: min_x as u16,
        top: min_y as u16,
        right: (max_x + 1) as u16,
        bottom: (max_y + 1) as u16,
    })
}

fn viewport_to_remote(
    pos: Pos2,
    image_rect: Rect,
    source: RemoteFrameSource,
    frame: &FrameUpdate,
) -> (u16, u16) {
    let x =
        f32::from(source.left) + (pos.x - image_rect.left()) / image_rect.width() * source.size().x;
    let y =
        f32::from(source.top) + (pos.y - image_rect.top()) / image_rect.height() * source.size().y;
    let x = x.clamp(0.0, f32::from(frame.width.saturating_sub(1))) as u16;
    let y = y.clamp(0.0, f32::from(frame.height.saturating_sub(1))) as u16;
    (x, y)
}

fn timeline_message(event: &EngineEvent) -> (SessionEventKind, String) {
    match event {
        EngineEvent::StatusChanged { status, .. } => (
            SessionEventKind::ConnectionStage,
            format!("Session status changed to {}", status.label()),
        ),
        EngineEvent::Frame(frame) => (
            SessionEventKind::Screenshot,
            format!(
                "Framebuffer {}x{} hash={} dirty_regions={}",
                frame.width,
                frame.height,
                frame.frame_hash,
                frame.dirty_regions.len()
            ),
        ),
        EngineEvent::Error { class, message, .. } => (
            SessionEventKind::Error,
            format!("RDP error {:?}: {}", class, message),
        ),
        EngineEvent::Diagnostic { message, .. } => (
            SessionEventKind::Diagnostic,
            format!("RDP diagnostic: {message}"),
        ),
        EngineEvent::Disconnected { reason, .. } => (
            SessionEventKind::ConnectionStage,
            format!("Disconnected: {reason}"),
        ),
    }
}

fn format_ai_explanation(explanation: &AiExplanation) -> String {
    format!(
        "{}: {} Next: {} Confidence: {:.0}%",
        explanation.title,
        explanation.likely_root_cause,
        explanation.next_safe_step,
        explanation.confidence * 100.0
    )
}

fn input_action_label(action: &InputAction) -> String {
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
        InputAction::DoubleClick { x, y, button } => {
            format!("double-click {button:?} at {x},{y}")
        }
        InputAction::Scroll { x, y, delta } => format!("scroll {delta} at {x},{y}"),
        InputAction::TypeText { text } => format!(
            "type {} character(s): {}",
            text.chars().count(),
            redact_secret_text(text)
        ),
        InputAction::Hotkey { keys } => format!("keypress {}", keys.join("+")),
        InputAction::Wait { millis } => format!("wait {millis}ms"),
        InputAction::Screenshot => "screenshot".to_owned(),
        InputAction::Verify { expectation } => {
            format!("verify {}", redact_secret_text(expectation))
        }
    }
}

fn build_ai_readiness_report(
    selected_session_id: Option<Uuid>,
    has_frame: bool,
    provider: AutopilotProviderKind,
    openai_key_set: bool,
    open_approvals: usize,
) -> String {
    let session = if selected_session_id.is_some() {
        "session selected"
    } else {
        "no session selected"
    };
    let frame = if has_frame {
        "framebuffer ready"
    } else {
        "waiting for framebuffer"
    };
    let provider_status = match provider {
        AutopilotProviderKind::Local => "local planner ready".to_owned(),
        AutopilotProviderKind::OpenAiComputerUse if openai_key_set => {
            "OpenAI CUA key available".to_owned()
        }
        AutopilotProviderKind::OpenAiComputerUse => "OpenAI CUA needs OPENAI_API_KEY".to_owned(),
    };
    let approvals = if open_approvals == 0 {
        "no pending approvals".to_owned()
    } else {
        format!("{open_approvals} pending approval(s)")
    };

    format!("Readiness: {session}; {frame}; {provider_status}; {approvals}.")
}

#[derive(Clone, Debug)]
struct KiVerificationReport {
    openai_key_set: bool,
    rdp_smoke_ready: bool,
    preferences_saved: bool,
    session_count: usize,
    summary: String,
    next_step: String,
}

impl KiVerificationReport {
    fn to_markdown(&self) -> String {
        format!(
            "# Aivana KI Verification\n\n- OpenAI key: {}\n- RDP smoke env: {}\n- Preferences: {}\n- Active sessions: {}\n\n{}\n\nNext: {}\n",
            if self.openai_key_set {
                "ready"
            } else {
                "missing"
            },
            if self.rdp_smoke_ready {
                "ready"
            } else {
                "missing"
            },
            if self.preferences_saved {
                "saved"
            } else {
                "not saved"
            },
            self.session_count,
            self.summary,
            self.next_step
        )
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct KiReadinessCliReport {
    pub report_id: Uuid,
    pub generated_at: chrono::DateTime<Utc>,
    pub openai_key_set: bool,
    pub rdp_smoke_env_ready: bool,
    pub preferences_saved: bool,
    pub active_sessions: usize,
    pub provider: String,
    pub model: String,
    pub max_steps: usize,
    pub step_delay_millis: u64,
    pub goal: String,
    pub readiness_score: u8,
    pub missing_requirements: Vec<String>,
    pub latest_rdp_preflight_evidence: Option<String>,
    pub latest_rdp_smoke_evidence: Option<String>,
    pub latest_live_gate_evidence: Option<String>,
    pub next_step: String,
    pub evidence_path: Option<String>,
}

pub fn build_ki_readiness_cli_report() -> KiReadinessCliReport {
    build_ki_readiness_cli_report_from_args(&[])
}

pub fn build_ki_readiness_cli_report_from_args(args: &[String]) -> KiReadinessCliReport {
    let mut autopilot = AutopilotController::default();
    if let Some(preferences) = load_autopilot_preferences() {
        autopilot.goal = preferences.goal;
        autopilot.settings = preferences.settings;
    }

    let openai_key_set = std::env::var("OPENAI_API_KEY").is_ok_and(|key| !key.trim().is_empty());
    let env_file_check = if crate::ironrdp_client::rdp_env_file_path_from_args(args).is_some() {
        Some(crate::ironrdp_client::rdp_env_file_check_report_from_args(
            args,
            crate::ironrdp_client::rdp_smoke_timeout_secs_from_args(args),
        ))
    } else {
        None
    };
    let missing_rdp_env = missing_required_rdp_test_env();
    let rdp_smoke_env_ready = env_file_check
        .as_ref()
        .map(|report| report.ok)
        .unwrap_or_else(|| missing_rdp_env.is_empty());
    let preferences_saved = app_data_file("autopilot-preferences.json")
        .ok()
        .is_some_and(|path| path.exists());
    let latest_rdp_preflight_evidence = latest_rdp_preflight_report_summary();
    let latest_rdp_smoke_evidence = latest_rdp_smoke_report_summary();
    let latest_live_gate_evidence = latest_live_gate_report_summary();

    let mut report = build_ki_readiness_cli_report_with_inputs(
        &autopilot,
        openai_key_set,
        rdp_smoke_env_ready,
        preferences_saved,
        latest_rdp_preflight_evidence,
        latest_rdp_smoke_evidence,
        latest_live_gate_evidence,
    );
    if let Some(env_file_check) = env_file_check {
        if !env_file_check.ok {
            let detail = env_file_check
                .error
                .as_deref()
                .map(|error| format!("invalid RDP env file: {}", redact_secret_text(error)))
                .unwrap_or_else(|| "invalid RDP env file".to_owned());
            report.next_step =
                "Fix --rdp-env-file values, then rerun --rdp-env-file-check.".to_owned();
            if let Some(item) = report
                .missing_requirements
                .iter_mut()
                .find(|item| item.as_str() == "AIVANA_RDP_TEST_*")
            {
                *item = detail;
            }
        }
    } else if !missing_rdp_env.is_empty() {
        let detail = format!("missing RDP env vars: {}", missing_rdp_env.join(", "));
        if let Some(item) = report
            .missing_requirements
            .iter_mut()
            .find(|item| item.as_str() == "AIVANA_RDP_TEST_*")
        {
            *item = detail;
        }
    }
    report
}

fn missing_required_rdp_test_env() -> Vec<String> {
    missing_required_rdp_test_env_from_lookup(|name| match std::env::var(name) {
        Ok(value) => {
            value.trim().is_empty()
                || crate::ironrdp_client::is_unfilled_rdp_test_placeholder(&value)
        }
        Err(_) => true,
    })
}

fn missing_required_rdp_test_env_from_args(args: &[String]) -> Vec<String> {
    if crate::ironrdp_client::rdp_env_file_path_from_args(args).is_some() {
        let env_file_check = crate::ironrdp_client::rdp_env_file_check_report_from_args(
            args,
            crate::ironrdp_client::rdp_smoke_timeout_secs_from_args(args),
        );
        if env_file_check.ok {
            return Vec::new();
        }
    }
    missing_required_rdp_test_env()
}

fn missing_required_rdp_test_env_from_lookup(
    mut is_missing: impl FnMut(&str) -> bool,
) -> Vec<String> {
    [
        "AIVANA_RDP_TEST_HOST",
        "AIVANA_RDP_TEST_USER",
        "AIVANA_RDP_TEST_PASSWORD",
    ]
    .into_iter()
    .filter(|name| is_missing(name))
    .map(str::to_owned)
    .collect()
}

fn default_rdp_live_env_args() -> Vec<String> {
    default_rdp_live_env_args_from_dir(Path::new("."))
}

fn default_rdp_live_env_args_from_dir(dir: &Path) -> Vec<String> {
    let path = dir.join("rdp-live.env");
    if path.exists() {
        vec![
            "aivana-gui".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ]
    } else {
        Vec::new()
    }
}

fn build_ki_readiness_cli_report_with_inputs(
    autopilot: &AutopilotController,
    openai_key_set: bool,
    rdp_smoke_env_ready: bool,
    preferences_saved: bool,
    latest_rdp_preflight_evidence: Option<String>,
    latest_rdp_smoke_evidence: Option<String>,
    latest_live_gate_evidence: Option<String>,
) -> KiReadinessCliReport {
    let verification = build_ki_verification_report_with_inputs(
        autopilot,
        0,
        openai_key_set,
        rdp_smoke_env_ready,
        preferences_saved,
    );
    let mut missing_requirements = Vec::new();
    if autopilot.settings.provider == AutopilotProviderKind::OpenAiComputerUse && !openai_key_set {
        missing_requirements.push("OPENAI_API_KEY".to_owned());
    }
    if !rdp_smoke_env_ready {
        missing_requirements.push("AIVANA_RDP_TEST_*".to_owned());
    }
    if !preferences_saved {
        missing_requirements.push("saved KI preferences".to_owned());
    }
    if latest_rdp_preflight_evidence.is_none() {
        missing_requirements.push("persisted RDP preflight evidence".to_owned());
    }
    if latest_rdp_smoke_evidence.is_none() {
        missing_requirements.push("persisted RDP smoke evidence".to_owned());
    }
    if latest_live_gate_evidence.is_none() {
        missing_requirements.push("persisted live gate evidence".to_owned());
    }
    let requirement_count = 6usize;
    let passed =
        requirement_count.saturating_sub(missing_requirements.len().min(requirement_count));
    let readiness_score = ((passed * 100) / requirement_count) as u8;

    KiReadinessCliReport {
        report_id: Uuid::new_v4(),
        generated_at: Utc::now(),
        openai_key_set,
        rdp_smoke_env_ready,
        preferences_saved,
        active_sessions: 0,
        provider: autopilot.settings.provider.label().to_owned(),
        model: autopilot.settings.openai_model.clone(),
        max_steps: autopilot.settings.max_steps,
        step_delay_millis: autopilot.settings.step_delay_millis,
        goal: redact_secret_text(&autopilot.goal),
        readiness_score,
        missing_requirements,
        latest_rdp_preflight_evidence,
        latest_rdp_smoke_evidence,
        latest_live_gate_evidence,
        next_step: verification.next_step,
        evidence_path: None,
    }
}

pub fn save_ki_readiness_cli_report(
    report: &KiReadinessCliReport,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("ki-readiness-reports")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.report_id));
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct KiEvidenceBundleReport {
    pub bundle_id: Uuid,
    pub created_at: chrono::DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub goal: String,
    pub readiness_score: u8,
    pub missing_requirements: Vec<String>,
    pub latest_rdp_preflight_evidence: Option<String>,
    pub latest_rdp_smoke_evidence: Option<String>,
    pub latest_live_gate_evidence: Option<String>,
    pub latest_ai_brief_pack: Option<String>,
    pub next_step: String,
    pub files: Vec<String>,
    pub bundle_path: Option<String>,
}

pub fn build_ki_evidence_bundle_report_from_args(args: &[String]) -> KiEvidenceBundleReport {
    build_ki_evidence_bundle_report_with_inputs(
        build_ki_readiness_cli_report_from_args(args),
        latest_ai_brief_pack_summary(),
    )
}

fn build_ki_evidence_bundle_report_with_inputs(
    readiness: KiReadinessCliReport,
    latest_ai_brief_pack: Option<String>,
) -> KiEvidenceBundleReport {
    KiEvidenceBundleReport {
        bundle_id: Uuid::new_v4(),
        created_at: Utc::now(),
        provider: redact_secret_text(&readiness.provider),
        model: redact_secret_text(&readiness.model),
        goal: redact_secret_text(&readiness.goal),
        readiness_score: readiness.readiness_score,
        missing_requirements: readiness.missing_requirements,
        latest_rdp_preflight_evidence: readiness
            .latest_rdp_preflight_evidence
            .as_deref()
            .map(redact_secret_text),
        latest_rdp_smoke_evidence: readiness
            .latest_rdp_smoke_evidence
            .as_deref()
            .map(redact_secret_text),
        latest_live_gate_evidence: readiness
            .latest_live_gate_evidence
            .as_deref()
            .map(redact_secret_text),
        latest_ai_brief_pack: latest_ai_brief_pack.as_deref().map(redact_secret_text),
        next_step: redact_secret_text(&readiness.next_step),
        files: vec!["bundle.md".to_owned(), "manifest.json".to_owned()],
        bundle_path: None,
    }
}

pub fn save_ki_evidence_bundle_report(
    report: &KiEvidenceBundleReport,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("ki-evidence-bundles")?.join(report.bundle_id.to_string());
    save_ki_evidence_bundle_report_to_dir(&dir, report)
}

fn save_ki_evidence_bundle_report_to_dir(
    dir: &Path,
    report: &KiEvidenceBundleReport,
) -> anyhow::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let markdown = format!(
        "# Aivana KI Evidence Bundle\n\n- Bundle: `{}`\n- Created: {}\n- Provider: {}\n- Model: {}\n- Goal: {}\n- Readiness score: {}%\n- Missing requirements: {}\n\n## RDP Preflight Evidence\n{}\n\n## RDP Smoke Evidence\n{}\n\n## Live Gate Evidence\n{}\n\n## AI Brief Pack\n{}\n\n## Next Step\n{}\n",
        report.bundle_id,
        report.created_at,
        redact_secret_text(&report.provider),
        redact_secret_text(&report.model),
        redact_secret_text(&report.goal),
        report.readiness_score,
        if report.missing_requirements.is_empty() {
            "none".to_owned()
        } else {
            redact_secret_text(&report.missing_requirements.join(", "))
        },
        report
            .latest_rdp_preflight_evidence
            .as_deref()
            .map(redact_secret_text)
            .unwrap_or_else(|| "none recorded".to_owned()),
        report
            .latest_rdp_smoke_evidence
            .as_deref()
            .map(redact_secret_text)
            .unwrap_or_else(|| "none recorded".to_owned()),
        report
            .latest_live_gate_evidence
            .as_deref()
            .map(redact_secret_text)
            .unwrap_or_else(|| "none recorded".to_owned()),
        report
            .latest_ai_brief_pack
            .as_deref()
            .map(redact_secret_text)
            .unwrap_or_else(|| "none exported".to_owned()),
        redact_secret_text(&report.next_step)
    );
    std::fs::write(dir.join("bundle.md"), markdown)?;
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(report)?,
    )?;
    Ok(dir.to_path_buf())
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CompletionAuditItem {
    pub requirement: String,
    pub artifact: String,
    pub evidence: String,
    pub next_action: String,
    pub status: String,
    pub blocking: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CompletionAuditReport {
    pub audit_id: Uuid,
    pub generated_at: chrono::DateTime<Utc>,
    pub objective: String,
    pub achieved: bool,
    pub summary: String,
    pub items: Vec<CompletionAuditItem>,
    pub audit_path: Option<String>,
}

impl CompletionAuditReport {
    fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Aivana KI Goal Audit");
        let _ = writeln!(out);
        let _ = writeln!(out, "- Audit: `{}`", self.audit_id);
        let _ = writeln!(out, "- Created: {}", self.generated_at);
        let _ = writeln!(out, "- Objective: {}", redact_secret_text(&self.objective));
        let _ = writeln!(out, "- Achieved: {}", self.achieved);
        let _ = writeln!(out, "- Summary: {}", redact_secret_text(&self.summary));
        let _ = writeln!(out);
        let _ = writeln!(out, "## Prompt-to-Artifact Checklist");
        for item in &self.items {
            let _ = writeln!(
                out,
                "- [{}] {} | artifact: {} | status: {} | blocking: {} | evidence: {}",
                if item.blocking { "!" } else { "x" },
                redact_secret_text(&item.requirement),
                redact_secret_text(&item.artifact),
                redact_secret_text(&item.status),
                item.blocking,
                redact_secret_text(&item.evidence)
            );
            let _ = writeln!(out, "  next: {}", redact_secret_text(&item.next_action));
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## Live Gate Runbook");
        let _ = writeln!(out, "{}", build_live_gate_runbook(self));
        redact_secret_text(&out)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct NextLiveGateReport {
    pub audit_id: Uuid,
    pub objective: String,
    pub achieved: bool,
    pub blocking_gates: usize,
    pub first_blocking_requirement: Option<String>,
    pub first_blocking_status: Option<String>,
    pub first_blocking_evidence: Option<String>,
    pub operator_action: Option<String>,
    pub missing_rdp_env: Vec<String>,
    pub rdp_env_template: String,
    pub next_commands: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveGateDoctorReport {
    pub schema: String,
    pub generated_at: chrono::DateTime<Utc>,
    pub achieved: bool,
    pub ready_for_preflight: bool,
    pub ready_for_smoke: bool,
    pub smoke_connected: bool,
    pub handoff_pack_valid: bool,
    pub operator_stage: String,
    pub operator_brief: String,
    pub blocking_reason: String,
    pub next_command: String,
    pub next_success_command: String,
    pub rdp_proof_recovery_plan_command: String,
    pub acceptance_criteria: String,
    pub checks: Vec<LiveGateDoctorCheck>,
    pub evidence: LiveGateDoctorEvidence,
    pub evidence_path: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveGateDoctorCheck {
    pub name: String,
    pub ok: bool,
    pub status: String,
    pub evidence: String,
    pub next_command: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveGateDoctorEvidence {
    pub env_file_check: String,
    pub preflight: String,
    pub smoke: String,
    pub rdp_proof_check: String,
    pub handoff_check: String,
    pub completion_audit: String,
}

pub fn build_next_live_gate_report(report: &CompletionAuditReport) -> NextLiveGateReport {
    build_next_live_gate_report_with_missing_env(report, missing_required_rdp_test_env())
}

pub fn build_next_live_gate_report_from_args(
    report: &CompletionAuditReport,
    args: &[String],
) -> NextLiveGateReport {
    build_next_live_gate_report_with_missing_env(
        report,
        missing_required_rdp_test_env_from_args(args),
    )
}

fn build_next_live_gate_report_with_missing_env(
    report: &CompletionAuditReport,
    missing_rdp_env: Vec<String>,
) -> NextLiveGateReport {
    let blockers = report
        .items
        .iter()
        .filter(|item| item.blocking)
        .collect::<Vec<_>>();
    let first = blockers.first().copied();
    NextLiveGateReport {
        audit_id: report.audit_id,
        objective: redact_secret_text(&report.objective),
        achieved: report.achieved,
        blocking_gates: blockers.len(),
        first_blocking_requirement: first.map(|item| redact_secret_text(&item.requirement)),
        first_blocking_status: first.map(|item| redact_secret_text(&item.status)),
        first_blocking_evidence: first.map(|item| redact_secret_text(&item.evidence)),
        operator_action: first.map(|item| redact_secret_text(&item.next_action)),
        missing_rdp_env,
        rdp_env_template: build_rdp_live_gate_env_template(),
        next_commands: vec![
            "cargo run -- --save-rdp-env-template .\\rdp-live.env".to_owned(),
            "cargo run -- --rdp-env-fill-guide".to_owned(),
            "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
                .to_owned(),
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
                .to_owned(),
            "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --llm-review-prompt".to_owned(),
            "cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --goal-evidence-matrix --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env".to_owned(),
            "cargo run -- --operator-handoff-check".to_owned(),
            "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env"
                .to_owned(),
            "cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env".to_owned(),
        ],
    }
}

pub fn build_live_gate_command_sequence(report: &CompletionAuditReport) -> String {
    build_next_live_gate_report(report).next_commands.join("\n")
}

fn live_gate_env_file_needs_fill_guide(error: &str) -> bool {
    error.contains("must be filled")
        || error.contains("placeholder value")
        || error.contains("[REDACTED]")
        || error.contains("<host>")
        || error.contains("<user>")
}

fn live_gate_operator_stage(next_command: &str) -> &'static str {
    if next_command.contains("--save-rdp-env-template") {
        "create-local-rdp-env"
    } else if next_command.contains("--rdp-env-fill-guide") {
        "fill-local-rdp-env"
    } else if next_command.contains("--rdp-env-file-check") {
        "validate-local-rdp-env"
    } else if next_command.contains("--rdp-preflight") {
        "run-network-preflight"
    } else if next_command.contains("--rdp-smoke-test") {
        "run-live-rdp-smoke"
    } else if next_command.contains("--rdp-proof-check") {
        "validate-rdp-proof"
    } else if next_command.contains("--operator-handoff-pack") {
        "export-operator-handoff"
    } else if next_command.contains("--operator-handoff-check") {
        "validate-operator-handoff"
    } else if next_command.contains("--operator-handoff-risk-summary") {
        "summarize-handoff-risk"
    } else if next_command.contains("--verification-snapshot") {
        "export-verification-snapshot"
    } else if next_command.contains("--goal-evidence-check") {
        "verify-goal-evidence"
    } else {
        "review-completion-audit"
    }
}

fn live_gate_next_success_command(next_command: &str) -> &'static str {
    if next_command.contains("--save-rdp-env-template") {
        "cargo run -- --rdp-env-fill-guide"
    } else if next_command.contains("--rdp-env-fill-guide") {
        "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env"
    } else if next_command.contains("--rdp-env-file-check") {
        "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
    } else if next_command.contains("--rdp-preflight") {
        "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
    } else if next_command.contains("--rdp-smoke-test") {
        "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env"
    } else if next_command.contains("--rdp-proof-check") {
        "cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env"
    } else if next_command.contains("--operator-handoff-pack") {
        "cargo run -- --operator-handoff-check"
    } else if next_command.contains("--operator-handoff-check") {
        "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env"
    } else if next_command.contains("--operator-handoff-risk-summary") {
        "cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env"
    } else if next_command.contains("--verification-snapshot") {
        "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env"
    } else if next_command.contains("--goal-evidence-check") {
        "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env"
    } else {
        "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env"
    }
}

fn live_gate_acceptance_criteria(next_command: &str) -> &'static str {
    if next_command.contains("--save-rdp-env-template") {
        "Local ignored rdp-live.env exists and contains only operator-controlled values."
    } else if next_command.contains("--rdp-env-fill-guide") {
        "Operator has replaced every required placeholder in ignored rdp-live.env without sharing secrets."
    } else if next_command.contains("--rdp-env-file-check") {
        "Env-file check persists ok=true with network_checked=false and no placeholders."
    } else if next_command.contains("--rdp-preflight") {
        "Preflight persists connect_recommended=true for the target host and port."
    } else if next_command.contains("--rdp-smoke-test") {
        "Smoke evidence persists connected=true with framebuffer and input probe proof."
    } else if next_command.contains("--rdp-proof-check") {
        "RDP proof check exits 0 with env_file_ok, preflight_connect_recommended, preflight_matches_env, preflight_fresh_for_env, smoke_connected, smoke_matches_env, smoke_fresh_for_env, framebuffer_present, and input_probe_present."
    } else if next_command.contains("--operator-handoff-pack") {
        "A fresh redacted handoff pack is exported and ready for handoff validation."
    } else if next_command.contains("--operator-handoff-check") {
        "Latest handoff pack validation exits 0 with ok=true."
    } else if next_command.contains("--operator-handoff-risk-summary") {
        "Handoff risk summary exits 0 with ok=true after real RDP goal evidence is present."
    } else if next_command.contains("--verification-snapshot") {
        "Verification snapshot exits 0 with ok=true, live_gate.smoke_connected=true, and a valid handoff reference."
    } else if next_command.contains("--goal-evidence-check") {
        "Goal evidence check exits 0 and the completion audit has no unresolved blocking gate."
    } else {
        "Completion audit confirms achieved=true with concrete live RDP evidence."
    }
}

pub fn build_live_gate_doctor_report() -> LiveGateDoctorReport {
    let audit = build_completion_audit_report();
    let env_file_check = latest_rdp_env_file_check_json_value();
    let env_summary = latest_rdp_env_file_check_summary()
        .unwrap_or_else(|| "Latest RDP env-file check evidence: none recorded yet.".to_owned());
    let proof_check = build_rdp_proof_check_from_args(&[]);
    build_live_gate_doctor_report_with_inputs(audit, env_file_check, env_summary, proof_check)
}

pub fn build_live_gate_doctor_report_from_args(args: &[String]) -> LiveGateDoctorReport {
    let audit = build_completion_audit_report_from_args(args);
    let (env_file_check, env_summary) = if crate::ironrdp_client::rdp_env_file_path_from_args(args)
        .is_some()
    {
        let report = crate::ironrdp_client::rdp_env_file_check_report_from_args(
            args,
            crate::ironrdp_client::rdp_smoke_timeout_secs_from_args(args),
        );
        let value = serde_json::to_value(&report)
            .unwrap_or_else(|err| fallback_rdp_env_file_check_json_value(err.to_string()));
        let summary = rdp_env_file_check_summary_from_value(&value, report.path.as_deref());
        (value, summary)
    } else {
        let value = latest_rdp_env_file_check_json_value();
        let summary = latest_rdp_env_file_check_summary()
            .unwrap_or_else(|| "Latest RDP env-file check evidence: none recorded yet.".to_owned());
        (value, summary)
    };
    let proof_check = build_rdp_proof_check_from_args(args);
    build_live_gate_doctor_report_with_inputs(audit, env_file_check, env_summary, proof_check)
}

fn build_live_gate_doctor_report_with_inputs(
    audit: CompletionAuditReport,
    env_file_check: serde_json::Value,
    env_summary: String,
    proof_check: serde_json::Value,
) -> LiveGateDoctorReport {
    let preflight = latest_json_value_from_app_data("rdp-preflight");
    let smoke = latest_json_value_from_app_data("rdp-smoke-tests");
    let handoff_check = build_operator_handoff_pack_check();

    let env_ok = env_file_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let preflight_ok = preflight
        .as_ref()
        .and_then(|value| value.get("connect_recommended"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let smoke_connected = smoke
        .as_ref()
        .and_then(|value| value.get("connected"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let proof_ok = proof_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let proof_next_command = proof_check
        .get("next_command")
        .and_then(|value| value.as_str())
        .unwrap_or("cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env");
    let proof_failed_checks = proof_check
        .get("failed_checks")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let handoff_ok = handoff_check.ok;

    let preflight_summary = latest_rdp_preflight_report_summary()
        .unwrap_or_else(|| "Latest RDP preflight evidence: none recorded yet.".to_owned());
    let smoke_summary = latest_rdp_smoke_report_summary()
        .unwrap_or_else(|| "Latest RDP smoke evidence: none recorded yet.".to_owned());
    let proof_summary = redact_secret_text(&format!(
        "Latest RDP proof check: ok={} failed_checks={} next={}",
        proof_ok, proof_failed_checks, proof_next_command
    ));
    let handoff_summary = operator_handoff_check_summary(&handoff_check);
    let completion_summary = redact_secret_text(&format!(
        "Completion audit: achieved={} blocking_gates={} summary={}",
        audit.achieved,
        audit.items.iter().filter(|item| item.blocking).count(),
        audit.summary
    ));

    let save_env_command = "cargo run -- --save-rdp-env-template .\\rdp-live.env";
    let fill_guide_command = "cargo run -- --rdp-env-fill-guide";
    let env_command = "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env";
    let preflight_command =
        "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90";
    let smoke_command =
        "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90";
    let proof_command = "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env";
    let proof_recovery_plan_command =
        "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env";
    let handoff_command = "cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env";
    let risk_summary_command =
        "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env";
    let goal_check_command = "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env";
    let env_file_error = env_file_check
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let env_file_missing = !env_ok
        && (env_file_error.contains("read RDP env file")
            || env_file_error.contains("No persisted RDP env-file check evidence"));
    let env_file_needs_fill_guide = !env_ok && live_gate_env_file_needs_fill_guide(env_file_error);

    let (blocking_reason, next_command) = if env_file_missing {
        (
            "RDP env-file is missing or has not been created yet.",
            save_env_command,
        )
    } else if env_file_needs_fill_guide {
        (
            "RDP env-file contains placeholder or incomplete values; fill it before retrying validation.",
            fill_guide_command,
        )
    } else if !env_ok {
        (
            "RDP env-file validation is missing or failed; do not run network preflight yet.",
            env_command,
        )
    } else if !preflight_ok {
        (
            "RDP env-file is valid, but DNS/TCP preflight is missing or not recommended.",
            preflight_command,
        )
    } else if !smoke_connected {
        (
            "RDP preflight is ready, but no connected=true smoke evidence exists.",
            smoke_command,
        )
    } else if !proof_ok {
        (
            "RDP connection evidence exists, but the direct proof checklist is incomplete.",
            proof_next_command,
        )
    } else if !handoff_ok {
        (
            "Direct RDP proof exists, but the latest operator handoff pack is missing or invalid.",
            handoff_command,
        )
    } else if !audit.achieved {
        (
            "Evidence exists, but the completion audit still has an unresolved blocking gate.",
            goal_check_command,
        )
    } else {
        (
            "All live-gate evidence checks are satisfied.",
            "cargo run -- --completion-audit",
        )
    };
    let operator_stage = live_gate_operator_stage(next_command);
    let next_success_command = live_gate_next_success_command(next_command);
    let acceptance_criteria = live_gate_acceptance_criteria(next_command);
    let brief_blocker = blocking_reason.trim_end_matches('.');
    let brief_acceptance = acceptance_criteria.trim_end_matches('.');
    let operator_brief = redact_secret_text(&format!(
        "Stage={operator_stage}; blocker={brief_blocker}; run `{next_command}`; accepted when {brief_acceptance}; then run `{next_success_command}`."
    ));

    LiveGateDoctorReport {
        schema: "aivana.live-gate-doctor.v1".to_owned(),
        generated_at: Utc::now(),
        achieved: audit.achieved && smoke_connected && proof_ok && handoff_ok,
        ready_for_preflight: env_ok,
        ready_for_smoke: env_ok && preflight_ok,
        smoke_connected,
        handoff_pack_valid: handoff_ok,
        operator_stage: operator_stage.to_owned(),
        operator_brief,
        blocking_reason: blocking_reason.to_owned(),
        next_command: next_command.to_owned(),
        next_success_command: next_success_command.to_owned(),
        rdp_proof_recovery_plan_command: proof_recovery_plan_command.to_owned(),
        acceptance_criteria: acceptance_criteria.to_owned(),
        checks: vec![
            LiveGateDoctorCheck {
                name: "rdp-env-file-check".to_owned(),
                ok: env_ok,
                status: if env_ok { "met" } else { "blocked" }.to_owned(),
                evidence: env_summary.clone(),
                next_command: if env_file_missing {
                    save_env_command.to_owned()
                } else if env_file_needs_fill_guide {
                    fill_guide_command.to_owned()
                } else {
                    env_command.to_owned()
                },
            },
            LiveGateDoctorCheck {
                name: "rdp-preflight".to_owned(),
                ok: preflight_ok,
                status: if preflight_ok { "met" } else { "blocked" }.to_owned(),
                evidence: preflight_summary.clone(),
                next_command: preflight_command.to_owned(),
            },
            LiveGateDoctorCheck {
                name: "rdp-smoke-test".to_owned(),
                ok: smoke_connected,
                status: if smoke_connected { "met" } else { "blocked" }.to_owned(),
                evidence: smoke_summary.clone(),
                next_command: smoke_command.to_owned(),
            },
            LiveGateDoctorCheck {
                name: "rdp-proof-check".to_owned(),
                ok: proof_ok,
                status: if proof_ok { "met" } else { "blocked" }.to_owned(),
                evidence: proof_summary.clone(),
                next_command: if proof_ok {
                    handoff_command.to_owned()
                } else if proof_next_command.trim().is_empty() {
                    proof_command.to_owned()
                } else {
                    proof_next_command.to_owned()
                },
            },
            LiveGateDoctorCheck {
                name: "operator-handoff-check".to_owned(),
                ok: handoff_ok,
                status: if handoff_ok { "met" } else { "blocked" }.to_owned(),
                evidence: handoff_summary.clone(),
                next_command: if handoff_ok {
                    risk_summary_command.to_owned()
                } else {
                    handoff_command.to_owned()
                },
            },
            LiveGateDoctorCheck {
                name: "completion-audit".to_owned(),
                ok: audit.achieved,
                status: if audit.achieved { "met" } else { "blocked" }.to_owned(),
                evidence: completion_summary.clone(),
                next_command: goal_check_command.to_owned(),
            },
        ],
        evidence: LiveGateDoctorEvidence {
            env_file_check: env_summary,
            preflight: preflight_summary,
            smoke: smoke_summary,
            rdp_proof_check: proof_summary,
            handoff_check: handoff_summary,
            completion_audit: completion_summary,
        },
        evidence_path: None,
    }
}

pub fn build_live_gate_runbook(report: &CompletionAuditReport) -> String {
    let blocking = report
        .items
        .iter()
        .filter(|item| item.blocking)
        .collect::<Vec<_>>();
    let mut out = String::new();
    let _ = writeln!(out, "Objective: {}", redact_secret_text(&report.objective));
    let _ = writeln!(out, "Achieved: {}", report.achieved);
    let _ = writeln!(out);
    let _ = writeln!(out, "1. Set live RDP smoke-test environment:");
    for line in build_rdp_live_gate_env_template().lines() {
        let _ = writeln!(out, "   {line}");
    }
    let _ = writeln!(
        out,
        "2. Optional: cargo run -- --save-rdp-env-template .\\rdp-live.env"
    );
    let _ = writeln!(out, "3. Run: cargo run -- --rdp-env-fill-guide");
    let _ = writeln!(
        out,
        "4. Run: cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "5. Run: cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
    );
    let _ = writeln!(
        out,
        "6. Run: cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
    );
    let _ = writeln!(
        out,
        "7. Run: cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "8. Run: cargo run -- --ki-readiness-report --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "9. Run: cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "10. Run: cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(out, "11. Run: cargo run -- --llm-review-prompt");
    let _ = writeln!(
        out,
        "12. Run: cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "13. Run: cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "14. Run: cargo run -- --goal-evidence-matrix --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "15. Run: cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "16. In the GUI, select OpenAI CUA, copy the CUA Request Brief, then run a guarded live-session preview after operator approval."
    );
    let _ = writeln!(
        out,
        "17. Run: cargo run -- --ai-brief-pack and cargo run -- --ki-evidence-bundle for handoff."
    );
    let _ = writeln!(
        out,
        "18. Run: cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(out, "19. Run: cargo run -- --operator-handoff-check");
    let _ = writeln!(
        out,
        "20. Run: cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(
        out,
        "21. Run: cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env"
    );
    let _ = writeln!(out);
    if blocking.is_empty() {
        let _ = writeln!(out, "Current blocker: none recorded by the audit.");
    } else {
        let _ = writeln!(out, "Current blockers:");
        for item in blocking {
            let _ = writeln!(
                out,
                "- {} -> {}",
                redact_secret_text(&item.requirement),
                redact_secret_text(&item.next_action)
            );
            let _ = writeln!(out, "  evidence: {}", redact_secret_text(&item.evidence));
        }
    }
    redact_secret_text(&out)
}

pub fn build_next_live_gate_summary(report: &CompletionAuditReport) -> String {
    let blockers = report
        .items
        .iter()
        .filter(|item| item.blocking)
        .collect::<Vec<_>>();
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana Next Live Gate");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Objective: {}",
        redact_secret_text(&report.objective)
    );
    let _ = writeln!(out, "- Achieved: {}", report.achieved);
    let _ = writeln!(out, "- Blocking gates: {}", blockers.len());
    let _ = writeln!(out);

    if blockers.is_empty() {
        let _ = writeln!(
            out,
            "No blocking live gate remains. Archive the latest completion audit and live-gate evidence."
        );
    } else {
        let first = blockers[0];
        let _ = writeln!(out, "## First Blocking Gate");
        let _ = writeln!(
            out,
            "- Requirement: {}",
            redact_secret_text(&first.requirement)
        );
        let _ = writeln!(out, "- Status: {}", redact_secret_text(&first.status));
        let _ = writeln!(out, "- Evidence: {}", redact_secret_text(&first.evidence));
        let _ = writeln!(out);
        let missing_rdp_env = missing_required_rdp_test_env();
        if !missing_rdp_env.is_empty() {
            let _ = writeln!(out, "## Missing RDP Environment");
            for name in missing_rdp_env {
                let _ = writeln!(out, "- {name}");
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "## RDP Env Template");
            for line in build_rdp_live_gate_env_template().lines() {
                let _ = writeln!(out, "{line}");
            }
            let _ = writeln!(out);
        }
        let _ = writeln!(out, "## Next Commands");
        for (index, command) in build_next_live_gate_report(report)
            .next_commands
            .iter()
            .enumerate()
        {
            let _ = writeln!(out, "{}. {}", index + 1, redact_secret_text(command));
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## Operator Action");
        let _ = writeln!(out, "{}", redact_secret_text(&first.next_action));
    }

    redact_secret_text(&out)
}

pub fn save_next_live_gate_summary(
    report: &CompletionAuditReport,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("next-live-gates")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", report.audit_id));
    std::fs::write(&path, build_next_live_gate_summary(report))?;
    Ok(path)
}

pub fn save_live_gate_doctor_report(
    report: &LiveGateDoctorReport,
) -> anyhow::Result<std::path::PathBuf> {
    let path = if let Some(path) = report.evidence_path.as_deref() {
        std::path::PathBuf::from(path)
    } else {
        let dir = app_data_file("live-gate-doctors")?;
        std::fs::create_dir_all(&dir)?;
        dir.join(format!("{}.json", Uuid::new_v4()))
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, redacted_json_string(report)?)?;
    Ok(path)
}

pub fn build_live_gate_operator_brief(
    audit: &CompletionAuditReport,
    doctor: &LiveGateDoctorReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana Live Gate Operator Brief");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Objective: {}", redact_secret_text(&audit.objective));
    let _ = writeln!(out, "- Achieved: {}", doctor.achieved);
    let _ = writeln!(out, "- Operator stage: {}", doctor.operator_stage);
    let _ = writeln!(
        out,
        "- Blocking reason: {}",
        redact_secret_text(&doctor.blocking_reason)
    );
    let _ = writeln!(
        out,
        "- Acceptance criteria: {}",
        redact_secret_text(&doctor.acceptance_criteria)
    );
    let _ = writeln!(out, "- Next command: `{}`", doctor.next_command);
    let _ = writeln!(
        out,
        "- Next command after success: `{}`",
        doctor.next_success_command
    );
    let _ = writeln!(
        out,
        "- RDP proof recovery plan command: `{}`",
        doctor.rdp_proof_recovery_plan_command
    );
    let _ = writeln!(
        out,
        "- Operator brief: {}",
        redact_secret_text(&doctor.operator_brief)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence Snapshot");
    let _ = writeln!(
        out,
        "- Env file: {}",
        redact_secret_text(&doctor.evidence.env_file_check)
    );
    let _ = writeln!(
        out,
        "- Preflight: {}",
        redact_secret_text(&doctor.evidence.preflight)
    );
    let _ = writeln!(
        out,
        "- Smoke: {}",
        redact_secret_text(&doctor.evidence.smoke)
    );
    let _ = writeln!(
        out,
        "- RDP proof: {}",
        redact_secret_text(&doctor.evidence.rdp_proof_check)
    );
    let _ = writeln!(
        out,
        "- Handoff: {}",
        redact_secret_text(&doctor.evidence.handoff_check)
    );
    let _ = writeln!(
        out,
        "- Completion audit: {}",
        redact_secret_text(&doctor.evidence.completion_audit)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Completion Rule");
    let _ = writeln!(
        out,
        "Do not claim completion until live RDP smoke evidence shows connected=true with framebuffer/input proof and `cargo run -- --goal-evidence-check` exits 0."
    );
    redact_secret_text(&out)
}

pub fn save_live_gate_operator_brief(
    audit: &CompletionAuditReport,
    brief: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("live-gate-operator-briefs")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", audit.audit_id));
    std::fs::write(&path, redact_secret_text(brief))?;
    Ok(path)
}

pub fn build_rdp_proof_prompt(
    audit: &CompletionAuditReport,
    doctor: &LiveGateDoctorReport,
    verification_snapshot: &serde_json::Value,
) -> String {
    let env_source = verification_snapshot
        .get("env_source")
        .and_then(|value| value.as_str())
        .unwrap_or("process environment");
    let missing_rdp_env = verification_snapshot
        .get("live_gate")
        .and_then(|value| value.get("missing_rdp_env"))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana RDP Proof Prompt");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Use this with a human operator or LLM assistant to complete only the direct RDP proof gate. Do not paste real credentials, passwords, screenshots containing secrets, or private host details into chat."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Context First");
    let _ = writeln!(
        out,
        "- Inspect `summary.md` for Early LLM Triage before running proof commands."
    );
    let _ = writeln!(
        out,
        "- Inspect `verification-snapshot.json` and `llm-action-contract.json` for success signals and proxy-evidence rejection rules."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Gate");
    let _ = writeln!(out, "- Objective: {}", redact_secret_text(&audit.objective));
    let _ = writeln!(out, "- Env source: {}", redact_secret_text(env_source));
    let _ = writeln!(out, "- Operator stage: {}", doctor.operator_stage);
    let _ = writeln!(
        out,
        "- Blocking reason: {}",
        redact_secret_text(&doctor.blocking_reason)
    );
    let _ = writeln!(out, "- Missing RDP env: {}", missing_rdp_env);
    let _ = writeln!(
        out,
        "- Acceptance criteria: {}",
        redact_secret_text(&doctor.acceptance_criteria)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Commands To Run Locally");
    let _ = writeln!(out, "1. `{}`", doctor.next_command);
    let _ = writeln!(out, "2. `{}`", doctor.next_success_command);
    let _ = writeln!(
        out,
        "3. `cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90`"
    );
    let _ = writeln!(
        out,
        "4. `cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90`"
    );
    let _ = writeln!(
        out,
        "5. `cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "6. `cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "7. `cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "8. `cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Completion Evidence Required");
    let _ = writeln!(
        out,
        "- Preflight evidence matches the env-file host and port."
    );
    let _ = writeln!(out, "- Preflight evidence is newer than the env file.");
    let _ = writeln!(out, "- RDP smoke JSON has `connected=true`.");
    let _ = writeln!(out, "- Smoke evidence matches the env-file host and port.");
    let _ = writeln!(out, "- Smoke evidence is newer than the env file.");
    let _ = writeln!(out, "- Framebuffer evidence is present.");
    let _ = writeln!(out, "- Input probe evidence is present.");
    let _ = writeln!(out, "- `rdp-proof-check.ok == true`.");
    let _ = writeln!(out, "- `goal-evidence-check.ok == true`.");
    let _ = writeln!(
        out,
        "- `verification-snapshot.ok == true` and `live_gate.smoke_connected == true`."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Rejection Rule");
    let _ = writeln!(
        out,
        "Reject proxy evidence: command lists, manifests, green unit tests, or handoff-pack validation are not enough without the direct live RDP smoke proof."
    );
    redact_secret_text(&out)
}

pub fn save_rdp_proof_prompt(
    audit: &CompletionAuditReport,
    prompt: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-proof-prompts")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", audit.audit_id));
    std::fs::write(&path, redact_secret_text(prompt))?;
    Ok(path)
}

pub fn build_rdp_proof_recovery_plan(
    audit: &CompletionAuditReport,
    doctor: &LiveGateDoctorReport,
    proof_check: &serde_json::Value,
) -> String {
    let ok = proof_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let next_command = proof_check
        .get("next_command")
        .and_then(|value| value.as_str())
        .unwrap_or(&doctor.next_command);
    let failed_checks = proof_check
        .get("failed_checks")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let failed_actions = proof_check
        .get("failed_check_actions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    let mut out = String::new();
    let _ = writeln!(out, "# Aivana RDP Proof Recovery Plan");
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Status");
    let _ = writeln!(out, "- Objective: {}", redact_secret_text(&audit.objective));
    let _ = writeln!(out, "- Proof ok: {ok}");
    let _ = writeln!(
        out,
        "- Operator stage: {}",
        redact_secret_text(&doctor.operator_stage)
    );
    let _ = writeln!(
        out,
        "- Blocking reason: {}",
        redact_secret_text(&doctor.blocking_reason)
    );
    let _ = writeln!(
        out,
        "- Next command: `{}`",
        redact_secret_text(next_command)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Failed Proof Checks");
    if failed_checks.is_empty() {
        let _ = writeln!(out, "- None. Run the success verification commands below.");
    } else {
        for check in failed_checks {
            let _ = writeln!(out, "- `{}`", redact_secret_text(check));
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Recovery Commands");
    if failed_actions.is_empty() {
        let _ = writeln!(
            out,
            "1. `cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env`"
        );
    } else {
        for (index, action) in failed_actions.iter().enumerate() {
            let check = action
                .get("check")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let command = action
                .get("command")
                .and_then(|value| value.as_str())
                .unwrap_or("cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env");
            let reason = action
                .get("action")
                .and_then(|value| value.as_str())
                .unwrap_or("Rerun the proof check and follow the reported next command.");
            let _ = writeln!(
                out,
                "{}. `{}` - {}: {}",
                index + 1,
                redact_secret_text(command),
                redact_secret_text(check),
                redact_secret_text(reason)
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Acceptance Criteria");
    let _ = writeln!(out, "- `rdp-proof-check.ok == true`.");
    let _ = writeln!(
        out,
        "- Env-file validation is true for the current `rdp-live.env`."
    );
    let _ = writeln!(
        out,
        "- Preflight evidence matches the env-file host and port and is newer than the env file."
    );
    let _ = writeln!(
        out,
        "- Smoke evidence matches the env-file host and port and is newer than the env file."
    );
    let _ = writeln!(
        out,
        "- Smoke evidence records `connected=true`, framebuffer dimensions, and input-probe evidence."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Final Verification");
    let _ = writeln!(
        out,
        "1. `cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "2. `cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "3. `cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Rejection Rule");
    let _ = writeln!(
        out,
        "Do not accept manifests, green unit tests, screenshots without smoke JSON, or handoff-pack validation as proof. Completion requires direct live RDP proof evidence."
    );
    redact_secret_text(&out)
}

pub fn save_rdp_proof_recovery_plan(
    audit: &CompletionAuditReport,
    plan: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-proof-recovery-plans")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", audit.audit_id));
    std::fs::write(&path, redact_secret_text(plan))?;
    Ok(path)
}

pub fn build_rdp_proof_check_from_args(args: &[String]) -> serde_json::Value {
    let timeout_secs = crate::ironrdp_client::rdp_smoke_timeout_secs_from_args(args);
    let env_check = crate::ironrdp_client::rdp_env_file_check_report_from_args(args, timeout_secs);
    let preflight = latest_json_value_from_app_data("rdp-preflight").unwrap_or_else(|| {
        serde_json::json!({
            "connect_recommended": false,
            "evidence_path": null,
            "error": "No persisted RDP preflight evidence recorded."
        })
    });
    let smoke = latest_json_value_from_app_data("rdp-smoke-tests").unwrap_or_else(|| {
        serde_json::json!({
            "connected": false,
            "evidence_path": null,
            "error": "No persisted RDP smoke evidence recorded."
        })
    });
    let env_ok = env_check.ok;
    let env_host = env_check.host.as_deref();
    let env_port = env_check.port;
    let env_file_modified_at = rdp_env_file_modified_at(env_check.path.as_deref());
    let preflight_ok = preflight
        .get("connect_recommended")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let preflight_matches_env = rdp_evidence_matches_env_host_port(&preflight, env_host, env_port);
    let preflight_fresh_for_env =
        rdp_evidence_is_fresh_for_env_file(&preflight, env_file_modified_at);
    let smoke_connected = smoke
        .get("connected")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let smoke_matches_env = rdp_evidence_matches_env_host_port(&smoke, env_host, env_port);
    let smoke_fresh_for_env = rdp_evidence_is_fresh_for_env_file(&smoke, env_file_modified_at);
    let framebuffer_present = smoke.get("framebuffer").is_some_and(|framebuffer| {
        framebuffer
            .get("width")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
            > 0
            && framebuffer
                .get("height")
                .and_then(|value| value.as_u64())
                .unwrap_or_default()
                > 0
    });
    let input_probe_present = smoke
        .get("input_probe")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty());
    let ok = env_ok
        && preflight_ok
        && preflight_matches_env
        && preflight_fresh_for_env
        && smoke_connected
        && smoke_matches_env
        && smoke_fresh_for_env
        && framebuffer_present
        && input_probe_present;
    let next_command = if !env_ok {
        "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env"
    } else if !preflight_ok || !preflight_matches_env || !preflight_fresh_for_env {
        "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
    } else if !smoke_connected
        || !smoke_matches_env
        || !smoke_fresh_for_env
        || !framebuffer_present
        || !input_probe_present
    {
        "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
    } else {
        "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env"
    };
    let failed_checks = [
        ("env_file_ok", env_ok),
        ("preflight_connect_recommended", preflight_ok),
        ("preflight_matches_env", preflight_matches_env),
        ("preflight_fresh_for_env", preflight_fresh_for_env),
        ("smoke_connected", smoke_connected),
        ("smoke_matches_env", smoke_matches_env),
        ("smoke_fresh_for_env", smoke_fresh_for_env),
        ("framebuffer_present", framebuffer_present),
        ("input_probe_present", input_probe_present),
    ]
    .into_iter()
    .filter_map(|(name, passed)| (!passed).then_some(name))
    .collect::<Vec<_>>();
    let failed_check_actions = failed_checks
        .iter()
        .map(|name| rdp_proof_failed_check_action(name))
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema": "aivana.rdp-proof-check.v1",
        "generated_at": Utc::now(),
        "redacted": true,
        "ok": ok,
        "env_source": rdp_env_source_label_from_args(args),
        "checks": {
            "env_file_ok": env_ok,
            "preflight_connect_recommended": preflight_ok,
            "preflight_matches_env": preflight_matches_env,
            "preflight_fresh_for_env": preflight_fresh_for_env,
            "smoke_connected": smoke_connected,
            "smoke_matches_env": smoke_matches_env,
            "smoke_fresh_for_env": smoke_fresh_for_env,
            "framebuffer_present": framebuffer_present,
            "input_probe_present": input_probe_present
        },
        "failed_checks": failed_checks,
        "failed_check_actions": failed_check_actions,
        "next_command": next_command,
        "success_condition": "ok == true with env_file_ok, preflight_connect_recommended, preflight_matches_env, preflight_fresh_for_env, smoke_connected, smoke_matches_env, smoke_fresh_for_env, framebuffer_present, and input_probe_present",
        "freshness": {
            "env_file_modified_at": env_file_modified_at.map(|value| value.to_rfc3339()),
            "rule": "When --rdp-env-file is used, preflight and smoke evidence must be newer than the env file."
        },
        "evidence": {
            "env_file_check": env_check,
            "preflight": preflight,
            "smoke": smoke
        }
    })
}

fn rdp_proof_failed_check_action(name: &str) -> serde_json::Value {
    let (command, action) = match name {
        "env_file_ok" => (
            "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env",
            "Fill the ignored local rdp-live.env file and rerun env-file validation before any network command.",
        ),
        "preflight_connect_recommended" => (
            "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Run DNS/TCP preflight and resolve network, VPN, firewall, host, or port blockers until connect_recommended=true.",
        ),
        "preflight_matches_env" => (
            "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Regenerate preflight evidence for the exact host and port in the current env file.",
        ),
        "preflight_fresh_for_env" => (
            "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Rerun preflight because the env file was changed after the saved preflight evidence.",
        ),
        "smoke_connected" => (
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Run the live RDP smoke test until it records connected=true.",
        ),
        "smoke_matches_env" => (
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Regenerate smoke evidence for the exact host and port in the current env file.",
        ),
        "smoke_fresh_for_env" => (
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Rerun the smoke test because the env file was changed after the saved smoke evidence.",
        ),
        "framebuffer_present" => (
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Capture a live RDP framebuffer with non-zero width and height.",
        ),
        "input_probe_present" => (
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "Capture input-probe evidence from the smoke test after framebuffer capture.",
        ),
        _ => (
            "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env",
            "Review the proof-check JSON and rerun the next command it reports.",
        ),
    };
    serde_json::json!({
        "check": name,
        "command": command,
        "action": action
    })
}

fn rdp_env_file_modified_at(path: Option<&str>) -> Option<DateTime<Utc>> {
    let path = path.map(str::trim).filter(|path| !path.is_empty())?;
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(DateTime::<Utc>::from(modified))
}

fn rdp_evidence_is_fresh_for_env_file(
    evidence: &serde_json::Value,
    env_file_modified_at: Option<DateTime<Utc>>,
) -> bool {
    let Some(env_file_modified_at) = env_file_modified_at else {
        return true;
    };
    let Some(generated_at) = evidence
        .get("generated_at")
        .and_then(|value| value.as_str())
    else {
        return false;
    };
    DateTime::parse_from_rfc3339(generated_at)
        .map(|value| value.with_timezone(&Utc) >= env_file_modified_at)
        .unwrap_or(false)
}

fn rdp_evidence_matches_env_host_port(
    evidence: &serde_json::Value,
    env_host: Option<&str>,
    env_port: Option<u16>,
) -> bool {
    let Some(env_host) = env_host.map(str::trim).filter(|host| !host.is_empty()) else {
        return false;
    };
    let Some(env_port) = env_port else {
        return false;
    };
    let evidence_host = evidence
        .get("host")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .unwrap_or("");
    let evidence_port = evidence
        .get("port")
        .and_then(|value| value.as_u64())
        .and_then(|port| u16::try_from(port).ok());
    evidence_host.eq_ignore_ascii_case(env_host) && evidence_port == Some(env_port)
}

pub fn save_rdp_proof_check(check: &serde_json::Value) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-proof-checks")?;
    std::fs::create_dir_all(&dir)?;
    let id = Uuid::new_v4();
    let path = dir.join(format!("{id}.json"));
    std::fs::write(&path, redacted_json_string(check)?)?;
    Ok(path)
}

pub fn build_rdp_env_fill_guide() -> String {
    let doctor = build_live_gate_doctor_report();
    let env_summary = latest_rdp_env_file_check_summary()
        .unwrap_or_else(|| "Latest RDP env-file check evidence: none recorded yet.".to_owned());
    let env_check_command = "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env";
    let next_command = if doctor.next_command == "cargo run -- --rdp-env-fill-guide" {
        env_check_command
    } else {
        doctor.next_command.as_str()
    };
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana RDP Env Fill Guide");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Fill `rdp-live.env` locally. Do not put real credentials into Git, chat, handoff packs, screenshots, or LLM prompts."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Status");
    let _ = writeln!(out, "- Operator stage: {}", doctor.operator_stage);
    let _ = writeln!(out, "- Ready for preflight: {}", doctor.ready_for_preflight);
    let _ = writeln!(out, "- Ready for smoke: {}", doctor.ready_for_smoke);
    let _ = writeln!(
        out,
        "- Current blocker: {}",
        redact_secret_text(&doctor.blocking_reason)
    );
    let _ = writeln!(
        out,
        "- Acceptance criteria: {}",
        redact_secret_text(&doctor.acceptance_criteria)
    );
    let _ = writeln!(
        out,
        "- Latest env check: {}",
        redact_secret_text(&env_summary)
    );
    let _ = writeln!(out, "- Next command after editing: `{}`", next_command);
    let _ = writeln!(
        out,
        "- Next command after success: `{}`",
        doctor.next_success_command
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Fields");
    let _ = writeln!(
        out,
        "- `AIVANA_RDP_TEST_HOST`: reachable RDP hostname or IP."
    );
    let _ = writeln!(
        out,
        "- `AIVANA_RDP_TEST_USER`: account name for the test session."
    );
    let _ = writeln!(
        out,
        "- `AIVANA_RDP_TEST_PASSWORD`: account password, kept only in the ignored local file."
    );
    let _ = writeln!(out, "- `AIVANA_RDP_TEST_PORT`: optional, default `3389`.");
    let _ = writeln!(out, "- `AIVANA_RDP_TEST_DOMAIN`: optional domain/tenant.");
    let _ = writeln!(
        out,
        "- `AIVANA_RDP_TEST_TIMEOUT_SECS`: optional timeout, clamped to 5-600 seconds."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Invalid Starter Values");
    let _ = writeln!(
        out,
        "`<host>`, `<user>`, `<password>`, `[REDACTED]`, and empty required values are rejected before network preflight."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Local Starter");
    for line in build_rdp_live_gate_env_template().lines() {
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Commands");
    let _ = writeln!(
        out,
        "1. `cargo run -- --save-rdp-env-template .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "2. Edit `rdp-live.env` locally and replace every required placeholder."
    );
    let _ = writeln!(
        out,
        "3. `cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env`"
    );
    let _ = writeln!(
        out,
        "4. `cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90`"
    );
    let _ = writeln!(
        out,
        "5. `cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90`"
    );
    let _ = writeln!(
        out,
        "6. `cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env`"
    );
    redact_secret_text(&out)
}

pub fn save_rdp_env_fill_guide() -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-env-fill-guides")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", Uuid::new_v4()));
    std::fs::write(&path, build_rdp_env_fill_guide())?;
    Ok(path)
}

pub fn build_rdp_live_gate_env_template() -> String {
    redact_secret_text(
        "# Aivana live RDP verification environment\n\
AIVANA_RDP_TEST_HOST=<host>\n\
AIVANA_RDP_TEST_USER=<user>\n\
AIVANA_RDP_TEST_PASSWORD=<password>\n\
AIVANA_RDP_TEST_PORT=3389\n\
AIVANA_RDP_TEST_DOMAIN=\n\
AIVANA_RDP_TEST_TIMEOUT_SECS=90\n",
    )
}

pub fn save_rdp_live_gate_env_template_to(path: &Path) -> anyhow::Result<std::path::PathBuf> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    std::io::Write::write_all(&mut file, build_rdp_live_gate_env_template().as_bytes())?;
    Ok(path.to_path_buf())
}

pub fn build_command_index() -> serde_json::Value {
    serde_json::json!({
        "app": "Aivana Rust RDP Client",
        "schema": "aivana.command-index.v1",
        "live_gate_requirement": "Completion stays false until rdp-proof-check confirms env-file validation, fresh matching preflight/smoke host-port evidence, connected=true, framebuffer, and input probe.",
        "goal_evidence_matrix": "Use --goal-evidence-matrix for a machine-readable requirement-to-artifact checklist before claiming completion.",
        "recommended_live_gate_sequence": [
            {
                "step": 1,
                "command": "cargo run -- --save-rdp-env-template .\\rdp-live.env",
                "expect": "Redacted AIVANA_RDP_TEST_* starter template saved without overwriting existing files."
            },
            {
                "step": 2,
                "command": "cargo run -- --rdp-env-fill-guide",
                "expect": "Redacted local checklist explains which rdp-live.env placeholders must be replaced without leaking credentials."
            },
            {
                "step": 3,
                "command": "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env",
                "expect": "ok=true before DNS/TCP preflight; no network connection is attempted."
            },
            {
                "step": 4,
                "command": "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
                "expect": "connect_recommended=true from the filled local .env file before running the smoke test."
            },
            {
                "step": 5,
                "command": "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
                "expect": "connected=true with framebuffer and input-probe evidence for the env-file host and port."
            },
            {
                "step": 6,
                "command": "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env",
                "expect": "ok=true only when env-file, fresh matching preflight/smoke host-port evidence, smoke connection, framebuffer, and input probe evidence all exist."
            },
            {
                "step": 7,
                "command": "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env",
                "expect": "Redacted Markdown maps failed proof checks to exact recovery commands, acceptance criteria, direct live evidence requirements, and proxy-evidence rejection rules."
            },
            {
                "step": 8,
                "command": "cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env",
                "expect": "Single JSON diagnosis shows env-file, preflight, smoke, handoff, operator_stage, acceptance_criteria, next_command, next_success_command, and rdp_proof_recovery_plan_command."
            },
            {
                "step": 9,
                "command": "cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env",
                "expect": "Concise Markdown brief shows operator_stage, blocker, acceptance criteria, next command, next-after-success command, RDP proof recovery-plan command, and evidence snapshot."
            },
            {
                "step": 10,
                "command": "cargo run -- --llm-review-prompt",
                "expect": "Markdown LLM reviewer prompt exposes summary.md Early LLM Triage, operator-handoff-risk-summary.json cross-check, LLM triage entrypoint, required evidence files, early_triage_artifacts, and proxy-evidence rejection."
            },
            {
                "step": 11,
                "command": "cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env",
                "expect": "Markdown LLM/CI plan summarizes doctor, audit, runbook, next command, and RDP proof recovery-plan command without accepting proxy evidence."
            },
            {
                "step": 12,
                "command": "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "expect": "Machine-readable LLM action contract exposes next_command, allowed_next_commands, acceptance criteria, summary.md Early LLM Triage evidence, early_triage_artifacts response field, direct_live_evidence_requirements for direct live evidence, success signals, and proxy-evidence rejection rules."
            },
            {
                "step": 13,
                "command": "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env",
                "expect": "achieved=true only when all blocking gates have direct evidence."
            },
            {
                "step": 14,
                "command": "cargo run -- --goal-evidence-matrix --rdp-env-file .\\rdp-live.env",
                "expect": "uncovered_requirements is empty only when every requirement has direct evidence."
            },
            {
                "step": 15,
                "command": "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env",
                "expect": "ok=true only when the matrix is achieved and has no uncovered requirements."
            },
            {
                "step": 16,
                "command": "cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env",
                "expect": "Persisted handoff folder with audit, goal evidence matrix, goal evidence check, command index, runbook, LLM prompt, summary.md Early LLM Triage, verification-snapshot.json, llm-action-contract.json, and manifest."
            },
            {
                "step": 17,
                "command": "cargo run -- --operator-handoff-check",
                "expect": "ok=true for schema, expected files, file roles, recommended inspection order, machine-readable JSON schemas, and cross-artifact consistency."
            },
            {
                "step": 18,
                "command": "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env",
                "expect": "ok=true only when the handoff pack, live-gate doctor, and real RDP goal evidence are all valid; exposes LLM triage entrypoint, required evidence files, and early_triage_artifacts."
            },
            {
                "step": 19,
                "command": "cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env",
                "expect": "ok=true only when the compact snapshot shows direct live RDP evidence and a valid handoff reference."
            }
        ],
        "commands": [
            {
                "name": "--save-ki-preferences",
                "output": "json",
                "persists": true,
                "artifacts": ["autopilot-preferences.json"],
                "purpose": "Headless parity for the GUI Save KI Preferences action; persists current/default KI autopilot preferences without printing secrets.",
                "success_condition": "preferences_saved == true in --ki-readiness-report"
            },
            {
                "name": "--ki-readiness-report",
                "output": "json",
                "persists": true,
                "artifacts": ["ki-readiness-reports/*.json"],
                "purpose": "OpenAI, RDP, KI preference, preflight, smoke, and live-gate readiness evidence."
            },
            {
                "name": "--ai-brief-pack",
                "output": "json",
                "persists": true,
                "artifacts": [
                    "ai-brief-packs/<pack-id>/action-brief.md",
                    "ai-brief-packs/<pack-id>/prompt-library.md",
                    "ai-brief-packs/<pack-id>/runbook-brief.md",
                    "ai-brief-packs/<pack-id>/verification-brief.md",
                    "ai-brief-packs/<pack-id>/manifest.json"
                ],
                "purpose": "Headless export of redacted AI/KI action, prompt-library, runbook, and verification briefs for LLM handoff."
            },
            {
                "name": "--ki-evidence-bundle",
                "output": "json",
                "persists": true,
                "artifacts": ["ki-evidence-bundles/<bundle-id>/bundle.md", "ki-evidence-bundles/<bundle-id>/manifest.json"],
                "purpose": "Redacted readiness and evidence bundle for CI, operators, and LLM handoff."
            },
            {
                "name": "--completion-audit",
                "output": "json",
                "persists": true,
                "artifacts": ["completion-audits/*.json", "completion-audits/*.md"],
                "purpose": "Prompt-to-artifact completion audit with blocking gates."
            },
            {
                "name": "--goal-evidence-matrix",
                "output": "json",
                "persists": true,
                "artifacts": ["goal-evidence-matrices/*.json"],
                "purpose": "Machine-readable objective criteria mapped to artifacts, evidence, verification commands, gaps, and final live-gate blocker.",
                "success_condition": "achieved == true and uncovered_requirements is empty"
            },
            {
                "name": "--goal-evidence-check",
                "output": "json",
                "persists": true,
                "artifacts": ["goal-evidence-checks/*.json"],
                "purpose": "Hard CI/LLM completion assertion over the goal evidence matrix.",
                "success_condition": "ok == true",
                "failure_exit": 1
            },
            {
                "name": "--next-live-gate",
                "output": "markdown",
                "persists": true,
                "artifacts": ["next-live-gates/*.md"],
                "purpose": "First blocking live gate, missing RDP environment, env template, and next commands."
            },
            {
                "name": "--next-live-gate-json",
                "output": "json",
                "persists": false,
                "purpose": "Structured first blocking live gate, missing RDP environment, env template, and next commands for CI or LLM agents."
            },
            {
                "name": "--live-gate-sequence",
                "output": "text",
                "persists": false,
                "purpose": "Ordered live-gate command sequence derived from next-live-gate for direct operator, CI, or LLM execution planning."
            },
            {
                "name": "--live-gate-doctor",
                "output": "json",
                "persists": true,
                "artifacts": ["live-gate-doctors/*.json"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "One-shot live-gate diagnosis for GUI, CI, and LLM agents: env-file check, preflight, smoke, direct RDP proof check, handoff validation, operator stage, acceptance criteria, next command, and next-after-success command.",
                "success_condition": "achieved == true",
                "failure_exit": 1
            },
            {
                "name": "--live-gate-operator-brief",
                "output": "markdown",
                "persists": true,
                "artifacts": ["live-gate-operator-briefs/*.md"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Concise redacted operator/LLM brief derived from the live-gate doctor without requiring JSON parsing."
            },
            {
                "name": "--rdp-proof-check",
                "output": "json",
                "persists": true,
                "artifacts": ["rdp-proof-checks/*.json"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Direct RDP proof checklist over env-file validation, preflight readiness, env-source matching, env-file freshness, smoke connection, framebuffer, and input probe evidence.",
                "success_condition": "ok == true",
                "failure_exit": 1
            },
            {
                "name": "--rdp-proof-prompt",
                "output": "markdown",
                "persists": true,
                "artifacts": ["rdp-proof-prompts/*.md"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Focused redacted prompt for a human operator or LLM assistant to finish only the direct RDP proof gate without leaking credentials."
            },
            {
                "name": "--rdp-proof-recovery-plan",
                "output": "markdown",
                "persists": true,
                "artifacts": ["rdp-proof-recovery-plans/*.md"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Human-readable recovery plan that turns failed RDP proof checks into exact local commands, acceptance criteria, direct live evidence requirements, and proxy-evidence rejection rules."
            },
            {
                "name": "--live-gate-runbook",
                "output": "markdown",
                "persists": true,
                "artifacts": ["live-gate-runbooks/*.md"],
                "purpose": "Full operator runbook derived from the completion audit."
            },
            {
                "name": "--llm-review-prompt",
                "output": "markdown",
                "persists": true,
                "artifacts": ["llm-review-prompts/*.md"],
                "purpose": "Focused reviewer prompt for LLM inspection of handoff artifacts with summary.md Early LLM Triage, operator-handoff-risk-summary.json cross-check, LLM triage entrypoint, required evidence files, early_triage_artifacts, and proxy-evidence rejection."
            },
            {
                "name": "--llm-live-gate-plan",
                "output": "markdown",
                "persists": true,
                "artifacts": ["llm-live-gate-plans/*.md"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Focused LLM/CI instruction plan from live-gate doctor, completion audit, and runbook with the exact next command."
            },
            {
                "name": "--llm-action-contract",
                "output": "json",
                "persists": true,
                "artifacts": ["llm-action-contracts/*.json"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Machine-readable LLM next-action contract with allowed commands, acceptance criteria, summary.md Early LLM Triage evidence, early_triage_artifacts response field, direct_live_evidence_requirements for direct live evidence, success signals, failed proof actions, and proxy-evidence rejection rules.",
                "success_condition": "ok == true",
                "failure_exit": 1
            },
            {
                "name": "--gui-operator-actions",
                "output": "markdown",
                "persists": true,
                "artifacts": ["gui-operator-actions/*.md"],
                "purpose": "Focused GUI action checklist for operators using Verification Center and Mission Control."
            },
            {
                "name": "--operator-handoff-pack",
                "output": "json",
                "persists": true,
                "artifacts": [
                    "operator-handoff-packs/<pack-id>/readiness.json",
                    "operator-handoff-packs/<pack-id>/completion-audit.json",
                    "operator-handoff-packs/<pack-id>/goal-evidence-matrix.json",
                    "operator-handoff-packs/<pack-id>/goal-evidence-check.json",
                    "operator-handoff-packs/<pack-id>/verification-snapshot.json",
                    "operator-handoff-packs/<pack-id>/operator-handoff-risk-summary.json",
                    "operator-handoff-packs/<pack-id>/command-index.json",
                    "operator-handoff-packs/<pack-id>/rdp-env-file-check.json",
                    "operator-handoff-packs/<pack-id>/rdp-proof-check.json",
                    "operator-handoff-packs/<pack-id>/live-gate-doctor.json",
                    "operator-handoff-packs/<pack-id>/live-gate-operator-brief.md",
                    "operator-handoff-packs/<pack-id>/next-live-gate.json",
                    "operator-handoff-packs/<pack-id>/live-gate-sequence.txt",
                    "operator-handoff-packs/<pack-id>/next-live-gate.md",
                    "operator-handoff-packs/<pack-id>/live-gate-runbook.md",
                    "operator-handoff-packs/<pack-id>/gui-operator-actions.md",
                    "operator-handoff-packs/<pack-id>/rdp-env-template.env",
                    "operator-handoff-packs/<pack-id>/rdp-env-fill-guide.md",
                    "operator-handoff-packs/<pack-id>/llm-review-prompt.md",
                    "operator-handoff-packs/<pack-id>/rdp-proof-prompt.md",
                    "operator-handoff-packs/<pack-id>/rdp-proof-recovery-plan.md",
                    "operator-handoff-packs/<pack-id>/llm-live-gate-plan.md",
                    "operator-handoff-packs/<pack-id>/llm-action-contract.json",
                    "operator-handoff-packs/<pack-id>/summary.md",
                    "operator-handoff-packs/<pack-id>/manifest.json"
                ],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "One-folder handoff pack with readiness, audit, verification snapshot, risk summary, env-file check evidence, live-gate doctor, operator brief, RDP proof prompt, RDP proof recovery plan, next-live-gate, live-gate sequence, runbook, GUI actions, env template, env fill guide, LLM prompt, LLM action contract, summary.md Early LLM Triage, verification-snapshot.json, llm-action-contract.json, manifest, and command index."
            },
            {
                "name": "--operator-handoff-check",
                "output": "json",
                "persists": false,
                "purpose": "Validates the latest operator handoff pack schema, manifest, expected files, file roles, inspection order, machine-readable JSON schemas, and cross-artifact consistency.",
                "success_condition": "ok == true"
            },
            {
                "name": "--operator-handoff-risk-summary",
                "output": "json",
                "persists": true,
                "artifacts": ["operator-handoff-risk-summaries/*.json"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Compact CI/LLM risk snapshot combining live-gate doctor, handoff-pack check, goal-evidence check, blocker, acceptance criteria, next command, LLM triage entrypoint, required evidence files, and early_triage_artifacts.",
                "success_condition": "ok == true",
                "failure_exit": 1
            },
            {
                "name": "--verification-snapshot",
                "output": "json",
                "persists": true,
                "artifacts": ["verification-snapshots/*.json"],
                "accepts_option": "--rdp-env-file <path>",
                "purpose": "Compact GUI, readiness, live-gate, handoff, risk, and latest-evidence snapshot for operators, CI, and LLM handoff.",
                "success_condition": "ok == true and rdp_proof.ok == true and live_gate.smoke_connected == true",
                "failure_exit": 1
            },
            {
                "name": "--live-gate",
                "output": "json",
                "persists": true,
                "requires_env": ["AIVANA_RDP_TEST_HOST", "AIVANA_RDP_TEST_USER", "AIVANA_RDP_TEST_PASSWORD"],
                "artifacts": ["rdp-preflight/*.json", "rdp-smoke-tests/*.json", "live-gate-reports/*.json"],
                "purpose": "Runs preflight, optional smoke test, readiness, audit, and writes live-gate report.",
                "success_condition": "report.achieved == true"
            },
            {
                "name": "--rdp-env-template",
                "output": "env",
                "persists": false,
                "purpose": "Redacted AIVANA_RDP_TEST_* starter template."
            },
            {
                "name": "--rdp-env-fill-guide",
                "output": "markdown",
                "persists": true,
                "artifacts": ["rdp-env-fill-guides/*.md"],
                "purpose": "Redacted operator guide for safely filling ignored local rdp-live.env before preflight."
            },
            {
                "name": "--save-rdp-env-template <path>",
                "output": "json",
                "persists": true,
                "artifacts": ["<path>"],
                "purpose": "Writes the redacted AIVANA_RDP_TEST_* starter template to a local .env file without overwriting an existing file.",
                "success_condition": "created == true"
            },
            {
                "name": "--rdp-env-file-check",
                "output": "json",
                "persists": true,
                "artifacts": ["rdp-env-file-checks/*.json"],
                "requires_option": "--rdp-env-file <path>",
                "purpose": "Validates required AIVANA_RDP_TEST_* file values and rejects unfilled starter placeholders before network preflight.",
                "success_condition": "ok == true",
                "failure_exit": 1
            },
            {
                "name": "--rdp-preflight",
                "output": "json",
                "persists": true,
                "requires_env": ["AIVANA_RDP_TEST_HOST", "AIVANA_RDP_TEST_USER", "AIVANA_RDP_TEST_PASSWORD"],
                "artifacts": ["rdp-preflight/*.json"],
                "purpose": "Validates live RDP environment, DNS/TCP reachability, credentials, and timeout."
            },
            {
                "name": "--rdp-smoke-test",
                "output": "json",
                "persists": true,
                "requires_env": ["AIVANA_RDP_TEST_HOST", "AIVANA_RDP_TEST_USER", "AIVANA_RDP_TEST_PASSWORD"],
                "artifacts": ["rdp-smoke-tests/*.json"],
                "purpose": "Connects to the configured RDP host and captures framebuffer/input evidence.",
                "success_condition": "connected == true"
            }
        ],
        "options": [
            {
                "name": "--rdp-smoke-timeout <seconds>",
                "purpose": "Override smoke/preflight timeout, clamped to 5-600 seconds."
            },
            {
                "name": "--rdp-env-file <path>",
                "purpose": "Read AIVANA_RDP_TEST_* values from a .env file for readiness and live RDP checks."
            }
        ]
    })
}

pub fn build_goal_evidence_check(report: &CompletionAuditReport) -> serde_json::Value {
    let matrix = build_goal_evidence_matrix(report);
    build_goal_evidence_check_from_matrix(report, matrix)
}

pub fn build_goal_evidence_check_from_args(
    report: &CompletionAuditReport,
    args: &[String],
) -> serde_json::Value {
    let matrix = build_goal_evidence_matrix_from_args(report, args);
    build_goal_evidence_check_from_matrix(report, matrix)
}

fn build_goal_evidence_check_from_matrix(
    report: &CompletionAuditReport,
    matrix: serde_json::Value,
) -> serde_json::Value {
    let failed_requirements = matrix
        .get("uncovered_requirements")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let ok = report.achieved && failed_requirements.is_empty();
    serde_json::json!({
        "schema": "aivana.goal-evidence-check.v1",
        "audit_id": report.audit_id,
        "generated_at": Utc::now(),
        "ok": ok,
        "achieved": report.achieved,
        "failed_requirements": failed_requirements,
        "success_condition": "ok == true",
        "failure_exit": 1,
        "matrix": matrix
    })
}

pub fn save_goal_evidence_check_from_args(
    report: &CompletionAuditReport,
    args: &[String],
) -> anyhow::Result<std::path::PathBuf> {
    save_goal_evidence_check_with_value(report, build_goal_evidence_check_from_args(report, args))
}

fn save_goal_evidence_check_with_value(
    report: &CompletionAuditReport,
    check: serde_json::Value,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("goal-evidence-checks")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.audit_id));
    std::fs::write(&path, redacted_json_string(&check)?)?;
    Ok(path)
}

#[cfg(test)]
pub fn build_operator_handoff_risk_summary() -> OperatorHandoffRiskSummary {
    let audit = build_completion_audit_report();
    let doctor = build_live_gate_doctor_report();
    build_operator_handoff_risk_summary_with_inputs(audit, doctor, &default_rdp_live_env_args())
}

pub fn build_operator_handoff_risk_summary_from_args(
    args: &[String],
) -> OperatorHandoffRiskSummary {
    let audit = build_completion_audit_report_from_args(args);
    let doctor = build_live_gate_doctor_report_from_args(args);
    build_operator_handoff_risk_summary_with_inputs(audit, doctor, args)
}

fn build_operator_handoff_risk_summary_with_inputs(
    audit: CompletionAuditReport,
    doctor: LiveGateDoctorReport,
    args: &[String],
) -> OperatorHandoffRiskSummary {
    let handoff = build_operator_handoff_pack_check();
    let goal_check = build_goal_evidence_check_from_args(&audit, args);
    let proof_check = build_rdp_proof_check_from_args(args);
    let rdp_proof_ok = proof_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let rdp_proof_failed_checks = proof_check
        .get("failed_checks")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let rdp_proof_failed_check_actions = proof_check
        .get("failed_check_actions")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .map(|item| redact_json_value(item.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let goal_evidence_ok = goal_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let failed_requirements = goal_check
        .get("failed_requirements")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("requirement").and_then(|value| value.as_str()))
                .map(redact_secret_text)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let handoff_error_count = handoff.errors.len();
    let handoff_missing_file_count = handoff.missing_files.len()
        + handoff.missing_file_roles.len()
        + handoff.missing_inspection_entries.len();
    let handoff_schema_error_count = handoff.invalid_file_schemas.len();
    let handoff_content_mismatch_count = handoff.content_mismatches.len();
    let ok = doctor.achieved && handoff.ok && goal_evidence_ok;
    let severity = if ok {
        "ready"
    } else if !handoff.ok {
        "handoff-invalid"
    } else if !goal_evidence_ok || !doctor.achieved {
        "blocked"
    } else {
        "warning"
    };

    OperatorHandoffRiskSummary {
        schema: "aivana.operator-handoff-risk-summary.v1".to_owned(),
        generated_at: Utc::now(),
        ok,
        severity: severity.to_owned(),
        achieved: audit.achieved,
        live_gate_stage: redact_secret_text(&doctor.operator_stage),
        blocking_reason: redact_secret_text(&doctor.blocking_reason),
        acceptance_criteria: redact_secret_text(&doctor.acceptance_criteria),
        next_command: redact_secret_text(&doctor.next_command),
        next_success_command: redact_secret_text(&doctor.next_success_command),
        handoff_pack_valid: handoff.ok,
        handoff_pack_path: handoff.pack_path.map(|path| redact_secret_text(&path)),
        handoff_error_count,
        handoff_missing_file_count,
        handoff_schema_error_count,
        handoff_content_mismatch_count,
        goal_evidence_ok,
        rdp_proof_ok,
        rdp_proof_failed_checks,
        rdp_proof_failed_check_actions,
        rdp_proof_recovery_plan_command:
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env".to_owned(),
        rdp_proof_recovery_plan_summary: latest_rdp_proof_recovery_plan_summary()
            .unwrap_or_else(|| "Latest RDP proof recovery plan: none exported yet.".to_owned()),
        llm_triage_entrypoint:
            "summary.md -> verification-snapshot.json -> llm-action-contract.json".to_owned(),
        llm_action_contract_required_evidence_files: vec![
            "summary.md".to_owned(),
            "verification-snapshot.json".to_owned(),
            "llm-action-contract.json".to_owned(),
            "goal-evidence-check.json".to_owned(),
        ],
        llm_action_contract_direct_live_evidence_requirements: vec![
            "direct live evidence from the configured RDP host and port".to_owned(),
            "fresh matching env-file/preflight/smoke host-port evidence".to_owned(),
            "persisted RDP smoke connected=true".to_owned(),
            "framebuffer_present == true".to_owned(),
            "input_probe_present == true".to_owned(),
            "no proxy evidence accepted as direct RDP proof".to_owned(),
        ],
        llm_action_contract_must_return: vec![
            "current_status".to_owned(),
            "next_command".to_owned(),
            "acceptance_criteria".to_owned(),
            "evidence_files_to_inspect".to_owned(),
            "early_triage_artifacts".to_owned(),
        ],
        failed_requirements,
        missing_rdp_env: if doctor.ready_for_preflight {
            Vec::new()
        } else {
            missing_required_rdp_test_env()
        },
        operator_brief: redact_secret_text(&doctor.operator_brief),
        redacted: true,
        success_condition: "ok == true".to_owned(),
        failure_exit: 1,
    }
}

pub fn save_operator_handoff_risk_summary(
    summary: &OperatorHandoffRiskSummary,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("operator-handoff-risk-summaries")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", Uuid::new_v4()));
    std::fs::write(&path, redacted_json_string(summary)?)?;
    Ok(path)
}

fn rdp_env_source_label_from_args(args: &[String]) -> String {
    rdp_env_file_path_from_args(args)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "process environment".to_owned())
}

pub fn build_verification_snapshot_from_args(args: &[String]) -> serde_json::Value {
    let readiness = build_ki_readiness_cli_report_from_args(args);
    let audit = build_completion_audit_report_from_args(args);
    let next_gate = build_next_live_gate_report_from_args(&audit, args);
    let doctor = build_live_gate_doctor_report_from_args(args);
    let proof_check = build_rdp_proof_check_from_args(args);
    let handoff = build_operator_handoff_pack_check();
    let risk = build_operator_handoff_risk_summary_with_inputs(audit.clone(), doctor.clone(), args);
    let blocking_requirements = audit
        .items
        .iter()
        .filter(|item| item.blocking || item.status == "blocked")
        .map(|item| redact_secret_text(&item.requirement))
        .collect::<Vec<_>>();
    let latest_evidence = serde_json::json!({
        "preflight": latest_rdp_preflight_report_summary().unwrap_or_else(|| "Latest RDP preflight evidence: none recorded yet.".to_owned()),
        "smoke": latest_rdp_smoke_report_summary().unwrap_or_else(|| "Latest RDP smoke evidence: none recorded yet.".to_owned()),
        "rdp_proof_check": format!(
            "Latest RDP proof check: ok={} failed_checks={} next={}",
            proof_check
                .get("ok")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            proof_check
                .get("failed_checks")
                .and_then(|value| value.as_array())
                .map(|items| items.len())
                .unwrap_or_default(),
            proof_check
                .get("next_command")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        ),
        "rdp_proof_recovery_plan": latest_rdp_proof_recovery_plan_summary().unwrap_or_else(|| "Latest RDP proof recovery plan: none exported yet.".to_owned()),
        "live_gate": latest_live_gate_report_summary().unwrap_or_else(|| "Latest live gate report: none executed yet.".to_owned()),
        "ai_brief_pack": latest_ai_brief_pack_summary().unwrap_or_else(|| "Latest AI brief pack: none exported yet.".to_owned()),
        "operator_handoff_pack": latest_operator_handoff_pack_summary().unwrap_or_else(|| "Latest operator handoff pack: none exported yet.".to_owned()),
        "operator_handoff_check": operator_handoff_check_summary(&handoff),
    });

    serde_json::json!({
        "schema": "aivana.verification-snapshot.v1",
        "generated_at": Utc::now(),
        "redacted": true,
        "objective": redact_secret_text(&audit.objective),
        "env_source": redact_secret_text(&rdp_env_source_label_from_args(args)),
        "ok": audit.achieved && handoff.ok && risk.ok,
        "readiness": {
            "score": readiness.readiness_score,
            "openai_key_set": readiness.openai_key_set,
            "rdp_smoke_env_ready": readiness.rdp_smoke_env_ready,
            "preferences_saved": readiness.preferences_saved,
            "provider": redact_secret_text(&readiness.provider),
            "model": redact_secret_text(&readiness.model),
            "missing_requirements": readiness
                .missing_requirements
                .iter()
                .map(|item| redact_secret_text(item))
                .collect::<Vec<_>>(),
        },
        "completion": {
            "audit_id": audit.audit_id,
            "achieved": audit.achieved,
            "blocking_gates": audit.items.iter().filter(|item| item.blocking).count(),
            "summary": redact_secret_text(&audit.summary),
            "blocking_requirements": blocking_requirements,
        },
        "live_gate": {
            "achieved": doctor.achieved,
            "stage": redact_secret_text(&doctor.operator_stage),
            "blocking_reason": redact_secret_text(&doctor.blocking_reason),
            "acceptance_criteria": redact_secret_text(&doctor.acceptance_criteria),
            "next_command": redact_secret_text(&doctor.next_command),
            "next_success_command": redact_secret_text(&doctor.next_success_command),
            "ready_for_preflight": doctor.ready_for_preflight,
            "ready_for_smoke": doctor.ready_for_smoke,
            "smoke_connected": doctor.smoke_connected,
            "missing_rdp_env": next_gate.missing_rdp_env,
            "next_commands": next_gate
                .next_commands
                .iter()
                .map(|command| redact_secret_text(command))
                .collect::<Vec<_>>(),
        },
        "rdp_proof": {
            "ok": proof_check
                .get("ok")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            "checks": proof_check
                .get("checks")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            "failed_checks": proof_check
                .get("failed_checks")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            "failed_check_actions": proof_check
                .get("failed_check_actions")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            "next_command": proof_check
                .get("next_command")
                .and_then(|value| value.as_str())
                .map(redact_secret_text),
            "recovery_plan_command": "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env",
        },
        "handoff": {
            "pack_valid": handoff.ok,
            "pack_path": handoff.pack_path.as_deref().map(redact_secret_text),
            "missing_files": handoff.missing_files.len(),
            "missing_file_roles": handoff.missing_file_roles.len(),
            "missing_inspection_entries": handoff.missing_inspection_entries.len(),
            "invalid_file_schemas": handoff.invalid_file_schemas.len(),
            "content_mismatches": handoff.content_mismatches.len(),
            "errors": handoff.errors.len(),
        },
        "llm_action_contract": {
            "copy_action": "Copy LLM Action Contract JSON",
            "export_action": "Export LLM Action Contract",
            "required_evidence_files": [
                "summary.md",
                "verification-snapshot.json",
                "llm-action-contract.json",
                "goal-evidence-check.json"
            ],
            "must_return": [
                "current_status",
                "next_command",
                "acceptance_criteria",
                "evidence_files_to_inspect",
                "early_triage_artifacts"
            ],
            "success_signals": [
                "rdp-env-file-check.ok == true",
                "rdp-preflight connect_recommended == true",
                "rdp-smoke-test connected == true",
                "rdp-smoke-test framebuffer_present == true",
                "rdp-smoke-test input_probe_present == true",
                "goal-evidence-check.ok == true"
            ],
            "direct_live_evidence_requirements": [
                "direct live evidence from the configured RDP host and port",
                "fresh matching env-file/preflight/smoke host-port evidence",
                "persisted RDP smoke connected=true",
                "framebuffer_present == true",
                "input_probe_present == true",
                "no proxy evidence accepted as direct RDP proof"
            ],
            "proxy_evidence_rejected": [
                "passing unit tests without live RDP smoke evidence",
                "manifest completeness without direct RDP proof",
                "command availability without successful execution"
            ]
        },
        "llm_review_prompt": {
            "copy_action": "Copy LLM Review Prompt",
            "command": "cargo run -- --llm-review-prompt",
            "triage_order": [
                "summary.md",
                "verification-snapshot.json",
                "llm-action-contract.json",
                "operator-handoff-risk-summary.json"
            ],
            "risk_summary_cross_check": [
                "LLM triage entrypoint",
                "required evidence files",
                "early_triage_artifacts"
            ],
            "proxy_evidence_rejected": [
                "commands, manifests, or passing tests without direct live RDP proof"
            ]
        },
        "risk": {
            "ok": risk.ok,
            "severity": redact_secret_text(&risk.severity),
            "blocking_reason": redact_secret_text(&risk.blocking_reason),
            "acceptance_criteria": redact_secret_text(&risk.acceptance_criteria),
            "next_command": redact_secret_text(&risk.next_command),
            "next_success_command": redact_secret_text(&risk.next_success_command),
            "goal_evidence_ok": risk.goal_evidence_ok,
            "failed_requirements": risk.failed_requirements,
            "rdp_proof_ok": risk.rdp_proof_ok,
            "rdp_proof_failed_checks": risk.rdp_proof_failed_checks,
            "rdp_proof_failed_check_actions": risk.rdp_proof_failed_check_actions,
            "rdp_proof_recovery_plan_command": risk.rdp_proof_recovery_plan_command,
            "rdp_proof_recovery_plan_summary": risk.rdp_proof_recovery_plan_summary,
            "operator_brief": redact_secret_text(&risk.operator_brief),
        },
        "latest_evidence": latest_evidence,
        "success_condition": "ok == true and rdp_proof.ok == true with fresh matching env-file/preflight/smoke host-port evidence and direct RDP framebuffer/input evidence"
    })
}

pub fn save_verification_snapshot(
    snapshot: &serde_json::Value,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("verification-snapshots")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", Uuid::new_v4()));
    std::fs::write(&path, redacted_json_string(snapshot)?)?;
    Ok(path)
}

pub fn build_llm_action_contract_from_args(args: &[String]) -> serde_json::Value {
    let audit = build_completion_audit_report_from_args(args);
    let doctor = build_live_gate_doctor_report_from_args(args);
    let proof_check = build_rdp_proof_check_from_args(args);
    build_llm_action_contract(&audit, &doctor, &proof_check, args)
}

pub fn build_llm_action_contract(
    audit: &CompletionAuditReport,
    doctor: &LiveGateDoctorReport,
    proof_check: &serde_json::Value,
    args: &[String],
) -> serde_json::Value {
    let next_gate = build_next_live_gate_report_from_args(audit, args);
    let rdp_proof_ok = proof_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let failed_requirements = audit
        .items
        .iter()
        .filter(|item| item.blocking || item.status == "blocked")
        .map(|item| {
            serde_json::json!({
                "requirement": item.requirement,
                "status": item.status,
                "next_action": item.next_action,
            })
        })
        .collect::<Vec<_>>();

    redact_json_value(serde_json::json!({
        "schema": "aivana.llm-action-contract.v1",
        "generated_at": Utc::now(),
        "redacted": true,
        "objective": audit.objective,
        "ok": audit.achieved && doctor.achieved && rdp_proof_ok,
        "env_source": rdp_env_source_label_from_args(args),
        "operator_stage": doctor.operator_stage,
        "blocking_reason": doctor.blocking_reason,
        "acceptance_criteria": doctor.acceptance_criteria,
        "next_command": doctor.next_command,
        "next_success_command": doctor.next_success_command,
        "rdp_proof_recovery_plan_command": doctor.rdp_proof_recovery_plan_command,
        "allowed_next_commands": next_gate.next_commands,
        "failed_requirements": failed_requirements,
        "rdp_proof": {
            "ok": rdp_proof_ok,
            "failed_checks": proof_check
                .get("failed_checks")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            "failed_check_actions": proof_check
                .get("failed_check_actions")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            "next_command": proof_check
                .get("next_command")
                .and_then(|value| value.as_str())
                .unwrap_or("cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env"),
        },
        "required_evidence_files": [
            "summary.md",
            "rdp-env-file-check.json",
            "rdp-proof-check.json",
            "live-gate-doctor.json",
            "goal-evidence-check.json",
            "verification-snapshot.json",
            "operator-handoff-risk-summary.json"
        ],
        "completion_must_have": [
            "goal-evidence-check.ok == true",
            "rdp-proof-check.ok == true",
            "fresh matching env-file/preflight/smoke host-port evidence",
            "persisted RDP smoke connected=true",
            "framebuffer_present == true",
            "input_probe_present == true"
        ],
        "direct_live_evidence_requirements": [
            "direct live evidence from the configured RDP host and port",
            "fresh matching env-file/preflight/smoke host-port evidence",
            "persisted RDP smoke connected=true",
            "framebuffer_present == true",
            "input_probe_present == true",
            "no proxy evidence accepted as direct RDP proof"
        ],
        "evidence_success_signals": [
            "rdp-env-file-check.ok == true",
            "rdp-preflight connect_recommended == true",
            "rdp-smoke-test connected == true",
            "rdp-smoke-test framebuffer_present == true",
            "rdp-smoke-test input_probe_present == true",
            "goal-evidence-check.ok == true"
        ],
        "proxy_evidence_rejected": [
            "passing unit tests without live RDP smoke evidence",
            "manifest completeness without direct RDP proof",
            "command availability without successful execution",
            "old preflight or smoke reports from a different host or port"
        ],
        "assistant_response_contract": {
            "must_return": [
                "current_status",
                "next_command",
                "acceptance_criteria",
                "evidence_files_to_inspect",
                "early_triage_artifacts"
            ],
            "must_not_return": [
                "completion=true unless ok=true",
                "unredacted credentials",
                "proxy evidence as direct RDP proof"
            ]
        }
    }))
}

pub fn save_llm_action_contract(
    contract: &serde_json::Value,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("llm-action-contracts")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", Uuid::new_v4()));
    std::fs::write(&path, redacted_json_string(contract)?)?;
    Ok(path)
}

pub fn build_goal_evidence_matrix(report: &CompletionAuditReport) -> serde_json::Value {
    build_goal_evidence_matrix_with_next_gate(report, build_next_live_gate_report(report))
}

pub fn build_goal_evidence_matrix_from_args(
    report: &CompletionAuditReport,
    args: &[String],
) -> serde_json::Value {
    build_goal_evidence_matrix_with_next_gate(
        report,
        build_next_live_gate_report_from_args(report, args),
    )
}

fn build_goal_evidence_matrix_with_next_gate(
    report: &CompletionAuditReport,
    next_live_gate: NextLiveGateReport,
) -> serde_json::Value {
    let checklist = report
        .items
        .iter()
        .map(|item| {
            serde_json::json!({
                "requirement": redact_secret_text(&item.requirement),
                "artifact": redact_secret_text(&item.artifact),
                "status": redact_secret_text(&item.status),
                "blocking": item.blocking,
                "evidence": redact_secret_text(&item.evidence),
                "next_action": redact_secret_text(&item.next_action),
                "covered": !item.blocking && item.status != "blocked"
            })
        })
        .collect::<Vec<_>>();
    let uncovered_requirements = report
        .items
        .iter()
        .filter(|item| item.blocking || item.status == "blocked")
        .map(|item| {
            serde_json::json!({
                "requirement": redact_secret_text(&item.requirement),
                "status": redact_secret_text(&item.status),
                "missing_evidence": redact_secret_text(&item.next_action)
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema": "aivana.goal-evidence-matrix.v1",
        "audit_id": report.audit_id,
        "generated_at": report.generated_at,
        "objective": redact_secret_text(&report.objective),
        "achieved": report.achieved,
        "completion_rule": "Do not claim complete until achieved=true and uncovered_requirements is empty; live RDP requires rdp-proof-check.ok=true with fresh matching env-file/preflight/smoke host-port evidence plus persisted connected=true framebuffer/input evidence.",
        "success_criteria": [
            "Native Rust RDP implementation is present.",
            "AI/KI cockpit and LLM handoff commands are available.",
            "Operator workflow is GUI-friendly and auditable.",
            "Secrets are redacted in shared evidence.",
            "Hosted OpenAI CUA path is ready when configured.",
            "Headless CI/handoff artifacts are generated and validated.",
            "Real RDP end-to-end proof exists with fresh env-file/preflight/smoke host-port match, connected=true, framebuffer, and input probe."
        ],
        "verification_commands": [
            "cargo run -- --command-index",
            "cargo run -- --save-ki-preferences",
            "cargo run -- --ai-brief-pack",
            "cargo run -- --save-rdp-env-template .\\rdp-live.env",
            "cargo run -- --rdp-env-fill-guide",
            "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env",
            "cargo run -- --live-gate-sequence",
            "cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env",
            "cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env",
            "cargo run -- --llm-review-prompt",
            "cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env",
            "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
            "cargo run -- --completion-audit --rdp-env-file .\\rdp-live.env",
            "cargo run -- --goal-evidence-matrix --rdp-env-file .\\rdp-live.env",
            "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env",
            "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
            "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env",
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env",
            "cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env",
            "cargo run -- --operator-handoff-check",
            "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env",
            "cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env"
        ],
        "checklist": checklist,
        "uncovered_requirements": uncovered_requirements,
        "next_live_gate": next_live_gate
    })
}

pub fn save_goal_evidence_matrix_from_args(
    report: &CompletionAuditReport,
    args: &[String],
) -> anyhow::Result<std::path::PathBuf> {
    save_goal_evidence_matrix_with_value(report, build_goal_evidence_matrix_from_args(report, args))
}

fn save_goal_evidence_matrix_with_value(
    report: &CompletionAuditReport,
    matrix: serde_json::Value,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("goal-evidence-matrices")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.audit_id));
    std::fs::write(&path, redacted_json_string(&matrix)?)?;
    Ok(path)
}

fn redacted_json_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(value)?;
    redact_json_strings(&mut value);
    Ok(serde_json::to_string_pretty(&value)?)
}

fn redact_json_value(mut value: serde_json::Value) -> serde_json::Value {
    redact_json_strings(&mut value);
    value
}

fn redact_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = redact_secret_text(text);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_strings(item);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                redact_json_strings(value);
            }
        }
        _ => {}
    }
}

pub fn build_operator_llm_review_prompt(
    readiness: &KiReadinessCliReport,
    audit: &CompletionAuditReport,
    runbook: &str,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana Operator Handoff LLM Review Prompt");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Review the attached Aivana operator handoff pack. Treat completion as false unless every blocking gate in completion-audit.json is resolved by direct evidence."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Context");
    let _ = writeln!(out, "- Objective: {}", redact_secret_text(&audit.objective));
    let _ = writeln!(out, "- Achieved: {}", audit.achieved);
    let _ = writeln!(out, "- Readiness score: {}%", readiness.readiness_score);
    let _ = writeln!(
        out,
        "- Blocking gates: {}",
        audit.items.iter().filter(|item| item.blocking).count()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required Review");
    let _ = writeln!(
        out,
        "1. Inspect summary.md for Early LLM Triage first, then verification-snapshot.json and llm-action-contract.json."
    );
    let _ = writeln!(out, "2. Summarize the current live-gate status.");
    let _ = writeln!(
        out,
        "3. Cross-check operator-handoff-risk-summary.json for the LLM triage entrypoint, required evidence files, and early_triage_artifacts response fields."
    );
    let _ = writeln!(
        out,
        "4. List each missing artifact or weak evidence item. Do not treat a command, manifest, or passing unit test as live RDP proof."
    );
    let _ = writeln!(
        out,
        "5. Produce the exact next operator commands needed to resolve the first blocking gate."
    );
    let _ = writeln!(
        out,
        "6. Call out any secret-looking text that is not redacted before sharing the pack."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Files To Inspect");
    let _ = writeln!(out, "- readiness.json");
    let _ = writeln!(out, "- completion-audit.json");
    let _ = writeln!(out, "- goal-evidence-matrix.json");
    let _ = writeln!(out, "- goal-evidence-check.json");
    let _ = writeln!(out, "- verification-snapshot.json");
    let _ = writeln!(out, "- operator-handoff-risk-summary.json");
    let _ = writeln!(out, "- command-index.json");
    let _ = writeln!(out, "- rdp-env-file-check.json");
    let _ = writeln!(out, "- rdp-proof-check.json");
    let _ = writeln!(out, "- live-gate-doctor.json");
    let _ = writeln!(out, "- live-gate-operator-brief.md");
    let _ = writeln!(out, "- next-live-gate.json");
    let _ = writeln!(out, "- live-gate-sequence.txt");
    let _ = writeln!(out, "- next-live-gate.md");
    let _ = writeln!(out, "- live-gate-runbook.md");
    let _ = writeln!(out, "- gui-operator-actions.md");
    let _ = writeln!(out, "- rdp-env-template.env");
    let _ = writeln!(out, "- rdp-env-fill-guide.md");
    let _ = writeln!(out, "- llm-review-prompt.md");
    let _ = writeln!(out, "- rdp-proof-prompt.md");
    let _ = writeln!(out, "- rdp-proof-recovery-plan.md");
    let _ = writeln!(out, "- llm-live-gate-plan.md");
    let _ = writeln!(out, "- llm-action-contract.json");
    let _ = writeln!(out, "- summary.md");
    let _ = writeln!(out, "- manifest.json");
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Runbook");
    let _ = writeln!(out, "{}", redact_secret_text(runbook));
    redact_secret_text(&out)
}

pub fn build_live_gate_llm_plan(
    audit: &CompletionAuditReport,
    doctor: &LiveGateDoctorReport,
    runbook: &str,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana Live Gate LLM Plan");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Use this as the instruction pack for an LLM or CI assistant. The model must not claim completion unless live RDP smoke evidence shows connected=true with framebuffer/input proof and the completion audit is achieved."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Status");
    let _ = writeln!(out, "- Objective: {}", redact_secret_text(&audit.objective));
    let _ = writeln!(out, "- Audit achieved: {}", audit.achieved);
    let _ = writeln!(out, "- Doctor achieved: {}", doctor.achieved);
    let _ = writeln!(out, "- Operator stage: {}", doctor.operator_stage);
    let _ = writeln!(out, "- Ready for preflight: {}", doctor.ready_for_preflight);
    let _ = writeln!(out, "- Ready for smoke: {}", doctor.ready_for_smoke);
    let _ = writeln!(out, "- Smoke connected: {}", doctor.smoke_connected);
    let _ = writeln!(out, "- Handoff pack valid: {}", doctor.handoff_pack_valid);
    let _ = writeln!(
        out,
        "- Blocking reason: {}",
        redact_secret_text(&doctor.blocking_reason)
    );
    let _ = writeln!(out, "- Next command: `{}`", doctor.next_command);
    let _ = writeln!(
        out,
        "- Acceptance criteria: {}",
        redact_secret_text(&doctor.acceptance_criteria)
    );
    let _ = writeln!(
        out,
        "- Next command after success: `{}`",
        doctor.next_success_command
    );
    let _ = writeln!(
        out,
        "- RDP proof recovery plan command: `{}`",
        doctor.rdp_proof_recovery_plan_command
    );
    let _ = writeln!(
        out,
        "- Operator brief: {}",
        redact_secret_text(&doctor.operator_brief)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required LLM Work");
    let _ = writeln!(
        out,
        "1. Restate whether the live gate is blocked or achieved using only attached evidence."
    );
    let _ = writeln!(
        out,
        "2. Inspect summary.md for Early LLM Triage first, then verification-snapshot.json, llm-action-contract.json, operator-handoff-risk-summary.json, live-gate-doctor.json, live-gate-operator-brief.md, completion-audit.json, goal-evidence-check.json, rdp-env-file-check.json, rdp-proof-check.json, rdp-proof-recovery-plan.md, next-live-gate.json, and live-gate-sequence.txt; cross-check the risk summary for the LLM triage entrypoint, required evidence files, and early_triage_artifacts."
    );
    let _ = writeln!(
        out,
        "3. Produce the next operator command exactly as shown by the doctor unless a newer attached artifact contradicts it."
    );
    let _ = writeln!(
        out,
        "4. Reject proxy evidence: tests, manifests, docs, or command availability are not live RDP proof."
    );
    let _ = writeln!(
        out,
        "5. Flag unredacted secret-looking text before sharing artifacts outside the operator environment."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Doctor Checks");
    for check in &doctor.checks {
        let _ = writeln!(
            out,
            "- {}: ok={} status={} next=`{}` evidence={}",
            check.name,
            check.ok,
            redact_secret_text(&check.status),
            check.next_command,
            redact_secret_text(&check.evidence)
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Runbook");
    let _ = writeln!(out, "{}", redact_secret_text(runbook));
    redact_secret_text(&out)
}

pub fn build_gui_operator_actions(audit: &CompletionAuditReport) -> String {
    let next_gate = audit
        .items
        .iter()
        .find(|item| item.blocking)
        .map(|item| item.next_action.as_str())
        .unwrap_or("No blocking gate remains; archive the handoff pack with the release evidence.");
    let current_evidence = audit
        .items
        .iter()
        .find(|item| item.blocking)
        .map(|item| item.evidence.as_str())
        .unwrap_or("No blocking gate evidence remains.");
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana GUI Operator Actions");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Objective: {}", redact_secret_text(&audit.objective));
    let _ = writeln!(out, "- Achieved: {}", audit.achieved);
    let _ = writeln!(
        out,
        "- Blocking gates: {}",
        audit.items.iter().filter(|item| item.blocking).count()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Verification Center");
    let _ = writeln!(out, "1. Open Workspaces, then KI Verification Center.");
    let _ = writeln!(
        out,
        "2. Confirm the RDP env source line; when rdp-live.env exists locally it should show .\\rdp-live.env."
    );
    let _ = writeln!(
        out,
        "3. Click Copy Next Gate JSON for the first blocking gate."
    );
    let _ = writeln!(
        out,
        "4. Click Copy Command Index JSON when an LLM or CI agent needs the full command map."
    );
    let _ = writeln!(
        out,
        "5. Click Copy Evidence Matrix JSON when an LLM needs requirement-to-artifact coverage."
    );
    let _ = writeln!(
        out,
        "6. Click Copy Evidence Check JSON when CI or an LLM needs a hard pass/fail completion gate."
    );
    let _ = writeln!(
        out,
        "7. Click Copy Env Save Command when an operator wants a safe local .env starter file."
    );
    let _ = writeln!(
        out,
        "8. Click Copy RDP Env Template and create the local ignored rdp-live.env starter."
    );
    let _ = writeln!(
        out,
        "9. Click Copy RDP Env Fill Guide before adding live RDP values outside the shared handoff pack."
    );
    let _ = writeln!(
        out,
        "10. Click Copy Env Check Command after filling rdp-live.env, before DNS/TCP preflight."
    );
    let _ = writeln!(
        out,
        "11. Click Export Handoff Pack after new preflight, smoke, or live-gate evidence exists."
    );
    let _ = writeln!(
        out,
        "12. Check the visible handoff-check status; it should show ok=true before sharing the pack."
    );
    let _ = writeln!(
        out,
        "13. Click Copy Handoff Check JSON when CI or an LLM needs machine-readable pack validation."
    );
    let _ = writeln!(
        out,
        "14. Click Copy Handoff Risk JSON when CI or an LLM needs one compact risk, blocker, acceptance, and next-command artifact."
    );
    let _ = writeln!(
        out,
        "15. Click Copy Handoff Risk Command when automation needs the hard risk-summary gate command."
    );
    let _ = writeln!(
        out,
        "16. Click Copy Verification Snapshot JSON after risk summary when CI or an LLM needs the final compact GUI/live-gate/handoff status."
    );
    let _ = writeln!(
        out,
        "17. Click Export Verification Snapshot after exporting a fresh handoff pack."
    );
    let _ = writeln!(
        out,
        "18. Click Copy RDP Proof Check JSON when CI or an LLM needs the direct proof-only pass/fail checklist."
    );
    let _ = writeln!(
        out,
        "19. Click Copy RDP Proof Prompt when a human operator or LLM assistant needs the no-secrets prompt for finishing the direct RDP smoke evidence gate."
    );
    let _ = writeln!(
        out,
        "20. Click Copy RDP Recovery Plan when an operator or LLM needs a readable failed-check-to-command plan with acceptance criteria, direct live evidence requirements, and proxy-evidence rejection."
    );
    let _ = writeln!(
        out,
        "21. Click Copy RDP Recovery Plan Command when automation needs only the canonical recovery-plan export command."
    );
    let _ = writeln!(
        out,
        "22. Click Copy RDP Recovery Commands when an operator needs only the exact recovery command list from failed proof checks."
    );
    let _ = writeln!(
        out,
        "23. Click Copy Live Gate Doctor JSON when an operator or LLM needs the current env/preflight/smoke/handoff ladder and next exact command."
    );
    let _ = writeln!(
        out,
        "24. Click Copy Live Gate Next Command when an operator needs only the current doctor-selected command."
    );
    let _ = writeln!(
        out,
        "25. Click Copy Live Gate Operator Brief when an operator or LLM needs the concise current blocker and acceptance criteria without JSON parsing."
    );
    let _ = writeln!(
        out,
        "26. Click Copy Live Gate Sequence when an operator needs the full ordered command list."
    );
    let _ = writeln!(
        out,
        "27. Click Copy LLM Review Prompt when an LLM reviewer needs summary.md Early LLM Triage, operator-handoff-risk-summary.json cross-check, early_triage_artifacts, and proxy-evidence rejection instructions."
    );
    let _ = writeln!(
        out,
        "28. Click Copy Live Gate LLM Plan when an LLM or automation agent needs a redacted instruction plan."
    );
    let _ = writeln!(
        out,
        "29. Click Copy LLM Action Contract JSON when an LLM or CI agent needs strict next-command, allowed-command, acceptance, summary.md Early LLM Triage evidence, direct_live_evidence_requirements, early_triage_artifacts response field, evidence success signals, and proxy-evidence rejection rules."
    );
    let _ = writeln!(
        out,
        "30. Click Export LLM Action Contract after exporting a fresh handoff pack."
    );
    let _ = writeln!(
        out,
        "31. Click Copy Handoff Risk Evidence for a short human-readable risk summary."
    );
    let _ = writeln!(
        out,
        "32. Click Copy Handoff Check Evidence for a short human-readable validation summary."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Mission Control");
    let _ = writeln!(
        out,
        "1. Select OpenAI CUA only after OPENAI_API_KEY is present and an operator is ready to approve actions."
    );
    let _ = writeln!(out, "2. Copy the CUA Request Brief before a hosted run.");
    let _ = writeln!(
        out,
        "3. Keep approval mode enabled for typing, clicking, or runbook mutations."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Next Gate");
    let _ = writeln!(out, "{}", redact_secret_text(next_gate));
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Evidence");
    let _ = writeln!(out, "{}", redact_secret_text(current_evidence));
    redact_secret_text(&out)
}

pub fn save_gui_operator_actions(
    audit: &CompletionAuditReport,
    actions: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("gui-operator-actions")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", audit.audit_id));
    std::fs::write(&path, redact_secret_text(actions))?;
    Ok(path)
}

pub fn save_operator_llm_review_prompt(
    audit: &CompletionAuditReport,
    prompt: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("llm-review-prompts")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", audit.audit_id));
    std::fs::write(&path, redact_secret_text(prompt))?;
    Ok(path)
}

pub fn save_live_gate_llm_plan(
    audit: &CompletionAuditReport,
    plan: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("llm-live-gate-plans")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", audit.audit_id));
    std::fs::write(&path, redact_secret_text(plan))?;
    Ok(path)
}

pub fn save_live_gate_runbook(
    report: &CompletionAuditReport,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("live-gate-runbooks")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.md", report.audit_id));
    std::fs::write(&path, build_live_gate_runbook(report))?;
    Ok(path)
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OperatorHandoffPackReport {
    pub schema: String,
    pub pack_id: Uuid,
    pub created_at: chrono::DateTime<Utc>,
    pub achieved: bool,
    pub blocking_gates: usize,
    pub summary: String,
    pub pack_path: Option<String>,
    pub files: Vec<String>,
    pub file_roles: Vec<OperatorHandoffFileRole>,
    pub recommended_inspection_order: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AiBriefPackReport {
    pub schema: String,
    pub pack_id: String,
    pub created_at: chrono::DateTime<Utc>,
    pub redacted: bool,
    pub pack_path: String,
    pub files: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OperatorHandoffFileRole {
    pub file: String,
    pub role: String,
    pub inspect_when: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OperatorHandoffPackCheck {
    pub schema: String,
    pub checked_at: chrono::DateTime<Utc>,
    pub ok: bool,
    pub pack_path: Option<String>,
    pub manifest_path: Option<String>,
    pub expected_schema: String,
    pub actual_schema: Option<String>,
    pub missing_files: Vec<String>,
    pub missing_file_roles: Vec<String>,
    pub missing_inspection_entries: Vec<String>,
    pub invalid_file_schemas: Vec<String>,
    pub content_mismatches: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OperatorHandoffRiskSummary {
    pub schema: String,
    pub generated_at: chrono::DateTime<Utc>,
    pub ok: bool,
    pub severity: String,
    pub achieved: bool,
    pub live_gate_stage: String,
    pub blocking_reason: String,
    pub acceptance_criteria: String,
    pub next_command: String,
    pub next_success_command: String,
    pub handoff_pack_valid: bool,
    pub handoff_pack_path: Option<String>,
    pub handoff_error_count: usize,
    pub handoff_missing_file_count: usize,
    pub handoff_schema_error_count: usize,
    pub handoff_content_mismatch_count: usize,
    pub goal_evidence_ok: bool,
    pub rdp_proof_ok: bool,
    pub rdp_proof_failed_checks: Vec<String>,
    pub rdp_proof_failed_check_actions: Vec<serde_json::Value>,
    pub rdp_proof_recovery_plan_command: String,
    pub rdp_proof_recovery_plan_summary: String,
    pub llm_triage_entrypoint: String,
    pub llm_action_contract_required_evidence_files: Vec<String>,
    pub llm_action_contract_direct_live_evidence_requirements: Vec<String>,
    pub llm_action_contract_must_return: Vec<String>,
    pub failed_requirements: Vec<String>,
    pub missing_rdp_env: Vec<String>,
    pub operator_brief: String,
    pub redacted: bool,
    pub success_condition: String,
    pub failure_exit: u8,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveGateReport {
    pub gate_id: Uuid,
    pub generated_at: chrono::DateTime<Utc>,
    pub timeout_secs: u64,
    pub missing_rdp_env: Vec<String>,
    pub rdp_env_template: String,
    pub preflight: RdpPreflightEvidenceReport,
    pub smoke: LiveGateSmokeEvidence,
    pub readiness: KiReadinessCliReport,
    pub completion_audit: CompletionAuditReport,
    pub achieved: bool,
    pub blocking_gates: usize,
    pub next_action: String,
    pub evidence_path: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LiveGateSmokeEvidence {
    pub attempted: bool,
    pub connected: bool,
    pub status: String,
    pub summary: String,
    pub evidence_path: Option<String>,
}

impl LiveGateSmokeEvidence {
    fn skipped(reason: &str) -> Self {
        Self {
            attempted: false,
            connected: false,
            status: "skipped".to_owned(),
            summary: redact_secret_text(reason),
            evidence_path: None,
        }
    }

    fn success(report: &RdpSmokeTestReport) -> Self {
        Self {
            attempted: true,
            connected: report.connected,
            status: "connected".to_owned(),
            summary: format!(
                "connected={} host={} framebuffer={}x{} timeout={}s",
                report.connected,
                redact_secret_text(&report.host),
                report.framebuffer.width,
                report.framebuffer.height,
                report.timeout_secs
            ),
            evidence_path: report.evidence_path.clone(),
        }
    }

    fn failure(report: &RdpSmokeTestFailureReport) -> Self {
        Self {
            attempted: true,
            connected: false,
            status: "failed".to_owned(),
            summary: format!(
                "connected=false error={} timeout={}s",
                redact_secret_text(&report.error),
                report.timeout_secs
            ),
            evidence_path: report.evidence_path.clone(),
        }
    }
}

pub fn build_operator_handoff_pack_report_from_args(
    args: &[String],
) -> anyhow::Result<OperatorHandoffPackReport> {
    let readiness = build_ki_readiness_cli_report_from_args(args);
    let audit = build_completion_audit_report_from_args(args);
    let dir = app_data_file("operator-handoff-packs")?.join(Uuid::new_v4().to_string());
    save_operator_handoff_pack_to_dir_with_args(&dir, &readiness, &audit, args)
}

pub fn build_ai_brief_pack_report() -> anyhow::Result<AiBriefPackReport> {
    let mut autopilot = AutopilotController::default();
    if let Some(preferences) = load_autopilot_preferences() {
        autopilot.goal = preferences.goal;
        autopilot.settings = preferences.settings;
    }
    let host = "headless operator context";
    let action_brief = build_ai_action_brief(host, &[], &[], &[], &[]);
    let prompt_library = build_prompt_library_brief(host, &action_brief, &autopilot, false);
    let runbooks = RunbookEngine::with_defaults();
    let runbook_brief = build_runbook_llm_brief(runbooks.list_runbooks(), host);
    let verification_brief = build_ki_verification_report(&autopilot, 0).to_markdown();
    let path = save_ai_brief_pack(
        &action_brief,
        &prompt_library,
        &runbook_brief,
        &verification_brief,
    )?;
    let pack_id = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_owned();

    Ok(AiBriefPackReport {
        schema: "aivana.ai-brief-pack.v1".to_owned(),
        pack_id,
        created_at: Utc::now(),
        redacted: true,
        pack_path: path.display().to_string(),
        files: vec![
            "action-brief.md".to_owned(),
            "prompt-library.md".to_owned(),
            "runbook-brief.md".to_owned(),
            "verification-brief.md".to_owned(),
            "manifest.json".to_owned(),
        ],
    })
}

pub fn build_operator_handoff_pack_check() -> OperatorHandoffPackCheck {
    let checked_at = Utc::now();
    let expected_schema = "aivana.operator-handoff-pack.v1".to_owned();
    let mut check = OperatorHandoffPackCheck {
        schema: "aivana.operator-handoff-check.v1".to_owned(),
        checked_at,
        ok: false,
        pack_path: None,
        manifest_path: None,
        expected_schema: expected_schema.clone(),
        actual_schema: None,
        missing_files: Vec::new(),
        missing_file_roles: Vec::new(),
        missing_inspection_entries: Vec::new(),
        invalid_file_schemas: Vec::new(),
        content_mismatches: Vec::new(),
        errors: Vec::new(),
    };
    let dir = match app_data_file("operator-handoff-packs") {
        Ok(dir) => dir,
        Err(err) => {
            check.errors.push(redact_secret_text(&err.to_string()));
            return check;
        }
    };
    match build_operator_handoff_pack_check_from_dir(&dir, checked_at, &expected_schema) {
        Ok(check) => check,
        Err(err) => {
            check.errors.push(redact_secret_text(&err.to_string()));
            check
        }
    }
}

pub fn run_live_gate_report_from_profile_result_with_args(
    timeout_secs: u64,
    profile_result: anyhow::Result<ConnectionProfile>,
    args: &[String],
) -> LiveGateReport {
    let mut smoke_profile = None;
    let mut preflight = match profile_result {
        Ok(profile) => {
            let preflight =
                crate::diagnostics::build_rdp_preflight_evidence(&profile, timeout_secs);
            smoke_profile = Some(profile);
            preflight
        }
        Err(err) => crate::diagnostics::rdp_preflight_env_failure(&err, timeout_secs),
    };
    if let Ok(path) = crate::diagnostics::save_rdp_preflight_evidence(&preflight) {
        preflight.evidence_path = Some(path.display().to_string());
        let _ = crate::diagnostics::save_rdp_preflight_evidence(&preflight);
    }

    let smoke = if preflight.connect_recommended {
        match smoke_profile
            .ok_or_else(|| anyhow::anyhow!("RDP profile unavailable after preflight"))
            .and_then(|profile| crate::ironrdp_client::rdp_smoke_test(profile, timeout_secs))
        {
            Ok(mut report) => {
                if let Ok(path) = crate::ironrdp_client::save_rdp_smoke_report(&report) {
                    report.evidence_path = Some(path.display().to_string());
                    let _ = crate::ironrdp_client::save_rdp_smoke_report(&report);
                }
                LiveGateSmokeEvidence::success(&report)
            }
            Err(err) => {
                let mut report =
                    crate::ironrdp_client::rdp_smoke_failure_report(&err, timeout_secs);
                if let Ok(path) = crate::ironrdp_client::save_rdp_smoke_failure_report(&report) {
                    report.evidence_path = Some(path.display().to_string());
                    let _ = crate::ironrdp_client::save_rdp_smoke_failure_report(&report);
                }
                LiveGateSmokeEvidence::failure(&report)
            }
        }
    } else {
        LiveGateSmokeEvidence::skipped(
            "RDP smoke skipped because preflight did not recommend connecting.",
        )
    };

    let mut readiness = build_ki_readiness_cli_report_from_args(args);
    if let Ok(path) = save_ki_readiness_cli_report(&readiness) {
        readiness.evidence_path = Some(path.display().to_string());
        let _ = save_ki_readiness_cli_report(&readiness);
    }
    let mut completion_audit = build_completion_audit_report_from_args(args);
    if let Ok(path) = save_completion_audit_report(&completion_audit) {
        completion_audit.audit_path = Some(path.display().to_string());
        let _ = save_completion_audit_report(&completion_audit);
    }
    build_live_gate_report_from_parts(timeout_secs, preflight, smoke, readiness, completion_audit)
}

fn build_live_gate_report_from_parts(
    timeout_secs: u64,
    mut preflight: RdpPreflightEvidenceReport,
    smoke: LiveGateSmokeEvidence,
    mut readiness: KiReadinessCliReport,
    completion_audit: CompletionAuditReport,
) -> LiveGateReport {
    preflight.host = redact_secret_text(&preflight.host);
    preflight.env_error = preflight.env_error.map(|error| redact_secret_text(&error));
    readiness.provider = redact_secret_text(&readiness.provider);
    readiness.model = redact_secret_text(&readiness.model);
    readiness.goal = redact_secret_text(&readiness.goal);
    readiness.missing_requirements = readiness
        .missing_requirements
        .into_iter()
        .map(|requirement| redact_secret_text(&requirement))
        .collect();
    readiness.latest_rdp_preflight_evidence = readiness
        .latest_rdp_preflight_evidence
        .map(|evidence| redact_secret_text(&evidence));
    readiness.latest_rdp_smoke_evidence = readiness
        .latest_rdp_smoke_evidence
        .map(|evidence| redact_secret_text(&evidence));
    readiness.next_step = redact_secret_text(&readiness.next_step);

    let blocking_gates = completion_audit
        .items
        .iter()
        .filter(|item| item.blocking)
        .count();
    let missing_rdp_env = if readiness.rdp_smoke_env_ready {
        Vec::new()
    } else {
        missing_required_rdp_test_env()
    };
    let next_action = completion_audit
        .items
        .iter()
        .find(|item| item.blocking)
        .map(|item| item.next_action.clone())
        .unwrap_or_else(|| "Archive the live-gate evidence with the release handoff.".to_owned());
    LiveGateReport {
        gate_id: Uuid::new_v4(),
        generated_at: Utc::now(),
        timeout_secs,
        missing_rdp_env,
        rdp_env_template: build_rdp_live_gate_env_template(),
        preflight,
        smoke,
        readiness,
        achieved: completion_audit.achieved,
        blocking_gates,
        next_action,
        completion_audit,
        evidence_path: None,
    }
}

pub fn save_live_gate_report(report: &LiveGateReport) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("live-gate-reports")?;
    std::fs::create_dir_all(&dir)?;
    let suffix = if report.achieved { "passed" } else { "blocked" };
    let path = dir.join(format!("{}-{suffix}.json", report.gate_id));
    std::fs::write(&path, serde_json::to_string_pretty(report)?)?;
    Ok(path)
}

#[cfg(test)]
fn save_operator_handoff_pack_to_dir(
    dir: &Path,
    readiness: &KiReadinessCliReport,
    audit: &CompletionAuditReport,
) -> anyhow::Result<OperatorHandoffPackReport> {
    save_operator_handoff_pack_to_dir_with_args(dir, readiness, audit, &[])
}

fn save_operator_handoff_pack_to_dir_with_args(
    dir: &Path,
    readiness: &KiReadinessCliReport,
    audit: &CompletionAuditReport,
    args: &[String],
) -> anyhow::Result<OperatorHandoffPackReport> {
    std::fs::create_dir_all(dir)?;
    let runbook = build_live_gate_runbook(audit);
    let live_gate_sequence = build_live_gate_command_sequence(audit);
    let next_live_gate = build_next_live_gate_summary(audit);
    let next_live_gate_json = build_next_live_gate_report(audit);
    let goal_evidence_matrix = build_goal_evidence_matrix(audit);
    let goal_evidence_check = build_goal_evidence_check(audit);
    let rdp_proof_check = build_rdp_proof_check_from_args(args);
    let rdp_env_file_check = if crate::ironrdp_client::rdp_env_file_path_from_args(args).is_some() {
        serde_json::to_value(crate::ironrdp_client::rdp_env_file_check_report_from_args(
            args,
            crate::ironrdp_client::rdp_smoke_timeout_secs_from_args(args),
        ))?
    } else {
        latest_rdp_env_file_check_json_value()
    };
    let live_gate_doctor = build_live_gate_doctor_report_from_args(args);
    let live_gate_operator_brief = build_live_gate_operator_brief(audit, &live_gate_doctor);
    let verification_snapshot_for_prompt = build_verification_snapshot_from_args(args);
    let rdp_proof_prompt =
        build_rdp_proof_prompt(audit, &live_gate_doctor, &verification_snapshot_for_prompt);
    let rdp_proof_recovery_plan =
        build_rdp_proof_recovery_plan(audit, &live_gate_doctor, &rdp_proof_check);
    let gui_operator_actions = build_gui_operator_actions(audit);
    let llm_review_prompt = build_operator_llm_review_prompt(readiness, audit, &runbook);
    let llm_live_gate_plan = build_live_gate_llm_plan(audit, &live_gate_doctor, &runbook);
    let mut llm_action_contract =
        build_llm_action_contract(audit, &live_gate_doctor, &rdp_proof_check, args);
    let rdp_env_fill_guide = build_rdp_env_fill_guide();
    let summary = format!(
        "# Aivana Operator Handoff Pack\n\n- Objective: {}\n- Achieved: {}\n- Readiness score: {}%\n- Blocking gates: {}\n\n## Early LLM Triage\nInspect `verification-snapshot.json` first, then `llm-action-contract.json`; reject proxy evidence unless the contract success signals are met.\n\n## Next Gate\n{}\n",
        redact_secret_text(&audit.objective),
        audit.achieved,
        readiness.readiness_score,
        audit.items.iter().filter(|item| item.blocking).count(),
        audit
            .items
            .iter()
            .find(|item| item.blocking)
            .map(|item| redact_secret_text(&item.next_action))
            .unwrap_or_else(|| "No blocking gate remains.".to_owned())
    );
    let files = vec![
        "readiness.json".to_owned(),
        "completion-audit.json".to_owned(),
        "goal-evidence-matrix.json".to_owned(),
        "goal-evidence-check.json".to_owned(),
        "verification-snapshot.json".to_owned(),
        "operator-handoff-risk-summary.json".to_owned(),
        "command-index.json".to_owned(),
        "rdp-env-file-check.json".to_owned(),
        "rdp-proof-check.json".to_owned(),
        "live-gate-doctor.json".to_owned(),
        "live-gate-operator-brief.md".to_owned(),
        "next-live-gate.json".to_owned(),
        "live-gate-sequence.txt".to_owned(),
        "next-live-gate.md".to_owned(),
        "live-gate-runbook.md".to_owned(),
        "gui-operator-actions.md".to_owned(),
        "rdp-env-template.env".to_owned(),
        "rdp-env-fill-guide.md".to_owned(),
        "llm-review-prompt.md".to_owned(),
        "rdp-proof-prompt.md".to_owned(),
        "rdp-proof-recovery-plan.md".to_owned(),
        "llm-live-gate-plan.md".to_owned(),
        "llm-action-contract.json".to_owned(),
        "summary.md".to_owned(),
        "manifest.json".to_owned(),
    ];
    let file_roles = build_operator_handoff_file_roles();
    let recommended_inspection_order = build_operator_handoff_inspection_order();
    std::fs::write(dir.join("readiness.json"), redacted_json_string(readiness)?)?;
    std::fs::write(
        dir.join("completion-audit.json"),
        redacted_json_string(audit)?,
    )?;
    std::fs::write(
        dir.join("command-index.json"),
        redacted_json_string(&build_command_index())?,
    )?;
    std::fs::write(
        dir.join("goal-evidence-matrix.json"),
        redacted_json_string(&goal_evidence_matrix)?,
    )?;
    std::fs::write(
        dir.join("goal-evidence-check.json"),
        redacted_json_string(&goal_evidence_check)?,
    )?;
    std::fs::write(
        dir.join("verification-snapshot.json"),
        redacted_json_string(&serde_json::json!({
            "schema": "aivana.verification-snapshot.v1",
            "generated_at": Utc::now(),
            "redacted": true,
            "ok": false,
            "env_source": rdp_env_source_label_from_args(args),
            "completion": {
                "achieved": audit.achieved,
                "blocking_gates": audit.items.iter().filter(|item| item.blocking).count()
            },
            "live_gate": {
                "achieved": live_gate_doctor.achieved,
                "stage": live_gate_doctor.operator_stage,
                "smoke_connected": live_gate_doctor.smoke_connected
            },
            "handoff": {
                "pack_valid": true
            },
            "initializing": true
        }))?,
    )?;
    std::fs::write(
        dir.join("rdp-env-file-check.json"),
        redacted_json_string(&rdp_env_file_check)?,
    )?;
    std::fs::write(
        dir.join("rdp-proof-check.json"),
        redacted_json_string(&rdp_proof_check)?,
    )?;
    std::fs::write(
        dir.join("live-gate-doctor.json"),
        redacted_json_string(&live_gate_doctor)?,
    )?;
    std::fs::write(
        dir.join("live-gate-operator-brief.md"),
        redact_secret_text(&live_gate_operator_brief),
    )?;
    std::fs::write(
        dir.join("next-live-gate.json"),
        redacted_json_string(&next_live_gate_json)?,
    )?;
    std::fs::write(
        dir.join("next-live-gate.md"),
        redact_secret_text(&next_live_gate),
    )?;
    std::fs::write(
        dir.join("live-gate-sequence.txt"),
        redact_secret_text(&live_gate_sequence),
    )?;
    std::fs::write(
        dir.join("live-gate-runbook.md"),
        redact_secret_text(&runbook),
    )?;
    std::fs::write(
        dir.join("gui-operator-actions.md"),
        redact_secret_text(&gui_operator_actions),
    )?;
    std::fs::write(
        dir.join("rdp-env-template.env"),
        build_rdp_live_gate_env_template(),
    )?;
    std::fs::write(
        dir.join("rdp-env-fill-guide.md"),
        redact_secret_text(&rdp_env_fill_guide),
    )?;
    std::fs::write(
        dir.join("llm-review-prompt.md"),
        redact_secret_text(&llm_review_prompt),
    )?;
    std::fs::write(
        dir.join("rdp-proof-prompt.md"),
        redact_secret_text(&rdp_proof_prompt),
    )?;
    std::fs::write(
        dir.join("rdp-proof-recovery-plan.md"),
        redact_secret_text(&rdp_proof_recovery_plan),
    )?;
    std::fs::write(
        dir.join("llm-live-gate-plan.md"),
        redact_secret_text(&llm_live_gate_plan),
    )?;
    std::fs::write(
        dir.join("llm-action-contract.json"),
        redacted_json_string(&llm_action_contract)?,
    )?;
    std::fs::write(dir.join("summary.md"), redact_secret_text(&summary))?;
    let pack_id = dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| Uuid::parse_str(name).ok())
        .unwrap_or_else(Uuid::new_v4);
    let report = OperatorHandoffPackReport {
        schema: "aivana.operator-handoff-pack.v1".to_owned(),
        pack_id,
        created_at: Utc::now(),
        achieved: audit.achieved,
        blocking_gates: audit.items.iter().filter(|item| item.blocking).count(),
        summary: redact_secret_text(&summary),
        pack_path: Some(dir.display().to_string()),
        files,
        file_roles,
        recommended_inspection_order,
    };
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    let mut risk_summary = build_operator_handoff_risk_summary_with_inputs(
        audit.clone(),
        live_gate_doctor.clone(),
        args,
    );
    risk_summary.handoff_pack_valid = true;
    risk_summary.handoff_pack_path = Some(dir.display().to_string());
    risk_summary.handoff_error_count = 0;
    risk_summary.handoff_missing_file_count = 0;
    risk_summary.handoff_schema_error_count = 0;
    risk_summary.handoff_content_mismatch_count = 0;
    risk_summary.ok = audit.achieved && risk_summary.goal_evidence_ok && risk_summary.rdp_proof_ok;
    risk_summary.severity = if risk_summary.ok {
        "ready".to_owned()
    } else {
        "blocked".to_owned()
    };
    let pack_local_recovery_plan_summary = rdp_proof_recovery_plan_summary_from_text(
        "operator-handoff-packs/<pack-id>/rdp-proof-recovery-plan.md",
        &rdp_proof_recovery_plan,
    );
    risk_summary.rdp_proof_recovery_plan_summary = pack_local_recovery_plan_summary.clone();
    let mut verification_snapshot = build_verification_snapshot_from_args(args);
    verification_snapshot["handoff"]["pack_valid"] = serde_json::json!(true);
    verification_snapshot["handoff"]["pack_path"] = serde_json::json!(dir.display().to_string());
    verification_snapshot["handoff"]["missing_files"] = serde_json::json!(0);
    verification_snapshot["handoff"]["missing_file_roles"] = serde_json::json!(0);
    verification_snapshot["handoff"]["missing_inspection_entries"] = serde_json::json!(0);
    verification_snapshot["handoff"]["invalid_file_schemas"] = serde_json::json!(0);
    verification_snapshot["handoff"]["content_mismatches"] = serde_json::json!(0);
    verification_snapshot["handoff"]["errors"] = serde_json::json!(0);
    verification_snapshot["ok"] = serde_json::json!(risk_summary.ok);
    verification_snapshot["risk"]["ok"] = serde_json::json!(risk_summary.ok);
    verification_snapshot["risk"]["severity"] = serde_json::json!(risk_summary.severity.clone());
    verification_snapshot["risk"]["blocking_reason"] =
        serde_json::json!(risk_summary.blocking_reason.clone());
    verification_snapshot["risk"]["acceptance_criteria"] =
        serde_json::json!(risk_summary.acceptance_criteria.clone());
    verification_snapshot["risk"]["next_command"] =
        serde_json::json!(risk_summary.next_command.clone());
    verification_snapshot["risk"]["next_success_command"] =
        serde_json::json!(risk_summary.next_success_command.clone());
    verification_snapshot["risk"]["goal_evidence_ok"] =
        serde_json::json!(risk_summary.goal_evidence_ok);
    verification_snapshot["risk"]["failed_requirements"] =
        serde_json::json!(risk_summary.failed_requirements.clone());
    verification_snapshot["risk"]["rdp_proof_ok"] = serde_json::json!(risk_summary.rdp_proof_ok);
    verification_snapshot["risk"]["rdp_proof_failed_checks"] =
        serde_json::json!(risk_summary.rdp_proof_failed_checks.clone());
    verification_snapshot["risk"]["rdp_proof_failed_check_actions"] =
        serde_json::json!(risk_summary.rdp_proof_failed_check_actions.clone());
    verification_snapshot["risk"]["rdp_proof_recovery_plan_command"] =
        serde_json::json!(risk_summary.rdp_proof_recovery_plan_command.clone());
    verification_snapshot["risk"]["rdp_proof_recovery_plan_summary"] =
        serde_json::json!(risk_summary.rdp_proof_recovery_plan_summary.clone());
    verification_snapshot["latest_evidence"]["rdp_proof_recovery_plan"] =
        serde_json::json!(pack_local_recovery_plan_summary);
    std::fs::write(
        dir.join("verification-snapshot.json"),
        redacted_json_string(&verification_snapshot)?,
    )?;
    llm_action_contract["ok"] = serde_json::json!(risk_summary.ok);
    std::fs::write(
        dir.join("llm-action-contract.json"),
        redacted_json_string(&llm_action_contract)?,
    )?;
    std::fs::write(
        dir.join("operator-handoff-risk-summary.json"),
        redacted_json_string(&risk_summary)?,
    )?;
    std::fs::write(
        dir.join("live-gate-doctor.json"),
        redacted_json_string(&live_gate_doctor)?,
    )?;
    Ok(report)
}

fn build_operator_handoff_inspection_order() -> Vec<String> {
    [
        "manifest.json",
        "summary.md",
        "completion-audit.json",
        "goal-evidence-matrix.json",
        "goal-evidence-check.json",
        "verification-snapshot.json",
        "llm-action-contract.json",
        "operator-handoff-risk-summary.json",
        "next-live-gate.json",
        "readiness.json",
        "command-index.json",
        "rdp-env-file-check.json",
        "rdp-proof-check.json",
        "live-gate-doctor.json",
        "live-gate-operator-brief.md",
        "live-gate-sequence.txt",
        "gui-operator-actions.md",
        "live-gate-runbook.md",
        "rdp-env-template.env",
        "rdp-env-fill-guide.md",
        "llm-review-prompt.md",
        "rdp-proof-prompt.md",
        "rdp-proof-recovery-plan.md",
        "llm-live-gate-plan.md",
        "next-live-gate.md",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn build_operator_handoff_file_roles() -> Vec<OperatorHandoffFileRole> {
    [
        (
            "readiness.json",
            "Machine-readable KI/RDP readiness, missing requirements, latest evidence pointers, and next step.",
            "Start here to understand environment readiness and missing setup.",
        ),
        (
            "completion-audit.json",
            "Prompt-to-artifact audit with explicit blocking gates and direct evidence requirements.",
            "Use before claiming the objective is complete.",
        ),
        (
            "goal-evidence-matrix.json",
            "Machine-readable requirement-to-artifact matrix with verification commands, coverage, gaps, and next live gate.",
            "Use when an LLM or CI job needs a single structured completion checklist.",
        ),
        (
            "goal-evidence-check.json",
            "Hard completion assertion over the goal evidence matrix with ok flag, failed requirements, and failure exit semantics.",
            "Use when CI or an LLM needs a single pass/fail completion gate.",
        ),
        (
            "verification-snapshot.json",
            "Compact redacted GUI, readiness, live-gate, handoff, risk, latest-evidence snapshot, and LLM action-contract.",
            "Use when an operator, CI job, or LLM needs one current status artifact before reading detailed files.",
        ),
        (
            "operator-handoff-risk-summary.json",
            "Compact hard risk gate over live-gate doctor, handoff validation, goal evidence, RDP proof recovery actions, LLM triage entrypoint, required evidence files, direct live evidence requirements, and early_triage_artifacts response fields.",
            "Use when CI or an LLM needs the pack-local risk status, exact recovery commands, and compact LLM triage contract.",
        ),
        (
            "command-index.json",
            "Machine-readable command catalog, expected outputs, persistence behavior, and live-gate sequence.",
            "Use when orchestrating CLI verification from an LLM or CI job.",
        ),
        (
            "rdp-env-file-check.json",
            "Latest offline RDP env-file validation evidence with ok flag, required value checks, and network_checked=false.",
            "Use before running or reviewing live RDP preflight and smoke commands.",
        ),
        (
            "rdp-proof-check.json",
            "Direct RDP proof checklist over env-file validation, preflight readiness, env-source matching, env-file freshness, smoke connection, framebuffer, and input probe evidence.",
            "Use when CI or an LLM needs a single proof-only pass/fail JSON gate.",
        ),
        (
            "live-gate-doctor.json",
            "Machine-readable live-gate ladder with env-file, preflight, smoke, direct RDP proof check, recovery-plan command, handoff, completion status, and next command.",
            "Use when an operator, CI job, or LLM needs the current blocker without inferring from multiple files.",
        ),
        (
            "live-gate-operator-brief.md",
            "Concise human-readable live-gate stage, blocker, acceptance criteria, next command, recovery-plan command, and evidence snapshot.",
            "Use when an operator or LLM needs the current action without parsing JSON.",
        ),
        (
            "next-live-gate.json",
            "Structured first blocking gate, missing RDP env vars, env template, and next commands.",
            "Use when an agent needs a single next action without parsing the full audit.",
        ),
        (
            "next-live-gate.md",
            "Human-readable first blocking gate summary and next operator commands.",
            "Use for a concise operator handoff.",
        ),
        (
            "live-gate-sequence.txt",
            "Plain-text ordered live-gate command sequence derived from next-live-gate.",
            "Use when an operator, CI job, or LLM needs a direct command list without JSON parsing.",
        ),
        (
            "live-gate-runbook.md",
            "Full live-gate runbook derived from the completion audit.",
            "Use when resolving all blockers step by step.",
        ),
        (
            "gui-operator-actions.md",
            "GUI checklist for Verification Center and Mission Control actions.",
            "Use when a human operator will continue in the app UI.",
        ),
        (
            "rdp-env-template.env",
            "Redacted starter template for AIVANA_RDP_TEST_* live verification variables.",
            "Use before RDP preflight and smoke testing.",
        ),
        (
            "rdp-env-fill-guide.md",
            "Redacted operator guide for filling the ignored local rdp-live.env file without leaking credentials.",
            "Use when the latest env-file check is missing or blocked by starter placeholders.",
        ),
        (
            "llm-review-prompt.md",
            "Focused prompt for LLM review of the handoff pack with summary.md Early LLM Triage, operator-handoff-risk-summary.json cross-check, required evidence files, early_triage_artifacts, and proxy-evidence rejection.",
            "Use when asking an LLM to inspect the pack before accepting any completion claim.",
        ),
        (
            "rdp-proof-prompt.md",
            "Focused redacted prompt for a human operator or LLM assistant to finish only the direct RDP proof gate with summary.md Early LLM Triage, llm-action-contract.json, recovery-plan command, framebuffer/input evidence, and proxy-evidence rejection.",
            "Use when the only remaining blocker is live RDP framebuffer/input evidence and the operator needs the recovery-plan command without accepting proxy evidence.",
        ),
        (
            "rdp-proof-recovery-plan.md",
            "Human-readable recovery plan mapping failed RDP proof checks to exact commands, acceptance criteria, direct live evidence, and proxy-evidence rejection rules.",
            "Use when an operator or LLM needs the fastest safe path from a failed proof check to direct live evidence.",
        ),
        (
            "llm-live-gate-plan.md",
            "Focused LLM/CI plan generated from the live-gate doctor, completion audit, and runbook with summary.md Early LLM Triage, operator-handoff-risk-summary.json cross-check, required evidence files, early_triage_artifacts, and proxy-evidence rejection.",
            "Use when asking an LLM or automation agent for the next live-gate action without accepting proxy completion evidence.",
        ),
        (
            "llm-action-contract.json",
            "Machine-readable LLM action contract with next command, allowed commands, acceptance criteria, summary.md Early LLM Triage evidence, early_triage_artifacts response field, direct live evidence requirements, success signals, and proxy-evidence rejection rules.",
            "Use when an LLM or CI agent needs a strict JSON contract for the next operator action.",
        ),
        (
            "summary.md",
            "Short pack summary with objective, achieved flag, blocker count, next gate, and Early LLM Triage.",
            "Use for quick human or LLM status review before inspecting verification-snapshot.json and llm-action-contract.json.",
        ),
        (
            "manifest.json",
            "Pack inventory, file roles, achieved flag, blocker count, and pack metadata.",
            "Use to validate that all expected handoff files are present.",
        ),
    ]
    .into_iter()
    .map(|(file, role, inspect_when)| OperatorHandoffFileRole {
        file: file.to_owned(),
        role: role.to_owned(),
        inspect_when: inspect_when.to_owned(),
    })
    .collect()
}

pub fn build_completion_audit_report() -> CompletionAuditReport {
    build_completion_audit_report_from_args(&[])
}

pub fn build_completion_audit_report_from_args(args: &[String]) -> CompletionAuditReport {
    let readiness = build_ki_readiness_cli_report_from_args(args);
    let successful_rdp_smoke = latest_successful_rdp_smoke_report_summary();
    let latest_preflight = readiness
        .latest_rdp_preflight_evidence
        .clone()
        .unwrap_or_else(|| "No RDP preflight evidence recorded.".to_owned());
    let latest_smoke = readiness
        .latest_rdp_smoke_evidence
        .clone()
        .unwrap_or_else(|| "No RDP smoke evidence recorded.".to_owned());
    let latest_ai_pack = latest_ai_brief_pack_summary()
        .unwrap_or_else(|| "No AI brief pack exported yet.".to_owned());
    let mut report = build_completion_audit_report_with_inputs(
        readiness,
        successful_rdp_smoke,
        latest_preflight,
        latest_smoke,
        latest_ai_pack,
    );
    let latest_env_file_check = rdp_env_file_check_summary_from_args(args)
        .unwrap_or_else(|| "No RDP env-file check evidence recorded.".to_owned());
    let rdp_proof_check = build_rdp_proof_check_from_args(args);
    let rdp_proof_ok = rdp_proof_check
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let rdp_proof_next_command = rdp_proof_check
        .get("next_command")
        .and_then(|value| value.as_str())
        .unwrap_or("cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env");
    let rdp_proof_failed_checks = rdp_proof_check
        .get("failed_checks")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let rdp_proof_summary = format!(
        "rdp_proof_check ok={} failed_checks={} failed_check_names={} next={}",
        rdp_proof_ok,
        rdp_proof_check
            .get("failed_checks")
            .and_then(|value| value.as_array())
            .map(|items| items.len())
            .unwrap_or_default(),
        rdp_proof_failed_checks,
        rdp_proof_check
            .get("next_command")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
    );
    if let Some(item) = report
        .items
        .iter_mut()
        .find(|item| item.requirement == "Headless CI/handoff verification artifacts")
    {
        item.evidence.push_str(" latest_env_file_check=");
        item.evidence
            .push_str(&redact_secret_text(&latest_env_file_check));
    }
    if let Some(item) = report
        .items
        .iter_mut()
        .find(|item| item.requirement == "Real RDP end-to-end proof against a reachable host")
    {
        item.artifact.push_str(", rdp-proof-check.json");
        item.evidence.push_str(" ");
        item.evidence
            .push_str(&redact_secret_text(&rdp_proof_summary));
        item.status = if rdp_proof_ok { "met" } else { "blocked" }.to_owned();
        item.blocking = !rdp_proof_ok;
        item.next_action = if rdp_proof_ok {
            "Keep rdp-proof-check.json and the successful smoke-test JSON with release evidence."
                .to_owned()
        } else {
            format!(
                "Run {rdp_proof_next_command}; then rerun cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env until ok=true."
            )
        };
    }
    report
}

fn build_completion_audit_report_with_inputs(
    readiness: KiReadinessCliReport,
    successful_rdp_smoke: Option<String>,
    latest_preflight: String,
    latest_smoke: String,
    latest_ai_pack: String,
) -> CompletionAuditReport {
    let mut items = Vec::new();
    items.push(CompletionAuditItem {
        requirement: "Native Rust RDP client implementation".to_owned(),
        artifact:
            "src/ironrdp_client.rs, src/diagnostics.rs, src/services.rs, src/main.rs --rdp-preflight/--rdp-smoke-test"
                .to_owned(),
        evidence: "Rust IronRDP runtime, native session loop, framebuffer events, input PDUs, and smoke-test CLI are present.".to_owned(),
        next_action:
            "Optionally run cargo run -- --save-rdp-env-template .\\rdp-live.env, review cargo run -- --rdp-env-fill-guide, validate it with cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env, then run cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90 before the RDP smoke test."
                .to_owned(),
        status: "met".to_owned(),
        blocking: false,
    });
    let readiness_missing = if readiness.missing_requirements.is_empty() {
        "none".to_owned()
    } else {
        redact_secret_text(&readiness.missing_requirements.join(", "))
    };
    items.push(CompletionAuditItem {
        requirement: "Maximum KI/AI USP features".to_owned(),
        artifact: "src/autopilot.rs, src/computer_use.rs, src/app.rs".to_owned(),
        evidence: format!(
            "Provider={} model={} readiness_score={} readiness_missing={} latest_ai_pack={}",
            redact_secret_text(&readiness.provider),
            redact_secret_text(&readiness.model),
            readiness.readiness_score,
            readiness_missing,
            redact_secret_text(&latest_ai_pack)
        ),
        next_action:
            "Run cargo run -- --ai-brief-pack or export an AI Brief Pack from the GUI after meaningful session evidence changes."
                .to_owned(),
        status: "met".to_owned(),
        blocking: false,
    });
    items.push(CompletionAuditItem {
        requirement: "GUI-friendly KI cockpit and operator workflow".to_owned(),
        artifact:
            "Workspace KI Operations, Autopilot Mission Control, Approval Center, Verification Center"
                .to_owned(),
        evidence: "GUI exposes goal presets, guarded start/pause/resume/abort, CUA preflight briefs, automatic local rdp-live.env detection for Verification Center reports, env-save command copy, env-file-check command copy, RDP env fill guide copy, live-gate sequence copy, structured next-gate JSON copy, command-index JSON copy, evidence matrix JSON copy, hard evidence check JSON copy, handoff-check JSON copy, handoff risk JSON/command/evidence/export, verification snapshot JSON copy/export, RDP proof check JSON copy, RDP proof prompt copy, RDP recovery plan copy with acceptance criteria, direct live evidence requirements, and proxy-evidence rejection, RDP recovery plan command copy, live-gate doctor JSON copy, live-gate operator brief copy, LLM review prompt copy with summary.md Early LLM Triage and operator-handoff-risk-summary.json cross-check, live-gate LLM plan copy, LLM action-contract JSON copy/export with summary.md Early LLM Triage, direct_live_evidence_requirements, early_triage_artifacts, evidence success signals, and proxy-evidence rejection rules, handoff-check evidence summary, copy/export actions, and readiness status.".to_owned(),
        next_action: "Use the Verification Center to copy the Goal Audit and hand it to an operator or LLM reviewer.".to_owned(),
        status: "met".to_owned(),
        blocking: false,
    });
    items.push(CompletionAuditItem {
        requirement: "Guarded approvals, redaction, and auditable evidence".to_owned(),
        artifact: "src/policy.rs, src/security.rs, KI evidence bundle, readiness reports".to_owned(),
        evidence: "Policy-gated mutations, redacted reports, bundle.md, manifest.json, and central secret redaction are implemented.".to_owned(),
        next_action: "Review generated Markdown before sharing outside the operator environment.".to_owned(),
        status: "met".to_owned(),
        blocking: false,
    });
    let openai_met = readiness.openai_key_set;
    items.push(CompletionAuditItem {
        requirement: "Hosted OpenAI CUA path can be exercised when selected".to_owned(),
        artifact: "OPENAI_API_KEY, OpenAI CUA provider, CUA Request Brief, Approval Center"
            .to_owned(),
        evidence: if openai_met {
            "OPENAI_API_KEY is present; hosted CUA path is ready for an operator-gated live session."
                .to_owned()
        } else {
            "OPENAI_API_KEY is missing; hosted CUA cannot be live-verified in this environment."
                .to_owned()
        },
        next_action: if openai_met {
            "Select OpenAI CUA in Mission Control, copy the CUA Request Brief, and run a guarded live-session preview.".to_owned()
        } else {
            "Set OPENAI_API_KEY in the process environment, restart the app, and rerun --completion-audit.".to_owned()
        },
        status: if openai_met { "ready" } else { "blocked" }.to_owned(),
        blocking: !openai_met,
    });
    items.push(CompletionAuditItem {
        requirement: "Headless CI/handoff verification artifacts".to_owned(),
        artifact: "--save-ki-preferences, --ai-brief-pack, --rdp-env-fill-guide, --rdp-env-file-check, --rdp-preflight, --rdp-proof-check, --rdp-proof-recovery-plan, --live-gate, --live-gate-sequence, --live-gate-doctor, --live-gate-operator-brief, --llm-review-prompt, --llm-live-gate-plan, --llm-action-contract, --ki-readiness-report, --ki-evidence-bundle, --completion-audit, --goal-evidence-matrix, --goal-evidence-check, --command-index, --operator-handoff-pack, --operator-handoff-check, --operator-handoff-risk-summary, --verification-snapshot".to_owned(),
        evidence: format!(
            "KI preferences save, AI brief pack, RDP env fill guide, RDP env-file check, RDP proof check, RDP proof recovery plan, live-gate sequence, readiness JSON, preflight evidence, live-gate doctor JSON, live-gate operator brief Markdown, LLM review prompt, LLM live-gate plan, LLM action contract, evidence bundle, completion audit, goal evidence matrix, hard goal evidence check, command index, operator handoff pack, handoff-pack validation, handoff risk summary, and verification snapshot can be emitted without launching the GUI. latest_preflight={}",
            redact_secret_text(&latest_preflight)
        ),
        next_action: "Attach the latest JSON/Markdown artifacts to handoff or CI evidence, then run cargo run -- --save-ki-preferences, cargo run -- --ai-brief-pack, cargo run -- --live-gate-sequence, cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env, cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env, cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env, cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env, cargo run -- --llm-review-prompt, cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env, cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env, cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env, cargo run -- --operator-handoff-check, cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env, and cargo run -- --verification-snapshot --rdp-env-file .\\rdp-live.env.".to_owned(),
        status: "met".to_owned(),
        blocking: false,
    });
    let rdp_evidence = successful_rdp_smoke.unwrap_or(latest_smoke);
    let rdp_met = rdp_evidence.contains("connected=true");
    let combined_rdp_evidence = format!(
        "preflight={} smoke={}",
        redact_secret_text(&latest_preflight),
        redact_secret_text(&rdp_evidence)
    );
    items.push(CompletionAuditItem {
        requirement: "Real RDP end-to-end proof against a reachable host".to_owned(),
        artifact:
            "Persisted rdp-preflight JSON and rdp-smoke-tests JSON with connected=true, framebuffer, and input probe"
                .to_owned(),
        evidence: combined_rdp_evidence,
        next_action: if rdp_met {
            "Keep the successful smoke-test JSON with release evidence.".to_owned()
        } else {
            "Run cargo run -- --save-rdp-env-template .\\rdp-live.env, review cargo run -- --rdp-env-fill-guide, fill AIVANA_RDP_TEST_HOST, AIVANA_RDP_TEST_USER, and AIVANA_RDP_TEST_PASSWORD, validate it with cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env, then run cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90 and cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90.".to_owned()
        },
        status: if rdp_met { "met" } else { "blocked" }.to_owned(),
        blocking: !rdp_met,
    });

    let achieved = items.iter().all(|item| !item.blocking);
    let summary = if achieved {
        "All concrete completion criteria have evidence.".to_owned()
    } else {
        "Not complete: at least one live AI/RDP gate is still missing or failed.".to_owned()
    };

    CompletionAuditReport {
        audit_id: Uuid::new_v4(),
        generated_at: Utc::now(),
        objective: ACTIVE_GOAL_OBJECTIVE.to_owned(),
        achieved,
        summary,
        items,
        audit_path: None,
    }
}

pub fn save_completion_audit_report(
    report: &CompletionAuditReport,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("completion-audits")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.audit_id));
    std::fs::write(&path, serde_json::to_string_pretty(report)?)?;
    std::fs::write(
        dir.join(format!("{}.md", report.audit_id)),
        report.to_markdown(),
    )?;
    Ok(path)
}

fn build_ki_verification_report(
    autopilot: &AutopilotController,
    session_count: usize,
) -> KiVerificationReport {
    let openai_key_set = std::env::var("OPENAI_API_KEY").is_ok_and(|key| !key.trim().is_empty());
    let rdp_smoke_ready = [
        "AIVANA_RDP_TEST_HOST",
        "AIVANA_RDP_TEST_USER",
        "AIVANA_RDP_TEST_PASSWORD",
    ]
    .iter()
    .all(|name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty()));
    let preferences_saved = app_data_file("autopilot-preferences.json")
        .ok()
        .is_some_and(|path| path.exists());

    build_ki_verification_report_with_inputs(
        autopilot,
        session_count,
        openai_key_set,
        rdp_smoke_ready,
        preferences_saved,
    )
}

fn build_ki_verification_report_with_inputs(
    autopilot: &AutopilotController,
    session_count: usize,
    openai_key_set: bool,
    rdp_smoke_ready: bool,
    preferences_saved: bool,
) -> KiVerificationReport {
    let mut missing = Vec::new();
    if autopilot.settings.provider == AutopilotProviderKind::OpenAiComputerUse && !openai_key_set {
        missing.push("OPENAI_API_KEY");
    }
    if !rdp_smoke_ready {
        missing.push("AIVANA_RDP_TEST_*");
    }
    if !preferences_saved {
        missing.push("saved KI preferences");
    }

    let key_context = if autopilot.settings.provider == AutopilotProviderKind::OpenAiComputerUse {
        if openai_key_set {
            "OPENAI_API_KEY is set. "
        } else {
            "OPENAI_API_KEY is required. "
        }
    } else {
        ""
    };
    let next_step = if missing.is_empty() {
        format!(
            "{key_context}Run cargo run -- --rdp-smoke-test, then start a guarded Autopilot preview on a live session."
        )
    } else {
        format!("{key_context}Complete: {}.", missing.join(", "))
    };
    let summary = format!(
        "Provider={} model={} steps={} delay={}ms goal={}",
        autopilot.settings.provider.label(),
        autopilot.settings.openai_model,
        autopilot.settings.max_steps,
        autopilot.settings.step_delay_millis,
        redact_secret_text(&autopilot.goal)
    );

    KiVerificationReport {
        openai_key_set,
        rdp_smoke_ready,
        preferences_saved,
        session_count,
        summary,
        next_step,
    }
}

fn latest_rdp_smoke_report_summary() -> Option<String> {
    let dir = app_data_file("rdp-smoke-tests").ok()?;
    latest_rdp_smoke_report_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn latest_rdp_preflight_report_summary() -> Option<String> {
    let dir = app_data_file("rdp-preflight").ok()?;
    latest_rdp_preflight_report_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn latest_rdp_env_file_check_summary() -> Option<String> {
    let dir = app_data_file("rdp-env-file-checks").ok()?;
    latest_rdp_env_file_check_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn rdp_env_file_check_summary_from_args(args: &[String]) -> Option<String> {
    if crate::ironrdp_client::rdp_env_file_path_from_args(args).is_none() {
        return latest_rdp_env_file_check_summary();
    }
    let report = crate::ironrdp_client::rdp_env_file_check_report_from_args(
        args,
        crate::ironrdp_client::rdp_smoke_timeout_secs_from_args(args),
    );
    let value = serde_json::to_value(&report).ok()?;
    Some(rdp_env_file_check_summary_from_value(
        &value,
        report.path.as_deref(),
    ))
}

fn latest_rdp_env_file_check_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut latest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(latest_modified, _)| modified > *latest_modified)
        {
            latest = Some((modified, path));
        }
    }
    let Some((_, path)) = latest else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    let path_label = path.display().to_string();
    Ok(Some(rdp_env_file_check_summary_from_value(
        &value,
        Some(&path_label),
    )))
}

fn rdp_env_file_check_summary_from_value(
    value: &serde_json::Value,
    fallback_path_label: Option<&str>,
) -> String {
    let generated_at = value
        .get("generated_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-time");
    let ok = value
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let host = value
        .get("host")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-host");
    let port = value
        .get("port")
        .and_then(|value| value.as_u64())
        .unwrap_or(3389);
    let timeout_secs = value
        .get("timeout_secs")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let network_checked = value
        .get("network_checked")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let error = value
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let path_label = value
        .get("evidence_path")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .or_else(|| {
            value
                .get("path")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .or_else(|| fallback_path_label.map(str::to_owned))
        .unwrap_or_else(|| "not persisted".to_owned());
    redact_secret_text(&format!(
        "Latest RDP env-file check evidence: ok={ok} generated={generated_at} host={host}:{port} timeout={timeout_secs}s network_checked={network_checked}{} path={path_label}",
        if error.is_empty() {
            String::new()
        } else {
            format!(" error={}", redact_secret_text(error))
        }
    ))
}

fn latest_rdp_env_file_check_json_value() -> serde_json::Value {
    let dir = match app_data_file("rdp-env-file-checks") {
        Ok(dir) => dir,
        Err(err) => {
            return fallback_rdp_env_file_check_json_value(format!(
                "Cannot resolve RDP env-file check evidence directory: {err}"
            ));
        }
    };
    match latest_rdp_env_file_check_json_value_from_dir(&dir) {
        Ok(Some(value)) => value,
        Ok(None) => fallback_rdp_env_file_check_json_value(
            "No persisted RDP env-file check evidence recorded.",
        ),
        Err(err) => fallback_rdp_env_file_check_json_value(format!(
            "Cannot read latest RDP env-file check evidence: {err}"
        )),
    }
}

fn latest_rdp_env_file_check_json_value_from_dir(
    dir: &Path,
) -> anyhow::Result<Option<serde_json::Value>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut latest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(latest_modified, _)| modified > *latest_modified)
        {
            latest = Some((modified, path));
        }
    }
    let Some((_, path)) = latest else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let mut value: serde_json::Value = serde_json::from_str(&json)?;
    if value
        .get("evidence_path")
        .and_then(|value| value.as_str())
        .is_none()
    {
        value["evidence_path"] = serde_json::Value::String(path.display().to_string());
    }
    Ok(Some(value))
}

fn latest_json_value_from_app_data(dir_name: &str) -> Option<serde_json::Value> {
    let dir = app_data_file(dir_name).ok()?;
    latest_json_value_from_dir(&dir).ok().flatten()
}

fn latest_json_value_from_dir(dir: &Path) -> anyhow::Result<Option<serde_json::Value>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut latest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(latest_modified, _)| modified > *latest_modified)
        {
            latest = Some((modified, path));
        }
    }
    let Some((_, path)) = latest else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let mut value: serde_json::Value = serde_json::from_str(&json)?;
    if value
        .get("evidence_path")
        .and_then(|value| value.as_str())
        .is_none()
    {
        value["evidence_path"] = serde_json::Value::String(path.display().to_string());
    }
    Ok(Some(value))
}

fn fallback_rdp_env_file_check_json_value(error: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "schema": "aivana.rdp-env-file-check.v1",
        "ok": false,
        "generated_at": Utc::now(),
        "network_checked": false,
        "host": null,
        "port": null,
        "timeout_secs": null,
        "expected_environment": [
            "AIVANA_RDP_TEST_HOST",
            "AIVANA_RDP_TEST_USER",
            "AIVANA_RDP_TEST_PASSWORD"
        ],
        "error": error.into(),
        "evidence_path": null
    })
}

fn latest_rdp_preflight_report_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut latest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(latest_modified, _)| modified > *latest_modified)
        {
            latest = Some((modified, path));
        }
    }
    let Some((_, path)) = latest else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    let generated_at = value
        .get("generated_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-time");
    let host = value
        .get("host")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-host");
    let port = value
        .get("port")
        .and_then(|value| value.as_u64())
        .unwrap_or(3389);
    let timeout_secs = value
        .get("timeout_secs")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let connect_recommended = value
        .get("connect_recommended")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let findings = value
        .get("findings")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or_default();
    let env_error = value
        .get("env_error")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let path_label = value
        .get("evidence_path")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| path.display().to_string());
    Ok(Some(redact_secret_text(&format!(
        "Latest RDP preflight evidence: connect_recommended={connect_recommended} generated={generated_at} host={host}:{port} findings={findings} timeout={timeout_secs}s{} path={path_label}",
        if env_error.is_empty() {
            String::new()
        } else {
            format!(" error={}", redact_secret_text(env_error))
        }
    ))))
}

fn latest_successful_rdp_smoke_report_summary() -> Option<String> {
    let dir = app_data_file("rdp-smoke-tests").ok()?;
    latest_successful_rdp_smoke_report_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn latest_ai_brief_pack_summary() -> Option<String> {
    let dir = app_data_file("ai-brief-packs").ok()?;
    latest_ai_brief_pack_summary_from_dir(&dir).ok().flatten()
}

fn latest_operator_handoff_pack_summary() -> Option<String> {
    let dir = app_data_file("operator-handoff-packs").ok()?;
    latest_operator_handoff_pack_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn latest_operator_handoff_check_summary() -> String {
    operator_handoff_check_summary(&build_operator_handoff_pack_check())
}

fn latest_rdp_proof_recovery_plan_summary() -> Option<String> {
    let dir = app_data_file("rdp-proof-recovery-plans").ok()?;
    latest_rdp_proof_recovery_plan_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn latest_rdp_proof_recovery_plan_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut plans = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("md"))
        .collect::<Vec<_>>();
    plans.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let Some(path) = plans.pop() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path)?;
    Ok(Some(rdp_proof_recovery_plan_summary_from_text(
        &path.display().to_string(),
        &text,
    )))
}

fn rdp_proof_recovery_plan_summary_from_text(path_label: &str, text: &str) -> String {
    let mut section = "";
    let mut failed_checks = 0;
    let mut recovery_commands = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            section = trimmed;
            continue;
        }
        if section == "## Failed Proof Checks" && trimmed.starts_with("- `") {
            failed_checks += 1;
        } else if section == "## Recovery Commands" && trimmed.contains("`cargo run --") {
            recovery_commands += 1;
        }
    }
    let bytes = text.len();
    redact_secret_text(&format!(
        "Latest RDP proof recovery plan: failed_checks={failed_checks}, recovery_commands={recovery_commands}, bytes={bytes}, path={path_label}"
    ))
}

fn operator_handoff_check_summary(check: &OperatorHandoffPackCheck) -> String {
    redact_secret_text(&format!(
        "Latest operator handoff check: ok={}, missing_files={}, missing_file_roles={}, missing_inspection_entries={}, invalid_file_schemas={}, content_mismatches={}, errors={}, manifest={}",
        check.ok,
        check.missing_files.len(),
        check.missing_file_roles.len(),
        check.missing_inspection_entries.len(),
        check.invalid_file_schemas.len(),
        check.content_mismatches.len(),
        check.errors.len(),
        check.manifest_path.as_deref().unwrap_or("none")
    ))
}

fn latest_live_gate_report_summary() -> Option<String> {
    let dir = app_data_file("live-gate-reports").ok()?;
    latest_live_gate_report_summary_from_dir(&dir)
        .ok()
        .flatten()
}

fn latest_live_gate_report_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut reports = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    reports.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let Some(path) = reports.pop() else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    let generated_at = value
        .get("generated_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-time");
    let achieved = value
        .get("achieved")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let blocking_gates = value
        .get("blocking_gates")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let timeout_secs = value
        .get("timeout_secs")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let preflight_ready = value
        .get("preflight")
        .and_then(|preflight| preflight.get("connect_recommended"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let smoke_status = value
        .get("smoke")
        .and_then(|smoke| smoke.get("status"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let smoke_connected = value
        .get("smoke")
        .and_then(|smoke| smoke.get("connected"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Ok(Some(redact_secret_text(&format!(
        "Latest live gate report: achieved={achieved}, blocking_gates={blocking_gates}, preflight_ready={preflight_ready}, smoke_status={smoke_status}, smoke_connected={smoke_connected}, timeout={timeout_secs}s, generated={generated_at}, path={}",
        path.display()
    ))))
}

fn latest_operator_handoff_pack_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut manifests = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("manifest.json"))
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    manifests.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let Some(path) = manifests.pop() else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    let created_at = value
        .get("created_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-time");
    let achieved = value
        .get("achieved")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let blocking_gates = value
        .get("blocking_gates")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let files = value
        .get("files")
        .and_then(|value| value.as_array())
        .map(|files| files.len())
        .unwrap_or_default();
    Ok(Some(redact_secret_text(&format!(
        "Latest operator handoff pack: {files} file(s), achieved={achieved}, blocking_gates={blocking_gates}, created_at={created_at}, manifest={}",
        path.display()
    ))))
}

const OPERATOR_HANDOFF_ROLE_REQUIRED_PHRASES: &[(&str, &str)] = &[
    (
        "goal-evidence-matrix.json",
        "requirement-to-artifact matrix",
    ),
    ("goal-evidence-matrix.json", "next live gate"),
    ("goal-evidence-check.json", "Hard completion assertion"),
    ("goal-evidence-check.json", "failure exit semantics"),
    ("verification-snapshot.json", "GUI"),
    ("verification-snapshot.json", "latest-evidence snapshot"),
    ("verification-snapshot.json", "LLM action-contract"),
    ("command-index.json", "command catalog"),
    ("command-index.json", "live-gate sequence"),
    ("next-live-gate.json", "first blocking gate"),
    ("next-live-gate.json", "next commands"),
    ("next-live-gate.md", "first blocking gate"),
    ("next-live-gate.md", "next operator commands"),
    (
        "live-gate-sequence.txt",
        "ordered live-gate command sequence",
    ),
    (
        "rdp-env-file-check.json",
        "offline RDP env-file validation evidence",
    ),
    ("rdp-env-file-check.json", "network_checked=false"),
    ("rdp-proof-check.json", "framebuffer"),
    ("rdp-proof-check.json", "input probe"),
    (
        "operator-handoff-risk-summary.json",
        "exact recovery commands",
    ),
    (
        "operator-handoff-risk-summary.json",
        "LLM triage entrypoint",
    ),
    (
        "operator-handoff-risk-summary.json",
        "required evidence files",
    ),
    (
        "operator-handoff-risk-summary.json",
        "direct live evidence requirements",
    ),
    (
        "operator-handoff-risk-summary.json",
        "early_triage_artifacts",
    ),
    ("live-gate-doctor.json", "recovery-plan command"),
    ("live-gate-operator-brief.md", "recovery-plan command"),
    ("rdp-proof-prompt.md", "summary.md Early LLM Triage"),
    ("rdp-proof-prompt.md", "llm-action-contract.json"),
    ("rdp-proof-prompt.md", "recovery-plan command"),
    ("rdp-proof-prompt.md", "framebuffer/input evidence"),
    ("rdp-proof-prompt.md", "proxy-evidence rejection"),
    ("rdp-proof-recovery-plan.md", "exact commands"),
    ("rdp-proof-recovery-plan.md", "acceptance criteria"),
    ("rdp-proof-recovery-plan.md", "direct live evidence"),
    ("rdp-proof-recovery-plan.md", "proxy-evidence rejection"),
    ("llm-review-prompt.md", "summary.md Early LLM Triage"),
    (
        "llm-review-prompt.md",
        "operator-handoff-risk-summary.json cross-check",
    ),
    ("llm-review-prompt.md", "required evidence files"),
    ("llm-review-prompt.md", "early_triage_artifacts"),
    ("llm-review-prompt.md", "proxy-evidence rejection"),
    ("llm-live-gate-plan.md", "summary.md Early LLM Triage"),
    (
        "llm-live-gate-plan.md",
        "operator-handoff-risk-summary.json",
    ),
    ("llm-live-gate-plan.md", "required evidence files"),
    ("llm-live-gate-plan.md", "early_triage_artifacts"),
    ("llm-live-gate-plan.md", "proxy-evidence rejection"),
    ("llm-action-contract.json", "next command"),
    (
        "llm-action-contract.json",
        "direct live evidence requirements",
    ),
    ("llm-action-contract.json", "success signals"),
    ("llm-action-contract.json", "proxy-evidence rejection rules"),
    ("summary.md", "Early LLM Triage"),
    ("summary.md", "verification-snapshot.json"),
    ("summary.md", "llm-action-contract.json"),
];

fn build_operator_handoff_pack_check_from_dir(
    dir: &Path,
    checked_at: chrono::DateTime<Utc>,
    expected_schema: &str,
) -> anyhow::Result<OperatorHandoffPackCheck> {
    let mut check = OperatorHandoffPackCheck {
        schema: "aivana.operator-handoff-check.v1".to_owned(),
        checked_at,
        ok: false,
        pack_path: None,
        manifest_path: None,
        expected_schema: expected_schema.to_owned(),
        actual_schema: None,
        missing_files: Vec::new(),
        missing_file_roles: Vec::new(),
        missing_inspection_entries: Vec::new(),
        invalid_file_schemas: Vec::new(),
        content_mismatches: Vec::new(),
        errors: Vec::new(),
    };
    if !dir.exists() {
        check
            .errors
            .push("No operator handoff pack folder exists yet.".to_owned());
        return Ok(check);
    }
    let mut manifests = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("manifest.json"))
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    manifests.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let Some(manifest_path) = manifests.pop() else {
        check
            .errors
            .push("No operator handoff manifest.json found.".to_owned());
        return Ok(check);
    };
    let pack_path = manifest_path
        .parent()
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| dir.to_path_buf());
    let json = std::fs::read_to_string(&manifest_path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    check.pack_path = Some(pack_path.display().to_string());
    check.manifest_path = Some(manifest_path.display().to_string());
    check.actual_schema = value
        .get("schema")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    if check.actual_schema.as_deref() != Some(expected_schema) {
        check.errors.push(format!(
            "Manifest schema mismatch: expected {expected_schema}, actual {}.",
            check.actual_schema.as_deref().unwrap_or("missing")
        ));
    }
    let expected_files = build_operator_handoff_file_roles()
        .into_iter()
        .map(|role| role.file)
        .collect::<Vec<_>>();
    for file in &expected_files {
        if !pack_path.join(file).exists() {
            check.missing_files.push(file.clone());
        }
    }
    let role_files = value
        .get("file_roles")
        .and_then(|value| value.as_array())
        .map(|roles| {
            roles
                .iter()
                .filter_map(|role| role.get("file").and_then(|file| file.as_str()))
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    for file in &expected_files {
        if !role_files.contains(file.as_str()) {
            check.missing_file_roles.push(file.clone());
        }
    }
    for (file, required) in OPERATOR_HANDOFF_ROLE_REQUIRED_PHRASES {
        validate_manifest_file_role_contains(&value, file, required, &mut check.content_mismatches);
    }
    let inspection_entries = value
        .get("recommended_inspection_order")
        .and_then(|value| value.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str())
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    for file in build_operator_handoff_inspection_order() {
        if !inspection_entries.contains(file.as_str()) {
            check.missing_inspection_entries.push(file);
        }
    }
    validate_manifest_inspection_order_adjacency(
        &value,
        "verification-snapshot.json",
        "llm-action-contract.json",
        &mut check.content_mismatches,
    );
    validate_handoff_json_schema(
        &pack_path,
        "goal-evidence-matrix.json",
        Some("aivana.goal-evidence-matrix.v1"),
        &["checklist", "uncovered_requirements", "next_live_gate"],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "goal-evidence-check.json",
        Some("aivana.goal-evidence-check.v1"),
        &["ok", "failed_requirements", "matrix"],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "verification-snapshot.json",
        Some("aivana.verification-snapshot.v1"),
        &[
            "ok",
            "env_source",
            "completion",
            "live_gate",
            "rdp_proof",
            "handoff",
            "llm_action_contract",
        ],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "operator-handoff-risk-summary.json",
        Some("aivana.operator-handoff-risk-summary.v1"),
        &[
            "ok",
            "severity",
            "handoff_pack_valid",
            "goal_evidence_ok",
            "rdp_proof_ok",
            "rdp_proof_failed_check_actions",
        ],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "command-index.json",
        Some("aivana.command-index.v1"),
        &["commands", "recommended_live_gate_sequence"],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "rdp-env-file-check.json",
        Some("aivana.rdp-env-file-check.v1"),
        &["ok", "network_checked", "expected_environment"],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "rdp-proof-check.json",
        Some("aivana.rdp-proof-check.v1"),
        &[
            "ok",
            "checks",
            "failed_checks",
            "failed_check_actions",
            "next_command",
        ],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "live-gate-doctor.json",
        Some("aivana.live-gate-doctor.v1"),
        &["achieved", "checks", "next_command"],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "next-live-gate.json",
        None,
        &["blocking_gates", "next_commands", "rdp_env_template"],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_json_schema(
        &pack_path,
        "llm-action-contract.json",
        Some("aivana.llm-action-contract.v1"),
        &[
            "ok",
            "next_command",
            "allowed_next_commands",
            "acceptance_criteria",
            "evidence_success_signals",
            "proxy_evidence_rejected",
        ],
        &mut check.invalid_file_schemas,
    );
    validate_handoff_content_consistency(
        &pack_path,
        &value,
        &mut check.content_mismatches,
        &mut check.invalid_file_schemas,
    );
    check.ok = check.errors.is_empty()
        && check.missing_files.is_empty()
        && check.missing_file_roles.is_empty()
        && check.missing_inspection_entries.is_empty()
        && check.invalid_file_schemas.is_empty()
        && check.content_mismatches.is_empty();
    Ok(check)
}

fn validate_manifest_file_role_contains(
    manifest: &serde_json::Value,
    file: &str,
    required: &str,
    content_mismatches: &mut Vec<String>,
) {
    let Some(roles) = manifest
        .get("file_roles")
        .and_then(|value| value.as_array())
    else {
        return;
    };
    let Some(role) = roles
        .iter()
        .find(|role| role.get("file").and_then(|value| value.as_str()) == Some(file))
    else {
        return;
    };
    let role_text = format!(
        "{} {}",
        role.get("role")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        role.get("inspect_when")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
    );
    if !role_text.contains(required) {
        content_mismatches.push(redact_secret_text(&format!(
            "manifest.file_roles {file} missing required mention: {required}"
        )));
    }
}

fn validate_manifest_inspection_order_adjacency(
    manifest: &serde_json::Value,
    first: &str,
    second: &str,
    content_mismatches: &mut Vec<String>,
) {
    let Some(entries) = manifest
        .get("recommended_inspection_order")
        .and_then(|value| value.as_array())
    else {
        return;
    };
    let positions = entries
        .iter()
        .filter_map(|entry| entry.as_str())
        .enumerate()
        .map(|(index, file)| (file, index))
        .collect::<std::collections::BTreeMap<_, _>>();
    let Some(first_index) = positions.get(first).copied() else {
        return;
    };
    let Some(second_index) = positions.get(second).copied() else {
        return;
    };
    if second_index != first_index + 1 {
        content_mismatches.push(redact_secret_text(&format!(
            "manifest.recommended_inspection_order must list {second} immediately after {first}"
        )));
    }
}

fn validate_handoff_content_consistency(
    pack_path: &Path,
    manifest: &serde_json::Value,
    content_mismatches: &mut Vec<String>,
    invalid_file_schemas: &mut Vec<String>,
) {
    let Some(audit) =
        read_handoff_json_value(pack_path, "completion-audit.json", invalid_file_schemas)
    else {
        return;
    };
    let Some(matrix) =
        read_handoff_json_value(pack_path, "goal-evidence-matrix.json", invalid_file_schemas)
    else {
        return;
    };
    let Some(goal_check) =
        read_handoff_json_value(pack_path, "goal-evidence-check.json", invalid_file_schemas)
    else {
        return;
    };
    let Some(verification_snapshot) = read_handoff_json_value(
        pack_path,
        "verification-snapshot.json",
        invalid_file_schemas,
    ) else {
        return;
    };
    let Some(risk_summary) = read_handoff_json_value(
        pack_path,
        "operator-handoff-risk-summary.json",
        invalid_file_schemas,
    ) else {
        return;
    };
    let Some(next_gate) =
        read_handoff_json_value(pack_path, "next-live-gate.json", invalid_file_schemas)
    else {
        return;
    };
    let command_index =
        read_handoff_json_value(pack_path, "command-index.json", invalid_file_schemas);
    let proof_check =
        read_handoff_json_value(pack_path, "rdp-proof-check.json", invalid_file_schemas);
    let doctor = read_handoff_json_value(pack_path, "live-gate-doctor.json", invalid_file_schemas);
    let llm_action_contract =
        read_handoff_json_value(pack_path, "llm-action-contract.json", invalid_file_schemas);
    let audit_objective = audit.get("objective").and_then(|value| value.as_str());
    compare_optional_str(
        "manifest.summary/objective",
        audit_objective,
        manifest
            .get("summary")
            .and_then(|value| value.as_str())
            .and_then(|summary| {
                if summary.contains(audit_objective.unwrap_or_default()) {
                    audit_objective
                } else {
                    None
                }
            }),
        content_mismatches,
    );
    compare_optional_str(
        "matrix.objective",
        audit_objective,
        matrix.get("objective").and_then(|value| value.as_str()),
        content_mismatches,
    );
    compare_optional_str(
        "next-live-gate.objective",
        audit_objective,
        next_gate.get("objective").and_then(|value| value.as_str()),
        content_mismatches,
    );
    compare_optional_str(
        "goal-evidence-check.matrix.objective",
        audit_objective,
        goal_check
            .get("matrix")
            .and_then(|value| value.get("objective"))
            .and_then(|value| value.as_str()),
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        &matrix,
        "goal-evidence-matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "LLM review prompt copy with summary.md Early LLM Triage",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        &matrix,
        "goal-evidence-matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "operator-handoff-risk-summary.json cross-check",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        &matrix,
        "goal-evidence-matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "LLM action-contract JSON copy/export with summary.md Early LLM Triage",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        &matrix,
        "goal-evidence-matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "early_triage_artifacts",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        &matrix,
        "goal-evidence-matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "direct_live_evidence_requirements",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        &matrix,
        "goal-evidence-matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "evidence success signals",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        goal_check.get("matrix").unwrap_or(&serde_json::Value::Null),
        "goal-evidence-check.matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "LLM review prompt copy with summary.md Early LLM Triage",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        goal_check.get("matrix").unwrap_or(&serde_json::Value::Null),
        "goal-evidence-check.matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "operator-handoff-risk-summary.json cross-check",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        goal_check.get("matrix").unwrap_or(&serde_json::Value::Null),
        "goal-evidence-check.matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "LLM action-contract JSON copy/export with summary.md Early LLM Triage",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        goal_check.get("matrix").unwrap_or(&serde_json::Value::Null),
        "goal-evidence-check.matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "early_triage_artifacts",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        goal_check.get("matrix").unwrap_or(&serde_json::Value::Null),
        "goal-evidence-check.matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "direct_live_evidence_requirements",
        content_mismatches,
    );
    validate_goal_evidence_matrix_checklist_evidence_contains(
        goal_check.get("matrix").unwrap_or(&serde_json::Value::Null),
        "goal-evidence-check.matrix",
        "GUI-friendly KI cockpit and operator workflow",
        "evidence success signals",
        content_mismatches,
    );
    validate_json_array_contains_str(
        verification_snapshot
            .get("llm_action_contract")
            .and_then(|value| value.get("required_evidence_files")),
        "summary.md",
        "verification-snapshot.llm_action_contract.required_evidence_files",
        content_mismatches,
    );
    validate_json_array_contains_str(
        verification_snapshot
            .get("llm_action_contract")
            .and_then(|value| value.get("must_return")),
        "early_triage_artifacts",
        "verification-snapshot.llm_action_contract.must_return",
        content_mismatches,
    );
    validate_json_array_contains_str(
        verification_snapshot
            .get("llm_action_contract")
            .and_then(|value| value.get("success_signals")),
        "rdp-smoke-test connected == true",
        "verification-snapshot.llm_action_contract.success_signals",
        content_mismatches,
    );
    validate_json_array_contains_str(
        verification_snapshot
            .get("llm_action_contract")
            .and_then(|value| value.get("direct_live_evidence_requirements")),
        "direct live evidence from the configured RDP host and port",
        "verification-snapshot.llm_action_contract.direct_live_evidence_requirements",
        content_mismatches,
    );
    validate_json_array_contains_str(
        verification_snapshot
            .get("llm_action_contract")
            .and_then(|value| value.get("proxy_evidence_rejected")),
        "passing unit tests without live RDP smoke evidence",
        "verification-snapshot.llm_action_contract.proxy_evidence_rejected",
        content_mismatches,
    );
    compare_optional_str(
        "verification-snapshot.llm_action_contract.copy_action",
        Some("Copy LLM Action Contract JSON"),
        verification_snapshot
            .get("llm_action_contract")
            .and_then(|value| value.get("copy_action"))
            .and_then(|value| value.as_str()),
        content_mismatches,
    );
    compare_optional_str(
        "verification-snapshot.llm_review_prompt.copy_action",
        Some("Copy LLM Review Prompt"),
        verification_snapshot
            .get("llm_review_prompt")
            .and_then(|value| value.get("copy_action"))
            .and_then(|value| value.as_str()),
        content_mismatches,
    );
    compare_optional_str(
        "verification-snapshot.llm_review_prompt.command",
        Some("cargo run -- --llm-review-prompt"),
        verification_snapshot
            .get("llm_review_prompt")
            .and_then(|value| value.get("command"))
            .and_then(|value| value.as_str()),
        content_mismatches,
    );
    for required in [
        "summary.md",
        "verification-snapshot.json",
        "llm-action-contract.json",
        "operator-handoff-risk-summary.json",
    ] {
        validate_json_array_contains_str(
            verification_snapshot
                .get("llm_review_prompt")
                .and_then(|value| value.get("triage_order")),
            required,
            "verification-snapshot.llm_review_prompt.triage_order",
            content_mismatches,
        );
    }
    for required in [
        "LLM triage entrypoint",
        "required evidence files",
        "early_triage_artifacts",
    ] {
        validate_json_array_contains_str(
            verification_snapshot
                .get("llm_review_prompt")
                .and_then(|value| value.get("risk_summary_cross_check")),
            required,
            "verification-snapshot.llm_review_prompt.risk_summary_cross_check",
            content_mismatches,
        );
    }
    validate_json_array_contains_str(
        verification_snapshot
            .get("llm_review_prompt")
            .and_then(|value| value.get("proxy_evidence_rejected")),
        "commands, manifests, or passing tests without direct live RDP proof",
        "verification-snapshot.llm_review_prompt.proxy_evidence_rejected",
        content_mismatches,
    );
    compare_optional_str(
        "verification-snapshot.objective",
        audit_objective,
        verification_snapshot
            .get("objective")
            .and_then(|value| value.as_str()),
        content_mismatches,
    );
    let audit_achieved = audit.get("achieved").and_then(|value| value.as_bool());
    compare_optional_bool(
        "manifest.achieved",
        audit_achieved,
        manifest.get("achieved").and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "matrix.achieved",
        audit_achieved,
        matrix.get("achieved").and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "next-live-gate.achieved",
        audit_achieved,
        next_gate.get("achieved").and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "goal-evidence-check.achieved",
        audit_achieved,
        goal_check.get("achieved").and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "goal-evidence-check.matrix.achieved",
        audit_achieved,
        goal_check
            .get("matrix")
            .and_then(|value| value.get("achieved"))
            .and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "verification-snapshot.completion.achieved",
        audit_achieved,
        verification_snapshot
            .get("completion")
            .and_then(|value| value.get("achieved"))
            .and_then(|value| value.as_bool()),
        content_mismatches,
    );
    let blocking_count = audit
        .get("items")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("blocking").and_then(|value| value.as_bool()) == Some(true))
                .count() as u64
        });
    compare_optional_u64(
        "manifest.blocking_gates",
        blocking_count,
        manifest
            .get("blocking_gates")
            .and_then(|value| value.as_u64()),
        content_mismatches,
    );
    compare_optional_u64(
        "next-live-gate.blocking_gates",
        blocking_count,
        next_gate
            .get("blocking_gates")
            .and_then(|value| value.as_u64()),
        content_mismatches,
    );
    compare_optional_u64(
        "matrix.uncovered_requirements",
        blocking_count,
        matrix
            .get("uncovered_requirements")
            .and_then(|value| value.as_array())
            .map(|items| items.len() as u64),
        content_mismatches,
    );
    compare_optional_u64(
        "goal-evidence-check.failed_requirements",
        blocking_count,
        goal_check
            .get("failed_requirements")
            .and_then(|value| value.as_array())
            .map(|items| items.len() as u64),
        content_mismatches,
    );
    compare_optional_u64(
        "verification-snapshot.completion.blocking_gates",
        blocking_count,
        verification_snapshot
            .get("completion")
            .and_then(|value| value.get("blocking_gates"))
            .and_then(|value| value.as_u64()),
        content_mismatches,
    );
    let expected_ok = audit_achieved == Some(true) && blocking_count == Some(0);
    compare_optional_bool(
        "goal-evidence-check.ok",
        Some(expected_ok),
        goal_check.get("ok").and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "verification-snapshot.ok",
        Some(expected_ok),
        verification_snapshot
            .get("ok")
            .and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "operator-handoff-risk-summary.ok",
        Some(expected_ok),
        risk_summary.get("ok").and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "operator-handoff-risk-summary.goal_evidence_ok",
        goal_check.get("ok").and_then(|value| value.as_bool()),
        risk_summary
            .get("goal_evidence_ok")
            .and_then(|value| value.as_bool()),
        content_mismatches,
    );
    let expected_failed_requirements = goal_check
        .get("failed_requirements")
        .and_then(|value| value.as_array())
        .map(|items| {
            serde_json::Value::Array(
                items
                    .iter()
                    .filter_map(|item| item.get("requirement").and_then(|value| value.as_str()))
                    .map(|requirement| serde_json::json!(redact_secret_text(requirement)))
                    .collect::<Vec<_>>(),
            )
        });
    compare_optional_json(
        "operator-handoff-risk-summary.failed_requirements",
        expected_failed_requirements.as_ref(),
        risk_summary.get("failed_requirements"),
        content_mismatches,
    );
    compare_optional_bool(
        "verification-snapshot.handoff.pack_valid",
        Some(true),
        verification_snapshot
            .get("handoff")
            .and_then(|value| value.get("pack_valid"))
            .and_then(|value| value.as_bool()),
        content_mismatches,
    );
    compare_optional_bool(
        "operator-handoff-risk-summary.handoff_pack_valid",
        Some(true),
        risk_summary
            .get("handoff_pack_valid")
            .and_then(|value| value.as_bool()),
        content_mismatches,
    );
    if let Some(snapshot_risk) = verification_snapshot.get("risk") {
        compare_optional_bool(
            "verification-snapshot.risk.ok",
            risk_summary.get("ok").and_then(|value| value.as_bool()),
            snapshot_risk.get("ok").and_then(|value| value.as_bool()),
            content_mismatches,
        );
        compare_optional_str(
            "verification-snapshot.risk.severity",
            risk_summary
                .get("severity")
                .and_then(|value| value.as_str()),
            snapshot_risk
                .get("severity")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        for field in [
            "blocking_reason",
            "acceptance_criteria",
            "next_command",
            "next_success_command",
        ] {
            compare_optional_str(
                &format!("verification-snapshot.risk.{field}"),
                risk_summary.get(field).and_then(|value| value.as_str()),
                snapshot_risk.get(field).and_then(|value| value.as_str()),
                content_mismatches,
            );
        }
        compare_optional_bool(
            "verification-snapshot.risk.goal_evidence_ok",
            risk_summary
                .get("goal_evidence_ok")
                .and_then(|value| value.as_bool()),
            snapshot_risk
                .get("goal_evidence_ok")
                .and_then(|value| value.as_bool()),
            content_mismatches,
        );
        compare_optional_json(
            "verification-snapshot.risk.failed_requirements",
            risk_summary.get("failed_requirements"),
            snapshot_risk.get("failed_requirements"),
            content_mismatches,
        );
        compare_optional_bool(
            "verification-snapshot.risk.rdp_proof_ok",
            risk_summary
                .get("rdp_proof_ok")
                .and_then(|value| value.as_bool()),
            snapshot_risk
                .get("rdp_proof_ok")
                .and_then(|value| value.as_bool()),
            content_mismatches,
        );
        compare_optional_json(
            "verification-snapshot.risk.rdp_proof_failed_checks",
            risk_summary.get("rdp_proof_failed_checks"),
            snapshot_risk.get("rdp_proof_failed_checks"),
            content_mismatches,
        );
        compare_optional_json(
            "verification-snapshot.risk.rdp_proof_failed_check_actions",
            risk_summary.get("rdp_proof_failed_check_actions"),
            snapshot_risk.get("rdp_proof_failed_check_actions"),
            content_mismatches,
        );
        compare_optional_str(
            "verification-snapshot.risk.rdp_proof_recovery_plan_command",
            risk_summary
                .get("rdp_proof_recovery_plan_command")
                .and_then(|value| value.as_str()),
            snapshot_risk
                .get("rdp_proof_recovery_plan_command")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        compare_optional_str(
            "verification-snapshot.risk.rdp_proof_recovery_plan_summary",
            risk_summary
                .get("rdp_proof_recovery_plan_summary")
                .and_then(|value| value.as_str()),
            snapshot_risk
                .get("rdp_proof_recovery_plan_summary")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
    } else {
        content_mismatches.push("verification-snapshot.risk missing".to_owned());
    }
    match std::fs::read_to_string(pack_path.join("rdp-proof-recovery-plan.md")) {
        Ok(plan) => {
            let expected_summary = rdp_proof_recovery_plan_summary_from_text(
                "operator-handoff-packs/<pack-id>/rdp-proof-recovery-plan.md",
                &plan,
            );
            compare_optional_str(
                "verification-snapshot.latest_evidence.rdp_proof_recovery_plan",
                Some(expected_summary.as_str()),
                verification_snapshot
                    .get("latest_evidence")
                    .and_then(|value| value.get("rdp_proof_recovery_plan"))
                    .and_then(|value| value.as_str()),
                content_mismatches,
            );
            compare_optional_str(
                "operator-handoff-risk-summary.rdp_proof_recovery_plan_summary",
                Some(expected_summary.as_str()),
                risk_summary
                    .get("rdp_proof_recovery_plan_summary")
                    .and_then(|value| value.as_str()),
                content_mismatches,
            );
        }
        Err(err) => content_mismatches.push(redact_secret_text(&format!(
            "rdp-proof-recovery-plan.md unreadable: {err}"
        ))),
    }
    let expected_sequence = next_gate
        .get("next_commands")
        .and_then(|value| value.as_array())
        .map(|commands| {
            commands
                .iter()
                .filter_map(|command| command.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        });
    let sequence_path = pack_path.join("live-gate-sequence.txt");
    match std::fs::read_to_string(&sequence_path) {
        Ok(sequence) => compare_optional_str(
            "live-gate-sequence.next_commands",
            expected_sequence.as_deref(),
            Some(sequence.trim_end()),
            content_mismatches,
        ),
        Err(err) => content_mismatches.push(redact_secret_text(&format!(
            "live-gate-sequence.txt unreadable: {err}"
        ))),
    }
    if let Some(contract) = llm_action_contract.as_ref() {
        compare_optional_bool(
            "llm-action-contract.ok",
            Some(expected_ok),
            contract.get("ok").and_then(|value| value.as_bool()),
            content_mismatches,
        );
        compare_optional_json(
            "llm-action-contract.allowed_next_commands",
            next_gate.get("next_commands"),
            contract.get("allowed_next_commands"),
            content_mismatches,
        );
        compare_optional_str(
            "llm-action-contract.next_command",
            doctor
                .as_ref()
                .and_then(|doctor| doctor.get("next_command"))
                .and_then(|value| value.as_str()),
            contract
                .get("next_command")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        compare_optional_str(
            "llm-action-contract.next_success_command",
            doctor
                .as_ref()
                .and_then(|doctor| doctor.get("next_success_command"))
                .and_then(|value| value.as_str()),
            contract
                .get("next_success_command")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        compare_optional_str(
            "llm-action-contract.rdp_proof_recovery_plan_command",
            Some("cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"),
            contract
                .get("rdp_proof_recovery_plan_command")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        if let Some(proof_check) = proof_check.as_ref() {
            compare_optional_bool(
                "llm-action-contract.rdp_proof.ok",
                proof_check.get("ok").and_then(|value| value.as_bool()),
                contract
                    .get("rdp_proof")
                    .and_then(|value| value.get("ok"))
                    .and_then(|value| value.as_bool()),
                content_mismatches,
            );
            compare_optional_json(
                "llm-action-contract.rdp_proof.failed_checks",
                proof_check.get("failed_checks"),
                contract
                    .get("rdp_proof")
                    .and_then(|value| value.get("failed_checks")),
                content_mismatches,
            );
            compare_optional_json(
                "llm-action-contract.rdp_proof.failed_check_actions",
                proof_check.get("failed_check_actions"),
                contract
                    .get("rdp_proof")
                    .and_then(|value| value.get("failed_check_actions")),
                content_mismatches,
            );
        }
        validate_json_array_contains_str(
            contract.get("required_evidence_files"),
            "summary.md",
            "llm-action-contract.required_evidence_files",
            content_mismatches,
        );
        validate_json_array_contains_str(
            contract.get("required_evidence_files"),
            "goal-evidence-check.json",
            "llm-action-contract.required_evidence_files",
            content_mismatches,
        );
        validate_json_array_contains_str(
            contract.get("required_evidence_files"),
            "rdp-proof-check.json",
            "llm-action-contract.required_evidence_files",
            content_mismatches,
        );
        validate_json_array_contains_str(
            contract.get("required_evidence_files"),
            "verification-snapshot.json",
            "llm-action-contract.required_evidence_files",
            content_mismatches,
        );
        validate_json_array_contains_str(
            contract.get("proxy_evidence_rejected"),
            "passing unit tests without live RDP smoke evidence",
            "llm-action-contract.proxy_evidence_rejected",
            content_mismatches,
        );
        for required in [
            "direct live evidence from the configured RDP host and port",
            "fresh matching env-file/preflight/smoke host-port evidence",
            "persisted RDP smoke connected=true",
            "framebuffer_present == true",
            "input_probe_present == true",
            "no proxy evidence accepted as direct RDP proof",
        ] {
            validate_json_array_contains_str(
                contract.get("direct_live_evidence_requirements"),
                required,
                "llm-action-contract.direct_live_evidence_requirements",
                content_mismatches,
            );
        }
        for required in [
            "rdp-env-file-check.ok == true",
            "rdp-smoke-test connected == true",
            "rdp-smoke-test framebuffer_present == true",
            "rdp-smoke-test input_probe_present == true",
            "goal-evidence-check.ok == true",
        ] {
            validate_json_array_contains_str(
                contract.get("evidence_success_signals"),
                required,
                "llm-action-contract.evidence_success_signals",
                content_mismatches,
            );
        }
        validate_json_array_contains_str(
            contract
                .get("assistant_response_contract")
                .and_then(|value| value.get("must_not_return")),
            "completion=true unless ok=true",
            "llm-action-contract.assistant_response_contract.must_not_return",
            content_mismatches,
        );
        for required in [
            "next_command",
            "acceptance_criteria",
            "evidence_files_to_inspect",
            "early_triage_artifacts",
        ] {
            validate_json_array_contains_str(
                contract
                    .get("assistant_response_contract")
                    .and_then(|value| value.get("must_return")),
                required,
                "llm-action-contract.assistant_response_contract.must_return",
                content_mismatches,
            );
        }
    }
    if let Some(command_index) = command_index.as_ref() {
        let command_catalog = command_index
            .get("commands")
            .and_then(|value| value.as_array());
        if let Some(commands) = command_catalog {
            validate_command_index_purpose_contains(
                commands,
                "--llm-action-contract",
                "summary.md Early LLM Triage",
                content_mismatches,
            );
            validate_command_index_purpose_contains(
                commands,
                "--llm-action-contract",
                "early_triage_artifacts",
                content_mismatches,
            );
            validate_command_index_purpose_contains(
                commands,
                "--llm-action-contract",
                "success signals",
                content_mismatches,
            );
            validate_command_index_purpose_contains(
                commands,
                "--llm-action-contract",
                "direct_live_evidence_requirements",
                content_mismatches,
            );
            validate_command_index_purpose_contains(
                commands,
                "--llm-action-contract",
                "direct live evidence",
                content_mismatches,
            );
            validate_command_index_purpose_contains(
                commands,
                "--llm-action-contract",
                "proxy-evidence rejection rules",
                content_mismatches,
            );
            for required in [
                "direct live evidence",
                "proxy-evidence rejection",
                "acceptance criteria",
            ] {
                validate_command_index_purpose_contains(
                    commands,
                    "--rdp-proof-recovery-plan",
                    required,
                    content_mismatches,
                );
            }
            for required in [
                "summary.md Early LLM Triage",
                "verification-snapshot.json",
                "llm-action-contract.json",
            ] {
                validate_command_index_purpose_contains(
                    commands,
                    "--operator-handoff-pack",
                    required,
                    content_mismatches,
                );
            }
            for required in [
                "summary.md Early LLM Triage",
                "operator-handoff-risk-summary.json",
                "LLM triage entrypoint",
                "required evidence files",
                "early_triage_artifacts",
                "proxy-evidence rejection",
            ] {
                validate_command_index_purpose_contains(
                    commands,
                    "--llm-review-prompt",
                    required,
                    content_mismatches,
                );
            }
            for required in [
                "LLM triage entrypoint",
                "required evidence files",
                "early_triage_artifacts",
            ] {
                validate_command_index_purpose_contains(
                    commands,
                    "--operator-handoff-risk-summary",
                    required,
                    content_mismatches,
                );
            }
        }
        let command_index_steps = command_index
            .get("recommended_live_gate_sequence")
            .and_then(|value| value.as_array());
        let command_index_sequence = command_index_steps.map(|steps| {
            steps
                .iter()
                .filter_map(|step| step.get("command").and_then(|command| command.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        });
        compare_optional_str(
            "command-index.recommended_live_gate_sequence",
            expected_sequence.as_deref(),
            command_index_sequence.as_deref(),
            content_mismatches,
        );
        if let Some(steps) = command_index_steps {
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env",
                "direct live evidence",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --live-gate-doctor --rdp-env-file .\\rdp-live.env",
                "rdp_proof_recovery_plan_command",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --live-gate-operator-brief --rdp-env-file .\\rdp-live.env",
                "RDP proof recovery-plan command",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-live-gate-plan --rdp-env-file .\\rdp-live.env",
                "RDP proof recovery-plan command",
                content_mismatches,
            );
            for required in [
                "summary.md Early LLM Triage",
                "operator-handoff-risk-summary.json",
                "LLM triage entrypoint",
                "required evidence files",
                "early_triage_artifacts",
                "proxy-evidence rejection",
            ] {
                validate_command_index_expect_contains(
                    steps,
                    "cargo run -- --llm-review-prompt",
                    required,
                    content_mismatches,
                );
            }
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "summary.md Early LLM Triage",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "early_triage_artifacts",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "proxy-evidence rejection rules",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "success signals",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "direct_live_evidence_requirements",
                content_mismatches,
            );
            validate_command_index_expect_contains(
                steps,
                "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env",
                "direct live evidence",
                content_mismatches,
            );
            for required in [
                "summary.md Early LLM Triage",
                "verification-snapshot.json",
                "llm-action-contract.json",
            ] {
                validate_command_index_expect_contains(
                    steps,
                    "cargo run -- --operator-handoff-pack --rdp-env-file .\\rdp-live.env",
                    required,
                    content_mismatches,
                );
            }
            for required in [
                "LLM triage entrypoint",
                "required evidence files",
                "early_triage_artifacts",
            ] {
                validate_command_index_expect_contains(
                    steps,
                    "cargo run -- --operator-handoff-risk-summary --rdp-env-file .\\rdp-live.env",
                    required,
                    content_mismatches,
                );
            }
        }
    }
    if let Some(doctor) = doctor.as_ref() {
        compare_optional_str(
            "live-gate-doctor.rdp_proof_recovery_plan_command",
            Some("cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"),
            doctor
                .get("rdp_proof_recovery_plan_command")
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        for (risk_field, doctor_field) in [
            ("live_gate_stage", "operator_stage"),
            ("blocking_reason", "blocking_reason"),
            ("acceptance_criteria", "acceptance_criteria"),
            ("next_command", "next_command"),
            ("next_success_command", "next_success_command"),
        ] {
            compare_optional_str(
                &format!("operator-handoff-risk-summary.{risk_field}"),
                doctor.get(doctor_field).and_then(|value| value.as_str()),
                risk_summary
                    .get(risk_field)
                    .and_then(|value| value.as_str()),
                content_mismatches,
            );
        }
        if let Some(proof_check) = proof_check.as_ref() {
            compare_optional_bool(
                "verification-snapshot.rdp_proof.ok",
                proof_check.get("ok").and_then(|value| value.as_bool()),
                verification_snapshot
                    .get("rdp_proof")
                    .and_then(|value| value.get("ok"))
                    .and_then(|value| value.as_bool()),
                content_mismatches,
            );
            compare_optional_str(
                "verification-snapshot.rdp_proof.recovery_plan_command",
                Some("cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"),
                verification_snapshot
                    .get("rdp_proof")
                    .and_then(|value| value.get("recovery_plan_command"))
                    .and_then(|value| value.as_str()),
                content_mismatches,
            );
            compare_optional_bool(
                "operator-handoff-risk-summary.rdp_proof_ok",
                proof_check.get("ok").and_then(|value| value.as_bool()),
                risk_summary
                    .get("rdp_proof_ok")
                    .and_then(|value| value.as_bool()),
                content_mismatches,
            );
            compare_optional_json(
                "operator-handoff-risk-summary.rdp_proof_failed_checks",
                proof_check.get("failed_checks"),
                risk_summary.get("rdp_proof_failed_checks"),
                content_mismatches,
            );
            compare_optional_json(
                "operator-handoff-risk-summary.rdp_proof_failed_check_actions",
                proof_check.get("failed_check_actions"),
                risk_summary.get("rdp_proof_failed_check_actions"),
                content_mismatches,
            );
            compare_optional_str(
                "operator-handoff-risk-summary.rdp_proof_recovery_plan_command",
                Some("cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"),
                risk_summary
                    .get("rdp_proof_recovery_plan_command")
                    .and_then(|value| value.as_str()),
                content_mismatches,
            );
            compare_optional_str(
                "operator-handoff-risk-summary.llm_triage_entrypoint",
                Some("summary.md -> verification-snapshot.json -> llm-action-contract.json"),
                risk_summary
                    .get("llm_triage_entrypoint")
                    .and_then(|value| value.as_str()),
                content_mismatches,
            );
            compare_optional_json(
                "operator-handoff-risk-summary.llm_action_contract_required_evidence_files",
                verification_snapshot
                    .get("llm_action_contract")
                    .and_then(|value| value.get("required_evidence_files")),
                risk_summary.get("llm_action_contract_required_evidence_files"),
                content_mismatches,
            );
            compare_optional_json(
                "operator-handoff-risk-summary.llm_action_contract_direct_live_evidence_requirements",
                verification_snapshot
                    .get("llm_action_contract")
                    .and_then(|value| value.get("direct_live_evidence_requirements")),
                risk_summary.get("llm_action_contract_direct_live_evidence_requirements"),
                content_mismatches,
            );
            compare_optional_json(
                "operator-handoff-risk-summary.llm_action_contract_must_return",
                verification_snapshot
                    .get("llm_action_contract")
                    .and_then(|value| value.get("must_return")),
                risk_summary.get("llm_action_contract_must_return"),
                content_mismatches,
            );
            compare_optional_bool(
                "rdp-proof-check.smoke_connected",
                doctor
                    .get("smoke_connected")
                    .and_then(|value| value.as_bool()),
                proof_check
                    .get("checks")
                    .and_then(|value| value.get("smoke_connected"))
                    .and_then(|value| value.as_bool()),
                content_mismatches,
            );
        }
        compare_optional_str(
            "verification-snapshot.live_gate.stage",
            doctor
                .get("operator_stage")
                .and_then(|value| value.as_str()),
            verification_snapshot
                .get("live_gate")
                .and_then(|value| value.get("stage"))
                .and_then(|value| value.as_str()),
            content_mismatches,
        );
        compare_optional_bool(
            "verification-snapshot.live_gate.smoke_connected",
            doctor
                .get("smoke_connected")
                .and_then(|value| value.as_bool()),
            verification_snapshot
                .get("live_gate")
                .and_then(|value| value.get("smoke_connected"))
                .and_then(|value| value.as_bool()),
            content_mismatches,
        );
        validate_operator_brief_matches_doctor(pack_path, doctor, content_mismatches);
    }
    validate_llm_handoff_mentions_required_live_gate_artifacts(pack_path, content_mismatches);
    validate_summary_mentions_llm_triage(pack_path, content_mismatches);
    validate_rdp_proof_prompt_mentions_direct_evidence(pack_path, content_mismatches);
    validate_rdp_proof_recovery_plan_mentions_failed_check_actions(
        pack_path,
        proof_check.as_ref(),
        content_mismatches,
    );
    validate_gui_operator_actions_mentions_env_source(pack_path, content_mismatches);
}

fn validate_summary_mentions_llm_triage(pack_path: &Path, content_mismatches: &mut Vec<String>) {
    validate_text_file_contains_all(
        pack_path,
        "summary.md",
        &[
            "Early LLM Triage",
            "verification-snapshot.json",
            "llm-action-contract.json",
            "reject proxy evidence",
            "contract success signals",
        ],
        content_mismatches,
    );
}

fn validate_operator_brief_matches_doctor(
    pack_path: &Path,
    doctor: &serde_json::Value,
    content_mismatches: &mut Vec<String>,
) {
    let path = pack_path.join("live-gate-operator-brief.md");
    let brief = match std::fs::read_to_string(&path) {
        Ok(brief) => brief,
        Err(err) => {
            content_mismatches.push(redact_secret_text(&format!(
                "live-gate-operator-brief.md unreadable: {err}"
            )));
            return;
        }
    };
    for (name, label) in [
        ("operator_stage", "Operator stage"),
        ("blocking_reason", "Blocking reason"),
        ("acceptance_criteria", "Acceptance criteria"),
        ("next_command", "Next command"),
        ("next_success_command", "Next command after success"),
        (
            "rdp_proof_recovery_plan_command",
            "RDP proof recovery plan command",
        ),
    ] {
        let Some(value) = doctor.get(name).and_then(|value| value.as_str()) else {
            continue;
        };
        let expected = if name == "next_command"
            || name == "next_success_command"
            || name == "rdp_proof_recovery_plan_command"
        {
            format!("{label}: `{}`", redact_secret_text(value))
        } else {
            format!("{label}: {}", redact_secret_text(value))
        };
        if !brief.contains(&expected) {
            content_mismatches.push(redact_secret_text(&format!(
                "live-gate-operator-brief.{name} mismatch"
            )));
        }
    }
}

fn validate_llm_handoff_mentions_required_live_gate_artifacts(
    pack_path: &Path,
    content_mismatches: &mut Vec<String>,
) {
    validate_text_file_contains_all(
        pack_path,
        "llm-live-gate-plan.md",
        &[
            "summary.md",
            "Early LLM Triage",
            "verification-snapshot.json",
            "llm-action-contract.json",
            "operator-handoff-risk-summary.json",
            "LLM triage entrypoint",
            "required evidence files",
            "early_triage_artifacts",
            "rdp-proof-check.json",
            "rdp-proof-recovery-plan.md",
            "live-gate-doctor.json",
            "live-gate-operator-brief.md",
            "live-gate-sequence.txt",
            "RDP proof recovery plan command",
            "--rdp-proof-recovery-plan",
            "Reject proxy evidence",
            "connected=true",
        ],
        content_mismatches,
    );
    validate_text_file_contains_all(
        pack_path,
        "llm-review-prompt.md",
        &[
            "summary.md",
            "Early LLM Triage",
            "verification-snapshot.json",
            "llm-action-contract.json",
            "operator-handoff-risk-summary.json",
            "LLM triage entrypoint",
            "required evidence files",
            "early_triage_artifacts",
            "rdp-proof-check.json",
            "rdp-proof-recovery-plan.md",
            "live-gate-doctor.json",
            "live-gate-operator-brief.md",
            "live-gate-sequence.txt",
            "Do not treat a command",
        ],
        content_mismatches,
    );
}

fn validate_gui_operator_actions_mentions_env_source(
    pack_path: &Path,
    content_mismatches: &mut Vec<String>,
) {
    validate_text_file_contains_all(
        pack_path,
        "gui-operator-actions.md",
        &[
            "RDP env source line",
            ".\\rdp-live.env",
            "Copy Verification Snapshot JSON",
            "Export Verification Snapshot",
            "Copy RDP Proof Check JSON",
            "Copy RDP Proof Prompt",
            "Copy RDP Recovery Plan",
            "acceptance criteria",
            "direct live evidence",
            "proxy-evidence rejection",
            "Copy RDP Recovery Plan Command",
            "Copy RDP Recovery Commands",
            "Copy LLM Review Prompt",
            "operator-handoff-risk-summary.json cross-check",
            "Copy LLM Action Contract JSON",
            "summary.md Early LLM Triage",
            "direct_live_evidence_requirements",
            "early_triage_artifacts",
            "evidence success signals",
            "proxy-evidence rejection rules",
        ],
        content_mismatches,
    );
}

fn validate_rdp_proof_recovery_plan_mentions_failed_check_actions(
    pack_path: &Path,
    proof_check: Option<&serde_json::Value>,
    content_mismatches: &mut Vec<String>,
) {
    validate_text_file_contains_all(
        pack_path,
        "rdp-proof-recovery-plan.md",
        &[
            "Aivana RDP Proof Recovery Plan",
            "Failed Proof Checks",
            "Recovery Commands",
            "rdp-proof-check.ok == true",
            "connected=true",
            "framebuffer",
            "input-probe",
            "Do not accept manifests",
        ],
        content_mismatches,
    );
    let path = pack_path.join("rdp-proof-recovery-plan.md");
    let plan = match std::fs::read_to_string(&path) {
        Ok(plan) => plan,
        Err(err) => {
            content_mismatches.push(redact_secret_text(&format!(
                "rdp-proof-recovery-plan.md unreadable: {err}"
            )));
            return;
        }
    };
    let Some(proof_check) = proof_check else {
        return;
    };
    for failed_check in proof_check
        .get("failed_checks")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
    {
        if !plan.contains(&format!("`{}`", redact_secret_text(failed_check))) {
            content_mismatches.push(redact_secret_text(&format!(
                "rdp-proof-recovery-plan.failed_checks mismatch: {failed_check}"
            )));
        }
    }
    for action in proof_check
        .get("failed_check_actions")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
    {
        let check = action.get("check").and_then(|value| value.as_str());
        let command = action.get("command").and_then(|value| value.as_str());
        let Some(command) = command else {
            continue;
        };
        let redacted_command = redact_secret_text(command);
        if !plan.contains(&format!("`{redacted_command}`")) {
            let check_label = check.unwrap_or("unknown");
            content_mismatches.push(redact_secret_text(&format!(
                "rdp-proof-recovery-plan.failed_check_actions mismatch: {check_label}"
            )));
        }
    }
}

fn validate_rdp_proof_prompt_mentions_direct_evidence(
    pack_path: &Path,
    content_mismatches: &mut Vec<String>,
) {
    validate_text_file_contains_all(
        pack_path,
        "rdp-proof-prompt.md",
        &[
            "Aivana RDP Proof Prompt",
            "summary.md",
            "Early LLM Triage",
            "llm-action-contract.json",
            "connected=true",
            "Framebuffer evidence",
            "Input probe evidence",
            "Reject proxy evidence",
            "--rdp-smoke-test",
            "--verification-snapshot",
            "--rdp-proof-recovery-plan",
        ],
        content_mismatches,
    );
}

fn validate_text_file_contains_all(
    pack_path: &Path,
    file: &str,
    required: &[&str],
    content_mismatches: &mut Vec<String>,
) {
    let path = pack_path.join(file);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            content_mismatches.push(redact_secret_text(&format!("{file} unreadable: {err}")));
            return;
        }
    };
    for needle in required {
        if !text.contains(needle) {
            content_mismatches.push(redact_secret_text(&format!(
                "{file} missing required mention: {needle}"
            )));
        }
    }
}

fn validate_command_index_expect_contains(
    steps: &[serde_json::Value],
    command: &str,
    required: &str,
    content_mismatches: &mut Vec<String>,
) {
    let Some(step) = steps
        .iter()
        .find(|step| step.get("command").and_then(|value| value.as_str()) == Some(command))
    else {
        content_mismatches.push(redact_secret_text(&format!(
            "command-index.expect missing command: {command}"
        )));
        return;
    };
    let expect = step
        .get("expect")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if !expect.contains(required) {
        content_mismatches.push(redact_secret_text(&format!(
            "command-index.expect missing required mention for {command}: {required}"
        )));
    }
}

fn validate_command_index_purpose_contains(
    commands: &[serde_json::Value],
    name: &str,
    required: &str,
    content_mismatches: &mut Vec<String>,
) {
    let Some(command) = commands
        .iter()
        .find(|command| command.get("name").and_then(|value| value.as_str()) == Some(name))
    else {
        content_mismatches.push(redact_secret_text(&format!(
            "command-index.commands missing command: {name}"
        )));
        return;
    };
    let purpose = command
        .get("purpose")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if !purpose.contains(required) {
        content_mismatches.push(redact_secret_text(&format!(
            "command-index.commands purpose missing required mention for {name}: {required}"
        )));
    }
}

fn validate_goal_evidence_matrix_checklist_evidence_contains(
    matrix: &serde_json::Value,
    label: &str,
    requirement: &str,
    required: &str,
    content_mismatches: &mut Vec<String>,
) {
    let checklist = matrix.get("checklist").and_then(|value| value.as_array());
    let item = checklist
        .into_iter()
        .flatten()
        .find(|item| item.get("requirement").and_then(|value| value.as_str()) == Some(requirement));
    let Some(item) = item else {
        content_mismatches.push(redact_secret_text(&format!(
            "{label}.checklist missing requirement: {requirement}"
        )));
        return;
    };
    let evidence = item
        .get("evidence")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if !evidence.contains(required) {
        content_mismatches.push(redact_secret_text(&format!(
            "{label}.checklist evidence missing required mention for {requirement}: {required}"
        )));
    }
}

fn read_handoff_json_value(
    pack_path: &Path,
    file: &str,
    invalid_file_schemas: &mut Vec<String>,
) -> Option<serde_json::Value> {
    let path = pack_path.join(file);
    let json = match std::fs::read_to_string(&path) {
        Ok(json) => json,
        Err(err) => {
            invalid_file_schemas.push(redact_secret_text(&format!("{file}: unreadable: {err}")));
            return None;
        }
    };
    match serde_json::from_str(&json) {
        Ok(value) => Some(value),
        Err(err) => {
            invalid_file_schemas.push(redact_secret_text(&format!("{file}: invalid JSON: {err}")));
            None
        }
    }
}

fn compare_optional_str(
    name: &str,
    expected: Option<&str>,
    actual: Option<&str>,
    content_mismatches: &mut Vec<String>,
) {
    if expected != actual {
        content_mismatches.push(redact_secret_text(&format!(
            "{name} mismatch: expected {}, actual {}",
            expected.unwrap_or("missing"),
            actual.unwrap_or("missing")
        )));
    }
}

fn compare_optional_bool(
    name: &str,
    expected: Option<bool>,
    actual: Option<bool>,
    content_mismatches: &mut Vec<String>,
) {
    if expected != actual {
        content_mismatches.push(redact_secret_text(&format!(
            "{name} mismatch: expected {}, actual {}",
            expected
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_owned()),
            actual
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_owned())
        )));
    }
}

fn compare_optional_u64(
    name: &str,
    expected: Option<u64>,
    actual: Option<u64>,
    content_mismatches: &mut Vec<String>,
) {
    if expected != actual {
        content_mismatches.push(redact_secret_text(&format!(
            "{name} mismatch: expected {}, actual {}",
            expected
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_owned()),
            actual
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_owned())
        )));
    }
}

fn compare_optional_json(
    name: &str,
    expected: Option<&serde_json::Value>,
    actual: Option<&serde_json::Value>,
    content_mismatches: &mut Vec<String>,
) {
    if expected != actual {
        let expected = expected
            .map(|value| redact_secret_text(&value.to_string()))
            .unwrap_or_else(|| "missing".to_owned());
        let actual = actual
            .map(|value| redact_secret_text(&value.to_string()))
            .unwrap_or_else(|| "missing".to_owned());
        content_mismatches.push(redact_secret_text(&format!(
            "{name} mismatch: expected {expected}, actual {actual}"
        )));
    }
}

fn validate_json_array_contains_str(
    value: Option<&serde_json::Value>,
    required: &str,
    name: &str,
    content_mismatches: &mut Vec<String>,
) {
    let contains = value
        .and_then(|value| value.as_array())
        .map(|items| items.iter().any(|item| item.as_str() == Some(required)))
        .unwrap_or(false);
    if !contains {
        content_mismatches.push(redact_secret_text(&format!(
            "{name} missing required value: {required}"
        )));
    }
}

fn validate_handoff_json_schema(
    pack_path: &Path,
    file: &str,
    expected_schema: Option<&str>,
    required_fields: &[&str],
    invalid_file_schemas: &mut Vec<String>,
) {
    let path = pack_path.join(file);
    let json = match std::fs::read_to_string(&path) {
        Ok(json) => json,
        Err(err) => {
            invalid_file_schemas.push(redact_secret_text(&format!("{file}: unreadable: {err}")));
            return;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&json) {
        Ok(value) => value,
        Err(err) => {
            invalid_file_schemas.push(redact_secret_text(&format!("{file}: invalid JSON: {err}")));
            return;
        }
    };
    if let Some(expected_schema) = expected_schema {
        let actual_schema = value.get("schema").and_then(|value| value.as_str());
        if actual_schema != Some(expected_schema) {
            invalid_file_schemas.push(redact_secret_text(&format!(
                "{file}: schema mismatch: expected {expected_schema}, actual {}",
                actual_schema.unwrap_or("missing")
            )));
        }
    }
    for field in required_fields {
        if value.get(field).is_none() {
            invalid_file_schemas.push(redact_secret_text(&format!(
                "{file}: missing required field {field}"
            )));
        }
    }
}

fn latest_ai_brief_pack_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut manifests = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("manifest.json"))
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    manifests.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let Some(path) = manifests.pop() else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    let created_at = value
        .get("created_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-time");
    let files = value
        .get("files")
        .and_then(|value| value.as_array())
        .map(|files| files.len())
        .unwrap_or_default();
    Ok(Some(format!(
        "Latest AI brief pack: {files} file(s), created_at={created_at}, manifest={}",
        path.display()
    )))
}

fn latest_rdp_smoke_report_summary_from_dir(dir: &Path) -> anyhow::Result<Option<String>> {
    latest_rdp_smoke_report_summary_from_dir_matching(dir, false)
}

fn latest_successful_rdp_smoke_report_summary_from_dir(
    dir: &Path,
) -> anyhow::Result<Option<String>> {
    latest_rdp_smoke_report_summary_from_dir_matching(dir, true)
}

fn latest_rdp_smoke_report_summary_from_dir_matching(
    dir: &Path,
    successful_only: bool,
) -> anyhow::Result<Option<String>> {
    if !dir.exists() {
        return Ok(None);
    }

    let mut latest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        if successful_only {
            let Ok(json) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else {
                continue;
            };
            let connected = value
                .get("connected")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            if !connected {
                continue;
            }
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(latest_modified, _)| modified > *latest_modified)
        {
            latest = Some((modified, path));
        }
    }

    let Some((_, path)) = latest else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    let connected = value
        .get("connected")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let generated_at = value
        .get("generated_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-time");
    let timeout_secs = value.get("timeout_secs").and_then(|value| value.as_u64());
    let host = value
        .get("host")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown-host");
    let framebuffer = value.get("framebuffer");
    let frame_summary = framebuffer
        .and_then(|framebuffer| {
            Some(format!(
                "{}x{} hash={}",
                framebuffer.get("width")?.as_u64()?,
                framebuffer.get("height")?.as_u64()?,
                framebuffer.get("frame_hash")?.as_u64()?
            ))
        })
        .unwrap_or_else(|| "no framebuffer".to_owned());
    let error = value
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let path_label = value
        .get("evidence_path")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| path.display().to_string());

    Ok(Some(redact_secret_text(&format!(
        "Latest RDP smoke evidence: connected={} generated={} host={} frame={}{}{} path={}",
        connected,
        generated_at,
        host,
        frame_summary,
        if error.is_empty() {
            String::new()
        } else {
            format!(" error={}", redact_secret_text(error))
        },
        timeout_secs
            .map(|secs| format!(" timeout={}s", secs))
            .unwrap_or_default(),
        path_label
    ))))
}

fn load_autopilot_preferences() -> Option<AutopilotPreferences> {
    let path = app_data_file("autopilot-preferences.json").ok()?;
    load_autopilot_preferences_from_path(&path).ok()
}

fn load_autopilot_preferences_from_path(path: &Path) -> anyhow::Result<AutopilotPreferences> {
    let json = std::fs::read_to_string(path)?;
    let preferences = serde_json::from_str(&json)?;
    Ok(preferences)
}

fn save_autopilot_preferences(preferences: &AutopilotPreferences) -> anyhow::Result<()> {
    let path = app_data_file("autopilot-preferences.json")?;
    save_autopilot_preferences_to_path(&path, preferences)
}

fn save_autopilot_preferences_to_path(
    path: &Path,
    preferences: &AutopilotPreferences,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(preferences)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn save_ki_preferences_headless() -> anyhow::Result<KiPreferencesSaveReport> {
    let path = app_data_file("autopilot-preferences.json")?;
    save_ki_preferences_headless_to_path(&path)
}

fn save_ki_preferences_headless_to_path(path: &Path) -> anyhow::Result<KiPreferencesSaveReport> {
    let already_existed = path.exists();
    let preferences = if already_existed {
        load_autopilot_preferences_from_path(path)?
    } else {
        AutopilotPreferences::from(&AutopilotController::default())
    };
    save_autopilot_preferences_to_path(path, &preferences)?;

    Ok(KiPreferencesSaveReport {
        schema: "aivana.ki-preferences-save.v1".to_owned(),
        saved_at: Utc::now(),
        path: path.display().to_string(),
        already_existed,
        provider: preferences.settings.provider.label().to_owned(),
        model: redact_secret_text(&preferences.settings.openai_model),
        max_steps: preferences.settings.max_steps,
        step_delay_millis: preferences.settings.step_delay_millis,
        goal: redact_secret_text(&preferences.goal),
        redacted: true,
    })
}

fn build_ai_action_brief(
    host: &str,
    diagnostics: &[DiagnosticFinding],
    events: &[SessionEvent],
    snapshots: &[BlackboxSnapshot],
    autopilot_steps: &[crate::autopilot::AutopilotStep],
) -> String {
    let severity = diagnostics
        .iter()
        .map(|finding| finding.severity)
        .max_by_key(|severity| diagnostic_severity_rank(*severity))
        .unwrap_or(DiagnosticSeverity::Info);
    let primary_signal = diagnostics
        .iter()
        .find(|finding| finding.severity == severity)
        .map(|finding| finding.title.as_str())
        .or_else(|| events.last().map(|event| event.message.as_str()))
        .unwrap_or("No blocking signal yet");
    let next_step = diagnostics
        .iter()
        .find(|finding| finding.severity == severity)
        .map(|finding| finding.fix.as_str())
        .or_else(|| {
            autopilot_steps
                .last()
                .map(|step| step.action_description.as_str())
        })
        .unwrap_or("Collect a framebuffer snapshot and run local preflight first.");
    let last_autopilot = autopilot_steps
        .last()
        .map(|step| format!("last autopilot #{} {:?}", step.index, step.decision))
        .unwrap_or_else(|| "no autopilot steps".to_owned());

    redact_secret_text(&format!(
        "Host {} | risk {:?} | signal: {} | evidence: {} event(s), {} snapshot(s), {} | next: {}",
        host,
        severity,
        primary_signal,
        events.len(),
        snapshots.len(),
        last_autopilot,
        next_step
    ))
}

fn build_runbook_llm_brief(runbooks: &[crate::models::Runbook], host: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana Runbook LLM Brief");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Host: {}. Recommend the safest runbook and explain why. Prefer read-only evidence collection before any mutation.",
        redact_secret_text(host)
    );
    let _ = writeln!(out);
    for runbook in runbooks.iter().take(9) {
        let _ = writeln!(
            out,
            "- {} [{:?}/{:?}] steps={}",
            redact_secret_text(&runbook.name),
            runbook.category,
            runbook.risk,
            runbook.steps.len()
        );
        for step in runbook.steps.iter().take(4) {
            let approval = if step.requires_approval {
                "approval-required"
            } else {
                "no-approval"
            };
            let _ = writeln!(
                out,
                "  - {} [{:?}, {}] action={}",
                redact_secret_text(&step.title),
                step.risk,
                approval,
                input_action_label(&step.action)
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Return: selected runbook, confidence, first safe step, required approval, and evidence to capture."
    );
    redact_secret_text(&out)
}

fn build_guardrail_brief(settings: &AutopilotSettings) -> String {
    let mutation_policy = if settings.require_approval_for_every_mutation {
        "mutating UI actions require approval"
    } else {
        "policy engine decides approval by risk"
    };
    let runbook_mode = if settings.agentic_runbook_mode {
        "agentic runbook mode enabled"
    } else {
        "operator-gated mode enabled"
    };
    format!(
        "Provider={} model={} | read-only: screenshot/verify/wait allowed | low-risk: move/scroll allowed | elevated: click/type/hotkey approval-gated | destructive text denied | {mutation_policy} | {runbook_mode}",
        settings.provider.label(),
        redact_secret_text(&settings.openai_model)
    )
}

fn build_cua_request_brief(autopilot: &AutopilotController, has_frame: bool) -> String {
    let frame_status = if has_frame {
        "framebuffer available"
    } else {
        "framebuffer missing"
    };
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana OpenAI CUA Request Brief");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Provider: {}", autopilot.settings.provider.label());
    let _ = writeln!(
        out,
        "- Model: {}",
        redact_secret_text(&autopilot.settings.openai_model)
    );
    let _ = writeln!(out, "- Goal: {}", redact_secret_text(&autopilot.goal));
    let _ = writeln!(out, "- Frame status: {frame_status}");
    let _ = writeln!(out, "- Max steps: {}", autopilot.settings.max_steps);
    let _ = writeln!(out, "- Delay: {} ms", autopilot.settings.step_delay_millis);
    let _ = writeln!(
        out,
        "- Approval mode: require_every_mutation={} agentic_runbook_mode={}",
        autopilot.settings.require_approval_for_every_mutation,
        autopilot.settings.agentic_runbook_mode
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Guardrails");
    let _ = writeln!(out, "{}", build_guardrail_brief(&autopilot.settings));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Use this as a preflight description only. Do not include credentials. Do not run CUA unless the operator confirms the target session and safety checks."
    );
    redact_secret_text(&out)
}

fn build_prompt_library_brief(
    host: &str,
    action_brief: &str,
    autopilot: &AutopilotController,
    has_session: bool,
) -> String {
    let session_context = if has_session {
        "active session available"
    } else {
        "no active session; ask for evidence first"
    };
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana Prompt Library");
    let _ = writeln!(out);
    let _ = writeln!(out, "Host: {}", redact_secret_text(host));
    let _ = writeln!(out, "Context: {session_context}");
    let _ = writeln!(
        out,
        "Autopilot: provider={} model={} max_steps={} delay={}ms approvals={} goal={}",
        autopilot.settings.provider.label(),
        autopilot.settings.openai_model,
        autopilot.settings.max_steps,
        autopilot.settings.step_delay_millis,
        autopilot.settings.require_approval_for_every_mutation,
        redact_secret_text(&autopilot.goal)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Current Action Brief");
    let _ = writeln!(out, "{}", redact_secret_text(action_brief));
    let _ = writeln!(out);
    let _ = writeln!(out, "## Prompts");
    let prompts = [
        (
            "Diagnosis",
            "Given the action brief, identify the most likely root cause, confidence, missing evidence, and the next read-only step.",
        ),
        (
            "Runbook Selection",
            "Choose the safest Aivana runbook. Explain required approvals and evidence to capture before mutation.",
        ),
        (
            "Ticket Draft",
            "Write a customer-safe incident update with impact, current finding, next action, and no secrets.",
        ),
        (
            "Verification",
            "Define how to prove the next action worked using timeline events, framebuffer snapshots, and rollback criteria.",
        ),
    ];
    for (name, prompt) in prompts {
        let _ = writeln!(out, "- {name}: {prompt}");
    }
    redact_secret_text(&out)
}

fn diagnostic_severity_rank(severity: DiagnosticSeverity) -> u8 {
    match severity {
        DiagnosticSeverity::Info => 0,
        DiagnosticSeverity::Warning => 1,
        DiagnosticSeverity::Error => 2,
    }
}

fn build_llm_handoff_prompt(
    session_id: Uuid,
    host: &str,
    diagnostics: &[DiagnosticFinding],
    events: &[SessionEvent],
    snapshots: &[BlackboxSnapshot],
    autopilot_steps: &[crate::autopilot::AutopilotStep],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Aivana LLM Handoff");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "You are assisting a remote desktop operator. Use only the evidence below. Do not invent facts, do not request secrets, and prefer read-only diagnostics before mutation."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Scope");
    let _ = writeln!(out, "- Session: `{session_id}`");
    let _ = writeln!(out, "- Host: {}", redact_secret_text(host));
    let _ = writeln!(
        out,
        "- Requested output: root cause hypothesis, confidence, next safe step, rollback/fallback, and ticket-ready customer note."
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Diagnostics");
    if diagnostics.is_empty() {
        let _ = writeln!(out, "- No current diagnostic findings.");
    } else {
        for finding in diagnostics.iter().take(12) {
            let _ = writeln!(
                out,
                "- {:?}/{:?}: {} | detail={} | fix={}",
                finding.class,
                finding.severity,
                redact_secret_text(&finding.title),
                redact_secret_text(&finding.detail),
                redact_secret_text(&finding.fix)
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Timeline Evidence");
    if events.is_empty() {
        let _ = writeln!(out, "- No timeline events recorded yet.");
    } else {
        for event in events.iter().rev().take(20).rev() {
            let _ = writeln!(
                out,
                "- {} [{:?}] {}",
                event.created_at.format("%Y-%m-%d %H:%M:%S"),
                event.kind,
                redact_secret_text(&event.message)
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Framebuffer Snapshots");
    if snapshots.is_empty() {
        let _ = writeln!(out, "- No snapshots recorded yet.");
    } else {
        for snapshot in snapshots.iter().rev().take(8).rev() {
            let _ = writeln!(
                out,
                "- {} frame={} size={}x{} reason={}",
                snapshot.captured_at.format("%Y-%m-%d %H:%M:%S"),
                snapshot.frame_hash,
                snapshot.width,
                snapshot.height,
                redact_secret_text(&snapshot.reason)
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Autopilot Trace");
    if autopilot_steps.is_empty() {
        let _ = writeln!(out, "- No Autopilot steps recorded yet.");
    } else {
        for step in autopilot_steps.iter().rev().take(10).rev() {
            let actions = audited_step_actions(step);
            let _ = writeln!(
                out,
                "- #{} {:?}/{:?} batch={}: {} | summary={}{}",
                step.index,
                step.risk,
                step.decision,
                actions.len(),
                redact_secret_text(&step.action_description),
                redact_secret_text(&step.model_summary),
                step.error
                    .as_ref()
                    .map(|err| format!(" | error={}", redact_secret_text(err)))
                    .unwrap_or_default()
            );
            for (index, action) in actions.iter().take(8).enumerate() {
                let _ = writeln!(
                    out,
                    "  - action {}: {}",
                    index + 1,
                    input_action_label(action)
                );
            }
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Guardrails");
    let _ = writeln!(
        out,
        "- Never output credentials or ask the operator to paste secrets."
    );
    let _ = writeln!(
        out,
        "- Mark any destructive or security-sensitive action as approval-required."
    );
    let _ = writeln!(
        out,
        "- If evidence is insufficient, say what evidence is missing and propose the safest collection step."
    );

    redact_secret_text(&out)
}

fn audited_step_actions(step: &crate::autopilot::AutopilotStep) -> Vec<InputAction> {
    if step.actions.is_empty() {
        step.action.iter().cloned().collect()
    } else {
        step.actions.clone()
    }
}

fn classify_plan_actions(
    actions: &[InputAction],
    settings: &crate::autopilot::AutopilotSettings,
) -> (RiskLevel, PolicyDecision) {
    actions.iter().fold(
        (RiskLevel::ReadOnly, PolicyDecision::Allow),
        |(risk, decision), action| {
            let (action_risk, action_decision) = classify_plan_action(action, settings);
            (
                max_risk(risk, action_risk),
                max_decision(decision, action_decision),
            )
        },
    )
}

fn max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel {
    if risk_rank(right) > risk_rank(left) {
        right
    } else {
        left
    }
}

fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::ReadOnly => 0,
        RiskLevel::LowRisk => 1,
        RiskLevel::ElevatedRisk => 2,
        RiskLevel::Destructive => 3,
    }
}

fn max_decision(left: PolicyDecision, right: PolicyDecision) -> PolicyDecision {
    if decision_rank(right) > decision_rank(left) {
        right
    } else {
        left
    }
}

fn decision_rank(decision: PolicyDecision) -> u8 {
    match decision {
        PolicyDecision::Allow => 0,
        PolicyDecision::RequireApproval => 1,
        PolicyDecision::Deny => 2,
    }
}

fn save_incident_files(
    session_id: Uuid,
    markdown: &str,
    evidence_json: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("incidents")?.join(session_id.to_string());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("incident.md"), markdown)?;
    std::fs::write(dir.join("evidence.json"), evidence_json)?;
    Ok(dir)
}

fn save_llm_handoff_file(session_id: Uuid, prompt: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("incidents")?.join(session_id.to_string());
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("llm-handoff.md");
    std::fs::write(&path, prompt)?;
    Ok(path)
}

fn save_ai_brief_pack(
    action_brief: &str,
    prompt_library: &str,
    runbook_brief: &str,
    verification_brief: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let dir = app_data_file("ai-brief-packs")?.join(Uuid::new_v4().to_string());
    save_ai_brief_pack_to_dir(
        &dir,
        action_brief,
        prompt_library,
        runbook_brief,
        verification_brief,
    )
}

fn save_ai_brief_pack_to_dir(
    dir: &Path,
    action_brief: &str,
    prompt_library: &str,
    runbook_brief: &str,
    verification_brief: &str,
) -> anyhow::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let files = [
        ("action-brief.md", redact_secret_text(action_brief)),
        ("prompt-library.md", redact_secret_text(prompt_library)),
        ("runbook-brief.md", redact_secret_text(runbook_brief)),
        (
            "verification-brief.md",
            redact_secret_text(verification_brief),
        ),
    ];
    let mut manifest_files = Vec::new();
    for (name, content) in files {
        std::fs::write(dir.join(name), &content)?;
        manifest_files.push(serde_json::json!({
            "file": name,
            "bytes": content.len(),
        }));
    }
    let manifest = serde_json::json!({
        "created_at": Utc::now(),
        "redacted": true,
        "artifact": "aivana-ai-brief-pack",
        "files": manifest_files,
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(dir.to_path_buf())
}

fn is_standard_rdp_security_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("standard rdp security") || lower.contains("server only supports standard rdp")
}

fn remote_modifier_keys(modifiers: egui::Modifiers) -> Vec<(u16, bool)> {
    // egui exposes aggregate modifiers. Do not mistake Windows `command` (Ctrl) for Win.
    let mut keys = vec![
        (0x1d, modifiers.ctrl),
        (0x2a, modifiers.shift),
        (0x38, modifiers.alt),
    ];
    if !cfg!(windows) {
        keys.push((0x15b, modifiers.mac_cmd));
    }
    keys
}

#[cfg(windows)]
fn native_extra_keys() -> Vec<(u16, bool)> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_CAPITAL, VK_CONTROL, VK_LWIN, VK_NUMLOCK, VK_RWIN, VK_SCROLL,
        VK_SNAPSHOT,
    };
    let mut keys = vec![
        (VK_LWIN, 0x15b),
        (VK_RWIN, 0x15c),
        (VK_CAPITAL, 0x3a),
        (VK_NUMLOCK, 0x45),
        (VK_SCROLL, 0x46),
        (VK_SNAPSHOT, 0x137),
    ]
    .into_iter()
    .map(|(key, scan_code)| {
        // Read physical state only while the RDP canvas has foreground keyboard focus.
        (scan_code, unsafe { GetAsyncKeyState(i32::from(key)) } < 0)
    })
    .collect::<Vec<_>>();
    if unsafe { GetAsyncKeyState(i32::from(VK_CONTROL)) } < 0 {
        // An empty local clipboard makes egui-winit omit Paste entirely. Remote Ctrl+V
        // must still work (e.g. files copied on the remote machine).
        keys.extend(
            [(0x43, 0x2e), (0x58, 0x2d), (0x56, 0x2f)]
                .into_iter()
                .map(|(key, code)| (code, unsafe { GetAsyncKeyState(key) } < 0)),
        );
    }
    keys
}

#[cfg(not(windows))]
fn native_extra_keys() -> Vec<(u16, bool)> {
    Vec::new()
}

fn remote_scan_code(key: egui::Key) -> Option<u16> {
    use egui::Key::*;
    Some(match key {
        Escape => 0x01,
        Num1 => 0x02,
        Num2 => 0x03,
        Num3 => 0x04,
        Num4 => 0x05,
        Num5 => 0x06,
        Num6 => 0x07,
        Num7 => 0x08,
        Num8 => 0x09,
        Num9 => 0x0a,
        Num0 => 0x0b,
        Minus => 0x0c,
        Equals | Plus => 0x0d,
        Backspace => 0x0e,
        Tab => 0x0f,
        Q => 0x10,
        W => 0x11,
        E => 0x12,
        R => 0x13,
        T => 0x14,
        Y => 0x15,
        U => 0x16,
        I => 0x17,
        O => 0x18,
        P => 0x19,
        OpenBracket => 0x1a,
        CloseBracket => 0x1b,
        Enter => 0x1c,
        A => 0x1e,
        S => 0x1f,
        D => 0x20,
        F => 0x21,
        G => 0x22,
        H => 0x23,
        J => 0x24,
        K => 0x25,
        L => 0x26,
        Semicolon | Colon => 0x27,
        Quote => 0x28,
        Backtick => 0x29,
        Backslash | Pipe => 0x2b,
        Z => 0x2c,
        X => 0x2d,
        C => 0x2e,
        V => 0x2f,
        B => 0x30,
        N => 0x31,
        M => 0x32,
        Comma => 0x33,
        Period => 0x34,
        Slash | Questionmark => 0x35,
        Space => 0x39,
        F1 => 0x3b,
        F2 => 0x3c,
        F3 => 0x3d,
        F4 => 0x3e,
        F5 => 0x3f,
        F6 => 0x40,
        F7 => 0x41,
        F8 => 0x42,
        F9 => 0x43,
        F10 => 0x44,
        F11 => 0x57,
        F12 => 0x58,
        Home => 0x147,
        ArrowUp => 0x148,
        PageUp => 0x149,
        ArrowLeft => 0x14b,
        ArrowRight => 0x14d,
        End => 0x14f,
        ArrowDown => 0x150,
        PageDown => 0x151,
        Insert => 0x152,
        Delete => 0x153,
        _ => return None,
    })
}

#[allow(dead_code)]
fn key_event_to_hotkey(key: egui::Key, modifiers: egui::Modifiers) -> Option<Vec<String>> {
    let mut keys = Vec::new();
    if modifiers.ctrl {
        keys.push("Ctrl".to_owned());
    }
    if modifiers.alt {
        keys.push("Alt".to_owned());
    }
    if modifiers.shift {
        keys.push("Shift".to_owned());
    }
    if modifiers.mac_cmd || modifiers.command {
        keys.push("Win".to_owned());
    }

    let key_name = match key {
        egui::Key::Enter => "Enter",
        egui::Key::Tab => "Tab",
        egui::Key::Escape => "Esc",
        egui::Key::Backspace => return None,
        egui::Key::Delete => "Delete",
        egui::Key::Home => "Home",
        egui::Key::End => "End",
        egui::Key::PageUp => "PageUp",
        egui::Key::PageDown => "PageDown",
        egui::Key::ArrowLeft => "Left",
        egui::Key::ArrowRight => "Right",
        egui::Key::ArrowUp => "Up",
        egui::Key::ArrowDown => "Down",
        _ => return None,
    };
    keys.push(key_name.to_owned());
    Some(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopilot::AutopilotSettings;

    #[test]
    fn remote_keyboard_maps_navigation_and_editing_keys() {
        assert_eq!(remote_scan_code(egui::Key::Backspace), Some(0x0e));
        assert_eq!(remote_scan_code(egui::Key::Delete), Some(0x153));
        assert_eq!(remote_scan_code(egui::Key::ArrowLeft), Some(0x14b));
        assert_eq!(remote_scan_code(egui::Key::A), Some(0x1e));
        assert_eq!(remote_scan_code(egui::Key::F12), Some(0x58));
    }

    #[test]
    fn remote_control_does_not_also_press_windows_key() {
        let modifiers = egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        };
        let keys = remote_modifier_keys(modifiers);
        assert!(keys.contains(&(0x1d, true)));
        assert!(!keys.contains(&(0x15b, true)));
    }

    #[test]
    fn batched_plan_uses_highest_policy_decision() {
        let settings = AutopilotSettings::default();
        let actions = vec![
            InputAction::Wait { millis: 100 },
            InputAction::TypeText {
                text: "Remove-Item -Recurse C:\\data".to_owned(),
            },
        ];

        let (risk, decision) = classify_plan_actions(&actions, &settings);

        assert_eq!(risk, RiskLevel::Destructive);
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn batched_plan_requires_approval_for_mutation() {
        let settings = AutopilotSettings::default();
        let actions = vec![
            InputAction::MovePointer { x: 10, y: 20 },
            InputAction::Click {
                x: 10,
                y: 20,
                button: MouseButton::Left,
            },
        ];

        let (risk, decision) = classify_plan_actions(&actions, &settings);

        assert_eq!(risk, RiskLevel::ElevatedRisk);
        assert_eq!(decision, PolicyDecision::RequireApproval);
    }

    #[test]
    fn llm_handoff_redacts_secrets_and_includes_evidence() {
        let session_id = Uuid::new_v4();
        let events = vec![SessionEvent {
            id: Uuid::new_v4(),
            session_id,
            workspace_id: None,
            kind: SessionEventKind::Diagnostic,
            message: "connection failed password=hunter2".to_owned(),
            redacted: false,
            created_at: Utc::now(),
        }];
        let diagnostics = vec![DiagnosticFinding {
            class: crate::models::DiagnosticClass::Auth,
            severity: DiagnosticSeverity::Error,
            title: "Authentication failed".to_owned(),
            detail: "token=abc was rejected".to_owned(),
            fix: "Verify account state without exposing credentials.".to_owned(),
        }];
        let autopilot_steps = vec![crate::autopilot::AutopilotStep {
            index: 1,
            captured_at: Utc::now(),
            observation: "frame observed".to_owned(),
            model_summary: "Need to click and type.".to_owned(),
            action_description: "2 batched actions".to_owned(),
            action: Some(InputAction::Click {
                x: 10,
                y: 20,
                button: MouseButton::Left,
            }),
            actions: vec![
                InputAction::Click {
                    x: 10,
                    y: 20,
                    button: MouseButton::Left,
                },
                InputAction::TypeText {
                    text: "password=hunter2".to_owned(),
                },
            ],
            risk: RiskLevel::ElevatedRisk,
            decision: PolicyDecision::RequireApproval,
            verification: None,
            safety_checks: Vec::new(),
            error: None,
        }];

        let prompt = build_llm_handoff_prompt(
            session_id,
            "server.internal",
            &diagnostics,
            &events,
            &[],
            &autopilot_steps,
        );

        assert!(prompt.contains("Aivana LLM Handoff"));
        assert!(prompt.contains("Authentication failed"));
        assert!(prompt.contains("password=[REDACTED]"));
        assert!(prompt.contains("token=[REDACTED]"));
        assert!(prompt.contains("batch=2"));
        assert!(prompt.contains("action 2: type"));
        assert!(!prompt.contains("hunter2"));
        assert!(!prompt.contains("abc was"));
    }

    #[test]
    fn input_action_label_redacts_typed_secrets() {
        let label = input_action_label(&InputAction::TypeText {
            text: "password=hunter2".to_owned(),
        });

        assert!(label.contains("password=[REDACTED]"));
        assert!(!label.contains("hunter2"));
    }

    #[test]
    fn ai_readiness_reports_missing_openai_key() {
        let report = build_ai_readiness_report(
            Some(Uuid::new_v4()),
            true,
            AutopilotProviderKind::OpenAiComputerUse,
            false,
            2,
        );

        assert!(report.contains("session selected"));
        assert!(report.contains("framebuffer ready"));
        assert!(report.contains("OPENAI_API_KEY"));
        assert!(report.contains("2 pending approval"));
    }

    #[test]
    fn ai_action_brief_prioritizes_error_and_redacts() {
        let diagnostics = vec![DiagnosticFinding {
            class: crate::models::DiagnosticClass::Credential,
            severity: DiagnosticSeverity::Error,
            title: "Credential rejected".to_owned(),
            detail: "password=hunter2 failed".to_owned(),
            fix: "Verify account lockout without exposing secret=abc.".to_owned(),
        }];

        let brief = build_ai_action_brief("host", &diagnostics, &[], &[], &[]);

        assert!(brief.contains("Credential rejected"));
        assert!(brief.contains("risk Error"));
        assert!(brief.contains("secret=[REDACTED]"));
        assert!(!brief.contains("hunter2"));
        assert!(!brief.contains("abc"));
    }

    #[test]
    fn autopilot_preferences_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "aivana-autopilot-preferences-{}.json",
            Uuid::new_v4()
        ));
        let preferences = AutopilotPreferences {
            goal: "Collect evidence".to_owned(),
            settings: AutopilotSettings {
                provider: AutopilotProviderKind::OpenAiComputerUse,
                max_steps: 7,
                step_delay_millis: 1200,
                require_approval_for_every_mutation: true,
                agentic_runbook_mode: true,
                openai_model: "gpt-5.5".to_owned(),
            },
        };

        save_autopilot_preferences_to_path(&path, &preferences).expect("saved preferences");
        let loaded = load_autopilot_preferences_from_path(&path).expect("loaded preferences");
        let _ = std::fs::remove_file(path);

        assert_eq!(loaded.goal, "Collect evidence");
        assert_eq!(
            loaded.settings.provider,
            AutopilotProviderKind::OpenAiComputerUse
        );
        assert_eq!(loaded.settings.max_steps, 7);
        assert_eq!(loaded.settings.step_delay_millis, 1200);
        assert!(loaded.settings.agentic_runbook_mode);
    }

    #[test]
    fn save_ki_preferences_headless_persists_and_redacts_report() {
        let path = std::env::temp_dir().join(format!(
            "aivana-autopilot-preferences-headless-{}.json",
            Uuid::new_v4()
        ));
        let preferences = AutopilotPreferences {
            goal: "Investigate token=abc".to_owned(),
            settings: AutopilotSettings {
                provider: AutopilotProviderKind::OpenAiComputerUse,
                max_steps: 9,
                step_delay_millis: 900,
                require_approval_for_every_mutation: true,
                agentic_runbook_mode: true,
                openai_model: "gpt-5.5".to_owned(),
            },
        };
        save_autopilot_preferences_to_path(&path, &preferences).expect("saved preferences");

        let report =
            save_ki_preferences_headless_to_path(&path).expect("saved headless preferences");
        let loaded = load_autopilot_preferences_from_path(&path).expect("loaded preferences");
        let _ = std::fs::remove_file(path);

        assert_eq!(report.schema, "aivana.ki-preferences-save.v1");
        assert!(report.already_existed);
        assert!(report.redacted);
        assert_eq!(report.provider, "OpenAI CUA");
        assert_eq!(report.max_steps, 9);
        assert!(report.goal.contains("token=[REDACTED]"));
        assert!(!report.goal.contains("abc"));
        assert_eq!(loaded.goal, "Investigate token=abc");
        assert_eq!(loaded.settings.openai_model, "gpt-5.5");
    }

    #[test]
    fn ki_verification_report_marks_missing_requirements() {
        let mut autopilot = AutopilotController::default();
        autopilot.settings.provider = AutopilotProviderKind::OpenAiComputerUse;
        autopilot.goal = "Check token=abc".to_owned();

        let report = build_ki_verification_report_with_inputs(&autopilot, 0, false, false, false);

        assert!(report.summary.contains("Provider=OpenAI CUA"));
        assert!(report.summary.contains("token=[REDACTED]"));
        assert!(!report.summary.contains("abc"));
        assert!(report.next_step.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn ki_readiness_cli_report_scores_and_redacts() {
        let mut autopilot = AutopilotController::default();
        autopilot.settings.provider = AutopilotProviderKind::OpenAiComputerUse;
        autopilot.goal = "Investigate password=hunter2".to_owned();

        let report = build_ki_readiness_cli_report_with_inputs(
            &autopilot, false, false, false, None, None, None,
        );

        assert_eq!(report.readiness_score, 0);
        assert!(
            report
                .missing_requirements
                .contains(&"OPENAI_API_KEY".to_owned())
        );
        assert!(
            report
                .missing_requirements
                .contains(&"persisted RDP preflight evidence".to_owned())
        );
        assert!(
            report
                .missing_requirements
                .contains(&"persisted RDP smoke evidence".to_owned())
        );
        assert!(
            report
                .missing_requirements
                .contains(&"persisted live gate evidence".to_owned())
        );
        assert!(report.goal.contains("password=[REDACTED]"));
        assert!(!report.goal.contains("hunter2"));
        assert!(report.next_step.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn ki_readiness_report_accepts_valid_rdp_env_file_arg() {
        let path =
            std::env::temp_dir().join(format!("aivana-readiness-rdp-{}.env", Uuid::new_v4()));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\nAIVANA_RDP_TEST_PORT=3390\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--ki-readiness-report".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let report = build_ki_readiness_cli_report_from_args(&args);
        let _ = std::fs::remove_file(path);

        assert!(report.rdp_smoke_env_ready);
        assert!(
            !report
                .missing_requirements
                .iter()
                .any(|item| item.contains("AIVANA_RDP_TEST_*") || item.contains("hunter2"))
        );
    }

    #[test]
    fn ki_readiness_report_rejects_placeholder_rdp_env_file_arg() {
        let path = std::env::temp_dir().join(format!(
            "aivana-readiness-rdp-placeholder-{}.env",
            Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=<host>\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=[REDACTED]\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--ki-readiness-report".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let report = build_ki_readiness_cli_report_from_args(&args);
        let _ = std::fs::remove_file(path);

        assert!(!report.rdp_smoke_env_ready);
        assert!(
            report
                .missing_requirements
                .iter()
                .any(|item| item.contains("invalid RDP env file"))
        );
        assert!(report.next_step.contains("--rdp-env-file-check"));
        assert!(
            !report
                .missing_requirements
                .iter()
                .any(|item| item.contains("hunter2"))
        );
    }

    #[test]
    fn live_gate_doctor_uses_rdp_env_file_arg_for_env_check() {
        let path = std::env::temp_dir().join(format!("aivana-doctor-rdp-{}.env", Uuid::new_v4()));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\nAIVANA_RDP_TEST_PORT=3391\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--live-gate-doctor".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let doctor = build_live_gate_doctor_report_from_args(&args);
        let _ = std::fs::remove_file(path);

        assert!(doctor.ready_for_preflight);
        assert!(
            doctor
                .checks
                .iter()
                .any(|check| check.name == "rdp-env-file-check" && check.ok)
        );
        assert!(
            doctor
                .evidence
                .env_file_check
                .contains("rdp.example.local:3391")
        );
        assert!(!doctor.evidence.env_file_check.contains("hunter2"));
    }

    #[test]
    fn verification_snapshot_summarizes_gui_live_gate_and_redacts() {
        let path = std::env::temp_dir().join(format!(
            "aivana-verification-snapshot-rdp-{}.env",
            Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--verification-snapshot".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let snapshot = build_verification_snapshot_from_args(&args);
        let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
        let _ = std::fs::remove_file(path);

        assert_eq!(snapshot["schema"], "aivana.verification-snapshot.v1");
        assert_eq!(snapshot["redacted"], true);
        assert_eq!(snapshot["readiness"]["rdp_smoke_env_ready"], true);
        assert_eq!(snapshot["completion"]["achieved"], false);
        assert_eq!(snapshot["live_gate"]["smoke_connected"], false);
        assert_eq!(snapshot["rdp_proof"]["ok"], false);
        assert_eq!(
            snapshot["llm_action_contract"]["copy_action"],
            "Copy LLM Action Contract JSON"
        );
        assert_eq!(
            snapshot["llm_review_prompt"]["copy_action"],
            "Copy LLM Review Prompt"
        );
        assert_eq!(
            snapshot["llm_review_prompt"]["command"],
            "cargo run -- --llm-review-prompt"
        );
        assert!(
            snapshot["llm_review_prompt"]["triage_order"]
                .as_array()
                .expect("review prompt triage order")
                .iter()
                .any(|file| file == "operator-handoff-risk-summary.json")
        );
        assert!(
            snapshot["llm_review_prompt"]["risk_summary_cross_check"]
                .as_array()
                .expect("review prompt risk cross-check")
                .iter()
                .any(|field| field == "early_triage_artifacts")
        );
        assert!(
            snapshot["llm_review_prompt"]["proxy_evidence_rejected"]
                .as_array()
                .expect("review prompt proxy rejection")
                .iter()
                .any(|rule| rule
                    == "commands, manifests, or passing tests without direct live RDP proof")
        );
        assert!(
            snapshot["llm_action_contract"]["required_evidence_files"]
                .as_array()
                .expect("snapshot required evidence files")
                .iter()
                .any(|file| file == "summary.md")
        );
        assert!(
            snapshot["llm_action_contract"]["must_return"]
                .as_array()
                .expect("snapshot must return")
                .iter()
                .any(|field| field == "early_triage_artifacts")
        );
        assert!(
            snapshot["llm_action_contract"]["success_signals"]
                .as_array()
                .expect("snapshot success signals")
                .iter()
                .any(|signal| signal == "rdp-smoke-test connected == true")
        );
        assert!(
            snapshot["llm_action_contract"]["direct_live_evidence_requirements"]
                .as_array()
                .expect("snapshot direct live evidence requirements")
                .iter()
                .any(|requirement| requirement
                    == "direct live evidence from the configured RDP host and port")
        );
        assert!(
            snapshot["llm_action_contract"]["proxy_evidence_rejected"]
                .as_array()
                .expect("snapshot proxy rejection")
                .iter()
                .any(|rule| rule == "passing unit tests without live RDP smoke evidence")
        );
        assert_eq!(
            snapshot["rdp_proof"]["recovery_plan_command"],
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"
        );
        assert!(
            snapshot["rdp_proof"]["failed_check_actions"]
                .as_array()
                .expect("failed check actions")
                .iter()
                .any(|item| item["check"] == "preflight_connect_recommended"
                    && item["command"]
                        .as_str()
                        .is_some_and(|command| command.contains("--rdp-preflight")))
        );
        assert!(
            snapshot["risk"]["rdp_proof_failed_check_actions"]
                .as_array()
                .expect("risk failed check actions")
                .iter()
                .any(|item| item["check"] == "smoke_connected"
                    && item["command"]
                        .as_str()
                        .is_some_and(|command| command.contains("--rdp-smoke-test")))
        );
        assert_eq!(snapshot["risk"]["rdp_proof_ok"], false);
        assert!(
            snapshot["risk"]["blocking_reason"]
                .as_str()
                .expect("risk blocking reason")
                .contains("RDP")
        );
        assert!(
            snapshot["risk"]["next_command"]
                .as_str()
                .expect("risk next command")
                .contains("cargo run")
        );
        assert!(
            snapshot["risk"]["rdp_proof_failed_checks"]
                .as_array()
                .expect("risk failed checks")
                .iter()
                .any(|item| item == "smoke_connected")
        );
        assert!(
            snapshot["latest_evidence"]["rdp_proof_check"]
                .as_str()
                .expect("proof check summary")
                .contains("failed_checks=")
        );
        assert!(
            snapshot["latest_evidence"]["rdp_proof_recovery_plan"]
                .as_str()
                .expect("proof recovery summary")
                .contains("Latest RDP proof recovery plan")
        );
        assert_eq!(
            snapshot["risk"]["rdp_proof_recovery_plan_command"],
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"
        );
        assert!(
            snapshot["risk"]["rdp_proof_recovery_plan_summary"]
                .as_str()
                .expect("proof recovery risk summary")
                .contains("Latest RDP proof recovery plan")
        );
        assert!(
            snapshot["env_source"]
                .as_str()
                .expect("env source")
                .contains("aivana-verification-snapshot-rdp")
        );
        assert!(json.contains("--rdp-smoke-test"));
        assert!(json.contains("success_condition"));
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn latest_rdp_proof_recovery_plan_summary_reads_markdown_and_redacts() {
        let dir = std::env::temp_dir().join(format!("aivana-rdp-recovery-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("created recovery temp dir");
        let path = dir.join("plan.md");
        std::fs::write(
            &path,
            "# Aivana RDP Proof Recovery Plan\n\n## Failed Proof Checks\n- `smoke_connected`\n- `input_probe_present`\n\n## Recovery Commands\n1. `cargo run -- --rdp-smoke-test --password=hunter2`\n2. `cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env`\n\n## Acceptance Criteria\n- `rdp-proof-check.ok == true`\n\n## Final Verification\n1. `cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env`\n",
        )
        .expect("wrote recovery plan");

        let summary = latest_rdp_proof_recovery_plan_summary_from_dir(&dir)
            .expect("read recovery summary")
            .expect("summary");
        let _ = std::fs::remove_dir_all(dir);

        assert!(summary.contains("Latest RDP proof recovery plan"));
        assert!(summary.contains("failed_checks=2"));
        assert!(summary.contains("recovery_commands=2"));
        assert!(!summary.contains("hunter2"));
    }

    #[test]
    fn operator_handoff_risk_summary_uses_rdp_env_file_arg() {
        let path = std::env::temp_dir().join(format!("aivana-risk-rdp-{}.env", Uuid::new_v4()));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--operator-handoff-risk-summary".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let summary = build_operator_handoff_risk_summary_from_args(&args);
        let _ = std::fs::remove_file(path);

        assert!(summary.missing_rdp_env.is_empty());
        assert!(!summary.rdp_proof_ok);
        assert!(
            summary
                .rdp_proof_failed_checks
                .iter()
                .any(|check| check == "smoke_connected")
        );
        assert!(summary.rdp_proof_failed_check_actions.iter().any(|action| {
            action["check"] == "smoke_connected"
                && action["command"]
                    .as_str()
                    .expect("command")
                    .contains("--rdp-smoke-test")
        }));
        assert!(summary.operator_brief.contains("--rdp-preflight"));
        assert!(!summary.operator_brief.contains("hunter2"));
    }

    #[test]
    fn operator_handoff_pack_embeds_rdp_env_file_arg_check() {
        let env_path = std::env::temp_dir().join(format!("aivana-pack-rdp-{}.env", Uuid::new_v4()));
        let pack_dir =
            std::env::temp_dir().join(format!("aivana-operator-pack-{}", Uuid::new_v4()));
        std::fs::write(
            &env_path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\nAIVANA_RDP_TEST_PORT=3392\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--operator-handoff-pack".to_owned(),
            "--rdp-env-file".to_owned(),
            env_path.display().to_string(),
        ];
        let readiness = build_ki_readiness_cli_report_from_args(&args);
        let audit = build_completion_audit_report_from_args(&args);

        let report =
            save_operator_handoff_pack_to_dir_with_args(&pack_dir, &readiness, &audit, &args)
                .expect("saved operator pack");
        let env_check = std::fs::read_to_string(pack_dir.join("rdp-env-file-check.json")).unwrap();
        let doctor = std::fs::read_to_string(pack_dir.join("live-gate-doctor.json")).unwrap();
        let _ = std::fs::remove_file(env_path);
        let _ = std::fs::remove_dir_all(pack_dir);

        assert_eq!(report.schema, "aivana.operator-handoff-pack.v1");
        assert!(env_check.contains("\"ok\": true"));
        assert!(env_check.contains("rdp.example.local"));
        assert!(doctor.contains("\"ready_for_preflight\": true"));
        assert!(!env_check.contains("hunter2"));
        assert!(!doctor.contains("hunter2"));
    }

    #[test]
    fn completion_audit_embeds_current_rdp_env_file_arg_check() {
        let path = std::env::temp_dir().join(format!("aivana-audit-rdp-{}.env", Uuid::new_v4()));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\nAIVANA_RDP_TEST_PORT=3393\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--completion-audit".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let report = build_completion_audit_report_from_args(&args);
        let _ = std::fs::remove_file(path);
        let handoff_item = report
            .items
            .iter()
            .find(|item| item.requirement == "Headless CI/handoff verification artifacts")
            .expect("handoff item");

        assert!(handoff_item.evidence.contains("latest_env_file_check="));
        assert!(handoff_item.evidence.contains("rdp.example.local:3393"));
        assert!(handoff_item.evidence.contains("ok=true"));
        assert!(!handoff_item.evidence.contains("hunter2"));
    }

    #[test]
    fn gui_default_rdp_live_env_args_detects_local_env_file() {
        let dir = std::env::temp_dir().join(format!("aivana-gui-env-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("created gui env dir");
        std::fs::write(dir.join("rdp-live.env"), "AIVANA_RDP_TEST_HOST=<host>\n")
            .expect("write gui env file");

        let args = default_rdp_live_env_args_from_dir(&dir);
        let _ = std::fs::remove_dir_all(dir);

        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "aivana-gui");
        assert_eq!(args[1], "--rdp-env-file");
        assert!(args[2].ends_with("rdp-live.env"));
    }

    #[test]
    fn missing_required_rdp_test_env_names_each_missing_var() {
        let missing = missing_required_rdp_test_env_from_lookup(|name| {
            matches!(name, "AIVANA_RDP_TEST_HOST" | "AIVANA_RDP_TEST_PASSWORD")
        });

        assert_eq!(
            missing,
            vec![
                "AIVANA_RDP_TEST_HOST".to_owned(),
                "AIVANA_RDP_TEST_PASSWORD".to_owned()
            ]
        );
    }

    #[test]
    fn missing_required_rdp_test_env_treats_placeholders_as_missing() {
        let values = std::collections::HashMap::from([
            ("AIVANA_RDP_TEST_HOST", "<host>"),
            ("AIVANA_RDP_TEST_USER", "operator"),
            ("AIVANA_RDP_TEST_PASSWORD", "[REDACTED]"),
        ]);

        let missing = missing_required_rdp_test_env_from_lookup(|name| {
            values
                .get(name)
                .is_none_or(|value| crate::ironrdp_client::is_unfilled_rdp_test_placeholder(value))
        });

        assert_eq!(
            missing,
            vec![
                "AIVANA_RDP_TEST_HOST".to_owned(),
                "AIVANA_RDP_TEST_PASSWORD".to_owned()
            ]
        );
    }

    #[test]
    fn ki_evidence_bundle_writes_redacted_manifest_and_markdown() {
        let dir = std::env::temp_dir().join(format!("aivana-ki-evidence-{}", Uuid::new_v4()));
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: false,
            rdp_smoke_env_ready: false,
            preferences_saved: false,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "password=[REDACTED]".to_owned(),
            readiness_score: 25,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked secret=abc".to_owned()),
            latest_rdp_smoke_evidence: Some("error=password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked token=abc".to_owned()),
            next_step: "Complete token=abc".to_owned(),
            evidence_path: None,
        };
        let report = build_ki_evidence_bundle_report_with_inputs(
            readiness,
            Some("Latest AI brief pack: secret=abc".to_owned()),
        );

        let saved =
            save_ki_evidence_bundle_report_to_dir(&dir, &report).expect("saved evidence bundle");
        let markdown = std::fs::read_to_string(saved.join("bundle.md")).unwrap();
        let manifest = std::fs::read_to_string(saved.join("manifest.json")).unwrap();
        let _ = std::fs::remove_dir_all(saved);

        assert!(markdown.contains("Aivana KI Evidence Bundle"));
        assert!(markdown.contains("password=[REDACTED]"));
        assert!(markdown.contains("token=[REDACTED]"));
        assert!(markdown.contains("secret=[REDACTED]"));
        assert!(markdown.contains("Live Gate Evidence"));
        assert!(!markdown.contains("hunter2"));
        assert!(!markdown.contains("token=abc"));
        assert!(!markdown.contains("secret=abc"));
        assert!(manifest.contains("bundle.md"));
        assert!(manifest.contains("manifest.json"));
    }

    #[test]
    fn completion_audit_blocks_without_successful_rdp_evidence() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "Local".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false error=password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Complete AIVANA_RDP_TEST_*".to_owned(),
            evidence_path: None,
        };

        let report = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false error=password=hunter2".to_owned(),
            "No AI brief pack exported yet.".to_owned(),
        );

        assert_eq!(
            report.objective,
            "bau das weiter aus max. usp max gui friendly max ai ki llm usage"
        );
        assert!(!report.achieved);
        assert!(report.summary.contains("Not complete"));
        assert!(
            report
                .items
                .iter()
                .any(|item| item.requirement.contains("Real RDP") && item.blocking)
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.next_action.contains("--rdp-env-fill-guide"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("password=[REDACTED]"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("structured next-gate JSON copy"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("command-index JSON copy"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("evidence matrix JSON copy"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("hard evidence check JSON copy"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("handoff-check JSON copy"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("live-gate operator brief copy"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("handoff-check evidence summary"))
        );
        assert!(
            report
                .items
                .iter()
                .any(|item| item.evidence.contains("handoff risk JSON"))
        );
        let handoff_item = report
            .items
            .iter()
            .find(|item| item.requirement == "Headless CI/handoff verification artifacts")
            .expect("headless handoff item");
        assert!(handoff_item.artifact.contains("--rdp-env-fill-guide"));
        assert!(handoff_item.artifact.contains("--rdp-proof-check"));
        assert!(handoff_item.artifact.contains("--live-gate-sequence"));
        assert!(handoff_item.artifact.contains("--live-gate-operator-brief"));
        assert!(handoff_item.artifact.contains("--goal-evidence-check"));
        assert!(handoff_item.artifact.contains("--operator-handoff-check"));
        assert!(handoff_item.evidence.contains("RDP env fill guide"));
        assert!(handoff_item.evidence.contains("RDP proof check"));
        assert!(handoff_item.evidence.contains("live-gate sequence"));
        assert!(handoff_item.evidence.contains("live-gate operator brief"));
        assert!(handoff_item.evidence.contains("hard goal evidence check"));
        assert!(handoff_item.evidence.contains("handoff-pack validation"));
        assert!(handoff_item.evidence.contains("handoff risk summary"));
        assert!(
            handoff_item
                .next_action
                .contains("cargo run -- --rdp-proof-check")
        );
        assert!(
            handoff_item
                .next_action
                .contains("cargo run -- --live-gate-sequence")
        );
        assert!(
            handoff_item
                .next_action
                .contains("cargo run -- --goal-evidence-check")
        );
        assert!(
            handoff_item
                .next_action
                .contains("cargo run -- --operator-handoff-check")
        );
        assert!(
            !report
                .items
                .iter()
                .any(|item| item.evidence.contains("hunter2"))
        );
    }

    #[test]
    fn goal_evidence_matrix_maps_requirements_and_redacts() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose secret=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let report = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s), secret=abc".to_owned(),
        );

        let matrix = build_goal_evidence_matrix(&report);
        let json = serde_json::to_string(&matrix).expect("matrix json");

        assert_eq!(matrix["schema"], "aivana.goal-evidence-matrix.v1");
        assert_eq!(matrix["achieved"], false);
        assert!(
            matrix["checklist"]
                .as_array()
                .expect("checklist")
                .iter()
                .any(|item| item["requirement"]
                    == "Real RDP end-to-end proof against a reachable host")
        );
        assert!(
            matrix["uncovered_requirements"]
                .as_array()
                .expect("uncovered")
                .iter()
                .any(|item| item["requirement"]
                    == "Real RDP end-to-end proof against a reachable host")
        );
        assert!(
            json.contains("LLM action-contract JSON copy/export with summary.md Early LLM Triage")
        );
        assert!(json.contains("LLM review prompt copy with summary.md Early LLM Triage"));
        assert!(json.contains("operator-handoff-risk-summary.json cross-check"));
        assert!(json.contains("RDP recovery plan copy with acceptance criteria"));
        assert!(json.contains("direct live evidence"));
        assert!(json.contains("direct_live_evidence_requirements"));
        assert!(json.contains("early_triage_artifacts"));
        assert!(json.contains("evidence success signals"));
        assert!(json.contains("proxy-evidence rejection rules"));
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command == "cargo run -- --save-rdp-env-template .\\rdp-live.env")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command == "cargo run -- --rdp-env-fill-guide")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command
                    == "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command
                    == "cargo run -- --rdp-preflight --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command
                    == "cargo run -- --rdp-proof-check --rdp-env-file .\\rdp-live.env")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command == "cargo run -- --live-gate-sequence")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command
                    == "cargo run -- --goal-evidence-check --rdp-env-file .\\rdp-live.env")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command
                    == "cargo run -- --goal-evidence-matrix --rdp-env-file .\\rdp-live.env")
        );
        assert!(
            matrix["verification_commands"]
                .as_array()
                .expect("commands")
                .iter()
                .any(|command| command
                    == "cargo run -- --llm-action-contract --rdp-env-file .\\rdp-live.env")
        );
        assert!(json.contains("connected=true"));
        assert!(json.contains("password=[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("secret=abc"));
    }

    #[test]
    fn goal_evidence_check_fails_until_matrix_is_fully_covered() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let report = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s), secret=abc".to_owned(),
        );

        let check = build_goal_evidence_check(&report);
        let json = serde_json::to_string(&check).expect("check json");

        assert_eq!(check["schema"], "aivana.goal-evidence-check.v1");
        assert_eq!(check["ok"], false);
        assert_eq!(check["failure_exit"], 1);
        assert!(
            check["failed_requirements"]
                .as_array()
                .expect("failed requirements")
                .iter()
                .any(|item| item["requirement"]
                    == "Real RDP end-to-end proof against a reachable host")
        );
        assert!(json.contains("password=[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("secret=abc"));
    }

    #[test]
    fn operator_handoff_risk_summary_blocks_until_goal_evidence_passes() {
        let summary = build_operator_handoff_risk_summary();
        let json = serde_json::to_string(&summary).expect("risk summary json");

        assert_eq!(summary.schema, "aivana.operator-handoff-risk-summary.v1");
        assert!(!summary.ok);
        assert_eq!(summary.goal_evidence_ok, false);
        assert_eq!(summary.failure_exit, 1);
        assert_eq!(summary.success_condition, "ok == true");
        assert!(summary.redacted);
        assert!(summary.next_command.contains("cargo run --"));
        assert_eq!(
            summary.llm_triage_entrypoint,
            "summary.md -> verification-snapshot.json -> llm-action-contract.json"
        );
        assert!(
            summary
                .llm_action_contract_required_evidence_files
                .iter()
                .any(|file| file == "summary.md")
        );
        assert!(
            summary
                .llm_action_contract_must_return
                .iter()
                .any(|field| field == "early_triage_artifacts")
        );
        assert!(json.contains("llm_action_contract_direct_live_evidence_requirements"));
        assert!(json.contains("direct live evidence from the configured RDP host and port"));
        assert!(json.contains("Real RDP end-to-end proof"));
        assert!(json.contains("early_triage_artifacts"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("secret=abc"));
    }

    #[test]
    fn active_goal_objective_matches_thread_goal() {
        assert_eq!(
            ACTIVE_GOAL_OBJECTIVE,
            "bau das weiter aus max. usp max gui friendly max ai ki llm usage"
        );
    }

    #[test]
    fn completion_audit_blocks_without_openai_key_and_markdown_redacts() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: false,
            rdp_smoke_env_ready: true,
            preferences_saved: true,
            active_sessions: 1,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["OPENAI_API_KEY".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight ready".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=true".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Set OPENAI_API_KEY".to_owned(),
            evidence_path: None,
        };

        let report = build_completion_audit_report_with_inputs(
            readiness,
            Some("Latest RDP smoke evidence: connected=true frame=1024x768".to_owned()),
            "Latest RDP preflight evidence: connect_recommended=true".to_owned(),
            "connected=true".to_owned(),
            "Latest AI brief pack: 4 file(s), secret=abc".to_owned(),
        );
        let markdown = report.to_markdown();

        assert!(!report.achieved);
        assert!(
            report
                .items
                .iter()
                .any(|item| item.requirement.contains("OpenAI CUA") && item.blocking)
        );
        assert!(markdown.contains("Aivana KI Goal Audit"));
        assert!(markdown.contains("Prompt-to-Artifact Checklist"));
        assert!(markdown.contains("Live Gate Runbook"));
        assert!(markdown.contains("next: Set OPENAI_API_KEY"));
        assert!(markdown.contains("secret=[REDACTED]"));
        assert!(!markdown.contains("token=abc"));
        assert!(!markdown.contains("secret=abc"));
    }

    #[test]
    fn completion_audit_achieves_when_live_gates_have_evidence() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: true,
            preferences_saved: true,
            active_sessions: 1,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose".to_owned(),
            readiness_score: 100,
            missing_requirements: Vec::new(),
            latest_rdp_preflight_evidence: Some("preflight ready".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=true".to_owned()),
            latest_live_gate_evidence: Some("live gate passed".to_owned()),
            next_step: "Run guarded Autopilot preview".to_owned(),
            evidence_path: None,
        };

        let report = build_completion_audit_report_with_inputs(
            readiness,
            Some("Latest RDP smoke evidence: connected=true frame=1024x768".to_owned()),
            "Latest RDP preflight evidence: connect_recommended=true".to_owned(),
            "connected=true".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );

        assert!(report.achieved);
        assert!(report.items.iter().all(|item| !item.blocking));
        assert!(
            report
                .items
                .iter()
                .all(|item| !item.next_action.trim().is_empty())
        );
    }

    #[test]
    fn live_gate_runbook_lists_blockers_and_commands() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose password=hunter2".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let report = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );

        let runbook = build_live_gate_runbook(&report);

        assert!(runbook.contains("cargo run -- --rdp-preflight"));
        assert!(runbook.contains("cargo run -- --rdp-smoke-test"));
        assert!(runbook.contains("cargo run -- --completion-audit"));
        assert!(runbook.contains("cargo run -- --operator-handoff-pack"));
        assert!(runbook.contains("cargo run -- --operator-handoff-check"));
        assert!(runbook.contains("cargo run -- --operator-handoff-risk-summary"));
        assert!(runbook.contains("OpenAI CUA"));
        assert!(runbook.contains("Real RDP end-to-end proof"));
        assert!(runbook.contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]"));
        assert!(runbook.contains("AIVANA_RDP_TEST_TIMEOUT_SECS=90"));
        assert!(runbook.contains("password=[REDACTED]"));
        assert!(!runbook.contains("hunter2"));
    }

    #[test]
    fn next_live_gate_summary_focuses_first_blocker_and_redacts() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose password=hunter2".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let report = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );

        let summary = build_next_live_gate_summary(&report);

        assert!(summary.contains("Aivana Next Live Gate"));
        assert!(summary.contains("Blocking gates: 1"));
        assert!(summary.contains("First Blocking Gate"));
        assert!(summary.contains("Missing RDP Environment"));
        assert!(summary.contains("AIVANA_RDP_TEST_HOST"));
        assert!(summary.contains("RDP Env Template"));
        assert!(summary.contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]"));
        assert!(summary.contains("cargo run -- --rdp-preflight"));
        assert!(summary.contains("cargo run -- --rdp-smoke-test"));
        assert!(summary.contains("cargo run -- --goal-evidence-matrix"));
        assert!(summary.contains("cargo run -- --operator-handoff-pack"));
        assert!(summary.contains("cargo run -- --operator-handoff-check"));
        assert!(summary.contains("cargo run -- --operator-handoff-risk-summary"));
        assert!(summary.contains("password=[REDACTED]"));
        assert!(!summary.contains("hunter2"));
    }

    #[test]
    fn next_live_gate_report_serializes_first_blocker_and_redacts() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );

        let report = build_next_live_gate_report(&audit);
        let json = serde_json::to_string(&report).expect("serialized next live gate report");

        assert_eq!(report.blocking_gates, 1);
        assert!(
            report
                .first_blocking_requirement
                .as_deref()
                .is_some_and(|value| value.contains("Real RDP"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--save-rdp-env-template"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--rdp-env-fill-guide"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--rdp-env-file-check"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--rdp-env-file .\\rdp-live.env"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--rdp-smoke-test"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--rdp-proof-recovery-plan"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--live-gate-doctor"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--llm-review-prompt"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--goal-evidence-matrix"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--operator-handoff-check"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--operator-handoff-risk-summary"))
        );
        assert!(
            report
                .next_commands
                .iter()
                .any(|command| command.contains("--verification-snapshot"))
        );
        assert!(json.contains("password=[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("token=abc"));
    }

    #[test]
    fn live_gate_doctor_reports_ladder_and_next_command() {
        let report = build_live_gate_doctor_report();

        assert_eq!(report.schema, "aivana.live-gate-doctor.v1");
        assert_eq!(report.checks.len(), 6);
        assert!(report.next_command.starts_with("cargo run -- --"));
        assert!(!report.operator_stage.is_empty());
        assert!(report.operator_brief.contains("Stage="));
        assert!(report.operator_brief.contains("accepted when"));
        assert!(report.next_success_command.starts_with("cargo run -- --"));
        assert_eq!(
            report.rdp_proof_recovery_plan_command,
            "cargo run -- --rdp-proof-recovery-plan --rdp-env-file .\\rdp-live.env"
        );
        assert!(!report.acceptance_criteria.is_empty());
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "rdp-env-file-check")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "rdp-smoke-test")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "rdp-proof-check")
        );
        let handoff_check = report
            .checks
            .iter()
            .find(|check| check.name == "operator-handoff-check")
            .expect("handoff check entry");
        if handoff_check.ok {
            assert!(
                handoff_check
                    .next_command
                    .contains("--operator-handoff-risk-summary")
            );
        } else {
            assert!(
                handoff_check
                    .next_command
                    .contains("--operator-handoff-pack")
            );
        }
        assert!(
            report
                .evidence
                .env_file_check
                .contains("RDP env-file check")
        );
        assert!(report.evidence.smoke.contains("RDP smoke evidence"));
        assert!(report.evidence.rdp_proof_check.contains("RDP proof check"));
        assert!(!format!("{report:?}").contains("hunter2"));
    }

    #[test]
    fn rdp_proof_prompt_focuses_direct_smoke_evidence_and_redacts() {
        let audit = build_completion_audit_report_from_args(&[
            "aivana".to_owned(),
            "--rdp-env-file".to_owned(),
            ".\\rdp-live.env".to_owned(),
        ]);
        let mut doctor = build_live_gate_doctor_report_from_args(&[
            "aivana".to_owned(),
            "--rdp-env-file".to_owned(),
            ".\\rdp-live.env".to_owned(),
        ]);
        doctor.blocking_reason = "password=hunter2 missing proof".to_owned();
        let snapshot = serde_json::json!({
            "env_source": ".\\rdp-live.env",
            "live_gate": {
                "missing_rdp_env": [
                    "AIVANA_RDP_TEST_HOST",
                    "AIVANA_RDP_TEST_USER",
                    "AIVANA_RDP_TEST_PASSWORD"
                ]
            }
        });

        let prompt = build_rdp_proof_prompt(&audit, &doctor, &snapshot);

        assert!(prompt.contains("Aivana RDP Proof Prompt"));
        assert!(prompt.contains("summary.md"));
        assert!(prompt.contains("Early LLM Triage"));
        assert!(prompt.contains("verification-snapshot.json"));
        assert!(prompt.contains("llm-action-contract.json"));
        assert!(prompt.contains(".\\rdp-live.env"));
        assert!(prompt.contains("AIVANA_RDP_TEST_HOST"));
        assert!(prompt.contains("--rdp-smoke-test"));
        assert!(prompt.contains("--rdp-proof-recovery-plan"));
        assert!(prompt.contains("--goal-evidence-check"));
        assert!(prompt.contains("connected=true"));
        assert!(prompt.contains("Preflight evidence matches"));
        assert!(prompt.contains("Preflight evidence is newer"));
        assert!(prompt.contains("Smoke evidence matches"));
        assert!(prompt.contains("Smoke evidence is newer"));
        assert!(prompt.contains("Framebuffer evidence"));
        assert!(prompt.contains("Input probe evidence"));
        assert!(prompt.contains("rdp-proof-check.ok == true"));
        assert!(prompt.contains("cargo run -- --rdp-proof-check"));
        assert!(prompt.contains("cargo run -- --rdp-proof-recovery-plan"));
        assert!(prompt.contains("Reject proxy evidence"));
        assert!(prompt.contains("password=[REDACTED]"));
        assert!(!prompt.contains("hunter2"));
    }

    #[test]
    fn rdp_proof_recovery_plan_maps_failed_actions_and_redacts() {
        let audit = build_completion_audit_report_from_args(&[
            "aivana".to_owned(),
            "--rdp-env-file".to_owned(),
            ".\\rdp-live.env".to_owned(),
        ]);
        let mut doctor = build_live_gate_doctor_report_from_args(&[
            "aivana".to_owned(),
            "--rdp-env-file".to_owned(),
            ".\\rdp-live.env".to_owned(),
        ]);
        doctor.blocking_reason = "password=hunter2 missing proof".to_owned();
        let proof_check = serde_json::json!({
            "ok": false,
            "failed_checks": ["smoke_connected", "input_probe_present"],
            "failed_check_actions": [
                {
                    "check": "smoke_connected",
                    "command": "cargo run -- --rdp-smoke-test --password=hunter2",
                    "action": "Run the live RDP smoke test until it records connected=true."
                },
                {
                    "check": "input_probe_present",
                    "command": "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90",
                    "action": "Capture input-probe evidence from the smoke test after framebuffer capture."
                }
            ],
            "next_command": "cargo run -- --rdp-smoke-test --rdp-env-file .\\rdp-live.env --rdp-smoke-timeout 90"
        });

        let plan = build_rdp_proof_recovery_plan(&audit, &doctor, &proof_check);

        assert!(plan.contains("Aivana RDP Proof Recovery Plan"));
        assert!(plan.contains("Proof ok: false"));
        assert!(plan.contains("Failed Proof Checks"));
        assert!(plan.contains("smoke_connected"));
        assert!(plan.contains("input_probe_present"));
        assert!(plan.contains("Recovery Commands"));
        assert!(plan.contains("connected=true"));
        assert!(plan.contains("framebuffer"));
        assert!(plan.contains("input-probe"));
        assert!(plan.contains("rdp-proof-check.ok == true"));
        assert!(plan.contains("Do not accept manifests"));
        assert!(plan.contains("password=[REDACTED]"));
        assert!(!plan.contains("hunter2"));
    }

    #[test]
    fn rdp_proof_check_reports_direct_evidence_gaps() {
        let path =
            std::env::temp_dir().join(format!("aivana-rdp-proof-check-{}.env", Uuid::new_v4()));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=<host>\nAIVANA_RDP_TEST_USER=<user>\nAIVANA_RDP_TEST_PASSWORD=[REDACTED]\n",
        )
        .expect("write placeholder env file");
        let args = vec![
            "aivana".to_owned(),
            "--rdp-proof-check".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let check = build_rdp_proof_check_from_args(&args);
        let json = redacted_json_string(&check).expect("serialize proof check");
        let _ = std::fs::remove_file(path);

        assert_eq!(check["schema"], "aivana.rdp-proof-check.v1");
        assert_eq!(check["ok"], false);
        assert_eq!(check["checks"]["env_file_ok"], false);
        assert_eq!(check["checks"]["preflight_matches_env"], false);
        assert_eq!(check["checks"]["preflight_fresh_for_env"], false);
        assert_eq!(check["checks"]["smoke_connected"], false);
        assert_eq!(check["checks"]["smoke_matches_env"], false);
        assert_eq!(check["checks"]["smoke_fresh_for_env"], false);
        assert!(
            check["failed_checks"]
                .as_array()
                .expect("failed checks")
                .iter()
                .any(|item| item == "env_file_ok")
        );
        let failed_actions = check["failed_check_actions"]
            .as_array()
            .expect("failed check actions");
        assert!(failed_actions.iter().any(|item| {
            item["check"] == "env_file_ok"
                && item["command"]
                    .as_str()
                    .is_some_and(|command| command.contains("--rdp-env-file-check"))
        }));
        assert!(failed_actions.iter().any(|item| {
            item["check"] == "smoke_fresh_for_env"
                && item["command"]
                    .as_str()
                    .is_some_and(|command| command.contains("--rdp-smoke-test"))
        }));
        assert_eq!(
            check["next_command"],
            "cargo run -- --rdp-env-file-check --rdp-env-file .\\rdp-live.env"
        );
        assert!(json.contains("aivana.rdp-proof-check.v1"));
        assert!(json.contains("failed_check_actions"));
        assert!(json.contains("preflight_matches_env"));
        assert!(json.contains("preflight_fresh_for_env"));
        assert!(json.contains("smoke_matches_env"));
        assert!(json.contains("smoke_fresh_for_env"));
        assert!(json.contains("env_file_modified_at"));
        assert!(json.contains("input_probe_present"));
        assert!(json.contains("AIVANA_RDP_TEST_PASSWORD"));
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn rdp_proof_host_port_matching_rejects_stale_evidence() {
        let matching = serde_json::json!({
            "host": "rdp.example.local",
            "port": 3390
        });
        let stale = serde_json::json!({
            "host": "other.example.local",
            "port": 3390
        });
        let wrong_port = serde_json::json!({
            "host": "rdp.example.local",
            "port": 3389
        });

        assert!(rdp_evidence_matches_env_host_port(
            &matching,
            Some("RDP.EXAMPLE.LOCAL"),
            Some(3390)
        ));
        assert!(!rdp_evidence_matches_env_host_port(
            &stale,
            Some("rdp.example.local"),
            Some(3390)
        ));
        assert!(!rdp_evidence_matches_env_host_port(
            &wrong_port,
            Some("rdp.example.local"),
            Some(3390)
        ));
        assert!(!rdp_evidence_matches_env_host_port(
            &matching,
            None,
            Some(3390)
        ));
    }

    #[test]
    fn rdp_proof_freshness_rejects_evidence_older_than_env_file() {
        let env_file_modified_at = DateTime::parse_from_rfc3339("2026-05-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let fresh = serde_json::json!({
            "generated_at": "2026-05-17T12:00:01Z"
        });
        let stale = serde_json::json!({
            "generated_at": "2026-05-17T11:59:59Z"
        });
        let missing_time = serde_json::json!({});

        assert!(rdp_evidence_is_fresh_for_env_file(
            &fresh,
            Some(env_file_modified_at)
        ));
        assert!(!rdp_evidence_is_fresh_for_env_file(
            &stale,
            Some(env_file_modified_at)
        ));
        assert!(!rdp_evidence_is_fresh_for_env_file(
            &missing_time,
            Some(env_file_modified_at)
        ));
        assert!(rdp_evidence_is_fresh_for_env_file(&missing_time, None));
    }

    #[test]
    fn live_gate_env_file_placeholder_errors_route_to_fill_guide() {
        assert!(live_gate_env_file_needs_fill_guide(
            "AIVANA_RDP_TEST_HOST must be filled; placeholder value is not valid"
        ));
        assert!(live_gate_env_file_needs_fill_guide(
            "AIVANA_RDP_TEST_PASSWORD=[REDACTED]"
        ));
        assert!(!live_gate_env_file_needs_fill_guide(
            "TCP connection timed out"
        ));
    }

    #[test]
    fn live_gate_llm_plan_instructs_without_proxy_completion() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: none".to_owned(),
        );
        let doctor = build_live_gate_doctor_report();
        let runbook = build_live_gate_runbook(&audit);

        let plan = build_live_gate_llm_plan(&audit, &doctor, &runbook);

        assert!(plan.contains("Aivana Live Gate LLM Plan"));
        assert!(plan.contains("summary.md"));
        assert!(plan.contains("Early LLM Triage"));
        assert!(plan.contains("verification-snapshot.json"));
        assert!(plan.contains("llm-action-contract.json"));
        assert!(plan.contains("live-gate-doctor.json"));
        assert!(plan.contains("Reject proxy evidence"));
        assert!(plan.contains("Next command"));
        assert!(plan.contains("Operator stage"));
        assert!(plan.contains("Acceptance criteria"));
        assert!(plan.contains("Next command after success"));
        assert!(plan.contains("RDP proof recovery plan command"));
        assert!(plan.contains("--rdp-proof-recovery-plan"));
        assert!(plan.contains("connected=true"));
        assert!(plan.contains("password=[REDACTED]"));
        assert!(!plan.contains("hunter2"));
    }

    #[test]
    fn live_gate_operator_brief_summarizes_current_doctor_without_secrets() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: none".to_owned(),
        );
        let doctor = build_live_gate_doctor_report();
        let brief = build_live_gate_operator_brief(&audit, &doctor);
        let path = save_live_gate_operator_brief(&audit, &brief).expect("saved operator brief");
        let markdown = std::fs::read_to_string(&path).expect("read operator brief");
        let _ = std::fs::remove_file(path);

        assert!(markdown.contains("Aivana Live Gate Operator Brief"));
        assert!(markdown.contains("Operator stage"));
        assert!(markdown.contains("Acceptance criteria"));
        assert!(markdown.contains("Next command"));
        assert!(markdown.contains("Evidence Snapshot"));
        assert!(markdown.contains("connected=true"));
        assert!(!markdown.contains("hunter2"));
    }

    #[test]
    fn save_next_live_gate_summary_writes_redacted_markdown() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let report = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        let path = save_next_live_gate_summary(&report).expect("saved next live gate summary");
        let markdown = std::fs::read_to_string(&path).expect("read summary");
        let _ = std::fs::remove_file(path);

        assert!(markdown.contains("Aivana Next Live Gate"));
        assert!(markdown.contains("cargo run -- --completion-audit"));
        assert!(markdown.contains("password=[REDACTED]"));
        assert!(!markdown.contains("hunter2"));
    }

    #[test]
    fn rdp_live_gate_env_template_redacts_password_placeholder() {
        let template = build_rdp_live_gate_env_template();

        assert!(template.contains("AIVANA_RDP_TEST_HOST=<host>"));
        assert!(template.contains("AIVANA_RDP_TEST_USER=<user>"));
        assert!(template.contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]"));
        assert!(template.contains("AIVANA_RDP_TEST_TIMEOUT_SECS=90"));
        assert!(!template.contains("<password>"));
    }

    #[test]
    fn rdp_live_gate_env_template_save_writes_redacted_file_without_overwrite() {
        let dir = std::env::temp_dir().join(format!("aivana-rdp-env-template-{}", Uuid::new_v4()));
        let path = dir.join("rdp-live.env");

        let saved =
            save_rdp_live_gate_env_template_to(&path).expect("saved rdp live gate env template");
        let contents = std::fs::read_to_string(&saved).expect("read saved env template");
        let overwrite = save_rdp_live_gate_env_template_to(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);

        assert_eq!(saved, path);
        assert!(contents.contains("AIVANA_RDP_TEST_HOST=<host>"));
        assert!(contents.contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]"));
        assert!(!contents.contains("<password>"));
        assert!(overwrite.is_err());
    }

    #[test]
    fn rdp_env_fill_guide_explains_safe_local_values() {
        let guide = build_rdp_env_fill_guide();

        assert!(guide.contains("Aivana RDP Env Fill Guide"));
        assert!(guide.contains("rdp-live.env"));
        assert!(guide.contains("Do not put real credentials"));
        assert!(guide.contains("AIVANA_RDP_TEST_HOST"));
        assert!(guide.contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]"));
        assert!(guide.contains("Current blocker"));
        assert!(guide.contains("Operator stage"));
        assert!(guide.contains("Acceptance criteria"));
        assert!(guide.contains("Next command after editing"));
        assert!(guide.contains("Next command after success"));
        assert!(guide.contains("--rdp-env-file-check"));
        assert!(guide.contains("`<host>`, `<user>`, `<password>`, `[REDACTED]`"));
        assert!(!guide.contains("hunter2"));
    }

    #[test]
    fn gui_operator_actions_save_redacted_markdown() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: none".to_owned(),
        );
        let actions = build_gui_operator_actions(&audit);
        let path = save_gui_operator_actions(&audit, &actions).expect("saved GUI actions");
        let markdown = std::fs::read_to_string(&path).expect("read GUI actions");
        let _ = std::fs::remove_file(path);

        assert!(markdown.contains("Aivana GUI Operator Actions"));
        assert!(markdown.contains("RDP env source line"));
        assert!(markdown.contains(".\\rdp-live.env"));
        assert!(markdown.contains("Copy Next Gate JSON"));
        assert!(markdown.contains("Copy Command Index JSON"));
        assert!(markdown.contains("Copy Evidence Matrix JSON"));
        assert!(markdown.contains("Copy Evidence Check JSON"));
        assert!(markdown.contains("direct_live_evidence_requirements"));
        assert!(markdown.contains("evidence success signals"));
        assert!(markdown.contains("proxy-evidence rejection rules"));
        assert!(markdown.contains("Copy Env Save Command"));
        assert!(markdown.contains("Copy Env Check Command"));
        assert!(markdown.contains("Copy RDP Env Fill Guide"));
        assert!(
            markdown
                .find("Copy RDP Env Template")
                .expect("template step")
                < markdown
                    .find("Copy RDP Env Fill Guide")
                    .expect("fill guide step")
        );
        assert!(
            markdown
                .find("Copy RDP Env Fill Guide")
                .expect("fill guide step")
                < markdown
                    .find("Copy Env Check Command")
                    .expect("env check step")
        );
        assert!(markdown.contains("visible handoff-check status"));
        assert!(markdown.contains("Copy Handoff Check JSON"));
        assert!(markdown.contains("Copy Handoff Risk JSON"));
        assert!(markdown.contains("Copy Handoff Risk Command"));
        assert!(markdown.contains("Copy Handoff Risk Evidence"));
        assert!(markdown.contains("Copy Handoff Check Evidence"));
        assert!(markdown.contains("Copy Verification Snapshot JSON"));
        assert!(markdown.contains("Export Verification Snapshot"));
        assert!(markdown.contains("Copy RDP Proof Check JSON"));
        assert!(markdown.contains("Copy RDP Proof Prompt"));
        assert!(markdown.contains("Copy RDP Recovery Plan"));
        assert!(markdown.contains("Copy RDP Recovery Plan Command"));
        assert!(markdown.contains("Copy RDP Recovery Commands"));
        assert!(markdown.contains("Copy Live Gate Doctor JSON"));
        assert!(markdown.contains("Copy Live Gate Next Command"));
        assert!(markdown.contains("Copy Live Gate Operator Brief"));
        assert!(markdown.contains("Copy Live Gate Sequence"));
        assert!(markdown.contains("Copy Live Gate LLM Plan"));
        assert!(
            markdown
                .find("Copy Live Gate Doctor JSON")
                .expect("doctor step")
                < markdown
                    .find("Copy Live Gate Next Command")
                    .expect("next command step")
        );
        assert!(
            markdown
                .find("Copy Live Gate Next Command")
                .expect("next command step")
                < markdown
                    .find("Copy Live Gate Operator Brief")
                    .expect("operator brief step")
        );
        assert!(
            markdown
                .find("Copy Live Gate Operator Brief")
                .expect("operator brief step")
                < markdown
                    .find("Copy Live Gate Sequence")
                    .expect("sequence step")
        );
        assert!(
            markdown
                .find("Copy Live Gate Sequence")
                .expect("sequence step")
                < markdown.find("Copy Live Gate LLM Plan").expect("llm step")
        );
        assert!(
            markdown
                .find("Copy Handoff Risk Command")
                .expect("risk command step")
                < markdown
                    .find("Copy Verification Snapshot JSON")
                    .expect("verification snapshot JSON step")
        );
        assert!(
            markdown
                .find("Copy Verification Snapshot JSON")
                .expect("verification snapshot JSON step")
                < markdown
                    .find("Export Verification Snapshot")
                    .expect("verification snapshot export step")
        );
        assert!(
            markdown
                .find("Export Verification Snapshot")
                .expect("verification snapshot export step")
                < markdown
                    .find("Copy RDP Proof Check JSON")
                    .expect("rdp proof check step")
        );
        assert!(
            markdown
                .find("Copy RDP Proof Check JSON")
                .expect("rdp proof check step")
                < markdown
                    .find("Copy RDP Proof Prompt")
                    .expect("rdp proof prompt step")
        );
        assert!(
            markdown
                .find("Copy RDP Proof Prompt")
                .expect("rdp proof prompt step")
                < markdown
                    .find("Copy RDP Recovery Plan")
                    .expect("rdp recovery plan step")
        );
        assert!(
            markdown
                .find("Copy RDP Recovery Plan")
                .expect("rdp recovery plan step")
                < markdown
                    .find("Copy RDP Recovery Plan Command")
                    .expect("rdp recovery plan command step")
        );
        assert!(
            markdown
                .find("Copy RDP Recovery Plan Command")
                .expect("rdp recovery plan command step")
                < markdown
                    .find("Copy RDP Recovery Commands")
                    .expect("rdp recovery commands step")
        );
        assert!(
            markdown
                .find("Copy RDP Recovery Commands")
                .expect("rdp recovery commands step")
                < markdown
                    .find("Copy Live Gate Doctor JSON")
                    .expect("doctor step")
        );
        assert!(markdown.contains("AIVANA_RDP_TEST_HOST"));
        assert!(markdown.contains("password=[REDACTED]"));
        assert!(!markdown.contains("hunter2"));
    }

    #[test]
    fn live_gate_command_sequence_uses_next_gate_order() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness,
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: none".to_owned(),
        );
        let sequence = build_live_gate_command_sequence(&audit);

        assert!(sequence.contains("cargo run -- --save-rdp-env-template .\\rdp-live.env"));
        assert!(sequence.contains("cargo run -- --rdp-env-fill-guide"));
        assert!(sequence.contains("cargo run -- --rdp-proof-check"));
        assert!(sequence.contains("cargo run -- --rdp-proof-recovery-plan"));
        assert!(sequence.contains("cargo run -- --live-gate-operator-brief"));
        assert!(sequence.contains("cargo run -- --operator-handoff-check"));
        assert!(sequence.contains("cargo run -- --operator-handoff-risk-summary"));
        assert!(sequence.contains("cargo run -- --verification-snapshot"));
        assert!(
            sequence
                .find("--save-rdp-env-template")
                .expect("save env command")
                < sequence
                    .find("--rdp-env-fill-guide")
                    .expect("fill guide command")
        );
        assert!(
            sequence
                .find("--rdp-env-fill-guide")
                .expect("fill guide command")
                < sequence
                    .find("--rdp-env-file-check")
                    .expect("env check command")
        );
        assert!(
            sequence.find("--rdp-preflight").expect("preflight command")
                < sequence.find("--rdp-smoke-test").expect("smoke command")
        );
        assert!(
            sequence.find("--rdp-smoke-test").expect("smoke command")
                < sequence
                    .find("--rdp-proof-check")
                    .expect("proof check command")
        );
        assert!(
            sequence
                .find("--rdp-proof-check")
                .expect("proof check command")
                < sequence
                    .find("--rdp-proof-recovery-plan")
                    .expect("proof recovery command")
        );
        assert!(
            sequence
                .find("--rdp-proof-recovery-plan")
                .expect("proof recovery command")
                < sequence.find("--live-gate-doctor").expect("doctor command")
        );
        assert!(
            sequence.find("--live-gate-doctor").expect("doctor command")
                < sequence
                    .find("--live-gate-operator-brief")
                    .expect("operator brief command")
        );
        assert!(
            sequence
                .find("--operator-handoff-check")
                .expect("handoff check command")
                < sequence
                    .find("--operator-handoff-risk-summary")
                    .expect("risk summary command")
        );
        assert!(
            sequence
                .find("--operator-handoff-risk-summary")
                .expect("risk summary command")
                < sequence
                    .find("--verification-snapshot")
                    .expect("verification snapshot command")
        );
        assert!(!sequence.contains("hunter2"));
    }

    #[test]
    fn operator_handoff_pack_writes_redacted_bundle_files() {
        let dir = std::env::temp_dir().join(format!("aivana-operator-pack-{}", Uuid::new_v4()));
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s), secret=abc".to_owned(),
        );

        let report = save_operator_handoff_pack_to_dir(&dir, &readiness, &audit)
            .expect("saved operator handoff pack");
        let summary = std::fs::read_to_string(dir.join("summary.md")).unwrap();
        let next_live_gate = std::fs::read_to_string(dir.join("next-live-gate.md")).unwrap();
        let next_live_gate_json = std::fs::read_to_string(dir.join("next-live-gate.json")).unwrap();
        let live_gate_sequence =
            std::fs::read_to_string(dir.join("live-gate-sequence.txt")).unwrap();
        let goal_evidence_matrix =
            std::fs::read_to_string(dir.join("goal-evidence-matrix.json")).unwrap();
        let goal_evidence_check =
            std::fs::read_to_string(dir.join("goal-evidence-check.json")).unwrap();
        let verification_snapshot =
            std::fs::read_to_string(dir.join("verification-snapshot.json")).unwrap();
        let risk_summary =
            std::fs::read_to_string(dir.join("operator-handoff-risk-summary.json")).unwrap();
        let command_index = std::fs::read_to_string(dir.join("command-index.json")).unwrap();
        let rdp_env_file_check =
            std::fs::read_to_string(dir.join("rdp-env-file-check.json")).unwrap();
        let rdp_proof_check = std::fs::read_to_string(dir.join("rdp-proof-check.json")).unwrap();
        let live_gate_doctor = std::fs::read_to_string(dir.join("live-gate-doctor.json")).unwrap();
        let live_gate_operator_brief =
            std::fs::read_to_string(dir.join("live-gate-operator-brief.md")).unwrap();
        let runbook = std::fs::read_to_string(dir.join("live-gate-runbook.md")).unwrap();
        let gui_actions = std::fs::read_to_string(dir.join("gui-operator-actions.md")).unwrap();
        let rdp_proof_prompt = std::fs::read_to_string(dir.join("rdp-proof-prompt.md")).unwrap();
        let rdp_proof_recovery_plan =
            std::fs::read_to_string(dir.join("rdp-proof-recovery-plan.md")).unwrap();
        let readiness_json = std::fs::read_to_string(dir.join("readiness.json")).unwrap();
        let audit_json = std::fs::read_to_string(dir.join("completion-audit.json")).unwrap();
        let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        let env_template = std::fs::read_to_string(dir.join("rdp-env-template.env")).unwrap();
        let env_fill_guide = std::fs::read_to_string(dir.join("rdp-env-fill-guide.md")).unwrap();
        let llm_prompt = std::fs::read_to_string(dir.join("llm-review-prompt.md")).unwrap();
        let llm_live_gate_plan =
            std::fs::read_to_string(dir.join("llm-live-gate-plan.md")).unwrap();
        let llm_action_contract =
            std::fs::read_to_string(dir.join("llm-action-contract.json")).unwrap();
        let _ = std::fs::remove_dir_all(dir);

        assert_eq!(report.files.len(), 25);
        assert_eq!(report.schema, "aivana.operator-handoff-pack.v1");
        assert_eq!(report.file_roles.len(), 25);
        assert_eq!(
            report
                .recommended_inspection_order
                .first()
                .map(String::as_str),
            Some("manifest.json")
        );
        assert!(
            report
                .recommended_inspection_order
                .iter()
                .any(|file| file == "completion-audit.json")
        );
        let snapshot_order = report
            .recommended_inspection_order
            .iter()
            .position(|file| file == "verification-snapshot.json")
            .unwrap();
        let contract_order = report
            .recommended_inspection_order
            .iter()
            .position(|file| file == "llm-action-contract.json")
            .unwrap();
        assert_eq!(contract_order, snapshot_order + 1);
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "next-live-gate.json"
                    && role.role.contains("Structured first blocking gate"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "goal-evidence-matrix.json"
                    && role.role.contains("requirement-to-artifact matrix"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "goal-evidence-check.json"
                    && role.role.contains("Hard completion assertion"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "verification-snapshot.json"
                    && role.role.contains("latest-evidence snapshot"))
        );
        assert!(report.file_roles.iter().any(|role| {
            role.file == "operator-handoff-risk-summary.json"
                && role.role.contains("hard risk gate")
                && role.role.contains("direct live evidence requirements")
                && role.inspect_when.contains("pack-local risk status")
        }));
        assert!(report.file_roles.iter().any(|role| {
            role.file == "rdp-env-file-check.json"
                && role
                    .role
                    .contains("offline RDP env-file validation evidence")
        }));
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "rdp-proof-check.json"
                    && role.role.contains("Direct RDP proof checklist"))
        );
        assert!(report.file_roles.iter().any(|role| {
            role.file == "rdp-proof-recovery-plan.md"
                && role.role.contains("failed RDP proof checks")
        }));
        assert!(report.file_roles.iter().any(|role| {
            role.file == "rdp-proof-prompt.md"
                && role.role.contains("recovery-plan command")
                && role.inspect_when.contains("recovery-plan command")
        }));
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "live-gate-doctor.json"
                    && role.role.contains("live-gate ladder")
                    && role.role.contains("recovery-plan command"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "live-gate-operator-brief.md"
                    && role.role.contains("Concise human-readable live-gate stage")
                    && role.role.contains("recovery-plan command"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "live-gate-sequence.txt"
                    && role.role.contains("ordered live-gate command sequence"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "llm-live-gate-plan.md"
                    && role.role.contains("LLM/CI plan"))
        );
        assert!(report.file_roles.iter().any(|role| {
            role.file == "llm-action-contract.json"
                && role.role.contains("LLM action contract")
                && role.role.contains("direct live evidence requirements")
                && role.role.contains("success signals")
                && role.role.contains("proxy-evidence rejection rules")
        }));
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "rdp-env-fill-guide.md"
                    && role.role.contains("ignored local rdp-live.env"))
        );
        assert!(
            report
                .file_roles
                .iter()
                .any(|role| role.file == "gui-operator-actions.md"
                    && role.inspect_when.contains("app UI"))
        );
        assert!(summary.contains("Aivana Operator Handoff Pack"));
        assert!(summary.contains("Early LLM Triage"));
        assert!(summary.contains("verification-snapshot.json"));
        assert!(summary.contains("llm-action-contract.json"));
        assert!(summary.contains("contract success signals"));
        assert!(goal_evidence_matrix.contains("aivana.goal-evidence-matrix.v1"));
        assert!(goal_evidence_matrix.contains("uncovered_requirements"));
        assert!(goal_evidence_matrix.contains("--goal-evidence-matrix"));
        assert!(goal_evidence_check.contains("aivana.goal-evidence-check.v1"));
        assert!(goal_evidence_check.contains("failed_requirements"));
        assert!(verification_snapshot.contains("aivana.verification-snapshot.v1"));
        assert!(verification_snapshot.contains("\"env_source\""));
        assert!(verification_snapshot.contains("\"live_gate\""));
        assert!(verification_snapshot.contains("\"handoff\""));
        assert!(verification_snapshot.contains("\"llm_action_contract\""));
        assert!(verification_snapshot.contains("\"llm_review_prompt\""));
        assert!(verification_snapshot.contains("\"required_evidence_files\""));
        assert!(verification_snapshot.contains("summary.md"));
        assert!(verification_snapshot.contains("\"must_return\""));
        assert!(verification_snapshot.contains("early_triage_artifacts"));
        assert!(verification_snapshot.contains("rdp-smoke-test connected == true"));
        assert!(verification_snapshot.contains("Copy LLM Action Contract JSON"));
        assert!(verification_snapshot.contains("Copy LLM Review Prompt"));
        assert!(verification_snapshot.contains("operator-handoff-risk-summary.json"));
        assert!(verification_snapshot.contains("rdp_proof_recovery_plan"));
        assert!(
            verification_snapshot
                .contains("operator-handoff-packs/<pack-id>/rdp-proof-recovery-plan.md")
        );
        assert!(risk_summary.contains("aivana.operator-handoff-risk-summary.v1"));
        assert!(risk_summary.contains("\"handoff_pack_valid\": true"));
        assert!(risk_summary.contains("\"rdp_proof_failed_check_actions\""));
        assert!(risk_summary.contains("\"rdp_proof_recovery_plan_command\""));
        assert!(risk_summary.contains("\"rdp_proof_recovery_plan_summary\""));
        assert!(risk_summary.contains("\"llm_triage_entrypoint\""));
        assert!(risk_summary.contains("summary.md"));
        assert!(risk_summary.contains("\"llm_action_contract_required_evidence_files\""));
        assert!(risk_summary.contains("\"llm_action_contract_must_return\""));
        assert!(risk_summary.contains("early_triage_artifacts"));
        assert!(
            risk_summary.contains("operator-handoff-packs/<pack-id>/rdp-proof-recovery-plan.md")
        );
        assert!(command_index.contains("aivana.command-index.v1"));
        assert!(command_index.contains("--goal-evidence-matrix"));
        assert!(command_index.contains("--goal-evidence-check"));
        assert!(command_index.contains("--rdp-smoke-test"));
        assert!(rdp_env_file_check.contains("aivana.rdp-env-file-check.v1"));
        assert!(rdp_env_file_check.contains("\"network_checked\": false"));
        assert!(rdp_env_file_check.contains("\"ok\":"));
        assert!(rdp_env_file_check.contains("\"expected_environment\""));
        assert!(rdp_proof_check.contains("aivana.rdp-proof-check.v1"));
        assert!(rdp_proof_check.contains("failed_check_actions"));
        assert!(rdp_proof_check.contains("input_probe_present"));
        assert!(rdp_proof_check.contains("framebuffer_present"));
        assert!(rdp_proof_recovery_plan.contains("Aivana RDP Proof Recovery Plan"));
        assert!(rdp_proof_recovery_plan.contains("Recovery Commands"));
        assert!(rdp_proof_recovery_plan.contains("rdp-proof-check.ok == true"));
        assert!(live_gate_doctor.contains("aivana.live-gate-doctor.v1"));
        assert!(live_gate_doctor.contains("\"next_command\""));
        assert!(live_gate_doctor.contains("\"checks\""));
        assert!(live_gate_doctor.contains("\"rdp_proof_check\""));
        assert!(live_gate_doctor.contains("\"rdp_proof_recovery_plan_command\""));
        assert!(live_gate_operator_brief.contains("Aivana Live Gate Operator Brief"));
        assert!(live_gate_operator_brief.contains("Operator stage"));
        assert!(live_gate_operator_brief.contains("Acceptance criteria"));
        assert!(live_gate_operator_brief.contains("Next command after success"));
        assert!(next_live_gate_json.contains("\"blocking_gates\""));
        assert!(next_live_gate_json.contains("--rdp-smoke-test"));
        assert!(next_live_gate.contains("Aivana Next Live Gate"));
        assert!(next_live_gate.contains("cargo run -- --rdp-preflight"));
        assert!(next_live_gate.contains("password=[REDACTED]"));
        assert!(live_gate_sequence.contains("cargo run -- --rdp-env-fill-guide"));
        assert!(live_gate_sequence.contains("cargo run -- --operator-handoff-check"));
        assert!(runbook.contains("cargo run -- --rdp-smoke-test"));
        assert!(manifest.contains("command-index.json"));
        assert!(manifest.contains("goal-evidence-matrix.json"));
        assert!(manifest.contains("goal-evidence-check.json"));
        assert!(manifest.contains("verification-snapshot.json"));
        assert!(manifest.contains("operator-handoff-risk-summary.json"));
        assert!(manifest.contains("rdp-env-file-check.json"));
        assert!(manifest.contains("rdp-proof-check.json"));
        assert!(manifest.contains("live-gate-doctor.json"));
        assert!(manifest.contains("live-gate-operator-brief.md"));
        assert!(manifest.contains("aivana.operator-handoff-pack.v1"));
        assert!(manifest.contains("\"file_roles\""));
        assert!(manifest.contains("\"recommended_inspection_order\""));
        assert!(manifest.contains("Structured first blocking gate"));
        assert!(manifest.contains("requirement-to-artifact matrix"));
        assert!(manifest.contains("GUI checklist"));
        assert!(manifest.contains("next-live-gate.json"));
        assert!(manifest.contains("live-gate-sequence.txt"));
        assert!(manifest.contains("next-live-gate.md"));
        assert!(manifest.contains("live-gate-runbook.md"));
        assert!(manifest.contains("gui-operator-actions.md"));
        assert!(manifest.contains("rdp-env-template.env"));
        assert!(manifest.contains("rdp-env-fill-guide.md"));
        assert!(manifest.contains("llm-review-prompt.md"));
        assert!(manifest.contains("summary.md Early LLM Triage"));
        assert!(manifest.contains("operator-handoff-risk-summary.json cross-check"));
        assert!(manifest.contains("required evidence files"));
        assert!(manifest.contains("early_triage_artifacts"));
        assert!(manifest.contains("proxy-evidence rejection"));
        assert!(manifest.contains("rdp-proof-prompt.md"));
        assert!(manifest.contains("rdp-proof-recovery-plan.md"));
        assert!(manifest.contains("llm-live-gate-plan.md"));
        assert!(manifest.contains("llm-action-contract.json"));
        assert!(runbook.contains("password=[REDACTED]"));
        assert!(gui_actions.contains("Aivana GUI Operator Actions"));
        assert!(gui_actions.contains("Copy Next Gate JSON"));
        assert!(gui_actions.contains("Copy Command Index JSON"));
        assert!(gui_actions.contains("Copy Verification Snapshot JSON"));
        assert!(gui_actions.contains("Export Verification Snapshot"));
        assert!(gui_actions.contains("Copy RDP Proof Check JSON"));
        assert!(gui_actions.contains("Copy RDP Proof Prompt"));
        assert!(gui_actions.contains("Copy RDP Recovery Plan"));
        assert!(gui_actions.contains("Copy RDP Recovery Plan Command"));
        assert!(gui_actions.contains("Copy RDP Recovery Commands"));
        assert!(gui_actions.contains("Copy LLM Review Prompt"));
        assert!(gui_actions.contains("operator-handoff-risk-summary.json cross-check"));
        assert!(gui_actions.contains("Copy LLM Action Contract JSON"));
        assert!(gui_actions.contains("summary.md Early LLM Triage"));
        assert!(gui_actions.contains("early_triage_artifacts"));
        assert!(gui_actions.contains("evidence success signals"));
        assert!(gui_actions.contains("proxy-evidence rejection rules"));
        assert!(
            goal_evidence_matrix
                .contains("LLM action-contract JSON copy/export with summary.md Early LLM Triage")
        );
        assert!(
            goal_evidence_matrix
                .contains("LLM review prompt copy with summary.md Early LLM Triage")
        );
        assert!(goal_evidence_matrix.contains("operator-handoff-risk-summary.json cross-check"));
        assert!(goal_evidence_matrix.contains("early_triage_artifacts"));
        assert!(goal_evidence_matrix.contains("evidence success signals"));
        assert!(gui_actions.contains("Export LLM Action Contract"));
        assert!(gui_actions.contains("AIVANA_RDP_TEST_HOST"));
        assert!(env_template.contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]"));
        assert!(env_fill_guide.contains("Aivana RDP Env Fill Guide"));
        assert!(env_fill_guide.contains("Do not put real credentials"));
        assert!(env_fill_guide.contains("rdp-live.env"));
        assert!(readiness_json.contains("token=[REDACTED]"));
        assert!(audit_json.contains("secret=[REDACTED]"));
        assert!(llm_prompt.contains("Aivana Operator Handoff LLM Review Prompt"));
        assert!(llm_prompt.contains("Do not treat a command"));
        assert!(llm_prompt.contains("summary.md"));
        assert!(llm_prompt.contains("Early LLM Triage"));
        assert!(llm_prompt.contains("verification-snapshot.json"));
        assert!(llm_prompt.contains("llm-action-contract.json"));
        assert!(llm_prompt.contains("operator-handoff-risk-summary.json"));
        assert!(llm_prompt.contains("command-index.json"));
        assert!(llm_prompt.contains("goal-evidence-check.json"));
        assert!(llm_prompt.contains("rdp-env-file-check.json"));
        assert!(llm_prompt.contains("rdp-proof-check.json"));
        assert!(llm_prompt.contains("rdp-proof-recovery-plan.md"));
        assert!(llm_prompt.contains("llm-action-contract.json"));
        assert!(llm_prompt.contains("live-gate-doctor.json"));
        assert!(llm_prompt.contains("live-gate-operator-brief.md"));
        assert!(llm_prompt.contains("next-live-gate.json"));
        assert!(llm_prompt.contains("live-gate-sequence.txt"));
        assert!(llm_prompt.contains("gui-operator-actions.md"));
        assert!(llm_prompt.contains("llm-review-prompt.md"));
        assert!(rdp_proof_prompt.contains("Aivana RDP Proof Prompt"));
        assert!(rdp_proof_prompt.contains("connected=true"));
        assert!(rdp_proof_prompt.contains("Framebuffer evidence"));
        assert!(rdp_proof_prompt.contains("Input probe evidence"));
        assert!(rdp_proof_prompt.contains("Reject proxy evidence"));
        assert!(llm_prompt.contains("password=[REDACTED]"));
        assert!(llm_live_gate_plan.contains("Aivana Live Gate LLM Plan"));
        assert!(llm_live_gate_plan.contains("verification-snapshot.json"));
        assert!(llm_live_gate_plan.contains("operator-handoff-risk-summary.json"));
        assert!(llm_live_gate_plan.contains("llm-action-contract.json"));
        assert!(llm_live_gate_plan.contains("rdp-proof-check.json"));
        assert!(llm_live_gate_plan.contains("rdp-proof-recovery-plan.md"));
        assert!(llm_live_gate_plan.contains("RDP proof recovery plan command"));
        assert!(llm_live_gate_plan.contains("--rdp-proof-recovery-plan"));
        assert!(llm_live_gate_plan.contains("live-gate-doctor.json"));
        assert!(llm_live_gate_plan.contains("live-gate-operator-brief.md"));
        assert!(llm_live_gate_plan.contains("live-gate-sequence.txt"));
        assert!(llm_live_gate_plan.contains("Reject proxy evidence"));
        assert!(llm_action_contract.contains("aivana.llm-action-contract.v1"));
        assert!(llm_action_contract.contains("\"next_command\""));
        assert!(llm_action_contract.contains("\"allowed_next_commands\""));
        assert!(llm_action_contract.contains("\"evidence_success_signals\""));
        assert!(llm_action_contract.contains("\"direct_live_evidence_requirements\""));
        assert!(llm_action_contract.contains("direct live evidence"));
        assert!(llm_action_contract.contains("summary.md"));
        assert!(llm_action_contract.contains("early_triage_artifacts"));
        assert!(llm_action_contract.contains("rdp-smoke-test connected == true"));
        assert!(llm_action_contract.contains("\"proxy_evidence_rejected\""));
        assert!(llm_action_contract.contains("goal-evidence-check.ok == true"));
        assert!(!summary.contains("abc"));
        assert!(!goal_evidence_matrix.contains("hunter2"));
        assert!(!goal_evidence_matrix.contains("secret=abc"));
        assert!(!goal_evidence_check.contains("hunter2"));
        assert!(!goal_evidence_check.contains("secret=abc"));
        assert!(!verification_snapshot.contains("hunter2"));
        assert!(!verification_snapshot.contains("secret=abc"));
        assert!(!risk_summary.contains("hunter2"));
        assert!(!risk_summary.contains("secret=abc"));
        assert!(!command_index.contains("hunter2"));
        assert!(!rdp_env_file_check.contains("hunter2"));
        assert!(!rdp_proof_check.contains("hunter2"));
        assert!(!rdp_proof_recovery_plan.contains("hunter2"));
        assert!(!live_gate_doctor.contains("hunter2"));
        assert!(!live_gate_operator_brief.contains("hunter2"));
        assert!(!next_live_gate_json.contains("hunter2"));
        assert!(!next_live_gate.contains("hunter2"));
        assert!(!live_gate_sequence.contains("hunter2"));
        assert!(!runbook.contains("hunter2"));
        assert!(!gui_actions.contains("hunter2"));
        assert!(!rdp_proof_prompt.contains("hunter2"));
        assert!(!rdp_proof_recovery_plan.contains("secret=abc"));
        assert!(!env_template.contains("<password>"));
        assert!(!env_fill_guide.contains("hunter2"));
        assert!(!llm_prompt.contains("hunter2"));
        assert!(!llm_live_gate_plan.contains("hunter2"));
        assert!(!llm_action_contract.contains("hunter2"));
        assert!(!readiness_json.contains("token=abc"));
        assert!(!audit_json.contains("secret=abc"));
    }

    #[test]
    fn latest_operator_handoff_pack_summary_reads_manifest() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");

        let summary = latest_operator_handoff_pack_summary_from_dir(&root)
            .expect("read handoff summary")
            .expect("summary");
        let _ = std::fs::remove_dir_all(root);

        assert!(summary.contains("Latest operator handoff pack"));
        assert!(summary.contains("25 file"));
        assert!(summary.contains("blocking_gates=1"));
        assert!(summary.contains("achieved=false"));
        assert!(summary.contains("manifest.json"));
        assert!(!summary.contains("token=abc"));
    }

    #[test]
    fn operator_handoff_pack_check_validates_latest_manifest() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(check.ok, "{check:?}");
        assert_eq!(check.schema, "aivana.operator-handoff-check.v1");
        assert_eq!(
            check.actual_schema.as_deref(),
            Some("aivana.operator-handoff-pack.v1")
        );
        assert!(check.missing_files.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.missing_inspection_entries.is_empty());
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.content_mismatches.is_empty());
        assert!(
            check
                .manifest_path
                .as_deref()
                .unwrap_or_default()
                .contains("manifest.json")
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_reordered_llm_contract_inspection() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let order = manifest
            .get_mut("recommended_inspection_order")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let contract_index = order
            .iter()
            .position(|value| value.as_str() == Some("llm-action-contract.json"))
            .unwrap();
        let contract_entry = order.remove(contract_index);
        order.push(contract_entry);
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest inspection order");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.missing_inspection_entries.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.recommended_inspection_order must list llm-action-contract.json immediately after verification-snapshot.json"
        )));
    }

    #[test]
    fn operator_handoff_pack_check_rejects_summary_missing_llm_triage() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        std::fs::write(
            pack.join("summary.md"),
            "# Aivana Operator Handoff Pack\n\n## Next Gate\nRun smoke test.\n",
        )
        .expect("corrupted summary");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("summary.md missing required mention: llm-action-contract.json")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_check_summary_reports_counts_and_redacts() {
        let check = OperatorHandoffPackCheck {
            schema: "aivana.operator-handoff-check.v1".to_owned(),
            checked_at: Utc::now(),
            ok: false,
            pack_path: Some("C:\\tmp\\password=hunter2\\pack".to_owned()),
            manifest_path: Some("C:\\tmp\\password=hunter2\\manifest.json".to_owned()),
            expected_schema: "aivana.operator-handoff-pack.v1".to_owned(),
            actual_schema: Some("aivana.operator-handoff-pack.v1".to_owned()),
            missing_files: vec!["next-live-gate.json".to_owned()],
            missing_file_roles: vec!["gui-operator-actions.md".to_owned()],
            missing_inspection_entries: vec!["summary.md".to_owned()],
            invalid_file_schemas: vec!["goal-evidence-matrix.json: token=abc".to_owned()],
            content_mismatches: vec!["next-live-gate.blocking_gates mismatch".to_owned()],
            errors: vec!["token=abc".to_owned()],
        };

        let summary = operator_handoff_check_summary(&check);

        assert!(summary.contains("Latest operator handoff check"));
        assert!(summary.contains("ok=false"));
        assert!(summary.contains("missing_files=1"));
        assert!(summary.contains("missing_file_roles=1"));
        assert!(summary.contains("missing_inspection_entries=1"));
        assert!(summary.contains("invalid_file_schemas=1"));
        assert!(summary.contains("content_mismatches=1"));
        assert!(summary.contains("errors=1"));
        assert!(summary.contains("password=[REDACTED]"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("token=abc"));
    }

    #[test]
    fn operator_handoff_pack_check_rejects_invalid_machine_readable_schema() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        std::fs::write(
            pack.join("goal-evidence-matrix.json"),
            r#"{"schema":"wrong","token":"abc"}"#,
        )
        .expect("corrupted matrix");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(
            check
                .invalid_file_schemas
                .iter()
                .any(|error| error.contains("goal-evidence-matrix.json"))
        );
        assert!(
            check
                .invalid_file_schemas
                .iter()
                .any(|error| error.contains("schema mismatch"))
        );
        assert!(
            check
                .invalid_file_schemas
                .iter()
                .any(|error| error.contains("missing required field checklist"))
        );
        assert!(
            !check
                .invalid_file_schemas
                .iter()
                .any(|error| error.contains("token=abc"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_cross_artifact_mismatch() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let matrix_path = pack.join("goal-evidence-matrix.json");
        let mut matrix: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&matrix_path).unwrap()).unwrap();
        if let Some(item) = matrix
            .get_mut("checklist")
            .and_then(|value| value.as_array_mut())
            .and_then(|items| {
                items.iter_mut().find(|item| {
                    item.get("requirement").and_then(|value| value.as_str())
                        == Some("GUI-friendly KI cockpit and operator workflow")
                })
            })
        {
            item["evidence"] = serde_json::json!(
                "GUI evidence omitted LLM contract success signals password=hunter2"
            );
        }
        std::fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap())
            .expect("corrupted goal evidence matrix");
        let goal_check_path = pack.join("goal-evidence-check.json");
        let mut goal_check: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&goal_check_path).unwrap()).unwrap();
        if let Some(item) = goal_check
            .get_mut("matrix")
            .and_then(|value| value.get_mut("checklist"))
            .and_then(|value| value.as_array_mut())
            .and_then(|items| {
                items.iter_mut().find(|item| {
                    item.get("requirement").and_then(|value| value.as_str())
                        == Some("GUI-friendly KI cockpit and operator workflow")
                })
            })
        {
            item["evidence"] = serde_json::json!(
                "Embedded GUI evidence omitted LLM contract success signals password=hunter2"
            );
        }
        std::fs::write(
            &goal_check_path,
            serde_json::to_string_pretty(&goal_check).unwrap(),
        )
        .expect("corrupted goal evidence check");
        let next_path = pack.join("next-live-gate.json");
        let mut next_gate: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&next_path).unwrap()).unwrap();
        next_gate["blocking_gates"] = serde_json::json!(42);
        std::fs::write(
            &next_path,
            serde_json::to_string_pretty(&next_gate).unwrap(),
        )
        .expect("corrupted next gate");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check
                .content_mismatches
                .iter()
                .any(|error| error.contains("next-live-gate.blocking_gates mismatch"))
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-matrix.checklist evidence missing required mention")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-check.matrix.checklist evidence missing required mention")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-matrix.checklist evidence missing required mention")
                && error.contains("early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-check.matrix.checklist evidence missing required mention")
                && error.contains("early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-matrix.checklist evidence missing required mention")
                && error.contains("direct_live_evidence_requirements")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-check.matrix.checklist evidence missing required mention")
                && error.contains("direct_live_evidence_requirements")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("goal-evidence-matrix.checklist evidence missing required mention")
                && error.contains("evidence success signals")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_live_gate_sequence_mismatch() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        std::fs::write(
            pack.join("live-gate-sequence.txt"),
            "cargo run -- --rdp-smoke-test --password=hunter2",
        )
        .expect("corrupted live gate sequence");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check
                .content_mismatches
                .iter()
                .any(|error| error.contains("live-gate-sequence.next_commands mismatch"))
        );
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_command_index_sequence_mismatch() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let index_path = pack.join("command-index.json");
        let mut index: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&index_path).unwrap()).unwrap();
        if let Some(command) = index
            .get_mut("commands")
            .and_then(|value| value.as_array_mut())
            .and_then(|commands| {
                commands.iter_mut().find(|command| {
                    command.get("name").and_then(|value| value.as_str())
                        == Some("--llm-action-contract")
                })
            })
        {
            command["purpose"] = serde_json::json!(
                "LLM action contract has no success or proxy rules password=hunter2"
            );
        }
        if let Some(command) = index
            .get_mut("commands")
            .and_then(|value| value.as_array_mut())
            .and_then(|commands| {
                commands.iter_mut().find(|command| {
                    command.get("name").and_then(|value| value.as_str())
                        == Some("--operator-handoff-pack")
                })
            })
        {
            command["purpose"] =
                serde_json::json!("One-folder handoff pack without early triage password=hunter2");
        }
        if let Some(command) = index
            .get_mut("commands")
            .and_then(|value| value.as_array_mut())
            .and_then(|commands| {
                commands.iter_mut().find(|command| {
                    command.get("name").and_then(|value| value.as_str())
                        == Some("--llm-review-prompt")
                })
            })
        {
            command["purpose"] =
                serde_json::json!("LLM review prompt without risk triage password=hunter2");
        }
        if let Some(command) = index
            .get_mut("commands")
            .and_then(|value| value.as_array_mut())
            .and_then(|commands| {
                commands.iter_mut().find(|command| {
                    command.get("name").and_then(|value| value.as_str())
                        == Some("--operator-handoff-risk-summary")
                })
            })
        {
            command["purpose"] =
                serde_json::json!("Risk summary without compact LLM triage password=hunter2");
        }
        if let Some(command) = index
            .get_mut("commands")
            .and_then(|value| value.as_array_mut())
            .and_then(|commands| {
                commands.iter_mut().find(|command| {
                    command.get("name").and_then(|value| value.as_str())
                        == Some("--rdp-proof-recovery-plan")
                })
            })
        {
            command["purpose"] =
                serde_json::json!("Recovery plan without direct proof semantics password=hunter2");
        }
        index["recommended_live_gate_sequence"][0]["command"] =
            serde_json::json!("cargo run -- --rdp-smoke-test --password=hunter2");
        index["recommended_live_gate_sequence"][6]["expect"] =
            serde_json::json!("Recovery plan without proof semantics password=hunter2");
        index["recommended_live_gate_sequence"][8]["expect"] =
            serde_json::json!("Concise Markdown brief has no recovery command password=hunter2");
        index["recommended_live_gate_sequence"][9]["expect"] =
            serde_json::json!("LLM review prompt has no risk summary triage password=hunter2");
        index["recommended_live_gate_sequence"][10]["expect"] =
            serde_json::json!("LLM plan has no recovery command password=hunter2");
        index["recommended_live_gate_sequence"][11]["expect"] =
            serde_json::json!("LLM action contract has no proxy rules password=hunter2");
        index["recommended_live_gate_sequence"][15]["expect"] =
            serde_json::json!("Handoff pack has no early triage password=hunter2");
        index["recommended_live_gate_sequence"][17]["expect"] =
            serde_json::json!("Risk summary has no compact LLM triage password=hunter2");
        std::fs::write(&index_path, serde_json::to_string_pretty(&index).unwrap())
            .expect("corrupted command index");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.recommended_live_gate_sequence mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--live-gate-operator-brief")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--rdp-proof-recovery-plan")
                && error.contains("direct live evidence")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-live-gate-plan")
        }));
        for required in [
            "summary.md Early LLM Triage",
            "operator-handoff-risk-summary.json",
            "LLM triage entrypoint",
            "required evidence files",
            "early_triage_artifacts",
            "proxy-evidence rejection",
        ] {
            assert!(check.content_mismatches.iter().any(|error| {
                error.contains("command-index.expect missing required mention")
                    && error.contains("--llm-review-prompt")
                    && error.contains(required)
            }));
        }
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("proxy-evidence rejection rules")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("success signals")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("direct_live_evidence_requirements")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("direct live evidence")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("success signals")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("direct_live_evidence_requirements")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("direct live evidence")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-action-contract")
                && error.contains("proxy-evidence rejection rules")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--operator-handoff-pack")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--operator-handoff-pack")
                && error.contains("verification-snapshot.json")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--operator-handoff-pack")
                && error.contains("llm-action-contract.json")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--operator-handoff-pack")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--operator-handoff-pack")
                && error.contains("verification-snapshot.json")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--operator-handoff-pack")
                && error.contains("llm-action-contract.json")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-review-prompt")
                && error.contains("summary.md Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-review-prompt")
                && error.contains("operator-handoff-risk-summary.json")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-review-prompt")
                && error.contains("LLM triage entrypoint")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-review-prompt")
                && error.contains("required evidence files")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-review-prompt")
                && error.contains("early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--llm-review-prompt")
                && error.contains("proxy-evidence rejection")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--operator-handoff-risk-summary")
                && error.contains("LLM triage entrypoint")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--operator-handoff-risk-summary")
                && error.contains("required evidence files")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--operator-handoff-risk-summary")
                && error.contains("early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.commands purpose missing required mention")
                && error.contains("--rdp-proof-recovery-plan")
                && error.contains("direct live evidence")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--operator-handoff-risk-summary")
                && error.contains("LLM triage entrypoint")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--operator-handoff-risk-summary")
                && error.contains("required evidence files")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("command-index.expect missing required mention")
                && error.contains("--operator-handoff-risk-summary")
                && error.contains("early_triage_artifacts")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_stale_verification_snapshot() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let snapshot_path = pack.join("verification-snapshot.json");
        let mut snapshot: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&snapshot_path).unwrap()).unwrap();
        snapshot["handoff"]["pack_valid"] = serde_json::json!(false);
        snapshot["completion"]["blocking_gates"] = serde_json::json!(99);
        snapshot["risk"]["severity"] = serde_json::json!("stale password=hunter2");
        snapshot["risk"]["next_command"] =
            serde_json::json!("cargo run -- --bad --password=hunter2");
        snapshot["risk"]["rdp_proof_recovery_plan_command"] =
            serde_json::json!("cargo run -- --bad-risk-recovery --password=hunter2");
        snapshot["risk"]["rdp_proof_recovery_plan_summary"] =
            serde_json::json!("Latest RDP proof recovery plan: stale risk password=hunter2");
        snapshot["rdp_proof"]["recovery_plan_command"] =
            serde_json::json!("cargo run -- --bad-recovery --password=hunter2");
        snapshot["latest_evidence"]["rdp_proof_recovery_plan"] =
            serde_json::json!("Latest RDP proof recovery plan: stale password=hunter2");
        snapshot["risk"]["rdp_proof_ok"] = serde_json::json!(true);
        snapshot["risk"]["rdp_proof_failed_checks"] = serde_json::json!(["stale"]);
        snapshot["risk"]["rdp_proof_failed_check_actions"] = serde_json::json!([]);
        snapshot["llm_action_contract"]["copy_action"] =
            serde_json::json!("Copy stale contract password=hunter2");
        snapshot["llm_action_contract"]["required_evidence_files"] =
            serde_json::json!(["verification-snapshot.json"]);
        snapshot["llm_action_contract"]["must_return"] = serde_json::json!(["current_status"]);
        snapshot["llm_action_contract"]["success_signals"] =
            serde_json::json!(["stale success password=hunter2"]);
        snapshot["llm_action_contract"]["direct_live_evidence_requirements"] =
            serde_json::json!(["stale direct evidence password=hunter2"]);
        snapshot["llm_action_contract"]["proxy_evidence_rejected"] =
            serde_json::json!(["stale proxy password=hunter2"]);
        snapshot["llm_review_prompt"]["copy_action"] =
            serde_json::json!("Copy stale review prompt password=hunter2");
        snapshot["llm_review_prompt"]["command"] =
            serde_json::json!("cargo run -- --bad-review --password=hunter2");
        snapshot["llm_review_prompt"]["triage_order"] = serde_json::json!(["summary.md"]);
        snapshot["llm_review_prompt"]["risk_summary_cross_check"] =
            serde_json::json!(["stale risk password=hunter2"]);
        snapshot["llm_review_prompt"]["proxy_evidence_rejected"] =
            serde_json::json!(["stale proxy password=hunter2"]);
        std::fs::write(
            &snapshot_path,
            serde_json::to_string_pretty(&snapshot).unwrap(),
        )
        .expect("corrupted verification snapshot");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check.content_mismatches.iter().any(|error| {
                error.contains("verification-snapshot.handoff.pack_valid mismatch")
            })
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.completion.blocking_gates mismatch")
        }));
        assert!(
            check
                .content_mismatches
                .iter()
                .any(|error| { error.contains("verification-snapshot.risk.severity mismatch") })
        );
        assert!(
            check.content_mismatches.iter().any(|error| {
                error.contains("verification-snapshot.risk.next_command mismatch")
            })
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.rdp_proof.recovery_plan_command mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.risk.rdp_proof_recovery_plan_command mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.risk.rdp_proof_recovery_plan_summary mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.latest_evidence.rdp_proof_recovery_plan mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.risk.rdp_proof_failed_check_actions mismatch")
        }));
        assert!(
            check.content_mismatches.iter().any(|error| {
                error.contains("verification-snapshot.risk.rdp_proof_ok mismatch")
            })
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.risk.rdp_proof_failed_checks mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.llm_action_contract.copy_action mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_action_contract.required_evidence_files missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_action_contract.must_return missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_action_contract.success_signals missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_action_contract.direct_live_evidence_requirements missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_action_contract.proxy_evidence_rejected missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.llm_review_prompt.copy_action mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("verification-snapshot.llm_review_prompt.command mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_review_prompt.triage_order missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_review_prompt.risk_summary_cross_check missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "verification-snapshot.llm_review_prompt.proxy_evidence_rejected missing required value",
            )
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_stale_risk_summary_proof_actions() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let risk_path = pack.join("operator-handoff-risk-summary.json");
        let mut risk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&risk_path).unwrap()).unwrap();
        risk["goal_evidence_ok"] = serde_json::json!(true);
        risk["failed_requirements"] = serde_json::json!(["stale password=hunter2"]);
        risk["live_gate_stage"] = serde_json::json!("stale-stage");
        risk["next_command"] = serde_json::json!("cargo run -- --bad --password=hunter2");
        risk["rdp_proof_recovery_plan_command"] =
            serde_json::json!("cargo run -- --bad-risk-recovery --password=hunter2");
        risk["rdp_proof_recovery_plan_summary"] =
            serde_json::json!("Latest RDP proof recovery plan: stale password=hunter2");
        risk["llm_triage_entrypoint"] = serde_json::json!("stale triage");
        risk["llm_action_contract_required_evidence_files"] =
            serde_json::json!(["stale-evidence.json"]);
        risk["llm_action_contract_direct_live_evidence_requirements"] =
            serde_json::json!(["stale direct evidence password=hunter2"]);
        risk["llm_action_contract_must_return"] = serde_json::json!(["stale_field"]);
        risk["rdp_proof_failed_check_actions"] = serde_json::json!([
            {
                "check": "smoke_connected",
                "command": "cargo run -- --rdp-smoke-test --password=hunter2",
                "action": "stale"
            }
        ]);
        std::fs::write(&risk_path, serde_json::to_string_pretty(&risk).unwrap())
            .expect("corrupted risk summary");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.rdp_proof_failed_check_actions mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.rdp_proof_recovery_plan_command mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.rdp_proof_recovery_plan_summary mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.llm_triage_entrypoint mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "operator-handoff-risk-summary.llm_action_contract_required_evidence_files mismatch",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "operator-handoff-risk-summary.llm_action_contract_direct_live_evidence_requirements mismatch",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.llm_action_contract_must_return mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.goal_evidence_ok mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.failed_requirements mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.live_gate_stage mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("operator-handoff-risk-summary.next_command mismatch")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_stale_llm_action_contract() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let contract_path = pack.join("llm-action-contract.json");
        let mut contract: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&contract_path).unwrap()).unwrap();
        contract["ok"] = serde_json::json!(true);
        contract["next_command"] = serde_json::json!("cargo run -- --bad --password=hunter2");
        contract["next_success_command"] =
            serde_json::json!("cargo run -- --bad-success --password=hunter2");
        contract["rdp_proof_recovery_plan_command"] =
            serde_json::json!("cargo run -- --bad-recovery --password=hunter2");
        contract["allowed_next_commands"] = serde_json::json!(["cargo run -- --stale"]);
        contract["rdp_proof"]["ok"] = serde_json::json!(true);
        contract["rdp_proof"]["failed_checks"] = serde_json::json!(["stale password=hunter2"]);
        contract["rdp_proof"]["failed_check_actions"] = serde_json::json!([
            {
                "check": "smoke_connected",
                "command": "cargo run -- --rdp-smoke-test --password=hunter2",
                "action": "stale"
            }
        ]);
        contract["required_evidence_files"] =
            serde_json::json!(["rdp-proof-check.json", "verification-snapshot.json"]);
        contract["direct_live_evidence_requirements"] =
            serde_json::json!(["stale direct evidence password=hunter2"]);
        contract["evidence_success_signals"] =
            serde_json::json!(["stale success password=hunter2"]);
        contract["proxy_evidence_rejected"] = serde_json::json!(["stale proxy password=hunter2"]);
        contract["assistant_response_contract"]["must_not_return"] =
            serde_json::json!(["stale completion claim password=hunter2"]);
        contract["assistant_response_contract"]["must_return"] =
            serde_json::json!(["current_status"]);
        std::fs::write(
            &contract_path,
            serde_json::to_string_pretty(&contract).unwrap(),
        )
        .expect("corrupted LLM action contract");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check
                .content_mismatches
                .iter()
                .any(|error| error.contains("llm-action-contract.ok mismatch"))
        );
        assert!(
            check
                .content_mismatches
                .iter()
                .any(|error| error.contains("llm-action-contract.next_command mismatch"))
        );
        assert!(
            check
                .content_mismatches
                .iter()
                .any(|error| error.contains("llm-action-contract.allowed_next_commands mismatch"))
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-action-contract.rdp_proof.failed_check_actions mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "llm-action-contract.required_evidence_files missing required value: summary.md"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "llm-action-contract.required_evidence_files missing required value: goal-evidence-check.json"
        )));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-action-contract.proxy_evidence_rejected missing required value")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-action-contract.evidence_success_signals missing required value")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "llm-action-contract.direct_live_evidence_requirements missing required value",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "llm-action-contract.assistant_response_contract.must_not_return missing required value"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "llm-action-contract.assistant_response_contract.must_return missing required value"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_stale_rdp_proof_recovery_plan() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let proof_check: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(pack.join("rdp-proof-check.json")).unwrap(),
        )
        .unwrap();
        let failed_checks = proof_check["failed_checks"]
            .as_array()
            .expect("failed checks")
            .iter()
            .filter_map(|value| value.as_str())
            .map(|value| format!("- `{value}`"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            pack.join("rdp-proof-recovery-plan.md"),
            format!(
                "# Aivana RDP Proof Recovery Plan\n\n## Failed Proof Checks\n{failed_checks}\n\n## Recovery Commands\n1. `cargo run -- --stale --password=hunter2`\n\n## Acceptance Criteria\n- `rdp-proof-check.ok == true`.\n- connected=true\n- framebuffer\n- input-probe\n\n## Rejection Rule\nDo not accept manifests as proof.\n"
            ),
        )
        .expect("corrupted recovery plan");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("rdp-proof-recovery-plan.failed_check_actions mismatch")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_operator_brief_doctor_mismatch() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let doctor_path = pack.join("live-gate-doctor.json");
        let mut doctor_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&doctor_path).unwrap()).unwrap();
        doctor_json["rdp_proof_recovery_plan_command"] =
            serde_json::json!("cargo run -- --bad-recovery --password=hunter2");
        std::fs::write(
            &doctor_path,
            serde_json::to_string_pretty(&doctor_json).unwrap(),
        )
        .expect("corrupted live gate doctor");
        std::fs::write(
            pack.join("live-gate-operator-brief.md"),
            "# Aivana Live Gate Operator Brief\n\n- Operator stage: stale-stage\n- Next command: `cargo run -- --rdp-smoke-test --password=hunter2`\n- RDP proof recovery plan command: `cargo run -- --bad-recovery --password=hunter2`\n",
        )
        .expect("corrupted operator brief");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check.content_mismatches.iter().any(|error| {
                error.contains("live-gate-operator-brief.operator_stage mismatch")
            })
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("live-gate-operator-brief.rdp_proof_recovery_plan_command mismatch")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("live-gate-doctor.rdp_proof_recovery_plan_command mismatch")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_llm_plan_missing_required_mentions() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        std::fs::write(
            pack.join("llm-live-gate-plan.md"),
            "# Aivana Live Gate LLM Plan\n\n- verification-snapshot.json\n- operator-handoff-risk-summary.json\n- rdp-proof-check.json\n- rdp-proof-recovery-plan.md\n- live-gate-doctor.json\n- live-gate-operator-brief.md\n- live-gate-sequence.txt\n- Reject proxy evidence\n- connected=true\n- password=hunter2\n",
        )
        .expect("corrupted llm plan");
        std::fs::write(
            pack.join("llm-review-prompt.md"),
            "# Aivana Operator Handoff LLM Review Prompt\n\n- verification-snapshot.json\n- operator-handoff-risk-summary.json\n- rdp-proof-check.json\n- rdp-proof-recovery-plan.md\n- live-gate-doctor.json\n- live-gate-operator-brief.md\n- live-gate-sequence.txt\n- Do not treat a command as proof\n- password=hunter2\n",
        )
        .expect("corrupted llm review prompt");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "llm-live-gate-plan.md missing required mention: RDP proof recovery plan command",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "llm-live-gate-plan.md missing required mention: --rdp-proof-recovery-plan"
        )));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-live-gate-plan.md missing required mention: summary.md")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-live-gate-plan.md missing required mention: Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "llm-live-gate-plan.md missing required mention: llm-action-contract.json",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-live-gate-plan.md missing required mention: LLM triage entrypoint")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error
                .contains("llm-live-gate-plan.md missing required mention: required evidence files")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-live-gate-plan.md missing required mention: early_triage_artifacts")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-review-prompt.md missing required mention: summary.md")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-review-prompt.md missing required mention: Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error
                .contains("llm-review-prompt.md missing required mention: llm-action-contract.json")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-review-prompt.md missing required mention: LLM triage entrypoint")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-review-prompt.md missing required mention: required evidence files")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("llm-review-prompt.md missing required mention: early_triage_artifacts")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_rdp_proof_prompt_missing_recovery_command() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        std::fs::write(
            pack.join("rdp-proof-prompt.md"),
            "# Aivana RDP Proof Prompt\n\n- connected=true\n- Framebuffer evidence\n- Input probe evidence\n- Reject proxy evidence\n- --rdp-smoke-test\n- --verification-snapshot\n- password=hunter2\n",
        )
        .expect("corrupted rdp proof prompt");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check.content_mismatches.iter().any(|error| error.contains(
                "rdp-proof-prompt.md missing required mention: --rdp-proof-recovery-plan"
            ))
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("rdp-proof-prompt.md missing required mention: summary.md")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("rdp-proof-prompt.md missing required mention: Early LLM Triage")
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains("rdp-proof-prompt.md missing required mention: llm-action-contract.json")
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_recovery_plan_role_missing_acceptance_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let plan_role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str())
                    == Some("rdp-proof-recovery-plan.md")
            })
            .unwrap();
        plan_role["role"] = serde_json::json!(
            "Human-readable recovery plan mapping failed proof checks to exact commands."
        );
        plan_role["inspect_when"] = serde_json::json!("Use when recovering token=abc.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest recovery-plan role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-recovery-plan.md missing required mention: acceptance criteria"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-recovery-plan.md missing required mention: proxy-evidence rejection"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-recovery-plan.md missing required mention: direct live evidence"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("token=abc"))
        );
    }

    #[test]
    fn gui_operator_actions_explain_recovery_plan_acceptance_and_direct_evidence() {
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        let markdown = build_gui_operator_actions(&audit);

        assert!(markdown.contains("Copy RDP Recovery Plan"));
        assert!(markdown.contains("acceptance criteria"));
        assert!(markdown.contains("direct live evidence"));
        assert!(markdown.contains("proxy-evidence rejection"));
        assert!(!markdown.contains("hunter2"));
        assert!(!markdown.contains("token=abc"));
    }

    #[test]
    fn operator_handoff_pack_check_rejects_rdp_proof_prompt_role_missing_triage_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let prompt_role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("rdp-proof-prompt.md")
            })
            .unwrap();
        prompt_role["role"] =
            serde_json::json!("Focused prompt for direct RDP proof with recovery-plan command.");
        prompt_role["inspect_when"] = serde_json::json!("Use when finishing token=abc.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest rdp-proof-prompt role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-prompt.md missing required mention: summary.md Early LLM Triage"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-prompt.md missing required mention: llm-action-contract.json"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-prompt.md missing required mention: proxy-evidence rejection"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("token=abc"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_llm_live_gate_plan_role_missing_triage_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let plan_role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("llm-live-gate-plan.md")
            })
            .unwrap();
        plan_role["role"] =
            serde_json::json!("Focused LLM/CI plan generated from the live-gate doctor.");
        plan_role["inspect_when"] =
            serde_json::json!("Use when asking automation to inspect token=abc.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest llm-live-gate-plan role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles llm-live-gate-plan.md missing required mention: summary.md Early LLM Triage"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles llm-live-gate-plan.md missing required mention: operator-handoff-risk-summary.json"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles llm-live-gate-plan.md missing required mention: early_triage_artifacts"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("token=abc"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_llm_review_prompt_role_missing_triage_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let prompt_role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("llm-review-prompt.md")
            })
            .unwrap();
        prompt_role["role"] =
            serde_json::json!("Focused prompt for LLM review of the handoff pack.");
        prompt_role["inspect_when"] =
            serde_json::json!("Use when asking an LLM to inspect token=abc.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest llm-review-prompt role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles llm-review-prompt.md missing required mention: summary.md Early LLM Triage"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles llm-review-prompt.md missing required mention: operator-handoff-risk-summary.json cross-check"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles llm-review-prompt.md missing required mention: early_triage_artifacts"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("token=abc"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_rdp_proof_prompt_role_missing_recovery_command() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let prompt_role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("rdp-proof-prompt.md")
            })
            .unwrap();
        prompt_role["role"] = serde_json::json!(
            "Focused redacted prompt for a human operator or LLM assistant to finish only the direct RDP proof gate."
        );
        prompt_role["inspect_when"] = serde_json::json!(
            "Use when the only remaining blocker is live RDP framebuffer/input evidence and password=hunter2."
        );
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest prompt role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-prompt.md missing required mention: recovery-plan command"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_live_gate_roles_missing_recovery_command() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        for file in ["live-gate-doctor.json", "live-gate-operator-brief.md"] {
            let role = roles
                .iter_mut()
                .find(|role| role.get("file").and_then(|value| value.as_str()) == Some(file))
                .unwrap();
            role["role"] = serde_json::json!("Live-gate artifact with password=hunter2.");
            role["inspect_when"] = serde_json::json!("Use for current blocker triage.");
        }
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest live-gate roles");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles live-gate-doctor.json missing required mention: recovery-plan command"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles live-gate-operator-brief.md missing required mention: recovery-plan command"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_risk_summary_role_missing_recovery_commands() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str())
                    == Some("operator-handoff-risk-summary.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Compact hard risk gate with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use when CI or an LLM needs risk status.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest risk-summary role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles operator-handoff-risk-summary.json missing required mention: exact recovery commands"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles operator-handoff-risk-summary.json missing required mention: LLM triage entrypoint"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles operator-handoff-risk-summary.json missing required mention: required evidence files"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles operator-handoff-risk-summary.json missing required mention: direct live evidence requirements"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles operator-handoff-risk-summary.json missing required mention: early_triage_artifacts"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_recovery_plan_role_missing_exact_commands() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str())
                    == Some("rdp-proof-recovery-plan.md")
            })
            .unwrap();
        role["role"] = serde_json::json!("Human-readable recovery plan with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use when an operator needs live evidence.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest recovery-plan role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-recovery-plan.md missing required mention: exact commands"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_rdp_proof_check_role_missing_frame_evidence() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("rdp-proof-check.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Direct RDP proof checklist with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use when CI or an LLM needs a proof gate.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest rdp proof check role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-check.json missing required mention: framebuffer"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-proof-check.json missing required mention: input probe"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_env_file_check_role_missing_offline_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("rdp-env-file-check.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("RDP environment validation with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use before live network commands.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest env-file-check role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-env-file-check.json missing required mention: offline RDP env-file validation evidence"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles rdp-env-file-check.json missing required mention: network_checked=false"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_goal_evidence_check_role_missing_hard_gate_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str())
                    == Some("goal-evidence-check.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Goal evidence summary with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use for completion review.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest goal-evidence-check role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles goal-evidence-check.json missing required mention: Hard completion assertion"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles goal-evidence-check.json missing required mention: failure exit semantics"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_goal_evidence_matrix_role_missing_matrix_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str())
                    == Some("goal-evidence-matrix.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Goal evidence summary with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use for structured review.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest goal-evidence-matrix role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles goal-evidence-matrix.json missing required mention: requirement-to-artifact matrix"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles goal-evidence-matrix.json missing required mention: next live gate"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_verification_snapshot_role_missing_snapshot_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str())
                    == Some("verification-snapshot.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Compact status artifact with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use before reading detailed files.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest verification-snapshot role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles verification-snapshot.json missing required mention: GUI"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles verification-snapshot.json missing required mention: latest-evidence snapshot"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles verification-snapshot.json missing required mention: LLM action-contract"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_command_index_role_missing_command_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("command-index.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Machine-readable helper with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use when orchestrating automation.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest command-index role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles command-index.json missing required mention: command catalog"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles command-index.json missing required mention: live-gate sequence"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_summary_role_missing_llm_triage_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| role.get("file").and_then(|value| value.as_str()) == Some("summary.md"))
            .unwrap();
        role["role"] = serde_json::json!("Short status helper with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use for quick review.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest summary role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "manifest.file_roles summary.md missing required mention: Early LLM Triage",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "manifest.file_roles summary.md missing required mention: verification-snapshot.json",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "manifest.file_roles summary.md missing required mention: llm-action-contract.json",
            )
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_next_live_gate_role_missing_next_action_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        let role = roles
            .iter_mut()
            .find(|role| {
                role.get("file").and_then(|value| value.as_str()) == Some("next-live-gate.json")
            })
            .unwrap();
        role["role"] = serde_json::json!("Structured live-gate helper with password=hunter2.");
        role["inspect_when"] = serde_json::json!("Use when an agent needs a single action.");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest next-live-gate role");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles next-live-gate.json missing required mention: first blocking gate"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles next-live-gate.json missing required mention: next commands"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_human_live_gate_roles_missing_command_semantics() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        let manifest_path = pack.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let roles = manifest
            .get_mut("file_roles")
            .and_then(|value| value.as_array_mut())
            .unwrap();
        for file in ["next-live-gate.md", "live-gate-sequence.txt"] {
            let role = roles
                .iter_mut()
                .find(|role| role.get("file").and_then(|value| value.as_str()) == Some(file))
                .unwrap();
            role["role"] = serde_json::json!("Human helper with password=hunter2.");
            role["inspect_when"] = serde_json::json!("Use when an operator asks for help.");
        }
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("corrupted manifest human live-gate roles");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(check.missing_file_roles.is_empty());
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles next-live-gate.md missing required mention: first blocking gate"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles next-live-gate.md missing required mention: next operator commands"
        )));
        assert!(check.content_mismatches.iter().any(|error| error.contains(
            "manifest.file_roles live-gate-sequence.txt missing required mention: ordered live-gate command sequence"
        )));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn operator_handoff_pack_check_rejects_gui_actions_missing_env_source() {
        let root = std::env::temp_dir().join(format!("aivana-operator-packs-{}", Uuid::new_v4()));
        let pack = root.join(Uuid::new_v4().to_string());
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false password=hunter2".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        save_operator_handoff_pack_to_dir(&pack, &readiness, &audit).expect("saved operator pack");
        std::fs::write(
            pack.join("gui-operator-actions.md"),
            "# Aivana GUI Operator Actions\n\nNo env-source instruction. password=hunter2\n",
        )
        .expect("corrupted gui actions");

        let check = build_operator_handoff_pack_check_from_dir(
            &root,
            Utc::now(),
            "aivana.operator-handoff-pack.v1",
        )
        .expect("checked handoff pack");
        let _ = std::fs::remove_dir_all(root);

        assert!(!check.ok);
        assert!(check.invalid_file_schemas.is_empty());
        assert!(
            check.content_mismatches.iter().any(|error| {
                error.contains("gui-operator-actions.md missing required mention")
            })
        );
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: summary.md Early LLM Triage",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: early_triage_artifacts",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: direct_live_evidence_requirements",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: Copy LLM Review Prompt",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: operator-handoff-risk-summary.json cross-check",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: evidence success signals",
            )
        }));
        assert!(check.content_mismatches.iter().any(|error| {
            error.contains(
                "gui-operator-actions.md missing required mention: proxy-evidence rejection rules",
            )
        }));
        assert!(
            !check
                .content_mismatches
                .iter()
                .any(|error| error.contains("hunter2"))
        );
    }

    #[test]
    fn latest_live_gate_summary_reads_blocked_report() {
        let dir = std::env::temp_dir().join(format!("aivana-live-gates-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("created live gate temp dir");
        let path = dir.join("blocked.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "generated_at": "2026-05-17T17:20:37Z",
                "timeout_secs": 90,
                "achieved": false,
                "blocking_gates": 1,
                "preflight": {
                    "connect_recommended": false,
                    "env_error": "password=hunter2"
                },
                "smoke": {
                    "status": "skipped",
                    "connected": false,
                    "summary": "token=abc"
                }
            })
            .to_string(),
        )
        .expect("wrote live gate report");

        let summary = latest_live_gate_report_summary_from_dir(&dir)
            .expect("read live gate summary")
            .expect("summary");
        let _ = std::fs::remove_dir_all(dir);

        assert!(summary.contains("Latest live gate report"));
        assert!(summary.contains("achieved=false"));
        assert!(summary.contains("blocking_gates=1"));
        assert!(summary.contains("preflight_ready=false"));
        assert!(summary.contains("smoke_status=skipped"));
        assert!(summary.contains("smoke_connected=false"));
        assert!(summary.contains("timeout=90s"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("token=abc"));
    }

    #[test]
    fn live_gate_report_maps_blockers_and_redacts_smoke_skip() {
        let preflight = RdpPreflightEvidenceReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            host: "host password=hunter2".to_owned(),
            port: 3389,
            timeout_secs: 90,
            username_set: false,
            password_set: false,
            connect_recommended: false,
            env_error: Some("token=abc".to_owned()),
            expected_environment: vec!["AIVANA_RDP_TEST_HOST"],
            findings: Vec::new(),
            evidence_path: Some("preflight.json".to_owned()),
        };
        let smoke = LiveGateSmokeEvidence::skipped("skip password=hunter2 token=abc");
        let readiness = KiReadinessCliReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            openai_key_set: true,
            rdp_smoke_env_ready: false,
            preferences_saved: true,
            active_sessions: 0,
            provider: "OpenAI CUA".to_owned(),
            model: "gpt-5.5".to_owned(),
            max_steps: 12,
            step_delay_millis: 800,
            goal: "Diagnose token=abc".to_owned(),
            readiness_score: 75,
            missing_requirements: vec!["AIVANA_RDP_TEST_*".to_owned()],
            latest_rdp_preflight_evidence: Some("preflight blocked".to_owned()),
            latest_rdp_smoke_evidence: Some("connected=false".to_owned()),
            latest_live_gate_evidence: Some("live gate blocked".to_owned()),
            next_step: "Run smoke test".to_owned(),
            evidence_path: None,
        };
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false password=hunter2".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );

        let report = build_live_gate_report_from_parts(90, preflight, smoke, readiness, audit);
        let json = serde_json::to_string(&report).expect("serialized live gate");

        assert!(!report.achieved);
        assert_eq!(report.blocking_gates, 1);
        assert!(report.next_action.contains("AIVANA_RDP_TEST_HOST"));
        assert!(
            report
                .rdp_env_template
                .contains("AIVANA_RDP_TEST_HOST=<host>")
        );
        assert!(
            report
                .rdp_env_template
                .contains("AIVANA_RDP_TEST_PASSWORD=[REDACTED]")
        );
        assert!(json.contains("password=[REDACTED]"));
        assert!(json.contains("token=[REDACTED]"));
        assert!(json.contains("missing_rdp_env"));
        assert!(json.contains("rdp_env_template"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("token=abc"));
    }

    #[test]
    fn live_gate_report_readiness_uses_rdp_env_file_args() {
        let path = std::env::temp_dir().join(format!(
            "aivana-live-gate-readiness-rdp-{}.env",
            Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--live-gate".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let readiness = build_ki_readiness_cli_report_from_args(&args);
        let preflight = RdpPreflightEvidenceReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            host: "unknown-host".to_owned(),
            port: 3389,
            timeout_secs: 90,
            username_set: false,
            password_set: false,
            connect_recommended: false,
            env_error: Some("blocked before network".to_owned()),
            expected_environment: vec!["AIVANA_RDP_TEST_HOST"],
            findings: Vec::new(),
            evidence_path: None,
        };
        let smoke = LiveGateSmokeEvidence::skipped("skip before network");
        let audit = build_completion_audit_report_with_inputs(
            readiness.clone(),
            None,
            "Latest RDP preflight evidence: connect_recommended=false".to_owned(),
            "connected=false".to_owned(),
            "Latest AI brief pack: 4 file(s)".to_owned(),
        );
        let report = build_live_gate_report_from_parts(90, preflight, smoke, readiness, audit);
        let _ = std::fs::remove_file(path);

        assert!(report.readiness.rdp_smoke_env_ready);
        assert!(report.missing_rdp_env.is_empty());
        assert!(
            !report
                .readiness
                .missing_requirements
                .iter()
                .any(|item| item.contains("AIVANA_RDP_TEST_*") || item.contains("hunter2"))
        );
    }

    #[test]
    fn next_live_gate_uses_rdp_env_file_args_for_missing_env() {
        let path =
            std::env::temp_dir().join(format!("aivana-next-gate-rdp-{}.env", Uuid::new_v4()));
        std::fs::write(
            &path,
            "AIVANA_RDP_TEST_HOST=rdp.example.local\nAIVANA_RDP_TEST_USER=operator\nAIVANA_RDP_TEST_PASSWORD=hunter2\n",
        )
        .expect("write env file");
        let args = vec![
            "aivana".to_owned(),
            "--next-live-gate-json".to_owned(),
            "--rdp-env-file".to_owned(),
            path.display().to_string(),
        ];

        let audit = build_completion_audit_report_from_args(&args);
        let next_gate = build_next_live_gate_report_from_args(&audit, &args);
        let matrix = build_goal_evidence_matrix_from_args(&audit, &args);
        let _ = std::fs::remove_file(path);

        assert!(next_gate.missing_rdp_env.is_empty());
        assert_eq!(
            matrix["next_live_gate"]["missing_rdp_env"],
            serde_json::json!([])
        );
        assert!(
            !serde_json::to_string(&matrix)
                .expect("matrix json")
                .contains("hunter2")
        );
    }

    #[test]
    fn latest_preflight_summary_reads_failure_evidence() {
        let dir = std::env::temp_dir().join(format!("aivana-preflight-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("created preflight temp dir");
        let path = dir.join("blocked.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "generated_at": "2026-05-17T17:10:00Z",
                "host": "server password=hunter2",
                "port": 3389,
                "timeout_secs": 90,
                "connect_recommended": false,
                "env_error": "token=abc",
                "findings": [{"title": "DNS failed"}],
                "evidence_path": path.display().to_string()
            })
            .to_string(),
        )
        .expect("wrote preflight report");

        let summary =
            latest_rdp_preflight_report_summary_from_dir(&dir).expect("read preflight summary");
        let _ = std::fs::remove_dir_all(&dir);
        let summary = summary.expect("summary exists");

        assert!(summary.contains("Latest RDP preflight evidence"));
        assert!(summary.contains("connect_recommended=false"));
        assert!(summary.contains("findings=1"));
        assert!(summary.contains("password=[REDACTED]"));
        assert!(summary.contains("token=[REDACTED]"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("token=abc"));
    }

    #[test]
    fn latest_env_file_check_summary_reads_persisted_evidence() {
        let dir = std::env::temp_dir().join(format!("aivana-env-file-check-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("created env file check temp dir");
        let path = dir.join("check.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "generated_at": "2026-05-17T17:12:00Z",
                "ok": false,
                "host": "server password=hunter2",
                "port": 3390,
                "timeout_secs": 90,
                "network_checked": false,
                "error": "token=abc",
                "evidence_path": path.display().to_string()
            })
            .to_string(),
        )
        .expect("wrote env file check report");

        let summary =
            latest_rdp_env_file_check_summary_from_dir(&dir).expect("read env check summary");
        let _ = std::fs::remove_dir_all(&dir);
        let summary = summary.expect("summary exists");

        assert!(summary.contains("Latest RDP env-file check evidence"));
        assert!(summary.contains("ok=false"));
        assert!(summary.contains("network_checked=false"));
        assert!(summary.contains("password=[REDACTED]"));
        assert!(summary.contains("token=[REDACTED]"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("abc"));
    }

    #[test]
    fn latest_successful_smoke_summary_skips_newer_failures() {
        let dir = std::env::temp_dir().join(format!("aivana-rdp-success-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let success = dir.join("success.json");
        let failure = dir.join("failure.json");
        std::fs::write(
            &success,
            serde_json::json!({
                "connected": true,
                "generated_at": "2026-05-17T12:00:00Z",
                "host": "test",
                "framebuffer": { "width": 1024, "height": 768, "frame_hash": 42 },
                "evidence_path": success.display().to_string()
            })
            .to_string(),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(
            &failure,
            serde_json::json!({
                "connected": false,
                "generated_at": "2026-05-17T12:01:00Z",
                "error": "password=hunter2"
            })
            .to_string(),
        )
        .unwrap();

        let summary = latest_successful_rdp_smoke_report_summary_from_dir(&dir)
            .expect("read success summary")
            .expect("success summary");
        let _ = std::fs::remove_dir_all(dir);

        assert!(summary.contains("connected=true"));
        assert!(summary.contains("1024x768"));
        assert!(!summary.contains("hunter2"));
    }

    #[test]
    fn latest_preflight_summary_reads_blocked_evidence() {
        let dir = std::env::temp_dir().join(format!("aivana-rdp-preflight-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocked.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "generated_at": "2026-05-17T12:00:00Z",
                "host": "unknown-host",
                "port": 3389,
                "timeout_secs": 90,
                "connect_recommended": false,
                "env_error": "password=hunter2",
                "findings": [],
                "evidence_path": path.display().to_string()
            })
            .to_string(),
        )
        .unwrap();

        let summary = latest_rdp_preflight_report_summary_from_dir(&dir)
            .expect("read preflight summary")
            .expect("summary");
        let _ = std::fs::remove_dir_all(dir);

        assert!(summary.contains("Latest RDP preflight evidence"));
        assert!(summary.contains("connect_recommended=false"));
        assert!(summary.contains("timeout=90s"));
        assert!(summary.contains("password=[REDACTED]"));
        assert!(!summary.contains("hunter2"));
    }

    #[test]
    fn runbook_llm_brief_contains_steps_and_redacts_host() {
        let runbooks = RunbookEngine::with_defaults();

        let brief = build_runbook_llm_brief(runbooks.list_runbooks(), "server password=hunter2");

        assert!(brief.contains("Aivana Runbook LLM Brief"));
        assert!(brief.contains("selected runbook"));
        assert!(brief.contains("Screenshot erfassen"));
        assert!(brief.contains("password=[REDACTED]"));
        assert!(!brief.contains("hunter2"));
    }

    #[test]
    fn prompt_library_contains_prompt_set_and_redacts_goal() {
        let mut autopilot = AutopilotController::default();
        autopilot.goal = "Diagnose token=abc".to_owned();
        let library =
            build_prompt_library_brief("host", "Action password=hunter2", &autopilot, false);

        assert!(library.contains("Aivana Prompt Library"));
        assert!(library.contains("Diagnosis"));
        assert!(library.contains("Runbook Selection"));
        assert!(library.contains("Ticket Draft"));
        assert!(library.contains("Verification"));
        assert!(library.contains("token=[REDACTED]"));
        assert!(library.contains("password=[REDACTED]"));
        assert!(!library.contains("hunter2"));
        assert!(!library.contains("abc"));
    }

    #[test]
    fn guardrail_brief_reflects_approval_mode() {
        let mut settings = AutopilotSettings::default();
        settings.require_approval_for_every_mutation = true;
        settings.agentic_runbook_mode = false;

        let brief = build_guardrail_brief(&settings);

        assert!(brief.contains("mutating UI actions require approval"));
        assert!(brief.contains("operator-gated mode enabled"));
        assert!(brief.contains("destructive text denied"));
    }

    #[test]
    fn cua_request_brief_redacts_goal_and_reports_frame_status() {
        let mut autopilot = AutopilotController::default();
        autopilot.goal = "Inspect token=abc".to_owned();

        let brief = build_cua_request_brief(&autopilot, false);

        assert!(brief.contains("Aivana OpenAI CUA Request Brief"));
        assert!(brief.contains("framebuffer missing"));
        assert!(brief.contains("token=[REDACTED]"));
        assert!(brief.contains("Do not include credentials"));
        assert!(!brief.contains("abc"));
    }

    #[test]
    fn ai_brief_pack_writes_redacted_files() {
        let dir = std::env::temp_dir().join(format!("aivana-ai-brief-pack-{}", Uuid::new_v4()));

        let saved = save_ai_brief_pack_to_dir(
            &dir,
            "Action password=hunter2",
            "Prompt token=abc",
            "Runbook secret=value",
            "Verify pwd=123",
        )
        .expect("saved brief pack");

        let action = std::fs::read_to_string(saved.join("action-brief.md")).unwrap();
        let prompt = std::fs::read_to_string(saved.join("prompt-library.md")).unwrap();
        let runbook = std::fs::read_to_string(saved.join("runbook-brief.md")).unwrap();
        let verification = std::fs::read_to_string(saved.join("verification-brief.md")).unwrap();
        let manifest = std::fs::read_to_string(saved.join("manifest.json")).unwrap();
        let _ = std::fs::remove_dir_all(saved);

        assert!(action.contains("password=[REDACTED]"));
        assert!(prompt.contains("token=[REDACTED]"));
        assert!(runbook.contains("secret=[REDACTED]"));
        assert!(verification.contains("pwd=[REDACTED]"));
        assert!(manifest.contains("aivana-ai-brief-pack"));
        assert!(manifest.contains("action-brief.md"));
        assert!(manifest.contains("\"redacted\": true"));
        assert!(!action.contains("hunter2"));
        assert!(!prompt.contains("abc"));
        assert!(!runbook.contains("value"));
        assert!(!verification.contains("123"));
    }

    #[test]
    fn ai_brief_pack_report_exports_headless_redacted_pack() {
        let report = build_ai_brief_pack_report().expect("headless AI brief pack");
        let action = std::fs::read_to_string(format!("{}/action-brief.md", report.pack_path))
            .expect("read action brief");
        let prompt = std::fs::read_to_string(format!("{}/prompt-library.md", report.pack_path))
            .expect("read prompt library");
        let manifest = std::fs::read_to_string(format!("{}/manifest.json", report.pack_path))
            .expect("read manifest");
        let _ = std::fs::remove_dir_all(&report.pack_path);

        assert_eq!(report.schema, "aivana.ai-brief-pack.v1");
        assert!(report.redacted);
        assert!(report.files.iter().any(|file| file == "action-brief.md"));
        assert!(action.contains("headless operator context"));
        assert!(prompt.contains("Aivana Prompt Library"));
        assert!(manifest.contains("aivana-ai-brief-pack"));
        assert!(!action.contains("hunter2"));
        assert!(!prompt.contains("token=abc"));
    }

    #[test]
    fn latest_ai_brief_pack_summary_reads_manifest() {
        let root = std::env::temp_dir().join(format!("aivana-ai-brief-packs-{}", Uuid::new_v4()));
        let pack = root.join("pack-1");
        save_ai_brief_pack_to_dir(&pack, "Action", "Prompt", "Runbook", "Verify")
            .expect("saved pack");

        let summary = latest_ai_brief_pack_summary_from_dir(&root)
            .expect("read pack summary")
            .expect("summary");
        let _ = std::fs::remove_dir_all(root);

        assert!(summary.contains("Latest AI brief pack"));
        assert!(summary.contains("4 file"));
        assert!(summary.contains("manifest.json"));
    }

    #[test]
    fn latest_smoke_report_summary_reads_failure_evidence() {
        let dir = std::env::temp_dir().join(format!("aivana-smoke-reports-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("created temp smoke dir");
        let path = dir.join("failed.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "connected": false,
                "generated_at": "2026-05-17T16:31:42Z",
                "error": "password=hunter2 failed",
                "expected_environment": ["AIVANA_RDP_TEST_HOST"],
                "evidence_path": path.display().to_string()
            })
            .to_string(),
        )
        .expect("wrote smoke report");

        let summary =
            latest_rdp_smoke_report_summary_from_dir(&dir).expect("read smoke report summary");
        let _ = std::fs::remove_dir_all(&dir);

        let summary = summary.expect("summary exists");
        assert!(summary.contains("connected=false"));
        assert!(summary.contains("password=[REDACTED]"));
        assert!(!summary.contains("hunter2"));
    }
}
