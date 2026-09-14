use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use uuid::Uuid;

use crate::ironrdp_client::{IronRdpRuntime, run_session};
use crate::models::{
    ConnectionProfile, DiagnosticClass, EngineEvent, FrameUpdate, InputAction, MouseButton,
    PerformanceMetrics, RemoteSession, SessionStatus,
};

pub struct ProfileStore {
    path: PathBuf,
}

impl ProfileStore {
    pub fn new() -> Result<Self> {
        let base_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Aivana")
            .join("RustRdpClient");
        fs::create_dir_all(&base_dir).context("failed to create app data directory")?;

        Ok(Self {
            path: base_dir.join("profiles.json"),
        })
    }

    pub fn load(&self) -> Result<Vec<ConnectionProfile>> {
        if !self.path.exists() {
            return Ok(Self::seed_profiles());
        }

        let json = fs::read_to_string(&self.path).context("failed to read profiles file")?;
        let mut profiles: Vec<ConnectionProfile> =
            serde_json::from_str(&json).context("failed to parse profiles file")?;
        let had_serialized_passwords = profiles.iter().any(|profile| !profile.password.is_empty());
        for profile in &mut profiles {
            profile.password.clear();
        }
        if had_serialized_passwords {
            let _ = self.save(&profiles);
        }
        Ok(profiles)
    }

    pub fn save(&self, profiles: &[ConnectionProfile]) -> Result<()> {
        let json =
            serde_json::to_string_pretty(profiles).context("failed to serialize profiles")?;
        crate::security::atomic_write(&self.path, json.as_bytes())
            .context("failed to write profiles file")
    }

    fn seed_profiles() -> Vec<ConnectionProfile> {
        vec![
            ConnectionProfile::sample("Production Gateway", "10.0.12.8", "Production", true),
            ConnectionProfile::sample("Build Server", "build-01.local", "Engineering", false),
            ConnectionProfile::sample("QA Desktop", "qa-win-03.local", "QA", false),
        ]
    }
}

pub trait RemoteDesktopEngine {
    fn connect(&mut self, profile: &ConnectionProfile) -> Result<RemoteSession>;
    fn reconnect(&mut self, session: &mut RemoteSession) -> Result<()>;
    fn resize(&mut self, session_id: Uuid, width: u16, height: u16) -> Result<()>;
    fn disconnect(&mut self, session_id: Uuid) -> Result<()>;
    fn tick(&mut self, session: &mut RemoteSession);
    fn poll_frame(&mut self, session_id: Uuid) -> Option<FrameUpdate>;
    fn send_input(&mut self, session_id: Uuid, action: InputAction) -> Result<()>;
    fn poll_events(&mut self, session_id: Uuid) -> Vec<EngineEvent>;
}

#[derive(Default)]
pub struct NativeRdpEngine {
    events: HashMap<Uuid, Receiver<EngineEvent>>,
    inputs: HashMap<Uuid, Sender<InputAction>>,
    profiles: HashMap<Uuid, ConnectionProfile>,
    latest_frames: HashMap<Uuid, FrameUpdate>,
    event_backlog: HashMap<Uuid, Vec<EngineEvent>>,
    workers: HashMap<Uuid, thread::JoinHandle<()>>,
    retries: HashMap<Uuid, RetryState>,
    held: HashMap<Uuid, HeldInput>,
    requested_sizes: HashMap<Uuid, (u16, u16)>,
    clipboard_focus: Option<Uuid>,
    manual_capture: bool,
    manual_inputs: Vec<(Uuid, InputAction, Instant)>,
}

#[derive(Default)]
struct HeldInput {
    keys: Vec<u16>,
    buttons: Vec<MouseButton>,
    pointer: (u16, u16),
}

impl HeldInput {
    fn record(&mut self, action: &InputAction) {
        match action {
            InputAction::Key { scan_code, pressed } => {
                self.keys.retain(|key| key != scan_code);
                if *pressed {
                    self.keys.push(*scan_code);
                }
            }
            InputAction::PointerButton {
                x,
                y,
                button,
                pressed,
            } => {
                self.pointer = (*x, *y);
                self.buttons.retain(|held| held != button);
                if *pressed {
                    self.buttons.push(*button);
                }
            }
            InputAction::MovePointer { x, y } => self.pointer = (*x, *y),
            _ => {}
        }
    }

    fn release(&mut self) -> Vec<InputAction> {
        let mut actions: Vec<_> = self
            .keys
            .drain(..)
            .rev()
            .map(|scan_code| InputAction::Key {
                scan_code,
                pressed: false,
            })
            .collect();
        let (x, y) = self.pointer;
        actions.extend(
            self.buttons
                .drain(..)
                .map(|button| InputAction::PointerButton {
                    x,
                    y,
                    button,
                    pressed: false,
                }),
        );
        actions
    }
}

#[derive(Default)]
struct RetryState {
    attempts: u8,
    due: Option<Instant>,
    disabled: bool,
    connected_since: Option<Instant>,
}

impl RetryState {
    fn schedule(&mut self, now: Instant) -> Option<Duration> {
        if self.disabled || self.attempts >= 5 || self.due.is_some() {
            return None;
        }
        let delay = Duration::from_secs(1 << self.attempts);
        self.attempts += 1;
        self.due = Some(now + delay);
        self.connected_since = None;
        Some(delay)
    }
}

impl RemoteDesktopEngine for NativeRdpEngine {
    fn connect(&mut self, profile: &ConnectionProfile) -> Result<RemoteSession> {
        let session_id = Uuid::new_v4();
        let profile_for_thread = profile.clone();
        let (event_sender, event_receiver) = mpsc::channel();
        let (input_sender, input_receiver) = mpsc::channel();

        self.workers.insert(
            session_id,
            spawn_runtime(session_id, profile_for_thread, event_sender, input_receiver),
        );
        self.retries.insert(session_id, RetryState::default());

        self.events.insert(session_id, event_receiver);
        self.inputs.insert(session_id, input_sender);
        self.profiles.insert(session_id, profile.clone());
        self.event_backlog.insert(session_id, Vec::new());

        Ok(RemoteSession {
            id: session_id,
            profile_id: profile.id,
            title: profile.name.clone(),
            status: SessionStatus::Connecting,
            connected_at: Utc::now(),
            metrics: PerformanceMetrics {
                latency_ms: 0.0,
                bandwidth_mbps: 0.0,
                frame_rate: 0.0,
                packet_loss_pct: 0.0,
                quality_score: 0,
            },
            last_error: None,
            frame_size: None,
        })
    }

    fn reconnect(&mut self, session: &mut RemoteSession) -> Result<()> {
        if !self.profiles.contains_key(&session.id) {
            return Err(anyhow!("session profile is not available for reconnect"));
        }
        crate::rdp_audio_input::stop_session(session.id);
        self.release_inputs(session.id);
        self.inputs.remove(&session.id);
        self.events.remove(&session.id);
        self.retries.insert(
            session.id,
            RetryState {
                due: Some(Instant::now()),
                ..Default::default()
            },
        );
        session.status = SessionStatus::Reconnecting;
        session.last_error = None;
        Ok(())
    }

    fn resize(&mut self, session_id: Uuid, width: u16, height: u16) -> Result<()> {
        if !self.profiles.get(&session_id).is_some_and(|profile| {
            profile.options.dynamic_resolution && profile.options.monitors.is_empty()
        }) {
            return Ok(());
        }
        if self.requested_sizes.get(&session_id) != Some(&(width, height)) {
            self.send_input(session_id, InputAction::Resize { width, height })?;
            self.requested_sizes.insert(session_id, (width, height));
        }
        Ok(())
    }

    fn disconnect(&mut self, session_id: Uuid) -> Result<()> {
        crate::rdp_audio_input::stop_session(session_id);
        self.release_inputs(session_id);
        self.retries.remove(&session_id);
        self.held.remove(&session_id);
        self.requested_sizes.remove(&session_id);
        self.inputs.remove(&session_id);
        self.events.remove(&session_id);
        self.profiles.remove(&session_id);
        self.latest_frames.remove(&session_id);
        self.event_backlog.remove(&session_id);
        Ok(())
    }

    fn tick(&mut self, session: &mut RemoteSession) {
        self.workers
            .retain(|id, worker| self.profiles.contains_key(id) || !worker.is_finished());
        let mut drained = Vec::new();
        let mut channel_closed = false;
        if let Some(receiver) = self.events.get(&session.id) {
            loop {
                match receiver.try_recv() {
                    Ok(event) => drained.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        channel_closed = true;
                        let already_has_terminal_event = drained.iter().any(|event| {
                            matches!(
                                event,
                                EngineEvent::Error { .. } | EngineEvent::Disconnected { .. }
                            )
                        });
                        if !already_has_terminal_event
                            && !matches!(
                                session.status,
                                SessionStatus::Failed
                                    | SessionStatus::Disconnected
                                    | SessionStatus::Reconnecting
                            )
                        {
                            drained.push(EngineEvent::Disconnected {
                                session_id: session.id,
                                reason: "RDP runtime stopped".to_owned(),
                            });
                        }
                        break;
                    }
                }
            }
        }
        if channel_closed {
            self.events.remove(&session.id);
        }

        for event in drained {
            match event {
                EngineEvent::Frame(frame) => {
                    self.apply_frame(session, frame);
                }
                other => {
                    self.apply_event(session, other.clone());
                    self.event_backlog
                        .entry(session.id)
                        .or_default()
                        .push(other);
                }
            }
        }

        self.advance_retry(session, Instant::now());
    }

    fn poll_frame(&mut self, session_id: Uuid) -> Option<FrameUpdate> {
        self.latest_frames.remove(&session_id)
    }

    fn send_input(&mut self, session_id: Uuid, action: InputAction) -> Result<()> {
        let sender = self
            .inputs
            .get(&session_id)
            .ok_or_else(|| anyhow!("session input channel is not available"))?;
        sender
            .send(action.clone())
            .context("send RDP input action")?;
        self.held.entry(session_id).or_default().record(&action);
        Ok(())
    }

    fn poll_events(&mut self, session_id: Uuid) -> Vec<EngineEvent> {
        self.event_backlog.remove(&session_id).unwrap_or_default()
    }
}

fn spawn_runtime(
    session_id: Uuid,
    profile: ConnectionProfile,
    event_sender: Sender<EngineEvent>,
    input_receiver: Receiver<InputAction>,
) -> thread::JoinHandle<()> {
    crate::rdp_audio_input::allow_session(session_id);
    thread::spawn(move || {
        run_session(IronRdpRuntime {
            profile,
            session_id,
            events: event_sender,
            input: input_receiver,
        });
    })
}

impl NativeRdpEngine {
    pub fn set_manual_capture(&mut self, enabled: bool) {
        self.manual_capture = enabled;
        if !enabled {
            self.manual_inputs.clear();
        }
    }
    pub fn take_manual_inputs(&mut self) -> Vec<(Uuid, InputAction, Instant)> {
        std::mem::take(&mut self.manual_inputs)
    }
    pub fn send_manual_input(&mut self, session_id: Uuid, action: InputAction) -> Result<()> {
        self.send_input(session_id, action.clone())?;
        if self.manual_capture
            && !matches!(action, InputAction::MovePointer { .. })
            && self.manual_inputs.len() < 512
        {
            // Text is only a marker; passwords never enter the observation queue.
            self.manual_inputs.push((
                session_id,
                match action {
                    InputAction::TypeText { .. } => InputAction::TypeText {
                        text: String::new(),
                    },
                    InputAction::Hotkey { .. } => InputAction::Hotkey { keys: vec![] },
                    other => other,
                },
                Instant::now(),
            ));
        }
        Ok(())
    }
    pub fn release_inputs(&mut self, session_id: Uuid) {
        if self.clipboard_focus == Some(session_id) {
            self.set_clipboard_focus(None);
        }
        if let Some(held) = self.held.get_mut(&session_id) {
            for action in held.release() {
                if let Some(sender) = self.inputs.get(&session_id) {
                    let _ = sender.send(action);
                }
            }
        }
    }

    pub fn release_inputs_except(&mut self, focused: Option<Uuid>) {
        if self.clipboard_focus != focused {
            self.set_clipboard_focus(None);
        }
        let ids: Vec<_> = self
            .held
            .keys()
            .copied()
            .filter(|id| Some(*id) != focused)
            .collect();
        for id in ids {
            self.release_inputs(id);
        }
    }

    pub fn set_clipboard_focus(&mut self, focused: Option<Uuid>) {
        if self.clipboard_focus == focused {
            return;
        }
        // Revoke synchronously across runtimes; queued focus events alone race during handoff.
        crate::rdp_channels::set_clipboard_owner(None);
        if let Some(old) = self.clipboard_focus.take() {
            let _ = self.send_input(old, InputAction::ClipboardFocus { active: false });
        }
        if let Some(id) = focused {
            crate::rdp_channels::set_clipboard_owner(Some(id));
            if self
                .send_input(id, InputAction::ClipboardFocus { active: true })
                .is_ok()
            {
                self.clipboard_focus = Some(id);
            } else {
                crate::rdp_channels::set_clipboard_owner(None);
            }
        }
    }

    pub fn key_is_held(&self, session_id: Uuid, code: u16) -> bool {
        self.held
            .get(&session_id)
            .is_some_and(|held| held.keys.contains(&code))
    }

    pub fn pointer_is_held(&self, session_id: Uuid) -> bool {
        self.held
            .get(&session_id)
            .is_some_and(|held| !held.buttons.is_empty())
    }

    pub fn retry_status(&self, session_id: Uuid) -> Option<(u8, Duration)> {
        let retry = self.retries.get(&session_id)?;
        Some((
            retry.attempts,
            retry.due?.saturating_duration_since(Instant::now()),
        ))
    }

    pub fn cancel_reconnect(&mut self, session_id: Uuid) {
        crate::rdp_audio_input::stop_session(session_id);
        if let Some(retry) = self.retries.get_mut(&session_id) {
            retry.disabled = true;
            retry.due = None;
        }
        self.release_inputs(session_id);
        self.inputs.remove(&session_id);
        self.events.remove(&session_id);
    }

    fn schedule_retry(&mut self, session: &mut RemoteSession) {
        if !self
            .profiles
            .get(&session.id)
            .is_some_and(|profile| profile.options.auto_reconnect)
        {
            return;
        }
        let Some(retry) = self.retries.get_mut(&session.id) else {
            return;
        };
        if let Some(delay) = retry.schedule(Instant::now()) {
            session.status = SessionStatus::Reconnecting;
            self.event_backlog
                .entry(session.id)
                .or_default()
                .push(EngineEvent::Diagnostic {
                    session_id: session.id,
                    message: format!(
                        "Automatic reconnection {}/5 in {} seconds",
                        retry.attempts,
                        delay.as_secs()
                    ),
                });
        }
    }

    fn advance_retry(&mut self, session: &mut RemoteSession, now: Instant) {
        // Reset the budget only after a stable connection, so rapid connect/drop loops are bounded.
        if let Some(retry) = self.retries.get_mut(&session.id) {
            if retry
                .connected_since
                .is_some_and(|since| now.duration_since(since) >= Duration::from_secs(60))
            {
                retry.attempts = 0;
                retry.connected_since = None;
            }
        }
        let due = self.retries.get(&session.id).and_then(|retry| retry.due);
        if !due.is_some_and(|due| now >= due) {
            return;
        }
        // Closing the old input channel requests shutdown. Never overlap workers for a session.
        if self
            .workers
            .get(&session.id)
            .is_some_and(|worker| !worker.is_finished())
        {
            return;
        }
        if let Some(worker) = self.workers.remove(&session.id) {
            let _ = worker.join();
        }
        let Some(profile) = self.profiles.get(&session.id).cloned() else {
            return;
        };
        if let Some(retry) = self.retries.get_mut(&session.id) {
            retry.due = None;
        }
        let (event_sender, event_receiver) = mpsc::channel();
        let (input_sender, input_receiver) = mpsc::channel();
        self.workers.insert(
            session.id,
            spawn_runtime(session.id, profile, event_sender, input_receiver),
        );
        self.events.insert(session.id, event_receiver);
        self.inputs.insert(session.id, input_sender);
        self.requested_sizes.remove(&session.id);
        if self.clipboard_focus == Some(session.id) {
            self.clipboard_focus = None;
        }
        session.status = SessionStatus::Reconnecting;
    }

    fn apply_frame(&mut self, session: &mut RemoteSession, frame: FrameUpdate) {
        session.status = SessionStatus::Connected;
        session.frame_size = Some((frame.width, frame.height));
        self.latest_frames.insert(session.id, frame);
    }

    fn apply_event(&mut self, session: &mut RemoteSession, event: EngineEvent) {
        match event {
            EngineEvent::StatusChanged { status, .. } => {
                session.status = status;
                session.last_error = None;
                if status == SessionStatus::Connected {
                    if let Some(retry) = self.retries.get_mut(&session.id) {
                        retry.due = None;
                        retry.connected_since = Some(Instant::now());
                    }
                }
            }
            EngineEvent::Frame(frame) => self.apply_frame(session, frame),
            EngineEvent::Error { message, class, .. } => {
                crate::rdp_audio_input::stop_session(session.id);
                session.status = SessionStatus::Failed;
                session.last_error = Some(message);
                self.inputs.remove(&session.id);
                self.held.remove(&session.id);
                if matches!(
                    class,
                    DiagnosticClass::Dns
                        | DiagnosticClass::Tcp
                        | DiagnosticClass::Timeout
                        | DiagnosticClass::Unknown
                ) {
                    self.schedule_retry(session);
                }
            }
            EngineEvent::Diagnostic { .. } | EngineEvent::GatewayMessage { .. } => {}
            EngineEvent::Disconnected { reason, .. } => {
                crate::rdp_audio_input::stop_session(session.id);
                session.status = SessionStatus::Disconnected;
                session.last_error = Some(reason);
                self.inputs.remove(&session.id);
                self.held.remove(&session.id);
                self.schedule_retry(session);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(profile: &ConnectionProfile) -> RemoteSession {
        RemoteSession {
            id: Uuid::new_v4(),
            profile_id: profile.id,
            title: profile.name.clone(),
            status: SessionStatus::Connected,
            connected_at: Utc::now(),
            metrics: PerformanceMetrics::default(),
            last_error: None,
            frame_size: None,
        }
    }

    #[test]
    fn retry_backoff_is_bounded_and_cancellable() {
        let now = Instant::now();
        let mut state = RetryState::default();
        for seconds in [1, 2, 4, 8, 16] {
            assert_eq!(state.schedule(now), Some(Duration::from_secs(seconds)));
            assert_eq!(
                state.schedule(now),
                None,
                "do not duplicate a pending retry"
            );
            state.due = None;
        }
        assert_eq!(state.schedule(now), None);
        let mut cancelled = RetryState {
            disabled: true,
            ..Default::default()
        };
        assert_eq!(cancelled.schedule(now), None);
    }

    #[test]
    fn held_repeats_release_once_at_latest_drag_coordinates() {
        let mut held = HeldInput::default();
        held.record(&InputAction::Key {
            scan_code: 0x1d,
            pressed: true,
        });
        held.record(&InputAction::Key {
            scan_code: 0x1e,
            pressed: true,
        });
        held.record(&InputAction::Key {
            scan_code: 0x1e,
            pressed: true,
        });
        held.record(&InputAction::PointerButton {
            x: 2,
            y: 3,
            button: MouseButton::Left,
            pressed: true,
        });
        held.record(&InputAction::MovePointer { x: 70, y: 80 });
        assert_eq!(
            held.release(),
            vec![
                InputAction::Key {
                    scan_code: 0x1e,
                    pressed: false
                },
                InputAction::Key {
                    scan_code: 0x1d,
                    pressed: false
                },
                InputAction::PointerButton {
                    x: 70,
                    y: 80,
                    button: MouseButton::Left,
                    pressed: false
                },
            ]
        );
        assert!(held.release().is_empty());
    }

    #[test]
    fn session_switch_releases_only_previous_session() {
        let mut engine = NativeRdpEngine::default();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let (sender, receiver) = mpsc::channel();
        engine.inputs.insert(first, sender);
        let (sender, other_receiver) = mpsc::channel();
        engine.inputs.insert(second, sender);
        engine
            .send_input(
                first,
                InputAction::Key {
                    scan_code: 0x2a,
                    pressed: true,
                },
            )
            .unwrap();
        engine
            .send_input(
                second,
                InputAction::Key {
                    scan_code: 0x1d,
                    pressed: true,
                },
            )
            .unwrap();
        receiver.try_recv().unwrap();
        other_receiver.try_recv().unwrap();
        engine.release_inputs_except(Some(second));
        assert_eq!(
            receiver.try_recv().unwrap(),
            InputAction::Key {
                scan_code: 0x2a,
                pressed: false
            }
        );
        assert!(other_receiver.try_recv().is_err());
        assert!(engine.key_is_held(second, 0x1d));
    }

    #[test]
    fn clipboard_focus_is_exclusive_and_blur_revokes_it() {
        let mut engine = NativeRdpEngine::default();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let (sender, receiver) = mpsc::channel();
        engine.inputs.insert(first, sender);
        let (sender, other_receiver) = mpsc::channel();
        engine.inputs.insert(second, sender);
        engine.set_clipboard_focus(Some(first));
        assert_eq!(
            receiver.try_recv().unwrap(),
            InputAction::ClipboardFocus { active: true }
        );
        engine.set_clipboard_focus(Some(first));
        assert!(
            receiver.try_recv().is_err(),
            "do not repeatedly advertise unchanged focus"
        );
        engine.set_clipboard_focus(Some(second));
        assert_eq!(
            receiver.try_recv().unwrap(),
            InputAction::ClipboardFocus { active: false }
        );
        assert_eq!(
            other_receiver.try_recv().unwrap(),
            InputAction::ClipboardFocus { active: true }
        );
        engine.release_inputs_except(None);
        assert_eq!(
            other_receiver.try_recv().unwrap(),
            InputAction::ClipboardFocus { active: false }
        );
    }

    #[test]
    fn manual_disconnect_cancels_queued_retry() {
        let profile = ConnectionProfile::sample("test", "localhost", "test", false);
        let mut session = session(&profile);
        let mut engine = NativeRdpEngine::default();
        engine.profiles.insert(session.id, profile);
        engine.retries.insert(session.id, RetryState::default());
        engine.schedule_retry(&mut session);
        assert!(engine.retry_status(session.id).is_some());
        engine.disconnect(session.id).unwrap();
        engine.advance_retry(&mut session, Instant::now() + Duration::from_secs(100));
        assert!(engine.retry_status(session.id).is_none());
        assert!(engine.inputs.is_empty());
        assert!(engine.workers.is_empty());
    }

    #[test]
    fn security_error_does_not_retry_but_network_error_does() {
        let profile = ConnectionProfile::sample("test", "localhost", "test", false);
        let mut session = session(&profile);
        let mut engine = NativeRdpEngine::default();
        engine.profiles.insert(session.id, profile);
        engine.retries.insert(session.id, RetryState::default());
        for class in [
            DiagnosticClass::Auth,
            DiagnosticClass::Certificate,
            DiagnosticClass::CredSspNla,
            crate::diagnostics::classify_error(
                "connection finalize: CredSSP STATUS_LOGON_FAILURE [0xc000006d]",
            ),
        ] {
            let id = session.id;
            engine.apply_event(
                &mut session,
                EngineEvent::Error {
                    session_id: id,
                    class,
                    message: "failure".into(),
                },
            );
            assert!(engine.retry_status(id).is_none());
        }
        let id = session.id;
        engine.apply_event(
            &mut session,
            EngineEvent::Error {
                session_id: id,
                class: DiagnosticClass::Tcp,
                message: "network lost".into(),
            },
        );
        assert_eq!(session.status, SessionStatus::Reconnecting);
        assert_eq!(engine.retry_status(id).unwrap().0, 1);
    }

    #[test]
    fn retry_waits_for_existing_worker_to_finish() {
        let profile = ConnectionProfile::sample("test", "localhost", "test", false);
        let mut session = session(&profile);
        let mut engine = NativeRdpEngine::default();
        engine.profiles.insert(session.id, profile);
        engine.retries.insert(
            session.id,
            RetryState {
                due: Some(Instant::now()),
                ..Default::default()
            },
        );
        let (stop, stopped) = mpsc::channel::<()>();
        engine.workers.insert(
            session.id,
            thread::spawn(move || {
                let _ = stopped.recv();
            }),
        );
        engine.advance_retry(&mut session, Instant::now() + Duration::from_secs(1));
        assert!(engine.inputs.is_empty(), "must not create second worker");
        assert!(engine.retry_status(session.id).is_some());
        drop(stop);
        engine.workers.remove(&session.id).unwrap().join().unwrap();
    }
}
