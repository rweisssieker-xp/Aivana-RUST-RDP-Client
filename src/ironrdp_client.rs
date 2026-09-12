use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ironrdp::connector::{self, ConnectionResult, Credentials};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageOutput};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use serde::Serialize;
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
use tokio_rustls::rustls;

use crate::legacy_rdp::{LegacySecurityMode, detect_server_security};
use crate::models::ConnectionProfile;
use crate::models::{DirtyRegion, EngineEvent, FrameUpdate, InputAction, MouseButton};
use crate::security::{app_data_file, redact_secret_text};

pub const DEFAULT_RDP_SMOKE_TIMEOUT_SECS: u64 = 30;

type UpgradedFramed = ironrdp_blocking::Framed<RdpTransport>;

enum BaseTransport {
    Direct(TcpStream),
    Gateway(crate::rd_gateway::GatewayStream),
}
impl BaseTransport {
    fn connect(profile: &ConnectionProfile) -> Result<Self> {
        Self::connect_with_messages(profile, None)
    }
    fn connect_with_messages(
        profile: &ConnectionProfile,
        messages: Option<std::sync::mpsc::SyncSender<String>>,
    ) -> Result<Self> {
        if profile.options.gateway.enabled {
            // Only runtime sessions supply the service-message channel. Probes remain headless.
            let interactions = messages
                .as_ref()
                .and_then(|_| crate::rd_gateway::interaction_sender());
            let (mut stream, _) = crate::rd_gateway::GatewayStream::connect_interactive(
                profile,
                &profile.options.gateway,
                &profile.options.gateway.password,
                messages,
                interactions,
            )?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            Ok(Self::Gateway(stream))
        } else {
            let addr = lookup_addr(&profile.host, profile.port)?;
            let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            Ok(Self::Direct(stream))
        }
    }
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Direct(s) => s.local_addr(),
            Self::Gateway(s) => s.local_addr(),
        }
    }
    fn set_read_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Direct(s) => s.set_read_timeout(t),
            Self::Gateway(s) => s.set_read_timeout(t),
        }
    }
}
impl Read for BaseTransport {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(s) => s.read(b),
            Self::Gateway(s) => s.read(b),
        }
    }
}
impl Write for BaseTransport {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(s) => s.write(b),
            Self::Gateway(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Direct(s) => s.flush(),
            Self::Gateway(s) => s.flush(),
        }
    }
}

enum RdpTransport {
    Tls(rustls::StreamOwned<rustls::ClientConnection, BaseTransport>),
    Plain(BaseTransport),
}

impl Read for RdpTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(stream) => stream.read(buf),
            Self::Plain(stream) => stream.read(buf),
        }
    }
}

impl Write for RdpTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(stream) => stream.write(buf),
            Self::Plain(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tls(stream) => stream.flush(),
            Self::Plain(stream) => stream.flush(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RdpSecurityMode {
    NlaCredSsp,
    TlsGraphicalLogin,
    StandardRdp,
}

pub struct IronRdpRuntime {
    pub profile: ConnectionProfile,
    pub session_id: uuid::Uuid,
    pub events: Sender<EngineEvent>,
    pub input: Receiver<InputAction>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RdpSmokeTestReport {
    pub report_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub generated_at: DateTime<Utc>,
    pub host: String,
    pub port: u16,
    pub connected: bool,
    pub timeout_secs: u64,
    pub framebuffer: RdpSmokeFramebufferReport,
    pub input_probe: String,
    pub elapsed_millis: u128,
    pub last_diagnostic: String,
    pub evidence_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RdpSmokeTestFailureReport {
    pub report_id: uuid::Uuid,
    pub generated_at: DateTime<Utc>,
    pub connected: bool,
    pub timeout_secs: u64,
    pub error: String,
    pub expected_environment: Vec<&'static str>,
    pub evidence_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RdpEnvFileCheckReport {
    pub report_id: uuid::Uuid,
    pub generated_at: DateTime<Utc>,
    pub schema: &'static str,
    pub ok: bool,
    pub path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username_set: bool,
    pub password_set: bool,
    pub timeout_secs: u64,
    pub network_checked: bool,
    pub error: Option<String>,
    pub expected_environment: Vec<&'static str>,
    pub evidence_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RdpSmokeFramebufferReport {
    pub width: u16,
    pub height: u16,
    pub frame_hash: u64,
    pub dirty_regions: usize,
}

pub fn probe_server_fingerprint(profile: &ConnectionProfile) -> Result<String> {
    block_unsupported_legacy_standard(profile)?;
    let config = build_config(profile);
    probe_server_fingerprint_with_config(profile, config).or_else(|err| {
        if should_try_tls_fallback(&err) {
            probe_server_fingerprint_with_config(profile, build_tls_config(profile))
                .context("legacy TLS graphical-login fallback")
        } else {
            Err(err)
        }
    })
}

fn probe_server_fingerprint_with_config(
    profile: &ConnectionProfile,
    config: connector::Config,
) -> Result<String> {
    let server_name = profile.host.clone();
    let mut tcp_stream = BaseTransport::connect(profile)?;
    tcp_stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let client_addr = tcp_stream
        .local_addr()
        .context("get local socket address")?;
    let mut framed = ironrdp_blocking::Framed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(config, client_addr);

    let should_upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("connection begin")?;
    let initial_stream = framed.into_inner_no_leftover();
    let (_upgraded_stream, server_public_key) =
        tls_upgrade(initial_stream, server_name).context("TLS upgrade")?;
    let _ = should_upgrade;
    Ok(fingerprint_bytes(&server_public_key))
}

pub fn rdp_smoke_timeout_secs_from_args(args: &[String]) -> u64 {
    let env_file = rdp_env_file_values_from_args(args).ok().flatten();
    let env_value = env_file
        .as_ref()
        .and_then(|values| values.get("AIVANA_RDP_TEST_TIMEOUT_SECS").cloned())
        .or_else(|| std::env::var("AIVANA_RDP_TEST_TIMEOUT_SECS").ok());
    resolve_rdp_smoke_timeout_secs(
        args.iter().map(String::as_str),
        env_value.as_deref(),
        DEFAULT_RDP_SMOKE_TIMEOUT_SECS,
    )
}

pub fn rdp_env_file_path_from_args(args: &[String]) -> Option<PathBuf> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--rdp-env-file=") {
            if !value.trim().is_empty() {
                return Some(PathBuf::from(value.trim()));
            }
        } else if arg == "--rdp-env-file" {
            if let Some(value) = args.next().filter(|value| !value.trim().is_empty()) {
                return Some(PathBuf::from(value.trim()));
            }
        }
    }
    None
}

fn rdp_env_file_values_from_args(args: &[String]) -> Result<Option<HashMap<String, String>>> {
    let Some(path) = rdp_env_file_path_from_args(args) else {
        return Ok(None);
    };
    Ok(Some(parse_rdp_env_file(
        &std::fs::read_to_string(&path)
            .with_context(|| format!("read RDP env file {}", path.display()))?,
    )))
}

fn parse_rdp_env_file(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.starts_with("AIVANA_RDP_TEST_") {
            continue;
        }
        values.insert(key.to_owned(), unquote_env_value(value.trim()).to_owned());
    }
    values
}

fn unquote_env_value(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn resolve_rdp_smoke_timeout_secs<'a, I>(args: I, env_value: Option<&str>, default_secs: u64) -> u64
where
    I: IntoIterator<Item = &'a str>,
{
    let mut timeout = env_value
        .and_then(parse_rdp_smoke_timeout_secs)
        .unwrap_or(default_secs);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--rdp-smoke-timeout=") {
            if let Some(parsed) = parse_rdp_smoke_timeout_secs(value) {
                timeout = parsed;
            }
        } else if arg == "--rdp-smoke-timeout" {
            if let Some(value) = args.next().and_then(parse_rdp_smoke_timeout_secs) {
                timeout = value;
            }
        }
    }
    timeout
}

fn parse_rdp_smoke_timeout_secs(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| secs.clamp(5, 600))
}

pub fn run_session(runtime: IronRdpRuntime) {
    let session_id = runtime.session_id;
    let events = runtime.events.clone();
    let result = run_session_inner(runtime);
    if let Err(err) = result {
        let detail = format!("{err:#}");
        events
            .send(EngineEvent::Error {
                session_id,
                class: crate::diagnostics::classify_error(&detail),
                message: detail,
            })
            .ok();
    }
}

pub fn rdp_test_profile_from_args(args: &[String]) -> Result<ConnectionProfile> {
    let values = rdp_env_file_values_from_args(args)?;
    rdp_test_profile_from_values(values.as_ref())
}

pub fn rdp_env_file_check_report_from_args(
    args: &[String],
    timeout_secs: u64,
) -> RdpEnvFileCheckReport {
    let path = rdp_env_file_path_from_args(args).map(|path| path.display().to_string());
    match rdp_test_profile_from_args(args) {
        Ok(profile) => RdpEnvFileCheckReport {
            report_id: uuid::Uuid::new_v4(),
            generated_at: Utc::now(),
            schema: "aivana.rdp-env-file-check.v1",
            ok: true,
            path,
            host: Some(redact_secret_text(&profile.host)),
            port: Some(profile.port),
            username_set: !profile.username.trim().is_empty(),
            password_set: !profile.password.trim().is_empty() || profile.credential_id.is_some(),
            timeout_secs,
            network_checked: false,
            error: None,
            expected_environment: rdp_test_expected_environment(),
            evidence_path: None,
        },
        Err(error) => RdpEnvFileCheckReport {
            report_id: uuid::Uuid::new_v4(),
            generated_at: Utc::now(),
            schema: "aivana.rdp-env-file-check.v1",
            ok: false,
            path,
            host: None,
            port: None,
            username_set: false,
            password_set: false,
            timeout_secs,
            network_checked: false,
            error: Some(redact_secret_text(&error.to_string())),
            expected_environment: rdp_test_expected_environment(),
            evidence_path: None,
        },
    }
}

pub fn save_rdp_env_file_check_report(
    report: &RdpEnvFileCheckReport,
) -> Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-env-file-checks")?;
    std::fs::create_dir_all(&dir)?;
    let suffix = if report.ok { "ok" } else { "failed" };
    let path = dir.join(format!("{}-{suffix}.json", report.report_id));
    let json =
        serde_json::to_string_pretty(report).context("serialize RDP env file check report")?;
    std::fs::write(&path, json).context("write RDP env file check report")?;
    Ok(path)
}

fn rdp_test_profile_from_values(
    values: Option<&HashMap<String, String>>,
) -> Result<ConnectionProfile> {
    let host = rdp_test_value(values, "AIVANA_RDP_TEST_HOST")?;
    let username = rdp_test_value(values, "AIVANA_RDP_TEST_USER")?;
    let password = rdp_test_value(values, "AIVANA_RDP_TEST_PASSWORD")?;
    let domain = rdp_test_optional_value(values, "AIVANA_RDP_TEST_DOMAIN").unwrap_or_default();
    let port = rdp_test_optional_value(values, "AIVANA_RDP_TEST_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3389);

    let mut profile = ConnectionProfile::sample("manual-rdp-smoke", &host, "Manual", false);
    profile.port = port;
    profile.username = username;
    profile.password = password;
    profile.domain = domain;

    Ok(profile)
}

fn rdp_test_value(values: Option<&HashMap<String, String>>, key: &'static str) -> Result<String> {
    let Some(value) = rdp_test_optional_value(values, key).filter(|value| !value.trim().is_empty())
    else {
        anyhow::bail!("{key} is required");
    };
    if is_unfilled_rdp_test_placeholder(&value) {
        anyhow::bail!("{key} must be filled; placeholder value is not valid");
    }
    Ok(value)
}

fn rdp_test_optional_value(values: Option<&HashMap<String, String>>, key: &str) -> Option<String> {
    values
        .and_then(|values| values.get(key).cloned())
        .or_else(|| std::env::var(key).ok())
}

pub(crate) fn is_unfilled_rdp_test_placeholder(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower == "[redacted]"
        || lower == "redacted"
        || (trimmed.starts_with('<') && trimmed.ends_with('>'))
}

pub fn rdp_smoke_test(profile: ConnectionProfile, timeout_secs: u64) -> Result<RdpSmokeTestReport> {
    let (events, receiver) = std::sync::mpsc::channel();
    let (input, input_receiver) = std::sync::mpsc::channel();
    let session_id = uuid::Uuid::new_v4();
    let host = profile.host.clone();
    let port = profile.port;

    std::thread::spawn(move || {
        run_session(IronRdpRuntime {
            profile,
            session_id,
            events,
            input: input_receiver,
        });
    });

    let timeout = Duration::from_secs(timeout_secs.max(5));
    let started = Instant::now();
    let deadline = Instant::now() + timeout;
    let mut saw_connected = false;
    let mut frame_info = None;
    let mut last_diagnostic = String::new();

    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(EngineEvent::GatewayMessage { .. }) => {}
            Ok(EngineEvent::StatusChanged { status, .. }) => {
                saw_connected |= status == crate::models::SessionStatus::Connected;
            }
            Ok(EngineEvent::Diagnostic { message, .. }) => {
                last_diagnostic = message;
            }
            Ok(EngineEvent::Frame(frame)) => {
                let center_x = frame.width / 2;
                let center_y = frame.height / 2;
                let _ = input.send(InputAction::MovePointer {
                    x: center_x,
                    y: center_y,
                });
                frame_info = Some((
                    frame.width,
                    frame.height,
                    frame.frame_hash,
                    frame.dirty_regions.len(),
                ));
                break;
            }
            Ok(EngineEvent::Error { class, message, .. }) => {
                anyhow::bail!("session error {class:?}: {message}");
            }
            Ok(EngineEvent::Disconnected { reason, .. }) => {
                anyhow::bail!("session disconnected before framebuffer: {reason}");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("session event channel closed before framebuffer");
            }
        }
    }

    drop(input);
    let Some((width, height, frame_hash, dirty_regions)) = frame_info else {
        anyhow::bail!(
            "RDP smoke test timed out after {}s; connected={saw_connected}; last diagnostic={last_diagnostic}",
            timeout.as_secs()
        );
    };
    if !saw_connected {
        anyhow::bail!(
            "framebuffer arrived before connected status; last diagnostic={last_diagnostic}"
        );
    }

    Ok(RdpSmokeTestReport {
        report_id: uuid::Uuid::new_v4(),
        session_id,
        generated_at: Utc::now(),
        host: redact_secret_text(&host),
        port,
        connected: true,
        timeout_secs: timeout.as_secs(),
        framebuffer: RdpSmokeFramebufferReport {
            width,
            height,
            frame_hash,
            dirty_regions,
        },
        input_probe: "pointer_move_sent".to_owned(),
        elapsed_millis: started.elapsed().as_millis(),
        last_diagnostic: redact_secret_text(&last_diagnostic),
        evidence_path: None,
    })
}

pub fn save_rdp_smoke_report(report: &RdpSmokeTestReport) -> Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-smoke-tests")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.report_id));
    let json = serde_json::to_string_pretty(report).context("serialize RDP smoke report")?;
    std::fs::write(&path, json).context("write RDP smoke report")?;
    Ok(path)
}

pub fn rdp_smoke_failure_report(
    error: &anyhow::Error,
    timeout_secs: u64,
) -> RdpSmokeTestFailureReport {
    RdpSmokeTestFailureReport {
        report_id: uuid::Uuid::new_v4(),
        generated_at: Utc::now(),
        connected: false,
        timeout_secs,
        error: redact_secret_text(&format!("{error:#}")),
        expected_environment: rdp_test_expected_environment(),
        evidence_path: None,
    }
}

fn rdp_test_expected_environment() -> Vec<&'static str> {
    vec![
        "AIVANA_RDP_TEST_HOST",
        "AIVANA_RDP_TEST_USER",
        "AIVANA_RDP_TEST_PASSWORD",
        "AIVANA_RDP_TEST_PORT (optional)",
        "AIVANA_RDP_TEST_DOMAIN (optional)",
        "AIVANA_RDP_TEST_TIMEOUT_SECS (optional, 5-600)",
    ]
}

pub fn save_rdp_smoke_failure_report(
    report: &RdpSmokeTestFailureReport,
) -> Result<std::path::PathBuf> {
    let dir = app_data_file("rdp-smoke-tests")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}-failed.json", report.report_id));
    let json =
        serde_json::to_string_pretty(report).context("serialize RDP smoke failure report")?;
    std::fs::write(&path, json).context("write RDP smoke failure report")?;
    Ok(path)
}

fn run_session_inner(runtime: IronRdpRuntime) -> Result<()> {
    let gateway_messages = if runtime.profile.options.gateway.enabled {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(8);
        let events = runtime.events.clone();
        let session_id = runtime.session_id;
        std::thread::spawn(move || {
            while let Ok(message) = rx.recv() {
                if events
                    .send(EngineEvent::GatewayMessage {
                        session_id,
                        message,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Some(tx)
    } else {
        None
    };
    let mut channels = crate::rdp_channels::Channels::new(
        &runtime.profile,
        runtime.events.clone(),
        runtime.session_id,
    )?;
    let detection = if runtime.profile.options.gateway.enabled {
        None
    } else {
        detect_server_security(&runtime.profile).ok()
    };
    let (connection_result, mut framed) = if detection
        .as_ref()
        .is_some_and(|detection| detection.mode == LegacySecurityMode::StandardRdp)
    {
        connect_standard_with_channels(&runtime.profile, Some(&mut channels))
            .context("legacy Standard RDP Security connect")?
    } else {
        let config = build_config(&runtime.profile);
        connect(
            config,
            &runtime.profile,
            Some(&mut channels),
            gateway_messages.clone(),
        )
        .or_else(|err| {
            if should_try_tls_fallback(&err) {
                connect(
                    build_tls_config(&runtime.profile),
                    &runtime.profile,
                    Some(&mut channels),
                    gateway_messages.clone(),
                )
                .context("legacy TLS graphical-login fallback")
            } else {
                Err(err)
            }
        })?
    };

    match framed.get_inner_mut().0 {
        RdpTransport::Tls(stream) => stream
            .sock
            .set_read_timeout(Some(Duration::from_millis(20)))?,
        RdpTransport::Plain(stream) => stream.set_read_timeout(Some(Duration::from_millis(20)))?,
    }
    let mut image = DecodedImage::new(
        ironrdp_graphics::image_processing::PixelFormat::RgbA32,
        connection_result.desktop_size.width,
        connection_result.desktop_size.height,
    );
    let desktop_width = connection_result.desktop_size.width;
    let desktop_height = connection_result.desktop_size.height;
    let mut active_stage = ActiveStage::new(connection_result);
    let mut stats = RdpLoopStats::default();
    let mut last_stats_event = Instant::now();

    runtime
        .events
        .send(EngineEvent::StatusChanged {
            session_id: runtime.session_id,
            status: crate::models::SessionStatus::Connected,
        })
        .ok();
    runtime
        .events
        .send(EngineEvent::Diagnostic {
            session_id: runtime.session_id,
            message: format!(
                "ActiveStage ready, negotiated desktop {desktop_width}x{desktop_height}"
            ),
        })
        .ok();

    loop {
        if !drain_input(
            &runtime.input,
            &mut active_stage,
            &mut image,
            &mut framed,
            &mut channels,
        )? {
            runtime
                .events
                .send(EngineEvent::Disconnected {
                    session_id: runtime.session_id,
                    reason: "Input channel closed by Relayne".to_owned(),
                })
                .ok();
            break;
        }

        for frame in channels.pump(&mut active_stage)? {
            framed.write_all(&frame)?;
        }
        match framed.read_pdu() {
            Ok((action, payload)) => {
                stats.pdus += 1;
                stats.last_payload_len = payload.len();
                match action {
                    ironrdp_pdu::Action::FastPath => stats.fast_path_pdus += 1,
                    ironrdp_pdu::Action::X224 => stats.x224_pdus += 1,
                }
                let outputs = active_stage.process(&mut image, action, &payload)?;
                let mut regular_outputs = Vec::new();
                for output in outputs {
                    if let ActiveStageOutput::DeactivateAll(mut activation) = output {
                        use ironrdp::connector::Sequence;
                        set_session_timeout(&mut framed, Duration::from_secs(10))?;
                        let mut buffer = ironrdp::core::WriteBuf::new();
                        while !activation.state().is_terminal() {
                            buffer.clear();
                            let written = if let Some(hint) = activation.next_pdu_hint() {
                                let bytes = framed.read_by_hint(hint)?;
                                activation.step(&bytes, &mut buffer)?
                            } else {
                                activation.step_no_input(&mut buffer)?
                            };
                            if let Some(size) = written.size() {
                                framed.write_all(&buffer[..size])?;
                            }
                        }
                        set_session_timeout(&mut framed, Duration::from_millis(20))?;
                        if let ironrdp::connector::connection_activation::ConnectionActivationState::Finalized { desktop_size, io_channel_id, user_channel_id, enable_server_pointer, pointer_software_rendering } = activation.connection_activation_state() {
                            image = DecodedImage::new(ironrdp_graphics::image_processing::PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            active_stage.set_fastpath_processor(ironrdp::session::fast_path::ProcessorBuilder {io_channel_id, user_channel_id, enable_server_pointer, pointer_software_rendering}.build());
                            active_stage.set_enable_server_pointer(enable_server_pointer);
                        }
                    } else {
                        regular_outputs.push(output);
                    }
                }
                let outputs = regular_outputs;
                let output_stats = process_outputs(
                    runtime.session_id,
                    outputs,
                    &mut framed,
                    &image,
                    &runtime.events,
                )?;
                stats.response_frames += output_stats.response_frames;
                stats.graphics_updates += output_stats.graphics_updates;
                stats.terminations += output_stats.terminations;
                stats.other_outputs += output_stats.other_outputs;
                if output_stats.terminations > 0 {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => {
                runtime
                    .events
                    .send(EngineEvent::Error {
                        session_id: runtime.session_id,
                        class: crate::diagnostics::classify_error(&e.to_string()),
                        message: e.to_string(),
                    })
                    .ok();
                break;
            }
        }

        if stats.pdus <= 5
            || stats.graphics_updates == 0 && last_stats_event.elapsed() >= Duration::from_secs(3)
            || last_stats_event.elapsed() >= Duration::from_secs(10)
        {
            runtime
                .events
                .send(EngineEvent::Diagnostic {
                    session_id: runtime.session_id,
                    message: stats.describe(),
                })
                .ok();
            last_stats_event = Instant::now();
        }
    }

    Ok(())
}

fn block_unsupported_legacy_standard(profile: &ConnectionProfile) -> Result<()> {
    if profile.options.gateway.enabled {
        return Ok(());
    }
    if let Ok(detection) = detect_server_security(profile) {
        if detection.mode == LegacySecurityMode::StandardRdp {
            anyhow::bail!(
                "standard rdp security detected on {}:{}: {}. Native RC4 security exchange is not implemented yet.",
                profile.host,
                profile.port,
                detection.detail
            );
        }
    }
    Ok(())
}

fn build_config(profile: &ConnectionProfile) -> connector::Config {
    build_config_for_security(profile, RdpSecurityMode::NlaCredSsp)
}

fn build_tls_config(profile: &ConnectionProfile) -> connector::Config {
    build_config_for_security(profile, RdpSecurityMode::TlsGraphicalLogin)
}

fn build_config_for_security(
    profile: &ConnectionProfile,
    security_mode: RdpSecurityMode,
) -> connector::Config {
    let (enable_tls, enable_credssp) = match security_mode {
        RdpSecurityMode::NlaCredSsp => (false, true),
        RdpSecurityMode::TlsGraphicalLogin => (true, false),
        RdpSecurityMode::StandardRdp => (false, false),
    };

    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: profile.username.clone(),
            password: profile.password.clone(),
        },
        domain: if profile.domain.trim().is_empty() {
            None
        } else {
            Some(profile.domain.clone())
        },
        enable_tls,
        enable_credssp,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: local_keyboard_layout(),
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: profile.options.width.clamp(200, 8192) & !1,
            height: profile.options.height.clamp(200, 8192),
        },
        bitmap: None,
        client_build: 0,
        client_name: "aivana-rust-rdp-client".to_owned(),
        client_dir: "native-rust".to_owned(),

        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(target_os = "ios")]
        platform: MajorPlatformType::IOS,
        #[cfg(target_os = "linux")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "android")]
        platform: MajorPlatformType::ANDROID,
        #[cfg(target_os = "freebsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "dragonfly")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "openbsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "netbsd")]
        platform: MajorPlatformType::UNIX,

        enable_server_pointer: false,
        request_data: None,
        autologon: false,
        enable_audio_playback: profile.options.audio_playback,
        pointer_software_rendering: true,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
    }
}

fn connect(
    config: connector::Config,
    profile: &ConnectionProfile,
    channels: Option<&mut crate::rdp_channels::Channels>,
    gateway_messages: Option<std::sync::mpsc::SyncSender<String>>,
) -> Result<(ConnectionResult, UpgradedFramed)> {
    let server_name = profile.host.clone();
    let mut tcp_stream = BaseTransport::connect_with_messages(profile, gateway_messages)?;
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("set read timeout")?;

    let client_addr = tcp_stream
        .local_addr()
        .context("get local socket address")?;
    let mut framed = ironrdp_blocking::Framed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(config, client_addr);

    if let Some(channels) = channels {
        channels.attach(&mut connector)?;
    }
    let should_upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("connection begin")?;

    let initial_stream = framed.into_inner_no_leftover();
    let (upgraded_stream, server_public_key) =
        tls_upgrade(initial_stream, server_name.clone()).context("TLS upgrade")?;

    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = ironrdp_blocking::Framed::new(RdpTransport::Tls(upgraded_stream));
    let mut network_client = ReqwestNetworkClient;

    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        server_name.into(),
        server_public_key,
        None,
    )
    .context("connection finalize")?;

    Ok((connection_result, upgraded_framed))
}

fn connect_standard(profile: &ConnectionProfile) -> Result<(ConnectionResult, UpgradedFramed)> {
    connect_standard_with_channels(profile, None)
}

fn connect_standard_with_channels(
    profile: &ConnectionProfile,
    channels: Option<&mut crate::rdp_channels::Channels>,
) -> Result<(ConnectionResult, UpgradedFramed)> {
    let mut tcp_stream = BaseTransport::connect(profile)?;
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("set read timeout")?;

    let client_addr = tcp_stream
        .local_addr()
        .context("get local socket address")?;
    let mut framed = ironrdp_blocking::Framed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(
        build_config_for_security(profile, RdpSecurityMode::StandardRdp),
        client_addr,
    );

    if let Some(channels) = channels {
        channels.attach(&mut connector)?;
    }
    let should_upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("connection begin")?;
    let plain_stream = framed.into_inner_no_leftover();
    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = ironrdp_blocking::Framed::new(RdpTransport::Plain(plain_stream));
    let mut network_client = ReqwestNetworkClient;

    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        profile.host.clone().into(),
        Vec::new(),
        None,
    )
    .context("connection finalize")?;

    Ok((connection_result, upgraded_framed))
}

fn drain_input(
    input: &Receiver<InputAction>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    framed: &mut UpgradedFramed,
    channels: &mut crate::rdp_channels::Channels,
) -> Result<bool> {
    loop {
        match input.try_recv() {
            Ok(action) => {
                match channels.action(&action, active_stage) {
                    Ok(Some(frame)) => {
                        if !frame.is_empty() {
                            framed.write_all(&frame)?;
                        }
                        continue;
                    }
                    Err(error) => {
                        channels.report_error(&error);
                        continue;
                    }
                    Ok(None) => {}
                }
                let events = input_action_to_fastpath(action);
                if events.is_empty() {
                    continue;
                }

                let outputs = active_stage.process_fastpath_input(image, &events)?;
                for output in outputs {
                    if let ActiveStageOutput::ResponseFrame(frame) = output {
                        framed.write_all(&frame).context("write input frame")?;
                    }
                }
            }
            Err(TryRecvError::Empty) => return Ok(true),
            Err(TryRecvError::Disconnected) => return Ok(false),
        }
    }
}

fn process_outputs(
    session_id: uuid::Uuid,
    outputs: Vec<ActiveStageOutput>,
    framed: &mut UpgradedFramed,
    image: &DecodedImage,
    events: &Sender<EngineEvent>,
) -> Result<OutputStats> {
    let mut stats = OutputStats::default();
    for output in outputs {
        match output {
            ActiveStageOutput::ResponseFrame(frame) => {
                stats.response_frames += 1;
                framed.write_all(&frame).context("write response")?
            }
            ActiveStageOutput::GraphicsUpdate(region) => {
                stats.graphics_updates += 1;
                events
                    .send(EngineEvent::Frame(FrameUpdate {
                        session_id,
                        width: image.width(),
                        height: image.height(),
                        pixels_rgba: image.data().to_vec(),
                        dirty_regions: vec![DirtyRegion {
                            left: region.left,
                            top: region.top,
                            right: region.right,
                            bottom: region.bottom,
                        }],
                        frame_hash: frame_hash(image.data()),
                        captured_at: chrono::Utc::now(),
                    }))
                    .ok();
            }
            ActiveStageOutput::Terminate(reason) => {
                stats.terminations += 1;
                events
                    .send(EngineEvent::Disconnected {
                        session_id,
                        reason: reason.description(),
                    })
                    .ok();
            }
            _ => stats.other_outputs += 1,
        }
    }

    Ok(stats)
}

#[derive(Default)]
struct RdpLoopStats {
    pdus: u64,
    fast_path_pdus: u64,
    x224_pdus: u64,
    response_frames: u64,
    graphics_updates: u64,
    terminations: u64,
    other_outputs: u64,
    last_payload_len: usize,
}

impl RdpLoopStats {
    fn describe(&self) -> String {
        format!(
            "pdus={} fast_path={} x224={} responses={} graphics_updates={} other_outputs={} terminations={} last_payload={} bytes",
            self.pdus,
            self.fast_path_pdus,
            self.x224_pdus,
            self.response_frames,
            self.graphics_updates,
            self.other_outputs,
            self.terminations,
            self.last_payload_len
        )
    }
}

#[derive(Default)]
struct OutputStats {
    response_frames: u64,
    graphics_updates: u64,
    terminations: u64,
    other_outputs: u64,
}

fn input_action_to_fastpath(
    action: InputAction,
) -> Vec<ironrdp_pdu::input::fast_path::FastPathInputEvent> {
    use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
    use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};

    match action {
        InputAction::Key { scan_code, pressed } => {
            let mut flags = if scan_code & 0x100 != 0 {
                KeyboardFlags::EXTENDED
            } else {
                KeyboardFlags::empty()
            };
            if !pressed {
                flags |= KeyboardFlags::RELEASE;
            }
            vec![FastPathInputEvent::KeyboardEvent(flags, scan_code as u8)]
        }
        InputAction::PointerButton {
            x,
            y,
            button,
            pressed,
        } => {
            let mut flags = match button {
                MouseButton::Left => PointerFlags::LEFT_BUTTON,
                MouseButton::Right => PointerFlags::RIGHT_BUTTON,
                MouseButton::Middle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
            };
            if pressed {
                flags |= PointerFlags::DOWN;
            }
            vec![FastPathInputEvent::MouseEvent(MousePdu {
                flags,
                number_of_wheel_rotation_units: 0,
                x_position: x,
                y_position: y,
            })]
        }
        InputAction::ClipboardFocus { .. }
        | InputAction::Resize { .. }
        | InputAction::ClipboardFiles { .. }
        | InputAction::ClipboardDownload { .. } => vec![],
        InputAction::MovePointer { x, y } => vec![FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::MOVE,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        })],
        InputAction::Click { x, y, button } => {
            let button_flag = match button {
                MouseButton::Left => PointerFlags::LEFT_BUTTON,
                MouseButton::Right => PointerFlags::RIGHT_BUTTON,
                MouseButton::Middle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
            };
            vec![
                FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::DOWN | button_flag,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                }),
                FastPathInputEvent::MouseEvent(MousePdu {
                    flags: button_flag,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                }),
            ]
        }
        InputAction::DoubleClick { x, y, button } => {
            let mut first = input_action_to_fastpath(InputAction::Click { x, y, button });
            first.extend(input_action_to_fastpath(InputAction::Click {
                x,
                y,
                button,
            }));
            first
        }
        InputAction::Scroll { x, y, delta } => vec![FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::VERTICAL_WHEEL
                | if delta < 0 {
                    PointerFlags::WHEEL_NEGATIVE
                } else {
                    PointerFlags::empty()
                },
            number_of_wheel_rotation_units: delta,
            x_position: x,
            y_position: y,
        })],
        InputAction::TypeText { text } => text
            .encode_utf16()
            .flat_map(|code| {
                [
                    FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), code),
                    FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, code),
                ]
            })
            .collect(),
        InputAction::Hotkey { keys } => {
            let mut pressed = Vec::new();
            let mut events = Vec::new();
            for key in keys {
                if let Some((scan_code, extended)) = key_to_scancode(&key) {
                    let flags = if extended {
                        KeyboardFlags::EXTENDED
                    } else {
                        KeyboardFlags::empty()
                    };
                    events.push(FastPathInputEvent::KeyboardEvent(flags, scan_code));
                    pressed.push((scan_code, flags));
                }
            }
            for (scan_code, flags) in pressed.into_iter().rev() {
                events.push(FastPathInputEvent::KeyboardEvent(
                    flags | KeyboardFlags::RELEASE,
                    scan_code,
                ));
            }
            events
        }
        InputAction::Wait { .. } | InputAction::Screenshot | InputAction::Verify { .. } => {
            Vec::new()
        }
    }
}

fn key_to_scancode(key: &str) -> Option<(u8, bool)> {
    match key.to_ascii_lowercase().as_str() {
        "a" => Some((0x1e, false)),
        "b" => Some((0x30, false)),
        "c" => Some((0x2e, false)),
        "d" => Some((0x20, false)),
        "e" => Some((0x12, false)),
        "f" => Some((0x21, false)),
        "g" => Some((0x22, false)),
        "h" => Some((0x23, false)),
        "i" => Some((0x17, false)),
        "j" => Some((0x24, false)),
        "k" => Some((0x25, false)),
        "l" => Some((0x26, false)),
        "m" => Some((0x32, false)),
        "n" => Some((0x31, false)),
        "o" => Some((0x18, false)),
        "p" => Some((0x19, false)),
        "q" => Some((0x10, false)),
        "r" => Some((0x13, false)),
        "s" => Some((0x1f, false)),
        "t" => Some((0x14, false)),
        "u" => Some((0x16, false)),
        "v" => Some((0x2f, false)),
        "w" => Some((0x11, false)),
        "x" => Some((0x2d, false)),
        "y" => Some((0x15, false)),
        "z" => Some((0x2c, false)),
        "enter" => Some((0x1c, false)),
        "tab" => Some((0x0f, false)),
        "esc" | "escape" => Some((0x01, false)),
        "space" => Some((0x39, false)),
        "ctrl" | "control" => Some((0x1d, false)),
        "alt" => Some((0x38, false)),
        "shift" => Some((0x2a, false)),
        "win" | "meta" | "windows" => Some((0x5b, true)),
        "del" | "delete" => Some((0x53, true)),
        "home" => Some((0x47, true)),
        "end" => Some((0x4f, true)),
        "pageup" => Some((0x49, true)),
        "pagedown" => Some((0x51, true)),
        "left" => Some((0x4b, true)),
        "right" => Some((0x4d, true)),
        "up" => Some((0x48, true)),
        "down" => Some((0x50, true)),
        _ => None,
    }
}

fn frame_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes.iter().step_by(257) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn fingerprint_bytes(bytes: &[u8]) -> String {
    let hash = frame_hash(bytes);
    format!("rdp-server-key-{hash:016x}")
}

fn should_try_tls_fallback(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}").to_lowercase();
    message.contains("negotiation failure")
        && !message.contains("standard rdp security")
        && !message.contains("auth")
        && !message.contains("password")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ConnectionProfile;

    #[test]
    #[ignore = "requires AIVANA_RDP_TEST_HOST and a reachable RDP endpoint"]
    fn manual_probe_server_fingerprint_or_security_mode() {
        let host = std::env::var("AIVANA_RDP_TEST_HOST").expect("AIVANA_RDP_TEST_HOST");
        let port = std::env::var("AIVANA_RDP_TEST_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(3389);
        let mut profile = ConnectionProfile::sample("manual-rdp-probe", &host, "Manual", false);
        profile.port = port;
        match probe_server_fingerprint(&profile) {
            Ok(fingerprint) => assert!(
                fingerprint.starts_with("rdp-server-key-"),
                "unexpected fingerprint format: {fingerprint}"
            ),
            Err(err) => {
                let message = format!("{err:#}").to_lowercase();
                assert!(
                    message.contains("standard rdp security"),
                    "unexpected RDP probe error: {err:#}"
                );
            }
        }
    }

    #[test]
    fn standard_rdp_detection_error_is_not_tls_fallback_candidate() {
        let err =
            anyhow::anyhow!("standard rdp security detected on legacy:3389: Standard RDP Security");

        assert!(!should_try_tls_fallback(&err));
    }

    #[test]
    fn runtime_failure_sends_error_event() {
        let (events, receiver) = std::sync::mpsc::channel();
        let (_input, input_receiver) = std::sync::mpsc::channel();
        let mut profile =
            ConnectionProfile::sample("invalid-rdp-host", "203.0.113.10", "Manual", false);
        profile.port = 9;
        let session_id = uuid::Uuid::new_v4();

        run_session(IronRdpRuntime {
            profile,
            session_id,
            events,
            input: input_receiver,
        });

        let event = receiver.try_recv().expect("runtime error event");
        assert!(matches!(event, EngineEvent::Error { .. }));
    }

    #[test]
    fn smoke_report_serializes_as_structured_json() {
        let report = RdpSmokeTestReport {
            report_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            generated_at: Utc::now(),
            host: "server.internal".to_owned(),
            port: 3389,
            connected: true,
            timeout_secs: 45,
            framebuffer: RdpSmokeFramebufferReport {
                width: 1280,
                height: 800,
                frame_hash: 42,
                dirty_regions: 1,
            },
            input_probe: "pointer_move_sent".to_owned(),
            elapsed_millis: 1500,
            last_diagnostic: "password=[REDACTED]".to_owned(),
            evidence_path: Some("C:\\tmp\\smoke.json".to_owned()),
        };

        let json = serde_json::to_string(&report).expect("serialized smoke report");

        assert!(json.contains("\"connected\":true"));
        assert!(json.contains("\"timeout_secs\":45"));
        assert!(json.contains("\"framebuffer\""));
        assert!(json.contains("\"input_probe\":\"pointer_move_sent\""));
        assert!(json.contains("\"evidence_path\""));
        assert!(json.contains("password=[REDACTED]"));
    }

    #[test]
    fn smoke_failure_report_redacts_and_lists_required_env() {
        let err = anyhow::anyhow!("connect failed password=hunter2");
        let report = rdp_smoke_failure_report(&err, 60);

        let json = serde_json::to_string(&report).expect("serialized smoke failure");

        assert!(json.contains("\"connected\":false"));
        assert!(json.contains("\"timeout_secs\":60"));
        assert!(json.contains("AIVANA_RDP_TEST_HOST"));
        assert!(json.contains("AIVANA_RDP_TEST_TIMEOUT_SECS"));
        assert!(json.contains("password=[REDACTED]"));
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn smoke_timeout_prefers_cli_and_clamps_bounds() {
        assert_eq!(
            resolve_rdp_smoke_timeout_secs(["app", "--rdp-smoke-test"], Some("90"), 30),
            90
        );
        assert_eq!(
            resolve_rdp_smoke_timeout_secs(
                ["app", "--rdp-smoke-test", "--rdp-smoke-timeout", "120"],
                Some("90"),
                30
            ),
            120
        );
        assert_eq!(
            resolve_rdp_smoke_timeout_secs(["app", "--rdp-smoke-timeout=1"], None, 30),
            5
        );
        assert_eq!(
            resolve_rdp_smoke_timeout_secs(["app", "--rdp-smoke-timeout=999"], None, 30),
            600
        );
    }

    #[test]
    fn rdp_env_file_parser_accepts_aivana_keys_and_quotes() {
        let values = parse_rdp_env_file(
            r#"
# comment
AIVANA_RDP_TEST_HOST="rdp.example.local"
AIVANA_RDP_TEST_USER='operator'
AIVANA_RDP_TEST_PASSWORD=secret
AIVANA_RDP_TEST_PORT=3390
IGNORED=value
"#,
        );

        assert_eq!(
            values.get("AIVANA_RDP_TEST_HOST").map(String::as_str),
            Some("rdp.example.local")
        );
        assert_eq!(
            values.get("AIVANA_RDP_TEST_USER").map(String::as_str),
            Some("operator")
        );
        assert_eq!(
            values.get("AIVANA_RDP_TEST_PASSWORD").map(String::as_str),
            Some("secret")
        );
        assert_eq!(
            values.get("AIVANA_RDP_TEST_PORT").map(String::as_str),
            Some("3390")
        );
        assert!(!values.contains_key("IGNORED"));
    }

    #[test]
    fn rdp_env_file_path_accepts_split_and_equals_forms() {
        let split = vec![
            "app".to_owned(),
            "--rdp-env-file".to_owned(),
            "C:\\tmp\\rdp.env".to_owned(),
        ];
        let equals = vec![
            "app".to_owned(),
            "--rdp-env-file=C:\\tmp\\rdp.env".to_owned(),
        ];

        assert_eq!(
            rdp_env_file_path_from_args(&split)
                .as_deref()
                .and_then(|path| path.to_str()),
            Some("C:\\tmp\\rdp.env")
        );
        assert_eq!(
            rdp_env_file_path_from_args(&equals)
                .as_deref()
                .and_then(|path| path.to_str()),
            Some("C:\\tmp\\rdp.env")
        );
    }

    #[test]
    fn rdp_test_profile_rejects_unfilled_template_placeholders() {
        assert!(is_unfilled_rdp_test_placeholder("[REDACTED]"));
        assert!(is_unfilled_rdp_test_placeholder("<password>"));

        let values = parse_rdp_env_file(
            r#"
AIVANA_RDP_TEST_HOST=<host>
AIVANA_RDP_TEST_USER=operator
AIVANA_RDP_TEST_PASSWORD=[REDACTED]
AIVANA_RDP_TEST_PORT=3389
"#,
        );

        let error = rdp_test_profile_from_values(Some(&values))
            .expect_err("template placeholders should not create a test profile")
            .to_string();

        assert!(error.contains("AIVANA_RDP_TEST_HOST"));
        assert!(error.contains("placeholder value is not valid"));
    }

    #[test]
    fn rdp_test_profile_accepts_filled_env_file_values() {
        let values = parse_rdp_env_file(
            r#"
AIVANA_RDP_TEST_HOST=rdp.example.local
AIVANA_RDP_TEST_USER=operator
AIVANA_RDP_TEST_PASSWORD=secret
AIVANA_RDP_TEST_PORT=3390
"#,
        );

        let profile =
            rdp_test_profile_from_values(Some(&values)).expect("filled env file creates profile");

        assert_eq!(profile.host, "rdp.example.local");
        assert_eq!(profile.username, "operator");
        assert_eq!(profile.password, "secret");
        assert_eq!(profile.port, 3390);
    }

    #[test]
    fn rdp_env_file_check_report_persists_json_evidence() {
        let report = RdpEnvFileCheckReport {
            report_id: uuid::Uuid::new_v4(),
            generated_at: Utc::now(),
            schema: "aivana.rdp-env-file-check.v1",
            ok: false,
            path: Some("C:\\tmp\\rdp-live.env".to_owned()),
            host: None,
            port: None,
            username_set: false,
            password_set: false,
            timeout_secs: 90,
            network_checked: false,
            error: Some("AIVANA_RDP_TEST_PASSWORD must be filled".to_owned()),
            expected_environment: rdp_test_expected_environment(),
            evidence_path: None,
        };

        let path = save_rdp_env_file_check_report(&report).expect("saved env file check report");
        let json = std::fs::read_to_string(&path).expect("read env file check report");
        let _ = std::fs::remove_file(&path);

        assert!(json.contains("aivana.rdp-env-file-check.v1"));
        assert!(json.contains("network_checked"));
        assert!(json.contains("AIVANA_RDP_TEST_PASSWORD"));
    }

    #[test]
    #[ignore = "requires AIVANA_RDP_TEST_HOST pointing at a Standard RDP Security endpoint"]
    fn manual_standard_rdp_connect_reaches_connector() {
        let host = std::env::var("AIVANA_RDP_TEST_HOST").expect("AIVANA_RDP_TEST_HOST");
        let port = std::env::var("AIVANA_RDP_TEST_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(3389);
        let mut profile = ConnectionProfile::sample("manual-standard-rdp", &host, "Manual", false);
        profile.port = port;

        let result = connect_standard(&profile);
        match &result {
            Ok((connection, _)) => println!(
                "manual standard RDP connect reached desktop {}x{}",
                connection.desktop_size.width, connection.desktop_size.height
            ),
            Err(err) => println!("manual standard RDP connect error: {err:#}"),
        }
        if let Err(err) = &result {
            let message = format!("{err:#}").to_lowercase();
            assert!(
                !message.contains("standard rdp security is not supported")
                    && !message.contains("server only supports standard rdp security"),
                "legacy connector still blocks Standard RDP Security: {err:#}"
            );
        }
    }

    #[test]
    #[ignore = "requires AIVANA_RDP_TEST_HOST, AIVANA_RDP_TEST_USER and AIVANA_RDP_TEST_PASSWORD"]
    fn manual_rdp_session_receives_framebuffer() {
        let host = std::env::var("AIVANA_RDP_TEST_HOST").expect("AIVANA_RDP_TEST_HOST");
        let username = std::env::var("AIVANA_RDP_TEST_USER").expect("AIVANA_RDP_TEST_USER");
        let password = std::env::var("AIVANA_RDP_TEST_PASSWORD").expect("AIVANA_RDP_TEST_PASSWORD");
        let domain = std::env::var("AIVANA_RDP_TEST_DOMAIN").unwrap_or_default();
        let port = std::env::var("AIVANA_RDP_TEST_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(3389);

        let (events, receiver) = std::sync::mpsc::channel();
        let (input, input_receiver) = std::sync::mpsc::channel();
        let mut profile = ConnectionProfile::sample("manual-rdp-session", &host, "Manual", false);
        profile.port = port;
        profile.username = username;
        profile.password = password;
        profile.domain = domain;
        let session_id = uuid::Uuid::new_v4();

        std::thread::spawn(move || {
            run_session(IronRdpRuntime {
                profile,
                session_id,
                events,
                input: input_receiver,
            });
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut saw_connected = false;
        let mut saw_frame = false;
        let mut last_diagnostic = String::new();

        while std::time::Instant::now() < deadline {
            match receiver.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(EngineEvent::GatewayMessage { .. }) => {}
                Ok(EngineEvent::StatusChanged { status, .. }) => {
                    println!("session status: {}", status.label());
                    saw_connected |= status == crate::models::SessionStatus::Connected;
                }
                Ok(EngineEvent::Diagnostic { message, .. }) => {
                    println!("session diagnostic: {message}");
                    last_diagnostic = message;
                }
                Ok(EngineEvent::Frame(frame)) => {
                    println!(
                        "session framebuffer: {}x{} hash={} dirty_regions={}",
                        frame.width,
                        frame.height,
                        frame.frame_hash,
                        frame.dirty_regions.len()
                    );
                    saw_frame = true;
                    break;
                }
                Ok(EngineEvent::Error { class, message, .. }) => {
                    panic!("session error {class:?}: {message}");
                }
                Ok(EngineEvent::Disconnected { reason, .. }) => {
                    panic!("session disconnected before framebuffer: {reason}");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("session event channel closed before framebuffer");
                }
            }
        }

        drop(input);
        assert!(saw_connected, "session never reached Connected");
        assert!(
            saw_frame,
            "session reached Connected but no framebuffer arrived; last diagnostic: {last_diagnostic}"
        );
    }
}

fn lookup_addr(hostname: &str, port: u16) -> Result<std::net::SocketAddr> {
    (hostname, port)
        .to_socket_addrs()?
        .next()
        .context("socket address not found")
}

fn tls_upgrade(
    stream: BaseTransport,
    server_name: String,
) -> Result<(
    rustls::StreamOwned<rustls::ClientConnection, BaseTransport>,
    Vec<u8>,
)> {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();

    config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    config.resumption = rustls::client::Resumption::disabled();

    let config = std::sync::Arc::new(config);
    let server_name = server_name.try_into()?;
    let client = rustls::ClientConnection::new(config, server_name)?;
    let mut tls_stream = rustls::StreamOwned::new(client, stream);

    tls_stream.flush()?;

    let cert = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("peer certificate is missing")?;

    let server_public_key = extract_tls_server_public_key(cert)?;
    Ok((tls_stream, server_public_key))
}

fn extract_tls_server_public_key(cert: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert)?;
    let server_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not aligned")?
        .to_owned();

    Ok(server_public_key)
}

mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme, pki_types};

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

fn local_keyboard_layout() -> u32 {
    #[cfg(windows)]
    {
        unsafe {
            windows_sys::Win32::UI::Input::KeyboardAndMouse::GetKeyboardLayout(0) as usize as u32
                & 0xffff
        }
    }
    #[cfg(not(windows))]
    {
        0
    }
}

fn set_session_timeout(framed: &mut UpgradedFramed, timeout: Duration) -> std::io::Result<()> {
    match framed.get_inner_mut().0 {
        RdpTransport::Tls(stream) => stream.sock.set_read_timeout(Some(timeout)),
        RdpTransport::Plain(stream) => stream.set_read_timeout(Some(timeout)),
    }
}
