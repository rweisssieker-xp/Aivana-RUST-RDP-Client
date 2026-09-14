//! CLIPRDR and display control integrations. Clipboard content is session-scoped.
use crate::{
    connection_options::ProfileOptions,
    models::{ConnectionProfile, EngineEvent, InputAction},
};
use anyhow::{Context, Result, bail};
use ironrdp::{
    cliprdr::{CliprdrClient, backend::CliprdrBackend, pdu::*},
    core::impl_as_any,
    displaycontrol::{
        client::DisplayControlClient,
        pdu::{DisplayControlMonitorLayout, DisplayControlPdu, MonitorLayoutEntry},
    },
    dvc::DrdynvcClient,
    session::ActiveStage,
    svc::{SvcMessage, SvcProcessorMessages},
};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc::Sender},
    time::{Duration, Instant},
};
const FILE_FORMAT: ClipboardFormatId = ClipboardFormatId(0xC001);
const CHUNK: u32 = 64 * 1024;
static CLIPBOARD_OWNER: Mutex<Option<uuid::Uuid>> = Mutex::new(None);
pub fn set_clipboard_owner(owner: Option<uuid::Uuid>) {
    *CLIPBOARD_OWNER.lock().unwrap() = owner;
}
fn owns_clipboard(session: uuid::Uuid) -> bool {
    *CLIPBOARD_OWNER.lock().unwrap() == Some(session)
}

#[derive(Debug)]
enum Request {
    Copy(Vec<ClipboardFormat>),
    Paste(ClipboardFormatId),
    Data(FormatDataResponse<'static>, bool),
    File(FileContentsResponse<'static>),
    Read(FileContentsRequest),
}
#[derive(Debug, Default)]
struct ClipboardState {
    notices: Vec<String>,
    focused: bool,
    remote_text: Option<String>,
    remote_text_format: bool,
    queue: VecDeque<Request>,
    text: String,
    paths: Vec<PathBuf>,
    ready: bool,
    file_stream: bool,
    remote_file_format: Option<ClipboardFormatId>,
    receiving_list: bool,
    destination: Option<PathBuf>,
    download_files: VecDeque<(u32, FileDescriptor)>,
    download: Option<Download>,
    stream: u32,
}
#[derive(Debug)]
struct Download {
    file: File,
    path: PathBuf,
    index: u32,
    size: u64,
    offset: u64,
    stream: u32,
}
#[derive(Debug)]
struct ClipboardBackend {
    state: Arc<Mutex<ClipboardState>>,
    events: Sender<EngineEvent>,
    session: uuid::Uuid,
}
impl_as_any!(ClipboardBackend);
impl ClipboardBackend {
    fn diagnostic(&self, message: impl Into<String>) {
        let _ = self.events.send(EngineEvent::Diagnostic {
            session_id: self.session,
            message: message.into(),
        });
    }
}
impl CliprdrBackend for ClipboardBackend {
    fn temporary_directory(&self) -> &str {
        ".aivana-clipboard"
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
            | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
    }
    fn on_ready(&mut self) {
        self.state.lock().unwrap().ready = true;
        self.diagnostic("Clipboard negotiated (text and file streams)");
    }
    fn on_request_format_list(&mut self) {
        let mut s = self.state.lock().unwrap();
        s.queue.push_back(Request::Copy(vec![ClipboardFormat::new(
            ClipboardFormatId::CF_UNICODETEXT,
        )]));
    }
    fn on_process_negotiated_capabilities(&mut self, caps: ClipboardGeneralCapabilityFlags) {
        self.state.lock().unwrap().file_stream =
            caps.contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED);
    }
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let mut s = self.state.lock().unwrap();
        s.remote_file_format = formats
            .iter()
            .find(|f| {
                f.name()
                    .is_some_and(|n| n.value() == "FileGroupDescriptorW")
            })
            .map(|f| f.id());
        if s.remote_file_format.is_some() {
            self.diagnostic(
                "Remote clipboard files are available; save them with Receive files",
            );
        } else if formats
            .iter()
            .any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT)
            && !s.receiving_list
        {
            s.remote_text_format = true;
            if owns_clipboard(self.session) {
                s.queue
                    .push_back(Request::Paste(ClipboardFormatId::CF_UNICODETEXT));
            }
        }
    }
    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let mut s = self.state.lock().unwrap();
        let response = if request.format == ClipboardFormatId::CF_UNICODETEXT {
            if owns_clipboard(self.session) {
                FormatDataResponse::new_unicode_string(&s.text)
            } else {
                FormatDataResponse::new_error()
            }
        } else if request.format == FILE_FORMAT {
            let list = PackedFileList {
                files: s
                    .paths
                    .iter()
                    .filter_map(|p| {
                        Some(FileDescriptor {
                            attributes: Some(ClipboardFileAttributes::NORMAL),
                            last_write_time: None,
                            file_size: Some(p.metadata().ok()?.len()),
                            name: p.file_name()?.to_string_lossy().into_owned(),
                        })
                    })
                    .collect(),
            };
            FormatDataResponse::new_file_list(&list)
                .unwrap_or_else(|_| FormatDataResponse::new_error())
        } else {
            FormatDataResponse::new_error()
        };
        s.queue.push_back(Request::Data(
            response,
            request.format == ClipboardFormatId::CF_UNICODETEXT,
        ));
    }
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let mut s = self.state.lock().unwrap();
        if response.is_error() {
            s.receiving_list = false;
            self.diagnostic("Remote clipboard rejected data");
            return;
        }
        if s.receiving_list {
            s.receiving_list = false;
            match response.to_file_list() {
                Ok(list) => {
                    s.download_files = list
                        .files
                        .into_iter()
                        .enumerate()
                        .map(|(i, f)| (i as u32, f))
                        .collect();
                    if let Err(e) = start_download(&mut s) {
                        self.diagnostic(format!("File reception: {e}"));
                    }
                }
                Err(e) => self.diagnostic(format!("Invalid file list: {e}")),
            }
        } else if let Ok(text) = response.to_unicode_string() {
            // Remember remote value before polling to suppress clipboard echo.
            s.text = text.clone();
            s.paths.clear();
            if !owns_clipboard(self.session) {
                s.remote_text = Some(text);
                return;
            }
            let owner = CLIPBOARD_OWNER.lock().unwrap();
            if *owner != Some(self.session) {
                s.remote_text = Some(text);
                return;
            }
            match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
                Ok(()) => {}
                Err(e) => self.diagnostic(format!("Local clipboard: {e}")),
            }
        }
    }
    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        let mut s = self.state.lock().unwrap();
        let response = (|| -> Result<FileContentsResponse<'static>> {
            let path = s.paths.get(request.index as usize).context("File index")?;
            let mut file = File::open(path)?;
            if request.flags.contains(FileContentsFlags::SIZE) {
                return Ok(FileContentsResponse::new_size_response(
                    request.stream_id,
                    file.metadata()?.len(),
                ));
            }
            if !request.flags.contains(FileContentsFlags::DATA) {
                bail!("Unknown file request");
            }
            file.seek(SeekFrom::Start(request.position))?;
            let mut data = vec![0; request.requested_size.min(CHUNK) as usize];
            let n = file.read(&mut data)?;
            data.truncate(n);
            Ok(FileContentsResponse::new_data_response(
                request.stream_id,
                data,
            ))
        })()
        .unwrap_or_else(|_| FileContentsResponse::new_error(request.stream_id));
        s.queue.push_back(Request::File(response));
    }
    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        let mut s = self.state.lock().unwrap();
        let Some(mut d) = s.download.take() else {
            return;
        };
        if response.stream_id() != d.stream {
            s.download = Some(d);
            return;
        }
        let bytes = response.data();
        if bytes.is_empty()
            || bytes.len() > CHUNK as usize
            || bytes.len() as u64 > d.size - d.offset
        {
            self.diagnostic("File reception canceled: invalid or missing data; partial file was retained");
            return;
        }
        if let Err(e) = d.file.write_all(bytes) {
            self.diagnostic(format!("Write file: {e}"));
            return;
        }
        d.offset += bytes.len() as u64;
        if d.offset == d.size {
            self.diagnostic(format!("File received: {}", d.path.display()));
            if let Err(e) = start_download(&mut s) {
                self.diagnostic(format!("File reception: {e}"));
            }
        } else {
            let request = download_request(&d);
            s.queue.push_back(Request::Read(request));
            s.download = Some(d);
        }
    }
    fn on_lock(&mut self, _: LockDataId) {} // Lock capability is not advertised.
    fn on_unlock(&mut self, _: LockDataId) {}
}
fn safe_filename(name: &str) -> Result<&str> {
    if name.is_empty()
        || name.chars().any(char::is_control)
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', ':', '\0', '*', '?', '<', '>', '|', '"'])
        || name.ends_with(['.', ' '])
    {
        bail!("Unsafe filename");
    }
    let base = name.split('.').next().unwrap().to_ascii_uppercase();
    if [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ]
    .contains(&base.as_str())
    {
        bail!("Reserved filename");
    }
    Ok(name)
}
fn download_request(d: &Download) -> FileContentsRequest {
    FileContentsRequest {
        stream_id: d.stream,
        index: d.index,
        flags: FileContentsFlags::DATA,
        position: d.offset,
        requested_size: (d.size - d.offset).min(CHUNK as u64) as u32,
        data_id: None,
    }
}
fn start_download(s: &mut ClipboardState) -> Result<()> {
    while let Some((index, descriptor)) = s.download_files.pop_front() {
        if descriptor
            .attributes
            .is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY))
        {
            bail!("Transfer folders as ZIP archives");
        }
        let name = safe_filename(&descriptor.name)?;
        let destination = s.destination.as_ref().context("Destination folder is missing")?;
        let path = destination.join(name);
        let size = descriptor.file_size.context("Remote file size is missing")?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .context("Destination file already exists or is not writable")?;
        s.stream = s.stream.wrapping_add(1);
        let download = Download {
            file,
            path,
            index,
            size,
            offset: 0,
            stream: s.stream,
        };
        if size == 0 {
            s.notices.push(format!(
                "Empty file received: {}",
                download.path.display()
            ));
            continue;
        }
        s.queue
            .push_back(Request::Read(download_request(&download)));
        s.download = Some(download);
        break;
    }
    Ok(())
}
pub struct Channels {
    state: Arc<Mutex<ClipboardState>>,
    events: Sender<EngineEvent>,
    session: uuid::Uuid,
    options: ProfileOptions,
    last_poll: Instant,
    pending_resize: Option<(u16, u16)>,
    microphone: Option<std::sync::mpsc::Receiver<crate::rdp_audio_input::CapturedAudio>>,
}
impl Channels {
    pub fn new(
        profile: &ConnectionProfile,
        events: Sender<EngineEvent>,
        session: uuid::Uuid,
    ) -> Result<Self> {
        Ok(Self {
            state: Default::default(),
            events,
            session,
            options: profile.options.clone(),
            last_poll: Instant::now(),
            pending_resize: None,
            microphone: None,
        })
    }
    fn diagnostic(&self, message: impl Into<String>) {
        let _ = self.events.send(EngineEvent::Diagnostic {
            session_id: self.session,
            message: message.into(),
        });
    }
    pub fn report_error(&self, error: &anyhow::Error) {
        self.diagnostic(format!("Kanalaktion: {error:#}"));
    }
    pub fn attach(&mut self, connector: &mut ironrdp::connector::ClientConnector) -> Result<()> {
        if !self.options.shared_folders.is_empty() {
            let backend = crate::rdp_drives::DriveBackend::new(&self.options.shared_folders)?
                .with_events(self.events.clone(), self.session);
            let drives = backend.announced_drives();
            connector.attach_static_channel(
                ironrdp::rdpdr::Rdpdr::new(Box::new(backend), "Relayne".into())
                    .with_drives(Some(drives)),
            );
        }
        if self.options.clipboard {
            connector.attach_static_channel(CliprdrClient::new(Box::new(ClipboardBackend {
                state: self.state.clone(),
                events: self.events.clone(),
                session: self.session,
            })));
        }
        if self.options.audio_playback {
            connector.attach_static_channel(ironrdp::rdpsnd::client::Rdpsnd::new(Box::new(
                crate::rdp_audio_output::Playback::new(self.events.clone(), self.session),
            )));
        }
        if !self.options.audio_playback && !self.options.shared_folders.is_empty() {
            connector.attach_static_channel(ironrdp::rdpsnd::client::Rdpsnd::new(Box::new(
                ironrdp::rdpsnd::client::NoopRdpsndBackend,
            )));
        }
        let mut dynamic = DrdynvcClient::new();
        if self.options.microphone {
            let (input, rx) =
                crate::rdp_audio_input::AudioInput::new(self.events.clone(), self.session);
            self.microphone = Some(rx);
            dynamic.attach_dynamic_channel(input);
        }
        if self.options.dynamic_resolution || !self.options.monitors.is_empty() {
            let monitors = self.options.monitors.clone();
            let events = self.events.clone();
            let session = self.session;
            let layout = if monitors.is_empty() {
                None
            } else {
                let entries = monitors
                    .iter()
                    .map(|m| {
                        let e = if m.primary {
                            MonitorLayoutEntry::new_primary(m.width, m.height)
                        } else {
                            MonitorLayoutEntry::new_secondary(m.width, m.height)
                        }?;
                        e.with_position(m.x, m.y)
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Some(DisplayControlMonitorLayout::new(&entries)?)
            };
            let display = DisplayControlClient::new(move |caps| {
                let _ = events.send(EngineEvent::Diagnostic {
                    session_id: session,
                    message: "Dynamic display confirmed by server".into(),
                });
                if let Some(layout) = &layout {
                    let area: u64 = monitors
                        .iter()
                        .map(|m| m.width as u64 * m.height as u64)
                        .sum();
                    if area > caps.max_monitor_area() {
                        let _ = events.send(EngineEvent::Diagnostic {
                            session_id: session,
                            message: "Monitor layout exceeds server display area".into(),
                        });
                        return Ok(vec![]);
                    }
                    return Ok(vec![Box::new(DisplayControlPdu::MonitorLayout(
                        layout.clone(),
                    ))]);
                }
                Ok(vec![])
            });
            dynamic.attach_dynamic_channel(display);
        }
        if self.options.dynamic_resolution
            || !self.options.monitors.is_empty()
            || self.options.microphone
        {
            connector.attach_static_channel(dynamic);
        }
        Ok(())
    }
    pub fn action(
        &mut self,
        action: &InputAction,
        stage: &mut ActiveStage,
    ) -> Result<Option<Vec<u8>>> {
        match action {
            InputAction::ClipboardFocus { active } => {
                let mut s = self.state.lock().unwrap();
                s.focused = *active;
                if *active && owns_clipboard(self.session) {
                    if let Some(text) = s.remote_text.take() {
                        let owner = CLIPBOARD_OWNER.lock().unwrap();
                        if *owner == Some(self.session) {
                            let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(text));
                        }
                    } else if s.remote_text_format {
                        s.queue
                            .push_back(Request::Paste(ClipboardFormatId::CF_UNICODETEXT));
                    }
                }
                Ok(Some(vec![]))
            }
            InputAction::Resize { width, height } => {
                if !self.options.dynamic_resolution || !self.options.monitors.is_empty() {
                    return Ok(Some(vec![]));
                }
                let ready = stage
                    .get_dvc::<DisplayControlClient>()
                    .and_then(|d| d.channel_processor_downcast_ref::<DisplayControlClient>())
                    .is_some_and(|d| d.ready());
                if !ready {
                    self.pending_resize = Some((*width, *height));
                    return Ok(Some(vec![]));
                }
                self.pending_resize = None;
                let w = (*width as u32).clamp(200, 8192) & !1;
                let h = (*height as u32).clamp(200, 8192);
                Ok(Some(
                    stage
                        .encode_resize(w, h, Some(100), None)
                        .context("Display control unavailable")??,
                ))
            }
            InputAction::ClipboardFiles { paths } => {
                if !self.options.clipboard {
                    bail!("Clipboard is disabled");
                }
                let mut s = self.state.lock().unwrap();
                if !s.file_stream {
                    bail!("Server does not support file clipboard");
                }
                let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
                for p in &paths {
                    if !p.is_file() {
                        bail!("Transfer only existing files (archive folders as ZIP)");
                    }
                    let name = p.file_name().context("Dateiname")?.to_string_lossy();
                    safe_filename(&name)?;
                    if name.encode_utf16().count() > 259 {
                        bail!("Dateiname zu lang");
                    }
                }
                s.paths = paths;
                s.queue.push_back(Request::Copy(vec![
                    ClipboardFormat::new(FILE_FORMAT)
                        .with_name(ClipboardFormatName::new("FileGroupDescriptorW")),
                ]));
                self.diagnostic("Files offered – select Paste in remote File Explorer");
                Ok(Some(vec![]))
            }
            InputAction::ClipboardDownload { directory } => {
                if !self.options.clipboard {
                    bail!("Clipboard is disabled");
                }
                let mut s = self.state.lock().unwrap();
                if s.download.is_some() || s.receiving_list {
                    bail!("File reception already in progress");
                }
                let format = s
                    .remote_file_format
                    .context("No remote files in clipboard")?;
                let path = Path::new(directory);
                std::fs::create_dir_all(path)?;
                s.destination = Some(path.canonicalize()?);
                s.receiving_list = true;
                s.queue.push_back(Request::Paste(format));
                Ok(Some(vec![]))
            }
            _ => Ok(None),
        }
    }
    pub fn pump(&mut self, stage: &mut ActiveStage) -> Result<Vec<Vec<u8>>> {
        let mut frames = vec![];
        if let Some((width, height)) = self.pending_resize {
            if let Some(frame) = self.action(&InputAction::Resize { width, height }, stage)? {
                if !frame.is_empty() {
                    frames.push(frame);
                }
            }
        }
        if let Some(receiver) = &self.microphone {
            if let Some((channel, generation)) = stage
                .get_dvc::<crate::rdp_audio_input::AudioInput>()
                .and_then(|d| {
                    Some((
                        d.channel_id()?,
                        d.channel_processor_downcast_ref::<crate::rdp_audio_input::AudioInput>()?
                            .generation(),
                    ))
                })
            {
                for packet in receiver.try_iter().take(32) {
                    if packet.generation != generation {
                        continue;
                    }
                    let messages = ironrdp::dvc::encode_dvc_messages(
                        channel,
                        vec![
                            Box::new(crate::rdp_audio_input::AudioPacket(vec![5])),
                            Box::new(packet.packet),
                        ],
                        ironrdp::svc::ChannelFlags::empty(),
                    )?;
                    frames.push(stage.encode_dvc_messages(messages)?);
                }
            }
        }
        if !self.options.clipboard {
            return Ok(frames);
        }
        if owns_clipboard(self.session) && self.last_poll.elapsed() > Duration::from_millis(400) {
            self.last_poll = Instant::now();
            let owner = CLIPBOARD_OWNER.lock().unwrap();
            if *owner == Some(self.session) {
                if let Ok(text) = arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                    let mut s = self.state.lock().unwrap();
                    if s.focused && s.ready && text != s.text && text.len() <= 4 * 1024 * 1024 {
                        s.text = text;
                        s.paths.clear();
                        s.queue.push_back(Request::Copy(vec![ClipboardFormat::new(
                            ClipboardFormatId::CF_UNICODETEXT,
                        )]));
                    }
                }
            }
        }
        let notices: Vec<_> = self.state.lock().unwrap().notices.drain(..).collect();
        for message in notices {
            self.diagnostic(message);
        }
        let requests: Vec<_> = self.state.lock().unwrap().queue.drain(..).collect();
        for request in requests {
            if !owns_clipboard(self.session)
                && matches!(&request,Request::Copy(formats) if formats.iter().all(|f|f.id()!=FILE_FORMAT))
            {
                continue;
            }
            if !owns_clipboard(self.session)
                && matches!(&request,Request::Paste(format) if *format==ClipboardFormatId::CF_UNICODETEXT)
            {
                continue;
            }
            let Some(clip) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                break;
            };
            let messages = match request {
                Request::Copy(f) => clip.initiate_copy(&f)?,
                Request::Paste(f) => clip.initiate_paste(f)?,
                Request::Data(d, text) => {
                    clip.submit_format_data(if text && !owns_clipboard(self.session) {
                        FormatDataResponse::new_error()
                    } else {
                        d
                    })?
                }
                Request::File(d) => clip.submit_file_contents(d)?,
                Request::Read(r) => {
                    SvcProcessorMessages::<CliprdrClient>::new(vec![SvcMessage::from(
                        ClipboardPdu::FileContentsRequest(r),
                    )])
                }
            };
            frames.push(stage.process_svc_processor_messages(messages)?);
        }
        Ok(frames)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn enabled_shared_folders_reach_channel_initialization() {
        let mut profile =
            crate::models::ConnectionProfile::sample("Test", "test.invalid", "Test", false);
        profile
            .options
            .shared_folders
            .push(crate::connection_options::SharedFolder {
                name: "Dateien".to_owned(),
                path: "C:\\Temp".to_owned(),
                read_only: true,
            });
        let (events, _) = std::sync::mpsc::channel();
        assert!(super::Channels::new(&profile, events, uuid::Uuid::new_v4()).is_ok());
    }

    use super::*;
    #[test]
    fn rejects_clipboard_path_traversal() {
        for name in ["../x", "C:\\x", "x/y", "NUL", "COM1.txt", "x:stream", ".."] {
            assert!(safe_filename(name).is_err());
        }
        assert!(safe_filename("report.txt").is_ok());
    }
    #[test]
    fn file_upload_serves_bounded_offset_chunks() {
        let dir = std::env::temp_dir().join(format!("aivana-clip-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("test.bin");
        std::fs::write(&path, b"abcdefgh").unwrap();
        let state = Arc::new(Mutex::new(ClipboardState {
            paths: vec![path],
            ..Default::default()
        }));
        let (tx, _) = std::sync::mpsc::channel();
        let mut backend = ClipboardBackend {
            state: state.clone(),
            events: tx,
            session: uuid::Uuid::new_v4(),
        };
        backend.on_file_contents_request(FileContentsRequest {
            stream_id: 17,
            index: 0,
            flags: FileContentsFlags::DATA,
            position: 2,
            requested_size: 3,
            data_id: None,
        });
        let mut guard = state.lock().unwrap();
        match guard.queue.pop_front().unwrap() {
            Request::File(response) => {
                assert_eq!(response.stream_id(), 17);
                assert_eq!(response.data(), b"cde");
            }
            _ => panic!("Expected file response"),
        }
        drop(guard);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn download_never_overwrites_existing_file() {
        let dir = std::env::temp_dir().join(format!("aivana-clip-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("existing.txt");
        std::fs::write(&path, b"original").unwrap();
        let mut state = ClipboardState {
            destination: Some(dir.clone()),
            ..Default::default()
        };
        state.download_files.push_back((
            0,
            FileDescriptor {
                attributes: None,
                last_write_time: None,
                file_size: Some(3),
                name: "existing.txt".into(),
            },
        ));
        assert!(start_download(&mut state).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
