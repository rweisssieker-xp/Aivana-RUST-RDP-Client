//! Capability-scoped RDPDR filesystem backend, including Windows.
//! Every remote path is resolved relative to a cap-std directory handle.
use crate::connection_options::SharedFolder;
use anyhow::{Context, Result, bail};
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use ironrdp::core::impl_as_any;
use ironrdp::pdu::PduResult;
use ironrdp::rdpdr::{
    RdpdrBackend,
    pdu::{
        RdpdrPdu,
        efs::*,
        esc::{ScardCall, ScardIoCtlCode},
    },
};
use ironrdp::svc::SvcMessage;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Share {
    root: Dir,
    source_path: PathBuf,
    name: String,
    read_only: bool,
}
#[derive(Debug)]
struct OpenFile {
    device: u32,
    path: PathBuf,
    file: Option<File>,
    directory: Option<Dir>,
    writable: bool,
    delete_pending: bool,
    entries: VecDeque<(String, Metadata)>,
}
impl OpenFile {
    fn metadata(&self) -> io::Result<Metadata> {
        match (&self.file, &self.directory) {
            (Some(file), _) => file.metadata(),
            (_, Some(dir)) => dir.dir_metadata(),
            _ => Err(io::Error::other("Closed handle")),
        }
    }
}
#[derive(Debug)]
pub struct DriveBackend {
    shares: HashMap<u32, Share>,
    files: HashMap<u32, OpenFile>,
    next_id: u32,
    events: Option<(
        std::sync::mpsc::Sender<crate::models::EngineEvent>,
        uuid::Uuid,
    )>,
}
impl_as_any!(DriveBackend);

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Access denied")
}
#[cfg(windows)]
fn disk_space(path: &Path) -> io::Result<(u64, u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            directory: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let (mut available, mut total, mut free) = (0, 0, 0);
    // SAFETY: terminated UTF-16 path and writable pointers to three u64 values
    // remain valid throughout this synchronous, read-only Win32 call.
    if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut free) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((total, available, free))
}
#[cfg(not(windows))]
fn disk_space(_: &Path) -> io::Result<(u64, u64, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Volume capacity requires Windows",
    ))
}
fn status(error: &io::Error) -> NtStatus {
    match error.kind() {
        io::ErrorKind::PermissionDenied => NtStatus::ACCESS_DENIED,
        io::ErrorKind::NotFound => NtStatus::NO_SUCH_FILE,
        io::ErrorKind::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        io::ErrorKind::Unsupported => NtStatus::NOT_SUPPORTED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}
fn checked_path(remote: &str) -> io::Result<PathBuf> {
    if remote.starts_with("\\\\")
        || remote.starts_with("//")
        || remote.contains(':')
        || remote.contains('\0')
    {
        return Err(denied());
    }
    let mut path = PathBuf::new();
    for part in remote
        .trim_start_matches(['\\', '/'])
        .split(['\\', '/'])
        .filter(|v| !v.is_empty())
    {
        let basename = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if part == ".."
            || part == "."
            || part.ends_with([' ', '.'])
            || part.contains(['*', '?', '<', '>', '|', '"'])
            || part.chars().any(char::is_control)
            || ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&basename.as_str())
            || (basename.len() == 4
                && (basename.starts_with("COM") || basename.starts_with("LPT"))
                && basename.as_bytes()[3].is_ascii_digit())
        {
            return Err(denied());
        }
        path.push(part);
    }
    if path.as_os_str().is_empty() {
        path.push(".");
    }
    Ok(path)
}
fn filetime(time: io::Result<cap_std::time::SystemTime>) -> i64 {
    time.ok()
        .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_nanos() / 100 + 116444736000000000).min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
fn attributes(meta: &Metadata, readonly: bool) -> FileAttributes {
    let mut flags = if meta.is_dir() {
        FileAttributes::FILE_ATTRIBUTE_DIRECTORY
    } else {
        FileAttributes::FILE_ATTRIBUTE_NORMAL
    };
    if readonly || meta.permissions().readonly() {
        flags |= FileAttributes::FILE_ATTRIBUTE_READONLY;
    }
    flags
}
fn basic(meta: &Metadata, readonly: bool) -> FileBasicInformation {
    FileBasicInformation {
        creation_time: filetime(meta.created()),
        last_access_time: filetime(meta.accessed()),
        last_write_time: filetime(meta.modified()),
        change_time: filetime(meta.modified()),
        file_attributes: attributes(meta, readonly),
    }
}
fn wildcard(pattern: &str, name: &str) -> bool {
    let pattern = if pattern == "*.*" { "*" } else { pattern };
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut i, mut j, mut star, mut matched) = (0, 0, None, 0);
    while j < n.len() {
        if i < p.len() && (p[i] == '?' || p[i] == n[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            matched = j;
        } else if let Some(s) = star {
            matched += 1;
            j = matched;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}
impl DriveBackend {
    pub fn new(folders: &[SharedFolder]) -> Result<Self> {
        let mut shares = HashMap::new();
        let mut names = std::collections::HashSet::new();
        for (index, folder) in folders.iter().enumerate() {
            if folder.name.is_empty()
                || folder.name.len() > 7
                || !folder
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                bail!("Freigabename: 1–7 Buchstaben/Ziffern/Unterstriche erforderlich");
            }
            if !names.insert(folder.name.to_ascii_lowercase()) {
                bail!("Freigabenamen müssen eindeutig sein");
            }
            let root = Dir::open_ambient_dir(&folder.path, cap_std::ambient_authority())
                .context("Freigabeordner konnte nicht geöffnet werden")?;
            shares.insert(
                index as u32 + 1,
                Share {
                    root,
                    source_path: PathBuf::from(&folder.path),
                    name: folder.name.clone(),
                    read_only: folder.read_only,
                },
            );
        }
        Ok(Self {
            shares,
            files: HashMap::new(),
            next_id: 1,
            events: None,
        })
    }
    pub fn with_events(
        mut self,
        events: std::sync::mpsc::Sender<crate::models::EngineEvent>,
        session: uuid::Uuid,
    ) -> Self {
        self.events = Some((events, session));
        self
    }
    pub fn announced_drives(&self) -> Vec<(u32, String)> {
        let mut drives: Vec<_> = self
            .shares
            .iter()
            .map(|(id, s)| (*id, s.name.clone()))
            .collect();
        drives.sort_by_key(|(id, _)| *id);
        drives
    }
    fn handle(&mut self, header: &DeviceIoRequest) -> io::Result<&mut OpenFile> {
        self.files
            .get_mut(&header.file_id)
            .filter(|f| f.device == header.device_id)
            .ok_or_else(denied)
    }
    fn create(&mut self, req: &DeviceCreateRequest) -> io::Result<(u32, Information)> {
        if self.files.len() >= 1024 {
            return Err(io::Error::other("Too many open handles"));
        }
        let share = self
            .shares
            .get(&req.device_io_request.device_id)
            .ok_or_else(denied)?;
        let path = checked_path(&req.path)?;
        let disposition = req.create_disposition.bits();
        if disposition > 5 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Create disposition",
            ));
        }
        let writes = req.desired_access.bits()
            & (0x40000000
                | 0x10000000
                | 0x2
                | 0x4
                | 0x10
                | 0x40
                | 0x100
                | 0x10000
                | 0x40000
                | 0x80000)
            != 0;
        let delete = req
            .create_options
            .contains(CreateOptions::FILE_DELETE_ON_CLOSE);
        let writable = writes
            || (req.desired_access.contains(DesiredAccess::MAXIMUM_ALLOWED) && !share.read_only);
        if share.read_only && (writes || delete || disposition != 1) {
            return Err(denied());
        }
        if disposition != 1 && !writable {
            return Err(denied());
        }
        if path == Path::new(".") && (delete || disposition != 1) {
            return Err(denied());
        }
        let existing = share.root.metadata(&path);
        let exists = existing.is_ok();
        let is_dir = req
            .create_options
            .contains(CreateOptions::FILE_DIRECTORY_FILE)
            || existing.as_ref().is_ok_and(|m| m.is_dir());
        if req
            .create_options
            .contains(CreateOptions::FILE_NON_DIRECTORY_FILE)
            && is_dir
        {
            return Err(denied());
        }
        let (file, directory) = if is_dir {
            if disposition == 2 && exists {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Directory exists",
                ));
            }
            if !exists && [2, 3].contains(&disposition) {
                share.root.create_dir(&path)?;
            }
            if [0, 4, 5].contains(&disposition) {
                return Err(denied());
            }
            (None, Some(share.root.open_dir(&path)?))
        } else {
            let mut options = OpenOptions::new();
            options.read(true).write(writable);
            match disposition {
                0 | 5 => {
                    options.create(true).truncate(true);
                }
                1 => {}
                2 => {
                    options.create_new(true);
                }
                3 => {
                    options.create(true);
                }
                4 => {
                    options.truncate(true);
                }
                _ => unreachable!(),
            }
            (Some(share.root.open_with(&path, &options)?), None)
        };
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Handle limit"))?;
        self.files.insert(
            id,
            OpenFile {
                device: req.device_io_request.device_id,
                path,
                file,
                directory,
                writable,
                delete_pending: delete,
                entries: VecDeque::new(),
            },
        );
        let information = if !exists {
            Information::from_bits_retain(2)
        } else if [0, 4, 5].contains(&disposition) {
            Information::FILE_OVERWRITTEN
        } else {
            Information::FILE_OPENED
        };
        Ok((id, information))
    }
    fn close(&mut self, header: &DeviceIoRequest) -> io::Result<()> {
        self.handle(header)?;
        let file = self.files.remove(&header.file_id).ok_or_else(denied)?;
        if file.delete_pending {
            let share = self.shares.get(&file.device).ok_or_else(denied)?;
            if share.read_only || !file.writable || file.path == Path::new(".") {
                return Err(denied());
            }
            let is_dir = file.directory.is_some();
            let path = file.path.clone();
            drop(file);
            if is_dir {
                share.root.remove_dir(path)
            } else {
                share.root.remove_file(path)
            }
        } else {
            Ok(())
        }
    }
    fn read(&mut self, req: &DeviceReadRequest) -> io::Result<Vec<u8>> {
        if req.length > 4 * 1024 * 1024 {
            return Err(denied());
        }
        let f = self
            .handle(&req.device_io_request)?
            .file
            .as_mut()
            .ok_or_else(denied)?;
        f.seek(SeekFrom::Start(req.offset))?;
        let mut data = vec![0; req.length as usize];
        let n = f.read(&mut data)?;
        data.truncate(n);
        Ok(data)
    }
    fn write(&mut self, req: &DeviceWriteRequest) -> io::Result<u32> {
        if req.write_data.len() > 4 * 1024 * 1024 {
            return Err(denied());
        }
        let f = self.handle(&req.device_io_request)?;
        if !f.writable {
            return Err(denied());
        }
        let f = f.file.as_mut().ok_or_else(denied)?;
        f.seek(SeekFrom::Start(req.offset))?;
        f.write_all(&req.write_data)?;
        Ok(req.write_data.len() as u32)
    }
    fn query(
        &mut self,
        req: &ServerDriveQueryInformationRequest,
    ) -> io::Result<FileInformationClass> {
        let readonly = self
            .shares
            .get(&req.device_io_request.device_id)
            .ok_or_else(denied)?
            .read_only;
        let f = self.handle(&req.device_io_request)?;
        let meta = f.metadata()?;
        match req.file_info_class_lvl {
            FileInformationClassLevel::FILE_BASIC_INFORMATION => {
                Ok(FileInformationClass::Basic(basic(&meta, readonly)))
            }
            FileInformationClassLevel::FILE_STANDARD_INFORMATION => {
                Ok(FileInformationClass::Standard(FileStandardInformation {
                    allocation_size: meta.len() as i64,
                    end_of_file: meta.len() as i64,
                    number_of_links: 1,
                    delete_pending: (f.delete_pending as u8).into(),
                    directory: (meta.is_dir() as u8).into(),
                }))
            }
            FileInformationClassLevel::FILE_ATTRIBUTE_TAG_INFORMATION => Ok(
                FileInformationClass::AttributeTag(FileAttributeTagInformation {
                    file_attributes: attributes(&meta, readonly),
                    reparse_tag: 0,
                }),
            ),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Information class",
            )),
        }
    }
    fn directory(
        &mut self,
        req: &ServerDriveQueryDirectoryRequest,
    ) -> io::Result<Option<FileInformationClass>> {
        let readonly = self
            .shares
            .get(&req.device_io_request.device_id)
            .ok_or_else(denied)?
            .read_only;
        let f = self.handle(&req.device_io_request)?;
        let dir = f.directory.as_ref().ok_or_else(denied)?;
        if req.initial_query != 0 {
            let pattern = req.path.rsplit(['\\', '/']).next().unwrap_or("*");
            f.entries.clear();
            for entry in dir.entries()? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !wildcard(pattern, &name) || checked_path(&name).is_err() {
                    continue;
                }
                // Metadata lookup through the directory capability forbids out-of-root symlinks.
                if let Ok(meta) = dir.metadata(&name) {
                    f.entries.push_back((name, meta));
                }
                if f.entries.len() > 100_000 {
                    return Err(io::Error::other("Directory entry limit"));
                }
            }
        }
        let Some((name, meta)) = f.entries.pop_front() else {
            return Ok(None);
        };
        let b = basic(&meta, readonly);
        let size = meta.len() as i64;
        let info = match req.file_info_class_lvl {
            FileInformationClassLevel::FILE_NAMES_INFORMATION => {
                FileInformationClass::Names(FileNamesInformation::new(name))
            }
            FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION => {
                FileInformationClass::BothDirectory(FileBothDirectoryInformation::new(
                    b.creation_time,
                    b.last_access_time,
                    b.last_write_time,
                    b.change_time,
                    size,
                    b.file_attributes,
                    name,
                ))
            }
            FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION => {
                FileInformationClass::FullDirectory(FileFullDirectoryInformation::new(
                    b.creation_time,
                    b.last_access_time,
                    b.last_write_time,
                    b.change_time,
                    size,
                    b.file_attributes,
                    name,
                ))
            }
            FileInformationClassLevel::FILE_DIRECTORY_INFORMATION => {
                FileInformationClass::Directory(FileDirectoryInformation::new(
                    b.creation_time,
                    b.last_access_time,
                    b.last_write_time,
                    b.change_time,
                    size,
                    b.file_attributes,
                    name,
                ))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Directory information class",
                ));
            }
        };
        Ok(Some(info))
    }
    fn set_information(&mut self, req: &ServerDriveSetInformationRequest) -> io::Result<()> {
        let f = self.handle(&req.device_io_request)?;
        if !f.writable || f.path == Path::new(".") {
            return Err(denied());
        }
        match &req.set_buffer {
            FileInformationClass::Basic(info) => {
                if info.file_attributes.bits() & !(0x1 | 0x10 | 0x20 | 0x80) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "File attributes",
                    ));
                }
                let file = if let Some(file) = &f.file {
                    file.try_clone()?.into_std()
                } else {
                    f.directory
                        .as_ref()
                        .ok_or_else(denied)?
                        .try_clone()?
                        .into_std_file()
                };
                let mut times = std::fs::FileTimes::new();
                let time = |ticks: i64| -> io::Result<std::time::SystemTime> {
                    let ticks = u64::try_from(ticks).map_err(|_| denied())?;
                    let epoch = std::time::UNIX_EPOCH
                        .checked_sub(std::time::Duration::from_secs(11644473600))
                        .ok_or_else(denied)?;
                    epoch
                        .checked_add(std::time::Duration::from_nanos(
                            ticks.checked_mul(100).ok_or_else(denied)?,
                        ))
                        .ok_or_else(denied)
                };
                if info.last_access_time > 0 {
                    times = times.set_accessed(time(info.last_access_time)?);
                }
                if info.last_write_time > 0 {
                    times = times.set_modified(time(info.last_write_time)?);
                }
                #[cfg(windows)]
                if info.creation_time > 0 {
                    use std::os::windows::fs::FileTimesExt;
                    times = times.set_created(time(info.creation_time)?);
                }
                file.set_times(times)?;
                if !info.file_attributes.is_empty() {
                    let mut permissions = file.metadata()?.permissions();
                    permissions.set_readonly(
                        info.file_attributes
                            .contains(FileAttributes::FILE_ATTRIBUTE_READONLY),
                    );
                    file.set_permissions(permissions)?;
                }
                Ok(())
            }
            FileInformationClass::EndOfFile(info) => {
                let length = u64::try_from(info.end_of_file).map_err(|_| denied())?;
                f.file.as_ref().ok_or_else(denied)?.set_len(length)
            }
            FileInformationClass::Disposition(info) => {
                f.delete_pending = info.delete_pending != 0;
                Ok(())
            }
            FileInformationClass::Allocation(info) => {
                if info.allocation_size < 0 {
                    return Err(denied());
                }
                let file = f.file.as_ref().ok_or_else(denied)?;
                if (info.allocation_size as u64) < file.metadata()?.len() {
                    file.set_len(info.allocation_size as u64)?;
                }
                Ok(())
            }
            FileInformationClass::Rename(info) => {
                if f.directory.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Directory rename is not supported",
                    ));
                }
                let target = checked_path(&info.file_name)?;
                let source = f.path.clone();
                let device = f.device;
                let share = self.shares.get(&device).ok_or_else(denied)?;
                if share.read_only || target == Path::new(".") {
                    return Err(denied());
                }
                // Hard-link creation atomically refuses an existing destination.
                // Avoid rename()'s overwrite race. Filesystems without hard-link
                // support return an explicit error and leave the source intact.
                share.root.hard_link(&source, &share.root, &target)?;
                share.root.remove_file(&source)?;
                for open in self
                    .files
                    .values_mut()
                    .filter(|open| open.device == device && open.path == source)
                {
                    open.path = target.clone();
                }
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Set information class",
            )),
        }
    }
}

impl RdpdrBackend for DriveBackend {
    fn handle_server_device_announce_response(
        &mut self,
        response: ServerDeviceAnnounceResponse,
    ) -> PduResult<()> {
        if let Some((events, session_id)) = &self.events {
            let name = self
                .shares
                .get(&response.device_id)
                .map(|s| s.name.as_str())
                .unwrap_or("Unbekannt");
            let message = if response.result_code == NtStatus::SUCCESS {
                format!("Ordnerfreigabe {name} vom Server bestätigt")
            } else {
                format!(
                    "Ordnerfreigabe {name} vom Server abgelehnt ({:?})",
                    response.result_code
                )
            };
            let _ = events.send(crate::models::EngineEvent::Diagnostic {
                session_id: *session_id,
                message,
            });
        }
        Ok(())
    }
    fn handle_scard_call(
        &mut self,
        _: DeviceControlRequest<ScardIoCtlCode>,
        _: ScardCall,
    ) -> PduResult<()> {
        Ok(())
    }
    fn handle_drive_io_request(
        &mut self,
        request: ServerDriveIoRequest,
    ) -> PduResult<Vec<SvcMessage>> {
        let pdu = match request {
            ServerDriveIoRequest::ServerCreateDriveRequest(req) => {
                let result = self.create(&req);
                let s = result
                    .as_ref()
                    .err()
                    .map(status)
                    .unwrap_or(NtStatus::SUCCESS);
                let (id, information) = result.unwrap_or((0, Information::FILE_SUPERSEDED));
                RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                    device_io_reply: DeviceIoResponse::new(req.device_io_request, s),
                    file_id: id,
                    information,
                })
            }
            ServerDriveIoRequest::DeviceCloseRequest(req) => {
                let s = self
                    .close(&req.device_io_request)
                    .err()
                    .as_ref()
                    .map(status)
                    .unwrap_or(NtStatus::SUCCESS);
                RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                    device_io_response: DeviceIoResponse::new(req.device_io_request, s),
                })
            }
            ServerDriveIoRequest::DeviceReadRequest(req) => {
                let result = self.read(&req);
                let s = result
                    .as_ref()
                    .err()
                    .map(status)
                    .unwrap_or(NtStatus::SUCCESS);
                RdpdrPdu::DeviceReadResponse(DeviceReadResponse {
                    device_io_reply: DeviceIoResponse::new(req.device_io_request, s),
                    read_data: result.unwrap_or_default(),
                })
            }
            ServerDriveIoRequest::DeviceWriteRequest(req) => {
                let result = self.write(&req);
                let s = result
                    .as_ref()
                    .err()
                    .map(status)
                    .unwrap_or(NtStatus::SUCCESS);
                RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse {
                    device_io_reply: DeviceIoResponse::new(req.device_io_request, s),
                    length: result.unwrap_or(0),
                })
            }
            ServerDriveIoRequest::ServerDriveQueryInformationRequest(req) => {
                let result = self.query(&req);
                let s = result
                    .as_ref()
                    .err()
                    .map(status)
                    .unwrap_or(NtStatus::SUCCESS);
                RdpdrPdu::ClientDriveQueryInformationResponse(ClientDriveQueryInformationResponse {
                    device_io_response: DeviceIoResponse::new(req.device_io_request, s),
                    buffer: result.ok(),
                })
            }
            ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(req) => {
                let result = self.directory(&req);
                let s = match &result {
                    Ok(Some(_)) => NtStatus::SUCCESS,
                    Ok(None) => NtStatus::NO_MORE_FILES,
                    Err(e) => status(e),
                };
                RdpdrPdu::ClientDriveQueryDirectoryResponse(ClientDriveQueryDirectoryResponse {
                    device_io_reply: DeviceIoResponse::new(req.device_io_request, s),
                    buffer: result.ok().flatten(),
                })
            }
            ServerDriveIoRequest::ServerDriveSetInformationRequest(req) => {
                let s = self
                    .set_information(&req)
                    .err()
                    .as_ref()
                    .map(status)
                    .unwrap_or(NtStatus::SUCCESS);
                RdpdrPdu::ClientDriveSetInformationResponse(
                    ClientDriveSetInformationResponse::new(&req, s)
                        .map_err(|e| ironrdp::pdu::encode_err!(e))?,
                )
            }
            ServerDriveIoRequest::ServerDriveQueryVolumeInformationRequest(req) => {
                let share = self.shares.get(&req.device_io_request.device_id);
                let buffer = share.and_then(|s| match req.fs_info_class_lvl {
                    FileSystemInformationClassLevel::FILE_FS_SIZE_INFORMATION => {
                        disk_space(&s.source_path)
                            .ok()
                            .map(|(total, available, _)| {
                                FileFsSizeInformation {
                                    total_alloc_units: (total / 4096) as i64,
                                    available_alloc_units: (available / 4096) as i64,
                                    sectors_per_alloc_unit: 8,
                                    bytes_per_sector: 512,
                                }
                                .into()
                            })
                    }
                    FileSystemInformationClassLevel::FILE_FS_FULL_SIZE_INFORMATION => {
                        disk_space(&s.source_path)
                            .ok()
                            .map(|(total, available, free)| {
                                FileFsFullSizeInformation {
                                    total_alloc_units: (total / 4096) as i64,
                                    caller_available_alloc_units: (available / 4096) as i64,
                                    actual_available_alloc_units: (free / 4096) as i64,
                                    sectors_per_alloc_unit: 8,
                                    bytes_per_sector: 512,
                                }
                                .into()
                            })
                    }
                    FileSystemInformationClassLevel::FILE_FS_VOLUME_INFORMATION => Some(
                        FileFsVolumeInformation {
                            volume_creation_time: 0,
                            volume_serial_number: req.device_io_request.device_id,
                            supports_objects: Boolean::False,
                            volume_label: s.name.clone(),
                        }
                        .into(),
                    ),
                    FileSystemInformationClassLevel::FILE_FS_ATTRIBUTE_INFORMATION => Some(
                        FileFsAttributeInformation {
                            file_system_attributes: FileSystemAttributes::from_bits_retain(
                                0x2 | if s.read_only { 0x80000 } else { 0 },
                            ),
                            max_component_name_len: 255,
                            file_system_name: "Relayne".into(),
                        }
                        .into(),
                    ),
                    _ => None,
                });
                let s = if buffer.is_some() {
                    NtStatus::SUCCESS
                } else {
                    NtStatus::NOT_SUPPORTED
                };
                RdpdrPdu::ClientDriveQueryVolumeInformationResponse(
                    ClientDriveQueryVolumeInformationResponse::new(
                        req.device_io_request,
                        s,
                        buffer,
                    ),
                )
            }
            ServerDriveIoRequest::DeviceControlRequest(req) => RdpdrPdu::DeviceControlResponse(
                DeviceControlResponse::new(req, NtStatus::NOT_SUPPORTED, None),
            ),
            ServerDriveIoRequest::ServerDriveNotifyChangeDirectoryRequest(req) => {
                RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                    device_io_response: DeviceIoResponse::new(
                        req.device_io_request,
                        NtStatus::NOT_SUPPORTED,
                    ),
                })
            }
            ServerDriveIoRequest::ServerDriveLockControlRequest(req) => {
                RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                    device_io_response: DeviceIoResponse::new(
                        req.device_io_request,
                        NtStatus::NOT_SUPPORTED,
                    ),
                })
            }
        };
        Ok(vec![SvcMessage::from(pdu)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header(file_id: u32) -> DeviceIoRequest {
        DeviceIoRequest {
            device_id: 1,
            file_id,
            completion_id: 1,
            major_function: MajorFunction::Create,
            minor_function: MinorFunction::from(0),
        }
    }
    fn request(path: &str, write: bool) -> DeviceCreateRequest {
        DeviceCreateRequest {
            device_io_request: header(0),
            desired_access: if write {
                DesiredAccess::GENERIC_WRITE
            } else {
                DesiredAccess::GENERIC_READ
            },
            allocation_size: 0,
            file_attributes: FileAttributes::FILE_ATTRIBUTE_NORMAL,
            shared_access: SharedAccess::FILE_SHARE_READ,
            create_disposition: if write {
                CreateDisposition::FILE_OPEN_IF
            } else {
                CreateDisposition::FILE_OPEN
            },
            create_options: CreateOptions::empty(),
            path: path.into(),
        }
    }
    fn backend(read_only: bool) -> (DriveBackend, PathBuf) {
        let path = std::env::temp_dir().join(format!("aivana-drive-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let backend = DriveBackend::new(&[SharedFolder {
            name: "TEST".into(),
            path: path.to_string_lossy().into(),
            read_only,
        }])
        .unwrap();
        (backend, path)
    }
    #[test]
    fn rejects_traversal_ads_device_and_unc_paths() {
        for p in [
            "../outside",
            "a/../../b",
            "C:\\file",
            "\\\\server\\share",
            "file:stream",
            "NUL",
            "CON.txt",
            "a. ",
            "/../x",
        ] {
            assert!(checked_path(p).is_err(), "{p}");
        }
        assert_eq!(
            checked_path("\\sub\\file.txt").unwrap(),
            PathBuf::from("sub").join("file.txt")
        );
    }
    #[test]
    fn writes_reads_and_obeys_read_only() {
        let (mut b, path) = backend(false);
        let (id, _) = b.create(&request("file.txt", true)).unwrap();
        b.write(&DeviceWriteRequest {
            device_io_request: header(id),
            offset: 0,
            write_data: b"hello".to_vec(),
        })
        .unwrap();
        assert_eq!(
            b.read(&DeviceReadRequest {
                device_io_request: header(id),
                length: 32,
                offset: 0
            })
            .unwrap(),
            b"hello"
        );
        b.close(&header(id)).unwrap();
        drop(b);
        let mut ro = DriveBackend::new(&[SharedFolder {
            name: "TEST".into(),
            path: path.to_string_lossy().into(),
            read_only: true,
        }])
        .unwrap();
        assert!(ro.create(&request("file.txt", true)).is_err());
        let (id, _) = ro.create(&request("file.txt", false)).unwrap();
        assert!(
            ro.write(&DeviceWriteRequest {
                device_io_request: header(id),
                offset: 0,
                write_data: vec![0]
            })
            .is_err()
        );
        drop(ro);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn wildcard_matches_windows_patterns() {
        assert!(wildcard("*.*", "README"));
        assert!(wildcard("*.TXT", "a.txt"));
        assert!(!wildcard("a?.txt", "abc.txt"));
    }
}
