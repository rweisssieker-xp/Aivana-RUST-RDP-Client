//! Fail-closed identity checks before any Docker pipe request is written.
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
#[cfg(test)]
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::{
    Foundation::{ERROR_NO_TOKEN, GetLastError},
    Security::{
        Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW},
        TOKEN_QUERY,
        WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
            WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
        },
    },
    System::{
        Com::CoTaskMemFree,
        Pipes::GetNamedPipeServerProcessId,
        Threading::{
            GetCurrentThread, OpenProcess, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
    UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};

pub(super) fn reject_thread_impersonation() -> Result<()> {
    // A thread token can have a different effective identity or privileges from
    // the reviewed process token. Reject it even when its SID happens to match.
    unsafe {
        let mut raw = std::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) != 0 {
            let _token = OwnedHandle::from_raw_handle(raw);
            anyhow::bail!("Thread impersonation is unsupported");
        }
        ensure!(
            GetLastError() == ERROR_NO_TOKEN,
            "Thread identity unavailable"
        );
    }
    Ok(())
}

pub(super) fn image_sha256(path: &Path) -> Result<String> {
    image_sha256_with_guard(path, || Ok(()))
}

fn live(cancel: &CancellationToken, deadline: Instant) -> Result<()> {
    ensure!(
        !cancel.is_cancelled() && Instant::now() < deadline,
        "Peer verification expired"
    );
    Ok(())
}

fn image_sha256_with_guard(path: &Path, mut guard: impl FnMut() -> Result<()>) -> Result<String> {
    guard()?;
    let mut file = fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= 512 * 1024 * 1024,
        "Peer image too large"
    );
    let mut hash = Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        guard()?;
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= 512 * 1024 * 1024, "Peer image too large");
        hash.update(&chunk[..n]);
    }
    guard()?;
    Ok(format!("{:x}", hash.finalize()))
}

fn program_files() -> Result<PathBuf> {
    unsafe {
        let mut raw = std::ptr::null_mut();
        ensure!(
            SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut raw) == 0
                && !raw.is_null(),
            "Program Files unavailable"
        );
        let len = (0..32768)
            .find(|&i| *raw.add(i) == 0)
            .ok_or_else(|| anyhow::anyhow!("Program Files path too long"))?;
        let wide = std::slice::from_raw_parts(raw, len).to_vec();
        CoTaskMemFree(raw.cast());
        let path = PathBuf::from(String::from_utf16(&wide)?);
        Ok(fs::canonicalize(path)?)
    }
}

fn trusted_docker_path(path: &Path) -> Result<()> {
    let root = program_files()?.join("Docker");
    ensure!(
        path.starts_with(&root),
        "Docker peer outside trusted installation"
    );
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    ensure!(
        name.eq_ignore_ascii_case("com.docker.backend.exe")
            || name.eq_ignore_ascii_case("dockerd.exe"),
        "Unexpected Docker peer image"
    );
    Ok(())
}

fn signed_image(path: &Path) -> Result<()> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    unsafe {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
        let publisher = if result == 0 {
            let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            let signer = if provider.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
            };
            let cert = if signer.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvCertFromChain(signer, 0)
            };
            if cert.is_null() || (*cert).pCert.is_null() {
                None
            } else {
                let mut name = [0_u16; 256];
                let n = CertGetNameStringW(
                    (*cert).pCert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    std::ptr::null(),
                    name.as_mut_ptr(),
                    name.len() as u32,
                );
                if n <= 1 || n as usize > name.len() {
                    None
                } else {
                    String::from_utf16(&name[..n as usize - 1]).ok()
                }
            }
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
        ensure!(result == 0, "Docker peer signature untrusted");
        ensure!(
            publisher.as_deref().is_some_and(|name| {
                ["Docker Inc", "Docker Inc.", "Docker, Inc", "Docker, Inc."]
                    .iter()
                    .any(|expected| name.eq_ignore_ascii_case(expected))
            }),
            "Docker peer publisher mismatch"
        );
    }
    Ok(())
}

fn peer_process(pipe: &OwnedHandle) -> Result<(OwnedHandle, PathBuf, u32)> {
    unsafe {
        let mut pid = 0_u32;
        ensure!(
            GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) != 0 && pid != 0,
            "Docker pipe peer unavailable"
        );
        let raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        ensure!(!raw.is_null(), "Docker pipe peer inaccessible");
        let process = OwnedHandle::from_raw_handle(raw);
        let mut wide = vec![0_u16; 32768];
        let mut len = wide.len() as u32;
        ensure!(
            QueryFullProcessImageNameW(process.as_raw_handle(), 0, wide.as_mut_ptr(), &mut len)
                != 0,
            "Docker pipe peer image unavailable"
        );
        let image = fs::canonicalize(PathBuf::from(String::from_utf16(&wide[..len as usize])?))?;
        Ok((process, image, pid))
    }
}

pub(super) fn verify_pipe_peer(
    pipe: &OwnedHandle,
    pipe_path: &str,
    reviewed_image_sha256: &str,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<OwnedHandle> {
    live(cancel, deadline)?;
    reject_thread_impersonation()?;
    ensure!(
        reviewed_image_sha256.len() == 64
            && reviewed_image_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid reviewed peer hash"
    );
    let (process, image, pid) = peer_process(pipe)?;
    live(cancel, deadline)?;
    #[cfg(test)]
    let fixture = pipe_path.starts_with(r"\\.\pipe\relayne-fixture-")
        && pid == unsafe { GetCurrentProcessId() }
        && image == fs::canonicalize(std::env::current_exe()?)?;
    #[cfg(not(test))]
    let fixture = {
        let _ = (pipe_path, pid);
        false
    };
    if !fixture {
        trusted_docker_path(&image)?;
        live(cancel, deadline)?;
        signed_image(&image)?;
        live(cancel, deadline)?;
    }
    ensure!(
        image_sha256_with_guard(&image, || live(cancel, deadline))?
            .eq_ignore_ascii_case(reviewed_image_sha256),
        "Docker peer image changed"
    );
    live(cancel, deadline)?;
    // The process handle remains held for the entire capture, preventing PID
    // reuse from changing the identity associated with this pipe connection.
    Ok(process)
}
