//! Docker Engine reads over one pinned local named-pipe handle. No CLI/config reload
//! occurs after the reviewed context endpoint and process-token identity are bound.
use super::containers::{docker_identity, parse_docker_inspect, parse_docker_stats, unavailable};
use crate::helper::{
    capability::{ProbeOutput, ProbeRequest},
    credentials::SecretResolver,
    evidence::EvidenceStatus,
    manifest::CapabilityId,
    scope::BoundScope,
};
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

const MAX_META: usize = 64 * 1024;
const MAX_RESPONSE: usize = 128 * 1024;
const MAX_HEADERS: usize = 8 * 1024;
static PEER_VERIFICATIONS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));

#[derive(Deserialize)]
struct ContextMeta {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Endpoints")]
    endpoints: Endpoints,
}
#[derive(Deserialize)]
struct Endpoints {
    docker: DockerEndpoint,
}
#[derive(Deserialize)]
struct DockerEndpoint {
    #[serde(rename = "Host")]
    host: String,
}

pub(super) fn context_meta_root() -> Result<PathBuf> {
    ensure!(
        std::env::var_os("DOCKER_CONFIG").is_none(),
        "Ambient Docker config is unsupported"
    );
    let home = std::env::var_os("USERPROFILE")
        .ok_or_else(|| anyhow::anyhow!("User profile unavailable"))?;
    Ok(PathBuf::from(home)
        .join(".docker")
        .join("contexts")
        .join("meta"))
}
pub(super) fn load_context(root: &Path, name: &str) -> Result<String> {
    if name == "default" {
        return Ok("npipe:////./pipe/docker_engine".into());
    }
    let mut found = None;
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        count += 1;
        ensure!(count <= 64, "Too many Docker contexts");
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let mut file = fs::File::open(entry.path().join("meta.json"))?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_META + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_META, "Docker context too large");
        let meta: ContextMeta = serde_json::from_slice(&bytes)?;
        if meta.name == name {
            ensure!(found.is_none(), "Duplicate Docker context");
            found = Some(meta.endpoints.docker.host);
        }
    }
    found.ok_or_else(|| anyhow::anyhow!("Docker context missing"))
}
pub(super) fn pipe_path(uri: &str) -> Result<String> {
    let name = uri
        .strip_prefix("npipe:////./pipe/")
        .ok_or_else(|| anyhow::anyhow!("Remote Docker endpoint unsupported"))?;
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "Invalid local pipe name"
    );
    Ok(format!(r"\\.\pipe\{name}"))
}

pub(super) fn reviewed_context(input: &str) -> Result<(&str, &str, &str)> {
    let mut parts = input.split('|');
    let (Some(uri), Some(daemon_id), Some(peer_sha), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        anyhow::bail!("Reviewed Docker pipe, daemon and peer required");
    };
    pipe_path(uri)?;
    ensure!(
        !daemon_id.is_empty() && daemon_id.len() <= 128,
        "Invalid daemon ID"
    );
    ensure!(
        peer_sha.len() == 64 && peer_sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid peer image digest"
    );
    Ok((uri, daemon_id, peer_sha))
}

#[cfg(windows)]
pub(super) fn process_sid_digest() -> Result<String> {
    super::docker_peer::reject_thread_impersonation()?;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Security::{GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    // SAFETY: all handles are owned, the TOKEN_USER buffer remains alive while its SID is read.
    unsafe {
        let mut raw = std::ptr::null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) != 0,
            "Token unavailable"
        );
        let token = OwnedHandle::from_raw_handle(raw);
        let mut size = 0_u32;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut size,
        );
        ensure!(
            size as usize >= std::mem::size_of::<TOKEN_USER>() && size <= 4096,
            "Token size invalid"
        );
        let words = (size as usize).div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        ensure!(
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                size,
                &mut size
            ) != 0,
            "Token unavailable"
        );
        let user = &*(storage.as_ptr() as *const TOKEN_USER);
        let sid_len = GetLengthSid(user.User.Sid);
        ensure!(sid_len > 0 && sid_len <= 256, "SID unavailable");
        let sid = std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), sid_len as usize);
        let mut hash = Sha256::new();
        hash.update(b"relayne-local-token-sid-v1\0");
        hash.update(sid);
        Ok(format!("{:x}", hash.finalize()))
    }
}

pub(super) struct PipeHttp {
    io: NamedPipeClient,
    _peer: OwnedHandle,
    deadline: Instant,
    pending: Vec<u8>,
}
impl PipeHttp {
    #[cfg(test)]
    pub(super) async fn open_test(path: &str, reviewed_image_sha256: &str) -> Result<Self> {
        Self::open(
            path,
            reviewed_image_sha256,
            &CancellationToken::new(),
            Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
    }

    pub(super) async fn open(
        path: &str,
        reviewed_image_sha256: &str,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Self> {
        Self::open_with(
            path,
            reviewed_image_sha256,
            cancel,
            deadline,
            super::docker_peer::verify_pipe_peer,
        )
        .await
    }

    async fn open_with<F>(
        path: &str,
        reviewed_image_sha256: &str,
        cancel: &CancellationToken,
        deadline: Instant,
        verifier: F,
    ) -> Result<Self>
    where
        F: FnOnce(&OwnedHandle, &str, &str, &CancellationToken, Instant) -> Result<OwnedHandle>
            + Send
            + 'static,
    {
        ensure!(
            !cancel.is_cancelled() && Instant::now() < deadline,
            "Docker capture expired"
        );
        super::docker_peer::reject_thread_impersonation()?;
        let mut options = ClientOptions::new();
        options
            .security_qos_flags(windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION);
        let io = options.open(path)?;
        // SAFETY: io owns the source handle until duplication completes.
        let identity_handle =
            unsafe { BorrowedHandle::borrow_raw(io.as_raw_handle()) }.try_clone_to_owned()?;
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => anyhow::bail!("Canceled"),
            _ = tokio::time::sleep_until(deadline.into()) => anyhow::bail!("Docker capture expired"),
            permit = PEER_VERIFICATIONS.clone().acquire_owned() => permit?,
        };
        ensure!(
            !cancel.is_cancelled() && Instant::now() < deadline,
            "Docker capture expired"
        );
        let path = path.to_owned();
        let reviewed_image_sha256 = reviewed_image_sha256.to_owned();
        let blocking_cancel = cancel.clone();
        let verification = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verifier(
                &identity_handle,
                &path,
                &reviewed_image_sha256,
                &blocking_cancel,
                deadline,
            )
        });
        let peer = tokio::select! {
            biased;
            _ = cancel.cancelled() => anyhow::bail!("Canceled"),
            _ = tokio::time::sleep_until(deadline.into()) => anyhow::bail!("Docker capture expired"),
            result = verification => result??,
        };
        ensure!(
            !cancel.is_cancelled() && Instant::now() < deadline,
            "Docker capture expired"
        );
        Ok(Self {
            io,
            _peer: peer,
            deadline,
            pending: Vec::new(),
        })
    }
    async fn receive(&mut self, cancel: &CancellationToken) -> Result<()> {
        let mut chunk = [0_u8; 4096];
        let n = tokio::select! {
            _ = cancel.cancelled() => anyhow::bail!("Canceled"),
            result = self.io.read(&mut chunk) => result?,
        };
        ensure!(n > 0, "Pipe closed");
        ensure!(
            self.pending
                .len()
                .checked_add(n)
                .is_some_and(|total| total <= MAX_RESPONSE + MAX_HEADERS),
            "Docker response overflow"
        );
        self.pending.extend_from_slice(&chunk[..n]);
        Ok(())
    }
    async fn take_exact(&mut self, n: usize, cancel: &CancellationToken) -> Result<Vec<u8>> {
        ensure!(n <= MAX_RESPONSE, "Docker response overflow");
        while self.pending.len() < n {
            self.receive(cancel).await?;
        }
        Ok(self.pending.drain(..n).collect())
    }
    async fn line(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
        loop {
            if let Some(i) = self.pending.windows(2).position(|w| w == b"\r\n") {
                ensure!(i <= MAX_HEADERS, "Docker header too large");
                let line = self.pending.drain(..i).collect();
                self.pending.drain(..2);
                return Ok(line);
            }
            ensure!(self.pending.len() <= MAX_HEADERS, "Docker header too large");
            self.receive(cancel).await?;
        }
    }
    pub(super) async fn get(
        &mut self,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<(u16, Vec<u8>)> {
        super::docker_peer::reject_thread_impersonation()?;
        ensure!(
            !cancel.is_cancelled() && Instant::now() < self.deadline,
            "Docker capture expired"
        );
        ensure!(
            path.starts_with('/')
                && path.len() <= 256
                && path.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid API path"
        );
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: keep-alive\r\nAccept: application/json\r\n\r\n"
        );
        tokio::select! {
            biased;
            _ = cancel.cancelled() => anyhow::bail!("Canceled"),
            _ = tokio::time::sleep_until(self.deadline.into()) => anyhow::bail!("Docker capture expired"),
            result = self.io.write_all(request.as_bytes()) => result?,
        }
        let status = self.line(cancel).await?;
        let mut header_bytes = status
            .len()
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("Docker headers overflow"))?;
        ensure!(header_bytes <= MAX_HEADERS, "Docker headers overflow");
        let status = std::str::from_utf8(&status)?;
        let mut words = status.split_ascii_whitespace();
        ensure!(
            matches!(words.next(), Some("HTTP/1.1" | "HTTP/1.0")),
            "Invalid Docker response"
        );
        let code: u16 = words
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing Docker status"))?
            .parse()?;
        let mut length = None;
        let mut chunked = false;
        loop {
            let line = self.line(cancel).await?;
            header_bytes = header_bytes
                .checked_add(line.len() + 2)
                .ok_or_else(|| anyhow::anyhow!("Docker headers overflow"))?;
            ensure!(header_bytes <= MAX_HEADERS, "Docker headers overflow");
            if line.is_empty() {
                break;
            }
            let text = std::str::from_utf8(&line)?;
            let (key, val) = text
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Malformed header"))?;
            let val = val.trim();
            if key.eq_ignore_ascii_case("content-length") {
                ensure!(length.is_none(), "Duplicate length");
                let n: usize = val.parse()?;
                ensure!(n <= MAX_RESPONSE, "Docker response overflow");
                length = Some(n);
            } else if key.eq_ignore_ascii_case("transfer-encoding") {
                ensure!(
                    val.eq_ignore_ascii_case("chunked"),
                    "Unsupported transfer encoding"
                );
                chunked = true;
            }
        }
        ensure!(!(chunked && length.is_some()), "Ambiguous response framing");
        let body = if chunked {
            let mut body = Vec::new();
            loop {
                let line = self.line(cancel).await?;
                let size = usize::from_str_radix(
                    std::str::from_utf8(&line)?.split(';').next().unwrap_or(""),
                    16,
                )?;
                ensure!(
                    body.len()
                        .checked_add(size)
                        .is_some_and(|n| n <= MAX_RESPONSE),
                    "Docker response overflow"
                );
                if size == 0 {
                    ensure!(self.line(cancel).await?.is_empty(), "Unsupported trailers");
                    break;
                }
                body.extend_from_slice(&self.take_exact(size, cancel).await?);
                ensure!(
                    self.take_exact(2, cancel).await? == b"\r\n",
                    "Malformed chunk"
                );
            }
            body
        } else {
            self.take_exact(
                length.ok_or_else(|| anyhow::anyhow!("Unframed Docker response"))?,
                cancel,
            )
            .await?
        };
        Ok((code, body))
    }
}

pub(super) async fn collect(
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
) -> Result<ProbeOutput> {
    let (root, sid) = match context_meta_root().and_then(|root| Ok((root, process_sid_digest()?))) {
        Ok(v) => v,
        Err(_) => {
            return Ok(unavailable(
                "docker:configuration",
                EvidenceStatus::Unavailable,
            ));
        }
    };
    collect_from_root(request, secrets, cancel, &root, &sid).await
}

pub(super) async fn collect_from_root(
    request: &ProbeRequest,
    secrets: &dyn SecretResolver,
    cancel: CancellationToken,
    root: &Path,
    sid: &str,
) -> Result<ProbeOutput> {
    let BoundScope::Docker {
        daemon_context,
        container_id,
        credential,
    } = &request.scope
    else {
        anyhow::bail!("Scope mismatch")
    };
    let subject = format!("docker:{daemon_context}:{container_id}");
    let cred = credential
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Credential missing"))?;
    let (reviewed_uri, reviewed_id, reviewed_peer_sha256) = match reviewed_context(&cred.context) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    let actual_uri = match load_context(root, daemon_context) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    if actual_uri != reviewed_uri {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let path = match pipe_path(reviewed_uri) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    let secret = match secrets.resolve(cred, cred.purpose) {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    if sid != cred.principal || secret.username() != cred.principal {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let expires_at = request.requested_at
        + chrono::Duration::seconds(
            request
                .deadline_secs
                .unwrap_or(super::super::worker::DEFAULT_DEADLINE_SECS) as i64,
        );
    let remaining = match expires_at
        .signed_duration_since(chrono::Utc::now())
        .to_std()
    {
        Ok(value) if !value.is_zero() => value,
        _ => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    let deadline = Instant::now() + remaining;
    let mut pipe = match PipeHttp::open(&path, reviewed_peer_sha256, &cancel, deadline).await {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    let (code, info) = match pipe.get("/info", &cancel).await {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    if code == 401 || code == 403 {
        return Ok(unavailable(&subject, EvidenceStatus::Denied));
    }
    if code != 200 || docker_identity(&info, reviewed_id).is_err() {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let path = match request.capability_id {
        CapabilityId::DockerContainerInspect => format!("/containers/{container_id}/json"),
        CapabilityId::DockerContainerStats => {
            format!("/containers/{container_id}/stats?stream=false&one-shot=true")
        }
        _ => anyhow::bail!("Capability mismatch"),
    };
    let (code, bytes) = match pipe.get(&path, &cancel).await {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    if code == 401 || code == 403 {
        return Ok(unavailable(&subject, EvidenceStatus::Denied));
    }
    if code != 200 {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let (code, info) = match pipe.get("/info", &cancel).await {
        Ok(v) => v,
        Err(_) => return Ok(unavailable(&subject, EvidenceStatus::Unavailable)),
    };
    if code != 200
        || docker_identity(&info, reviewed_id).is_err()
        || secrets.resolve(cred, cred.purpose).is_err()
    {
        return Ok(unavailable(&subject, EvidenceStatus::Unavailable));
    }
    let mut parsed = match request.capability_id {
        CapabilityId::DockerContainerInspect => parse_docker_inspect(&bytes, container_id),
        _ => parse_docker_stats(&bytes, container_id),
    }
    .unwrap_or_else(|_| unavailable(&subject, EvidenceStatus::Partial));
    // The pipe and OS principal are pinned, but Engine's JSON ID alone is not a
    // cryptographic peer attestation. Preserve the read as ineligible diagnosis.
    if parsed.status == EvidenceStatus::Complete {
        parsed.status = EvidenceStatus::Partial;
    }
    Ok(parsed)
}

#[cfg(test)]
mod peer_verification_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use uuid::Uuid;

    fn fixture() -> (String, NamedPipeServer) {
        let path = format!(r"\\.\pipe\relayne-fixture-{}", Uuid::new_v4());
        let server = ServerOptions::new().create(&path).unwrap();
        // Keep the server live while the client opens; the caller also uses the
        // returned handle to verify that no HTTP request reached the peer.
        (path, server)
    }

    #[test]
    fn slow_peer_verification_obeys_deadline_and_cancel_without_writing() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for cancel_first in [false, true] {
                let (path, mut server) = fixture();
                let connected = tokio::spawn(async move {
                    server.connect().await.unwrap();
                    server
                });
                let cancel = CancellationToken::new();
                let trigger = cancel.clone();
                let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let started_in_verifier = started.clone();
                let reviewed_hash = "a".repeat(64);
                let deadline = Instant::now() + std::time::Duration::from_millis(70);
                if cancel_first {
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(35)).await;
                        trigger.cancel();
                    });
                }
                let opened = PipeHttp::open_with(
                    &path,
                    &reviewed_hash,
                    &cancel,
                    deadline,
                    move |handle, _, _, _, _| {
                        started_in_verifier.store(true, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(220));
                        Ok(handle.try_clone()?)
                    },
                );
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(150), opened)
                        .await
                        .unwrap()
                        .is_err()
                );
                assert!(started.load(Ordering::SeqCst));
                let mut server = connected.await.unwrap();
                let mut bytes = [0_u8; 8];
                let read = tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    server.read(&mut bytes),
                )
                .await;
                assert!(
                    matches!(read, Ok(Ok(0)) | Err(_)),
                    "expired verification wrote HTTP bytes"
                );
            }
        });
    }

    #[test]
    fn canceled_verifications_keep_both_global_slots_occupied() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let active = Arc::new(AtomicUsize::new(0));
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
            let mut tasks = Vec::new();
            let mut servers = Vec::new();
            let mut tokens = Vec::new();
            for _ in 0..2 {
                let (path, server) = fixture();
                servers.push(server);
                let cancel = CancellationToken::new();
                tokens.push(cancel.clone());
                let active = active.clone();
                let release_rx = release_rx.clone();
                tasks.push(tokio::spawn(async move {
                    PipeHttp::open_with(
                        &path,
                        &"a".repeat(64),
                        &cancel,
                        Instant::now() + std::time::Duration::from_secs(2),
                        move |_, _, _, _, _| {
                            active.fetch_add(1, Ordering::SeqCst);
                            release_rx.lock().unwrap().recv().unwrap();
                            active.fetch_sub(1, Ordering::SeqCst);
                            anyhow::bail!("Fixture verifier")
                        },
                    )
                    .await
                }));
            }
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while active.load(Ordering::SeqCst) != 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            for token in &tokens {
                token.cancel();
            }
            for task in tasks {
                assert!(task.await.unwrap().is_err());
            }
            assert_eq!(active.load(Ordering::SeqCst), 2);

            let (path, server) = fixture();
            servers.push(server);
            let entered = Arc::new(AtomicUsize::new(0));
            let entered_verifier = entered.clone();
            let queued = PipeHttp::open_with(
                &path,
                &"a".repeat(64),
                &CancellationToken::new(),
                Instant::now() + std::time::Duration::from_millis(60),
                move |_, _, _, _, _| {
                    entered_verifier.fetch_add(1, Ordering::SeqCst);
                    anyhow::bail!("Unexpected verifier entry")
                },
            )
            .await;
            assert!(queued.is_err());
            assert_eq!(entered.load(Ordering::SeqCst), 0);
            assert_eq!(active.load(Ordering::SeqCst), 2);
            release_tx.send(()).unwrap();
            release_tx.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while active.load(Ordering::SeqCst) != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        });
    }
}
