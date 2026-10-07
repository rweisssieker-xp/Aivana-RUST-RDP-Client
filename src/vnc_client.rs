//! RFB 3.3/3.7/3.8 client for macOS Screen Sharing with a VNC password.
use crate::{
    ironrdp_client::IronRdpRuntime,
    models::{
        DiagnosticClass, DirtyRegion, EngineEvent, FrameUpdate, InputAction, MouseButton,
        SessionStatus,
    },
};
use anyhow::{Context, Result, bail, ensure};
use des::cipher::{BlockCipherEncrypt, KeyInit};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    sync::mpsc,
    thread,
    time::Duration,
};

const MAX_PIXELS: usize = 16_777_216;
fn frame_len(w: u16, h: u16) -> Result<usize> {
    let n = usize::from(w) * usize::from(h);
    ensure!(
        n > 0 && n <= MAX_PIXELS,
        "Unsupported VNC desktop size: {w}×{h}"
    );
    Ok(n * 4)
}
fn bytes<const N: usize>(r: &mut impl Read) -> Result<[u8; N]> {
    let mut b = [0; N];
    r.read_exact(&mut b)?;
    Ok(b)
}
fn u16be(r: &mut impl Read) -> Result<u16> {
    Ok(u16::from_be_bytes(bytes(r)?))
}
fn u32be(r: &mut impl Read) -> Result<u32> {
    Ok(u32::from_be_bytes(bytes(r)?))
}
fn string(r: &mut impl Read) -> Result<String> {
    let n = u32be(r)? as usize;
    ensure!(n <= 1_048_576, "VNC text exceeds limit");
    let mut b = vec![0; n];
    r.read_exact(&mut b)?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}
fn authenticate(s: &mut TcpStream, password: &str) -> Result<(u16, u16)> {
    ensure!(
        !password.is_empty() && password.is_ascii() && password.len() <= 8,
        "VNC requires a 1–8 character ASCII VNC password configured in macOS Screen Sharing computer settings (not the Mac account password)"
    );
    let version = bytes::<12>(s)?;
    ensure!(
        &version[..8] == b"RFB 003." && version[11] == b'\n',
        "Unsupported VNC protocol banner"
    );
    let minor = std::str::from_utf8(&version[8..11])?.parse::<u16>()?;
    let negotiated = if minor >= 8 {
        8
    } else if minor >= 7 {
        7
    } else if minor >= 3 {
        3
    } else {
        bail!("Unsupported RFB version")
    };
    s.write_all(format!("RFB 003.{negotiated:03}\n").as_bytes())?;
    if negotiated == 3 {
        let kind = u32be(s)?;
        if kind == 0 {
            bail!("VNC refused connection: {}", string(s)?);
        }
        ensure!(
            kind == 2,
            "Enable VNC password access in macOS Screen Sharing; server does not offer VNC password authentication"
        );
    } else {
        let n = bytes::<1>(s)?[0] as usize;
        if n == 0 {
            bail!("VNC refused connection: {}", string(s)?);
        }
        let mut kinds = vec![0; n];
        s.read_exact(&mut kinds)?;
        ensure!(
            kinds.contains(&2),
            "Enable VNC password access in macOS Screen Sharing; Apple account authentication is not supported"
        );
        s.write_all(&[2])?;
    }
    let mut challenge = bytes::<16>(s)?;
    let mut key = [0u8; 8];
    for (dst, src) in key.iter_mut().zip(password.bytes()) {
        *dst = src.reverse_bits();
    }
    let cipher = des::Des::new(&key.into());
    for chunk in challenge.chunks_exact_mut(8) {
        let mut block = des::cipher::Block::<des::Des>::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    s.write_all(&challenge)?;
    let status = u32be(s)?;
    if status != 0 {
        if negotiated >= 8 {
            bail!("VNC authentication failed: {}", string(s)?);
        }
        bail!("VNC authentication failed; check the Screen Sharing VNC password");
    }
    s.write_all(&[1])?; // Share the existing Mac desktop.
    let size = (u16be(s)?, u16be(s)?);
    frame_len(size.0, size.1)?;
    let _server_format = bytes::<16>(s)?;
    let _name = string(s)?;
    // 32 bpp little endian true colour: byte order R, G, B, unused.
    s.write_all(&[
        0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0,
    ])?;
    s.write_all(&[2, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 255, 255, 255, 33])?; // Raw, CopyRect, DesktopSize
    Ok(size)
}

fn request(s: &mut TcpStream, w: u16, h: u16, incremental: bool) -> Result<()> {
    let mut b = vec![3, u8::from(incremental), 0, 0, 0, 0];
    b.extend(w.to_be_bytes());
    b.extend(h.to_be_bytes());
    s.write_all(&b)?;
    Ok(())
}

fn read_frame(s: &mut impl Read, w: &mut u16, h: &mut u16, pixels: &mut Vec<u8>) -> Result<bool> {
    match bytes::<1>(s)?[0] {
        0 => {
            bytes::<1>(s)?;
            let count = u16be(s)?;
            ensure!(count <= 4096, "Too many VNC rectangles");
            for _ in 0..count {
                let x = u16be(s)? as usize;
                let y = u16be(s)? as usize;
                let rw = u16be(s)?;
                let rh = u16be(s)?;
                let encoding = u32be(s)? as i32;
                if encoding == -223 {
                    let len = frame_len(rw, rh)?;
                    *w = rw;
                    *h = rh;
                    pixels.clear();
                    pixels.resize(len, 0);
                    continue;
                }
                let width = usize::from(*w);
                let height = usize::from(*h);
                let rw = usize::from(rw);
                let rh = usize::from(rh);
                ensure!(
                    x + rw <= width && y + rh <= height,
                    "VNC rectangle outside desktop"
                );
                match encoding {
                    0 => {
                        for row in y..y + rh {
                            let start = (row * width + x) * 4;
                            let target = &mut pixels[start..start + rw * 4];
                            s.read_exact(target)?;
                            for pixel in target.chunks_exact_mut(4) {
                                pixel[3] = 255;
                            }
                        }
                    }
                    1 => {
                        let sx = u16be(s)? as usize;
                        let sy = u16be(s)? as usize;
                        ensure!(
                            sx + rw <= width && sy + rh <= height,
                            "VNC CopyRect outside desktop"
                        );
                        // Row order preserves overlapping source regions.
                        for i in 0..rh {
                            let row = if y > sy { rh - 1 - i } else { i };
                            let source = ((sy + row) * width + sx) * 4;
                            pixels
                                .copy_within(source..source + rw * 4, ((y + row) * width + x) * 4);
                        }
                    }
                    _ => bail!("Unsupported VNC encoding: {encoding}"),
                }
            }
            Ok(true)
        }
        2 => Ok(false), // Bell
        3 => {
            bytes::<3>(s)?;
            let _ = string(s)?;
            Ok(false)
        }
        kind => bail!("Unsupported VNC server message: {kind}"),
    }
}

pub fn run_session(runtime: IronRdpRuntime) {
    if let Err(error) = run(&runtime) {
        let _ = runtime.events.send(EngineEvent::Error {
            session_id: runtime.session_id,
            class: DiagnosticClass::Protocol,
            message: format!("VNC: {error:#}"),
        });
    }
}
fn run(runtime: &IronRdpRuntime) -> Result<()> {
    let profile = &runtime.profile;
    let mut socket = None;
    for addr in (profile.host.as_str(), profile.port)
        .to_socket_addrs()
        .context("Resolve VNC host")?
        .take(8)
    {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            socket = Some(s);
            break;
        }
    }
    let mut socket = socket.context("Cannot connect to VNC host")?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.set_nodelay(true)?;
    let (mut w, mut h) = authenticate(&mut socket, &profile.password)?;
    socket.set_read_timeout(None)?;
    request(&mut socket, w, h, false)?;
    let mut reader = socket.try_clone()?;
    let (tx, rx) = mpsc::sync_channel(2);
    let worker = thread::spawn(move || {
        let mut pixels = vec![0; frame_len(w, h).unwrap()];
        loop {
            match read_frame(&mut reader, &mut w, &mut h, &mut pixels) {
                Ok(false) => continue,
                Ok(true) => {
                    if tx.send(Ok((w, h, pixels.clone()))).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                    break;
                }
            }
        }
    });
    let result = (|| -> Result<()> {
        runtime.events.send(EngineEvent::StatusChanged {
            session_id: runtime.session_id,
            status: SessionStatus::Connected,
        })?;
        let mut buttons = 0;
        let mut last_size = (w, h);
        loop {
            // A bounded input batch keeps framebuffer consumption responsive.
            for _ in 0..128 {
                match runtime.input.try_recv() {
                    Ok(action) => input(&mut socket, action, &mut buttons)?,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            match rx.recv_timeout(Duration::from_millis(8)) {
                Ok(frame) => {
                    let (w, h, pixels) = frame?;
                    let hash = pixels
                        .iter()
                        .step_by(257)
                        .fold(0xcbf29ce484222325u64, |a, b| {
                            (a ^ u64::from(*b)).wrapping_mul(0x100000001b3)
                        });
                let frame = FrameUpdate {
                        session_id: runtime.session_id,
                        width: w,
                        height: h,
                        pixels_rgba: pixels,
                        dirty_regions: vec![DirtyRegion {
                            left: 0,
                            top: 0,
                            right: w - 1,
                            bottom: h - 1,
                        }],
                        frame_hash: hash,
                        captured_at: chrono::Utc::now(),
                };
                if let Some(frames) = &runtime.frames {
                    frames.publish(frame);
                } else {
                    runtime.events.send(EngineEvent::Frame(frame))?;
                }
                    request(&mut socket, w, h, last_size == (w, h))?;
                    last_size = (w, h);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => bail!("VNC reader stopped"),
            }
        }
    })();
    let _ = socket.shutdown(Shutdown::Both);
    drop(rx);
    let _ = worker.join();
    result
}

fn pointer(s: &mut impl Write, x: u16, y: u16, mask: u8) -> Result<()> {
    let mut b = vec![5, mask];
    b.extend(x.to_be_bytes());
    b.extend(y.to_be_bytes());
    s.write_all(&b)?;
    Ok(())
}
fn key(s: &mut impl Write, symbol: u32, pressed: bool) -> Result<()> {
    let mut b = vec![4, u8::from(pressed), 0, 0];
    b.extend(symbol.to_be_bytes());
    s.write_all(&b)?;
    Ok(())
}
fn button(b: MouseButton) -> u8 {
    match b {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 4,
    }
}
fn input(s: &mut impl Write, action: InputAction, mask: &mut u8) -> Result<()> {
    match action {
        InputAction::MovePointer { x, y } => pointer(s, x, y, *mask)?,
        InputAction::PointerButton {
            x,
            y,
            button: b,
            pressed,
        } => {
            if pressed {
                *mask |= button(b)
            } else {
                *mask &= !button(b)
            };
            pointer(s, x, y, *mask)?;
        }
        InputAction::Click { x, y, button: b } | InputAction::DoubleClick { x, y, button: b } => {
            let count = if matches!(action, InputAction::DoubleClick { .. }) {
                2
            } else {
                1
            };
            for _ in 0..count {
                pointer(s, x, y, *mask | button(b))?;
                pointer(s, x, y, *mask)?;
            }
        }
        InputAction::Scroll { x, y, delta } => {
            let bit = if delta > 0 { 8 } else { 16 };
            for _ in 0..(i32::from(delta).unsigned_abs().div_ceil(120)).min(20) {
                pointer(s, x, y, *mask | bit)?;
                pointer(s, x, y, *mask)?;
            }
        }
        InputAction::Key { scan_code, pressed } => {
            if let Some(symbol) = scan_keysym(scan_code) {
                key(s, symbol, pressed)?;
            }
        }
        InputAction::TypeText { text } => {
            for c in text.chars() {
                let symbol = char_keysym(c);
                key(s, symbol, true)?;
                key(s, symbol, false)?;
            }
        }
        InputAction::Hotkey { keys } => {
            let symbols: Vec<_> = keys
                .iter()
                .map(|k| named_keysym(k).with_context(|| format!("Unsupported VNC hotkey: {k}")))
                .collect::<Result<_>>()?;
            for symbol in &symbols {
                key(s, *symbol, true)?;
            }
            for symbol in symbols.iter().rev() {
                key(s, *symbol, false)?;
            }
        }
        _ => {} // RDP-only resize, clipboard files, and local orchestration actions.
    }
    Ok(())
}
fn char_keysym(c: char) -> u32 {
    match c {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        c if u32::from(c) <= 255 => u32::from(c),
        c => 0x01000000 | u32::from(c),
    }
}
fn named_keysym(k: &str) -> Option<u32> {
    let lower = k.to_ascii_lowercase();
    Some(match lower.as_str() {
        "ctrl" | "control" => 0xffe3,
        "alt" | "option" => 0xffe9,
        "shift" => 0xffe1,
        "win" | "windows" | "meta" | "cmd" | "command" => 0xffeb,
        "enter" | "return" => 0xff0d,
        "tab" => 0xff09,
        "esc" | "escape" => 0xff1b,
        "space" => 32,
        "backspace" => 0xff08,
        "delete" | "del" => 0xffff,
        "left" => 0xff51,
        "up" => 0xff52,
        "right" => 0xff53,
        "down" => 0xff54,
        "home" => 0xff50,
        "end" => 0xff57,
        "pageup" => 0xff55,
        "pagedown" => 0xff56,
        _ if lower.chars().count() == 1 => char_keysym(lower.chars().next()?),
        _ => return None,
    })
}
fn scan_keysym(scan: u16) -> Option<u32> {
    let chars = [
        (0x02, "1234567890-="),
        (0x10, "qwertyuiop[]"),
        (0x1e, "asdfghjkl;'`"),
        (0x2c, "zxcvbnm,./"),
    ];
    for (start, text) in chars {
        if scan >= start && usize::from(scan - start) < text.len() {
            return Some(u32::from(text.as_bytes()[usize::from(scan - start)]));
        }
    }
    Some(match scan {
        0x01 => 0xff1b,
        0x0e => 0xff08,
        0x0f => 0xff09,
        0x1c | 0x11c => 0xff0d,
        0x1d => 0xffe3,
        0x11d => 0xffe4,
        0x2a => 0xffe1,
        0x36 => 0xffe2,
        0x38 => 0xffe9,
        0x138 => 0xffea,
        0x15b => 0xffeb,
        0x15c => 0xffec,
        0x39 => 32,
        0x3a => 0xffe5,
        0x2b => 92,
        0x147 => 0xff50,
        0x148 => 0xff52,
        0x149 => 0xff55,
        0x14b => 0xff51,
        0x14d => 0xff53,
        0x14f => 0xff57,
        0x150 => 0xff54,
        0x151 => 0xff56,
        0x152 => 0xff63,
        0x153 => 0xffff,
        0x3b..=0x44 => 0xffbe + u32::from(scan - 0x3b),
        0x57 => 0xffc8,
        0x58 => 0xffc9,
        _ => return None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_framebuffers() {
        assert!(frame_len(0, 100).is_err());
        assert!(frame_len(65535, 65535).is_err());
        assert_eq!(frame_len(1920, 1080).unwrap(), 1920 * 1080 * 4);
    }

    #[test]
    fn maps_mac_modifiers_and_unicode() {
        assert_eq!(scan_keysym(0x15b), Some(0xffeb)); // Windows -> Command
        assert_eq!(scan_keysym(0x38), Some(0xffe9)); // Alt -> Option
        assert_eq!(scan_keysym(0x14b), Some(0xff51));
        assert_eq!(char_keysym('€'), 0x010020ac);
        assert_eq!(char_keysym('ä'), 0xe4);
    }

    fn rect_message(x: u16, y: u16, w: u16, h: u16, encoding: i32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 0, 0, 1];
        for v in [x, y, w, h] {
            b.extend(v.to_be_bytes());
        }
        b.extend(encoding.to_be_bytes());
        b.extend(payload);
        b
    }

    #[test]
    fn frame_decoder_handles_raw_overlap_resize_and_invalid_bounds() {
        let (mut w, mut h) = (2, 2);
        let mut pixels = vec![0; 16];
        let raw = rect_message(
            0,
            0,
            2,
            2,
            0,
            &[1, 2, 3, 0, 4, 5, 6, 0, 7, 8, 9, 0, 10, 11, 12, 0],
        );
        assert!(read_frame(&mut raw.as_slice(), &mut w, &mut h, &mut pixels).unwrap());
        assert_eq!(&pixels[..8], &[1, 2, 3, 255, 4, 5, 6, 255]);
        let copy = rect_message(0, 1, 2, 1, 1, &[0, 0, 0, 0]);
        read_frame(&mut copy.as_slice(), &mut w, &mut h, &mut pixels).unwrap();
        assert_eq!(pixels[..8], pixels[8..]);
        let invalid = rect_message(1, 0, 2, 1, 0, &[]);
        assert!(read_frame(&mut invalid.as_slice(), &mut w, &mut h, &mut pixels).is_err());
        let resize = rect_message(0, 0, 3, 1, -223, &[]);
        read_frame(&mut resize.as_slice(), &mut w, &mut h, &mut pixels).unwrap();
        assert_eq!((w, h, pixels.len()), (3, 1, 12));
        let truncated = rect_message(0, 0, 1, 1, 0, &[1]);
        assert!(read_frame(&mut truncated.as_slice(), &mut w, &mut h, &mut pixels).is_err());
    }

    #[test]
    fn input_keeps_drag_button_and_releases_command_hotkey() {
        let mut wire = Vec::new();
        let mut mask = 0;
        input(
            &mut wire,
            InputAction::PointerButton {
                x: 2,
                y: 3,
                button: MouseButton::Left,
                pressed: true,
            },
            &mut mask,
        )
        .unwrap();
        input(
            &mut wire,
            InputAction::MovePointer { x: 4, y: 5 },
            &mut mask,
        )
        .unwrap();
        input(
            &mut wire,
            InputAction::PointerButton {
                x: 4,
                y: 5,
                button: MouseButton::Left,
                pressed: false,
            },
            &mut mask,
        )
        .unwrap();
        assert_eq!(
            wire,
            vec![5, 1, 0, 2, 0, 3, 5, 1, 0, 4, 0, 5, 5, 0, 0, 4, 0, 5]
        );
        wire.clear();
        input(
            &mut wire,
            InputAction::Hotkey {
                keys: vec!["Command".into(), "c".into()],
            },
            &mut mask,
        )
        .unwrap();
        assert_eq!(&wire[..8], &[4, 1, 0, 0, 0, 0, 255, 235]);
        assert_eq!(&wire[24..], &[4, 0, 0, 0, 0, 0, 255, 235]);
    }

    #[test]
    fn local_server_exercises_auth_frame_input_and_disconnect() {
        use crate::models::ConnectionProfile;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"RFB 003.008\n").unwrap();
            assert_eq!(bytes::<12>(&mut s).unwrap(), *b"RFB 003.008\n");
            s.write_all(&[2, 1, 2]).unwrap(); // None offered too; must choose password.
            assert_eq!(bytes::<1>(&mut s).unwrap(), [2]);
            s.write_all(&[0x5a; 16]).unwrap();
            let response = bytes::<16>(&mut s).unwrap();
            // Independent DES/ECB known answer for reversed-bit "testpass" key.
            assert_eq!(
                response,
                [
                    0xe0, 0x0c, 0x24, 0xc9, 0xc0, 0xb8, 0x96, 0x4c, 0xe0, 0x0c, 0x24, 0xc9, 0xc0,
                    0xb8, 0x96, 0x4c
                ]
            );
            s.write_all(&[0, 0, 0, 0]).unwrap();
            assert_eq!(bytes::<1>(&mut s).unwrap(), [1]);
            s.write_all(&[0, 2, 0, 1]).unwrap();
            s.write_all(&[0; 16]).unwrap();
            s.write_all(&[0, 0, 0, 0]).unwrap();
            assert_eq!(bytes::<20>(&mut s).unwrap()[4..8], [32, 24, 0, 1]);
            assert_eq!(&bytes::<16>(&mut s).unwrap()[..4], &[2, 0, 0, 3]);
            assert_eq!(bytes::<10>(&mut s).unwrap(), [3, 0, 0, 0, 0, 0, 0, 2, 0, 1]);
            s.write_all(&rect_message(0, 0, 2, 1, 0, &[1, 2, 3, 0, 4, 5, 6, 0]))
                .unwrap();
            assert_eq!(bytes::<10>(&mut s).unwrap()[1], 1);
            assert_eq!(bytes::<6>(&mut s).unwrap(), [5, 0, 0, 1, 0, 0]);
            assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
        });
        let mut profile = ConnectionProfile::sample("Mac", "127.0.0.1", "test", false);
        profile.port = port;
        profile.password = "testpass".into();
        let (events, rx) = mpsc::channel();
        let (input, inputs) = mpsc::channel();
        let runtime = IronRdpRuntime {
            frames: None,
            profile,
            session_id: uuid::Uuid::new_v4(),
            events,
            input: inputs,
        };
        let client = thread::spawn(move || run_session(runtime));
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            EngineEvent::StatusChanged {
                status: SessionStatus::Connected,
                ..
            }
        ));
        let EngineEvent::Frame(frame) = rx.recv_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("expected frame")
        };
        assert_eq!(frame.pixels_rgba, vec![1, 2, 3, 255, 4, 5, 6, 255]);
        input.send(InputAction::MovePointer { x: 1, y: 0 }).unwrap();
        drop(input);
        client.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn rejects_servers_without_password_authentication() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            s.write_all(b"RFB 003.008\n").unwrap();
            bytes::<12>(&mut s).unwrap();
            s.write_all(&[1, 1]).unwrap(); // Unauthenticated access only.
        });
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert!(
            authenticate(&mut socket, "testpass")
                .unwrap_err()
                .to_string()
                .contains("VNC password")
        );
        server.join().unwrap();
    }
}
