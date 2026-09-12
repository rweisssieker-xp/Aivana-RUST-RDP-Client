//! Interactive OpenSSH over a native pseudoterminal. Credentials stay in the PTY.
use crate::operations::Endpoint;
use portable_pty::{ChildKiller, CommandBuilder, PtySize};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

pub struct Terminal {
    pub parser: Arc<Mutex<vt100::Parser<TerminalCallbacks>>>,
    pub status: Arc<Mutex<String>>,
    commands: mpsc::SyncSender<Command>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    size: (u16, u16),
}
enum Command {
    Input(Vec<u8>),
    Resize(u16, u16),
}
impl Terminal {
    pub fn connect(endpoint: &Endpoint) -> anyhow::Result<Self> {
        Endpoint::new(&endpoint.host, &endpoint.user, endpoint.port).map_err(anyhow::Error::msg)?;
        let mut command = CommandBuilder::new(if cfg!(windows) { "ssh.exe" } else { "ssh" });
        command.args([
            "-tt",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-p",
            &endpoint.port.to_string(),
        ]);
        if !endpoint.user.is_empty() {
            command.args(["-l", &endpoint.user]);
        }
        command.arg(&endpoint.host);
        command.env("TERM", "xterm-256color");
        Self::spawn(command)
    }
    fn spawn(command: CommandBuilder) -> anyhow::Result<Self> {
        let pair = portable_pty::native_pty_system().openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;
        let mut child = pair.slave.spawn_command(command)?;
        let killer = child.clone_killer();
        drop(pair.slave);
        let (commands, receiver) = mpsc::sync_channel(64);
        let parser = Arc::new(Mutex::new(vt100::Parser::new_with_callbacks(
            24,
            80,
            2000,
            TerminalCallbacks {
                commands: commands.clone(),
            },
        )));
        let status = Arc::new(Mutex::new("OpenSSH gestartet".into()));
        let output = parser.clone();
        thread::spawn(move || {
            let mut bytes = [0u8; 8192];
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut parser) = output.lock() {
                            parser.process(&bytes[..n]);
                        } else {
                            break;
                        }
                    }
                }
            }
        });
        let shared_status = status.clone();
        let shared_parser = parser.clone();
        thread::spawn(move || {
            loop {
                match child.try_wait() {
                    Ok(Some(exit)) => {
                        if let Ok(mut s) = shared_status.lock() {
                            *s = format!("Beendet: {exit}");
                        }
                        break;
                    }
                    Err(_) => break,
                    Ok(None) => {}
                }
                let result = match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(Command::Input(bytes)) => writer
                        .write_all(&bytes)
                        .and_then(|_| writer.flush())
                        .map_err(anyhow::Error::from),
                    Ok(Command::Resize(rows, cols)) => {
                        let result = pair.master.resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                        if result.is_ok() {
                            if let Ok(mut p) = shared_parser.lock() {
                                p.screen_mut().set_size(rows, cols);
                            }
                        }
                        result
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                if result.is_err() {
                    break;
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        });
        Ok(Self {
            parser,
            status,
            commands,
            killer,
            size: (24, 80),
        })
    }
    pub fn input(&self, bytes: Vec<u8>) -> Result<(), String> {
        if bytes.len() > 65536 {
            return Err("Eingabe ist auf 64 KiB begrenzt.".into());
        }
        self.commands
            .try_send(Command::Input(bytes))
            .map_err(|_| "Terminal-Eingabepuffer voll oder Sitzung beendet.".into())
    }
    pub fn resize(&mut self, rows: u16, cols: u16) {
        let size = (rows.clamp(2, 160), cols.clamp(10, 320));
        if size != self.size
            && self
                .commands
                .try_send(Command::Resize(size.0, size.1))
                .is_ok()
        {
            self.size = size;
        }
    }
    pub fn close(&mut self) {
        let _ = self.killer.kill();
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminal_interprets_cursor_and_erase() {
        let mut parser = vt100::Parser::new(24, 80, 100);
        parser.process(b"hello\rworld\x1b[2;1Hnext\x1b[2Kdone");
        assert!(parser.screen().contents().starts_with("world"));
        assert!(parser.screen().contents().contains("done"));
        assert!(!parser.screen().contents().contains("hello"));
    }
    #[test]
    fn local_pty_emits_output_and_exits() {
        let mut command =
            portable_pty::CommandBuilder::new(if cfg!(windows) { "cmd.exe" } else { "sh" });
        if cfg!(windows) {
            command.args(["/c", "echo RELAYNE_PTY_OK"]);
        } else {
            command.args(["-c", "printf RELAYNE_PTY_OK"]);
        }
        let terminal = super::Terminal::spawn(command).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if terminal
                .parser
                .lock()
                .unwrap()
                .screen()
                .contents()
                .contains("RELAYNE_PTY_OK")
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "PTY output timeout");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

/// Answer terminal status/device queries; OSC clipboard operations remain disabled.
pub struct TerminalCallbacks {
    commands: mpsc::SyncSender<Command>,
}
impl vt100::Callbacks for TerminalCallbacks {
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        _: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        let parameter = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        let answer = match (i1, c, parameter) {
            (None, 'n', 5) => Some("\x1b[0n".to_owned()),
            (None, 'n', 6) => {
                let (row, col) = screen.cursor_position();
                Some(format!("\x1b[{};{}R", row + 1, col + 1))
            }
            (None, 'c', 0) => Some("\x1b[?1;2c".to_owned()),
            _ => None,
        };
        if let Some(answer) = answer {
            let _ = self.commands.try_send(Command::Input(answer.into_bytes()));
        }
    }
}

