//! MS-RDPEAI AUDIO_INPUT DVC. Negotiates PCM16 and captures through the native default microphone.

//! Protocol reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeai/c4e53155-f577-43c6-ac1d-fad49540d02d

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{Context, Result, bail};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use ironrdp::{
    core::{Encode, EncodeResult, WriteCursor, impl_as_any},
    dvc::{DvcClientProcessor, DvcEncode, DvcMessage, DvcProcessor},
    pdu::PduResult,
};

use crate::models::EngineEvent;

static SESSIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<uuid::Uuid, Arc<AtomicBool>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
fn session_flag(session: uuid::Uuid) -> Arc<AtomicBool> {
    SESSIONS
        .lock()
        .unwrap()
        .entry(session)
        .or_insert_with(|| Arc::new(AtomicBool::new(false)))
        .clone()
}
pub fn stop_session(session: uuid::Uuid) {
    session_flag(session).store(true, Ordering::SeqCst);
}
pub fn allow_session(session: uuid::Uuid) {
    SESSIONS
        .lock()
        .unwrap()
        .insert(session, Arc::new(AtomicBool::new(false)));
}
#[derive(Debug)]

pub struct AudioPacket(pub Vec<u8>);

pub struct CapturedAudio {
    pub generation: u64,
    pub packet: AudioPacket,
}

impl Encode for AudioPacket {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ironrdp::core::ensure_size!(in:dst,size:self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }

    fn size(&self) -> usize {
        self.0.len()
    }
    fn name(&self) -> &'static str {
        "AUDIO_INPUT"
    }
}

impl DvcEncode for AudioPacket {}

#[derive(Clone, Debug)]

struct PcmFormat {
    channels: u16,
    rate: u32,
    wire: Vec<u8>,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn pcm_formats(bytes: &[u8]) -> Result<Vec<PcmFormat>> {
    let count = u32_at(bytes, 1).context("AUDIN format count is missing")? as usize;

    if count > 1024 {
        bail!("AUDIN has too many formats");
    }

    let mut at = 9;
    let mut formats = vec![];

    for _ in 0..count {
        let header = bytes
            .get(at..at + 18)
            .context("AUDIN format is truncated")?;

        let tag = u16::from_le_bytes([header[0], header[1]]);
        let channels = u16::from_le_bytes([header[2], header[3]]);

        let rate = u32_at(header, 4).unwrap();
        let extra = u16::from_le_bytes([header[16], header[17]]) as usize;

        let length = 18 + extra;
        let wire = bytes
            .get(at..at + length)
            .context("AUDIN extended format is truncated")?
            .to_vec();

        let bits = u16::from_le_bytes([header[14], header[15]]);
        let align = u16::from_le_bytes([header[12], header[13]]);

        if tag == 1
            && (1..=2).contains(&channels)
            && (8000..=96000).contains(&rate)
            && bits == 16
            && align == channels * 2
            && extra == 0
        {
            formats.push(PcmFormat {
                channels,
                rate,
                wire,
            });
        }

        at += length;
    }
    Ok(formats)
}

struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub struct AudioInput {
    formats: Vec<PcmFormat>,
    packets: mpsc::SyncSender<CapturedAudio>,
    events: Sender<EngineEvent>,
    session: uuid::Uuid,
    capture: Option<Capture>,
    frames: u32,
    version: bool,
    generation: u64,
}

impl_as_any!(AudioInput);

impl AudioInput {
    pub fn new(
        events: Sender<EngineEvent>,
        session: uuid::Uuid,
    ) -> (Self, Receiver<CapturedAudio>) {
        let (tx, rx) = mpsc::sync_channel(32);
        (
            Self {
                formats: vec![],
                packets: tx,
                events,
                session,
                capture: None,
                frames: 0,
                version: false,
                generation: 0,
            },
            rx,
        )
    }

    fn diagnostic(&self, message: impl Into<String>) {
        let _ = self.events.send(EngineEvent::Diagnostic {
            session_id: self.session,
            message: message.into(),
        });
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn stop_capture(&mut self) {
        self.capture = None;
        self.generation = self.generation.wrapping_add(1);
    }

    fn open(&mut self, index: u32, frames: u32) -> Result<()> {
        self.stop_capture();
        let session_stop = session_flag(self.session);
        if session_stop.load(Ordering::SeqCst) {
            bail!("Microphone: session already ended");
        }

        let generation = self.generation;

        let format = self
            .formats
            .get(index as usize)
            .context("AUDIN format is unknown")?
            .clone();

        if frames == 0 || frames > 96000 {
            bail!("AUDIN packet size is invalid");
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let packets = self.packets.clone();
        let events = self.events.clone();
        let session = self.session;

        let (ready_tx, ready_rx) = mpsc::sync_channel(1);

        let thread = std::thread::spawn(move || {
            let setup = (|| -> Result<cpal::Stream> {
                let device = cpal::default_host()
                    .default_input_device()
                    .context("No microphone found")?;

                let supported = device.default_input_config()?;
                let config: cpal::StreamConfig = supported.clone().into();

                let rate = config.sample_rate.0;
                let channels = config.channels;
                let error_events = events.clone();

                let on_error = move |error| {
                    let _ = error_events.send(EngineEvent::Diagnostic {
                        session_id: session,
                        message: format!("Microphone error: {error}"),
                    });
                };

                let converter = Converter::new(
                    rate,
                    channels,
                    format.rate,
                    format.channels,
                    frames,
                    packets,
                    generation,
                );

                let stream = match supported.sample_format() {
                    cpal::SampleFormat::F32 => {
                        let mut c = converter;
                        device.build_input_stream(
                            &config,
                            move |data: &[f32], _| c.push(data.iter().copied()),
                            on_error,
                            None,
                        )?
                    }

                    cpal::SampleFormat::I16 => {
                        let mut c = converter;
                        device.build_input_stream(
                            &config,
                            move |data: &[i16], _| c.push(data.iter().map(|v| *v as f32 / 32768.0)),
                            on_error,
                            None,
                        )?
                    }

                    cpal::SampleFormat::U16 => {
                        let mut c = converter;
                        device.build_input_stream(
                            &config,
                            move |data: &[u16], _| {
                                c.push(data.iter().map(|v| (*v as f32 - 32768.0) / 32768.0))
                            },
                            on_error,
                            None,
                        )?
                    }

                    _ => bail!("Microphone format is unsupported"),
                };
                if session_stop.load(Ordering::SeqCst) {
                    bail!("Microphone session cancelled");
                }
                stream.play()?;
                Ok(stream)
            })();

            match setup {
                Ok(stream) => {
                    let _ = ready_tx.send(Ok(()));
                    while !thread_stop.load(Ordering::Relaxed)
                        && !session_stop.load(Ordering::SeqCst)
                    {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    drop(stream);
                }

                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                }
            }
        });

        let capture = Capture {
            stop,
            thread: Some(thread),
        };

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.capture = Some(capture);
                self.frames = frames;
                self.diagnostic("Microphone active: native capture to remote session");
                Ok(())
            }
            Ok(Err(e)) => bail!(e),
            Err(e) => bail!("Microphone startup: {e}"),
        }
    }
}

impl DvcClientProcessor for AudioInput {}

impl DvcProcessor for AudioInput {
    fn channel_name(&self) -> &str {
        "AUDIO_INPUT"
    }

    fn start(&mut self, _: u32) -> PduResult<Vec<DvcMessage>> {
        Ok(vec![])
    }

    fn close(&mut self, _: u32) {
        self.stop_capture();
        self.version = false;
        self.formats.clear();
        self.frames = 0;
        self.diagnostic("Microphone channel closed");
    }

    fn process(&mut self, _: u32, bytes: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let Some(&kind) = bytes.first() else {
            return Ok(vec![]);
        };

        match kind {
            1 if bytes.len() == 5 && u32_at(bytes, 1).is_some_and(|v| v > 0) => {
                self.stop_capture();
                self.formats.clear();
                self.frames = 0;
                self.version = true;
                Ok(vec![Box::new(AudioPacket(vec![1, 1, 0, 0, 0]))])
            }

            2 if self.version => {
                self.stop_capture();
                self.frames = 0;
                self.formats.clear();

                match pcm_formats(bytes) {
                    Ok(formats) => self.formats = formats,
                    Err(e) => {
                        self.version = false;
                        self.diagnostic(e.to_string());
                        return Ok(vec![]);
                    }
                }

                if self.formats.is_empty() {
                    self.diagnostic("Microphone: no shared PCM16 format");
                }

                let size = 9 + self.formats.iter().map(|f| f.wire.len()).sum::<usize>();
                let mut p = vec![2];
                p.extend_from_slice(&(self.formats.len() as u32).to_le_bytes());
                p.extend_from_slice(&(size as u32).to_le_bytes());
                for f in &self.formats {
                    p.extend_from_slice(&f.wire);
                }

                Ok(vec![
                    Box::new(AudioPacket(vec![5])),
                    Box::new(AudioPacket(p)),
                ])
            }

            3 if bytes.len() >= 27 && self.version && !self.formats.is_empty() => {
                let extra = u16::from_le_bytes([bytes[25], bytes[26]]) as usize;
                if bytes.len() < 27 + extra {
                    self.stop_capture();
                    self.version = false;
                    self.formats.clear();
                    self.frames = 0;
                    self.diagnostic("Microphone stopped: incomplete capture format");
                    return Ok(vec![]);
                }
                let frames = u32_at(bytes, 1).unwrap();
                let index = u32_at(bytes, 5).unwrap();

                match self.open(index, frames) {
                    Ok(()) => {
                        let mut change = vec![7];
                        change.extend_from_slice(&index.to_le_bytes());
                        Ok(vec![
                            Box::new(AudioPacket(change)),
                            Box::new(AudioPacket(vec![4, 0, 0, 0, 0])),
                        ])
                    }
                    Err(e) => {
                        self.diagnostic(format!("Unable to open microphone: {e}"));
                        Ok(vec![Box::new(AudioPacket(vec![4, 1, 0, 0, 0]))])
                    }
                }
            }

            7 if bytes.len() >= 5 && self.frames > 0 => {
                let index = u32_at(bytes, 1).unwrap();
                match self.open(index, self.frames) {
                    Ok(()) => Ok(vec![Box::new(AudioPacket(bytes[..5].to_vec()))]),
                    Err(e) => {
                        self.diagnostic(format!("Microphone format: {e}"));
                        Ok(vec![])
                    }
                }
            }

            1 | 2 | 3 | 7 => {
                self.stop_capture();
                self.version = false;
                self.formats.clear();
                self.frames = 0;
                self.diagnostic("Microphone stopped: invalid channel message");
                Ok(vec![])
            }

            _ => Ok(vec![]),
        }
    }
}

/// Streaming rate/channel conversion. The packet size is dictated by the server.

struct Converter {
    input_rate: u32,
    input_channels: usize,
    output_rate: u32,
    output_channels: usize,
    phase: u64,
    frame: Vec<f32>,
    packet: Vec<u8>,
    packet_bytes: usize,
    generation: u64,
    packets: mpsc::SyncSender<CapturedAudio>,
}

impl Converter {
    fn new(
        input_rate: u32,
        input_channels: u16,
        output_rate: u32,
        output_channels: u16,
        frames: u32,
        packets: mpsc::SyncSender<CapturedAudio>,
        generation: u64,
    ) -> Self {
        Self {
            input_rate,
            input_channels: input_channels as usize,
            output_rate,
            output_channels: output_channels as usize,
            phase: 0,
            frame: vec![],
            packet: vec![6],
            packet_bytes: frames as usize * output_channels as usize * 2 + 1,
            generation,
            packets,
        }
    }

    fn push(&mut self, samples: impl Iterator<Item = f32>) {
        for sample in samples {
            self.frame.push(sample);
            if self.frame.len() < self.input_channels {
                continue;
            }
            self.phase += self.output_rate as u64;
            while self.phase >= self.input_rate as u64 {
                self.phase -= self.input_rate as u64;
                for channel in 0..self.output_channels {
                    let value = if self.output_channels == 1 {
                        self.frame.iter().sum::<f32>() / self.input_channels as f32
                    } else {
                        self.frame[channel.min(self.input_channels - 1)]
                    };
                    let value = (value.clamp(-1.0, 1.0) * 32767.0) as i16;
                    self.packet.extend_from_slice(&value.to_le_bytes());
                }
                if self.packet.len() == self.packet_bytes {
                    let packet = std::mem::replace(&mut self.packet, vec![6]);
                    let _ = self.packets.try_send(CapturedAudio {
                        generation: self.generation,
                        packet: AudioPacket(packet),
                    });
                }
            }
            self.frame.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_packets_have_exact_frame_count() {
        let (tx, rx) = mpsc::sync_channel(32);
        let mut c = Converter::new(48000, 2, 16000, 1, 160, tx, 0);
        c.push(std::iter::repeat_n(0.5, 960));
        let packet = rx.try_recv().unwrap();
        assert_eq!(packet.packet.0.len(), 321);
        assert_eq!(packet.packet.0[0], 6);
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn malformed_formats_are_rejected() {
        assert!(pcm_formats(&[2, 1, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
    #[test]
    fn cancelled_session_never_opens_device() {
        let session = uuid::Uuid::new_v4();
        stop_session(session);
        let (tx, _) = mpsc::channel();
        let (mut input, _) = AudioInput::new(tx, session);
        assert!(
            input
                .open(0, 160)
                .unwrap_err()
                .to_string()
                .contains("ended")
        );
        allow_session(session);
        assert!(!session_flag(session).load(Ordering::SeqCst));
    }
    #[test]
    fn malformed_negotiation_invalidates_capture_generation() {
        let (tx, _) = mpsc::channel();
        let (mut input, _) = AudioInput::new(tx, uuid::Uuid::new_v4());
        input.process(1, &[1, 1, 0, 0, 0]).unwrap();
        let generation = input.generation();
        input.process(1, &[2, 1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(input.generation() > generation);
        assert!(!input.version);
        assert!(input.formats.is_empty());
    }
    #[test]
    fn pcm_negotiation_retains_wire_format() {
        let mut wire = vec![2, 1, 0, 0, 0, 27, 0, 0, 0];
        wire.extend_from_slice(&[
            1, 0, 1, 0, 0x80, 0x3e, 0, 0, 0, 0x7d, 0, 0, 2, 0, 16, 0, 0, 0,
        ]);
        let formats = pcm_formats(&wire).unwrap();
        assert_eq!(formats.len(), 1);
        assert_eq!(formats[0].rate, 16000);
        wire[23] = 8;
        assert!(pcm_formats(&wire).unwrap().is_empty());
    }
}
