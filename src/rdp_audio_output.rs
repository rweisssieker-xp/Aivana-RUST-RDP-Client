//! Native PCM playback, with a bounded queue and explicit CPAL stream lifecycle.
use crate::models::EngineEvent;
use anyhow::{Context, Result, bail};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use ironrdp::rdpsnd::{
    client::RdpsndClientHandler,
    pdu::{AudioFormat, PitchPdu, VolumePdu, WaveFormat},
};
use std::{
    borrow::Cow,
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender, SyncSender},
    },
    thread::JoinHandle,
    time::Duration,
};
#[derive(Debug)]
pub struct Playback {
    formats: Vec<AudioFormat>,
    events: Sender<EngineEvent>,
    session: uuid::Uuid,
    tx: Option<SyncSender<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    failed: bool,
}
impl Playback {
    pub fn new(events: Sender<EngineEvent>, session: uuid::Uuid) -> Self {
        let mut value = Self {
            formats: vec![],
            events,
            session,
            tx: None,
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            failed: false,
        };
        match cpal::default_host()
            .default_output_device()
            .and_then(|d| d.default_output_config().ok())
        {
            Some(config)
                if matches!(
                    config.sample_format(),
                    cpal::SampleFormat::F32 | cpal::SampleFormat::I16 | cpal::SampleFormat::U16
                ) =>
            {
                let channels = config.channels();
                let rate = config.sample_rate().0;
                value.formats.push(AudioFormat {
                    format: WaveFormat::PCM,
                    n_channels: channels,
                    n_samples_per_sec: rate,
                    n_avg_bytes_per_sec: rate * channels as u32 * 2,
                    n_block_align: channels * 2,
                    bits_per_sample: 16,
                    data: None,
                });
            }
            _ => {
                value.diagnostic("Audio nicht verfügbar: kein unterstütztes Ausgabegerät");
                value.failed = true;
            }
        }
        value
    }
    fn diagnostic(&self, message: impl Into<String>) {
        let _ = self.events.send(EngineEvent::Diagnostic {
            session_id: self.session,
            message: message.into(),
        });
    }
    fn start(&mut self) -> Result<()> {
        let format = self.formats.first().context("Audioformat fehlt")?.clone();
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(32);
        self.tx = Some(tx);
        self.stop.store(false, Ordering::Relaxed);
        let stop = self.stop.clone();
        let events = self.events.clone();
        let session = self.session;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        self.thread = Some(std::thread::spawn(move || {
            let setup = (|| -> Result<cpal::Stream> {
                let device = cpal::default_host()
                    .default_output_device()
                    .context("Kein Ausgabegerät")?;
                let supported = device.default_output_config()?;
                let config = cpal::StreamConfig {
                    channels: format.n_channels,
                    sample_rate: cpal::SampleRate(format.n_samples_per_sec),
                    buffer_size: cpal::BufferSize::Default,
                };
                let mut queued = VecDeque::<i16>::new();
                let mut next_sample = move || {
                    if queued.is_empty() {
                        if let Ok(data) = rx.try_recv() {
                            queued.extend(
                                data.chunks_exact(2)
                                    .map(|b| i16::from_le_bytes([b[0], b[1]])),
                            );
                        }
                    }
                    queued.pop_front().unwrap_or(0)
                };
                let error_events = events.clone();
                let on_error = move |error| {
                    let _ = error_events.send(EngineEvent::Diagnostic {
                        session_id: session,
                        message: format!("Audiowiedergabe: {error}"),
                    });
                };
                let stream = match supported.sample_format() {
                    cpal::SampleFormat::F32 => device.build_output_stream(
                        &config,
                        move |data: &mut [f32], _| {
                            for out in data {
                                *out = next_sample() as f32 / 32768.0;
                            }
                        },
                        on_error,
                        None,
                    )?,
                    cpal::SampleFormat::I16 => device.build_output_stream(
                        &config,
                        move |data: &mut [i16], _| {
                            for out in data {
                                *out = next_sample();
                            }
                        },
                        on_error,
                        None,
                    )?,
                    cpal::SampleFormat::U16 => device.build_output_stream(
                        &config,
                        move |data: &mut [u16], _| {
                            for out in data {
                                *out = (next_sample() as i32 + 32768) as u16;
                            }
                        },
                        on_error,
                        None,
                    )?,
                    _ => bail!("Audio-Ausgabeformat nicht unterstützt"),
                };
                stream.play()?;
                Ok(stream)
            })();
            match setup {
                Ok(stream) => {
                    let _ = ready_tx.send(Ok(()));
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    drop(stream);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                }
            }
        }));
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.diagnostic("Audio aktiv: Remote-PCM über lokales Ausgabegerät");
                Ok(())
            }
            Ok(Err(e)) => bail!(e),
            Err(e) => bail!("Audiostart: {e}"),
        }
    }
}
impl RdpsndClientHandler for Playback {
    fn get_formats(&self) -> &[AudioFormat] {
        &self.formats
    }
    fn wave(&mut self, format_no: usize, _: u32, data: Cow<'_, [u8]>) {
        if self.failed {
            return;
        }
        if format_no != 0 || data.len() > 4 * 1024 * 1024 {
            self.diagnostic("Audio: ungültiges Format oder Paket");
            return;
        }
        if self.thread.is_none() {
            if let Err(e) = self.start() {
                self.diagnostic(format!("Audio nicht gestartet: {e}"));
                self.failed = true;
                return;
            }
        }
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(data.into_owned());
        }
    }
    // Volume/pitch control is not advertised; local system audio controls remain authoritative.
    fn set_volume(&mut self, _: VolumePdu) {}
    fn set_pitch(&mut self, _: PitchPdu) {}
    fn close(&mut self) {
        self.tx = None;
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
impl Drop for Playback {
    fn drop(&mut self) {
        self.close();
    }
}
