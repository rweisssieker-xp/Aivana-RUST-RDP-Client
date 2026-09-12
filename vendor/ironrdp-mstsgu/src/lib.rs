#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(
    html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg"
)]

#[macro_use]
mod macros;

mod ntlm;
mod proto;

use core::fmt;
use core::fmt::Display;
use core::pin::Pin;
use core::task::Poll;
use core::time::Duration;
use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{FutureExt as _, SinkExt as _, StreamExt as _};
use hyper::body::Bytes;
use ironrdp_core::{Decode as _, Encode, ReadCursor, WriteCursor};
use ironrdp_tls::TlsStream;
use log::{error, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Message, http};
use tokio_util::sync::PollSender;

use self::proto::{
    ChannelPkt, ChannelResp, DataPkt, HandshakeReqPkt, HandshakeRespPkt, HttpCapsTy, KeepalivePkt,
    PktHdr, PktTy, TunnelAuthPkt, TunnelAuthRespPkt, TunnelReqPkt, TunnelRespPkt,
};

#[derive(Clone)]
pub struct GwConnectTarget {
    pub ntlm: bool,
    /// Pluggable authentication cookie, requested from the application when enabled.
    pub paa: bool,
    pub interactions: Option<std::sync::mpsc::SyncSender<GatewayInteraction>>,
    pub target_port: u16,
    pub messages: Option<std::sync::mpsc::SyncSender<String>>,
    pub gw_endpoint: String,
    pub gw_user: String,
    pub gw_pass: String,

    pub server: String,
}

/// One-shot UI requests. Dropping the reply cancels the connection; never auto-accept.
#[derive(Debug)]
pub enum GatewayInteraction {
    Consent { gateway: String, message: String, reply: oneshot::Sender<bool> },
    /// Gateway-provider-issued PAA cookie, not a generic OAuth bearer token or OTP.
    PaaToken { gateway: String, reply: oneshot::Sender<Option<String>> },
}

async fn consent(
    target: &GwConnectTarget,
    message: String,
) -> Result<(), Error> {
    let sender = target.interactions.as_ref().ok_or_else(||
        Error::new("Gateway consent requires interactive UI", GwErrorKind::UnsupportedFeature))?;
    let (reply, response) = oneshot::channel();
    sender.try_send(GatewayInteraction::Consent {
        gateway: target.gw_endpoint.clone(), message, reply,
    }).map_err(|_| Error::new("Gateway consent UI unavailable", GwErrorKind::Connect))?;
    match tokio::time::timeout(Duration::from_secs(90), response).await {
        Ok(Ok(true)) => Ok(()),
        _ => Err(Error::new("Gateway consent declined, cancelled or timed out", GwErrorKind::Connect)),
    }
}

type Error = ironrdp_error::Error<GwErrorKind>;

#[derive(Debug)]
#[non_exhaustive]
pub enum GwErrorKind {
    InvalidGwTarget,
    Connect,
    PacketEof,
    UnsupportedFeature,
    Custom,
    Encode,
    Decode,
}

trait GwErrorExt {
    fn custom<E>(context: &'static str, e: E) -> Self
    where
        E: core::error::Error + Sync + Send + 'static;
}

impl GwErrorExt for ironrdp_error::Error<GwErrorKind> {
    #[track_caller]
    fn custom<E>(context: &'static str, e: E) -> Self
    where
        E: core::error::Error + Sync + Send + 'static,
    {
        Self::new(context, GwErrorKind::Custom).with_source(e)
    }
}

impl Display for GwErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = match self {
            GwErrorKind::InvalidGwTarget => "invalid GW Target",
            GwErrorKind::Connect => "connection error",
            GwErrorKind::PacketEof => "PacketEOF",
            GwErrorKind::UnsupportedFeature => "unsupported feature",
            GwErrorKind::Custom => "custom",
            GwErrorKind::Encode => "encode",
            GwErrorKind::Decode => "decode",
        };
        f.write_str(x)
    }
}

impl core::error::Error for GwErrorKind {}

struct GwConn {
    client_name: String,
    target: GwConnectTarget,
    paa_cookie: Option<Vec<u8>>,
    ws_sink: SplitSink<WebSocketStream<TlsStream<TcpStream>>, Message>,
    ws_stream: SplitStream<WebSocketStream<TlsStream<TcpStream>>>,
}

pub struct GwClient {
    work: tokio::task::JoinHandle<Result<(), Error>>,
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    rx_bufs: Vec<Bytes>,
    tx: PollSender<Bytes>,
}

impl Drop for GwClient {
    fn drop(&mut self) {
        self.work.abort();
    }
}

impl GwClient {
    pub async fn connect(
        target: &GwConnectTarget,
        client_name: &str,
    ) -> Result<(GwClient, core::net::SocketAddr), Error> {
        let paa_cookie = if target.paa {
            let sender = target.interactions.as_ref().ok_or_else(||
                Error::new("PAA token requires interactive UI", GwErrorKind::UnsupportedFeature))?;
            let (reply, response) = oneshot::channel();
            sender.try_send(GatewayInteraction::PaaToken { gateway: target.gw_endpoint.clone(), reply })
                .map_err(|_| Error::new("PAA token UI unavailable", GwErrorKind::Connect))?;
            let token = tokio::time::timeout(Duration::from_secs(90), response).await
                .map_err(|_| Error::new("PAA token input timed out", GwErrorKind::Connect))?
                .map_err(|_| Error::new("PAA token input cancelled", GwErrorKind::Connect))?
                .ok_or_else(|| Error::new("PAA token input cancelled", GwErrorKind::Connect))?;
            Some(encode_paa_cookie(&token)?)
        } else { None };
        let gw_host = target
            .gw_endpoint
            .split(":")
            .nth(0)
            .ok_or_else(|| Error::new("Connect", GwErrorKind::InvalidGwTarget))?;

        let stream = TcpStream::connect(&target.gw_endpoint)
            .await
            .map_err(|e| custom_err!("TCP connect", e))?;
        let client_addr = stream
            .local_addr()
            .map_err(|e| custom_err!("get socket local address", e))?;

        let (stream, _) = ironrdp_tls::upgrade(stream, gw_host)
            .await
            .map_err(|e| custom_err!("TLS connect", e))?;

        let authorization = if target.paa {
            "PAA".to_owned()
        } else if target.ntlm {
            "SSPI_NTLM".to_owned()
        } else {
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", target.gw_user, target.gw_pass))
            )
        };
        let req = http::Request::builder()
            .method("RDG_OUT_DATA")
            .header(hyper::header::HOST, gw_host)
            .header("Rdg-Connection-Id", format!("{{{}}}", uuid::Uuid::new_v4()))
            .uri("/remoteDesktopGateway/")
            .header(hyper::header::AUTHORIZATION, authorization)
            .header(hyper::header::CONNECTION, "Upgrade")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::SEC_WEBSOCKET_VERSION, "13")
            .header(hyper::header::SEC_WEBSOCKET_KEY, generate_key())
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| custom_err!("failed to build request", e))?;

        let stream = hyper_util::rt::tokio::TokioIo::new(stream);
        let (mut sender, mut conn) = hyper::client::conn::http1::handshake(stream)
            .await
            .map_err(|e| custom_err!("H1 Handshake", e))?;
        let (tx, rx) = oneshot::channel();

        let jh = tokio::task::spawn(async move {
            tokio::select! {
                Err(e) = &mut conn => error!("Handshake error: {:?}", e),
                _ = rx => (),
            }
            conn.into_parts()
        });
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| custom_err!("WS Upgrade Send error", e))?;

        if resp.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::new("WS Upgrade", GwErrorKind::Connect));
        }

        let _ = tx.send(()); // TODO: Not needed since it doesnt keep alive conn?
        let stream = jh
            .await
            .map_err(|e| custom_err!("WS join", e))?
            .io
            .into_inner();

        Self::connect_ws(target.clone(), client_name, stream, paa_cookie)
            .await
            .map(|x| (x, client_addr))
    }

    async fn connect_ws(
        target: GwConnectTarget,
        client_name: &str,
        tls_stream: TlsStream<TcpStream>,
        paa_cookie: Option<Vec<u8>>,
    ) -> Result<GwClient, Error> {
        let ws_stream: WebSocketStream<_> =
            WebSocketStream::from_raw_socket(tls_stream, Role::Client, None).await;
        let (ws_sink, ws_stream) = ws_stream.split();
        let mut gw = GwConn {
            client_name: client_name.to_owned(),
            target,
            paa_cookie,
            ws_sink,
            ws_stream,
        };

        gw.handshake().await?;
        if gw.target.ntlm && !gw.target.paa {
            gw.ntlm_auth().await?;
        }
        gw.tunnel().await?;
        gw.tunnel_auth().await?;
        gw.channel().await?;

        let (in_tx, in_rx) = tokio::sync::mpsc::channel(4);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Bytes>(4);

        let work = tokio::spawn(async move {
            let iv = Duration::from_secs(15 * 60);
            let mut keepalive_interval =
                tokio::time::interval_at(tokio::time::Instant::now() + iv, iv);

            loop {
                let mut wsbuf = [0u8; 8192];

                tokio::select!(
                    _ = keepalive_interval.tick() => {
                        let pos = {
                            let mut cur = WriteCursor::new(&mut wsbuf);
                            KeepalivePkt.encode(&mut cur).map_err(|e| custom_err!("PktEncode", e))?;
                            cur.pos()
                        };

                        gw.ws_sink.send(Message::Binary(Bytes::copy_from_slice(&wsbuf[..pos]))).await.map_err(|e| custom_err!("ws send", e))?;
                    },
                    next = gw.ws_stream.next() => {
                        let tmp = next.ok_or_else(|| Error::new("WS Stream Dead", GwErrorKind::Connect))?;
                        let msg = tmp.map_err(|e| custom_err!("Stream", e))?.into_data();
                        let mut cur = ReadCursor::new(&msg);
                        let hdr = PktHdr::decode(&mut cur).map_err(|e| custom_err!("Header Decode", e))?;

                        let header_length = usize::try_from(hdr.length).map_err(|_| Error::new("PktHdr too big", GwErrorKind::Decode))?;
                        if header_length < hdr.size() || cur.len() != header_length - hdr.size() { return Err(Error::new("Invalid gateway frame length", GwErrorKind::Decode)); }
                        match hdr.ty {
                            PktTy::Keepalive => {
                                continue;
                            },
                            PktTy::ServiceMessage => { gw.service_message(cur.remaining())?; },
                            PktTy::ReauthMessage => { return Err(Error::new("Gateway requires reauthentication; reconnect explicitly", GwErrorKind::Connect)); },
                            PktTy::Data => {
                                let p = DataPkt::decode(&mut cur).map_err(|e| custom_err!("PktDecode", e))?;
                                in_tx.send(Bytes::from(p.data.to_vec())).await.map_err(|e| custom_err!("in_tx dead", e))?;
                            },
                            x => {
                                warn!("Unhandled gw packet type {x:?}");
                            }
                        }
                    },
                    next = out_rx.recv() => {
                        let next = next.ok_or_else(|| Error::new("WS Sink Dead", GwErrorKind::Connect))?;
                        let pkt = DataPkt { data: &next };

                        let pos = {
                            let mut cur = WriteCursor::new(&mut wsbuf);
                            pkt.encode(&mut cur).map_err(|e| custom_err!("PktEncode", e))?;
                            cur.pos()
                        };
                        gw.ws_sink.send(Message::Binary(Bytes::copy_from_slice(&wsbuf[..pos]))).await.map_err(|e| custom_err!("ws send", e))?;
                    }
                );
            }
        });

        Ok(GwClient {
            work,
            rx: in_rx,
            rx_bufs: vec![],
            tx: PollSender::new(out_tx),
        })
    }
}

impl GwConn {
    fn service_message(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() < 2 {
            return Err(Error::new(
                "Gateway service message length",
                GwErrorKind::Decode,
            ));
        }
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if len != bytes.len() - 2 {
            return Err(Error::new(
                "Gateway service message bounds",
                GwErrorKind::Decode,
            ));
        }
        let message = decode_gateway_text(&bytes[2..])?;
        if let Some(sender) = &self.target.messages {
            let _ = sender.try_send(message);
        }
        Ok(())
    }
    async fn send_packet<E: Encode>(&mut self, payload: &E) -> Result<(), Error> {
        if payload.size() > 65536 {
            return Err(Error::new("Gateway packet limit", GwErrorKind::Encode));
        }
        let mut buf = vec![0u8; payload.size()];
        let pos = {
            let mut cur = WriteCursor::new(&mut buf);
            payload
                .encode(&mut cur)
                .map_err(|e| Error::new("packet encode", GwErrorKind::Encode).with_source(e))?;
            cur.pos()
        };
        self.ws_sink
            .send(Message::Binary(Bytes::copy_from_slice(&buf[..pos])))
            .await
            .map_err(|e| custom_err!("WebSocket send error", e))?;
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<(PktHdr, Bytes), Error> {
        loop {
            let mut msg = self
                .ws_stream
                .next()
                .await
                .ok_or_else(|| Error::new("Stream closed", GwErrorKind::Connect))?
                .map_err(|e| custom_err!("WS err", e))?
                .into_data();
            let mut cur = ReadCursor::new(&msg);

            let hdr =
                PktHdr::decode(&mut cur).map_err(|_| Error::new("PktHdr", GwErrorKind::Decode))?;

            let header_length = usize::try_from(hdr.length)
                .map_err(|_| Error::new("PktHdr too big", GwErrorKind::Decode))?;
            if header_length < hdr.size() || cur.len() != header_length - hdr.size() {
                return Err(Error::new("read_packet", GwErrorKind::PacketEof));
            }

            let body = msg.split_off(cur.pos());
            if hdr.ty == PktTy::ServiceMessage {
                self.service_message(&body)?;
                continue;
            }
            if hdr.ty == PktTy::Keepalive {
                continue;
            }
            return Ok((hdr, body));
        }
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        // For NTLM we would include extended_auth: NTLM_SSPI in this handshake req here.
        let hs = HandshakeReqPkt {
            ver_major: 1,
            ver_minor: 0,
            extended_auth: if self.target.paa {
                proto::HttpExtendedAuth::HTTP_EXTENDED_AUTH_PAA
            } else if self.target.ntlm {
                proto::HttpExtendedAuth::HTTP_EXTENDED_AUTH_SSPI_NTLM
            } else {
                proto::HttpExtendedAuth::empty()
            },
            ..HandshakeReqPkt::default()
        };
        self.send_packet(&hs).await?;
        let (hdr, bytes) = self.read_packet().await?;
        if hdr.ty != PktTy::HandshakeResp {
            return Err(Error::new(
                "Expected gateway handshake response",
                GwErrorKind::Decode,
            ));
        }
        let mut cur = ReadCursor::new(&bytes);
        let resp = HandshakeRespPkt::decode(&mut cur)
            .map_err(|_| Error::new("Handshake", GwErrorKind::Decode))?;
        if resp.error_code != 0
            || resp.ver_major != 1
            || resp.ver_minor != 0
            || resp.server_version != 0
        {
            return Err(Error::new("Handshake", GwErrorKind::Connect));
        }
        if self.target.paa && !resp.extended_auth.contains(proto::HttpExtendedAuth::HTTP_EXTENDED_AUTH_PAA) {
            return Err(Error::new("Gateway rejected required PAA mode", GwErrorKind::Connect));
        }
        if self.target.ntlm && !self.target.paa
            && !resp
                .extended_auth
                .contains(proto::HttpExtendedAuth::HTTP_EXTENDED_AUTH_SSPI_NTLM)
        {
            return Err(Error::new(
                "Gateway rejected required NTLM mode",
                GwErrorKind::Connect,
            ));
        }
        Ok(())
    }

    async fn tunnel(&mut self) -> Result<(), Error> {
        let req = TunnelReqPkt {
            // Havent seen any server working without this.
            caps: HttpCapsTy::MessagingConsentSign.as_u32()
                | HttpCapsTy::MessagingServiceMsg.as_u32(),
            paa_cookie: self.paa_cookie.take(),
            ..TunnelReqPkt::default()
        };
        self.send_packet(&req).await?;

        let (hdr, bytes) = self.read_packet().await?;
        if hdr.ty != PktTy::TunnelResp {
            return Err(Error::new("Expected gateway tunnel response", GwErrorKind::Decode));
        }
        let mut cur = ReadCursor::new(&bytes);

        let resp = TunnelRespPkt::decode(&mut cur)
            .map_err(|_| Error::new("TunnelDecode", GwErrorKind::Decode))?;
        if resp.status_code != 0 {
            return Err(Error::new("Tunnel", GwErrorKind::Connect));
        }
        if !cur.eof() {
            return Err(Error::new(
                "Trailing gateway response bytes",
                GwErrorKind::Decode,
            ));
        }
        if !resp.consent_msg.is_empty() {
            consent(&self.target, decode_gateway_text(&resp.consent_msg)?).await?;
        }
        Ok(())
    }

    async fn tunnel_auth(&mut self) -> Result<(), Error> {
        let req = TunnelAuthPkt {
            fields_present: 0,
            client_name: self.client_name.clone(),
        };
        self.send_packet(&req).await?;

        let (hdr, bytes) = self.read_packet().await?;
        if hdr.ty != PktTy::TunnelAuthResponse {
            return Err(Error::new(
                "Expected gateway tunnel authorization",
                GwErrorKind::Decode,
            ));
        }
        let mut cur = ReadCursor::new(&bytes);
        let resp: TunnelAuthRespPkt = TunnelAuthRespPkt::decode(&mut cur)
            .map_err(|_| Error::new("TunnelAuth", GwErrorKind::Decode))?;

        if resp.error_code() != 0 {
            return Err(Error::new("TunnelAuth", GwErrorKind::Connect));
        }
        Ok(())
    }

    async fn channel(&mut self) -> Result<ChannelResp, Error> {
        let req = ChannelPkt {
            resources: vec![self.target.server.clone()],
            port: self.target.target_port,
            protocol: 3,
        };
        self.send_packet(&req).await?;

        let (hdr, bytes) = self.read_packet().await?;
        if hdr.ty != PktTy::ChannelResp {
            return Err(Error::new("Expected channel response", GwErrorKind::Decode));
        }
        let mut cur: ReadCursor<'_> = ReadCursor::new(&bytes);
        let resp: ChannelResp = ChannelResp::decode(&mut cur)
            .map_err(|_| Error::new("ChannelResp", GwErrorKind::Decode))?;
        if resp.error_code() != 0 {
            return Err(Error::new("ChannelCreate", GwErrorKind::Connect));
        }
        if !cur.eof() {
            return Err(Error::new(
                "Trailing gateway response bytes",
                GwErrorKind::Decode,
            ));
        }
        Ok(resp)
    }
}

impl AsyncRead for GwClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Propagate error or premature exit (?)
        match self.work.poll_unpin(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(_) => {
                return Poll::Ready(Err(io::Error::other("Premature Work Task end?")));
            }
            _ => (),
        }

        // Get new bufs
        if let Poll::Ready(Some(new_buf)) = self.rx.poll_recv(cx) {
            self.rx_bufs.push(new_buf);
        }

        // Read from all queued bufs
        let mut n = 0;
        self.rx_bufs.retain_mut(|rx_buf| {
            let rem = buf.remaining();
            if rem == 0 {
                return true;
            }
            let max = core::cmp::min(rem, rx_buf.len());
            buf.put_slice(&rx_buf[..max]);
            n += max;
            let _ = rx_buf.split_to(max);

            !rx_buf.is_empty()
        });

        if n > 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for GwClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // Propagate error or premature exit (?)
        match self.work.poll_unpin(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(_) => {
                return Poll::Ready(Err(io::Error::other("Premature Work Task end?")));
            }
            Poll::Pending => (),
        }

        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                if self.tx.send_item(Bytes::from(buf.to_vec())).is_err() {
                    return Poll::Ready(Err(io::Error::other("Sender closed")));
                }
                return Poll::Ready(Ok(buf.len()));
            }
            Poll::Ready(Err(err)) => {
                return Poll::Ready(Err(io::Error::other(err)));
            }
            Poll::Pending => (),
        }

        Poll::Pending
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // TODO: call flush on the backing sink (e.g. websocket, but atleast for that backend doesnt seem to matter)?
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn encode_paa_cookie(token: &str) -> Result<Vec<u8>, Error> {
    // Match the UTF-16 cookie convention used by RD Gateway PAA providers/FreeRDP.
    // The binary field itself is MS-TSGU HTTP_byte_BLOB, not an HTTP header.
    let units = token.encode_utf16().count();
    if units == 0 || units > 32749 || token.contains('\0') {
        return Err(Error::new("Invalid or oversized PAA cookie", GwErrorKind::InvalidGwTarget));
    }
    Ok(token.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect())
}

fn decode_gateway_text(bytes: &[u8]) -> Result<String, Error> {
    if bytes.len() % 2 != 0 { return Err(Error::new("Gateway message UTF-16 length", GwErrorKind::Decode)); }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16(&units).map(|s| s.trim_end_matches(char::from(0)).to_owned()).map_err(|e| custom_err!("Gateway message UTF-16", e))
}
#[cfg(test)]
mod message_tests {
    use super::*;
    #[test]
    fn paa_cookie_is_bounded_utf16_not_an_authorization_header() {
        assert_eq!(encode_paa_cookie("é").unwrap(), [0xe9, 0, 0, 0]);
        assert!(encode_paa_cookie("").is_err());
        assert!(encode_paa_cookie("a\0b").is_err());
        assert!(encode_paa_cookie(&"x".repeat(32750)).is_err());
    }
    #[test]
    fn consent_requires_explicit_response_and_cancel_fails_closed() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        for decision in [Some(true), Some(false), None] {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let target = GwConnectTarget {
                ntlm: true, paa: false, interactions: Some(sender), target_port: 3389,
                messages: None, gw_endpoint: "gateway.example:443".into(),
                gw_user: String::new(), gw_pass: String::new(), server: "target.example".into(),
            };
            let ui = std::thread::spawn(move || {
                match receiver.recv().unwrap() {
                    GatewayInteraction::Consent { message, reply, .. } => {
                        assert_eq!(message, "Consent text");
                        if let Some(value) = decision { reply.send(value).unwrap(); }
                    }
                    _ => panic!("Unexpected interaction"),
                }
            });
            let accepted = runtime.block_on(consent(&target, "Consent text".into())).is_ok();
            ui.join().unwrap();
            assert_eq!(accepted, decision == Some(true));
        }
    }
    #[test]
    fn service_message_unicode_and_malformed() {
        let bytes: Vec<u8> = "MFA bestätigen\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(super::decode_gateway_text(&bytes).unwrap(), "MFA bestätigen");
        assert!(super::decode_gateway_text(&[1]).is_err());
    }
}
