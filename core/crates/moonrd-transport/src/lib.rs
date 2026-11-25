//! QUIC transport between native Moon Remote peers.
//!
//! Used for same-account sessions over EasyTier and for LAN direct mode. Browser
//! viewers and support sessions use WebRTC instead (Phase 6); the session layer on top
//! is the same.
//!
//! * TLS 1.3 with raw public keys (RFC 7250): each side authenticates with its device
//!   Ed25519 key. The viewer pins the host's key from the device list; the host accepts
//!   only keys on its [`AllowList`].
//! * The channel binding for SPAKE2 is taken from the TLS exporter, so the PIN check is
//!   tied to this exact QUIC connection.
//! * The viewer opens one bidirectional control stream carrying length-delimited
//!   `Envelope`s ([`ControlStream`]).

mod keys;
mod verify;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use moonrd_proto::Envelope;
use moonrd_session::frame::{self, Decoder, FrameError};
use moonrd_session::pake::ChannelBinding;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::{AlwaysResolvesClientRawPublicKeys, ResolvesClientCert};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::server::{AlwaysResolvesServerRawPublicKeys, ResolvesServerCert};

pub use keys::{public_from_spki, spki, DeviceKey, PublicKey};
pub use quinn::Endpoint;
pub use verify::AllowList;

/// ALPN protocol id.
pub const ALPN: &[u8] = b"moonrd/1";
/// TLS exporter label for the SPAKE2 channel binding.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-moonrd-v1-binding";
/// Server name sent in the handshake; meaningless with raw public keys but required.
const SERVER_NAME: &str = "moonrd.invalid";

/// Transport errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS setup: {0}")]
    Tls(#[from] rustls::Error),
    #[error("QUIC setup: {0}")]
    Setup(String),
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("stream write: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("stream read: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("framing: {0}")]
    Frame(#[from] FrameError),
    #[error("peer did not present a usable device key")]
    NoPeerKey,
    #[error("TLS exporter unavailable")]
    Exporter,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("30 s fits")));
    // Bound obsolete video already handed to QUIC when the viewer falls behind.
    t.send_window(1024 * 1024);
    Arc::new(t)
}

/// Builds a host endpoint bound to `addr` (an EasyTier virtual address or, in LAN mode,
/// a physical one) that accepts viewers on `allow`.
pub fn host_endpoint(addr: SocketAddr, key: &DeviceKey, allow: AllowList) -> Result<quinn::Endpoint, Error> {
    let provider = provider();
    let certified = key.certified(&provider)?;
    let algs = provider.signature_verification_algorithms;
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verify::AllowedViewers { allow, algs }))
        .with_cert_resolver(resolver);
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0; // no 0-RTT: control messages must not be replayable
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| Error::Setup(e.to_string()))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config());
    Ok(quinn::Endpoint::server(cfg, addr)?)
}

/// Builds a viewer endpoint bound to `bind` (use port 0).
pub fn viewer_endpoint(bind: SocketAddr) -> Result<quinn::Endpoint, Error> {
    Ok(quinn::Endpoint::client(bind)?)
}

/// An established, mutually authenticated connection.
pub struct Session {
    pub conn: quinn::Connection,
    /// The peer's device key, as verified during the handshake.
    pub peer_key: PublicKey,
    /// Binding for the SPAKE2 run on this connection.
    pub binding: ChannelBinding,
}

impl Session {
    fn from_conn(conn: quinn::Connection) -> Result<Self, Error> {
        let peer_key = conn
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .and_then(|certs| certs.first().and_then(|c| public_from_spki(c)))
            .ok_or(Error::NoPeerKey)?;
        let mut ekm = [0u8; 32];
        conn.export_keying_material(&mut ekm, EXPORTER_LABEL, b"").map_err(|_| Error::Exporter)?;
        Ok(Self { conn, peer_key, binding: ChannelBinding::from_tls_exporter(&ekm) })
    }

    /// Viewer: opens the control stream.
    pub async fn open_control(&self) -> Result<ControlStream, Error> {
        let (send, recv) = self.conn.open_bi().await?;
        Ok(ControlStream::new(send, recv))
    }

    /// Host: accepts the viewer's control stream.
    pub async fn accept_control(&self) -> Result<ControlStream, Error> {
        let (send, recv) = self.conn.accept_bi().await?;
        Ok(ControlStream::new(send, recv))
    }
}

/// Viewer: connects to the host at `addr`, which must present `host_key`.
pub async fn connect(endpoint: &quinn::Endpoint, addr: SocketAddr, key: &DeviceKey, host_key: PublicKey) -> Result<Session, Error> {
    let provider = provider();
    let certified = key.certified(&provider)?;
    let algs = provider.signature_verification_algorithms;
    let resolver: Arc<dyn ResolvesClientCert> = Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verify::PinnedHost { expected: host_key, algs }))
        .with_client_cert_resolver(resolver);
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| Error::Setup(e.to_string()))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport_config());
    let conn = endpoint.connect_with(cfg, addr, SERVER_NAME)?.await?;
    Session::from_conn(conn)
}

/// Host: waits for the next authenticated viewer. Returns `None` when the endpoint closes.
/// Handshake failures (unknown viewer key, wrong ALPN) are skipped.
pub async fn accept(endpoint: &quinn::Endpoint) -> Option<Result<Session, Error>> {
    let incoming = endpoint.accept().await?;
    Some(match incoming.await {
        Ok(conn) => Session::from_conn(conn),
        Err(e) => Err(e.into()),
    })
}

/// Reliable, ordered stream of `Envelope`s.
pub struct ControlStream {
    send: ControlSender,
    recv: ControlReceiver,
}

pub struct ControlSender(quinn::SendStream);

pub struct ControlReceiver {
    stream: quinn::RecvStream,
    decoder: Decoder,
}

impl ControlStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send: ControlSender(send), recv: ControlReceiver { stream: recv, decoder: Decoder::new() } }
    }

    /// QUIC's two directions have independent flow control. Drive them concurrently
    /// so a blocked video write cannot prevent the host from receiving input.
    pub fn split(self) -> (ControlSender, ControlReceiver) {
        (self.send, self.recv)
    }

    pub async fn send(&mut self, msg: &Envelope) -> Result<(), Error> {
        self.send.send(msg).await
    }

    pub async fn recv(&mut self) -> Result<Option<Envelope>, Error> {
        self.recv.recv().await
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        self.send.finish()
    }

    pub async fn finish_and_flush(&mut self, timeout: Duration) {
        self.send.finish_and_flush(timeout).await;
    }
}

impl ControlReceiver {
    /// Next message, `None` when the peer finished the stream.
    pub async fn recv(&mut self) -> Result<Option<Envelope>, Error> {
        loop {
            if let Some(m) = self.decoder.next_frame()? {
                return Ok(Some(m));
            }
            match self.stream.read_chunk(64 * 1024, true).await? {
                Some(chunk) => self.decoder.push(&chunk.bytes),
                None if self.decoder.pending() == 0 => return Ok(None),
                None => return Err(Error::Frame(FrameError::Decode("stream ended inside a frame".into()))),
            }
        }
    }
}

impl ControlSender {
    pub async fn send(&mut self, msg: &Envelope) -> Result<(), Error> {
        self.0.write_all(&frame::encode(msg)).await?;
        Ok(())
    }

    /// Finishes the sending side.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.0.finish().map_err(|e| Error::Setup(e.to_string()))
    }

    /// Finishes the sending side and waits (up to `timeout`) until the peer has
    /// received everything. Use before closing the connection after a final message
    /// such as a refusal: dropping a quinn connection discards unacknowledged data.
    pub async fn finish_and_flush(&mut self, timeout: Duration) {
        if self.0.finish().is_ok() {
            let _ = tokio::time::timeout(timeout, self.0.stopped()).await;
        }
    }
}
