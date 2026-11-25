//! Host-side QUIC listener on loopback, SPAKE2 PIN/pairing handshake, and live session
//! bridge to the in-session agent pipe.
//!
//! Because EasyTier runs without a TUN adapter, the host's QUIC server binds
//! `127.0.0.1:0` (OS-chosen port). EasyTier proxies UDP packets sent to the host's
//! virtual IP and port onto loopback. The viewer's Ed25519 device key is verified by
//! TLS 1.3 raw public keys against [`DeviceDirectory`], and then [`HostHandshake`] runs
//! SPAKE2 against the host's PIN verifier, lockout state, and pairings.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use moonrd_proto::auth_message::Step;
use moonrd_proto::envelope::Msg;
use moonrd_proto::{AuthMessage, Bye, ByeReason, Envelope, Pong, SpecialActionKind};
use moonrd_session::handshake::{HostContext, HostHandshake, Outcome, grant_pairing};
use moonrd_session::lockout::Policy;
use moonrd_transport::{AllowList, ControlStream, DeviceKey, Endpoint, PublicKey};
use tokio::sync::watch;

use crate::agent_pipe::AgentBridge;
use crate::server_api::DeviceView;
use crate::state::Host;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Maps allowed viewer Ed25519 public keys to their server device IDs, and keeps the
/// QUIC [`AllowList`] in sync.
#[derive(Clone, Default)]
pub struct DeviceDirectory {
    allow: AllowList,
    by_key: Arc<RwLock<HashMap<PublicKey, String>>>,
}

impl DeviceDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_list(&self) -> AllowList {
        self.allow.clone()
    }

    pub fn device_id_for(&self, key: &PublicKey) -> Option<String> {
        self.by_key.read().unwrap_or_else(|e| e.into_inner()).get(key).cloned()
    }

    /// Replaces the allowed viewer set from `GET /v1/devices` and prunes pairings whose
    /// viewer device was removed from the account.
    pub fn update(&self, devices: &[DeviceView], host: &Mutex<Host>) {
        let mut map = HashMap::new();
        let valid_ids: Vec<&str> = devices.iter().map(|d| d.id.as_str()).collect();
        for d in devices {
            if d.is_self {
                continue;
            }
            if let Ok(raw) = B64.decode(&d.public_key)
                && let Ok(key) = <[u8; 32]>::try_from(raw.as_slice())
            {
                map.insert(key, d.id.clone());
            }
        }
        self.allow.replace(map.keys().copied());
        *self.by_key.write().unwrap_or_else(|e| e.into_inner()) = map;

        let mut h = host.lock().unwrap_or_else(|e| e.into_inner());
        let before = h.state.pairings.list().len();
        h.state.pairings.retain_devices(&valid_ids);
        if h.state.pairings.list().len() != before {
            let _ = h.save();
        }
    }
}

/// Callback invoked when an authenticated viewer requests `SPECIAL_ACTION_CTRL_ALT_DEL`.
pub type SasHook = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;

/// Binds the host QUIC endpoint on `127.0.0.1:0` and returns the endpoint plus its port.
pub fn bind_loopback(device_key: &DeviceKey, directory: &DeviceDirectory) -> Result<(Endpoint, u16), moonrd_transport::Error> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let ep = moonrd_transport::host_endpoint(addr, device_key, directory.allow_list())?;
    let port = ep.local_addr()?.port();
    Ok((ep, port))
}

/// Default UDP port for LAN direct mode (when enabled by the user).
pub const LAN_DIRECT_PORT: u16 = 47000;

/// Binds the host QUIC endpoint on `0.0.0.0:<port>` for LAN direct mode.
pub fn bind_lan(device_key: &DeviceKey, directory: &DeviceDirectory, port: u16) -> Result<(Endpoint, u16), moonrd_transport::Error> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    let ep = moonrd_transport::host_endpoint(addr, device_key, directory.allow_list())?;
    let bound = ep.local_addr()?.port();
    Ok((ep, bound))
}

/// Accepts incoming QUIC viewer connections until `shutdown` fires.
pub async fn serve<F>(
    endpoint: Endpoint,
    host: Arc<Mutex<Host>>,
    directory: DeviceDirectory,
    bridge: AgentBridge,
    send_sas: SasHook,
    mut shutdown: watch::Receiver<bool>,
    log: F,
) where
    F: Fn(&str) + Send + Sync + 'static,
{
    let log = Arc::new(log);
    loop {
        let incoming = tokio::select! {
            _ = shutdown.changed() => break,
            res = moonrd_transport::accept(&endpoint) => match res {
                Some(r) => r,
                None => break,
            },
        };
        let session = match incoming {
            Ok(s) => s,
            Err(e) => {
                log(&format!("quic: rejected connection: {e}"));
                continue;
            }
        };
        let host = host.clone();
        let directory = directory.clone();
        let bridge = bridge.clone();
        let send_sas = send_sas.clone();
        let stop = shutdown.clone();
        let log = log.clone();
        tokio::spawn(async move {
            handle_session(session, host, directory, bridge, send_sas, stop, &*log).await;
        });
    }
    endpoint.close(0u32.into(), b"host shutdown");
}

async fn handle_session<F: Fn(&str)>(
    session: moonrd_transport::Session,
    host: Arc<Mutex<Host>>,
    directory: DeviceDirectory,
    bridge: AgentBridge,
    send_sas: SasHook,
    mut shutdown: watch::Receiver<bool>,
    log: &F,
) {
    let Some(viewer_device_id) = directory.device_id_for(&session.peer_key) else {
        log("quic: viewer key disappeared from directory");
        return;
    };

    let mut control = match tokio::time::timeout(Duration::from_secs(10), session.accept_control()).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            log(&format!("quic: accept_control failed: {e}"));
            return;
        }
        Err(_) => {
            log("quic: viewer did not open control stream");
            return;
        }
    };

    let ctx = {
        let h = host.lock().unwrap_or_else(|e| e.into_inner());
        let (host_device_id, host_display_name) = match &h.state.registration {
            Some(r) => (r.device_id.clone(), r.name.clone()),
            None => (String::new(), String::new()),
        };
        HostContext {
            host_device_id,
            host_display_name,
            host_version: env!("CARGO_PKG_VERSION").into(),
            binding: session.binding,
            transport_viewer_device: Some(viewer_device_id.clone()),
            pin: h.state.pin.clone(),
            support_code: None,
            policy: Policy::default(),
        }
    };

    let mut hs = HostHandshake::new(ctx);
    let established = loop {
        let msg = tokio::select! {
            _ = shutdown.changed() => {
                send_bye(&mut control, ByeReason::HostShutdown).await;
                return;
            }
            r = tokio::time::timeout(HANDSHAKE_TIMEOUT, control.recv()) => match r {
                Ok(Ok(Some(m))) => m,
                Ok(Ok(None)) => return,
                Ok(Err(e)) => {
                    log(&format!("quic: handshake read error: {e}"));
                    return;
                }
                Err(_) => {
                    log("quic: handshake timed out");
                    return;
                }
            },
        };

        let outcome = {
            let mut h = host.lock().unwrap_or_else(|e| e.into_inner());
            hs.on_message(msg, &mut *h)
        };

        match outcome {
            Outcome::Continue(out) => {
                if send_all(&mut control, &out).await.is_err() {
                    return;
                }
            }
            Outcome::Established { out, session } => {
                if send_all(&mut control, &out).await.is_err() {
                    return;
                }
                break session;
            }
            Outcome::Failed { out, failure } => {
                log(&format!("quic: handshake failed for viewer={viewer_device_id}: {failure:?}"));
                let _ = send_all(&mut control, &out).await;
                control.finish_and_flush(FLUSH_TIMEOUT).await;
                return;
            }
            Outcome::NeedSecret { .. } | Outcome::NeedConsent { .. } => {
                // Support sessions with user consent are Phase 7.
                send_bye(&mut control, ByeReason::ProtocolError).await;
                return;
            }
        }
    };

    log(&format!("quic: session established viewer={} method={:?}", established.peer.device_id, established.method));

    let crate::agent_pipe::ViewerAttachment { input, mut from_agent } = bridge.attach_viewer();
    let (mut send, mut recv) = control.split();
    let (replies, mut pending_replies) = tokio::sync::mpsc::channel(8);
    let receive_input = async {
        while let Ok(Some(env)) = recv.recv().await {
            match &env.msg {
                Some(Msg::Ping(p)) => {
                    let _ = replies.try_send(Envelope { msg: Some(Msg::Pong(Pong { nonce: p.nonce, sent_time_us: p.sent_time_us })) });
                }
                Some(Msg::Auth(AuthMessage { step: Some(Step::PairingRequest(req)) })) => {
                    let grant = {
                        let mut h = host.lock().unwrap_or_else(|e| e.into_inner());
                        grant_pairing(established.method, &established.peer, &req.viewer_label, &mut *h)
                    };
                    let _ = replies.try_send(grant);
                }
                Some(Msg::SpecialAction(a)) if a.kind == SpecialActionKind::SpecialActionCtrlAltDel as i32 => {
                    if let Err(e) = send_sas() {
                        log(&format!("quic: send_sas failed: {e}"));
                    }
                }
                Some(Msg::Bye(_)) => break,
                Some(_) => { input.send_to_agent(env); }
                None => {}
            }
        }
    };
    let send_output = async {
        loop {
            let env = tokio::select! {
                biased;
                Some(reply) = pending_replies.recv() => reply,
                msg = from_agent.recv() => match msg {
                    Some(env) => env,
                    None => {
                        let bye = Envelope { msg: Some(Msg::Bye(Bye { reason: ByeReason::HostUserEnded as i32, resume_token: Vec::new() })) };
                        let _ = send.send(&bye).await;
                        send.finish_and_flush(FLUSH_TIMEOUT).await;
                        break;
                    }
                },
            };
            if send.send(&env).await.is_err() { break; }
        }
    };
    tokio::select! {
        _ = shutdown.changed() => {},
        _ = receive_input => {},
        _ = send_output => {},
    }

    log(&format!("quic: session ended viewer={}", established.peer.device_id));
}

async fn send_all(control: &mut ControlStream, msgs: &[Envelope]) -> Result<(), moonrd_transport::Error> {
    for m in msgs {
        control.send(m).await?;
    }
    Ok(())
}

async fn send_bye(control: &mut ControlStream, reason: ByeReason) {
    let bye = Envelope { msg: Some(Msg::Bye(Bye { reason: reason as i32, resume_token: Vec::new() })) };
    let _ = control.send(&bye).await;
    control.finish_and_flush(FLUSH_TIMEOUT).await;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ed25519_dalek::SigningKey;
    use moonrd_proto::{AuthMethod, ClipboardData, KeyEvent, PairingRequest, Ping, PointerButton, PointerEvent, SessionKind, SpecialAction, VideoFrame};
    use moonrd_session::handshake::{Failure, HeldPairing, ViewerContext, ViewerHandshake};
    use moonrd_session::frame::{self, Decoder};
    use rand_core::OsRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::agent_pipe::serve_stream;
    use crate::state::{Protector, Registration, StateFile};

    struct Plain;
    impl Protector for Plain {
        fn protect(&self, p: &[u8]) -> io::Result<Vec<u8>> {
            Ok(p.to_vec())
        }
        fn unprotect(&self, s: &[u8]) -> io::Result<Vec<u8>> {
            Ok(s.to_vec())
        }
    }

    fn make_device_key(sk: &SigningKey) -> DeviceKey {
        DeviceKey::new(sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    pub(crate) async fn run_viewer_handshake(
        control: &mut ControlStream,
        ctx: ViewerContext,
        pin: Option<&str>,
    ) -> Result<moonrd_session::handshake::Established<moonrd_session::handshake::HostInfo>, Failure> {
        let (mut vh, hello) = ViewerHandshake::new(ctx);
        control.send(&hello).await.unwrap();
        loop {
            let msg = control.recv().await.unwrap().expect("stream closed during handshake");
            let outcome = match vh.on_message(msg) {
                Outcome::NeedSecret { out, .. } => {
                    for m in &out {
                        control.send(m).await.unwrap();
                    }
                    vh.provide_secret(pin.expect("pin required"))
                }
                other => other,
            };
            match outcome {
                Outcome::Continue(out) => {
                    for m in &out {
                        control.send(m).await.unwrap();
                    }
                }
                Outcome::Established { out, session } => {
                    for m in &out {
                        control.send(m).await.unwrap();
                    }
                    return Ok(session);
                }
                Outcome::Failed { out, failure } => {
                    for m in &out {
                        control.send(m).await.unwrap();
                    }
                    return Err(failure);
                }
                Outcome::NeedSecret { .. } | Outcome::NeedConsent { .. } => unreachable!(),
            }
        }
    }

    #[tokio::test]
    async fn full_pin_pairing_agent_bridge_and_sas_over_quic() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = Host::open(StateFile::new(dir.path().join("host.bin"), Box::new(Plain))).unwrap();
        let host_sk = h.device_key().unwrap();
        let host_key = make_device_key(&host_sk);
        h.set_pin("482916").unwrap();
        h.complete_registration(Registration {
            server_url: "http://127.0.0.1:8621".into(),
            device_id: "d-host".into(),
            user_sub: "u1".into(),
            name: "Office".into(),
            device_token: "mrdd_host".into(),
            roster_key: "AAAA".into(),
            roster_key_id: "k1".into(),
        })
        .unwrap();
        let host = Arc::new(Mutex::new(h));

        let viewer_sk = SigningKey::generate(&mut OsRng);
        let viewer_key = make_device_key(&viewer_sk);

        let directory = DeviceDirectory::new();
        directory.update(
            &[DeviceView {
                id: "d-viewer".into(),
                name: "Laptop".into(),
                kind: "viewer".into(),
                public_key: B64.encode(viewer_key.public()),
                online: true,
                is_self: false,
            }],
            &host,
        );

        let bridge = AgentBridge::new();
        let (stop_tx, stop_rx) = watch::channel(false);

        // Attach a fake in-session agent on a duplex stream.
        let (service_end, mut agent_end) = tokio::io::duplex(16 * 1024);
        let agent_task = tokio::spawn(serve_stream(service_end, bridge.clone(), stop_rx.clone()));
        while !bridge.agent_connected() {
            tokio::task::yield_now().await;
        }

        let sas_calls = Arc::new(AtomicUsize::new(0));
        let sas_calls_hook = sas_calls.clone();
        let sas_hook: SasHook = Arc::new(move || {
            sas_calls_hook.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let (ep, port) = bind_loopback(&host_key, &directory).unwrap();
        let server_task = tokio::spawn(serve(ep, host.clone(), directory.clone(), bridge.clone(), sas_hook, stop_rx.clone(), |_| {}));

        let viewer_ep = moonrd_transport::viewer_endpoint(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

        // 1. Wrong PIN is refused and increments lockout.
        {
            let sess = moonrd_transport::connect(&viewer_ep, addr, &viewer_key, *host_key.public()).await.unwrap();
            let mut ctrl = sess.open_control().await.unwrap();
            let err = run_viewer_handshake(
                &mut ctrl,
                ViewerContext {
                    kind: SessionKind::RemoteAccess,
                    device_id: "d-viewer".into(),
                    display_name: "Laptop".into(),
                    client_version: "0.1.0".into(),
                    binding: sess.binding,
                    pairing: None,
                },
                Some("999888"),
            )
            .await
            .unwrap_err();
            assert!(matches!(err, Failure::BadSecret { method: AuthMethod::Pin, remaining: 4, .. }));
            assert_eq!(host.lock().unwrap().state.lockout.failures, 1);
        }

        // 2. Correct PIN establishes session, grants pairing, bridges agent and triggers SAS.
        let granted_pairing = {
            let sess = moonrd_transport::connect(&viewer_ep, addr, &viewer_key, *host_key.public()).await.unwrap();
            let mut ctrl = sess.open_control().await.unwrap();
            let est = run_viewer_handshake(
                &mut ctrl,
                ViewerContext {
                    kind: SessionKind::RemoteAccess,
                    device_id: "d-viewer".into(),
                    display_name: "Laptop".into(),
                    client_version: "0.1.0".into(),
                    binding: sess.binding,
                    pairing: None,
                },
                Some("482916"),
            )
            .await
            .unwrap();
            assert_eq!(est.method, AuthMethod::Pin);
            assert_eq!(host.lock().unwrap().state.lockout.failures, 0);

            // Ping -> Pong.
            ctrl.send(&Envelope { msg: Some(Msg::Ping(Ping { nonce: 42, sent_time_us: 1000 })) }).await.unwrap();
            let pong = ctrl.recv().await.unwrap().unwrap();
            assert!(matches!(pong.msg, Some(Msg::Pong(p)) if p.nonce == 42));

            // PairingRequest -> PairingGrant.
            ctrl.send(&Envelope {
                msg: Some(Msg::Auth(AuthMessage { step: Some(Step::PairingRequest(PairingRequest { viewer_label: "My Laptop".into() })) })),
            })
            .await
            .unwrap();
            let grant_env = ctrl.recv().await.unwrap().unwrap();
            let grant = match grant_env.msg {
                Some(Msg::Auth(AuthMessage { step: Some(Step::PairingGrant(g)) })) => g,
                other => panic!("expected PairingGrant, got {other:?}"),
            };
            assert!(!grant.pairing_id.is_empty());
            assert_eq!(grant.pairing_key.len(), 32);

            // PointerEvent -> arrives on agent pipe (after the automatic KeyframeRequest).
            ctrl.send(&Envelope {
                msg: Some(Msg::Pointer(PointerEvent {
                    display_id: 1,
                    x: 123,
                    y: 456,
                    button: PointerButton::Left as i32,
                    pressed: true,
                    wheel_x: 0,
                    wheel_y: 0,
                })),
            })
            .await
            .unwrap();

            let mut dec = Decoder::new();
            let mut buf = [0u8; 4096];
            let mut saw_pointer = false;
            for _ in 0..4 {
                let n = agent_end.read(&mut buf).await.unwrap();
                dec.push(&buf[..n]);
                while let Some(m) = dec.next_frame().unwrap() {
                    if matches!(m.msg, Some(Msg::Pointer(p)) if p.x == 123 && p.y == 456) {
                        saw_pointer = true;
                    }
                }
                if saw_pointer {
                    break;
                }
            }
            assert!(saw_pointer);

            // Agent -> viewer ClipboardData.
            let clip = Envelope { msg: Some(Msg::Clipboard(ClipboardData { text: "from-host".into() })) };
            agent_end.write_all(&frame::encode(&clip)).await.unwrap();
            let got = ctrl.recv().await.unwrap().unwrap();
            assert!(matches!(got.msg, Some(Msg::Clipboard(c)) if c.text == "from-host"));

            // CtrlAltDel -> invokes SAS hook.
            ctrl.send(&Envelope { msg: Some(Msg::SpecialAction(SpecialAction { kind: SpecialActionKind::SpecialActionCtrlAltDel as i32 })) })
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while sas_calls.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();

            // Leave the viewer's receive side untouched and fill QUIC's video send
            // window. The reverse direction must still deliver input to the agent.
            let video = frame::encode(&Envelope { msg: Some(Msg::VideoFrame(VideoFrame {
                sequence: 1, data: vec![0; 1024 * 1024], ..Default::default()
            })) });
            for _ in 0..24 {
                agent_end.write_all(&video).await.unwrap();
            }
            let inputs = [
                Msg::Key(KeyEvent { scancode: 0x04, pressed: true, ..Default::default() }),
                Msg::Pointer(PointerEvent { x: 555, y: 777, button: PointerButton::Left as i32, pressed: true, ..Default::default() }),
            ];
            for input in &inputs {
                ctrl.send(&Envelope { msg: Some(input.clone()) }).await.unwrap();
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                let mut index = 0;
                while index < inputs.len() {
                    let n = agent_end.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0);
                    dec.push(&buf[..n]);
                    while let Some(msg) = dec.next_frame().unwrap() {
                        if msg.msg.as_ref() == inputs.get(index) { index += 1; }
                    }
                }
            }).await.expect("key and click must arrive while video is blocked");

            HeldPairing { id: grant.pairing_id, key: grant.pairing_key.try_into().unwrap() }
        };

        // 3. Reconnect with the granted pairing key — no PIN needed!
        {
            let sess = moonrd_transport::connect(&viewer_ep, addr, &viewer_key, *host_key.public()).await.unwrap();
            let mut ctrl = sess.open_control().await.unwrap();
            let est = run_viewer_handshake(
                &mut ctrl,
                ViewerContext {
                    kind: SessionKind::RemoteAccess,
                    device_id: "d-viewer".into(),
                    display_name: "Laptop".into(),
                    client_version: "0.1.0".into(),
                    binding: sess.binding,
                    pairing: Some(granted_pairing),
                },
                None,
            )
            .await
            .unwrap();
            assert_eq!(est.method, AuthMethod::Pairing);
        }

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), agent_task).await;
    }
}
