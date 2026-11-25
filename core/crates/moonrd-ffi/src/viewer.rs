//! Viewer session driver: QUIC connect → SPAKE2 handshake → H.264 DXVA decode & D3D11
//! HWND rendering + bidirectional input/clipboard/control forwarding.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::mpsc::Sender as StdSender;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use moonrd_proto::auth_message::Step;
use moonrd_proto::envelope::Msg;
use moonrd_proto::{
    AuthMessage, AuthMethod, Bye, ByeReason, Envelope, PairingRequest, SessionKind, VideoConfig,
};
use moonrd_session::handshake::{Failure, HeldPairing, Outcome, ViewerContext, ViewerHandshake};
use moonrd_transport::{DeviceKey, PublicKey};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectParams {
    pub addr: String,
    pub host_public_key: String,
    pub viewer_seed: String,
    pub viewer_device_id: String,
    #[serde(default)]
    pub viewer_display_name: String,
    /// Native Win32 HWND cast to u64 (0 = headless / no video presenter).
    #[serde(default)]
    pub hwnd: u64,
    #[serde(default)]
    pub client_session_id: Option<String>,
    #[serde(default)]
    pub pairing_id: Option<String>,
    #[serde(default)]
    pub pairing_key: Option<String>,
    #[serde(default)]
    pub overlay: Option<ViewerOverlay>,
    #[serde(default)]
    pub local_rpc_port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewerOverlay {
    network_name: String,
    credential: String,
    ipv4: String,
    peers: Vec<String>,
}

/// A session owns its UDP forward and EasyTier child. The host may run on a different
/// account from the interactive user, so a viewer can also join independently.
fn start_overlay(overlay: ViewerOverlay, viewer_id: &str, remote: SocketAddr) -> std::io::Result<(SocketAddr, tokio::process::Child, tempfile::TempDir)> {
    use moonrd_et::config::{CompanionConfig, core_args, pick_free_loopback_port};
    use std::io;
    let install = std::env::current_exe()?;
    let root = install.parent().ok_or_else(|| io::Error::other("missing executable directory"))?;
    let data = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or_else(|| io::Error::other("missing user data directory"))?)
        .join("MoonRemote").join("viewer-routes");
    std::fs::create_dir_all(&data)?;
    let temp = tempfile::tempdir_in(data)?;
    let config = temp.path().join("viewer.toml");
    let cfg = CompanionConfig {
        hostname: viewer_id.to_owned(), network_name: overlay.network_name, credential: overlay.credential,
        ipv4: overlay.ipv4, peers: overlay.peers,
    };
    std::fs::write(&config, cfg.to_toml())?;
    let local = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?;
    let mut cmd = tokio::process::Command::new(root.join("easytier").join("easytier-core.exe"));
    cmd.args(core_args(&config, pick_free_loopback_port()?))
        .arg("--port-forward").arg(format!("udp://{local}/{remote}"))
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    Ok((local, cmd.spawn()?, temp))
}

struct Forward {
    cli: std::path::PathBuf,
    rpc: u16,
    local: u16,
    remote: std::net::SocketAddrV4,
}

impl Forward {
    async fn add(rpc: u16, remote: std::net::SocketAddrV4) -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let cli = exe.with_file_name("easytier").join("easytier-cli.exe");
        let local = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port();
        let mut cmd = tokio::process::Command::new(&cli);
        cmd.args(moonrd_et::config::port_forward_add(rpc, local, *remote.ip(), remote.port())).kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let out = tokio::time::timeout(Duration::from_secs(8), cmd.output()).await??;
        if !out.status.success() { return Err(std::io::Error::other("EasyTier refused the session forward")); }
        Ok(Self { cli, rpc, local, remote })
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        let mut cmd = std::process::Command::new(&self.cli);
        cmd.args(moonrd_et::config::port_forward_remove(self.rpc, self.local, *self.remote.ip(), self.remote.port()));
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x08000000);
        let _ = cmd.output();
    }
}

pub enum ViewerCmd {
    SubmitPin { pin: String, remember: bool, label: String },
    Send(Envelope),
    Disconnect,
}

fn emit_event(events: &StdSender<Value>, session_id: Option<&str>, mut event: Value) {
    if let Some(id) = session_id {
        event["clientSessionId"] = json!(id);
    }
    let _ = events.send(event);
}

pub async fn run_session(
    params: ConnectParams,
    mut cmd_rx: mpsc::Receiver<ViewerCmd>,
    events: StdSender<Value>,
) {
    let emit = |v: Value| emit_event(&events, params.client_session_id.as_deref(), v);
    emit(json!({"type": "state", "state": "connecting"}));

    let mut addr: SocketAddr = match params.addr.parse() {
        Ok(a) => a,
        Err(e) => {
            emit(json!({"type": "disconnected", "reason": format!("invalid address: {e}")}));
            return;
        }
    };
    let _forward = if let (Some(rpc), SocketAddr::V4(remote)) = (params.local_rpc_port, addr) {
        match Forward::add(rpc, remote).await {
            Ok(forward) => { addr = (Ipv4Addr::LOCALHOST, forward.local).into(); Some(forward) }
            Err(e) => { emit(json!({"type":"disconnected","reason":format!("EasyTier forward: {e}")})); return; }
        }
    } else { None };
    let _route = if let Some(overlay) = params.overlay {
        match start_overlay(overlay, &params.viewer_device_id, addr) {
            Ok((local, child, config)) => { addr = local; Some((child, config)) }
            Err(e) => {
                emit(json!({"type":"disconnected","reason":format!("viewer network: {e}")}));
                return;
            }
        }
    } else { None };
    let host_key: PublicKey = match B64.decode(&params.host_public_key).ok().and_then(|b| b.try_into().ok()) {
        Some(k) => k,
        None => {
            emit(json!({"type": "disconnected", "reason": "invalid hostPublicKey"}));
            return;
        }
    };
    let seed: [u8; 32] = match B64.decode(&params.viewer_seed).ok().and_then(|b| b.try_into().ok()) {
        Some(s) => s,
        None => {
            emit(json!({"type": "disconnected", "reason": "invalid viewerSeed"}));
            return;
        }
    };
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let viewer_key = DeviceKey::new(seed, sk.verifying_key().to_bytes());

    let pairing = match (params.pairing_id.as_deref(), params.pairing_key.as_deref()) {
        (Some(id_b64), Some(key_b64)) => {
            match (B64.decode(id_b64).ok(), B64.decode(key_b64).ok().and_then(|k| <[u8; 32]>::try_from(k).ok())) {
                (Some(id), Some(key)) => Some(HeldPairing { id, key }),
                _ => None,
            }
        }
        _ => None,
    };

    let ep = match moonrd_transport::viewer_endpoint(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))) {
        Ok(ep) => ep,
        Err(e) => {
            emit(json!({"type": "disconnected", "reason": format!("quic endpoint: {e}")}));
            return;
        }
    };

    let mut retry = true;
    let session = loop {
        let timeout = Duration::from_secs(if retry { 8 } else { 15 });
        let attempt = tokio::select! {
            result = tokio::time::timeout(timeout, moonrd_transport::connect(&ep, addr, &viewer_key, host_key)) => result,
            _ = async {
                while let Some(command) = cmd_rx.recv().await {
                    if matches!(command, ViewerCmd::Disconnect) { break; }
                }
            } => {
                emit(json!({"type": "disconnected", "reason": "cancelled"}));
                return;
            }
        };
        match attempt {
            Ok(Ok(session)) => break session,
            Ok(Err(e)) => {
                emit(json!({"type": "disconnected", "reason": format!("connect failed: {e}")}));
                return;
            }
            Err(_) if retry => {
                retry = false;
                emit(json!({"type": "state", "state": "retrying_transport"}));
            }
            Err(_) => {
                emit(json!({"type": "disconnected", "reason": "connect timed out"}));
                return;
            }
        }
    };

    let mut control = match session.open_control().await {
        Ok(c) => c,
        Err(e) => {
            emit(json!({"type": "disconnected", "reason": format!("open control stream: {e}")}));
            return;
        }
    };

    let (mut hs, hello) = ViewerHandshake::new(ViewerContext {
        kind: SessionKind::RemoteAccess,
        device_id: params.viewer_device_id,
        display_name: params.viewer_display_name,
        client_version: env!("CARGO_PKG_VERSION").into(),
        binding: session.binding,
        pairing,
    });
    if let Err(e) = control.send(&hello).await {
        emit(json!({"type": "disconnected", "reason": format!("send hello: {e}")}));
        return;
    }

    let mut pending_remember: Option<String> = None;

    let established = loop {
        let msg = match control.recv().await {
            Ok(Some(m)) => m,
            Ok(None) => {
                emit(json!({"type": "disconnected", "reason": "host closed during handshake"}));
                return;
            }
            Err(e) => {
                emit(json!({"type": "disconnected", "reason": format!("handshake read: {e}")}));
                return;
            }
        };

        let mut outcome = hs.on_message(msg);
        if let Outcome::NeedSecret { method, out } = outcome {
            for m in &out {
                let _ = control.send(m).await;
            }
            emit(json!({
                "type": "need_secret",
                "method": format!("{method:?}"),
                "hostName": hs.host().map(|h| h.display_name.clone()).unwrap_or_default(),
            }));
            // Wait for submit_pin or disconnect.
            let pin = loop {
                let command = tokio::select! {
                    command = cmd_rx.recv() => command,
                    received = control.recv() => {
                        let Ok(Some(message)) = received else {
                            emit(json!({"type":"disconnected","reason":"host closed while waiting for PIN"}));
                            return;
                        };
                        match hs.on_message(message) {
                            Outcome::Continue(out) => {
                                for message in out {
                                    if control.send(&message).await.is_err() {
                                        emit(json!({"type":"disconnected","reason":"host closed during PIN exchange"}));
                                        return;
                                    }
                                }
                                continue;
                            }
                            Outcome::Failed { failure, .. } => {
                                emit(json!({"type":"disconnected","reason":format!("{failure:?}")}));
                                return;
                            }
                            _ => {
                                emit(json!({"type":"disconnected","reason":"unexpected PIN exchange"}));
                                return;
                            }
                        }
                    }
                };
                match command {
                    Some(ViewerCmd::SubmitPin { pin, remember, label }) => {
                        if remember {
                            pending_remember = Some(label);
                        }
                        break pin;
                    }
                    Some(ViewerCmd::Disconnect) | None => {
                        let _ = control
                            .send(&Envelope { msg: Some(Msg::Bye(Bye { reason: ByeReason::UserClosed as i32, resume_token: vec![] })) })
                            .await;
                        emit(json!({"type": "disconnected", "reason": "cancelled"}));
                        return;
                    }
                    Some(ViewerCmd::Send(_)) => {}
                }
            };
            outcome = hs.provide_secret(&pin);
        }

        match outcome {
            Outcome::Continue(out) => {
                for m in &out {
                    if let Err(e) = control.send(m).await {
                        emit(json!({"type": "disconnected", "reason": format!("handshake send: {e}")}));
                        return;
                    }
                }
            }
            Outcome::Established { out, session } => {
                for m in &out {
                    let _ = control.send(m).await;
                }
                break session;
            }
            Outcome::Failed { out, failure } => {
                for m in &out {
                    let _ = control.send(m).await;
                }
                let retry_with_pin = matches!(failure, Failure::BadSecret { lockout_secs: 0, .. });
                emit(json!({"type": "auth_failed", "reason": format!("{failure:?}"), "retryWithPin": retry_with_pin}));
                emit(json!({"type": "disconnected", "reason": format!("{failure:?}")}));
                return;
            }
            Outcome::NeedSecret { .. } | Outcome::NeedConsent { .. } => {}
        }
    };

    emit(json!({
        "type": "connected",
        "method": format!("{:?}", established.method),
        "hostDeviceId": established.peer.device_id,
        "hostName": established.peer.display_name,
    }));

    // Request "remember this controller" pairing if requested during PIN entry.
    if established.method == AuthMethod::Pin
        && let Some(label) = pending_remember.take()
    {
        let _ = control
            .send(&Envelope {
                msg: Some(Msg::Auth(AuthMessage { step: Some(Step::PairingRequest(PairingRequest { viewer_label: label })) })),
            })
            .await;
    }

    // Optional video presenter thread (when hwnd != 0 on Windows). Keeping decode/Present
    // on its own OS thread keeps the async QUIC loop non-blocking and Send.
    #[cfg(windows)]
    let video_tx = (params.hwnd != 0).then(|| spawn_presenter(params.hwnd, events.clone(), params.client_session_id.clone()));
    #[cfg(windows)]
    let mut legacy_config = None;
    #[cfg(windows)]
    let mut active_config: Option<std::sync::Arc<PresentationConfig>> = None;

    let (mut send, mut recv) = control.split();
    let send_input = async {
        loop {
            match cmd_rx.recv().await {
                Some(ViewerCmd::Send(env)) => {
                    if send.send(&env).await.is_err() {
                        break;
                    }
                }
                Some(ViewerCmd::Disconnect) | None => {
                    let _ = send
                        .send(&Envelope { msg: Some(Msg::Bye(Bye { reason: ByeReason::UserClosed as i32, resume_token: vec![] })) })
                        .await;
                    send.finish_and_flush(Duration::from_secs(1)).await;
                    break;
                }
                Some(ViewerCmd::SubmitPin { .. }) => {}
            }
        }
    };
    let receive_output = async {
        while let Ok(Some(env)) = recv.recv().await {
            match env.msg {
                Some(Msg::DisplayList(dl)) => {
                    #[cfg(windows)]
                    if let Some(d) = dl.displays.iter().find(|d| d.id == dl.active_id) {
                        // Older agents only sent the codec announcement at startup;
                        // their encoder always used the active display with these limits.
                        legacy_config = Some(PresentationConfig {
                            video: VideoConfig {
                                width: d.width.clamp(320, 1920) & !1, height: d.height.clamp(240, 1080) & !1,
                                fps: 30, ..Default::default()
                            },
                            active_id: dl.active_id,
                        });
                    }
                    let items: Vec<Value> = dl.displays.iter().map(|d| json!({
                        "id": d.id, "name": d.name, "width": d.width, "height": d.height, "primary": d.primary
                    })).collect();
                    emit(json!({"type": "displays", "activeId": dl.active_id, "displays": items}));
                }
                Some(Msg::VideoConfig(vc)) => {
                    emit(json!({
                        "type": "video_config",
                        "width": vc.width,
                        "height": vc.height,
                        "fps": vc.fps,
                        "hardware": vc.hardware,
                        "encoderName": vc.encoder_name,
                    }));
                    #[cfg(windows)]
                    {
                        let active_id = if vc.display_id != 0 { vc.display_id }
                            else { legacy_config.as_ref().map_or(1, |c| c.active_id) };
                        active_config = Some(std::sync::Arc::new(PresentationConfig { video: vc, active_id }));
                    }
                    #[cfg(not(windows))]
                    let _ = vc;
                }
                Some(Msg::VideoFrame(vf)) => {
                    #[cfg(windows)]
                    if active_config.is_none() && vf.keyframe {
                        active_config = legacy_config.clone().map(std::sync::Arc::new);
                    }
                    #[cfg(windows)]
                    if let (Some(tx), Some(cfg)) = (&video_tx, &active_config) {
                        let _ = tx.try_send((cfg.clone(), vf));
                    }
                    #[cfg(not(windows))]
                    let _ = vf;
                }
                Some(Msg::Clipboard(c)) => {
                    emit(json!({"type": "clipboard", "text": c.text}));
                }
                Some(Msg::Notice(n)) => {
                    emit(json!({"type": "notice", "kind": n.kind, "message": n.message}));
                }
                Some(Msg::Auth(AuthMessage { step: Some(Step::PairingGrant(g)) })) => {
                    if g.pairing_id.len() == 16 && g.pairing_key.len() == 32 {
                        emit(json!({
                            "type": "pairing_granted",
                            "pairingId": B64.encode(&g.pairing_id),
                            "pairingKey": B64.encode(&g.pairing_key),
                        }));
                    } else {
                        emit(json!({"type": "pairing_declined"}));
                    }
                }
                Some(Msg::Bye(b)) => {
                    return format!("bye({})", b.reason);
                }
                _ => {}
            }
        }
        "closed".into()
    };
    let reason = tokio::select! {
        _ = send_input => "closed".into(),
        reason = receive_output => reason,
    };
    emit(json!({"type": "disconnected", "reason": reason}));
}

#[cfg(windows)]
#[derive(Clone)]
struct PresentationConfig {
    video: VideoConfig,
    active_id: u32,
}

#[cfg(windows)]
type PresentFrame = (std::sync::Arc<PresentationConfig>, moonrd_proto::VideoFrame);

#[cfg(windows)]
fn spawn_presenter(hwnd: u64, events: StdSender<Value>, session_id: Option<String>) -> std::sync::mpsc::SyncSender<PresentFrame> {
    use moonrd_media::decoder::HwndPresenter;
    use std::sync::Arc;
    use windows::Win32::Foundation::HWND;
    let (tx, rx) = std::sync::mpsc::sync_channel::<PresentFrame>(8);
    let _ = std::thread::Builder::new().name("moonrd-presenter".into()).spawn(move || {
        let emit = |v| emit_event(&events, session_id.as_deref(), v);
        let hwnd = HWND(hwnd as usize as *mut core::ffi::c_void);
        if let Err(e) = moonrd_media::init_media_foundation() {
            emit(json!({"type":"notice","message":format!("Video initialization failed: {e}")}));
            return;
        }
        let mut p = None;
        let mut current: Option<Arc<PresentationConfig>> = None;
        let mut presented = false;
        let mut reported_error = false;
        while let Ok((cfg, frame)) = rx.recv() {
            let vc = &cfg.video;
            if current.as_ref().is_none_or(|before| !Arc::ptr_eq(before, &cfg)) {
                if !frame.keyframe { continue; }
                // Destroy the previous flip-model swap chain before binding the same HWND.
                drop(p.take());
                current = Some(cfg.clone());
                presented = false;
                reported_error = false;
                match unsafe { HwndPresenter::new(hwnd, vc.width, vc.height, vc.fps) } {
                    Ok(next) => p = Some(next),
                    Err(e) => {
                        emit(json!({"type":"notice","message":format!("Video presenter failed: {e}")}));
                    }
                }
            }
            let Some(p) = p.as_mut() else { continue; };
            match p.present_frame(&frame.data, frame.keyframe, (frame.capture_time_us as i64) * 10) {
                Ok(true) if !presented => {
                    presented = true;
                    emit(json!({"type":"video_started", "width":vc.width, "height":vc.height,
                        "displayId":cfg.active_id, "canSwitchDisplay":vc.display_id != 0}));
                }
                Err(e) if !reported_error => {
                    reported_error = true;
                    emit(json!({"type":"notice","message":format!("Video decode failed: {e}")}));
                }
                _ => {}
            }
        }
    });
    tx
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use moonrd_service::agent_pipe::AgentBridge;
    use moonrd_service::quic_host::{DeviceDirectory, bind_loopback, serve};
    use moonrd_service::server_api::DeviceView;
    use moonrd_service::state::{Host, StateFile};
    use moonrd_service::win::DpapiMachine;
    use std::sync::{Arc, Mutex};

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn viewer_remembers_host_after_delayed_pin_and_reconnects_without_it() {
        let temp = tempfile::tempdir().unwrap();
        let mut h = Host::open(StateFile::new(temp.path().join("test.bin"), Box::new(DpapiMachine))).unwrap();
        let host_sk = h.device_key().unwrap();
        let host_key = DeviceKey::new(host_sk.to_bytes(), host_sk.verifying_key().to_bytes());
        h.set_pin("482916").unwrap();
        let host = Arc::new(Mutex::new(h));
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let directory = DeviceDirectory::new();
        directory.update(&[DeviceView {
            id: "test-viewer".into(), name: "Viewer".into(), kind: "viewer".into(),
            public_key: B64.encode(sk.verifying_key().to_bytes()), online: true, is_self: false,
        }], &host);
        let (ep, port) = bind_loopback(&host_key, &directory).unwrap();
        let (stop, stopping) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve(ep, host, directory, AgentBridge::new(), Arc::new(|| Ok(())), stopping, |_| {}));
        let params = || ConnectParams {
            addr: format!("127.0.0.1:{port}"), host_public_key: B64.encode(host_key.public()),
            viewer_seed: B64.encode(sk.to_bytes()), viewer_device_id: "test-viewer".into(), viewer_display_name: "Viewer".into(),
            hwnd: 0, client_session_id: Some("ui-session".into()), pairing_id: None, pairing_key: None, overlay: None, local_rpc_port: None,
        };
        let (tx, rx) = mpsc::channel(8);
        let (events, received) = std::sync::mpsc::channel();
        let viewer = tokio::spawn(run_session(params(), rx, events));
        let (pairing_id, pairing_key) = loop {
            let event = received.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(event["clientSessionId"], "ui-session");
            match event["type"].as_str() {
                Some("need_secret") => {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    tx.send(ViewerCmd::SubmitPin { pin: "482916".into(), remember: true, label: "Test viewer".into() }).await.unwrap();
                }
                Some("connected") => assert_eq!(event["method"], "Pin"),
                Some("pairing_granted") => break (
                    event["pairingId"].as_str().unwrap().to_owned(),
                    event["pairingKey"].as_str().unwrap().to_owned(),
                ),
                Some("disconnected" | "auth_failed") => panic!("viewer handshake failed: {event}"),
                _ => {}
            }
        };
        tx.send(ViewerCmd::Disconnect).await.unwrap();
        viewer.await.unwrap();
        let (tx, rx) = mpsc::channel(8);
        let (events, received) = std::sync::mpsc::channel();
        let viewer = tokio::spawn(run_session(ConnectParams {
            client_session_id: Some("reconnect".into()),
            pairing_id: Some(pairing_id),
            pairing_key: Some(pairing_key),
            ..params()
        }, rx, events));
        loop {
            let event = received.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(event["clientSessionId"], "reconnect");
            match event["type"].as_str() {
                Some("connected") => {
                    assert_eq!(event["method"], "Pairing");
                    break;
                }
                Some("need_secret" | "disconnected" | "auth_failed") => panic!("remembered connection failed: {event}"),
                _ => {}
            }
        }
        tx.send(ViewerCmd::Disconnect).await.unwrap();
        viewer.await.unwrap();
        stop.send(true).unwrap();
        server.await.unwrap();
    }
}
