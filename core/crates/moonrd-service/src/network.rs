//! Coordinates the host service's network stack:
//! * QUIC loopback listener (`quic_host`)
//! * EasyTier companion process & credential renewal (`et`)
//! * Signalling WebSocket client (`signal`)
//! * Account device directory refresh (`server_api` → `DeviceDirectory`)
//!
//! Reacts immediately to registration / unregistration changes via `reload`.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use moonrd_transport::DeviceKey;
use serde::Serialize;
use tokio::sync::watch;

use crate::agent_pipe::AgentBridge;
use crate::et::{self, EtLoopConfig, EtStatus, ProcessLauncher};
use crate::quic_host::{self, DeviceDirectory, SasHook};
use crate::runtime::Log;
use crate::server_api::{ApiError, ServerClient};
use crate::signal::{self, InviteHandler, InviteReply, Outbound, SignalStatus};
use crate::state::Host;

const DEVICE_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Combined network status reported under `status.live.network`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub et: EtStatus,
    pub signal: SignalStatus,
    pub quic_port: Option<u16>,
    pub lan_quic_port: Option<u16>,
}

impl Default for NetworkStatus {
    fn default() -> Self {
        Self { et: EtStatus::Stopped, signal: SignalStatus::Disconnected, quic_port: None, lan_quic_port: None }
    }
}

pub struct NetworkConfig {
    pub data_dir: PathBuf,
    pub easytier_core: Option<PathBuf>,
    pub send_sas: SasHook,
}

struct HostInviteHandler {
    client: ServerClient,
    host: Arc<Mutex<Host>>,
    directory: DeviceDirectory,
    et_status: watch::Receiver<EtStatus>,
    quic_port: u16,
    bridge: AgentBridge,
    stop: watch::Receiver<bool>,
    web_slots: Arc<tokio::sync::Semaphore>,
    log: Log,
}

impl InviteHandler for HostInviteHandler {
fn on_invite<'a>(&'a self, invite: &'a Outbound) -> Pin<Box<dyn Future<Output = InviteReply> + Send + 'a>> {
        Box::pin(async move {
            let has_pin = self.host.lock().unwrap_or_else(|e| e.into_inner()).state.pin.is_some();
            if !has_pin {
                return InviteReply::Reject { reason: "host_pin_not_set".into() };
            }
            if invite.data.as_ref().and_then(|d| d["transport"].as_str()) == Some("webrtc") {
                let Some(offer) = invite.data.as_ref().and_then(|d| d["sdp"].as_str()) else {
                    return InviteReply::Reject { reason: "missing browser SDP offer".into() };
                };
                let Ok(slot) = self.web_slots.clone().try_acquire_owned() else {
                    return InviteReply::Reject { reason: "host busy".into() };
                };
                return match crate::web_host::answer(offer, &self.client, self.host.clone(), self.bridge.clone(), self.stop.clone(), slot).await {
                    Ok(sdp) => InviteReply::WebAnswer { sdp },
                    Err(e) => { self.log.line(format!("web: session setup failed: {e}")); InviteReply::Reject { reason: "browser session setup failed".into() } }
                };
            }
            // Refresh the device allow list so a newly added viewer device is accepted.
            match self.client.list_devices().await {
                Ok(devices) => self.directory.update(&devices, &self.host),
                Err(e) => self.log.line(format!("network: device refresh on invite failed: {e}")),
            }
            match self.et_status.borrow().ipv4_addr() {
                Some(ipv4) => InviteReply::QuicEndpoint { ipv4, port: self.quic_port },
                None => InviteReply::Reject { reason: "host_et_not_ready".into() },
            }
        })
    }
}

/// Runs the network stack until `shutdown` resolves. Restarts automatically whenever
/// `reload` changes (registration / unregistration via the UI pipe).
pub async fn run(
    cfg: NetworkConfig,
    host: Arc<Mutex<Host>>,
    bridge: AgentBridge,
    mut reload: watch::Receiver<u64>,
    status_tx: watch::Sender<NetworkStatus>,
    mut shutdown: watch::Receiver<bool>,
    log: Log,
) {
    loop {
        if *shutdown.borrow() {
            break;
        }

        let reg_and_key = {
            let h = host.lock().unwrap_or_else(|e| e.into_inner());
            match (&h.state.registration, h.state.device_seed) {
                (Some(reg), Some(seed)) => Some((reg.clone(), seed, h.state.lan_direct)),
                _ => None,
            }
        };

        let Some((reg, seed, lan_direct)) = reg_and_key else {
            let _ = status_tx.send(NetworkStatus::default());
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = reload.changed() => continue,
            }
        };

        let client = match ServerClient::new(&reg.server_url, &reg.device_token) {
            Ok(c) => c,
            Err(e) => {
                log.line(format!("network: invalid server config: {e}"));
                let _ = status_tx.send(NetworkStatus {
                    et: EtStatus::Error { message: e.to_string() },
                    signal: SignalStatus::Error { message: e.to_string() },
                    quic_port: None,
                    lan_quic_port: None,
                });
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = reload.changed() => continue,
                }
            }
        };

        let sk = SigningKey::from_bytes(&seed);
        let device_key = DeviceKey::new(seed, sk.verifying_key().to_bytes());
        let directory = DeviceDirectory::new();

        let (ep, quic_port) = match quic_host::bind_loopback(&device_key, &directory) {
            Ok(pair) => pair,
            Err(e) => {
                log.line(format!("network: failed to bind QUIC loopback endpoint: {e}"));
                let _ = status_tx.send(NetworkStatus {
                    et: EtStatus::Stopped,
                    signal: SignalStatus::Error { message: format!("quic bind: {e}") },
                    quic_port: None,
                    lan_quic_port: None,
                });
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = reload.changed() => continue,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => continue,
                }
            }
        };
        log.line(format!("network: QUIC listening on 127.0.0.1:{quic_port}"));

        // Initial device list load (best-effort; retried periodically and on invites).
        match client.list_devices().await {
            Ok(devices) => {
                directory.update(&devices, &host);
                log.line(format!("network: loaded {} account devices", devices.len()));
            }
            Err(ApiError::Unauthorized) => {
                log.line("network: device token rejected (401); waiting for re-registration");
                let _ = status_tx.send(NetworkStatus {
                    et: EtStatus::Revoked,
                    signal: SignalStatus::Revoked,
                    quic_port: None,
                    lan_quic_port: None,
                });
                ep.close(0u32.into(), b"revoked");
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = reload.changed() => continue,
                }
            }
            Err(e) => log.line(format!("network: initial device list failed: {e}")),
        }

        // Also cache signed roster for offline LAN mode when online.
        let roster_path = cfg.data_dir.join("roster.json");
        if let Ok(sr) = client.fetch_roster().await {
            if let Ok(bytes) = serde_json::to_vec(&sr) {
                let _ = std::fs::write(&roster_path, bytes);
            }
        } else if let Ok(bytes) = std::fs::read(&roster_path)
            && let Ok(sr) = serde_json::from_slice::<crate::roster::SignedRoster>(&bytes)
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if let Ok(r) = crate::roster::verify_roster(&reg.roster_key, &reg.user_sub, &sr, now) {
                directory.update(&r.to_device_views(&reg.device_id), &host);
                log.line(format!("network: loaded offline signed roster ({} devices)", r.devices.len()));
            }
        }

        let (sub_stop_tx, sub_stop_rx) = watch::channel(false);
        let (et_tx, mut et_rx) = watch::channel(if cfg.easytier_core.is_some() {
            EtStatus::Starting
        } else {
            EtStatus::NotInstalled
        });
        let (sig_tx, mut sig_rx) = watch::channel(SignalStatus::Connecting);

        // Optional LAN direct QUIC listener (off by default).
        let (lan_quic_port, lan_task) = if lan_direct {
            match quic_host::bind_lan(&device_key, &directory, quic_host::LAN_DIRECT_PORT)
                .or_else(|_| quic_host::bind_lan(&device_key, &directory, 0))
            {
                Ok((lan_ep, port)) => {
                    log.line(format!("network: LAN direct QUIC listening on 0.0.0.0:{port}"));
                    let lan_log = log.clone();
                    let t = tokio::spawn(quic_host::serve(
                        lan_ep,
                        host.clone(),
                        directory.clone(),
                        bridge.clone(),
                        cfg.send_sas.clone(),
                        sub_stop_rx.clone(),
                        move |m| lan_log.line(m),
                    ));
                    (Some(port), Some(t))
                }
                Err(e) => {
                    log.line(format!("network: LAN direct bind failed: {e}"));
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        // 1. QUIC accept loop.
        let quic_log = log.clone();
        let quic_task = tokio::spawn(quic_host::serve(
            ep,
            host.clone(),
            directory.clone(),
            bridge.clone(),
            cfg.send_sas.clone(),
            sub_stop_rx.clone(),
            move |m| quic_log.line(m),
        ));

        // 2. EasyTier companion loop (if easytier-core.exe is present).
        let et_task = if let Some(exe) = cfg.easytier_core.clone().filter(|p| p.is_file()) {
            let launcher = ProcessLauncher { exe, config_path: cfg.data_dir.join("et").join("moonrd.toml") };
            let et_cfg = EtLoopConfig::new(reg.device_id.clone());
            let et_log = log.clone();
            let et_client = client.clone();
            let et_stop = sub_stop_rx.clone();
            Some(tokio::spawn(async move {
                et::run_loop(et_client, launcher, et_cfg, et_tx, et_stop, move |m| et_log.line(m)).await;
            }))
        } else {
            log.line("network: easytier-core.exe not found; running without EasyTier");
            let _ = et_tx.send(EtStatus::NotInstalled);
            None
        };

        // 3. Signalling WebSocket loop.
        let invite_handler = HostInviteHandler {
            client: client.clone(),
            host: host.clone(),
            directory: directory.clone(),
            et_status: et_rx.clone(),
            bridge: bridge.clone(), stop: sub_stop_rx.clone(), web_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            quic_port,
            log: log.clone(),
        };
        let sig_log = log.clone();
        let sig_client = client.clone();
        let sig_stop = sub_stop_rx.clone();
        let sig_task = tokio::spawn(async move {
            signal::run_loop(sig_client, invite_handler, sig_tx, sig_stop, move |m| sig_log.line(m)).await;
        });

        // 4. Periodic device list refresh (keeps AllowList & pairings in sync).
        let refresh_client = client.clone();
        let refresh_host = host.clone();
        let refresh_dir = directory.clone();
        let mut refresh_stop = sub_stop_rx.clone();
        let refresh_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = refresh_stop.changed() => break,
                    _ = tokio::time::sleep(DEVICE_REFRESH_INTERVAL) => {
                        if let Ok(devices) = refresh_client.list_devices().await {
                            refresh_dir.update(&devices, &refresh_host);
                        }
                    }
                }
            }
        });

        // Forward status updates and wait for shutdown, reload, or revocation.
        let mut revoked = false;
        loop {
            let snap = NetworkStatus {
                et: et_rx.borrow().clone(),
                signal: sig_rx.borrow().clone(),
                quic_port: Some(quic_port),
                lan_quic_port,
            };
            let is_revoked = snap.et == EtStatus::Revoked || snap.signal == SignalStatus::Revoked;
            let _ = status_tx.send(snap);
            if is_revoked {
                revoked = true;
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = reload.changed() => break,
                r = et_rx.changed() => if r.is_err() { break },
                r = sig_rx.changed() => if r.is_err() { break },
            }
        }

        let _ = sub_stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), quic_task).await;
        if let Some(t) = lan_task {
            let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
        }
        if let Some(t) = et_task {
            let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), sig_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), refresh_task).await;

        if revoked {
            log.line("network: device revoked by server; waiting for re-registration");
            let _ = status_tx.send(NetworkStatus {
                et: EtStatus::Revoked,
                signal: SignalStatus::Revoked,
                quic_port: None,
                lan_quic_port: None,
            });
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = reload.changed() => continue,
            }
        }
    }

    let _ = status_tx.send(NetworkStatus::default());
}
