//! Supervises the host's companion `easytier-core` process.
//!
//! Responsibilities:
//! * Fetch a per-device EasyTier credential from `POST /v1/et/credential` using the
//!   host's device token.
//! * Write the writable TOML config (`moonrd-et::config::CompanionConfig`) into the
//!   service's private directory and start `easytier-core` with `--rpc-portal` on a
//!   free loopback port.
//! * Watch stdout/stderr for `is_credential_rejected` (server revoked or expired the
//!   credential) and immediately re-enrol with a fresh credential.
//! * Renew the credential at 75% of its TTL and restart the companion smoothly (the
//!   server keeps the two newest credentials valid).
//! * Stop and report `Revoked` if the server rejects the device token with HTTP 401.

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};

use moonrd_et::config::{CompanionConfig, core_args, is_credential_rejected, pick_free_loopback_port};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};

use crate::server_api::{ApiError, EtGrant, ServerClient};

const BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const STABLE_AFTER: Duration = Duration::from_secs(15);

/// Live EasyTier status exposed through the UI pipe `status` response.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum EtStatus {
    Stopped,
    NotInstalled,
    Starting,
    Running {
        ipv4: String,
        #[serde(rename = "rpcPort")]
        rpc_port: u16,
        #[serde(rename = "expiresAt")]
        expires_at: String,
    },
    Unavailable,
    Revoked,
    Error {
        message: String,
    },
}

impl EtStatus {
    /// Virtual IPv4 address if EasyTier is currently running.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        match self {
            EtStatus::Running { ipv4, .. } => ipv4.parse().ok(),
            _ => None,
        }
    }
}

/// Source of EasyTier credentials (implemented by [`ServerClient`] and test fakes).
pub trait CredentialSource: Send + Sync {
    fn fetch<'a>(&'a self, occupied: &'a [String]) -> Pin<Box<dyn Future<Output = Result<EtGrant, ApiError>> + Send + 'a>>;
}

impl CredentialSource for ServerClient {
    fn fetch<'a>(&'a self, occupied: &'a [String]) -> Pin<Box<dyn Future<Output = Result<EtGrant, ApiError>> + Send + 'a>> {
        Box::pin(self.request_et_credential(occupied))
    }
}

/// A running companion instance whose log lines stream over `logs` and which can be
/// waited on or stopped.
pub struct RunningCompanion {
    pub rpc_port: u16,
    pub logs: mpsc::Receiver<String>,
    handle: Box<dyn CompanionHandle>,
}

trait CompanionHandle: Send {
    fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<i32>> + Send + '_>>;
    fn kill(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Starts one `easytier-core` instance for a given config.
pub trait CompanionLauncher: Send + Sync {
    fn spawn(&self, cfg: &CompanionConfig) -> io::Result<RunningCompanion>;
    fn cleanup(&self) {}
}

/// Real `easytier-core` process launcher.
pub struct ProcessLauncher {
    pub exe: PathBuf,
    pub config_path: PathBuf,
}

struct ChildHandle {
    child: Child,
}

impl CompanionHandle for ChildHandle {
    fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<i32>> + Send + '_>> {
        Box::pin(async move {
            let status = self.child.wait().await?;
            Ok(status.code().unwrap_or(-1))
        })
    }

    fn kill(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = self.child.kill().await;
            let _ = self.child.wait().await;
        })
    }
}

impl ProcessLauncher {
    fn write_toml(&self, toml: &str) -> io::Result<()> {
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.config_path.with_extension("toml.tmp");
        std::fs::write(&tmp, toml.as_bytes())?;
        std::fs::rename(&tmp, &self.config_path)?;
        Ok(())
    }
}

impl CompanionLauncher for ProcessLauncher {
    fn spawn(&self, cfg: &CompanionConfig) -> io::Result<RunningCompanion> {
        self.write_toml(&cfg.to_toml())?;
        let rpc_port = pick_free_loopback_port()?;
        let args = core_args(&self.config_path, rpc_port);
        let mut cmd = Command::new(&self.exe);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn()?;
        let (tx, rx) = mpsc::channel(64);
        if let Some(out) = child.stdout.take() {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if tx.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }
        if let Some(err) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if tx.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }
        Ok(RunningCompanion { rpc_port, logs: rx, handle: Box::new(ChildHandle { child }) })
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// Configuration for the EasyTier supervision loop.
pub struct EtLoopConfig {
    pub hostname: String,
    pub occupied: Vec<String>,
    /// Optional override for renewal delay (used in tests); when `None`, uses
    /// `EtGrant::renew_after(SystemTime::now())`.
    pub renew_override: Option<Duration>,
    /// Base backoff for retries (defaults to [`BACKOFF_BASE`]).
    pub backoff_base: Duration,
}

impl EtLoopConfig {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self { hostname: device_id.into(), occupied: Vec::new(), renew_override: None, backoff_base: BACKOFF_BASE }
    }
}

fn backoff_delay(base: Duration, failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(10);
    (base * 2u32.pow(exp)).min(BACKOFF_MAX)
}

/// Runs the EasyTier companion loop until `shutdown` resolves or the device token is
/// revoked (HTTP 401). Publishes live state on `status_tx`.
pub async fn run_loop<S, L, F>(
    source: S,
    launcher: L,
    cfg: EtLoopConfig,
    status_tx: watch::Sender<EtStatus>,
    mut shutdown: watch::Receiver<bool>,
    mut log: F,
) where
    S: CredentialSource,
    L: CompanionLauncher,
    F: FnMut(&str),
{
    let mut failures = 0u32;

    loop {
        if *shutdown.borrow() {
            break;
        }
        let _ = status_tx.send(EtStatus::Starting);
        let grant = tokio::select! {
            _ = shutdown.changed() => break,
            r = source.fetch(&cfg.occupied) => r,
        };

        let grant = match grant {
            Ok(g) => g,
            Err(ApiError::Unauthorized) => {
                log("easytier: device token rejected (401); stopping");
                let _ = status_tx.send(EtStatus::Revoked);
                break;
            }
            Err(ApiError::Unavailable(msg)) => {
                failures += 1;
                let wait = backoff_delay(cfg.backoff_base, failures);
                log(&format!("easytier: server unavailable ({msg}); retry in {}s", wait.as_secs()));
                let _ = status_tx.send(EtStatus::Unavailable);
                if sleep_or_shutdown(wait, &mut shutdown).await {
                    break;
                }
                continue;
            }
            Err(e) => {
                failures += 1;
                let wait = backoff_delay(cfg.backoff_base, failures);
                log(&format!("easytier: credential fetch failed ({e}); retry in {}s", wait.as_secs()));
                let _ = status_tx.send(EtStatus::Error { message: e.to_string() });
                if sleep_or_shutdown(wait, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let Some(ipv4_addr) = grant.ipv4_addr() else {
            failures += 1;
            let wait = backoff_delay(cfg.backoff_base, failures);
            log(&format!("easytier: invalid ipv4 in grant: {}", grant.ipv4));
            let _ = status_tx.send(EtStatus::Error { message: format!("invalid ipv4 {}", grant.ipv4) });
            if sleep_or_shutdown(wait, &mut shutdown).await {
                break;
            }
            continue;
        };

        let companion_cfg = CompanionConfig {
            hostname: cfg.hostname.clone(),
            network_name: grant.network_name.clone(),
            credential: grant.credential.clone(),
            peers: grant.peers.clone(),
            ipv4: grant.ipv4.clone(),
        };

        let mut running = match launcher.spawn(&companion_cfg) {
            Ok(r) => r,
            Err(e) => {
                failures += 1;
                let wait = backoff_delay(cfg.backoff_base, failures);
                log(&format!("easytier: spawn failed ({e}); retry in {}s", wait.as_secs()));
                let _ = status_tx.send(EtStatus::Error { message: format!("spawn failed: {e}") });
                if sleep_or_shutdown(wait, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let started = Instant::now();
        let renew_delay = cfg.renew_override.unwrap_or_else(|| grant.renew_after(SystemTime::now()));
        log(&format!(
            "easytier: started ip={} rpc={} renew_in={}s",
            ipv4_addr,
            running.rpc_port,
            renew_delay.as_secs()
        ));
        let _ = status_tx.send(EtStatus::Running {
            ipv4: ipv4_addr.to_string(),
            rpc_port: running.rpc_port,
            expires_at: grant.expires_at.clone(),
        });

        let renew_sleep = tokio::time::sleep(renew_delay);
        tokio::pin!(renew_sleep);

        enum End {
            Shutdown,
            Renew,
            CredentialRejected,
            Exited(io::Result<i32>),
        }

        let end = loop {
            tokio::select! {
                _ = shutdown.changed() => break End::Shutdown,
                _ = &mut renew_sleep => break End::Renew,
                code = running.handle.wait() => break End::Exited(code),
                line = running.logs.recv() => {
                    if let Some(line) = line
                        && is_credential_rejected(&line)
                    {
                        break End::CredentialRejected;
                    }
                }
            }
        };

        match end {
            End::Shutdown => {
                running.handle.kill().await;
                break;
            }
            End::Renew => {
                log("easytier: renewing credential");
                running.handle.kill().await;
                failures = 0;
            }
            End::CredentialRejected => {
                log("easytier: credential rejected by peer; re-enrolling");
                running.handle.kill().await;
                // Brief pause to avoid tight-looping if the server keeps issuing an
                // immediately-rejected credential.
                failures += 1;
                if failures > 1 {
                    let wait = backoff_delay(cfg.backoff_base, failures - 1);
                    if sleep_or_shutdown(wait, &mut shutdown).await {
                        break;
                    }
                }
            }
            End::Exited(res) => {
                if started.elapsed() >= STABLE_AFTER {
                    failures = 0;
                } else {
                    failures += 1;
                }
                let wait = backoff_delay(cfg.backoff_base, failures);
                log(&format!("easytier: exited ({res:?}); restarting in {}s", wait.as_secs()));
                let _ = status_tx.send(EtStatus::Error { message: format!("easytier exited: {res:?}") });
                if sleep_or_shutdown(wait, &mut shutdown).await {
                    break;
                }
            }
        }
    }

    launcher.cleanup();
    if *status_tx.borrow() != EtStatus::Revoked {
        let _ = status_tx.send(EtStatus::Stopped);
    }
}

async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = shutdown.changed() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}

/// Locates `easytier-core.exe` next to `exe_dir` (`<exe_dir>/easytier/easytier-core.exe`
/// or `<exe_dir>/easytier-core.exe`).
pub fn find_easytier_core(exe_dir: &Path) -> Option<PathBuf> {
    let candidates = [exe_dir.join("easytier").join("easytier-core.exe"), exe_dir.join("easytier-core.exe")];
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct FakeSource {
        responses: Mutex<Vec<Result<EtGrant, ApiError>>>,
        calls: AtomicUsize,
    }

    impl FakeSource {
        fn new(responses: Vec<Result<EtGrant, ApiError>>) -> Self {
            Self { responses: Mutex::new(responses), calls: AtomicUsize::new(0) }
        }
    }

    impl CredentialSource for Arc<FakeSource> {
        fn fetch<'a>(&'a self, _occupied: &'a [String]) -> Pin<Box<dyn Future<Output = Result<EtGrant, ApiError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self.responses.lock().unwrap().remove(0);
            Box::pin(async move { next })
        }
    }

    struct FakeHandle {
        exit_rx: tokio::sync::oneshot::Receiver<i32>,
        killed: Arc<AtomicUsize>,
    }

    impl CompanionHandle for FakeHandle {
        fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<i32>> + Send + '_>> {
            Box::pin(async move {
                match (&mut self.exit_rx).await {
                    Ok(c) => Ok(c),
                    Err(_) => std::future::pending().await,
                }
            })
        }
        fn kill(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.killed.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    struct FakeLauncher {
        spawned: Mutex<Vec<CompanionConfig>>,
        log_senders: Mutex<Vec<mpsc::Sender<String>>>,
        killed: Arc<AtomicUsize>,
        cleaned: AtomicUsize,
    }

    impl FakeLauncher {
        fn new() -> Self {
            Self {
                spawned: Mutex::new(Vec::new()),
                log_senders: Mutex::new(Vec::new()),
                killed: Arc::new(AtomicUsize::new(0)),
                cleaned: AtomicUsize::new(0),
            }
        }
    }

    impl CompanionLauncher for Arc<FakeLauncher> {
        fn spawn(&self, cfg: &CompanionConfig) -> io::Result<RunningCompanion> {
            self.spawned.lock().unwrap().push(cfg.clone());
            let (tx, rx) = mpsc::channel(16);
            self.log_senders.lock().unwrap().push(tx);
            let (_exit_tx, exit_rx) = tokio::sync::oneshot::channel();
            Ok(RunningCompanion {
                rpc_port: 49999,
                logs: rx,
                handle: Box::new(FakeHandle { exit_rx, killed: self.killed.clone() }),
            })
        }
        fn cleanup(&self) {
            self.cleaned.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn grant(cred: &str) -> EtGrant {
        EtGrant {
            network_name: "mrd-test".into(),
            credential: cred.into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            peers: vec!["tcp://remote.moonl.cloud:21017".into()],
            ipv4: "10.250.17.3/24".into(),
        }
    }

    #[tokio::test]
    async fn re_enrols_on_credential_rejection_and_stops_on_revoked() {
        let src = Arc::new(FakeSource::new(vec![
            Ok(grant("cred-1")),
            Ok(grant("cred-2")),
            Err(ApiError::Unauthorized),
        ]));
        let launcher = Arc::new(FakeLauncher::new());
        let (status_tx, mut status_rx) = watch::channel(EtStatus::Stopped);
        let (_stop_tx, stop_rx) = watch::channel(false);

        let mut cfg = EtLoopConfig::new("dev-1");
        cfg.backoff_base = Duration::from_millis(10);

        let task = tokio::spawn(run_loop(src.clone(), launcher.clone(), cfg, status_tx, stop_rx, |_| {}));

        // Wait until first instance is Running.
        loop {
            status_rx.changed().await.unwrap();
            if matches!(*status_rx.borrow(), EtStatus::Running { .. }) {
                break;
            }
        }
        assert_eq!(launcher.spawned.lock().unwrap()[0].credential, "cred-1");

        // Trigger credential rejection -> should fetch cred-2 and respawn.
        let tx0 = launcher.log_senders.lock().unwrap()[0].clone();
        tx0.send("ERROR invalid proof and unknown credential".into()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while launcher.spawned.lock().unwrap().len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(launcher.spawned.lock().unwrap()[1].credential, "cred-2");

        // Trigger another rejection -> 3rd fetch returns 401 -> loop exits with Revoked.
        let tx1 = launcher.log_senders.lock().unwrap()[1].clone();
        tx1.send("ERROR invalid proof and unknown credential".into()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
        assert_eq!(*status_rx.borrow(), EtStatus::Revoked);
        assert_eq!(launcher.killed.load(Ordering::SeqCst), 2);
        assert_eq!(launcher.cleaned.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn renews_credential_on_schedule() {
        let src = Arc::new(FakeSource::new(vec![Ok(grant("cred-1")), Ok(grant("cred-2"))]));
        let launcher = Arc::new(FakeLauncher::new());
        let (status_tx, _status_rx) = watch::channel(EtStatus::Stopped);
        let (stop_tx, stop_rx) = watch::channel(false);

        let mut cfg = EtLoopConfig::new("dev-1");
        cfg.renew_override = Some(Duration::from_millis(30));
        cfg.backoff_base = Duration::from_millis(10);

        let task = tokio::spawn(run_loop(src.clone(), launcher.clone(), cfg, status_tx, stop_rx, |_| {}));

        tokio::time::timeout(Duration::from_secs(2), async {
            while launcher.spawned.lock().unwrap().len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(launcher.spawned.lock().unwrap()[0].credential, "cred-1");
        assert_eq!(launcher.spawned.lock().unwrap()[1].credential, "cred-2");

        let _ = stop_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
        assert_eq!(launcher.cleaned.load(Ordering::SeqCst), 1);
    }
}
