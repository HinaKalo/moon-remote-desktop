//! The running service: state, UI pipe and agent supervision, shared by service mode
//! and console (development) mode.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::agent::{Event, Supervisor};
use crate::agent_pipe::{self, AgentBridge};
use crate::network::{self, NetworkConfig, NetworkStatus};
use crate::pipe;
use crate::state::{Host, StateFile};

/// Agent executable expected next to the service binary.
pub const AGENT_EXE: &str = "moonrd-agent.exe";

pub struct Config {
    pub data_dir: PathBuf,
    pub pipe_name: String,
    pub pipe_sddl: String,
    /// Pipe used by the in-session agent (`\\.\pipe\moonrd-agent`, SYSTEM-only in
    /// service mode).
    pub agent_pipe_name: String,
    pub agent_pipe_sddl: String,
    /// Console mode: no ACL changes on the data dir, every pipe caller trusted (the pipe
    /// ACL admits only the current user).
    pub console: bool,
    /// Started in the console session; `None` disables supervision.
    pub agent_exe: Option<PathBuf>,
    /// Bundled `easytier-core.exe` companion binary; `None` runs without EasyTier.
    pub easytier_core: Option<PathBuf>,
}

/// Messages from the service control handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Stop,
    SessionChanged,
}

/// Appends timestamped lines to the service log (and stderr in console mode).
#[derive(Clone)]
pub struct Log {
    file: Arc<Mutex<Option<std::fs::File>>>,
    echo: bool,
}

impl Log {
    pub fn open(path: PathBuf, echo: bool) -> Self {
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Self { file: Arc::new(Mutex::new(file)), echo }
    }

    pub fn line(&self, msg: impl AsRef<str>) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let line = format!("{ts} {}\n", msg.as_ref());
        if self.echo {
            eprint!("{line}");
        }
        if let Ok(mut f) = self.file.lock()
            && let Some(f) = f.as_mut()
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// Runs until `Signal::Stop`. Blocking.
#[cfg(windows)]
pub fn run(cfg: Config, signals: Receiver<Signal>) -> io::Result<()> {
    use crate::agent::windows_platform::WinPlatform;
    use crate::win::{DATA_DIR_SDDL, DpapiMachine, Job, secure_dir};

    if cfg.console {
        std::fs::create_dir_all(&cfg.data_dir)?;
    } else {
        secure_dir(&cfg.data_dir, DATA_DIR_SDDL)?;
    }
    let log = Log::open(cfg.data_dir.join("service.log"), cfg.console);
    log.line(format!("moonrd-service {} starting (console={})", env!("CARGO_PKG_VERSION"), cfg.console));

    let host = Host::open(StateFile::new(cfg.data_dir.join("host-state.bin"), Box::new(DpapiMachine)))?;
    let host = Arc::new(Mutex::new(host));
    let agent_live = Arc::new(Mutex::new(json!({"agent": "not running"})));
    let bridge = AgentBridge::new();

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (reload_tx, reload_rx) = tokio::sync::watch::channel(0u64);
    let (net_status_tx, net_status_rx) = tokio::sync::watch::channel(NetworkStatus::default());

    let pipe_opts = pipe::server::Options { name: cfg.pipe_name.clone(), sddl: cfg.pipe_sddl.clone(), trust_all: cfg.console };
    let agent_live_for_pipe = agent_live.clone();
    let bridge_for_pipe = bridge.clone();
    let net_for_pipe = net_status_rx.clone();
    let extra: Arc<dyn Fn() -> pipe::StatusExtra + Send + Sync> = Arc::new(move || {
        let mut obj = agent_live_for_pipe.lock().map(|v| v.clone()).unwrap_or_else(|_| json!({}));
        if let Some(map) = obj.as_object_mut() {
            map.insert("agentPipeConnected".into(), json!(bridge_for_pipe.agent_connected()));
            map.insert("activeViewer".into(), json!(bridge_for_pipe.viewer_attached()));
            map.insert("network".into(), serde_json::to_value(net_for_pipe.borrow().clone()).unwrap_or_default());
        }
        obj
    });
    let on_change: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        reload_tx.send_modify(|n| *n = n.wrapping_add(1));
    });

    let pipe_log = log.clone();
    let pipe_host = host.clone();
    let pipe_stop = stop_rx.clone();
    let pipe_task = rt.spawn(async move {
        if let Err(e) = pipe::server::serve(pipe_opts, pipe_host, extra, on_change, pipe_stop).await {
            pipe_log.line(format!("UI pipe stopped: {e}"));
        }
    });
    log.line(format!("UI pipe listening on {}", cfg.pipe_name));

    let agent_pipe_opts = agent_pipe::server::Options { name: cfg.agent_pipe_name.clone(), sddl: cfg.agent_pipe_sddl.clone() };
    let agent_pipe_log = log.clone();
    let agent_pipe_bridge = bridge.clone();
    let agent_pipe_stop = stop_rx.clone();
    let agent_pipe_task = rt.spawn(async move {
        if let Err(e) = agent_pipe::server::serve(agent_pipe_opts, agent_pipe_bridge, agent_pipe_stop).await {
            agent_pipe_log.line(format!("agent pipe stopped: {e}"));
        }
    });
    log.line(format!("agent pipe listening on {}", cfg.agent_pipe_name));

    let net_cfg = NetworkConfig {
        data_dir: cfg.data_dir.clone(),
        easytier_core: cfg.easytier_core.clone(),
        send_sas: Arc::new(crate::win::send_sas),
    };
    let net_task = rt.spawn(network::run(net_cfg, host, bridge, reload_rx, net_status_tx, stop_rx, log.clone()));

    let mut supervisor = match &cfg.agent_exe {
        Some(exe) if exe.exists() => {
            Some(Supervisor::new(WinPlatform { exe: exe.clone(), args: "--from-service".into(), job: Job::new()? }))
        }
        Some(exe) => {
            log.line(format!("agent {} not installed; running without it", exe.display()));
            None
        }
        None => None,
    };

    loop {
        match signals.recv_timeout(Duration::from_secs(1)) {
            Ok(Signal::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Signal::SessionChanged) | Err(RecvTimeoutError::Timeout) => {}
        }
        if let Some(sup) = supervisor.as_mut() {
            let ev = sup.tick(Instant::now());
            if ev != Event::Idle {
                log.line(format!("agent: {ev:?}"));
            }
            if let Ok(mut l) = agent_live.lock() {
                *l = json!({
                    "agent": if sup.agent_session().is_some() { "running" } else { "not running" },
                    "agentSession": sup.agent_session(),
                    "agentFailures": sup.failures(),
                });
            }
        }
    }

    log.line("stopping");
    if let Some(sup) = supervisor.as_mut() {
        sup.stop();
    }
    let _ = stop_tx.send(true);
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(3), pipe_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), agent_pipe_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), net_task).await;
    });
    rt.shutdown_timeout(Duration::from_secs(2));
    log.line("stopped");
    Ok(())
}
