//! `moonrd-host` — lightweight host-only Moon Remote plugin.
//!
//! * Starts automatically on Windows login (`--background`) with no GUI window.
//! * Interactive launch opens the tiny local setup wizard (`http://127.0.0.1:<port>/`)
//!   in the browser to sign in with Moon SSO, set a PIN, and toggle auto-start.
//! * Runs the full host network stack (EasyTier v2.7.1, signalling WS, QUIC loopback
//!   listener, SPAKE2 PIN verification) and supervises `moonrd-agent.exe --dev`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
#[cfg(windows)]
mod setup_ui;
#[cfg(windows)]
mod update;

#[cfg(not(windows))]
fn main() {
    eprintln!("moonrd-host runs on Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(e) = entry().await {
        eprintln!("moonrd-host: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
async fn entry() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if std::env::args().any(|arg| arg == "--version") {
        println!("Moon Remote Core 0.1.{}", update::build_code());
    } else if std::env::args().any(|arg| arg == "--check-update") {
        if let Some(release) = update::check(&update::client()?).await? {
            println!("Moon Remote Core update: {} (verified)", release.version_name);
        } else {
            println!("Moon Remote Core 0.1.{} is current", update::build_code());
        }
    } else {
        run().await?;
    }
    Ok(())
}

#[cfg(windows)]
async fn run() -> std::io::Result<()> {
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use moonrd_service::agent_pipe::{self, AgentBridge, DEV_AGENT_PIPE_NAME};
    use moonrd_service::et::find_easytier_core;
    use moonrd_service::network::{self, NetworkConfig, NetworkStatus};
    use moonrd_service::runtime::{AGENT_EXE, Log};
    use moonrd_service::state::{Host, StateFile};
    use moonrd_service::win::DpapiMachine;
    use tokio::net::TcpListener;
    use tokio::process::Command;
    use tokio::sync::watch;

    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let background = args.iter().any(|a| a == "--background");
    let update_ready = args.windows(2).find(|pair| pair[0] == "--update-ready").map(|pair| PathBuf::from(&pair[1]));
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("LOCALAPPDATA not set"))?;
    let data_dir = local.join("MoonRemote").join("host-plugin");
    std::fs::create_dir_all(&data_dir)?;

    let log = Log::open(data_dir.join("host-plugin.log"), false);
    let build = update::build_code();
    log.line(format!("moonrd-host 0.1.{build} starting (background={background})"));

    let instance = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(data_dir.join("host-plugin.lock"))?;
    if instance.try_lock().is_err() {
        log.line("another Core host is already running");
        return Ok(());
    }
    if update_ready.is_none() {
        match update::prepare(&data_dir).await {
            Ok(Some((code, staged))) => {
                instance.unlock()?;
                match update::activate(&data_dir, code, staged, background).await {
                    Ok(()) => { log.line(format!("Core updated to 0.1.{code}")); return Ok(()); }
                    Err(e) => {
                        log.line(format!("Core activation failed; keeping installed build: {e}"));
                        instance.try_lock().map_err(std::io::Error::other)?;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => log.line(format!("Core update check or download failed: {e}")),
        };
    }

    let host = Host::open(StateFile::new(data_dir.join("host-state.bin"), Box::new(DpapiMachine)))?;
    let host = Arc::new(Mutex::new(host));
    let bridge = AgentBridge::new();

    let (stop_tx, stop_rx) = watch::channel(false);
    let (reload_tx, reload_rx) = watch::channel(0u64);
    let (net_status_tx, net_status_rx) = watch::channel(NetworkStatus::default());

    // 1. Agent pipe server (current user + SYSTEM).
    let agent_pipe_opts = agent_pipe::server::Options {
        name: DEV_AGENT_PIPE_NAME.into(),
        sddl: "D:P(A;;GA;;;OW)(A;;GA;;;SY)".into(),
    };
    let ap_bridge = bridge.clone();
    let ap_stop = stop_rx.clone();
    let ap_log = log.clone();
    tokio::spawn(async move {
        if let Err(e) = agent_pipe::server::serve(agent_pipe_opts, ap_bridge, ap_stop).await {
            ap_log.line(format!("agent pipe error: {e}"));
        }
    });

    // 2. Supervise local in-session `moonrd-agent.exe --dev` (if present next to us).
    let agent_exe = exe_dir.join(AGENT_EXE);
    if agent_exe.is_file() {
        let mut agent_stop = stop_rx.clone();
        let agent_log = log.clone();
        tokio::spawn(async move {
            loop {
                if *agent_stop.borrow() {
                    break;
                }
                let mut cmd = Command::new(&agent_exe);
                cmd.arg("--dev").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
                match cmd.spawn() {
                    Ok(mut child) => {
                        tokio::select! {
                            _ = agent_stop.changed() => { let _ = child.kill().await; break; }
                            _ = child.wait() => {}
                        }
                    }
                    Err(e) => agent_log.line(format!("spawn agent failed: {e}")),
                }
                tokio::select! {
                    _ = agent_stop.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
            }
        });
    }

    // 3. Host network stack (EasyTier + Signalling WS + QUIC loopback + SPAKE2).
    let net_cfg = NetworkConfig {
        data_dir: data_dir.clone(),
        easytier_core: find_easytier_core(&exe_dir),
        send_sas: Arc::new(moonrd_service::win::send_sas),
    };
    let net_host = host.clone();
    let net_bridge = bridge.clone();
    let net_stop = stop_rx.clone();
    let net_log = log.clone();
    tokio::spawn(async move {
        network::run(net_cfg, net_host, net_bridge, reload_rx, net_status_tx, net_stop, net_log).await;
    });

    // 4. Local loopback setup & status wizard.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let setup_ctx = Arc::new(setup_ui::SetupContext::new(host, net_status_rx, reload_tx, exe_path, port));
    log.line(format!("setup wizard listening on http://127.0.0.1:{port}/"));
    if let Some(marker) = &update_ready {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !bridge.agent_connected() { tokio::time::sleep(Duration::from_millis(50)).await; }
        }).await.map_err(|_| std::io::Error::other("updated Core could not attach its capture agent"))?;
        std::fs::write(marker, build.to_string())?;
    }

    // Explicit launches open the setup wizard. Startup and background handoffs stay silent.
    if !background {
        let url = format!("http://127.0.0.1:{port}/");
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();
    }

    setup_ui::serve(listener, setup_ctx, stop_rx).await;
    let _ = stop_tx.send(true);
    Ok(())
}
