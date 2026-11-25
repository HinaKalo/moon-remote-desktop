//! `moonrd-service` command line.
//!
//! ```text
//! moonrd-service install       register the Windows service (administrator)
//! moonrd-service uninstall     stop and remove it (administrator)
//! moonrd-service run           entry point used by the Service Control Manager
//! moonrd-service console       run in the foreground as the current user (development):
//!                              own pipe \\.\pipe\moonrd-service-dev reachable only by
//!                              this user, state in %LOCALAPPDATA%\MoonRemote\dev-host
//! ```

#[cfg(windows)]
fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let result = match cmd.as_str() {
        "install" => service::install(),
        "uninstall" => service::uninstall(),
        "run" => service::dispatch(),
        "console" => service::console(),
        "user" => service::user_background(),
        _ => {
            eprintln!("usage: moonrd-service install | uninstall | run | console | user");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("moonrd-service {cmd}: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("moonrd-service runs on Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
mod service {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    use moonrd_service::agent_pipe::{AGENT_PIPE_NAME, AGENT_PIPE_SDDL, DEV_AGENT_PIPE_NAME};
    use moonrd_service::et::find_easytier_core;
    use moonrd_service::pipe::{DEV_PIPE_NAME, PIPE_NAME};
    use moonrd_service::runtime::{self, AGENT_EXE, Config, Signal};
    use moonrd_service::win::UI_PIPE_SDDL;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const SERVICE_NAME: &str = "MoonRemoteHost";
    const DISPLAY_NAME: &str = "Moon Remote Host";
    const DESCRIPTION: &str = "Lets your signed-in Moon Remote devices connect to this computer.";

    fn ws(e: windows_service::Error) -> io::Error {
        io::Error::other(e.to_string())
    }

    fn exe_dir() -> io::Result<PathBuf> {
        let exe = std::env::current_exe()?;
        exe.parent().map(PathBuf::from).ok_or_else(|| io::Error::other("no exe directory"))
    }

    fn program_data() -> PathBuf {
        std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    }

    pub fn install() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .map_err(ws)?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![OsString::from("run")],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let svc = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
            .map_err(ws)?;
        svc.set_description(DESCRIPTION).map_err(ws)?;
        svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(2) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(10) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
            ]),
        })
        .map_err(ws)?;
        svc.start(&[] as &[&OsStr]).map_err(ws)?;
        println!("{SERVICE_NAME} installed and started");
        Ok(())
    }

    pub fn uninstall() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(ws)?;
        let svc = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
            .map_err(ws)?;
        if svc.query_status().map_err(ws)?.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            for _ in 0..50 {
                if svc.query_status().map_err(ws)?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        svc.delete().map_err(ws)?;
        println!("{SERVICE_NAME} removed (host state in %ProgramData%\\MoonRemote is kept)");
        Ok(())
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch() -> io::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(ws)
    }

    fn service_main(_args: Vec<OsString>) {
        let _ = run_service();
    }

    fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        }
    }

    fn run_service() -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(Signal::Stop);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(_) => {
                let _ = tx.send(Signal::SessionChanged);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register(SERVICE_NAME, handler).map_err(ws)?;
        let accept = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::SESSION_CHANGE;
        handle.set_service_status(status(ServiceState::Running, accept, 0)).map_err(ws)?;

        let dir = exe_dir()?;
        let cfg = Config {
            data_dir: program_data().join("MoonRemote").join("host"),
            pipe_name: PIPE_NAME.into(),
            pipe_sddl: UI_PIPE_SDDL.into(),
            agent_pipe_name: AGENT_PIPE_NAME.into(),
            agent_pipe_sddl: AGENT_PIPE_SDDL.into(),
            console: false,
            agent_exe: Some(dir.join(AGENT_EXE)),
            easytier_core: find_easytier_core(&dir),
        };
        let result = runtime::run(cfg, rx);
        let code = if result.is_ok() { 0 } else { 1 };
        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code)).map_err(ws)?;
        result
    }

    pub fn console() -> io::Result<()> {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or_else(|| io::Error::other("LOCALAPPDATA not set"))?;
        let (tx, rx) = mpsc::channel();
        // Ctrl+C / closing the console stops cleanly.
        let ctrl = tx.clone();
        std::thread::spawn(move || {
            let mut line = String::new();
            // EOF on stdin (e.g. the parent closing it) also stops the dev service.
            let _ = std::io::stdin().read_line(&mut line);
            let _ = ctrl.send(Signal::Stop);
        });
        let dir = exe_dir()?;
        let cfg = Config {
            data_dir: local.join("MoonRemote").join("dev-host"),
            pipe_name: DEV_PIPE_NAME.into(),
            // Only the current user (owner rights) and SYSTEM.
            pipe_sddl: "D:P(A;;GA;;;OW)(A;;GA;;;SY)".into(),
            agent_pipe_name: DEV_AGENT_PIPE_NAME.into(),
            agent_pipe_sddl: "D:P(A;;GA;;;OW)(A;;GA;;;SY)".into(),
            console: true,
            agent_exe: None,
            easytier_core: find_easytier_core(&dir),
        };
        eprintln!("console mode: press Enter to stop");
        runtime::run(cfg, rx)
    }

    /// Runs as a background per-user host daemon (launched automatically by MoonRemote UI
    /// when the Windows system service is not installed). Does not exit on stdin EOF.
    pub fn user_background() -> io::Result<()> {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or_else(|| io::Error::other("LOCALAPPDATA not set"))?;
        let (_tx, rx) = mpsc::channel();
        let dir = exe_dir()?;
        let cfg = Config {
            data_dir: local.join("MoonRemote").join("dev-host"),
            pipe_name: DEV_PIPE_NAME.into(),
            pipe_sddl: "D:P(A;;GA;;;OW)(A;;GA;;;SY)".into(),
            agent_pipe_name: DEV_AGENT_PIPE_NAME.into(),
            agent_pipe_sddl: "D:P(A;;GA;;;OW)(A;;GA;;;SY)".into(),
            console: true,
            agent_exe: None,
            easytier_core: find_easytier_core(&dir),
        };
        runtime::run(cfg, rx)
    }
}
