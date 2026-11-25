//! `moonrd-agent` entry point.
//!
//! Connects to `moonrd-service` over `\\.\pipe\moonrd-agent` (or `\\.\pipe\moonrd-agent-dev`
//! with `--dev`), captures the active display via DXGI + Media Foundation H.264, and
//! applies incoming input/clipboard/display commands.

#[cfg(not(windows))]
fn main() {
    eprintln!("moonrd-agent runs on Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let dev = std::env::args().any(|a| a == "--dev");
    let pipe_name = if dev { r"\\.\pipe\moonrd-agent-dev" } else { r"\\.\pipe\moonrd-agent" };
    if let Err(e) = run_agent(pipe_name).await {
        eprintln!("moonrd-agent: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
async fn run_agent(pipe_name: &str) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use moonrd_agent::clipboard::ClipboardSync;
    use moonrd_agent::desktop;
    use moonrd_agent::input;
    use moonrd_media::gpu;
    use moonrd_proto::envelope::Msg;
    use moonrd_proto::{
        ClipboardData, Display, DisplayList, Envelope, Notice, NoticeKind, SpecialActionKind,
    };
    use moonrd_session::frame::{self, Decoder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio::sync::{mpsc, watch};

    moonrd_media::init_media_foundation().map_err(|e| std::io::Error::other(e.to_string()))?;

    // Retry briefly while the service's agent pipe is coming up.
    let client = loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(231) || e.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    };

    let (mut reader, mut writer) = tokio::io::split(client);
    let (out_tx, mut out_rx) = mpsc::channel::<Envelope>(128);

    // Track current display list and active display for pointer coordinate mapping.
    let displays = gpu::enumerate_displays().unwrap_or_default();
    let active_display: Arc<Mutex<Display>> = Arc::new(Mutex::new(
        displays
            .iter()
            .find(|d| d.primary)
            .or_else(|| displays.first())
            .cloned()
            .unwrap_or(Display { id: 1, name: "Primary".into(), x: 0, y: 0, width: 1920, height: 1080, dpi: 96, primary: true }),
    ));
    let force_key = Arc::new(AtomicBool::new(true));

    let initial_display_id = active_display.lock().unwrap().id;
    // Send initial DisplayList.
    let _ = out_tx
        .send(Envelope {
            msg: Some(Msg::DisplayList(DisplayList {
                active_id: initial_display_id,
                displays: displays.clone(),
            })),
        })
        .await;

    let (select_display, requested) = watch::channel(initial_display_id);
    let media = tokio::spawn(capture_session::run(requested, out_tx.clone(), active_display.clone(), force_key.clone()));

    // Clipboard sync + desktop polling timer.
    let clip = Arc::new(Mutex::new(ClipboardSync::new()));
    let mut clip_interval = tokio::time::interval(Duration::from_millis(500));

    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];

    let send_media = async {
        while let Some(env) = out_rx.recv().await {
            writer.write_all(&frame::encode(&env)).await?;
        }
        Ok(())
    };
    let read_input = async {
        loop {
            tokio::select! {
                _ = clip_interval.tick() => {
                    if let Some(text) = clip.lock().unwrap().poll_local() {
                        let _ = out_tx.try_send(Envelope { msg: Some(Msg::Clipboard(ClipboardData { text })) });
                    }
                }
                read = reader.read(&mut buf) => {
                    let n = read?;
                    if n == 0 {
                        break;
                    }
                    decoder.push(&buf[..n]);
                    while let Some(env) = decoder.next_frame().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))? {
                        match env.msg {
                            Some(Msg::KeyframeRequest(_)) => {
                                force_key.store(true, Ordering::Relaxed);
                            }
                            Some(Msg::Pointer(p)) => {
                                let _ = desktop::sync_input_desktop();
                                let disp = active_display.lock().unwrap().clone();
                                input::inject_pointer(&p, &disp);
                            }
                            Some(Msg::Key(k)) => {
                                let _ = desktop::sync_input_desktop();
                                input::inject_key(&k);
                            }
                            Some(Msg::Clipboard(c)) => {
                                clip.lock().unwrap().apply_remote(&c.text);
                            }
                            Some(Msg::SelectDisplay(sel)) => {
                                if gpu::enumerate_displays().is_ok_and(|all| all.iter().any(|d| d.id == sel.id)) {
                                    select_display.send_replace(sel.id);
                                } else {
                                    let _ = out_tx.try_send(Envelope { msg: Some(Msg::Notice(Notice {
                                        kind: NoticeKind::Unspecified as i32,
                                        message: "Requested display is unavailable".into(),
                                    })) });
                                    select_display.send_replace(active_display.lock().unwrap().id);
                                }
                            }
                            Some(Msg::SpecialAction(a)) => {
                                match SpecialActionKind::try_from(a.kind).unwrap_or(SpecialActionKind::SpecialActionUnspecified) {
                                    SpecialActionKind::SpecialActionLockWorkstation => input::lock_workstation(),
                                    SpecialActionKind::SpecialActionBlockLocalInput => input::block_local_input(true),
                                    SpecialActionKind::SpecialActionUnblockLocalInput => input::block_local_input(false),
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(())
    };
    let result = tokio::select! {
        result = send_media => result,
        result = read_input => result,
    };
    drop(out_rx);
    drop(select_display);
    let _ = media.await;
    result
}

#[cfg(windows)]
mod capture_session;
