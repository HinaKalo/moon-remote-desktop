use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

use moonrd_agent::desktop;
use moonrd_media::capture::{self, CaptureCfg};
use moonrd_media::encoder::{self, EncMsg, EncoderCfg, H264Encoder};
use moonrd_media::gpu;
use moonrd_proto::{Display, DisplayList, Envelope, Notice, NoticeKind, VideoFrame, envelope::Msg};
use tokio::sync::{mpsc, watch};

pub async fn run(
    mut requested: watch::Receiver<u32>,
    output: mpsc::Sender<Envelope>,
    active: Arc<Mutex<Display>>,
    force_key: Arc<AtomicBool>,
) {
    let mut restore = None;
    loop {
        let target = restore
            .take()
            .unwrap_or_else(|| *requested.borrow_and_update());
        let stop = Arc::new(AtomicBool::new(false));
        let capture_stop = stop.clone();
        let capture_output = output.clone();
        let capture_active = active.clone();
        let capture_key = force_key.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            capture_display(
                target,
                capture_output,
                capture_active,
                capture_key,
                capture_stop,
            )
        });

        tokio::select! {
            changed = requested.changed() => {
                stop.store(true, Ordering::Relaxed);
                let _ = task.await;
                if changed.is_err() { break; }
            }
            result = &mut task => {
                if output.is_closed() { break; }
                let message = match result {
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => e.to_string(),
                    Ok(Ok(())) => "capture stopped".into(),
                };
                let _ = output.try_send(notice(NoticeKind::Unspecified, format!("Display {target}: {message}")));
                let last_active = active.lock().unwrap().id;
                if requested.has_changed().unwrap_or(false) { continue; }
                if target != last_active {
                    restore = Some(last_active);
                    continue;
                }
                if requested.changed().await.is_err() { break; }
            }
        }
    }
}

fn notice(kind: NoticeKind, message: String) -> Envelope {
    Envelope {
        msg: Some(Msg::Notice(Notice {
            kind: kind as i32,
            message,
        })),
    }
}

fn capture_display(
    id: u32,
    tx: mpsc::Sender<Envelope>,
    active: Arc<Mutex<Display>>,
    force_key: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    moonrd_media::init_media_foundation()?;
    let _ = desktop::sync_input_desktop();
    let (adapter, output, display) = gpu::find_output(Some(id))?;
    if display.id != id {
        return Err(io::Error::other("display is no longer attached").into());
    }
    let gpu = gpu::create_device(&adapter)?;
    let manager = gpu::create_dxgi_device_manager(&gpu.device)?;
    let fps = 30;
    let size = |long: f64, short: f64| {
        let scale = (long / display.width.max(display.height) as f64)
            .min(short / display.height.min(display.width).max(1) as f64)
            .min(1.0);
        (
            ((display.width as f64 * scale) as u32 & !1).max(2),
            ((display.height as f64 * scale) as u32 & !1).max(2),
        )
    };
    let ((out_w, out_h), enc) = [size(3840., 2160.), size(1920., 1080.)]
        .into_iter()
        .find_map(|(width, height)| {
            H264Encoder::create(
                &EncoderCfg {
                    width,
                    height,
                    fps,
                    bitrate_bps: (width as u64 * height as u64 * 3).clamp(2_000_000, 25_000_000)
                        as u32,
                    prefer_hw: true,
                    adapter_luid: gpu.luid,
                },
                &manager,
            )
            .ok()
            .map(|enc| ((width, height), enc))
        })
        .ok_or_else(|| io::Error::other("H.264 encoder initialization failed"))?;

    let mut config = enc.video_config();
    config.display_id = display.id;
    let displays = gpu::enumerate_displays()?;
    let mut announced = false;
    let (enc_tx, enc_rx) = std::sync::mpsc::channel::<EncMsg>();
    let cap_tx = enc_tx.clone();
    let cap_key = force_key.clone();
    let cap_stop = stop.clone();
    let notice_tx = tx.clone();
    force_key.store(true, Ordering::Relaxed);
    let cap = thread::Builder::new()
        .name("moonrd-capture".into())
        .spawn(move || {
            let _ = desktop::sync_input_desktop();
            let result = capture::run(
                gpu.device,
                gpu.ctx,
                output,
                CaptureCfg { out_w, out_h, fps },
                cap_tx.clone(),
                cap_key,
                cap_stop,
                || {
                    if desktop::sync_input_desktop().is_some_and(|ds| ds.secure) {
                        let _ = notice_tx.try_send(notice(
                            NoticeKind::SecureDesktop,
                            "secure desktop active".into(),
                        ));
                    }
                },
            );
            let _ = cap_tx.send(EncMsg::Stop);
            result
        })?;

    let result = encoder::run(enc, enc_tx, enc_rx, force_key.clone(), |frame| {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let video = Envelope {
            msg: Some(Msg::VideoFrame(VideoFrame {
                sequence: frame.sequence,
                capture_time_us: frame.capture_time_us,
                keyframe: frame.keyframe,
                data: frame.data.to_vec(),
            })),
        };
        if !announced {
            if !frame.keyframe {
                force_key.store(true, Ordering::Relaxed);
                return true;
            }
            let metadata = [
                Envelope {
                    msg: Some(Msg::DisplayList(DisplayList {
                        active_id: display.id,
                        displays: displays.clone(),
                    })),
                },
                Envelope {
                    msg: Some(Msg::VideoConfig(config.clone())),
                },
            ];
            // Input must follow the output being published, even when the previous
            // display's frames are still in flight toward the viewer.
            *active.lock().unwrap() = display.clone();
            for message in metadata.into_iter().chain([video]) {
                if tx.blocking_send(message).is_err() {
                    return false;
                }
            }
            announced = true;
            return true;
        }
        match tx.try_send(video) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                force_key.store(true, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    });
    stop.store(true, Ordering::Relaxed);
    let capture_result = cap
        .join()
        .map_err(|_| io::Error::other("capture thread failed"))?;
    result?;
    capture_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires an unlocked Windows desktop with a DXGI output"]
    async fn publishes_matching_display_metadata_before_the_first_keyframe() {
        let displays = gpu::enumerate_displays().unwrap();
        let primary = displays.iter().find(|d| d.primary).unwrap().clone();
        let active = Arc::new(Mutex::new(primary.clone()));
        let (select, requested) = watch::channel(primary.id);
        let (tx, mut rx) = mpsc::channel(64);
        let handle = tokio::spawn(run(
            requested,
            tx,
            active.clone(),
            Arc::new(AtomicBool::new(true)),
        ));
        for (index, display) in displays.iter().chain(std::iter::once(&primary)).enumerate() {
            if index != 0 || display.id != primary.id {
                select.send_replace(display.id);
            }
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut announced = false;
                let mut configured = false;
                while let Some(env) = rx.recv().await {
                    match env.msg {
                        Some(Msg::DisplayList(list)) => announced = list.active_id == display.id,
                        Some(Msg::VideoConfig(config)) => {
                            configured = config.display_id == display.id && announced
                        }
                        Some(Msg::VideoFrame(frame)) if frame.keyframe && configured => {
                            assert_eq!(active.lock().unwrap().id, display.id);
                            return;
                        }
                        _ => {}
                    }
                }
                panic!("capture closed before announcing display {}", display.id);
            })
            .await
            .expect("capture/config/IDR timed out");
        }
        drop(rx);
        drop(select);
        handle.await.unwrap();
        println!("Verified {} attached DXGI output(s) and a pipeline restart", displays.len());
    }
}
