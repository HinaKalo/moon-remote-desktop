//! DXGI Desktop Duplication capture loop producing GPU NV12 textures for [`crate::encoder`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::core::{Interface, Result};

use crate::encoder::{CapturedFrame, EncMsg};
use crate::gpu::{self, VideoConv};
use crate::{qpc, qpc_freq, qpc_to_us};

#[derive(Clone, Debug)]
pub struct CaptureCfg {
    pub out_w: u32,
    pub out_h: u32,
    pub fps: u32,
}

/// Runs DXGI Desktop Duplication on the current thread until `stop` is set or `tx`
/// disconnects. Calls `on_access_lost` whenever DXGI loses access (e.g. UAC / secure
/// desktop transition) so the caller can switch desktops before re-duplicating.
#[allow(clippy::too_many_arguments)]
pub fn run<F>(
    device: ID3D11Device,
    ctx: ID3D11DeviceContext,
    output: IDXGIOutput1,
    cfg: CaptureCfg,
    tx: Sender<EncMsg>,
    force_key: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    mut on_access_lost: F,
) -> Result<()>
where
    F: FnMut(),
{
    unsafe {
        let mut dup = output.DuplicateOutput(&device)?;
        let dd = dup.GetDesc();
        let (dw, dh) = (dd.ModeDesc.Width, dd.ModeDesc.Height);
        let copy = gpu::texture(
            &device,
            dw,
            dh,
            DXGI_FORMAT_B8G8R8A8_UNORM,
            D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET,
            D3D11_USAGE_DEFAULT,
            D3D11_CPU_ACCESS_FLAG(0),
        )?;
        let mut conv = VideoConv::new(
            &device,
            &ctx,
            dw,
            dh,
            cfg.out_w,
            cfg.out_h,
            cfg.fps,
            DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
            DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
        )?;
        let mut ring = Vec::with_capacity(8);
        for _ in 0..8 {
            let t = gpu::texture(
                &device,
                cfg.out_w,
                cfg.out_h,
                DXGI_FORMAT_NV12,
                D3D11_BIND_RENDER_TARGET | D3D11_BIND_VIDEO_ENCODER,
                D3D11_USAGE_DEFAULT,
                D3D11_CPU_ACCESS_FLAG(0),
            )
            .or_else(|_| {
                gpu::texture(
                    &device,
                    cfg.out_w,
                    cfg.out_h,
                    DXGI_FORMAT_NV12,
                    D3D11_BIND_RENDER_TARGET,
                    D3D11_USAGE_DEFAULT,
                    D3D11_CPU_ACCESS_FLAG(0),
                )
            })?;
            ring.push(t);
        }

        let idle_interval = qpc_freq();
        let interval_qpc = idle_interval / cfg.fps.max(1) as i64;
        let early = interval_qpc / 4;
        let mut next_due = 0i64;
        let mut next_static_key = 0i64;
        let mut next_idle = 0i64;
        let mut dirty = false;
        let mut last_tex: Option<ID3D11Texture2D> = None;
        let mut idx = 0usize;
        let mut seq = 0u64;

        while !stop.load(Ordering::Relaxed) {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut res: Option<IDXGIResource> = None;
            let r = dup.AcquireNextFrame(0, &mut info, &mut res);
            let now = qpc();
            let mut got = false;
            match r {
                Ok(()) => {
                    if (info.LastPresentTime != 0 || last_tex.is_none())
                        && let Some(r) = res
                    {
                        let desk: ID3D11Texture2D = r.cast()?;
                        ctx.CopyResource(&copy, &desk);
                        drop(desk);
                        dirty = true;
                        got = true;
                    }
                    let _ = dup.ReleaseFrame();
                }
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {}
                Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                    drop(dup);
                    on_access_lost();
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        thread::sleep(Duration::from_millis(100));
                        on_access_lost();
                        if let Ok(d) = output.DuplicateOutput(&device) {
                            dup = d;
                            force_key.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }

            if dirty && ((got && now >= next_due - early) || now >= next_due) {
                next_due = (next_due + interval_qpc).max(now + interval_qpc - early);
                next_idle = now + idle_interval;
                dirty = false;
                let nv12 = ring[idx].clone();
                idx = (idx + 1) % ring.len();
                conv.blt(&copy, 0, &nv12)?;
                ctx.Flush();
                seq += 1;
                last_tex = Some(nv12.clone());
                if tx.send(EncMsg::Frame(CapturedFrame { tex: nv12, sequence: seq, capture_time_us: qpc_to_us(now) })).is_err() {
                    return Ok(());
                }
            } else if (now >= next_idle || (now >= next_static_key && force_key.load(Ordering::Relaxed)))
                && let Some(tex) = last_tex.clone()
            {
                // Keep packet-loss detection possible even if the last desktop update
                // vanished in transit. Explicit keyframe requests can use the cached texture sooner.
                next_idle = now + idle_interval;
                next_static_key = now + interval_qpc;
                seq += 1;
                if tx.send(EncMsg::Frame(CapturedFrame { tex, sequence: seq, capture_time_us: qpc_to_us(now) })).is_err() {
                    return Ok(());
                }
            } else {
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}
