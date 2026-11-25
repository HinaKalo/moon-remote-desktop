//! Media Foundation D3D11 (DXVA) H.264 decoder and D3D11 flip-model swapchain presenter
//! targeting any Win32 `HWND` (e.g. Avalonia `NativeControlHost`).

use std::mem::ManuallyDrop;

use windows::Win32::Foundation::{E_FAIL, HWND};
use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Variant::{VARIANT, VT_UI4};
use windows::core::{Interface, Result};

use crate::gpu::{self, Gpu, VideoConv};

fn pack(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

/// Low-latency Microsoft H.264 Video Decoder MFT in D3D11 (DXVA) mode.
pub struct H264Decoder {
    mft: IMFTransform,
    provides_samples: bool,
    out_size: u32,
}

impl H264Decoder {
    pub fn new(mgr: &IMFDXGIDeviceManager, width: u32, height: u32, fps: u32) -> Result<Self> {
        unsafe {
            let mft: IMFTransform = CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER)?;
            let attrs = mft.GetAttributes()?;
            let d3d = attrs.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) != 0;
            let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            if let Ok(c) = mft.cast::<ICodecAPI>() {
                let mut v = VARIANT::default();
                let inner = &mut *v.Anonymous.Anonymous;
                inner.vt = VT_UI4;
                inner.Anonymous.ulVal = 1;
                let _ = c.SetValue(&CODECAPI_AVLowLatencyMode, &v);
            }
            if d3d {
                mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, mgr.as_raw() as usize)?;
            }
            let inp = MFCreateMediaType()?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            inp.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height))?;
            inp.SetUINT64(&MF_MT_FRAME_RATE, pack(fps.max(1), 1))?;
            inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            mft.SetInputType(0, &inp, 0)?;

            let mut d = Self { mft, provides_samples: false, out_size: 0 };
            d.set_nv12_output()?;
            d.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            d.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            Ok(d)
        }
    }

    unsafe fn set_nv12_output(&mut self) -> Result<()> {
        unsafe {
            let mut i = 0;
            loop {
                let t = self.mft.GetOutputAvailableType(0, i)?;
                if t.GetGUID(&MF_MT_SUBTYPE)? == MFVideoFormat_NV12 {
                    self.mft.SetOutputType(0, &t, 0)?;
                    break;
                }
                i += 1;
            }
            let si = self.mft.GetOutputStreamInfo(0)?;
            self.provides_samples = si.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0) as u32
                != 0;
            self.out_size = si.cbSize;
            Ok(())
        }
    }

    /// Feeds one Annex B access unit and returns any decoded NV12 `IMFSample`s.
    pub fn decode(&mut self, annex_b: &[u8], pts_100ns: i64) -> Result<Vec<IMFSample>> {
        unsafe {
            // Trailing AUD lets the MS decoder finish the picture immediately without
            // waiting for the next access unit.
            let mut data = annex_b.to_vec();
            if data.starts_with(&[0, 0, 0, 1, 9]) {
                data.drain(..6);
            } else if data.starts_with(&[0, 0, 1, 9]) {
                data.drain(..5);
            }
            data.extend_from_slice(&[0, 0, 0, 1, 9, 0xF0]);

            let buf = MFCreateMemoryBuffer(data.len() as u32)?;
            let mut p = std::ptr::null_mut();
            buf.Lock(&mut p, None, None)?;
            std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
            buf.Unlock()?;
            buf.SetCurrentLength(data.len() as u32)?;
            let s = MFCreateSample()?;
            s.AddBuffer(&buf)?;
            s.SetSampleTime(pts_100ns)?;
            self.mft.ProcessInput(0, &s, 0)?;

            let mut outs = Vec::new();
            loop {
                let sample = if self.provides_samples {
                    None
                } else {
                    let s = MFCreateSample()?;
                    s.AddBuffer(&MFCreateMemoryBuffer(self.out_size)?)?;
                    Some(s)
                };
                let mut out = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: ManuallyDrop::new(sample),
                    dwStatus: 0,
                    pEvents: ManuallyDrop::new(None),
                }];
                let mut status = 0;
                let r = self.mft.ProcessOutput(0, &mut out, &mut status);
                let [o] = out;
                let sample = ManuallyDrop::into_inner(o.pSample);
                drop(ManuallyDrop::into_inner(o.pEvents));
                match r {
                    Ok(()) => {
                        if let Some(s) = sample {
                            outs.push(s);
                        }
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => break,
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        self.set_nv12_output()?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(outs)
        }
    }
}

/// Complete native viewer video pipeline: H.264 Annex B → DXVA decode → NV12→BGRA GPU
/// blit → D3D11 flip-model swapchain on an external `HWND`.
pub struct HwndPresenter {
    _gpu: Gpu,
    decoder: H264Decoder,
    swapchain: IDXGISwapChain1,
    conv: VideoConv,
    got_key: bool,
}

impl HwndPresenter {
    /// Creates the decoder and swapchain bound to `hwnd` (must be a valid Win32 window handle).
    ///
    /// # Safety
    /// `hwnd` must remain valid for the lifetime of `HwndPresenter`.
    pub unsafe fn new(hwnd: HWND, width: u32, height: u32, fps: u32) -> Result<Self> {
        unsafe {
            let adapter = gpu::default_adapter()?;
            let g = gpu::create_device(&adapter)?;
            let mgr = gpu::create_dxgi_device_manager(&g.device)?;
            let decoder = H264Decoder::new(&mgr, width, height, fps)?;

            let factory: IDXGIFactory2 = adapter.GetParent()?;
            let scd = DXGI_SWAP_CHAIN_DESC1 {
                Width: width,
                Height: height,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: 2,
                Scaling: DXGI_SCALING_STRETCH,
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
                AlphaMode: DXGI_ALPHA_MODE_IGNORE,
                ..Default::default()
            };
            let swapchain = factory.CreateSwapChainForHwnd(&g.device, hwnd, &scd, None, None)?;
            let conv = VideoConv::new(
                &g.device,
                &g.ctx,
                width,
                height,
                width,
                height,
                fps,
                DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
                DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
            )?;
            Ok(Self { _gpu: g, decoder, swapchain, conv, got_key: false })
        }
    }

    /// Decodes one H.264 frame and presents it to the swapchain. Returns `true` if a frame
    /// was presented.
    pub fn present_frame(&mut self, annex_b: &[u8], keyframe: bool, pts_100ns: i64) -> Result<bool> {
        if !self.got_key {
            if !keyframe {
                return Ok(false);
            }
            self.got_key = true;
        }
        let outs = self.decoder.decode(annex_b, pts_100ns)?;
        let Some(sample) = outs.into_iter().last() else {
            return Ok(false);
        };
        unsafe {
            let buf = sample.GetBufferByIndex(0)?;
            let dxb: IMFDXGIBuffer = buf.cast()?;
            let mut p = std::ptr::null_mut();
            dxb.GetResource(&ID3D11Texture2D::IID, &mut p)?;
            let tex = ID3D11Texture2D::from_raw(p);
            let slice = dxb.GetSubresourceIndex()?;
            let back: ID3D11Texture2D = self.swapchain.GetBuffer(0)?;
            self.conv.blt(&tex, slice, &back)?;
            drop(back);
            let hr = self.swapchain.Present(0, DXGI_PRESENT(0));
            if hr.is_err() {
                return Err(windows::core::Error::new(E_FAIL, format!("Present failed: {hr:?}")));
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::{CapturedFrame, EncoderCfg, H264Encoder};
    use crate::init_media_foundation;
    use windows::Win32::Graphics::Direct3D11::*;

    #[test]
    fn encode_then_decode_synthetic_frame() {
        init_media_foundation().unwrap();
        let Ok(adapter) = gpu::default_adapter() else {
            return; // headless environment without DXGI adapter
        };
        let g = gpu::create_device(&adapter).unwrap();
        let mgr = gpu::create_dxgi_device_manager(&g.device).unwrap();

        let (w, h, fps) = (640, 360, 30);
        let cfg = EncoderCfg { width: w, height: h, fps, bitrate_bps: 2_000_000, prefer_hw: true, adapter_luid: g.luid };
        let mut enc = H264Encoder::create(&cfg, &mgr).unwrap();
        let mut dec = H264Decoder::new(&mgr, w, h, fps).unwrap();

        let nv12 = gpu::texture(
            &g.device,
            w,
            h,
            DXGI_FORMAT_NV12,
            D3D11_BIND_RENDER_TARGET,
            D3D11_USAGE_DEFAULT,
            D3D11_CPU_ACCESS_FLAG(0),
        )
        .unwrap();

        // Feed a few frames until we get an encoded keyframe, then decode it.
        if !enc.info.is_async {
            let mut decoded_any = false;
            for seq in 1..=5u64 {
                enc.feed(&CapturedFrame { tex: nv12.clone(), sequence: seq, capture_time_us: seq * 33_333 }, seq == 1)
                    .unwrap();
                while let Some(f) = enc.pull().unwrap() {
                    let outs = dec.decode(&f.data, (seq as i64) * 333_333).unwrap();
                    if !outs.is_empty() {
                        decoded_any = true;
                    }
                }
            }
            assert!(decoded_any, "decoder produced no frames");
        }
    }
}
