//! D3D11 device creation, display enumeration, and fixed-function `ID3D11VideoProcessor`
//! for zero-copy BGRA ↔ NV12 conversion and scaling on the GPU.

use std::collections::HashMap;
use std::mem::ManuallyDrop;

use moonrd_proto::Display;
use windows::Win32::Foundation::{E_FAIL, HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Media::MediaFoundation::{IMFDXGIDeviceManager, MFCreateDXGIDeviceManager};
use windows::core::{Interface, Result};

pub struct Gpu {
    pub device: ID3D11Device,
    pub ctx: ID3D11DeviceContext,
    pub adapter: IDXGIAdapter1,
    pub adapter_name: String,
    pub luid: i64,
}

/// Enumerates all attached desktop displays in DXGI order.
pub fn enumerate_displays() -> Result<Vec<Display>> {
    let mut out = Vec::new();
    let mut id = 1u32;
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        let mut ai = 0;
        while let Ok(adapter) = factory.EnumAdapters1(ai) {
            let mut oi = 0;
            while let Ok(output) = adapter.EnumOutputs(oi) {
                let desc = output.GetDesc()?;
                if desc.AttachedToDesktop.as_bool() {
                    let r = desc.DesktopCoordinates;
                    let name = String::from_utf16_lossy(&desc.DeviceName)
                        .trim_end_matches('\0')
                        .to_string();
                    out.push(Display {
                        id,
                        name,
                        x: r.left,
                        y: r.top,
                        width: (r.right - r.left).max(0) as u32,
                        height: (r.bottom - r.top).max(0) as u32,
                        dpi: 96,
                        primary: r.left == 0 && r.top == 0,
                    });
                    id += 1;
                }
                oi += 1;
            }
            ai += 1;
        }
    }
    Ok(out)
}

/// Finds the adapter + output for `display_id` (1-based, or the primary display when
/// `None` / not found).
pub fn find_output(display_id: Option<u32>) -> Result<(IDXGIAdapter1, IDXGIOutput1, Display)> {
    let mut fallback = None;
    let mut id = 1u32;
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        let mut ai = 0;
        while let Ok(adapter) = factory.EnumAdapters1(ai) {
            let mut oi = 0;
            while let Ok(output) = adapter.EnumOutputs(oi) {
                let desc = output.GetDesc()?;
                if desc.AttachedToDesktop.as_bool() {
                    let r = desc.DesktopCoordinates;
                    let primary = r.left == 0 && r.top == 0;
                    let info = Display {
                        id,
                        name: String::from_utf16_lossy(&desc.DeviceName)
                            .trim_end_matches('\0')
                            .to_string(),
                        x: r.left,
                        y: r.top,
                        width: (r.right - r.left).max(0) as u32,
                        height: (r.bottom - r.top).max(0) as u32,
                        dpi: 96,
                        primary,
                    };
                    if display_id == Some(id) || (display_id.is_none() && primary) {
                        return Ok((adapter, output.cast()?, info));
                    }
                    if fallback.is_none() || primary {
                        fallback = Some((adapter.clone(), output.cast()?, info));
                    }
                    id += 1;
                }
                oi += 1;
            }
            ai += 1;
        }
    }
    fallback.ok_or_else(|| windows::core::Error::new(E_FAIL, "no desktop output found"))
}

/// Finds the default DXGI adapter (used by the native viewer decoder/presenter).
pub fn default_adapter() -> Result<IDXGIAdapter1> {
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        factory.EnumAdapters1(0)
    }
}

pub fn create_device(adapter: &IDXGIAdapter1) -> Result<Gpu> {
    unsafe {
        let mut device = None;
        let mut ctx = None;
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut ctx),
        )?;
        let device: ID3D11Device = device.unwrap();
        let mt: ID3D11Multithread = device.cast()?;
        let _ = mt.SetMultithreadProtected(true);
        let desc = adapter.GetDesc1()?;
        let name = String::from_utf16_lossy(&desc.Description)
            .trim_end_matches('\0')
            .to_string();
        let luid = ((desc.AdapterLuid.HighPart as i64) << 32) | desc.AdapterLuid.LowPart as i64;
        Ok(Gpu { device, ctx: ctx.unwrap(), adapter: adapter.clone(), adapter_name: name, luid })
    }
}

pub fn create_dxgi_device_manager(device: &ID3D11Device) -> Result<IMFDXGIDeviceManager> {
    unsafe {
        let mut token = 0u32;
        let mut mgr = None;
        MFCreateDXGIDeviceManager(&mut token, &mut mgr)?;
        let mgr = mgr.unwrap();
        mgr.ResetDevice(device, token)?;
        Ok(mgr)
    }
}

pub fn texture(
    device: &ID3D11Device,
    w: u32,
    h: u32,
    format: DXGI_FORMAT,
    bind: D3D11_BIND_FLAG,
    usage: D3D11_USAGE,
    cpu: D3D11_CPU_ACCESS_FLAG,
) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: w,
        Height: h,
        MipLevels: 1,
        ArraySize: 1,
        Format: format,
        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
        Usage: usage,
        BindFlags: bind.0 as u32,
        CPUAccessFlags: cpu.0 as u32,
        MiscFlags: 0,
    };
    let mut t = None;
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut t))? };
    Ok(t.unwrap())
}

/// Fixed-size video processor: one input size/format → one output size/format.
pub struct VideoConv {
    vdev: ID3D11VideoDevice,
    vctx: ID3D11VideoContext1,
    vp: ID3D11VideoProcessor,
    venum: ID3D11VideoProcessorEnumerator,
    in_views: HashMap<(usize, u32), ID3D11VideoProcessorInputView>,
    out_views: HashMap<usize, ID3D11VideoProcessorOutputView>,
}

impl VideoConv {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device: &ID3D11Device,
        ctx: &ID3D11DeviceContext,
        in_w: u32,
        in_h: u32,
        out_w: u32,
        out_h: u32,
        fps: u32,
        in_cs: DXGI_COLOR_SPACE_TYPE,
        out_cs: DXGI_COLOR_SPACE_TYPE,
    ) -> Result<Self> {
        unsafe {
            let vdev: ID3D11VideoDevice = device.cast()?;
            let vctx: ID3D11VideoContext1 = ctx.cast()?;
            let desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputFrameRate: DXGI_RATIONAL { Numerator: fps.max(1), Denominator: 1 },
                InputWidth: in_w,
                InputHeight: in_h,
                OutputFrameRate: DXGI_RATIONAL { Numerator: fps.max(1), Denominator: 1 },
                OutputWidth: out_w,
                OutputHeight: out_h,
                Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
            };
            let venum = vdev.CreateVideoProcessorEnumerator(&desc)?;
            let vp = vdev.CreateVideoProcessor(&venum, 0)?;
            vctx.VideoProcessorSetStreamColorSpace1(&vp, 0, in_cs);
            vctx.VideoProcessorSetOutputColorSpace1(&vp, out_cs);
            vctx.VideoProcessorSetStreamFrameFormat(&vp, 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
            vctx.VideoProcessorSetStreamAutoProcessingMode(&vp, 0, false);
            let src = RECT { left: 0, top: 0, right: in_w as i32, bottom: in_h as i32 };
            let dst = RECT { left: 0, top: 0, right: out_w as i32, bottom: out_h as i32 };
            vctx.VideoProcessorSetStreamSourceRect(&vp, 0, true, Some(&src));
            vctx.VideoProcessorSetStreamDestRect(&vp, 0, true, Some(&dst));
            vctx.VideoProcessorSetOutputTargetRect(&vp, true, Some(&dst));
            Ok(Self { vdev, vctx, vp, venum, in_views: HashMap::new(), out_views: HashMap::new() })
        }
    }

    pub fn blt(&mut self, input: &ID3D11Texture2D, in_slice: u32, output: &ID3D11Texture2D) -> Result<()> {
        unsafe {
            let ikey = (input.as_raw() as usize, in_slice);
            if !self.in_views.contains_key(&ikey) {
                let d = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                    FourCC: 0,
                    ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                        Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: in_slice },
                    },
                };
                let mut v = None;
                self.vdev.CreateVideoProcessorInputView(input, &self.venum, &d, Some(&mut v))?;
                if self.in_views.len() > 64 {
                    self.in_views.clear();
                }
                self.in_views.insert(ikey, v.unwrap());
            }
            let okey = output.as_raw() as usize;
            if !self.out_views.contains_key(&okey) {
                let d = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                    ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                        Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
                    },
                };
                let mut v = None;
                self.vdev.CreateVideoProcessorOutputView(output, &self.venum, &d, Some(&mut v))?;
                if self.out_views.len() > 16 {
                    self.out_views.clear();
                }
                self.out_views.insert(okey, v.unwrap());
            }
            let stream = D3D11_VIDEO_PROCESSOR_STREAM {
                Enable: true.into(),
                pInputSurface: ManuallyDrop::new(Some(self.in_views[&ikey].clone())),
                ..Default::default()
            };
            let streams = [stream];
            let r = self.vctx.VideoProcessorBlt(&self.vp, &self.out_views[&okey], 0, &streams);
            let [mut s] = streams;
            ManuallyDrop::drop(&mut s.pInputSurface);
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_displays_or_runs_headless() {
        // On a desktop session this returns at least 1 display; on headless CI it may be empty,
        // but must not panic.
        let _ = enumerate_displays();
    }
}
