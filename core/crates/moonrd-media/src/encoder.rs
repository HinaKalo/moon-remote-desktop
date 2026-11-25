//! Media Foundation H.264 encoder MFT (hardware NVENC/QSV/AMF with software fallback).

use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

use moonrd_proto::{Codec, VideoConfig};
use windows::Win32::Foundation::{E_FAIL, VARIANT_BOOL};
use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};
use windows::core::{GUID, Interface, Result};

use crate::{EncodedFrame, has_nal, qpc, qpc_freq, qpc_to_us};

/// One NV12 D3D11 texture captured from the desktop, ready for the encoder.
pub struct CapturedFrame {
    pub tex: ID3D11Texture2D,
    pub sequence: u64,
    pub capture_time_us: u64,
}
// D3D11 objects are free-threaded once the device is multithread-protected.
unsafe impl Send for CapturedFrame {}

pub enum EncMsg {
    Frame(CapturedFrame),
    NeedInput,
    HaveOutput,
    Stop,
    EventError(String),
}

#[derive(Clone, Debug)]
pub struct EncoderCfg {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
    pub prefer_hw: bool,
    pub adapter_luid: i64,
}

#[derive(Clone, Debug, Default)]
pub struct EncoderInfo {
    pub name: String,
    pub hardware: bool,
    pub is_async: bool,
    pub d3d_aware: bool,
    pub profile: String,
}

fn var_u32(v: u32) -> VARIANT {
    let mut var = VARIANT::default();
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_UI4;
        inner.Anonymous.ulVal = v;
    }
    var
}

fn var_bool(b: bool) -> VARIANT {
    let mut var = VARIANT::default();
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous.boolVal = VARIANT_BOOL(if b { -1 } else { 0 });
    }
    var
}

fn pack(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

struct SendBox<T>(T);
unsafe impl<T> Send for SendBox<T> {}

unsafe fn activate_name(a: &IMFActivate) -> String {
    unsafe {
        let mut p = windows::core::PWSTR::null();
        let mut len = 0u32;
        if a.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut p, &mut len).is_ok() {
            let s = p.to_string().unwrap_or_default();
            CoTaskMemFree(Some(p.0 as _));
            s
        } else {
            "<unnamed>".into()
        }
    }
}

unsafe fn enum_encoders(hw: bool) -> Result<Vec<(String, IMFActivate)>> {
    unsafe {
        let input = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_NV12 };
        let output = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_H264 };
        let flags = if hw {
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER
        } else {
            MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER
        };
        let mut pp: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut n = 0u32;
        MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, flags, Some(&input), Some(&output), &mut pp, &mut n)?;
        let mut v = Vec::new();
        if !pp.is_null() {
            for a in std::slice::from_raw_parts_mut(pp, n as usize) {
                if let Some(a) = a.take() {
                    v.push((activate_name(&a), a));
                }
            }
            CoTaskMemFree(Some(pp as _));
        }
        Ok(v)
    }
}

pub struct H264Encoder {
    mft: IMFTransform,
    codec: Option<ICodecAPI>,
    pub info: EncoderInfo,
    provides_samples: bool,
    out_size: u32,
    seq_header: Vec<u8>,
    pending: HashMap<i64, (u64, u64)>,
    start_qpc: i64,
    cfg: EncoderCfg,
}

impl H264Encoder {
    pub fn create(cfg: &EncoderCfg, dev_mgr: &IMFDXGIDeviceManager) -> Result<Self> {
        unsafe {
            let mut candidates = Vec::new();
            if cfg.prefer_hw
                && let Ok(mut v) = enum_encoders(true)
            {
                v.sort_by_key(|(_, a)| match a.GetUINT64(&MFT_ENUM_ADAPTER_LUID).ok() {
                    Some(l) if l as i64 == cfg.adapter_luid => 0,
                    None => 1,
                    _ => 2,
                });
                for (n, a) in v {
                    candidates.push((n, a, true));
                }
            }
            for (n, a) in enum_encoders(false)? {
                candidates.push((n, a, false));
            }
            let mut last_err = None;
            for (name, act, hw) in candidates {
                match Self::try_open(cfg, dev_mgr, &name, &act, hw) {
                    Ok(e) => return Ok(e),
                    Err(err) => {
                        let _ = act.ShutdownObject();
                        last_err = Some(err);
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| windows::core::Error::new(E_FAIL, "no H.264 encoder MFT")))
        }
    }

    pub fn video_config(&self) -> VideoConfig {
        VideoConfig {
            codec: Codec::H264 as i32,
            width: self.cfg.width,
            height: self.cfg.height,
            fps: self.cfg.fps,
            bitrate_kbps: self.cfg.bitrate_bps / 1000,
            hardware: self.info.hardware,
            encoder_name: self.info.name.clone(),
            display_id: 0,
        }
    }

    unsafe fn try_open(
        cfg: &EncoderCfg,
        dev_mgr: &IMFDXGIDeviceManager,
        name: &str,
        act: &IMFActivate,
        hw: bool,
    ) -> Result<Self> {
        unsafe {
            let mft: IMFTransform = act.ActivateObject()?;
            let attrs = mft.GetAttributes()?;
            let is_async = attrs.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) != 0;
            if is_async {
                attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
            }
            let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            let d3d_aware = attrs.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) != 0;
            if d3d_aware {
                mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, dev_mgr.as_raw() as usize)?;
            }
            let codec: Option<ICodecAPI> = mft.cast().ok();
            if let Some(c) = &codec {
                let set = |g: &GUID, v: VARIANT| {
                    let _ = c.SetValue(g, &v);
                };
                set(&CODECAPI_AVLowLatencyMode, var_bool(true));
                set(&CODECAPI_AVEncCommonRateControlMode, var_u32(eAVEncCommonRateControlMode_CBR.0 as u32));
                set(&CODECAPI_AVEncCommonMeanBitRate, var_u32(cfg.bitrate_bps));
                set(&CODECAPI_AVEncCommonBufferSize, var_u32(cfg.bitrate_bps / 2));
                set(&CODECAPI_AVEncMPVDefaultBPictureCount, var_u32(0));
                set(&CODECAPI_AVEncMPVGOPSize, var_u32(cfg.fps * 10));
                set(&CODECAPI_AVEncCommonQualityVsSpeed, var_u32(33));
            }

            let profiles = [
                (eAVEncH264VProfile_ConstrainedBase.0, "ConstrainedBaseline"),
                (eAVEncH264VProfile_Base.0, "Baseline"),
                (eAVEncH264VProfile_Main.0, "Main"),
            ];
            let mut chosen = None;
            for (p, pname) in profiles {
                let out = MFCreateMediaType()?;
                out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
                out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
                out.SetUINT32(&MF_MT_AVG_BITRATE, cfg.bitrate_bps)?;
                out.SetUINT64(&MF_MT_FRAME_SIZE, pack(cfg.width, cfg.height))?;
                out.SetUINT64(&MF_MT_FRAME_RATE, pack(cfg.fps, 1))?;
                out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
                out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
                out.SetUINT32(&MF_MT_MPEG2_PROFILE, p as u32)?;
                out.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709.0 as u32)?;
                out.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32)?;
                if mft.SetOutputType(0, &out, 0).is_ok() {
                    chosen = Some(pname.to_string());
                    break;
                }
            }
            let profile = chosen.ok_or_else(|| windows::core::Error::new(E_FAIL, "no H.264 profile accepted"))?;

            let inp = MFCreateMediaType()?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            inp.SetUINT64(&MF_MT_FRAME_SIZE, pack(cfg.width, cfg.height))?;
            inp.SetUINT64(&MF_MT_FRAME_RATE, pack(cfg.fps, 1))?;
            inp.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
            inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            mft.SetInputType(0, &inp, 0)?;

            let mut seq_header = Vec::new();
            if let Ok(cur) = mft.GetOutputCurrentType(0)
                && let Ok(n) = cur.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER)
            {
                seq_header.resize(n as usize, 0);
                if cur.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut seq_header, None).is_err() {
                    seq_header.clear();
                }
            }

            let si = mft.GetOutputStreamInfo(0)?;
            let provides_samples = si.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0) as u32
                != 0;

            let _ = mft.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;

            Ok(Self {
                mft,
                codec,
                info: EncoderInfo { name: name.to_string(), hardware: hw, is_async, d3d_aware, profile },
                provides_samples,
                out_size: si.cbSize.max(cfg.width * cfg.height),
                seq_header,
                pending: HashMap::new(),
                start_qpc: qpc(),
                cfg: cfg.clone(),
            })
        }
    }

    pub fn feed(&mut self, f: &CapturedFrame, force_key: bool) -> Result<()> {
        unsafe {
            if force_key
                && let Some(c) = &self.codec
            {
                let _ = c.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &var_u32(1));
            }
            let buf = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, &f.tex, 0, false)?;
            let b2: IMF2DBuffer = buf.cast()?;
            buf.SetCurrentLength(b2.GetContiguousLength()?)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buf)?;
            let pts = ((qpc() - self.start_qpc) as i128 * 10_000_000 / qpc_freq() as i128) as i64;
            sample.SetSampleTime(pts)?;
            sample.SetSampleDuration(10_000_000 / self.cfg.fps.max(1) as i64)?;
            self.pending.insert(pts, (f.sequence, f.capture_time_us));
            if self.pending.len() > 64
                && let Some(&min) = self.pending.keys().min()
            {
                self.pending.remove(&min);
            }
            self.mft.ProcessInput(0, &sample, 0)
        }
    }

    pub fn pull(&mut self) -> Result<Option<EncodedFrame>> {
        unsafe {
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
            let mut status = 0u32;
            let r = self.mft.ProcessOutput(0, &mut out, &mut status);
            let [o] = out;
            let sample = ManuallyDrop::into_inner(o.pSample);
            drop(ManuallyDrop::into_inner(o.pEvents));
            match r {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let t = self.mft.GetOutputAvailableType(0, 0)?;
                    self.mft.SetOutputType(0, &t, 0)?;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
            let Some(sample) = sample else { return Ok(None) };
            let buf = sample.ConvertToContiguousBuffer()?;
            let mut p = std::ptr::null_mut();
            let mut len = 0u32;
            buf.Lock(&mut p, None, Some(&mut len))?;
            let bytes = std::slice::from_raw_parts(p, len as usize);
            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) != 0;
            let mut data = Vec::with_capacity(bytes.len() + self.seq_header.len());
            if keyframe && !self.seq_header.is_empty() && !has_nal(bytes, 7) {
                data.extend_from_slice(&self.seq_header);
            }
            data.extend_from_slice(bytes);
            buf.Unlock()?;
            let pts = sample.GetSampleTime().unwrap_or(0);
            let (sequence, capture_time_us) = self.pending.remove(&pts).unwrap_or((0, qpc_to_us(qpc())));
            Ok(Some(EncodedFrame { sequence, capture_time_us, keyframe, data: data.into() }))
        }
    }
}

/// Runs the encoder loop on the current thread, delivering encoded frames to `on_frame`.
pub fn run<F>(
    mut enc: H264Encoder,
    tx: Sender<EncMsg>,
    rx: Receiver<EncMsg>,
    force_key: Arc<AtomicBool>,
    mut on_frame: F,
) -> Result<()>
where
    F: FnMut(EncodedFrame) -> bool,
{
    struct EventPump(Arc<AtomicBool>, Option<thread::JoinHandle<()>>);
    impl Drop for EventPump {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
            if let Some(handle) = self.1.take() { let _ = handle.join(); }
        }
    }

    let _pump = if enc.info.is_async {
        let generator: IMFMediaEventGenerator = enc.mft.cast()?;
        let g = SendBox(generator);
        let tx = tx.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let handle = thread::Builder::new()
            .name("moonrd-mft-events".into())
            .spawn(move || {
                let g = g;
                while !cancelled.load(Ordering::Relaxed) {
                    let ev = match unsafe { g.0.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                        Ok(ev) => ev,
                        Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(e) => {
                            let _ = tx.send(EncMsg::EventError(format!("{e:?}")));
                            return;
                        }
                    };
                    let t = unsafe { ev.GetType() }.unwrap_or(0);
                    let msg = if t == METransformNeedInput.0 as u32 {
                        EncMsg::NeedInput
                    } else if t == METransformHaveOutput.0 as u32 {
                        EncMsg::HaveOutput
                    } else {
                        continue;
                    };
                    if tx.send(msg).is_err() {
                        return;
                    }
                }
            })
            .map_err(|e| windows::core::Error::new(E_FAIL, e.to_string()))?;
        Some(EventPump(stop, Some(handle)))
    } else { None };
    drop(tx);

    let mut need_input = 0u32;
    let mut queued: Option<CapturedFrame> = None;

    for msg in rx {
        match msg {
            EncMsg::Stop => break,
            EncMsg::Frame(f) => {
                if enc.info.is_async {
                    if need_input > 0 {
                        need_input -= 1;
                        enc.feed(&f, force_key.swap(false, Ordering::Relaxed))?;
                    } else {
                        queued = Some(f);
                    }
                } else {
                    enc.feed(&f, force_key.swap(false, Ordering::Relaxed))?;
                    while let Some(out) = enc.pull()? {
                        if !on_frame(out) {
                            return Ok(());
                        }
                    }
                }
            }
            EncMsg::NeedInput => {
                if let Some(f) = queued.take() {
                    enc.feed(&f, force_key.swap(false, Ordering::Relaxed))?;
                } else {
                    need_input += 1;
                }
            }
            EncMsg::HaveOutput => {
                if let Some(out) = enc.pull()?
                    && !on_frame(out)
                {
                    return Ok(());
                }
            }
            EncMsg::EventError(e) => {
                return Err(windows::core::Error::new(E_FAIL, format!("MFT event pump: {e}")));
            }
        }
    }
    Ok(())
}
