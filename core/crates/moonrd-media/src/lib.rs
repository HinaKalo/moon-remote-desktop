//! Windows screen capture, hardware H.264 encoding/decoding, and D3D11 rendering.
//!
//! Ported from the validated Phase 0b spike (`spikes/media/REPORT.md`):
//! * [`gpu`]: D3D11 device, display enumeration, and fixed-function `ID3D11VideoProcessor`
//!   (BGRA ↔ NV12 conversion + scaling on the GPU, zero CPU copies).
//! * [`capture`]: DXGI Desktop Duplication with non-blocking `AcquireNextFrame(0)` and
//!   `ACCESS_LOST` recovery (mode changes, UAC / secure desktop switches).
//! * [`encoder`]: Media Foundation H.264 hardware MFT (NVENC/QSV/AMF) with software MFT
//!   fallback, low-latency CBR, and on-demand IDR keyframes.
//! * [`decoder`]: Media Foundation D3D11 (DXVA) H.264 decoder with low-latency AUD
//!   handling and a D3D11 flip-model swapchain presenter for any `HWND`.

#[cfg(windows)]
pub mod capture;
#[cfg(windows)]
pub mod decoder;
#[cfg(windows)]
pub mod encoder;
#[cfg(windows)]
pub mod gpu;

use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[cfg(windows)]
    #[error("Win32/COM error: {0}")]
    Win(#[from] windows::core::Error),
    #[error("{0}")]
    Other(String),
}

/// One encoded H.264 Annex B access unit.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub sequence: u64,
    pub capture_time_us: u64,
    pub keyframe: bool,
    pub data: Arc<[u8]>,
}

/// True if the Annex B buffer contains a NAL unit of the given type (e.g. 5=IDR, 7=SPS).
pub fn has_nal(b: &[u8], ty: u8) -> bool {
    let mut i = 0;
    while i + 3 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            if b[i + 3] & 0x1f == ty {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// Ensures COM (MTA) and Media Foundation are started for the current process.
#[cfg(windows)]
pub fn init_media_foundation() -> Result<(), MediaError> {
    use std::sync::OnceLock;
    use windows::Win32::Media::MediaFoundation::{MFSTARTUP_NOSOCKET, MFStartup, MF_VERSION};
    use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};

    struct Apartment(bool);
    impl Drop for Apartment {
        fn drop(&mut self) {
            if self.0 { unsafe { CoUninitialize() }; }
        }
    }
    // COM is per thread; the Media Foundation startup is per process. An existing
    // STA belongs to its caller and does not need a matching CoUninitialize here.
    thread_local! { static COM: Apartment = Apartment(unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok()); }
    COM.with(|_| {});
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    match INIT.get_or_init(|| unsafe {
        MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET).map_err(|e| e.to_string())
    }) {
        Ok(()) => Ok(()),
        Err(e) => Err(MediaError::Other(e.clone())),
    }
}

#[cfg(windows)]
pub(crate) fn qpc() -> i64 {
    use windows::Win32::System::Performance::QueryPerformanceCounter;
    let mut v = 0i64;
    unsafe {
        let _ = QueryPerformanceCounter(&mut v);
    }
    v
}

#[cfg(windows)]
pub(crate) fn qpc_freq() -> i64 {
    use std::sync::OnceLock;
    use windows::Win32::System::Performance::QueryPerformanceFrequency;
    static F: OnceLock<i64> = OnceLock::new();
    *F.get_or_init(|| {
        let mut f = 0i64;
        unsafe {
            let _ = QueryPerformanceFrequency(&mut f);
        }
        f.max(1)
    })
}

#[cfg(windows)]
pub(crate) fn qpc_to_us(ticks: i64) -> u64 {
    ((ticks.max(0) as i128) * 1_000_000 / qpc_freq() as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_annex_b_nal_types() {
        let sps = [0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f];
        assert!(has_nal(&sps, 7));
        assert!(!has_nal(&sps, 5));
        let idr = [0, 0, 1, 0x65, 0x88];
        assert!(has_nal(&idr, 5));
    }
}
