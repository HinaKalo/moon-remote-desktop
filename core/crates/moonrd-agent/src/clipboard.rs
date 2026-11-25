//! Win32 Unicode text clipboard sync with loop/echo suppression.

/// Tracks clipboard sequence numbers and last written text so remote updates do not
/// bounce back to the viewer.
#[derive(Default)]
pub struct ClipboardSync {
    last_seq: u32,
    last_written: String,
}

impl ClipboardSync {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks whether the local clipboard changed and returns the new text if it differs
    /// from the last remote text we wrote.
    #[cfg(windows)]
    pub fn poll_local(&mut self) -> Option<String> {
        let seq = unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() };
        if seq == self.last_seq {
            return None;
        }
        self.last_seq = seq;
        let text = read_text()?;
        if text == self.last_written {
            return None;
        }
        self.last_written = text.clone();
        Some(text)
    }

    /// Applies clipboard text received from the remote viewer.
    #[cfg(windows)]
    pub fn apply_remote(&mut self, text: &str) {
        if text == self.last_written {
            return;
        }
        if write_text(text) {
            self.last_written = text.to_string();
            self.last_seq = unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() };
        }
    }
}

#[cfg(windows)]
fn read_text() -> Option<String> {
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};

    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        if OpenClipboard(None).is_err() {
            return None;
        }
        let result = (|| {
            let h = GetClipboardData(CF_UNICODETEXT).ok()?;
            let hglobal = windows::Win32::Foundation::HGLOBAL(h.0);
            let ptr = GlobalLock(hglobal) as *const u16;
            if ptr.is_null() {
                return None;
            }
            let mut len = 0usize;
            // Cap at 1 MiB of UTF-16 code units.
            while len < 512 * 1024 && *ptr.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(hglobal);
            Some(s)
        })();
        let _ = CloseClipboard();
        result
    }
}

#[cfg(windows)]
fn write_text(text: &str) -> bool {
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};

    const CF_UNICODETEXT: u32 = 13;
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * 2;
    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }
        let ok = (|| {
            let _ = EmptyClipboard();
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes).ok()?;
            let ptr = GlobalLock(h) as *mut u16;
            if ptr.is_null() {
                return None;
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
            let _ = GlobalUnlock(h);
            SetClipboardData(CF_UNICODETEXT, Some(windows::Win32::Foundation::HANDLE(h.0))).ok()?;
            Some(())
        })()
        .is_some();
        let _ = CloseClipboard();
        ok
    }
}
