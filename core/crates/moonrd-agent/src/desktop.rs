//! Follows active Windows input desktop switches (Default ↔ Winlogon / UAC secure desktop).

use std::ffi::c_void;

use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_ACCESS_FLAGS, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop, UOI_NAME,
};

/// Result of attempting to attach the current thread to the active input desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopState {
    pub name: String,
    pub secure: bool,
}

/// Opens the currently active input desktop, attaches the calling thread to it, and
/// returns its name and whether it is a secure desktop (`Winlogon`).
pub fn sync_input_desktop() -> Option<DesktopState> {
    unsafe {
        let access = DESKTOP_ACCESS_FLAGS(0x01FF); // DESKTOP_ALL_ACCESS
        let hdesk = OpenInputDesktop(Default::default(), false, access).ok()?;
        let mut name_buf = [0u16; 128];
        let mut needed = 0u32;
        let _ = GetUserObjectInformationW(
            windows::Win32::Foundation::HANDLE(hdesk.0),
            UOI_NAME,
            Some(name_buf.as_mut_ptr() as *mut c_void),
            (name_buf.len() * 2) as u32,
            Some(&mut needed),
        );
        let len = name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len());
        let name = String::from_utf16_lossy(&name_buf[..len]);
        let _ = SetThreadDesktop(hdesk);
        let _ = CloseDesktop(hdesk);
        let secure = name.eq_ignore_ascii_case("Winlogon") || name.eq_ignore_ascii_case("Screen-saver");
        Some(DesktopState { name, secure })
    }
}
