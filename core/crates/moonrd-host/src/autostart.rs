//! Manages per-user Windows auto-start (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).

use std::io;
use std::path::Path;

pub const RUN_VALUE_NAME: &str = "MoonRemoteHostPlugin";

pub fn autostart_command(exe: &Path) -> String {
    format!("\"{}\" --background", exe.display())
}

#[cfg(windows)]
pub fn set_enabled(exe: &Path, enabled: bool) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW,
    };
    use windows::core::w;

    fn wide_nul(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    unsafe {
        let mut hkey = HKEY::default();
        let subkey = w!(r"Software\Microsoft\Windows\CurrentVersion\Run");
        let r = RegOpenKeyExW(HKEY_CURRENT_USER, subkey, Some(0), KEY_SET_VALUE, &mut hkey);
        if r.is_err() {
            return Err(io::Error::from_raw_os_error(r.0 as i32));
        }
        let name = wide_nul(RUN_VALUE_NAME);
        let res = if enabled {
            let cmd = wide_nul(&autostart_command(exe));
            let bytes = std::slice::from_raw_parts(cmd.as_ptr() as *const u8, cmd.len() * 2);
            RegSetValueExW(hkey, windows::core::PCWSTR(name.as_ptr()), Some(0), REG_SZ, Some(bytes))
        } else {
            RegDeleteValueW(hkey, windows::core::PCWSTR(name.as_ptr()))
        };
        let _ = RegCloseKey(hkey);
        if res.is_err() && enabled {
            return Err(io::Error::from_raw_os_error(res.0 as i32));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub fn is_enabled() -> bool {
    use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW};
    use windows::core::w;

    unsafe {
        let mut hkey = HKEY::default();
        let subkey = w!(r"Software\Microsoft\Windows\CurrentVersion\Run");
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey, Some(0), KEY_QUERY_VALUE, &mut hkey).is_err() {
            return false;
        }
        let mut size = 0u32;
        let ok = RegQueryValueExW(hkey, w!("MoonRemoteHostPlugin"), None, None, None, Some(&mut size)).is_ok();
        let _ = RegCloseKey(hkey);
        ok
    }
}

#[cfg(not(windows))]
pub fn set_enabled(_exe: &Path, _enabled: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn is_enabled() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_quoted_autostart_command() {
        let cmd = autostart_command(Path::new(r"C:\Program Files\MoonRemoteHost\moonrd-host.exe"));
        assert_eq!(cmd, r#""C:\Program Files\MoonRemoteHost\moonrd-host.exe" --background"#);
    }
}
