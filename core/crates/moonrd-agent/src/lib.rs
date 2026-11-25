//! Moon Remote in-session host agent.
//!
//! Started by `moonrd-service` as LocalSystem inside the active console session, this
//! process connects back to the service over the SYSTEM-only named pipe
//! `\\.\pipe\moonrd-agent` and handles everything that must run inside a desktop session:
//!
//! * [`desktop`]: switching the thread desktop to follow UAC / lock / logon screens.
//! * [`input`]: HID-to-scancode translation, virtual-desktop pointer mapping, `SendInput`.
//! * [`clipboard`]: Unicode clipboard read/write with echo suppression.

pub mod clipboard;
#[cfg(windows)]
pub mod desktop;
pub mod input;
