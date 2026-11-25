//! Keyboard and mouse input mapping and Win32 `SendInput` injection.

use moonrd_proto::{Display, KeyEvent, PointerButton, PointerEvent};

/// Converts a normalized display coordinate (`0..65535` on each axis of `display`) into
/// Windows `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` coordinates (`0..65535` across
/// the entire virtual desktop).
pub fn map_pointer_to_virtual_desktop(
    display: &Display,
    x: u32,
    y: u32,
    virt_left: i32,
    virt_top: i32,
    virt_width: i32,
    virt_height: i32,
) -> (i32, i32) {
    let vw = virt_width.max(1) as f64;
    let vh = virt_height.max(1) as f64;
    let px = display.x as f64 + 0.5 + (x.min(65535) as f64 / 65535.0) * display.width.saturating_sub(1) as f64;
    let py = display.y as f64 + 0.5 + (y.min(65535) as f64 / 65535.0) * display.height.saturating_sub(1) as f64;
    let nx = (((px - virt_left as f64) / vw) * 65535.0).round().clamp(0.0, 65535.0) as i32;
    let ny = (((py - virt_top as f64) / vh) * 65535.0).round().clamp(0.0, 65535.0) as i32;
    (nx, ny)
}

/// Maps a USB HID usage page 0x07 key code to a Windows Set 1 scan code and whether it
/// requires `KEYEVENTF_EXTENDEDKEY`.
pub fn hid_to_scancode(usage: u32) -> Option<(u16, bool)> {
    let (sc, ext) = match usage {
        // Letters A..Z (0x04..0x1D)
        0x04 => (0x1E, false), // A
        0x05 => (0x30, false), // B
        0x06 => (0x2E, false), // C
        0x07 => (0x20, false), // D
        0x08 => (0x12, false), // E
        0x09 => (0x21, false), // F
        0x0A => (0x22, false), // G
        0x0B => (0x23, false), // H
        0x0C => (0x17, false), // I
        0x0D => (0x24, false), // J
        0x0E => (0x25, false), // K
        0x0F => (0x26, false), // L
        0x10 => (0x32, false), // M
        0x11 => (0x31, false), // N
        0x12 => (0x18, false), // O
        0x13 => (0x19, false), // P
        0x14 => (0x10, false), // Q
        0x15 => (0x13, false), // R
        0x16 => (0x1F, false), // S
        0x17 => (0x14, false), // T
        0x18 => (0x16, false), // U
        0x19 => (0x2F, false), // V
        0x1A => (0x11, false), // W
        0x1B => (0x2D, false), // X
        0x1C => (0x15, false), // Y
        0x1D => (0x2C, false), // Z
        // Digits 1..0 (0x1E..0x27)
        0x1E => (0x02, false),
        0x1F => (0x03, false),
        0x20 => (0x04, false),
        0x21 => (0x05, false),
        0x22 => (0x06, false),
        0x23 => (0x07, false),
        0x24 => (0x08, false),
        0x25 => (0x09, false),
        0x26 => (0x0A, false),
        0x27 => (0x0B, false),
        // Control / punctuation
        0x28 => (0x1C, false), // Enter
        0x29 => (0x01, false), // Escape
        0x2A => (0x0E, false), // Backspace
        0x2B => (0x0F, false), // Tab
        0x2C => (0x39, false), // Space
        0x2D => (0x0C, false), // -
        0x2E => (0x0D, false), // =
        0x2F => (0x1A, false), // [
        0x30 => (0x1B, false), // ]
        0x31 => (0x2B, false), // \
        0x33 => (0x27, false), // ;
        0x34 => (0x28, false), // '
        0x35 => (0x29, false), // `
        0x36 => (0x33, false), // ,
        0x37 => (0x34, false), // .
        0x38 => (0x35, false), // /
        0x39 => (0x3A, false), // CapsLock
        // F1..F12
        0x3A => (0x3B, false),
        0x3B => (0x3C, false),
        0x3C => (0x3D, false),
        0x3D => (0x3E, false),
        0x3E => (0x3F, false),
        0x3F => (0x40, false),
        0x40 => (0x41, false),
        0x41 => (0x42, false),
        0x42 => (0x43, false),
        0x43 => (0x44, false),
        0x44 => (0x57, false),
        0x45 => (0x58, false),
        // Navigation
        0x46 => (0x37, true),  // PrintScreen
        0x47 => (0x46, false), // ScrollLock
        0x49 => (0x52, true),  // Insert
        0x4A => (0x47, true),  // Home
        0x4B => (0x49, true),  // PageUp
        0x4C => (0x53, true),  // Delete
        0x4D => (0x4F, true),  // End
        0x4E => (0x51, true),  // PageDown
        0x4F => (0x4D, true),  // Right
        0x50 => (0x4B, true),  // Left
        0x51 => (0x50, true),  // Down
        0x52 => (0x48, true),  // Up
        // Modifiers
        0xE0 => (0x1D, false), // Left Ctrl
        0xE1 => (0x2A, false), // Left Shift
        0xE2 => (0x38, false), // Left Alt
        0xE3 => (0x5B, true),  // Left Win
        0xE4 => (0x1D, true),  // Right Ctrl
        0xE5 => (0x36, false), // Right Shift
        0xE6 => (0x38, true),  // Right Alt
        0xE7 => (0x5C, true),  // Right Win
        _ => return None,
    };
    Some((sc, ext))
}

#[cfg(windows)]
pub fn inject_pointer(ev: &PointerEvent, display: &Display) {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    unsafe {
        let stale_display = ev.display_id != 0 && ev.display_id != display.id;
        if stale_display && (ev.pressed || ev.button == PointerButton::None as i32) { return; }
        let vl = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let vt = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        let (dx, dy) = map_pointer_to_virtual_desktop(display, ev.x, ev.y, vl, vt, vw, vh);

        // A release may arrive from the previous display while ending a drag.
        let mut flags = if stale_display { Default::default() }
            else { MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK };
        let mut mouse_data = 0u32;

        match PointerButton::try_from(ev.button).unwrap_or(PointerButton::None) {
            PointerButton::Left => flags |= if ev.pressed { MOUSEEVENTF_LEFTDOWN } else { MOUSEEVENTF_LEFTUP },
            PointerButton::Right => flags |= if ev.pressed { MOUSEEVENTF_RIGHTDOWN } else { MOUSEEVENTF_RIGHTUP },
            PointerButton::Middle => flags |= if ev.pressed { MOUSEEVENTF_MIDDLEDOWN } else { MOUSEEVENTF_MIDDLEUP },
            PointerButton::Back => {
                flags |= if ev.pressed { MOUSEEVENTF_XDOWN } else { MOUSEEVENTF_XUP };
                mouse_data = 1;
            }
            PointerButton::Forward => {
                flags |= if ev.pressed { MOUSEEVENTF_XDOWN } else { MOUSEEVENTF_XUP };
                mouse_data = 2;
            }
            PointerButton::None => {}
        }

        let mut inputs = vec![INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: mouse_data, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
        }];

        if ev.wheel_y != 0 {
            inputs.push(INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: ev.wheel_y as u32,
                        dwFlags: MOUSEEVENTF_WHEEL,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            });
        }
        if ev.wheel_x != 0 {
            inputs.push(INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: ev.wheel_x as u32,
                        dwFlags: MOUSEEVENTF_HWHEEL,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            });
        }

        let _ = SendInput(&inputs, size_of::<INPUT>() as i32);
    }
}

#[cfg(windows)]
pub fn inject_key(ev: &KeyEvent) {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    unsafe {
        if !ev.text.is_empty() {
            let mut inputs = Vec::new();
            for unit in ev.text.encode_utf16() {
                inputs.push(INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: unit,
                            dwFlags: KEYEVENTF_UNICODE,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                });
                inputs.push(INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: unit,
                            dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                });
            }
            if !inputs.is_empty() {
                let _ = SendInput(&inputs, size_of::<INPUT>() as i32);
            }
            return;
        }

        let (scan, ext) = match hid_to_scancode(ev.scancode) {
            Some(pair) => pair,
            None => (ev.scancode as u16, ev.extended),
        };
        let mut flags = KEYEVENTF_SCANCODE;
        if ext || ev.extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if !ev.pressed {
            flags |= KEYEVENTF_KEYUP;
        }
        let input = [INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 },
            },
        }];
        let _ = SendInput(&input, size_of::<INPUT>() as i32);
    }
}

#[cfg(windows)]
pub fn lock_workstation() {
    unsafe {
        let _ = windows::Win32::System::Shutdown::LockWorkStation();
    }
}

#[cfg(windows)]
pub fn block_local_input(block: bool) {
    unsafe {
        let _ = windows::Win32::UI::Input::KeyboardAndMouse::BlockInput(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_secondary_monitor_pointer_coords() {
        // Two 1920x1080 monitors side-by-side: primary at (0,0), secondary at (1920,0).
        let secondary = Display { id: 2, name: "D2".into(), x: 1920, y: 0, width: 1920, height: 1080, dpi: 96, primary: false };
        // Center of secondary monitor -> x = 75% of 65535, y = 50% of 65535.
        let (dx, dy) = map_pointer_to_virtual_desktop(&secondary, 32768, 32768, 0, 0, 3840, 1080);
        assert!((dx - 49151).abs() <= 2, "dx={dx}");
        assert!((dy - 32768).abs() <= 2, "dy={dy}");
        let primary = Display { x: 0, ..secondary };
        let (edge, _) = map_pointer_to_virtual_desktop(&primary, 65535, 0, 0, 0, 3840, 1080);
        assert!(edge < 32768, "right edge must remain on the first monitor");
    }

    #[test]
    fn hid_scancode_table_covers_common_keys() {
        assert_eq!(hid_to_scancode(0x04), Some((0x1E, false))); // A
        assert_eq!(hid_to_scancode(0x28), Some((0x1C, false))); // Enter
        assert_eq!(hid_to_scancode(0x4F), Some((0x4D, true))); // Right arrow (extended)
        assert_eq!(hid_to_scancode(0xE0), Some((0x1D, false))); // Left Ctrl
        assert_eq!(hid_to_scancode(0xE4), Some((0x1D, true))); // Right Ctrl (extended)
    }
}
