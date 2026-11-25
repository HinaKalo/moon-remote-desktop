//! No-op replacement for Npcap's `Packet.dll` (see `spikes/easytier/REPORT.md` §5).
//!
//! easytier-core and easytier-cli v2.7.1 hard-import these 11 functions for the
//! experimental `faketcp` tunnel only. Npcap's DLL may not be redistributed without an
//! OEM licence, so we ship this instead: every call fails, which disables faketcp and
//! nothing else. Contains no Npcap code.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

#[unsafe(no_mangle)]
pub extern "C" fn PacketOpenAdapter(_name: *const c_char) -> *mut c_void {
    null_mut()
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketCloseAdapter(_a: *mut c_void) {}
#[unsafe(no_mangle)]
pub extern "C" fn PacketSetHwFilter(_a: *mut c_void, _f: u32) -> u8 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketSetBuff(_a: *mut c_void, _d: i32) -> u8 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketSetMinToCopy(_a: *mut c_void, _n: i32) -> u8 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketAllocatePacket() -> *mut c_void {
    null_mut()
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketInitPacket(_p: *mut c_void, _b: *mut c_void, _l: u32) {}
#[unsafe(no_mangle)]
pub extern "C" fn PacketFreePacket(_p: *mut c_void) {}
#[unsafe(no_mangle)]
pub extern "C" fn PacketReceivePacket(_a: *mut c_void, _p: *mut c_void, _s: u8) -> u8 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketSendPacket(_a: *mut c_void, _p: *mut c_void, _s: u8) -> u8 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PacketGetAdapterNames(_b: *mut c_char, _l: *mut u32) -> u8 {
    0
}
