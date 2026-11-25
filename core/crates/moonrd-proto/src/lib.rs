//! Generated types for the Moon Remote session protocol (`proto/moonrd.proto`).

#![allow(clippy::doc_lazy_continuation, clippy::large_enum_variant)]

/// Protocol version carried in `Hello` / `HelloAck`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Package `moonrd.v1`.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/moonrd.v1.rs"));
}

pub use v1::*;
