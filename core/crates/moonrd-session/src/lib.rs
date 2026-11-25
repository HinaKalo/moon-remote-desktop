//! Transport-independent session layer of Moon Remote.
//!
//! * [`frame`]: length-delimited `Envelope` framing for reliable streams.
//! * [`pin`]: PIN rules and the host's stored PIN verifier (Argon2id).
//! * [`pake`]: SPAKE2 authentication tied to the transport channel, with key confirmation.
//! * [`lockout`]: host-side limit on PIN guessing.
//! * [`pairing`]: "remember this controller" keys.
//! * [`handshake`]: host and viewer handshake state machines (sans-IO).

pub mod frame;
pub mod handshake;
pub mod lockout;
pub mod pairing;
pub mod pake;
pub mod pin;
pub mod release;

pub use moonrd_proto as proto;
