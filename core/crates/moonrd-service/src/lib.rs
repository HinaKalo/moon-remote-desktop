//! Moon Remote host service (Windows, LocalSystem).
//!
//! The service owns the network side and every secret: device key and token, PIN
//! verifier, lockout state and pairings never leave it. A per-session agent process
//! (started by [`agent`]) does capture, encoding and input on the user's desktop and
//! talks to the service over a local pipe only SYSTEM can open. When the session
//! switches (logon screen ↔ desktop, fast user switching) only the agent restarts; the
//! viewer's connection stays up.
//!
//! * [`state`]: persistent host state (encrypted, atomic writes).
//! * [`pipe`]: JSON API for the desktop UI over `\.\pipe\moonrd-service`.
//! * [`agent`]: keeps one agent running in the active console session.
//! * [`agent_pipe`]: SYSTEM-only pipe protocol between the service and the in-session agent.
//! * [`server_api`], [`et`], [`signal`], [`quic_host`], [`network`]: server API client,
//!   EasyTier companion supervision, signalling WebSocket, and loopback QUIC host.
//! * `win` (Windows): DPAPI, ACLs, pipe-client checks, session spawn, Ctrl+Alt+Del.

mod web_host;
pub mod agent;
pub mod agent_pipe;
pub mod et;
pub mod network;
pub mod pipe;
pub mod quic_host;
pub mod roster;
pub mod runtime;
pub mod server_api;
pub mod signal;
pub mod state;
#[cfg(windows)]
pub mod win;
