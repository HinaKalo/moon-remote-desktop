//! Companion-process support for the bundled `easytier-core` (pinned v2.7.1).
//!
//! Moon Remote runs its own EasyTier instance next to whatever EasyTier the user may
//! already have installed:
//!
//! * [`config`] builds the instance's TOML and command line: own instance name, no TUN,
//!   no listeners, management RPC on a free loopback port, the server-issued device
//!   credential (never the network secret), plus the `easytier-cli` calls for runtime
//!   port forwards.
//! * [`detect()`] looks for a user-installed EasyTier so the UI can report it and the
//!   server can avoid handing out an overlapping virtual subnet. It never talks to the
//!   user's instance in a way that could reveal its secrets.
//!
//! Background: `spikes/easytier/REPORT.md`.

pub mod config;
mod detect;

pub use detect::{detect, parse_tasklist_csv, ExternalEasyTier, KNOWN_PROCESS_NAMES};

/// Management RPC port of a stock easytier-core / easytier-cli.
pub const STOCK_RPC_PORT: u16 = 15888;
/// Management RPC port of the easytier-gui background service.
pub const GUI_RPC_PORT: u16 = 15999;
/// Default peer listener port (TCP and UDP); 11011 is the default for ws/wg listeners.
pub const STOCK_LISTENER_PORT: u16 = 11010;
pub const STOCK_LISTENER_PORT_ALT: u16 = 11011;

/// EasyTier version this build is tested with.
pub const PINNED_VERSION: &str = "2.7.1";
