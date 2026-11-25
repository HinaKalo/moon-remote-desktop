//! Launching the companion `easytier-core` (v2.7.1), as validated in the Phase 0a spike
//! (`spikes/easytier/REPORT.md` §3, §4, §7):
//!
//! * No TUN adapter on hosts or controllers: no admin rights, no wintun, nothing that can
//!   collide with the user's `et_*` adapters. The host's QUIC server listens on
//!   `127.0.0.1:<port>`; EasyTier proxies UDP sent to a no-TUN node's own virtual IP to
//!   loopback.
//! * The network settings live in a TOML file passed with `-c`; argv carries only
//!   process-level flags. That keeps the instance writable, which runtime
//!   `port-forward add/remove` requires. The file holds the device credential, so the
//!   caller must create it in a directory only the current user can read.
//! * The credential goes in `[secure_mode] local_private_key`; no network secret ever
//!   reaches the device.
//! * No listeners (`listeners = []`): we never take 11010 or any port the user's
//!   EasyTier uses. The management RPC binds a free loopback port picked here, never
//!   EasyTier's "0" (which tries 0.0.0.0:15888 first).

use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::Path;

use crate::{GUI_RPC_PORT, STOCK_RPC_PORT};

/// Instance name of every Moon Remote EasyTier instance.
pub const INSTANCE_NAME: &str = "moonrd";
/// Adapter name reserved for a future TUN mode; distinct from EasyTier's `et_N`.
pub const DEV_NAME: &str = "moonrd0";

/// What the server's `POST /v1/et/credential` returned, plus local choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionConfig {
    /// Shown to other peers; a short device id, never the PC name.
    pub hostname: String,
    pub network_name: String,
    /// Base64 X25519 private key issued by the server.
    pub credential: String,
    /// Server node addresses, e.g. `tcp://remote.moonl.cloud:21017`.
    pub peers: Vec<String>,
    /// This device's address, e.g. `10.250.17.3/24`.
    pub ipv4: String,
}

/// Escapes a TOML basic string.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl CompanionConfig {
    /// The TOML to write to the instance's config file.
    pub fn to_toml(&self) -> String {
        let mut t = String::new();
        t.push_str(&format!("instance_name = {}\n", toml_str(INSTANCE_NAME)));
        t.push_str(&format!("hostname = {}\n", toml_str(&self.hostname)));
        t.push_str(&format!("ipv4 = {}\n", toml_str(&self.ipv4)));
        t.push_str("listeners = []\n\n");
        t.push_str("[network_identity]\n");
        t.push_str(&format!("network_name = {}\n\n", toml_str(&self.network_name)));
        for p in &self.peers {
            t.push_str(&format!("[[peer]]\nuri = {}\n\n", toml_str(p)));
        }
        t.push_str("[secure_mode]\nenabled = true\n");
        t.push_str(&format!("local_private_key = {}\n\n", toml_str(&self.credential)));
        t.push_str("[flags]\n");
        t.push_str(&format!("dev_name = {}\n", toml_str(DEV_NAME)));
        t.push_str("no_tun = true\n");
        t
    }
}

/// Command line for `easytier-core` started on `config_file` with its RPC on `rpc_port`.
pub fn core_args(config_file: &Path, rpc_port: u16) -> Vec<OsString> {
    vec![
        "-c".into(),
        config_file.as_os_str().to_owned(),
        "--rpc-portal".into(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port).to_string().into(),
        "--rpc-portal-whitelist".into(),
        "127.0.0.1/32".into(),
        "--console-log-level".into(),
        "warn".into(),
    ]
}

/// `easytier-cli` arguments for a JSON command against our instance.
pub fn cli_args(rpc_port: u16, command: &[&str]) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec![
        "-p".into(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port).to_string().into(),
        "-o".into(),
        "json".into(),
    ];
    v.extend(command.iter().map(OsString::from));
    v
}

/// Controller: forward `127.0.0.1:local_port` (UDP) to the host's QUIC port.
pub fn port_forward_add(rpc_port: u16, local_port: u16, host_ip: Ipv4Addr, host_port: u16) -> Vec<OsString> {
    let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port).to_string();
    let remote = SocketAddrV4::new(host_ip, host_port).to_string();
    cli_args(rpc_port, &["port-forward", "add", "udp", &local, &remote])
}

/// Controller: remove the forward added by [`port_forward_add`].
pub fn port_forward_remove(rpc_port: u16, local_port: u16, host_ip: Ipv4Addr, host_port: u16) -> Vec<OsString> {
    let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port).to_string();
    let remote = SocketAddrV4::new(host_ip, host_port).to_string();
    cli_args(rpc_port, &["port-forward", "remove", "udp", &local, &remote])
}

/// True for the log line EasyTier prints when the server revoked or expired our
/// credential. The node then retries forever, so the supervisor must stop it and
/// fetch a new credential instead.
pub fn is_credential_rejected(log_line: &str) -> bool {
    log_line.contains("invalid proof and unknown credential")
}

/// Ports never used for our RPC: EasyTier's CLI default and the GUI service's.
const RESERVED_RPC_PORTS: [u16; 2] = [STOCK_RPC_PORT, GUI_RPC_PORT];

/// Asks the OS for a free TCP port on 127.0.0.1, skipping ports the user's EasyTier
/// tools default to.
///
/// The port is released before returning, so another process could take it before
/// easytier-core binds; the supervisor treats a bind failure as retryable.
pub fn pick_free_loopback_port() -> io::Result<u16> {
    for _ in 0..16 {
        let l = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let port = l.local_addr()?.port();
        if !RESERVED_RPC_PORTS.contains(&port) {
            return Ok(port);
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "no usable loopback port"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CompanionConfig {
        CompanionConfig {
            hostname: "d-3f9a1c2b".into(),
            network_name: "mrd-0a1b2c".into(),
            credential: "abc+/def=".into(),
            peers: vec!["tcp://remote.moonl.cloud:21017".into(), "udp://remote.moonl.cloud:21017".into()],
            ipv4: "10.250.17.3/24".into(),
        }
    }

    #[test]
    fn toml_has_the_validated_shape() {
        let t = cfg().to_toml();
        for needle in [
            "instance_name = \"moonrd\"",
            "hostname = \"d-3f9a1c2b\"",
            "ipv4 = \"10.250.17.3/24\"",
            "listeners = []",
            "[network_identity]\nnetwork_name = \"mrd-0a1b2c\"",
            "[[peer]]\nuri = \"tcp://remote.moonl.cloud:21017\"",
            "[[peer]]\nuri = \"udp://remote.moonl.cloud:21017\"",
            "[secure_mode]\nenabled = true\nlocal_private_key = \"abc+/def=\"",
            "dev_name = \"moonrd0\"",
            "no_tun = true",
        ] {
            assert!(t.contains(needle), "missing {needle:?} in\n{t}");
        }
        assert!(!t.contains("network_secret"), "devices never get the network secret");
    }

    #[test]
    fn toml_strings_are_escaped() {
        let mut c = cfg();
        c.hostname = "a\"b\\c\nd\u{1}".into();
        assert!(c.to_toml().contains(r#"hostname = "a\"b\\c\nd\u0001""#));
    }

    #[test]
    fn argv_has_only_process_flags() {
        let args: Vec<String> = core_args(std::path::Path::new(r"C:\Users\a\AppData\Local\MoonRemote\et\moonrd.toml"), 49731)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "-c",
                r"C:\Users\a\AppData\Local\MoonRemote\et\moonrd.toml",
                "--rpc-portal",
                "127.0.0.1:49731",
                "--rpc-portal-whitelist",
                "127.0.0.1/32",
                "--console-log-level",
                "warn"
            ]
        );
        // A network option on argv would make the instance read-only (no runtime port-forward).
        for forbidden in ["--network-name", "--network-secret", "--secure-mode", "--credential", "--no-tun"] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn port_forward_commands() {
        let s = |v: Vec<OsString>| v.into_iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ");
        assert_eq!(
            s(port_forward_add(49731, 47001, Ipv4Addr::new(10, 250, 17, 2), 47000)),
            "-p 127.0.0.1:49731 -o json port-forward add udp 127.0.0.1:47001 10.250.17.2:47000"
        );
        assert_eq!(
            s(port_forward_remove(49731, 47001, Ipv4Addr::new(10, 250, 17, 2), 47000)),
            "-p 127.0.0.1:49731 -o json port-forward remove udp 127.0.0.1:47001 10.250.17.2:47000"
        );
    }

    #[test]
    fn rejected_credential_is_recognised() {
        assert!(is_credential_rejected("2026-11-20 ERROR authentication failed: invalid proof and unknown credential"));
        assert!(!is_credential_rejected("peer connected"));
    }

    #[test]
    fn free_port_skips_reserved_and_is_bindable() {
        let port = pick_free_loopback_port().unwrap();
        assert!(!RESERVED_RPC_PORTS.contains(&port) && port != 0);
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).expect("still free");
    }
}
