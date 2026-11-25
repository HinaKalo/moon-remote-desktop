use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};

use crate::{GUI_RPC_PORT, STOCK_LISTENER_PORT, STOCK_LISTENER_PORT_ALT, STOCK_RPC_PORT};

/// Executable names of EasyTier front ends a user may have installed.
pub const KNOWN_PROCESS_NAMES: &[&str] =
    &["easytier-core.exe", "easytier-gui.exe", "easytier-mini.exe", "easytier-web.exe", "easytier-web-embed.exe"];

/// What we could observe about an EasyTier install that is not ours.
///
/// Moon Remote never stops, reconfigures or connects to this instance. In particular it
/// never calls `node` on a foreign RPC port: that output contains the user's network
/// secret. The result is shown on the diagnostics page. Services, adapters (`et_N`)
/// and footprints are further signals the host service can add with Windows APIs; see
/// `spikes/easytier/detect-existing.ps1`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalEasyTier {
    /// Running processes matching [`KNOWN_PROCESS_NAMES`], with their PIDs.
    pub processes: Vec<(String, u32)>,
    /// Something already holds 15888 (stock management port) or 15999 (GUI service).
    pub stock_rpc_port_busy: bool,
    /// Something already holds 11010/11011 (stock peer listeners), TCP or UDP.
    pub stock_listener_port_busy: bool,
}

impl ExternalEasyTier {
    pub fn found(&self) -> bool {
        !self.processes.is_empty() || self.stock_rpc_port_busy || self.stock_listener_port_busy
    }
}

/// Looks for a user-installed EasyTier. Never fails: anything it cannot check is
/// reported as "not seen".
///
/// Our own companion processes are excluded by PID via `own_pids`.
pub fn detect(own_pids: &[u32]) -> ExternalEasyTier {
    let processes = list_processes()
        .into_iter()
        .filter(|(name, pid)| {
            KNOWN_PROCESS_NAMES.iter().any(|k| k.eq_ignore_ascii_case(name)) && !own_pids.contains(pid)
        })
        .collect();
    ExternalEasyTier {
        processes,
        stock_rpc_port_busy: tcp_port_busy(STOCK_RPC_PORT) || tcp_port_busy(GUI_RPC_PORT),
        stock_listener_port_busy: [STOCK_LISTENER_PORT, STOCK_LISTENER_PORT_ALT]
            .iter()
            .any(|&p| tcp_port_busy(p) || udp_port_busy(p)),
    }
}

fn tcp_port_busy(port: u16) -> bool {
    // Binding the wildcard address fails if anyone holds the port on any interface.
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).is_err()
}

fn udp_port_busy(port: u16) -> bool {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).is_err()
}

#[cfg(windows)]
fn list_processes() -> Vec<(String, u32)> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) if out.status.success() => parse_tasklist_csv(&String::from_utf8_lossy(&out.stdout)),
        _ => Vec::new(),
    }
}

#[cfg(not(windows))]
fn list_processes() -> Vec<(String, u32)> {
    // Windows-only product; nothing to list elsewhere.
    Vec::new()
}

/// Parses `tasklist /FO CSV /NH` output into `(image name, pid)` pairs.
///
/// Each line looks like `"easytier-core.exe","4242","Services","0","12,345 K"`; fields
/// are quoted and the memory column may contain commas, so only the first two quoted
/// fields are read.
pub fn parse_tasklist_csv(text: &str) -> Vec<(String, u32)> {
    text.lines()
        .filter_map(|line| {
            let mut fields = quoted_fields(line);
            let name = fields.next()?;
            let pid = fields.next()?.parse().ok()?;
            Some((name, pid))
        })
        .collect()
}

fn quoted_fields(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split("\",\"").map(|f| f.trim().trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\r\n\
\"easytier-core.exe\",\"4242\",\"Services\",\"0\",\"12,345 K\"\r\n\
\"EasyTier-GUI.exe\",\"5150\",\"Console\",\"1\",\"80,120 K\"\r\n\
\"explorer.exe\",\"7000\",\"Console\",\"1\",\"150,000 K\"\r\n\
garbage line\r\n";

    #[test]
    fn parses_names_and_pids() {
        let parsed = parse_tasklist_csv(SAMPLE);
        assert_eq!(parsed[1], ("easytier-core.exe".to_string(), 4242));
        assert_eq!(parsed[2], ("EasyTier-GUI.exe".to_string(), 5150));
        assert_eq!(parsed.len(), 4, "malformed lines are skipped");
    }

    #[test]
    fn matching_is_case_insensitive() {
        let names: Vec<_> = parse_tasklist_csv(SAMPLE)
            .into_iter()
            .filter(|(n, _)| KNOWN_PROCESS_NAMES.iter().any(|k| k.eq_ignore_ascii_case(n)))
            .map(|(_, pid)| pid)
            .collect();
        assert_eq!(names, [4242, 5150]);
    }

    #[test]
    fn busy_port_is_detected() {
        let held = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        assert!(tcp_port_busy(port));
        drop(held);
        assert!(!tcp_port_busy(port));
    }

    #[test]
    fn empty_result_reports_nothing_found() {
        assert!(!ExternalEasyTier::default().found());
    }
}
