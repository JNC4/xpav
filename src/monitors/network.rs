//! Scans /proc/net/tcp for connections to mining pools and C2 servers.

use crate::config::{NetworkMonitorConfig, ResponseAction};
use crate::detection::{
    ConnectionInfo, DetectionEvent, DetectionSource, ProcessInfo, Severity, ThreatType,
};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct NetworkMonitor {
    config: NetworkMonitorConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    blocked_domains_lower: HashSet<String>,
    blocked_ips: HashSet<IpAddr>,
    reported_connections: HashSet<(u32, String, u16)>,
    scan_count: u32,
}

impl NetworkMonitor {
    pub fn new(config: NetworkMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        let blocked_domains_lower: HashSet<String> = config
            .blocked_domains
            .iter()
            .map(|d| d.to_lowercase())
            .collect();

        let blocked_ips: HashSet<IpAddr> = config
            .blocked_ips
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();

        Self {
            config,
            event_tx,
            blocked_domains_lower,
            blocked_ips,
            reported_connections: HashSet::new(),
            scan_count: 0,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Network monitor started");

        let interval = tokio::time::Duration::from_millis(self.config.scan_interval_ms);

        loop {
            if let Err(e) = self.scan_connections().await {
                error!("Error scanning connections: {}", e);
            }

            self.scan_count += 1;
            if self.scan_count >= 60 {
                self.reported_connections.clear();
                self.scan_count = 0;
            }

            tokio::time::sleep(interval).await;
        }
    }

    async fn scan_connections(&mut self) -> Result<()> {
        let tcp_content =
            fs::read_to_string("/proc/net/tcp").context("Failed to read /proc/net/tcp")?;

        for line in tcp_content.lines().skip(1) {
            if let Some(conn) = parse_tcp_line(line) {
                if conn.state == "ESTABLISHED" && conn.remote_addr != "0.0.0.0" {
                    self.check_connection(&conn).await;
                }
            }
        }

        if let Ok(tcp6_content) = fs::read_to_string("/proc/net/tcp6") {
            for line in tcp6_content.lines().skip(1) {
                if let Some(conn) = parse_tcp6_line(line) {
                    if conn.state == "ESTABLISHED" && conn.remote_addr != "::" {
                        self.check_connection(&conn).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_connection(&mut self, conn: &ConnectionInfo) {
        let conn_key = (
            conn.pid.unwrap_or(0),
            conn.remote_addr.clone(),
            conn.remote_port,
        );
        if self.reported_connections.contains(&conn_key) {
            return;
        }

        let is_mining_port = matches!(conn.remote_port,
            3333 | 4444 | 5555 | 7777 | 8888 | 9999 | // Common mining ports
            14433 | 14444 | 45560 | 45700 // SSL mining ports
        );

        let remote_ip: Option<IpAddr> = conn.remote_addr.parse().ok();
        let is_blocked_ip = remote_ip.is_some_and(|ip| self.blocked_ips.contains(&ip));

        // Can't reverse-DNS IPs, so check if cmdline mentions a blocked domain
        let proc_info = conn.pid.and_then(|pid| get_process_info(pid).ok());
        let cmdline_lower = proc_info
            .as_ref()
            .map(|p| p.cmdline.to_lowercase())
            .unwrap_or_default();

        let matched_domain = self.blocked_domains_lower.iter().find(|domain| {
            cmdline_lower.contains(domain.as_str())
        });

        if let Some(domain) = matched_domain {
            self.report_detection(
                ThreatType::MiningPoolConnection,
                Severity::Critical,
                format!(
                    "Connection to mining pool: {} ({}:{}) from PID {:?}",
                    domain, conn.remote_addr, conn.remote_port, conn.pid
                ),
                domain,
                conn,
                proc_info.as_ref(),
            )
            .await;
            self.reported_connections.insert(conn_key);
        } else if is_blocked_ip {
            self.report_detection(
                ThreatType::C2Connection,
                Severity::High,
                format!(
                    "Connection to blocked IP: {}:{} from PID {:?}",
                    conn.remote_addr, conn.remote_port, conn.pid
                ),
                &conn.remote_addr,
                conn,
                proc_info.as_ref(),
            )
            .await;
            self.reported_connections.insert(conn_key);
        } else if is_mining_port {
            debug!(
                "Connection to potential mining port: {}:{} from PID {:?}",
                conn.remote_addr, conn.remote_port, conn.pid
            );
        }
    }

    async fn report_detection(
        &self,
        threat_type: ThreatType,
        severity: Severity,
        description: String,
        pattern: &str,
        conn: &ConnectionInfo,
        proc: Option<&ProcessInfo>,
    ) {
        let mut event = DetectionEvent::new(
            DetectionSource::NetworkMonitor,
            threat_type,
            severity,
            description,
        )
        .with_pattern(pattern)
        .with_connection(conn.clone());

        if let Some(p) = proc {
            event = event.with_process(p.clone());
        }

        warn!(
            remote_addr = %conn.remote_addr,
            remote_port = conn.remote_port,
            pid = ?conn.pid,
            pattern = %pattern,
            severity = ?severity,
            "Detection: {}", event.description
        );

        if self.config.action == ResponseAction::Kill {
            if let Some(pid) = conn.pid {
                self.kill_process(pid);
            }
        }

        if let Err(e) = self.event_tx.send(event).await {
            error!("Failed to send detection event: {}", e);
        }
    }

    fn kill_process(&self, pid: u32) {
        info!(pid = pid, "Killing process with suspicious connection");
        if let Err(e) = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            error!(pid = pid, "Failed to kill process: {}", e);
        }
    }
}

fn parse_tcp_line(line: &str) -> Option<ConnectionInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parse_addr_port(parts[1])?;
    let remote = parse_addr_port(parts[2])?;
    let state = parse_tcp_state(parts[3]);

    let inode: u64 = parts[9].parse().ok()?;
    let pid = find_pid_by_inode(inode);

    Some(ConnectionInfo {
        local_addr: local.0,
        local_port: local.1,
        remote_addr: remote.0,
        remote_port: remote.1,
        state,
        pid,
        process_name: pid.and_then(|p| get_process_name(p)),
    })
}

fn parse_tcp6_line(line: &str) -> Option<ConnectionInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parse_addr6_port(parts[1])?;
    let remote = parse_addr6_port(parts[2])?;
    let state = parse_tcp_state(parts[3]);

    let inode: u64 = parts[9].parse().ok()?;
    let pid = find_pid_by_inode(inode);

    Some(ConnectionInfo {
        local_addr: local.0,
        local_port: local.1,
        remote_addr: remote.0,
        remote_port: remote.1,
        state,
        pid,
        process_name: pid.and_then(|p| get_process_name(p)),
    })
}

fn parse_addr_port(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr_hex = parts[0];
    let port_hex = parts[1];

    let addr_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let addr = Ipv4Addr::from(addr_u32.swap_bytes());

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    Some((addr.to_string(), port))
}

fn parse_addr6_port(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr_hex = parts[0];
    let port_hex = parts[1];

    if addr_hex.len() != 32 {
        return None;
    }

    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
    }

    // /proc/net/tcp6 groups bytes in 4-byte chunks, each chunk little-endian
    for chunk in bytes.chunks_exact_mut(4) {
        chunk.reverse();
    }

    let addr = std::net::Ipv6Addr::from(bytes);
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if let Some(ipv4) = addr.to_ipv4_mapped() {
        Some((ipv4.to_string(), port))
    } else {
        Some((addr.to_string(), port))
    }
}

fn parse_tcp_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
    .to_string()
}

fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let proc_dir = fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if let Ok(pid) = name_str.parse::<u32>() {
            let fd_path = format!("/proc/{}/fd", pid);
            if let Ok(fds) = fs::read_dir(&fd_path) {
                for fd in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.contains(&format!("socket:[{}]", inode)) {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

fn get_process_name(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{}/comm", pid);
    fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn get_process_info(pid: u32) -> Result<ProcessInfo> {
    let proc_path = PathBuf::from(format!("/proc/{}", pid));

    let cmdline = fs::read_to_string(proc_path.join("cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string();

    let name = fs::read_to_string(proc_path.join("comm"))
        .unwrap_or_default()
        .trim()
        .to_string();

    let exe_path = fs::read_link(proc_path.join("exe")).ok();
    let cwd = fs::read_link(proc_path.join("cwd")).ok();

    let status = fs::read_to_string(proc_path.join("status")).unwrap_or_default();
    let ppid = parse_status_field(&status, "PPid:").unwrap_or(0);
    let uid = parse_status_field(&status, "Uid:").unwrap_or(0);

    Ok(ProcessInfo {
        pid,
        ppid,
        name,
        cmdline,
        exe_path,
        cwd,
        uid,
        username: None,
        start_time: None,
        ancestors: Vec::new(),
    })
}

fn parse_status_field(status: &str, field: &str) -> Option<u32> {
    for line in status.lines() {
        if line.starts_with(field) {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_addr_port() {
        // 127.0.0.1:53 in hex (little-endian)
        let result = parse_addr_port("0100007F:0035");
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_tcp_state() {
        assert_eq!(parse_tcp_state("01"), "ESTABLISHED");
        assert_eq!(parse_tcp_state("0A"), "LISTEN");
    }
}
