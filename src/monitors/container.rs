//! Container Monitor
//!
//! Detects container environments and monitors for:
//! - Container escapes
//! - Suspicious namespace changes
//! - Privileged container operations
//! - Host mount access from containers
//!
//! Supports Docker, Kubernetes, LXC, and systemd-nspawn.

use crate::config::ContainerMonitorConfig;
use crate::detection::{DetectionEvent, DetectionSource, ProcessInfo, Severity, ThreatType};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Container runtime type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    Podman,
    Kubernetes,
    LXC,
    SystemdNspawn,
    None,
}

/// Information about the current container context
#[derive(Debug, Clone)]
pub struct ContainerContext {
    pub runtime: ContainerRuntime,
    pub container_id: Option<String>,
    pub is_privileged: bool,
    pub capabilities: Vec<String>,
    pub namespaces: HashMap<String, u64>,
    pub cgroup_path: Option<String>,
}

/// Process with potential escape behavior
#[derive(Debug, Clone)]
struct EscapeCandidate {
    pid: u32,
    reason: String,
    severity: Severity,
}

pub struct ContainerMonitor {
    config: ContainerMonitorConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    context: Option<ContainerContext>,
    initial_namespaces: HashMap<String, u64>,
    suspicious_caps: HashSet<String>,
    reported_escapes: HashSet<u32>,
}

impl ContainerMonitor {
    pub fn new(config: ContainerMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        let suspicious_caps: HashSet<String> = config
            .suspicious_capabilities
            .iter()
            .cloned()
            .collect();

        Self {
            config,
            event_tx,
            context: None,
            initial_namespaces: HashMap::new(),
            suspicious_caps,
            reported_escapes: HashSet::new(),
        }
    }

    /// Run the container monitor loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Container monitor starting...");

        // Detect container context
        self.context = Some(self.detect_context()?);

        if let Some(ref ctx) = self.context {
            info!(
                runtime = ?ctx.runtime,
                container_id = ?ctx.container_id,
                is_privileged = ctx.is_privileged,
                "Container context detected"
            );

            if ctx.runtime == ContainerRuntime::None {
                info!("Not running in a container, monitoring for containers on host");
            }
        }

        // Store initial namespaces
        self.initial_namespaces = self.get_current_namespaces(1)?;

        let interval = tokio::time::Duration::from_millis(self.config.scan_interval_ms);

        info!("Container monitor running");

        loop {
            if let Err(e) = self.scan().await {
                debug!("Error in container scan: {}", e);
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Detect the current container context
    fn detect_context(&self) -> Result<ContainerContext> {
        let runtime = self.detect_runtime();
        let container_id = self.get_container_id();
        let is_privileged = self.check_privileged();
        let capabilities = self.get_capabilities(1)?;
        let namespaces = self.get_current_namespaces(1)?;
        let cgroup_path = self.get_cgroup_path();

        Ok(ContainerContext {
            runtime,
            container_id,
            is_privileged,
            capabilities,
            namespaces,
            cgroup_path,
        })
    }

    /// Detect the container runtime
    fn detect_runtime(&self) -> ContainerRuntime {
        // Check /.dockerenv
        if PathBuf::from("/.dockerenv").exists() {
            return ContainerRuntime::Docker;
        }

        // Check cgroup for container hints
        if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker") {
                return ContainerRuntime::Docker;
            }
            if cgroup.contains("containerd") {
                return ContainerRuntime::Containerd;
            }
            if cgroup.contains("podman") {
                return ContainerRuntime::Podman;
            }
            if cgroup.contains("kubepods") {
                return ContainerRuntime::Kubernetes;
            }
            if cgroup.contains("lxc") {
                return ContainerRuntime::LXC;
            }
            if cgroup.contains("machine.slice") {
                return ContainerRuntime::SystemdNspawn;
            }
        }

        // Check for Kubernetes service account
        if PathBuf::from("/var/run/secrets/kubernetes.io").exists() {
            return ContainerRuntime::Kubernetes;
        }

        ContainerRuntime::None
    }

    /// Get container ID from cgroup or environment
    fn get_container_id(&self) -> Option<String> {
        // Try cgroup first
        if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
            for line in cgroup.lines() {
                // Docker format: 0::/docker/<container_id>
                if let Some(docker_pos) = line.find("/docker/") {
                    let id_start = docker_pos + 8;
                    if line.len() > id_start {
                        let id = &line[id_start..];
                        return Some(id.chars().take(12).collect());
                    }
                }
                // Kubernetes format: kubepods/.../<container_id>
                if line.contains("kubepods") {
                    if let Some(last_slash) = line.rfind('/') {
                        let id = &line[last_slash + 1..];
                        if !id.is_empty() {
                            return Some(id.chars().take(12).collect());
                        }
                    }
                }
            }
        }

        // Try hostname (often set to container ID)
        if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
            let hostname = hostname.trim();
            if hostname.len() == 12 && hostname.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hostname.to_string());
            }
        }

        None
    }

    /// Check if running as privileged container
    fn check_privileged(&self) -> bool {
        // Check for CAP_SYS_ADMIN
        if let Ok(caps) = self.get_capabilities(1) {
            if caps.contains(&"CAP_SYS_ADMIN".to_string()) {
                // CAP_SYS_ADMIN alone isn't definitive, check more
                // Privileged containers have access to all devices
                if PathBuf::from("/dev/sda").exists() || PathBuf::from("/dev/nvme0").exists() {
                    return true;
                }
            }
        }

        // Check if we can access host /proc
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            if mounts.contains("proc /host") {
                return true;
            }
        }

        false
    }

    /// Get capabilities for a process
    fn get_capabilities(&self, pid: u32) -> Result<Vec<String>> {
        let status_path = format!("/proc/{}/status", pid);
        let status = fs::read_to_string(&status_path).context("Failed to read status")?;

        let mut capabilities = Vec::new();

        for line in status.lines() {
            if line.starts_with("CapEff:") {
                if let Some(hex) = line.split_whitespace().nth(1) {
                    capabilities = Self::decode_capabilities(hex);
                }
            }
        }

        Ok(capabilities)
    }

    /// Decode capability hex string to capability names
    fn decode_capabilities(hex: &str) -> Vec<String> {
        let cap_value = u64::from_str_radix(hex, 16).unwrap_or(0);
        let mut caps = Vec::new();

        // Map of capability bit positions to names
        let cap_names = [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        ];

        for (i, name) in cap_names.iter().enumerate() {
            if (cap_value >> i) & 1 == 1 {
                caps.push(name.to_string());
            }
        }

        caps
    }

    /// Get current namespace IDs for a process
    fn get_current_namespaces(&self, pid: u32) -> Result<HashMap<String, u64>> {
        let ns_path = format!("/proc/{}/ns", pid);
        let mut namespaces = HashMap::new();

        let ns_types = ["mnt", "pid", "net", "ipc", "uts", "user", "cgroup"];

        for ns_type in ns_types {
            let ns_link = format!("{}/{}", ns_path, ns_type);
            if let Ok(link) = fs::read_link(&ns_link) {
                let link_str = link.to_string_lossy();
                // Format: type:[inode]
                if let Some(start) = link_str.find('[') {
                    if let Some(end) = link_str.find(']') {
                        if let Ok(inode) = link_str[start + 1..end].parse::<u64>() {
                            namespaces.insert(ns_type.to_string(), inode);
                        }
                    }
                }
            }
        }

        Ok(namespaces)
    }

    /// Get cgroup path for current process
    fn get_cgroup_path(&self) -> Option<String> {
        fs::read_to_string("/proc/1/cgroup")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .next()
                    .and_then(|line| line.split(':').nth(2))
                    .map(|s| s.to_string())
            })
    }

    /// Perform a full container security scan
    async fn scan(&mut self) -> Result<()> {
        // Check for container escapes
        if self.config.detect_escapes {
            self.check_for_escapes().await?;
        }

        // Monitor namespace changes
        if self.config.monitor_namespaces {
            self.check_namespace_changes().await?;
        }

        // Monitor privileged operations
        if self.config.monitor_privileged {
            self.check_privileged_operations().await?;
        }

        // Check host mount access
        if self.config.alert_host_mount_access {
            self.check_host_mount_access().await?;
        }

        Ok(())
    }

    /// Check for container escape attempts
    async fn check_for_escapes(&mut self) -> Result<()> {
        let mut candidates: Vec<EscapeCandidate> = Vec::new();

        // Scan all processes for escape indicators
        let proc_dir = fs::read_dir("/proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                if self.reported_escapes.contains(&pid) {
                    continue;
                }

                if let Some(candidate) = self.check_process_for_escape(pid) {
                    candidates.push(candidate);
                }
            }
        }

        for candidate in candidates {
            let proc_info = self.get_process_info(candidate.pid);

            let mut event = DetectionEvent::new(
                DetectionSource::ContainerMonitor,
                ThreatType::ContainerEscape,
                candidate.severity,
                format!(
                    "Potential container escape detected: PID {} - {}",
                    candidate.pid, candidate.reason
                ),
            )
            .with_pattern(&candidate.reason);

            if let Some(info) = proc_info {
                event = event.with_process(info);
            }

            warn!(
                pid = candidate.pid,
                reason = %candidate.reason,
                "Container escape attempt detected"
            );

            self.event_tx.send(event).await.ok();
            self.reported_escapes.insert(candidate.pid);
        }

        Ok(())
    }

    /// Check a single process for escape indicators
    fn check_process_for_escape(&self, pid: u32) -> Option<EscapeCandidate> {
        // Check if process has different namespace than init
        if let Ok(proc_ns) = self.get_current_namespaces(pid) {
            for (ns_type, init_inode) in &self.initial_namespaces {
                if let Some(proc_inode) = proc_ns.get(ns_type) {
                    if proc_inode != init_inode {
                        // Namespace differs - could be escape or nested container
                        // Check if it's accessing host resources
                        if self.is_accessing_host_resources(pid) {
                            return Some(EscapeCandidate {
                                pid,
                                reason: format!(
                                    "Process in different {} namespace accessing host resources",
                                    ns_type
                                ),
                                severity: Severity::Critical,
                            });
                        }
                    }
                }
            }
        }

        // Check for suspicious capabilities
        if let Ok(caps) = self.get_capabilities(pid) {
            let suspicious: Vec<_> = caps
                .iter()
                .filter(|c| self.suspicious_caps.contains(*c))
                .collect();

            if !suspicious.is_empty() {
                // Check cmdline for suspicious activity
                if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
                    let cmdline = cmdline.replace('\0', " ");
                    let cmdline_lower = cmdline.to_lowercase();

                    // Suspicious commands with dangerous caps
                    if cmdline_lower.contains("nsenter")
                        || cmdline_lower.contains("unshare")
                        || cmdline_lower.contains("mount")
                        || cmdline_lower.contains("chroot")
                    {
                        return Some(EscapeCandidate {
                            pid,
                            reason: format!(
                                "Suspicious command with capabilities: {} (caps: {:?})",
                                cmdline.trim(),
                                suspicious
                            ),
                            severity: Severity::High,
                        });
                    }
                }
            }
        }

        None
    }

    /// Check if process is accessing host resources
    fn is_accessing_host_resources(&self, pid: u32) -> bool {
        // Check for access to /host, /hostfs, or root filesystem indicators
        if let Ok(root) = fs::read_link(format!("/proc/{}/root", pid)) {
            let root_str = root.to_string_lossy();
            if root_str == "/" {
                // Process has access to real root - check if we're in a container
                if self.context.as_ref().is_some_and(|c| c.runtime != ContainerRuntime::None) {
                    return true;
                }
            }
        }

        // Check cwd for host paths
        if let Ok(cwd) = fs::read_link(format!("/proc/{}/cwd", pid)) {
            let cwd_str = cwd.to_string_lossy();
            if cwd_str.starts_with("/host") || cwd_str.starts_with("/hostfs") {
                return true;
            }
        }

        false
    }

    /// Check for namespace changes
    async fn check_namespace_changes(&self) -> Result<()> {
        // Scan processes for unexpected namespace changes
        let proc_dir = fs::read_dir("/proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                if pid == 1 {
                    continue;
                }

                if let Ok(proc_ns) = self.get_current_namespaces(pid) {
                    // Check for processes that have escaped to host namespaces
                    for (ns_type, proc_inode) in &proc_ns {
                        if let Some(init_inode) = self.initial_namespaces.get(ns_type) {
                            if proc_inode != init_inode {
                                // Check if this is a legitimate nested container or escape
                                if let Ok(cmdline) =
                                    fs::read_to_string(format!("/proc/{}/cmdline", pid))
                                {
                                    let cmdline = cmdline.replace('\0', " ");

                                    // Skip container runtime processes
                                    if cmdline.contains("containerd")
                                        || cmdline.contains("dockerd")
                                        || cmdline.contains("runc")
                                    {
                                        continue;
                                    }

                                    debug!(
                                        pid = pid,
                                        ns_type = %ns_type,
                                        "Process in different namespace"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for privileged container operations
    async fn check_privileged_operations(&self) -> Result<()> {
        // Look for processes performing privileged operations
        let proc_dir = fs::read_dir("/proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
                    let cmdline = cmdline.replace('\0', " ").to_lowercase();

                    // Check for privileged operations
                    let suspicious_ops = [
                        ("mount", "mount operation"),
                        ("insmod", "kernel module load"),
                        ("modprobe", "kernel module load"),
                        ("kmod", "kernel module operation"),
                        ("bpftool", "eBPF manipulation"),
                        ("debugfs", "debug filesystem access"),
                    ];

                    for (pattern, desc) in suspicious_ops {
                        if cmdline.contains(pattern) {
                            let proc_info = self.get_process_info(pid);

                            let mut event = DetectionEvent::new(
                                DetectionSource::ContainerMonitor,
                                ThreatType::PrivilegedContainerOperation,
                                Severity::High,
                                format!(
                                    "Privileged operation in container: PID {} - {} ({})",
                                    pid,
                                    desc,
                                    cmdline.trim()
                                ),
                            )
                            .with_pattern(desc);

                            if let Some(info) = proc_info {
                                event = event.with_process(info);
                            }

                            debug!(
                                pid = pid,
                                operation = desc,
                                "Privileged operation detected"
                            );

                            self.event_tx.send(event).await.ok();
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for access to host mounts
    async fn check_host_mount_access(&self) -> Result<()> {
        // Check /proc/mounts for host filesystem mounts
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }

                let mount_point = parts[1];

                // Check for suspicious host mounts
                if mount_point.starts_with("/host")
                    || mount_point == "/var/run/docker.sock"
                    || mount_point.contains("docker.sock")
                {
                    // Check if any process is accessing this mount
                    let proc_dir = fs::read_dir("/proc")?;

                    for entry in proc_dir.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();

                        if let Ok(pid) = name_str.parse::<u32>() {
                            if let Ok(cwd) = fs::read_link(format!("/proc/{}/cwd", pid)) {
                                if cwd.to_string_lossy().starts_with(mount_point) {
                                    let proc_info = self.get_process_info(pid);

                                    let mut event = DetectionEvent::new(
                                        DetectionSource::ContainerMonitor,
                                        ThreatType::HostMountAccess,
                                        Severity::High,
                                        format!(
                                            "Process accessing host mount: PID {} in {}",
                                            pid, mount_point
                                        ),
                                    )
                                    .with_pattern(format!("mount={}", mount_point));

                                    if let Some(info) = proc_info {
                                        event = event.with_process(info);
                                    }

                                    warn!(
                                        pid = pid,
                                        mount_point = mount_point,
                                        "Host mount access detected"
                                    );

                                    self.event_tx.send(event).await.ok();
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get process info for a PID
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        let proc_path = PathBuf::from(format!("/proc/{}", pid));

        let cmdline = fs::read_to_string(proc_path.join("cmdline"))
            .ok()?
            .replace('\0', " ")
            .trim()
            .to_string();

        let name = fs::read_to_string(proc_path.join("comm"))
            .ok()?
            .trim()
            .to_string();

        let exe_path = fs::read_link(proc_path.join("exe")).ok();
        let cwd = fs::read_link(proc_path.join("cwd")).ok();

        let status = fs::read_to_string(proc_path.join("status")).ok()?;
        let ppid = Self::parse_status_field(&status, "PPid:").unwrap_or(0);
        let uid = Self::parse_status_field(&status, "Uid:").unwrap_or(0);

        Some(ProcessInfo {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_capabilities() {
        // 0x21 = CAP_CHOWN (0) + CAP_SYS_ADMIN (21)
        let caps = ContainerMonitor::decode_capabilities("0000000000200001");
        assert!(caps.contains(&"CAP_CHOWN".to_string()));
        assert!(caps.contains(&"CAP_SYS_ADMIN".to_string()));
    }

    #[test]
    fn test_container_runtime_detection() {
        let (tx, _rx) = mpsc::channel(100);
        let monitor = ContainerMonitor::new(ContainerMonitorConfig::default(), tx);

        // This will detect actual environment
        let runtime = monitor.detect_runtime();
        // Just verify it returns a valid value
        match runtime {
            ContainerRuntime::Docker
            | ContainerRuntime::Containerd
            | ContainerRuntime::Podman
            | ContainerRuntime::Kubernetes
            | ContainerRuntime::LXC
            | ContainerRuntime::SystemdNspawn
            | ContainerRuntime::None => {}
        }
    }

    #[test]
    fn test_namespace_parsing() {
        let (tx, _rx) = mpsc::channel(100);
        let monitor = ContainerMonitor::new(ContainerMonitorConfig::default(), tx);

        // Get namespaces for current process
        if let Ok(ns) = monitor.get_current_namespaces(std::process::id()) {
            // Should have at least some namespaces
            assert!(!ns.is_empty());
            // Should include common namespace types
            assert!(ns.contains_key("pid") || ns.contains_key("mnt"));
        }
    }
}
