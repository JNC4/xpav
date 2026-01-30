//! eBPF Monitor
//!
//! Monitors for malicious eBPF program usage including:
//! - Periodic auditing of loaded eBPF programs via bpftool
//! - Detection of suspicious kprobe attachments (getdents, sys_bpf hiding)
//! - XDP/TC attachment monitoring on network interfaces
//! - Baseline comparison for unexpected program loads
//!
//! Requires root and bpftool to be installed.

use crate::config::EbpfMonitorConfig;
use crate::detection::{DetectionEvent, DetectionSource, Severity, ThreatType};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Information about a loaded eBPF program
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfProgram {
    pub id: u32,
    pub prog_type: String,
    pub name: String,
    pub tag: String,
    #[serde(default)]
    pub loaded_at: Option<String>,
    #[serde(default)]
    pub pinned: Vec<String>,
}

/// Information about XDP attachment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XdpAttachment {
    pub interface: String,
    pub prog_id: u32,
    pub mode: String,
}

/// Information about TC attachment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcAttachment {
    pub interface: String,
    pub direction: String, // ingress or egress
    pub prog_id: u32,
}

/// Baseline of expected eBPF programs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfBaseline {
    pub programs: HashMap<String, EbpfProgram>, // keyed by tag
    pub allowed_xdp_interfaces: HashSet<String>,
    pub allowed_tc_interfaces: HashSet<String>,
    pub allowed_kprobe_functions: HashSet<String>,
}

pub struct EbpfMonitor {
    config: EbpfMonitorConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    baseline: Option<EbpfBaseline>,
    known_program_tags: HashSet<String>,
    sensitive_functions: HashSet<String>,
    /// H1 Fix: Cached bpftool path and hash for integrity verification
    bpftool_path: Option<PathBuf>,
    bpftool_hash: Option<String>,
    /// H1 Fix: Use native enumeration if bpftool unavailable
    use_native_fallback: bool,
}

impl EbpfMonitor {
    pub fn new(config: EbpfMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        let sensitive_functions: HashSet<String> = config
            .sensitive_kprobe_functions
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        // H1 Fix: Find and cache bpftool path with hash verification
        let (bpftool_path, bpftool_hash) = Self::find_and_hash_bpftool();
        let use_native_fallback = bpftool_path.is_none();

        if use_native_fallback {
            info!("bpftool not found, using native fallback enumeration");
        }

        Self {
            config,
            event_tx,
            baseline: None,
            known_program_tags: HashSet::new(),
            sensitive_functions,
            bpftool_path,
            bpftool_hash,
            use_native_fallback,
        }
    }

    /// H1 Fix: Find bpftool and compute its hash for integrity verification.
    fn find_and_hash_bpftool() -> (Option<PathBuf>, Option<String>) {
        let paths = [
            "/usr/sbin/bpftool",
            "/sbin/bpftool",
            "/usr/bin/bpftool",
            "/bin/bpftool",
            "/usr/local/sbin/bpftool",
        ];

        for path_str in paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                // Compute SHA256 hash for integrity verification
                if let Ok(content) = fs::read(&path) {
                    let hash = format!("{:x}", Sha256::digest(&content));
                    return (Some(path), Some(hash));
                }
                return (Some(path), None);
            }
        }

        (None, None)
    }

    /// H1 Fix: Verify bpftool integrity before use.
    fn verify_bpftool(&self) -> bool {
        if let (Some(path), Some(expected_hash)) = (&self.bpftool_path, &self.bpftool_hash) {
            if let Ok(content) = fs::read(path) {
                let actual_hash = format!("{:x}", Sha256::digest(&content));
                if &actual_hash != expected_hash {
                    warn!(
                        "bpftool integrity check failed! Expected {}, got {}",
                        expected_hash, actual_hash
                    );
                    return false;
                }
            }
        }
        true
    }

    /// H1 Fix: Native eBPF program enumeration via /sys/fs/bpf and /proc.
    fn get_loaded_programs_native(&self) -> Result<Vec<EbpfProgram>> {
        let mut programs = Vec::new();

        // Parse /proc/*/fdinfo/* for BPF file descriptors
        let proc_dir = fs::read_dir("/proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                let fdinfo_path = format!("/proc/{}/fdinfo", pid);
                if let Ok(fdinfo_dir) = fs::read_dir(&fdinfo_path) {
                    for fd_entry in fdinfo_dir.flatten() {
                        if let Ok(content) = fs::read_to_string(fd_entry.path()) {
                            // Look for BPF program file descriptors
                            if content.contains("prog_type:") {
                                if let Some(prog) = Self::parse_bpf_fdinfo(&content, pid) {
                                    programs.push(prog);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also enumerate pinned BPF objects in /sys/fs/bpf
        if let Ok(bpf_fs) = fs::read_dir("/sys/fs/bpf") {
            for entry in bpf_fs.flatten() {
                let path = entry.path();
                // Pinned BPF programs appear as files in /sys/fs/bpf
                if path.is_file() {
                    programs.push(EbpfProgram {
                        id: 0, // Can't get ID without bpftool
                        prog_type: "unknown".to_string(),
                        name: path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        tag: format!("pinned:{}", path.display()),
                        loaded_at: None,
                        pinned: vec![path.to_string_lossy().to_string()],
                    });
                }
            }
        }

        Ok(programs)
    }

    /// Parse BPF program info from /proc/[pid]/fdinfo/[fd].
    fn parse_bpf_fdinfo(content: &str, _pid: u32) -> Option<EbpfProgram> {
        let mut prog_type = String::new();
        let mut prog_id = 0u32;
        let mut prog_tag = String::new();

        for line in content.lines() {
            if line.starts_with("prog_type:") {
                prog_type = line.split_whitespace().nth(1)?.to_string();
            } else if line.starts_with("prog_id:") {
                prog_id = line.split_whitespace().nth(1)?.parse().ok()?;
            } else if line.starts_with("prog_tag:") {
                prog_tag = line.split_whitespace().nth(1)?.to_string();
            }
        }

        if !prog_type.is_empty() {
            Some(EbpfProgram {
                id: prog_id,
                prog_type,
                name: String::new(),
                tag: if prog_tag.is_empty() {
                    format!("id:{}", prog_id)
                } else {
                    prog_tag
                },
                loaded_at: None,
                pinned: vec![],
            })
        } else {
            None
        }
    }

    /// Run the eBPF monitor loop
    pub async fn run(&mut self) -> Result<()> {
        info!("eBPF monitor starting...");

        // Check if bpftool is available
        if !Self::check_bpftool() {
            warn!("bpftool not found - eBPF monitoring limited");
        }

        // Load or create baseline
        self.load_or_create_baseline().await?;

        let interval = tokio::time::Duration::from_millis(self.config.scan_interval_ms);

        info!("eBPF monitor running");

        loop {
            if let Err(e) = self.scan().await {
                error!("Error in eBPF scan: {}", e);
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Check if bpftool is available
    fn check_bpftool() -> bool {
        Command::new("bpftool")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Load baseline from file or create new one
    async fn load_or_create_baseline(&mut self) -> Result<()> {
        if let Some(ref path) = self.config.baseline_file {
            if path.exists() {
                let content = fs::read_to_string(path)
                    .context("Failed to read eBPF baseline file")?;
                self.baseline = Some(serde_json::from_str(&content)
                    .context("Failed to parse eBPF baseline")?);
                info!("Loaded eBPF baseline from {}", path.display());
                return Ok(());
            }
        }

        if self.config.auto_baseline {
            let baseline = self.create_baseline().await?;
            if let Some(ref path) = self.config.baseline_file {
                let content = serde_json::to_string_pretty(&baseline)?;
                fs::write(path, content)?;
                info!("Created eBPF baseline at {}", path.display());
            }
            // Populate known tags from baseline
            for prog in baseline.programs.values() {
                self.known_program_tags.insert(prog.tag.clone());
            }
            self.baseline = Some(baseline);
        }

        Ok(())
    }

    /// Create a baseline of current eBPF state
    async fn create_baseline(&self) -> Result<EbpfBaseline> {
        let programs = self.get_loaded_programs()?;
        let mut baseline = EbpfBaseline::default();

        for prog in programs {
            baseline.programs.insert(prog.tag.clone(), prog);
        }

        // Get current XDP attachments
        if let Ok(xdp) = self.get_xdp_attachments() {
            for attachment in xdp {
                baseline.allowed_xdp_interfaces.insert(attachment.interface);
            }
        }

        // Get current TC attachments
        if let Ok(tc) = self.get_tc_attachments() {
            for attachment in tc {
                baseline.allowed_tc_interfaces.insert(attachment.interface);
            }
        }

        // Get current kprobe attachments
        if let Ok(kprobes) = self.get_kprobe_functions() {
            for func in kprobes {
                baseline.allowed_kprobe_functions.insert(func);
            }
        }

        Ok(baseline)
    }

    /// Perform a full eBPF scan
    async fn scan(&mut self) -> Result<()> {
        // 1. Check loaded programs
        if let Ok(programs) = self.get_loaded_programs() {
            self.check_programs(&programs).await?;
        }

        // 2. Check XDP attachments
        if self.config.monitor_xdp {
            if let Ok(xdp) = self.get_xdp_attachments() {
                self.check_xdp_attachments(&xdp).await?;
            }
        }

        // 3. Check TC attachments
        if self.config.monitor_tc {
            if let Ok(tc) = self.get_tc_attachments() {
                self.check_tc_attachments(&tc).await?;
            }
        }

        // 4. Check kprobe attachments for sensitive functions
        if let Ok(kprobes) = self.get_kprobe_functions() {
            self.check_kprobe_attachments(&kprobes).await?;
        }

        Ok(())
    }

    /// Get list of loaded eBPF programs via bpftool or native fallback.
    /// H1 Fix: Verifies bpftool integrity and falls back to native enumeration if needed.
    fn get_loaded_programs(&self) -> Result<Vec<EbpfProgram>> {
        // H1 Fix: Use native fallback if bpftool unavailable
        if self.use_native_fallback {
            return self.get_loaded_programs_native();
        }

        // H1 Fix: Verify bpftool integrity before use
        if !self.verify_bpftool() {
            warn!("bpftool integrity verification failed, using native fallback");
            return self.get_loaded_programs_native();
        }

        let bpftool_path = self.bpftool_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("bpftool path not set"))?;

        let output = Command::new(bpftool_path)
            .args(["prog", "list", "--json"])
            .output()
            .context("Failed to run bpftool prog list")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Fall back to native enumeration on error
            warn!("bpftool failed ({}), using native fallback", stderr.trim());
            return self.get_loaded_programs_native();
        }

        let json: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .context("Failed to parse bpftool output")?;

        let mut programs = Vec::new();
        for entry in json {
            let prog = EbpfProgram {
                id: entry["id"].as_u64().unwrap_or(0) as u32,
                prog_type: entry["type"].as_str().unwrap_or("unknown").to_string(),
                name: entry["name"].as_str().unwrap_or("").to_string(),
                tag: entry["tag"].as_str().unwrap_or("").to_string(),
                loaded_at: entry["loaded_at"].as_str().map(|s| s.to_string()),
                pinned: entry["pinned"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            programs.push(prog);
        }

        Ok(programs)
    }

    /// Get XDP attachments from network interfaces
    fn get_xdp_attachments(&self) -> Result<Vec<XdpAttachment>> {
        let mut attachments = Vec::new();

        // Parse ip link show for xdp info
        let output = Command::new("ip")
            .args(["-j", "link", "show"])
            .output()
            .context("Failed to run ip link show")?;

        if !output.status.success() {
            return Ok(attachments);
        }

        if let Ok(json) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
            for iface in json {
                let ifname = iface["ifname"].as_str().unwrap_or("");
                if let Some(xdp) = iface.get("xdp") {
                    if let Some(prog_id) = xdp["prog"]["id"].as_u64() {
                        let mode = xdp["mode"].as_str().unwrap_or("generic").to_string();
                        attachments.push(XdpAttachment {
                            interface: ifname.to_string(),
                            prog_id: prog_id as u32,
                            mode,
                        });
                    }
                }
            }
        }

        Ok(attachments)
    }

    /// Get TC eBPF attachments
    fn get_tc_attachments(&self) -> Result<Vec<TcAttachment>> {
        let mut attachments = Vec::new();

        // Get list of interfaces
        let output = Command::new("ls")
            .args(["/sys/class/net"])
            .output()
            .context("Failed to list network interfaces")?;

        let output_str = String::from_utf8_lossy(&output.stdout).to_string();
        let interfaces: Vec<&str> = output_str.split_whitespace().collect();

        for iface in interfaces {
            // Check ingress
            if let Ok(tc_output) = Command::new("tc")
                .args(["filter", "show", "dev", iface, "ingress"])
                .output()
            {
                let tc_str = String::from_utf8_lossy(&tc_output.stdout);
                if tc_str.contains("bpf") {
                    // Parse prog id from output
                    if let Some(id) = Self::parse_tc_prog_id(&tc_str) {
                        attachments.push(TcAttachment {
                            interface: iface.to_string(),
                            direction: "ingress".to_string(),
                            prog_id: id,
                        });
                    }
                }
            }

            // Check egress
            if let Ok(tc_output) = Command::new("tc")
                .args(["filter", "show", "dev", iface, "egress"])
                .output()
            {
                let tc_str = String::from_utf8_lossy(&tc_output.stdout);
                if tc_str.contains("bpf") {
                    if let Some(id) = Self::parse_tc_prog_id(&tc_str) {
                        attachments.push(TcAttachment {
                            interface: iface.to_string(),
                            direction: "egress".to_string(),
                            prog_id: id,
                        });
                    }
                }
            }
        }

        Ok(attachments)
    }

    /// Parse TC filter output for BPF program ID
    fn parse_tc_prog_id(output: &str) -> Option<u32> {
        // Look for "id <number>" in tc output
        for line in output.lines() {
            if line.contains("bpf") {
                if let Some(id_pos) = line.find("id ") {
                    let id_str = &line[id_pos + 3..];
                    if let Some(id) = id_str.split_whitespace().next() {
                        return id.parse().ok();
                    }
                }
            }
        }
        None
    }

    /// Get list of functions with kprobe attachments
    fn get_kprobe_functions(&self) -> Result<Vec<String>> {
        let mut functions = Vec::new();

        // Check /sys/kernel/debug/kprobes/list
        if let Ok(content) = fs::read_to_string("/sys/kernel/debug/kprobes/list") {
            for line in content.lines() {
                // Format: c0000000001dc0e0  k  do_sys_open+0x0    [FTRACE]
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let func_name = parts[2].split('+').next().unwrap_or("");
                    if !func_name.is_empty() {
                        functions.push(func_name.to_string());
                    }
                }
            }
        }

        // Also check bpftool for kprobe type programs
        if let Ok(output) = Command::new("bpftool")
            .args(["prog", "list", "--json"])
            .output()
        {
            if let Ok(json) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
                for prog in json {
                    if prog["type"].as_str() == Some("kprobe") {
                        if let Some(name) = prog["name"].as_str() {
                            functions.push(name.to_string());
                        }
                    }
                }
            }
        }

        Ok(functions)
    }

    /// Check programs against baseline
    async fn check_programs(&mut self, programs: &[EbpfProgram]) -> Result<()> {
        for prog in programs {
            // Skip if we've seen this program tag before
            if self.known_program_tags.contains(&prog.tag) {
                continue;
            }

            // Check if this is in the baseline
            let in_baseline = self
                .baseline
                .as_ref()
                .is_some_and(|b| b.programs.contains_key(&prog.tag));

            if !in_baseline && self.config.alert_on_new_programs {
                let severity = self.assess_program_severity(prog);
                let threat_type = if severity >= Severity::High {
                    ThreatType::SuspiciousEbpfProgram
                } else {
                    ThreatType::SuspiciousEbpfProgram
                };

                let event = DetectionEvent::new(
                    DetectionSource::EbpfMonitor,
                    threat_type,
                    severity,
                    format!(
                        "New eBPF program detected: {} (type={}, id={}, tag={})",
                        prog.name, prog.prog_type, prog.id, prog.tag
                    ),
                )
                .with_pattern(format!("prog_type={}", prog.prog_type));

                warn!(
                    prog_name = %prog.name,
                    prog_type = %prog.prog_type,
                    prog_id = prog.id,
                    tag = %prog.tag,
                    "New eBPF program detected"
                );

                self.event_tx.send(event).await.ok();
            }

            // Track this program
            self.known_program_tags.insert(prog.tag.clone());
        }

        Ok(())
    }

    /// Assess severity of an eBPF program based on type and name
    fn assess_program_severity(&self, prog: &EbpfProgram) -> Severity {
        let name_lower = prog.name.to_lowercase();
        let prog_type = prog.prog_type.to_lowercase();

        // Kprobe programs are higher risk
        if prog_type == "kprobe" || prog_type == "kretprobe" {
            // Check if it hooks sensitive functions
            if self.sensitive_functions.iter().any(|f| name_lower.contains(f)) {
                return Severity::Critical;
            }
            return Severity::High;
        }

        // Tracing programs
        if prog_type.contains("trace") {
            return Severity::Medium;
        }

        // XDP at network entry point
        if prog_type == "xdp" {
            return Severity::High;
        }

        // TC for traffic manipulation
        if prog_type.contains("sched") || prog_type == "tc" {
            return Severity::High;
        }

        // LSM hooks for security bypass
        if prog_type == "lsm" {
            return Severity::Critical;
        }

        Severity::Medium
    }

    /// Check XDP attachments
    async fn check_xdp_attachments(&self, attachments: &[XdpAttachment]) -> Result<()> {
        for attachment in attachments {
            let in_baseline = self
                .baseline
                .as_ref()
                .is_some_and(|b| b.allowed_xdp_interfaces.contains(&attachment.interface));

            if !in_baseline {
                let event = DetectionEvent::new(
                    DetectionSource::EbpfMonitor,
                    ThreatType::UnexpectedXdpAttachment,
                    Severity::High,
                    format!(
                        "Unexpected XDP attachment on interface {}: prog_id={}, mode={}",
                        attachment.interface, attachment.prog_id, attachment.mode
                    ),
                )
                .with_pattern(format!("interface={}", attachment.interface));

                warn!(
                    interface = %attachment.interface,
                    prog_id = attachment.prog_id,
                    mode = %attachment.mode,
                    "Unexpected XDP attachment"
                );

                self.event_tx.send(event).await.ok();
            }
        }

        Ok(())
    }

    /// Check TC attachments
    async fn check_tc_attachments(&self, attachments: &[TcAttachment]) -> Result<()> {
        for attachment in attachments {
            let in_baseline = self
                .baseline
                .as_ref()
                .is_some_and(|b| b.allowed_tc_interfaces.contains(&attachment.interface));

            if !in_baseline {
                let event = DetectionEvent::new(
                    DetectionSource::EbpfMonitor,
                    ThreatType::UnexpectedTcAttachment,
                    Severity::High,
                    format!(
                        "Unexpected TC attachment on interface {}: direction={}, prog_id={}",
                        attachment.interface, attachment.direction, attachment.prog_id
                    ),
                )
                .with_pattern(format!(
                    "interface={} direction={}",
                    attachment.interface, attachment.direction
                ));

                warn!(
                    interface = %attachment.interface,
                    direction = %attachment.direction,
                    prog_id = attachment.prog_id,
                    "Unexpected TC attachment"
                );

                self.event_tx.send(event).await.ok();
            }
        }

        Ok(())
    }

    /// Check kprobe attachments for sensitive functions
    async fn check_kprobe_attachments(&self, functions: &[String]) -> Result<()> {
        for func in functions {
            let func_lower = func.to_lowercase();

            // Check if in baseline
            let in_baseline = self
                .baseline
                .as_ref()
                .is_some_and(|b| b.allowed_kprobe_functions.contains(func));

            if in_baseline {
                continue;
            }

            // Check if this is a sensitive function
            if self.sensitive_functions.contains(&func_lower) {
                let severity = if func_lower.contains("getdents")
                    || func_lower.contains("sys_bpf")
                    || func_lower.contains("filldir")
                {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let threat_type = if severity == Severity::Critical {
                    ThreatType::EbpfRootkit
                } else {
                    ThreatType::SensitiveKprobeAttachment
                };

                let event = DetectionEvent::new(
                    DetectionSource::EbpfMonitor,
                    threat_type,
                    severity,
                    format!(
                        "Kprobe attached to sensitive function: {} (possible rootkit)",
                        func
                    ),
                )
                .with_pattern(format!("function={}", func));

                warn!(
                    function = %func,
                    severity = ?severity,
                    "Sensitive kprobe attachment detected"
                );

                self.event_tx.send(event).await.ok();
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assess_severity() {
        let (tx, _rx) = mpsc::channel(100);
        let monitor = EbpfMonitor::new(EbpfMonitorConfig::default(), tx);

        let kprobe_prog = EbpfProgram {
            id: 1,
            prog_type: "kprobe".to_string(),
            name: "test".to_string(),
            tag: "abc123".to_string(),
            loaded_at: None,
            pinned: vec![],
        };
        assert!(monitor.assess_program_severity(&kprobe_prog) >= Severity::High);

        let xdp_prog = EbpfProgram {
            id: 2,
            prog_type: "xdp".to_string(),
            name: "filter".to_string(),
            tag: "def456".to_string(),
            loaded_at: None,
            pinned: vec![],
        };
        assert!(monitor.assess_program_severity(&xdp_prog) >= Severity::High);
    }

    #[test]
    fn test_parse_tc_prog_id() {
        let tc_output = "filter protocol all pref 1 bpf chain 0 handle 0x1 direct-action not_in_hw id 42 tag abc123";
        assert_eq!(EbpfMonitor::parse_tc_prog_id(tc_output), Some(42));

        let no_bpf = "filter protocol ip pref 1000 u32";
        assert_eq!(EbpfMonitor::parse_tc_prog_id(no_bpf), None);
    }
}
