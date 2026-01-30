//! Memory Scanner
//!
//! Scans process memory for signs of:
//! - Fileless malware (executable pages in suspicious locations)
//! - Process injection
//! - Known shellcode patterns
//!
//! Requires root to read /proc/*/maps and /proc/*/mem.

use crate::config::MemoryScannerConfig;
use crate::detection::{DetectionEvent, DetectionSource, ProcessInfo, Severity, ThreatType};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Information about a memory region
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: String,
}

pub struct MemoryScanner {
    config: MemoryScannerConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    skip_processes: HashSet<String>,
    shellcode_patterns: Vec<Vec<u8>>,
    scanned_pids: HashSet<u32>,
}

impl MemoryScanner {
    pub fn new(config: MemoryScannerConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        let skip_processes: HashSet<String> = config
            .skip_processes
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        // Parse shellcode patterns from hex strings
        let shellcode_patterns: Vec<Vec<u8>> = config
            .shellcode_patterns
            .iter()
            .filter_map(|hex| hex::decode(hex).ok())
            .collect();

        Self {
            config,
            event_tx,
            skip_processes,
            shellcode_patterns,
            scanned_pids: HashSet::new(),
        }
    }

    /// Run the memory scanner loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Memory scanner starting...");

        let interval = tokio::time::Duration::from_millis(self.config.scan_interval_ms);

        info!("Memory scanner running");

        loop {
            if let Err(e) = self.scan().await {
                debug!("Error in memory scan: {}", e);
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Perform a full memory scan
    async fn scan(&mut self) -> Result<()> {
        let proc_dir = fs::read_dir("/proc").context("Failed to read /proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only process numeric entries (PIDs)
            if let Ok(pid) = name_str.parse::<u32>() {
                if self.should_scan_pid(pid) {
                    if let Err(e) = self.scan_process(pid).await {
                        debug!("Failed to scan process {}: {}", pid, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if we should scan this PID
    fn should_scan_pid(&self, pid: u32) -> bool {
        // Skip kernel threads (PID 1 and 2)
        if pid <= 2 {
            return false;
        }

        // Check UID filter
        if !self.config.scan_uids.is_empty() {
            if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
                for line in status.lines() {
                    if line.starts_with("Uid:") {
                        if let Some(uid_str) = line.split_whitespace().nth(1) {
                            if let Ok(uid) = uid_str.parse::<u32>() {
                                if !self.config.scan_uids.contains(&uid) {
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check process name filter
        if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
            let name = comm.trim().to_lowercase();
            if self.skip_processes.contains(&name) {
                return false;
            }
        }

        true
    }

    /// Scan a single process's memory
    async fn scan_process(&mut self, pid: u32) -> Result<()> {
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)
            .context("Failed to read maps")?;

        let regions = Self::parse_maps(&maps_content);

        // Check for suspicious executable regions
        if self.config.check_suspicious_exec_regions {
            self.check_suspicious_regions(pid, &regions).await?;
        }

        // Scan for shellcode patterns in anonymous executable regions
        if !self.shellcode_patterns.is_empty() {
            self.scan_for_shellcode(pid, &regions).await?;
        }

        Ok(())
    }

    /// Parse /proc/[pid]/maps content
    pub fn parse_maps(content: &str) -> Vec<MemoryRegion> {
        let mut regions = Vec::new();

        for line in content.lines() {
            if let Some(region) = Self::parse_map_line(line) {
                regions.push(region);
            }
        }

        regions
    }

    /// Parse a single line from /proc/[pid]/maps
    fn parse_map_line(line: &str) -> Option<MemoryRegion> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            return None;
        }

        let start = u64::from_str_radix(addr_parts[0], 16).ok()?;
        let end = u64::from_str_radix(addr_parts[1], 16).ok()?;

        let permissions = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
        let device = parts[3].to_string();
        let inode = parts[4].parse().unwrap_or(0);
        let pathname = parts.get(5).map(|s| s.to_string()).unwrap_or_default();

        Some(MemoryRegion {
            start,
            end,
            permissions,
            offset,
            device,
            inode,
            pathname,
        })
    }

    /// Check for suspicious executable memory regions
    async fn check_suspicious_regions(&self, pid: u32, regions: &[MemoryRegion]) -> Result<()> {
        for region in regions {
            // Look for executable regions
            if !region.permissions.contains('x') {
                continue;
            }

            let is_suspicious = self.is_suspicious_exec_region(region);

            if is_suspicious {
                let proc_info = self.get_process_info(pid);
                let region_size = region.end - region.start;

                // Skip if below threshold
                if region_size < self.config.min_suspicious_size {
                    continue;
                }

                let threat_type = if region.pathname.is_empty() {
                    ThreatType::FilelessMalware
                } else if region.pathname.contains("[stack]") || region.pathname.contains("[heap]") {
                    ThreatType::ProcessInjection
                } else {
                    ThreatType::SuspiciousMemoryRegion
                };

                let severity = if threat_type == ThreatType::FilelessMalware {
                    Severity::Critical
                } else if threat_type == ThreatType::ProcessInjection {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mut event = DetectionEvent::new(
                    DetectionSource::MemoryScanner,
                    threat_type.clone(),
                    severity,
                    format!(
                        "Suspicious executable memory region in PID {}: 0x{:x}-0x{:x} ({} bytes, perms={}, path={})",
                        pid,
                        region.start,
                        region.end,
                        region_size,
                        region.permissions,
                        if region.pathname.is_empty() { "[anonymous]" } else { &region.pathname }
                    ),
                )
                .with_pattern(format!(
                    "perms={} path={}",
                    region.permissions,
                    if region.pathname.is_empty() { "anonymous" } else { &region.pathname }
                ));

                if let Some(info) = proc_info {
                    event = event.with_process(info);
                }

                warn!(
                    pid = pid,
                    region_start = format!("0x{:x}", region.start),
                    region_end = format!("0x{:x}", region.end),
                    permissions = %region.permissions,
                    threat_type = ?threat_type,
                    "Suspicious memory region detected"
                );

                self.event_tx.send(event).await.ok();
            }
        }

        Ok(())
    }

    /// Determine if an executable region is suspicious
    fn is_suspicious_exec_region(&self, region: &MemoryRegion) -> bool {
        // Anonymous executable memory (no file backing) is suspicious
        if region.pathname.is_empty() && region.inode == 0 {
            // But only if it's also writable (rwx = classic injection)
            if region.permissions.contains('w') {
                return true;
            }
            // Or if it's just executable but not from a library
            if !region.permissions.contains('w') {
                // Could be JIT - check size
                let size = region.end - region.start;
                if size > 1024 * 1024 {
                    // > 1MB anonymous exec is suspicious
                    return true;
                }
            }
        }

        // Executable heap or stack is always suspicious
        if region.pathname.contains("[heap]") || region.pathname.contains("[stack]") {
            return true;
        }

        // Executable region in /tmp, /dev/shm, /var/tmp
        if region.pathname.starts_with("/tmp/")
            || region.pathname.starts_with("/dev/shm/")
            || region.pathname.starts_with("/var/tmp/")
            || region.pathname.starts_with("/run/")
        {
            return true;
        }

        // Memory mapped from deleted file
        if region.pathname.contains("(deleted)") {
            return true;
        }

        false
    }

    /// Scan for shellcode patterns in suspicious regions
    async fn scan_for_shellcode(&self, pid: u32, regions: &[MemoryRegion]) -> Result<()> {
        // Only scan anonymous executable regions for shellcode
        for region in regions {
            if !region.permissions.contains('x') {
                continue;
            }

            // Focus on anonymous and suspicious regions
            if !region.pathname.is_empty()
                && !region.pathname.contains("[heap]")
                && !region.pathname.contains("[stack]")
                && !region.pathname.starts_with("/tmp/")
                && !region.pathname.starts_with("/dev/shm/")
            {
                continue;
            }

            // Read region memory
            let mem_path = format!("/proc/{}/mem", pid);
            let mut mem_file = match File::open(&mem_path) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let region_size = (region.end - region.start) as usize;
            // Limit scan size to avoid performance issues
            let scan_size = region_size.min(1024 * 1024); // Max 1MB

            if mem_file.seek(SeekFrom::Start(region.start)).is_err() {
                continue;
            }

            let mut buffer = vec![0u8; scan_size];
            if mem_file.read_exact(&mut buffer).is_err() {
                // Try reading what we can
                buffer.resize(scan_size, 0);
                if mem_file.read(&mut buffer).is_err() {
                    continue;
                }
            }

            // Search for shellcode patterns
            for pattern in &self.shellcode_patterns {
                if let Some(offset) = Self::find_pattern(&buffer, pattern) {
                    let proc_info = self.get_process_info(pid);

                    let mut event = DetectionEvent::new(
                        DetectionSource::MemoryScanner,
                        ThreatType::ShellcodeDetected,
                        Severity::Critical,
                        format!(
                            "Shellcode pattern detected in PID {} at 0x{:x} (region 0x{:x}-0x{:x})",
                            pid,
                            region.start + offset as u64,
                            region.start,
                            region.end
                        ),
                    )
                    .with_pattern(format!("pattern={}", hex::encode(pattern)));

                    if let Some(info) = proc_info {
                        event = event.with_process(info);
                    }

                    warn!(
                        pid = pid,
                        offset = format!("0x{:x}", region.start + offset as u64),
                        pattern = %hex::encode(pattern),
                        "Shellcode detected"
                    );

                    self.event_tx.send(event).await.ok();
                    break; // One detection per region is enough
                }
            }
        }

        Ok(())
    }

    /// Find a byte pattern in a buffer
    fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }

        haystack
            .windows(needle.len())
            .position(|window| window == needle)
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
    fn test_parse_map_line() {
        let line = "7f1234560000-7f1234562000 r-xp 00000000 08:01 12345 /usr/lib/libfoo.so";
        let region = MemoryScanner::parse_map_line(line).unwrap();

        assert_eq!(region.start, 0x7f1234560000);
        assert_eq!(region.end, 0x7f1234562000);
        assert_eq!(region.permissions, "r-xp");
        assert_eq!(region.pathname, "/usr/lib/libfoo.so");
    }

    #[test]
    fn test_parse_anonymous_map() {
        let line = "7ffc12340000-7ffc12345000 rwxp 00000000 00:00 0";
        let region = MemoryScanner::parse_map_line(line).unwrap();

        assert_eq!(region.permissions, "rwxp");
        assert!(region.pathname.is_empty());
        assert_eq!(region.inode, 0);
    }

    #[test]
    fn test_find_pattern() {
        let haystack = vec![0x00, 0x0f, 0x05, 0x00, 0x00];
        let needle = vec![0x0f, 0x05]; // syscall

        assert_eq!(MemoryScanner::find_pattern(&haystack, &needle), Some(1));
    }

    #[test]
    fn test_suspicious_region_detection() {
        let (tx, _rx) = mpsc::channel(100);
        let scanner = MemoryScanner::new(MemoryScannerConfig::default(), tx);

        // Anonymous rwx region should be suspicious
        let anon_rwx = MemoryRegion {
            start: 0x7f0000000000,
            end: 0x7f0000001000,
            permissions: "rwxp".to_string(),
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(scanner.is_suspicious_exec_region(&anon_rwx));

        // Heap exec should be suspicious
        let heap_exec = MemoryRegion {
            start: 0x1000000,
            end: 0x2000000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: "[heap]".to_string(),
        };
        assert!(scanner.is_suspicious_exec_region(&heap_exec));

        // /tmp exec should be suspicious
        let tmp_exec = MemoryRegion {
            start: 0x7f0000000000,
            end: 0x7f0000001000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "08:01".to_string(),
            inode: 12345,
            pathname: "/tmp/malware.so".to_string(),
        };
        assert!(scanner.is_suspicious_exec_region(&tmp_exec));

        // Normal library should not be suspicious
        let normal_lib = MemoryRegion {
            start: 0x7f0000000000,
            end: 0x7f0000001000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "08:01".to_string(),
            inode: 12345,
            pathname: "/usr/lib/libc.so.6".to_string(),
        };
        assert!(!scanner.is_suspicious_exec_region(&normal_lib));
    }
}
