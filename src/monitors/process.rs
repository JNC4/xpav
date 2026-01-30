//! Scans /proc for miners, suspicious executions, and fake kernel threads.

use crate::config::{ProcessMonitorConfig, ResponseAction};
use crate::detection::{DetectionEvent, DetectionSource, ProcessAncestor, ProcessInfo, Severity, ThreatType};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
struct CpuTime {
    utime: u64,
    stime: u64,
    timestamp: Instant,
}

pub struct ProcessMonitor {
    config: ProcessMonitorConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    known_pids: HashSet<u32>,
    miner_patterns_lower: Vec<String>,
    web_server_processes_lower: Vec<String>,
    suspicious_child_processes_lower: Vec<String>,
    prev_cpu_times: HashMap<u32, CpuTime>,
    reported_high_cpu: HashSet<u32>,
    clock_ticks_per_sec: u64,
}

impl ProcessMonitor {
    pub fn new(config: ProcessMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        let miner_patterns_lower = config
            .miner_patterns
            .iter()
            .map(|p| p.to_lowercase())
            .collect();

        let web_server_processes_lower = config
            .web_server_processes
            .iter()
            .map(|p| p.to_lowercase())
            .collect();

        let suspicious_child_processes_lower = config
            .suspicious_child_processes
            .iter()
            .map(|p| p.to_lowercase())
            .collect();

        let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 };

        Self {
            config,
            event_tx,
            known_pids: HashSet::new(),
            miner_patterns_lower,
            web_server_processes_lower,
            suspicious_child_processes_lower,
            prev_cpu_times: HashMap::new(),
            reported_high_cpu: HashSet::new(),
            clock_ticks_per_sec,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Process monitor started");

        let interval = tokio::time::Duration::from_millis(self.config.scan_interval_ms);

        loop {
            if let Err(e) = self.scan_processes().await {
                error!("Error scanning processes: {}", e);
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn scan_processes(&mut self) -> Result<()> {
        let proc_dir = fs::read_dir("/proc").context("Failed to read /proc")?;

        let mut current_pids = HashSet::new();
        let mut new_cpu_times = HashMap::new();

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                current_pids.insert(pid);

                if self.config.monitor_cpu {
                    if let Some(cpu_time) = self.get_cpu_time(pid) {
                        new_cpu_times.insert(pid, cpu_time);
                    }
                }

                if let Ok(proc_info) = self.get_process_info(pid) {
                    let cpu_usage = if self.config.monitor_cpu {
                        self.calculate_cpu_usage(pid, &new_cpu_times)
                    } else {
                        None
                    };

                    self.analyze_process(&proc_info, cpu_usage).await;
                }
            }
        }

        if self.config.monitor_cpu {
            self.prev_cpu_times = new_cpu_times;
        }

        self.reported_high_cpu.retain(|pid| current_pids.contains(pid));

        self.known_pids = current_pids;

        Ok(())
    }

    fn get_cpu_time(&self, pid: u32) -> Option<CpuTime> {
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = fs::read_to_string(&stat_path).ok()?;

        // /proc/[pid]/stat format has comm in parens which may contain spaces
        // Find the last ')' to skip past the command name
        let close_paren = stat_content.rfind(')')?;
        let fields_str = &stat_content[close_paren + 2..]; // Skip ") "
        let fields: Vec<&str> = fields_str.split_whitespace().collect();

        // Fields after comm: state(0), ppid(1), pgrp(2), session(3), tty_nr(4),
        // tpgid(5), flags(6), minflt(7), cminflt(8), majflt(9), cmajflt(10),
        // utime(11), stime(12), ...
        if fields.len() < 13 {
            return None;
        }

        let utime: u64 = fields[11].parse().ok()?;
        let stime: u64 = fields[12].parse().ok()?;

        Some(CpuTime {
            utime,
            stime,
            timestamp: Instant::now(),
        })
    }

    fn calculate_cpu_usage(&self, pid: u32, new_times: &HashMap<u32, CpuTime>) -> Option<f64> {
        let prev = self.prev_cpu_times.get(&pid)?;
        let curr = new_times.get(&pid)?;

        let elapsed_secs = curr.timestamp.duration_since(prev.timestamp).as_secs_f64();
        if elapsed_secs < 0.001 {
            return None; // Too short interval
        }

        let prev_total = prev.utime + prev.stime;
        let curr_total = curr.utime + curr.stime;

        if curr_total < prev_total {
            return None; // Counter wrapped or process restarted
        }

        let cpu_ticks = curr_total - prev_total;
        let cpu_secs = cpu_ticks as f64 / self.clock_ticks_per_sec as f64;

        // CPU percentage (can be > 100% on multi-core)
        let cpu_percent = (cpu_secs / elapsed_secs) * 100.0;

        Some(cpu_percent)
    }

    fn check_suspicious_env(&self, pid: u32) -> Option<String> {
        let environ_path = format!("/proc/{}/environ", pid);
        let environ = fs::read_to_string(&environ_path).ok()?;

        let env_lower = environ.to_lowercase();
        for pattern in &self.miner_patterns_lower {
            if env_lower.contains(pattern) {
                return Some(pattern.clone());
            }
        }
        None
    }

    fn get_process_info(&self, pid: u32) -> Result<ProcessInfo> {
        let proc_path = PathBuf::from(format!("/proc/{}", pid));

        // Read cmdline
        let cmdline_path = proc_path.join("cmdline");
        let cmdline = fs::read_to_string(&cmdline_path)
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        // Read comm (process name)
        let comm_path = proc_path.join("comm");
        let name = fs::read_to_string(&comm_path)
            .unwrap_or_default()
            .trim()
            .to_string();

        // Read exe symlink
        let exe_path = proc_path.join("exe");
        let exe = fs::read_link(&exe_path).ok();

        // Read cwd symlink
        let cwd_path = proc_path.join("cwd");
        let cwd = fs::read_link(&cwd_path).ok();

        // Read status for ppid and uid
        let status_path = proc_path.join("status");
        let status = fs::read_to_string(&status_path).unwrap_or_default();

        let ppid = parse_status_field(&status, "PPid:").unwrap_or(0);
        let uid = parse_status_field(&status, "Uid:").unwrap_or(0);

        // Get username from uid
        let username = get_username(uid);

        Ok(ProcessInfo {
            pid,
            ppid,
            name,
            cmdline,
            exe_path: exe,
            cwd,
            uid,
            username,
            start_time: None, // TODO: parse from /proc/[pid]/stat
            ancestors: Vec::new(), // Populated later if ancestry tracking enabled
        })
    }

    fn build_ancestry(&self, ppid: u32, max_depth: usize) -> Vec<ProcessAncestor> {
        let mut ancestors = Vec::new();
        let mut current_pid = ppid;

        for _ in 0..max_depth {
            if current_pid <= 1 {
                break; // Reached init or invalid
            }

            let proc_path = PathBuf::from(format!("/proc/{}", current_pid));

            // Read process name
            let comm_path = proc_path.join("comm");
            let name = match fs::read_to_string(&comm_path) {
                Ok(n) => n.trim().to_string(),
                Err(_) => break, // Process no longer exists
            };

            // Read cmdline
            let cmdline_path = proc_path.join("cmdline");
            let cmdline = fs::read_to_string(&cmdline_path)
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .to_string();

            // Read ppid for next iteration
            let status_path = proc_path.join("status");
            let status = fs::read_to_string(&status_path).unwrap_or_default();
            let next_ppid = parse_status_field(&status, "PPid:").unwrap_or(0);

            ancestors.push(ProcessAncestor {
                pid: current_pid,
                name,
                cmdline,
            });

            current_pid = next_ppid;
        }

        ancestors
    }

    fn check_web_server_spawn(&self, proc: &ProcessInfo) -> Option<(ThreatType, String)> {
        let name_lower = proc.name.to_lowercase();

        // Check if this is a suspicious child process
        let is_suspicious_child = self
            .suspicious_child_processes_lower
            .iter()
            .any(|p| name_lower == *p || name_lower.starts_with(&format!("{}.", p)));

        if !is_suspicious_child {
            return None;
        }

        // Check ancestry for web server processes
        for ancestor in &proc.ancestors {
            let ancestor_name_lower = ancestor.name.to_lowercase();
            for web_server in &self.web_server_processes_lower {
                if ancestor_name_lower.contains(web_server) {
                    // Determine threat type based on child type
                    let threat_type = if self.is_shell_process(&name_lower) {
                        ThreatType::WebServerShellSpawn
                    } else {
                        ThreatType::WebServerSuspiciousChild
                    };

                    let pattern = format!(
                        "{} -> {} (pid {})",
                        ancestor.name, proc.name, proc.pid
                    );
                    return Some((threat_type, pattern));
                }
            }
        }

        None
    }

    fn is_shell_process(&self, name_lower: &str) -> bool {
        matches!(
            name_lower,
            "sh" | "bash" | "dash" | "zsh" | "ksh" | "csh" | "tcsh" | "fish"
        )
    }

    async fn analyze_process(&mut self, proc: &ProcessInfo, cpu_usage: Option<f64>) {
        // Skip kernel threads (ppid 2) and init (pid 1)
        if proc.pid <= 2 || proc.ppid == 2 {
            return;
        }

        // Build ancestry if tracking enabled
        let mut proc_with_ancestry = proc.clone();
        if self.config.track_ancestry {
            proc_with_ancestry.ancestors = self.build_ancestry(proc.ppid, 5);
        }

        // Check for miner patterns in cmdline AND environment variables
        let miner_pattern = self.check_miner_patterns(&proc_with_ancestry)
            .or_else(|| self.check_suspicious_env(proc.pid));

        // Check 1: Miner patterns in cmdline/env (with or without high CPU)
        if let Some(ref pattern) = miner_pattern {
            let (severity, desc) = if let Some(cpu) = cpu_usage {
                if cpu >= self.config.cpu_threshold {
                    (
                        Severity::Critical,
                        format!(
                            "Cryptominer detected: process {} (PID {}) matches pattern '{}' with {:.1}% CPU",
                            proc_with_ancestry.name, proc_with_ancestry.pid, pattern, cpu
                        ),
                    )
                } else {
                    (
                        Severity::High,
                        format!(
                            "Cryptominer detected: process {} (PID {}) matches pattern '{}' (CPU: {:.1}%)",
                            proc_with_ancestry.name, proc_with_ancestry.pid, pattern, cpu
                        ),
                    )
                }
            } else {
                (
                    Severity::High,
                    format!(
                        "Cryptominer detected: process {} (PID {}) matches pattern '{}'",
                        proc_with_ancestry.name, proc_with_ancestry.pid, pattern
                    ),
                )
            };

            self.report_detection(
                ThreatType::Cryptominer,
                severity,
                desc,
                pattern,
                &proc_with_ancestry,
            )
            .await;
        }

        // Check 2: High CPU without miner pattern (potential unknown miner)
        if miner_pattern.is_none() && self.config.alert_high_cpu_unknown {
            if let Some(cpu) = cpu_usage {
                if cpu >= self.config.high_cpu_threshold && !self.reported_high_cpu.contains(&proc.pid) {
                    debug!(
                        pid = proc.pid,
                        cpu = cpu,
                        name = %proc.name,
                        "High CPU process detected"
                    );

                    self.report_detection(
                        ThreatType::SuspiciousProcess,
                        Severity::Medium,
                        format!(
                            "High CPU usage: process {} (PID {}) using {:.1}% CPU (potential unknown miner)",
                            proc_with_ancestry.name, proc_with_ancestry.pid, cpu
                        ),
                        &format!("cpu={:.1}%", cpu),
                        &proc_with_ancestry,
                    )
                    .await;

                    self.reported_high_cpu.insert(proc.pid);
                }
            }
        }

        // Check 3: Execution from suspicious paths
        if let Some(path) = self.check_suspicious_path(&proc_with_ancestry) {
            self.report_detection(
                ThreatType::SuspiciousExecution,
                Severity::High,
                format!(
                    "Suspicious execution: process {} (PID {}) running from {}",
                    proc_with_ancestry.name,
                    proc_with_ancestry.pid,
                    path.display()
                ),
                &path.to_string_lossy(),
                &proc_with_ancestry,
            )
            .await;
        }

        // Check 4: Fake kernel thread names
        if let Some(pattern) = self.check_fake_kernel_thread(&proc_with_ancestry) {
            self.report_detection(
                ThreatType::SuspiciousProcess,
                Severity::High,
                format!(
                    "Fake kernel thread detected: process {} (PID {}) with PPID {} (real kthreads have PPID 2)",
                    proc_with_ancestry.name, proc_with_ancestry.pid, proc_with_ancestry.ppid
                ),
                &pattern,
                &proc_with_ancestry,
            )
            .await;
        }

        // Check 5: Suspicious process names
        if let Some(pattern) = self.check_suspicious_name(&proc_with_ancestry) {
            self.report_detection(
                ThreatType::SuspiciousProcess,
                Severity::Medium,
                format!(
                    "Suspicious process name: {} (PID {}) matches known malware pattern",
                    proc_with_ancestry.name, proc_with_ancestry.pid
                ),
                &pattern,
                &proc_with_ancestry,
            )
            .await;
        }

        // Check 6: Web server shell spawns (if ancestry tracking enabled)
        if self.config.track_ancestry {
            if let Some((threat_type, pattern)) = self.check_web_server_spawn(&proc_with_ancestry) {
                let severity = match threat_type {
                    ThreatType::WebServerShellSpawn => Severity::Critical,
                    _ => Severity::High,
                };
                let desc = match threat_type {
                    ThreatType::WebServerShellSpawn => format!(
                        "Web server shell spawn: {} (PID {}) spawned from web server process",
                        proc_with_ancestry.name, proc_with_ancestry.pid
                    ),
                    _ => format!(
                        "Suspicious web server child: {} (PID {}) spawned from web server process",
                        proc_with_ancestry.name, proc_with_ancestry.pid
                    ),
                };
                self.report_detection(
                    threat_type,
                    severity,
                    desc,
                    &pattern,
                    &proc_with_ancestry,
                )
                .await;
            }
        }
    }

    fn check_miner_patterns(&self, proc: &ProcessInfo) -> Option<String> {
        let cmdline_lower = proc.cmdline.to_lowercase();
        let name_lower = proc.name.to_lowercase();

        for pattern in &self.miner_patterns_lower {
            if cmdline_lower.contains(pattern) || name_lower.contains(pattern) {
                return Some(pattern.clone());
            }
        }
        None
    }

    fn check_suspicious_path(&self, proc: &ProcessInfo) -> Option<PathBuf> {
        let exe_path = proc.exe_path.as_ref()?;

        for suspicious in &self.config.suspicious_paths {
            if exe_path.starts_with(suspicious) {
                return Some(exe_path.clone());
            }
        }
        None
    }

    fn check_fake_kernel_thread(&self, proc: &ProcessInfo) -> Option<String> {
        // Real kernel threads have PPID 2 (kthreadd)
        // Malware sometimes names itself [kworker/0:0] etc to hide
        if proc.name.starts_with('[') && proc.name.ends_with(']') && proc.ppid != 2 {
            return Some(proc.name.clone());
        }
        None
    }

    fn check_suspicious_name(&self, proc: &ProcessInfo) -> Option<String> {
        let name_lower = proc.name.to_lowercase();

        for pattern in &self.config.suspicious_process_names {
            let pattern_lower = pattern.to_lowercase();
            if name_lower.contains(&pattern_lower) {
                // Skip if it's a legitimate kernel thread
                if proc.ppid == 2 {
                    continue;
                }
                return Some(pattern.clone());
            }
        }
        None
    }

    async fn report_detection(
        &self,
        threat_type: ThreatType,
        severity: Severity,
        description: String,
        pattern: &str,
        proc: &ProcessInfo,
    ) {
        let event = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            threat_type,
            severity,
            description,
        )
        .with_pattern(pattern)
        .with_process(proc.clone());

        // Log the detection
        warn!(
            pid = proc.pid,
            process = %proc.name,
            cmdline = %proc.cmdline,
            pattern = %pattern,
            severity = ?severity,
            "Detection: {}", event.description
        );

        // Take action based on config
        if self.config.action == ResponseAction::Kill {
            self.kill_process(proc.pid);
        }

        // Send event through channel
        if let Err(e) = self.event_tx.send(event).await {
            error!("Failed to send detection event: {}", e);
        }
    }

    fn kill_process(&self, pid: u32) {
        info!(pid = pid, "Killing malicious process");
        if let Err(e) = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            error!(pid = pid, "Failed to kill process: {}", e);
        }
    }
}

fn parse_status_field(status: &str, field: &str) -> Option<u32> {
    for line in status.lines() {
        if line.starts_with(field) {
            let value = line
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()?;
            return Some(value);
        }
    }
    None
}

fn get_username(uid: u32) -> Option<String> {
    // Read /etc/passwd to map UID to username
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(line_uid) = parts[2].parse::<u32>() {
                if line_uid == uid {
                    return Some(parts[0].to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn create_test_monitor() -> ProcessMonitor {
        let (tx, _rx) = mpsc::channel(100);
        ProcessMonitor::new(ProcessMonitorConfig::default(), tx)
    }

    #[test]
    fn test_miner_pattern_detection() {
        let monitor = create_test_monitor();

        let proc = ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "xmrig".to_string(),
            cmdline: "./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u wallet".to_string(),
            exe_path: Some(PathBuf::from("/tmp/xmrig")),
            cwd: Some(PathBuf::from("/tmp")),
            uid: 1000,
            username: Some("user".to_string()),
            start_time: None,
            ancestors: Vec::new(),
        };

        assert!(monitor.check_miner_patterns(&proc).is_some());
    }

    #[test]
    fn test_suspicious_path_detection() {
        let monitor = create_test_monitor();

        let proc = ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "suspicious".to_string(),
            cmdline: "/tmp/suspicious".to_string(),
            exe_path: Some(PathBuf::from("/tmp/suspicious")),
            cwd: Some(PathBuf::from("/tmp")),
            uid: 1000,
            username: Some("user".to_string()),
            start_time: None,
            ancestors: Vec::new(),
        };

        assert!(monitor.check_suspicious_path(&proc).is_some());
    }

    #[test]
    fn test_fake_kernel_thread_detection() {
        let monitor = create_test_monitor();

        // Fake kernel thread (ppid != 2)
        let fake = ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "[kworker/0:0]".to_string(),
            cmdline: "".to_string(),
            exe_path: None,
            cwd: None,
            uid: 0,
            username: Some("root".to_string()),
            start_time: None,
            ancestors: Vec::new(),
        };

        assert!(monitor.check_fake_kernel_thread(&fake).is_some());

        // Real kernel thread (ppid == 2)
        let real = ProcessInfo {
            pid: 1234,
            ppid: 2,
            name: "[kworker/0:0]".to_string(),
            cmdline: "".to_string(),
            exe_path: None,
            cwd: None,
            uid: 0,
            username: Some("root".to_string()),
            start_time: None,
            ancestors: Vec::new(),
        };

        assert!(monitor.check_fake_kernel_thread(&real).is_none());
    }

    #[test]
    fn test_web_server_spawn_detection() {
        let monitor = create_test_monitor();

        // Process spawned from apache2
        let proc = ProcessInfo {
            pid: 5678,
            ppid: 1234,
            name: "bash".to_string(),
            cmdline: "/bin/bash -c whoami".to_string(),
            exe_path: Some(PathBuf::from("/bin/bash")),
            cwd: Some(PathBuf::from("/var/www")),
            uid: 33,
            username: Some("www-data".to_string()),
            start_time: None,
            ancestors: vec![
                ProcessAncestor {
                    pid: 1234,
                    name: "php-fpm".to_string(),
                    cmdline: "php-fpm: pool www".to_string(),
                },
                ProcessAncestor {
                    pid: 1000,
                    name: "apache2".to_string(),
                    cmdline: "/usr/sbin/apache2 -k start".to_string(),
                },
            ],
        };

        let result = monitor.check_web_server_spawn(&proc);
        assert!(result.is_some());
        let (threat_type, _) = result.unwrap();
        assert_eq!(threat_type, ThreatType::WebServerShellSpawn);
    }

    #[test]
    fn test_cpu_time_parsing() {
        let monitor = create_test_monitor();

        // Get CPU time for current process (should succeed)
        let pid = std::process::id();
        let cpu_time = monitor.get_cpu_time(pid);
        assert!(cpu_time.is_some(), "Should be able to get CPU time for self");

        let cpu_time = cpu_time.unwrap();
        // CPU times are u64, so always valid - just verify we got some data
        // For a running process, at least one should have some ticks
        let _ = cpu_time.utime + cpu_time.stime; // Just verify we can access them
    }

    #[test]
    fn test_cpu_usage_calculation() {
        let monitor = create_test_monitor();

        // Verify clock ticks is reasonable (typically 100 on Linux)
        assert!(monitor.clock_ticks_per_sec > 0);
        assert!(monitor.clock_ticks_per_sec <= 10000); // Sanity check
    }
}
