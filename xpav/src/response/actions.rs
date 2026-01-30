//! Response actions for threat mitigation.
//!
//! This module provides actions that can be taken in response to detected threats:
//! - Kill: Terminate a malicious process
//! - Block: Block network connections using iptables/nftables
//! - Quarantine: Move suspicious files to quarantine directory

use anyhow::{Context, Result};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

use crate::persistence::{quarantine_file, DEFAULT_QUARANTINE_DIR};

/// Available response actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    /// Log only, take no action
    Alert,
    /// Kill the process
    Kill {
        pid: u32,
        /// Expected exe path for TOCTOU protection
        expected_exe: Option<PathBuf>,
        /// Expected process start time for TOCTOU protection
        expected_start_time: Option<u64>,
    },
    /// Block an IP address
    BlockIp { ip: String, duration_secs: Option<u64> },
    /// Block a port
    BlockPort { port: u16, protocol: String },
    /// Quarantine a file
    Quarantine { path: PathBuf },
    /// Custom command
    Custom { command: String },
}

/// Validate that a string is a valid IP address (prevents command injection).
fn validate_ip(ip: &str) -> Result<()> {
    ip.parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("Invalid IP address format: {}", ip))?;
    Ok(())
}

/// Get the start time (in clock ticks since boot) for a process from /proc/[pid]/stat.
fn get_process_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = fs::read_to_string(&stat_path).ok()?;

    // /proc/[pid]/stat format has comm in parens which may contain spaces
    // Find the last ')' to skip past the command name
    let close_paren = stat_content.rfind(')')?;
    let fields_str = &stat_content[close_paren + 2..]; // Skip ") "
    let fields: Vec<&str> = fields_str.split_whitespace().collect();

    // Field 22 (0-indexed as 19 after skipping pid, comm, state) is starttime
    // After the closing paren: state(0), ppid(1), ..., starttime(19)
    if fields.len() > 19 {
        fields[19].parse().ok()
    } else {
        None
    }
}

/// Executor for response actions.
pub struct ResponseActions {
    /// Whether to actually execute actions (false = dry run)
    execute: bool,
    /// Whether to use nftables (true) or iptables (false)
    use_nftables: bool,
}

impl ResponseActions {
    /// Create a new action executor.
    pub fn new(dry_run: bool) -> Self {
        let use_nftables = Self::detect_nftables();
        Self {
            execute: !dry_run,
            use_nftables,
        }
    }

    /// Detect if nftables is available and preferred.
    fn detect_nftables() -> bool {
        Command::new("nft")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Execute a response action.
    pub fn execute(&self, action: &ResponseAction) -> Result<ActionResult> {
        match action {
            ResponseAction::Alert => Ok(ActionResult::Success {
                action: "alert".to_string(),
                message: "Logged alert".to_string(),
            }),
            ResponseAction::Kill { pid, expected_exe, expected_start_time } => {
                self.kill_process(*pid, expected_exe.as_deref(), *expected_start_time)
            }
            ResponseAction::BlockIp { ip, duration_secs } => self.block_ip(ip, *duration_secs),
            ResponseAction::BlockPort { port, protocol } => self.block_port(*port, protocol),
            ResponseAction::Quarantine { path } => self.quarantine(path),
            ResponseAction::Custom { command } => self.run_custom(command),
        }
    }

    /// Kill a process by PID with TOCTOU protection.
    ///
    /// Verifies process identity before kill to prevent PID recycling attacks:
    /// - Checks that /proc/[pid]/exe matches expected executable
    /// - Checks that process start time matches expected value
    pub fn kill_process(
        &self,
        pid: u32,
        expected_exe: Option<&Path>,
        expected_start_time: Option<u64>,
    ) -> Result<ActionResult> {
        info!("Kill action for PID {}", pid);

        if !self.execute {
            return Ok(ActionResult::DryRun {
                action: "kill".to_string(),
                would_do: format!("Would kill process {}", pid),
            });
        }

        // TOCTOU protection: Verify process identity before kill
        // Check exe path matches if provided
        if let Some(expected) = expected_exe {
            let exe_path = format!("/proc/{}/exe", pid);
            match fs::read_link(&exe_path) {
                Ok(actual) => {
                    if actual != expected {
                        warn!(
                            "PID {} exe mismatch: expected {:?}, got {:?}",
                            pid, expected, actual
                        );
                        return Ok(ActionResult::Failed {
                            action: "kill".to_string(),
                            error: format!(
                                "PID {} reused (exe mismatch), aborting kill for safety",
                                pid
                            ),
                        });
                    }
                }
                Err(_) => {
                    // Process may have already exited
                    return Ok(ActionResult::Failed {
                        action: "kill".to_string(),
                        error: format!("Process {} no longer exists", pid),
                    });
                }
            }
        }

        // Check start time matches if provided
        if let Some(expected_time) = expected_start_time {
            if let Some(actual_time) = get_process_start_time(pid) {
                if actual_time != expected_time {
                    warn!(
                        "PID {} start time mismatch: expected {}, got {}",
                        pid, expected_time, actual_time
                    );
                    return Ok(ActionResult::Failed {
                        action: "kill".to_string(),
                        error: format!(
                            "PID {} reused (start time mismatch), aborting kill for safety",
                            pid
                        ),
                    });
                }
            }
        }

        // First try SIGTERM
        let result = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );

        match result {
            Ok(_) => {
                // Wait a moment then check if process is still alive
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Check if process still exists
                let proc_path = format!("/proc/{}", pid);
                if Path::new(&proc_path).exists() {
                    // Re-verify identity before SIGKILL (another TOCTOU check)
                    let should_kill = if let Some(expected) = expected_exe {
                        fs::read_link(format!("/proc/{}/exe", pid))
                            .map(|actual| actual == expected)
                            .unwrap_or(false)
                    } else {
                        true
                    };

                    if should_kill {
                        // Process still alive, try SIGKILL
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                }

                Ok(ActionResult::Success {
                    action: "kill".to_string(),
                    message: format!("Killed process {}", pid),
                })
            }
            Err(e) => Ok(ActionResult::Failed {
                action: "kill".to_string(),
                error: format!("Failed to kill process {}: {}", pid, e),
            }),
        }
    }

    /// Block an IP address using iptables or nftables.
    ///
    /// IP address is validated before use to prevent command injection.
    pub fn block_ip(&self, ip: &str, duration_secs: Option<u64>) -> Result<ActionResult> {
        // Validate IP format to prevent command injection (C5 fix)
        validate_ip(ip)?;

        info!("Block IP action for {}", ip);

        if !self.execute {
            return Ok(ActionResult::DryRun {
                action: "block_ip".to_string(),
                would_do: format!("Would block IP {} for {:?}s", ip, duration_secs),
            });
        }

        // For nftables, we use the built-in timeout feature instead of spawning threads.
        // For iptables, we use at/batch scheduling if duration is specified.
        let result = if self.use_nftables {
            self.block_ip_nftables(ip, duration_secs)
        } else {
            self.block_ip_iptables(ip, duration_secs)
        };

        result.map(|_| ActionResult::Success {
            action: "block_ip".to_string(),
            message: format!("Blocked IP {}{}", ip,
                duration_secs.map(|d| format!(" for {}s", d)).unwrap_or_default()),
        })
    }

    fn block_ip_iptables(&self, ip: &str, duration_secs: Option<u64>) -> Result<()> {
        // IP is already validated by block_ip() caller

        // Check if rule already exists to avoid duplicates
        let check = Command::new("iptables")
            .args(["-C", "INPUT", "-s", ip, "-j", "DROP"])
            .output()
            .context("Failed to check iptables")?;

        if check.status.success() {
            // Rule already exists
            return Ok(());
        }

        let output = Command::new("iptables")
            .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output()
            .context("Failed to execute iptables")?;

        if !output.status.success() {
            anyhow::bail!(
                "iptables failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // For iptables with duration, schedule removal using 'at' if available
        // Write to a temp script file to avoid shell interpolation (C5 fix)
        if let Some(secs) = duration_secs {
            // Create a temp script file with the unblock command
            // This avoids shell interpolation of the IP address
            let script_dir = "/var/run/xpav";
            let _ = fs::create_dir_all(script_dir);

            let script_path = format!("{}/unblock_{}.sh", script_dir, ip.replace(['.', ':'], "_"));
            let script_content = format!(
                "#!/bin/sh\niptables -D INPUT -s '{}' -j DROP\nrm -f '{}'\n",
                ip, script_path
            );

            if fs::write(&script_path, &script_content).is_ok() {
                // Make script executable
                let _ = Command::new("chmod").args(["+x", &script_path]).output();

                // Schedule script execution using 'at'
                // Pass script path directly without shell interpolation
                let _ = Command::new("at")
                    .args([&format!("now + {} seconds", secs)])
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .and_then(|mut child| {
                        if let Some(stdin) = child.stdin.as_mut() {
                            use std::io::Write;
                            let _ = writeln!(stdin, "{}", script_path);
                        }
                        child.wait()
                    });
            }
            // If 'at' or script creation fails, log a warning but don't fail
            // The rule will remain until manually removed
        }

        Ok(())
    }

    fn block_ip_nftables(&self, ip: &str, duration_secs: Option<u64>) -> Result<()> {
        // Ensure the table exists
        let _ = Command::new("nft")
            .args(["add", "table", "inet", "xpav_filter"])
            .output();

        // Ensure the set exists with timeout flag
        let _ = Command::new("nft")
            .args([
                "add", "set", "inet", "xpav_filter", "blocked_ips",
                "{ type ipv4_addr; flags timeout; }",
            ])
            .output();

        // Ensure the chain exists
        let _ = Command::new("nft")
            .args([
                "add", "chain", "inet", "xpav_filter", "input",
                "{ type filter hook input priority 0; }",
            ])
            .output();

        // Check if the drop rule already exists before adding
        let check = Command::new("nft")
            .args(["list", "chain", "inet", "xpav_filter", "input"])
            .output();

        let rule_exists = check
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("@blocked_ips"))
            .unwrap_or(false);

        if !rule_exists {
            let _ = Command::new("nft")
                .args([
                    "add", "rule", "inet", "xpav_filter", "input",
                    "ip", "saddr", "@blocked_ips", "drop",
                ])
                .output();
        }

        // Add the IP to the set with optional timeout
        // nftables timeout syntax: { 1.2.3.4 timeout 60s }
        let element = match duration_secs {
            Some(secs) => format!("{{ {} timeout {}s }}", ip, secs),
            None => format!("{{ {} }}", ip),
        };

        let output = Command::new("nft")
            .args([
                "add", "element", "inet", "xpav_filter", "blocked_ips",
                &element,
            ])
            .output()
            .context("Failed to execute nft")?;

        if !output.status.success() {
            anyhow::bail!("nft failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }

    /// Block a port.
    pub fn block_port(&self, port: u16, protocol: &str) -> Result<ActionResult> {
        info!("Block port action for {} {}", protocol, port);

        if !self.execute {
            return Ok(ActionResult::DryRun {
                action: "block_port".to_string(),
                would_do: format!("Would block port {} {}", protocol, port),
            });
        }

        let output = if self.use_nftables {
            Command::new("nft")
                .args([
                    "add", "rule", "inet", "filter", "input",
                    protocol, "dport", &port.to_string(), "drop",
                ])
                .output()
        } else {
            Command::new("iptables")
                .args([
                    "-A", "INPUT", "-p", protocol,
                    "--dport", &port.to_string(), "-j", "DROP",
                ])
                .output()
        }
        .context("Failed to execute firewall command")?;

        if output.status.success() {
            Ok(ActionResult::Success {
                action: "block_port".to_string(),
                message: format!("Blocked {} port {}", protocol, port),
            })
        } else {
            Ok(ActionResult::Failed {
                action: "block_port".to_string(),
                error: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    /// Quarantine a file.
    pub fn quarantine(&self, path: &Path) -> Result<ActionResult> {
        info!("Quarantine action for {}", path.display());

        if !self.execute {
            return Ok(ActionResult::DryRun {
                action: "quarantine".to_string(),
                would_do: format!("Would quarantine {}", path.display()),
            });
        }

        if !path.exists() {
            return Ok(ActionResult::Failed {
                action: "quarantine".to_string(),
                error: format!("File does not exist: {}", path.display()),
            });
        }

        match quarantine_file(path) {
            Ok(quarantine_path) => Ok(ActionResult::Success {
                action: "quarantine".to_string(),
                message: format!(
                    "Quarantined {} to {}",
                    path.display(),
                    quarantine_path.display()
                ),
            }),
            Err(e) => Ok(ActionResult::Failed {
                action: "quarantine".to_string(),
                error: format!("Failed to quarantine: {}", e),
            }),
        }
    }

    /// Run a custom command.
    pub fn run_custom(&self, command: &str) -> Result<ActionResult> {
        warn!("Custom command action: {}", command);

        if !self.execute {
            return Ok(ActionResult::DryRun {
                action: "custom".to_string(),
                would_do: format!("Would run: {}", command),
            });
        }

        let output = Command::new("sh")
            .args(["-c", command])
            .output()
            .context("Failed to execute custom command")?;

        if output.status.success() {
            Ok(ActionResult::Success {
                action: "custom".to_string(),
                message: format!("Executed: {}", command),
            })
        } else {
            Ok(ActionResult::Failed {
                action: "custom".to_string(),
                error: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    /// List quarantined files.
    pub fn list_quarantine() -> Result<Vec<PathBuf>> {
        let quarantine_dir = Path::new(DEFAULT_QUARANTINE_DIR);
        if !quarantine_dir.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        for entry in std::fs::read_dir(quarantine_dir)? {
            if let Ok(entry) = entry {
                files.push(entry.path());
            }
        }

        Ok(files)
    }

    /// Restore a file from quarantine.
    pub fn restore_from_quarantine(quarantine_path: &Path, restore_to: &Path) -> Result<()> {
        std::fs::rename(quarantine_path, restore_to).context("Failed to restore file")?;
        info!(
            "Restored {} to {}",
            quarantine_path.display(),
            restore_to.display()
        );
        Ok(())
    }
}

/// Result of executing an action.
#[derive(Debug, Clone)]
pub enum ActionResult {
    /// Action executed successfully
    Success { action: String, message: String },
    /// Action was not executed (dry run)
    DryRun { action: String, would_do: String },
    /// Action failed
    Failed { action: String, error: String },
}

impl ActionResult {
    /// Check if the action was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, ActionResult::Success { .. })
    }

    /// Check if this was a dry run.
    pub fn is_dry_run(&self) -> bool {
        matches!(self, ActionResult::DryRun { .. })
    }

    /// Check if the action failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, ActionResult::Failed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_result() {
        let success = ActionResult::Success {
            action: "test".to_string(),
            message: "OK".to_string(),
        };
        assert!(success.is_success());
        assert!(!success.is_dry_run());
        assert!(!success.is_failed());

        let dry_run = ActionResult::DryRun {
            action: "test".to_string(),
            would_do: "nothing".to_string(),
        };
        assert!(!dry_run.is_success());
        assert!(dry_run.is_dry_run());
    }

    #[test]
    fn test_dry_run_kill() {
        let actions = ResponseActions::new(true); // dry run
        let result = actions.kill_process(99999, None, None).unwrap();
        assert!(result.is_dry_run());
    }

    #[test]
    fn test_ip_validation_rejects_injection() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());
        assert!(validate_ip("192.168.1.1; rm -rf /").is_err());
        assert!(validate_ip("$(whoami)").is_err());
        assert!(validate_ip("192.168.1.1`id`").is_err());
        assert!(validate_ip("not-an-ip").is_err());
    }

    #[test]
    fn test_dry_run_block_ip() {
        let actions = ResponseActions::new(true);
        let result = actions.block_ip("192.168.1.100", Some(60)).unwrap();
        assert!(result.is_dry_run());
    }

    #[test]
    fn test_dry_run_quarantine() {
        let actions = ResponseActions::new(true);
        let result = actions.quarantine(Path::new("/tmp/test_file")).unwrap();
        assert!(result.is_dry_run());
    }
}
