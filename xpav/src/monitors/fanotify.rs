//! Fanotify File Monitor
//!
//! Real-time file monitoring using the Linux fanotify API.
//! Watches web roots for new/modified files and scans them for webshells.
//!
//! Supports context-aware scanning for false positive reduction.
//!
//! Requires CAP_SYS_ADMIN (root) to operate.

use crate::allowlist::AllowlistChecker;
use crate::config::{FalsePositiveReductionConfig, FileMonitorConfig, ResponseAction};
use crate::detection::{
    DetectionEvent, DetectionSource, FileEventType, FileInfo, Severity, ThreatType,
};
use crate::scanner::{FrameworkDetector, ScanContext, WebshellScanner};
use anyhow::{Context, Result};
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use std::collections::HashSet;
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct FanotifyMonitor {
    config: FileMonitorConfig,
    fp_config: FalsePositiveReductionConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    scanner: WebshellScanner,
    scan_extensions: HashSet<String>,
    framework_detector: Arc<FrameworkDetector>,
    allowlist: Arc<AllowlistChecker>,
}

impl FanotifyMonitor {
    pub fn new(config: FileMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self::with_fp_config(
            config,
            FalsePositiveReductionConfig::default(),
            event_tx,
            Arc::new(AllowlistChecker::default()),
        )
    }

    pub fn with_fp_config(
        config: FileMonitorConfig,
        fp_config: FalsePositiveReductionConfig,
        event_tx: mpsc::Sender<DetectionEvent>,
        allowlist: Arc<AllowlistChecker>,
    ) -> Self {
        let scanner = WebshellScanner::new(config.obfuscation_threshold);
        let scan_extensions: HashSet<String> = config
            .scan_extensions
            .iter()
            .map(|e| e.to_lowercase())
            .collect();

        Self {
            config,
            fp_config,
            event_tx,
            scanner,
            scan_extensions,
            framework_detector: Arc::new(FrameworkDetector::new()),
            allowlist,
        }
    }

    /// Run the fanotify monitor loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Fanotify file monitor starting...");

        // Initialize fanotify
        // Use FAN_CLASS_NOTIF for notification-only mode (doesn't require permission responses)
        let init_flags = InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC;

        let fanotify = Fanotify::init(init_flags, EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC)
            .context("Failed to initialize fanotify (requires CAP_SYS_ADMIN/root)")?;

        // Mark directories to watch
        let mask = MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_EVENT_ON_CHILD;
        let mark_flags = MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT;

        for path in &self.config.watch_paths {
            // Expand glob patterns like /home/*/public_html
            let expanded_paths = expand_glob_path(path);

            for expanded_path in expanded_paths {
                if expanded_path.exists() && expanded_path.is_dir() {
                    match fanotify.mark(mark_flags, mask, None, Some(&expanded_path)) {
                        Ok(_) => {
                            info!("Watching path: {}", expanded_path.display());
                        }
                        Err(e) => {
                            warn!(
                                "Failed to mark path {} for monitoring: {}",
                                expanded_path.display(),
                                e
                            );
                        }
                    }
                } else {
                    debug!("Path does not exist or is not a directory: {}", expanded_path.display());
                }
            }
        }

        info!("Fanotify file monitor running");

        // Create async wrapper for the fanotify fd
        let raw_fd = fanotify.as_fd().as_raw_fd();
        let async_fd = AsyncFd::with_interest(FdWrapper(raw_fd), Interest::READABLE)
            .context("Failed to create async fd")?;

        // Event processing loop
        loop {
            // Wait for fanotify to be readable
            let mut guard = async_fd.readable().await?;

            // Read and process events
            match fanotify.read_events() {
                Ok(events) => {
                    for event in events {
                        if let Err(e) = self.handle_event(&event).await {
                            error!("Error handling fanotify event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    // EAGAIN is normal for non-blocking reads
                    if e != nix::errno::Errno::EAGAIN {
                        error!("Error reading fanotify events: {}", e);
                    }
                }
            }

            guard.clear_ready();
        }
    }

    /// Handle a single fanotify event
    async fn handle_event(
        &self,
        event: &nix::sys::fanotify::FanotifyEvent,
    ) -> Result<()> {
        // Get the file path from the fd
        let fd = match event.fd() {
            Some(fd) => fd,
            None => return Ok(()), // FAN_NOFD event
        };

        let path = get_path_from_fd(fd.as_raw_fd())?;

        // Check if we should scan this file
        if self.should_scan_file(&path) {
            let mask = event.mask();

            if mask.contains(MaskFlags::FAN_CLOSE_WRITE) && self.config.scan_new_files {
                // File was written/modified - scan it
                if let Err(e) = self.scan_file(&path).await {
                    debug!("Error scanning file {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Check if a file should be scanned based on extension
    fn should_scan_file(&self, path: &Path) -> bool {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        self.scan_extensions.contains(&extension)
    }

    /// Scan a file for webshell patterns
    async fn scan_file(&self, path: &Path) -> Result<()> {
        // Check if file is allowlisted
        if self.allowlist.is_file_allowed(path, None) {
            debug!(path = %path.display(), "File allowlisted, skipping scan");
            return Ok(());
        }

        let content = fs::read_to_string(path).context("Failed to read file")?;

        // Build scan context if context-aware scanning is enabled
        let result = if self.fp_config.context_scoring {
            let context = ScanContext::from_path_with_detector(path, Some(&self.framework_detector));

            // Check for suppressed categories
            let suppressed = self.allowlist.get_suppressed_categories(path);

            // Use context-aware scanning
            let mut result = self.scanner.scan_with_context(&content, &context);

            // Filter out suppressed detections
            if !suppressed.is_empty() {
                result.detections.retain(|d| {
                    let category_name = format!("{:?}", d.category);
                    !suppressed.contains(&category_name)
                });

                // Recalculate threat level after filtering
                if result.detections.is_empty() {
                    result.threat_level = crate::scanner::webshell::ThreatLevel::Clean;
                    result.is_malicious = false;
                }
            }

            debug!(
                path = %path.display(),
                framework = ?context.framework,
                is_vendor = context.is_vendor,
                is_minified = context.is_minified,
                score_multiplier = context.score_multiplier,
                "Context-aware scan completed"
            );

            result
        } else {
            self.scanner.scan(&content)
        };

        if result.is_malicious {
            let threat_type = if result.obfuscation_score >= self.config.obfuscation_threshold * 2 {
                ThreatType::WebshellObfuscated
            } else {
                ThreatType::Webshell
            };

            let severity = match result.threat_level {
                crate::scanner::webshell::ThreatLevel::Malicious => Severity::Critical,
                crate::scanner::webshell::ThreatLevel::Suspicious => Severity::High,
                crate::scanner::webshell::ThreatLevel::Clean => Severity::Low,
            };

            let detection_desc: String = result
                .detections
                .iter()
                .take(3)
                .map(|d| d.description.clone())
                .collect::<Vec<_>>()
                .join("; ");

            let event = DetectionEvent::new(
                DetectionSource::FileMonitor,
                threat_type.clone(),
                severity,
                format!(
                    "Webshell detected in {}: {}",
                    path.display(),
                    detection_desc
                ),
            )
            .with_file(FileInfo {
                path: path.to_path_buf(),
                event_type: FileEventType::Modified,
                old_content_hash: None,
                new_content_hash: None,
            })
            .with_pattern(format!(
                "obfuscation_score={}, detections={}",
                result.obfuscation_score,
                result.detections.len()
            ));

            warn!(
                path = %path.display(),
                threat_type = ?threat_type,
                severity = ?severity,
                obfuscation_score = result.obfuscation_score,
                "Webshell detected"
            );

            // Take action based on config
            if self.config.action == ResponseAction::Block {
                // Quarantine the file by making it non-executable and renaming
                self.quarantine_file(path).await?;
            }

            // Send event
            if let Err(e) = self.event_tx.send(event).await {
                error!("Failed to send detection event: {}", e);
            }
        }

        Ok(())
    }

    /// Quarantine a malicious file
    async fn quarantine_file(&self, path: &Path) -> Result<()> {
        let quarantine_name = format!(
            "{}.quarantine.{}",
            path.display(),
            chrono::Utc::now().timestamp()
        );

        // Rename the file
        fs::rename(path, &quarantine_name).context("Failed to quarantine file")?;

        // Make it non-executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o000);
            fs::set_permissions(&quarantine_name, perms).ok();
        }

        info!(
            original = %path.display(),
            quarantine = %quarantine_name,
            "File quarantined"
        );

        Ok(())
    }
}

/// Wrapper for RawFd to implement AsRawFd for AsyncFd
struct FdWrapper(RawFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Get file path from a file descriptor via /proc/self/fd/
fn get_path_from_fd(fd: RawFd) -> Result<PathBuf> {
    let link_path = format!("/proc/self/fd/{}", fd);
    let path = fs::read_link(&link_path).context("Failed to read fd link")?;
    Ok(path)
}

/// Expand glob patterns in paths (simple implementation)
fn expand_glob_path(path: &Path) -> Vec<PathBuf> {
    let path_str = path.to_string_lossy();

    if !path_str.contains('*') {
        return vec![path.to_path_buf()];
    }

    // Handle /home/*/public_html pattern
    let parts: Vec<&str> = path_str.split('/').collect();
    let mut results = vec![PathBuf::from("/")];

    for part in parts {
        if part.is_empty() {
            continue;
        }

        if part == "*" {
            // Expand wildcard
            let mut new_results = Vec::new();
            for base in &results {
                if let Ok(entries) = fs::read_dir(base) {
                    for entry in entries.flatten() {
                        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            new_results.push(entry.path());
                        }
                    }
                }
            }
            results = new_results;
        } else {
            // Append fixed part
            results = results.iter().map(|p| p.join(part)).collect();
        }
    }

    // Filter to only existing directories
    results
        .into_iter()
        .filter(|p| p.exists() && p.is_dir())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_glob_simple_path() {
        let results = expand_glob_path(Path::new("/var/www"));
        assert_eq!(results, vec![PathBuf::from("/var/www")]);
    }

    #[test]
    fn test_should_scan_file() {
        let (tx, _rx) = mpsc::channel(100);
        let monitor = FanotifyMonitor::new(FileMonitorConfig::default(), tx);

        assert!(monitor.should_scan_file(Path::new("/var/www/test.php")));
        assert!(monitor.should_scan_file(Path::new("/var/www/test.PHP")));
        assert!(monitor.should_scan_file(Path::new("/var/www/test.phtml")));
        assert!(!monitor.should_scan_file(Path::new("/var/www/test.txt")));
        assert!(!monitor.should_scan_file(Path::new("/var/www/test.js")));
    }
}
