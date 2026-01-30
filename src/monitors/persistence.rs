//! Persistence Monitor
//!
//! Monitors persistence mechanisms for unauthorized changes:
//! - Crontab and cron.d
//! - SSH authorized_keys
//! - Systemd user units
//! - /etc/ld.so.preload

use crate::config::PersistenceMonitorConfig;
use crate::detection::{
    DetectionEvent, DetectionSource, FileEventType, FileInfo, Severity, ThreatType,
};
use anyhow::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct PersistenceMonitor {
    config: PersistenceMonitorConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    file_hashes: HashMap<PathBuf, String>,
}

/// Paths to monitor for persistence mechanisms
struct WatchPaths {
    cron: Vec<PathBuf>,
    ssh: Vec<PathBuf>,
    systemd: Vec<PathBuf>,
    ld_preload: Vec<PathBuf>,
}

impl WatchPaths {
    fn new() -> Self {
        Self {
            cron: vec![
                PathBuf::from("/etc/crontab"),
                PathBuf::from("/etc/cron.d"),
                PathBuf::from("/etc/cron.daily"),
                PathBuf::from("/etc/cron.hourly"),
                PathBuf::from("/etc/cron.weekly"),
                PathBuf::from("/etc/cron.monthly"),
                PathBuf::from("/var/spool/cron"),
                PathBuf::from("/var/spool/cron/crontabs"),
            ],
            ssh: vec![
                PathBuf::from("/root/.ssh"),
                PathBuf::from("/home"), // Will enumerate user dirs
            ],
            systemd: vec![
                PathBuf::from("/etc/systemd/system"),
                PathBuf::from("/lib/systemd/system"),
                PathBuf::from("/usr/lib/systemd/system"),
            ],
            ld_preload: vec![PathBuf::from("/etc/ld.so.preload")],
        }
    }

}

impl PersistenceMonitor {
    pub fn new(config: PersistenceMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self {
            config,
            event_tx,
            file_hashes: HashMap::new(),
        }
    }

    /// Run the persistence monitor
    pub async fn run(&mut self) -> Result<()> {
        info!("Persistence monitor started");

        // Get paths to watch based on config
        let watch_paths = self.get_watch_paths();

        // Create initial baseline of file hashes
        self.create_baseline(&watch_paths);

        // Set up inotify watcher
        let (tx, rx) = std_mpsc::channel();

        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        // Add watches for configured paths
        for path in &watch_paths {
            if path.exists() {
                let mode = if path.is_dir() {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };

                if let Err(e) = watcher.watch(path, mode) {
                    debug!("Could not watch {}: {}", path.display(), e);
                } else {
                    debug!("Watching: {}", path.display());
                }
            }
        }

        // Also watch home directories for SSH keys
        if self.config.watch_ssh_keys {
            self.watch_home_ssh_dirs(&mut watcher);
        }

        // Process events
        loop {
            match rx.recv() {
                Ok(Ok(event)) => {
                    self.handle_event(event).await;
                }
                Ok(Err(e)) => {
                    error!("Watch error: {}", e);
                }
                Err(e) => {
                    error!("Channel error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Get paths to watch based on configuration
    fn get_watch_paths(&self) -> Vec<PathBuf> {
        let all_paths = WatchPaths::new();
        let mut paths = Vec::new();

        if self.config.watch_crontab {
            paths.extend(all_paths.cron.into_iter());
        }
        if self.config.watch_ssh_keys {
            paths.extend(all_paths.ssh.into_iter());
        }
        if self.config.watch_systemd {
            paths.extend(all_paths.systemd.into_iter());
        }
        if self.config.watch_ld_preload {
            paths.extend(all_paths.ld_preload.into_iter());
        }

        paths
    }

    /// Watch SSH directories in all home directories
    fn watch_home_ssh_dirs(&self, watcher: &mut RecommendedWatcher) {
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                let ssh_path = entry.path().join(".ssh");
                if ssh_path.exists() {
                    if let Err(e) = watcher.watch(&ssh_path, RecursiveMode::NonRecursive) {
                        debug!("Could not watch {}: {}", ssh_path.display(), e);
                    } else {
                        debug!("Watching: {}", ssh_path.display());
                    }
                }
            }
        }
    }

    /// Create baseline hashes for all watched files
    fn create_baseline(&mut self, paths: &[PathBuf]) {
        for path in paths {
            if path.is_file() {
                if let Some(hash) = hash_file(path) {
                    self.file_hashes.insert(path.clone(), hash);
                }
            } else if path.is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let file_path = entry.path();
                        if file_path.is_file() {
                            if let Some(hash) = hash_file(&file_path) {
                                self.file_hashes.insert(file_path, hash);
                            }
                        }
                    }
                }
            }
        }

        debug!("Created baseline for {} files", self.file_hashes.len());
    }

    /// Handle a file system event
    async fn handle_event(&mut self, event: Event) {
        let (event_type, paths) = match event.kind {
            EventKind::Create(_) => (FileEventType::Created, event.paths),
            EventKind::Modify(_) => (FileEventType::Modified, event.paths),
            EventKind::Remove(_) => (FileEventType::Deleted, event.paths),
            _ => return,
        };

        for path in paths {
            // Determine threat type based on path
            let threat_type = self.classify_path(&path);
            if threat_type.is_none() {
                continue;
            }
            let threat_type = threat_type.unwrap();

            // Check if this is a significant change
            let (severity, description) = self.analyze_change(&path, &event_type, &threat_type);

            // Get old and new hashes
            let old_hash = self.file_hashes.get(&path).cloned();
            let new_hash = if event_type != FileEventType::Deleted {
                hash_file(&path)
            } else {
                None
            };

            // Update baseline
            if let Some(ref hash) = new_hash {
                self.file_hashes.insert(path.clone(), hash.clone());
            } else if event_type == FileEventType::Deleted {
                self.file_hashes.remove(&path);
            }

            // Skip if file unchanged
            if event_type == FileEventType::Modified && old_hash == new_hash {
                continue;
            }

            // Create detection event
            let file_info = FileInfo {
                path: path.clone(),
                event_type: event_type.clone(),
                old_content_hash: old_hash,
                new_content_hash: new_hash,
            };

            let event = DetectionEvent::new(
                DetectionSource::PersistenceMonitor,
                threat_type,
                severity,
                description.clone(),
            )
            .with_file(file_info);

            warn!(
                path = %path.display(),
                event_type = ?event_type,
                severity = ?severity,
                "Detection: {}", description
            );

            if let Err(e) = self.event_tx.send(event).await {
                error!("Failed to send detection event: {}", e);
            }
        }
    }

    /// Classify what type of persistence mechanism a path represents
    fn classify_path(&self, path: &Path) -> Option<ThreatType> {
        let path_str = path.to_string_lossy();

        if path_str.contains("cron") || path_str.contains("/var/spool/cron") {
            if self.config.watch_crontab {
                return Some(ThreatType::CronModification);
            }
        }

        if path_str.contains(".ssh") || path_str.contains("authorized_keys") {
            if self.config.watch_ssh_keys {
                return Some(ThreatType::SshKeyModification);
            }
        }

        if path_str.contains("systemd") && path_str.ends_with(".service") {
            if self.config.watch_systemd {
                return Some(ThreatType::SystemdModification);
            }
        }

        if path_str.contains("ld.so.preload") {
            if self.config.watch_ld_preload {
                return Some(ThreatType::LdPreloadModification);
            }
        }

        None
    }

    /// Analyze a change and determine severity
    fn analyze_change(
        &self,
        path: &Path,
        event_type: &FileEventType,
        threat_type: &ThreatType,
    ) -> (Severity, String) {
        let path_str = path.to_string_lossy();

        match threat_type {
            ThreatType::SshKeyModification => {
                let severity = if path_str.contains("root") {
                    Severity::Critical
                } else {
                    Severity::High
                };
                let desc = format!(
                    "SSH key {:?}: {}",
                    event_type,
                    path.display()
                );
                (severity, desc)
            }

            ThreatType::CronModification => {
                // Check for suspicious patterns in new cron content
                let content = fs::read_to_string(path).unwrap_or_default();
                let suspicious = content.contains("curl")
                    || content.contains("wget")
                    || content.contains("base64")
                    || content.contains("/tmp/")
                    || content.contains("/dev/shm");

                let severity = if suspicious {
                    Severity::Critical
                } else {
                    Severity::Medium
                };
                let desc = format!(
                    "Cron {:?}: {}{}",
                    event_type,
                    path.display(),
                    if suspicious { " (suspicious content)" } else { "" }
                );
                (severity, desc)
            }

            ThreatType::SystemdModification => {
                let severity = Severity::High;
                let desc = format!(
                    "Systemd service {:?}: {}",
                    event_type,
                    path.display()
                );
                (severity, desc)
            }

            ThreatType::LdPreloadModification => {
                // ld.so.preload modification is almost always malicious
                let severity = Severity::Critical;
                let desc = format!(
                    "ld.so.preload {:?}: {} - potential library injection attack",
                    event_type,
                    path.display()
                );
                (severity, desc)
            }

            _ => (
                Severity::Medium,
                format!("Persistence mechanism {:?}: {}", event_type, path.display()),
            ),
        }
    }
}

/// Simple hash function for file content
fn hash_file(path: &Path) -> Option<String> {
    let content = fs::read(path).ok()?;

    // Simple FNV-1a hash for performance
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in content {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    Some(format!("{:016x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_file() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "test content").unwrap();

        let hash1 = hash_file(temp.path());
        assert!(hash1.is_some());

        // Same content should give same hash
        let mut temp2 = NamedTempFile::new().unwrap();
        writeln!(temp2, "test content").unwrap();
        let hash2 = hash_file(temp2.path());
        assert_eq!(hash1, hash2);

        // Different content should give different hash
        let mut temp3 = NamedTempFile::new().unwrap();
        writeln!(temp3, "different content").unwrap();
        let hash3 = hash_file(temp3.path());
        assert_ne!(hash1, hash3);
    }
}
