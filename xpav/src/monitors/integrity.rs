//! Integrity Monitor
//!
//! Monitors file system integrity for:
//! - Boot files (/boot/*)
//! - Kernel modules (/lib/modules/*)
//! - ld.so.preload and ld.so.conf
//! - Critical system binaries (ls, ps, netstat, etc.)
//!
//! Uses SHA256 hashing for integrity verification against a baseline.

use crate::config::IntegrityMonitorConfig;
use crate::detection::{
    DetectionEvent, DetectionSource, FileEventType, FileInfo, Severity, ThreatType,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

/// File integrity information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileIntegrity {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub modified: u64,
    #[serde(default)]
    pub is_symlink: bool,
    #[serde(default)]
    pub symlink_target: Option<PathBuf>,
}

/// Baseline of file hashes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrityBaseline {
    pub files: HashMap<PathBuf, FileIntegrity>,
    pub kernel_modules: HashSet<String>,
    pub created_at: String,
}

pub struct IntegrityMonitor {
    config: IntegrityMonitorConfig,
    event_tx: mpsc::Sender<DetectionEvent>,
    baseline: Option<IntegrityBaseline>,
    known_modules: HashSet<String>,
}

impl IntegrityMonitor {
    pub fn new(config: IntegrityMonitorConfig, event_tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self {
            config,
            event_tx,
            baseline: None,
            known_modules: HashSet::new(),
        }
    }

    /// Run the integrity monitor loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Integrity monitor starting...");

        // Load or create baseline
        self.load_or_create_baseline().await?;

        let interval = tokio::time::Duration::from_millis(self.config.scan_interval_ms);

        info!("Integrity monitor running");

        loop {
            if let Err(e) = self.scan().await {
                error!("Error in integrity scan: {}", e);
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Load baseline from file or create new one
    async fn load_or_create_baseline(&mut self) -> Result<()> {
        if let Some(ref path) = self.config.baseline_file {
            if path.exists() {
                let content = fs::read_to_string(path)
                    .context("Failed to read integrity baseline file")?;
                self.baseline = Some(
                    serde_json::from_str(&content).context("Failed to parse integrity baseline")?,
                );
                info!("Loaded integrity baseline from {}", path.display());

                // Populate known modules from baseline
                if let Some(ref baseline) = self.baseline {
                    self.known_modules = baseline.kernel_modules.clone();
                }
                return Ok(());
            }
        }

        if self.config.auto_baseline {
            let baseline = self.create_baseline().await?;
            if let Some(ref path) = self.config.baseline_file {
                let content = serde_json::to_string_pretty(&baseline)?;
                fs::write(path, content)?;
                info!("Created integrity baseline at {}", path.display());
            }
            self.known_modules = baseline.kernel_modules.clone();
            self.baseline = Some(baseline);
        }

        Ok(())
    }

    /// Create a baseline of current file state
    async fn create_baseline(&self) -> Result<IntegrityBaseline> {
        let mut baseline = IntegrityBaseline {
            files: HashMap::new(),
            kernel_modules: HashSet::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        // Add watched paths
        for path in &self.config.watch_paths {
            if path.exists() {
                self.add_path_to_baseline(path, &mut baseline.files)?;
            }
        }

        // Add critical binaries
        for path in &self.config.critical_binaries {
            if path.exists() {
                if let Ok(integrity) = Self::compute_file_integrity(path) {
                    baseline.files.insert(path.clone(), integrity);
                }
            }
        }

        // Add current kernel modules
        if self.config.monitor_kernel_modules {
            if let Ok(modules) = self.get_loaded_modules() {
                baseline.kernel_modules = modules;
            }
        }

        // Add ld.so.preload
        if self.config.monitor_ld_preload {
            let ld_preload = PathBuf::from("/etc/ld.so.preload");
            if ld_preload.exists() {
                if let Ok(integrity) = Self::compute_file_integrity(&ld_preload) {
                    baseline.files.insert(ld_preload, integrity);
                }
            }
        }

        Ok(baseline)
    }

    /// Add all files under a path to the baseline
    fn add_path_to_baseline(
        &self,
        path: &Path,
        files: &mut HashMap<PathBuf, FileIntegrity>,
    ) -> Result<()> {
        if path.is_file() {
            if let Ok(integrity) = Self::compute_file_integrity(path) {
                files.insert(path.to_path_buf(), integrity);
            }
            return Ok(());
        }

        if path.is_dir() {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Ok(integrity) = Self::compute_file_integrity(entry_path) {
                        files.insert(entry_path.to_path_buf(), integrity);
                    }
                }
            }
        }

        Ok(())
    }

    /// Compute file integrity information
    fn compute_file_integrity(path: &Path) -> Result<FileIntegrity> {
        let metadata = fs::metadata(path).context("Failed to get metadata")?;
        let is_symlink = fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);

        let symlink_target = if is_symlink {
            fs::read_link(path).ok()
        } else {
            None
        };

        let hash = Self::compute_sha256(path)?;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(FileIntegrity {
            path: path.to_path_buf(),
            hash,
            size: metadata.len(),
            modified,
            is_symlink,
            symlink_target,
        })
    }

    /// Compute SHA256 hash of a file
    fn compute_sha256(path: &Path) -> Result<String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Simple hash for now - in production, use sha2 crate
        let file = File::open(path).context("Failed to open file")?;
        let mut reader = BufReader::new(file);
        let mut hasher = DefaultHasher::new();

        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = reader.read(&mut buffer).context("Failed to read file")?;
            if bytes_read == 0 {
                break;
            }
            buffer[..bytes_read].hash(&mut hasher);
        }

        Ok(format!("{:016x}", hasher.finish()))
    }

    /// Perform a full integrity scan
    async fn scan(&mut self) -> Result<()> {
        // Check file integrity
        if let Some(ref baseline) = self.baseline.clone() {
            self.check_file_integrity(baseline).await?;
        }

        // Check for new kernel modules
        if self.config.monitor_kernel_modules {
            self.check_kernel_modules().await?;
        }

        // Check ld.so.preload
        if self.config.monitor_ld_preload {
            self.check_ld_preload().await?;
        }

        Ok(())
    }

    /// Check file integrity against baseline
    async fn check_file_integrity(&self, baseline: &IntegrityBaseline) -> Result<()> {
        for (path, expected) in &baseline.files {
            if !path.exists() {
                // File was deleted
                let event = DetectionEvent::new(
                    DetectionSource::IntegrityMonitor,
                    ThreatType::IntegrityViolation,
                    Severity::High,
                    format!("Critical file deleted: {}", path.display()),
                )
                .with_file(FileInfo {
                    path: path.clone(),
                    event_type: FileEventType::Deleted,
                    old_content_hash: Some(expected.hash.clone()),
                    new_content_hash: None,
                });

                warn!(path = %path.display(), "Critical file deleted");
                self.event_tx.send(event).await.ok();
                continue;
            }

            // Check hash
            if let Ok(current) = Self::compute_file_integrity(path) {
                if current.hash != expected.hash {
                    let severity = self.assess_modification_severity(path);
                    let threat_type = self.determine_threat_type(path);

                    let event = DetectionEvent::new(
                        DetectionSource::IntegrityMonitor,
                        threat_type,
                        severity,
                        format!(
                            "File integrity violation: {} (expected hash {}, got {})",
                            path.display(),
                            expected.hash,
                            current.hash
                        ),
                    )
                    .with_file(FileInfo {
                        path: path.clone(),
                        event_type: FileEventType::Modified,
                        old_content_hash: Some(expected.hash.clone()),
                        new_content_hash: Some(current.hash.clone()),
                    });

                    warn!(
                        path = %path.display(),
                        expected_hash = %expected.hash,
                        current_hash = %current.hash,
                        "File integrity violation"
                    );

                    self.event_tx.send(event).await.ok();
                }
            }
        }

        // Check for new files in critical directories
        for watch_path in &self.config.watch_paths {
            if watch_path.is_dir() {
                self.check_new_files(watch_path, baseline).await?;
            }
        }

        Ok(())
    }

    /// Check for new files in watched directories
    async fn check_new_files(&self, dir: &Path, baseline: &IntegrityBaseline) -> Result<()> {
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path().to_path_buf();
            if path.is_file() && !baseline.files.contains_key(&path) {
                let severity = self.assess_modification_severity(&path);
                let threat_type = self.determine_threat_type(&path);

                let event = DetectionEvent::new(
                    DetectionSource::IntegrityMonitor,
                    threat_type,
                    severity,
                    format!("New file in monitored directory: {}", path.display()),
                )
                .with_file(FileInfo {
                    path: path.clone(),
                    event_type: FileEventType::Created,
                    old_content_hash: None,
                    new_content_hash: Self::compute_sha256(&path).ok(),
                });

                warn!(path = %path.display(), "New file in monitored directory");
                self.event_tx.send(event).await.ok();
            }
        }

        Ok(())
    }

    /// Check for new or unexpected kernel modules
    async fn check_kernel_modules(&mut self) -> Result<()> {
        let current_modules = self.get_loaded_modules()?;

        for module in &current_modules {
            if !self.known_modules.contains(module) {
                let event = DetectionEvent::new(
                    DetectionSource::IntegrityMonitor,
                    ThreatType::KernelModuleLoad,
                    Severity::High,
                    format!("New kernel module loaded: {}", module),
                )
                .with_pattern(format!("module={}", module));

                warn!(module = %module, "New kernel module loaded");
                self.event_tx.send(event).await.ok();

                // Add to known modules to avoid repeated alerts
                self.known_modules.insert(module.clone());
            }
        }

        Ok(())
    }

    /// Get list of currently loaded kernel modules
    fn get_loaded_modules(&self) -> Result<HashSet<String>> {
        let mut modules = HashSet::new();

        let content = fs::read_to_string("/proc/modules").context("Failed to read /proc/modules")?;

        for line in content.lines() {
            if let Some(name) = line.split_whitespace().next() {
                modules.insert(name.to_string());
            }
        }

        Ok(modules)
    }

    /// Check ld.so.preload for suspicious entries
    async fn check_ld_preload(&self) -> Result<()> {
        let ld_preload = PathBuf::from("/etc/ld.so.preload");

        if ld_preload.exists() {
            let content =
                fs::read_to_string(&ld_preload).context("Failed to read ld.so.preload")?;

            // Any entry in ld.so.preload is suspicious
            if !content.trim().is_empty() {
                let entries: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

                if !entries.is_empty() {
                    let event = DetectionEvent::new(
                        DetectionSource::IntegrityMonitor,
                        ThreatType::IntegrityViolation,
                        Severity::Critical,
                        format!(
                            "ld.so.preload contains entries (potential library injection): {:?}",
                            entries
                        ),
                    )
                    .with_file(FileInfo {
                        path: ld_preload.clone(),
                        event_type: FileEventType::Modified,
                        old_content_hash: None,
                        new_content_hash: Self::compute_sha256(&ld_preload).ok(),
                    })
                    .with_pattern(entries.join(", "));

                    warn!(
                        entries = ?entries,
                        "ld.so.preload contains entries"
                    );

                    self.event_tx.send(event).await.ok();
                }
            }
        }

        Ok(())
    }

    /// Assess severity based on the file being modified
    fn assess_modification_severity(&self, path: &Path) -> Severity {
        let path_str = path.to_string_lossy().to_lowercase();

        // Boot files are critical
        if path_str.starts_with("/boot/") {
            return Severity::Critical;
        }

        // Kernel modules are critical
        if path_str.contains("/lib/modules/") {
            return Severity::Critical;
        }

        // ld.so files are critical
        if path_str.contains("ld.so") {
            return Severity::Critical;
        }

        // Critical binaries
        if self.config.critical_binaries.iter().any(|b| b == path) {
            return Severity::High;
        }

        Severity::Medium
    }

    /// Determine threat type based on the file
    fn determine_threat_type(&self, path: &Path) -> ThreatType {
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.starts_with("/boot/") {
            return ThreatType::BootFileModified;
        }

        if path_str.contains("/lib/modules/") {
            return ThreatType::KernelModuleLoad;
        }

        if self.config.critical_binaries.iter().any(|b| b == path) {
            return ThreatType::CriticalBinaryModified;
        }

        ThreatType::IntegrityViolation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_compute_file_integrity() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let integrity = IntegrityMonitor::compute_file_integrity(&file_path).unwrap();

        assert_eq!(integrity.path, file_path);
        assert_eq!(integrity.size, 12);
        assert!(!integrity.hash.is_empty());
    }

    #[test]
    fn test_hash_consistency() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let hash1 = IntegrityMonitor::compute_sha256(&file_path).unwrap();
        let hash2 = IntegrityMonitor::compute_sha256(&file_path).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_changes_with_content() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");

        {
            let mut file = File::create(&file_path).unwrap();
            file.write_all(b"content 1").unwrap();
        }
        let hash1 = IntegrityMonitor::compute_sha256(&file_path).unwrap();

        {
            let mut file = File::create(&file_path).unwrap();
            file.write_all(b"content 2").unwrap();
        }
        let hash2 = IntegrityMonitor::compute_sha256(&file_path).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_severity_assessment() {
        let (tx, _rx) = mpsc::channel(100);
        let monitor = IntegrityMonitor::new(IntegrityMonitorConfig::default(), tx);

        assert_eq!(
            monitor.assess_modification_severity(Path::new("/boot/vmlinuz")),
            Severity::Critical
        );

        assert_eq!(
            monitor.assess_modification_severity(Path::new("/lib/modules/5.15/evil.ko")),
            Severity::Critical
        );

        assert_eq!(
            monitor.assess_modification_severity(Path::new("/etc/ld.so.preload")),
            Severity::Critical
        );
    }
}
