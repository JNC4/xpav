//! Baseline persistence with atomic writes.
//!
//! This module provides safe, atomic file persistence for baselines.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Default directory for XPAV data.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/xpav";

/// Default directory for quarantined files.
pub const DEFAULT_QUARANTINE_DIR: &str = "/var/lib/xpav/quarantine";

/// Store for baseline data with atomic write support.
pub struct BaselineStore {
    /// Path to the baseline file
    path: PathBuf,
    /// Whether to create parent directories
    create_parents: bool,
}

impl BaselineStore {
    /// Create a new baseline store for the given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            create_parents: true,
        }
    }

    /// Create a store with default path for the given baseline name.
    pub fn with_name(name: &str) -> Self {
        let path = PathBuf::from(DEFAULT_DATA_DIR).join(format!("{}.json", name));
        Self::new(path)
    }

    /// Set whether to create parent directories on save.
    pub fn create_parents(mut self, create: bool) -> Self {
        self.create_parents = create;
        self
    }

    /// Get the path to the baseline file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the baseline file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Load the baseline from disk.
    pub fn load<T: DeserializeOwned>(&self) -> Result<T> {
        let file = File::open(&self.path)
            .with_context(|| format!("Failed to open baseline file: {}", self.path.display()))?;
        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)
            .with_context(|| format!("Failed to parse baseline file: {}", self.path.display()))?;
        Ok(data)
    }

    /// Load the baseline, or return a default value if it doesn't exist.
    pub fn load_or_default<T: DeserializeOwned + Default>(&self) -> T {
        self.load().unwrap_or_default()
    }

    /// Load the baseline, or create it with the given initializer.
    pub fn load_or_init<T, F>(&self, init: F) -> Result<T>
    where
        T: DeserializeOwned + Serialize,
        F: FnOnce() -> T,
    {
        if self.exists() {
            self.load()
        } else {
            let data = init();
            self.save(&data)?;
            Ok(data)
        }
    }

    /// Save the baseline to disk atomically.
    ///
    /// This writes to a temporary file first, then renames it to the target path.
    /// This ensures that the baseline file is never left in a partial state.
    pub fn save<T: Serialize>(&self, data: &T) -> Result<()> {
        // Create parent directories if needed
        if self.create_parents {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create directory: {}", parent.display())
                })?;
            }
        }

        // Write to temporary file
        let temp_path = self.path.with_extension("json.tmp");
        {
            let file = File::create(&temp_path).with_context(|| {
                format!("Failed to create temp file: {}", temp_path.display())
            })?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, data).with_context(|| {
                format!("Failed to serialize baseline to: {}", temp_path.display())
            })?;
            writer.flush()?;
            // Ensure data is synced to disk before rename for crash safety
            writer.get_ref().sync_all().with_context(|| {
                format!("Failed to sync temp file: {}", temp_path.display())
            })?;
        }

        // Atomically rename to target path
        fs::rename(&temp_path, &self.path).with_context(|| {
            format!(
                "Failed to rename {} to {}",
                temp_path.display(),
                self.path.display()
            )
        })?;

        Ok(())
    }

    /// Delete the baseline file.
    pub fn delete(&self) -> Result<()> {
        if self.exists() {
            fs::remove_file(&self.path)
                .with_context(|| format!("Failed to delete baseline: {}", self.path.display()))?;
        }
        Ok(())
    }
}

/// Ensure the XPAV data directories exist.
pub fn ensure_data_dirs() -> Result<()> {
    fs::create_dir_all(DEFAULT_DATA_DIR)
        .with_context(|| format!("Failed to create data directory: {}", DEFAULT_DATA_DIR))?;
    fs::create_dir_all(DEFAULT_QUARANTINE_DIR)
        .with_context(|| format!("Failed to create quarantine directory: {}", DEFAULT_QUARANTINE_DIR))?;
    Ok(())
}

/// Quarantine a file by moving it to the quarantine directory.
pub fn quarantine_file(path: &Path) -> Result<PathBuf> {
    ensure_data_dirs()?;

    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Add timestamp to avoid conflicts
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let quarantine_name = format!("{}_{}", timestamp, filename);
    let quarantine_path = PathBuf::from(DEFAULT_QUARANTINE_DIR).join(quarantine_name);

    fs::rename(path, &quarantine_path).with_context(|| {
        format!(
            "Failed to quarantine file {} to {}",
            path.display(),
            quarantine_path.display()
        )
    })?;

    Ok(quarantine_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
    struct TestBaseline {
        version: u32,
        items: Vec<String>,
    }

    #[test]
    fn test_baseline_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_baseline.json");

        let store = BaselineStore::new(&path);
        let baseline = TestBaseline {
            version: 1,
            items: vec!["item1".to_string(), "item2".to_string()],
        };

        store.save(&baseline).unwrap();
        assert!(store.exists());

        let loaded: TestBaseline = store.load().unwrap();
        assert_eq!(loaded, baseline);
    }

    #[test]
    fn test_baseline_load_or_default() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("nonexistent.json");

        let store = BaselineStore::new(&path);
        let loaded: TestBaseline = store.load_or_default();
        assert_eq!(loaded, TestBaseline::default());
    }

    #[test]
    fn test_baseline_load_or_init() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("init_baseline.json");

        let store = BaselineStore::new(&path);
        let loaded: TestBaseline = store
            .load_or_init(|| TestBaseline {
                version: 42,
                items: vec!["initialized".to_string()],
            })
            .unwrap();

        assert_eq!(loaded.version, 42);
        assert!(store.exists());
    }

    #[test]
    fn test_baseline_atomic_write() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("atomic.json");

        let store = BaselineStore::new(&path);
        let baseline = TestBaseline {
            version: 1,
            items: vec!["test".to_string()],
        };

        store.save(&baseline).unwrap();

        // Temp file should not exist after save
        let temp_path = path.with_extension("json.tmp");
        assert!(!temp_path.exists());
        assert!(path.exists());
    }

    #[test]
    fn test_baseline_creates_parents() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("deep/nested/dir/baseline.json");

        let store = BaselineStore::new(&path);
        let baseline = TestBaseline::default();

        store.save(&baseline).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_baseline_delete() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("delete_me.json");

        let store = BaselineStore::new(&path);
        store.save(&TestBaseline::default()).unwrap();
        assert!(store.exists());

        store.delete().unwrap();
        assert!(!store.exists());
    }
}
