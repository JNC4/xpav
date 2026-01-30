//! Process registry using DashMap for concurrent access.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Information about a tracked process.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name
    pub name: String,
    /// Full command line
    pub cmdline: String,
    /// Path to executable
    pub exe_path: Option<PathBuf>,
    /// Current working directory
    pub cwd: Option<PathBuf>,
    /// User ID
    pub uid: u32,
    /// When the process was first seen
    pub first_seen: DateTime<Utc>,
    /// When the process was last seen
    pub last_seen: DateTime<Utc>,
    /// Cumulative CPU time in jiffies
    pub cpu_time: u64,
    /// Previous CPU time for delta calculation
    pub prev_cpu_time: u64,
    /// Whether this process has been reported as suspicious
    pub reported: bool,
    /// Custom tags for tracking
    pub tags: Vec<String>,
}

impl ProcessEntry {
    /// Create a new process entry.
    pub fn new(
        pid: u32,
        ppid: u32,
        name: String,
        cmdline: String,
        exe_path: Option<PathBuf>,
        cwd: Option<PathBuf>,
        uid: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            pid,
            ppid,
            name,
            cmdline,
            exe_path,
            cwd,
            uid,
            first_seen: now,
            last_seen: now,
            cpu_time: 0,
            prev_cpu_time: 0,
            reported: false,
            tags: Vec::new(),
        }
    }

    /// Update the last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
    }

    /// Update CPU time and return the delta.
    pub fn update_cpu_time(&mut self, new_time: u64) -> u64 {
        self.prev_cpu_time = self.cpu_time;
        self.cpu_time = new_time;
        self.cpu_time.saturating_sub(self.prev_cpu_time)
    }

    /// Mark this process as reported.
    pub fn mark_reported(&mut self) {
        self.reported = true;
    }

    /// Add a tag to this process.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Check if process has a specific tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Calculate how long since the process was last seen.
    pub fn age(&self) -> Duration {
        let now = Utc::now();
        (now - self.last_seen).to_std().unwrap_or(Duration::ZERO)
    }
}

/// Concurrent registry of processes using DashMap.
#[derive(Debug)]
pub struct ProcessRegistry {
    /// Map of PID to process entry
    processes: DashMap<u32, ProcessEntry>,
    /// Stale threshold - processes not seen for this duration are considered stale
    stale_threshold: Duration,
}

impl ProcessRegistry {
    /// Create a new process registry.
    pub fn new() -> Self {
        Self {
            processes: DashMap::new(),
            stale_threshold: Duration::from_secs(60),
        }
    }

    /// Create a process registry with custom stale threshold.
    pub fn with_stale_threshold(stale_secs: u64) -> Self {
        Self {
            processes: DashMap::new(),
            stale_threshold: Duration::from_secs(stale_secs),
        }
    }

    /// Insert or update a process entry.
    pub fn upsert(&self, entry: ProcessEntry) {
        let pid = entry.pid;
        self.processes
            .entry(pid)
            .and_modify(|e| {
                e.last_seen = Utc::now();
                e.cmdline = entry.cmdline.clone();
                e.exe_path = entry.exe_path.clone();
                e.cwd = entry.cwd.clone();
            })
            .or_insert(entry);
    }

    /// Get a process entry by PID.
    pub fn get(&self, pid: u32) -> Option<ProcessEntry> {
        self.processes.get(&pid).map(|e| e.clone())
    }

    /// Check if a process exists.
    pub fn contains(&self, pid: u32) -> bool {
        self.processes.contains_key(&pid)
    }

    /// Remove a process entry.
    pub fn remove(&self, pid: u32) -> Option<ProcessEntry> {
        self.processes.remove(&pid).map(|(_, e)| e)
    }

    /// Mark a process as reported.
    pub fn mark_reported(&self, pid: u32) {
        if let Some(mut entry) = self.processes.get_mut(&pid) {
            entry.mark_reported();
        }
    }

    /// Check if a process has been reported.
    pub fn is_reported(&self, pid: u32) -> bool {
        self.processes
            .get(&pid)
            .map(|e| e.reported)
            .unwrap_or(false)
    }

    /// Update CPU time for a process and return the delta.
    pub fn update_cpu_time(&self, pid: u32, new_time: u64) -> Option<u64> {
        self.processes
            .get_mut(&pid)
            .map(|mut e| e.update_cpu_time(new_time))
    }

    /// Add a tag to a process.
    pub fn add_tag(&self, pid: u32, tag: impl Into<String>) {
        if let Some(mut entry) = self.processes.get_mut(&pid) {
            entry.add_tag(tag);
        }
    }

    /// Get the number of tracked processes.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// Get all PIDs.
    pub fn pids(&self) -> Vec<u32> {
        self.processes.iter().map(|e| *e.key()).collect()
    }

    /// Get all processes matching a predicate.
    pub fn filter<F>(&self, predicate: F) -> Vec<ProcessEntry>
    where
        F: Fn(&ProcessEntry) -> bool,
    {
        self.processes
            .iter()
            .filter(|e| predicate(e.value()))
            .map(|e| e.clone())
            .collect()
    }

    /// Remove stale processes (not seen recently).
    pub fn cleanup_stale(&self) {
        let now = Utc::now();
        self.processes.retain(|_, entry| {
            let age = (now - entry.last_seen).to_std().unwrap_or(Duration::ZERO);
            age < self.stale_threshold
        });
    }

    /// Remove processes that no longer exist in /proc.
    pub fn cleanup_dead(&self) {
        self.processes.retain(|pid, _| {
            std::path::Path::new(&format!("/proc/{}", pid)).exists()
        });
    }

    /// Get child processes of a given PID.
    pub fn children_of(&self, ppid: u32) -> Vec<ProcessEntry> {
        self.filter(|e| e.ppid == ppid)
    }

    /// Get process ancestry chain up to a given depth.
    pub fn ancestry(&self, pid: u32, max_depth: usize) -> Vec<ProcessEntry> {
        let mut chain = Vec::new();
        let mut current_pid = pid;

        for _ in 0..max_depth {
            if let Some(entry) = self.get(current_pid) {
                let ppid = entry.ppid;
                chain.push(entry);
                if ppid == 0 || ppid == current_pid {
                    break;
                }
                current_pid = ppid;
            } else {
                break;
            }
        }

        chain
    }
}

impl Default for ProcessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_entry_creation() {
        let entry = ProcessEntry::new(
            1234,
            1,
            "test".to_string(),
            "/usr/bin/test arg1 arg2".to_string(),
            Some(PathBuf::from("/usr/bin/test")),
            Some(PathBuf::from("/home/user")),
            1000,
        );

        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.ppid, 1);
        assert_eq!(entry.name, "test");
        assert!(!entry.reported);
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_process_registry_upsert() {
        let registry = ProcessRegistry::new();
        let entry = ProcessEntry::new(
            1234,
            1,
            "test".to_string(),
            "test".to_string(),
            None,
            None,
            1000,
        );

        registry.upsert(entry);
        assert!(registry.contains(1234));
        assert_eq!(registry.len(), 1);

        let retrieved = registry.get(1234).unwrap();
        assert_eq!(retrieved.name, "test");
    }

    #[test]
    fn test_process_registry_mark_reported() {
        let registry = ProcessRegistry::new();
        let entry = ProcessEntry::new(
            1234,
            1,
            "test".to_string(),
            "test".to_string(),
            None,
            None,
            1000,
        );

        registry.upsert(entry);
        assert!(!registry.is_reported(1234));

        registry.mark_reported(1234);
        assert!(registry.is_reported(1234));
    }

    #[test]
    fn test_process_cpu_time_tracking() {
        let registry = ProcessRegistry::new();
        let entry = ProcessEntry::new(
            1234,
            1,
            "test".to_string(),
            "test".to_string(),
            None,
            None,
            1000,
        );

        registry.upsert(entry);

        // First update
        let delta1 = registry.update_cpu_time(1234, 100).unwrap();
        assert_eq!(delta1, 100);

        // Second update
        let delta2 = registry.update_cpu_time(1234, 150).unwrap();
        assert_eq!(delta2, 50);
    }

    #[test]
    fn test_process_tags() {
        let registry = ProcessRegistry::new();
        let entry = ProcessEntry::new(
            1234,
            1,
            "test".to_string(),
            "test".to_string(),
            None,
            None,
            1000,
        );

        registry.upsert(entry);
        registry.add_tag(1234, "suspicious");
        registry.add_tag(1234, "miner");

        let retrieved = registry.get(1234).unwrap();
        assert!(retrieved.has_tag("suspicious"));
        assert!(retrieved.has_tag("miner"));
        assert!(!retrieved.has_tag("benign"));
    }

    #[test]
    fn test_ancestry_chain() {
        let registry = ProcessRegistry::new();

        // Create a process tree: init(1) -> bash(100) -> python(200) -> script(300)
        registry.upsert(ProcessEntry::new(1, 0, "init".to_string(), "init".to_string(), None, None, 0));
        registry.upsert(ProcessEntry::new(100, 1, "bash".to_string(), "bash".to_string(), None, None, 1000));
        registry.upsert(ProcessEntry::new(200, 100, "python".to_string(), "python".to_string(), None, None, 1000));
        registry.upsert(ProcessEntry::new(300, 200, "script".to_string(), "script".to_string(), None, None, 1000));

        let ancestry = registry.ancestry(300, 10);
        assert_eq!(ancestry.len(), 4);
        assert_eq!(ancestry[0].name, "script");
        assert_eq!(ancestry[1].name, "python");
        assert_eq!(ancestry[2].name, "bash");
        assert_eq!(ancestry[3].name, "init");
    }
}
