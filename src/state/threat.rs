//! Threat registry for correlation and tracking.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::time::Duration;

use crate::detection::{DetectionSource, Severity, ThreatType};

/// Unique identifier for a threat entry.
pub type ThreatId = String;

/// Information about a tracked threat.
#[derive(Debug, Clone)]
pub struct ThreatEntry {
    /// Unique identifier
    pub id: ThreatId,
    /// Type of threat
    pub threat_type: ThreatType,
    /// Severity level
    pub severity: Severity,
    /// Source that detected this threat
    pub source: DetectionSource,
    /// Associated process ID (if any)
    pub pid: Option<u32>,
    /// Associated file path (if any)
    pub file_path: Option<String>,
    /// Associated remote address (if any)
    pub remote_addr: Option<String>,
    /// When the threat was first detected
    pub first_seen: DateTime<Utc>,
    /// When the threat was last seen
    pub last_seen: DateTime<Utc>,
    /// Number of times this threat has been seen
    pub occurrence_count: u64,
    /// Whether action has been taken
    pub action_taken: bool,
    /// Description of the action taken
    pub action_description: Option<String>,
    /// Custom metadata for correlation
    pub metadata: HashMap<String, String>,
    /// Expiration time (for auto-cleanup)
    pub expires_at: Option<DateTime<Utc>>,
}

impl ThreatEntry {
    /// Create a new threat entry.
    pub fn new(
        threat_type: ThreatType,
        severity: Severity,
        source: DetectionSource,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: generate_threat_id(),
            threat_type,
            severity,
            source,
            pid: None,
            file_path: None,
            remote_addr: None,
            first_seen: now,
            last_seen: now,
            occurrence_count: 1,
            action_taken: false,
            action_description: None,
            metadata: HashMap::new(),
            expires_at: None,
        }
    }

    /// Set process ID.
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set file path.
    pub fn with_file(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Set remote address.
    pub fn with_remote(mut self, addr: impl Into<String>) -> Self {
        self.remote_addr = Some(addr.into());
        self
    }

    /// Set expiration time.
    pub fn with_ttl(mut self, ttl_secs: i64) -> Self {
        self.expires_at = Some(Utc::now() + ChronoDuration::seconds(ttl_secs));
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Increment occurrence count and update last seen.
    pub fn record_occurrence(&mut self) {
        self.occurrence_count += 1;
        self.last_seen = Utc::now();
    }

    /// Record that an action was taken.
    pub fn record_action(&mut self, description: impl Into<String>) {
        self.action_taken = true;
        self.action_description = Some(description.into());
    }

    /// Check if this threat has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() > exp)
            .unwrap_or(false)
    }

    /// Calculate how long since the threat was last seen.
    pub fn age(&self) -> Duration {
        let now = Utc::now();
        (now - self.last_seen).to_std().unwrap_or(Duration::ZERO)
    }

    /// Calculate the total duration of this threat.
    pub fn duration(&self) -> Duration {
        (self.last_seen - self.first_seen)
            .to_std()
            .unwrap_or(Duration::ZERO)
    }
}

/// Generate a unique threat ID using atomic counter and random bytes.
fn generate_threat_id() -> ThreatId {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Atomic counter ensures uniqueness even for same-nanosecond calls
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Use getrandom for cryptographic randomness if available, fallback to mixing
    let random_part: u32 = {
        let mut buf = [0u8; 4];
        if getrandom::getrandom(&mut buf).is_ok() {
            u32::from_ne_bytes(buf)
        } else {
            // Fallback: mix counter, pid, and time
            let mix = counter
                .wrapping_mul(0x517cc1b727220a95)
                .wrapping_add(std::process::id() as u64)
                .wrapping_mul(0x2545f4914f6cdd1d);
            mix as u32
        }
    };

    format!(
        "threat-{:016x}-{:04x}-{:08x}",
        now.as_nanos() as u64,
        counter & 0xFFFF,
        random_part
    )
}

/// Key for deduplicating similar threats.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreatKey {
    pub threat_type: String,
    pub source: String,
    pub pid: Option<u32>,
    pub file_path: Option<String>,
    pub remote_addr: Option<String>,
}

impl ThreatKey {
    /// Create a key from a threat entry.
    pub fn from_entry(entry: &ThreatEntry) -> Self {
        Self {
            threat_type: format!("{:?}", entry.threat_type),
            source: format!("{:?}", entry.source),
            pid: entry.pid,
            file_path: entry.file_path.clone(),
            remote_addr: entry.remote_addr.clone(),
        }
    }
}

/// Concurrent registry of threats for correlation.
#[derive(Debug)]
pub struct ThreatRegistry {
    /// Map of threat ID to threat entry
    threats: DashMap<ThreatId, ThreatEntry>,
    /// Map of dedup key to threat ID for finding similar threats
    dedup_index: DashMap<ThreatKey, ThreatId>,
    /// Default TTL for threats
    default_ttl_secs: i64,
}

impl ThreatRegistry {
    /// Create a new threat registry.
    pub fn new() -> Self {
        Self {
            threats: DashMap::new(),
            dedup_index: DashMap::new(),
            default_ttl_secs: 3600, // 1 hour default
        }
    }

    /// Create with custom TTL.
    pub fn with_ttl(ttl_secs: i64) -> Self {
        Self {
            threats: DashMap::new(),
            dedup_index: DashMap::new(),
            default_ttl_secs: ttl_secs,
        }
    }

    /// Insert a new threat or update existing.
    /// Returns the threat ID.
    pub fn insert(&self, mut entry: ThreatEntry) -> ThreatId {
        let key = ThreatKey::from_entry(&entry);

        // Check if we already have this threat
        if let Some(existing_id) = self.dedup_index.get(&key) {
            let id = existing_id.clone();
            if let Some(mut existing) = self.threats.get_mut(&id) {
                existing.record_occurrence();
                // Escalate severity if needed
                if entry.severity > existing.severity {
                    existing.severity = entry.severity;
                }
            }
            return id;
        }

        // Set TTL if not already set
        if entry.expires_at.is_none() {
            entry.expires_at = Some(Utc::now() + ChronoDuration::seconds(self.default_ttl_secs));
        }

        let id = entry.id.clone();
        self.dedup_index.insert(key, id.clone());
        self.threats.insert(id.clone(), entry);
        id
    }

    /// Get a threat by ID.
    pub fn get(&self, id: &ThreatId) -> Option<ThreatEntry> {
        self.threats.get(id).map(|e| e.clone())
    }

    /// Remove a threat by ID.
    pub fn remove(&self, id: &ThreatId) -> Option<ThreatEntry> {
        if let Some((_, entry)) = self.threats.remove(id) {
            let key = ThreatKey::from_entry(&entry);
            self.dedup_index.remove(&key);
            Some(entry)
        } else {
            None
        }
    }

    /// Get the number of tracked threats.
    pub fn len(&self) -> usize {
        self.threats.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.threats.is_empty()
    }

    /// Get all threats matching a predicate.
    pub fn filter<F>(&self, predicate: F) -> Vec<ThreatEntry>
    where
        F: Fn(&ThreatEntry) -> bool,
    {
        self.threats
            .iter()
            .filter(|e| predicate(e.value()))
            .map(|e| e.clone())
            .collect()
    }

    /// Get threats by type.
    pub fn by_type(&self, threat_type: &ThreatType) -> Vec<ThreatEntry> {
        self.filter(|e| &e.threat_type == threat_type)
    }

    /// Get threats by severity.
    pub fn by_severity(&self, severity: Severity) -> Vec<ThreatEntry> {
        self.filter(|e| e.severity >= severity)
    }

    /// Get threats by source.
    pub fn by_source(&self, source: &DetectionSource) -> Vec<ThreatEntry> {
        self.filter(|e| &e.source == source)
    }

    /// Get threats associated with a PID.
    pub fn by_pid(&self, pid: u32) -> Vec<ThreatEntry> {
        self.filter(|e| e.pid == Some(pid))
    }

    /// Get active (not expired) threats.
    pub fn active_threats(&self) -> Vec<ThreatEntry> {
        self.filter(|e| !e.is_expired())
    }

    /// Get threats seen in the last N seconds.
    pub fn recent_threats(&self, seconds: i64) -> Vec<ThreatEntry> {
        let cutoff = Utc::now() - ChronoDuration::seconds(seconds);
        self.filter(|e| e.last_seen > cutoff)
    }

    /// Clean up expired threats.
    pub fn cleanup_expired(&self) {
        let expired_ids: Vec<ThreatId> = self
            .threats
            .iter()
            .filter(|e| e.is_expired())
            .map(|e| e.id.clone())
            .collect();

        for id in expired_ids {
            self.remove(&id);
        }
    }

    /// Record that an action was taken for a threat.
    pub fn record_action(&self, id: &ThreatId, description: impl Into<String>) {
        if let Some(mut entry) = self.threats.get_mut(id) {
            entry.record_action(description);
        }
    }

    /// Get summary statistics.
    pub fn stats(&self) -> ThreatStats {
        let mut by_severity = HashMap::new();
        let mut by_type = HashMap::new();
        let mut by_source = HashMap::new();
        let mut total_occurrences = 0u64;

        for entry in self.threats.iter() {
            *by_severity.entry(format!("{:?}", entry.severity)).or_insert(0) += 1;
            *by_type.entry(format!("{:?}", entry.threat_type)).or_insert(0) += 1;
            *by_source.entry(format!("{:?}", entry.source)).or_insert(0) += 1;
            total_occurrences += entry.occurrence_count;
        }

        ThreatStats {
            total_threats: self.threats.len(),
            total_occurrences,
            by_severity,
            by_type,
            by_source,
        }
    }
}

impl Default for ThreatRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about tracked threats.
#[derive(Debug, Clone)]
pub struct ThreatStats {
    pub total_threats: usize,
    pub total_occurrences: u64,
    pub by_severity: HashMap<String, usize>,
    pub by_type: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_entry_creation() {
        let entry = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::High,
            DetectionSource::ProcessMonitor,
        );

        assert_eq!(entry.threat_type, ThreatType::Cryptominer);
        assert_eq!(entry.severity, Severity::High);
        assert_eq!(entry.occurrence_count, 1);
        assert!(!entry.action_taken);
    }

    #[test]
    fn test_threat_registry_insert() {
        let registry = ThreatRegistry::new();
        let entry = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::High,
            DetectionSource::ProcessMonitor,
        )
        .with_pid(1234);

        let id = registry.insert(entry);
        assert!(!id.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_threat_deduplication() {
        let registry = ThreatRegistry::new();

        // Insert same threat twice
        let entry1 = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::High,
            DetectionSource::ProcessMonitor,
        )
        .with_pid(1234);

        let entry2 = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::High,
            DetectionSource::ProcessMonitor,
        )
        .with_pid(1234);

        let id1 = registry.insert(entry1);
        let id2 = registry.insert(entry2);

        // Should be deduplicated to same ID
        assert_eq!(id1, id2);
        assert_eq!(registry.len(), 1);

        // Occurrence count should be 2
        let threat = registry.get(&id1).unwrap();
        assert_eq!(threat.occurrence_count, 2);
    }

    #[test]
    fn test_threat_severity_escalation() {
        let registry = ThreatRegistry::new();

        let entry1 = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::Medium,
            DetectionSource::ProcessMonitor,
        )
        .with_pid(1234);

        let entry2 = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::Critical,
            DetectionSource::ProcessMonitor,
        )
        .with_pid(1234);

        let id = registry.insert(entry1);
        registry.insert(entry2);

        let threat = registry.get(&id).unwrap();
        assert_eq!(threat.severity, Severity::Critical);
    }

    #[test]
    fn test_threat_filtering() {
        let registry = ThreatRegistry::new();

        registry.insert(
            ThreatEntry::new(ThreatType::Cryptominer, Severity::High, DetectionSource::ProcessMonitor)
                .with_pid(100),
        );
        registry.insert(
            ThreatEntry::new(ThreatType::Webshell, Severity::Critical, DetectionSource::FileMonitor)
                .with_pid(200),
        );
        registry.insert(
            ThreatEntry::new(ThreatType::C2Connection, Severity::High, DetectionSource::NetworkMonitor)
                .with_pid(100),
        );

        let high_threats = registry.by_severity(Severity::High);
        assert_eq!(high_threats.len(), 3);

        let pid100_threats = registry.by_pid(100);
        assert_eq!(pid100_threats.len(), 2);

        let webshells = registry.by_type(&ThreatType::Webshell);
        assert_eq!(webshells.len(), 1);
    }

    #[test]
    fn test_threat_expiration() {
        let registry = ThreatRegistry::with_ttl(1); // 1 second TTL

        let entry = ThreatEntry::new(
            ThreatType::Cryptominer,
            Severity::High,
            DetectionSource::ProcessMonitor,
        );
        registry.insert(entry);

        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));

        registry.cleanup_expired();
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_threat_id_uniqueness() {
        use std::collections::HashSet;

        // Generate many threat IDs rapidly and verify they're all unique
        let mut ids: HashSet<ThreatId> = HashSet::new();
        let count = 1000;

        for _ in 0..count {
            let id = generate_threat_id();
            assert!(ids.insert(id.clone()), "Duplicate threat ID generated: {}", id);
        }

        assert_eq!(ids.len(), count);
    }

    #[test]
    fn test_threat_id_format() {
        let id = generate_threat_id();

        // Verify format: threat-{16 hex}-{4 hex}-{8 hex}
        assert!(id.starts_with("threat-"));
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "threat");
        assert_eq!(parts[1].len(), 16); // timestamp
        assert_eq!(parts[2].len(), 4);  // counter
        assert_eq!(parts[3].len(), 8);  // random

        // All parts after "threat-" should be valid hex
        for i in 1..4 {
            assert!(parts[i].chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
