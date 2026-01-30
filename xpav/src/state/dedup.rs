//! Event deduplication with TTL.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use lru::LruCache;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// Entry in the deduplication cache.
#[derive(Debug, Clone)]
pub struct DedupEntry {
    /// When this entry was first seen
    pub first_seen: DateTime<Utc>,
    /// When this entry was last seen
    pub last_seen: DateTime<Utc>,
    /// Number of times this event has occurred
    pub count: u64,
    /// When this entry expires
    pub expires_at: DateTime<Utc>,
}

impl DedupEntry {
    /// Create a new dedup entry with the given TTL.
    pub fn new(ttl_secs: i64) -> Self {
        let now = Utc::now();
        Self {
            first_seen: now,
            last_seen: now,
            count: 1,
            expires_at: now + ChronoDuration::seconds(ttl_secs),
        }
    }

    /// Update the entry for a new occurrence.
    pub fn record_occurrence(&mut self, ttl_secs: i64) {
        let now = Utc::now();
        self.last_seen = now;
        self.count += 1;
        // Extend expiration on each occurrence
        self.expires_at = now + ChronoDuration::seconds(ttl_secs);
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Key for deduplication.
/// Uses a hash of the key fields for efficient storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DedupKey(u64);

impl DedupKey {
    /// Create a dedup key from multiple fields.
    pub fn new<H: Hash>(fields: &[H]) -> Self {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        for field in fields {
            field.hash(&mut hasher);
        }
        Self(hasher.finish())
    }

    /// Create from a single string.
    pub fn from_str(s: &str) -> Self {
        Self::new(&[s])
    }

    /// Create from source, type, and optional identifiers.
    pub fn from_event(source: &str, event_type: &str, identifier: Option<&str>) -> Self {
        match identifier {
            Some(id) => Self::new(&[source, event_type, id]),
            None => Self::new(&[source, event_type]),
        }
    }
}

/// Event deduplicator with TTL-based expiration.
/// Uses an LRU cache to bound memory usage.
pub struct EventDeduplicator {
    /// LRU cache of dedup entries
    cache: Mutex<LruCache<DedupKey, DedupEntry>>,
    /// Default TTL in seconds
    ttl_secs: i64,
}

impl std::fmt::Debug for EventDeduplicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventDeduplicator")
            .field("ttl_secs", &self.ttl_secs)
            .field("len", &self.len())
            .finish()
    }
}

impl EventDeduplicator {
    /// Create a new deduplicator with default settings.
    pub fn new() -> Self {
        Self::with_config(300, 10000) // 5 minute TTL, 10k max entries
    }

    /// Create with custom settings.
    pub fn with_config(ttl_secs: u64, max_entries: usize) -> Self {
        let capacity = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            ttl_secs: ttl_secs as i64,
        }
    }

    /// Check if an event should be deduplicated.
    /// Returns true if this is a new event (not seen recently).
    /// Returns false if this event should be suppressed (already seen).
    pub fn should_report(&self, key: DedupKey) -> bool {
        let mut cache = self.cache.lock().unwrap();

        if let Some(entry) = cache.get_mut(&key) {
            if entry.is_expired() {
                // Entry expired, treat as new
                *entry = DedupEntry::new(self.ttl_secs);
                true
            } else {
                // Entry still valid, suppress
                entry.record_occurrence(self.ttl_secs);
                false
            }
        } else {
            // New entry
            cache.put(key, DedupEntry::new(self.ttl_secs));
            true
        }
    }

    /// Check and report with custom TTL.
    pub fn should_report_with_ttl(&self, key: DedupKey, ttl_secs: i64) -> bool {
        let mut cache = self.cache.lock().unwrap();

        if let Some(entry) = cache.get_mut(&key) {
            if entry.is_expired() {
                *entry = DedupEntry::new(ttl_secs);
                true
            } else {
                entry.record_occurrence(ttl_secs);
                false
            }
        } else {
            cache.put(key, DedupEntry::new(ttl_secs));
            true
        }
    }

    /// Get the dedup entry for a key without modifying it.
    pub fn get(&self, key: &DedupKey) -> Option<DedupEntry> {
        let mut cache = self.cache.lock().unwrap();
        cache.peek(key).cloned()
    }

    /// Get the occurrence count for a key.
    pub fn occurrence_count(&self, key: &DedupKey) -> u64 {
        self.get(key).map(|e| e.count).unwrap_or(0)
    }

    /// Remove an entry from the cache.
    pub fn remove(&self, key: &DedupKey) -> Option<DedupEntry> {
        let mut cache = self.cache.lock().unwrap();
        cache.pop(key)
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clean up expired entries.
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.lock().unwrap();
        // LRU cache doesn't have a retain method, so we need to collect and remove
        let expired_keys: Vec<DedupKey> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            cache.pop(&key);
        }
    }

    /// Clear all entries.
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Get statistics about the deduplicator.
    pub fn stats(&self) -> DedupStats {
        let cache = self.cache.lock().unwrap();
        let mut total_occurrences = 0u64;
        let mut expired_count = 0usize;

        for (_, entry) in cache.iter() {
            total_occurrences += entry.count;
            if entry.is_expired() {
                expired_count += 1;
            }
        }

        DedupStats {
            entry_count: cache.len(),
            expired_count,
            total_occurrences,
            ttl_secs: self.ttl_secs,
        }
    }
}

impl Default for EventDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the deduplicator.
#[derive(Debug, Clone)]
pub struct DedupStats {
    pub entry_count: usize,
    pub expired_count: usize,
    pub total_occurrences: u64,
    pub ttl_secs: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_dedup_key_creation() {
        let key1 = DedupKey::from_str("test");
        let key2 = DedupKey::from_str("test");
        let key3 = DedupKey::from_str("other");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_dedup_key_from_event() {
        let key1 = DedupKey::from_event("process", "miner", Some("1234"));
        let key2 = DedupKey::from_event("process", "miner", Some("1234"));
        let key3 = DedupKey::from_event("process", "miner", Some("5678"));

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_deduplicator_new_event() {
        let dedup = EventDeduplicator::new();
        let key = DedupKey::from_str("test");

        // First occurrence should be reported
        assert!(dedup.should_report(key.clone()));

        // Second occurrence should be suppressed
        assert!(!dedup.should_report(key.clone()));

        // Count should be 2
        assert_eq!(dedup.occurrence_count(&key), 2);
    }

    #[test]
    fn test_deduplicator_expiration() {
        let dedup = EventDeduplicator::with_config(1, 100); // 1 second TTL
        let key = DedupKey::from_str("test");

        // First occurrence
        assert!(dedup.should_report(key.clone()));

        // Wait for expiration
        thread::sleep(Duration::from_secs(2));

        // Should be treated as new after expiration
        assert!(dedup.should_report(key.clone()));
    }

    #[test]
    fn test_deduplicator_lru_eviction() {
        let dedup = EventDeduplicator::with_config(300, 3); // Max 3 entries

        let key1 = DedupKey::from_str("test1");
        let key2 = DedupKey::from_str("test2");
        let key3 = DedupKey::from_str("test3");
        let key4 = DedupKey::from_str("test4");

        dedup.should_report(key1.clone());
        dedup.should_report(key2.clone());
        dedup.should_report(key3.clone());

        assert_eq!(dedup.len(), 3);

        // Adding a 4th should evict the least recently used (key1)
        dedup.should_report(key4.clone());

        assert_eq!(dedup.len(), 3);

        // key1 should be evicted, so it should be reported as new
        assert!(dedup.should_report(key1.clone()));
    }

    #[test]
    fn test_deduplicator_cleanup() {
        let dedup = EventDeduplicator::with_config(1, 100);

        let key1 = DedupKey::from_str("test1");
        let key2 = DedupKey::from_str("test2");

        dedup.should_report(key1.clone());

        // Wait for key1 to expire
        thread::sleep(Duration::from_secs(2));

        // Add key2 (won't be expired)
        dedup.should_report(key2.clone());

        assert_eq!(dedup.len(), 2);

        dedup.cleanup_expired();

        // Only key2 should remain
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn test_deduplicator_stats() {
        let dedup = EventDeduplicator::new();

        let key = DedupKey::from_str("test");
        dedup.should_report(key.clone());
        dedup.should_report(key.clone());
        dedup.should_report(key.clone());

        let stats = dedup.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.total_occurrences, 3);
    }
}
