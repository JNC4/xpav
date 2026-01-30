//! Unified state store for cross-monitor coordination.
//!
//! This module provides a centralized state store that enables:
//! - Shared process registry for deduplication
//! - Connection tracking across monitors
//! - Threat correlation data
//! - Event deduplication with TTL

mod connection;
pub mod dedup;
mod process;
mod threat;

pub use connection::{ConnectionRegistry, ConnectionState};
pub use dedup::{DedupEntry, EventDeduplicator};
pub use process::{ProcessEntry, ProcessRegistry};
pub use threat::{ThreatEntry, ThreatRegistry};

use std::sync::Arc;

/// Central state store shared across all monitors.
///
/// This store provides concurrent-safe access to:
/// - Process information and tracking
/// - Network connection state
/// - Threat correlation data
/// - Event deduplication
#[derive(Debug)]
pub struct StateStore {
    /// Registry of known processes
    pub processes: ProcessRegistry,
    /// Registry of network connections
    pub connections: ConnectionRegistry,
    /// Registry of detected threats for correlation
    pub threats: ThreatRegistry,
    /// Event deduplication with TTL
    pub dedup: EventDeduplicator,
}

impl StateStore {
    /// Create a new state store with default settings.
    pub fn new() -> Self {
        Self {
            processes: ProcessRegistry::new(),
            connections: ConnectionRegistry::new(),
            threats: ThreatRegistry::new(),
            dedup: EventDeduplicator::new(),
        }
    }

    /// Create a new state store with custom TTL settings.
    pub fn with_config(dedup_ttl_secs: u64, max_dedup_entries: usize) -> Self {
        Self {
            processes: ProcessRegistry::new(),
            connections: ConnectionRegistry::new(),
            threats: ThreatRegistry::new(),
            dedup: EventDeduplicator::with_config(dedup_ttl_secs, max_dedup_entries),
        }
    }

    /// Create a shared reference to the state store.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Clean up expired entries across all registries.
    pub fn cleanup_expired(&self) {
        self.processes.cleanup_stale();
        self.connections.cleanup_stale();
        self.threats.cleanup_expired();
        self.dedup.cleanup_expired();
    }

    /// Get statistics about the state store.
    pub fn stats(&self) -> StateStats {
        StateStats {
            process_count: self.processes.len(),
            connection_count: self.connections.len(),
            threat_count: self.threats.len(),
            dedup_count: self.dedup.len(),
        }
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the state store.
#[derive(Debug, Clone)]
pub struct StateStats {
    pub process_count: usize,
    pub connection_count: usize,
    pub threat_count: usize,
    pub dedup_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_store_creation() {
        let store = StateStore::new();
        let stats = store.stats();
        assert_eq!(stats.process_count, 0);
        assert_eq!(stats.connection_count, 0);
        assert_eq!(stats.threat_count, 0);
        assert_eq!(stats.dedup_count, 0);
    }

    #[test]
    fn test_state_store_shared() {
        let store = StateStore::new().shared();
        assert_eq!(Arc::strong_count(&store), 1);
        let store2 = Arc::clone(&store);
        assert_eq!(Arc::strong_count(&store), 2);
        drop(store2);
        assert_eq!(Arc::strong_count(&store), 1);
    }
}
