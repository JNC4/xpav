//! Event enrichment with additional context.

use crate::detection::DetectionEvent;
use crate::state::StateStore;
use std::sync::Arc;

/// Enriches detection events with additional context from the state store.
#[derive(Debug, Default)]
pub struct EventEnricher {
    /// Whether to add process ancestry
    add_ancestry: bool,
    /// Whether to add related connections
    add_connections: bool,
    /// Maximum ancestry depth
    max_ancestry_depth: usize,
}

impl EventEnricher {
    /// Create a new event enricher with default settings.
    pub fn new() -> Self {
        Self {
            add_ancestry: true,
            add_connections: true,
            max_ancestry_depth: 5,
        }
    }

    /// Set whether to add process ancestry.
    pub fn with_ancestry(mut self, enabled: bool) -> Self {
        self.add_ancestry = enabled;
        self
    }

    /// Set whether to add related connections.
    pub fn with_connections(mut self, enabled: bool) -> Self {
        self.add_connections = enabled;
        self
    }

    /// Set the maximum ancestry depth.
    pub fn with_ancestry_depth(mut self, depth: usize) -> Self {
        self.max_ancestry_depth = depth;
        self
    }

    /// Enrich an event with additional context from the state store.
    pub fn enrich(&self, mut event: DetectionEvent, state: &Arc<StateStore>) -> DetectionEvent {
        // Add process ancestry if we have process info
        if self.add_ancestry {
            if let Some(ref mut process) = event.process {
                if process.ancestors.is_empty() {
                    let ancestry = state.processes.ancestry(process.pid, self.max_ancestry_depth);
                    for ancestor in ancestry.into_iter().skip(1) {
                        process.ancestors.push(crate::detection::ProcessAncestor {
                            pid: ancestor.pid,
                            name: ancestor.name,
                            cmdline: ancestor.cmdline,
                        });
                    }
                }
            }
        }

        // Add related connection info
        if self.add_connections {
            if let Some(ref process) = event.process {
                let connections = state.connections.connections_from_pid(process.pid);
                if !connections.is_empty() && event.connection.is_none() {
                    // Add the first active connection as context
                    if let Some(conn) = connections.into_iter().find(|c| c.state.is_active()) {
                        event.connection = Some(crate::detection::ConnectionInfo {
                            local_addr: conn.key.local_addr.to_string(),
                            local_port: conn.key.local_port,
                            remote_addr: conn.key.remote_addr.to_string(),
                            remote_port: conn.key.remote_port,
                            state: conn.state.to_string(),
                            pid: conn.pid,
                            process_name: conn.process_name,
                        });
                    }
                }
            }
        }

        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionSource, ProcessInfo, Severity, ThreatType};
    use crate::state::ProcessEntry;

    #[test]
    fn test_enricher_creation() {
        let enricher = EventEnricher::new();
        assert!(enricher.add_ancestry);
        assert!(enricher.add_connections);
        assert_eq!(enricher.max_ancestry_depth, 5);
    }

    #[test]
    fn test_enricher_adds_ancestry() {
        let state = StateStore::new().shared();

        // Add some processes to the state
        state.processes.upsert(ProcessEntry::new(
            1, 0, "init".to_string(), "init".to_string(), None, None, 0,
        ));
        state.processes.upsert(ProcessEntry::new(
            100, 1, "bash".to_string(), "bash".to_string(), None, None, 1000,
        ));
        state.processes.upsert(ProcessEntry::new(
            200, 100, "malware".to_string(), "malware".to_string(), None, None, 1000,
        ));

        let enricher = EventEnricher::new();
        let mut event = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::Cryptominer,
            Severity::High,
            "Test",
        );
        event.process = Some(ProcessInfo {
            pid: 200,
            ppid: 100,
            name: "malware".to_string(),
            cmdline: "malware".to_string(),
            exe_path: None,
            cwd: None,
            uid: 1000,
            username: None,
            start_time: None,
            ancestors: vec![],
        });

        let enriched = enricher.enrich(event, &state);
        assert!(enriched.process.is_some());
        let process = enriched.process.unwrap();
        assert!(!process.ancestors.is_empty());
    }
}
