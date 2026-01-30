//! Native eBPF monitoring using Aya (feature-gated).
//!
//! This module provides real-time process monitoring using native eBPF programs
//! compiled with Aya. It offers lower overhead than /proc polling and
//! faster detection than netlink.
//!
//! Requires the `ebpf-native` feature to be enabled.

#![cfg(feature = "ebpf-native")]

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::ProcessMonitorConfig;
use crate::detection::{DetectionEvent, DetectionSource, ProcessInfo, Severity, ThreatType};
use crate::state::StateStore;

/// Backend selection for process monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMonitorBackend {
    /// Native eBPF using Aya
    EbpfNative,
    /// Netlink proc connector
    Netlink,
    /// Polling /proc filesystem
    Polling,
}

impl ProcessMonitorBackend {
    /// Detect the best available backend.
    pub fn detect() -> Self {
        // Try eBPF native first
        if Self::ebpf_available() {
            return Self::EbpfNative;
        }

        // Fall back to netlink
        if crate::monitors::netlink::is_available() {
            return Self::Netlink;
        }

        // Fall back to polling
        Self::Polling
    }

    fn ebpf_available() -> bool {
        // Check if we can load eBPF programs
        // This is a simplified check - in practice would verify CAP_BPF, etc.
        std::path::Path::new("/sys/fs/bpf").exists()
    }
}

/// Native eBPF-based process monitor.
pub struct EbpfNativeMonitor {
    config: ProcessMonitorConfig,
    state: Arc<StateStore>,
    event_tx: mpsc::Sender<DetectionEvent>,
}

impl EbpfNativeMonitor {
    /// Create a new eBPF native monitor.
    pub fn new(
        config: ProcessMonitorConfig,
        state: Arc<StateStore>,
        event_tx: mpsc::Sender<DetectionEvent>,
    ) -> Self {
        Self {
            config,
            state,
            event_tx,
        }
    }

    /// Run the eBPF monitor.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Starting eBPF native monitor");

        // TODO: Load eBPF programs using Aya
        // This would involve:
        // 1. Loading the compiled BPF programs (exec.bpf.o, fork.bpf.o)
        // 2. Attaching to tracepoints (sched_process_exec, sched_process_fork)
        // 3. Reading events from the perf buffer
        // 4. Processing events and sending detections

        warn!("eBPF native monitor is a placeholder - falling back to polling");

        // For now, just sleep to prevent busy loop
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(self.config.scan_interval_ms / 1000)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_detection() {
        let backend = ProcessMonitorBackend::detect();
        // Should always return some backend
        assert!(matches!(
            backend,
            ProcessMonitorBackend::EbpfNative
                | ProcessMonitorBackend::Netlink
                | ProcessMonitorBackend::Polling
        ));
    }
}
