//! Native eBPF monitoring using Aya (feature-gated).
//!
//! This module provides real-time process monitoring using native eBPF programs
//! compiled with Aya. It offers lower overhead than /proc polling and
//! faster detection than netlink.
//!
//! The module attaches to kernel tracepoints:
//! - `sched:sched_process_exec` - Process execution
//! - `sched:sched_process_fork` - Process fork
//! - `sched:sched_process_exit` - Process exit
//!
//! Requires the `ebpf-native` feature and:
//! - Root/CAP_BPF capabilities
//! - Kernel 5.4+ with BPF support
//! - `/sys/fs/bpf` filesystem mounted
//!
//! ## Building eBPF Programs
//!
//! Before using this feature, build the eBPF programs:
//! ```sh
//! cargo xtask build-ebpf
//! ```
//!
//! This compiles the `xpav-ebpf` crate to BPF bytecode and places it in
//! `target/bpf/xpav_ebpf.o`.

#![cfg(feature = "ebpf-native")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::ProcessMonitorConfig;
use crate::detection::{DetectionEvent, DetectionSource, ProcessInfo, Severity, ThreatType};
use crate::state::StateStore;

// Use shared types from xpav-common
use xpav_common::ExecEvent;

/// Backend selection for process monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMonitorBackend {
    /// Native eBPF using Aya
    BpfNative,
    /// Netlink proc connector
    Netlink,
    /// Polling /proc filesystem
    Polling,
}

impl ProcessMonitorBackend {
    /// Detect the best available backend.
    pub fn detect() -> Self {
        // Try eBPF native first (only if program exists)
        if Self::ebpf_available() && Self::ebpf_program_exists() {
            return Self::BpfNative;
        }

        // Fall back to netlink
        if crate::monitors::netlink::is_available() {
            return Self::Netlink;
        }

        // Fall back to polling
        Self::Polling
    }

    /// Check if eBPF is available on this system.
    pub fn ebpf_available() -> bool {
        // Check /sys/fs/bpf exists
        if !Path::new("/sys/fs/bpf").exists() {
            return false;
        }

        // Check kernel version >= 5.4
        if let Ok(version) = kernel_version() {
            if version < (5, 4) {
                return false;
            }
        } else {
            return false;
        }

        true
    }

    /// Check if the eBPF program file exists.
    fn ebpf_program_exists() -> bool {
        for path in EBPF_PROGRAM_PATHS {
            if Path::new(path).exists() {
                return true;
            }
        }
        false
    }
}

/// Paths to search for the compiled eBPF program.
const EBPF_PROGRAM_PATHS: &[&str] = &[
    // Development: built by `cargo xtask build-ebpf`
    "./target/bpf/xpav_ebpf.o",
    // Installed system-wide
    "/usr/share/xpav/ebpf/xpav_ebpf.o",
    "/usr/local/share/xpav/ebpf/xpav_ebpf.o",
    // Relative to binary
    "../share/xpav/ebpf/xpav_ebpf.o",
];

/// Get the kernel version as (major, minor).
fn kernel_version() -> Result<(u32, u32), std::io::Error> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let parts: Vec<&str> = release.trim().split('.').collect();

    if parts.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid kernel version format",
        ));
    }

    let major: u32 = parts[0]
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid major"))?;
    let minor: u32 = parts[1]
        .split('-')
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid minor"))?;

    Ok((major, minor))
}

/// Native eBPF-based process monitor.
pub struct BpfNativeMonitor {
    config: ProcessMonitorConfig,
    #[allow(dead_code)]
    state: Arc<StateStore>,
    event_tx: mpsc::Sender<DetectionEvent>,
    miner_patterns_lower: Vec<String>,
}

impl BpfNativeMonitor {
    /// Create a new eBPF native monitor.
    pub fn new(
        config: ProcessMonitorConfig,
        state: Arc<StateStore>,
        event_tx: mpsc::Sender<DetectionEvent>,
    ) -> Self {
        let miner_patterns_lower = config
            .miner_patterns
            .iter()
            .map(|p| p.to_lowercase())
            .collect();

        Self {
            config,
            state,
            event_tx,
            miner_patterns_lower,
        }
    }

    /// Run the eBPF monitor.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Starting native eBPF process monitor");

        // Check if eBPF is available
        if !ProcessMonitorBackend::ebpf_available() {
            warn!("eBPF not available on this system");
            return Err(anyhow::anyhow!("eBPF not available"));
        }

        // Load eBPF programs
        let ebpf_result = self.load_ebpf_programs();

        match ebpf_result {
            Ok(mut ebpf) => {
                info!("eBPF programs loaded successfully");
                self.run_with_ebpf(&mut ebpf).await
            }
            Err(e) => {
                warn!("Failed to load eBPF programs: {}", e);
                Err(e)
            }
        }
    }

    /// Load eBPF programs from file.
    fn load_ebpf_programs(&self) -> anyhow::Result<Bpf> {
        // Search for the compiled eBPF program
        for path in EBPF_PROGRAM_PATHS {
            if Path::new(path).exists() {
                info!("Loading eBPF programs from {}", path);
                return Ok(Bpf::load_file(path)?);
            }
        }

        Err(anyhow::anyhow!(
            "No eBPF program found. Build with: cargo xtask build-ebpf\n\
             Searched paths:\n  {}",
            EBPF_PROGRAM_PATHS.join("\n  ")
        ))
    }

    /// Run the monitor with loaded eBPF programs.
    async fn run_with_ebpf(&self, ebpf: &mut Bpf) -> anyhow::Result<()> {
        // Attach to sched_process_exec tracepoint
        let exec_prog = ebpf
            .program_mut("trace_exec")
            .ok_or_else(|| anyhow::anyhow!("trace_exec program not found in eBPF object"))?;
        let exec_prog: &mut TracePoint = exec_prog.try_into()?;
        exec_prog.load()?;
        exec_prog.attach("sched", "sched_process_exec")?;
        info!("Attached to sched_process_exec tracepoint");

        // Try to attach fork and exit programs if they exist
        if let Some(prog) = ebpf.program_mut("trace_fork") {
            if let Ok(fork_prog) = TryInto::<&mut TracePoint>::try_into(prog) {
                if fork_prog.load().is_ok() {
                    if fork_prog.attach("sched", "sched_process_fork").is_ok() {
                        info!("Attached to sched_process_fork tracepoint");
                    }
                }
            }
        }

        if let Some(prog) = ebpf.program_mut("trace_exit") {
            if let Ok(exit_prog) = TryInto::<&mut TracePoint>::try_into(prog) {
                if exit_prog.load().is_ok() {
                    if exit_prog.attach("sched", "sched_process_exit").is_ok() {
                        info!("Attached to sched_process_exit tracepoint");
                    }
                }
            }
        }

        // Get the perf event array for exec events
        let exec_events_map = ebpf
            .take_map("EXEC_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EXEC_EVENTS map not found"))?;
        let mut exec_events = AsyncPerfEventArray::try_from(exec_events_map)?;

        // Spawn tasks to read from each CPU's perf buffer
        let cpus = online_cpus()?;
        let (event_tx, mut event_rx) = mpsc::channel::<ExecEvent>(1024);

        for cpu_id in cpus {
            let mut buf = exec_events.open(cpu_id, None)?;
            let tx = event_tx.clone();

            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<ExecEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(events) => events,
                        Err(e) => {
                            error!("Error reading perf events on CPU {}: {}", cpu_id, e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };

                    for i in 0..events.read {
                        let buf = &buffers[i];
                        if buf.len() >= std::mem::size_of::<ExecEvent>() {
                            // Safety: We verified the buffer is large enough and ExecEvent is repr(C)
                            let event: ExecEvent =
                                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
                            if tx.send(event).await.is_err() {
                                return; // Channel closed
                            }
                        }
                    }
                }
            });
        }

        drop(event_tx); // Drop our sender so we can detect when all spawned tasks exit

        // Process events
        info!("Native eBPF monitor running");
        while let Some(event) = event_rx.recv().await {
            self.process_exec_event(&event).await;
        }

        Ok(())
    }

    /// Process an exec event from eBPF.
    async fn process_exec_event(&self, event: &ExecEvent) {
        let comm = String::from_utf8_lossy(event.comm_bytes());
        let filename = String::from_utf8_lossy(event.filename_bytes());

        debug!(
            pid = event.pid,
            ppid = event.ppid,
            uid = event.uid,
            comm = %comm,
            filename = %filename,
            "Process exec event"
        );

        // Check for miner patterns
        let filename_lower = filename.to_lowercase();
        let comm_lower = comm.to_lowercase();

        for pattern in &self.miner_patterns_lower {
            if filename_lower.contains(pattern) || comm_lower.contains(pattern) {
                self.report_miner_detection(event, &comm, &filename, pattern)
                    .await;
                return;
            }
        }

        // Check for suspicious paths
        for suspicious in &self.config.suspicious_paths {
            if filename.starts_with(suspicious.to_str().unwrap_or("")) {
                self.report_suspicious_execution(event, &comm, &filename)
                    .await;
                return;
            }
        }

        // Check for fake kernel threads
        if comm.starts_with('[') && comm.ends_with(']') && event.ppid != 2 {
            self.report_fake_kthread(event, &comm, &filename).await;
        }
    }

    /// Report a miner detection.
    async fn report_miner_detection(
        &self,
        event: &ExecEvent,
        comm: &str,
        filename: &str,
        pattern: &str,
    ) {
        let proc_info = ProcessInfo {
            pid: event.pid,
            ppid: event.ppid,
            name: comm.to_string(),
            cmdline: filename.to_string(),
            exe_path: Some(PathBuf::from(filename)),
            cwd: None,
            uid: event.uid,
            username: None,
            start_time: None,
            ancestors: Vec::new(),
        };

        let detection = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::Cryptominer,
            Severity::Critical,
            format!(
                "Cryptominer detected via eBPF: {} (PID {}) matches pattern '{}'",
                proc_info.name, proc_info.pid, pattern
            ),
        )
        .with_process(proc_info)
        .with_pattern(pattern);

        warn!(
            pid = event.pid,
            pattern = %pattern,
            comm = %comm,
            "Cryptominer detected via eBPF"
        );

        if let Err(e) = self.event_tx.send(detection).await {
            error!("Failed to send detection event: {}", e);
        }
    }

    /// Report a suspicious execution.
    async fn report_suspicious_execution(&self, event: &ExecEvent, comm: &str, filename: &str) {
        let proc_info = ProcessInfo {
            pid: event.pid,
            ppid: event.ppid,
            name: comm.to_string(),
            cmdline: filename.to_string(),
            exe_path: Some(PathBuf::from(filename)),
            cwd: None,
            uid: event.uid,
            username: None,
            start_time: None,
            ancestors: Vec::new(),
        };

        let detection = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::SuspiciousExecution,
            Severity::High,
            format!(
                "Suspicious execution via eBPF: {} (PID {}) running from {}",
                proc_info.name, proc_info.pid, filename
            ),
        )
        .with_process(proc_info)
        .with_pattern(filename);

        warn!(
            pid = event.pid,
            path = %filename,
            comm = %comm,
            "Suspicious execution detected via eBPF"
        );

        if let Err(e) = self.event_tx.send(detection).await {
            error!("Failed to send detection event: {}", e);
        }
    }

    /// Report a fake kernel thread.
    async fn report_fake_kthread(&self, event: &ExecEvent, comm: &str, filename: &str) {
        let proc_info = ProcessInfo {
            pid: event.pid,
            ppid: event.ppid,
            name: comm.to_string(),
            cmdline: filename.to_string(),
            exe_path: None,
            cwd: None,
            uid: event.uid,
            username: None,
            start_time: None,
            ancestors: Vec::new(),
        };

        let detection = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::SuspiciousProcess,
            Severity::High,
            format!(
                "Fake kernel thread via eBPF: {} (PID {}) with PPID {} (real kthreads have PPID 2)",
                proc_info.name, proc_info.pid, proc_info.ppid
            ),
        )
        .with_process(proc_info);

        warn!(
            pid = event.pid,
            ppid = event.ppid,
            comm = %comm,
            "Fake kernel thread detected via eBPF"
        );

        if let Err(e) = self.event_tx.send(detection).await {
            error!("Failed to send detection event: {}", e);
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
            ProcessMonitorBackend::BpfNative
                | ProcessMonitorBackend::Netlink
                | ProcessMonitorBackend::Polling
        ));
    }

    #[test]
    fn test_kernel_version() {
        let version = kernel_version();
        // Should succeed on Linux
        assert!(version.is_ok());
        let (major, minor) = version.unwrap();
        assert!(major >= 4); // We need at least Linux 4.x
        println!("Kernel version: {}.{}", major, minor);
    }

    #[test]
    fn test_ebpf_available_check() {
        // This just verifies the function doesn't panic
        let available = ProcessMonitorBackend::ebpf_available();
        println!("eBPF available: {}", available);
    }
}
