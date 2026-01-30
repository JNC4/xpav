//! Common types for detection events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    Cryptominer,
    SuspiciousExecution,
    SuspiciousProcess,
    MiningPoolConnection,
    C2Connection,
    PersistenceMechanism,
    SshKeyModification,
    CronModification,
    SystemdModification,
    LdPreloadModification,
    // Webshell
    Webshell,
    WebshellObfuscated,
    SuspiciousFileExecution,
    WebServerShellSpawn,
    WebServerSuspiciousChild,
    // eBPF
    EbpfRootkit,
    SuspiciousEbpfProgram,
    UnexpectedXdpAttachment,
    UnexpectedTcAttachment,
    SensitiveKprobeAttachment,
    // Memory
    FilelessMalware,
    ProcessInjection,
    SuspiciousMemoryRegion,
    ShellcodeDetected,
    // Integrity
    IntegrityViolation,
    KernelModuleLoad,
    BootFileModified,
    CriticalBinaryModified,
    // Container
    ContainerEscape,
    SuspiciousNamespaceChange,
    PrivilegedContainerOperation,
    HostMountAccess,
    SuspiciousCapability,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    ProcessMonitor,
    NetworkMonitor,
    PersistenceMonitor,
    FileMonitor,
    EbpfMonitor,
    MemoryScanner,
    IntegrityMonitor,
    ContainerMonitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub uid: u32,
    pub username: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<ProcessAncestor>,
}

/// Simplified process info for ancestry chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
}

/// Information about a network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

/// Information about a file modification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: PathBuf,
    pub event_type: FileEventType,
    pub old_content_hash: Option<String>,
    pub new_content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Accessed,
}

/// A detection event from any monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: DetectionSource,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub description: String,
    pub matched_pattern: Option<String>,
    pub process: Option<ProcessInfo>,
    pub connection: Option<ConnectionInfo>,
    pub file: Option<FileInfo>,
    pub raw_data: Option<serde_json::Value>,
}

impl DetectionEvent {
    pub fn new(
        source: DetectionSource,
        threat_type: ThreatType,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid_simple(),
            timestamp: Utc::now(),
            source,
            threat_type,
            severity,
            description: description.into(),
            matched_pattern: None,
            process: None,
            connection: None,
            file: None,
            raw_data: None,
        }
    }

    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.process = Some(process);
        self
    }

    pub fn with_connection(mut self, connection: ConnectionInfo) -> Self {
        self.connection = Some(connection);
        self
    }

    pub fn with_file(mut self, file: FileInfo) -> Self {
        self.file = Some(file);
        self
    }

    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.matched_pattern = Some(pattern.into());
        self
    }
}

/// Simple UUID generation without external dependency
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let rand_part: u64 = now.as_nanos() as u64 ^ std::process::id() as u64;
    format!("{:016x}-{:08x}", now.as_nanos() as u64, rand_part as u32)
}
