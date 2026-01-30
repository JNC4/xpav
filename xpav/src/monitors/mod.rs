//! Monitor modules
//!
//! Each monitor watches a specific aspect of the system for malicious behavior.

pub mod container;
pub mod ebpf;
pub mod fanotify;
pub mod integrity;
pub mod memory;
pub mod netlink;
pub mod network;
pub mod persistence;
pub mod process;

// eBPF native support (feature-gated)
#[cfg(feature = "ebpf-native")]
pub mod ebpf_common;
#[cfg(feature = "ebpf-native")]
pub mod ebpf_native;

// Core exports
pub use container::ContainerMonitor;
pub use ebpf::EbpfMonitor;
pub use fanotify::FanotifyMonitor;
pub use integrity::IntegrityMonitor;
pub use memory::MemoryScanner;
pub use netlink::NetlinkProcConnector;
pub use network::NetworkMonitor;
pub use persistence::PersistenceMonitor;
pub use process::ProcessMonitor;

// eBPF native exports
#[cfg(feature = "ebpf-native")]
pub use ebpf_native::{BpfNativeMonitor, ProcessMonitorBackend};
