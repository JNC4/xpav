//! Monitor modules
//!
//! Each monitor watches a specific aspect of the system for malicious behavior.

pub mod process;
pub mod network;
pub mod persistence;
pub mod fanotify;
pub mod netlink;
// Phase 3 monitors
pub mod ebpf;
pub mod memory;
pub mod integrity;
pub mod container;

#[cfg(feature = "ebpf-native")]
pub mod ebpf_native;

pub use process::ProcessMonitor;
pub use network::NetworkMonitor;
pub use persistence::PersistenceMonitor;
pub use fanotify::FanotifyMonitor;
pub use netlink::NetlinkProcConnector;
// Phase 3 exports
pub use ebpf::EbpfMonitor;
pub use memory::MemoryScanner;
pub use integrity::IntegrityMonitor;
pub use container::ContainerMonitor;
