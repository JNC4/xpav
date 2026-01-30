//! Shared types for xpav eBPF programs and userspace.
//!
//! These types are used to communicate between eBPF programs running in the kernel
//! and the userspace monitoring application. All types use `#[repr(C)]` for ABI
//! compatibility and fixed-size arrays for stack allocation in eBPF.

#![no_std]

/// Maximum length for process names (comm field in kernel).
/// This matches the kernel's TASK_COMM_LEN.
pub const COMM_LEN: usize = 16;

/// Maximum length for file paths in events.
/// Limited to fit in eBPF stack (512 bytes total).
pub const PATH_LEN: usize = 256;

/// Event emitted when a process calls execve().
///
/// Sent from the `sched_process_exec` tracepoint.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Process ID (tgid in kernel terms).
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User ID of the process owner.
    pub uid: u32,
    /// Group ID of the process owner.
    pub gid: u32,
    /// Timestamp in nanoseconds since boot (from bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Process name (comm), null-terminated.
    pub comm: [u8; COMM_LEN],
    /// Executable path, null-terminated.
    pub filename: [u8; PATH_LEN],
}

impl ExecEvent {
    /// Create a zeroed event.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            timestamp_ns: 0,
            comm: [0; COMM_LEN],
            filename: [0; PATH_LEN],
        }
    }

    /// Get the process name as a byte slice (up to null terminator).
    pub fn comm_bytes(&self) -> &[u8] {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMM_LEN);
        &self.comm[..end]
    }

    /// Get the filename as a byte slice (up to null terminator).
    pub fn filename_bytes(&self) -> &[u8] {
        let end = self
            .filename
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PATH_LEN);
        &self.filename[..end]
    }
}

impl Default for ExecEvent {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Event emitted when a process forks.
///
/// Sent from the `sched_process_fork` tracepoint.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    /// Parent process ID.
    pub parent_pid: u32,
    /// Newly created child process ID.
    pub child_pid: u32,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Parent process name.
    pub parent_comm: [u8; COMM_LEN],
}

impl ForkEvent {
    /// Create a zeroed event.
    pub const fn zeroed() -> Self {
        Self {
            parent_pid: 0,
            child_pid: 0,
            timestamp_ns: 0,
            parent_comm: [0; COMM_LEN],
        }
    }

    /// Get the parent process name as a byte slice.
    pub fn parent_comm_bytes(&self) -> &[u8] {
        let end = self
            .parent_comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMM_LEN);
        &self.parent_comm[..end]
    }
}

impl Default for ForkEvent {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Event emitted when a process exits.
///
/// Sent from the `sched_process_exit` tracepoint.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    /// Process ID that exited.
    pub pid: u32,
    /// Exit code (from task->exit_code).
    pub exit_code: i32,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Process name at exit.
    pub comm: [u8; COMM_LEN],
}

impl ExitEvent {
    /// Create a zeroed event.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            exit_code: 0,
            timestamp_ns: 0,
            comm: [0; COMM_LEN],
        }
    }

    /// Get the process name as a byte slice.
    pub fn comm_bytes(&self) -> &[u8] {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMM_LEN);
        &self.comm[..end]
    }
}

impl Default for ExitEvent {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Event type discriminator for multiplexed event streams.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Exec = 1,
    Fork = 2,
    Exit = 3,
}

// Safety implementations for aya::Pod
// These are only compiled when the "user" feature is enabled (userspace code).
// The types are repr(C) with only primitive types and fixed-size arrays,
// making them safe to transmute from raw bytes.

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ForkEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExitEvent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_event_size() {
        // Verify struct size for eBPF stack compatibility
        // Must fit in 512 byte eBPF stack with room for other variables
        assert!(core::mem::size_of::<ExecEvent>() <= 300);
    }

    #[test]
    fn test_fork_event_size() {
        assert!(core::mem::size_of::<ForkEvent>() <= 40);
    }

    #[test]
    fn test_exit_event_size() {
        assert!(core::mem::size_of::<ExitEvent>() <= 40);
    }

    #[test]
    fn test_exec_event_alignment() {
        // Verify 8-byte alignment for timestamp_ns field
        assert_eq!(core::mem::align_of::<ExecEvent>(), 8);
    }
}
