//! Common data structures for eBPF program communication.
//!
//! This module re-exports types from `xpav-common` which are shared between
//! the eBPF programs (kernel) and userspace monitor.
//!
//! The types are defined in a separate crate so they can be used by both:
//! - `xpav-ebpf` (compiled to BPF bytecode, runs in kernel)
//! - `xpav` (compiled to native, runs in userspace)

#![cfg(feature = "ebpf-native")]

// Re-export everything from xpav-common
pub use xpav_common::*;

/// Extension trait for ExecEvent to provide string conversion helpers.
///
/// The base type in xpav-common is `#![no_std]` so it can only return `&[u8]`.
/// This trait adds convenient `&str` methods for userspace code.
pub trait ExecEventExt {
    /// Get the process name as a string, with invalid UTF-8 replaced.
    fn comm_str(&self) -> std::borrow::Cow<'_, str>;
    /// Get the filename as a string, with invalid UTF-8 replaced.
    fn filename_str(&self) -> std::borrow::Cow<'_, str>;
}

impl ExecEventExt for ExecEvent {
    fn comm_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.comm_bytes())
    }

    fn filename_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.filename_bytes())
    }
}

/// Extension trait for ForkEvent string conversion.
pub trait ForkEventExt {
    /// Get the parent process name as a string.
    fn parent_comm_str(&self) -> std::borrow::Cow<'_, str>;
}

impl ForkEventExt for ForkEvent {
    fn parent_comm_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.parent_comm_bytes())
    }
}

/// Extension trait for ExitEvent string conversion.
pub trait ExitEventExt {
    /// Get the process name as a string.
    fn comm_str(&self) -> std::borrow::Cow<'_, str>;
}

impl ExitEventExt for ExitEvent {
    fn comm_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.comm_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_event_size() {
        // Verify the struct is the expected size for eBPF compatibility
        assert!(std::mem::size_of::<ExecEvent>() <= 512);
    }

    #[test]
    fn test_fork_event_size() {
        assert!(std::mem::size_of::<ForkEvent>() <= 64);
    }

    #[test]
    fn test_exit_event_size() {
        assert!(std::mem::size_of::<ExitEvent>() <= 64);
    }

    #[test]
    fn test_comm_str() {
        let mut event = ExecEvent::default();
        event.comm[0] = b't';
        event.comm[1] = b'e';
        event.comm[2] = b's';
        event.comm[3] = b't';
        assert_eq!(event.comm_str().as_ref(), "test");
    }

    #[test]
    fn test_filename_str() {
        let mut event = ExecEvent::default();
        let path = b"/bin/test";
        event.filename[..path.len()].copy_from_slice(path);
        assert_eq!(event.filename_str().as_ref(), "/bin/test");
    }
}
