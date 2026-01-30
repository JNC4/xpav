//! Netlink proc connector for real-time process events.
//!
//! This module provides low-latency process monitoring using the Linux
//! proc connector via netlink. It receives notifications for process
//! fork, exec, exit, and other lifecycle events.

use std::os::unix::io::{AsRawFd, RawFd};
use std::io;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_CONNECTOR};

/// Connector IDs from the Linux kernel.
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;

/// Process event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEvent {
    /// No event
    None,
    /// Process forked
    Fork { parent_pid: u32, parent_tgid: u32, child_pid: u32, child_tgid: u32 },
    /// Process executed a new program
    Exec { pid: u32, tgid: u32 },
    /// Process changed UID
    Uid { pid: u32, tgid: u32, ruid: u32, euid: u32 },
    /// Process changed GID
    Gid { pid: u32, tgid: u32, rgid: u32, egid: u32 },
    /// Process changed session ID
    Sid { pid: u32, tgid: u32 },
    /// Process changed process trace flags
    Ptrace { pid: u32, tgid: u32, tracer_pid: u32, tracer_tgid: u32 },
    /// Process changed comm (name)
    Comm { pid: u32, tgid: u32, comm: [u8; 16] },
    /// Process exited
    Exit { pid: u32, tgid: u32, exit_code: u32 },
    /// Process coresump
    Coredump { pid: u32, tgid: u32 },
}

/// Event types for the proc connector.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEventType {
    None = 0,
    Fork = 0x00000001,
    Exec = 0x00000002,
    Uid = 0x00000004,
    Gid = 0x00000040,
    Sid = 0x00000080,
    Ptrace = 0x00000100,
    Comm = 0x00000200,
    Coredump = 0x40000000,
    Exit = 0x80000000,
}

/// Netlink proc connector for receiving process events.
pub struct NetlinkProcConnector {
    socket: Socket,
}

impl NetlinkProcConnector {
    /// Create a new proc connector.
    /// Requires CAP_NET_ADMIN capability.
    pub fn new() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_CONNECTOR)?;

        // Bind to the proc connector group
        let addr = SocketAddr::new(std::process::id(), CN_IDX_PROC);
        socket.bind(&addr)?;

        // Subscribe to proc events
        Self::subscribe(&socket, true)?;

        Ok(Self { socket })
    }

    /// Subscribe or unsubscribe from proc events.
    fn subscribe(socket: &Socket, subscribe: bool) -> io::Result<()> {
        // Build the subscription message
        let mut msg = vec![0u8; 32];

        // cn_msg header
        let idx = CN_IDX_PROC;
        let val = CN_VAL_PROC;
        msg[0..4].copy_from_slice(&idx.to_ne_bytes());
        msg[4..8].copy_from_slice(&val.to_ne_bytes());

        // Sequence and ack
        msg[8..12].copy_from_slice(&0u32.to_ne_bytes());  // seq
        msg[12..16].copy_from_slice(&0u32.to_ne_bytes()); // ack

        // Length of proc_cn_mcast_op (4 bytes)
        msg[16..18].copy_from_slice(&4u16.to_ne_bytes());
        msg[18..20].copy_from_slice(&0u16.to_ne_bytes()); // flags

        // proc_cn_mcast_op: PROC_CN_MCAST_LISTEN=1, PROC_CN_MCAST_IGNORE=2
        let op: u32 = if subscribe { 1 } else { 2 };
        msg[20..24].copy_from_slice(&op.to_ne_bytes());

        // Create netlink header
        let total_len = 16 + msg.len(); // NLMSG_HDRLEN + payload
        let mut packet = vec![0u8; total_len];

        // Netlink header
        packet[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
        packet[4..6].copy_from_slice(&0u16.to_ne_bytes()); // nlmsg_type (NLMSG_DONE = 3, but use 0)
        packet[6..8].copy_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        packet[8..12].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        packet[12..16].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid

        // Copy payload
        packet[16..].copy_from_slice(&msg[..total_len - 16]);

        let dest = SocketAddr::new(0, CN_IDX_PROC);
        socket.send_to(&packet, &dest, 0)?;

        Ok(())
    }

    /// Receive the next process event.
    /// This call blocks until an event is available.
    pub fn recv(&self) -> io::Result<Option<ProcEvent>> {
        let mut buf = vec![0u8; 4096];
        let n = self.socket.recv(&mut buf, 0)?;

        // Parse using helper that properly handles offsets
        Self::parse_proc_event(&buf[..n], n)
    }

    /// Parse a proc connector message with proper offset handling.
    ///
    /// Message structure:
    /// - nlmsghdr (16 bytes, NLMSG_ALIGN to 4 bytes)
    /// - cn_msg header (20 bytes):
    ///   - cb_id: 8 bytes (idx + val)
    ///   - seq: 4 bytes
    ///   - ack: 4 bytes
    ///   - len: 2 bytes
    ///   - flags: 2 bytes
    /// - proc_event:
    ///   - what: 4 bytes
    ///   - cpu: 4 bytes
    ///   - timestamp_ns: 8 bytes (u64, 8-byte aligned)
    ///   - event_data: variable (starts at offset 16 within proc_event)
    fn parse_proc_event(buf: &[u8], n: usize) -> io::Result<Option<ProcEvent>> {
        // Constants for header sizes
        const NLMSG_HDRLEN: usize = 16;
        const CN_MSG_HDRLEN: usize = 20;
        const PROC_EVENT_HDRLEN: usize = 16; // what + cpu + timestamp_ns

        // Minimum size: nlmsghdr + cn_msg + proc_event header
        let min_size = NLMSG_HDRLEN + CN_MSG_HDRLEN + PROC_EVENT_HDRLEN;
        if n < min_size {
            return Ok(None);
        }

        // Validate nlmsghdr
        let nlmsg_len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if nlmsg_len > n || nlmsg_len < min_size {
            return Ok(None);
        }

        // cn_msg starts after nlmsghdr
        let cn_msg_offset = NLMSG_HDRLEN;

        // Validate cn_msg idx and val
        let cn_idx = u32::from_ne_bytes([
            buf[cn_msg_offset],
            buf[cn_msg_offset + 1],
            buf[cn_msg_offset + 2],
            buf[cn_msg_offset + 3],
        ]);
        let cn_val = u32::from_ne_bytes([
            buf[cn_msg_offset + 4],
            buf[cn_msg_offset + 5],
            buf[cn_msg_offset + 6],
            buf[cn_msg_offset + 7],
        ]);

        if cn_idx != CN_IDX_PROC || cn_val != CN_VAL_PROC {
            return Ok(None); // Not a proc connector message
        }

        // Get cn_msg data length
        let cn_data_len = u16::from_ne_bytes([
            buf[cn_msg_offset + 16],
            buf[cn_msg_offset + 17],
        ]) as usize;

        // proc_event starts after cn_msg header
        let proc_event_offset = cn_msg_offset + CN_MSG_HDRLEN;

        // Validate we have enough data
        if proc_event_offset + cn_data_len > n {
            return Ok(None);
        }

        // Read proc_event.what (event type)
        let event_type = u32::from_ne_bytes([
            buf[proc_event_offset],
            buf[proc_event_offset + 1],
            buf[proc_event_offset + 2],
            buf[proc_event_offset + 3],
        ]);

        // Event data starts at proc_event + 16 (after what, cpu, timestamp_ns)
        let event_data_offset = proc_event_offset + PROC_EVENT_HDRLEN;

        // Helper to read u32 at offset, returns None if out of bounds
        let read_u32 = |off: usize| -> Option<u32> {
            if off + 4 <= n {
                Some(u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
            } else {
                None
            }
        };

        // Parse event based on type - return None if data is truncated
        let event = match event_type {
            x if x == ProcEventType::Fork as u32 => {
                // Fork event data: parent_pid, parent_tgid, child_pid, child_tgid (4 x u32)
                match (
                    read_u32(event_data_offset),
                    read_u32(event_data_offset + 4),
                    read_u32(event_data_offset + 8),
                    read_u32(event_data_offset + 12),
                ) {
                    (Some(parent_pid), Some(parent_tgid), Some(child_pid), Some(child_tgid)) => {
                        Some(ProcEvent::Fork { parent_pid, parent_tgid, child_pid, child_tgid })
                    }
                    _ => None,
                }
            }
            x if x == ProcEventType::Exec as u32 => {
                // Exec event data: process_pid, process_tgid (2 x u32)
                match (read_u32(event_data_offset), read_u32(event_data_offset + 4)) {
                    (Some(pid), Some(tgid)) => Some(ProcEvent::Exec { pid, tgid }),
                    _ => None,
                }
            }
            x if x == ProcEventType::Exit as u32 => {
                // Exit event data: process_pid, process_tgid, exit_code, exit_signal (4 x u32)
                match (
                    read_u32(event_data_offset),
                    read_u32(event_data_offset + 4),
                    read_u32(event_data_offset + 8),
                ) {
                    (Some(pid), Some(tgid), Some(exit_code)) => {
                        Some(ProcEvent::Exit { pid, tgid, exit_code })
                    }
                    _ => None,
                }
            }
            x if x == ProcEventType::Uid as u32 => {
                // UID event data: process_pid, process_tgid, ruid, euid (4 x u32)
                match (
                    read_u32(event_data_offset),
                    read_u32(event_data_offset + 4),
                    read_u32(event_data_offset + 8),
                    read_u32(event_data_offset + 12),
                ) {
                    (Some(pid), Some(tgid), Some(ruid), Some(euid)) => {
                        Some(ProcEvent::Uid { pid, tgid, ruid, euid })
                    }
                    _ => None,
                }
            }
            x if x == ProcEventType::Gid as u32 => {
                // GID event data: process_pid, process_tgid, rgid, egid (4 x u32)
                match (
                    read_u32(event_data_offset),
                    read_u32(event_data_offset + 4),
                    read_u32(event_data_offset + 8),
                    read_u32(event_data_offset + 12),
                ) {
                    (Some(pid), Some(tgid), Some(rgid), Some(egid)) => {
                        Some(ProcEvent::Gid { pid, tgid, rgid, egid })
                    }
                    _ => None,
                }
            }
            x if x == ProcEventType::Sid as u32 => {
                // SID event data: process_pid, process_tgid (2 x u32)
                match (read_u32(event_data_offset), read_u32(event_data_offset + 4)) {
                    (Some(pid), Some(tgid)) => Some(ProcEvent::Sid { pid, tgid }),
                    _ => None,
                }
            }
            x if x == ProcEventType::Ptrace as u32 => {
                // Ptrace event data: process_pid, process_tgid, tracer_pid, tracer_tgid (4 x u32)
                match (
                    read_u32(event_data_offset),
                    read_u32(event_data_offset + 4),
                    read_u32(event_data_offset + 8),
                    read_u32(event_data_offset + 12),
                ) {
                    (Some(pid), Some(tgid), Some(tracer_pid), Some(tracer_tgid)) => {
                        Some(ProcEvent::Ptrace { pid, tgid, tracer_pid, tracer_tgid })
                    }
                    _ => None,
                }
            }
            x if x == ProcEventType::Comm as u32 => {
                // Comm event data: process_pid, process_tgid, comm[16]
                match (read_u32(event_data_offset), read_u32(event_data_offset + 4)) {
                    (Some(pid), Some(tgid)) => {
                        let comm_offset = event_data_offset + 8;
                        if comm_offset + 16 <= n {
                            let mut comm = [0u8; 16];
                            comm.copy_from_slice(&buf[comm_offset..comm_offset + 16]);
                            Some(ProcEvent::Comm { pid, tgid, comm })
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            x if x == ProcEventType::Coredump as u32 => {
                // Coredump event data: process_pid, process_tgid, parent_pid, parent_tgid
                match (read_u32(event_data_offset), read_u32(event_data_offset + 4)) {
                    (Some(pid), Some(tgid)) => Some(ProcEvent::Coredump { pid, tgid }),
                    _ => None,
                }
            }
            _ => Some(ProcEvent::None),
        };

        Ok(event)
    }

    /// Get the raw file descriptor for use with async I/O.
    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        let fd = self.as_raw_fd();
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let mut flags = OFlag::from_bits_truncate(flags);
        if nonblocking {
            flags |= OFlag::O_NONBLOCK;
        } else {
            flags.remove(OFlag::O_NONBLOCK);
        }
        fcntl(fd, FcntlArg::F_SETFL(flags))?;
        Ok(())
    }
}

impl Drop for NetlinkProcConnector {
    fn drop(&mut self) {
        // Unsubscribe from proc events
        let _ = Self::subscribe(&self.socket, false);
    }
}

/// Check if netlink proc connector is available.
pub fn is_available() -> bool {
    // Try to create a connector - if it fails, netlink is not available
    NetlinkProcConnector::new().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_event_types() {
        assert_eq!(ProcEventType::Fork as u32, 0x00000001);
        assert_eq!(ProcEventType::Exec as u32, 0x00000002);
        assert_eq!(ProcEventType::Exit as u32, 0x80000000);
    }

    #[test]
    fn test_parse_exec_event() {
        // Simulate a proc connector exec event message
        // nlmsghdr (16) + cn_msg (20) + proc_event header (16) + exec data (8)
        let mut buf = vec![0u8; 60];

        // nlmsghdr
        let nlmsg_len: u32 = 60;
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());

        // cn_msg header at offset 16
        buf[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes()); // idx
        buf[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes()); // val
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // seq
        buf[28..32].copy_from_slice(&0u32.to_ne_bytes()); // ack
        let data_len: u16 = 24; // proc_event header (16) + exec data (8)
        buf[32..34].copy_from_slice(&data_len.to_ne_bytes()); // len
        buf[34..36].copy_from_slice(&0u16.to_ne_bytes()); // flags

        // proc_event at offset 36
        let what = ProcEventType::Exec as u32;
        buf[36..40].copy_from_slice(&what.to_ne_bytes()); // what
        buf[40..44].copy_from_slice(&0u32.to_ne_bytes()); // cpu
        buf[44..52].copy_from_slice(&0u64.to_ne_bytes()); // timestamp_ns

        // exec event data at offset 52
        let pid: u32 = 12345;
        let tgid: u32 = 12345;
        buf[52..56].copy_from_slice(&pid.to_ne_bytes());
        buf[56..60].copy_from_slice(&tgid.to_ne_bytes());

        let result = NetlinkProcConnector::parse_proc_event(&buf, 60).unwrap();
        assert!(result.is_some());

        match result.unwrap() {
            ProcEvent::Exec { pid: p, tgid: t } => {
                assert_eq!(p, 12345);
                assert_eq!(t, 12345);
            }
            _ => panic!("Expected Exec event"),
        }
    }

    #[test]
    fn test_parse_fork_event() {
        // nlmsghdr (16) + cn_msg (20) + proc_event header (16) + fork data (16)
        let mut buf = vec![0u8; 68];

        // nlmsghdr
        let nlmsg_len: u32 = 68;
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());

        // cn_msg header at offset 16
        buf[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        buf[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        let data_len: u16 = 32; // proc_event header (16) + fork data (16)
        buf[32..34].copy_from_slice(&data_len.to_ne_bytes());

        // proc_event at offset 36
        let what = ProcEventType::Fork as u32;
        buf[36..40].copy_from_slice(&what.to_ne_bytes());

        // fork event data at offset 52
        let parent_pid: u32 = 1000;
        let parent_tgid: u32 = 1000;
        let child_pid: u32 = 2000;
        let child_tgid: u32 = 2000;
        buf[52..56].copy_from_slice(&parent_pid.to_ne_bytes());
        buf[56..60].copy_from_slice(&parent_tgid.to_ne_bytes());
        buf[60..64].copy_from_slice(&child_pid.to_ne_bytes());
        buf[64..68].copy_from_slice(&child_tgid.to_ne_bytes());

        let result = NetlinkProcConnector::parse_proc_event(&buf, 68).unwrap();
        assert!(result.is_some());

        match result.unwrap() {
            ProcEvent::Fork { parent_pid, parent_tgid, child_pid, child_tgid } => {
                assert_eq!(parent_pid, 1000);
                assert_eq!(parent_tgid, 1000);
                assert_eq!(child_pid, 2000);
                assert_eq!(child_tgid, 2000);
            }
            _ => panic!("Expected Fork event"),
        }
    }

    #[test]
    fn test_parse_invalid_message() {
        // Too short message
        let buf = vec![0u8; 10];
        let result = NetlinkProcConnector::parse_proc_event(&buf, 10).unwrap();
        assert!(result.is_none());

        // Wrong connector ID
        let mut buf = vec![0u8; 60];
        buf[0..4].copy_from_slice(&60u32.to_ne_bytes());
        buf[16..20].copy_from_slice(&999u32.to_ne_bytes()); // wrong idx
        let result = NetlinkProcConnector::parse_proc_event(&buf, 60).unwrap();
        assert!(result.is_none());
    }

    // Integration test - only works with CAP_NET_ADMIN
    #[test]
    #[ignore]
    fn test_netlink_connector() {
        let connector = NetlinkProcConnector::new().expect("Failed to create connector");
        connector.set_nonblocking(true).expect("Failed to set nonblocking");

        // Try to receive an event (may or may not get one immediately)
        let _ = connector.recv();
    }
}
