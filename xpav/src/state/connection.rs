//! Connection registry for network state tracking.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Unique identifier for a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
}

impl ConnectionKey {
    /// Create a new connection key.
    pub fn new(
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            protocol,
        }
    }

    /// Create a key from string addresses (for convenience).
    pub fn from_strings(
        local_addr: &str,
        local_port: u16,
        remote_addr: &str,
        remote_port: u16,
        protocol: Protocol,
    ) -> Option<Self> {
        let local: IpAddr = local_addr.parse().ok()?;
        let remote: IpAddr = remote_addr.parse().ok()?;
        Some(Self::new(local, local_port, remote, remote_port, protocol))
    }
}

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Tcp6 => write!(f, "tcp6"),
            Protocol::Udp6 => write!(f, "udp6"),
        }
    }
}

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl ConnectionState {
    /// Parse from TCP state number.
    pub fn from_tcp_state(state: u8) -> Self {
        match state {
            0x01 => ConnectionState::Established,
            0x02 => ConnectionState::SynSent,
            0x03 => ConnectionState::SynRecv,
            0x04 => ConnectionState::FinWait1,
            0x05 => ConnectionState::FinWait2,
            0x06 => ConnectionState::TimeWait,
            0x07 => ConnectionState::Close,
            0x08 => ConnectionState::CloseWait,
            0x09 => ConnectionState::LastAck,
            0x0A => ConnectionState::Listen,
            0x0B => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }

    /// Check if this is an active connection state.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ConnectionState::Established | ConnectionState::SynSent | ConnectionState::SynRecv
        )
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::SynSent => write!(f, "SYN_SENT"),
            ConnectionState::SynRecv => write!(f, "SYN_RECV"),
            ConnectionState::FinWait1 => write!(f, "FIN_WAIT1"),
            ConnectionState::FinWait2 => write!(f, "FIN_WAIT2"),
            ConnectionState::TimeWait => write!(f, "TIME_WAIT"),
            ConnectionState::Close => write!(f, "CLOSE"),
            ConnectionState::CloseWait => write!(f, "CLOSE_WAIT"),
            ConnectionState::LastAck => write!(f, "LAST_ACK"),
            ConnectionState::Listen => write!(f, "LISTEN"),
            ConnectionState::Closing => write!(f, "CLOSING"),
            ConnectionState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Information about a tracked network connection.
#[derive(Debug, Clone)]
pub struct ConnectionEntry {
    /// Connection key
    pub key: ConnectionKey,
    /// TCP state (for TCP connections)
    pub state: ConnectionState,
    /// Process ID owning this connection
    pub pid: Option<u32>,
    /// Process name owning this connection
    pub process_name: Option<String>,
    /// User ID
    pub uid: Option<u32>,
    /// When the connection was first seen
    pub first_seen: DateTime<Utc>,
    /// When the connection was last seen
    pub last_seen: DateTime<Utc>,
    /// Bytes sent (if tracked)
    pub bytes_sent: u64,
    /// Bytes received (if tracked)
    pub bytes_recv: u64,
    /// Whether this connection has been reported as suspicious
    pub reported: bool,
    /// Custom tags for tracking
    pub tags: Vec<String>,
}

impl ConnectionEntry {
    /// Create a new connection entry.
    pub fn new(key: ConnectionKey, state: ConnectionState) -> Self {
        let now = Utc::now();
        Self {
            key,
            state,
            pid: None,
            process_name: None,
            uid: None,
            first_seen: now,
            last_seen: now,
            bytes_sent: 0,
            bytes_recv: 0,
            reported: false,
            tags: Vec::new(),
        }
    }

    /// Set process information.
    pub fn with_process(mut self, pid: u32, name: Option<String>) -> Self {
        self.pid = Some(pid);
        self.process_name = name;
        self
    }

    /// Set user ID.
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Update the last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
    }

    /// Update connection state.
    pub fn update_state(&mut self, state: ConnectionState) {
        self.state = state;
        self.touch();
    }

    /// Mark this connection as reported.
    pub fn mark_reported(&mut self) {
        self.reported = true;
    }

    /// Add a tag to this connection.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Check if connection has a specific tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Calculate how long since the connection was last seen.
    pub fn age(&self) -> Duration {
        let now = Utc::now();
        (now - self.last_seen).to_std().unwrap_or(Duration::ZERO)
    }

    /// Get the remote endpoint as a string.
    pub fn remote_endpoint(&self) -> String {
        format!("{}:{}", self.key.remote_addr, self.key.remote_port)
    }
}

/// Concurrent registry of network connections.
#[derive(Debug)]
pub struct ConnectionRegistry {
    /// Map of connection key to connection entry
    connections: DashMap<ConnectionKey, ConnectionEntry>,
    /// Stale threshold - connections not seen for this duration are considered stale
    stale_threshold: Duration,
}

impl ConnectionRegistry {
    /// Create a new connection registry.
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            stale_threshold: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a registry with custom stale threshold.
    pub fn with_stale_threshold(stale_secs: u64) -> Self {
        Self {
            connections: DashMap::new(),
            stale_threshold: Duration::from_secs(stale_secs),
        }
    }

    /// Insert or update a connection entry.
    pub fn upsert(&self, entry: ConnectionEntry) {
        let key = entry.key.clone();
        self.connections
            .entry(key)
            .and_modify(|e| {
                e.last_seen = Utc::now();
                e.state = entry.state;
                if entry.pid.is_some() {
                    e.pid = entry.pid;
                    e.process_name = entry.process_name.clone();
                }
            })
            .or_insert(entry);
    }

    /// Get a connection entry by key.
    pub fn get(&self, key: &ConnectionKey) -> Option<ConnectionEntry> {
        self.connections.get(key).map(|e| e.clone())
    }

    /// Check if a connection exists.
    pub fn contains(&self, key: &ConnectionKey) -> bool {
        self.connections.contains_key(key)
    }

    /// Remove a connection entry.
    pub fn remove(&self, key: &ConnectionKey) -> Option<ConnectionEntry> {
        self.connections.remove(key).map(|(_, e)| e)
    }

    /// Mark a connection as reported.
    pub fn mark_reported(&self, key: &ConnectionKey) {
        if let Some(mut entry) = self.connections.get_mut(key) {
            entry.mark_reported();
        }
    }

    /// Check if a connection has been reported.
    pub fn is_reported(&self, key: &ConnectionKey) -> bool {
        self.connections
            .get(key)
            .map(|e| e.reported)
            .unwrap_or(false)
    }

    /// Get the number of tracked connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Get all connections matching a predicate.
    pub fn filter<F>(&self, predicate: F) -> Vec<ConnectionEntry>
    where
        F: Fn(&ConnectionEntry) -> bool,
    {
        self.connections
            .iter()
            .filter(|e| predicate(e.value()))
            .map(|e| e.clone())
            .collect()
    }

    /// Get all connections to a specific remote address.
    pub fn connections_to(&self, remote_addr: &IpAddr) -> Vec<ConnectionEntry> {
        self.filter(|e| &e.key.remote_addr == remote_addr)
    }

    /// Get all connections from a specific process.
    pub fn connections_from_pid(&self, pid: u32) -> Vec<ConnectionEntry> {
        self.filter(|e| e.pid == Some(pid))
    }

    /// Get all active (established) connections.
    pub fn active_connections(&self) -> Vec<ConnectionEntry> {
        self.filter(|e| e.state.is_active())
    }

    /// Remove stale connections (not seen recently).
    pub fn cleanup_stale(&self) {
        let now = Utc::now();
        self.connections.retain(|_, entry| {
            let age = (now - entry.last_seen).to_std().unwrap_or(Duration::ZERO);
            age < self.stale_threshold
        });
    }

    /// Get connections to a specific port.
    pub fn connections_to_port(&self, port: u16) -> Vec<ConnectionEntry> {
        self.filter(|e| e.key.remote_port == port)
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_connection_key() {
        let key = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );

        assert_eq!(key.local_port, 8080);
        assert_eq!(key.remote_port, 443);
    }

    #[test]
    fn test_connection_registry_upsert() {
        let registry = ConnectionRegistry::new();
        let key = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        let entry = ConnectionEntry::new(key.clone(), ConnectionState::Established);

        registry.upsert(entry);
        assert!(registry.contains(&key));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_connection_state_parsing() {
        assert_eq!(ConnectionState::from_tcp_state(0x01), ConnectionState::Established);
        assert_eq!(ConnectionState::from_tcp_state(0x0A), ConnectionState::Listen);
        assert_eq!(ConnectionState::from_tcp_state(0xFF), ConnectionState::Unknown);
    }

    #[test]
    fn test_connection_reporting() {
        let registry = ConnectionRegistry::new();
        let key = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        let entry = ConnectionEntry::new(key.clone(), ConnectionState::Established);

        registry.upsert(entry);
        assert!(!registry.is_reported(&key));

        registry.mark_reported(&key);
        assert!(registry.is_reported(&key));
    }

    #[test]
    fn test_connections_by_pid() {
        let registry = ConnectionRegistry::new();

        // Add two connections from different PIDs
        let key1 = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        let key2 = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8081,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );

        let entry1 = ConnectionEntry::new(key1, ConnectionState::Established).with_process(100, Some("curl".to_string()));
        let entry2 = ConnectionEntry::new(key2, ConnectionState::Established).with_process(200, Some("wget".to_string()));

        registry.upsert(entry1);
        registry.upsert(entry2);

        let conns_100 = registry.connections_from_pid(100);
        assert_eq!(conns_100.len(), 1);
        assert_eq!(conns_100[0].process_name, Some("curl".to_string()));
    }
}
