//! Mock infrastructure for testing.

use xpav::detection::{DetectionEvent, DetectionSource, ProcessInfo, Severity, ThreatType};
use std::path::PathBuf;

/// Create a mock detection event.
pub fn mock_detection_event(
    source: DetectionSource,
    threat_type: ThreatType,
    severity: Severity,
) -> DetectionEvent {
    DetectionEvent::new(source, threat_type, severity, "Mock detection event")
}

/// Create a mock process detection event.
pub fn mock_process_event(pid: u32, name: &str, threat_type: ThreatType) -> DetectionEvent {
    let mut event = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        threat_type,
        Severity::High,
        format!("Process {} ({}) detected", name, pid),
    );

    event.process = Some(ProcessInfo {
        pid,
        ppid: 1,
        name: name.to_string(),
        cmdline: format!("/usr/bin/{}", name),
        exe_path: Some(PathBuf::from(format!("/usr/bin/{}", name))),
        cwd: Some(PathBuf::from("/tmp")),
        uid: 1000,
        username: Some("testuser".to_string()),
        start_time: None,
        ancestors: vec![],
    });

    event
}

/// Create a mock cryptominer detection.
pub fn mock_cryptominer_event(pid: u32) -> DetectionEvent {
    mock_process_event(pid, "xmrig", ThreatType::Cryptominer)
}

/// Create a mock webshell detection.
pub fn mock_webshell_event(path: &str) -> DetectionEvent {
    let mut event = DetectionEvent::new(
        DetectionSource::FileMonitor,
        ThreatType::Webshell,
        Severity::Critical,
        format!("Webshell detected: {}", path),
    );

    event.file = Some(xpav::detection::FileInfo {
        path: PathBuf::from(path),
        event_type: xpav::detection::FileEventType::Created,
        old_content_hash: None,
        new_content_hash: Some("abc123".to_string()),
    });

    event
}

/// Create a mock C2 connection detection.
pub fn mock_c2_event(remote_ip: &str, remote_port: u16) -> DetectionEvent {
    let mut event = DetectionEvent::new(
        DetectionSource::NetworkMonitor,
        ThreatType::C2Connection,
        Severity::Critical,
        format!("C2 connection to {}:{}", remote_ip, remote_port),
    );

    event.connection = Some(xpav::detection::ConnectionInfo {
        local_addr: "192.168.1.100".to_string(),
        local_port: 54321,
        remote_addr: remote_ip.to_string(),
        remote_port,
        state: "ESTABLISHED".to_string(),
        pid: Some(1234),
        process_name: Some("malware".to_string()),
    });

    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_detection_event() {
        let event = mock_detection_event(
            DetectionSource::ProcessMonitor,
            ThreatType::Cryptominer,
            Severity::High,
        );
        assert_eq!(event.source, DetectionSource::ProcessMonitor);
        assert_eq!(event.threat_type, ThreatType::Cryptominer);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn test_mock_process_event() {
        let event = mock_process_event(1234, "test_process", ThreatType::SuspiciousProcess);
        assert!(event.process.is_some());
        let process = event.process.unwrap();
        assert_eq!(process.pid, 1234);
        assert_eq!(process.name, "test_process");
    }

    #[test]
    fn test_mock_webshell_event() {
        let event = mock_webshell_event("/var/www/shell.php");
        assert!(event.file.is_some());
        let file = event.file.unwrap();
        assert_eq!(file.path.display().to_string(), "/var/www/shell.php");
    }

    #[test]
    fn test_mock_c2_event() {
        let event = mock_c2_event("10.0.0.1", 4444);
        assert!(event.connection.is_some());
        let conn = event.connection.unwrap();
        assert_eq!(conn.remote_addr, "10.0.0.1");
        assert_eq!(conn.remote_port, 4444);
    }
}
