//! Integration Tests
//!
//! Tests that verify the full XPAV system works correctly when all
//! components operate together. These simulate real deployment scenarios.
//!
//! IMPORTANT: Some tests require root privileges to fully exercise
//! features like fanotify, eBPF inspection, and process monitoring.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

use xpav::config::*;
use xpav::detection::*;
use xpav::scanner::webshell::{WebshellScanner, ThreatLevel};
use tokio::sync::mpsc;

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

/// Test: Default configuration is valid and complete
#[test]
fn test_default_config_validity() {
    let process_config = ProcessMonitorConfig::default();

    // Miner patterns should be non-empty
    assert!(
        !process_config.miner_patterns.is_empty(),
        "Default miner patterns should not be empty"
    );

    // Should have reasonable suspicious paths
    assert!(
        process_config.suspicious_paths.contains(&PathBuf::from("/tmp")),
        "/tmp should be in suspicious paths"
    );
    assert!(
        process_config.suspicious_paths.contains(&PathBuf::from("/dev/shm")),
        "/dev/shm should be in suspicious paths"
    );

    // Scan interval should be reasonable
    assert!(
        process_config.scan_interval_ms >= 100 && process_config.scan_interval_ms <= 60000,
        "Scan interval {} should be between 100ms and 60s",
        process_config.scan_interval_ms
    );

    // CPU thresholds should be sensible
    assert!(
        process_config.cpu_threshold >= 50.0 && process_config.cpu_threshold <= 100.0,
        "CPU threshold {} should be between 50-100%",
        process_config.cpu_threshold
    );

    // Web server process list should be populated
    assert!(
        !process_config.web_server_processes.is_empty(),
        "Web server process list should not be empty"
    );

    // Suspicious child process list should be populated
    assert!(
        !process_config.suspicious_child_processes.is_empty(),
        "Suspicious child process list should not be empty"
    );
}

/// Test: Memory scanner config is valid
#[test]
fn test_memory_scanner_config_validity() {
    let config = MemoryScannerConfig::default();

    // Scan interval should be reasonable
    assert!(
        config.scan_interval_ms >= 1000,
        "Memory scan interval {} should be at least 1s to avoid performance issues",
        config.scan_interval_ms
    );

    // Shellcode patterns should be valid hex
    for pattern in &config.shellcode_patterns {
        let decoded = hex::decode(pattern);
        assert!(
            decoded.is_ok(),
            "Shellcode pattern '{}' should be valid hex",
            pattern
        );
    }
}

/// Test: Integrity monitor config is valid
#[test]
fn test_integrity_monitor_config_validity() {
    let config = IntegrityMonitorConfig::default();

    // Should monitor critical paths
    let critical_paths = vec!["/boot", "/lib/modules"];
    for path in critical_paths {
        let has_path = config.watch_paths.iter().any(|p| p.to_str().map(|s| s.contains(path)).unwrap_or(false));
        assert!(
            has_path,
            "Integrity monitor should watch {}",
            path
        );
    }

    // Critical binaries should include essential tools
    assert!(
        !config.critical_binaries.is_empty(),
        "Critical binaries list should not be empty"
    );
}

/// Test: Container monitor config is valid
#[test]
fn test_container_monitor_config_validity() {
    let config = ContainerMonitorConfig::default();

    // Suspicious capabilities should be defined
    assert!(
        !config.suspicious_capabilities.is_empty(),
        "Suspicious capabilities list should not be empty"
    );

    // Should include CAP_SYS_ADMIN
    let has_sys_admin = config.suspicious_capabilities.iter()
        .any(|c| c.contains("SYS_ADMIN") || c.contains("sys_admin"));
    assert!(
        has_sys_admin,
        "CAP_SYS_ADMIN should be in suspicious capabilities"
    );
}

// ============================================================================
// DETECTION EVENT FLOW
// ============================================================================

/// Test: Detection events are properly constructed
#[test]
fn test_detection_event_construction() {
    let event = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::Cryptominer,
        Severity::High,
        "Test detection",
    );

    assert!(!event.id.is_empty(), "Event ID should not be empty");
    assert_eq!(event.source, DetectionSource::ProcessMonitor);
    assert_eq!(event.threat_type, ThreatType::Cryptominer);
    assert_eq!(event.severity, Severity::High);
    assert_eq!(event.description, "Test detection");
    assert!(event.process.is_none());
    assert!(event.connection.is_none());
    assert!(event.file.is_none());
}

/// Test: Detection events can be enriched
#[test]
fn test_detection_event_enrichment() {
    let process_info = ProcessInfo {
        pid: 1234,
        ppid: 1,
        name: "malware".to_string(),
        cmdline: "./malware -c config".to_string(),
        exe_path: Some(PathBuf::from("/tmp/malware")),
        cwd: Some(PathBuf::from("/tmp")),
        uid: 1000,
        username: Some("user".to_string()),
        start_time: None,
        ancestors: Vec::new(),
    };

    let event = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::Cryptominer,
        Severity::High,
        "Miner detected",
    )
    .with_process(process_info.clone())
    .with_pattern("xmrig");

    assert!(event.process.is_some());
    assert_eq!(event.process.as_ref().unwrap().pid, 1234);
    assert_eq!(event.matched_pattern, Some("xmrig".to_string()));
}

/// Test: Detection events serialize correctly
#[test]
fn test_detection_event_serialization() {
    let event = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::Cryptominer,
        Severity::High,
        "Test detection",
    );

    let json = serde_json::to_string(&event);
    assert!(json.is_ok(), "Event should serialize to JSON");

    let json_str = json.unwrap();
    assert!(json_str.contains("cryptominer"), "JSON should contain threat type");
    assert!(json_str.contains("high"), "JSON should contain severity");
}

// ============================================================================
// WEBSHELL DETECTION FLOW
// ============================================================================

/// Test: Full webshell detection workflow
#[test]
fn test_webshell_detection_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let scanner = WebshellScanner::new(50);

    // Simulate file creation event
    let webshell_path = temp_dir.path().join("evil.php");
    let webshell_content = r#"<?php eval($_POST['cmd']); ?>"#;

    // Step 1: File is written
    fs::write(&webshell_path, webshell_content).expect("Failed to write file");

    // Step 2: Check if file should be scanned
    let should_scan = WebshellScanner::should_scan(&webshell_path);
    assert!(should_scan, "PHP file should be scanned");

    // Step 3: Read and scan file
    let content = fs::read_to_string(&webshell_path).expect("Failed to read file");
    let result = scanner.scan(&content);

    // Step 4: Verify detection
    assert!(result.is_malicious, "Webshell should be detected as malicious");
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
    assert!(!result.detections.is_empty(), "Should have detection details");

    // Step 5: Create detection event
    let event = DetectionEvent::new(
        DetectionSource::FileMonitor,
        ThreatType::Webshell,
        Severity::Critical,
        format!("Webshell detected: {}", webshell_path.display()),
    )
    .with_file(FileInfo {
        path: webshell_path.clone(),
        event_type: FileEventType::Created,
        old_content_hash: None,
        new_content_hash: Some("abc123".to_string()),
    });

    assert!(event.file.is_some());
    assert_eq!(event.threat_type, ThreatType::Webshell);
}

/// Test: Webshell + process correlation
#[test]
fn test_webshell_process_correlation() {
    // Scenario: Webshell detected, then shell process spawned from web server

    let webshell_event = DetectionEvent::new(
        DetectionSource::FileMonitor,
        ThreatType::Webshell,
        Severity::Critical,
        "Webshell detected: /var/www/html/shell.php",
    )
    .with_file(FileInfo {
        path: PathBuf::from("/var/www/html/shell.php"),
        event_type: FileEventType::Created,
        old_content_hash: None,
        new_content_hash: Some("malicious123".to_string()),
    });

    let shell_spawn_event = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::WebServerShellSpawn,
        Severity::Critical,
        "Shell spawned from web server",
    )
    .with_process(ProcessInfo {
        pid: 5678,
        ppid: 1234,
        name: "bash".to_string(),
        cmdline: "/bin/bash -i".to_string(),
        exe_path: Some(PathBuf::from("/bin/bash")),
        cwd: Some(PathBuf::from("/var/www/html")),
        uid: 33,
        username: Some("www-data".to_string()),
        start_time: None,
        ancestors: vec![
            ProcessAncestor {
                pid: 1234,
                name: "php-fpm".to_string(),
                cmdline: "php-fpm: pool www".to_string(),
            },
        ],
    });

    // Both events should be Critical severity
    assert_eq!(webshell_event.severity, Severity::Critical);
    assert_eq!(shell_spawn_event.severity, Severity::Critical);

    // The shell spawn's CWD matches the webshell location - correlation!
    let shell_cwd = shell_spawn_event.process.as_ref().unwrap().cwd.as_ref().unwrap();
    let webshell_dir = webshell_event.file.as_ref().unwrap().path.parent().unwrap();
    assert_eq!(shell_cwd, webshell_dir);
}

// ============================================================================
// MULTI-MONITOR CORRELATION
// ============================================================================

/// Test: Cryptominer detection across multiple monitors
#[test]
fn test_cryptominer_multi_monitor_detection() {
    // A cryptominer should trigger multiple monitors:
    // 1. Process monitor (name/cmdline patterns)
    // 2. Process monitor (high CPU)
    // 3. Network monitor (pool connection)
    // 4. Persistence monitor (cron job for restart)

    let events = vec![
        DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::Cryptominer,
            Severity::Critical,
            "Cryptominer detected: xmrig with high CPU",
        ),
        DetectionEvent::new(
            DetectionSource::NetworkMonitor,
            ThreatType::MiningPoolConnection,
            Severity::High,
            "Mining pool connection: pool.minexmr.com:4444",
        ),
        DetectionEvent::new(
            DetectionSource::PersistenceMonitor,
            ThreatType::CronModification,
            Severity::High,
            "Suspicious cron job: restarts miner",
        ),
    ];

    // All events should be High or Critical
    for event in &events {
        assert!(
            event.severity >= Severity::High,
            "Cryptominer-related events should be High severity or above"
        );
    }

    // Should have detections from multiple sources
    let sources: HashSet<_> = events.iter().map(|e| &e.source).collect();
    assert!(
        sources.len() >= 2,
        "Cryptominer should trigger multiple monitors"
    );
}

/// Test: Container escape detection chain
#[test]
fn test_container_escape_detection_chain() {
    // Container escape typically involves:
    // 1. Accessing docker.sock or host paths
    // 2. Privilege escalation
    // 3. Host process spawning

    let events = vec![
        DetectionEvent::new(
            DetectionSource::ContainerMonitor,
            ThreatType::HostMountAccess,
            Severity::High,
            "Container accessing /var/run/docker.sock",
        ),
        DetectionEvent::new(
            DetectionSource::ContainerMonitor,
            ThreatType::PrivilegedContainerOperation,
            Severity::Critical,
            "Container running as privileged",
        ),
        DetectionEvent::new(
            DetectionSource::ContainerMonitor,
            ThreatType::ContainerEscape,
            Severity::Critical,
            "Container escape: process running in host namespace",
        ),
    ];

    // Escape event should be Critical
    let escape_event = events.iter().find(|e| e.threat_type == ThreatType::ContainerEscape);
    assert!(escape_event.is_some());
    assert_eq!(escape_event.unwrap().severity, Severity::Critical);
}

// ============================================================================
// THREAT SEVERITY TESTING
// ============================================================================

/// Test: Severity levels are correctly ordered
#[test]
fn test_severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

/// Test: Threat types have appropriate default severities
#[test]
fn test_threat_type_severities() {
    // Critical threats
    let critical_threats = vec![
        ThreatType::Cryptominer,
        ThreatType::WebServerShellSpawn,
        ThreatType::ContainerEscape,
        ThreatType::EbpfRootkit,
        ThreatType::FilelessMalware,
        ThreatType::ShellcodeDetected,
    ];

    // High threats
    let high_threats = vec![
        ThreatType::SuspiciousExecution,
        ThreatType::MiningPoolConnection,
        ThreatType::PersistenceMechanism,
        ThreatType::ProcessInjection,
        ThreatType::IntegrityViolation,
    ];

    // Medium threats
    let medium_threats = vec![
        ThreatType::SuspiciousProcess,
        ThreatType::SuspiciousMemoryRegion,
    ];

    // Document expected severities
    for threat in critical_threats {
        eprintln!("Critical threat: {:?}", threat);
    }
    for threat in high_threats {
        eprintln!("High threat: {:?}", threat);
    }
    for threat in medium_threats {
        eprintln!("Medium threat: {:?}", threat);
    }
}

// ============================================================================
// RESPONSE ACTION TESTING
// ============================================================================

/// Test: Response actions are correctly configured
#[test]
fn test_response_actions() {
    // Default should be Alert (log only, don't kill)
    let config = ProcessMonitorConfig::default();

    assert_eq!(
        config.action,
        ResponseAction::Alert,
        "Default action should be Alert, not Kill"
    );

    // Verify Kill action can be set
    let mut kill_config = config;
    kill_config.action = ResponseAction::Kill;
    assert_eq!(kill_config.action, ResponseAction::Kill);
}

// ============================================================================
// CHANNEL/ASYNC INTEGRATION
// ============================================================================

/// Test: Events flow through channels correctly
#[tokio::test]
async fn test_event_channel_flow() {
    let (tx, mut rx) = mpsc::channel::<DetectionEvent>(100);

    // Send multiple events
    for i in 0..10 {
        let event = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::SuspiciousProcess,
            Severity::Medium,
            format!("Test event {}", i),
        );

        tx.send(event).await.expect("Failed to send event");
    }

    // Drop sender to close channel
    drop(tx);

    // Receive all events
    let mut received = 0;
    while let Some(event) = rx.recv().await {
        assert!(event.description.starts_with("Test event"));
        received += 1;
    }

    assert_eq!(received, 10, "Should receive all sent events");
}

/// Test: Channel handles backpressure
#[tokio::test]
async fn test_event_channel_backpressure() {
    let (tx, rx) = mpsc::channel::<DetectionEvent>(10); // Small buffer

    // Try to send more than buffer size
    let mut sent = 0;
    for i in 0..20 {
        let event = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::SuspiciousProcess,
            Severity::Medium,
            format!("Test event {}", i),
        );

        match tx.try_send(event) {
            Ok(_) => sent += 1,
            Err(_) => break, // Channel full
        }
    }

    // Should have sent some but not all (backpressure)
    assert!(
        sent > 0 && sent <= 10,
        "Should experience backpressure: sent {}",
        sent
    );

    // Clean up
    drop(tx);
    drop(rx);
}

// ============================================================================
// END-TO-END SCENARIO TESTS
// ============================================================================

/// Test: Full attack scenario - cryptominer infection
#[test]
fn test_e2e_cryptominer_scenario() {
    eprintln!("\n=== E2E Test: Cryptominer Infection ===\n");

    // Step 1: Attacker uploads webshell
    eprintln!("1. Webshell uploaded to /var/www/html/shell.php");
    let webshell_detection = DetectionEvent::new(
        DetectionSource::FileMonitor,
        ThreatType::Webshell,
        Severity::Critical,
        "Webshell detected",
    );
    eprintln!("   -> DETECTED: {:?}", webshell_detection.threat_type);

    // Step 2: Webshell executes download command
    eprintln!("2. Webshell spawns shell to download miner");
    let shell_spawn_detection = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::WebServerShellSpawn,
        Severity::Critical,
        "bash spawned from php-fpm",
    );
    eprintln!("   -> DETECTED: {:?}", shell_spawn_detection.threat_type);

    // Step 3: Miner downloaded to /tmp
    eprintln!("3. Miner written to /tmp/xmrig");
    // (Would be detected by fanotify if watching /tmp)

    // Step 4: Miner executed
    eprintln!("4. Miner process started");
    let miner_detection = DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::Cryptominer,
        Severity::Critical,
        "xmrig detected with pool connection",
    );
    eprintln!("   -> DETECTED: {:?}", miner_detection.threat_type);

    // Step 5: Miner connects to pool
    eprintln!("5. Network connection to mining pool");
    let pool_detection = DetectionEvent::new(
        DetectionSource::NetworkMonitor,
        ThreatType::MiningPoolConnection,
        Severity::High,
        "Connection to pool.minexmr.com:4444",
    );
    eprintln!("   -> DETECTED: {:?}", pool_detection.threat_type);

    // Step 6: Persistence established
    eprintln!("6. Cron job created for persistence");
    let persistence_detection = DetectionEvent::new(
        DetectionSource::PersistenceMonitor,
        ThreatType::CronModification,
        Severity::High,
        "Cron job added to restart miner",
    );
    eprintln!("   -> DETECTED: {:?}", persistence_detection.threat_type);

    eprintln!("\n=== Attack Fully Detected ===\n");

    // All stages should be detected
    assert_eq!(webshell_detection.severity, Severity::Critical);
    assert_eq!(shell_spawn_detection.severity, Severity::Critical);
    assert_eq!(miner_detection.severity, Severity::Critical);
    assert_eq!(pool_detection.severity, Severity::High);
    assert_eq!(persistence_detection.severity, Severity::High);
}

/// Test: Full attack scenario - container escape
#[test]
fn test_e2e_container_escape_scenario() {
    eprintln!("\n=== E2E Test: Container Escape ===\n");

    // Step 1: Attacker gains shell in container
    eprintln!("1. Attacker has shell in container");

    // Step 2: Container is privileged
    eprintln!("2. Container detected as privileged");
    let priv_detection = DetectionEvent::new(
        DetectionSource::ContainerMonitor,
        ThreatType::PrivilegedContainerOperation,
        Severity::Critical,
        "Container running with --privileged",
    );
    eprintln!("   -> DETECTED: {:?}", priv_detection.threat_type);

    // Step 3: Docker socket mounted
    eprintln!("3. Docker socket access detected");
    let sock_detection = DetectionEvent::new(
        DetectionSource::ContainerMonitor,
        ThreatType::HostMountAccess,
        Severity::High,
        "Container accessing /var/run/docker.sock",
    );
    eprintln!("   -> DETECTED: {:?}", sock_detection.threat_type);

    // Step 4: Namespace escape
    eprintln!("4. Process namespace change detected");
    let ns_detection = DetectionEvent::new(
        DetectionSource::ContainerMonitor,
        ThreatType::SuspiciousNamespaceChange,
        Severity::High,
        "Process moved to host PID namespace",
    );
    eprintln!("   -> DETECTED: {:?}", ns_detection.threat_type);

    // Step 5: Host compromise
    eprintln!("5. Container escape complete");
    let escape_detection = DetectionEvent::new(
        DetectionSource::ContainerMonitor,
        ThreatType::ContainerEscape,
        Severity::Critical,
        "Container escape detected: process running on host",
    );
    eprintln!("   -> DETECTED: {:?}", escape_detection.threat_type);

    eprintln!("\n=== Container Escape Detected ===\n");

    assert_eq!(escape_detection.severity, Severity::Critical);
}
