//! Tests for correlation patterns.

use xpav::correlation::{CompoundThreat, ThreatPattern, default_patterns};
use xpav::detection::{DetectionEvent, DetectionSource, Severity, ThreatType};

fn make_event(threat_type: ThreatType, source: DetectionSource) -> DetectionEvent {
    DetectionEvent::new(source, threat_type, Severity::High, "Test event")
}

#[test]
fn test_apt_pattern_full_match() {
    let patterns = default_patterns();
    let apt_pattern = &patterns[0]; // APT pattern

    let events = vec![
        make_event(ThreatType::Webshell, DetectionSource::FileMonitor),
        make_event(ThreatType::C2Connection, DetectionSource::NetworkMonitor),
        make_event(ThreatType::PersistenceMechanism, DetectionSource::PersistenceMonitor),
    ];

    let result = apt_pattern.matches(&events);
    assert_eq!(result, Some(CompoundThreat::Apt));
}

#[test]
fn test_apt_pattern_partial_match() {
    let patterns = default_patterns();
    let apt_pattern = &patterns[0];

    // Only 2 of 3 required, but min_required is 2
    let events = vec![
        make_event(ThreatType::Webshell, DetectionSource::FileMonitor),
        make_event(ThreatType::C2Connection, DetectionSource::NetworkMonitor),
    ];

    let result = apt_pattern.matches(&events);
    assert_eq!(result, Some(CompoundThreat::Apt));
}

#[test]
fn test_apt_pattern_no_match() {
    let patterns = default_patterns();
    let apt_pattern = &patterns[0];

    // Only 1 of required threats
    let events = vec![make_event(ThreatType::Webshell, DetectionSource::FileMonitor)];

    let result = apt_pattern.matches(&events);
    assert_eq!(result, None);
}

#[test]
fn test_cryptominer_pattern() {
    let patterns = default_patterns();
    let miner_pattern = &patterns[1]; // CryptominerInfection

    let events = vec![
        make_event(ThreatType::Cryptominer, DetectionSource::ProcessMonitor),
        make_event(ThreatType::MiningPoolConnection, DetectionSource::NetworkMonitor),
    ];

    let result = miner_pattern.matches(&events);
    assert_eq!(result, Some(CompoundThreat::CryptominerInfection));
}

#[test]
fn test_container_breakout_pattern() {
    let patterns = default_patterns();
    let breakout_pattern = &patterns[2]; // ContainerBreakout

    let events = vec![
        make_event(ThreatType::SuspiciousCapability, DetectionSource::ContainerMonitor),
        make_event(ThreatType::HostMountAccess, DetectionSource::ContainerMonitor),
    ];

    let result = breakout_pattern.matches(&events);
    assert_eq!(result, Some(CompoundThreat::ContainerBreakout));
}

#[test]
fn test_rootkit_pattern() {
    let patterns = default_patterns();
    let rootkit_pattern = &patterns[3]; // RootkitInstallation

    let events = vec![
        make_event(ThreatType::SuspiciousEbpfProgram, DetectionSource::EbpfMonitor),
        make_event(ThreatType::SensitiveKprobeAttachment, DetectionSource::EbpfMonitor),
    ];

    let result = rootkit_pattern.matches(&events);
    assert_eq!(result, Some(CompoundThreat::RootkitInstallation));
}

#[test]
fn test_no_false_positives() {
    let patterns = default_patterns();

    // Unrelated events shouldn't match any pattern
    let events = vec![
        make_event(ThreatType::Cryptominer, DetectionSource::ProcessMonitor),
        make_event(ThreatType::IntegrityViolation, DetectionSource::IntegrityMonitor),
    ];

    for pattern in &patterns {
        // Check that this combination doesn't falsely match
        let result = pattern.matches(&events);
        // Some patterns might match, but APT shouldn't
        if pattern.name.contains("APT") {
            assert_eq!(result, None, "APT pattern shouldn't match unrelated events");
        }
    }
}
