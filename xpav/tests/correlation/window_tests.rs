//! Tests for the sliding window.

use xpav::correlation::SlidingWindow;
use xpav::detection::{DetectionEvent, DetectionSource, Severity, ThreatType};

fn make_event(threat_type: ThreatType) -> DetectionEvent {
    DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        threat_type,
        Severity::High,
        "Test event",
    )
}

#[test]
fn test_window_add() {
    let mut window = SlidingWindow::new(300);
    assert!(window.is_empty());

    window.add(make_event(ThreatType::Cryptominer));
    assert_eq!(window.len(), 1);

    window.add(make_event(ThreatType::Webshell));
    assert_eq!(window.len(), 2);
}

#[test]
fn test_window_max_events() {
    let mut window = SlidingWindow::with_max_events(300, 3);

    window.add(make_event(ThreatType::Cryptominer));
    window.add(make_event(ThreatType::Webshell));
    window.add(make_event(ThreatType::C2Connection));

    assert_eq!(window.len(), 3);

    // Adding a 4th event should evict the oldest
    window.add(make_event(ThreatType::PersistenceMechanism));
    assert_eq!(window.len(), 3);
}

#[test]
fn test_window_filter_by_type() {
    let mut window = SlidingWindow::new(300);

    window.add(make_event(ThreatType::Cryptominer));
    window.add(make_event(ThreatType::Webshell));
    window.add(make_event(ThreatType::Cryptominer));

    let miners = window.by_threat_type(&ThreatType::Cryptominer);
    assert_eq!(miners.len(), 2);

    let webshells = window.by_threat_type(&ThreatType::Webshell);
    assert_eq!(webshells.len(), 1);
}

#[test]
fn test_window_filter_by_source() {
    let mut window = SlidingWindow::new(300);

    window.add(DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::Cryptominer,
        Severity::High,
        "Process event",
    ));
    window.add(DetectionEvent::new(
        DetectionSource::NetworkMonitor,
        ThreatType::C2Connection,
        Severity::High,
        "Network event",
    ));
    window.add(DetectionEvent::new(
        DetectionSource::ProcessMonitor,
        ThreatType::SuspiciousProcess,
        Severity::Medium,
        "Another process event",
    ));

    let process_events = window.by_source(&DetectionSource::ProcessMonitor);
    assert_eq!(process_events.len(), 2);

    let network_events = window.by_source(&DetectionSource::NetworkMonitor);
    assert_eq!(network_events.len(), 1);
}

#[test]
fn test_window_clear() {
    let mut window = SlidingWindow::new(300);

    window.add(make_event(ThreatType::Cryptominer));
    window.add(make_event(ThreatType::Webshell));

    assert!(!window.is_empty());

    window.clear();

    assert!(window.is_empty());
    assert_eq!(window.len(), 0);
}

#[test]
fn test_window_events() {
    let mut window = SlidingWindow::new(300);

    window.add(make_event(ThreatType::Cryptominer));
    window.add(make_event(ThreatType::Webshell));

    let events = window.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].threat_type, ThreatType::Cryptominer);
    assert_eq!(events[1].threat_type, ThreatType::Webshell);
}
