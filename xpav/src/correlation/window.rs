//! Sliding time window for event correlation.

use crate::detection::DetectionEvent;
use chrono::{Duration, Utc};
use std::collections::VecDeque;

/// Sliding time window that keeps events within a specified duration.
#[derive(Debug)]
pub struct SlidingWindow {
    /// Events in the window
    events: VecDeque<DetectionEvent>,
    /// Window duration in seconds
    window_secs: i64,
    /// Maximum number of events to keep
    max_events: usize,
}

impl SlidingWindow {
    /// Create a new sliding window with the given duration in seconds.
    pub fn new(window_secs: u64) -> Self {
        Self {
            events: VecDeque::new(),
            window_secs: window_secs as i64,
            max_events: 10000, // Prevent unbounded growth
        }
    }

    /// Create with custom maximum event count.
    pub fn with_max_events(window_secs: u64, max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            window_secs: window_secs as i64,
            max_events,
        }
    }

    /// Add an event to the window.
    pub fn add(&mut self, event: DetectionEvent) {
        self.cleanup_old();

        // Enforce max events
        while self.events.len() >= self.max_events {
            self.events.pop_front();
        }

        self.events.push_back(event);
    }

    /// Get all events in the window (clones all events).
    /// For iteration without cloning, use `iter()` instead.
    pub fn events(&self) -> Vec<DetectionEvent> {
        self.events.iter().cloned().collect()
    }

    /// Get an iterator over events without cloning.
    pub fn iter(&self) -> impl Iterator<Item = &DetectionEvent> {
        self.events.iter()
    }

    /// Get the number of events in the window.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Check if any event matches a predicate (without cloning).
    pub fn any<F>(&self, predicate: F) -> bool
    where
        F: Fn(&DetectionEvent) -> bool,
    {
        self.events.iter().any(predicate)
    }

    /// Count events matching a predicate (without cloning).
    pub fn count<F>(&self, predicate: F) -> usize
    where
        F: Fn(&DetectionEvent) -> bool,
    {
        self.events.iter().filter(|e| predicate(e)).count()
    }

    /// Remove events older than the window duration.
    fn cleanup_old(&mut self) {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs);
        while let Some(front) = self.events.front() {
            if front.timestamp < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get events matching a predicate (clones matched events).
    /// For checking without cloning, use `any()` or `count()` instead.
    pub fn filter<F>(&self, predicate: F) -> Vec<DetectionEvent>
    where
        F: Fn(&DetectionEvent) -> bool,
    {
        self.events.iter().filter(|e| predicate(e)).cloned().collect()
    }

    /// Iterate over events matching a predicate without cloning.
    pub fn filter_iter<'a, F>(&'a self, predicate: F) -> impl Iterator<Item = &'a DetectionEvent>
    where
        F: Fn(&DetectionEvent) -> bool + 'a,
    {
        self.events.iter().filter(move |e| predicate(e))
    }

    /// Get events by threat type.
    pub fn by_threat_type(&self, threat_type: &crate::detection::ThreatType) -> Vec<DetectionEvent> {
        self.filter(|e| &e.threat_type == threat_type)
    }

    /// Get events by source.
    pub fn by_source(&self, source: &crate::detection::DetectionSource) -> Vec<DetectionEvent> {
        self.filter(|e| &e.source == source)
    }

    /// Get events associated with a specific PID.
    pub fn by_pid(&self, pid: u32) -> Vec<DetectionEvent> {
        self.filter(|e| e.process.as_ref().map(|p| p.pid) == Some(pid))
    }

    /// Clear all events from the window.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionSource, Severity, ThreatType};

    fn make_event(threat_type: ThreatType) -> DetectionEvent {
        DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            threat_type,
            Severity::High,
            "Test event",
        )
    }

    #[test]
    fn test_sliding_window_add() {
        let mut window = SlidingWindow::new(300);
        window.add(make_event(ThreatType::Cryptominer));
        assert_eq!(window.len(), 1);
    }

    #[test]
    fn test_sliding_window_max_events() {
        let mut window = SlidingWindow::with_max_events(300, 3);

        window.add(make_event(ThreatType::Cryptominer));
        window.add(make_event(ThreatType::Webshell));
        window.add(make_event(ThreatType::C2Connection));
        window.add(make_event(ThreatType::PersistenceMechanism));

        assert_eq!(window.len(), 3);
    }

    #[test]
    fn test_sliding_window_filter() {
        let mut window = SlidingWindow::new(300);
        window.add(make_event(ThreatType::Cryptominer));
        window.add(make_event(ThreatType::Webshell));
        window.add(make_event(ThreatType::Cryptominer));

        let miners = window.by_threat_type(&ThreatType::Cryptominer);
        assert_eq!(miners.len(), 2);
    }

    #[test]
    fn test_sliding_window_iter() {
        let mut window = SlidingWindow::new(300);
        window.add(make_event(ThreatType::Cryptominer));
        window.add(make_event(ThreatType::Webshell));

        // Test iterator without cloning
        let count = window.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_sliding_window_any() {
        let mut window = SlidingWindow::new(300);
        window.add(make_event(ThreatType::Cryptominer));
        window.add(make_event(ThreatType::Webshell));

        assert!(window.any(|e| e.threat_type == ThreatType::Cryptominer));
        assert!(!window.any(|e| e.threat_type == ThreatType::C2Connection));
    }

    #[test]
    fn test_sliding_window_count() {
        let mut window = SlidingWindow::new(300);
        window.add(make_event(ThreatType::Cryptominer));
        window.add(make_event(ThreatType::Webshell));
        window.add(make_event(ThreatType::Cryptominer));

        assert_eq!(window.count(|e| e.threat_type == ThreatType::Cryptominer), 2);
        assert_eq!(window.count(|e| e.threat_type == ThreatType::Webshell), 1);
        assert_eq!(window.count(|e| e.threat_type == ThreatType::C2Connection), 0);
    }

    #[test]
    fn test_sliding_window_filter_iter() {
        let mut window = SlidingWindow::new(300);
        window.add(make_event(ThreatType::Cryptominer));
        window.add(make_event(ThreatType::Webshell));
        window.add(make_event(ThreatType::Cryptominer));

        // Test filter_iter without cloning (only counts references)
        let miner_count = window.filter_iter(|e| e.threat_type == ThreatType::Cryptominer).count();
        assert_eq!(miner_count, 2);
    }
}
