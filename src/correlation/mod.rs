//! Correlation engine for detecting compound threats.
//!
//! This module will be fully implemented in Phase 4.1.

mod enrichment;
mod patterns;
mod scoring;
mod window;

pub use enrichment::EventEnricher;
pub use patterns::{CompoundThreat, ThreatPattern, default_patterns};
pub use scoring::SeverityScorer;
pub use window::SlidingWindow;

use crate::detection::DetectionEvent;
use crate::state::StateStore;
use chrono;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Correlation engine that detects compound threats from individual events.
pub struct CorrelationEngine {
    /// Shared state store
    state: Arc<StateStore>,
    /// Sliding time window for event correlation
    window: SlidingWindow,
    /// Event enricher
    enricher: EventEnricher,
    /// Threat patterns to match
    patterns: Vec<ThreatPattern>,
    /// Severity scorer
    scorer: SeverityScorer,
}

impl CorrelationEngine {
    /// Create a new correlation engine.
    pub fn new(state: Arc<StateStore>) -> Self {
        Self {
            state,
            window: SlidingWindow::new(300), // 5 minute window
            enricher: EventEnricher::new(),
            patterns: patterns::default_patterns(),
            scorer: SeverityScorer::new(),
        }
    }

    /// Create with custom window duration.
    pub fn with_window_secs(state: Arc<StateStore>, window_secs: u64) -> Self {
        Self {
            state,
            window: SlidingWindow::new(window_secs),
            enricher: EventEnricher::new(),
            patterns: patterns::default_patterns(),
            scorer: SeverityScorer::new(),
        }
    }

    /// Process an incoming event and check for correlations.
    pub fn process(&mut self, event: DetectionEvent) -> Vec<CorrelatedEvent> {
        // Enrich the event with additional context
        let enriched = self.enricher.enrich(event, &self.state);

        // Add to sliding window
        self.window.add(enriched.clone());

        // Check all patterns
        let mut results = Vec::new();

        for pattern in &self.patterns {
            // Filter events to the pattern's specific time window
            // Each pattern has its own window_secs (e.g., APT=600s, Rootkit=60s)
            let cutoff = chrono::Utc::now() - chrono::Duration::seconds(pattern.window_secs as i64);
            let events_in_window: Vec<DetectionEvent> = self.window
                .filter_iter(|e| e.timestamp > cutoff)
                .cloned()
                .collect();

            if let Some(compound) = pattern.matches(&events_in_window) {
                let severity = self.scorer.score(&compound, &events_in_window);
                results.push(CorrelatedEvent {
                    original: enriched.clone(),
                    compound_threat: Some(compound),
                    escalated_severity: Some(severity),
                    related_events: events_in_window,
                });
            }
        }

        // If no compound threat, return the original event
        if results.is_empty() {
            results.push(CorrelatedEvent {
                original: enriched,
                compound_threat: None,
                escalated_severity: None,
                related_events: Vec::new(),
            });
        }

        results
    }

    /// Run the correlation engine as an async task.
    pub async fn run(
        mut self,
        mut input: mpsc::Receiver<DetectionEvent>,
        output: mpsc::Sender<CorrelatedEvent>,
    ) {
        while let Some(event) = input.recv().await {
            for correlated in self.process(event) {
                if output.send(correlated).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// An event that has been processed by the correlation engine.
#[derive(Debug, Clone)]
pub struct CorrelatedEvent {
    /// The original detection event
    pub original: DetectionEvent,
    /// Compound threat if detected
    pub compound_threat: Option<CompoundThreat>,
    /// Escalated severity if applicable
    pub escalated_severity: Option<crate::detection::Severity>,
    /// Related events that contributed to the correlation
    pub related_events: Vec<DetectionEvent>,
}

impl CorrelatedEvent {
    /// Check if this is a compound threat.
    pub fn is_compound(&self) -> bool {
        self.compound_threat.is_some()
    }

    /// Get the effective severity (escalated if compound, original otherwise).
    pub fn effective_severity(&self) -> crate::detection::Severity {
        self.escalated_severity.unwrap_or(self.original.severity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionSource, Severity, ThreatType};

    #[test]
    fn test_correlation_engine_creation() {
        let state = StateStore::new().shared();
        let engine = CorrelationEngine::new(state);
        assert!(!engine.patterns.is_empty());
    }

    #[test]
    fn test_process_single_event() {
        let state = StateStore::new().shared();
        let mut engine = CorrelationEngine::new(state);

        let event = DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::Cryptominer,
            Severity::High,
            "Test cryptominer detected",
        );

        let results = engine.process(event);
        assert!(!results.is_empty());
    }
}
