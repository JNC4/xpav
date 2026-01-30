//! Severity scoring and escalation.

use crate::correlation::patterns::CompoundThreat;
use crate::detection::{DetectionEvent, Severity};

/// Scores and potentially escalates severity based on correlation.
#[derive(Debug, Default)]
pub struct SeverityScorer {
    /// Base escalation for compound threats
    escalate_compound: bool,
    /// Escalate on high occurrence count
    escalate_on_frequency: bool,
    /// Frequency threshold for escalation
    frequency_threshold: usize,
}

impl SeverityScorer {
    /// Create a new severity scorer with default settings.
    pub fn new() -> Self {
        Self {
            escalate_compound: true,
            escalate_on_frequency: true,
            frequency_threshold: 5,
        }
    }

    /// Set whether to escalate compound threats.
    pub fn with_compound_escalation(mut self, enabled: bool) -> Self {
        self.escalate_compound = enabled;
        self
    }

    /// Set whether to escalate on frequency.
    pub fn with_frequency_escalation(mut self, enabled: bool, threshold: usize) -> Self {
        self.escalate_on_frequency = enabled;
        self.frequency_threshold = threshold;
        self
    }

    /// Score a compound threat and return the appropriate severity.
    pub fn score(&self, compound: &CompoundThreat, events: &[DetectionEvent]) -> Severity {
        let base_severity = self.base_severity(compound);

        if !self.escalate_compound {
            return base_severity;
        }

        // Check if we should escalate based on frequency
        if self.escalate_on_frequency && events.len() >= self.frequency_threshold {
            return self.escalate(base_severity);
        }

        // Check if any individual event is already critical
        if events.iter().any(|e| e.severity == Severity::Critical) {
            return Severity::Critical;
        }

        base_severity
    }

    /// Get the base severity for a compound threat type.
    fn base_severity(&self, compound: &CompoundThreat) -> Severity {
        match compound {
            CompoundThreat::Apt => Severity::Critical,
            CompoundThreat::CryptominerInfection => Severity::High,
            CompoundThreat::ContainerBreakout => Severity::Critical,
            CompoundThreat::RootkitInstallation => Severity::Critical,
            CompoundThreat::WebshellAttackChain => Severity::Critical,
            CompoundThreat::SupplyChainCompromise => Severity::Critical,
        }
    }

    /// Escalate a severity level.
    fn escalate(&self, severity: Severity) -> Severity {
        match severity {
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High => Severity::Critical,
            Severity::Critical => Severity::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionSource, ThreatType};

    fn make_event(severity: Severity) -> DetectionEvent {
        DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            ThreatType::Cryptominer,
            severity,
            "Test",
        )
    }

    #[test]
    fn test_apt_severity() {
        let scorer = SeverityScorer::new();
        let events = vec![make_event(Severity::High), make_event(Severity::High)];
        let severity = scorer.score(&CompoundThreat::Apt, &events);
        assert_eq!(severity, Severity::Critical);
    }

    #[test]
    fn test_cryptominer_severity() {
        let scorer = SeverityScorer::new();
        let events = vec![make_event(Severity::Medium)];
        let severity = scorer.score(&CompoundThreat::CryptominerInfection, &events);
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn test_frequency_escalation() {
        let scorer = SeverityScorer::new().with_frequency_escalation(true, 3);
        let events = vec![
            make_event(Severity::Medium),
            make_event(Severity::Medium),
            make_event(Severity::Medium),
        ];
        let severity = scorer.score(&CompoundThreat::CryptominerInfection, &events);
        assert_eq!(severity, Severity::Critical);
    }

    #[test]
    fn test_critical_event_takes_precedence() {
        let scorer = SeverityScorer::new();
        let events = vec![make_event(Severity::Critical)];
        let severity = scorer.score(&CompoundThreat::CryptominerInfection, &events);
        assert_eq!(severity, Severity::Critical);
    }
}
