//! Compound threat pattern definitions.

use crate::detection::{DetectionEvent, ThreatType};
use serde::{Deserialize, Serialize};

/// Types of compound threats that can be detected through correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompoundThreat {
    /// APT: webshell + C2 + persistence
    Apt,
    /// Cryptominer infection: miner + pool connection + cron job
    CryptominerInfection,
    /// Container breakout: privilege escalation + namespace change + host access
    ContainerBreakout,
    /// Rootkit installation: eBPF program + sensitive kprobe
    RootkitInstallation,
    /// Webshell attack chain: webshell + shell spawn + data exfiltration
    WebshellAttackChain,
    /// Supply chain compromise: integrity violation + suspicious execution
    SupplyChainCompromise,
}

impl std::fmt::Display for CompoundThreat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompoundThreat::Apt => write!(f, "APT (Advanced Persistent Threat)"),
            CompoundThreat::CryptominerInfection => write!(f, "Cryptominer Infection"),
            CompoundThreat::ContainerBreakout => write!(f, "Container Breakout"),
            CompoundThreat::RootkitInstallation => write!(f, "Rootkit Installation"),
            CompoundThreat::WebshellAttackChain => write!(f, "Webshell Attack Chain"),
            CompoundThreat::SupplyChainCompromise => write!(f, "Supply Chain Compromise"),
        }
    }
}

/// A pattern that defines a compound threat.
#[derive(Debug)]
pub struct ThreatPattern {
    /// Name of the pattern
    pub name: String,
    /// The compound threat this pattern detects
    pub compound_threat: CompoundThreat,
    /// Required threat types (all must be present)
    pub required: Vec<ThreatType>,
    /// Optional threat types (boost confidence if present)
    pub optional: Vec<ThreatType>,
    /// Minimum number of required threats to match
    pub min_required: usize,
    /// Time window for correlation (seconds)
    pub window_secs: u64,
}

impl ThreatPattern {
    /// Create a new threat pattern.
    pub fn new(name: impl Into<String>, compound_threat: CompoundThreat) -> Self {
        Self {
            name: name.into(),
            compound_threat,
            required: Vec::new(),
            optional: Vec::new(),
            min_required: 0,
            window_secs: 300,
        }
    }

    /// Add a required threat type.
    pub fn require(mut self, threat_type: ThreatType) -> Self {
        self.required.push(threat_type);
        self
    }

    /// Add an optional threat type.
    pub fn optional(mut self, threat_type: ThreatType) -> Self {
        self.optional.push(threat_type);
        self
    }

    /// Set minimum required threats.
    pub fn min_required(mut self, min: usize) -> Self {
        self.min_required = min;
        self
    }

    /// Set the time window.
    pub fn window(mut self, secs: u64) -> Self {
        self.window_secs = secs;
        self
    }

    /// Check if this pattern matches the given events.
    pub fn matches(&self, events: &[DetectionEvent]) -> Option<CompoundThreat> {
        let event_types: Vec<&ThreatType> = events.iter().map(|e| &e.threat_type).collect();

        // Count how many required types are present
        let required_count = self
            .required
            .iter()
            .filter(|t| event_types.contains(t))
            .count();

        // Check minimum required threshold
        let threshold = if self.min_required > 0 {
            self.min_required
        } else {
            self.required.len()
        };

        if required_count >= threshold {
            Some(self.compound_threat.clone())
        } else {
            None
        }
    }
}

/// Create the default set of threat patterns.
pub fn default_patterns() -> Vec<ThreatPattern> {
    vec![
        // APT: webshell + C2 + persistence
        ThreatPattern::new("APT Detection", CompoundThreat::Apt)
            .require(ThreatType::Webshell)
            .require(ThreatType::C2Connection)
            .require(ThreatType::PersistenceMechanism)
            .min_required(2)
            .window(600),
        // Cryptominer infection
        ThreatPattern::new("Cryptominer Infection", CompoundThreat::CryptominerInfection)
            .require(ThreatType::Cryptominer)
            .require(ThreatType::MiningPoolConnection)
            .optional(ThreatType::CronModification)
            .min_required(2)
            .window(300),
        // Container breakout
        ThreatPattern::new("Container Breakout", CompoundThreat::ContainerBreakout)
            .require(ThreatType::SuspiciousCapability)
            .require(ThreatType::SuspiciousNamespaceChange)
            .require(ThreatType::HostMountAccess)
            .min_required(2)
            .window(120),
        // Rootkit installation
        ThreatPattern::new("Rootkit Installation", CompoundThreat::RootkitInstallation)
            .require(ThreatType::SuspiciousEbpfProgram)
            .require(ThreatType::SensitiveKprobeAttachment)
            .min_required(2)
            .window(60),
        // Webshell attack chain
        ThreatPattern::new("Webshell Attack Chain", CompoundThreat::WebshellAttackChain)
            .require(ThreatType::Webshell)
            .require(ThreatType::WebServerShellSpawn)
            .optional(ThreatType::C2Connection)
            .min_required(2)
            .window(300),
        // Supply chain compromise
        ThreatPattern::new("Supply Chain Compromise", CompoundThreat::SupplyChainCompromise)
            .require(ThreatType::IntegrityViolation)
            .require(ThreatType::CriticalBinaryModified)
            .optional(ThreatType::SuspiciousExecution)
            .min_required(2)
            .window(600),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionSource, Severity};

    fn make_event(threat_type: ThreatType) -> DetectionEvent {
        DetectionEvent::new(
            DetectionSource::ProcessMonitor,
            threat_type,
            Severity::High,
            "Test",
        )
    }

    #[test]
    fn test_apt_pattern() {
        let patterns = default_patterns();
        let apt_pattern = &patterns[0];

        // Should match with webshell + C2
        let events = vec![
            make_event(ThreatType::Webshell),
            make_event(ThreatType::C2Connection),
        ];
        assert!(apt_pattern.matches(&events).is_some());

        // Should not match with just webshell
        let events = vec![make_event(ThreatType::Webshell)];
        assert!(apt_pattern.matches(&events).is_none());
    }

    #[test]
    fn test_cryptominer_pattern() {
        let patterns = default_patterns();
        let miner_pattern = &patterns[1];

        let events = vec![
            make_event(ThreatType::Cryptominer),
            make_event(ThreatType::MiningPoolConnection),
        ];
        assert_eq!(
            miner_pattern.matches(&events),
            Some(CompoundThreat::CryptominerInfection)
        );
    }

    #[test]
    fn test_container_breakout_pattern() {
        let patterns = default_patterns();
        let breakout_pattern = &patterns[2];

        let events = vec![
            make_event(ThreatType::SuspiciousCapability),
            make_event(ThreatType::HostMountAccess),
        ];
        assert_eq!(
            breakout_pattern.matches(&events),
            Some(CompoundThreat::ContainerBreakout)
        );
    }
}
