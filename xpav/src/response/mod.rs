//! Response actions - handles threat detection events

pub mod actions;

pub use actions::{ActionResult, ResponseAction, ResponseActions};

use crate::config::{LogFormat, RateLimitConfig};
use crate::detection::{DetectionEvent, DetectionSource, Severity};
use crate::metrics::{DETECTIONS_TOTAL, EVENTS_PROCESSED, WEBHOOK_FAILURES, WEBHOOK_SUCCESS};
use crate::state::dedup::{DedupKey, EventDeduplicator};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn as tracing_warn};

#[cfg(feature = "webhooks")]
use tracing::{error, warn};

/// Rate limiter for detection events.
pub struct RateLimiter {
    dedup: EventDeduplicator,
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        // Use the longest cooldown as the TTL
        let max_ttl = config.low_seconds
            .max(config.medium_seconds)
            .max(config.high_seconds)
            .max(config.critical_seconds);

        Self {
            dedup: EventDeduplicator::with_config(max_ttl, 10000),
            config,
        }
    }

    /// Check if an event should be reported (not rate limited).
    pub fn should_report(&self, event: &DetectionEvent) -> bool {
        if !self.config.enabled {
            return true;
        }

        let ttl = self.cooldown_for_severity(&event.severity);
        let key = self.make_key(event);
        self.dedup.should_report_with_ttl(key, ttl as i64)
    }

    /// Get the cooldown period for a severity level.
    fn cooldown_for_severity(&self, severity: &Severity) -> u64 {
        match severity {
            Severity::Low => self.config.low_seconds,
            Severity::Medium => self.config.medium_seconds,
            Severity::High => self.config.high_seconds,
            Severity::Critical => self.config.critical_seconds,
        }
    }

    /// Create a deduplication key for an event.
    ///
    /// Keys are designed for better deduplication:
    /// - File detections: use path (not hash) - same file = same threat
    /// - Process spawns: use `parent_name>child_name` (not PIDs) - same spawn pattern = same threat
    /// - Execution: use exe path (not PID) - same executable = same threat
    /// - Network: use remote addr:port (existing behavior)
    fn make_key(&self, event: &DetectionEvent) -> DedupKey {
        // Build identifier based on event type for better deduplication
        let identifier = if let Some(ref file) = event.file {
            // File detections: use path for dedup (same file = same threat)
            Some(file.path.display().to_string())
        } else if let Some(ref proc) = event.process {
            // Process detections: build key based on threat type
            match event.threat_type {
                // For shell spawns from web servers, use parent>child pattern
                crate::detection::ThreatType::WebServerShellSpawn
                | crate::detection::ThreatType::WebServerSuspiciousChild => {
                    // Get parent name from ancestors if available
                    let parent_name = proc
                        .ancestors
                        .first()
                        .map(|a| a.name.clone())
                        .unwrap_or_else(|| format!("ppid:{}", proc.ppid));
                    Some(format!("{}>{}", parent_name, proc.name))
                }
                // For suspicious execution (from /tmp etc), use exe path
                crate::detection::ThreatType::SuspiciousExecution => {
                    proc.exe_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .or_else(|| Some(proc.name.clone()))
                }
                // For cryptominers, use name + pattern match (same miner = same threat)
                crate::detection::ThreatType::Cryptominer => {
                    Some(format!("miner:{}", proc.name))
                }
                // For other process detections, use exe path if available
                _ => proc
                    .exe_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .or_else(|| Some(format!("{}:{}", proc.name, proc.pid))),
            }
        } else if let Some(ref conn) = event.connection {
            // Network detections: use remote endpoint
            Some(format!("{}:{}", conn.remote_addr, conn.remote_port))
        } else {
            None
        };

        DedupKey::from_event(
            &format!("{:?}", event.source),
            &format!("{:?}", event.threat_type),
            identifier.as_deref(),
        )
    }

    /// Get the number of rate-limited events.
    pub fn limited_count(&self) -> usize {
        self.dedup.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

/// Burst detector for identifying event floods.
///
/// When too many events from the same source occur within a time window,
/// this indicates either:
/// 1. A false positive pattern (legitimate activity triggering many alerts)
/// 2. An actual attack (but individual alerts are less useful than aggregate)
pub struct BurstDetector {
    /// Event timestamps per detection source
    counters: HashMap<DetectionSource, VecDeque<Instant>>,
    /// Threshold: (count, window duration)
    threshold: (usize, Duration),
    /// Sources currently in burst mode
    burst_sources: HashMap<DetectionSource, Instant>,
}

impl BurstDetector {
    /// Create a new burst detector.
    ///
    /// - `threshold_count`: Number of events to trigger burst mode
    /// - `window_seconds`: Time window for counting events
    pub fn new(threshold_count: usize, window_seconds: u64) -> Self {
        Self {
            counters: HashMap::new(),
            threshold: (threshold_count, Duration::from_secs(window_seconds)),
            burst_sources: HashMap::new(),
        }
    }

    /// Record an event and check if we're in burst mode.
    ///
    /// Returns `true` if the source is currently experiencing a burst.
    pub fn record_and_check_burst(&mut self, source: DetectionSource) -> bool {
        let now = Instant::now();

        // Clean up expired burst states
        self.burst_sources
            .retain(|_, start| now.duration_since(*start) < self.threshold.1 * 2);

        // If already in burst mode for this source, stay in it
        if self.burst_sources.contains_key(&source) {
            return true;
        }

        // Get or create counter for this source
        let counter = self.counters.entry(source).or_insert_with(VecDeque::new);

        // Remove old timestamps
        let cutoff = now - self.threshold.1;
        while counter.front().map(|t| *t < cutoff).unwrap_or(false) {
            counter.pop_front();
        }

        // Add current event
        counter.push_back(now);

        // Check if we've hit the threshold
        if counter.len() >= self.threshold.0 {
            tracing_warn!(
                source = ?source,
                count = counter.len(),
                window_secs = self.threshold.1.as_secs(),
                "Burst detected - entering burst suppression mode"
            );
            self.burst_sources.insert(source, now);
            counter.clear(); // Reset counter
            return true;
        }

        false
    }

    /// Check if a source is currently in burst mode without recording.
    pub fn is_in_burst(&self, source: &DetectionSource) -> bool {
        if let Some(start) = self.burst_sources.get(source) {
            Instant::now().duration_since(*start) < self.threshold.1 * 2
        } else {
            false
        }
    }

    /// Get the number of sources currently in burst mode.
    pub fn burst_count(&self) -> usize {
        self.burst_sources.len()
    }
}

impl Default for BurstDetector {
    fn default() -> Self {
        Self::new(50, 60) // 50 events in 60 seconds
    }
}

pub struct ResponseHandler {
    log_format: LogFormat,
    webhook_url: Option<String>,
    #[allow(dead_code)]
    dry_run: bool,
    rate_limiter: RateLimiter,
    burst_detector: std::sync::Mutex<BurstDetector>,
    #[cfg(feature = "webhooks")]
    http_client: reqwest::Client,
}

impl ResponseHandler {
    /// Create a new response handler.
    pub fn new(log_format: LogFormat, webhook_url: Option<String>, dry_run: bool) -> Self {
        Self::with_rate_limit(log_format, webhook_url, dry_run, RateLimitConfig::default())
    }

    /// Create a new response handler with custom rate limiting.
    pub fn with_rate_limit(
        log_format: LogFormat,
        webhook_url: Option<String>,
        dry_run: bool,
        rate_limit_config: RateLimitConfig,
    ) -> Self {
        Self::with_burst_detection(
            log_format,
            webhook_url,
            dry_run,
            rate_limit_config,
            50, // default burst threshold
            60, // default burst window
        )
    }

    /// Create a new response handler with custom rate limiting and burst detection.
    pub fn with_burst_detection(
        log_format: LogFormat,
        webhook_url: Option<String>,
        dry_run: bool,
        rate_limit_config: RateLimitConfig,
        burst_threshold: usize,
        burst_window_seconds: u64,
    ) -> Self {
        #[cfg(feature = "webhooks")]
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            log_format,
            webhook_url,
            dry_run,
            rate_limiter: RateLimiter::new(rate_limit_config),
            burst_detector: std::sync::Mutex::new(BurstDetector::new(
                burst_threshold,
                burst_window_seconds,
            )),
            #[cfg(feature = "webhooks")]
            http_client,
        }
    }

    pub async fn run(&self, mut rx: mpsc::Receiver<DetectionEvent>) {
        info!("Response handler started");
        while let Some(event) = rx.recv().await {
            self.handle_event(&event).await;
        }
    }

    async fn handle_event(&self, event: &DetectionEvent) {
        EVENTS_PROCESSED.inc();

        // Check burst detection first
        let in_burst = {
            if let Ok(mut detector) = self.burst_detector.lock() {
                detector.record_and_check_burst(event.source)
            } else {
                false
            }
        };

        if in_burst {
            debug!(
                "Event suppressed due to burst: {:?} from {:?}",
                event.threat_type, event.source
            );
            return;
        }

        // Check rate limiting
        if !self.rate_limiter.should_report(event) {
            debug!(
                "Event rate limited: {:?} from {:?}",
                event.threat_type, event.source
            );
            return;
        }

        DETECTIONS_TOTAL
            .with_label_values(&[&event.source.to_string(), &severity_label(&event.severity)])
            .inc();

        self.log_event(event);

        #[cfg(feature = "webhooks")]
        if let Some(ref url) = self.webhook_url {
            if !self.dry_run {
                self.send_webhook(url, event).await;
            }
        }
    }

    fn log_event(&self, event: &DetectionEvent) {
        match self.log_format {
            LogFormat::Json => {
                if let Ok(json) = serde_json::to_string(event) {
                    println!("{}", json);
                }
            }
            LogFormat::Text => {
                println!(
                    "[{}] {} - {} (severity: {:?})",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    event.source,
                    event.description,
                    event.severity
                );
            }
        }
    }

    #[cfg(feature = "webhooks")]
    async fn send_webhook(&self, url: &str, event: &DetectionEvent) {
        let payload = serde_json::json!({
            "timestamp": event.timestamp.to_rfc3339(),
            "source": event.source.to_string(),
            "severity": severity_label(&event.severity),
            "threat_type": format!("{:?}", event.threat_type),
            "description": event.description,
            "process": event.process.as_ref().map(|p| serde_json::json!({
                "pid": p.pid,
                "name": p.name,
                "cmdline": p.cmdline,
                "exe_path": p.exe_path,
                "uid": p.uid,
            })),
            "file": event.file.as_ref().map(|f| serde_json::json!({
                "path": f.path,
            })),
            "connection": event.connection.as_ref().map(|c| serde_json::json!({
                "remote_addr": c.remote_addr,
                "remote_port": c.remote_port,
                "local_port": c.local_port,
            })),
        });

        match self.http_client.post(url).json(&payload).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    WEBHOOK_SUCCESS.inc();
                } else {
                    WEBHOOK_FAILURES.inc();
                    warn!("Webhook returned status {}: {}", resp.status(), url);
                }
            }
            Err(e) => {
                WEBHOOK_FAILURES.inc();
                error!("Webhook failed: {} - {}", url, e);
            }
        }
    }
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

impl std::fmt::Display for crate::detection::DetectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessMonitor => write!(f, "process"),
            Self::NetworkMonitor => write!(f, "network"),
            Self::PersistenceMonitor => write!(f, "persistence"),
            Self::FileMonitor => write!(f, "file"),
            Self::EbpfMonitor => write!(f, "ebpf"),
            Self::MemoryScanner => write!(f, "memory"),
            Self::IntegrityMonitor => write!(f, "integrity"),
            Self::ContainerMonitor => write!(f, "container"),
        }
    }
}
