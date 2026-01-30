//! Response actions - handles threat detection events

pub mod actions;

pub use actions::{ActionResult, ResponseAction, ResponseActions};

use crate::config::{LogFormat, RateLimitConfig};
use crate::detection::{DetectionEvent, Severity};
use crate::metrics::{DETECTIONS_TOTAL, EVENTS_PROCESSED, WEBHOOK_FAILURES, WEBHOOK_SUCCESS};
use crate::state::dedup::{DedupKey, EventDeduplicator};
use tokio::sync::mpsc;
use tracing::{debug, info};

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
    fn make_key(&self, event: &DetectionEvent) -> DedupKey {
        // Key is based on: source, threat_type, and relevant identifier
        let identifier = event.process.as_ref()
            .map(|p| p.pid.to_string())
            .or_else(|| event.file.as_ref().map(|f| f.path.display().to_string()))
            .or_else(|| event.connection.as_ref().map(|c| format!("{}:{}", c.remote_addr, c.remote_port)));

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

pub struct ResponseHandler {
    log_format: LogFormat,
    webhook_url: Option<String>,
    #[allow(dead_code)]
    dry_run: bool,
    rate_limiter: RateLimiter,
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

        // Check rate limiting
        if !self.rate_limiter.should_report(event) {
            debug!("Event rate limited: {:?} from {:?}", event.threat_type, event.source);
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

fn severity_label(s: &Severity) -> String {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }.to_string()
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
