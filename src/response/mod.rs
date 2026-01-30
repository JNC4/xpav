//! Response actions - handles threat detection events

use crate::config::LogFormat;
use crate::detection::{DetectionEvent, Severity};
use crate::metrics::{DETECTIONS_TOTAL, EVENTS_PROCESSED, WEBHOOK_FAILURES, WEBHOOK_SUCCESS};
use tokio::sync::mpsc;
use tracing::info;

#[cfg(feature = "webhooks")]
use tracing::{error, warn};

pub struct ResponseHandler {
    log_format: LogFormat,
    webhook_url: Option<String>,
    #[allow(dead_code)]
    dry_run: bool,
    #[cfg(feature = "webhooks")]
    http_client: reqwest::Client,
}

impl ResponseHandler {
    pub fn new(log_format: LogFormat, webhook_url: Option<String>, dry_run: bool) -> Self {
        #[cfg(feature = "webhooks")]
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            log_format,
            webhook_url,
            dry_run,
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
