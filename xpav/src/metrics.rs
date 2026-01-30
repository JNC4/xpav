//! Prometheus metrics and health/metrics HTTP endpoints

#[cfg(feature = "metrics")]
mod inner {
    use axum::{routing::get, Router};
    use once_cell::sync::Lazy;
    use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
    use std::net::SocketAddr;
    use tokio::sync::watch;
    use tracing::{error, info};

    pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

    pub static DETECTIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        let opts = Opts::new("xpav_detections_total", "Total detections by source and severity");
        let counter = IntCounterVec::new(opts, &["source", "severity"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    });

    pub static EVENTS_PROCESSED: Lazy<IntCounter> = Lazy::new(|| {
        let counter = IntCounter::new("xpav_events_processed_total", "Total events processed").unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    });

    pub static WEBHOOK_SUCCESS: Lazy<IntCounter> = Lazy::new(|| {
        let counter = IntCounter::new("xpav_webhook_success_total", "Successful webhook sends").unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    });

    pub static WEBHOOK_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
        let counter = IntCounter::new("xpav_webhook_failures_total", "Failed webhook sends").unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    });

    pub static ACTIVE_MONITORS: Lazy<IntGauge> = Lazy::new(|| {
        let gauge = IntGauge::new("xpav_active_monitors", "Number of active monitors").unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    });

    pub static START_TIME: Lazy<IntGauge> = Lazy::new(|| {
        let gauge = IntGauge::new("xpav_start_time_seconds", "Unix timestamp when XPAV started").unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge.set(chrono::Utc::now().timestamp());
        gauge
    });

    async fn health_handler() -> &'static str { "OK" }

    async fn metrics_handler() -> String {
        let encoder = TextEncoder::new();
        let metric_families = REGISTRY.gather();
        encoder.encode_to_string(&metric_families).unwrap_or_default()
    }

    async fn ready_handler(ready: axum::extract::State<watch::Receiver<bool>>) -> (axum::http::StatusCode, &'static str) {
        if *ready.borrow() {
            (axum::http::StatusCode::OK, "READY")
        } else {
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "NOT READY")
        }
    }

    pub async fn start_server(addr: SocketAddr, ready_rx: watch::Receiver<bool>) {
        let _ = &*START_TIME;
        let _ = &*ACTIVE_MONITORS;

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/healthz", get(health_handler))
            .route("/ready", get(ready_handler))
            .route("/readyz", get(ready_handler))
            .route("/metrics", get(metrics_handler))
            .with_state(ready_rx);

        info!("Metrics server listening on {}", addr);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind metrics server to {}: {}", addr, e);
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            error!("Metrics server error: {}", e);
        }
    }
}

#[cfg(feature = "metrics")]
pub use inner::*;

// Stub implementations when metrics feature is disabled
#[cfg(not(feature = "metrics"))]
pub mod stubs {
    use std::net::SocketAddr;
    use tokio::sync::watch;

    pub struct NoOpCounter;
    impl NoOpCounter {
        pub fn inc(&self) {}
        pub fn with_label_values(&self, _: &[&str]) -> Self { Self }
    }

    pub struct NoOpGauge;
    impl NoOpGauge {
        pub fn inc(&self) {}
        pub fn set(&self, _: i64) {}
    }

    pub static DETECTIONS_TOTAL: NoOpCounter = NoOpCounter;
    pub static EVENTS_PROCESSED: NoOpCounter = NoOpCounter;
    pub static WEBHOOK_SUCCESS: NoOpCounter = NoOpCounter;
    pub static WEBHOOK_FAILURES: NoOpCounter = NoOpCounter;
    pub static ACTIVE_MONITORS: NoOpGauge = NoOpGauge;

    pub async fn start_server(_addr: SocketAddr, _ready_rx: watch::Receiver<bool>) {
        // No-op when metrics disabled
    }
}

#[cfg(not(feature = "metrics"))]
pub use stubs::*;
