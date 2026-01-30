use xpav::config::Config;
use xpav::config_broadcast::ConfigBroadcaster;
use xpav::metrics::{self, ACTIVE_MONITORS};
use xpav::monitors::{
    ContainerMonitor, EbpfMonitor, FanotifyMonitor, IntegrityMonitor, MemoryScanner,
    NetworkMonitor, PersistenceMonitor, ProcessMonitor,
};
use xpav::response::ResponseHandler;
use xpav::state::StateStore;
use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "xpav", author = "REIUK LTD", version)]
#[command(about = "☧ Chi Rho Anti-Virus - Behavioral threat detection for Linux")]
#[command(long_about = r#"
  __  __ ____   ___  __    __
   \ \/ // __ \ / _ \ \ \  / /
    \  // /_/ // /_\ \ \ \/ /
    /  \\  __// /   \ \ \  /
   /_/\_\\_/  /_/    \_\ \/

        ☧ Chi Rho Anti-Virus
            REIUK LTD

Behavioral threat detection for Linux. Detects cryptominers, webshells,
container escapes, persistence mechanisms, and fileless malware through
behavioral analysis rather than signatures.
"#)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/xpav/config.toml")]
    config: PathBuf,

    /// Run in dry-run mode (no kill actions)
    #[arg(short, long)]
    dry_run: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output logs as JSON
    #[arg(long)]
    json: bool,

    /// Metrics/health endpoint address
    #[arg(long, default_value = "127.0.0.1:9090")]
    metrics_addr: SocketAddr,

    /// Disable metrics/health endpoint
    #[arg(long)]
    no_metrics: bool,
}

macro_rules! spawn_monitor {
    ($config:expr, $tx:expr, $handles:expr, $field:ident, $Monitor:ty, $name:literal) => {
        if $config.$field.enabled {
            let cfg = $config.$field.clone();
            let tx = $tx.clone();
            ACTIVE_MONITORS.inc();
            $handles.push(tokio::spawn(async move {
                let mut m = <$Monitor>::new(cfg, tx);
                if let Err(e) = m.run().await {
                    error!(concat!($name, " error: {}"), e);
                }
            }));
            info!(concat!($name, " enabled"));
        }
    };
    ($config:expr, $tx:expr, $handles:expr, $field:ident, $Monitor:ty, $name:literal, $extra:literal) => {
        if $config.$field.enabled {
            let cfg = $config.$field.clone();
            let tx = $tx.clone();
            ACTIVE_MONITORS.inc();
            $handles.push(tokio::spawn(async move {
                let mut m = <$Monitor>::new(cfg, tx);
                if let Err(e) = m.run().await {
                    error!(concat!($name, " error: {}", $extra), e);
                }
            }));
            info!(concat!($name, " enabled", $extra));
        }
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    let filter = EnvFilter::from_default_env().add_directive(level.into());

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    if args.json {
        subscriber.json().init();
    } else {
        subscriber.with_target(false).init();
    }

    let config_path = Arc::new(args.config.clone());
    let mut config = Config::load_or_default(&args.config);
    if args.dry_run {
        config.general.dry_run = true;
    }

    // Create shared state store
    let state = StateStore::new().shared();
    info!("State store initialized");

    // Create config broadcaster for hot-reload
    let (config_broadcaster, _config_rx) = ConfigBroadcaster::new(config.clone());

    if !args.json {
        eprintln!(r#"
  __  __ ____   ___  __    __
   \ \/ // __ \ / _ \ \ \  / /
    \  // /_/ // /_\ \ \ \/ /
    /  \\  __// /   \ \ \  /
   /_/\_\\_/  /_/    \_\ \/   v{}

        ☧ Chi Rho Anti-Virus

            REIUK LTD
"#, env!("CARGO_PKG_VERSION"));
    }

    info!("Config: {}", args.config.display());
    info!("Dry run: {}", config.general.dry_run);

    let (ready_tx, ready_rx) = watch::channel(false);

    if !args.no_metrics {
        let metrics_addr = args.metrics_addr;
        let metrics_ready_rx = ready_rx.clone();
        tokio::spawn(async move {
            metrics::start_server(metrics_addr, metrics_ready_rx).await;
        });
    }

    let (event_tx, event_rx) = mpsc::channel(1000);

    let response_handler = ResponseHandler::new(
        config.general.log_format,
        config.general.alert_webhook.clone(),
        config.general.dry_run,
    );
    let response_handle = tokio::spawn(async move {
        response_handler.run(event_rx).await;
    });

    let mut handles = Vec::new();

    spawn_monitor!(config, event_tx, handles, process_monitor, ProcessMonitor, "Process monitor");
    spawn_monitor!(config, event_tx, handles, network_monitor, NetworkMonitor, "Network monitor");
    spawn_monitor!(config, event_tx, handles, persistence_monitor, PersistenceMonitor, "Persistence monitor");
    spawn_monitor!(config, event_tx, handles, file_monitor, FanotifyMonitor, "File monitor", " (requires root)");
    spawn_monitor!(config, event_tx, handles, ebpf_monitor, EbpfMonitor, "eBPF monitor", " (requires root and bpftool)");
    spawn_monitor!(config, event_tx, handles, memory_scanner, MemoryScanner, "Memory scanner", " (requires root)");
    spawn_monitor!(config, event_tx, handles, integrity_monitor, IntegrityMonitor, "Integrity monitor");
    spawn_monitor!(config, event_tx, handles, container_monitor, ContainerMonitor, "Container monitor");

    drop(event_tx);

    let _ = ready_tx.send(true);

    info!("XPAV running. Press Ctrl+C to stop.");
    if !args.no_metrics {
        info!("Metrics available at http://{}/metrics", args.metrics_addr);
        info!("Health check at http://{}/health", args.metrics_addr);
    }

    // Spawn periodic state cleanup task
    let state_cleanup = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            state_cleanup.cleanup_expired();
        }
    });

    let config_path_clone = config_path.clone();
    let mut config_broadcaster = config_broadcaster;
    tokio::spawn(async move {
        loop {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(mut sig) => {
                    sig.recv().await;
                    info!("Received SIGHUP, reloading config...");
                    match Config::load(&config_path_clone) {
                        Ok(new_config) => {
                            if let Err(e) = config_broadcaster.update(new_config.clone()) {
                                warn!("Failed to broadcast config update: {}", e);
                            } else {
                                info!("Config reloaded and broadcast to monitors");
                            }
                            if new_config.general.dry_run {
                                info!("Config has dry_run=true");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to reload config: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to set up SIGHUP handler: {}", e);
                    break;
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    let _ = ready_tx.send(false);

    for handle in handles {
        handle.abort();
    }
    response_handle.abort();

    info!("XPAV stopped.");
    Ok(())
}
