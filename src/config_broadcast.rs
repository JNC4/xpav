//! Configuration broadcast for hot-reloading.
//!
//! This module will be fully implemented in Phase 3.1.

use crate::config::Config;
use std::sync::Arc;
use tokio::sync::watch;

/// Broadcasts configuration updates to all monitors.
pub struct ConfigBroadcaster {
    /// Sender for broadcasting config updates
    sender: watch::Sender<Arc<Config>>,
    /// Current configuration
    current: Arc<Config>,
}

impl ConfigBroadcaster {
    /// Create a new config broadcaster with the initial configuration.
    pub fn new(config: Config) -> (Self, watch::Receiver<Arc<Config>>) {
        let config = Arc::new(config);
        let (sender, receiver) = watch::channel(Arc::clone(&config));

        let broadcaster = Self {
            sender,
            current: config,
        };

        (broadcaster, receiver)
    }

    /// Update the configuration and broadcast to all receivers.
    pub fn update(&mut self, config: Config) -> Result<(), watch::error::SendError<Arc<Config>>> {
        let config = Arc::new(config);
        self.current = Arc::clone(&config);
        self.sender.send(config)
    }

    /// Get the current configuration.
    pub fn current(&self) -> Arc<Config> {
        Arc::clone(&self.current)
    }

    /// Subscribe to configuration updates.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Config>> {
        self.sender.subscribe()
    }

    /// Get the number of active receivers.
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// Trait for monitors that can receive configuration updates.
pub trait ConfigUpdatable {
    /// Apply a configuration update.
    fn apply_config_update(&mut self, config: &Config);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcaster_creation() {
        let config = Config::default();
        let (broadcaster, _receiver) = ConfigBroadcaster::new(config);
        assert_eq!(broadcaster.receiver_count(), 1);
    }

    #[test]
    fn test_broadcaster_subscribe() {
        let config = Config::default();
        let (broadcaster, _receiver1) = ConfigBroadcaster::new(config);
        let _receiver2 = broadcaster.subscribe();
        assert_eq!(broadcaster.receiver_count(), 2);
    }

    #[tokio::test]
    async fn test_broadcaster_update() {
        let config = Config::default();
        let (mut broadcaster, mut receiver) = ConfigBroadcaster::new(config);

        // Initial value
        assert!(!receiver.borrow().general.dry_run);

        // Update config
        let mut new_config = Config::default();
        new_config.general.dry_run = true;
        broadcaster.update(new_config).unwrap();

        // Receiver should see the update
        receiver.changed().await.unwrap();
        assert!(receiver.borrow().general.dry_run);
    }
}
