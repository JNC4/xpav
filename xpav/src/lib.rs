//! XPAV - Chi Rho Anti-Virus
//!
//! A lightweight, behavioral Linux security daemon that catches what ClamAV misses.
//!
//! This library provides the core detection and monitoring functionality.
//! The binary in main.rs uses this library to run the daemon.

pub mod allowlist;
pub mod config;
pub mod config_broadcast;
pub mod correlation;
pub mod detection;
pub mod metrics;
pub mod monitors;
pub mod persistence;
pub mod response;
pub mod scanner;
pub mod state;
pub mod util;

// Re-export commonly used types
pub use config::*;
pub use detection::*;
pub use state::StateStore;
