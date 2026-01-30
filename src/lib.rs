//! XPAV - Chi Rho Anti-Virus
//!
//! A lightweight, behavioral Linux security daemon that catches what ClamAV misses.
//!
//! This library provides the core detection and monitoring functionality.
//! The binary in main.rs uses this library to run the daemon.

pub mod config;
pub mod detection;
pub mod metrics;
pub mod monitors;
pub mod response;
pub mod scanner;

// Re-export commonly used types
pub use config::*;
pub use detection::*;
