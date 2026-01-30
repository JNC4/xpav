//! Production-Grade Test Suite for XPAV
//!
//! This test suite simulates real-world attack scenarios, evasion techniques,
//! and edge cases that would be encountered in production environments.
//!
//! Test Categories:
//! 1. Real Attack Scenarios - Simulates actual malware behavior
//! 2. Evasion Techniques - Tests detection bypass attempts
//! 3. False Positive Testing - Ensures legitimate software isn't flagged
//! 4. Stress Testing - High load and rapid event scenarios
//! 5. Integration Testing - Full system behavior
//!
//! IMPORTANT: Some tests require root privileges to run fully.
//! Run with: sudo cargo test --test production -- --nocapture

pub mod fixtures;
pub mod scenarios;
pub mod evasion;
pub mod false_positives;
pub mod stress;
pub mod integration;
