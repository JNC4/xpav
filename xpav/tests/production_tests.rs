//! Production-Grade Test Suite for XPAV
//!
//! This is the main entry point for production tests.
//! Run with: cargo test --test production_tests
//!
//! Some tests require root privileges for full functionality.
//! Run with: sudo cargo test --test production_tests

mod production;

pub use production::*;
