//! Unit tests for state store.

use xpav::state::{StateStore, ProcessEntry};
use std::sync::Arc;

#[test]
fn test_state_store_creation() {
    let store = StateStore::new();
    let stats = store.stats();
    assert_eq!(stats.process_count, 0);
    assert_eq!(stats.connection_count, 0);
    assert_eq!(stats.threat_count, 0);
    assert_eq!(stats.dedup_count, 0);
}

#[test]
fn test_state_store_shared() {
    let store = Arc::new(StateStore::new());
    assert_eq!(Arc::strong_count(&store), 1);

    let store2 = Arc::clone(&store);
    assert_eq!(Arc::strong_count(&store), 2);

    drop(store2);
    assert_eq!(Arc::strong_count(&store), 1);
}

#[test]
fn test_process_registry() {
    let store = StateStore::new();

    // Add a process
    let entry = ProcessEntry::new(
        1234,
        1,
        "test_process".to_string(),
        "/usr/bin/test arg1 arg2".to_string(),
        None,
        None,
        1000,
    );
    store.processes.upsert(entry);

    assert!(store.processes.contains(1234));
    assert!(!store.processes.contains(5678));

    let retrieved = store.processes.get(1234).unwrap();
    assert_eq!(retrieved.name, "test_process");
    assert_eq!(retrieved.uid, 1000);
}

#[test]
fn test_process_reporting() {
    let store = StateStore::new();

    let entry = ProcessEntry::new(
        1234,
        1,
        "test".to_string(),
        "test".to_string(),
        None,
        None,
        1000,
    );
    store.processes.upsert(entry);

    assert!(!store.processes.is_reported(1234));
    store.processes.mark_reported(1234);
    assert!(store.processes.is_reported(1234));
}

#[test]
fn test_deduplication() {
    let store = StateStore::new();

    use xpav::state::dedup::DedupKey;

    let key = DedupKey::from_str("test_event");

    // First occurrence should be reported
    assert!(store.dedup.should_report(key.clone()));

    // Second occurrence should be suppressed
    assert!(!store.dedup.should_report(key.clone()));
}

#[test]
fn test_cleanup() {
    let store = StateStore::new();

    // Add some data
    let entry = ProcessEntry::new(
        99999, // Non-existent PID
        1,
        "ghost".to_string(),
        "ghost".to_string(),
        None,
        None,
        0,
    );
    store.processes.upsert(entry);

    // Cleanup dead processes
    store.processes.cleanup_dead();

    // Ghost process should be removed (PID 99999 doesn't exist)
    assert!(!store.processes.contains(99999));
}
