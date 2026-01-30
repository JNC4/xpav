//! Property-based tests for event deduplication.

use proptest::prelude::*;
use xpav::state::dedup::{DedupKey, EventDeduplicator};

proptest! {
    /// First occurrence should always be reported
    #[test]
    fn first_occurrence_reported(key in "[a-z]{5,20}") {
        let dedup = EventDeduplicator::new();
        let key = DedupKey::from_str(&key);
        prop_assert!(dedup.should_report(key), "First occurrence should be reported");
    }

    /// Second occurrence should be suppressed
    #[test]
    fn second_occurrence_suppressed(key in "[a-z]{5,20}") {
        let dedup = EventDeduplicator::new();
        let key = DedupKey::from_str(&key);

        dedup.should_report(key.clone()); // First
        prop_assert!(!dedup.should_report(key), "Second occurrence should be suppressed");
    }

    /// Different keys should not affect each other
    #[test]
    fn different_keys_independent(key1 in "[a-z]{5,10}", key2 in "[A-Z]{5,10}") {
        let dedup = EventDeduplicator::new();
        let k1 = DedupKey::from_str(&key1);
        let k2 = DedupKey::from_str(&key2);

        dedup.should_report(k1.clone());
        prop_assert!(dedup.should_report(k2), "Different keys should be independent");
    }

    /// Occurrence count should increase with each report attempt
    #[test]
    fn occurrence_count_increases(key in "[a-z]{5,20}", n in 2..10usize) {
        let dedup = EventDeduplicator::new();
        let key = DedupKey::from_str(&key);

        for _ in 0..n {
            dedup.should_report(key.clone());
        }

        let count = dedup.occurrence_count(&key);
        prop_assert_eq!(count, n as u64, "Occurrence count should match");
    }
}
