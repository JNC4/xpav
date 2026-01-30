//! Property-based tests for entropy calculation.

use proptest::prelude::*;
use xpav::scanner::entropy::calculate_entropy;

proptest! {
    /// Entropy should always be between 0.0 and 8.0
    #[test]
    fn entropy_bounds(data in prop::collection::vec(any::<u8>(), 1..10000)) {
        let entropy = calculate_entropy(&data);
        prop_assert!(entropy >= 0.0, "Entropy should be >= 0, got {}", entropy);
        prop_assert!(entropy <= 8.0, "Entropy should be <= 8, got {}", entropy);
    }

    /// Entropy of single repeated byte should be 0
    #[test]
    fn entropy_repeated_byte(byte: u8, len in 10..1000usize) {
        let data = vec![byte; len];
        let entropy = calculate_entropy(&data);
        prop_assert_eq!(entropy, 0.0, "Repeated byte should have zero entropy");
    }

    /// Entropy should increase with more unique values
    #[test]
    fn entropy_increases_with_diversity(len in 100..1000usize) {
        // All same byte
        let data1 = vec![0u8; len];
        let e1 = calculate_entropy(&data1);

        // Two bytes
        let mut data2 = vec![0u8; len / 2];
        data2.extend(vec![1u8; len / 2]);
        let e2 = calculate_entropy(&data2);

        // Four bytes
        let mut data4 = Vec::new();
        for _ in 0..len/4 {
            data4.push(0);
            data4.push(1);
            data4.push(2);
            data4.push(3);
        }
        let e4 = calculate_entropy(&data4);

        prop_assert!(e1 <= e2, "Two bytes should have more entropy than one");
        prop_assert!(e2 <= e4, "Four bytes should have more entropy than two");
    }

    /// Entropy should be deterministic
    #[test]
    fn entropy_deterministic(data in prop::collection::vec(any::<u8>(), 1..1000)) {
        let e1 = calculate_entropy(&data);
        let e2 = calculate_entropy(&data);
        prop_assert_eq!(e1, e2, "Entropy should be deterministic");
    }
}
