//! Unit tests for entropy calculation.

use xpav::scanner::entropy::{calculate_entropy, EntropyClassification};

#[test]
fn test_entropy_all_zeros() {
    let data = vec![0u8; 10000];
    let entropy = calculate_entropy(&data);
    assert_eq!(entropy, 0.0, "All zeros should have zero entropy");
}

#[test]
fn test_entropy_uniform_distribution() {
    // Create data with uniform distribution of all 256 byte values
    let mut data = Vec::new();
    for _ in 0..100 {
        for i in 0..=255u8 {
            data.push(i);
        }
    }
    let entropy = calculate_entropy(&data);
    // Should be very close to 8.0 (maximum entropy)
    assert!(entropy > 7.9, "Uniform distribution should have near-maximum entropy, got {}", entropy);
}

#[test]
fn test_entropy_binary() {
    // 50% zeros, 50% ones - should have entropy of 1.0
    let mut data = vec![0u8; 500];
    data.extend(vec![1u8; 500]);
    let entropy = calculate_entropy(&data);
    assert!((entropy - 1.0).abs() < 0.01, "Binary distribution should have entropy ~1.0, got {}", entropy);
}

#[test]
fn test_entropy_classification() {
    assert_eq!(EntropyClassification::from_entropy(0.5), EntropyClassification::VeryLow);
    assert_eq!(EntropyClassification::from_entropy(2.0), EntropyClassification::Low);
    assert_eq!(EntropyClassification::from_entropy(5.5), EntropyClassification::Normal);
    assert_eq!(EntropyClassification::from_entropy(7.0), EntropyClassification::High);
    assert_eq!(EntropyClassification::from_entropy(7.8), EntropyClassification::VeryHigh);
}

#[test]
fn test_entropy_suspicious() {
    assert!(!EntropyClassification::VeryLow.is_suspicious());
    assert!(!EntropyClassification::Low.is_suspicious());
    assert!(!EntropyClassification::Normal.is_suspicious());
    assert!(EntropyClassification::High.is_suspicious());
    assert!(EntropyClassification::VeryHigh.is_suspicious());
}
