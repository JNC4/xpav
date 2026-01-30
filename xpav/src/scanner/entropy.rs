//! Shannon entropy calculation for detecting packed/encrypted executables.
//!
//! High entropy files are often packed, encrypted, or obfuscated.
//! Normal executables typically have entropy between 5.0-6.5.
//! Packed executables often have entropy > 7.0.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Result of entropy analysis.
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// Shannon entropy (0.0 - 8.0)
    pub entropy: f64,
    /// File size in bytes
    pub size: u64,
    /// Whether the file is considered high entropy
    pub is_high_entropy: bool,
    /// Classification based on entropy
    pub classification: EntropyClassification,
}

/// Classification based on entropy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClassification {
    /// Very low entropy (< 1.0) - likely mostly zeros or repetitive
    VeryLow,
    /// Low entropy (1.0 - 4.0) - text files, scripts
    Low,
    /// Normal entropy (4.0 - 6.5) - typical executables
    Normal,
    /// High entropy (6.5 - 7.5) - compressed data, some packed executables
    High,
    /// Very high entropy (> 7.5) - encrypted, heavily packed, or random data
    VeryHigh,
}

impl EntropyClassification {
    /// Get the classification from an entropy value.
    pub fn from_entropy(entropy: f64) -> Self {
        match entropy {
            e if e < 1.0 => EntropyClassification::VeryLow,
            e if e < 4.0 => EntropyClassification::Low,
            e if e < 6.5 => EntropyClassification::Normal,
            e if e < 7.5 => EntropyClassification::High,
            _ => EntropyClassification::VeryHigh,
        }
    }

    /// Check if this classification is suspicious.
    pub fn is_suspicious(&self) -> bool {
        matches!(self, EntropyClassification::High | EntropyClassification::VeryHigh)
    }
}

/// Calculate Shannon entropy for a byte slice.
///
/// Shannon entropy measures the average information content per byte.
/// Returns a value between 0.0 (all same bytes) and 8.0 (perfectly random).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut frequencies = [0u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequencies {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Calculate entropy for a file.
pub fn calculate_file_entropy(path: &Path) -> std::io::Result<EntropyResult> {
    calculate_file_entropy_with_threshold(path, 7.0)
}

/// Calculate entropy for a file with a custom threshold.
pub fn calculate_file_entropy_with_threshold(
    path: &Path,
    threshold: f64,
) -> std::io::Result<EntropyResult> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    // Don't analyze empty files or very small files
    if size < 64 {
        return Ok(EntropyResult {
            entropy: 0.0,
            size,
            is_high_entropy: false,
            classification: EntropyClassification::VeryLow,
        });
    }

    // For very large files, sample instead of reading everything
    let max_read_size: u64 = 10 * 1024 * 1024; // 10 MB max

    let entropy = if size > max_read_size {
        // Sample-based entropy for large files (samples from beginning, middle, end)
        calculate_sampled_entropy(&mut file, size, max_read_size as usize)?
    } else {
        // Read entire file for smaller files
        let mut buffer = Vec::with_capacity(size as usize);
        file.read_to_end(&mut buffer)?;
        calculate_entropy(&buffer)
    };

    let classification = EntropyClassification::from_entropy(entropy);
    let is_high_entropy = entropy >= threshold;

    Ok(EntropyResult {
        entropy,
        size,
        is_high_entropy,
        classification,
    })
}

/// Calculate entropy using sampling for large files.
/// Samples from beginning, middle, and end to catch packed executables
/// that have low-entropy headers but high-entropy payloads.
fn calculate_sampled_entropy(
    file: &mut std::fs::File,
    total_size: u64,
    sample_size: usize,
) -> std::io::Result<f64> {
    use std::io::{Read, Seek, SeekFrom};

    // Sample from 3 regions: beginning, middle, and end
    // This catches packers that have normal headers but encrypted bodies
    let region_size = sample_size / 3;
    let mut combined_buffer = Vec::with_capacity(sample_size);

    // Region 1: Beginning of file
    file.seek(SeekFrom::Start(0))?;
    let mut buf1 = vec![0u8; region_size.min(total_size as usize)];
    let n1 = file.read(&mut buf1)?;
    combined_buffer.extend_from_slice(&buf1[..n1]);

    // Region 2: Middle of file
    if total_size > region_size as u64 * 2 {
        let middle_offset = (total_size / 2).saturating_sub(region_size as u64 / 2);
        file.seek(SeekFrom::Start(middle_offset))?;
        let mut buf2 = vec![0u8; region_size];
        let n2 = file.read(&mut buf2)?;
        combined_buffer.extend_from_slice(&buf2[..n2]);
    }

    // Region 3: End of file (last region_size bytes)
    if total_size > region_size as u64 {
        let end_offset = total_size.saturating_sub(region_size as u64);
        file.seek(SeekFrom::Start(end_offset))?;
        let mut buf3 = vec![0u8; region_size];
        let n3 = file.read(&mut buf3)?;
        combined_buffer.extend_from_slice(&buf3[..n3]);
    }

    Ok(calculate_entropy(&combined_buffer))
}

/// Analyze an ELF or PE section for entropy.
/// Useful for detecting packed sections within executables.
pub fn analyze_sections(data: &[u8]) -> Vec<SectionEntropy> {
    let mut sections = Vec::new();

    // Check for ELF magic
    if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        sections = analyze_elf_sections(data);
    }
    // Check for PE magic (MZ header)
    else if data.len() >= 2 && &data[0..2] == b"MZ" {
        sections = analyze_pe_sections(data);
    }

    sections
}

/// Entropy information for a section.
#[derive(Debug, Clone)]
pub struct SectionEntropy {
    /// Section name
    pub name: String,
    /// Section offset in file
    pub offset: usize,
    /// Section size
    pub size: usize,
    /// Section entropy
    pub entropy: f64,
    /// Whether this section is suspicious
    pub is_suspicious: bool,
}

/// Analyze ELF sections for entropy (simplified).
fn analyze_elf_sections(data: &[u8]) -> Vec<SectionEntropy> {
    // Simplified ELF analysis - just analyze overall code sections
    // A full implementation would parse the ELF header and section table
    let mut sections = Vec::new();

    // Check for 64-bit ELF
    if data.len() < 64 || data[4] != 2 {
        return sections;
    }

    // Analyze chunks of the file
    let chunk_size = 4096;
    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let entropy = calculate_entropy(chunk);
        if entropy > 7.0 {
            sections.push(SectionEntropy {
                name: format!("chunk_{}", i),
                offset: i * chunk_size,
                size: chunk.len(),
                entropy,
                is_suspicious: true,
            });
        }
    }

    sections
}

/// Analyze PE sections for entropy (simplified).
fn analyze_pe_sections(data: &[u8]) -> Vec<SectionEntropy> {
    // Simplified PE analysis
    let mut sections = Vec::new();

    // Analyze chunks
    let chunk_size = 4096;
    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let entropy = calculate_entropy(chunk);
        if entropy > 7.0 {
            sections.push(SectionEntropy {
                name: format!("chunk_{}", i),
                offset: i * chunk_size,
                size: chunk.len(),
                entropy,
                is_suspicious: true,
            });
        }
    }

    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 1000];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_single_byte() {
        let data = vec![0xAB; 1000];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_two_bytes() {
        let mut data = vec![0u8; 1000];
        for i in 0..500 {
            data[i] = 0;
        }
        for i in 500..1000 {
            data[i] = 1;
        }
        let entropy = calculate_entropy(&data);
        assert!((entropy - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_random() {
        // Pseudo-random data should have high entropy
        let data: Vec<u8> = (0..10000).map(|i| (i * 7 + 13) as u8).collect();
        let entropy = calculate_entropy(&data);
        // Should be close to 8.0 for random-looking data
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_entropy_text() {
        // English text has moderate entropy
        let data = b"The quick brown fox jumps over the lazy dog. This is a test of entropy calculation for typical English text content.";
        let entropy = calculate_entropy(data);
        // Text typically has entropy between 3.5-5.0
        assert!(entropy > 3.0 && entropy < 6.0);
    }

    #[test]
    fn test_classification() {
        assert_eq!(EntropyClassification::from_entropy(0.5), EntropyClassification::VeryLow);
        assert_eq!(EntropyClassification::from_entropy(2.5), EntropyClassification::Low);
        assert_eq!(EntropyClassification::from_entropy(5.0), EntropyClassification::Normal);
        assert_eq!(EntropyClassification::from_entropy(7.0), EntropyClassification::High);
        assert_eq!(EntropyClassification::from_entropy(7.8), EntropyClassification::VeryHigh);
    }

    #[test]
    fn test_suspicious_classification() {
        assert!(!EntropyClassification::VeryLow.is_suspicious());
        assert!(!EntropyClassification::Low.is_suspicious());
        assert!(!EntropyClassification::Normal.is_suspicious());
        assert!(EntropyClassification::High.is_suspicious());
        assert!(EntropyClassification::VeryHigh.is_suspicious());
    }

    #[test]
    fn test_empty_data() {
        let entropy = calculate_entropy(&[]);
        assert_eq!(entropy, 0.0);
    }
}
