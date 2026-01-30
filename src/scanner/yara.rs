//! YARA rule scanning (feature-gated).
//!
//! Provides file and memory scanning using YARA rules.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use yara::{Compiler, Rules};

use crate::config::YaraConfig;

/// Result of a YARA scan.
#[derive(Debug, Clone)]
pub struct YaraScanResult {
    /// Path that was scanned
    pub path: Option<PathBuf>,
    /// Rules that matched
    pub matches: Vec<YaraMatch>,
    /// Whether any rules matched
    pub has_matches: bool,
}

impl YaraScanResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            path: None,
            matches: Vec::new(),
            has_matches: false,
        }
    }
}

/// A single YARA rule match.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Rule identifier
    pub rule: String,
    /// Rule namespace
    pub namespace: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: Vec<(String, String)>,
    /// String matches
    pub strings: Vec<YaraString>,
}

/// A string match within a YARA rule.
#[derive(Debug, Clone)]
pub struct YaraString {
    /// String identifier
    pub identifier: String,
    /// Offset where the string was found
    pub offset: usize,
    /// Matched data
    pub data: Vec<u8>,
}

/// YARA scanner with compiled rules.
pub struct YaraScanner {
    /// Compiled rules
    rules: Arc<Rules>,
    /// Configuration
    config: YaraConfig,
    /// Number of compiled rules
    rule_count: usize,
}

impl YaraScanner {
    /// Create a new YARA scanner from configuration.
    pub fn new(config: &YaraConfig) -> Result<Self> {
        let (rules, rule_count) = Self::compile_rules(&config.rules_dir)?;
        Ok(Self {
            rules: Arc::new(rules),
            config: config.clone(),
            rule_count,
        })
    }

    /// Create a scanner from a single rule file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let mut compiler = Compiler::new()?;
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read YARA rule: {}", path.display()))?;
        compiler
            .add_rules_str(&content)
            .with_context(|| format!("Failed to compile YARA rule: {}", path.display()))?;
        let rules = compiler.compile_rules()?;
        let rule_count = Self::count_rules_in_content(&content);

        Ok(Self {
            rules: Arc::new(rules),
            config: YaraConfig::default(),
            rule_count,
        })
    }

    /// Create a scanner from rule content.
    pub fn from_rules(rules_content: &str) -> Result<Self> {
        let mut compiler = Compiler::new()?;
        compiler
            .add_rules_str(rules_content)
            .context("Failed to compile YARA rules")?;
        let rules = compiler.compile_rules()?;
        let rule_count = Self::count_rules_in_content(rules_content);

        Ok(Self {
            rules: Arc::new(rules),
            config: YaraConfig::default(),
            rule_count,
        })
    }

    /// Count rules in YARA source content by counting "rule <name>" declarations.
    fn count_rules_in_content(content: &str) -> usize {
        // Simple heuristic: count "rule " at start of line (after whitespace)
        // This handles most common YARA formatting styles
        content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("rule ") || trimmed.starts_with("private rule ")
                    || trimmed.starts_with("global rule ")
            })
            .count()
    }

    /// Compile all rules from a directory.
    fn compile_rules(rules_dir: &Path) -> Result<(Rules, usize)> {
        let mut compiler = Compiler::new()?;
        let mut total_rules = 0;

        if !rules_dir.exists() {
            // Return empty rules if directory doesn't exist
            let rules = compiler.compile_rules().context("Failed to compile empty rules")?;
            return Ok((rules, 0));
        }

        // Find all .yar and .yara files
        for entry in walkdir::WalkDir::new(rules_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str());
                if matches!(ext, Some("yar") | Some("yara")) {
                    let content = fs::read_to_string(path)
                        .with_context(|| format!("Failed to read: {}", path.display()))?;
                    if let Err(e) = compiler.add_rules_str(&content) {
                        tracing::warn!("Failed to compile {}: {}", path.display(), e);
                        // Continue with other rules
                    } else {
                        total_rules += Self::count_rules_in_content(&content);
                    }
                }
            }
        }

        let rules = compiler.compile_rules().context("Failed to compile YARA rules")?;
        Ok((rules, total_rules))
    }

    /// Scan a file.
    pub fn scan_file(&self, path: &Path) -> Result<YaraScanResult> {
        // Check file size
        let metadata = fs::metadata(path)?;
        let max_size = self.config.max_file_size_mb * 1024 * 1024;
        if metadata.len() > max_size {
            return Ok(YaraScanResult {
                path: Some(path.to_path_buf()),
                matches: Vec::new(),
                has_matches: false,
            });
        }

        let scan_results = self.rules.scan_file(path, self.config.timeout_secs as i32)?;
        let matches = self.convert_matches(&scan_results);

        Ok(YaraScanResult {
            path: Some(path.to_path_buf()),
            has_matches: !matches.is_empty(),
            matches,
        })
    }

    /// Scan memory (process memory or arbitrary bytes).
    pub fn scan_memory(&self, data: &[u8]) -> Result<YaraScanResult> {
        let scan_results = self.rules.scan_mem(data, self.config.timeout_secs as i32)?;
        let matches = self.convert_matches(&scan_results);

        Ok(YaraScanResult {
            path: None,
            has_matches: !matches.is_empty(),
            matches,
        })
    }

    /// Convert yara crate matches to our format.
    fn convert_matches(&self, results: &[yara::Rule<'_>]) -> Vec<YaraMatch> {
        results
            .iter()
            .map(|rule| {
                let strings = rule
                    .strings
                    .iter()
                    .flat_map(|s| {
                        s.matches.iter().map(move |m| YaraString {
                            identifier: s.identifier.to_string(),
                            offset: m.offset,
                            data: m.data.to_vec(),
                        })
                    })
                    .collect();

                let metadata = rule
                    .metadatas
                    .iter()
                    .map(|m| (m.identifier.to_string(), format!("{:?}", m.value)))
                    .collect();

                YaraMatch {
                    rule: rule.identifier.to_string(),
                    namespace: rule.namespace.to_string(),
                    tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                    metadata,
                    strings,
                }
            })
            .collect()
    }

    /// Reload rules from the configured directory.
    pub fn reload(&mut self) -> Result<()> {
        let (rules, rule_count) = Self::compile_rules(&self.config.rules_dir)?;
        self.rules = Arc::new(rules);
        self.rule_count = rule_count;
        Ok(())
    }

    /// Get the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
rule TestRule {
    meta:
        description = "Test rule for unit testing"
    strings:
        $test = "MALWARE_MARKER"
    condition:
        $test
}
"#;

    #[test]
    fn test_yara_scanner_creation() {
        let scanner = YaraScanner::from_rules(TEST_RULE);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_yara_scan_memory_match() {
        let scanner = YaraScanner::from_rules(TEST_RULE).unwrap();
        let result = scanner.scan_memory(b"This contains MALWARE_MARKER in it").unwrap();
        assert!(result.has_matches);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].rule, "TestRule");
    }

    #[test]
    fn test_yara_scan_memory_no_match() {
        let scanner = YaraScanner::from_rules(TEST_RULE).unwrap();
        let result = scanner.scan_memory(b"This is clean content").unwrap();
        assert!(!result.has_matches);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_empty_rules() {
        let scanner = YaraScanner::from_rules("").unwrap();
        let result = scanner.scan_memory(b"Any content").unwrap();
        assert!(!result.has_matches);
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_rule_count_single() {
        let scanner = YaraScanner::from_rules(TEST_RULE).unwrap();
        assert_eq!(scanner.rule_count(), 1);
    }

    #[test]
    fn test_rule_count_multiple() {
        let multi_rules = r#"
rule FirstRule {
    strings:
        $a = "test1"
    condition:
        $a
}

private rule SecondRule {
    strings:
        $b = "test2"
    condition:
        $b
}

global rule ThirdRule {
    strings:
        $c = "test3"
    condition:
        $c
}
"#;
        let scanner = YaraScanner::from_rules(multi_rules).unwrap();
        assert_eq!(scanner.rule_count(), 3);
    }
}
