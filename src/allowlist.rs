//! Allowlist management for suppressing false positives.
//!
//! This module will be fully implemented in Phase 1.3.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Configuration for allowlists.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub process: ProcessAllowlist,
    #[serde(default)]
    pub file: FileAllowlist,
    #[serde(default)]
    pub network: NetworkAllowlist,
}

/// Allowlist for processes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessAllowlist {
    /// Exact executable paths to allow
    #[serde(default)]
    pub paths: Vec<String>,
    /// Process name patterns (regex)
    #[serde(default)]
    pub name_patterns: Vec<String>,
    /// SHA256 hashes of allowed executables
    #[serde(default)]
    pub hashes: Vec<String>,
}

/// Allowlist for files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileAllowlist {
    /// File path patterns (glob)
    #[serde(default)]
    pub path_patterns: Vec<String>,
    /// SHA256 hashes of allowed files
    #[serde(default)]
    pub hashes: Vec<String>,
}

/// Allowlist for network connections.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkAllowlist {
    /// Allowed IP addresses
    #[serde(default)]
    pub ips: Vec<String>,
    /// Allowed domains
    #[serde(default)]
    pub domains: Vec<String>,
    /// Process paths allowed to make any connection
    #[serde(default)]
    pub process_paths: Vec<String>,
}

/// Compiled allowlist checker for efficient matching.
pub struct AllowlistChecker {
    // Process allowlist
    process_paths: HashSet<String>,
    process_name_patterns: Vec<Regex>,
    process_hashes: HashSet<String>,

    // File allowlist
    file_path_patterns: Vec<glob::Pattern>,
    file_hashes: HashSet<String>,

    // Network allowlist
    network_ips: HashSet<String>,
    network_domains: HashSet<String>,
    network_process_paths: HashSet<String>,
}

impl AllowlistChecker {
    /// Create a new allowlist checker from configuration.
    pub fn new(config: &AllowlistConfig) -> Self {
        let process_name_patterns = config
            .process
            .name_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        let file_path_patterns = config
            .file
            .path_patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Self {
            process_paths: config.process.paths.iter().cloned().collect(),
            process_name_patterns,
            process_hashes: config.process.hashes.iter().cloned().collect(),
            file_path_patterns,
            file_hashes: config.file.hashes.iter().cloned().collect(),
            network_ips: config.network.ips.iter().cloned().collect(),
            network_domains: config.network.domains.iter().cloned().collect(),
            network_process_paths: config.network.process_paths.iter().cloned().collect(),
        }
    }

    /// Check if a process is allowlisted.
    pub fn is_process_allowed(&self, path: Option<&Path>, name: &str, hash: Option<&str>) -> bool {
        // Check path
        if let Some(p) = path {
            if let Some(path_str) = p.to_str() {
                if self.process_paths.contains(path_str) {
                    return true;
                }
            }
        }

        // Check name patterns
        for pattern in &self.process_name_patterns {
            if pattern.is_match(name) {
                return true;
            }
        }

        // Check hash
        if let Some(h) = hash {
            if self.process_hashes.contains(h) {
                return true;
            }
        }

        false
    }

    /// Check if a file is allowlisted.
    pub fn is_file_allowed(&self, path: &Path, hash: Option<&str>) -> bool {
        // Check path patterns
        if let Some(path_str) = path.to_str() {
            for pattern in &self.file_path_patterns {
                if pattern.matches(path_str) {
                    return true;
                }
            }
        }

        // Check hash
        if let Some(h) = hash {
            if self.file_hashes.contains(h) {
                return true;
            }
        }

        false
    }

    /// Check if a network connection is allowlisted.
    pub fn is_connection_allowed(
        &self,
        remote_ip: &str,
        domain: Option<&str>,
        process_path: Option<&Path>,
    ) -> bool {
        // Check IP
        if self.network_ips.contains(remote_ip) {
            return true;
        }

        // Check domain
        if let Some(d) = domain {
            if self.network_domains.contains(d) {
                return true;
            }
            // Check if it's a proper subdomain of an allowed domain
            // e.g., "sub.example.com" is a subdomain of "example.com"
            // but "malwareexample.com" is NOT a subdomain of "example.com"
            for allowed in &self.network_domains {
                // Must end with ".allowed" to be a proper subdomain
                let subdomain_suffix = format!(".{}", allowed);
                if d.ends_with(&subdomain_suffix) {
                    return true;
                }
            }
        }

        // Check process path
        if let Some(p) = process_path {
            if let Some(path_str) = p.to_str() {
                if self.network_process_paths.contains(path_str) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if the allowlist is empty (no rules defined).
    pub fn is_empty(&self) -> bool {
        self.process_paths.is_empty()
            && self.process_name_patterns.is_empty()
            && self.process_hashes.is_empty()
            && self.file_path_patterns.is_empty()
            && self.file_hashes.is_empty()
            && self.network_ips.is_empty()
            && self.network_domains.is_empty()
            && self.network_process_paths.is_empty()
    }
}

impl Default for AllowlistChecker {
    fn default() -> Self {
        Self::new(&AllowlistConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_allowlist() {
        let checker = AllowlistChecker::default();
        assert!(checker.is_empty());
        assert!(!checker.is_process_allowed(None, "test", None));
    }

    #[test]
    fn test_process_path_allowlist() {
        let config = AllowlistConfig {
            process: ProcessAllowlist {
                paths: vec!["/usr/bin/safe".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);
        assert!(checker.is_process_allowed(Some(Path::new("/usr/bin/safe")), "safe", None));
        assert!(!checker.is_process_allowed(Some(Path::new("/usr/bin/unsafe")), "unsafe", None));
    }

    #[test]
    fn test_process_name_pattern() {
        let config = AllowlistConfig {
            process: ProcessAllowlist {
                name_patterns: vec!["^systemd.*".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);
        assert!(checker.is_process_allowed(None, "systemd-resolved", None));
        assert!(!checker.is_process_allowed(None, "malware", None));
    }

    #[test]
    fn test_file_allowlist() {
        let config = AllowlistConfig {
            file: FileAllowlist {
                path_patterns: vec!["/var/log/*.log".to_string()],
                hashes: vec!["abc123".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);
        assert!(checker.is_file_allowed(Path::new("/var/log/test.log"), None));
        assert!(checker.is_file_allowed(Path::new("/etc/passwd"), Some("abc123")));
        assert!(!checker.is_file_allowed(Path::new("/etc/shadow"), None));
    }

    #[test]
    fn test_network_allowlist() {
        let config = AllowlistConfig {
            network: NetworkAllowlist {
                ips: vec!["8.8.8.8".to_string()],
                domains: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);
        assert!(checker.is_connection_allowed("8.8.8.8", None, None));
        assert!(checker.is_connection_allowed("1.2.3.4", Some("example.com"), None));
        assert!(checker.is_connection_allowed("1.2.3.4", Some("sub.example.com"), None));
        assert!(!checker.is_connection_allowed("1.2.3.4", Some("malware.com"), None));
    }

    #[test]
    fn test_subdomain_check_no_false_positives() {
        // Verify that "malwareexample.com" doesn't match "example.com"
        let config = AllowlistConfig {
            network: NetworkAllowlist {
                domains: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);

        // These should match (exact or proper subdomain)
        assert!(checker.is_connection_allowed("1.2.3.4", Some("example.com"), None));
        assert!(checker.is_connection_allowed("1.2.3.4", Some("sub.example.com"), None));
        assert!(checker.is_connection_allowed("1.2.3.4", Some("deep.sub.example.com"), None));

        // These should NOT match (not a proper subdomain)
        assert!(!checker.is_connection_allowed("1.2.3.4", Some("malwareexample.com"), None));
        assert!(!checker.is_connection_allowed("1.2.3.4", Some("fakeexample.com"), None));
        assert!(!checker.is_connection_allowed("1.2.3.4", Some("example.com.malware.com"), None));
    }
}
