//! TOML-based configuration for all monitors.

use crate::allowlist::AllowlistConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_SCAN_INTERVAL_MS: u64 = 1000;
const DEFAULT_CPU_THRESHOLD: f64 = 50.0;
const DEFAULT_HIGH_CPU_THRESHOLD: f64 = 90.0;
const DEFAULT_OBFUSCATION_THRESHOLD: u32 = 50;
const DEFAULT_EBPF_SCAN_INTERVAL_MS: u64 = 5000;
const DEFAULT_MEMORY_SCAN_INTERVAL_MS: u64 = 30000;
const DEFAULT_INTEGRITY_SCAN_INTERVAL_MS: u64 = 60000;
const DEFAULT_CONTAINER_SCAN_INTERVAL_MS: u64 = 5000;
const DEFAULT_MIN_SUSPICIOUS_SIZE: u64 = 4096;

const SUSPICIOUS_PATHS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/run/user", "/run", "/var/run"];

const MINER_PATTERNS: &[&str] = &[
    "stratum+tcp://", "stratum+ssl://", "stratum+udp://", "stratum://",
    "xmrig", "xmr-stak", "--donate-level", "--cpu-priority", "-o pool.", "--coin=",
    "minerd", "minergate", "cpuminer", "ccminer", "cgminer", "bfgminer", "ethminer",
    "nheqminer", "t-rex", "phoenixminer", "nbminer", "gminer", "lolminer",
    "kthreaddk", "kdevtmpfsi", "kinsing", "kerberods", "dwarfpool",
    "pool.minexmr", "xmrpool.", "supportxmr", "nanopool.org", "hashvault.pro",
    "moneroocean", "2miners.com", "f2pool.", "antpool.", "nicehash",
];

const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    "[kworker/", "[kthreadd]", "[migration/",
    "kdevtmpfsi", "kinsing", "solr", "dbused", ".rsync", "ld-linux",
];

const WEB_SERVER_PROCESSES: &[&str] = &[
    "apache2", "httpd", "nginx", "php-fpm", "php-cgi", "php", "lighttpd", "caddy",
];

const SUSPICIOUS_CHILD_PROCESSES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh",
    "curl", "wget", "nc", "netcat", "ncat", "socat",
    "python", "python3", "perl", "ruby", "nmap", "id", "whoami", "uname",
];

const WATCH_PATHS: &[&str] = &["/var/www", "/srv/http", "/srv/www", "/home/*/public_html"];

const SCAN_EXTENSIONS: &[&str] = &[
    "php", "phtml", "php3", "php4", "php5", "php7", "phar", "inc",
    "jsp", "jspx", "jspa", "jsw", "jsv",  // Java Server Pages
    "aspx", "ashx", "asmx", "ascx", "asp", // ASP.NET
    "py", "pyw",  // Python
];

const SENSITIVE_KPROBE_FUNCTIONS: &[&str] = &[
    "getdents", "getdents64", "filldir", "filldir64",
    "sys_bpf", "__sys_bpf",
    "tcp4_seq_show", "udp4_seq_show", "tcp6_seq_show", "udp6_seq_show",
    "sys_read", "sys_write", "do_sys_open", "sys_execve", "sys_execveat",
];

const MEMORY_SKIP_PROCESSES: &[&str] = &["systemd", "init", "kthreadd"];

const SHELLCODE_PATTERNS: &[&str] = &[
    "0f05", "cd80",
    "31c048bbd19d9691d08c97ff", "6a3b58", "4831f64889e6", "48c7c03b",
];

const INTEGRITY_PATHS: &[&str] = &[
    "/boot", "/lib/modules", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
];

const CRITICAL_BINARIES: &[&str] = &[
    "/bin/ls", "/bin/ps", "/bin/netstat", "/usr/bin/ls", "/usr/bin/ps",
    "/usr/bin/netstat", "/usr/bin/ss", "/usr/bin/top", "/usr/bin/htop",
    "/usr/bin/lsof", "/bin/login", "/usr/bin/sudo", "/usr/bin/su",
    "/usr/bin/ssh", "/usr/sbin/sshd",
];

const SUSPICIOUS_CAPABILITIES: &[&str] = &[
    "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_NET_ADMIN",
    "CAP_NET_RAW", "CAP_SYS_RAWIO", "CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE",
];

const MINING_POOLS: &[&str] = &[
    "pool.minexmr.com", "xmrpool.eu", "supportxmr.com", "pool.supportxmr.com",
    "xmr.nanopool.org", "monerohash.com", "moneroocean.stream", "hashvault.pro",
    "xmr.2miners.com", "xmr-us-east1.nanopool.org", "xmr-eu1.nanopool.org",
    "xmr-asia1.nanopool.org", "nicehash.com", "miningpoolhub.com", "f2pool.com",
    "antpool.com", "poolin.com", "viabtc.com", "btc.com", "slushpool.com",
    "ethermine.org", "sparkpool.com", "eth.2miners.com", "pastebin.com",
];

fn to_string_vec(arr: &[&str]) -> Vec<String> {
    arr.iter().map(|s| s.to_string()).collect()
}

fn to_pathbuf_vec(arr: &[&str]) -> Vec<PathBuf> {
    arr.iter().map(PathBuf::from).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub allowlists: AllowlistConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub false_positive_reduction: FalsePositiveReductionConfig,
    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,
    #[serde(default)]
    pub network_monitor: NetworkMonitorConfig,
    #[serde(default)]
    pub persistence_monitor: PersistenceMonitorConfig,
    #[serde(default)]
    pub file_monitor: FileMonitorConfig,
    #[serde(default)]
    pub ebpf_monitor: EbpfMonitorConfig,
    #[serde(default)]
    pub memory_scanner: MemoryScannerConfig,
    #[serde(default)]
    pub integrity_monitor: IntegrityMonitorConfig,
    #[serde(default)]
    pub container_monitor: ContainerMonitorConfig,
    #[serde(default)]
    pub yara: YaraConfig,
    #[serde(default)]
    pub correlation: CorrelationConfig,
}

/// Configuration for false positive reduction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveReductionConfig {
    /// Enable context-aware scoring
    #[serde(default = "default_true")]
    pub context_scoring: bool,
    /// Auto-detect frameworks (WordPress, Laravel, Symfony, etc.)
    #[serde(default = "default_true")]
    pub auto_framework_detection: bool,
    /// Score multiplier for vendor directory files (0.0-1.0)
    #[serde(default = "default_vendor_multiplier")]
    pub vendor_dir_multiplier: f32,
    /// Trust minified/bundled code (reduce obfuscation scores)
    #[serde(default = "default_true")]
    pub trust_minified: bool,
    /// Cache directory score multiplier
    #[serde(default = "default_cache_multiplier")]
    pub cache_dir_multiplier: f32,
    /// Burst detection threshold (events within window)
    #[serde(default = "default_burst_threshold")]
    pub burst_threshold: usize,
    /// Burst detection window in seconds
    #[serde(default = "default_burst_window")]
    pub burst_window_seconds: u64,
}

fn default_vendor_multiplier() -> f32 {
    0.5
}

fn default_cache_multiplier() -> f32 {
    0.3
}

fn default_burst_threshold() -> usize {
    50
}

fn default_burst_window() -> u64 {
    60
}

impl Default for FalsePositiveReductionConfig {
    fn default() -> Self {
        Self {
            context_scoring: true,
            auto_framework_detection: true,
            vendor_dir_multiplier: 0.5,
            trust_minified: true,
            cache_dir_multiplier: 0.3,
            burst_threshold: 50,
            burst_window_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub log_format: LogFormat,
    #[serde(default)]
    pub alert_webhook: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_log_level() -> String { "info".to_string() }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseAction {
    #[default]
    Alert,
    Kill,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_ms: u64,
    #[serde(default = "default_suspicious_paths")]
    pub suspicious_paths: Vec<PathBuf>,
    #[serde(default = "default_miner_patterns")]
    pub miner_patterns: Vec<String>,
    #[serde(default = "default_suspicious_process_names")]
    pub suspicious_process_names: Vec<String>,
    #[serde(default)]
    pub action: ResponseAction,
    #[serde(default)]
    pub track_ancestry: bool,
    #[serde(default = "default_web_server_processes")]
    pub web_server_processes: Vec<String>,
    #[serde(default = "default_suspicious_child_processes")]
    pub suspicious_child_processes: Vec<String>,
    #[serde(default = "default_true")]
    pub monitor_cpu: bool,
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: f64,
    #[serde(default)]
    pub alert_high_cpu_unknown: bool,
    #[serde(default = "default_high_cpu_threshold")]
    pub high_cpu_threshold: f64,
    /// Use netlink proc_events instead of polling (falls back to polling if unavailable)
    #[serde(default = "default_true")]
    pub use_netlink: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_ms: u64,
    #[serde(default = "default_mining_pools")]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub blocklist_urls: Vec<String>,
    #[serde(default)]
    pub action: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMonitorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub watch_crontab: bool,
    #[serde(default = "default_true")]
    pub watch_ssh_keys: bool,
    #[serde(default = "default_true")]
    pub watch_systemd: bool,
    #[serde(default = "default_true")]
    pub watch_ld_preload: bool,
    #[serde(default)]
    pub action: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub scan_new_files: bool,
    #[serde(default)]
    pub block_suspicious_exec: bool,
    #[serde(default = "default_scan_extensions")]
    pub scan_extensions: Vec<String>,
    #[serde(default = "default_obfuscation_threshold")]
    pub obfuscation_threshold: u32,
    #[serde(default)]
    pub action: ResponseAction,
    /// Enable entropy analysis for detecting packed/encrypted executables
    #[serde(default)]
    pub entropy_analysis: bool,
    /// Entropy threshold (0.0-8.0, higher = more suspicious)
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfMonitorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ebpf_scan_interval")]
    pub scan_interval_ms: u64,
    #[serde(default)]
    pub baseline_file: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub auto_baseline: bool,
    #[serde(default = "default_true")]
    pub alert_on_new_programs: bool,
    #[serde(default = "default_sensitive_kprobe_functions")]
    pub sensitive_kprobe_functions: Vec<String>,
    #[serde(default = "default_true")]
    pub monitor_xdp: bool,
    #[serde(default = "default_true")]
    pub monitor_tc: bool,
    #[serde(default)]
    pub action: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScannerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_memory_scan_interval")]
    pub scan_interval_ms: u64,
    #[serde(default)]
    pub scan_uids: Vec<u32>,
    #[serde(default = "default_memory_skip_processes")]
    pub skip_processes: Vec<String>,
    #[serde(default = "default_true")]
    pub check_suspicious_exec_regions: bool,
    #[serde(default = "default_shellcode_patterns")]
    pub shellcode_patterns: Vec<String>,
    #[serde(default = "default_min_suspicious_size")]
    pub min_suspicious_size: u64,
    #[serde(default)]
    pub action: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityMonitorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_integrity_scan_interval")]
    pub scan_interval_ms: u64,
    #[serde(default)]
    pub baseline_file: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub auto_baseline: bool,
    #[serde(default = "default_integrity_paths")]
    pub watch_paths: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub monitor_kernel_modules: bool,
    #[serde(default = "default_true")]
    pub monitor_boot: bool,
    #[serde(default = "default_true")]
    pub monitor_ld_preload: bool,
    #[serde(default = "default_critical_binaries")]
    pub critical_binaries: Vec<PathBuf>,
    #[serde(default)]
    pub action: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMonitorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_container_scan_interval")]
    pub scan_interval_ms: u64,
    #[serde(default = "default_true")]
    pub detect_escapes: bool,
    #[serde(default = "default_true")]
    pub monitor_namespaces: bool,
    #[serde(default = "default_true")]
    pub monitor_privileged: bool,
    #[serde(default = "default_true")]
    pub alert_host_mount_access: bool,
    #[serde(default = "default_suspicious_capabilities")]
    pub suspicious_capabilities: Vec<String>,
    #[serde(default)]
    pub action: ResponseAction,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cooldown in seconds for low severity events
    #[serde(default = "default_low_cooldown")]
    pub low_seconds: u64,
    /// Cooldown in seconds for medium severity events
    #[serde(default = "default_medium_cooldown")]
    pub medium_seconds: u64,
    /// Cooldown in seconds for high severity events
    #[serde(default = "default_high_cooldown")]
    pub high_seconds: u64,
    /// Cooldown in seconds for critical severity events
    #[serde(default = "default_critical_cooldown")]
    pub critical_seconds: u64,
}

fn default_low_cooldown() -> u64 { 300 }
fn default_medium_cooldown() -> u64 { 120 }
fn default_high_cooldown() -> u64 { 60 }
fn default_critical_cooldown() -> u64 { 30 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            low_seconds: 300,
            medium_seconds: 120,
            high_seconds: 60,
            critical_seconds: 30,
        }
    }
}

/// YARA scanning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    /// Enable YARA scanning (requires yara feature)
    #[serde(default)]
    pub enabled: bool,
    /// Directory containing YARA rules
    #[serde(default = "default_yara_rules_dir")]
    pub rules_dir: PathBuf,
    /// Scan files on creation
    #[serde(default = "default_true")]
    pub scan_on_file_create: bool,
    /// Scan process memory
    #[serde(default)]
    pub scan_memory: bool,
    /// Maximum file size to scan in MB
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    /// Timeout for YARA scans in seconds
    #[serde(default = "default_yara_timeout")]
    pub timeout_secs: u64,
}

fn default_yara_rules_dir() -> PathBuf { PathBuf::from("/etc/xpav/rules") }
fn default_max_file_size_mb() -> u64 { 10 }
fn default_yara_timeout() -> u64 { 30 }

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_dir: default_yara_rules_dir(),
            scan_on_file_create: true,
            scan_memory: false,
            max_file_size_mb: 10,
            timeout_secs: 30,
        }
    }
}

/// Correlation engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Enable correlation engine
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Time window for correlation in seconds
    #[serde(default = "default_correlation_window")]
    pub window_secs: u64,
    /// Maximum events to keep in window
    #[serde(default = "default_max_correlation_events")]
    pub max_events: usize,
}

fn default_correlation_window() -> u64 { 300 }
fn default_max_correlation_events() -> usize { 1000 }
fn default_entropy_threshold() -> f64 { 7.0 }

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 300,
            max_events: 1000,
        }
    }
}

fn default_true() -> bool { true }
fn default_scan_interval() -> u64 { DEFAULT_SCAN_INTERVAL_MS }
fn default_cpu_threshold() -> f64 { DEFAULT_CPU_THRESHOLD }
fn default_high_cpu_threshold() -> f64 { DEFAULT_HIGH_CPU_THRESHOLD }
fn default_obfuscation_threshold() -> u32 { DEFAULT_OBFUSCATION_THRESHOLD }
fn default_ebpf_scan_interval() -> u64 { DEFAULT_EBPF_SCAN_INTERVAL_MS }
fn default_memory_scan_interval() -> u64 { DEFAULT_MEMORY_SCAN_INTERVAL_MS }
fn default_integrity_scan_interval() -> u64 { DEFAULT_INTEGRITY_SCAN_INTERVAL_MS }
fn default_container_scan_interval() -> u64 { DEFAULT_CONTAINER_SCAN_INTERVAL_MS }
fn default_min_suspicious_size() -> u64 { DEFAULT_MIN_SUSPICIOUS_SIZE }

fn default_suspicious_paths() -> Vec<PathBuf> { to_pathbuf_vec(SUSPICIOUS_PATHS) }
fn default_miner_patterns() -> Vec<String> { to_string_vec(MINER_PATTERNS) }
fn default_suspicious_process_names() -> Vec<String> { to_string_vec(SUSPICIOUS_PROCESS_NAMES) }
fn default_web_server_processes() -> Vec<String> { to_string_vec(WEB_SERVER_PROCESSES) }
fn default_suspicious_child_processes() -> Vec<String> { to_string_vec(SUSPICIOUS_CHILD_PROCESSES) }
fn default_watch_paths() -> Vec<PathBuf> { to_pathbuf_vec(WATCH_PATHS) }
fn default_scan_extensions() -> Vec<String> { to_string_vec(SCAN_EXTENSIONS) }
fn default_sensitive_kprobe_functions() -> Vec<String> { to_string_vec(SENSITIVE_KPROBE_FUNCTIONS) }
fn default_memory_skip_processes() -> Vec<String> { to_string_vec(MEMORY_SKIP_PROCESSES) }
fn default_shellcode_patterns() -> Vec<String> { to_string_vec(SHELLCODE_PATTERNS) }
fn default_integrity_paths() -> Vec<PathBuf> { to_pathbuf_vec(INTEGRITY_PATHS) }
fn default_critical_binaries() -> Vec<PathBuf> { to_pathbuf_vec(CRITICAL_BINARIES) }
fn default_suspicious_capabilities() -> Vec<String> { to_string_vec(SUSPICIOUS_CAPABILITIES) }
fn default_mining_pools() -> Vec<String> { to_string_vec(MINING_POOLS) }

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: LogFormat::Json,
            alert_webhook: None,
            dry_run: false,
        }
    }
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_ms: DEFAULT_SCAN_INTERVAL_MS,
            suspicious_paths: default_suspicious_paths(),
            miner_patterns: default_miner_patterns(),
            suspicious_process_names: default_suspicious_process_names(),
            action: ResponseAction::Alert,
            track_ancestry: false,
            web_server_processes: default_web_server_processes(),
            suspicious_child_processes: default_suspicious_child_processes(),
            monitor_cpu: true,
            cpu_threshold: DEFAULT_CPU_THRESHOLD,
            alert_high_cpu_unknown: false,
            high_cpu_threshold: DEFAULT_HIGH_CPU_THRESHOLD,
            use_netlink: true,
        }
    }
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_ms: DEFAULT_SCAN_INTERVAL_MS,
            blocked_domains: default_mining_pools(),
            blocked_ips: vec![],
            blocklist_urls: vec![],
            action: ResponseAction::Alert,
        }
    }
}

impl Default for PersistenceMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_crontab: true,
            watch_ssh_keys: true,
            watch_systemd: true,
            watch_ld_preload: true,
            action: ResponseAction::Alert,
        }
    }
}

impl Default for FileMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_paths: default_watch_paths(),
            scan_new_files: true,
            block_suspicious_exec: false,
            scan_extensions: default_scan_extensions(),
            obfuscation_threshold: DEFAULT_OBFUSCATION_THRESHOLD,
            action: ResponseAction::Alert,
            entropy_analysis: false,
            entropy_threshold: default_entropy_threshold(),
        }
    }
}

impl Default for EbpfMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_ms: DEFAULT_EBPF_SCAN_INTERVAL_MS,
            baseline_file: None,
            auto_baseline: true,
            alert_on_new_programs: true,
            sensitive_kprobe_functions: default_sensitive_kprobe_functions(),
            monitor_xdp: true,
            monitor_tc: true,
            action: ResponseAction::Alert,
        }
    }
}

impl Default for MemoryScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_ms: DEFAULT_MEMORY_SCAN_INTERVAL_MS,
            scan_uids: vec![],
            skip_processes: default_memory_skip_processes(),
            check_suspicious_exec_regions: true,
            shellcode_patterns: default_shellcode_patterns(),
            min_suspicious_size: DEFAULT_MIN_SUSPICIOUS_SIZE,
            action: ResponseAction::Alert,
        }
    }
}

impl Default for IntegrityMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_ms: DEFAULT_INTEGRITY_SCAN_INTERVAL_MS,
            baseline_file: None,
            auto_baseline: true,
            watch_paths: default_integrity_paths(),
            monitor_kernel_modules: true,
            monitor_boot: true,
            monitor_ld_preload: true,
            critical_binaries: default_critical_binaries(),
            action: ResponseAction::Alert,
        }
    }
}

impl Default for ContainerMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_ms: DEFAULT_CONTAINER_SCAN_INTERVAL_MS,
            detect_escapes: true,
            monitor_namespaces: true,
            monitor_privileged: true,
            alert_host_mount_access: true,
            suspicious_capabilities: default_suspicious_capabilities(),
            action: ResponseAction::Alert,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            allowlists: AllowlistConfig::default(),
            rate_limit: RateLimitConfig::default(),
            false_positive_reduction: FalsePositiveReductionConfig::default(),
            process_monitor: ProcessMonitorConfig::default(),
            network_monitor: NetworkMonitorConfig::default(),
            persistence_monitor: PersistenceMonitorConfig::default(),
            file_monitor: FileMonitorConfig::default(),
            ebpf_monitor: EbpfMonitorConfig::default(),
            memory_scanner: MemoryScannerConfig::default(),
            integrity_monitor: IntegrityMonitorConfig::default(),
            container_monitor: ContainerMonitorConfig::default(),
            yara: YaraConfig::default(),
            correlation: CorrelationConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn load_or_default(path: &std::path::Path) -> Self {
        Self::load(path).unwrap_or_default()
    }
}
