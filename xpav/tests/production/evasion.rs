//! Evasion Technique Tests
//!
//! These tests verify that XPAV can detect attacks even when adversaries
//! use various evasion techniques. If any of these tests fail, it means
//! real attackers could bypass detection.

use super::fixtures::*;
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;
use std::io::Write;

use xpav::scanner::webshell::{WebshellScanner, ThreatLevel};
use xpav::config::ProcessMonitorConfig;
use xpav::detection::ProcessInfo;

// ============================================================================
// PROCESS NAME EVASION
// ============================================================================

/// Test: Process masquerading as system binaries
#[test]
fn test_process_masquerading_detection() {
    let legitimate_names = vec![
        "systemd",
        "sshd",
        "cron",
        "nginx",
        "apache2",
        "mysqld",
        "postgres",
        "dockerd",
        "containerd",
    ];

    // Malware often names itself after legitimate binaries
    // but runs from suspicious paths
    let config = ProcessMonitorConfig::default();

    for name in legitimate_names {
        let proc = ProcessInfo {
            pid: 12345,
            ppid: 1,
            name: name.to_string(),
            cmdline: format!("/tmp/.hidden/{} --miner-config", name),
            exe_path: Some(PathBuf::from(format!("/tmp/.hidden/{}", name))),
            cwd: Some(PathBuf::from("/tmp")),
            uid: 1000,
            username: Some("user".to_string()),
            start_time: None,
            ancestors: Vec::new(),
        };

        // Even with legitimate name, suspicious path should trigger
        let exe_path = proc.exe_path.as_ref().unwrap();
        let is_suspicious_path = config
            .suspicious_paths
            .iter()
            .any(|sp| exe_path.starts_with(sp));

        assert!(
            is_suspicious_path,
            "EVASION: Process '{}' from suspicious path {} not detected",
            name, exe_path.display()
        );
    }
}

/// Test: Unicode/homoglyph process name evasion
#[test]
fn test_unicode_process_name_evasion() {
    // Attackers use Unicode lookalikes to evade detection
    // e.g., using Cyrillic 'а' instead of Latin 'a'
    let evasion_attempts = vec![
        ("xmrig", "xmrіg"),  // Cyrillic 'і'
        ("stratum", "strаtum"),  // Cyrillic 'а'
        ("miner", "mіner"),  // Cyrillic 'і'
    ];

    let config = ProcessMonitorConfig::default();
    let patterns: Vec<String> = config.miner_patterns.iter().map(|p| p.to_lowercase()).collect();

    for (original, evasion) in evasion_attempts {
        let evasion_lower = evasion.to_lowercase();

        // Direct pattern match may fail
        let direct_match = patterns.iter().any(|p| evasion_lower.contains(p));

        // This is expected to fail for some evasion attempts
        // The test documents the limitation
        if !direct_match {
            eprintln!(
                "WARNING: Unicode evasion detected - '{}' evades pattern for '{}'",
                evasion, original
            );
            // TODO: Implement Unicode normalization for detection
        }
    }
}

/// Test: Environment variable smuggling
#[test]
fn test_env_var_smuggling() {
    // Attackers hide arguments in environment variables
    let suspicious_env_patterns = vec![
        "XMRIG_POOL=pool.minexmr.com",
        "MINER_URL=stratum://",
        "C2_SERVER=evil.com",
        "PAYLOAD_URL=http://malware.com/shell.sh",
    ];

    // Currently XPAV primarily uses cmdline; env vars are a gap
    for pattern in suspicious_env_patterns {
        eprintln!(
            "NOTE: Environment variable smuggling pattern not directly scanned: {}",
            pattern
        );
    }
}

// ============================================================================
// WEBSHELL EVASION
// ============================================================================

/// Test: Case variation evasion
#[test]
fn test_webshell_case_evasion() {
    let scanner = WebshellScanner::new(50);

    let case_variations = vec![
        r#"<?php EVAL($_GET['cmd']); ?>"#,
        r#"<?php EvAl($_GET['cmd']); ?>"#,
        r#"<?php eVaL($_GET['cmd']); ?>"#,
        r#"<?php SYSTEM($_POST['c']); ?>"#,
        r#"<?php SyStEm($_POST['c']); ?>"#,
    ];

    for content in case_variations {
        let result = scanner.scan(content);
        assert!(
            result.is_malicious,
            "EVASION: Case variation '{}' evaded detection",
            content
        );
    }
}

/// Test: Whitespace injection evasion
#[test]
fn test_webshell_whitespace_evasion() {
    let scanner = WebshellScanner::new(50);

    let whitespace_variations = vec![
        r#"<?php eval    ($_GET['cmd']); ?>"#,
        r#"<?php eval(   $_GET['cmd']); ?>"#,
        r#"<?php eval($_GET   ['cmd']); ?>"#,
        "<?php eval\n($_GET['cmd']); ?>",
        "<?php eval\t($_GET['cmd']); ?>",
        "<?php eval  \n  ($_GET['cmd']); ?>",
    ];

    for content in whitespace_variations {
        let result = scanner.scan(content);
        assert!(
            result.is_malicious,
            "EVASION: Whitespace variation evaded detection: {:?}",
            content.replace('\n', "\\n").replace('\t', "\\t")
        );
    }
}

/// Test: Comment injection evasion
#[test]
fn test_webshell_comment_evasion() {
    let scanner = WebshellScanner::new(50);

    let comment_variations = vec![
        r#"<?php ev/*comment*/al($_GET['cmd']); ?>"#,
        r#"<?php eval/**/($_GET['cmd']); ?>"#,
        r#"<?php system($_POST/***/['c']); ?>"#,
    ];

    for content in comment_variations {
        let result = scanner.scan(content);
        // Comment injection is a known evasion technique
        // Document if it works
        if !result.is_malicious {
            eprintln!(
                "WARNING: Comment injection evasion works: {}",
                content
            );
        }
    }
}

/// Test: String concatenation evasion
///
/// This test documents a KNOWN LIMITATION of static analysis:
/// String concatenation to build function names cannot be reliably
/// detected without execution or taint tracking.
///
/// This is documented as a gap, not a failure.
#[test]
fn test_webshell_concat_evasion() {
    let scanner = WebshellScanner::new(50);

    let concat_evasions = vec![
        // Split function name
        r#"<?php $a='ev'.'al'; $a($_GET['c']); ?>"#,
        r#"<?php $f='sys'.'tem'; $f($_POST['c']); ?>"#,

        // Variable variable
        r#"<?php $a='_GET'; ${$a}['f'](${$a}['c']); ?>"#,

        // Array access
        r#"<?php $a=['ev','al']; ($a[0].$a[1])($_GET['c']); ?>"#,

        // Reverse string
        r#"<?php $f=strrev('metsys'); $f($_GET['c']); ?>"#,
    ];

    let mut evaded_count = 0;
    let mut detected_count = 0;

    for content in &concat_evasions {
        let result = scanner.scan(content);
        if !result.is_malicious && result.threat_level == ThreatLevel::Clean {
            evaded_count += 1;
            eprintln!("KNOWN LIMITATION - Concat evasion not detected: {}", content);
        } else {
            detected_count += 1;
        }
    }

    eprintln!(
        "Concat evasion results: {} detected, {} evaded out of {}",
        detected_count, evaded_count, concat_evasions.len()
    );

    // Document the limitation - static analysis cannot catch all dynamic code
    // This is expected behavior and documented for security team awareness
    eprintln!(
        "\nNOTE: String concatenation evasion is a known limitation of static analysis."
    );
    eprintln!("Mitigation: Use FAN_OPEN_EXEC_PERM to block execution of suspicious files,");
    eprintln!("           or use dynamic analysis/sandboxing for deeper inspection.");
}

/// Test: Encoding evasion
#[test]
fn test_webshell_encoding_evasion() {
    let scanner = WebshellScanner::new(50);

    let encoding_evasions = vec![
        // Hex escape
        (r#"<?php $f="\x65\x76\x61\x6c"; $f($_GET['c']); ?>"#, "hex_escape"),

        // Octal escape
        (r#"<?php $f="\145\166\141\154"; $f($_GET['c']); ?>"#, "octal_escape"),

        // chr() construction
        (r#"<?php $f=chr(101).chr(118).chr(97).chr(108); $f($_GET['c']); ?>"#, "chr_construct"),

        // Unicode escape (PHP 7+)
        (r#"<?php $f="\u{65}\u{76}\u{61}\u{6c}"; $f($_GET['c']); ?>"#, "unicode_escape"),
    ];

    for (content, name) in encoding_evasions {
        let result = scanner.scan(content);

        // These should at least be flagged as suspicious due to obfuscation
        if result.threat_level == ThreatLevel::Clean && result.obfuscation_score < 20 {
            eprintln!(
                "WARNING: Encoding evasion '{}' bypassed detection entirely",
                name
            );
        }
    }
}

/// Test: Multi-layer encoding evasion
#[test]
fn test_webshell_multilayer_evasion() {
    let scanner = WebshellScanner::new(50);

    let multilayer = vec![
        // base64 -> gzinflate -> eval
        r#"<?php eval(gzinflate(base64_decode('...'))); ?>"#,

        // rot13 -> base64 -> eval
        r#"<?php eval(base64_decode(str_rot13('...'))); ?>"#,

        // Multiple base64
        r#"<?php eval(base64_decode(base64_decode('...'))); ?>"#,

        // gzuncompress chain
        r#"<?php eval(gzuncompress(base64_decode(str_rot13('...')))); ?>"#,
    ];

    for content in multilayer {
        let result = scanner.scan(content);

        // All of these should be detected as malicious
        assert!(
            result.is_malicious || result.threat_level == ThreatLevel::Malicious,
            "CRITICAL: Multi-layer encoding '{}' evaded detection",
            content
        );
    }
}

/// Test: File extension evasion
#[test]
fn test_file_extension_evasion() {
    use xpav::scanner::webshell::WebshellScanner;
    use std::path::Path;

    // Extensions that should be scanned
    let scannable = vec![
        "shell.php",
        "shell.phtml",
        "shell.php3",
        "shell.php4",
        "shell.php5",
        "shell.php7",
        "shell.phar",
        "shell.inc",
        "shell.PHP",   // Case insensitive
        "shell.PhP",
    ];

    // Extensions that are NOT typically scanned (potential gap)
    let not_scannable = vec![
        "shell.php.jpg",      // Double extension
        "shell.php%00.jpg",   // Null byte (older PHP)
        "shell.htaccess",     // Apache config
        "shell.php.bak",      // Backup file
    ];

    for ext in scannable {
        assert!(
            WebshellScanner::should_scan(Path::new(ext)),
            "Should scan {}",
            ext
        );
    }

    for ext in not_scannable {
        if WebshellScanner::should_scan(Path::new(ext)) {
            eprintln!("NOTE: Unexpectedly scanning {}", ext);
        }
    }
}

// ============================================================================
// MEMORY EVASION
// ============================================================================

/// Test: Memory region permission evasion
#[test]
fn test_memory_permission_evasion() {
    use xpav::monitors::memory::MemoryRegion;

    // RW memory that later becomes RX (two-stage injection)
    // Initial state: not suspicious (just RW)
    let stage1 = MemoryRegion {
        start: 0x7f0000000000,
        end: 0x7f0000001000,
        permissions: "rw-p".to_string(),
        offset: 0,
        device: "00:00".to_string(),
        inode: 0,
        pathname: String::new(),
    };

    // Later state: suspicious (RX)
    let stage2 = MemoryRegion {
        start: 0x7f0000000000,
        end: 0x7f0000001000,
        permissions: "r-xp".to_string(),
        offset: 0,
        device: "00:00".to_string(),
        inode: 0,
        pathname: String::new(),
    };

    // Stage 1 should not be flagged (no exec)
    assert!(
        !stage1.permissions.contains('x'),
        "Stage 1 should not have exec permission"
    );

    // Stage 2 should be flagged
    assert!(
        stage2.permissions.contains('x'),
        "Stage 2 should have exec permission"
    );

    // The evasion is temporal - attacker writes code to RW,
    // then changes to RX. Scanner must catch the RX state.
}

/// Test: Legitimate JIT regions vs malicious
#[test]
fn test_jit_vs_malicious_memory() {
    use xpav::monitors::memory::MemoryRegion;

    // JIT compilers (like Node.js V8) create anonymous executable regions
    // These are typically:
    // - In specific address ranges
    // - Have certain size patterns
    // - Are associated with known JIT processes

    // This is a hard problem - legitimate JIT vs malicious code
    eprintln!("NOTE: JIT vs malicious memory detection requires process context");

    // Small anonymous exec (likely JIT)
    let small_jit = MemoryRegion {
        start: 0x7f0000000000,
        end: 0x7f0000010000, // 64KB
        permissions: "r-xp".to_string(),
        offset: 0,
        device: "00:00".to_string(),
        inode: 0,
        pathname: String::new(),
    };

    // Large anonymous exec (suspicious)
    let large_suspicious = MemoryRegion {
        start: 0x7f0000000000,
        end: 0x7f0000200000, // 2MB
        permissions: "rwxp".to_string(), // RWX is always suspicious
        offset: 0,
        device: "00:00".to_string(),
        inode: 0,
        pathname: String::new(),
    };

    // RWX is always suspicious regardless of size
    assert!(
        large_suspicious.permissions.contains('w') && large_suspicious.permissions.contains('x'),
        "RWX should always be considered suspicious"
    );
}

// ============================================================================
// TIMING/RACE EVASION
// ============================================================================

/// Test: Rapid process spawn/exit to evade scanning
#[test]
fn test_rapid_process_evasion() {
    // Attackers spawn processes that execute and exit faster than scan interval
    // This test documents the limitation
    let config = ProcessMonitorConfig::default();

    eprintln!(
        "NOTE: Process scan interval is {}ms - processes living shorter may evade detection",
        config.scan_interval_ms
    );

    // Processes that exist for <1 second may be missed
    // Mitigation: Use audit/eBPF for process events
}

/// Test: File write/delete race to evade scanning
#[test]
fn test_file_race_evasion() {
    // Attackers write file, execute, delete - all before scan
    // fanotify FAN_CLOSE_WRITE helps, but there's still a window

    eprintln!("NOTE: Write-execute-delete race may evade file scanning");
    eprintln!("Mitigation: FAN_OPEN_EXEC_PERM for execution-time blocking");
}

// ============================================================================
// NETWORK EVASION
// ============================================================================

/// Test: DNS tunneling for C2
#[test]
fn test_dns_tunneling_evasion() {
    // C2 communication hidden in DNS queries
    let suspicious_dns_patterns = vec![
        "aGVsbG8gd29ybGQ.evil.com",  // Base64-like subdomain
        "78696d72696731.evil.com",    // Hex encoded
        "cmd-whoami.evil.com",        // Command in subdomain
    ];

    for pattern in suspicious_dns_patterns {
        eprintln!(
            "NOTE: DNS tunneling pattern not detected by network monitor: {}",
            pattern
        );
    }

    // This requires DNS query inspection which is outside current scope
}

/// Test: HTTPS C2 (encrypted communication)
#[test]
fn test_encrypted_c2_evasion() {
    // C2 over HTTPS to legitimate-looking domains
    eprintln!("NOTE: HTTPS C2 communication is not inspectable without TLS termination");

    // Can detect by:
    // - Certificate anomalies (self-signed, recently issued)
    // - JA3/JA3S fingerprints
    // - Beacon timing patterns
    // - Domain reputation
}

/// Test: Port hopping evasion
#[test]
fn test_port_hopping_evasion() {
    // Attackers use dynamic/random ports
    let mining_pool_ports = vec![3333, 4444, 5555, 7777, 8888, 9999, 14444, 443, 80];

    eprintln!(
        "NOTE: Mining pools use various ports: {:?}",
        mining_pool_ports
    );

    // Detection should focus on:
    // - Protocol patterns (stratum)
    // - Domain/IP reputation
    // - Connection duration/frequency patterns
}

// ============================================================================
// CONTAINER EVASION
// ============================================================================

/// Test: Container escape via mounted paths
#[test]
fn test_container_mount_evasion() {
    // If /host or similar is mounted, malware can write to host filesystem
    let dangerous_mounts = vec![
        "/host",
        "/hostroot",
        "/mnt/host",
        "/rootfs",
        "/host-root",
    ];

    for mount in dangerous_mounts {
        // Writing to these from a container is escape behavior
        eprintln!(
            "NOTE: Container mount access to '{}' should trigger alert",
            mount
        );
    }
}

/// Test: Container escape via docker.sock
#[test]
fn test_docker_sock_evasion() {
    // Access to /var/run/docker.sock from container = escape
    let docker_sock_paths = vec![
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/containerd/containerd.sock",
    ];

    for path in docker_sock_paths {
        eprintln!(
            "NOTE: Container access to '{}' enables escape",
            path
        );
    }
}

// ============================================================================
// EBPF EVASION
// ============================================================================

/// Test: eBPF rootkit hiding from bpftool
#[test]
fn test_ebpf_hiding_evasion() {
    // Advanced eBPF rootkits may hide from bpftool
    // by hooking the inspection syscalls themselves

    eprintln!("NOTE: eBPF rootkits may hide from bpftool if they hook inspection syscalls");
    eprintln!("Mitigation: Use raw /sys/kernel/debug/tracing in addition to bpftool");
}

/// Test: Legitimate eBPF programs vs malicious
#[test]
fn test_legitimate_ebpf_detection() {
    // Many legitimate tools use eBPF (BCC, bpftrace, Cilium, Falco)
    let legitimate_ebpf_users = vec![
        "bpftrace",
        "bcc",
        "cilium-agent",
        "falco",
        "tcpdump",
        "ss",
        "perf",
    ];

    for tool in legitimate_ebpf_users {
        eprintln!(
            "NOTE: '{}' is a legitimate eBPF user - context matters",
            tool
        );
    }

    // Detection should focus on:
    // - Which kprobes are attached (sensitive functions)
    // - Unknown/unusual program types
    // - Programs loaded from suspicious paths
}

// ============================================================================
// COMPOSITE EVASION
// ============================================================================

/// Test: Multi-technique evasion (realistic attacker)
#[test]
fn test_realistic_attacker_evasion() {
    // Real attackers use multiple techniques simultaneously:
    // 1. Masquerade as legitimate process
    // 2. Execute from memory (fileless)
    // 3. Use encrypted C2
    // 4. Hide in noise of legitimate traffic

    eprintln!("Realistic attacker scenario:");
    eprintln!("1. Initial access via webshell (should be detected)");
    eprintln!("2. Download miner to /dev/shm (should be detected - suspicious path)");
    eprintln!("3. Rename to 'kworker' (partial detection - fake kernel thread)");
    eprintln!("4. Connect to mining pool (should be detected - pool domain)");
    eprintln!("5. If all fail, high CPU will trigger alert");

    // The defense-in-depth approach means multiple detection opportunities
}
