//! Stress Tests
//!
//! Tests that verify XPAV can handle high-load production scenarios
//! without missing events or degrading performance.
//!
//! IMPORTANT: Some of these tests spawn many processes/files and should
//! be run with appropriate system resources.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use xpav::scanner::webshell::WebshellScanner;
use xpav::monitors::memory::MemoryScanner;

// ============================================================================
// WEBSHELL SCANNER STRESS TESTS
// ============================================================================

/// Test: Scan 1000 files rapidly
#[test]
fn test_rapid_file_scanning() {
    let scanner = WebshellScanner::new(50);
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let file_count = 1000;
    let mut scan_times = Vec::with_capacity(file_count);

    // Create and scan many files
    for i in 0..file_count {
        let file_path = temp_dir.path().join(format!("file_{}.php", i));
        let content = if i % 10 == 0 {
            // 10% malicious
            format!("<?php eval($_GET['{}']); ?>", i)
        } else {
            // 90% legitimate
            format!("<?php echo 'Hello {}'; ?>", i)
        };

        fs::write(&file_path, &content).expect("Failed to write file");

        let start = Instant::now();
        let _ = scanner.scan(&content);
        scan_times.push(start.elapsed());
    }

    // Analyze performance
    let total_time: Duration = scan_times.iter().sum();
    let avg_time = total_time / file_count as u32;
    let max_time = scan_times.iter().max().unwrap();
    let min_time = scan_times.iter().min().unwrap();

    eprintln!("Scanned {} files in {:?}", file_count, total_time);
    eprintln!("Average scan time: {:?}", avg_time);
    eprintln!("Min/Max scan time: {:?} / {:?}", min_time, max_time);

    // Performance assertions
    assert!(
        avg_time < Duration::from_millis(10),
        "Average scan time {:?} exceeds 10ms threshold",
        avg_time
    );

    assert!(
        *max_time < Duration::from_millis(100),
        "Max scan time {:?} exceeds 100ms threshold - possible DoS vector",
        max_time
    );
}

/// Test: Scan very large file without hanging
#[test]
fn test_large_file_scanning() {
    let scanner = WebshellScanner::new(50);

    // Create a 10MB PHP file
    let large_content = format!(
        "<?php\n{}\necho 'end';\n?>",
        "// comment\n".repeat(500_000)
    );

    let start = Instant::now();
    let result = scanner.scan(&large_content);
    let elapsed = start.elapsed();

    eprintln!("Large file ({} bytes) scanned in {:?}", large_content.len(), elapsed);

    // Should complete in reasonable time (< 5 seconds)
    assert!(
        elapsed < Duration::from_secs(5),
        "Large file scan took too long: {:?}",
        elapsed
    );

    // Large legitimate file should be clean
    assert!(
        !result.is_malicious,
        "Large legitimate file incorrectly flagged"
    );
}

/// Test: Scan file with pathological regex patterns
#[test]
fn test_regex_dos_resistance() {
    let scanner = WebshellScanner::new(50);

    // Patterns that could cause regex backtracking
    let pathological_inputs = vec![
        // Long repeated patterns
        "a".repeat(10000) + &"b".repeat(10000),

        // Nested structures
        "(".repeat(1000) + &")".repeat(1000),

        // Many alternations
        (0..1000).map(|i| format!("pattern{}", i)).collect::<Vec<_>>().join("|"),

        // Long lines with special chars
        "\\x".repeat(5000),
    ];

    for (i, input) in pathological_inputs.iter().enumerate() {
        let content = format!("<?php /* {} */ ?>", input);

        let start = Instant::now();
        let _ = scanner.scan(&content);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "Pathological input {} caused slow scan: {:?}",
            i, elapsed
        );
    }
}

/// Test: Concurrent scanning
#[test]
fn test_concurrent_scanning() {
    let scanner = Arc::new(WebshellScanner::new(50));
    let scan_count = Arc::new(AtomicUsize::new(0));
    let detection_count = Arc::new(AtomicUsize::new(0));

    let thread_count = 8;
    let files_per_thread = 100;
    let mut handles = vec![];

    let start = Instant::now();

    for t in 0..thread_count {
        let scanner = Arc::clone(&scanner);
        let scan_count = Arc::clone(&scan_count);
        let detection_count = Arc::clone(&detection_count);

        let handle = thread::spawn(move || {
            for i in 0..files_per_thread {
                let content = if (t * files_per_thread + i) % 20 == 0 {
                    format!("<?php eval($_GET['{}']); ?>", i)
                } else {
                    format!("<?php echo '{}'; ?>", i)
                };

                let result = scanner.scan(&content);
                scan_count.fetch_add(1, Ordering::Relaxed);

                if result.is_malicious {
                    detection_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let elapsed = start.elapsed();
    let total_scans = scan_count.load(Ordering::Relaxed);
    let total_detections = detection_count.load(Ordering::Relaxed);

    eprintln!(
        "Concurrent scan: {} files in {:?} ({} threads)",
        total_scans, elapsed, thread_count
    );
    eprintln!(
        "Rate: {:.0} scans/sec",
        total_scans as f64 / elapsed.as_secs_f64()
    );
    eprintln!("Detections: {}", total_detections);

    assert_eq!(
        total_scans,
        thread_count * files_per_thread,
        "Not all scans completed"
    );

    // Should have some detections (5% are malicious)
    assert!(
        total_detections > 0,
        "No detections in concurrent test"
    );
}

// ============================================================================
// MEMORY MAPS PARSING STRESS TESTS
// ============================================================================

/// Test: Parse large /proc/[pid]/maps
#[test]
fn test_large_maps_parsing() {
    // Generate a large maps file (typical Chrome/Firefox can have 1000+ regions)
    let mut maps_content = String::new();

    for i in 0..2000 {
        let start = 0x7f0000000000u64 + i * 0x1000;
        let end = start + 0x1000;
        let perms = if i % 3 == 0 { "r-xp" } else { "r--p" };
        let path = if i % 5 == 0 {
            format!("/usr/lib/library{}.so", i)
        } else {
            String::new()
        };

        maps_content.push_str(&format!(
            "{:012x}-{:012x} {} {:08x} 08:01 {:>6} {}\n",
            start, end, perms, 0, i, path
        ));
    }

    let start = Instant::now();
    let regions = MemoryScanner::parse_maps(&maps_content);
    let elapsed = start.elapsed();

    eprintln!(
        "Parsed {} regions in {:?}",
        regions.len(), elapsed
    );

    assert_eq!(regions.len(), 2000, "Should parse all regions");

    assert!(
        elapsed < Duration::from_millis(100),
        "Maps parsing took too long: {:?}",
        elapsed
    );
}

/// Test: Parse malformed maps lines
#[test]
fn test_malformed_maps_handling() {
    let malformed_content = r#"
this is not a valid line
7f1234560000-7f1234562000 r-xp 00000000 08:01 12345 /valid/path
incomplete-line
7f1234562000-7f1234564000
another bad line without proper format
7f1234564000-7f1234566000 r--p 00000000 08:01 12346 /another/valid
"#;

    // Should not panic
    let regions = MemoryScanner::parse_maps(malformed_content);

    // Should still parse valid lines
    assert!(
        regions.len() >= 2,
        "Should parse at least the valid lines"
    );
}

// ============================================================================
// PROCESS PATTERN MATCHING STRESS TESTS
// ============================================================================

/// Test: Match patterns against many processes
#[test]
fn test_pattern_matching_performance() {
    use xpav::config::ProcessMonitorConfig;

    let config = ProcessMonitorConfig::default();
    let patterns: Vec<String> = config
        .miner_patterns
        .iter()
        .map(|p| p.to_lowercase())
        .collect();

    let process_count = 10000;
    let mut cmdlines: Vec<String> = Vec::with_capacity(process_count);

    // Generate diverse process cmdlines
    for i in 0..process_count {
        let cmdline = match i % 100 {
            0 => format!("./xmrig -o pool.com:3333 -u wallet{}", i), // Miner
            1..=10 => format!("/usr/bin/python3 script{}.py", i),
            11..=20 => format!("/usr/sbin/nginx -g daemon off;"),
            21..=30 => format!("/usr/bin/node /app/server{}.js", i),
            31..=40 => format!("java -jar application{}.jar", i),
            41..=50 => format!("/usr/bin/postgres -D /var/lib/pgsql/data"),
            51..=60 => format!("/usr/sbin/sshd -D"),
            61..=70 => format!("/usr/bin/dockerd --host=unix:///var/run/docker.sock"),
            _ => format!("/usr/bin/generic_process_{}", i),
        };
        cmdlines.push(cmdline);
    }

    let start = Instant::now();
    let mut detections = 0;

    for cmdline in &cmdlines {
        let cmdline_lower = cmdline.to_lowercase();
        if patterns.iter().any(|p| cmdline_lower.contains(p)) {
            detections += 1;
        }
    }

    let elapsed = start.elapsed();

    eprintln!(
        "Matched {} patterns against {} processes in {:?}",
        patterns.len(), process_count, elapsed
    );
    eprintln!(
        "Rate: {:.0} checks/sec",
        process_count as f64 / elapsed.as_secs_f64()
    );
    eprintln!("Detections: {}", detections);

    // Should be fast (allow up to 500ms for slower systems/CI)
    assert!(
        elapsed < Duration::from_millis(500),
        "Pattern matching too slow: {:?}",
        elapsed
    );

    // Should detect the miners (1%)
    assert!(
        detections >= process_count / 100 - 5,
        "Missing detections: got {}, expected ~{}",
        detections, process_count / 100
    );
}

// ============================================================================
// FILE SYSTEM STRESS TESTS
// ============================================================================

/// Test: Handle rapid file creation/modification
#[test]
fn test_rapid_file_changes() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_count = 100;
    let iterations = 10;

    let start = Instant::now();

    for iter in 0..iterations {
        // Create files
        for i in 0..file_count {
            let path = temp_dir.path().join(format!("file_{}_{}.php", iter, i));
            let content = format!("<?php echo '{}'; ?>", i);
            fs::write(&path, content).expect("Failed to write");
        }

        // Modify files
        for i in 0..file_count {
            let path = temp_dir.path().join(format!("file_{}_{}.php", iter, i));
            let content = format!("<?php echo 'modified {}'; ?>", i);
            fs::write(&path, content).expect("Failed to write");
        }

        // Delete files
        for i in 0..file_count {
            let path = temp_dir.path().join(format!("file_{}_{}.php", iter, i));
            fs::remove_file(&path).ok();
        }
    }

    let elapsed = start.elapsed();
    let total_ops = iterations * file_count * 3; // create, modify, delete

    eprintln!(
        "Performed {} file ops in {:?}",
        total_ops, elapsed
    );
    eprintln!(
        "Rate: {:.0} ops/sec",
        total_ops as f64 / elapsed.as_secs_f64()
    );
}

/// Test: Deep directory traversal
#[test]
fn test_deep_directory_scan() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create deep directory structure
    let depth = 20;
    let files_per_level = 5;

    let mut current = temp_dir.path().to_path_buf();
    for level in 0..depth {
        current = current.join(format!("level_{}", level));
        fs::create_dir_all(&current).expect("Failed to create dir");

        for f in 0..files_per_level {
            let file_path = current.join(format!("file_{}.php", f));
            let content = format!("<?php echo 'level {} file {}'; ?>", level, f);
            fs::write(&file_path, content).expect("Failed to write");
        }
    }

    // Scan entire tree
    let scanner = WebshellScanner::new(50);
    let start = Instant::now();
    let mut scanned = 0;

    fn scan_dir(
        dir: &PathBuf,
        scanner: &WebshellScanner,
        scanned: &mut usize,
    ) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    scan_dir(&path, scanner, scanned);
                } else if path.extension().map(|e| e == "php").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&path) {
                        scanner.scan(&content);
                        *scanned += 1;
                    }
                }
            }
        }
    }

    scan_dir(&temp_dir.path().to_path_buf(), &scanner, &mut scanned);

    let elapsed = start.elapsed();

    eprintln!(
        "Scanned {} files in {} deep dirs in {:?}",
        scanned, depth, elapsed
    );

    assert!(
        scanned == depth * files_per_level,
        "Should scan all files: {} != {}",
        scanned, depth * files_per_level
    );
}

// ============================================================================
// MEMORY STRESS TESTS
// ============================================================================

/// Test: Scanner doesn't leak memory
#[test]
fn test_no_memory_leak() {
    let scanner = WebshellScanner::new(50);

    // Scan many times and verify no significant memory growth
    // (This is a basic test - real memory leak detection needs tools like valgrind)

    for _ in 0..10000 {
        let content = format!("<?php echo '{}'; ?>", rand::random::<u64>());
        let _ = scanner.scan(&content);
    }

    // If we got here without OOM, basic test passed
    // For production, use valgrind or heaptrack
}

/// Test: Handle very long lines without issues
#[test]
fn test_very_long_lines() {
    let scanner = WebshellScanner::new(50);

    // Create file with extremely long line
    let long_line = "a".repeat(1_000_000);
    let content = format!("<?php // {} ?>", long_line);

    let start = Instant::now();
    let result = scanner.scan(&content);
    let elapsed = start.elapsed();

    eprintln!(
        "Scanned {} byte content in {:?}",
        content.len(), elapsed
    );

    // Should have high obfuscation score for very long line
    assert!(
        result.obfuscation_score > 0,
        "Should detect long line as obfuscation indicator"
    );

    assert!(
        elapsed < Duration::from_secs(5),
        "Long line scan too slow: {:?}",
        elapsed
    );
}

// Simple random for test purposes
mod rand {
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn random<T: From<u64>>() -> T {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        T::from(nanos)
    }
}
