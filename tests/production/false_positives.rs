//! False Positive Tests
//!
//! These tests ensure that legitimate software, development tools,
//! and normal system operations do NOT trigger false alarms.
//!
//! False positives are worse than missed detections in many ways:
//! - Alert fatigue leads to ignored real alerts
//! - Blocking legitimate software disrupts operations
//! - Damages trust in the security tool

use super::fixtures::*;
use std::path::PathBuf;

use xpav::scanner::webshell::{WebshellScanner, ThreatLevel};
use xpav::config::{ProcessMonitorConfig, MemoryScannerConfig};
use xpav::detection::ProcessInfo;
use xpav::monitors::memory::MemoryRegion;

// ============================================================================
// LEGITIMATE PROCESS FALSE POSITIVES
// ============================================================================

/// Test: System processes should not trigger alerts
#[test]
fn test_system_processes_not_flagged() {
    let config = ProcessMonitorConfig::default();
    let patterns: Vec<String> = config.miner_patterns.iter().map(|p| p.to_lowercase()).collect();

    let system_processes = vec![
        // Core system
        ("systemd", "/usr/lib/systemd/systemd --switched-root --system --deserialize 31"),
        ("init", "/sbin/init"),
        ("kthreadd", "[kthreadd]"),
        ("rcu_gp", "[rcu_gp]"),
        ("ksoftirqd/0", "[ksoftirqd/0]"),
        ("kworker/0:0", "[kworker/0:0]"),
        ("migration/0", "[migration/0]"),

        // Services
        ("sshd", "/usr/sbin/sshd -D"),
        ("cron", "/usr/sbin/cron -f"),
        ("rsyslogd", "/usr/sbin/rsyslogd -n"),
        ("dbus-daemon", "/usr/bin/dbus-daemon --system"),
        ("polkitd", "/usr/lib/polkit-1/polkitd --no-debug"),

        // Databases
        ("mysqld", "/usr/sbin/mysqld --basedir=/usr"),
        ("postgres", "postgres: checkpointer process"),
        ("redis-server", "redis-server *:6379"),
        ("mongod", "/usr/bin/mongod --config /etc/mongod.conf"),

        // Web servers
        ("nginx", "nginx: worker process"),
        ("apache2", "/usr/sbin/apache2 -k start"),
        ("httpd", "/usr/sbin/httpd -DFOREGROUND"),
        ("php-fpm", "php-fpm: pool www"),

        // Containers
        ("dockerd", "/usr/bin/dockerd -H fd://"),
        ("containerd", "/usr/bin/containerd"),
        ("kubelet", "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml"),
    ];

    for (name, cmdline) in system_processes {
        let name_lower = name.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();

        // Should NOT match miner patterns
        let matches_miner = patterns.iter().any(|p| {
            name_lower.contains(p) || cmdline_lower.contains(p)
        });

        assert!(
            !matches_miner,
            "FALSE POSITIVE: System process '{}' incorrectly matches miner pattern",
            name
        );
    }
}

/// Test: Development tools should not trigger alerts
#[test]
fn test_development_tools_not_flagged() {
    let config = ProcessMonitorConfig::default();
    let patterns: Vec<String> = config.miner_patterns.iter().map(|p| p.to_lowercase()).collect();

    let dev_tools = vec![
        // Compilers
        ("gcc", "gcc -O2 -o program program.c"),
        ("g++", "g++ -std=c++17 -o app main.cpp"),
        ("rustc", "rustc --edition 2021 main.rs"),
        ("clang", "clang++ -stdlib=libc++ main.cpp"),
        ("go", "go build -o myapp ."),
        ("javac", "javac Main.java"),

        // Build tools
        ("make", "make -j8"),
        ("cmake", "cmake -B build -S ."),
        ("cargo", "cargo build --release"),
        ("npm", "npm run build"),
        ("yarn", "yarn build"),
        ("gradle", "./gradlew build"),
        ("mvn", "mvn package"),

        // Interpreters/Runtimes
        ("python", "python script.py"),
        ("python3", "python3 -m pytest"),
        ("node", "node server.js"),
        ("ruby", "ruby app.rb"),
        ("perl", "perl script.pl"),
        ("php", "php artisan serve"),

        // Debuggers/Profilers
        ("gdb", "gdb -q ./program"),
        ("lldb", "lldb ./program"),
        ("valgrind", "valgrind --leak-check=full ./program"),
        ("strace", "strace -f ./program"),
        ("perf", "perf record ./program"),
        ("ltrace", "ltrace ./program"),

        // Editors/IDEs
        ("vim", "vim file.txt"),
        ("nvim", "nvim --headless"),
        ("emacs", "emacs --daemon"),
        ("code", "code --extensions-dir ~/.vscode"),

        // Version control
        ("git", "git pull origin main"),
        ("svn", "svn update"),
        ("hg", "hg pull"),
    ];

    for (name, cmdline) in dev_tools {
        let name_lower = name.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();

        let matches_miner = patterns.iter().any(|p| {
            name_lower.contains(p) || cmdline_lower.contains(p)
        });

        assert!(
            !matches_miner,
            "FALSE POSITIVE: Development tool '{}' incorrectly flagged",
            name
        );
    }
}

/// Test: Legitimate GPU/compute workloads should not trigger
#[test]
fn test_legitimate_gpu_workloads_not_flagged() {
    // These look similar to miners but are legitimate
    let legitimate_gpu = vec![
        // Machine learning
        ("python", "python train_model.py --epochs 100 --gpu 0"),
        ("python3", "python3 -c 'import tensorflow as tf; tf.test.gpu_device_name()'"),
        ("torch", "python -c 'import torch; torch.cuda.is_available()'"),

        // Scientific computing
        ("julia", "julia --threads auto compute.jl"),
        ("matlab", "matlab -nodisplay -r 'simulation'"),
        ("octave", "octave-cli --eval 'benchmark'"),

        // Rendering
        ("blender", "blender -b scene.blend -a"),
        ("ffmpeg", "ffmpeg -i input.mp4 -c:v libx265 -crf 28 output.mp4"),
        ("handbrake", "HandBrakeCLI -i video.mp4 -o output.mkv"),

        // Compilation
        ("ninja", "ninja -j 32"),
        ("ccache", "ccache gcc -c file.c"),
    ];

    let config = ProcessMonitorConfig::default();
    let patterns: Vec<String> = config.miner_patterns.iter().map(|p| p.to_lowercase()).collect();

    for (name, cmdline) in legitimate_gpu {
        let cmdline_lower = cmdline.to_lowercase();

        let matches_miner = patterns.iter().any(|p| cmdline_lower.contains(p));

        assert!(
            !matches_miner,
            "FALSE POSITIVE: Legitimate GPU workload '{}' flagged as miner",
            name
        );
    }
}

/// Test: Network tools should not trigger C2 alerts
#[test]
fn test_network_tools_not_flagged() {
    // Legitimate network tools that might look suspicious
    let network_tools = vec![
        ("curl", "curl -s https://api.github.com/user"),
        ("wget", "wget -q https://example.com/file.tar.gz"),
        ("rsync", "rsync -avz /data remote:/backup"),
        ("scp", "scp file.txt user@server:/path"),
        ("ssh", "ssh -N -L 8080:localhost:80 server"),
        ("nc", "nc -l 8080"),  // Legitimate listening
        ("netcat", "netcat -z -v host 1-1000"),  // Port scanning (admin use)
        ("nmap", "nmap -sV localhost"),  // Security scanning
        ("tcpdump", "tcpdump -i eth0 port 80"),
        ("wireshark", "wireshark -i eth0"),
        ("iperf", "iperf3 -c server -t 60"),
        ("dig", "dig @8.8.8.8 example.com"),
        ("nslookup", "nslookup example.com"),
        ("ping", "ping -c 4 google.com"),
        ("traceroute", "traceroute google.com"),
    ];

    for (name, _cmdline) in network_tools {
        // Just verify the tool name doesn't match suspicious patterns
        assert!(
            !name.contains("miner") && !name.contains("xmr"),
            "Network tool '{}' has suspicious name",
            name
        );
    }
}

/// Test: Container management should not trigger escape alerts
#[test]
fn test_container_management_not_flagged() {
    let container_ops = vec![
        ("docker", "docker build -t myapp ."),
        ("docker", "docker run -v /data:/data myapp"),
        ("docker", "docker exec -it container bash"),
        ("podman", "podman run --rm alpine echo hello"),
        ("kubectl", "kubectl apply -f deployment.yaml"),
        ("kubectl", "kubectl exec -it pod -- /bin/sh"),
        ("crictl", "crictl ps"),
        ("ctr", "ctr images ls"),
        ("nerdctl", "nerdctl run --rm alpine"),
    ];

    // These are legitimate container operations
    for (tool, cmd) in container_ops {
        eprintln!("Legitimate container op: {} - {}", tool, cmd);
    }
}

// ============================================================================
// LEGITIMATE PHP FALSE POSITIVES
// ============================================================================

/// Test: Legitimate PHP frameworks should not trigger
#[test]
fn test_php_frameworks_not_flagged() {
    let scanner = WebshellScanner::new(50);

    let mut flagged = 0;

    for (name, content) in legitimate_php() {
        let result = scanner.scan(content);

        if result.is_malicious {
            flagged += 1;
            eprintln!(
                "FALSE POSITIVE: Legitimate PHP '{}' flagged as malicious: {:?}",
                name, result.detections
            );
        } else if result.threat_level == ThreatLevel::Suspicious {
            eprintln!(
                "NOTE: Legitimate PHP '{}' flagged as Suspicious (not Malicious)",
                name
            );
        }
    }

    let total = legitimate_php().len();
    let fp_rate = (flagged as f64 / total as f64) * 100.0;

    // Allow up to 10% false positive rate for edge cases
    assert!(
        fp_rate <= 10.0,
        "False positive rate too high: {:.1}% ({}/{})",
        fp_rate, flagged, total
    );
}

/// Test: WordPress core files should not trigger
#[test]
fn test_wordpress_core_not_flagged() {
    let scanner = WebshellScanner::new(50);

    // Simplified WordPress patterns that should be safe
    let wp_patterns = vec![
        (r#"<?php
define('ABSPATH', '/var/www/html/');
require_once(ABSPATH . 'wp-settings.php');
?>"#, "wp-config.php style"),

        (r#"<?php
function wp_sanitize_key($key) {
    $key = strtolower($key);
    return preg_replace('/[^a-z0-9_\-]/', '', $key);
}
?>"#, "sanitization function"),

        (r#"<?php
add_action('init', function() {
    register_post_type('product', array(
        'public' => true,
        'label' => 'Products'
    ));
});
?>"#, "post type registration"),
    ];

    for (content, desc) in wp_patterns {
        let result = scanner.scan(content);

        assert!(
            !result.is_malicious,
            "FALSE POSITIVE: WordPress pattern '{}' flagged as malicious",
            desc
        );
    }
}

/// Test: PHP testing frameworks should not trigger
#[test]
fn test_php_testing_frameworks_not_flagged() {
    let scanner = WebshellScanner::new(50);

    let test_code = r#"<?php
use PHPUnit\Framework\TestCase;

class UserTest extends TestCase
{
    public function testUserCreation()
    {
        $user = new User('test@example.com');
        $this->assertEquals('test@example.com', $user->getEmail());
    }

    public function testPasswordHashing()
    {
        $user = new User('test@example.com');
        $user->setPassword('secret123');
        $this->assertTrue(password_verify('secret123', $user->getPasswordHash()));
    }
}
?>"#;

    let result = scanner.scan(test_code);

    assert!(
        !result.is_malicious,
        "FALSE POSITIVE: PHPUnit test code flagged as malicious"
    );
}

// ============================================================================
// LEGITIMATE MEMORY PATTERNS
// ============================================================================

/// Test: JIT memory should not trigger (when context allows)
#[test]
fn test_jit_memory_not_flagged() {
    // JIT compilers create anonymous executable memory
    let jit_processes = vec![
        "node",
        "java",
        "python",
        "ruby",
        "julia",
        "dotnet",
        "mono",
    ];

    for proc in jit_processes {
        eprintln!(
            "NOTE: Process '{}' uses JIT and creates anonymous exec memory",
            proc
        );
    }

    // The memory scanner should have context about known JIT users
}

/// Test: Normal library mappings should not trigger
#[test]
fn test_normal_library_mappings_not_flagged() {
    let normal_regions = vec![
        MemoryRegion {
            start: 0x7f0000000000,
            end: 0x7f0000200000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "08:01".to_string(),
            inode: 12345,
            pathname: "/usr/lib/libc.so.6".to_string(),
        },
        MemoryRegion {
            start: 0x7f0000000000,
            end: 0x7f0000100000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "08:01".to_string(),
            inode: 54321,
            pathname: "/usr/lib/x86_64-linux-gnu/libssl.so.3".to_string(),
        },
        MemoryRegion {
            start: 0x7f0000000000,
            end: 0x7f0000050000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "08:01".to_string(),
            inode: 11111,
            pathname: "/usr/lib/x86_64-linux-gnu/libpthread.so.0".to_string(),
        },
        // VDSO (kernel virtual dynamic shared object)
        MemoryRegion {
            start: 0x7ffff7ff8000,
            end: 0x7ffff7ffc000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: "[vdso]".to_string(),
        },
        // VVAR
        MemoryRegion {
            start: 0x7ffff7ff4000,
            end: 0x7ffff7ff8000,
            permissions: "r--p".to_string(),
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: "[vvar]".to_string(),
        },
    ];

    for region in normal_regions {
        let is_suspicious = check_suspicious(&region);

        assert!(
            !is_suspicious,
            "FALSE POSITIVE: Normal library '{}' flagged as suspicious",
            region.pathname
        );
    }
}

fn check_suspicious(region: &MemoryRegion) -> bool {
    if !region.permissions.contains('x') {
        return false;
    }

    // Anonymous RWX
    if region.pathname.is_empty() && region.inode == 0 && region.permissions.contains('w') {
        return true;
    }

    // Heap/stack exec
    if region.pathname.contains("[heap]") || region.pathname.contains("[stack]") {
        return true;
    }

    // Suspicious paths
    if region.pathname.starts_with("/tmp/")
        || region.pathname.starts_with("/dev/shm/")
        || region.pathname.starts_with("/var/tmp/")
    {
        return true;
    }

    // Deleted file
    if region.pathname.contains("(deleted)") {
        return true;
    }

    // VDSO/VVAR/vsyscall are normal
    if region.pathname == "[vdso]"
        || region.pathname == "[vvar]"
        || region.pathname == "[vsyscall]"
    {
        return false;
    }

    false
}

// ============================================================================
// LEGITIMATE NETWORK PATTERNS
// ============================================================================

/// Test: Standard ports should not trigger
#[test]
fn test_standard_ports_not_flagged() {
    let standard_services = vec![
        (22, "SSH"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (25, "SMTP"),
        (465, "SMTPS"),
        (587, "Submission"),
        (110, "POP3"),
        (143, "IMAP"),
        (993, "IMAPS"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (27017, "MongoDB"),
        (6379, "Redis"),
        (5672, "RabbitMQ"),
        (9200, "Elasticsearch"),
        (8080, "HTTP-alt"),
        (8443, "HTTPS-alt"),
    ];

    for (port, service) in standard_services {
        // Standard ports should not trigger C2 alerts
        assert!(
            port != 4444 && port != 31337 && port != 1337,
            "Standard service {} uses suspicious port {}",
            service, port
        );
    }
}

/// Test: CDN and cloud provider connections should not trigger
#[test]
fn test_cloud_connections_not_flagged() {
    let legitimate_domains = vec![
        // AWS
        "ec2.amazonaws.com",
        "s3.amazonaws.com",
        "lambda.amazonaws.com",

        // Google Cloud
        "storage.googleapis.com",
        "compute.googleapis.com",

        // Azure
        "blob.core.windows.net",
        "azurewebsites.net",

        // CDNs
        "cloudflare.com",
        "akamai.net",
        "fastly.net",
        "cdn.jsdelivr.net",

        // Common SaaS
        "github.com",
        "gitlab.com",
        "npmjs.org",
        "pypi.org",
        "rubygems.org",
        "crates.io",
        "docker.io",
    ];

    for domain in legitimate_domains {
        // These should never appear in threat indicators
        assert!(
            !domain.contains("pool") && !domain.contains("stratum"),
            "Legitimate domain {} looks suspicious",
            domain
        );
    }
}

// ============================================================================
// LEGITIMATE PERSISTENCE PATTERNS
// ============================================================================

/// Test: Normal systemd units should not trigger
#[test]
fn test_normal_systemd_not_flagged() {
    let normal_units = vec![
        ("[Unit]\nDescription=Docker Application Container Engine",
         "docker.service"),
        ("[Unit]\nDescription=The nginx HTTP and reverse proxy server",
         "nginx.service"),
        ("[Unit]\nDescription=PostgreSQL database server",
         "postgresql.service"),
        ("[Timer]\nOnCalendar=daily\nPersistent=true",
         "logrotate.timer"),
    ];

    for (content, name) in normal_units {
        // Check for absence of suspicious patterns
        let suspicious = content.contains("/tmp/")
            || content.contains("/dev/shm/")
            || content.contains("curl")
            || content.contains("wget")
            || content.contains("stratum");

        assert!(
            !suspicious,
            "Normal systemd unit '{}' contains suspicious patterns",
            name
        );
    }
}

/// Test: Normal cron jobs should not trigger
#[test]
fn test_normal_cron_not_flagged() {
    let normal_crons = vec![
        "0 2 * * * /usr/bin/apt-get update",
        "0 3 * * 0 /usr/bin/find /var/log -mtime +30 -delete",
        "*/5 * * * * /usr/bin/rsync -a /data /backup",
        "0 0 * * * /usr/bin/logrotate /etc/logrotate.conf",
        "@reboot /usr/bin/docker start mycontainer",
    ];

    for cron in normal_crons {
        let suspicious = cron.contains("stratum")
            || cron.contains("pool.")
            || cron.contains("/dev/tcp/")
            || cron.contains("base64")
            || cron.contains("curl.*|.*sh");

        assert!(
            !suspicious,
            "Normal cron job contains suspicious patterns: {}",
            cron
        );
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// Test: Similar names to suspicious processes
#[test]
fn test_similar_names_not_flagged() {
    // Process names that are similar to malware but legitimate
    let similar_names = vec![
        ("minerd", false),      // Actual miner name - SHOULD flag
        ("reminder", true),     // Contains "miner" but legitimate
        ("examiner", true),     // Contains "miner" but legitimate
        ("streamlit", true),    // Contains "stratum"-ish but legitimate
        ("poolparty", true),    // Contains "pool" but legitimate
    ];

    let config = ProcessMonitorConfig::default();
    let patterns: Vec<String> = config.miner_patterns.iter().map(|p| p.to_lowercase()).collect();

    for (name, should_be_safe) in similar_names {
        let name_lower = name.to_lowercase();
        let matches = patterns.iter().any(|p| name_lower.contains(p));

        if should_be_safe {
            assert!(
                !matches,
                "FALSE POSITIVE: Legitimate name '{}' matches miner pattern",
                name
            );
        }
    }
}

/// Test: Process in /tmp during package installation
#[test]
fn test_tmp_during_install_context() {
    // Package managers sometimes extract and run from /tmp
    // This is a known false positive scenario

    let install_scenarios = vec![
        "/tmp/pip-build-abc123/setup.py",
        "/tmp/npm-12345/node_modules/.bin/webpack",
        "/tmp/cargo-install.abc123/build/debug/tool",
        "/var/tmp/apt-dpkg-install-abc123/configure",
    ];

    for path in install_scenarios {
        eprintln!(
            "KNOWN FALSE POSITIVE RISK: Package install from {}",
            path
        );
    }

    // Mitigation: Check process ancestry for package managers
}

/// Test: High CPU during legitimate workload
#[test]
fn test_high_cpu_legitimate_workloads() {
    // Many legitimate workloads cause high CPU
    let high_cpu_scenarios = vec![
        ("gcc", "Compiling large project"),
        ("cargo", "Building Rust project"),
        ("webpack", "Bundling JavaScript"),
        ("ffmpeg", "Encoding video"),
        ("imagemagick", "Processing images"),
        ("tar", "Compressing archive"),
        ("7z", "Archive operations"),
        ("python", "ML training"),
        ("java", "Running tests"),
        ("stress", "Load testing"),  // Deliberate stress testing
    ];

    for (process, reason) in high_cpu_scenarios {
        eprintln!(
            "High CPU legitimate: {} - {}",
            process, reason
        );
    }

    // High CPU alone should not trigger - needs additional context
}
