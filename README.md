# XPAV - Chi Rho Anti-Virus

> **Note:** This project is not actively maintained and exists for reference purposes only.

```
  __  __ ____   ___  __    __
   \ \/ // __ \ / _ \ \ \  / /
    \  // /_/ // /_\ \ \ \/ /
    /  \\  __// /   \ \ \  /
   /_/\_\\_/  /_/    \_\ \/

        Chi Rho Anti-Virus
            REIUK LTD
```

A lightweight Linux security daemon that detects threats through **behavioral analysis** rather than signature databases.

## Why XPAV?

Traditional antivirus (like ClamAV) relies on hash databases - if malware isn't in the database, it's invisible. XPAV takes a different approach: it watches what programs *do*, not what they *are*.

- No signature updates needed
- Catches zero-day threats
- Detects fileless malware
- Low memory footprint (~26MB)

## What It Detects

### Cryptominers
- Process patterns: `xmrig`, `xmr-stak`, mining flags
- Network: connections to mining pools (`stratum://`, port 3333)
- CPU: sustained high usage with mining characteristics

### Webshells
- PHP input→eval chains: `$_GET` → `eval/system/exec`
- Obfuscation: base64 decode chains, chr() abuse, hex strings
- Known shells: c99, r57, b374k signatures
- Web server spawn detection: apache/nginx spawning bash

### Persistence Mechanisms
- SSH key injection (`authorized_keys` modification)
- Cron backdoors
- Systemd service creation
- LD_PRELOAD hijacking

### Container Escapes
- Privileged container operations
- Suspicious namespace changes
- Host mount access attempts
- Capability abuse

### Fileless Malware
- Memory-only execution (no file on disk)
- Process injection
- Shellcode patterns in memory regions
- Anonymous executable mappings

### eBPF Rootkits
- Suspicious BPF program attachments
- XDP/TC hook monitoring
- Sensitive kprobe detection

### System Integrity
- Kernel module loading
- Boot file modifications
- Critical binary changes

## Installation

```bash
# Build (userspace only)
cargo build --release -p xpav

# Build with native eBPF support (requires nightly)
cargo xtask build --release

# Install binary
sudo cp target/release/xpav /usr/local/bin/

# Install config
sudo mkdir -p /etc/xpav
sudo cp config.example.toml /etc/xpav/config.toml

# Install systemd service (optional)
sudo cp xpav.service /etc/systemd/system/
sudo systemctl enable --now xpav
```

## Usage

```bash
# Run with defaults
sudo xpav

# Dry-run mode (log only, no actions)
sudo xpav --dry-run

# Verbose output
sudo xpav -vv

# JSON logging (for SIEM integration)
sudo xpav --json

# Custom config
sudo xpav --config /path/to/config.toml

# Disable metrics endpoint
sudo xpav --no-metrics
```

## Configuration

See `config.example.toml` for all options. Key settings:

```toml
[general]
dry_run = false
log_format = "text"  # or "json"
alert_webhook = "https://your-webhook.example.com/alerts"

[process_monitor]
enabled = true
scan_interval_ms = 1000
miner_patterns = ["xmrig", "stratum://", ...]

[network_monitor]
enabled = true
mining_pool_ports = [3333, 3334, 4444, ...]

[file_monitor]
enabled = true
watch_paths = ["/var/www", "/srv/http"]

[persistence_monitor]
enabled = true
watch_authorized_keys = true
watch_crontabs = true
watch_systemd = true
```

## Endpoints

When metrics are enabled (default):

- `GET /health` - Health check (returns "OK")
- `GET /ready` - Readiness check
- `GET /metrics` - Prometheus metrics

Default address: `127.0.0.1:9090`

## Requirements

- Linux (uses `/proc`, fanotify, eBPF)
- Root for most monitors (fanotify, eBPF, memory scanning)
- Rust nightly to build (for Edition 2024 and eBPF cross-compilation)
- `rust-src` and `llvm-tools` components (installed automatically via `rust-toolchain.toml`)

## Feature Flags

```bash
# Full build (default features)
cargo build --release -p xpav

# Minimal build (no HTTP endpoints)
cargo build --release -p xpav --no-default-features

# With native eBPF monitoring
cargo xtask build --release

# With YARA scanning
cargo build --release -p xpav --features yara
```

| Feature | Description | Default |
|---------|-------------|---------|
| `metrics` | Prometheus metrics + health endpoints | Yes |
| `webhooks` | HTTP webhook alerting | Yes |
| `ebpf-native` | Native eBPF monitoring via Aya | No |
| `yara` | YARA rule scanning | No |

## Architecture

```
xpav/                  - Workspace root
├── xpav/              - Main userspace daemon
│   ├── Process Monitor    - /proc scanning for suspicious processes
│   ├── Network Monitor    - /proc/net for mining pool connections
│   ├── Persistence Monitor - inotify on SSH keys, cron, systemd
│   ├── File Monitor       - fanotify for real-time file scanning
│   ├── eBPF Monitor       - bpftool for rootkit detection
│   ├── Memory Scanner     - /proc/PID/maps for fileless malware
│   ├── Integrity Monitor  - File hash tracking
│   ├── Container Monitor  - Namespace and capability monitoring
│   └── Response Handler   - Logging, webhooks, Prometheus metrics
├── xpav-ebpf/         - eBPF programs (kernel-space)
├── xpav-common/       - Shared types between userspace and eBPF
└── xtask/             - Build automation (eBPF cross-compilation)
```

## License

MIT

## Author

Julius C (REIUK LTD)
