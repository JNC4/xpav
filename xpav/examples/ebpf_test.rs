//! Standalone test for eBPF loading and exec event capture.
//! Run with: sudo cargo run -p xpav --example ebpf_test --features ebpf-native

use std::time::Duration;

use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use std::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;

// Use shared types from xpav-common
use xpav_common::ExecEvent;

const EBPF_PATH: &str = "./target/bpf/xpav_ebpf.o";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== xpav eBPF End-to-End Test ===\n");

    // Step 1: Verify the .o file exists
    println!("[1/4] Checking eBPF program file...");
    if !std::path::Path::new(EBPF_PATH).exists() {
        anyhow::bail!(
            "eBPF program not found at {}. Run: cargo xtask build-ebpf",
            EBPF_PATH
        );
    }
    println!("      Found: {}", EBPF_PATH);

    // Step 2: Load BPF programs
    println!("\n[2/4] Loading eBPF programs...");
    let mut bpf = Bpf::load_file(EBPF_PATH)?;
    println!("      Loaded successfully!");

    // List available programs and maps
    println!("\n      Programs:");
    for (name, _) in bpf.programs() {
        println!("        - {}", name);
    }
    println!("      Maps:");
    for (name, _) in bpf.maps() {
        println!("        - {}", name);
    }

    // Step 3: Attach to tracepoints
    println!("\n[3/4] Attaching to tracepoints...");

    // Try exit first (no memset calls)
    println!("      Loading trace_exit...");
    let exit_prog = bpf
        .program_mut("trace_exit")
        .ok_or_else(|| anyhow::anyhow!("trace_exit program not found"))?;
    let exit_prog: &mut TracePoint = exit_prog.try_into()?;
    exit_prog.load()?;
    exit_prog.attach("sched", "sched_process_exit")?;
    println!("      Attached to sched:sched_process_exit");

    // Now try exec
    println!("      Loading trace_exec...");
    let exec_prog = bpf
        .program_mut("trace_exec")
        .ok_or_else(|| anyhow::anyhow!("trace_exec program not found"))?;
    let exec_prog: &mut TracePoint = exec_prog.try_into()?;
    exec_prog.load()?;
    exec_prog.attach("sched", "sched_process_exec")?;
    println!("      Attached to sched:sched_process_exec");

    // Set up perf event array for exec events
    let exec_events_map = bpf
        .take_map("EXEC_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("EXEC_EVENTS map not found"))?;
    let mut exec_events = AsyncPerfEventArray::try_from(exec_events_map)?;

    // Channel to receive events
    let (event_tx, mut event_rx) = mpsc::channel::<ExecEvent>(64);

    // Spawn readers for each CPU
    let cpus = online_cpus()?;
    println!("      Setting up perf buffers for {} CPUs", cpus.len());

    for cpu_id in cpus {
        let mut buf = exec_events.open(cpu_id, None)?;
        let tx = event_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ExecEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        eprintln!("Error reading perf events on CPU {}: {}", cpu_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                for i in 0..events.read {
                    let buf = &buffers[i];
                    if buf.len() >= std::mem::size_of::<ExecEvent>() {
                        let event: ExecEvent =
                            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
    drop(event_tx);

    // Step 4: Spawn test process and capture event
    println!("\n[4/4] Spawning test process and waiting for exec event...");

    // Give perf buffers time to initialize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn a test process
    let test_cmd = "echo";
    println!("      Executing: {} test-marker-12345", test_cmd);

    let _child = Command::new(test_cmd).arg("test-marker-12345").spawn().expect("spawn test cmd");

    // Wait for at least one exec event (with timeout)
    let mut events_received = 0;
    let test_timeout = Duration::from_secs(5);

    println!(
        "      Waiting for exec events (timeout: {}s)...\n",
        test_timeout.as_secs()
    );

    let start = std::time::Instant::now();
    loop {
        match timeout(Duration::from_millis(500), event_rx.recv()).await {
            Ok(Some(event)) => {
                events_received += 1;
                let comm = String::from_utf8_lossy(event.comm_bytes());
                let filename = String::from_utf8_lossy(event.filename_bytes());

                println!(
                    "      EVENT #{}: pid={} ppid={} uid={} comm=\"{}\" filename=\"{}\"",
                    events_received, event.pid, event.ppid, event.uid, comm, filename
                );

                // Check for our test marker or common commands
                if events_received >= 3 {
                    break;
                }
            }
            Ok(None) => {
                println!("      Channel closed");
                break;
            }
            Err(_) => {
                // Timeout on recv
                if start.elapsed() > test_timeout {
                    break;
                }
                // Spawn another process to trigger more events
                let _ = Command::new("true").spawn();
            }
        }
    }

    println!("\n=== Test Results ===");
    if events_received > 0 {
        println!(
            "SUCCESS: Received {} exec event(s) from eBPF perf buffer!",
            events_received
        );
        println!("\nThe eBPF implementation is working correctly:");
        println!("  - eBPF program loads from {}", EBPF_PATH);
        println!("  - Tracepoint attachment works");
        println!("  - Perf buffer communication works");
        println!("  - Events flow from kernel to userspace");
        Ok(())
    } else {
        anyhow::bail!("FAILED: No exec events received within timeout period")
    }
}
