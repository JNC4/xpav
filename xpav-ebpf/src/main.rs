//! eBPF programs for xpav process monitoring.
//!
//! This crate compiles to BPF bytecode and runs in the Linux kernel.
//! It attaches to scheduler tracepoints to monitor process lifecycle events:
//! - `sched_process_exec` - Process execution (execve)
//! - `sched_process_fork` - Process creation (fork/clone)
//! - `sched_process_exit` - Process termination
//!
//! Events are sent to userspace via perf event arrays.

#![no_std]
#![no_main]
// Prevent the compiler from generating calls to memset/memcpy
#![feature(core_intrinsics)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use core::mem::MaybeUninit;
use xpav_common::{ExecEvent, ExitEvent, ForkEvent, COMM_LEN, PATH_LEN};

/// Perf event array for exec events.
/// Userspace reads from this to receive process execution notifications.
#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

/// Perf event array for fork events.
#[map]
static FORK_EVENTS: PerfEventArray<ForkEvent> = PerfEventArray::new(0);

/// Perf event array for exit events.
#[map]
static EXIT_EVENTS: PerfEventArray<ExitEvent> = PerfEventArray::new(0);

/// Zero out a byte array without using memset (uses volatile writes to prevent optimization)
#[inline(always)]
fn zero_array<const N: usize>(arr: &mut [u8; N]) {
    for i in 0..N {
        unsafe {
            core::ptr::write_volatile(&mut arr[i], 0);
        }
    }
}

/// Tracepoint handler for sched_process_exec.
///
/// Triggered when a process calls execve() to execute a new program.
/// This is the primary detection point for new process execution.
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn trace_exec(ctx: TracePointContext) -> i64 {
    match unsafe { try_trace_exec(&ctx) } {
        Ok(()) => 0,
        Err(e) => e,
    }
}

#[inline(always)]
unsafe fn try_trace_exec(ctx: &TracePointContext) -> Result<(), i64> {
    // Get current process info
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    // Create event without using memset - use MaybeUninit and initialize manually
    let mut event: MaybeUninit<ExecEvent> = MaybeUninit::uninit();
    let event_ptr = event.as_mut_ptr();

    // Initialize scalar fields
    (*event_ptr).pid = (pid_tgid >> 32) as u32;
    (*event_ptr).ppid = 0;
    (*event_ptr).uid = uid_gid as u32;
    (*event_ptr).gid = (uid_gid >> 32) as u32;
    (*event_ptr).timestamp_ns = bpf_ktime_get_ns();

    // Zero out arrays manually to avoid memset
    zero_array(&mut (*event_ptr).comm);
    zero_array(&mut (*event_ptr).filename);

    let event = event.assume_init_mut();

    // Read process name (comm)
    if let Ok(comm) = bpf_get_current_comm() {
        // Copy byte by byte to avoid memcpy
        for i in 0..COMM_LEN {
            event.comm[i] = comm[i];
        }
    }

    // The sched_process_exec tracepoint provides filename in the context.
    // Format from /sys/kernel/debug/tracing/events/sched/sched_process_exec/format:
    //   field:__data_loc char[] filename; offset:8; size:4; signed:0;
    //   field:pid_t pid; offset:12; size:4; signed:1;
    //   field:pid_t old_pid; offset:16; size:4; signed:1;
    //
    // The __data_loc format stores offset and length in a u32.
    // We need to read the filename from the data section.

    // Read the __data_loc value for filename
    let data_loc: u32 = ctx.read_at(8).map_err(|e| e as i64)?;
    let filename_offset = (data_loc & 0xFFFF) as usize;
    let filename_len = ((data_loc >> 16) & 0xFFFF) as usize;

    // Read filename from context data
    if filename_len > 0 && filename_offset > 0 {
        let read_len = if filename_len < PATH_LEN - 1 { filename_len } else { PATH_LEN - 1 };
        // Read the filename bytes from the context
        for i in 0..read_len {
            if let Ok(byte) = ctx.read_at::<u8>(filename_offset + i) {
                event.filename[i] = byte;
                if byte == 0 {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Read pid from tracepoint (this is the new pid after exec)
    if let Ok(tp_pid) = ctx.read_at::<i32>(12) {
        if tp_pid > 0 {
            event.pid = tp_pid as u32;
        }
    }

    EXEC_EVENTS.output(ctx, event, 0);
    Ok(())
}

/// Tracepoint handler for sched_process_fork.
///
/// Triggered when a process calls fork() or clone() to create a child.
#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn trace_fork(ctx: TracePointContext) -> i64 {
    match unsafe { try_trace_fork(&ctx) } {
        Ok(()) => 0,
        Err(e) => e,
    }
}

#[inline(always)]
unsafe fn try_trace_fork(ctx: &TracePointContext) -> Result<(), i64> {
    // sched_process_fork format:
    //   field:char parent_comm[16]; offset:8; size:16; signed:0;
    //   field:pid_t parent_pid; offset:24; size:4; signed:1;
    //   field:char child_comm[16]; offset:28; size:16; signed:0;
    //   field:pid_t child_pid; offset:44; size:4; signed:1;

    // Create event without using memset
    let mut event: MaybeUninit<ForkEvent> = MaybeUninit::uninit();
    let event_ptr = event.as_mut_ptr();

    (*event_ptr).parent_pid = 0;
    (*event_ptr).child_pid = 0;
    (*event_ptr).timestamp_ns = bpf_ktime_get_ns();
    zero_array(&mut (*event_ptr).parent_comm);

    let event = event.assume_init_mut();

    // Read parent_pid
    if let Ok(parent_pid) = ctx.read_at::<i32>(24) {
        event.parent_pid = parent_pid as u32;
    }

    // Read child_pid
    if let Ok(child_pid) = ctx.read_at::<i32>(44) {
        event.child_pid = child_pid as u32;
    }

    // Read parent_comm (16 bytes at offset 8)
    for i in 0..COMM_LEN {
        if let Ok(byte) = ctx.read_at::<u8>(8 + i) {
            event.parent_comm[i] = byte;
            if byte == 0 {
                break;
            }
        } else {
            break;
        }
    }

    FORK_EVENTS.output(ctx, event, 0);
    Ok(())
}

/// Tracepoint handler for sched_process_exit.
///
/// Triggered when a process terminates.
#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn trace_exit(ctx: TracePointContext) -> i64 {
    match unsafe { try_trace_exit(&ctx) } {
        Ok(()) => 0,
        Err(e) => e,
    }
}

#[inline(always)]
unsafe fn try_trace_exit(ctx: &TracePointContext) -> Result<(), i64> {
    // sched_process_exit format (varies by kernel, typical):
    //   field:char comm[16]; offset:8; size:16; signed:0;
    //   field:pid_t pid; offset:24; size:4; signed:1;
    //   field:int prio; offset:28; size:4; signed:1;
    //
    // Note: exit_code is not directly in the tracepoint.
    // We'd need to read it from task_struct for accurate values.

    // Create event without using memset
    let mut event: MaybeUninit<ExitEvent> = MaybeUninit::uninit();
    let event_ptr = event.as_mut_ptr();

    (*event_ptr).pid = 0;
    (*event_ptr).exit_code = 0;
    (*event_ptr).timestamp_ns = bpf_ktime_get_ns();
    zero_array(&mut (*event_ptr).comm);

    let event = event.assume_init_mut();

    // Read pid
    if let Ok(pid) = ctx.read_at::<i32>(24) {
        event.pid = pid as u32;
    }

    // Read comm (16 bytes at offset 8)
    for i in 0..COMM_LEN {
        if let Ok(byte) = ctx.read_at::<u8>(8 + i) {
            event.comm[i] = byte;
            if byte == 0 {
                break;
            }
        } else {
            break;
        }
    }

    EXIT_EVENTS.output(ctx, event, 0);
    Ok(())
}

/// Panic handler required for no_std.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
