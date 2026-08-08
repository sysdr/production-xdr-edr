#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use linux_agent_common::ExecEvent;

#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Prefer sched_process_exec (stable tracepoint) over execve kprobes for default telemetry.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sched_process_exec(_ctx: TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xffff_ffff) as u32;

    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    let mut event = ExecEvent {
        pid,
        // Parent pid/start are enriched in userspace from /proc when available.
        ppid: 0,
        uid,
        start_time_ns: 0,
        parent_start_time_ns: 0,
        comm,
        filename: [0; 256],
    };

    // Filename via tracepoint __data_loc is kernel-offset sensitive. Lab default uses
    // comm; Reader VM enrichment: read /proc/<pid>/exe or regenerate offsets with aya-tool
    // (TIER 2). Copy comm into filename so OCSF process.file.path is non-empty in live mode.
    event.filename[..16].copy_from_slice(&event.comm);

    if let Some(mut slot) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }
    Ok(())
}

/// Log-only prevention placeholder. Enforce (non-zero return) needs CONFIG_BPF_LSM,
/// `bpf` on the LSM list, and Module 10 depth-lab controls — do not enable deny here.
#[cfg(feature = "lsm-stub")]
#[aya_ebpf::macros::lsm(hook = "bprm_check_security")]
pub fn lsm_bprm_check_security_stub(_ctx: *mut core::ffi::c_void) -> i32 {
    0 // allow
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
