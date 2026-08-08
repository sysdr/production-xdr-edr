//! Live eBPF attach path — compiled on Linux hosts (always linked with Aya).
//!
//! TIER 2: Aya loader call sites track crates.io aya 0.14.x (verified July 2026).
//! Re-check https://aya-rs.dev/book/ and crates.io if attach APIs shift.

#![cfg(target_os = "linux")]

use anyhow::{anyhow, Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use linux_agent_common::ExecEvent;
use std::convert::TryFrom;
use std::path::Path;

pub fn load_and_attach(object_path: &Path) -> Result<Ebpf> {
    let mut bpf = Ebpf::load_file(object_path)
        .with_context(|| format!("load eBPF object {}", object_path.display()))?;

    let program: &mut TracePoint = bpf
        .program_mut("sched_process_exec")
        .ok_or_else(|| anyhow!("program sched_process_exec missing from object"))?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    #[cfg(feature = "lsm-stub")]
    {
        eprintln!(
            "lsm-stub: feature enabled — verify `cat /sys/kernel/security/lsm` contains bpf before enforce (Module 10)"
        );
    }

    Ok(bpf)
}

pub fn poll_exec_events(bpf: &mut Ebpf, mut on_event: impl FnMut(ExecEvent)) -> Result<()> {
    let map = bpf
        .map_mut("EXEC_EVENTS")
        .ok_or_else(|| anyhow!("EXEC_EVENTS map missing"))?;
    let mut ring = RingBuf::try_from(map)?;

    loop {
        if let Some(item) = ring.next() {
            let bytes = item.as_ref();
            if bytes.len() >= ExecEvent::SIZE {
                let mut buf = [0u8; ExecEvent::SIZE];
                buf.copy_from_slice(&bytes[..ExecEvent::SIZE]);
                // SAFETY: ExecEvent is #[repr(C)] and matches the eBPF writer layout.
                let ev = unsafe { std::ptr::read(buf.as_ptr() as *const ExecEvent) };
                on_event(ev);
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
