# agent-linux

Issue 02 / Module 1 — Linux agent v0: process exec telemetry via eBPF (Aya), emitting OCSF-shaped JSON.

Newsletter: `docs/issue-notes/02-linux-agent-ebpf.md`  
Guide: `docs/implementation-guides/02-linux-agent-ebpf.md`  
Tag: `v02-linux-agent-ebpf`

## What is real vs stubbed

| Capability | Status |
|---|---|
| OCSF JSON encoder (`type_uid`, `process.uid`, actor/parent) | **Real** |
| Noise filter + in-memory process tree | **Real** |
| Fixture replay (`--mode replay`) | **Real** — Sandbox / CI / macOS |
| Deep telemetry `--class file\|network\|persistence` (Issues 07–09) | **Real fixtures** — live hooks remain Reader VM |
| eBPF program source (`sched_process_exec` + optional LSM stub) | **Shipped** — build on Linux bpf target |
| Live kernel attach (`--mode live`) | **Reader VM** — needs Linux + privileges + built object |
| LSM **enforce** (deny exec) | **Stub / deferred** to Module 10 |
| gRPC ingest to backend | **Not in this issue** — stdout JSON only |

## Quick start (any host)

```bash
cd agent-linux
cargo test -p linux-agent
cargo run -p linux-agent -- --mode replay --print-tree
cargo run -p linux-agent -- --mode replay --class file
cargo run -p linux-agent -- --mode replay --class network
cargo run -p linux-agent -- --mode replay --class persistence
```

## Live mode (Linux Reader VM)

See the implementation guide for bpfel build flags (track current Aya book). Then:

```bash
cargo build -p linux-agent
sudo ./target/debug/linux-agent \
  --mode live \
  --ebpf-object linux-agent-ebpf/target/bpfel-unknown-none/release/linux-agent-ebpf
```

## Layout

```
linux-agent/           userspace binary
linux-agent-common/    shared ExecEvent ABI
linux-agent-ebpf/      eBPF programs (separate manifest, bpf target)
fixtures/              recorded exec events for replay tests
```

## Sandbox / CI / Reader VM

| | Sandbox / CI | Reader VM |
|---|---|---|
| Unit tests + replay | Yes | Yes |
| Live eBPF attach | No | Yes |
| LSM enforce | No | Module 10 |

## Crate versions

Pin against [crates.io](https://crates.io) at build time. This tree was checked against **aya 0.14.x** and **aya-ebpf 0.2.x** (July 2026).
