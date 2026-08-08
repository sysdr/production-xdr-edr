# QA checklist — Issue 02 (`v02-linux-agent-ebpf`)

- [x] Started from real Issue 01 tree (extended `agent-linux/`, did not recreate proto/scaffold from memory)
- [x] Read `docs/ocsf-mapping.md` + `proto/` before extending (no proto field renumbers; JSON mirrors mapping)
- [x] `protoc` N/A (proto unchanged)
- [x] Article code excerpt exists verbatim in `agent-linux/linux-agent/src/ocsf.rs` (`type_uid_launch`, `process_uid`)
- [x] Article: professional tone; no mid-thought/mentor voice; no banned phrases; no explicit What/Why/How headings; completion criteria; short blocks
- [x] Diagrams: white bg, multi-color (orange/teal/indigo/green), shadows, rounded rects + circles; concept + tree + system-context under `docs/diagrams/v02-linux-agent-ebpf/`
- [x] Versions: aya/aya-ebpf cited with crates.io check date; OCSF `os.type_id` 200 verified against schema enum
- [x] Sandbox / CI / Reader VM matrix in guide + module README
- [x] Deliverable: `linux-agent` streams OCSF-shaped process-creation events (replay proven; live gated)
- [x] OCSF mapping doc updated with Issue 02 agent population note (no new proto fields)
- [x] Safety: LSM stub log-only / allow; no free-form RCE or exploit PoCs
