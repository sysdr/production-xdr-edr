mod deep;
mod filter;
mod ocsf;
mod replay;
mod tree;

#[cfg(target_os = "linux")]
mod live;

use clap::{Parser, ValueEnum};
use deep::EventClass;
use filter::NoiseFilter;
use ocsf::{to_ocsf_json, AgentMeta};
use std::path::PathBuf;
use tree::ProcessTree;

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    /// Replay recorded fixtures (Sandbox / CI / macOS).
    Replay,
    /// Attach to sched_process_exec (Linux Reader VM, needs privileges + eBPF object).
    Live,
}

#[derive(Parser, Debug)]
#[command(name = "linux-agent", about = "Issue 02/07–09 — eBPF / deep telemetry → OCSF JSON")]
struct Args {
    #[arg(long, value_enum, default_value_t = Mode::Replay)]
    mode: Mode,

    /// Event class for replay (process default; file/network/persistence = Issues 07–09)
    #[arg(long, value_enum, default_value_t = EventClass::Process)]
    class: EventClass,

    /// Fixture JSONL for --mode replay
    #[arg(long, default_value = "fixtures/exec-events.jsonl")]
    fixture: PathBuf,

    /// Print in-memory process tree after the stream (replay) or periodically (live N/A → end)
    #[arg(long, default_value_t = false)]
    print_tree: bool,

    /// Extra comma-separated basenames to drop
    #[arg(long, default_value = "")]
    deny: String,

    /// Path to compiled eBPF object (live mode). Build linux-agent-ebpf on the Reader VM.
    #[arg(long, default_value = "target/bpfel-unknown-none/release/linux-agent-ebpf")]
    ebpf_object: PathBuf,
}

fn main() {
    let args = Args::parse();
    let meta = AgentMeta::default();
    let mut filter = NoiseFilter::default();
    if !args.deny.is_empty() {
        filter = filter.with_extra_denylist(args.deny.split(',').map(|s| s.trim().to_string()));
    }
    let mut tree = ProcessTree::default();

    match args.mode {
        Mode::Replay => run_replay(&args, &meta, &filter, &mut tree),
        Mode::Live => {
            if args.class != EventClass::Process {
                eprintln!("live mode currently supports --class process only (Reader VM eBPF)");
                std::process::exit(2);
            }
            run_live(&args, &meta, &filter, &mut tree);
        }
    }

    if args.print_tree {
        for line in tree.render_lines() {
            eprintln!("tree: {line}");
        }
    }
}

fn default_fixture_for(class: EventClass) -> &'static str {
    match class {
        EventClass::Process => "fixtures/exec-events.jsonl",
        EventClass::File => "fixtures/file-events.jsonl",
        EventClass::Network => "fixtures/network-events.jsonl",
        EventClass::Persistence => "fixtures/persistence-events.jsonl",
    }
}

fn run_replay(args: &Args, meta: &AgentMeta, filter: &NoiseFilter, tree: &mut ProcessTree) {
    let fixture = if args.fixture == PathBuf::from("fixtures/exec-events.jsonl")
        && args.class != EventClass::Process
    {
        PathBuf::from(default_fixture_for(args.class))
    } else {
        args.fixture.clone()
    };
    let path = resolve_fixture(&fixture);
    if args.class != EventClass::Process {
        deep::replay_class(&path, args.class, meta).unwrap_or_else(|e| {
            eprintln!("failed to load deep fixture {}: {e}", path.display());
            std::process::exit(1);
        });
        return;
    }
    let events = replay::load_jsonl(&path).unwrap_or_else(|e| {
        eprintln!("failed to load fixture {}: {e}", path.display());
        std::process::exit(1);
    });
    for ev in events {
        if !filter.allow(&ev) {
            continue;
        }
        tree.ingest(&ev, meta);
        let v = to_ocsf_json(&ev, meta);
        println!("{}", serde_json::to_string(&v).expect("serialize"));
    }
}

fn resolve_fixture(p: &PathBuf) -> PathBuf {
    if p.exists() {
        return p.clone();
    }
    // When run from repo root or workspace root
    let candidates = [
        PathBuf::from("agent-linux").join(p),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(p),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("fixtures")
            .join(p.file_name().unwrap_or_default()),
    ];
    for c in candidates {
        if c.exists() {
            return c;
        }
    }
    p.clone()
}

fn run_live(args: &Args, meta: &AgentMeta, filter: &NoiseFilter, tree: &mut ProcessTree) {
    #[cfg(target_os = "linux")]
    {
        let mut bpf = live::load_and_attach(&args.ebpf_object).unwrap_or_else(|e| {
            eprintln!("live attach failed: {e:#}");
            std::process::exit(1);
        });
        let meta = meta.clone();
        let filter = filter.clone();
        live::poll_exec_events(&mut bpf, |ev| {
            if !filter.allow(&ev) {
                return;
            }
            tree.ingest(&ev, &meta);
            let v = to_ocsf_json(&ev, &meta);
            println!("{}", serde_json::to_string(&v).expect("serialize"));
        })
        .unwrap_or_else(|e| {
            eprintln!("poll failed: {e:#}");
            std::process::exit(1);
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, meta, filter, tree);
        eprintln!(
            "live mode requires Linux (and a built eBPF object).\n\
             Use `--mode replay` on Sandbox/CI/macOS. See docs/implementation-guides/02-linux-agent-ebpf.md"
        );
        std::process::exit(2);
    }
}
