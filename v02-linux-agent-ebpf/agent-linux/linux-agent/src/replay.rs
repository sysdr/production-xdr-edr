use linux_agent_common::ExecEvent;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Deserialize)]
struct FixtureLine {
    pid: u32,
    ppid: u32,
    uid: u32,
    start_time_ns: u64,
    parent_start_time_ns: u64,
    comm: String,
    filename: String,
}

pub fn load_jsonl(path: &Path) -> std::io::Result<Vec<ExecEvent>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let row: FixtureLine = serde_json::from_str(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        out.push(ExecEvent::from_fixture(
            row.pid,
            row.ppid,
            row.uid,
            row.start_time_ns,
            row.parent_start_time_ns,
            &row.comm,
            &row.filename,
        ));
    }
    Ok(out)
}
