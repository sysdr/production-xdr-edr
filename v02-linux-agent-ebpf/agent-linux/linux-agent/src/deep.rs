//! Issues 07–09 — replay OCSF file / network / persistence fixtures (CI path).
//! Live fanotify / ETW file / ESF / Network Extension remains Reader VM.

use crate::ocsf::AgentMeta;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EventClass {
    Process,
    File,
    Network,
    Persistence,
}

#[derive(Debug, Deserialize)]
struct FileFixture {
    process_uid: String,
    process_pid: u32,
    process_name: String,
    file_path: String,
    #[serde(default = "default_activity")]
    activity: String,
    #[serde(default = "default_time")]
    time: i64,
}

#[derive(Debug, Deserialize)]
struct NetworkFixture {
    process_uid: String,
    process_pid: u32,
    process_name: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    #[serde(default = "default_time")]
    time: i64,
}

#[derive(Debug, Deserialize)]
struct PersistenceFixture {
    process_uid: String,
    process_pid: u32,
    process_name: String,
    mechanism: String,
    path_or_key: String,
    #[serde(default = "default_time")]
    time: i64,
}

fn default_activity() -> String {
    "Create".into()
}
fn default_time() -> i64 {
    1_700_000_001_000
}

fn encode_file(row: &FileFixture, meta: &AgentMeta) -> Value {
    let name = row
        .file_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&row.file_path);
    json!({
        "class_uid": 1001,
        "category_uid": 1,
        "activity_id": 1,
        "type_uid": 100101,
        "severity_id": 1,
        "time": row.time,
        "metadata": {
            "product": {
                "name": "linux-agent",
                "vendor_name": "systemdrd",
                "version": meta.product_version
            },
            "version": meta.ocsf_version
        },
        "device": {
            "hostname": meta.hostname,
            "os": { "type": "Linux", "type_id": 200 },
            "agent_id": meta.agent_id
        },
        "file": { "path": row.file_path, "name": name },
        "process": {
            "uid": row.process_uid,
            "pid": row.process_pid,
            "name": row.process_name
        },
        "unmapped": { "activity_name": row.activity, "hook": "fanotify_fixture" }
    })
}

fn encode_network(row: &NetworkFixture, meta: &AgentMeta) -> Value {
    json!({
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 1,
        "type_uid": 400101,
        "severity_id": 1,
        "time": row.time,
        "metadata": {
            "product": {
                "name": "linux-agent",
                "vendor_name": "systemdrd",
                "version": meta.product_version
            },
            "version": meta.ocsf_version
        },
        "device": {
            "hostname": meta.hostname,
            "os": { "type": "Linux", "type_id": 200 },
            "agent_id": meta.agent_id
        },
        "src_endpoint": { "ip": row.src_ip, "port": row.src_port },
        "dst_endpoint": { "ip": row.dst_ip, "port": row.dst_port },
        "connection_info": { "protocol_name": "TCP" },
        "process": {
            "uid": row.process_uid,
            "pid": row.process_pid,
            "name": row.process_name
        },
        "unmapped": { "hook": "ebpf_tcp_connect_fixture" }
    })
}

fn encode_persistence(row: &PersistenceFixture, meta: &AgentMeta) -> Value {
    json!({
        "class_uid": 1007,
        "category_uid": 1,
        "activity_id": 1,
        "type_uid": 100701,
        "severity_id": 1,
        "time": row.time,
        "metadata": {
            "product": {
                "name": "linux-agent",
                "vendor_name": "systemdrd",
                "version": meta.product_version
            },
            "version": meta.ocsf_version
        },
        "device": {
            "hostname": meta.hostname,
            "os": { "type": "Linux", "type_id": 200 },
            "agent_id": meta.agent_id
        },
        "process": {
            "uid": row.process_uid,
            "pid": row.process_pid,
            "name": row.process_name
        },
        "unmapped": {
            "event_kind": "persistence",
            "mechanism": row.mechanism,
            "path_or_key": row.path_or_key,
            "hook": "cron_systemd_ldpreload_fixture"
        }
    })
}

pub fn replay_class(path: &Path, class: EventClass, meta: &AgentMeta) -> std::io::Result<()> {
    let file = File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let v = match class {
            EventClass::File => {
                let row: FileFixture = serde_json::from_str(&line)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                encode_file(&row, meta)
            }
            EventClass::Network => {
                let row: NetworkFixture = serde_json::from_str(&line)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                encode_network(&row, meta)
            }
            EventClass::Persistence => {
                let row: PersistenceFixture = serde_json::from_str(&line)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                encode_persistence(&row, meta)
            }
            EventClass::Process => unreachable!("process uses replay module"),
        };
        println!("{}", serde_json::to_string(&v).expect("serialize"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_uid() {
        let row = FileFixture {
            process_uid: "lab-boot:100:1".into(),
            process_pid: 100,
            process_name: "writer".into(),
            file_path: "/tmp/x.bin".into(),
            activity: "Create".into(),
            time: 1,
        };
        let v = encode_file(&row, &AgentMeta::default());
        assert_eq!(v["type_uid"], 100101);
        assert_eq!(v["process"]["uid"], "lab-boot:100:1");
    }
}
