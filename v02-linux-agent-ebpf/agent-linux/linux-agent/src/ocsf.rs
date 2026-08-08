use linux_agent_common::ExecEvent;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct AgentMeta {
    pub boot_id: String,
    pub hostname: String,
    pub agent_id: String,
    pub product_version: String,
    pub ocsf_version: String,
}

impl Default for AgentMeta {
    fn default() -> Self {
        Self {
            boot_id: "lab-boot".into(),
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into()),
            agent_id: "linux-agent-lab".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            ocsf_version: "1.8.0".into(),
        }
    }
}

pub fn type_uid_launch() -> i32 {
    1007 * 100 + 1 // process_activity Launch → 100701
}

pub fn process_uid(boot_id: &str, pid: u32, start_time_ns: u64) -> String {
    format!("{boot_id}:{pid}:{start_time_ns}")
}

/// Map a ring-buffer / fixture ExecEvent into OCSF-shaped JSON for stdout.
pub fn to_ocsf_json(ev: &ExecEvent, meta: &AgentMeta) -> Value {
    let type_uid = type_uid_launch();
    let proc_uid = process_uid(&meta.boot_id, ev.pid, ev.start_time_ns);
    let parent_uid = process_uid(&meta.boot_id, ev.ppid, ev.parent_start_time_ns);
    let name = ev.comm_str();
    let path = ev.filename_str();
    let start_ms = (ev.start_time_ns / 1_000_000) as i64;

    json!({
        "class_uid": 1007,
        "category_uid": 1,
        "activity_id": 1,
        "type_uid": type_uid,
        "severity_id": 1,
        "time": start_ms,
        "metadata": {
            "product": {
                "name": "linux-agent",
                "vendor_name": "systemdrd",
                "version": meta.product_version,
            },
            "version": meta.ocsf_version,
        },
        "device": {
            "hostname": meta.hostname,
            "os": { "type": "Linux", "type_id": 200 },
            "agent_id": meta.agent_id,
        },
        "actor": {
            "user": { "uid": ev.uid.to_string() },
            "process": {
                "pid": ev.ppid,
                "uid": parent_uid,
                "name": "",
            }
        },
        "process": {
            "uid": proc_uid,
            "pid": ev.pid,
            "name": name,
            "cmd_line": path,
            "created_time": start_ms,
            "file": { "path": path },
            "parent_process": {
                "pid": ev.ppid,
                "uid": parent_uid,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_agent_common::ExecEvent;

    #[test]
    fn type_uid_is_100701() {
        assert_eq!(type_uid_launch(), 100701);
    }

    #[test]
    fn uid_includes_boot_pid_start() {
        let u = process_uid("b", 42, 99);
        assert_eq!(u, "b:42:99");
    }

    #[test]
    fn json_carries_required_fields() {
        let ev = ExecEvent::from_fixture(
            100, 1, 1000, 1_700_000_000_000_000_000, 1_600_000_000_000_000_000,
            "curl", "/usr/bin/curl",
        );
        let v = to_ocsf_json(&ev, &AgentMeta::default());
        assert_eq!(v["type_uid"], 100701);
        assert!(v["process"]["uid"].as_str().unwrap().contains(":100:"));
        assert!(!v["process"]["parent_process"]["uid"].as_str().unwrap().is_empty());
    }
}
