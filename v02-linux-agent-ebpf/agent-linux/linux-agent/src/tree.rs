use crate::ocsf::{process_uid, AgentMeta};
use linux_agent_common::ExecEvent;
use std::collections::HashMap;

/// In-memory parent→children index keyed by durable process.uid (not pid alone).
#[derive(Default, Debug)]
pub struct ProcessTree {
    /// process.uid → parent process.uid
    parent_of: HashMap<String, String>,
    /// process.uid → display name
    names: HashMap<String, String>,
}

impl ProcessTree {
    pub fn ingest(&mut self, ev: &ExecEvent, meta: &AgentMeta) {
        let uid = process_uid(&meta.boot_id, ev.pid, ev.start_time_ns);
        let parent = process_uid(&meta.boot_id, ev.ppid, ev.parent_start_time_ns);
        self.parent_of.insert(uid.clone(), parent);
        self.names.insert(uid, ev.comm_str().to_string());
    }

    #[allow(dead_code)]
    pub fn parent_of(&self, uid: &str) -> Option<&str> {
        self.parent_of.get(uid).map(|s| s.as_str())
    }

    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let mut uids: Vec<_> = self.names.keys().cloned().collect();
        uids.sort();
        for uid in uids {
            let name = self.names.get(&uid).map(|s| s.as_str()).unwrap_or("?");
            let parent = self.parent_of.get(&uid).map(|s| s.as_str()).unwrap_or("-");
            lines.push(format!("{name} uid={uid} parent_uid={parent}"));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_agent_common::ExecEvent;

    #[test]
    fn links_child_to_parent_uid() {
        let meta = AgentMeta {
            boot_id: "b".into(),
            ..AgentMeta::default()
        };
        let mut tree = ProcessTree::default();
        let parent = ExecEvent::from_fixture(1, 0, 0, 100, 0, "bash", "/bin/bash");
        let child = ExecEvent::from_fixture(2, 1, 0, 200, 100, "curl", "/usr/bin/curl");
        tree.ingest(&parent, &meta);
        tree.ingest(&child, &meta);
        let child_uid = process_uid("b", 2, 200);
        let parent_uid = process_uid("b", 1, 100);
        assert_eq!(tree.parent_of(&child_uid), Some(parent_uid.as_str()));
    }
}
