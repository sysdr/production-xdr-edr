use linux_agent_common::ExecEvent;
use std::collections::HashSet;

/// Drop high-volume or self-generated execs before they become "detections."
#[derive(Debug, Clone)]
pub struct NoiseFilter {
    deny_basenames: HashSet<String>,
    self_pids: HashSet<u32>,
}

impl Default for NoiseFilter {
    fn default() -> Self {
        let mut deny_basenames = HashSet::new();
        for name in ["linux-agent", "sleep", "true", "false"] {
            deny_basenames.insert(name.into());
        }
        Self {
            deny_basenames,
            self_pids: HashSet::from([std::process::id()]),
        }
    }
}

impl NoiseFilter {
    pub fn with_extra_denylist(mut self, names: impl IntoIterator<Item = String>) -> Self {
        self.deny_basenames.extend(names);
        self
    }

    pub fn allow(&self, ev: &ExecEvent) -> bool {
        if self.self_pids.contains(&ev.pid) {
            return false;
        }
        let base = basename(ev.filename_str());
        let comm = ev.comm_str();
        if self.deny_basenames.contains(base) || self.deny_basenames.contains(comm) {
            return false;
        }
        true
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_agent_common::ExecEvent;

    #[test]
    fn drops_denylisted_basename() {
        let f = NoiseFilter::default();
        let ev = ExecEvent::from_fixture(10, 1, 0, 1, 0, "sleep", "/usr/bin/sleep");
        assert!(!f.allow(&ev));
    }

    #[test]
    fn keeps_interesting_binary() {
        let f = NoiseFilter::default();
        let ev = ExecEvent::from_fixture(10, 1, 0, 1, 0, "curl", "/usr/bin/curl");
        assert!(f.allow(&ev));
    }
}
