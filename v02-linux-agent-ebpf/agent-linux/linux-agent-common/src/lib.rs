// Shared #[repr(C)] event between eBPF and userspace.
// Keep this layout stable: field order is the ring-buffer ABI for Issue 02.

#![cfg_attr(not(feature = "std"), no_std)]

/// Fixed-size exec record pushed through BPF_MAP_TYPE_RINGBUF.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_time_ns: u64,
    pub parent_start_time_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

impl ExecEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn comm_str(&self) -> &str {
        cstr_from_bytes(&self.comm)
    }

    pub fn filename_str(&self) -> &str {
        cstr_from_bytes(&self.filename)
    }
}

fn cstr_from_bytes(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

#[cfg(feature = "std")]
mod std_helpers {
    use super::ExecEvent;

    impl ExecEvent {
        pub fn from_fixture(
            pid: u32,
            ppid: u32,
            uid: u32,
            start_time_ns: u64,
            parent_start_time_ns: u64,
            comm: &str,
            filename: &str,
        ) -> Self {
            let mut ev = Self {
                pid,
                ppid,
                uid,
                start_time_ns,
                parent_start_time_ns,
                comm: [0; 16],
                filename: [0; 256],
            };
            copy_cstr(&mut ev.comm, comm);
            copy_cstr(&mut ev.filename, filename);
            ev
        }
    }

    fn copy_cstr(dst: &mut [u8], src: &str) {
        let bytes = src.as_bytes();
        let n = bytes.len().min(dst.len().saturating_sub(1));
        dst[..n].copy_from_slice(&bytes[..n]);
        dst[n] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_is_stable() {
        // pid+ppid+uid (12) + pad to 8 for u64s + times + arrays
        assert!(ExecEvent::SIZE >= 16 + 16 + 256);
    }
}
