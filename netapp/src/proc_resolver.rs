use std::fs;

/// Full process name for `pid`, read fresh from /proc each call (the eBPF
/// side only has the truncated 16-byte `bpf_get_current_comm`, so we don't
/// even bother storing a name in the map -- this is always accurate).
pub fn process_name(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(raw.trim_end().to_string())
}

/// Whether `pid` still exists, used to reap dead entries from the
/// fixed-capacity eBPF hash map.
pub fn is_alive(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}
