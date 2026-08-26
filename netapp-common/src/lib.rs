#![no_std]

/// Cumulative TCP and UDP bytes attributed to a process (keyed by TGID,
/// i.e. the pid as seen in /proc), tracked separately per protocol.
/// System-wide, not scoped to any single interface.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ProcTraffic {
    pub tcp_tx_bytes: u64,
    pub tcp_rx_bytes: u64,
    pub udp_tx_bytes: u64,
    pub udp_rx_bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcTraffic {}

/// Cumulative packet/byte counters for a single monitored interface.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct IfaceCounters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IfaceCounters {}
