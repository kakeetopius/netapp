#[derive(Debug, Clone, Default)]
pub struct IfaceSnapshot {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
}

#[derive(Debug, Clone, Default)]
pub struct ProcRow {
    pub pid: u32,
    pub name: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_rate: f64,
    pub rx_rate: f64,
}

#[derive(Debug, Clone, Default)]
pub struct AppState {
    pub iface: IfaceSnapshot,
    pub procs: Vec<ProcRow>,
    pub top_n: usize,
}
