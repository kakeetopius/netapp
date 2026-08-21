use clap::Parser;

/// Live per-process + per-interface traffic monitor built on eBPF.
#[derive(Parser, Debug)]
#[command(name = "netapp", version, about)]
pub struct Args {
    /// Network interface to attach the XDP/TC interface-level counters to.
    /// Per-process attribution is system-wide and always active regardless
    /// of this flag (sockets aren't tied to a single NIC).
    #[arg(short, long)]
    pub interface: String,

    /// Dashboard refresh interval, in milliseconds.
    #[arg(long, default_value_t = 1000)]
    pub interval: u64,

    /// Number of process rows to show, sorted by total traffic.
    #[arg(long, default_value_t = 15)]
    pub top: usize,
}
