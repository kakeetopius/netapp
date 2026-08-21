mod cli;
mod proc_resolver;
mod tui;

use std::collections::HashMap as StdHashMap;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use aya::maps::{PerCpuArray, PerCpuHashMap};
use aya::programs::{tc, KProbe, SchedClassifier, TcAttachType, Xdp, XdpMode};
use clap::Parser;
use netapp_common::{IfaceCounters, ProcTraffic};
use tui::app::{AppState, IfaceSnapshot, ProcRow};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = cli::Args::parse();

    bump_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netapp"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        log::warn!("failed to initialize eBPF logger: {e}");
    }

    attach_kprobe(&mut ebpf, "kretprobe_tcp_sendmsg", "tcp_sendmsg")?;
    attach_kprobe(&mut ebpf, "kprobe_tcp_cleanup_rbuf", "tcp_cleanup_rbuf")?;
    attach_kprobe(&mut ebpf, "kretprobe_udp_sendmsg", "udp_sendmsg")?;
    attach_kprobe(&mut ebpf, "kretprobe_udp_recvmsg", "udp_recvmsg")?;

    let xdp: &mut Xdp = ebpf.program_mut("xdp_ingress").unwrap().try_into()?;
    xdp.load()?;
    xdp.attach(&args.interface, XdpMode::default())
        .context("failed to attach XDP program - is the interface name correct?")?;

    let mut created_clsact = false;
    match tc::qdisc_add_clsact(&args.interface) {
        Ok(()) => created_clsact = true,
        Err(e) => log::debug!("clsact qdisc not added (may already exist): {e}"),
    }
    let tc_prog: &mut SchedClassifier = ebpf.program_mut("tc_egress").unwrap().try_into()?;
    tc_prog.load()?;
    tc_prog
        .attach(&args.interface, TcAttachType::Egress)
        .context("failed to attach TC egress program")?;

    let result = run_dashboard(&mut ebpf, &args).await;

    if created_clsact {
        eprintln!(
            "note: left the clsact qdisc on {} in place; remove it with `sudo tc qdisc del dev {} clsact` if you don't need it",
            args.interface, args.interface
        );
    }

    result
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::warn!("failed to bump RLIMIT_MEMLOCK, continuing anyway");
    }
}

fn attach_kprobe(ebpf: &mut aya::Ebpf, prog_name: &str, kernel_fn: &str) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("eBPF program {prog_name} not found"))?
        .try_into()?;
    program.load()?;
    program
        .attach(kernel_fn, 0)
        .with_context(|| format!("failed to attach {prog_name} to kernel fn {kernel_fn}"))?;
    Ok(())
}

async fn run_dashboard(ebpf: &mut aya::Ebpf, args: &cli::Args) -> anyhow::Result<()> {
    let mut terminal = tui::init()?;

    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<crossterm::event::KeyEvent>();
    std::thread::spawn(move || loop {
        match crossterm::event::poll(Duration::from_millis(200)) {
            Ok(true) => {
                if let Ok(crossterm::event::Event::Key(key)) = crossterm::event::read() {
                    if key_tx.send(key).is_err() {
                        break;
                    }
                }
            }
            Ok(false) => {}
            Err(_) => break,
        }
    });

    let mut prev_iface = IfaceCounters::default();
    // Keyed by TGID only, not TGID + process start time (see the
    // PROC_TRAFFIC doc comment in netapp-ebpf/src/main.rs) -- a TGID
    // recycled within one reap interval could inherit stale counters.
    let mut prev_procs: StdHashMap<u32, ProcTraffic> = StdHashMap::new();
    let mut last_tick = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(args.interval));

    let res: anyhow::Result<()> = loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = Instant::now();
                let dt = now.duration_since(last_tick).as_secs_f64().max(0.001);
                last_tick = now;

                match build_state(ebpf, args, &mut prev_iface, &mut prev_procs, dt) {
                    Ok(state) => {
                        if let Err(e) = terminal.draw(|f| tui::ui::draw(f, &state)) {
                            break Err(e.into());
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
            Some(key) = key_rx.recv() => {
                let is_quit = key.code == crossterm::event::KeyCode::Char('q')
                    || (key.code == crossterm::event::KeyCode::Char('c')
                        && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL));
                if is_quit {
                    break Ok(());
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break Ok(());
            }
        }
    };

    tui::restore()?;
    res
}

fn build_state(
    ebpf: &mut aya::Ebpf,
    args: &cli::Args,
    prev_iface: &mut IfaceCounters,
    prev_procs: &mut StdHashMap<u32, ProcTraffic>,
    dt: f64,
) -> anyhow::Result<AppState> {
    let iface_map: PerCpuArray<_, IfaceCounters> = PerCpuArray::try_from(
        ebpf.map("IFACE_STATS").context("IFACE_STATS map missing")?,
    )?;
    let per_cpu_values = iface_map.get(&0, 0)?;
    let mut cur_iface = IfaceCounters::default();
    for v in per_cpu_values.iter() {
        cur_iface.rx_bytes += v.rx_bytes;
        cur_iface.rx_packets += v.rx_packets;
        cur_iface.tx_bytes += v.tx_bytes;
        cur_iface.tx_packets += v.tx_packets;
    }
    let rx_rate = cur_iface.rx_bytes.saturating_sub(prev_iface.rx_bytes) as f64 / dt;
    let tx_rate = cur_iface.tx_bytes.saturating_sub(prev_iface.tx_bytes) as f64 / dt;
    let iface_snapshot = IfaceSnapshot {
        name: args.interface.clone(),
        rx_bytes: cur_iface.rx_bytes,
        rx_packets: cur_iface.rx_packets,
        tx_bytes: cur_iface.tx_bytes,
        tx_packets: cur_iface.tx_packets,
        rx_rate,
        tx_rate,
    };
    *prev_iface = cur_iface;

    let mut procs = Vec::new();
    let mut seen: Vec<u32> = Vec::new();
    {
        let proc_map: PerCpuHashMap<_, u32, ProcTraffic> = PerCpuHashMap::try_from(
            ebpf.map("PROC_TRAFFIC").context("PROC_TRAFFIC map missing")?,
        )?;
        for entry in proc_map.iter() {
            let (pid, per_cpu) = entry?;
            seen.push(pid);
            if !proc_resolver::is_alive(pid) {
                continue;
            }
            let mut traffic = ProcTraffic::default();
            for v in per_cpu.iter() {
                traffic.tcp_tx_bytes += v.tcp_tx_bytes;
                traffic.tcp_rx_bytes += v.tcp_rx_bytes;
                traffic.udp_tx_bytes += v.udp_tx_bytes;
                traffic.udp_rx_bytes += v.udp_rx_bytes;
            }
            let prev = prev_procs.get(&pid).copied().unwrap_or_default();
            let tcp_tx_rate = traffic.tcp_tx_bytes.saturating_sub(prev.tcp_tx_bytes) as f64 / dt;
            let tcp_rx_rate = traffic.tcp_rx_bytes.saturating_sub(prev.tcp_rx_bytes) as f64 / dt;
            let udp_tx_rate = traffic.udp_tx_bytes.saturating_sub(prev.udp_tx_bytes) as f64 / dt;
            let udp_rx_rate = traffic.udp_rx_bytes.saturating_sub(prev.udp_rx_bytes) as f64 / dt;
            let name = proc_resolver::process_name(pid).unwrap_or_else(|| "?".to_string());
            let total_bytes = traffic.tcp_tx_bytes
                + traffic.tcp_rx_bytes
                + traffic.udp_tx_bytes
                + traffic.udp_rx_bytes;
            procs.push(ProcRow {
                pid,
                name,
                tcp_tx_rate,
                tcp_rx_rate,
                udp_tx_rate,
                udp_rx_rate,
                total_bytes,
            });
            prev_procs.insert(pid, traffic);
        }
    }

    // Reap dead pids so the fixed-capacity eBPF map doesn't fill up.
    let dead: Vec<u32> = seen
        .into_iter()
        .filter(|pid| !proc_resolver::is_alive(*pid))
        .collect();
    if !dead.is_empty() {
        let mut proc_map_mut: PerCpuHashMap<_, u32, ProcTraffic> = PerCpuHashMap::try_from(
            ebpf.map_mut("PROC_TRAFFIC")
                .context("PROC_TRAFFIC map missing")?,
        )?;
        for pid in dead {
            let _ = proc_map_mut.remove(&pid);
            prev_procs.remove(&pid);
        }
    }

    procs.sort_by_key(|p| std::cmp::Reverse(p.total_bytes));
    procs.truncate(args.top);

    Ok(AppState {
        iface: iface_snapshot,
        procs,
        top_n: args.top,
    })
}
