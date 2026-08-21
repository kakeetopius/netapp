#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, kprobe, kretprobe, map, xdp},
    maps::{HashMap, PerCpuArray},
    programs::{ProbeContext, RetProbeContext, TcContext, XdpContext},
    EbpfContext,
};
use netapp_common::{IfaceCounters, ProcTraffic};

/// System-wide per-process traffic, keyed by TGID (the pid as seen in
/// /proc/<pid>). Not scoped to any single interface -- sockets aren't tied
/// to one NIC at the syscall level.
#[map]
static PROC_TRAFFIC: HashMap<u32, ProcTraffic> = HashMap::with_max_entries(10240, 0);

/// Aggregate counters for the single interface the user attached us to.
/// Per-CPU to avoid contention on the fast path; summed in userspace.
#[map]
static IFACE_STATS: PerCpuArray<IfaceCounters> = PerCpuArray::with_max_entries(1, 0);

fn update_proc(tgid: u32, tx: u64, rx: u64) {
    unsafe {
        if let Some(p) = PROC_TRAFFIC.get_ptr_mut(&tgid) {
            (*p).tx_bytes += tx;
            (*p).rx_bytes += rx;
            return;
        }
    }
    let _ = PROC_TRAFFIC.insert(
        &tgid,
        &ProcTraffic {
            tx_bytes: tx,
            rx_bytes: rx,
        },
        0,
    );
}

// --- TCP ---

#[kprobe]
pub fn kprobe_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    // int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    if let Some(size) = ctx.arg::<usize>(2) {
        update_proc(ctx.tgid(), size as u64, 0);
    }
    0
}

#[kprobe]
pub fn kprobe_tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    // void tcp_cleanup_rbuf(struct sock *sk, int copied)
    if let Some(copied) = ctx.arg::<i32>(1) {
        if copied > 0 {
            update_proc(ctx.tgid(), 0, copied as u64);
        }
    }
    0
}

// --- UDP ---

#[kprobe]
pub fn kprobe_udp_sendmsg(ctx: ProbeContext) -> u32 {
    // int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    if let Some(len) = ctx.arg::<usize>(2) {
        update_proc(ctx.tgid(), len as u64, 0);
    }
    0
}

#[kretprobe]
pub fn kretprobe_udp_recvmsg(ctx: RetProbeContext) -> u32 {
    // int udp_recvmsg(...); return value is bytes received (or -errno)
    let ret: i32 = ctx.ret();
    if ret > 0 {
        update_proc(ctx.tgid(), 0, ret as u64);
    }
    0
}

// --- Interface counters ---

#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    if let Some(c) = IFACE_STATS.get_ptr_mut(0) {
        let len = (ctx.data_end() - ctx.data()) as u64;
        unsafe {
            (*c).rx_bytes += len;
            (*c).rx_packets += 1;
        }
    }
    xdp_action::XDP_PASS
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    if let Some(c) = IFACE_STATS.get_ptr_mut(0) {
        let len = ctx.len() as u64;
        unsafe {
            (*c).tx_bytes += len;
            (*c).tx_packets += 1;
        }
    }
    TC_ACT_PIPE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
