#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, kprobe, kretprobe, map, xdp},
    maps::{PerCpuArray, PerCpuHashMap},
    programs::{ProbeContext, RetProbeContext, TcContext, XdpContext},
    EbpfContext,
};
use netapp_common::{IfaceCounters, ProcTraffic};

/// System-wide per-process traffic, keyed by TGID (the pid as seen in
/// /proc/<pid>). Not scoped to any single interface -- sockets aren't tied
/// to one NIC at the syscall level.
///
/// Per-CPU: a plain (non-per-CPU) HashMap's `get_ptr_mut` read-modify-write
/// isn't synchronized across CPUs, so concurrent probes updating the same
/// TGID (e.g. a multi-threaded process sending on two cores at once) can
/// race and lose an increment. Per-CPU slots make each CPU's accumulation
/// race-free; userspace sums the slots back together when reading.
///
/// Known limitation: entries are keyed by TGID alone, not TGID + process
/// start time. If the kernel reuses a TGID for a brand new process within
/// one reap interval (see `proc_resolver::is_alive` in the userspace
/// loader), the new process would inherit the old one's counters. Avoiding
/// that fully requires reading task start-time from inside the eBPF probes
/// themselves, which is a bigger change than this map type swap -- left as
/// a known edge case rather than "fixed" here, since it needs a same-tick
/// TGID recycle to trigger, which this system's PID allocator makes very
/// unlikely in practice.
#[map]
static PROC_TRAFFIC: PerCpuHashMap<u32, ProcTraffic> = PerCpuHashMap::with_max_entries(10240, 0);

/// Aggregate counters for the single interface the user attached us to.
/// Per-CPU to avoid contention on the fast path; summed in userspace.
#[map]
static IFACE_STATS: PerCpuArray<IfaceCounters> = PerCpuArray::with_max_entries(1, 0);

// A compile-time-constant zero value, not a runtime-constructed struct
// literal: rustc const-evaluates and promotes this into a `.rodata` entry,
// so inserting it needs no runtime initialization of the 32-byte struct.
// Building a *partial* literal at runtime instead (e.g. `ProcTraffic { tcp_tx_bytes:
// tx, ..everything else: 0 }`) gets merged by LLVM into a `memset` call over
// the zeroed fields, which the BPF backend can't lower ("call to built-in
// function 'memset' is not supported"). Always going through this zero
// constant on first-insert, then mutating fields individually through the
// pointer (same as the already-present case), avoids that entirely.
const ZERO_TRAFFIC: ProcTraffic = ProcTraffic {
    tcp_tx_bytes: 0,
    tcp_rx_bytes: 0,
    udp_tx_bytes: 0,
    udp_rx_bytes: 0,
};

fn ensure_entry(tgid: u32) {
    if PROC_TRAFFIC.get_ptr_mut(&tgid).is_none() {
        let _ = PROC_TRAFFIC.insert(&tgid, &ZERO_TRAFFIC, 0);
    }
}

fn update_tcp(tgid: u32, tx: u64, rx: u64) {
    ensure_entry(tgid);
    unsafe {
        if let Some(p) = PROC_TRAFFIC.get_ptr_mut(&tgid) {
            (*p).tcp_tx_bytes += tx;
            (*p).tcp_rx_bytes += rx;
        }
    }
}

fn update_udp(tgid: u32, tx: u64, rx: u64) {
    ensure_entry(tgid);
    unsafe {
        if let Some(p) = PROC_TRAFFIC.get_ptr_mut(&tgid) {
            (*p).udp_tx_bytes += tx;
            (*p).udp_rx_bytes += rx;
        }
    }
}

// --- TCP ---

#[kretprobe]
pub fn kretprobe_tcp_sendmsg(ctx: RetProbeContext) -> u32 {
    // int tcp_sendmsg(...); return value is bytes actually sent (or -errno),
    // not the requested size -- a failed/short send shouldn't count as TX.
    let ret: i32 = ctx.ret();
    if ret > 0 {
        update_tcp(ctx.tgid(), ret as u64, 0);
    }
    0
}

#[kprobe]
pub fn kprobe_tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    // void tcp_cleanup_rbuf(struct sock *sk, int copied)
    if let Some(copied) = ctx.arg::<i32>(1) {
        if copied > 0 {
            update_tcp(ctx.tgid(), 0, copied as u64);
        }
    }
    0
}

// --- UDP ---

#[kretprobe]
pub fn kretprobe_udp_sendmsg(ctx: RetProbeContext) -> u32 {
    // int udp_sendmsg(...); return value is bytes actually sent (or -errno).
    let ret: i32 = ctx.ret();
    if ret > 0 {
        update_udp(ctx.tgid(), ret as u64, 0);
    }
    0
}

#[kretprobe]
pub fn kretprobe_udp_recvmsg(ctx: RetProbeContext) -> u32 {
    // int udp_recvmsg(...); return value is bytes received (or -errno)
    let ret: i32 = ctx.ret();
    if ret > 0 {
        update_udp(ctx.tgid(), 0, ret as u64);
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
