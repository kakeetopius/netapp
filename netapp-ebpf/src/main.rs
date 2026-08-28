#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    helpers::bpf_get_current_pid_tgid,
    macros::{classifier, kprobe, kretprobe, map, xdp},
    maps::{HashMap, PerCpuArray, PerCpuHashMap},
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

/// Counts tgids dropped because `PROC_TRAFFIC` was full (see `ensure_entry`
/// below), so userspace can at least surface *that* traffic is going
/// unaccounted rather than this failing completely silently. Not logged via
/// aya-log's `warn!` from here: that macro pulls in the AYA_LOGS ring buffer
/// map, and calling it from a function inlined into several different BPF
/// programs (as `ensure_entry` is, via `update_tcp`/`update_udp`) hits a map
/// relocation bug in this project's aya version pinning -- BPF_PROG_LOAD
/// fails on the very first probe with "fd N is not pointing to valid
/// bpf_map" even from a single, non-shared call site. A plain counter map
/// sidesteps it entirely.
#[map]
static PROC_TRAFFIC_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
    if PROC_TRAFFIC.get_ptr_mut(&tgid).is_none()
        && PROC_TRAFFIC.insert(&tgid, &ZERO_TRAFFIC, 0).is_err()
    {
        // Most likely the 10240-entry cap is full (heavy process churn
        // between userspace reap passes).
        if let Some(c) = PROC_TRAFFIC_DROPPED.get_ptr_mut(0) {
            unsafe { *c += 1 };
        }
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

/// MSG_PEEK, from `<linux/socket.h>`.
const MSG_PEEK: i32 = 2;

/// `udp_recvmsg`'s return value counts bytes copied to userspace even for a
/// MSG_PEEK read, which doesn't dequeue the datagram -- the caller typically
/// peeks it, then reads it again for real, and a naive kretprobe would count
/// that datagram's bytes twice. This map lets the kretprobe below know
/// whether the call it's returning from was a peek, keyed by pid_tgid (each
/// thread's own in-flight call) since concurrent recvmsg calls from other
/// threads/processes must not interfere with each other.
#[map]
static UDP_RECV_PEEK: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn kprobe_udp_recvmsg(ctx: ProbeContext) -> u32 {
    // int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
    if let Some(flags) = ctx.arg::<i32>(3) {
        if flags & MSG_PEEK != 0 {
            let pid_tgid = bpf_get_current_pid_tgid();
            let _ = UDP_RECV_PEEK.insert(&pid_tgid, &1u8, 0);
        }
    }
    0
}

#[kretprobe]
pub fn kretprobe_udp_recvmsg(ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let peeked = UDP_RECV_PEEK.get_ptr(&pid_tgid).is_some();
    if peeked {
        let _ = UDP_RECV_PEEK.remove(&pid_tgid);
    }

    // int udp_recvmsg(...); return value is bytes received (or -errno)
    let ret: i32 = ctx.ret();
    if ret > 0 && !peeked {
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
