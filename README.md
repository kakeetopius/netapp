# netapp

Live per-process + per-interface network traffic monitor, built with eBPF (via [Aya](https://aya-rs.dev)) and Rust.

- **Per-process traffic**: kprobes on `tcp_sendmsg`/`tcp_cleanup_rbuf`/`udp_sendmsg`/`udp_recvmsg`
  attribute TX/RX bytes to the owning process (keyed by TGID), tracked separately for TCP and UDP.
  This is **system-wide** — sockets aren't tied to a single NIC, so this table is not filtered by `-i`.
- **Interface totals**: an XDP program (ingress) + TC classifier (egress) count aggregate
  packets/bytes on the one interface passed via `-i`.

The TUI shows both, clearly separated, since they answer different questions.

## One-time setup

```bash
sudo pacman -S --needed bpf-linker
```

Building the eBPF crate needs a nightly Rust toolchain whose bundled LLVM matches the system's
`bpf-linker` (which is linked against `llvm-libs` from pacman, currently 22.x). This repo pins
`nightly-2026-06-01` in `netapp/build.rs` for exactly that reason — a newer default `nightly`
bundles LLVM 23, which this system's `bpf-linker` can't read (`ERROR llvm: Invalid record`).
Installed with:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none
source "$HOME/.cargo/env"
rustup toolchain install nightly-2026-06-01 --profile minimal --component rust-src
```

`--no-modify-path` was used deliberately so this doesn't change the system's default `cargo`/`rustc`
(still the pacman stable toolchain) outside of this project. That means **you need to
`source "$HOME/.cargo/env"` in any shell where you build/run this project**, so `cargo` can find
the `rustup` binary and hand the eBPF sub-build off to the pinned nightly.

If a future `bpf-linker` update tracks LLVM 23+, `netapp/build.rs`'s `Toolchain::Custom(...)` can
just be swapped back to `Toolchain::default()` (plain `nightly`).

## Build

```bash
source "$HOME/.cargo/env"
cd /tmp/netapp
cargo build --release
```

## Run

Loading kprobes/XDP/TC needs root. `sudo` on this machine goes through fingerprint auth, which
doesn't work in non-interactive contexts (e.g. `cargo test` invoking the same runner), so
`.cargo/config.toml` sets a `pkexec` runner for `cargo run` instead. To run the built release
binary directly:

```bash
pkexec --keep-cwd env RUST_LOG=info ./target/release/netapp -i wlan0 --interval 500 --top 15
```

Press `q` or Ctrl-C to quit. On exit, if the interface didn't already have a `clsact` qdisc, one
was added for the TC egress program and is **not** auto-removed (removing it isn't done
automatically since something else might be relying on it). Clean it up manually if you don't
need it:

```bash
pkexec tc qdisc del dev wlan0 clsact
```

## Verifying it works

- Compare the interface panel against `ip -s link show wlan0` before/after a known transfer
  (`curl` a large file, `ping -c 100 ...`) — deltas should be in the same ballpark.
- Run something with an identifiable PID (`iperf3 -c <server>`, a long `curl`), cross-check via
  `pgrep`/`ss -tnp`, and confirm it shows up with nonzero traffic in the process table; confirm
  the row disappears a little after the process exits (reaping works).
- Generate TCP/UDP loopback traffic (`iperf3 -s & server_pid=$!`, then `iperf3 -c 127.0.0.1 -t 10`
  and `iperf3 -c 127.0.0.1 -u -t 10`, then `kill $server_pid`) while monitoring `wlan0` — it
  should appear in the process table but *not* move the interface panel, which demonstrates the
  system-wide-vs-interface-scoped distinction described above. (Don't use
  `ping` for this: ICMP never goes through the TCP/UDP functions netapp probes, so it won't show
  up in the process table at all.)
- While `netapp` is running: `pkexec bpftool prog list` / `pkexec bpftool link list` show its
  programs/links with `pids netapp(<pid>)` -- note their IDs. After quitting, those specific IDs
  should be gone (a bare "should show nothing left attached" isn't right on a system that already
  has other, unrelated BPF programs loaded -- e.g. systemd's -- which is normal and expected).

## Caveats

- The kprobe targets (`tcp_sendmsg`, `tcp_cleanup_rbuf`, `udp_sendmsg`, `udp_recvmsg`) are
  internal, non-exported kernel symbols verified against this machine's kernel via
  `bpftool btf dump file /sys/kernel/btf/vmlinux`. A kernel upgrade could rename or inline them,
  *or* change their argument count/order -- `netapp-ebpf/src/main.rs`'s `ctx.arg::<i32>(N)` calls
  (e.g. `udp_recvmsg`'s `flags` at index 3) assume this same, currently-verified signature and
  aren't portable across kernel versions where it differs (older kernels had an extra `noblock`
  parameter before `flags`, for instance). Re-verify both the symbol and its `FUNC_PROTO` arg
  list with the same command if probes fail to attach or start reading the wrong argument.
