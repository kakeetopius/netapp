# netapp

Live per-process + per-interface network traffic monitor, built with eBPF (via [Aya](https://aya-rs.dev)) and Rust.

- **Per-process traffic**: kprobes on `tcp_sendmsg`/`tcp_cleanup_rbuf`/`udp_sendmsg`/`udp_recvmsg`
  attribute TX/RX bytes to the owning process (keyed by TGID). This is **system-wide** — sockets
  aren't tied to a single NIC, so this table is not filtered by `-i`.
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

Loading kprobes/XDP/TC needs root, and there's no passwordless sudo on this machine, so
`.cargo/config.toml` sets a `sudo -E` runner for `cargo run`. To run the built release binary
directly:

```bash
sudo -E ./target/release/netapp -i wlan0 --interval 500 --top 15
```

Press `q` or Ctrl-C to quit. On exit, if the interface didn't already have a `clsact` qdisc, one
was added for the TC egress program and is **not** auto-removed (removing it isn't done
automatically since something else might be relying on it). Clean it up manually if you don't
need it:

```bash
sudo tc qdisc del dev wlan0 clsact
```

## Verifying it works

- Compare the interface panel against `ip -s link show wlan0` before/after a known transfer
  (`curl` a large file, `ping -c 100 ...`) — deltas should be in the same ballpark.
- Run something with an identifiable PID (`iperf3 -c <server>`, a long `curl`), cross-check via
  `pgrep`/`ss -tnp`, and confirm it shows up with nonzero traffic in the process table; confirm
  the row disappears a little after the process exits (reaping works).
- Generate loopback traffic (`ping -c 5 127.0.0.1`) while monitoring `wlan0` — it should appear
  in the process table but *not* move the interface panel, which demonstrates the
  system-wide-vs-interface-scoped distinction described above.
- After quitting: `sudo bpftool prog list` / `sudo bpftool link list` should show nothing left
  attached.

## Caveats

- The kprobe targets (`tcp_sendmsg`, `tcp_cleanup_rbuf`, `udp_sendmsg`, `udp_recvmsg`) are
  internal, non-exported kernel symbols verified against this machine's kernel
  (`7.1.8-1-cachyos`) via `bpftool btf dump file /sys/kernel/btf/vmlinux`. A kernel upgrade could
  rename or inline them; re-verify with the same command if probes fail to attach.
