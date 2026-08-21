fn main() -> anyhow::Result<()> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let root_dir = format!("{manifest_dir}/../netapp-ebpf");

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "netapp-ebpf",
            root_dir: &root_dir,
            no_default_features: false,
            features: &[],
        }],
        // Pinned to a specific nightly whose bundled LLVM (22.1.x) matches
        // the system's `bpf-linker`, which is linked against llvm-libs 22.
        // A newer default `nightly` bundles LLVM 23, which bpf-linker can't
        // read ("ERROR llvm: Invalid record") until the distro's bpf-linker
        // package catches up.
        aya_build::Toolchain::Custom("nightly-2026-06-01"),
    )
}
