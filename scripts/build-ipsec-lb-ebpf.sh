#!/usr/bin/env bash
# Build the XDP eBPF SWu IPsec LB datapath object and refresh the committed
# artifact at crates/opc-ipsec-lb/bpf/opc-ipsec-lb-xdp.bpf.o.
#
# The build is pinned to match the GTP-U datapath artifact policy:
#   - Rust toolchain: $OPC_EBPF_TOOLCHAIN (default nightly-2026-06-22, needs
#     the rust-src component for -Z build-std)
#   - bpf-linker: $OPC_BPF_LINKER or `bpf-linker` on PATH
#   - absolute paths are remapped out of debug info/BTF
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="${repo_root}/crates/opc-ipsec-lb-ebpf"
artifact="${repo_root}/crates/opc-ipsec-lb/bpf/opc-ipsec-lb-xdp.bpf.o"

toolchain="${OPC_EBPF_TOOLCHAIN:-nightly-2026-06-22}"
linker="${OPC_BPF_LINKER:-bpf-linker}"
target_dir="${crate_dir}/target"

sysroot="$(rustc "+${toolchain}" --print sysroot)"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"

rustflags=(
  "--remap-path-prefix=${repo_root}=/opc-sdk"
  "--remap-path-prefix=${sysroot}=/rust-sysroot"
  "--remap-path-prefix=${cargo_home}=/cargo-home"
  "--remap-path-prefix=${HOME}=/build-home"
)

(
  cd "${crate_dir}"
  env CARGO_TARGET_DIR="${target_dir}" \
    CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="${linker}" \
    CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS="${rustflags[*]}" \
    cargo "+${toolchain}" build --release --locked
)

mkdir -p "$(dirname "${artifact}")"
cp "${target_dir}/bpfel-unknown-none/release/opc-ipsec-lb-xdp" "${artifact}"
echo "wrote ${artifact}"
sha256sum "${artifact}"
