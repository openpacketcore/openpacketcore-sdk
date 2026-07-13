#!/usr/bin/env bash
# Build the tc eBPF XFRM fixed-DSCP companion and refresh the committed object
# at crates/opc-ipsec-xfrm/bpf/opc-ipsec-xfrm-dscp.bpf.o.
#
# Reproducibility matches the other SDK datapath artifacts:
#   - Rust toolchain: $OPC_EBPF_TOOLCHAIN (default nightly-2026-06-22)
#   - bpf-linker: $OPC_BPF_LINKER or `bpf-linker` on PATH
#   - build directory: $OPC_EBPF_TARGET_DIR (worktrees must override it)
#   - absolute paths remapped out of debug info/BTF
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="${repo_root}/crates/opc-ipsec-xfrm-ebpf"
artifact="${repo_root}/crates/opc-ipsec-xfrm/bpf/opc-ipsec-xfrm-dscp.bpf.o"

toolchain="${OPC_EBPF_TOOLCHAIN:-nightly-2026-06-22}"
linker="${OPC_BPF_LINKER:-bpf-linker}"
target_dir="${OPC_EBPF_TARGET_DIR:-${crate_dir}/target}"

sysroot="$(rustc "+${toolchain}" --print sysroot)"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"

rustflags=(
  "-C" "debuginfo=2"
  "-C" "linker=${linker}"
  "-C" "link-arg=--btf"
  "--remap-path-prefix=${repo_root}=/opc-sdk"
  "--remap-path-prefix=${sysroot}=/rust-sysroot"
  "--remap-path-prefix=${cargo_home}=/cargo-home"
  "--remap-path-prefix=${HOME}=/build-home"
)

(
  cd "${crate_dir}"
  env CARGO_TARGET_DIR="${target_dir}" \
    RUSTFLAGS="${rustflags[*]}" \
    cargo "+${toolchain}" build --release --locked
)

mkdir -p "$(dirname "${artifact}")"
cp "${target_dir}/bpfel-unknown-none/release/opc-ipsec-xfrm-dscp" "${artifact}"
echo "wrote ${artifact}"
sha256sum "${artifact}"
