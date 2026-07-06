#!/usr/bin/env bash
# Build the tc eBPF GTP-U datapath object and refresh the committed artifact
# at crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o.
#
# The build is pinned so the artifact is reproducible byte-for-byte:
#   - Rust toolchain: $OPC_EBPF_TOOLCHAIN (default nightly-2026-06-22, needs
#     the rust-src component for -Z build-std)
#   - bpf-linker: $OPC_BPF_LINKER or `bpf-linker` on PATH; CI pins 0.10.3
#   - all absolute paths are remapped out of the debug info/BTF
#
# CI rebuilds the object with the same pins and fails on drift
# (.github/workflows/gtpu-privileged.yml).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="${repo_root}/crates/opc-gtpu-dataplane-ebpf"
artifact="${repo_root}/crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o"

toolchain="${OPC_EBPF_TOOLCHAIN:-nightly-2026-06-22}"
linker="${OPC_BPF_LINKER:-bpf-linker}"
target_dir="${crate_dir}/target"

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

cp "${target_dir}/bpfel-unknown-none/release/opc-gtpu-datapath" "${artifact}"
echo "wrote ${artifact}"
sha256sum "${artifact}"
