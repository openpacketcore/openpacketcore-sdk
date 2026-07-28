#!/usr/bin/env bash
# Build the cgroup-skb gate plus sched-cls control/view eBPF programs and refresh the object at
# crates/opc-egress-fence/bpf/opc-egress-fence.bpf.o.
#
# Reproducibility policy:
#   - Rust toolchain: $OPC_EBPF_TOOLCHAIN (default nightly-2026-06-22)
#   - bpf-linker: $OPC_BPF_LINKER or `bpf-linker` on PATH
#   - build directory: $OPC_EBPF_TARGET_DIR (worktrees must override it)
#   - checkout, Cargo-home, toolchain, and user-home paths are remapped
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="${repo_root}/crates/opc-egress-fence-ebpf"
artifact="${OPC_EBPF_ARTIFACT:-${repo_root}/crates/opc-egress-fence/bpf/opc-egress-fence.bpf.o}"

toolchain="${OPC_EBPF_TOOLCHAIN:-nightly-2026-06-22}"
linker="${OPC_BPF_LINKER:-bpf-linker}"
target_dir="${OPC_EBPF_TARGET_DIR:-${crate_dir}/target}"
features="${OPC_EBPF_FEATURES:-}"

sysroot="$(rustc "+${toolchain}" --print sysroot)"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"

rustflags=(
  "-C" "debuginfo=2"
  "-C" "linker=${linker}"
  "-C" "link-arg=--btf"
  "--remap-path-prefix=${HOME}=/build-home"
  "--remap-path-prefix=${cargo_home}=/cargo-home"
  "--remap-path-prefix=${sysroot}=/rust-sysroot"
  "--remap-path-prefix=${repo_root}=/opc-sdk"
)

(
  cd "${crate_dir}"
  cargo_args=(build --release --locked --package opc-egress-fence-ebpf)
  if [[ -n "${features}" ]]; then
    cargo_args+=(--features "${features}")
  fi
  env CARGO_TARGET_DIR="${target_dir}" \
    RUSTFLAGS="${rustflags[*]}" \
    cargo "+${toolchain}" "${cargo_args[@]}"
)

mkdir -p "$(dirname "${artifact}")"
cp "${target_dir}/bpfel-unknown-none/release/opc-egress-fence" "${artifact}"
echo "wrote ${artifact}"
sha256sum "${artifact}"
