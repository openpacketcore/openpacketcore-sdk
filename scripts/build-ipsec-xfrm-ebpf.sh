#!/usr/bin/env bash
# Build the XFRM eBPF companions and refresh both committed objects under
# crates/opc-ipsec-xfrm/bpf/.
#
# Reproducibility matches the other SDK datapath artifacts:
#   - Rust toolchain: $OPC_EBPF_TOOLCHAIN (default nightly-2026-06-22)
#   - bpf-linker: $OPC_BPF_LINKER or `bpf-linker` on PATH
#   - build directory: $OPC_EBPF_TARGET_DIR (worktrees must override it)
#   - clang/LLVM major: 18, overridable with $OPC_CLANG and
#     $OPC_LLVM_OBJCOPY for an equivalently pinned toolchain
#   - absolute paths remapped out of debug info/BTF
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="${repo_root}/crates/opc-ipsec-xfrm-ebpf"
dscp_artifact="${repo_root}/crates/opc-ipsec-xfrm/bpf/opc-ipsec-xfrm-dscp.bpf.o"
observation_artifact="${repo_root}/crates/opc-ipsec-xfrm/bpf/opc-ipsec-xfrm-observation.bpf.o"
observation_source="${crate_dir}/src/observation.bpf.c"

toolchain="${OPC_EBPF_TOOLCHAIN:-nightly-2026-06-22}"
linker="${OPC_BPF_LINKER:-bpf-linker}"
clang="${OPC_CLANG:-clang-18}"
llvm_objcopy="${OPC_LLVM_OBJCOPY:-llvm-objcopy-18}"
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

observation_build="${target_dir}/bpfel-unknown-none/release/opc-ipsec-xfrm-observation"
mkdir -p "$(dirname "${observation_build}")"
"${clang}" \
  -target bpfel \
  -O2 \
  -g \
  -Wall \
  -Wextra \
  -Werror \
  "-ffile-prefix-map=${repo_root}=/opc-sdk" \
  -fdebug-compilation-dir=/opc-sdk \
  -c "${observation_source}" \
  -o "${observation_build}"

if readelf -sW "${observation_build}" |
  awk '$7 == "UND" && $8 != "" { found = 1 } END { exit !found }'; then
  echo "observation object contains unresolved symbols" >&2
  readelf -sW "${observation_build}" |
    awk '$7 == "UND" && $8 != "" { print }' >&2
  exit 1
fi

# A .BTF.ext section alone is insufficient: the former Rust probe emitted one
# with a zero-length CO-RE subsection. Inspect the actual subsection length.
btf_ext="${target_dir}/opc-ipsec-xfrm-observation.BTF.ext"
"${llvm_objcopy}" --dump-section ".BTF.ext=${btf_ext}" "${observation_build}"
core_relocation_bytes="$(od -An -tu4 -j28 -N4 "${btf_ext}" | tr -d '[:space:]')"
if [[ -z "${core_relocation_bytes}" || "${core_relocation_bytes}" == "0" ]]; then
  echo "observation object has no CO-RE relocation records" >&2
  exit 1
fi

mkdir -p "$(dirname "${dscp_artifact}")"
cp "${target_dir}/bpfel-unknown-none/release/opc-ipsec-xfrm-dscp" "${dscp_artifact}"
cp "${observation_build}" "${observation_artifact}"
echo "wrote ${dscp_artifact}"
sha256sum "${dscp_artifact}"
echo "wrote ${observation_artifact} (${core_relocation_bytes} CO-RE bytes)"
sha256sum "${observation_artifact}"
