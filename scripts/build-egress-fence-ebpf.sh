#!/usr/bin/env bash
# Build the root-cgroup gate plus unattached control/view programs from two
# distinct absolute source paths, validate their stable functional inventory,
# and only then refresh the checked-in object.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
production_artifact="${repo_root}/crates/opc-egress-fence/bpf/opc-egress-fence.bpf.o"
artifact="${OPC_EBPF_ARTIFACT:-${production_artifact}}"
expected_artifact="${OPC_EBPF_EXPECTED_ARTIFACT:-}"
toolchain="${OPC_EBPF_TOOLCHAIN:-nightly-2026-06-22}"
linker="${OPC_BPF_LINKER:-bpf-linker}"
target_dir="${OPC_EBPF_TARGET_DIR:-${repo_root}/crates/opc-egress-fence-ebpf/target}"
comparison_target_dir="${OPC_EBPF_COMPARISON_TARGET_DIR:-${target_dir}-path2}"
features="${OPC_EBPF_FEATURES:-}"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
sysroot="$(rustc "+${toolchain}" --print sysroot)"

mutation_build=0
gate_mutation_build=0
fault_build=0
case "${features}" in
  "")
    ;;
  production)
    ;;
  fault-inject-delete)
    fault_build=1
    ;;
  mutation-bypass-gate)
    mutation_build=1
    gate_mutation_build=1
    ;;
  mutation-bypass-deadline)
    mutation_build=1
    ;;
  *)
    printf '%s\n' "unsupported eBPF feature selection" >&2
    exit 2
    ;;
esac

if (( mutation_build || fault_build )); then
  if [[ -z "${OPC_EBPF_ARTIFACT:-}" ]]; then
    printf '%s\n' "test-only build requires an explicit separate artifact path" >&2
    exit 2
  fi
  if [[ "$(realpath -m "${artifact}")" == "$(realpath -m "${production_artifact}")" ]]; then
    printf '%s\n' "test-only build cannot replace the production artifact" >&2
    exit 2
  fi
fi

if [[ -n "${expected_artifact}" ]]; then
  case "${expected_artifact}" in
    /*) ;;
    *)
      printf '%s\n' "expected eBPF artifact path must be absolute" >&2
      exit 2
      ;;
  esac
  if [[ ! -f "${expected_artifact}" ]]; then
    printf '%s\n' "expected eBPF artifact is unavailable" >&2
    exit 2
  fi
fi

for required_tool in "${linker}" llvm-objcopy llvm-readelf bpftool; do
  command -v "${required_tool}" >/dev/null
done

case "${target_dir}:${comparison_target_dir}" in
  /*:/*) ;;
  *) printf '%s\n' "eBPF target directories must be absolute" >&2; exit 2 ;;
esac
if [[ "${target_dir}" == "${comparison_target_dir}" ]]; then
  printf '%s\n' "eBPF comparison target must be distinct" >&2
  exit 2
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "${work_dir}"' EXIT
comparison_root="${work_dir}/second-absolute-root"
mkdir -p "${comparison_root}"
cp -a "${repo_root}/." "${comparison_root}/"

build_object() {
  local source_root="$1"
  local build_target="$2"
  local output="$3"
  local crate_dir="${source_root}/crates/opc-egress-fence-ebpf"
  local rustflags=(
    "-A" "linker_messages"
    "-C" "debuginfo=2"
    "-C" "linker=${linker}"
    "-C" "link-arg=--btf"
    "--remap-path-prefix=${HOME}=/build-home"
    "--remap-path-prefix=${cargo_home}=/cargo-home"
    "--remap-path-prefix=${sysroot}=/rust-sysroot"
    "--remap-path-prefix=${source_root}=/opc-sdk"
    "--remap-path-prefix=${build_target}=/cargo-target"
  )
  local cargo_args=(build --quiet --release --locked --package opc-egress-fence-ebpf)
  if (( gate_mutation_build )); then
    cargo_args+=(--no-default-features)
  fi
  if [[ -n "${features}" ]]; then
    cargo_args+=(--features "${features}")
  fi
  (
    cd "${crate_dir}"
    env CARGO_HOME="${cargo_home}" \
      CARGO_TARGET_DIR="${build_target}" \
      RUSTFLAGS="${rustflags[*]}" \
      cargo "+${toolchain}" "${cargo_args[@]}"
  )
  cp "${build_target}/bpfel-unknown-none/release/opc-egress-fence" "${output}"
}

inventory_object() {
  local object="$1"
  local inventory_dir="$2"
  mkdir -p "${inventory_dir}/sections"
  : >"${inventory_dir}/functional-sections"
  for section in .text cgroup_skb/egress classifier .maps license; do
    local safe_name="${section//\//_}"
    local section_file="${inventory_dir}/sections/${safe_name}"
    llvm-objcopy --dump-section "${section}=${section_file}" "${object}"
    printf '%s %s\n' \
      "${section}" \
      "$(sha256sum "${section_file}" | awk '{print $1}')" \
      >>"${inventory_dir}/functional-sections"
  done
  llvm-readelf --symbols --wide "${object}" \
    | awk '$5 == "GLOBAL" && ($4 == "FUNC" || $4 == "OBJECT") {
        print $3, $4, $5, $6, $7, $8
      }' \
    | LC_ALL=C sort >"${inventory_dir}/program-map-symbols"
  : >"${inventory_dir}/functional-relocations"
  for section in .rel.text .relcgroup_skb/egress .relclassifier .rel.BTF; do
    local safe_name="${section//\//_}"
    local section_file="${inventory_dir}/sections/${safe_name}"
    llvm-objcopy --dump-section "${section}=${section_file}" "${object}"
    printf '%s %s\n' \
      "${section}" \
      "$(sha256sum "${section_file}" | awk '{print $1}')" \
      >>"${inventory_dir}/functional-relocations"
  done
  # Raw BTF dumps expose equivalent type-ID allocation order; C output
  # canonicalizes the semantic type graph used by the map/program ABI gate.
  bpftool btf dump file "${object}" format c \
    >"${inventory_dir}/map-program-btf"
}

primary_object="${work_dir}/primary.bpf.o"
comparison_object="${work_dir}/comparison.bpf.o"
build_object "${repo_root}" "${target_dir}" "${primary_object}"
build_object "${comparison_root}" "${comparison_target_dir}" "${comparison_object}"

inventory_object "${primary_object}" "${work_dir}/primary-inventory"
inventory_object "${comparison_object}" "${work_dir}/comparison-inventory"
for inventory in \
  functional-sections \
  program-map-symbols \
  functional-relocations \
  map-program-btf
do
  if ! cmp -s \
    "${work_dir}/primary-inventory/${inventory}" \
    "${work_dir}/comparison-inventory/${inventory}"
  then
    printf 'eBPF stable functional inventory mismatch: %s\n' "${inventory}" >&2
    printf 'primary_inventory_sha256=%s\n' \
      "$(sha256sum "${work_dir}/primary-inventory/${inventory}" | awk '{print $1}')" >&2
    printf 'comparison_inventory_sha256=%s\n' \
      "$(sha256sum "${work_dir}/comparison-inventory/${inventory}" | awk '{print $1}')" >&2
    exit 1
  fi
done

if [[ -n "${expected_artifact}" ]]; then
  inventory_object "${expected_artifact}" "${work_dir}/expected-inventory"
  for inventory in \
    functional-sections \
    program-map-symbols \
    functional-relocations \
    map-program-btf
  do
    if ! cmp -s \
      "${work_dir}/primary-inventory/${inventory}" \
      "${work_dir}/expected-inventory/${inventory}"
    then
      printf 'eBPF committed functional inventory mismatch: %s\n' "${inventory}" >&2
      printf 'rebuilt_inventory_sha256=%s\n' \
        "$(sha256sum "${work_dir}/primary-inventory/${inventory}" | awk '{print $1}')" >&2
      printf 'committed_inventory_sha256=%s\n' \
        "$(sha256sum "${work_dir}/expected-inventory/${inventory}" | awk '{print $1}')" >&2
      exit 1
    fi
  done
fi

if cmp -s "${primary_object}" "${comparison_object}"; then
  reproducibility="whole-object-byte-identical"
else
  reproducibility="stable-functional-inventory"
fi

mkdir -p "$(dirname "${artifact}")"
cp "${primary_object}" "${artifact}"
object_digest="$(sha256sum "${artifact}" | awk '{print $1}')"
inventory_digest="$(
  cd "${work_dir}/primary-inventory"
  sha256sum \
    functional-relocations \
    functional-sections \
    map-program-btf \
    program-map-symbols \
    | awk '{print $1}' \
    | sha256sum \
    | awk '{print $1}'
)"
printf 'egress-fence object rebuild: PASS (%s)\n' "${reproducibility}"
printf 'object_sha256=%s\n' "${object_digest}"
printf 'functional_inventory_sha256=%s\n' "${inventory_digest}"
