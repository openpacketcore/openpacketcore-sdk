#!/usr/bin/env bash
# CI-facing true-root cgroup-v2 production/RED detector.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../../.." && pwd)"
manifest="${repo_root}/crates/opc-egress-fence-ebpf/Cargo.toml"
production_object="${OPC_EGRESS_FENCE_PRODUCTION_OBJECT:-${repo_root}/crates/opc-egress-fence/bpf/opc-egress-fence.bpf.o}"
deadline_mutation_object="${OPC_EGRESS_FENCE_DEADLINE_MUTATION_OBJECT:-${1:-}}"
gate_mutation_object="${OPC_EGRESS_FENCE_GATE_MUTATION_OBJECT:-${2:-}}"
target_dir="${OPC_EGRESS_FENCE_DETECTOR_TARGET_DIR:-/mnt/portable/opc-secondary/target-egress-fence-privileged-detector}"
host_target="$(rustc -vV | awk '/^host:/ { print $2 }')"

if [[ ! -f "${production_object}" \
  || ! -f "${deadline_mutation_object}" \
  || ! -f "${gate_mutation_object}" ]]
then
  printf '%s\n' "egress-fence privileged runner: DEFECTIVE (object unavailable)"
  exit 2
fi
case "${production_object}:${deadline_mutation_object}:${gate_mutation_object}:${target_dir}" in
  /*:/*:/*:/*) ;;
  *)
    printf '%s\n' "egress-fence privileged runner: DEFECTIVE (path not absolute)"
    exit 2
    ;;
esac

CARGO_TARGET_DIR="${target_dir}" \
  cargo build \
    --quiet \
    --locked \
    --manifest-path "${manifest}" \
    --package opc-egress-fence-object-oracle \
    --bin opc-egress-fence-privileged-detector \
    --target "${host_target}"

detector="${target_dir}/${host_target}/debug/opc-egress-fence-privileged-detector"
if (( EUID == 0 )); then
  privileged=()
else
  privileged=(sudo -n)
fi

require_cleanup_pass() {
  local mode="$1"
  local expected="$2"
  local output
  local status
  set +e
  output="$(
    "${privileged[@]}" env \
      OPC_EGRESS_FENCE_RUN_PRIVILEGED=1 \
      "${detector}" \
      "${mode}" \
      "${production_object}" \
      2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -ne 0 || "${output}" != "${expected}" ]]; then
    printf '%s\n' "egress-fence privileged runner: DEFECTIVE (cleanup detector weak)"
    exit 2
  fi
  printf '%s\n' "${expected}"
}

require_cleanup_pass \
  "--cleanup-fault-attach" \
  "egress-fence privileged cleanup detector: PASS (post-attach)"
require_cleanup_pass \
  "--cleanup-fault-veth" \
  "egress-fence privileged cleanup detector: PASS (post-veth)"
require_cleanup_pass \
  "--cleanup-fault-child" \
  "egress-fence privileged cleanup detector: PASS (post-child)"

"${privileged[@]}" env \
  OPC_EGRESS_FENCE_RUN_PRIVILEGED=1 \
  "${detector}" \
  --production \
  "${production_object}"

require_red() {
  local object="$1"
  local expected="$2"
  local output
  local status
  set +e
  output="$(
    "${privileged[@]}" env \
      OPC_EGRESS_FENCE_RUN_PRIVILEGED=1 \
      "${detector}" \
      --mutation \
      "${object}" \
      2>&1
  )"
  status=$?
  set -e
  printf '%s\n' "${output}"
  if [[ "${status}" -ne 1 || "${output}" != "${expected}" ]]; then
    printf '%s\n' "egress-fence privileged runner: DEFECTIVE (mutation detector weak)"
    exit 2
  fi
}

require_red \
  "${deadline_mutation_object}" \
  "egress-fence privileged detector: RED (expired-authority traffic observed)"
require_red \
  "${gate_mutation_object}" \
  "egress-fence privileged detector: RED (stale-authority traffic observed)"

printf '%s\n' "egress-fence privileged runner: PASS"
