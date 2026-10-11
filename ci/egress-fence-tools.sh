#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  ""|--ebpf) ;;
  *) printf '%s\n' "usage: $0 [--ebpf]" >&2; exit 2 ;;
esac
sudo apt-get update
sudo apt-get install -y iproute2 linux-tools-common linux-tools-generic llvm
bpftool_path="$(
  find /usr/lib/linux-tools \
    -name bpftool \
    -perm /111 \
    -print \
    | sort -V \
    | tail -n 1
)"
if [[ -z "${bpftool_path}" ]]; then
  printf '%s\n' "egress-fence CI: DEFECTIVE (bpftool unavailable)"
  exit 2
fi
sudo install -m 0755 "${bpftool_path}" /usr/local/bin/bpftool
bpftool version
if [[ "${1:-}" == --ebpf ]]; then
  cargo install bpf-linker --version 0.10.3 --locked
fi
