#!/usr/bin/env bash
set -euo pipefail
kernel="$(uname -r)"
numeric="${kernel%%-*}"
major="${numeric%%.*}"
remainder="${numeric#*.}"
minor="${remainder%%.*}"
if [[ ! "${major}" =~ ^[0-9]+$ || ! "${minor}" =~ ^[0-9]+$ ]]; then
  printf '%s\n' "egress-fence CI: DEFECTIVE (kernel revision UAPI unavailable)"
  exit 2
fi
if (( major < 6 || (major == 6 && minor < 17) )); then
  printf '%s\n' "egress-fence CI: DEFECTIVE (kernel revision UAPI unavailable)"
  exit 2
fi
if [[ "$(stat --file-system --format=%T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  printf '%s\n' "egress-fence CI: DEFECTIVE (true cgroup-v2 root unavailable)"
  exit 2
fi
if ! mountpoint --quiet /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi
