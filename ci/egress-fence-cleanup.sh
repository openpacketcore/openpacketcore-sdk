#!/usr/bin/env bash
set -euo pipefail
attachments="$(sudo bpftool cgroup show /sys/fs/cgroup 2>/dev/null)"
if [[ -n "${attachments}" ]]; then
  printf '%s\n' "egress-fence CI: DEFECTIVE (root attachment remained)"
  exit 2
fi
if sudo find /sys/fs/bpf \
  -maxdepth 1 \
  -name 'opc-egress-fence-*' \
  -print \
  -quit \
  | grep -q .
then
  printf '%s\n' "egress-fence CI: DEFECTIVE (pin inventory remained)"
  exit 2
fi
if sudo findmnt \
  --raw \
  --noheadings \
  --output TARGET \
  --types bpf \
  | awk '
      /^\/run\/opc-egress-fence-detector-bpffs-[0-9]+$/ {
        found = 1
      }
      END { exit !found }
    '
then
  printf '%s\n' "egress-fence CI: DEFECTIVE (private BPF mount remained)"
  exit 2
fi
if sudo find /run \
  -mindepth 1 \
  -maxdepth 1 \
  -type d \
  -name 'opc-egress-fence-detector-bpffs-*' \
  -print \
  -quit \
  | grep -q .
then
  printf '%s\n' "egress-fence CI: DEFECTIVE (private pin directory remained)"
  exit 2
fi
netns_inventory="$(sudo ip netns list)"
if awk '$1 ~ /^oef[rs]/ { found = 1 } END { exit !found }' \
  <<< "${netns_inventory}"; then
  printf '%s\n' "egress-fence CI: DEFECTIVE (network namespace remained)"
  exit 2
fi
if sudo find /sys/class/net \
  -mindepth 1 \
  -maxdepth 1 \
  -printf '%f\n' \
  | grep -Eq '^e[rs][on][0-9a-f]+$'
then
  printf '%s\n' "egress-fence CI: DEFECTIVE (host veth remained)"
  exit 2
fi
printf '%s\n' "egress-fence CI cleanup: PASS"
