#!/usr/bin/env bash
# Provision a private fs-verity-capable temporary filesystem for Linux gates.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' "fs-verity test storage requires Linux" >&2
  exit 1
fi

: "${RUNNER_TEMP:?RUNNER_TEMP must name the runner-owned scratch root}"
: "${GITHUB_ENV:?GITHUB_ENV must name the GitHub environment file}"

scratch="$(mktemp -d "${RUNNER_TEMP}/opc-fsverity.XXXXXX")"
image="${scratch}/ext4.img"
mountpoint="${scratch}/tmp"

mkdir -p "${mountpoint}"
truncate -s 4G "${image}"
mkfs.ext4 -q -b 4096 -O verity "${image}"
sudo mount -o loop,nosuid,nodev "${image}" "${mountpoint}"
sudo chown "$(id -u):$(id -g)" "${mountpoint}"

# Every tempfile-backed fixed-profile database and snapshot must exercise the
# production kernel seal. A runner filesystem without the verity superblock
# feature must not turn those tests into observational-hash coverage.
printf 'TMPDIR=%s\n' "${mountpoint}" >> "${GITHUB_ENV}"
