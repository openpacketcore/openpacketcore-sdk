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
snapshot_root="${mountpoint}/snapshots"

mkdir -p "${mountpoint}"
truncate -s 4G "${image}"
mkfs.ext4 -q -b 4096 -O verity "${image}"
sudo mount -o loop,nosuid,nodev "${image}" "${mountpoint}"
sudo chown "$(id -u):$(id -g)" "${mountpoint}"
install -d -m 700 "${snapshot_root}"

# Immutable snapshot fixtures opt into this private root explicitly. Keep
# TMPDIR on the runner filesystem: SQLite databases, WALs, and general test
# scratch are mutable and should not amplify loop-backed ext4 I/O.
printf 'OPC_FS_VERITY_SNAPSHOT_ROOT=%s\n' "${snapshot_root}" >> "${GITHUB_ENV}"
# The fs-verity sys crate keeps a portable unit-test path for developer
# machines. CI sets this marker only after mounting the dedicated ext4 image,
# so its qualification test fails rather than skipping if that filesystem
# cannot seal an artifact.
printf '%s\n' 'OPC_FS_VERITY_QUALIFICATION=required' >> "${GITHUB_ENV}"
