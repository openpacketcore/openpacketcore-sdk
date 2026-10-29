#!/usr/bin/env bash
# Keep mutable test data on runner disk, independently of the fs-verity mount.
set -euo pipefail

case "${1:-}" in
  prepare)
    : "${RUNNER_TEMP:?}" "${GITHUB_ENV:?}"
    umask 0077
    scratch="$(mktemp -d "${RUNNER_TEMP%/}/opc-disk-scratch.XXXXXXXX")"
    if ! filesystem="$(stat -f -c '%t' "$scratch")"; then
      rmdir -- "$scratch"
      exit 1
    fi
    case "$filesystem" in
      1021994|858458f6)
        rmdir -- "$scratch"
        echo '::error::durable tests require disk-backed runner scratch' >&2
        exit 1
        ;;
    esac
    if ! printf 'TMPDIR=%s\nOPC_CI_DISK_TMPDIR=%s\n' "$scratch" "$scratch" >> "$GITHUB_ENV"; then
      rmdir -- "$scratch"
      exit 1
    fi
    ;;
  cleanup)
    scratch="${OPC_CI_DISK_TMPDIR:-}"
    [[ -n "$scratch" ]] || exit 0
    : "${RUNNER_TEMP:?}"
    # Never use a later step's TMPDIR override as deletion authority.
    if [[ "${scratch%/*}" != "${RUNNER_TEMP%/}" ||
          ! "${scratch##*/}" =~ ^opc-disk-scratch\.[[:alnum:]]{8}$ || -L "$scratch" ]]; then
      echo '::error::refusing to remove unrelated runner scratch' >&2
      exit 1
    fi
    if ! rm -rf -- "$scratch"; then
      # Privileged tests may leave root-owned directories below this private root.
      [[ "${2:-}" == --privileged ]] || exit 1
      sudo -n rm -rf -- "$scratch"
    fi
    ;;
  *)
    echo 'usage: disk-scratch.sh prepare | cleanup [--privileged]' >&2
    exit 2
    ;;
esac
