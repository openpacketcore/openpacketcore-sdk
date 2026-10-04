#!/usr/bin/env bash
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "::error::rg is required to check vendored DTLS source invariants" >&2
  exit 1
fi

violated=0
check() {
  local message="$1"
  shift
  if rg "$@"; then
    echo "::error::${message}"
    violated=1
  else
    local status=$?
    if [[ ${status} -ne 1 ]]; then
      echo "::error::vendored DTLS source scan failed with rg exit ${status}: ${message}" >&2
      violated=1
    fi
  fi
}

check "vendored DTLS source must not panic on unreachable paths" \
  -n '\b(unreachable!|unimplemented!|todo!)' vendor/dimpl/src
check "the DTLS 1.3 path must not reference RFC 6083" \
  -n 'Rfc6083|rfc6083' vendor/dimpl/src/dtls13
check "Config must be constructed explicitly, never defaulted" \
  -n 'impl Default for Config|Config::default\(\)' \
  vendor/dimpl/src vendor/dimpl/tests vendor/dimpl/README.md

exit "${violated}"
