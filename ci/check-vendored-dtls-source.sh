#!/usr/bin/env bash
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "::error::rg is required to check vendored DTLS source invariants" >&2
  exit 1
fi

violated=0
check() {
  local message="$1" pattern="$2"
  shift 2
  local -a scan_options=(--no-ignore --hidden --text --follow)
  local status path count
  if rg "${scan_options[@]}" -n -- "${pattern}" "$@"; then
    echo "::error::${message}"
    violated=1
  else
    status=$?
    if [[ ${status} -ne 1 ]]; then
      echo "::error::vendored DTLS source scan failed with rg exit ${status}: ${message}" >&2
      violated=1
      return
    fi
  fi

  for path in "$@"; do
    status=0
    count=$(rg "${scan_options[@]}" --files --null -- "${path}" | {
      count=0
      while IFS= read -r -d '' _; do
        ((count += 1))
      done
      printf '%s' "${count}"
    }) || status=$?
    if [[ ${status} -ne 0 && ${status} -ne 1 ]]; then
      echo "::error::vendored DTLS source scan failed with rg exit ${status}: ${path}" >&2
      violated=1
      continue
    fi
    echo "Scanned ${count} files in ${path}: ${message}"
    if [[ ${count} -eq 0 ]]; then
      echo "::error::vendored DTLS source scan found no files in ${path}: ${message}" >&2
      violated=1
    fi
  done
}

check "vendored DTLS source must not panic on unreachable paths" \
  '\b(unreachable!|unimplemented!|todo!)' vendor/dimpl/src
check "the DTLS 1.3 path must not reference RFC 6083" \
  'Rfc6083|rfc6083' vendor/dimpl/src/dtls13
check "Config must be constructed explicitly, never defaulted" \
  'impl Default for Config|Config::default\(\)' \
  vendor/dimpl/src vendor/dimpl/tests vendor/dimpl/README.md

exit "${violated}"
