#!/usr/bin/env bash
# Verify the exact kernel-readable license carried by a GTP-U eBPF ELF object.
set -euo pipefail
export LC_ALL=C

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <opc-gtpu-datapath.bpf.o>" >&2
  exit 2
fi

object="$1"
if [[ ! -f "${object}" ]]; then
  echo "GTP-U eBPF object does not exist: ${object}" >&2
  exit 1
fi
if ! command -v readelf >/dev/null; then
  echo "readelf is required to verify the GTP-U eBPF object license" >&2
  exit 1
fi

section_summary="$(
  readelf -SW "${object}" \
    | sed -E 's/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+//' \
    | awk '
      $1 == "license" {
        count++
        if ($2 == "PROGBITS") {
          progbits_count++
        }
      }
      END { print count + 0, progbits_count + 0 }
    '
)"
read -r section_count progbits_count <<<"${section_summary}"
if [[ "${section_count}" != 1 || "${progbits_count}" != 1 ]]; then
  echo "expected exactly one section named license with type PROGBITS in ${object}; found ${section_count} named license (${progbits_count} PROGBITS)" >&2
  exit 1
fi

license_hex="$(
  readelf --hex-dump=license "${object}" \
    | awk '
      $1 ~ /^0x[[:xdigit:]]+$/ {
        for (field = 2; field <= NF; field++) {
          value = $field
          if (value !~ /^[[:xdigit:]]+$/ || length(value) > 8 || length(value) % 2 != 0) {
            break
          }
          printf "%s", tolower(value)
        }
      }
      END { print "" }
    '
)"
expected_license_hex="4475616c204d49542f47504c00"
if [[ "${license_hex}" != "${expected_license_hex}" ]]; then
  echo "unexpected license section bytes in ${object}: ${license_hex}" >&2
  exit 1
fi

echo "verified ${object}: license contains exact Dual MIT/GPL\\0 bytes"
