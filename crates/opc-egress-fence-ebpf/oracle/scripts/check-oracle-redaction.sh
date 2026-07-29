#!/usr/bin/env bash
# Prove that top-level object-load failures erase caller paths and diagnostics.
set -euo pipefail

oracle="${1:-}"
if [[ "${oracle}" != /* || ! -x "${oracle}" ]]; then
  printf '%s\n' "egress-fence oracle redaction check: DEFECTIVE (oracle unavailable)"
  exit 2
fi

probe_root="$(mktemp -d)"
trap 'rm -rf -- "${probe_root}"' EXIT
sentinel="must-not-appear-private-object"
probe_path="${probe_root}/${sentinel}.bpf.o"

set +e
output="$("${oracle}" "${probe_path}" 2>&1)"
status=$?
set -e

expected="egress-fence independent object oracle: DEFECTIVE (object validation failed)"
if [[ "${status}" -ne 2 \
  || "${output}" != "${expected}" \
  || "${output}" == *"${sentinel}"* ]]
then
  printf '%s\n' "egress-fence oracle redaction check: DEFECTIVE (unstable failure boundary)"
  exit 2
fi

printf '%s\n' "egress-fence oracle redaction check: PASS"
