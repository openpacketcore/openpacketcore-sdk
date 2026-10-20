#!/usr/bin/env bash
# Download a qualification image; the caller must verify its pinned checksum.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: download-image.sh URL OUTPUT' >&2
  exit 2
fi
url="$1"
image="$2"

# A reused state directory may contain bytes from a different image/profile.
# Resume only bytes written during this invocation.
rm -f -- "$image"
for attempt in 1 2 3 4; do
  # Plain --retry does not retry partial transfers (18). Separate invocations
  # retain their bytes, whereas --retry-all-errors resets failed output.
  if curl --http1.1 --fail --location --continue-at - \
    --speed-limit 1024 --speed-time 30 \
    --output "$image" --url "$url"; then
    exit 0
  else
    status=$?
  fi
  if [[ "$attempt" -eq 4 ]]; then
    exit "$status"
  fi
  # A server that ignores Range or returns the wrong offset needs a fresh GET.
  if [[ "$status" -eq 33 ]]; then
    rm -f -- "$image"
  fi
  sleep "$((1 << (attempt - 1)))"
done
