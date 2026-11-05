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
headers="$(mktemp)"
trap 'rm -f -- "$headers"' EXIT
transport_failures=0
http_deadline=0
http_delay=30
while :; do
  # Plain --retry does not retry partial transfers (18). Separate invocations
  # retain their bytes, whereas --retry-all-errors resets failed output.
  if http_code="$(curl --http1.1 --fail --location --continue-at - \
    --speed-limit 1024 --speed-time 30 \
    --dump-header "$headers" --write-out '%{http_code}' \
    --output "$image" --url "$url")"; then
    exit 0
  else
    status=$?
  fi
  if [[ "$http_code" == 429 || "$http_code" == 5[0-9][0-9] ]]; then
    now="$(date +%s)"
    if [[ "$http_deadline" -eq 0 ]]; then
      http_deadline=$((now + 300))
    fi
    remaining=$((http_deadline - now))
    if [[ "$remaining" -le 0 ]]; then
      exit "$status"
    fi
    delay="$http_delay"
    if [[ "$delay" -gt "$remaining" ]]; then
      delay="$remaining"
    fi
    # Redirects can supply several header blocks. Only the final response's
    # Retry-After applies; accept both delay-seconds and an HTTP date.
    retry_after="$(awk '
      /^HTTP\// { value = "" }
      tolower($0) ~ /^retry-after:/ {
        value = substr($0, index($0, ":") + 1)
        gsub(/^[ \t]+|[ \t\r]+$/, "", value)
      }
      END { print value }
    ' "$headers")"
    server_delay=0
    if [[ "$retry_after" =~ ^[0-9]+$ ]]; then
      # A longer delay cannot fit the retry window; avoid integer overflow.
      if [[ "${#retry_after}" -gt 9 ]]; then
        exit "$status"
      fi
      server_delay=$((10#$retry_after))
    elif [[ -n "$retry_after" ]]; then
      if retry_at="$(date --date="$retry_after" +%s 2>/dev/null)"; then
        server_delay=$((retry_at - now))
      fi
    fi
    if [[ "$server_delay" -gt "$remaining" ]]; then
      # Do not retry earlier than requested, or sleep past our retry budget.
      exit "$status"
    fi
    if [[ "$server_delay" -gt "$delay" ]]; then
      delay="$server_delay"
    fi
    http_delay=$((http_delay * 2))
  elif [[ "$http_code" == 4[0-9][0-9] ]]; then
    exit "$status"
  else
    # Preserve the existing short recovery window for interrupted transfers.
    transport_failures=$((transport_failures + 1))
    if [[ "$transport_failures" -eq 4 ]]; then
      exit "$status"
    fi
    delay=$((1 << (transport_failures - 1)))
  fi
  # A server that ignores Range or returns the wrong offset needs a fresh GET.
  if [[ "$status" -eq 33 ]]; then
    rm -f -- "$image"
  fi
  sleep "$delay"
done
