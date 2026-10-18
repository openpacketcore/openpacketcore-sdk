#!/usr/bin/env bash
# Own a private fs-verity filesystem for exactly one command's lifetime.
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/fsverity-runtime.py" "$@"
