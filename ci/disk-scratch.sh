#!/usr/bin/env bash
# Mutable test scratch is separate from the immutable fs-verity snapshot mount.
set -euo pipefail
exec python3 -I "${BASH_SOURCE[0]%/*}/disk-scratch.py" "$@"
