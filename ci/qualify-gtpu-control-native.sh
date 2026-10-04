#!/usr/bin/env bash
# Execute the shared UDP queue proof in a root-owned private network namespace.
set -euo pipefail

if [[ $# -ne 2 || ! -x "$1" || "$1" != /* || "$2" != /* ]]; then
  echo 'usage: qualify-gtpu-control-native.sh ABSOLUTE_TEST_BINARY ABSOLUTE_LOG_DIRECTORY' >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo 'GTP-U control qualification requires root in a private network namespace' >&2
  exit 2
fi
if [[ "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ]]; then
  echo 'GTP-U control qualification requires a private network namespace' >&2
  exit 2
fi
gtpu_control_binary="$1"
gtpu_control_logs="$2"
gtpu_control_case='control_port::native_tests::control_socket_native_preserves_tuple_budget_and_exact_socket'
umask 022
mkdir -p "$gtpu_control_logs"
ip link set lo up
"$gtpu_control_binary" --list --ignored --format terse > "$gtpu_control_logs/inventory.log"
test "$(grep -Fxc -- "$gtpu_control_case: test" "$gtpu_control_logs/inventory.log")" = 1
timeout 15s "$gtpu_control_binary" --ignored --exact "$gtpu_control_case" \
  --test-threads=1 --nocapture 2>&1 | tee "$gtpu_control_logs/native.log"
grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$gtpu_control_logs/native.log"
grep -Fq 'native shared GTP-U control socket: exact tuple, bounded response, required extension, single queue verified' "$gtpu_control_logs/native.log"
echo 'native GTP-U shared control qualification completed: 1 executed, 0 ignored'
