#!/usr/bin/env bash
# Execute the shared UDP queue and both IPv4 injection proofs in a private netns.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 || ! -x "$1" || "$1" != /* || "$2" != /* ]]; then
  echo 'usage: qualify-gtpu-control-native.sh ABSOLUTE_TEST_BINARY ABSOLUTE_LOG_DIRECTORY [required|kernel-config]' >&2
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
gtpu_injection_case='injection::native_tests::raw_ipv4_injection_preserves_bearer_source_fragments_and_containment'
gtpu_interface_case='injection::native_tests::xfrm_interface_injection_preserves_packets_and_containment'
gtpu_interface_expectation="${3:-required}"
case "$gtpu_interface_expectation" in
  required) ;;
  kernel-config)
    gtpu_kernel_config="/boot/config-$(uname -r)"
    if grep -Eq '^CONFIG_XFRM_INTERFACE=(y|m)$' "$gtpu_kernel_config"; then
      gtpu_interface_expectation=required
    elif grep -Fxq '# CONFIG_XFRM_INTERFACE is not set' "$gtpu_kernel_config"; then
      gtpu_interface_expectation=unsupported
    else
      echo 'XFRM interface support is not established by the running kernel configuration' >&2
      exit 2
    fi
    ;;
  *) echo 'invalid XFRM interface qualification expectation' >&2; exit 2 ;;
esac
umask 022
mkdir -p "$gtpu_control_logs"
ip link set lo up
"$gtpu_control_binary" --list --ignored --format terse > "$gtpu_control_logs/inventory.log"
test "$(grep -Fxc -- "$gtpu_control_case: test" "$gtpu_control_logs/inventory.log")" = 1
test "$(grep -Fxc -- "$gtpu_injection_case: test" "$gtpu_control_logs/inventory.log")" = 1
test "$(grep -Fxc -- "$gtpu_interface_case: test" "$gtpu_control_logs/inventory.log")" = 1
timeout 15s "$gtpu_control_binary" --ignored --exact "$gtpu_control_case" \
  --test-threads=1 --nocapture 2>&1 | tee "$gtpu_control_logs/native.log"
grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$gtpu_control_logs/native.log"
grep -Fq 'native shared GTP-U control socket: exact tuple, bounded response, required extension, single queue verified' "$gtpu_control_logs/native.log"
# The control proof deliberately renames loopback; injection needs a fresh
# namespace of its own, including an empty XFRM policy/state table.
timeout 45s unshare -n -- "$gtpu_control_binary" --ignored --exact "$gtpu_injection_case" \
  --test-threads=1 --nocapture 2>&1 | tee "$gtpu_control_logs/injection.log"
grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$gtpu_control_logs/injection.log"
grep -Fq 'OPC_GTPU_RAW_INJECTION_PROVEN:' "$gtpu_control_logs/injection.log"
timeout 45s unshare -n -- "$gtpu_control_binary" --ignored --exact "$gtpu_interface_case" \
  --test-threads=1 --nocapture 2>&1 | tee "$gtpu_control_logs/interface.log"
grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$gtpu_control_logs/interface.log"
if [[ "$gtpu_interface_expectation" == required ]]; then
  grep -Fq 'OPC_GTPU_XFRM_INTERFACE_INJECTION_PROVEN:' "$gtpu_control_logs/interface.log"
else
  grep -Fq 'OPC_GTPU_XFRM_INTERFACE_UNSUPPORTED_PROVEN:' "$gtpu_control_logs/interface.log"
fi
echo "native GTP-U control and injection qualification completed: 3 executed, 0 ignored; XFRM interface expectation: $gtpu_interface_expectation"
