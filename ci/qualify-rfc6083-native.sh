#!/usr/bin/env bash
# Run only inside an explicitly private Linux network namespace, as root.
# The binary is built by the unprivileged caller; no Cargo command runs here.
set -euo pipefail

if [[ $# -ne 2 || ! -x "$1" || "$1" != /* || "$2" != /* ]]; then
  echo 'usage: qualify-rfc6083-native.sh ABSOLUTE_TEST_BINARY ABSOLUTE_LOG_DIRECTORY' >&2
  exit 2
fi
rfc6083_current_ns="$(readlink /proc/self/ns/net)"
rfc6083_initial_ns="$(readlink /proc/1/ns/net)"
if [[ "$rfc6083_current_ns" == "$rfc6083_initial_ns" ]]; then
  echo 'RFC 6083 native qualification requires a private network namespace' >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo 'RFC 6083 native qualification requires root in the private namespace' >&2
  exit 2
fi

rfc6083_binary="$1"
rfc6083_logs="$2"
# These files contain only synthetic test diagnostics and must be readable by
# the unprivileged artifact uploader after this root process exits.
umask 022
mkdir -p "$rfc6083_logs"
ip link set dev lo up
sysctl -w net.sctp.auth_enable=1
test "$(sysctl -n net.sctp.auth_enable)" = 1

rfc6083_cases=(
  dtls_tests::generic::revocation::generic_kernel_required_crls_retire_both_roles
  dtls_tests::generic::generic_kernel_ppid66_handshake_opaque_delivery_and_reciprocal_close
  dtls_tests::generic::generic_kernel_terminal_carrier_revokes_readback_before_queued_delivery
  dtls_tests::generic::generic_kernel_constructor_rejects_unprotected_or_nonpristine_carriers
  dtls_tests::kernel_loopback_completes_real_rfc6083_handshake_and_reciprocal_close
  dtls_tests::generic::streams::generic_kernel_multistream_preserves_payload_streams_and_close
  dtls_tests::generic::paths::generic_kernel_multihoming_preserves_protection_and_bounds_total_path_loss
  dtls_tests::generic::restart::generic_kernel_process_restart_requires_fresh_mutual_authentication
  dtls_tests::generic::rekey::generic_kernel_rekey_preserves_multistream_records_and_rotates_keys
  dtls_tests::generic::sni::generic_kernel_sni_preserves_name_through_rekey_and_delivery
)
"$rfc6083_binary" --list --ignored --format terse > "$rfc6083_logs/inventory.log"
for rfc6083_case in "${rfc6083_cases[@]}"; do
  test "$(grep -Fxc -- "$rfc6083_case: test" "$rfc6083_logs/inventory.log")" = 1
  rfc6083_log="$rfc6083_logs/${rfc6083_case##*::}.log"
  if [[ "$rfc6083_case" == dtls_tests::generic::rekey::* || "$rfc6083_case" == dtls_tests::generic::sni::* ]]; then
    rfc6083_wire_args=()
    rfc6083_wire_profile=rekey-wire
    if [[ "$rfc6083_case" == dtls_tests::generic::sni::* ]]; then
      rfc6083_wire_args=(--sni)
      rfc6083_wire_profile=sni-wire
    fi
    # A fresh nested namespace excludes delayed shutdown traffic from the
    # earlier multihoming/process cases from this exact wire observation.
    timeout 60s unshare -n -- bash -c '
      set -euo pipefail
      ip link set lo up
      sysctl -w net.sctp.auth_enable=1
      exec python3 "$@"
    ' rekey-wire "$(dirname "$0")/qualify-rfc6083-rekey-wire.py" \
      "$rfc6083_binary" "$rfc6083_logs/$rfc6083_wire_profile" "${rfc6083_wire_args[@]}" 2>&1 | tee "$rfc6083_log"
  else
    timeout 60s "$rfc6083_binary" --ignored --exact "$rfc6083_case" \
      --test-threads=1 --nocapture 2>&1 | tee "$rfc6083_log"
  fi
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$rfc6083_log"
done
grep -Fq 'native protected SCTP path assertions completed' \
  "$rfc6083_logs/generic_kernel_multihoming_preserves_protection_and_bounds_total_path_loss.log"
grep -Fq 'native protected SCTP process restart assertions completed' \
  "$rfc6083_logs/generic_kernel_process_restart_requires_fresh_mutual_authentication.log"
grep -Fq 'native protected SCTP rekey assertions completed: 3 ciphers, 9 transitions per peer' \
  "$rfc6083_logs/generic_kernel_rekey_preserves_multistream_records_and_rotates_keys.log"
grep -Fq 'native SCTP-AUTH rekey wire verified: 6 directions, key IDs 0..4, 0 capture drops' \
  "$rfc6083_logs/generic_kernel_rekey_preserves_multistream_records_and_rotates_keys.log"
grep -Fq 'native protected SCTP SNI assertions completed: 3 ciphers, 6 transitions per peer' \
  "$rfc6083_logs/generic_kernel_sni_preserves_name_through_rekey_and_delivery.log"
grep -Fq 'native SNI wire verified: 3 named ClientHellos, 3 acknowledged ServerHellos, key IDs 0..3, 0 capture drops' \
  "$rfc6083_logs/generic_kernel_sni_preserves_name_through_rekey_and_delivery.log"
echo 'native RFC 6083 qualification completed: 10 executed, 0 ignored'
