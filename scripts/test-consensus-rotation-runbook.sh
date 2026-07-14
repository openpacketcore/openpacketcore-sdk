#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031,SC2034,SC2329
set -Eeuo pipefail
umask 077
export LC_ALL=C

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
RUNBOOK="$ROOT/docs/consensus-operator-runbook.md"
SCRATCH=$(mktemp -d)
trap 'rm -rf -- "$SCRATCH"' EXIT
chmod 0700 "$SCRATCH"

SCRIPT="$SCRATCH/campaign.sh"
LIBRARY="$SCRATCH/campaign-library.sh"
awk '
  /^```bash$/ && !inside { inside=1; next }
  inside && /^```$/ { exit }
  inside { print }
' "$RUNBOOK" >"$SCRIPT"
awk '
  /^trap on_error ERR$/ { exit }
  { print }
' "$SCRIPT" >"$LIBRARY"
bash -n "$SCRIPT"
if command -v shellcheck >/dev/null; then
  shellcheck -s bash "$SCRIPT"
fi

MOCK="$SCRATCH/cnfctl"
cat >"$MOCK" <<'MOCK'
#!/usr/bin/env bash
set -u
if [[ ${1:-} == --lease-token-fd ]]; then
  token_fd=$2
  shift 2
  IFS= read -r -d '' token <&"$token_fd" || true
  [[ -n $token ]] || exit 77
  if [[ -n ${MOCK_EXPECTED_TOKEN:-} && $token != "$MOCK_EXPECTED_TOKEN" ]]; then
    exit 78
  fi
fi
if [[ ${1:-} == --lease-fence ]]; then
  lease_fence=$2
  shift 2
  [[ $lease_fence == "${MOCK_LEASE_FENCE:-9}" ]] || exit 78
fi
if [[ ${1:-} == campaign-state && ${2:-} == initialize-or-verify ]]; then
    if [[ ${MOCK_ACQUIRE_OUTCOME:-acquired} == busy ]]; then exit 75; fi
    minimum_expiry=
    while (($#)); do
      if [[ $1 == --minimum-lease-expiry-epoch ]]; then
        minimum_expiry=$2
        break
      fi
      shift
    done
    [[ $minimum_expiry =~ ^[0-9]+$ ]] || exit 65
    printf '%s\t%s\t%s\t%s\n' "$(printf 'A%.0s' {1..43})" \
      "sha256:$(printf 'b%.0s' {1..64})" "${MOCK_LEASE_FENCE:-9}" \
      "$minimum_expiry"
elif [[ ${1:-} == campaign-state && ${2:-} == next-operation-id ]]; then
    [[ ${MOCK_FAIL_ALLOC:-0} != 1 ]] || exit 1
    sequence_file=${MOCK_SEQUENCE_FILE:?}
    sequence=40
    [[ ! -f $sequence_file ]] || read -r sequence <"$sequence_file"
    sequence=$((sequence + 1))
    printf '%s\n' "$sequence" >"$sequence_file"
    printf '%s\n' "$sequence"
elif [[ ${1:-} == campaign-state && ${2:-} == renew-exclusive-lease ]]; then
    [[ ${MOCK_FAIL_RENEW:-0} != 1 ]] || exit 1
    minimum_expiry=
    while (($#)); do
      if [[ $1 == --minimum-expiry-epoch ]]; then minimum_expiry=$2; break; fi
      shift
    done
    [[ $minimum_expiry =~ ^[0-9]+$ ]] || exit 65
    if [[ -n ${MOCK_RENEW_LOG:-} ]]; then
      printf '%s\n' "$minimum_expiry" >>"$MOCK_RENEW_LOG"
    fi
    printf '%s\t%s\n' "${MOCK_RENEW_OUTPUT_FENCE:-${MOCK_LEASE_FENCE:-9}}" \
      "$((minimum_expiry + ${MOCK_RENEW_EXPIRY_ADJUSTMENT:-0}))"
elif [[ ${1:-} == campaign-state && ${2:-} == release-exclusive-lease ]]; then
    printf '%s\n' release >>"${MOCK_LEASE_LOG:?}"
    : >"${MOCK_RELEASED_FILE:?}"
    [[ ${MOCK_RELEASE_RESPONSE_LOSS:-0} != 1 ]] || exit 1
elif [[ ${1:-} == campaign-state && ${2:-} == readback-exclusive-lease ]]; then
    [[ -e ${MOCK_RELEASED_FILE:?} ]] || exit 1
    printf '%s\n' readback >>"${MOCK_LEASE_LOG:?}"
elif [[ ${1:-} == withdrawal-operation-outcome ]]; then
    if [[ -n ${MOCK_OUTCOME_LOG:-} ]]; then
      printf '%s\n' readback >>"$MOCK_OUTCOME_LOG"
    fi
    [[ ${MOCK_FAIL_WITHDRAWAL_READBACK:-0} != 1 ]] || exit 1
    if [[ -e ${MOCK_WITHDRAWAL_STATE:?} ]]; then
      printf '%s\n' committed
    else
      printf '%s\n' not-committed
    fi
elif [[ ${1:-} == campaign-state && ${2:-} == member-ordinals ]]; then
    printf '%s\n' 0 1 2
elif [[ ${1:-} == campaign-state && ${2:-} == next-checkpoint-id ]]; then
    checkpoint_file=${MOCK_CHECKPOINT_FILE:?}
    checkpoint=0
    [[ ! -f $checkpoint_file ]] || read -r checkpoint <"$checkpoint_file"
    checkpoint=$((checkpoint + 1))
    printf '%s\n' "$checkpoint" >"$checkpoint_file"
    printf '%s\n' "$checkpoint"
elif [[ ${1:-} == campaign-state && ${2:-} == list-members ]]; then
    printf '%s\n' 2 1 0
elif [[ ${1:-} == withdraw-ready-traffic-and-durable-mutations || \
  ${1:-} == emergency-withdraw-ready-traffic-and-durable-mutations ]]
then
    idempotency_key=
    while (($#)); do
      if [[ $1 == --idempotency-key ]]; then idempotency_key=$2; break; fi
      shift
    done
    [[ -n $idempotency_key ]] || exit 65
    if [[ -n ${MOCK_ACTION_INVOCATION_LOG:-} ]]; then
      printf '%s\n' "$idempotency_key" >>"$MOCK_ACTION_INVOCATION_LOG"
    fi
    if [[ -n ${MOCK_WITHDRAWAL_UNCOMMITTED_ONCE_STATUS:-} && \
      ! -e ${MOCK_WITHDRAWAL_UNCOMMITTED_ONCE_MARKER:?} ]]
    then
      : >"$MOCK_WITHDRAWAL_UNCOMMITTED_ONCE_MARKER"
      printf '%s\n' 'SECRET /var/run/private/spiffe-id' >&2
      exit "$MOCK_WITHDRAWAL_UNCOMMITTED_ONCE_STATUS"
    fi
    if [[ ! -e ${MOCK_WITHDRAWAL_STATE:?} ]]; then
      : >"$MOCK_WITHDRAWAL_STATE"
      printf '%s\n' action >>"${MOCK_ACTION_LOG:?}"
    fi
    printf '%s\n' 'SECRET /var/run/private/spiffe-id' >&2
    response_status=${MOCK_WITHDRAWAL_RESPONSE_STATUS:-0}
    [[ $response_status =~ ^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]] || \
      exit 65
    ((response_status == 0)) || exit "$response_status"
elif [[ ${1:-} == mock-stderr ]]; then
    printf '%s\n' 'SECRET /var/run/private/spiffe-id' >&2
    exit 7
elif [[ ${1:-} == mock-inherited-stdout ]]; then
    sleep 60 &
    printf '%s\n' "$!" >"${MOCK_INHERITED_PID_FILE:?}"
    printf '%s\n' bounded
elif [[ ${1:-} == evidence-success ]]; then
    command cat "${MOCK_EVIDENCE_FILE:?}"
fi
MOCK
chmod 0700 "$MOCK"

export NS=test WORKLOAD=quorum SELECTOR='app=test'
export CNFCTL=$MOCK CAMPAIGN_ID=campaign-a EXPECTED_MEMBERS=3
RELEASE_DIGEST="sha256:$(printf '1%.0s' {1..64})"
export RELEASE_DIGEST
export TOPOLOGY_CONFIG_EPOCH=7
export EVIDENCE_ROOT="$SCRATCH/evidence" STATE_ROOT="$SCRATCH/state"
export ALERT_RULES=alerts.yaml PREVIOUS_OVERLAP_MANIFEST_SET=previous
export NEW_SVID_OVERLAP_MANIFEST_SET=new-overlap
export FINAL_NEW_ONLY_MANIFEST_SET=new-only OLD_CHAIN_PROBE=old-chain
export OLD_CHAIN_EXPECTED_FAILURE_DELTA=2
export MAX_AUTH_AGE_SECONDS=900 ROTATION_JITTER_SECONDS=30 DRAIN_SECONDS=30
export RECONNECT_MAX_SECONDS=60 OBSERVATION_SECONDS=300
export MOCK_SEQUENCE_FILE="$SCRATCH/sequence" MOCK_ACTION_LOG="$SCRATCH/actions"
export MOCK_CHECKPOINT_FILE="$SCRATCH/checkpoint-sequence"
export MOCK_WITHDRAWAL_STATE="$SCRATCH/withdrawal-state"
mkdir -m 0700 "$EVIDENCE_ROOT" "$STATE_ROOT"

# shellcheck source=/dev/null
source "$LIBRARY"
LEASE_TOKEN=$(printf 'A%.0s' {1..43})
LEASE_BINDING="sha256:$(printf 'b%.0s' {1..64})"
LEASE_FENCE=9
LEASE_EXPIRES_EPOCH=$(( $(date -u +%s) + LEASE_TTL_SECONDS ))
LEASE_ACQUIRED=1

allocate_operation
first_allocated_operation=$CURRENT_OPERATION_ID
allocate_operation
second_allocated_operation=$CURRENT_OPERATION_ID
[[ $first_allocated_operation == 41 && $second_allocated_operation == 42 ]]
load_members
[[ ${MEMBERS[*]} == '0 1 2' ]]
state_members touched renewed all
[[ ${STATE_MEMBERS[*]} == '2 1 0' ]]
next_checkpoint
[[ $CURRENT_CHECKPOINT_ID == 1 ]]
[[ $CURRENT_CHECKPOINT == "$STATE_DIR/checkpoint-1.bin" ]]

[[ $ROLLBACK_MEMBER_SECONDS == 3080 ]]
[[ $RECOVERY_RELEASE_TOTAL_SECONDS == 60 ]]
[[ $ROLLBACK_FIXED_SECONDS == 2760 ]]
[[ $ROLLBACK_BUDGET_SECONDS == 21240 ]]
[[ $((ROLLBACK_FIXED_SECONDS + 2 * 5 * ROLLBACK_MEMBER_SECONDS)) == 33560 ]]
[[ $HARD_SPAN_SECONDS == 22560 ]]
[[ $OVERLAP_WAIT_SECONDS == 22590 ]]
[[ $LEASE_TTL_SECONDS == 22620 ]]
[[ $FORWARD_CAMPAIGN_SECONDS == 57600 ]]
[[ $FORWARD_CERTIFICATE_HORIZON_SECONDS == 80160 ]]
[[ $((900 + 30 + 30 + 60 + 300 + 33560)) == 34880 ]]

# Renewal is inside every command bound and covers even the longest command.
# Wrong fences, short renewal, and stale tokens fail closed.
export MOCK_RENEW_LOG="$SCRATCH/renewals"
: >"$MOCK_RENEW_LOG"
renew_start=$(date -u +%s)
run_cnfctl "$OVERLAP_WAIT_SECONDS" mock-noop
renewed_until=$(tail -n 1 "$MOCK_RENEW_LOG")
((renewed_until >= renew_start + OVERLAP_WAIT_SECONDS + \
  LEASE_RENEWAL_RESERVE_SECONDS))
export MOCK_RENEW_OUTPUT_FENCE=10
if run_cnfctl "$STATE_OPERATION_SECONDS" mock-noop; then exit 1; fi
unset MOCK_RENEW_OUTPUT_FENCE
export MOCK_RENEW_EXPIRY_ADJUSTMENT=-1
if run_cnfctl "$STATE_OPERATION_SECONDS" mock-noop; then exit 1; fi
unset MOCK_RENEW_EXPIRY_ADJUSTMENT
MOCK_EXPECTED_TOKEN=$(printf 'Z%.0s' {1..43})
export MOCK_EXPECTED_TOKEN
if run_cnfctl_raw "$STATE_OPERATION_SECONDS" mock-noop; then exit 1; fi
unset MOCK_EXPECTED_TOKEN

# Busy is a typed non-error acquisition outcome: no lease, rollback,
# withdrawal, or fleet command is permitted.
BUSY_ROOT="$SCRATCH/busy"
mkdir -m 0700 "$BUSY_ROOT" "$BUSY_ROOT/evidence" "$BUSY_ROOT/state"
BUSY_ACTIONS="$BUSY_ROOT/actions"
set +e
MOCK_ACQUIRE_OUTCOME=busy MOCK_ACTION_LOG="$BUSY_ACTIONS" \
  EVIDENCE_ROOT="$BUSY_ROOT/evidence" STATE_ROOT="$BUSY_ROOT/state" \
  CNFCTL="$MOCK" bash "$SCRIPT" >/dev/null 2>"$BUSY_ROOT/diagnostic"
busy_status=$?
set -e
[[ $busy_status == 75 && ! -e $BUSY_ACTIONS ]]
[[ ! -s $BUSY_ROOT/diagnostic ]]

# Run the complete main path with a semantically invalid successful preflight
# document. Recovery may perform its one withdrawal, but no publication or next
# campaign mutation is reachable.
FULL_MOCK="$SCRATCH/full-cnfctl"
cat >"$FULL_MOCK" <<'FULL_MOCK'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} == --lease-token-fd ]]; then
  token_fd=$2
  shift 2
  IFS= read -r -d '' token <&"$token_fd" || true
  [[ $token == "$(printf 'A%.0s' {1..43})" ]] || exit 78
fi
if [[ ${1:-} == --lease-fence ]]; then
  [[ $2 == 9 ]] || exit 78
  shift 2
fi
args=("$@")
value_after() {
  local wanted=$1 index
  for ((index = 0; index + 1 < ${#args[@]}; index++)); do
    if [[ ${args[$index]} == "$wanted" ]]; then
      printf '%s' "${args[$((index + 1))]}"
      return 0
    fi
  done
  return 1
}
has_arg() {
  local wanted=$1 item
  for item in "${args[@]}"; do [[ $item == "$wanted" ]] && return 0; done
  return 1
}
if [[ ${1:-} == campaign-state && ${2:-} == initialize-or-verify ]]; then
  expiry=$(value_after --minimum-lease-expiry-epoch)
  printf '%s\t%s\t9\t%s\n' "$(printf 'A%.0s' {1..43})" \
    "sha256:$(printf 'b%.0s' {1..64})" "$expiry"
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == renew-exclusive-lease ]]; then
  expiry=$(value_after --minimum-expiry-epoch)
  printf '9\t%s\n' "$expiry"
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == next-operation-id ]]; then
  operation=0
  [[ ! -e ${FULL_OPERATION_FILE:?} ]] || read -r operation <"$FULL_OPERATION_FILE"
  operation=$((operation + 1))
  printf '%s\n' "$operation" >"$FULL_OPERATION_FILE"
  printf '%s\n' "$operation"
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == next-checkpoint-id ]]; then
  checkpoint=0
  [[ ! -e ${FULL_CHECKPOINT_FILE:?} ]] || \
    read -r checkpoint <"$FULL_CHECKPOINT_FILE"
  checkpoint=$((checkpoint + 1))
  printf '%s\n' "$checkpoint" >"$FULL_CHECKPOINT_FILE"
  printf '%s\n' "$checkpoint"
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == member-ordinals ]]; then
  printf '%s\n' 0 1 2
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == list-members ]]; then
  printf '%s\n' 2 1 0
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == resume-action ]]; then
  printf '%s\n' forward
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == require-rollback ]]; then
  exit 1
fi
if [[ ${1:-} == campaign-state && ${2:-} == release-exclusive-lease ]]; then
  printf '%s\n' release >>"${FULL_LEASE_LOG:?}"
  : >"${FULL_RELEASED_FILE:?}"
  exit 0
fi
if [[ ${1:-} == campaign-state && ${2:-} == readback-exclusive-lease ]]; then
  [[ -e ${FULL_RELEASED_FILE:?} ]] || exit 1
  printf '%s\n' readback >>"${FULL_LEASE_LOG:?}"
  exit 0
fi
if [[ ${1:-} == withdrawal-operation-outcome ]]; then
  if [[ -e ${FULL_WITHDRAWAL_STATE:?} ]]; then
    printf '%s\n' committed
  else
    printf '%s\n' not-committed
  fi
  exit 0
fi
if [[ ${1:-} == withdraw-ready-traffic-and-durable-mutations ]]; then
  if [[ ! -e ${FULL_WITHDRAWAL_STATE:?} ]]; then
    : >"$FULL_WITHDRAWAL_STATE"
    printf '%s\n' withdrawal >>"${FULL_FLEET_LOG:?}"
  fi
  exit 0
fi
if has_arg --evidence-step; then
  phase=$(value_after --evidence-phase)
  step=$(value_after --evidence-step)
  operation=$(value_after --evidence-operation-id)
  nonce=$(value_after --evidence-operation-nonce)
  invocation=$(value_after --evidence-invocation-id)
  lease=$(value_after --evidence-lease-binding)
  fence=$(value_after --evidence-lease-fence)
  required=$(value_after --evidence-required-remaining-seconds)
  expected_success=0
  if has_arg --evidence-expected-success-delta; then
    expected_success=$(value_after --evidence-expected-success-delta)
  fi
  member=null
  checkpoint=null
  if has_arg --evidence-member-ordinal; then
    member=$(value_after --evidence-member-ordinal)
  fi
  if has_arg --evidence-checkpoint-id; then
    checkpoint=$(value_after --evidence-checkpoint-id)
  fi
  ready=${FULL_EXPECTED_MEMBERS:?}
  durable=true
  series=true
  paths_expected=0
  paths_passed=0
  success_delta=$expected_success
  source_before=null
  source_after=null
  controller_before=null
  controller_after=null
  process_binding="sha256:$(printf 'd%.0s' {1..64})"
  withdrawal_state=not-withdrawn
  if [[ $step == source-ready ]]; then
    source_before=1
    source_after=2
  fi
  if [[ $step == controller-ready ]]; then
    controller_before=1
    controller_after=2
  fi
  if [[ $step == directed-paths ]]; then
    paths_expected=2
    paths_passed=2
  fi
  if [[ ${FULL_FORCE_POLICY_FAILURE:-0} == 1 && $phase == preflight && \
    $step == policy-binding ]]
  then
    ready=$((ready - 1))
  fi
  if [[ $step == withdrawal ]]; then
    ready=0
    durable=false
    series=false
    process_binding=null
    withdrawal_state=ready-traffic-and-durable-mutations-withdrawn
  fi
  printf '%s\t%s\t%s\n' "$phase" "$step" "$member" \
    >>"${FULL_EVIDENCE_LOG:?}"
  if [[ $phase == "${FULL_INVALID_PHASE:-overlap}" && \
    $step == "${FULL_INVALID_STEP:?}" ]]
  then
    case "$step" in
      policy-binding) ready=$((ready - 1)) ;;
      source-ready) source_after=$source_before ;;
      controller-ready) controller_after=$controller_before ;;
      directed-paths) paths_expected=0; paths_passed=0 ;;
      fleet-post-gate) success_delta=$((10#$expected_success + 1)) ;;
      withdrawal) withdrawal_state=not-withdrawn ;;
      *) exit 64 ;;
    esac
  fi
  timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  jq -n \
    --arg campaign "${CAMPAIGN_ID:?}" --arg release "${RELEASE_DIGEST:?}" \
    --arg topology "${TOPOLOGY_CONFIG_EPOCH:?}" --arg invocation "$invocation" \
    --arg lease "$lease" --arg fence "$fence" --arg operation "$operation" \
    --arg nonce "$nonce" --arg phase "$phase" --arg step "$step" \
    --arg timestamp "$timestamp" --arg process "$process_binding" \
    --arg withdrawal_state "$withdrawal_state" \
    --arg success_delta "$success_delta" --arg source_before "$source_before" \
    --arg source_after "$source_after" \
    --arg controller_before "$controller_before" \
    --arg controller_after "$controller_after" \
    --argjson member "$member" --arg checkpoint "$checkpoint" \
    --argjson required "$required" --argjson ready "$ready" \
    --argjson paths_expected "$paths_expected" \
    --argjson paths_passed "$paths_passed" \
    --argjson durable "$durable" --argjson series "$series" \
    --argjson members "${FULL_EXPECTED_MEMBERS:?}" \
    --argjson rollback "${FULL_ROLLBACK_BUDGET:?}" \
    --argjson hard "${FULL_HARD_SPAN:?}" \
    --argjson forward "${FULL_FORWARD_CAMPAIGN:?}" \
    --argjson horizon "${FULL_FORWARD_HORIZON:?}" '
    {
      affected_paths_expected: $paths_expected,
      affected_paths_passed: $paths_passed,
      agreeing_voters: (if $durable then 2 else 0 end),
      auth_alert_silenced_or_inhibited: false,
      auth_or_trust_failure_delta: "0", campaign_id: $campaign,
      checkpoint_id: (if $checkpoint == "null" then null else $checkpoint end),
      controller_epoch_after:
        (if $controller_after == "null" then null else $controller_after end),
      controller_epoch_before:
        (if $controller_before == "null" then null else $controller_before end),
      critical_auth_alert_visible: false, drain_overrun_delta: "0",
      drain_seconds: 30, durable_ready: $durable, exit_status: 0,
      expected_campaign_auth_delta: "0", expected_member_auth_delta: "0",
      expected_members: $members, expired_delta: "0",
      forward_campaign_seconds: $forward,
      forward_certificate_horizon_seconds: $horizon,
      fresh_reachable_voters: (if $durable then 2 else 0 end),
      hard_span_seconds: $hard, invocation_id: $invocation,
      lease_binding: $lease, lease_fence: $fence, max_auth_age_seconds: 900,
      member_ordinal: $member, min_expiry_remaining_seconds: $required,
      observation_seconds: 300, observed_campaign_auth_delta: "0",
      observed_member_auth_delta: "0", old_chain_expected_failure_delta: 2,
      operation_id: $operation, operation_nonce: $nonce, phase: $phase,
      probe_checkpoint_id: null, probe_process_incarnation_set_binding: null,
      probe_receipt_count: 0, probe_receipt_set_binding: null,
      process_incarnation_changes: 0,
      process_incarnation_set_binding:
        (if $process == "null" then null else $process end),
      ready_controllers: $ready, ready_sources: $ready,
      reconnect_failure_delta: "0", reconnect_max_seconds: 60,
      referenced_probe_operation_id: null,
      referenced_probe_operation_nonce: null, rejected_delta: "0",
      release_digest: $release, required_quorum: 2,
      required_remaining_seconds: $required, reset_count: 0,
      retained_delta: "0", rollback_budget_seconds: $rollback,
      rotation_jitter_seconds: 30, saturated_series: 0,
      schema: "opc.security.rotation.evidence.v1", series_complete: $series,
      source_version_after:
        (if $source_after == "null" then null else $source_after end),
      source_version_before:
        (if $source_before == "null" then null else $source_before end),
      step: $step, success_delta: $success_delta,
      topology_config_epoch: $topology,
      unaccounted_auth_delta: "0", utc_timestamp: $timestamp,
      withdrawal_state: $withdrawal_state
    }'
  exit 0
fi
exit 0
FULL_MOCK
chmod 0700 "$FULL_MOCK"
export FULL_EXPECTED_MEMBERS=3 FULL_ROLLBACK_BUDGET=21240
export FULL_HARD_SPAN=22560 FULL_FORWARD_CAMPAIGN=57600
export FULL_FORWARD_HORIZON=80160

run_full_failure_case() {
  local case_name=$1 invalid_step=$2 invalid_phase=${3:-overlap}
  local trigger_policy_failure=${4:-0} root full_status
  root="$SCRATCH/full-$case_name"
  mkdir -m 0700 "$root" "$root/evidence" "$root/state"
  export FULL_OPERATION_FILE="$root/operation"
  export FULL_CHECKPOINT_FILE="$root/checkpoint"
  export FULL_LEASE_LOG="$root/lease-log"
  export FULL_RELEASED_FILE="$root/released"
  export FULL_FLEET_LOG="$root/fleet-log"
  export FULL_EVIDENCE_LOG="$root/evidence-log"
  export FULL_WITHDRAWAL_STATE="$root/withdrawal-state"
  : >"$FULL_LEASE_LOG"
  : >"$FULL_FLEET_LOG"
  : >"$FULL_EVIDENCE_LOG"
  set +e
  FULL_INVALID_PHASE="$invalid_phase" FULL_INVALID_STEP="$invalid_step" \
    FULL_FORCE_POLICY_FAILURE="$trigger_policy_failure" \
    CNFCTL="$FULL_MOCK" CAMPAIGN_ID="campaign-$case_name" \
    EVIDENCE_ROOT="$root/evidence" STATE_ROOT="$root/state" \
    bash "$SCRIPT" >/dev/null 2>"$root/diagnostic"
  full_status=$?
  set -e
  [[ $full_status != 0 ]]
  [[ $(grep -c '^withdrawal$' "$FULL_FLEET_LOG") == 1 ]]
  [[ $(grep -c '^release$' "$FULL_LEASE_LOG") == 1 ]]
  [[ $(grep -c '^readback$' "$FULL_LEASE_LOG") == 1 ]]
  FULL_CASE_ROOT=$root
}

# Invalid successful evidence stops before the next substantive forward
# command. Recovery may perform its single fail-safe withdrawal, but it cannot
# turn the rejected document into progress.
run_full_failure_case source source-ready
grep -q $'^overlap\tsource-ready\t0$' "$FULL_CASE_ROOT/evidence-log"
if grep -q $'^overlap\tcontroller-ready\t0$' \
  "$FULL_CASE_ROOT/evidence-log"; then exit 1; fi

run_full_failure_case controller controller-ready
grep -q $'^overlap\tcontroller-ready\t0$' "$FULL_CASE_ROOT/evidence-log"
if grep -q $'^overlap\treauthentication\t0$' \
  "$FULL_CASE_ROOT/evidence-log"; then exit 1; fi

run_full_failure_case directed directed-paths
grep -q $'^overlap\tdirected-paths\t0$' "$FULL_CASE_ROOT/evidence-log"
if grep -q $'^overlap\tdurable-readiness\t0$' \
  "$FULL_CASE_ROOT/evidence-log"; then exit 1; fi

run_full_failure_case success fleet-post-gate
grep -q $'^overlap\tfleet-post-gate\t0$' "$FULL_CASE_ROOT/evidence-log"
if grep -q $'^overlap\tfleet-checkpoint\t1$' \
  "$FULL_CASE_ROOT/evidence-log"; then exit 1; fi

run_full_failure_case withdrawal withdrawal withdrawal 1
[[ $(grep -c $'^withdrawal\twithdrawal\tnull$' \
  "$FULL_CASE_ROOT/evidence-log") == 1 ]]
[[ $(grep -c '^withdrawal$' "$FULL_CASE_ROOT/fleet-log") == 1 ]]

NONCE=$(printf 'a%.0s' {1..32})
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
make_evidence() {
  jq -n \
    --arg campaign "$CAMPAIGN_ID" --arg release "$RELEASE_DIGEST" \
    --arg topology "$TOPOLOGY_CONFIG_EPOCH" --arg invocation "$INVOCATION_ID" \
    --arg lease "$LEASE_BINDING" --arg operation '42' --arg nonce "$NONCE" \
    --arg timestamp "$TIMESTAMP" --argjson members "$EXPECTED_MEMBERS" \
    --argjson hard_span "$HARD_SPAN_SECONDS" \
    --argjson forward_campaign "$FORWARD_CAMPAIGN_SECONDS" \
    --argjson forward_horizon "$FORWARD_CERTIFICATE_HORIZON_SECONDS" \
    --argjson rollback_budget "$ROLLBACK_BUDGET_SECONDS" '
    {
      affected_paths_expected: 0, affected_paths_passed: 0,
      agreeing_voters: 2, auth_alert_silenced_or_inhibited: false,
      auth_or_trust_failure_delta: "0", critical_auth_alert_visible: false,
      campaign_id: $campaign, checkpoint_id: "7",
      controller_epoch_after: null, controller_epoch_before: null,
      drain_overrun_delta: "0", drain_seconds: 30, durable_ready: true,
      exit_status: 0, expected_members: $members, expired_delta: "0",
      expected_campaign_auth_delta: "0", expected_member_auth_delta: "0",
      forward_campaign_seconds: $forward_campaign,
      forward_certificate_horizon_seconds: $forward_horizon,
      fresh_reachable_voters: 2, hard_span_seconds: $hard_span,
      invocation_id: $invocation, lease_binding: $lease, lease_fence: "9",
      max_auth_age_seconds: 900, member_ordinal: 1,
      min_expiry_remaining_seconds: 1000, observation_seconds: 300,
      old_chain_expected_failure_delta: 2,
      operation_id: $operation, operation_nonce: $nonce, phase: "preflight",
      process_incarnation_changes: 0, ready_controllers: $members,
      process_incarnation_set_binding:
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      probe_checkpoint_id: null, probe_process_incarnation_set_binding: null,
      probe_receipt_count: 0, probe_receipt_set_binding: null,
      referenced_probe_operation_id: null,
      referenced_probe_operation_nonce: null,
      ready_sources: $members, reconnect_failure_delta: "0",
      reconnect_max_seconds: 60, rejected_delta: "0", release_digest: $release,
      required_quorum: 2, required_remaining_seconds: 100, reset_count: 0,
      retained_delta: "0", rollback_budget_seconds: $rollback_budget,
      rotation_jitter_seconds: 30, saturated_series: 0,
      schema: "opc.security.rotation.evidence.v1", series_complete: true,
      source_version_after: null, source_version_before: null,
      step: "policy-binding", success_delta: "0",
      observed_campaign_auth_delta: "0", observed_member_auth_delta: "0",
      topology_config_epoch: $topology, unaccounted_auth_delta: "0",
      utc_timestamp: $timestamp, withdrawal_state: "not-withdrawn"
    }'
}

BASE=$(make_evidence)
export MOCK_EVIDENCE_FILE="$SCRATCH/mock-evidence.json"
printf '%s\n' "$BASE" >"$MOCK_EVIDENCE_FILE"
printf '%s' "$BASE" | validate_evidence preflight policy-binding 1 7 100 42 \
  "$NONCE" 0 >/dev/null
[[ $BASE != *"$LEASE_TOKEN"* ]]

CURRENT_OPERATION_ID=42
CURRENT_OPERATION_NONCE=$NONCE
EVIDENCE_DIR="$EVIDENCE_ROOT/$CAMPAIGN_ID"
save_current_operation_evidence valid preflight policy-binding 1 7 100 30 \
  evidence-success
[[ -f $EVIDENCE_DIR/42-valid.json ]]
if grep -q -- "$LEASE_TOKEN" "$EVIDENCE_DIR/42-valid.json"; then exit 1; fi

must_reject() {
  local document=$1 member=${2:-1} checkpoint=${3:-7} operation=${4:-42}
  local nonce=${5:-$NONCE} auth_delta=${6:-0}
  if printf '%s' "$document" | validate_evidence preflight policy-binding \
    "$member" "$checkpoint" 100 "$operation" "$nonce" "$auth_delta" \
    >/dev/null 2>&1
  then
    printf '%s\n' 'validator unexpectedly accepted adversarial evidence' >&2
    exit 1
  fi
}

must_reject "$(jq '.member_ordinal = 2' <<<"$BASE")"
must_reject "$(jq '.checkpoint_id = "8"' <<<"$BASE")"
must_reject "$(jq '.lease_binding = "sha256:'"$(printf 'c%.0s' {1..64})"'"' \
  <<<"$BASE")"
must_reject "$(jq '.invocation_id = "00000000000000000000000000000000"' \
  <<<"$BASE")"
must_reject "$(jq '.operation_id = "43"' <<<"$BASE")"
must_reject "$BASE" 1 7 42 "$(printf 'd%.0s' {1..32})"
must_reject "$(jq '.phase = "overlap"' <<<"$BASE")"
must_reject "$(jq '.step = "manifest-validation"' <<<"$BASE")"
must_reject "$(jq '.utc_timestamp = "2000-01-01T00:00:00Z"' <<<"$BASE")"
for mutation in \
  '.ready_sources = 2' \
  '.ready_controllers = 2' \
  '.durable_ready = false' \
  '.fresh_reachable_voters = 1' \
  '.agreeing_voters = 1' \
  '.series_complete = false' \
  '.reset_count = 1' \
  '.process_incarnation_changes = 1' \
  '.saturated_series = 1' \
  '.min_expiry_remaining_seconds = 99' \
  '.affected_paths_expected = 1 | .affected_paths_passed = 0' \
  '.retained_delta = "1"' \
  '.rejected_delta = "1"' \
  '.expired_delta = "1"' \
  '.drain_overrun_delta = "1"' \
  '.auth_or_trust_failure_delta = "1"' \
  '.reconnect_failure_delta = "1"' \
  '.unaccounted_auth_delta = "1"' \
  '.exit_status = 1'
do
  must_reject "$(jq "$mutation" <<<"$BASE")"
done

# Step-local claims are semantic gates, not merely well-typed optional fields.
# Source/controller readiness proves a strict per-process advance, directed
# probing proves at least one path and every expected path, and target-success
# commands bind their exact requested delta.
SOURCE_READY=$(jq '
  .phase = "overlap" | .step = "source-ready" |
  .source_version_before = "41" | .source_version_after = "42"
' <<<"$BASE")
printf '%s' "$SOURCE_READY" | validate_evidence overlap source-ready 1 7 100 \
  42 "$NONCE" 0 >/dev/null
for mutation in \
  '.source_version_before = null' \
  '.source_version_after = null' \
  '.source_version_after = "41"' \
  '.source_version_after = "40"'
do
  if printf '%s' "$(jq "$mutation" <<<"$SOURCE_READY")" | \
    validate_evidence overlap source-ready 1 7 100 42 "$NONCE" 0 \
    >/dev/null 2>&1
  then
    exit 1
  fi
done

CONTROLLER_READY=$(jq '
  .phase = "overlap" | .step = "controller-ready" |
  .controller_epoch_before = "7" | .controller_epoch_after = "8"
' <<<"$BASE")
printf '%s' "$CONTROLLER_READY" | validate_evidence overlap controller-ready \
  1 7 100 42 "$NONCE" 0 >/dev/null
for mutation in \
  '.controller_epoch_before = null' \
  '.controller_epoch_after = null' \
  '.controller_epoch_after = "7"' \
  '.controller_epoch_after = "6"'
do
  if printf '%s' "$(jq "$mutation" <<<"$CONTROLLER_READY")" | \
    validate_evidence overlap controller-ready 1 7 100 42 "$NONCE" 0 \
    >/dev/null 2>&1
  then
    exit 1
  fi
done

DIRECTED=$(jq '
  .phase = "overlap" | .step = "directed-paths" |
  .affected_paths_expected = 2 | .affected_paths_passed = 2
' <<<"$BASE")
printf '%s' "$DIRECTED" | validate_evidence overlap directed-paths 1 7 100 \
  42 "$NONCE" 0 >/dev/null
for mutation in \
  '.affected_paths_expected = 0 | .affected_paths_passed = 0' \
  '.affected_paths_passed = 1'
do
  if printf '%s' "$(jq "$mutation" <<<"$DIRECTED")" | \
    validate_evidence overlap directed-paths 1 7 100 42 "$NONCE" 0 \
    >/dev/null 2>&1
  then
    exit 1
  fi
done

FLEET_POST=$(jq '
  .phase = "overlap" | .step = "fleet-post-gate" | .success_delta = "1"
' <<<"$BASE")
printf '%s' "$FLEET_POST" | validate_evidence overlap fleet-post-gate 1 7 \
  100 42 "$NONCE" 0 1 >/dev/null
if printf '%s' "$FLEET_POST" | validate_evidence overlap fleet-post-gate 1 7 \
  100 42 "$NONCE" 0 0 >/dev/null 2>&1
then
  exit 1
fi
printf '%s\n' "$FLEET_POST" >"$MOCK_EVIDENCE_FILE"
save_current_operation_evidence exact-success overlap fleet-post-gate 1 7 100 \
  30 evidence-success --target-success-delta 1
printf '%s\n' "$(jq '.success_delta = "0"' <<<"$FLEET_POST")" \
  >"$MOCK_EVIDENCE_FILE"
if save_current_operation_evidence wrong-success overlap fleet-post-gate 1 7 \
  100 30 evidence-success --target-success-delta 1 2>/dev/null
then
  exit 1
fi
printf '%s\n' "$BASE" >"$MOCK_EVIDENCE_FILE"
if printf '%s' "$(jq '.phase = "overlap"' <<<"$BASE")" | \
  validate_evidence overlap policy-binding 1 7 100 42 "$NONCE" 0 \
  >/dev/null 2>&1
then
  exit 1
fi

# Withdrawal is the only readiness exception, and even it remains a closed,
# zero-delta, exact-binding document.
WITHDRAWAL=$(jq '
  .phase = "withdrawal" | .step = "withdrawal" |
  .member_ordinal = null | .checkpoint_id = null |
  .required_remaining_seconds = 0 | .min_expiry_remaining_seconds = 0 |
  .ready_sources = 0 | .ready_controllers = 0 | .durable_ready = false |
  .fresh_reachable_voters = 0 | .agreeing_voters = 0 |
  .series_complete = false | .process_incarnation_set_binding = null
  | .withdrawal_state = "ready-traffic-and-durable-mutations-withdrawn"
' <<<"$BASE")
printf '%s' "$WITHDRAWAL" | validate_evidence withdrawal withdrawal null null \
  0 42 "$NONCE" 0 >/dev/null
for mutation in \
  '.withdrawal_state = "not-withdrawn"' \
  '.success_delta = "1"' \
  '.retained_delta = "1"' \
  '.affected_paths_expected = 1 | .affected_paths_passed = 1' \
  '.source_version_before = "1" | .source_version_after = "2"'
do
  if printf '%s' "$(jq "$mutation" <<<"$WITHDRAWAL")" | \
    validate_evidence withdrawal withdrawal null null 0 42 "$NONCE" 0 \
    >/dev/null 2>&1
  then
    exit 1
  fi
done
NEGATIVE=$(jq '
  .phase = "final" |
  .step = "old-chain-rejection" |
  .auth_or_trust_failure_delta = "2" |
  .affected_paths_expected = 2 |
  .affected_paths_passed = 2 |
  .probe_checkpoint_id = "7" |
  .probe_process_incarnation_set_binding = .process_incarnation_set_binding |
  .probe_receipt_count = 2 |
  .probe_receipt_set_binding =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
  .expected_member_auth_delta = "2" |
  .observed_member_auth_delta = "2" |
  .expected_campaign_auth_delta = "2" |
  .observed_campaign_auth_delta = "2"
' <<<"$BASE")
EXPECTED_PROBE_RECEIPT_COUNT=2
EXPECTED_MEMBER_AUTH_DELTA=2
EXPECTED_CAMPAIGN_AUTH_DELTA=2
printf '%s' "$NEGATIVE" | validate_evidence final old-chain-rejection 1 7 100 \
  42 "$NONCE" 2 >/dev/null
if printf '%s' "$(jq '.auth_or_trust_failure_delta = "3"' <<<"$NEGATIVE")" | \
  validate_evidence final old-chain-rejection 1 7 100 42 "$NONCE" 2 \
  >/dev/null 2>&1
then
  exit 1
fi
if printf '%s' "$(jq '.affected_paths_passed = 1' <<<"$NEGATIVE")" | \
  validate_evidence final old-chain-rejection 1 7 100 42 "$NONCE" 2 \
  >/dev/null 2>&1
then
  exit 1
fi

PROBE_OPERATION=41
PROBE_NONCE=$(printf 'f%.0s' {1..32})
PROBE_RECEIPT_BINDING="sha256:$(printf 'e%.0s' {1..64})"
PROBE_PROCESS_BINDING="sha256:$(printf 'd%.0s' {1..64})"
ACCOUNTING=$(jq \
  --arg operation "$PROBE_OPERATION" --arg nonce "$PROBE_NONCE" \
  --arg receipt "$PROBE_RECEIPT_BINDING" --arg process "$PROBE_PROCESS_BINDING" '
  .step = "negative-probe-accounting" |
  .referenced_probe_operation_id = $operation |
  .referenced_probe_operation_nonce = $nonce |
  .probe_receipt_set_binding = $receipt |
  .probe_receipt_count = 2 |
  .probe_checkpoint_id = "7" |
  .probe_process_incarnation_set_binding = $process |
  .process_incarnation_set_binding = $process |
  .critical_auth_alert_visible = true
' <<<"$NEGATIVE")
EXPECTED_REFERENCED_PROBE_OPERATION_ID=$PROBE_OPERATION
EXPECTED_REFERENCED_PROBE_OPERATION_NONCE=$PROBE_NONCE
EXPECTED_PROBE_RECEIPT_SET_BINDING=$PROBE_RECEIPT_BINDING
EXPECTED_PROBE_RECEIPT_COUNT=2
EXPECTED_PROBE_CHECKPOINT_ID=7
EXPECTED_PROBE_PROCESS_BINDING=$PROBE_PROCESS_BINDING
printf '%s' "$ACCOUNTING" | validate_evidence final negative-probe-accounting \
  1 7 100 42 "$NONCE" 2 >/dev/null
for mutation in \
  '.referenced_probe_operation_id = "40"' \
  '.referenced_probe_operation_nonce = "00000000000000000000000000000000"' \
  '.probe_receipt_set_binding = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  '.probe_receipt_count = 1' \
  '.probe_receipt_count = 3' \
  '.observed_member_auth_delta = "1"' \
  '.observed_campaign_auth_delta = "3"' \
  '.unaccounted_auth_delta = "1"' \
  '.reset_count = 1' \
  '.process_incarnation_changes = 1' \
  '.process_incarnation_set_binding = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  '.critical_auth_alert_visible = false' \
  '.auth_alert_silenced_or_inhibited = true'
do
  if printf '%s' "$(jq "$mutation" <<<"$ACCOUNTING")" | \
    validate_evidence final negative-probe-accounting 1 7 100 42 "$NONCE" 2 \
    >/dev/null 2>&1
  then
    exit 1
  fi
done
EXPECTED_AUTH_FAILURE_DELTA=0
EXPECTED_REFERENCED_PROBE_OPERATION_ID=null
EXPECTED_REFERENCED_PROBE_OPERATION_NONCE=null
EXPECTED_PROBE_RECEIPT_SET_BINDING=null
EXPECTED_PROBE_RECEIPT_COUNT=0
EXPECTED_PROBE_CHECKPOINT_ID=null
EXPECTED_PROBE_PROCESS_BINDING=null
EXPECTED_MEMBER_AUTH_DELTA=0
EXPECTED_CAMPAIGN_AUTH_DELTA=0

# The fleet-size formulas are closed and their exact certificate boundary is
# admitted; one second short is rejected before a publication can be called.
[[ $FORWARD_CAMPAIGN_SECONDS == 57600 ]]
[[ $FORWARD_CERTIFICATE_HORIZON_SECONDS == 80160 ]]
BOUNDARY3=$(jq \
  --argjson horizon "$FORWARD_CERTIFICATE_HORIZON_SECONDS" '
  .required_remaining_seconds = $horizon |
  .min_expiry_remaining_seconds = $horizon
' <<<"$BASE")
printf '%s' "$BOUNDARY3" | validate_evidence preflight policy-binding 1 7 \
  "$FORWARD_CERTIFICATE_HORIZON_SECONDS" 42 "$NONCE" 0 >/dev/null
if printf '%s' "$(jq '.min_expiry_remaining_seconds -= 1' <<<"$BOUNDARY3")" | \
  validate_evidence preflight policy-binding 1 7 \
    "$FORWARD_CERTIFICATE_HORIZON_SECONDS" 42 "$NONCE" 0 >/dev/null 2>&1
then
  exit 1
fi

EXPECTED_MEMBERS=5
ROLLBACK_BUDGET_SECONDS=33560
HARD_SPAN_SECONDS=34880
OVERLAP_WAIT_SECONDS=34910
LEASE_TTL_SECONDS=34940
FORWARD_CAMPAIGN_SECONDS=91880
FORWARD_CERTIFICATE_HORIZON_SECONDS=126760
BOUNDARY5=$(jq \
  --argjson rollback "$ROLLBACK_BUDGET_SECONDS" \
  --argjson hard "$HARD_SPAN_SECONDS" \
  --argjson forward "$FORWARD_CAMPAIGN_SECONDS" \
  --argjson horizon "$FORWARD_CERTIFICATE_HORIZON_SECONDS" '
  .expected_members = 5 | .ready_sources = 5 | .ready_controllers = 5 |
  .fresh_reachable_voters = 3 | .agreeing_voters = 3 | .required_quorum = 3 |
  .rollback_budget_seconds = $rollback | .hard_span_seconds = $hard |
  .forward_campaign_seconds = $forward |
  .forward_certificate_horizon_seconds = $horizon |
  .required_remaining_seconds = $horizon |
  .min_expiry_remaining_seconds = $horizon
' <<<"$BASE")
printf '%s' "$BOUNDARY5" | validate_evidence preflight policy-binding 1 7 \
  "$FORWARD_CERTIFICATE_HORIZON_SECONDS" 42 "$NONCE" 0 >/dev/null
if printf '%s' "$(jq '.min_expiry_remaining_seconds -= 1' <<<"$BOUNDARY5")" | \
  validate_evidence preflight policy-binding 1 7 \
    "$FORWARD_CERTIFICATE_HORIZON_SECONDS" 42 "$NONCE" 0 >/dev/null 2>&1
then
  exit 1
fi
EXPECTED_MEMBERS=3
ROLLBACK_BUDGET_SECONDS=21240
HARD_SPAN_SECONDS=22560
OVERLAP_WAIT_SECONDS=22590
LEASE_TTL_SECONDS=22620
FORWARD_CAMPAIGN_SECONDS=57600
FORWARD_CERTIFICATE_HORIZON_SECONDS=80160

# The freshness clock is sampled after bounded capture. The fake clock refuses
# to answer until a delayed producer marks capture completion, then exercises
# both inclusive boundaries and the two adjacent rejected seconds.
CLOCK_BIN="$SCRATCH/fake-clock"
mkdir -m 0700 "$CLOCK_BIN"
cat >"$CLOCK_BIN/date" <<'FAKE_DATE'
#!/usr/bin/env bash
set -eu
[[ ${1:-} == -u && ${2:-} == +%s ]] || exit 64
if [[ ${REQUIRE_CAPTURE_MARKER:-0} == 1 ]]; then
  [[ -e ${CLOCK_MARKER:?} ]] || exit 88
fi
printf '%s\n' "${FAKE_NOW_EPOCH:?}"
FAKE_DATE
chmod 0700 "$CLOCK_BIN/date"
FAKE_NOW_EPOCH=1893456000
FAKE_BASE=$(jq --arg timestamp '2030-01-01T00:00:00Z' \
  '.utc_timestamp = $timestamp' <<<"$BASE")
CLOCK_MARKER="$SCRATCH/capture-complete"
rm -f "$CLOCK_MARKER"
{
  sleep 1
  : >"$CLOCK_MARKER"
  printf '%s' "$FAKE_BASE"
} | PATH="$CLOCK_BIN:$PATH" FAKE_NOW_EPOCH=$FAKE_NOW_EPOCH \
  REQUIRE_CAPTURE_MARKER=1 CLOCK_MARKER="$CLOCK_MARKER" \
  validate_evidence preflight policy-binding 1 7 100 42 "$NONCE" 0 >/dev/null
for offset in -30 5; do
  boundary_timestamp=$(date -u -d "@$((FAKE_NOW_EPOCH + offset))" \
    +%Y-%m-%dT%H:%M:%SZ)
  printf '%s' "$(jq --arg timestamp "$boundary_timestamp" \
    '.utc_timestamp = $timestamp' <<<"$BASE")" | \
    PATH="$CLOCK_BIN:$PATH" FAKE_NOW_EPOCH=$FAKE_NOW_EPOCH \
    validate_evidence preflight policy-binding 1 7 100 42 "$NONCE" 0 \
    >/dev/null
done
for offset in -31 6; do
  boundary_timestamp=$(date -u -d "@$((FAKE_NOW_EPOCH + offset))" \
    +%Y-%m-%dT%H:%M:%SZ)
  if printf '%s' "$(jq --arg timestamp "$boundary_timestamp" \
    '.utc_timestamp = $timestamp' <<<"$BASE")" | \
    PATH="$CLOCK_BIN:$PATH" FAKE_NOW_EPOCH=$FAKE_NOW_EPOCH \
    validate_evidence preflight policy-binding 1 7 100 42 "$NONCE" 0 \
    >/dev/null 2>&1
  then
    exit 1
  fi
done

# No-replace publication admits exactly one concurrent writer and never changes
# a pre-existing destination.
PUBLISH="$SCRATCH/publish"
mkdir -m 0700 "$PUBLISH"
printf '%s\n' first >"$PUBLISH/a"
printf '%s\n' second >"$PUBLISH/b"
chmod 0600 "$PUBLISH/a" "$PUBLISH/b"
EVIDENCE_DIR=$PUBLISH
set +e
durable_publish_evidence "$PUBLISH/a" "$PUBLISH/result" & first_pid=$!
durable_publish_evidence "$PUBLISH/b" "$PUBLISH/result" & second_pid=$!
wait "$first_pid"; first_status=$?
wait "$second_pid"; second_status=$?
set -e
publish_successes=0
if ((first_status == 0)); then publish_successes=$((publish_successes + 1)); fi
if ((second_status == 0)); then publish_successes=$((publish_successes + 1)); fi
[[ $publish_successes == 1 ]]
[[ $(<"$PUBLISH/result") == first || $(<"$PUBLISH/result") == second ]]
printf '%s\n' preserved >"$PUBLISH/existing"
printf '%s\n' replacement >"$PUBLISH/replacement"
chmod 0600 "$PUBLISH/existing" "$PUBLISH/replacement"
if durable_publish_evidence "$PUBLISH/replacement" "$PUBLISH/existing"; then
  exit 1
fi
[[ $(<"$PUBLISH/existing") == preserved ]]

# Inject failure into the first directory fsync, after the atomic link. The
# publisher must surface failure; campaign completion may not trust the linked
# artifact merely because its name is visible.
mkdir -m 0700 "$SCRATCH/fail-bin"
REAL_PYTHON=$(command -v python3)
export REAL_PYTHON
cat >"$SCRATCH/fail-bin/python3" <<'PYTHON_WRAPPER'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} != - ]]; then
  exec "${REAL_PYTHON:?}" "$@"
fi
shift
exec "${REAL_PYTHON:?}" -c '
import os
import sys

program = sys.stdin.read()
real_fsync = os.fsync
fsync_calls = 0

def injected_fsync(fd):
    global fsync_calls
    fsync_calls += 1
    if fsync_calls == 2:
        raise OSError(5, "injected directory fsync failure")
    return real_fsync(fd)

os.fsync = injected_fsync
exec(compile(program, "<durable-publisher>", "exec"))
' "$@"
PYTHON_WRAPPER
chmod 0700 "$SCRATCH/fail-bin/python3"
printf '%s\n' sync-failure >"$PUBLISH/sync-source"
chmod 0600 "$PUBLISH/sync-source"
if PATH="$SCRATCH/fail-bin:$PATH" durable_publish_evidence \
  "$PUBLISH/sync-source" "$PUBLISH/sync-result"
then
  exit 1
fi
[[ -e $PUBLISH/sync-result ]]
[[ $(<"$PUBLISH/sync-result") == sync-failure ]]

# Evidence staging failure occurs after, and cannot repeat, withdrawal. The
# child deliberately emits a prohibited secret on stderr; only fixed text may
# escape the wrapper.
EVIDENCE_DIR=/proc
WITHDRAWAL_ATTEMPTED=0
rm -f "$MOCK_ACTION_LOG" "$MOCK_WITHDRAWAL_STATE"
if withdraw_serving 2>"$SCRATCH/withdraw-diagnostic"; then
  withdraw_status=0
else
  withdraw_status=$?
fi
[[ $withdraw_status != 0 && $WITHDRAWAL_ATTEMPTED == 1 ]]
[[ $(wc -l <"$MOCK_ACTION_LOG") == 1 ]]
if grep -q 'SECRET\|/var/run\|spiffe' "$SCRATCH/withdraw-diagnostic"; then
  exit 1
fi
grep -q '^rotation campaign: withdrawal evidence unavailable$' \
  "$SCRATCH/withdraw-diagnostic"
if withdraw_serving 2>/dev/null; then
  exit 1
fi
[[ $(wc -l <"$MOCK_ACTION_LOG") == 1 ]]

# Simulate ENOSPC independently of directory permissions: staging fails after
# the action, and the action still occurs exactly once.
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$SCRATCH/fail-bin/mktemp"
chmod 0700 "$SCRATCH/fail-bin/mktemp"
EVIDENCE_DIR="$EVIDENCE_ROOT/$CAMPAIGN_ID"
WITHDRAWAL_ATTEMPTED=0
rm -f "$MOCK_ACTION_LOG" "$MOCK_WITHDRAWAL_STATE"
if PATH="$SCRATCH/fail-bin:$PATH" withdraw_serving \
  2>"$SCRATCH/enospc-diagnostic"
then
  enospc_status=0
else
  enospc_status=$?
fi
[[ $enospc_status != 0 && $WITHDRAWAL_ATTEMPTED == 1 ]]
if [[ ! -e $MOCK_ACTION_LOG ]]; then
  command cat "$SCRATCH/enospc-diagnostic" >&2
  exit 1
fi
[[ $(wc -l <"$MOCK_ACTION_LOG") == 1 ]]
if grep -q 'SECRET\|/var/run\|spiffe' "$SCRATCH/enospc-diagnostic"; then
  exit 1
fi

# State-operation allocation failure also cannot suppress the dedicated
# withdrawal-only command.
EVIDENCE_DIR="$EVIDENCE_ROOT/$CAMPAIGN_ID"
WITHDRAWAL_ATTEMPTED=0
rm -f "$MOCK_ACTION_LOG" "$MOCK_WITHDRAWAL_STATE"
export MOCK_ACTION_INVOCATION_LOG="$SCRATCH/allocator-invocations"
rm -f "$MOCK_ACTION_INVOCATION_LOG"
export MOCK_FAIL_ALLOC=1
if withdraw_serving 2>"$SCRATCH/allocator-diagnostic"; then
  allocator_status=0
else
  allocator_status=$?
fi
unset MOCK_FAIL_ALLOC
[[ $allocator_status != 0 && $WITHDRAWAL_ATTEMPTED == 1 ]]
[[ $(wc -l <"$MOCK_ACTION_LOG") == 1 ]]
[[ $(<"$MOCK_ACTION_INVOCATION_LOG") == emergency-campaign-a-7 ]]
unset MOCK_ACTION_INVOCATION_LOG

# A committed action whose raw response status is 76 is still ambiguous. It is
# reconciled by authoritative readback and produces evidence once; the raw
# status cannot masquerade as the separate pre-action-renewal result.
RESPONSE_ROOT="$SCRATCH/withdraw-response-loss"
mkdir -m 0700 "$RESPONSE_ROOT"
(
  export MOCK_ACTION_LOG="$RESPONSE_ROOT/effective"
  export MOCK_ACTION_INVOCATION_LOG="$RESPONSE_ROOT/invocations"
  export MOCK_WITHDRAWAL_STATE="$RESPONSE_ROOT/state"
  export MOCK_OUTCOME_LOG="$RESPONSE_ROOT/readbacks"
  export MOCK_WITHDRAWAL_RESPONSE_STATUS=76
  WITHDRAWAL_ATTEMPTED=0
  WITHDRAWAL_ACTION_STARTED=0
  WITHDRAWAL_ACTION_COMMITTED=0
  WITHDRAWAL_ACTION_DEADLINE_EPOCH=0
  save_current_operation_evidence() {
    printf '%s\n' evidence >>"$RESPONSE_ROOT/evidence"
    return 0
  }
  withdraw_serving
  [[ $WITHDRAWAL_ACTION_STARTED == 1 ]]
  [[ $WITHDRAWAL_ACTION_COMMITTED == 1 ]]
  [[ $WITHDRAWAL_ATTEMPT_RESULT == action-returned ]]
  [[ $WITHDRAWAL_ACTION_STATUS == 76 ]]
)
[[ $(wc -l <"$RESPONSE_ROOT/effective") == 1 ]]
[[ $(wc -l <"$RESPONSE_ROOT/invocations") == 1 ]]
[[ $(wc -l <"$RESPONSE_ROOT/readbacks") == 1 ]]
[[ $(wc -l <"$RESPONSE_ROOT/evidence") == 1 ]]

# An action status 76 that authoritative readback reports as uncommitted must
# retry the same durable key. The retry also returns 76 after committing; its
# readback proves one effective action and permits one evidence document.
UNCOMMITTED_ROOT="$SCRATCH/withdraw-uncommitted-76"
mkdir -m 0700 "$UNCOMMITTED_ROOT"
(
  export MOCK_ACTION_LOG="$UNCOMMITTED_ROOT/effective"
  export MOCK_ACTION_INVOCATION_LOG="$UNCOMMITTED_ROOT/invocations"
  export MOCK_WITHDRAWAL_STATE="$UNCOMMITTED_ROOT/state"
  export MOCK_OUTCOME_LOG="$UNCOMMITTED_ROOT/readbacks"
  export MOCK_WITHDRAWAL_UNCOMMITTED_ONCE_STATUS=76
  export MOCK_WITHDRAWAL_UNCOMMITTED_ONCE_MARKER="$UNCOMMITTED_ROOT/first"
  export MOCK_WITHDRAWAL_RESPONSE_STATUS=76
  WITHDRAWAL_ATTEMPTED=0
  WITHDRAWAL_ACTION_STARTED=0
  WITHDRAWAL_ACTION_COMMITTED=0
  WITHDRAWAL_ACTION_DEADLINE_EPOCH=0
  save_current_operation_evidence() {
    printf '%s\n' evidence >>"$UNCOMMITTED_ROOT/evidence"
    return 0
  }
  withdraw_serving
  [[ $WITHDRAWAL_ACTION_STARTED == 1 ]]
  [[ $WITHDRAWAL_ACTION_COMMITTED == 1 ]]
  [[ $WITHDRAWAL_ATTEMPT_RESULT == action-returned ]]
  [[ $WITHDRAWAL_ACTION_STATUS == 76 ]]
)
[[ $(wc -l <"$UNCOMMITTED_ROOT/effective") == 1 ]]
[[ $(wc -l <"$UNCOMMITTED_ROOT/invocations") == 2 ]]
[[ $(wc -l <"$UNCOMMITTED_ROOT/readbacks") == 2 ]]
[[ $(sort -u "$UNCOMMITTED_ROOT/invocations" | wc -l) == 1 ]]
[[ $(wc -l <"$UNCOMMITTED_ROOT/evidence") == 1 ]]

# Lease-renewal failure is a proven pre-action outcome: no action, readback,
# or evidence is allowed.
RENEW_ROOT="$SCRATCH/withdraw-renew-failure"
mkdir -m 0700 "$RENEW_ROOT"
(
  export MOCK_ACTION_LOG="$RENEW_ROOT/effective"
  export MOCK_ACTION_INVOCATION_LOG="$RENEW_ROOT/invocations"
  export MOCK_WITHDRAWAL_STATE="$RENEW_ROOT/state"
  export MOCK_OUTCOME_LOG="$RENEW_ROOT/readbacks"
  export MOCK_FAIL_RENEW=1
  WITHDRAWAL_ATTEMPTED=0
  WITHDRAWAL_ACTION_STARTED=0
  WITHDRAWAL_ACTION_COMMITTED=0
  WITHDRAWAL_ACTION_DEADLINE_EPOCH=0
  save_current_operation_evidence() {
    printf '%s\n' evidence >>"$RENEW_ROOT/evidence"
    return 0
  }
  if withdraw_serving 2>/dev/null; then exit 1; fi
  [[ $WITHDRAWAL_ACTION_STARTED == 0 ]]
  [[ $WITHDRAWAL_ACTION_COMMITTED == 0 ]]
  [[ $WITHDRAWAL_ATTEMPT_RESULT == pre-action-renewal-failed ]]
  [[ $WITHDRAWAL_ACTION_STATUS == 0 ]]
)
[[ ! -e $RENEW_ROOT/effective ]]
[[ ! -e $RENEW_ROOT/invocations ]]
[[ ! -e $RENEW_ROOT/state ]]
[[ ! -e $RENEW_ROOT/readbacks ]]
[[ ! -e $RENEW_ROOT/evidence ]]

# Failed readback leaves the action outcome ambiguous. The bounded retry uses
# the identical durable key twice; the authority applies it effectively once
# and no evidence is claimed without committed readback.
READBACK_ROOT="$SCRATCH/withdraw-readback-failure"
mkdir -m 0700 "$READBACK_ROOT"
(
  export MOCK_ACTION_LOG="$READBACK_ROOT/effective"
  export MOCK_ACTION_INVOCATION_LOG="$READBACK_ROOT/invocations"
  export MOCK_WITHDRAWAL_STATE="$READBACK_ROOT/state"
  export MOCK_OUTCOME_LOG="$READBACK_ROOT/readbacks"
  export MOCK_FAIL_WITHDRAWAL_READBACK=1
  WITHDRAWAL_ATTEMPTED=0
  WITHDRAWAL_ACTION_STARTED=0
  WITHDRAWAL_ACTION_COMMITTED=0
  WITHDRAWAL_ACTION_DEADLINE_EPOCH=0
  save_current_operation_evidence() {
    printf '%s\n' evidence >>"$READBACK_ROOT/evidence"
    return 0
  }
  if withdraw_serving 2>/dev/null; then exit 1; fi
  [[ $WITHDRAWAL_ACTION_STARTED == 1 ]]
  [[ $WITHDRAWAL_ACTION_COMMITTED == 0 ]]
)
[[ $(wc -l <"$READBACK_ROOT/effective") == 1 ]]
[[ $(wc -l <"$READBACK_ROOT/invocations") == 2 ]]
[[ $(wc -l <"$READBACK_ROOT/readbacks") == 2 ]]
[[ $(sort -u "$READBACK_ROOT/invocations" | wc -l) == 1 ]]
[[ ! -e $READBACK_ROOT/evidence ]]

if run_cnfctl 30 mock-stderr >/dev/null 2>"$SCRATCH/stderr-diagnostic"; then
  stderr_status=0
else
  stderr_status=$?
fi
[[ $stderr_status == 7 ]]
[[ ! -s $SCRATCH/stderr-diagnostic ]]

# A grandchild that inherits stdout cannot hold a bounded capture open after
# the command shell exits. The reader has its own deadline inside the declared
# seven-second operation bound.
export MOCK_INHERITED_PID_FILE="$SCRATCH/inherited-stdout-pid"
capture_started=$(date -u +%s)
set +e
capture_cnfctl_bounded unleased 7 64 mock-inherited-stdout
inherited_status=$?
set -e
capture_elapsed=$(( $(date -u +%s) - capture_started ))
[[ $inherited_status == 74 ]]
((capture_elapsed <= 7))
if [[ -s $MOCK_INHERITED_PID_FILE ]]; then
  kill -KILL "$(<"$MOCK_INHERITED_PID_FILE")" 2>/dev/null || true
fi

# A release response can be lost after the authority commits it. Idempotent
# readback closes that outcome, clears the local token, and a second call cannot
# issue another release.
export MOCK_LEASE_LOG="$SCRATCH/lease-lifecycle"
export MOCK_RELEASED_FILE="$SCRATCH/released"
: >"$MOCK_LEASE_LOG"
rm -f "$MOCK_RELEASED_FILE"
export MOCK_RELEASE_RESPONSE_LOSS=1
LEASE_TOKEN=$(printf 'A%.0s' {1..43})
LEASE_ACQUIRED=1
release_exclusive_lease recovery
unset MOCK_RELEASE_RESPONSE_LOSS
[[ $LEASE_ACQUIRED == 0 ]]
[[ $(grep -c '^release$' "$MOCK_LEASE_LOG") == 1 ]]
[[ $(grep -c '^readback$' "$MOCK_LEASE_LOG") == 1 ]]
release_exclusive_lease recovery
[[ $(grep -c '^release$' "$MOCK_LEASE_LOG") == 1 ]]

# A response-lost rollback transition mutates once. Resume reads the durable
# terminal transition and performs only the semantic readback gate.
ROLLBACK_ONCE_LOG="$SCRATCH/rollback-once"
: >"$ROLLBACK_ONCE_LOG"
(
  MEMBERS=(0)
  ACTIVE_DEADLINE_EPOCH=$(( $(date -u +%s) + 1000 ))
  CURRENT_CHECKPOINT_ID=7
  CURRENT_CHECKPOINT="$STATE_DIR/checkpoint-7.bin"
  next_checkpoint() {
    CURRENT_CHECKPOINT_ID=7
    CURRENT_CHECKPOINT="$STATE_DIR/checkpoint-7.bin"
  }
  capture_scalar() {
    if [[ -e $SCRATCH/rollback-transition-complete ]]; then
      printf '%s' complete
    else
      printf '%s' apply
    fi
  }
  remaining_rollback_seconds() { printf '%s' 900; }
  validate_publication_material() { return 0; }
  post_member_gate() { return 0; }
  save_evidence() {
    local step=$3
    case "$step" in
      rollback-authorize-and-publish)
        printf '%s\n' mutation >>"$ROLLBACK_ONCE_LOG"
        : >"$SCRATCH/rollback-transition-complete"
        return 1
        ;;
      rollback-transition-readback)
        printf '%s\n' readback >>"$ROLLBACK_ONCE_LOG"
        return 0
        ;;
      *) return 0 ;;
    esac
  }
  set +e
  rollback_member rollback-before-removal 0 previous
  first_rollback_status=$?
  set -e
  [[ $first_rollback_status != 0 ]]
  rollback_member rollback-before-removal 0 previous
)
[[ $(grep -c '^mutation$' "$ROLLBACK_ONCE_LOG") == 1 ]]
[[ $(grep -c '^readback$' "$ROLLBACK_ONCE_LOG") == 1 ]]

# Recovery is one state machine per invocation, and a status-0 incomplete EXIT
# still recovers exactly once and exits nonzero.
RECOVERY_ONCE_LOG="$SCRATCH/recovery-once"
: >"$RECOVERY_ONCE_LOG"
(
  RECOVERY_ACTIVE=0 RECOVERY_FINISHED=0 RECOVERY_ATTEMPTED=0
  COMPLETION_RECORDED=0 LEASE_ACQUIRED=0 WITHDRAWAL_ATTEMPTED=0
  abort_campaign() {
    printf '%s\n' abort >>"$RECOVERY_ONCE_LOG"
    return 0
  }
  recover_failure first
  if recover_failure second; then exit 1; fi
)
[[ $(grep -c '^abort$' "$RECOVERY_ONCE_LOG") == 1 ]]

# The secondary-signal trap is active before every recovery-entry mutation.
# A signal at each exposed boundary is deferred while rollback and withdrawal
# remain single-shot.
for recovery_boundary in trap-installed attempted active; do
  BOUNDARY_LOG="$SCRATCH/recovery-boundary-$recovery_boundary"
  : >"$BOUNDARY_LOG"
  (
    RECOVERY_ACTIVE=0 RECOVERY_FINISHED=0 RECOVERY_ATTEMPTED=0
    COMPLETION_RECORDED=0 LEASE_ACQUIRED=0 WITHDRAWAL_ATTEMPTED=0
    SECONDARY_SIGNAL=0
    recovery_entry_boundary() {
      printf 'boundary:%s\n' "$1" >>"$BOUNDARY_LOG"
      if [[ $1 == "$recovery_boundary" ]]; then
        kill -TERM "$BASHPID"
      fi
    }
    abort_campaign() {
      printf '%s\n' abort >>"$BOUNDARY_LOG"
      return 1
    }
    withdraw_serving() {
      WITHDRAWAL_ATTEMPTED=1
      printf '%s\n' withdraw >>"$BOUNDARY_LOG"
      return 0
    }
    recover_failure "boundary-$recovery_boundary"
    [[ $SECONDARY_SIGNAL == 1 ]]
  ) 2>/dev/null
  [[ $(grep -c '^abort$' "$BOUNDARY_LOG") == 1 ]]
  [[ $(grep -c '^withdraw$' "$BOUNDARY_LOG") == 1 ]]
done

INCOMPLETE_LOG="$SCRATCH/incomplete-zero"
set +e
(
  CAMPAIGN_COMPLETE=0 EXIT_WITHOUT_RECOVERY=0 RECOVERY_FINISHED=0
  LAST_ERROR_STATUS=0 LEASE_TOKEN=secret
  recover_failure() {
    printf '%s\n' recovered >>"$INCOMPLETE_LOG"
    RECOVERY_FINISHED=1
    return 0
  }
  trap on_exit EXIT
  exit 0
)
incomplete_status=$?
set -e
[[ $incomplete_status != 0 ]]
[[ $(grep -c '^recovered$' "$INCOMPLETE_LOG") == 1 ]]

# An unexpected exit and a second signal during recovery both finish the
# fail-safe withdrawal instead of terminating the recovery handler.
RECOVERY_LOG="$SCRATCH/recovery"
(
  RECOVERY_ACTIVE=0 RECOVERY_FINISHED=0 CAMPAIGN_COMPLETE=0
  RECOVERY_ATTEMPTED=0 COMPLETION_RECORDED=0 LEASE_ACQUIRED=0
  WITHDRAWAL_ATTEMPTED=0 ACTIVE_DEADLINE_EPOCH=0
  abort_campaign() { return 1; }
  withdraw_serving() {
    printf '%s\n' unexpected-withdraw >>"$RECOVERY_LOG"
    return 0
  }
  trap on_error ERR
  trap on_exit EXIT
  false
) || true
grep -q '^unexpected-withdraw$' "$RECOVERY_LOG"

(
  RECOVERY_ACTIVE=0 RECOVERY_FINISHED=0 CAMPAIGN_COMPLETE=0
  RECOVERY_ATTEMPTED=0 COMPLETION_RECORDED=0 LEASE_ACQUIRED=0
  WITHDRAWAL_ATTEMPTED=0 ACTIVE_DEADLINE_EPOCH=0
  abort_campaign() {
    kill -TERM "$BASHPID"
    return 1
  }
  on_secondary_signal() {
    printf '%s\n' secondary-signal >>"$RECOVERY_LOG"
    SECONDARY_SIGNAL=1
  }
  withdraw_serving() {
    printf '%s\n' signal-withdraw >>"$RECOVERY_LOG"
    return 0
  }
  trap on_error ERR
  trap on_exit EXIT
  trap 'on_signal TERM 143' TERM
  false
) 2>"$SCRATCH/recovery-diagnostic" || true
grep -q '^secondary-signal$' "$RECOVERY_LOG"
grep -q '^signal-withdraw$' "$RECOVERY_LOG"
grep -q '^rotation campaign: recovery completed after deferred signal$' \
  "$SCRATCH/recovery-diagnostic"

printf '%s\n' 'consensus rotation runbook adversarial tests: ok'
