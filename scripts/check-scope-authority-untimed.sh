#!/usr/bin/env bash
# Regression gate for the removed timed scope-authority contract.
set -euo pipefail
cd "$(dirname "$0")/.."

# Ordinary session leases, protocol lifetimes and RPC waiting budgets remain
# independent APIs. Match the removed scope vocabulary, not those mechanisms.
forbidden='ScopeClockBounds|Scope(Lease|Authority)Clock|SCOPE_(RENEWAL_INTERVAL|FORWARDING_GRACE|CLOCK_GUARD)|ScopeGateClosed|ResumeSameExecution|Scope(Lease|Authority)Operation::(Acquire|Select|Renew|Release)|Scope(Lease|Authority)Error::(Expired|ClockUncertain)|is_live_at|renew_by|excluded_until'
if rg -n --glob '*.rs' "$forbidden" crates/opc-session-store/src crates/opc-session-store/tests; then
    printf '%s\n' 'removed timed scope authority reappeared' >&2
    exit 1
else
    scope_grep_status=$?
    [[ "$scope_grep_status" == 1 ]] || exit "$scope_grep_status"
fi

# Neither command/state codec nor the shared batch planner accepts apply time.
if rg -n '\bTimestamp\b|\bapply_time\b|\bScopeClock' \
    crates/opc-session-store/src/scope_authority.rs \
    crates/opc-session-store/src/scope_authority/state.rs \
    crates/opc-session-store/src/scope_authority/command.rs \
    crates/opc-session-store/src/scope_authority/profile.rs \
    crates/opc-session-store/src/scope_batch.rs \
    crates/opc-session-store/src/scope_batch/state.rs; then
    printf '%s\n' 'scope apply or authority encoding accepts a time input' >&2
    exit 1
else
    scope_grep_status=$?
    [[ "$scope_grep_status" == 1 ]] || exit "$scope_grep_status"
fi
printf '%s\n' 'untimed scope authority removal gate passed'
