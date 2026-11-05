"""Full-size native persistence proofs retain explicit checked test profiles.

Keep exact names: the million-entry log and 131,073-roster history boundaries
and the ordinary smoke regressions stay fixed in separate test processes.
"""

ROSTER_HISTORY_TEST = (
    "consensus::native::generation::catalog::tests::roster_tests::"
    "native_roster_completed_history_exceeds_old_capacity_and_cold_reopens"
)
ROSTER_HISTORY_SHARD = "roster-history"

LONG_JOURNAL_TEST = (
    "sqlite::consensus::tests::native::basis::mixed_journals::"
    "native_journal_pressure_large_mixed_cold_replay_rebases_before_exhaustion"
)

TESTS = (
    "consensus::store::sequential_wal_sdk_tests::native_log_bound::"
    "native_leader_full_bound_reproposes_one_idempotent_request_and_reopens",
    "consensus::storage::tests::native_log_retained_bound::"
    "native_log_retained_bound_survives_snapshot_purge_and_restart",
    "consensus::storage::tests::native_log_retained_bound::"
    "native_log_retained_bound_survives_snapshot_purge_and_restart_async",
    "consensus::native::lease_deferral_tests::"
    "native_lease_deferral_lost_journal_cannot_pin_the_full_retained_window",
    "sqlite::consensus::tests::lease_deferral::"
    "sqlite_lease_deferral_lost_journal_cannot_pin_the_full_retained_window",
    "consensus::native::lease_deferral_tests::"
    "native_lease_deferral_grouped_retirement_validates_a_surviving_resolution",
    "consensus::native::lease_deferral_tests::"
    "native_lease_deferral_retirement_rejects_unexpired_removed_and_surviving_receipts",
    "consensus::native::lease_deferral_tests::"
    "native_lease_deferral_full_closed_epoch_retires_after_completion_or_abandonment",
    "consensus::native::lease_deferral_tests::"
    "review_cohort_native_resolution_retirement_grouped",
    "consensus::native::lease_deferral_tests::"
    "review_cohort_native_resolution_retirement_separate",
    "consensus::native::generation::catalog::tests::lease_deferral_tests::"
    "native_catalog_lease_deferral_retirement_grouped_apply_and_checkpoint",
    "consensus::native::generation::catalog::tests::lease_deferral_tests::"
    "native_catalog_lease_deferral_retirement_separate_apply_one_checkpoint",
    "consensus::native::generation::catalog::tests::lease_deferral_tests::"
    "native_catalog_lease_deferral_retirement_separate_checkpoints",
    "consensus::native::generation::catalog::tests::lease_deferral_tests::"
    "native_catalog_lease_deferral_retirement_rejects_false_deletion_witnesses",
    ROSTER_HISTORY_TEST,
    "consensus::native::generation::catalog::tests::retention_tests::"
    "native_notification_retention_passes_original_lifetime_limit_and_reopens",
    "consensus::native::generation::catalog::tests::retention_tests::"
    "native_key_retention_passes_original_lifetime_limit_and_reopens",
    LONG_JOURNAL_TEST,
)

CORE_TESTS = TESTS

# One expensive proof per hosted runner. Keep these separate from the ordinary
# matrices: their compilation alone exceeded the old heavy/egress headroom.
def core_shards() -> tuple[str, ...]:
    shards = []
    log_index = 0
    for name in CORE_TESTS:
        if name == ROSTER_HISTORY_TEST:
            shards.append(ROSTER_HISTORY_SHARD)
        else:
            shards.append(f"native-log-{log_index}")
            log_index += 1
    return tuple(shards)


CORE_SHARDS = core_shards()
EGRESS_SHARDS = tuple(range(4, 4 + len(TESTS)))


def profile_env(name: str) -> dict[str, str]:
    """Select each proof's original optimization and enabled checks."""
    if name == LONG_JOURNAL_TEST:
        # The long replay fixture keeps its original unoptimized profile.
        return {"CARGO_PROFILE_TEST_OPT_LEVEL": "0"}
    if name == ROSTER_HISTORY_TEST:
        return {
            "CARGO_PROFILE_TEST_OPT_LEVEL": "3",
            "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS": "true",
            "CARGO_PROFILE_TEST_OVERFLOW_CHECKS": "true",
        }
    return {"CARGO_PROFILE_TEST_OPT_LEVEL": "1"}
