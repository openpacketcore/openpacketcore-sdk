"""Full-size store history and native log proofs run at test O1 with debug checks still enabled.

These exact names keep the million-entry bound and live admission window intact.
The default three-cycle regressions retain their ordinary test profile.
"""

FULL_WINDOW_BUILDS = (
    "consensus::store::async_persistence::tests::log_admission::"
    "log_admission_full_window_blocked_build_durable",
    "consensus::store::async_persistence::tests::log_admission::"
    "log_admission_full_window_blocked_build_async",
)

FULL_WINDOW_TRANSFERS = (
    "consensus::store::async_persistence::tests::log_admission::"
    "log_admission_full_window_blocked_transfer_durable",
    "consensus::store::async_persistence::tests::log_admission::"
    "log_admission_full_window_blocked_transfer_async",
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
    *FULL_WINDOW_BUILDS,
    *FULL_WINDOW_TRANSFERS,
)

# One expensive proof per hosted runner. Keep these separate from the ordinary
# matrices: their O1 compilation alone exceeded the old heavy/egress headroom.
CORE_SHARDS = tuple(f"native-log-{index}" for index in range(len(TESTS)))
EGRESS_SHARDS = tuple(range(4, 4 + len(TESTS)))
