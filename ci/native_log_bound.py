"""Full-size native log proofs run at test O1 with debug checks still enabled.

Keep exact names: neither the million-entry bound nor the default three-cycle
regressions changes when the expensive proofs run in separate test processes.
"""

TESTS = (
    "consensus::store::sequential_wal_sdk_tests::native_log_bound::"
    "native_leader_full_bound_reproposes_one_idempotent_request_and_reopens",
    "consensus::storage::tests::native_log_retained_bound::"
    "native_log_retained_bound_survives_snapshot_purge_and_restart",
    "consensus::storage::tests::native_log_retained_bound::"
    "native_log_retained_bound_survives_snapshot_purge_and_restart_async",
)

# One expensive proof per hosted runner. Keep these separate from the ordinary
# matrices: their O1 compilation alone exceeded the old heavy/egress headroom.
CORE_SHARDS = tuple(f"native-log-{index}" for index in range(len(TESTS)))
EGRESS_SHARDS = tuple(range(4, 4 + len(TESTS)))
