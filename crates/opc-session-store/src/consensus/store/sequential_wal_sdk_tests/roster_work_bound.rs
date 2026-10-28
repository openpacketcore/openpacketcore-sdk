use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_work_history_snapshot_preserves_signed_seed() {
    assert_work_history_snapshot(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_work_history_snapshot_preserves_signed_seed() {
    assert_work_history_snapshot(false).await;
}

async fn assert_work_history_snapshot(native: bool) {
    use super::super::membership_tests::{
        roster_ingress_test_root, seed_roster_maintenance_work_history, MutableClock,
    };
    use std::str::FromStr;

    let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
    let start = opc_types::Timestamp::from_str("2025-01-01T00:00:00Z").unwrap();
    let clock = Arc::new(MutableClock::new(start));
    let mut fleet = Fleet::new_roster_production(
        "roster-work-history-snapshot",
        native,
        roster_ingress_test_root(),
    );
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let mut ticks = Vec::new();
        for voter in &fleet.stores {
            ticks.push(voter.schedule_roster_maintenance_ticks_for_test().await);
        }
        let leader = fleet
            .stores
            .iter()
            .find(|voter| voter.status().leader_id == Some(voter.status().node_id))
            .unwrap();
        // Small snapshot coverage isolates the persistence precondition. The
        // separate work comparison still requires both 1,800 and 18,000 rows.
        seed_roster_maintenance_work_history(leader, &fleet.stores, &clock, start, 20).await;
        for voter in &fleet.stores {
            assert_eq!(
                voter
                    .protected_roster_diagnostic_snapshot()
                    .retained_reservations,
                20
            );
        }
        drop(ticks);
    })
    .catch_unwind()
    .await;
    fleet.close_after_test(result).await;
}
