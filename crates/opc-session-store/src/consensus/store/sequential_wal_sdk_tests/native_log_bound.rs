//! Real leader proposals retain one idempotent response across log reclamation.

use super::*;
use crate::consensus::{SessionConsensusCommand, SessionConsensusRequestId, SessionMutationIntent};
use opc_consensus::DURABLE_OPENRAFT_PROFILE;

const WAIT: Duration = Duration::from_secs(300);

async fn settled_prefix(store: &ConsensusSessionStore, minimum_snapshot: u64) {
    let wal = store.inner.private_wal.as_ref().unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            let selected = wal
                .with_native_read(|state| Ok(state.current_snapshot()))
                .unwrap();
            if let Some(snapshot) = selected {
                let cut = snapshot.0.last_log_id.unwrap();
                if cut.index >= minimum_snapshot {
                    let expected = cut.index - DURABLE_OPENRAFT_PROFILE.retained_logs;
                    let state = wal.native_log_state().unwrap();
                    let (count, first, purged, _) = wal.native_log_inventory_for_test().unwrap();
                    if purged == Some(expected) {
                        assert_eq!(state.last_purged_log_id.unwrap().index, expected);
                        assert_eq!(first, Some(expected + 1));
                        assert_eq!(count as u64, state.last_log_id.unwrap().index - expected);
                        assert!(
                            count as u64 <= 262_144,
                            "normal leader run stays below the provisional window"
                        );
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("automatic snapshot and engine purge settle");
}

async fn leader_cycles(cycles: u64) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let root =
        std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").expect("strict snapshot root required");
    let snapshots = tempfile::tempdir_in(root).unwrap();
    let mut fleet = Fleet::new_native("native-leader-log-retention");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let started = Instant::now();
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let store = &fleet.stores[leader];
        let command = SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: store.inner.storage_identity,
            request_id: SessionConsensusRequestId::from_bytes([0xC9; 16]),
            logical_time: store.inner.clock.now_utc(),
            intent: SessionMutationIntent::Authorized {
                origin: store.inner.local_node_id,
                authority_identity: store.inner.storage_identity,
                mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
            },
        };
        // Feed actual leader proposals. Public status deduplication would avoid
        // appending and could not test the retained-log lifetime limit.
        let first = store
            .inner
            .raft
            .client_write(command.clone())
            .await
            .unwrap();
        assert!(first.data.result.is_ok());
        let response = serde_json::to_vec(&first.data).unwrap();
        let business_digest = store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .with_native_read(|state| Ok(state.application_digest()))
            .unwrap();
        let total = cycles * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot;
        let mut last = first.log_id;
        for start in (0..total).step_by(DURABLE_OPENRAFT_PROFILE.max_payload_entries as usize) {
            let count = (total - start).min(DURABLE_OPENRAFT_PROFILE.max_payload_entries);
            let replies = tokio::time::timeout(
                WAIT,
                join_all((0..count).map(|_| store.inner.raft.client_write(command.clone()))),
            )
            .await
            .unwrap();
            for reply in replies {
                let reply = reply.unwrap();
                assert_eq!(
                    serde_json::to_vec(&reply.data).unwrap(),
                    response,
                    "one original idempotent response survives every proposal"
                );
                assert!(reply.log_id.index > last.index);
                last = reply.log_id;
            }
            assert_eq!(
                store
                    .inner
                    .private_wal
                    .as_ref()
                    .unwrap()
                    .with_native_read(|state| Ok(state.application_digest()))
                    .unwrap(),
                business_digest,
                "re-proposals never bind fresh business rows"
            );
            if (start + count) % DURABLE_OPENRAFT_PROFILE.logs_per_snapshot == 0 {
                let minimum = last
                    .index
                    .saturating_sub(DURABLE_OPENRAFT_PROFILE.logs_per_snapshot);
                for voter in &fleet.stores {
                    settled_prefix(voter, minimum).await;
                }
            }
        }
        assert!(last.index >= total + first.log_id.index);
        for voter in &fleet.stores {
            voter
                .inner
                .raft
                .wait(Some(WAIT))
                .applied_index_at_least(Some(last.index), "final leader proposal applied")
                .await
                .unwrap();
            settled_prefix(
                voter,
                last.index - DURABLE_OPENRAFT_PROFILE.logs_per_snapshot,
            )
            .await;
        }
        eprintln!(
            "NATIVE_LEADER_LOG_BOUND proposals={total} last={} voters=3 elapsed_s={:.3}",
            last.index,
            started.elapsed().as_secs_f64()
        );
        (command, response, last.index)
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    let (command, response, last) = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let reply = fleet.stores[leader]
            .inner
            .raft
            .client_write(command)
            .await
            .unwrap();
        assert!(reply.log_id.index > last);
        assert_eq!(serde_json::to_vec(&reply.data).unwrap(), response);
        for voter in &fleet.stores {
            voter
                .inner
                .raft
                .wait(Some(WAIT))
                .applied_index_at_least(
                    Some(reply.log_id.index),
                    "reopened leader proposal applied",
                )
                .await
                .unwrap();
            settled_prefix(voter, last - DURABLE_OPENRAFT_PROFILE.logs_per_snapshot).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_leader_three_cycles_reproposes_one_idempotent_request_and_reopens() {
    leader_cycles(3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_leader_full_bound_reproposes_one_idempotent_request_and_reopens() {
    let bound = crate::consensus::native::log::MAX_RETAINED_LOG_ENTRIES as u64;
    leader_cycles(bound / DURABLE_OPENRAFT_PROFILE.logs_per_snapshot + 2).await;
}
