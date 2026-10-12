//! Exact native-log retention through automatic snapshot and purge cycles.
//! No product limit, snapshot interval, purge policy, or WAL limit is changed.

use super::*;
use crate::consensus::native::log::MAX_RETAINED_LOG_ENTRIES;
use crate::consensus::SessionRaft;
use crate::sqlite::consensus::wal::Wal;
use opc_consensus::engine::raft::{AppendEntriesRequest, AppendEntriesResponse};
use opc_consensus::engine::Vote;
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain, DURABLE_OPENRAFT_PROFILE};
use std::time::Instant;

const WAIT: Duration = Duration::from_secs(300);

pub(super) async fn open_engine(
    directory: &FixedRawReadStoreFixture,
    mode: SessionPersistenceMode,
) -> (SqliteSessionBackend, SessionRaft, Arc<Wal>, PathBuf) {
    let backend = SqliteSessionBackend::open(directory.path().join("retained-bound.sqlite"))
        .expect("open ordinary fixed native backend");
    let local = SessionConsensusNodeId::new(8).unwrap();
    let members = fixed_raw_read_members();
    let peers = members
        .iter()
        .copied()
        .filter(|node| *node != local)
        .map(|node| {
            (
                node,
                Arc::new(MembershipObservationProbePeer { node_id: node })
                    as Arc<dyn SessionConsensusPeer>,
            )
        })
        .collect();
    let network = SessionRaftNetworkFactory::try_new(identity(1), local, members.clone(), peers)
        .expect("ordinary fixed network");
    let (log, machine, _) = open_fixed_with_persistence_and_roster_attestation_root(
        &backend,
        SnapshotDirectory::from_path(directory.snapshot_path().join("retained-bound-snapshots")),
        identity(1),
        members.clone(),
        fixed_raw_read_bindings(&members),
        network.peer_directory(),
        PlacementResiliencePolicy::AllowReducedResilience,
        None,
        SnapshotIntegrityPolicy::FsVerity,
        mode,
    )
    .await
    .expect("ordinary fixed storage constructor");
    let wal = Arc::clone(
        machine
            .core
            .private_wal
            .as_ref()
            .expect("native WAL selected"),
    );
    assert!(wal.is_native());
    let mut config = durable_openraft_config(DurableOpenraftDomain::SessionState).unwrap();
    // The test supplies the leader's committed entries directly. Suppress only
    // campaigns while it waits for disk work; snapshot/purge/WAL policy stays
    // exactly the production profile and is executed by the real engine.
    config.enable_elect = false;
    assert_eq!(
        config.max_in_snapshot_log_to_keep,
        DURABLE_OPENRAFT_PROFILE.retained_logs
    );
    let hook_directory = snapshot_namespace_test_hook_directory(&machine._snapshot_directory_lease);
    let raft = SessionRaft::new(local, Arc::new(config), network, log, machine)
        .await
        .expect("open actual Raft engine");
    (backend, raft, wal, hook_directory)
}

fn append_request(start: u64, end: u64) -> AppendEntriesRequest<SessionRaftTypeConfig> {
    let entries = (start..end)
        .map(|index| {
            if index == 0 {
                fixed_initial_membership_entry()
            } else {
                blank_entry(index)
            }
        })
        .collect();
    AppendEntriesRequest {
        vote: Vote::new_committed(1, node_id()),
        prev_log_id: start.checked_sub(1).map(log_id),
        leader_commit: Some(log_id(end - 1)),
        entries,
    }
}

fn generation_bytes(directory: &FixedRawReadStoreFixture) -> u64 {
    std::fs::read_dir(directory.path().join("retained-bound.sqlite.native-wal"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "native")
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum()
}

fn assert_reclaimed_committed_coverage(wal: &Wal, end: u64, keep: u64) {
    let purged = end - keep - 1;
    // Once this row is absent, the admitted purge frontier covers an older
    // committed lineage by ordering. At the frontier and in retained rows,
    // equal indices still require the exact complete LogId.
    assert!(wal
        .async_covers_committed(&[log_id(purged - 1), log_id_with_term(0, purged - 1)])
        .unwrap());
    assert!(wal
        .async_covers_committed(&[log_id(purged), log_id(end - 1)])
        .unwrap());
    for uncovered in [
        log_id_with_term(0, purged),
        log_id_with_term(0, end - 1),
        log_id_with_term(2, purged - 1),
        log_id(end),
    ] {
        assert!(!wal.async_covers_committed(&[uncovered]).unwrap());
    }
}

async fn bounded_cycles(mode: SessionPersistenceMode, cycles: u64) {
    let started = Instant::now();
    let directory = FixedRawReadStoreFixture::new();
    let (backend, raft, wal, hook_directory) = open_engine(&directory, mode).await;
    let profile = DURABLE_OPENRAFT_PROFILE;
    let bound = MAX_RETAINED_LOG_ENTRIES as u64;
    assert_eq!(MAX_RETAINED_LOG_ENTRIES, 1_048_576);
    assert_eq!(profile.logs_per_snapshot, 4_096);
    assert_eq!(profile.retained_logs, 1_024);
    assert_eq!(profile.max_payload_entries, 64);
    assert_eq!(bound % profile.logs_per_snapshot, 0);
    let total = cycles * profile.logs_per_snapshot;
    let initial_bytes = generation_bytes(&directory);
    eprintln!("NATIVE_LOG_BOUND start mode={mode:?} entries={total} bound={bound} batch={} snapshot_every={} keep={}",
        profile.max_payload_entries, profile.logs_per_snapshot, profile.retained_logs);
    let mut snapshots = 0u64;
    let mut last_checkpoint = 0;
    let gate = Arc::new(SnapshotArtifactGate::new());
    let _return_gate = FixedSnapshotReturnGateGuard::install(hook_directory, Arc::clone(&gate));
    for start in (0..total).step_by(profile.max_payload_entries as usize) {
        let end = (start + profile.max_payload_entries).min(total);
        if end.is_multiple_of(profile.logs_per_snapshot) {
            gate.arm();
        }
        assert_eq!(
            tokio::time::timeout(WAIT, raft.append_entries(append_request(start, end)))
                .await
                .expect("normal append returns")
                .unwrap_or_else(|error| panic!("append [{start},{end}) failed: {error:?}")),
            AppendEntriesResponse::Success,
        );
        raft.wait(Some(WAIT))
            .applied_index_at_least(Some(end - 1), "real state machine applies committed blanks")
            .await
            .expect("normal apply completes");
        if !end.is_multiple_of(profile.logs_per_snapshot) {
            continue;
        }
        tokio::time::timeout(WAIT, gate.wait_started())
            .await
            .expect("automatic snapshot reaches its return boundary");
        let peak = wal.native_log_inventory_for_test().unwrap();
        assert_eq!(
            peak.0 as u64,
            if snapshots == 0 {
                profile.logs_per_snapshot
            } else {
                profile.retained_logs + profile.logs_per_snapshot
            },
            "retention peak before this snapshot permits purge"
        );
        let snapshot_cut = log_id(end - 1);
        let purge_cut = log_id(end - profile.retained_logs - 1);
        assert!(wal
            .async_covers_committed(&[log_id(purge_cut.index - 1)])
            .unwrap());
        assert!(
            !wal.async_covers_committed(&[log_id_with_term(0, purge_cut.index - 1)])
                .unwrap(),
            "a retained row requires exact lineage before physical removal"
        );
        gate.release();
        // Do not trigger either operation manually: these are the engine's
        // automatic LogsSinceLast snapshot and policy-based purge.
        raft.wait(Some(WAIT))
            .metrics(
                |m| m.snapshot == Some(snapshot_cut) && m.purged == Some(purge_cut),
                "automatic snapshot and purge reach the production cuts",
            )
            .await
            .expect("production snapshot and purge cadence completes");
        snapshots += 1;
        let inventory = wal.native_log_inventory_for_test().unwrap();
        assert_eq!(
            inventory.0 as u64, profile.retained_logs,
            "snapshot/purge remove every covered physical row"
        );
        assert_eq!(inventory.1, Some(end - profile.retained_logs));
        assert_eq!(inventory.2, Some(purge_cut.index));
        assert_reclaimed_committed_coverage(&wal, end, profile.retained_logs);
        assert!(
            inventory.3 > last_checkpoint,
            "snapshot publication selects a newer native checkpoint"
        );
        last_checkpoint = inventory.3;
        assert_eq!(
            wal.native_log_read(0, None, None).unwrap().len() as u64,
            profile.retained_logs,
            "Raft's logical view excludes the purged prefix"
        );
        assert!(raft.metrics().borrow().running_state.is_ok());
        eprintln!("NATIVE_LOG_BOUND appended={end} snapshots={snapshots} inventory={inventory:?} elapsed_s={:.3}",
            started.elapsed().as_secs_f64());
    }
    assert_eq!(snapshots, cycles);
    let extent = generation_bytes(&directory);
    assert!(
        extent > initial_bytes,
        "append-only generation growth is measured separately from retained rows"
    );
    eprintln!(
        "NATIVE_LOG_BOUND file_bytes_before={initial_bytes} file_bytes_after={extent} growth={}",
        extent - initial_bytes
    );
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    raft.shutdown().await.unwrap();
    drop(raft);
    wal.shutdown_after_consensus().unwrap();
    drop(wal);
    drop(backend);

    let (backend, raft, wal, _) = open_engine(&directory, mode).await;
    let inventory = wal.native_log_inventory_for_test().unwrap();
    assert_eq!(
        inventory.0 as u64, profile.retained_logs,
        "reopen preserves the selected physical inventory"
    );
    assert_eq!(inventory.1, Some(total - profile.retained_logs));
    assert_eq!(inventory.2, Some(total - profile.retained_logs - 1));
    assert_reclaimed_committed_coverage(&wal, total, profile.retained_logs);
    assert!(
        raft.metrics().borrow().running_state.is_ok(),
        "reopen preserves a running engine after reclamation"
    );
    eprintln!(
        "NATIVE_LOG_BOUND reopened inventory={inventory:?} elapsed_s={:.3}",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(
        tokio::time::timeout(WAIT, raft.append_entries(append_request(total, total + 1)))
            .await
            .expect("continued append returns")
            .expect("continued append succeeds"),
        AppendEntriesResponse::Success
    );
    raft.wait(Some(WAIT))
        .applied_index_at_least(Some(total), "continued append applies")
        .await
        .unwrap();
    let continued = wal.native_log_inventory_for_test().unwrap();
    assert_eq!(continued.0 as u64, profile.retained_logs + 1);
    assert_eq!(continued.1, Some(total - profile.retained_logs));
    assert_eq!(continued.2, Some(total - profile.retained_logs - 1));
    assert_eq!(
        wal.native_log_state().unwrap().last_log_id,
        Some(log_id(total))
    );
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    assert!(raft.metrics().borrow().running_state.is_ok());
    raft.shutdown().await.unwrap();
    drop(raft);
    wal.shutdown_after_consensus().unwrap();
    drop(wal);
    drop(backend);
    eprintln!("NATIVE_LOG_BOUND complete appended={} snapshots={snapshots} continued_appends=1 elapsed_s={:.3}",
        total + 1, started.elapsed().as_secs_f64());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_log_three_cycles_reclaim_and_reopen_durable() {
    bounded_cycles(SessionPersistenceMode::Durable, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_log_three_cycles_reclaim_and_reopen_async() {
    bounded_cycles(SessionPersistenceMode::Async, 3).await;
}

// Required heavy-shard tests: deliberately not ignored. The shard manifest
// removes these exact names from the ordinary misc run and executes both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_log_retained_bound_survives_snapshot_purge_and_restart() {
    bounded_cycles(SessionPersistenceMode::Durable, 258).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_log_retained_bound_survives_snapshot_purge_and_restart_async() {
    bounded_cycles(SessionPersistenceMode::Async, 258).await;
}
