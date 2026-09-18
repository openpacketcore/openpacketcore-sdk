//! A completed shutdown is distinct from an uncertified cold incarnation.
//! All effects use the real native writer, retained roots and public opener.

use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;
use crate::sqlite::consensus::wal::Point;

fn proof(fleet: &Fleet, index: usize) -> PathBuf {
    fleet
        .directory
        .path()
        .join(format!("node-{index}.sqlite.native-wal/ASYNC-CLOSED"))
}

fn recovery(fleet: &Fleet, index: usize) -> SessionAsyncRecoveryState {
    fleet.store(index).persistence_health().recovery.unwrap()
}

fn install_proof(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

async fn finish(fleet: &mut Fleet, result: Result<(), Box<dyn std::any::Any + Send>>) {
    for index in 0..fleet.stores.len() {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_proof_is_one_use_and_does_not_grant_traffic() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        for index in 0..3 {
            fleet.close_clean(index).await.unwrap();
            assert!(proof(&fleet, index).is_file());
        }
        fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
        assert_eq!(recovery(&fleet, 0), SessionAsyncRecoveryState::Active);
        assert!(!proof(&fleet, 0).exists());
        assert!(!fleet.store(0).status().admitted);
        assert!(!fleet
            .store(0)
            .probe_fixed_quorum_readiness()
            .await
            .traffic_authority()
            .is_granted());
        // A subsequent incarnation that lacks completed consensus shutdown
        // cannot reuse the predecessor's consumed proof.
        fleet.close(0).await;
        fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
        assert_eq!(
            recovery(&fleet, 0),
            SessionAsyncRecoveryState::AwaitingLiveQuorum
        );
        assert!(!proof(&fleet, 0).exists());
    })
    .catch_unwind()
    .await;
    finish(&mut fleet, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_shutdown_cannot_certify_a_quarantined_predecessor() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        for index in [0, 1] {
            fleet.close(index).await;
        }
        for index in [0, 1] {
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
            assert_eq!(
                recovery(&fleet, index),
                SessionAsyncRecoveryState::AwaitingLiveQuorum
            );
            fleet.close_clean(index).await.unwrap();
            assert!(!proof(&fleet, index).exists());
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
            assert_eq!(
                recovery(&fleet, index),
                SessionAsyncRecoveryState::AwaitingLiveQuorum
            );
        }
    })
    .catch_unwind()
    .await;
    finish(&mut fleet, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_publication_failures_preserve_exact_recovery_boundary() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    for (point, certified) in [
        (Point::BeforeAsyncClosedWrite, false),
        (Point::AfterAsyncClosedFileSync, false),
        (Point::AfterAsyncClosedRename, true),
        (Point::AfterAsyncClosedDirectorySync, true),
    ] {
        let mut fleet = Fleet::new(3);
        let result = AssertUnwindSafe(async {
            fleet
                .open_with_io_hook(
                    0,
                    Arc::new(move |at| {
                        if at == point {
                            Err(std::io::Error::from_raw_os_error(libc::EIO))
                        } else {
                            Ok(())
                        }
                    }),
                )
                .await
                .unwrap();
            for index in [1, 2] {
                fleet
                    .open(index, SessionPersistenceMode::Async)
                    .await
                    .unwrap();
            }
            fleet.form().await;
            assert!(fleet.close_clean(0).await.is_err());
            assert_eq!(proof(&fleet, 0).exists(), certified);
            fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
            assert_eq!(
                recovery(&fleet, 0),
                if certified {
                    SessionAsyncRecoveryState::Active
                } else {
                    SessionAsyncRecoveryState::AwaitingLiveQuorum
                }
            );
            assert!(!proof(&fleet, 0).exists());
            assert!(!proof(&fleet, 0)
                .with_file_name("ASYNC-CLOSED.preparing")
                .exists());
        })
        .catch_unwind()
        .await;
        finish(&mut fleet, result).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_consumption_failure_never_starts_an_uncertified_owner() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    for (point, proof_remains) in [
        (Point::BeforeAsyncClosedConsume, true),
        (Point::AfterAsyncClosedUnlink, false),
        (Point::AfterAsyncClosedConsumeSync, false),
    ] {
        let mut fleet = Fleet::new(3);
        let result = AssertUnwindSafe(async {
            fleet.start().await;
            fleet.close_clean(0).await.unwrap();
            let before = fleet.engine_calls_from(fleet.peers[0].node);
            assert!(fleet
                .open_with_io_hook(
                    0,
                    Arc::new(move |at| {
                        if at == point {
                            Err(std::io::Error::from_raw_os_error(libc::EIO))
                        } else {
                            Ok(())
                        }
                    }),
                )
                .await
                .is_err());
            assert_eq!(fleet.engine_calls_from(fleet.peers[0].node), before);
            assert_eq!(proof(&fleet, 0).exists(), proof_remains);
            fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
            assert_eq!(
                recovery(&fleet, 0),
                if proof_remains {
                    SessionAsyncRecoveryState::Active
                } else {
                    SessionAsyncRecoveryState::AwaitingLiveQuorum
                }
            );
        })
        .catch_unwind()
        .await;
        finish(&mut fleet, result).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_rejects_foreign_corrupt_and_stale_selected_proof() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let provider = provider();
        let first = create_request(fleet.store(fleet.leader()), 71, &provider).await;
        create(fleet.store(fleet.leader()), &first).await;
        fleet.close_clean(0).await.unwrap();
        let old = std::fs::read(proof(&fleet, 0)).unwrap();
        fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
        fleet.form().await;
        let second = create_request(fleet.store(fleet.leader()), 72, &provider).await;
        let outcome = create(fleet.store(fleet.leader()), &second).await;
        assert_recorded(fleet.store(0), &second, &outcome).await;
        fleet.close(0).await;
        install_proof(&proof(&fleet, 0), &old);
        assert!(fleet.open(0, SessionPersistenceMode::Async).await.is_err());
        assert_eq!(std::fs::read(proof(&fleet, 0)).unwrap(), old);

        fleet.close_clean(1).await.unwrap();
        let own = std::fs::read(proof(&fleet, 1)).unwrap();
        std::fs::write(proof(&fleet, 1), &old).unwrap();
        assert!(fleet.open(1, SessionPersistenceMode::Async).await.is_err());
        let mut corrupt = own.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(proof(&fleet, 1), &corrupt).unwrap();
        assert!(fleet.open(1, SessionPersistenceMode::Async).await.is_err());
        // Restore the exact already-published fixture only to verify that
        // these negative attempts did not consume or replace its owner.
        std::fs::write(proof(&fleet, 1), &own).unwrap();
        fleet.open(1, SessionPersistenceMode::Async).await.unwrap();
        assert_eq!(recovery(&fleet, 1), SessionAsyncRecoveryState::Active);
    })
    .catch_unwind()
    .await;
    finish(&mut fleet, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_rejects_file_replacement_at_consumption() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        fleet.close_clean(0).await.unwrap();
        let path = proof(&fleet, 0);
        let retained = std::fs::read(&path).unwrap();
        let replacement = retained.clone();
        let before = fleet.engine_calls_from(fleet.peers[0].node);
        assert!(fleet
            .open_with_io_hook(
                0,
                Arc::new(move |at| {
                    if at == Point::BeforeAsyncClosedConsume {
                        let held = std::fs::File::open(&path)?;
                        std::fs::remove_file(&path)?;
                        install_proof(&path, &replacement);
                        drop(held);
                    }
                    Ok(())
                }),
            )
            .await
            .is_err());
        assert_eq!(fleet.engine_calls_from(fleet.peers[0].node), before);
        assert_eq!(std::fs::read(proof(&fleet, 0)).unwrap(), retained);
    })
    .catch_unwind()
    .await;
    finish(&mut fleet, result).await;
}

struct Release(Arc<SnapshotArtifactGate>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_closed_cancelled_shutdown_retains_lock_until_proof_is_complete() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let gate = Arc::new(SnapshotArtifactGate::new());
    let release = Release(Arc::clone(&gate));
    let result = AssertUnwindSafe(async {
        let held = Arc::clone(&gate);
        fleet
            .open_with_io_hook(
                0,
                Arc::new(move |at| {
                    if at == Point::AfterAsyncClosedFileSync {
                        held.block_if_armed_blocking();
                    }
                    Ok(())
                }),
            )
            .await
            .unwrap();
        for index in [1, 2] {
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
        }
        fleet.form().await;
        let provider = provider();
        let first = create_request(fleet.store(fleet.leader()), 73, &provider).await;
        let old_lease = create(fleet.store(fleet.leader()), &first)
            .await
            .lease()
            .clone();
        gate.arm();
        let old = fleet.store(0).clone();
        let mut retired_log = crate::sqlite::consensus::wal::adapter::WalLogStore::new(Arc::clone(
            old.inner.private_wal.as_ref().unwrap(),
        ));
        let old_vote = old.inner.raft.metrics().borrow().vote;
        *fleet.peers[0].handler.write().await = None;
        fleet.stores[0] = None;
        let caller = {
            let old = old.clone();
            tokio::spawn(async move { old.shutdown().await })
        };
        tokio::time::timeout(OPERATION_BOUND, gate.wait_started())
            .await
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(old.shutdown().await, Err(consensus_unavailable()));
        assert!(!proof(&fleet, 0).exists());
        assert!(fleet.open(0, SessionPersistenceMode::Async).await.is_err());
        gate.release();
        old.shutdown().await.unwrap();
        assert!(proof(&fleet, 0).exists());
        assert!(old.delete_fenced(&old_lease).await.is_err());
        // Public handles retain the existing snapshot namespace lease even
        // after shutdown. Retain the retired log owner across replacement,
        // but release the public handle as ordinary reopen requires.
        drop(old);
        fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
        fleet.form().await;
        assert!(opc_consensus::engine::storage::RaftLogStorage::save_vote(
            &mut retired_log,
            &old_vote,
        )
        .await
        .is_err());
        let second = create_request(fleet.store(fleet.leader()), 74, &provider).await;
        let outcome = create(fleet.store(fleet.leader()), &second).await;
        assert_recorded(fleet.store(0), &second, &outcome).await;
    })
    .catch_unwind()
    .await;
    drop(release);
    finish(&mut fleet, result).await;
}
