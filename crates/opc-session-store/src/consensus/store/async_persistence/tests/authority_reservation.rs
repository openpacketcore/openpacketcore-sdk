//! An authority ceiling must survive independently of lagging generations.

use super::*;
use crate::sqlite::consensus::wal::async_authority::Reservation;
use crate::sqlite::consensus::wal::Point;
use std::path::PathBuf;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_authority_promise_is_durable_idempotent_and_monotonic() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let index = (fleet.leader() + 1) % 3;
        fleet.close(index).await;
        fleet
            .open(index, SessionPersistenceMode::Async)
            .await
            .unwrap();
        let wal = fleet.store(index).inner.private_wal.as_ref().unwrap();
        let (root, before) = wal.async_authority().unwrap().unwrap();
        assert!(before == Reservation::initial());
        let after = Reservation::recovery(2, [0xD1; 32]).unwrap();
        wal.promise_async_authority(before, after).unwrap();
        let selected = std::fs::read(authority(&fleet, index)).unwrap();
        wal.promise_async_authority(before, after).unwrap();
        assert_eq!(selected, std::fs::read(authority(&fleet, index)).unwrap());
        assert!(wal
            .promise_async_authority(before, Reservation::recovery(2, [0xD2; 32]).unwrap())
            .is_err());
        assert!(wal.promise_async_authority(after, before).is_err());
        assert!(wal.async_authority().unwrap() == Some((root, after)));
        fleet.close(index).await;
        fleet
            .open(index, SessionPersistenceMode::Async)
            .await
            .unwrap();
        assert!(
            fleet
                .store(index)
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .async_authority()
                .unwrap()
                == Some((root, after))
        );
        assert!(
            !fleet.store(index).inner.persistence_protocol.is_active(),
            "a persisted reservation is never an admission proof"
        );
    })
    .catch_unwind()
    .await;
    for index in 0..3 {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_authority_interrupted_promise_never_grants_old_owner_new_range() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    for point in [
        Point::BeforeAsyncAuthorityWrite,
        Point::AfterAsyncAuthorityFileSync,
        Point::AfterAsyncAuthorityRename,
        Point::AfterAsyncAuthorityDirectorySync,
    ] {
        let mut fleet = Fleet::new(3);
        let armed = Arc::new(AtomicBool::new(false));
        let result = AssertUnwindSafe(async {
            let fault = Arc::clone(&armed);
            let hook: crate::sqlite::consensus::wal::owner::IoHookForTest = Arc::new(move |at| {
                if at == point && fault.load(Ordering::Acquire) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                Ok(())
            });
            fleet.open_with_io_hook(0, Arc::clone(&hook)).await.unwrap();
            for index in 1..3 {
                fleet
                    .open(index, SessionPersistenceMode::Async)
                    .await
                    .unwrap();
            }
            fleet.form().await;
            fleet.close(0).await;
            fleet.open_with_io_hook(0, hook).await.unwrap();
            fleet.store(0).drain_async_persistence().await.unwrap();
            let before = Reservation::initial();
            let after = Reservation::recovery(2, [0xD3; 32]).unwrap();
            armed.store(true, Ordering::Release);
            let wal = fleet.store(0).inner.private_wal.as_ref().unwrap();
            assert!(wal.promise_async_authority(before, after).is_err());
            assert!(wal.async_authority().is_err());
            assert!(wal.promise_async_authority(before, after).is_err());
            assert!(fleet.close_result(0).await.is_err());
            fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
            let (_, selected) = fleet
                .store(0)
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .async_authority()
                .unwrap()
                .unwrap();
            assert!(
                selected
                    == if matches!(
                        point,
                        Point::AfterAsyncAuthorityRename | Point::AfterAsyncAuthorityDirectorySync
                    ) {
                        after
                    } else {
                        before
                    }
            );
            assert!(!fleet.store(0).inner.persistence_protocol.is_active());
        })
        .catch_unwind()
        .await;
        for index in 0..3 {
            let _ = fleet.close_result(index).await;
        }
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

fn authority(fleet: &Fleet, index: usize) -> PathBuf {
    fleet
        .directory
        .path()
        .join(format!("node-{index}.sqlite.native-wal/ASYNC-AUTHORITY"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_authority_reservation_is_unchanged_by_ordinary_acknowledgements() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let publications = Arc::new(AtomicU64::new(0));
        for index in 0..3 {
            let publications = Arc::clone(&publications);
            fleet
                .open_with_io_hook(
                    index,
                    Arc::new(move |at| {
                        if matches!(
                            at,
                            Point::BeforeAsyncAuthorityWrite
                                | Point::AfterAsyncAuthorityFileSync
                                | Point::AfterAsyncAuthorityDirectorySync
                        ) {
                            publications.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    }),
                )
                .await
                .unwrap();
        }
        fleet.form().await;
        assert_eq!(publications.load(Ordering::Relaxed), 9);
        let retained = (0..3)
            .map(|index| std::fs::read(authority(&fleet, index)).unwrap())
            .collect::<Vec<_>>();
        let provider = provider();
        let leader = fleet.leader();
        let request = create_request(fleet.store(leader), 101, &provider).await;
        let outcome = create(fleet.store(leader), &request).await;
        for (index, before) in retained.iter().enumerate() {
            assert_recorded(fleet.store(index), &request, &outcome).await;
            assert_eq!(&std::fs::read(authority(&fleet, index)).unwrap(), before);
            fleet.store(index).drain_async_persistence().await.unwrap();
            assert_eq!(&std::fs::read(authority(&fleet, index)).unwrap(), before);
        }
        assert_eq!(publications.load(Ordering::Relaxed), 9);
    })
    .catch_unwind()
    .await;
    for index in 0..3 {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_authority_missing_corrupt_or_foreign_record_cannot_consume_close_evidence() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        for index in 0..3 {
            fleet.close_clean(index).await.unwrap();
        }
        let own = std::fs::read(authority(&fleet, 0)).unwrap();
        let foreign = std::fs::read(authority(&fleet, 1)).unwrap();
        let proof = authority(&fleet, 0).with_file_name("ASYNC-CLOSED");
        let retained = std::fs::read(&proof).unwrap();
        let held = fleet.directory.path().join("held-authority");
        std::fs::rename(authority(&fleet, 0), &held).unwrap();
        assert!(fleet.open(0, SessionPersistenceMode::Async).await.is_err());
        assert_eq!(std::fs::read(&proof).unwrap(), retained);
        std::fs::rename(&held, authority(&fleet, 0)).unwrap();
        for invalid in [Vec::new(), foreign, {
            let mut corrupt = own.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            corrupt
        }] {
            std::fs::write(authority(&fleet, 0), invalid).unwrap();
            assert!(fleet.open(0, SessionPersistenceMode::Async).await.is_err());
            assert_eq!(std::fs::read(&proof).unwrap(), retained);
        }
        // Remove only the synthetic negative fixture. The exact selected
        // authority is restored to show rejection never consumed the proof.
        std::fs::write(authority(&fleet, 0), &own).unwrap();
        fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
        assert!(!fleet.store(0).status().admitted);
        assert!(!fleet
            .store(0)
            .probe_fixed_quorum_readiness()
            .await
            .traffic_authority()
            .is_granted());
    })
    .catch_unwind()
    .await;
    for index in 0..3 {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_authority_publication_failure_never_starts_an_engine() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    for point in [
        Point::BeforeAsyncAuthorityWrite,
        Point::AfterAsyncAuthorityFileSync,
        Point::AfterAsyncAuthorityDirectorySync,
    ] {
        let mut fleet = Fleet::new(3);
        let reached = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&reached);
        assert!(fleet
            .open_with_io_hook(
                0,
                Arc::new(move |at| {
                    if at == point {
                        observed.store(true, Ordering::Release);
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                    Ok(())
                })
            )
            .await
            .is_err());
        assert!(reached.load(Ordering::Acquire));
        assert_eq!(fleet.engine_calls_from(fleet.peers[0].node), 0);
        assert!(fleet.stores.iter().all(Option::is_none));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_authority_replacement_at_sync_cannot_publish_an_owner() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let path = authority(&fleet, 0);
    let reached = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&reached);
    assert!(fleet
        .open_with_io_hook(
            0,
            Arc::new(move |at| {
                if at == Point::AfterAsyncAuthorityFileSync {
                    observed.store(true, Ordering::Release);
                    let held = std::fs::File::open(&path)?;
                    let original = std::fs::read(&path)?;
                    std::fs::remove_file(&path)?;
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut replacement = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)?;
                    replacement.write_all(&original)?;
                    replacement.sync_all()?;
                    drop(held);
                }
                Ok(())
            })
        )
        .await
        .is_err());
    assert!(reached.load(Ordering::Acquire));
    assert_eq!(fleet.engine_calls_from(fleet.peers[0].node), 0);
    assert!(fleet.stores.iter().all(Option::is_none));
}
