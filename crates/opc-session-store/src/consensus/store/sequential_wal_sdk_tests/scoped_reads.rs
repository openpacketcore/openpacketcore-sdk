//! Exact expiry and authority boundaries for the optimized scoped read path.

use super::*;

#[derive(Debug)]
struct ReadClock(std::sync::Mutex<crate::Timestamp>);

impl crate::Clock for ReadClock {
    fn now_utc(&self) -> crate::Timestamp {
        *self.0.lock().expect("controlled read clock")
    }
}

impl ReadClock {
    fn set(&self, value: crate::Timestamp) {
        *self.0.lock().expect("controlled read clock") = value;
    }
}

async fn expiry_and_authority(native: bool) {
    let start =
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed expiry boundary");
    let expires_at = crate::Timestamp::from_offset_datetime(start + time::Duration::SECOND);
    let clock = Arc::new(ReadClock(std::sync::Mutex::new(
        crate::Timestamp::from_offset_datetime(start),
    )));
    let snapshots = tempfile::tempdir_in(
        std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").expect("designated snapshot root"),
    )
    .expect("fresh expiry control snapshot directory");
    let mut fleet = Fleet::new_with_mode("scoped-read-expiry", native);
    fleet.clock = Some(clock.clone());
    if native {
        fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    }
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        for store in &fleet.stores {
            assert_eq!(
                store
                    .inner
                    .private_wal
                    .as_ref()
                    .expect("selected WAL")
                    .is_native(),
                native
            );
        }
        let backend = EncryptingSessionBackend::new(
            Arc::new(fleet.stores[0].clone()),
            provider(),
            "scoped-expiry",
        );
        let key = key(0);
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("scoped-expiry-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("real public lease");
        let mut expected = record(key.clone(), &lease, 1);
        expected.expires_at = Some(expires_at);
        assert_eq!(
            backend
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease,
                    expected_generation: None,
                    new_record: expected,
                })
                .await
                .expect("real encrypted finite record CAS"),
            CompareAndSetResult::Success
        );
        let encrypted = SessionBackend::get(&fleet.stores[0], &key)
            .await
            .expect("independent generic read")
            .expect("committed finite record");
        drop(backend);
        clock.set(crate::Timestamp::from_offset_datetime(
            start + time::Duration::SECOND - time::Duration::NANOSECOND,
        ));
        for store in &fleet.stores {
            let actual = store
                .consumer_get(
                    store.consumer_scope().expect("scope"),
                    &key,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("scoped read before exact expiry");
            assert_eq!(
                actual,
                Some(encrypted.clone()),
                "one nanosecond before expiry remains visible"
            );
        }
        clock.set(expires_at);
        for store in &fleet.stores {
            assert!(
                store
                    .consumer_get(
                        store.consumer_scope().expect("scope"),
                        &key,
                        tokio::time::Instant::now() + Duration::from_secs(1)
                    )
                    .await
                    .expect("scoped read at exact expiry")
                    .is_none(),
                "the visible finite record must advance committed time before returning absence"
            );
        }
        clock.set(crate::Timestamp::from_offset_datetime(start));
        for store in &fleet.stores {
            assert!(
                store
                    .consumer_get(
                        store.consumer_scope().expect("scope"),
                        &key,
                        tokio::time::Instant::now() + Duration::from_secs(1)
                    )
                    .await
                    .expect("clock rollback read")
                    .is_none(),
                "wall-clock rollback cannot resurrect the committed expiry"
            );
        }
        for peer in &fleet.peers {
            *peer.handler.write().await = None;
        }
        drop(fleet.close().await);
        fleet.open().await;
        for store in &fleet.stores {
            assert!(
                store
                    .consumer_get(
                        store.consumer_scope().expect("cold scope"),
                        &key,
                        tokio::time::Instant::now() + Duration::from_secs(1)
                    )
                    .await
                    .expect("cold scoped read")
                    .is_none(),
                "cold reconstruction preserves the exact expiry despite clock rollback"
            );
        }
        for peer in &fleet.peers {
            *peer.handler.write().await = None;
        }
        for store in &fleet.stores {
            let scope = store
                .consumer_scope()
                .expect("scope captured before majority probe");
            assert!(
                store
                    .consumer_get(
                        scope,
                        &key,
                        tokio::time::Instant::now() + Duration::from_millis(25)
                    )
                    .await
                    .is_err(),
                "even already-proven local absence requires a fresh majority"
            );
        }
    })
    .catch_unwind()
    .await;
    for peer in &fleet.peers {
        *peer.handler.write().await = None;
    }
    drop(fleet.close().await);
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_native_reads_preserve_expiry_rollback_cold_state_and_majority() {
    expiry_and_authority(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_sql_reads_preserve_expiry_rollback_cold_state_and_majority() {
    expiry_and_authority(false).await;
}
