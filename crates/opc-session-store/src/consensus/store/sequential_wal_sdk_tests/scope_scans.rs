//! Public shutdown drains the actual native and SQLite retained captures.

use super::*;
use crate::scope_scan::admission::CaptureCost;
use crate::scope_scan::backend::{CapturedBackend, CapturedScope};
use crate::scope_scan::registry::RegisteredView;
use crate::scope_scheduler::{ScopeSchedulerKey, ScopeWorkClass};
use crate::sqlite::scope_scan::SqliteScopeScan;
use std::io;
use std::sync::mpsc;
use tokio::sync::oneshot;

type View = RegisteredView<Option<CapturedScope>>;
const TIMEOUT: Duration = Duration::from_secs(10);

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, future).await.unwrap()
}

async fn retain(store: &ConsensusSessionStore) -> View {
    let registry = Arc::clone(&store.inner.scope_views);
    let wal = store
        .inner
        .private_wal
        .as_ref()
        .filter(|wal| wal.is_native())
        .cloned();
    let source = store.inner.scope_database.clone().unwrap();
    let identity = store.inner.storage_identity;
    let cost = if let Some(wal) = wal.as_ref() {
        CaptureCost::Native(wal.native_scope_cost(&|| Ok(())).unwrap() as u64)
    } else {
        let conn = store.inner.backend.lock_connection_for_test().await;
        registry.observe_wal(Some(
            opc_sqlite_file_control_sys::main_journal_descriptor(&conn)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
        ));
        CaptureCost::Sqlite
    };
    let key = ScopeSchedulerKey::from_bytes([0x74; 32]);
    let view = registry
        .admit(
            key,
            cost,
            None,
            store
                .inner
                .proposal_admission
                .reserve_for(key, ScopeWorkClass::Normal)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    let reservation = view.reservation.clone();
    bounded(
        view.runtime
            .start_normal(move |slot, _| {
                let backend = if let Some(wal) = wal {
                    let capture = wal
                        .native_scope_capture(&|| Ok(()), |bytes| {
                            registry
                                .adjust_native_cost(&reservation, bytes as u64)
                                .map_err(io::Error::other)
                        })
                        .unwrap()
                        .unwrap();
                    CapturedBackend::Native {
                        owner: Arc::downgrade(&wal),
                        capture: Box::new(capture),
                    }
                } else {
                    CapturedBackend::Sqlite(Box::new(
                        SqliteScopeScan::capture(&source, identity, &|| Ok(())).unwrap(),
                    ))
                };
                *slot = Some(CapturedScope::lifecycle_fixture(backend));
                let applied = match &slot.as_ref().unwrap().backend {
                    CapturedBackend::Native { owner, capture } => owner
                        .upgrade()
                        .unwrap()
                        .native_scope_read(capture, &|| Ok(()), |cut, check| {
                            check()?;
                            Ok(cut.applied())
                        })
                        .unwrap(),
                    CapturedBackend::Sqlite(scan) => scan
                        .read(
                            || false,
                            |connection, check| {
                                check()?;
                                crate::sqlite::consensus::read_applied_sync(connection, identity)
                            },
                        )
                        .unwrap(),
                };
                assert!(applied.is_some(), "fixture retains an actual applied cut");
            })
            .unwrap()
            .result(),
    )
    .await
    .unwrap();
    view
}

struct Release(Option<mpsc::Sender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

async fn shutdown_drains(native: bool, active: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_with_mode("scope_scan_shutdown", native);
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let store = &fleet.stores[0];
        let view = retain(store).await;
        let wal = store.inner.private_wal.as_ref().unwrap();
        let registry = Arc::clone(&store.inner.scope_views);
        let (release, wait) = mpsc::channel();
        let release = Release(Some(release));
        let (entered, started) = oneshot::channel();
        let worker = if active {
            let worker = view
                .runtime
                .start_normal(move |slot, cancellation| {
                    assert!(slot.is_some());
                    assert!(entered.send(cancellation.clone()).is_ok());
                    wait.recv_timeout(TIMEOUT).unwrap();
                })
                .unwrap();
            Some((worker, bounded(started).await.unwrap()))
        } else {
            None
        };
        let mut shutdown = Box::pin(store.shutdown());
        if let Some((_, cancellation)) = worker.as_ref() {
            bounded(async {
                tokio::select! {
                    () = cancellation.cancelled() => (),
                    result = shutdown.as_mut() => panic!(
                        "shutdown returned before cancelling and draining accepted scope work: {result:?}"
                    ),
                }
            })
            .await;
            assert_eq!(registry.metrics().active_views, 1);
            assert_eq!(
                wal.integration_observations().unwrap()["writer_joined"],
                false,
                "physical WAL shutdown must wait for retained workers"
            );
            // Cancelling the observer must not abandon the shared drain.
            drop(shutdown);
            drop(release);
            bounded(store.shutdown()).await.unwrap();
        } else {
            drop(release);
            bounded(shutdown).await.unwrap();
        }
        if let Some((worker, _)) = worker {
            assert!(bounded(worker.result()).await.is_err());
        }
        assert_eq!(
            registry.metrics().active_views,
            0,
            "public shutdown must release idle captures without another client call"
        );
        assert!(view.runtime.start_normal(|_, _| ()).is_err());
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_shutdown_releases_idle_native_view() {
    shutdown_drains(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_shutdown_releases_idle_sqlite_view() {
    shutdown_drains(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_shutdown_drains_active_native_view_before_joining_wal() {
    shutdown_drains(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_shutdown_drains_active_sqlite_view_before_joining_wal() {
    shutdown_drains(false, true).await;
}
