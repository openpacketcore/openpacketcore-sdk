//! The public state-machine installation path revokes retained scan resources.

mod composition;

use super::*;
use crate::scope_scan::activity::ViewInvalidation;
use crate::scope_scan::admission::CaptureCost;
use crate::scope_scan::{
    backend::{CapturedBackend, CapturedScope},
    registry::RegisteredView,
};
use crate::scope_scheduler::{
    ScopeScheduler, ScopeSchedulerKey, ScopeSchedulerOwner, ScopeWorkClass,
};
use crate::sqlite::consensus::wal::integration::PrivateWalTest;
use crate::sqlite::scope_scan::SqliteScopeScan;
use futures_util::poll;
use std::sync::mpsc;
use tokio::sync::oneshot;

type View = RegisteredView<Option<CapturedScope>>;
const TIMEOUT: Duration = Duration::from_secs(10);

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, future).await.unwrap()
}

fn key() -> ScopeSchedulerKey {
    ScopeSchedulerKey::from_bytes([0x73; 32])
}

async fn retain(core: &SqliteConsensusCore, scheduler: &ScopeScheduler) -> View {
    let registry = Arc::clone(&core.scope_views);
    let wal = core
        .private_wal
        .as_ref()
        .filter(|wal| wal.is_native())
        .cloned();
    let source = core.database_file.clone().unwrap();
    let identity = core.storage_identity;
    let cost = if let Some(wal) = wal.as_ref() {
        CaptureCost::Native(wal.native_scope_cost(&|| Ok(())).unwrap() as u64)
    } else {
        let conn = core.conn.lock().await;
        let bytes = opc_sqlite_file_control_sys::main_journal_descriptor(&conn)
            .unwrap()
            .metadata()
            .unwrap()
            .len();
        registry.observe_wal(Some(bytes));
        CaptureCost::Sqlite
    };
    let view = registry
        .admit(
            key(),
            cost,
            None,
            scheduler
                .reserve(key(), ScopeWorkClass::Normal)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    let reservation = view.reservation.clone();
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
        })
        .unwrap()
        .result()
        .await
        .unwrap();
    view
}

fn token(directory: &FixedRawReadStoreFixture, native: bool) -> Arc<PrivateWalTest> {
    Arc::new(if native {
        PrivateWalTest::new_native(directory.path().join("wal"), [0xC5; 32])
    } else {
        PrivateWalTest::new(directory.path().join("wal"), [0xC5; 32])
    })
}

struct Release(Option<mpsc::Sender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

async fn install_drains(native: bool, active: bool) {
    let directory = portable_fixed_fixture();
    let target = token(&directory, native);
    let (_backend, mut log, mut machine) = open_private_snapshot_store_with_integrity(
        &directory,
        Arc::clone(&target),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    append_commit_and_apply(
        &mut log,
        &mut machine,
        [fixed_initial_membership_entry()],
        "scan target",
    )
    .await;
    let donor_directory = portable_fixed_fixture();
    let donor_token = token(&donor_directory, native);
    let (_donor_backend, mut donor_log, mut donor) = open_private_snapshot_store_with_integrity(
        &donor_directory,
        Arc::clone(&donor_token),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    append_commit_and_apply(
        &mut donor_log,
        &mut donor,
        [
            fixed_initial_membership_entry(),
            blank_entry(1),
            blank_entry(2),
        ],
        "scan donor",
    )
    .await;
    let mut incoming = donor
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .unwrap();
    let mut receiver = machine.begin_receiving_snapshot().await.unwrap();
    tokio::io::copy(&mut incoming.snapshot, &mut receiver)
        .await
        .unwrap();
    let scheduler_owner = ScopeSchedulerOwner::default();
    let scheduler = scheduler_owner.scheduler();
    let view = retain(&machine.core, &scheduler).await;
    let registry = Arc::clone(&machine.core.scope_views);
    let conn = Arc::clone(&machine.core.conn);
    let epoch = view.epoch;
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
                assert!(cancellation.is_cancelled());
            })
            .unwrap();
        Some((worker, bounded(started).await.unwrap()))
    } else {
        None
    };
    let mut install = Box::pin(machine.install_snapshot(&incoming.meta, receiver));
    if let Some((_, cancelled)) = worker.as_ref() {
        assert!(poll!(install.as_mut()).is_pending());
        assert!(
            cancelled.is_cancelled(),
            "actual install must revoke accepted work before replacement"
        );
        assert!(
            conn.try_lock().is_ok(),
            "draining must precede the primary connection lock"
        );
        assert_eq!(
            registry.metrics().active_views,
            1,
            "worker must retain its actual capture charge until it exits"
        );
    }
    drop(release);
    bounded(install).await.unwrap();
    if let Some((worker, _)) = worker {
        assert!(bounded(worker.result()).await.is_err());
    }
    assert!(
        !registry.is_current(epoch),
        "installed state must invalidate the old epoch"
    );
    assert_eq!(
        registry.metrics().active_views,
        0,
        "install must drain captures before returning"
    );
    assert!(view.runtime.start_normal(|_, _| ()).is_err());
    let replacement = retain(&machine.core, &scheduler).await;
    assert_ne!(replacement.epoch, epoch);
    assert_eq!(machine.applied_state().await.unwrap().0, Some(log_id(2)));
    drop(replacement);
    target.current().unwrap().shutdown().unwrap();
    donor_token.current().unwrap().shutdown().unwrap();
}

#[tokio::test]
async fn scope_scan_install_releases_idle_native_view() {
    install_drains(true, false).await;
}
#[tokio::test]
async fn scope_scan_install_releases_idle_sqlite_view() {
    install_drains(false, false).await;
}
#[tokio::test]
async fn scope_scan_install_drains_active_native_view_before_primary_lock() {
    install_drains(true, true).await;
}
#[tokio::test]
async fn scope_scan_install_drains_active_sqlite_view_before_primary_lock() {
    install_drains(false, true).await;
}

#[tokio::test]
async fn scope_scan_failed_install_stays_closed_and_releases_idle_view() {
    let directory = portable_fixed_fixture();
    let token = token(&directory, false);
    let (_backend, mut log, mut machine) = open_private_snapshot_store_with_integrity(
        &directory,
        Arc::clone(&token),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    append_commit_and_apply(
        &mut log,
        &mut machine,
        [fixed_initial_membership_entry()],
        "failed install target",
    )
    .await;
    let scheduler_owner = ScopeSchedulerOwner::default();
    let scheduler = scheduler_owner.scheduler();
    let view = retain(&machine.core, &scheduler).await;
    let registry = Arc::clone(&machine.core.scope_views);
    let mut receiver = machine.begin_receiving_snapshot().await.unwrap();
    receiver.write_all(b"invalid snapshot").await.unwrap();
    let meta = owned_purge_meta(log_id(2));
    assert!(machine.install_snapshot(&meta, receiver).await.is_err());
    assert_eq!(
        registry.metrics().active_views,
        0,
        "failed install must release retained resources"
    );
    assert!(view.runtime.start_normal(|_, _| ()).is_err());
    assert!(
        registry
            .admit(
                key(),
                CaptureCost::Sqlite,
                None,
                scheduler
                    .reserve(key(), ScopeWorkClass::Normal)
                    .await
                    .unwrap()
            )
            .await
            .is_err(),
        "failed install cannot reopen admission"
    );
    token.current().unwrap().shutdown().unwrap();
}

#[tokio::test]
async fn scope_scan_backend_clone_restart_drains_old_registry_and_keeps_new_owner_distinct() {
    let directory = portable_fixed_fixture();
    let backend =
        SqliteSessionBackend::open(directory.path().join("scope-restart.sqlite")).unwrap();
    let members = fixed_raw_read_members();
    let initialize = |backend: SqliteSessionBackend| {
        let members = members.clone();
        let snapshots = directory.snapshot_path().join("scans");
        async move {
            SqliteConsensusCore::initialize(
                &backend,
                snapshots,
                identity(1),
                members.clone(),
                fixed_raw_read_bindings(&members),
                ConsensusAuthorityProfile::FixedImmutable,
                Some(PlacementResiliencePolicy::AllowReducedResilience),
            )
            .await
            .unwrap()
        }
    };
    let first = initialize(backend.clone()).await;
    let clone = first.clone();
    assert!(Arc::ptr_eq(&first.scope_views, &clone.scope_views));
    let scheduler_owner = ScopeSchedulerOwner::default();
    let scheduler = scheduler_owner.scheduler();
    let view = retain(&first, &scheduler).await;
    let next = initialize(backend.clone()).await;
    assert!(
        view.runtime.start_normal(|_, _| ()).is_err(),
        "backend restart must revoke old captures"
    );
    assert_eq!(first.scope_views.metrics().active_views, 0);
    assert!(
        !Arc::ptr_eq(&first.scope_views, &next.scope_views),
        "new core must own a new registry"
    );
    let fresh = retain(&next, &scheduler).await;
    first
        .scope_views
        .close_and_drain(ViewInvalidation::BackendRestarted)
        .await;
    assert!(
        next.scope_views.is_current(fresh.epoch),
        "old shutdown cannot revoke the new generation"
    );
    drop(fresh);
}

fn one_view_limits() -> crate::scope_scan::ScopeScanLimits {
    crate::scope_scan::ScopeScanLimits::new(
        1,
        1,
        512 * 1024 * 1024,
        1024 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap()
}

async fn configured_core(
    backend: &SqliteSessionBackend,
    directory: &FixedRawReadStoreFixture,
) -> SqliteConsensusCore {
    let members = fixed_raw_read_members();
    SqliteConsensusCore::initialize(
        backend,
        directory.snapshot_path().join("configured-scans"),
        identity(1),
        members.clone(),
        fixed_raw_read_bindings(&members),
        ConsensusAuthorityProfile::FixedImmutable,
        Some(PlacementResiliencePolicy::AllowReducedResilience),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn scope_scan_configured_node_cap_is_shared_by_actual_backend_clones() {
    let directory = portable_fixed_fixture();
    let backend = SqliteSessionBackend::open(directory.path().join("configured.sqlite"))
        .unwrap()
        .with_scope_scan_limits(one_view_limits());
    let core = configured_core(&backend.clone(), &directory).await;
    let cloned_core = core.clone();
    let owner = ScopeSchedulerOwner::default();
    let scheduler = owner.scheduler();
    let first = retain(&core, &scheduler).await;
    let second = retain(&cloned_core, &scheduler);
    tokio::pin!(second);
    assert!(poll!(&mut second).is_pending());
    assert_eq!(
        core.scope_views.metrics().active_views,
        1,
        "the backend must consume its configured node cap"
    );
    assert_eq!(core.scope_views.metrics().waiting_views, 1);
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).running,
        0
    );
    assert!(core.scope_views.is_current(first.epoch));
    drop(first);
    let second = bounded(second).await;
    assert_eq!(core.scope_views.metrics().active_views, 1);
    drop(second);
    assert_eq!(core.scope_views.metrics().active_views, 0);
}

#[tokio::test]
async fn scope_scan_limit_update_changes_only_the_next_backend_generation() {
    let directory = portable_fixed_fixture();
    let backend = SqliteSessionBackend::open(directory.path().join("next-config.sqlite")).unwrap();
    let first = configured_core(&backend, &directory).await;
    let owner = ScopeSchedulerOwner::default();
    let scheduler = owner.scheduler();
    let old_one = retain(&first, &scheduler).await;
    let old_two = retain(&first, &scheduler).await;
    let _updated_clone = backend.clone().with_scope_scan_limits(one_view_limits());
    assert!(first.scope_views.is_current(old_one.epoch));
    assert!(first.scope_views.is_current(old_two.epoch));
    assert_eq!(first.scope_views.metrics().active_views, 2);
    let next = configured_core(&backend, &directory).await;
    assert_eq!(first.scope_views.metrics().active_views, 0);
    let fresh = retain(&next, &scheduler).await;
    let pending = retain(&next, &scheduler);
    tokio::pin!(pending);
    assert!(poll!(&mut pending).is_pending());
    assert_eq!(
        next.scope_views.metrics().active_views,
        1,
        "all backend clones must share the next-generation limits"
    );
    assert_eq!(next.scope_views.metrics().waiting_views, 1);
    drop(fresh);
    drop(bounded(pending).await);
}
