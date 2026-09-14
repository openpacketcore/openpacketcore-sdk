//! Public Async bootstrap interruption and an acknowledged, unpersisted quorum.
//! These injected I/O failures exercise owner ordering, not power-loss emulation.

use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::sqlite::consensus::wal::owner::{RootHookForTest, RootPointForTest};

type NativeFiles = BTreeMap<PathBuf, (u64, u64, Option<Vec<u8>>)>;

fn native_files(directory: &Path) -> NativeFiles {
    fn visit(root: &Path, path: &Path, files: &mut NativeFiles) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_dir() || metadata.is_file());
        files.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            (
                metadata.dev(),
                metadata.ino(),
                metadata.is_file().then(|| fs::read(path).unwrap()),
            ),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), files);
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(directory, directory, &mut files);
    files
}

fn selection(database: &Path) -> Option<Vec<u8>> {
    let database = File::open(database).unwrap();
    let mut bytes = [0; 168];
    match rustix::fs::fgetxattr(&database, "user.opc.native-root-v1", &mut bytes) {
        Ok(length) => {
            assert_eq!(length, bytes.len());
            Some(bytes.to_vec())
        }
        Err(rustix::io::Errno::NODATA) => None,
        Err(error) => panic!("read ordinary database selection: {error}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_public_root_interruption_never_reseeds_or_admits() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let points = [
        RootPointForTest::BeforeCreate,
        RootPointForTest::AfterCreate,
        RootPointForTest::AfterWrite,
        RootPointForTest::AfterFileSync,
        RootPointForTest::AfterDirectorySync,
        RootPointForTest::AfterParentSync,
        RootPointForTest::AfterSelection,
        RootPointForTest::AfterSelectionSync,
    ];
    for (cut, point) in points.iter().copied().enumerate() {
        let mut fleet = Fleet::new(3);
        let result = AssertUnwindSafe(async {
            let observed = Arc::new(Mutex::new(Vec::new()));
            let hook: RootHookForTest = {
                let observed = Arc::clone(&observed);
                Arc::new(move |actual| {
                    observed.lock().unwrap().push(actual);
                    if actual == point {
                        Err(std::io::Error::from_raw_os_error(libc::EIO))
                    } else {
                        Ok(())
                    }
                })
            };
            let opened = fleet
                .open_with_hooks(0, SessionPersistenceMode::Async, None, Some(hook))
                .await;
            assert_eq!(*observed.lock().unwrap(), points[..=cut]);
            // Attachment errors preserve the public storage CorruptState ->
            // RecoveryRequired mapping; the earlier read-only reopen
            // preflight separately reports StorageUnavailable below.
            assert_eq!(
                opened,
                Err(ConsensusSessionStoreOpenError::RecoveryRequired),
                "public creation interrupted at {point:?}"
            );
            assert!(fleet.stores.iter().all(Option::is_none));
            let node = fleet.peers[0].node;
            assert_eq!(fleet.engine_calls_from(node), 0);
            let database = fleet.directory.path().join("node-0.sqlite");
            let native = fleet.directory.path().join("node-0.sqlite.native-wal");
            let files = native_files(&native);
            let selected = selection(&database);
            if matches!(
                point,
                RootPointForTest::AfterSelection | RootPointForTest::AfterSelectionSync
            ) {
                assert_eq!(selected, Some(fs::read(native.join("ROOT")).unwrap()));
                fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
                let cold = fleet.store(0);
                assert_eq!(
                    cold.persistence_health().recovery,
                    Some(SessionAsyncRecoveryState::AwaitingLiveQuorum)
                );
                assert!(cold.inner.raft.metrics().borrow().last_applied.is_none());
                assert!(!cold.status().admitted);
                assert_eq!(
                    cold.probe_fixed_quorum_readiness()
                        .await
                        .traffic_authority(),
                    FixedQuorumTrafficAuthority::RecoveryRequired
                );
                assert_eq!(
                    cold.initialize_cluster().await,
                    Err(ConsensusSessionStoreOpenError::RecoveryRequired)
                );
                assert_eq!(fleet.engine_calls_from(node), 0);
                fleet.close(0).await;

                // The inode witness must also forbid treating a missing
                // selected namespace as a new public Async database.
                let saved = fleet.directory.path().join("saved-native");
                fs::rename(&native, &saved).unwrap();
                let saved_files = native_files(&saved);
                assert_eq!(
                    fleet.open(0, SessionPersistenceMode::Async).await,
                    Err(ConsensusSessionStoreOpenError::StorageUnavailable)
                );
                assert!(!native.exists());
                assert_eq!(native_files(&saved), saved_files);
                assert_eq!(selection(&database), selected);
            } else {
                assert!(selected.is_none());
                assert_eq!(
                    fleet.open(0, SessionPersistenceMode::Async).await,
                    Err(ConsensusSessionStoreOpenError::StorageUnavailable)
                );
                assert_eq!(native_files(&native), files);
                assert_eq!(selection(&database), selected);
            }
            assert_eq!(fleet.engine_calls_from(node), 0);
        })
        .catch_unwind()
        .await;
        fleet.close_all().await;
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_public_reopen_before_first_generation_requires_live_quorum() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        for index in 0..3 {
            let hook: GenerationHook =
                Arc::new(|| Err(std::io::Error::from_raw_os_error(libc::ENOSPC)));
            fleet
                .open_with_hook(index, SessionPersistenceMode::Async, Some(hook))
                .await
                .unwrap();
        }
        let initial = (0..3)
            .map(|index| fleet.selector(index))
            .collect::<Vec<_>>();
        fleet.form().await;
        let leader = fleet.leader();
        let provider = provider();
        let request = create_request(fleet.store(leader), 1, &provider).await;
        let outcome = create(fleet.store(leader), &request).await;
        fleet
            .store(leader)
            .activate_fenced_transition_capability()
            .await
            .unwrap();
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &request, &outcome).await;
            assert!(store.inner.raft.metrics().borrow().last_applied.is_some());
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if fleet.stores.iter().flatten().all(|store| {
                    store
                        .persistence_health()
                        .asynchronous
                        .unwrap()
                        .background_failure
                        .is_some()
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every first ordinary background generation fails before selection");
        for (index, store) in fleet.stores.iter().flatten().enumerate() {
            let health = store.persistence_health();
            assert!(health.engine_running);
            assert_eq!(health.recovery, Some(SessionAsyncRecoveryState::Active));
            assert_eq!(health.storage_state, SessionStorageState::Running);
            assert!(health.storage_failure.is_none());
            let progress = health.asynchronous.unwrap();
            assert_eq!(progress.completed_generation, 0);
            assert_eq!(progress.completed_sequence, 0);
            assert!(progress.resident_generation > 0);
            assert!(progress.saturated);
            let failure = progress.background_failure.unwrap();
            assert_eq!(
                failure.stage,
                crate::SessionStorageFailureStage::Persistence
            );
            assert_eq!(failure.kind, crate::SessionStorageFailureKind::StorageFull);
            assert_eq!(failure.os_error, Some(libc::ENOSPC));
            assert_eq!(fleet.selector(index), initial[index]);
            assert_eq!(
                store.drain_async_persistence().await,
                Err(SessionPersistenceDrainError::Failed(failure))
            );
            assert_recorded(store, &request, &outcome).await;
        }
        assert!(fleet.engine_calls_from(fleet.peers[leader].node) > 0);
        for (index, selected) in initial.iter().enumerate() {
            assert!(fleet.close_result(index).await.is_err());
            assert_eq!(fleet.selector(index), *selected);
        }
        let before = fleet
            .peers
            .iter()
            .map(|peer| fleet.engine_calls_from(peer.node))
            .collect::<Vec<_>>();
        for index in 0..3 {
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
            let cold = fleet.store(index);
            assert_eq!(
                cold.persistence_health().recovery,
                Some(SessionAsyncRecoveryState::AwaitingLiveQuorum)
            );
            assert!(cold.inner.raft.metrics().borrow().last_applied.is_none());
            assert!(!cold.status().admitted);
        }
        for cold in fleet.stores.iter().flatten() {
            cold.inner.raft.trigger().elect().await.unwrap();
        }
        let results = join_all(
            fleet
                .stores
                .iter()
                .flatten()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        assert!(
            results
                .iter()
                .all(|result| *result == Err(ConsensusSessionStoreOpenError::RecoveryRequired)),
            "participated but never persisted, then all-cold: {results:?}"
        );
        for (index, cold) in fleet.stores.iter().flatten().enumerate() {
            assert_eq!(
                fleet.engine_calls_from(fleet.peers[index].node),
                before[index]
            );
            assert_eq!(
                cold.probe_fixed_quorum_readiness()
                    .await
                    .traffic_authority(),
                FixedQuorumTrafficAuthority::RecoveryRequired
            );
            assert!(cold.fenced_transition_v2_status(&request).await.is_err());
            assert!(!cold.status().admitted);
            assert!(cold.inner.raft.metrics().borrow().last_applied.is_none());
        }
    })
    .catch_unwind()
    .await;
    // A failed assertion may leave a faulted writer. shutdown still joins it
    // and may report its expected drain error; preserve the original panic.
    let mut shutdown = Vec::new();
    for index in 0..3 {
        shutdown.push(fleet.close_result(index).await);
    }
    if result.is_ok() {
        assert!(
            shutdown.iter().all(Result::is_ok),
            "cold shutdown: {shutdown:?}"
        );
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
