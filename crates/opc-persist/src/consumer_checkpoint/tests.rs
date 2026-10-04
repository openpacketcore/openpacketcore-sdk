use super::*;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider};
use std::collections::BTreeMap;
use std::str::FromStr;

fn options(path: &Path) -> ConsumerCheckpointOptions {
    let scope = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x21; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x22; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let binding = ConsumerCheckpointBinding::new(
        scope,
        SchemaDigest::from_bytes([0x31; 32]),
        SpiffeId::from_str("spiffe://checkpoint.test/tenant/checkpoint-test/ns/default/sa/consumer/nf/smf/instance/one").unwrap(),
        TenantId::from_static("checkpoint-test"),
        [0x41; 32],
    )
    .unwrap();
    ConsumerCheckpointOptions::new(
        path,
        binding,
        RetainedConfigDurability::Ephemeral,
        1024 * 1024,
        16 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .unwrap()
}

fn keys(seed: u8) -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("checkpoint-test-key").unwrap(),
            KeyPurpose::ConfigConsumerCheckpoint,
            TenantId::from_static("checkpoint-test"),
            Zeroizing::new([seed; 32]),
        )
        .unwrap();
    provider
}

fn files(path: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read(entry.path()).unwrap())
        })
        .collect()
}

#[tokio::test]
async fn checkpoint_drop_and_shutdown_hold_admission_through_sqlite_close() {
    struct CloseProbe {
        path: PathBuf,
        saw_lock: Arc<AtomicBool>,
    }
    impl Drop for CloseProbe {
        fn drop(&mut self) {
            let file = open_file(&self.path, true, false).expect("lock file");
            let result =
                rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive);
            self.saw_lock.store(
                result == Err(rustix::io::Errno::WOULDBLOCK),
                Ordering::Release,
            );
        }
    }
    for explicit_shutdown in [false, true] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("checkpoint.sqlite");
        let provider = keys(0x51);
        let store = ConsumerCheckpointStore::provision(options(&path), provider.clone())
            .await
            .expect("provision");
        let saw_lock = Arc::new(AtomicBool::new(false));
        let probe = CloseProbe {
            path: lock_path(&path),
            saw_lock: Arc::clone(&saw_lock),
        };
        // SQLite removes this callback before closing. It must not be the
        // final owner of the admission guard, including on explicit shutdown.
        store
            .connection
            .lock()
            .expect("connection")
            .as_ref()
            .expect("open")
            .authorizer(Some(move |_: rusqlite::hooks::AuthContext<'_>| {
                let _ = &probe;
                rusqlite::hooks::Authorization::Allow
            }))
            .expect("SQLite test hook registration");
        if explicit_shutdown {
            store.shutdown().await.expect("shutdown");
        } else {
            drop(store);
        }
        assert!(
            saw_lock.load(Ordering::Acquire),
            "checkpoint admission ended before SQLite close"
        );
        ConsumerCheckpointStore::reopen(options(&path), provider)
            .await
            .expect("reopen after close")
            .shutdown()
            .await
            .expect("release");
    }
}

#[tokio::test]
async fn checkpoint_is_sealed_cas_storage_without_voter_or_authoring_tables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let options = options(&path);
    let provider = keys(0x51);
    let mut store = ConsumerCheckpointStore::provision(options.clone(), provider.clone())
        .await
        .unwrap();
    let (generation, empty) = store.read_back().await.unwrap().into_parts();
    assert_eq!(generation, 1);
    assert!(empty.is_empty());
    let payload = b"synthetic-config-private-canary".to_vec();
    let (next, read) = store
        .compare_and_set(generation, Zeroizing::new(payload.clone()))
        .await
        .unwrap()
        .into_parts();
    assert_eq!(next, 2);
    assert_eq!(*read, payload);
    assert_eq!(
        store
            .compare_and_set(generation, Zeroizing::new(vec![1]))
            .await
            .unwrap_err(),
        ConsumerCheckpointError::Conflict
    );
    let (actual, _) = store.read_back().await.unwrap().into_parts();
    assert_eq!(actual, next);
    store.shutdown().await.unwrap();
    for bytes in files(dir.path()).values() {
        assert!(!bytes.windows(payload.len()).any(|w| w == payload));
    }
    let conn = Connection::open(&path).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(tables, ["consumer_checkpoint"]);
    drop(conn);
    let mut reopened = ConsumerCheckpointStore::reopen(options.clone(), provider.clone())
        .await
        .unwrap();
    let (actual, read) = reopened.read_back().await.unwrap().into_parts();
    assert_eq!(actual, next);
    assert_eq!(*read, payload);
    assert_eq!(
        ConsumerCheckpointStore::reopen(options.clone(), provider.clone())
            .await
            .unwrap_err(),
        ConsumerCheckpointError::InUse
    );
    reopened.shutdown().await.unwrap();
    let before = files(dir.path());
    assert_eq!(
        ConsumerCheckpointStore::provision(options, provider)
            .await
            .unwrap_err(),
        ConsumerCheckpointError::AlreadyExists
    );
    assert_eq!(before, files(dir.path()));
}

#[tokio::test]
async fn reopen_rejects_extra_schema_objects_with_sqlite_lookalike_names() {
    // SDK #799 requires the checkpoint's exact storage schema. Ordinary user
    // objects can resemble SQLite's reserved prefix without using that prefix.
    for extra in [
        "CREATE TABLE sqliteXextra (value BLOB)",
        "CREATE INDEX sqliteXextra ON consumer_checkpoint(generation)",
        "CREATE VIEW sqliteXextra AS SELECT generation FROM consumer_checkpoint",
        "CREATE TRIGGER sqliteXextra BEFORE UPDATE ON consumer_checkpoint BEGIN SELECT RAISE(IGNORE); END",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.sqlite");
        let options = options(&path);
        let provider = keys(0x61);
        let mut store = ConsumerCheckpointStore::provision(options.clone(), provider.clone())
            .await
            .unwrap();
        let (generation, _) = store.read_back().await.unwrap().into_parts();
        store
            .compare_and_set(generation, Zeroizing::new(b"synthetic checkpoint".to_vec()))
            .await
            .unwrap();
        store.shutdown().await.unwrap();

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(extra).unwrap();
        drop(conn);
        let before = files(dir.path());
        let result = ConsumerCheckpointStore::reopen(options, provider).await;
        assert!(
            matches!(result, Err(ConsumerCheckpointError::Rejected)),
            "extra application schema must reject reopen: {extra}"
        );
        assert_eq!(before, files(dir.path()));
    }
}

#[tokio::test]
async fn wrong_scope_schema_consumer_backing_key_and_truncation_do_not_modify_original() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let options = options(&path);
    let provider = keys(0x52);
    ConsumerCheckpointStore::provision(options.clone(), provider.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    for mutation in 0..6 {
        let mut wrong = options.clone();
        let mut key: Arc<dyn KeyProvider> = provider.clone();
        match mutation {
            0 => {
                wrong.binding.scope = ConfigConsensusIdentity::new(
                    wrong.binding.scope.cluster_id(),
                    wrong.binding.scope.configuration_id(),
                    ConfigConsensusConfigurationEpoch::new(2).unwrap(),
                )
            }
            1 => wrong.binding.schema = SchemaDigest::from_bytes([0x32; 32]),
            2 => {
                wrong.binding.consumer =
                    SpiffeId::from_str("spiffe://checkpoint.test/tenant/checkpoint-test/ns/default/sa/consumer/nf/smf/instance/two").unwrap()
            }
            3 => wrong.binding.backing = [0x42; 32],
            4 => wrong.binding.tenant = TenantId::from_static("wrong-checkpoint-test"),
            _ => key = keys(0x53),
        }
        let before = files(dir.path());
        assert_eq!(
            ConsumerCheckpointStore::reopen(wrong, key)
                .await
                .unwrap_err(),
            ConsumerCheckpointError::Rejected
        );
        assert_eq!(before, files(dir.path()));
    }
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, &original[..original.len() / 2]).unwrap();
    let before = files(dir.path());
    assert!(
        ConsumerCheckpointStore::reopen(options.clone(), provider.clone())
            .await
            .is_err()
    );
    assert_eq!(before, files(dir.path()));
    std::fs::remove_file(&path).unwrap();
    let before = files(dir.path());
    assert_eq!(
        ConsumerCheckpointStore::reopen(options, provider)
            .await
            .unwrap_err(),
        ConsumerCheckpointError::RecoveryRequired
    );
    assert_eq!(before, files(dir.path()));
}

#[tokio::test]
async fn rotation_reseals_the_complete_checkpoint_without_an_old_key_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let options = options(&path);
    let provider = keys(0x54);
    let mut store = ConsumerCheckpointStore::provision(options.clone(), provider.clone())
        .await
        .unwrap();
    let (generation, _) = store.read_back().await.unwrap().into_parts();
    let new_id = provider
        .rotate_key(
            KeyPurpose::ConfigConsumerCheckpoint,
            &options.binding.tenant,
        )
        .await
        .unwrap();
    let rotated = provider.get_key_by_id(&new_id).await.unwrap();
    store
        .compare_and_set(
            generation,
            Zeroizing::new(b"synthetic rotated payload".to_vec()),
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    let historical_only = Arc::new(MemoryKeyProvider::new());
    historical_only.insert_historical_key(rotated).unwrap();
    let mut reopened = ConsumerCheckpointStore::reopen(options, historical_only)
        .await
        .unwrap();
    assert_eq!(
        &**reopened.read_back().await.unwrap().into_parts().1,
        b"synthetic rotated payload"
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn byte_bounds_and_file_replacement_fence_the_handle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let options = options(&path);
    let provider = keys(0x55);
    let mut store = ConsumerCheckpointStore::provision(options.clone(), provider)
        .await
        .unwrap();
    let (generation, _) = store.read_back().await.unwrap().into_parts();
    assert_eq!(
        store
            .compare_and_set(
                generation,
                Zeroizing::new(vec![0; options.max_payload_bytes + 1])
            )
            .await
            .unwrap_err(),
        ConsumerCheckpointError::Limit
    );
    let original = std::fs::read(&path).unwrap();
    std::fs::rename(&path, path.with_extension("displaced")).unwrap();
    std::fs::write(&path, original).unwrap();
    assert!(store.read_back().await.is_err());
    assert_eq!(
        store
            .compare_and_set(generation, Zeroizing::new(vec![1]))
            .await
            .unwrap_err(),
        ConsumerCheckpointError::Conflict
    );
}

pub(super) fn crash_at(stage: &str) {
    if std::env::var("OPC_CHECKPOINT_STORAGE_CUT").as_deref() == Ok(stage) {
        std::process::exit(92);
    }
}

#[test]
fn checkpoint_storage_process_child() {
    let Some(path) = std::env::var_os("OPC_CHECKPOINT_STORAGE_CHILD") else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let options = options(Path::new(&path));
        let provider = keys(0x56);
        if std::env::var("OPC_CHECKPOINT_STORAGE_CUT")
            .unwrap()
            .starts_with("provision-")
        {
            let store = ConsumerCheckpointStore::provision(options, provider)
                .await
                .unwrap();
            store.shutdown().await.unwrap();
        } else {
            let mut store = ConsumerCheckpointStore::reopen(options, provider)
                .await
                .unwrap();
            let (generation, _) = store.read_back().await.unwrap().into_parts();
            store
                .connection
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .pragma_update(None, "wal_autocheckpoint", 0)
                .unwrap();
            store
                .compare_and_set(
                    generation,
                    Zeroizing::new(b"synthetic-after-crash".to_vec()),
                )
                .await
                .unwrap();
        }
    });
    panic!("configured storage cut was not reached");
}

fn run_crash(path: &Path, stage: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "consumer_checkpoint::tests::checkpoint_storage_process_child",
            "--nocapture",
        ])
        .env("OPC_CHECKPOINT_STORAGE_CHILD", path)
        .env("OPC_CHECKPOINT_STORAGE_CUT", stage)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(92));
}

#[tokio::test]
async fn provisioning_process_cuts_never_turn_partial_storage_into_new_state() {
    for stage in [
        "provision-lock",
        "provision-database",
        "provision-schema",
        "provision-complete",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.sqlite");
        run_crash(&path, stage);
        let before = files(dir.path());
        assert_eq!(
            ConsumerCheckpointStore::provision(options(&path), keys(0x56))
                .await
                .unwrap_err(),
            ConsumerCheckpointError::AlreadyExists
        );
        assert_eq!(files(dir.path()), before);
        let result = ConsumerCheckpointStore::reopen(options(&path), keys(0x56)).await;
        if stage == "provision-complete" {
            let mut store = result.unwrap();
            let (generation, bytes) = store.read_back().await.unwrap().into_parts();
            assert_eq!(generation, 1);
            assert!(bytes.is_empty());
            store.shutdown().await.unwrap();
        } else {
            assert!(result.is_err());
            assert_eq!(files(dir.path()), before);
        }
    }
}

#[tokio::test]
async fn actual_wal_process_loss_recovers_only_complete_authenticated_transactions() {
    for stage in ["before-commit", "after-commit", "after-checkpoint"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.sqlite");
        let options = options(&path);
        let mut store = ConsumerCheckpointStore::provision(options.clone(), keys(0x56))
            .await
            .unwrap();
        store.read_back().await.unwrap();
        store
            .compare_and_set(1, Zeroizing::new(b"synthetic-before-crash".to_vec()))
            .await
            .unwrap();
        store.shutdown().await.unwrap();
        run_crash(&path, stage);
        if stage == "after-commit" {
            assert!(std::fs::metadata(suffixed(&path, "-wal")).unwrap().len() > 32);
        }
        let before = files(dir.path());
        assert_eq!(
            ConsumerCheckpointStore::reopen(options.clone(), keys(0x57))
                .await
                .unwrap_err(),
            ConsumerCheckpointError::Rejected
        );
        assert_eq!(files(dir.path()), before);
        let mut store = ConsumerCheckpointStore::reopen(options, keys(0x56))
            .await
            .unwrap();
        let (generation, bytes) = store.read_back().await.unwrap().into_parts();
        if stage == "before-commit" {
            assert_eq!(generation, 2);
            assert_eq!(&**bytes, b"synthetic-before-crash");
        } else {
            assert_eq!(generation, 3);
            assert_eq!(&**bytes, b"synthetic-after-crash");
        }
        store.shutdown().await.unwrap();
    }
}

fn minimum_budget_options(path: &Path, maximum_payload: usize) -> ConsumerCheckpointOptions {
    let template = options(path);
    let candidate = |budget| {
        ConsumerCheckpointOptions::new(
            path,
            template.binding.clone(),
            template.durability,
            maximum_payload,
            budget,
            template.timeout,
        )
    };
    // Find the public constructor's actual acceptance boundary. A successful
    // options object must accommodate its declared payload, regardless of the
    // internal storage-capacity formula.
    let mut rejected = 0;
    let mut accepted = 1024 * 1024 * 1024;
    assert!(candidate(accepted).is_ok());
    while accepted - rejected > 1 {
        let budget = rejected + (accepted - rejected) / 2;
        if candidate(budget).is_ok() {
            accepted = budget;
        } else {
            rejected = budget;
        }
    }
    candidate(accepted).unwrap()
}

#[tokio::test]
async fn maximum_payload_fits_the_minimum_accepted_storage_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let maximum_payload = 16 * 1024 * 1024;
    let options = minimum_budget_options(&path, maximum_payload);
    let accepted = options.max_storage_bytes;
    let mut store = ConsumerCheckpointStore::provision(options.clone(), keys(0x60))
        .await
        .unwrap();
    store.read_back().await.unwrap();
    for (index, size) in [maximum_payload, maximum_payload / 2, maximum_payload]
        .into_iter()
        .enumerate()
    {
        let generation = index as u64 + 1;
        let payload = Zeroizing::new(vec![generation as u8; size]);
        let result = store.compare_and_set(generation, payload.clone()).await;
        assert!(
            result.is_ok(),
            "accepted storage budget {accepted} cannot store maximum payload at generation {generation}: {result:?}"
        );
        assert_eq!(*result.unwrap().into_parts().1, *payload);
        check_storage_size(&options).unwrap();
    }
    store.shutdown().await.unwrap();
    let mut reopened = ConsumerCheckpointStore::reopen(options, keys(0x60))
        .await
        .unwrap();
    let (generation, payload) = reopened.read_back().await.unwrap().into_parts();
    assert_eq!(generation, 4);
    assert_eq!(&**payload, vec![3; maximum_payload]);
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn repeated_maximum_replacements_remain_within_the_minimum_storage_budget() {
    let dir = tempfile::tempdir().unwrap();
    let options = minimum_budget_options(&dir.path().join("checkpoint.sqlite"), 65536);
    let mut store = ConsumerCheckpointStore::provision(options.clone(), keys(0x58))
        .await
        .unwrap();
    store.read_back().await.unwrap();
    for generation in 1..=20 {
        let payload = Zeroizing::new(vec![
            generation as u8;
            if generation % 2 == 0 { 32768 } else { 65536 }
        ]);
        let read = store
            .compare_and_set(generation, payload.clone())
            .await
            .unwrap();
        assert_eq!(*read.into_parts().1, *payload);
        check_storage_size(&options).unwrap();
    }
    store.shutdown().await.unwrap();
    let mut store = ConsumerCheckpointStore::reopen(options, keys(0x58))
        .await
        .unwrap();
    assert_eq!(store.read_back().await.unwrap().into_parts().0, 21);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancellation_retains_owned_io_and_requires_readback_before_retry() {
    let dir = tempfile::tempdir().unwrap();
    let options = options(&dir.path().join("checkpoint.sqlite"));
    let mut store = ConsumerCheckpointStore::provision(options.clone(), keys(0x59))
        .await
        .unwrap();
    store.read_back().await.unwrap();
    let connection = store.connection.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _guard = connection.lock().unwrap();
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    entered_rx.await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(50),
        store.compare_and_set(1, Zeroizing::new(b"cancelled synthetic value".to_vec()))
    )
    .await
    .is_err());
    assert!(store.pending.is_some());
    assert_eq!(
        store
            .compare_and_set(1, Zeroizing::new(vec![1]))
            .await
            .unwrap_err(),
        ConsumerCheckpointError::Conflict
    );
    assert_eq!(
        ConsumerCheckpointStore::reopen(options.clone(), keys(0x59))
            .await
            .unwrap_err(),
        ConsumerCheckpointError::InUse
    );
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let (generation, payload) = store.read_back().await.unwrap().into_parts();
    assert_eq!(generation, 1);
    assert!(payload.is_empty());
    store.shutdown().await.unwrap();
    ConsumerCheckpointStore::reopen(options, keys(0x59))
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}
