//! A failed startup resource allocation must leave a clean volume unchanged.

use std::path::{Path, PathBuf};

use super::*;
use crate::sqlite::startup_pressure;

fn retained_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

async fn failed_timer_preserves_clean_restart(mode: SessionPersistenceMode) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        for index in 0..3 {
            fleet.open(index, mode).await.unwrap();
        }
        fleet.form().await;
        for index in 0..3 {
            fleet.close_clean(index).await.unwrap();
        }
        // Positive control: these two clean voters can serve with the third offline.
        for index in 0..2 {
            fleet.open(index, mode).await.unwrap();
        }
        fleet.form().await;
        for index in 0..2 {
            fleet.close_clean(index).await.unwrap();
        }

        let proof = PathBuf::from("node-0.sqlite.native-wal/ASYNC-CLOSED");
        let before = retained_files(fleet.directory.path());
        if mode == SessionPersistenceMode::Async {
            assert!(before.contains_key(&proof), "clean shutdown publishes its proof");
        }
        let calls = fleet.engine_calls_from(fleet.peers[0].node);
        startup_pressure::arm();
        let failure = fleet.open(0, mode).await.expect_err("startup timer must actually fail");
        let after = retained_files(fleet.directory.path());
        assert_eq!(
            fleet.engine_calls_from(fleet.peers[0].node), calls,
            "a failed startup must not send an engine RPC"
        );
        eprintln!(
            "mode={mode:?}, startup={failure:?}, retained_files_unchanged={}, clean_proof_retained={}",
            before == after, after.contains_key(&proof)
        );

        fleet.open(0, mode).await.expect("retry the same volume after pressure clears");
        let health = fleet.store(0).persistence_health();
        assert!(
            fleet.store(0).inner.persistence_protocol.is_active(),
            "startup allocation failure must preserve clean-restart admission: {:?}", health.recovery
        );
        if mode == SessionPersistenceMode::Async {
            assert_eq!(health.recovery, Some(SessionAsyncRecoveryState::Active));
            assert_eq!(after.get(&proof), before.get(&proof), "failed open preserves the exact proof");
            assert!(!fleet.directory.path().join(&proof).exists(), "successful retry still consumes the one-use proof");
        }
        assert!(before == after, "failed startup must preserve all retained file names and bytes");
        fleet.open(1, mode).await.unwrap();
        assert!(fleet.stores[2].is_none(), "third voter remains offline");
        fleet.form().await;
        assert!(fleet.stores[2].is_none());
        for index in 0..2 {
            fleet.close_clean(index).await.unwrap();
        }
        if mode == SessionPersistenceMode::Async {
            assert!(fleet.directory.path().join(&proof).is_file(), "successful retry can publish a new clean proof");
        }
        // The failure must identify both the startup resource and the OS cause.
        assert_eq!(failure, ConsensusSessionStoreOpenError::AuthorityBackoffUnavailable {
            kind: std::io::Error::from_raw_os_error(libc::EMFILE).kind(),
            raw_os_error: Some(libc::EMFILE),
        });
        let diagnostic = failure.to_string();
        assert!(diagnostic.contains("authority backoff timer"), "{diagnostic}");
        assert!(diagnostic.contains(&std::io::Error::from_raw_os_error(libc::EMFILE).to_string()), "{diagnostic}");
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test]
async fn fixed_startup_timer_emfile_preserves_async_clean_restart() {
    if startup_pressure::isolate(concat!(
        module_path!(),
        "::fixed_startup_timer_emfile_preserves_async_clean_restart"
    )) {
        return;
    }
    failed_timer_preserves_clean_restart(SessionPersistenceMode::Async).await;
}

#[tokio::test]
async fn fixed_startup_timer_emfile_preserves_durable_clean_restart() {
    if startup_pressure::isolate(concat!(
        module_path!(),
        "::fixed_startup_timer_emfile_preserves_durable_clean_restart"
    )) {
        return;
    }
    failed_timer_preserves_clean_restart(SessionPersistenceMode::Durable).await;
}
