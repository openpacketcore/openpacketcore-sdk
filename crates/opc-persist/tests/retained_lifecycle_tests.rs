//! Synthetic retained-authority lifecycle regressions for issue #800.
#![cfg(unix)]
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConfigStore, ConsensusConfigStore, RetainedConfigBinding,
    RetainedConfigDurability, RetainedConfigError, RetainedConfigOptions, SqliteBackend,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

fn topology(epoch: u64) -> ConfigConsensusTopology {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(epoch).expect("synthetic epoch"),
    );
    let node = ConfigConsensusNodeId::new(1).expect("synthetic node");
    ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).expect("topology")
}
fn options(path: &Path, epoch: u64, backing: u8, scope: u8, limit: u64) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology(epoch), [backing; 32], [scope; 32]).expect("binding"),
        RetainedConfigDurability::Ephemeral,
        limit,
        Duration::from_secs(30),
    )
    .expect("options")
}
fn ordinary(path: &Path) -> RetainedConfigOptions {
    options(path, 1, 0x41, 0x42, 16 * 1024 * 1024)
}
fn key() -> AuditKey {
    AuditKey::new([0x71; 32]).expect("synthetic key")
}
fn files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(path)
        .expect("directory")
        .map(|entry| {
            let entry = entry.expect("entry");
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).expect("bytes"),
            )
        })
        .collect()
}
async fn provision(path: &Path) -> SqliteBackend {
    SqliteBackend::provision_config_authority(ordinary(path), key())
        .await
        .expect("provision")
}
#[tokio::test]
async fn ordinary_restart_cannot_recreate_missing_retained_database() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    std::fs::rename(&path, dir.path().join("removed.sqlite")).expect("storage loss");
    let before = files(dir.path());
    assert!(matches!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::RecoveryRequired)
    ));
    assert!(!path.exists());
    assert_eq!(before, files(dir.path()));
}

#[tokio::test]
async fn whole_group_storage_loss_cannot_recreate_authority_on_restart() {
    let dir = tempfile::tempdir().expect("storage");
    let nodes = [1, 2, 3].map(|id| ConfigConsensusNodeId::new(id).expect("node"));
    let mut candidates = Vec::new();
    for node in nodes {
        let path = dir.path().join(format!("member-{}.sqlite", node.get()));
        let scope = ConfigConsensusTopology::try_new(
            topology(1).identity(),
            node,
            nodes.into_iter().collect(),
        )
        .expect("roster");
        let candidate = RetainedConfigOptions::new(
            &path,
            RetainedConfigBinding::new(scope, [0x41; 32], [0x42; 32]).expect("binding"),
            RetainedConfigDurability::Ephemeral,
            16 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .expect("options");
        drop(
            SqliteBackend::provision_config_authority(candidate.clone(), key())
                .await
                .expect("member"),
        );
        candidates.push(candidate);
    }
    for entry in std::fs::read_dir(dir.path()).expect("fixture storage") {
        std::fs::remove_file(entry.expect("fixture file").path()).expect("synthetic group loss");
    }
    let before = files(dir.path());
    for candidate in candidates {
        assert!(matches!(
            SqliteBackend::reopen_config_authority(candidate, key()).await,
            Err(RetainedConfigError::RecoveryRequired)
        ));
        assert_eq!(before, files(dir.path()));
    }
}

#[tokio::test]
async fn missing_or_altered_authority_metadata_is_never_initialized_on_reopen() {
    for sql in [
        "DROP TABLE consensus_retained_binding",
        "DELETE FROM consensus_retained_binding",
        "CREATE TRIGGER consensus_retained_extra AFTER INSERT ON consensus_retained_binding BEGIN SELECT 1; END",
        "DROP TABLE config_raft_identity",
        "DELETE FROM config_raft_machine",
    ] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        drop(provision(&path).await);
        let conn = rusqlite::Connection::open(&path).expect("synthetic fault access");
        conn.execute_batch(sql).expect("metadata mutation");
        drop(conn);
        let before = files(dir.path());
        assert!(SqliteBackend::reopen_config_authority(ordinary(&path),key()).await.is_err());
        assert_eq!(before,files(dir.path()));
    }
}

#[tokio::test]
async fn retained_preflight_cannot_overwrite_a_legacy_probe_file() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    std::fs::write(
        dir.path().join(".opc_persist_fsync_test"),
        b"PRIVATE-PROBE-CANARY",
    )
    .expect("unrelated file");
    let conn = rusqlite::Connection::open(&path).expect("fault connection");
    conn.execute_batch("DELETE FROM consensus_retained_binding")
        .expect("corrupt metadata");
    drop(conn);
    let candidate = RetainedConfigOptions::new(
        &path,
        RetainedConfigBinding::new(topology(1), [0x41; 32], [0x42; 32]).expect("binding"),
        RetainedConfigDurability::Durable { min_free_bytes: 0 },
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("options");
    let before = files(dir.path());
    assert!(SqliteBackend::reopen_config_authority(candidate, key())
        .await
        .is_err());
    assert_eq!(before, files(dir.path()));
}
#[tokio::test]
async fn explicit_provision_then_reopen_preserves_storage_and_profile() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = provision(&path).await;
    assert!(backend.load_latest().await.expect("read").is_none());
    drop(backend);
    let backend = SqliteBackend::reopen_config_authority(ordinary(&path), key())
        .await
        .expect("reopen");
    assert!(backend.load_latest().await.expect("read").is_none());
    assert!(backend.preflight().await.expect("profile").ephemeral_mode);
}
#[tokio::test]
async fn concurrent_openers_cannot_acquire_two_backing_leases() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let first = provision(&path).await;
    assert!(matches!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::InUse)
    ));
    let clone = first.clone();
    drop(first);
    assert!(matches!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::InUse)
    ));
    drop(clone);
    assert!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key())
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn wrong_key_scope_epoch_and_backing_reject_without_touching_sqlite() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    let before = files(dir.path());
    for candidate in [
        options(&path, 2, 0x41, 0x42, 16 * 1024 * 1024),
        options(&path, 1, 0x43, 0x42, 16 * 1024 * 1024),
        options(&path, 1, 0x41, 0x43, 16 * 1024 * 1024),
    ] {
        let result = SqliteBackend::reopen_config_authority(candidate, key()).await;
        assert!(
            matches!(&result, Err(RetainedConfigError::Rejected)),
            "wrong retained binding outcome: {:?}",
            result.err()
        );
        assert_eq!(before, files(dir.path()));
    }
    for wrong_key in [
        AuditKey::new([0x72; 32]).expect("other key"),
        AuditKey::new_with_epoch([0x71; 32], 2).expect("other epoch"),
    ] {
        assert!(matches!(
            SqliteBackend::reopen_config_authority(ordinary(&path), wrong_key).await,
            Err(RetainedConfigError::Rejected)
        ));
        assert_eq!(before, files(dir.path()));
    }
}
#[tokio::test]
async fn rejected_corruption_leaves_database_and_journals_unchanged() {
    use std::io::Write;
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("file");
    file.write_all(b"corrupt-header!!")
        .expect("corrupt fixture");
    file.sync_all().expect("sync");
    drop(file);
    let before = files(dir.path());
    assert!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key())
            .await
            .is_err()
    );
    assert_eq!(
        before,
        files(dir.path()),
        "failed validation must not create WAL sidecars"
    );
}
#[tokio::test]
async fn copied_database_cannot_substitute_for_exact_backing_identity() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    let copy = dir.path().join("copy.sqlite");
    std::fs::copy(&path, &copy).expect("copy");
    std::fs::rename(copy, &path).expect("replace");
    let before = files(dir.path());
    assert!(matches!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::Rejected)
    ));
    assert_eq!(before, files(dir.path()));
}
#[tokio::test]
async fn provisioning_never_adopts_existing_or_incomplete_storage() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    std::fs::write(&path, b"interrupted provisioning").expect("fixture");
    let before = files(dir.path());
    assert!(matches!(
        SqliteBackend::provision_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::AlreadyExists)
    ));
    assert_eq!(before, files(dir.path()));
    assert!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key())
            .await
            .is_err()
    );
    assert_eq!(before, files(dir.path()));
}
#[tokio::test]
async fn validation_byte_bound_precedes_original_recovery() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    let before = files(dir.path());
    assert!(matches!(
        SqliteBackend::reopen_config_authority(options(&path, 1, 0x41, 0x42, 64), key()).await,
        Err(RetainedConfigError::AdmissionBound)
    ));
    assert_eq!(before, files(dir.path()));
}
#[tokio::test]
async fn legacy_create_or_open_cannot_bypass_retained_admission() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    let before = files(dir.path());
    assert!(SqliteBackend::open_with_audit_key(&path, true, 0, key())
        .await
        .is_err());
    assert_eq!(before, files(dir.path()));
}
#[tokio::test]
async fn symlink_and_hardlink_substitution_fail_closed() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(provision(&path).await);
    let original = dir.path().join("original.sqlite");
    std::fs::rename(&path, &original).expect("move");
    std::os::unix::fs::symlink(&original, &path).expect("symlink");
    assert!(matches!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::Rejected)
    ));
    std::fs::remove_file(&path).expect("remove fixture link");
    std::fs::hard_link(&original, &path).expect("hardlink");
    assert!(matches!(
        SqliteBackend::reopen_config_authority(ordinary(&path), key()).await,
        Err(RetainedConfigError::Rejected)
    ));
}
#[tokio::test]
async fn topology_mismatch_rejects_before_snapshot_directory_creation() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = provision(&path).await;
    let snapshots = dir.path().join("snapshots");
    assert!(
        ConsensusConfigStore::open(topology(2), backend, &snapshots, BTreeMap::new())
            .await
            .is_err()
    );
    assert!(!snapshots.exists());
}
#[tokio::test]
async fn diagnostics_do_not_expose_paths_or_binding_values() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("PRIVATE-STORAGE-CANARY.sqlite");
    let options = ordinary(&path);
    let backend = SqliteBackend::provision_config_authority(options.clone(), key())
        .await
        .expect("provision");
    let printed = format!(
        "{options:?} {backend:?} {:?}",
        RetainedConfigError::Rejected
    );
    assert!(!printed.contains("PRIVATE-STORAGE-CANARY"));
    assert!(!printed.contains(&path.to_string_lossy().to_string()));
}
