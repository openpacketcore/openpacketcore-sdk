//! Profile admission before original native WAL recovery.
//! These tests do not qualify larger configuration consensus or snapshots.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use opc_crypto::ConfigCapacityProfile;
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConfigStore, ConsensusConfigStore, PersistErrorKind,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigError, RetainedConfigOptions,
    SqliteBackend,
};
use sha2::{Digest, Sha256};

fn topology() -> ConfigConsensusTopology {
    let node = ConfigConsensusNodeId::new(1).expect("synthetic node");
    ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xE1; 32]),
            ConfigConsensusConfigurationId::from_bytes([0xE2; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("singleton fixture topology")
}

fn options(path: &Path, profile: ConfigCapacityProfile) -> RetainedConfigOptions {
    let binding = RetainedConfigBinding::new(topology(), [0xE3; 32], [0xE4; 32])
        .expect("synthetic scope")
        .with_capacity_profile(profile);
    assert_eq!(binding.capacity_profile(), profile);
    RetainedConfigOptions::new(
        path,
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained limits")
}

fn key() -> AuditKey {
    AuditKey::new([0xE5; 32]).expect("synthetic audit key")
}

fn disk_fixture() -> PathBuf {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit local or hosted scratch root is required");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-profile-")
        .tempdir_in(scratch)
        .expect("private retained profile fixture")
        .keep();
    let output = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector required");
    assert!(output.status.success(), "filesystem detection failed");
    let filesystem = std::str::from_utf8(&output.stdout)
        .expect("filesystem encoding")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    root
}

fn file_digests(root: &Path) -> BTreeMap<std::ffi::OsString, [u8; 32]> {
    std::fs::read_dir(root)
        .expect("fixture directory")
        .map(|entry| {
            let entry = entry.expect("fixture entry");
            let bytes = std::fs::read(entry.path()).expect("fixture file");
            (entry.file_name(), Sha256::digest(bytes).into())
        })
        .collect()
}

#[test]
fn config_capacity_957_native_wal_child() {
    let Some(path) = std::env::var_os("OPC_CONFIG_CAPACITY_957_WAL_FIXTURE") else {
        return;
    };
    let connection = rusqlite::Connection::open_with_flags(
        PathBuf::from(path),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .expect("open previously provisioned synthetic store");
    let record: Vec<u8> = connection
        .query_row(
            "SELECT record FROM consensus_retained_binding WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("original valid binding");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA wal_autocheckpoint=0;
             BEGIN IMMEDIATE;
             DELETE FROM consensus_retained_binding WHERE singleton=1;",
        )
        .expect("dirty the binding page inside one native transaction");
    // SQLite may elide an unchanged-value UPDATE entirely. Remove and restore
    // the exact authenticated row in one transaction to require a WAL frame
    // while preserving the provisioned authority and its complete schema.
    assert_eq!(
        connection
            .execute(
                "INSERT INTO consensus_retained_binding (singleton, record) VALUES (1, ?1)",
                [&record],
            )
            .expect("restore the exact original binding"),
        1
    );
    connection
        .execute_batch("COMMIT;")
        .expect("durably commit unchanged valid binding through native WAL");
    let committed: Vec<u8> = connection
        .query_row(
            "SELECT record FROM consensus_retained_binding WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("committed binding");
    assert!(committed == record, "native WAL preserves exact binding");
    // Abrupt exit retains the real WAL. No destructor may checkpoint it first.
    std::process::exit(91);
}

#[tokio::test]
async fn config_capacity_957_profile_mismatch_precedes_original_wal_recovery() {
    for (selected, rejected) in [
        (
            ConfigCapacityProfile::BoundedV1,
            ConfigCapacityProfile::Legacy,
        ),
        (
            ConfigCapacityProfile::Legacy,
            ConfigCapacityProfile::BoundedV1,
        ),
    ] {
        let root = disk_fixture();
        let path = root.join("config.sqlite");
        drop(
            SqliteBackend::provision_config_authority(options(&path, selected), key())
                .await
                .expect("provision native retained authority"),
        );
        let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "config_capacity_957_native_wal_child"])
            .env("OPC_CONFIG_CAPACITY_957_WAL_FIXTURE", &path)
            .output()
            .expect("run finite WAL fixture child");
        assert_eq!(
            child.status.code(),
            Some(91),
            "native WAL setup must complete"
        );
        assert!(
            std::fs::metadata(root.join("config.sqlite-wal"))
                .expect("native WAL")
                .len()
                > 32
        );
        let before = file_digests(&root);
        let rejected_result =
            SqliteBackend::reopen_config_authority(options(&path, rejected), key()).await;
        assert!(
            matches!(rejected_result, Err(RetainedConfigError::Rejected)),
            "wrong profile rejects"
        );
        assert!(
            before == file_digests(&root),
            "rejection must preserve every original file byte"
        );
        drop(
            SqliteBackend::reopen_config_authority(options(&path, selected), key())
                .await
                .expect("matching profile recovers the exact original WAL"),
        );
        println!("CONFIG_CAPACITY_PROFILE wrong_profile_rejected=true original_files_unchanged=true matching_reopen=true");
    }
}

#[tokio::test]
async fn config_capacity_957_store_profile_owns_reservations_and_requires_history_proofs() {
    let root = disk_fixture();
    let backend = SqliteBackend::provision_config_authority(
        options(
            &root.join("config.sqlite"),
            ConfigCapacityProfile::BoundedV1,
        ),
        key(),
    )
    .await
    .expect("provision bounded-profile binding");
    assert!(backend
        .load_latest()
        .await
        .expect("explicitly provisioned empty proof-bound history")
        .is_none());
    let store = ConsensusConfigStore::open(
        topology(),
        backend.clone(),
        root.join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("explicit bounded store profile");
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    let reservations: Vec<_> = (0..8)
        .map(|_| {
            store
                .try_reserve_config_preparation()
                .expect("available slot")
                .expect("bounded reservation")
        })
        .collect();
    assert!(
        store.try_reserve_config_preparation().is_err(),
        "ninth preparation rejects without waiting"
    );
    drop(reservations);
    let released: Vec<_> = (0..8)
        .map(|_| {
            store
                .try_reserve_config_preparation()
                .expect("released slot")
                .expect("bounded reservation")
        })
        .collect();
    assert!(
        store.try_reserve_config_preparation().is_err(),
        "no duplicate release"
    );
    drop(released);
    store.shutdown().await.expect("native owners released");
    drop(store);
    // Losing the required proof schema must never select legacy history
    // semantics, even when the requested history is empty.
    let connection =
        rusqlite::Connection::open(root.join("config.sqlite")).expect("native corruption fixture");
    connection
        .execute_batch("DROP TABLE config_raft_capacity_records")
        .expect("remove required proof schema");
    drop(connection);
    let read_error = backend
        .load_latest()
        .await
        .expect_err("bounded history must not fall back to legacy reads");
    assert!(matches!(read_error.kind(), PersistErrorKind::CorruptBlob));
}
