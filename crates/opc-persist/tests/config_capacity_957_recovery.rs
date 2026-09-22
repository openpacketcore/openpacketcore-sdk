//! Public recovery API on native retained Durable storage. A singleton is a
//! contract control, not authenticated multi-node or failover qualification.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_persist::{
    AttestedConfigCommit, AuditKey, CommitRecord, CommitSource, ConfigCommitRecoveryHandle,
    ConfigCommitRecoveryOutcome, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusRequestId, ConfigConsensusTopology, ConfigStore, ConsensusConfigStore,
    PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions,
    SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

const CALLER: &str =
    "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/a";

fn commit() -> AttestedConfigCommit {
    let tx_id = TxId::new();
    let committed_at = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed time"),
    );
    let schema_digest = SchemaDigest::from_bytes([0xA1; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        1,
        ConfigAad::new(tx_id, None, committed_at, CALLER, schema_digest, "running").expect("AAD"),
    );
    let key = KeyHandle::new(
        KeyId::new("synthetic-recovery-key").expect("key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xA2; 32]),
    );
    let plaintext = b"{\"synthetic\":true}";
    let encrypted = opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
        &key,
        &aad,
        plaintext,
        [0xA3; opc_key::AES_256_GCM_SIV_NONCE_LEN],
    )
    .expect("actual envelope");
    AttestedConfigCommit::try_new(
        CommitRecord {
            tx_id,
            parent_tx_id: None,
            version: ConfigVersion::new(1),
            committed_at,
            principal: CALLER.into(),
            source: CommitSource::LocalOperator,
            schema_digest,
            plaintext_digest: Sha256::digest(plaintext).to_vec(),
            encrypted_blob: encrypted.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        },
        Vec::new(),
        encrypted.claim().expect("fresh encryption claim"),
    )
    .expect("attested input")
}

fn topology() -> ConfigConsensusTopology {
    let node = ConfigConsensusNodeId::new(1).expect("node");
    ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xA4; 32]),
            ConfigConsensusConfigurationId::from_bytes([0xA5; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("topology")
}

fn options(root: &Path) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology(), [0xA6; 32], [0xA7; 32]).expect("binding"),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained options")
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
        .prefix("config-capacity-recovery-")
        .tempdir_in(scratch)
        .expect("private fixture")
        .keep();
    let fs = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector required");
    assert!(fs.status.success());
    let fs = std::str::from_utf8(&fs.stdout)
        .expect("filesystem encoding")
        .trim();
    assert!(!fs.is_empty() && !matches!(fs, "tmpfs" | "ramfs"));
    root
}

async fn open(root: &Path, reopen: bool) -> ConsensusConfigStore {
    let key = AuditKey::new([0xA8; 32]).expect("audit key");
    let backend = if reopen {
        SqliteBackend::reopen_config_authority(options(root), key).await
    } else {
        SqliteBackend::provision_config_authority(options(root), key).await
    }
    .expect("retained native Durable backend");
    let store =
        ConsensusConfigStore::open(topology(), backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("native singleton");
    store
        .initialize_cluster()
        .await
        .expect("admitted singleton");
    store
        .probe_durable_readiness()
        .await
        .expect("initial leader and local apply");
    store
}

fn counts(root: &Path) -> [i64; 4] {
    let conn = rusqlite::Connection::open_with_flags(
        root.join("config.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read-only native inspection");
    [
        "config_history",
        "audit_trail",
        "config_raft_log",
        "config_raft_request_outcomes",
    ]
    .map(|table| {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("effect count")
    })
}

#[tokio::test]
async fn config_capacity_957_public_recovery_is_exact_read_only_and_survives_reopen() {
    let root = disk_fixture();
    let store = open(&root, false).await;
    let before = counts(&root);
    assert!(store
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xB0; 16]),
            commit(),
            "different caller",
        )
        .is_err());
    assert_eq!(counts(&root), before);
    let input = commit();
    let expected_id = input.record().tx_id;
    let operation = store
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xB1; 16]),
            input,
            CALLER,
        )
        .expect("prepare once");
    let handle = ConfigCommitRecoveryHandle::from_bytes(operation.recovery_handle().as_bytes())
        .expect("retained handle before transmission");
    assert_eq!(counts(&root), before, "preparation has no SQL effect");
    assert!(matches!(
        store
            .lookup_commit_operation(&handle, CALLER)
            .await
            .expect("unsent lookup"),
        ConfigCommitRecoveryOutcome::Unresolved
    ));
    assert_eq!(counts(&root), before, "missing lookup never proposes");
    store
        .append_prepared_commit(operation)
        .await
        .expect("exact commit");
    let committed = counts(&root);
    assert!(matches!(
        store
            .lookup_commit_operation(&handle, CALLER)
            .await
            .expect("lookup"),
        ConfigCommitRecoveryOutcome::Committed
    ));
    assert!(store
        .lookup_commit_operation(&handle, "different caller")
        .await
        .is_err());
    assert_eq!(counts(&root), committed, "recovery is read-only");
    assert_eq!(
        store
            .load_latest()
            .await
            .expect("readback")
            .expect("head")
            .record
            .tx_id,
        expected_id
    );

    let conflicting = store
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xB2; 16]),
            commit(),
            CALLER,
        )
        .expect("prepare lineage conflict");
    let rejection = conflicting.recovery_handle().clone();
    assert!(matches!(
        store
            .append_prepared_commit_local(conflicting)
            .await
            .expect_err("applied conflict")
            .kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    let rejected = counts(&root);
    assert!(
        matches!(store.lookup_commit_operation(&rejection, CALLER).await.expect("retained rejection"), ConfigCommitRecoveryOutcome::Rejected(error) if matches!(error.kind(), PersistErrorKind::ConstraintViolation(_)))
    );
    assert_eq!(counts(&root), rejected);

    let collision = store
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xB1; 16]),
            commit(),
            CALLER,
        )
        .expect("prepare same request, different payload");
    let collision = collision.recovery_handle().clone();
    assert!(matches!(
        store
            .lookup_commit_operation(&collision, CALLER)
            .await
            .expect("same ID lookup"),
        ConfigCommitRecoveryOutcome::Unresolved
    ));
    assert_eq!(
        counts(&root),
        rejected,
        "cannot expose another payload's outcome"
    );

    store.shutdown().await.expect("orderly shutdown");
    drop(store);
    let reopened = open(&root, true).await;
    let before_lookup = counts(&root);
    assert!(matches!(
        reopened
            .lookup_commit_operation(&handle, CALLER)
            .await
            .expect("recover after retained reopen"),
        ConfigCommitRecoveryOutcome::Committed
    ));
    assert!(matches!(
        reopened
            .lookup_commit_operation(&rejection, CALLER)
            .await
            .expect("rejection after reopen"),
        ConfigCommitRecoveryOutcome::Rejected(_)
    ));
    assert_eq!(counts(&root), before_lookup);
    assert_eq!(
        reopened
            .load_latest()
            .await
            .expect("retained readback")
            .expect("head")
            .record
            .tx_id,
        expected_id
    );
    reopened.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn config_capacity_957_invalid_recovery_rejects_before_read_barrier() {
    let root = disk_fixture();
    let store = open(&root, false).await;
    let prepared = store
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xB3; 16]),
            commit(),
            CALLER,
        )
        .expect("prepared");
    let handle = prepared.recovery_handle();
    let before = counts(&root);
    // The closed engine makes any later read barrier unavailable.
    store.shutdown().await.expect("stop engine");
    let mut bytes = handle.as_bytes().to_vec();
    bytes[104] ^= 1;
    let changed = ConfigCommitRecoveryHandle::from_bytes(&bytes).expect("structural parse only");
    for (candidate, caller) in [(&changed, CALLER), (handle, "different caller")] {
        let error = store
            .lookup_commit_operation(candidate, caller)
            .await
            .expect_err("invalid authority");
        assert!(
            matches!(error.kind(), PersistErrorKind::ConstraintViolation(_)),
            "validation must precede unavailable engine"
        );
    }
    assert_eq!(counts(&root), before);
}
