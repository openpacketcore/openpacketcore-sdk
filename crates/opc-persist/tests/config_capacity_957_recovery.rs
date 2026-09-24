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

#[derive(Debug, PartialEq, Eq)]
struct RecoveryWindow {
    application_sequence: i64,
    retained_count: i64,
    oldest_sequence: i64,
    newest_sequence: i64,
    original_sequence: Option<i64>,
}

fn recovery_window(root: &Path, original: ConfigConsensusRequestId) -> RecoveryWindow {
    use rusqlite::OptionalExtension;

    let mut conn = rusqlite::Connection::open_with_flags(
        root.join("config.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read-only retained window inspection");
    let view = conn.transaction().expect("consistent read-only view");
    let application_sequence = view
        .query_row(
            "SELECT application_sequence FROM config_raft_machine WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("actual applied application frontier");
    let (retained_count, oldest_sequence, newest_sequence) = view
        .query_row(
            "SELECT COUNT(*), MIN(applied_sequence), MAX(applied_sequence) FROM config_raft_request_outcomes",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("nonempty retained result window");
    let original_sequence = view
        .query_row(
            "SELECT applied_sequence FROM config_raft_request_outcomes WHERE request_id=?1",
            [original.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .expect("exact original outcome presence");
    RecoveryWindow {
        application_sequence,
        retained_count,
        oldest_sequence,
        newest_sequence,
        original_sequence,
    }
}

#[tokio::test]
async fn config_capacity_957_recovery_window_expiry_stays_unresolved_after_reopen() {
    // This exercises the unchanged 4096-applied-sequence public recovery
    // window through native Durable Raft writes. It is not an enlarged
    // history budget, multi-node snapshot or larger-config qualification.
    const RETAINED_OUTCOMES: i64 = 4096;
    let root = disk_fixture();
    let store = open(&root, false).await;
    let original = ConfigConsensusRequestId::from_bytes([0xB4; 16]);
    let input = commit();
    let expected = input.record().clone();
    let operation = store
        .prepare_recoverable_commit(original, input, CALLER)
        .expect("prepare original operation once");
    let handle = operation.recovery_handle().clone();
    store
        .append_prepared_commit_local(operation)
        .await
        .expect("original known commit");
    let initial = recovery_window(&root, original);
    let committed_sequence = initial.original_sequence.expect("original retained result");
    assert_eq!(initial.application_sequence, committed_sequence);
    assert_eq!(initial.retained_count, 1);

    let missing = TxId::new();
    assert!(
        missing != expected.tx_id,
        "separate synthetic missing transaction"
    );
    for step in 1_i64..=RETAINED_OUTCOMES {
        // These are distinct synthetic rejected operations, not retries of
        // the committed configuration under replacement operation identities.
        // No direct SQL writes or fabricated sequence/frontier changes occur.
        let mut bytes = [0xB5; 16];
        bytes[..8].copy_from_slice(&step.to_be_bytes());
        let result = store
            .create_rollback_point_local_idempotent(
                ConfigConsensusRequestId::from_bytes(bytes),
                missing,
                None,
            )
            .await
            .expect_err("applied missing-target rejection");
        assert!(matches!(result.kind(), PersistErrorKind::RollbackNotFound));
        if step == RETAINED_OUTCOMES - 1 {
            let inside = recovery_window(&root, original);
            assert_eq!(inside.application_sequence, committed_sequence + step);
            assert_eq!(inside.retained_count, RETAINED_OUTCOMES);
            assert_eq!(inside.oldest_sequence, committed_sequence);
            assert_eq!(inside.newest_sequence, committed_sequence + step);
            assert_eq!(inside.original_sequence, Some(committed_sequence));
            assert!(matches!(
                store
                    .lookup_commit_operation(&handle, CALLER)
                    .await
                    .expect("last retained position"),
                ConfigCommitRecoveryOutcome::Committed
            ));
            assert_eq!(recovery_window(&root, original), inside);
        }
    }
    let expired = recovery_window(&root, original);
    assert_eq!(
        expired.application_sequence,
        committed_sequence + RETAINED_OUTCOMES
    );
    assert_eq!(expired.retained_count, RETAINED_OUTCOMES);
    assert_eq!(expired.oldest_sequence, committed_sequence + 1);
    assert_eq!(
        expired.newest_sequence,
        committed_sequence + RETAINED_OUTCOMES
    );
    assert_eq!(expired.original_sequence, None);
    assert!(matches!(
        store
            .lookup_commit_operation(&handle, CALLER)
            .await
            .expect("first expired position"),
        ConfigCommitRecoveryOutcome::Unresolved
    ));
    assert_eq!(recovery_window(&root, original), expired);
    assert!(
        store
            .load_latest()
            .await
            .expect("committed readback")
            .expect("head")
            .record
            == expected,
        "expired recovery evidence does not undo or reclassify the known commit"
    );
    store.shutdown().await.expect("orderly native shutdown");
    drop(store);

    let reopened = open(&root, true).await;
    let before = recovery_window(&root, original);
    assert_eq!(
        before, expired,
        "retained frontier and expiry survive reopen"
    );
    assert!(matches!(
        reopened
            .lookup_commit_operation(&handle, CALLER)
            .await
            .expect("same original handle after retained reopen"),
        ConfigCommitRecoveryOutcome::Unresolved
    ));
    assert_eq!(recovery_window(&root, original), before);
    assert!(
        reopened
            .load_latest()
            .await
            .expect("retained readback")
            .expect("head")
            .record
            == expected,
        "complete committed record remains readable after outcome expiry"
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown retained fixture");
    println!("CONFIG_CAPACITY_RECOVERY_WINDOW inside=true expired=true retained_after_reopen=true");
}
