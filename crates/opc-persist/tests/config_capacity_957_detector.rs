//! Proposed-success detector for #957 on the unchanged SDK.
//!
//! Install as crates/opc-persist/tests/config_capacity_957_detector.rs for an
//! explicitly recorded baseline run. A failed setup is not behavioral RED.
//! This singleton disk detector does not qualify multi-node transport/recovery.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use opc_crypto::encrypt_attested_envelope_with_handle_and_nonce;
use opc_key::{
    ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing, AES_256_GCM_SIV_NONCE_LEN,
};
use opc_persist::{
    AttestedConfigCommit, AuditKey, CommitRecord, CommitSource, ConfigConsensusClusterId,
    ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId, ConfigConsensusIdentity,
    ConfigConsensusNodeId, ConfigConsensusTopology, ConfigStore, ConsensusConfigStore,
    PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions,
    SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

const PROPOSED_LOGICAL_BYTES: usize = 1_572_864;

fn encrypted_commit(
    logical_bytes: usize,
    parent: Option<TxId>,
    version: u64,
) -> (AttestedConfigCommit, CommitRecord) {
    let empty = serde_json::to_vec(&serde_json::json!({"payload": ""})).expect("JSON shape");
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "payload": "q".repeat(logical_bytes.checked_sub(empty.len()).expect("payload budget"))
    }))
    .expect("synthetic JSON");
    assert_eq!(plaintext.len(), logical_bytes);
    let tx_id = TxId::new();
    let committed_at = Timestamp::now_utc();
    let principal = "spiffe://test.example/tenant/synthetic/ns/test/sa/config/nf/test/instance/a";
    let schema_digest = SchemaDigest::from_bytes([0x31; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        version,
        ConfigAad::new(
            tx_id,
            parent,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic config AAD"),
    );
    let key = KeyHandle::new(
        KeyId::new("synthetic-capacity-key").expect("synthetic key ID"),
        KeyPurpose::Config,
        TenantId::from_static("synthetic"),
        Zeroizing::new([0x63; 32]),
    );
    let nonce = [u8::try_from(version).expect("fixture version"); AES_256_GCM_SIV_NONCE_LEN];
    let envelope = encrypt_attested_envelope_with_handle_and_nonce(&key, &aad, &plaintext, nonce)
        .expect("real authenticated encryption");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::LocalOperator,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let commit = AttestedConfigCommit::try_new(
        record.clone(),
        vec![],
        envelope.claim().expect("fresh encryption claim"),
    )
    .expect("attested fixture");
    (commit, record)
}

fn effect_counts(database: &Path) -> [i64; 4] {
    let reader =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("independent read-only storage observation");
    [
        "SELECT COUNT(*) FROM config_history",
        "SELECT COUNT(*) FROM audit_trail",
        "SELECT COUNT(*) FROM config_raft_log",
        "SELECT COUNT(*) FROM config_raft_request_outcomes",
    ]
    .map(|query| {
        reader
            .query_row(query, [], |row| row.get(0))
            .expect("effect count")
    })
}

#[tokio::test]
async fn config_capacity_957_larger_logical_value_commits_atomically() {
    // The existing hosted opc-persist workflow supplies RUNNER_TEMP, while
    // local qualification selects an explicit TMPDIR. Verify either root.
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            if std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
                std::env::var_os("RUNNER_TEMP")
            } else {
                None
            }
        })
        .expect("explicit local or hosted scratch root is required");
    // Keep the original database on success and failure for private evidence.
    let directory = tempfile::Builder::new()
        .prefix("config-capacity-957-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&directory)
        .output()
        .expect("filesystem detector is required");
    assert!(filesystem.status.success(), "filesystem detection failed");
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem detector encoding")
        .trim();
    assert!(
        !filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"),
        "disk-backed scratch is required"
    );
    println!("CONFIG_CAPACITY_STORAGE disk_backed=true durability=Durable");
    let node = ConfigConsensusNodeId::new(1).expect("node");
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("synthetic-config-capacity").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x42; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology = ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
        .expect("singleton detector topology");
    let database = directory.join("config.sqlite");
    let options = RetainedConfigOptions::new(
        database.clone(),
        RetainedConfigBinding::new(topology.clone(), [0x12; 32], [0x34; 32])
            .expect("new retained binding"),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained admission options");
    let backend = SqliteBackend::provision_config_authority(
        options,
        AuditKey::new([0x55; 32]).expect("synthetic audit key"),
    )
    .await
    .expect("durable filesystem and retained provisioning must succeed");
    let store = ConsensusConfigStore::open(
        topology,
        backend,
        directory.join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("open unchanged consensus engine");
    store
        .initialize_cluster()
        .await
        .expect("initialize detector");
    let (control, expected_control) = encrypted_commit(256 * 1024, None, 1);
    let control_result = store.append_attested_commit(control).await;
    if control_result.is_err() {
        store.shutdown().await.expect("stop after control failure");
        panic!("small positive control failed; this is not a capacity RED");
    }
    let read_control = store
        .load_latest()
        .await
        .expect("control readback")
        .expect("control");
    assert!(
        read_control.record == expected_control,
        "exact small control readback"
    );
    println!("CONFIG_CAPACITY_CONTROL_COMMITTED logical_bytes=262144");
    let before = effect_counts(&database);
    let (candidate, expected_candidate) =
        encrypted_commit(PROPOSED_LOGICAL_BYTES, Some(expected_control.tx_id), 2);
    let outcome = store.append_attested_commit(candidate).await;
    let readback = store
        .load_latest()
        .await
        .expect("post-attempt readback")
        .expect("head");
    let after = effect_counts(&database);
    store
        .shutdown()
        .await
        .expect("stop engine before evaluating detector");
    if let Err(error) = &outcome {
        assert!(matches!(
            error.kind(),
            PersistErrorKind::ConstraintViolation(_)
        ));
        assert!(
            readback.record == expected_control,
            "rejection preserves exact head"
        );
        assert_eq!(
            before, after,
            "rejection precedes configuration/audit/log/replay effects"
        );
        println!("CONFIG_CAPACITY_REJECTED_WITHOUT_EFFECTS logical_bytes=1572864");
    }
    assert!(
        outcome.is_ok(),
        "CONFIG_CAPACITY_957_RED: proposed 1572864-byte logical configuration was rejected"
    );
    assert!(
        readback.record == expected_candidate,
        "exact atomic large readback"
    );
}
