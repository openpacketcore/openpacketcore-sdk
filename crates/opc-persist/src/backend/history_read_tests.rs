use super::*;
use crate::{
    AttestedConfigCommit, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConsensusConfigStore,
};
use opc_crypto::encrypt_attested_envelope_with_handle_and_nonce;
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::TenantId;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn commit(tx_id: TxId, parent: Option<TxId>, version: u64, fenced: bool) -> AttestedConfigCommit {
    let time = Timestamp::now_utc();
    let principal = "spiffe://test.example/tenant/test/ns/core/sa/config/nf/test/instance/one";
    let schema = SchemaDigest::from_bytes([0x64; 32]);
    let key = KeyHandle::new(
        KeyId::new("read-snapshot-test").expect("key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0x64; 32]),
    );
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        ConfigAad::new(tx_id, parent, time, principal, schema, "running").expect("AAD"),
    );
    let envelope = encrypt_attested_envelope_with_handle_and_nonce(
        &key,
        &aad,
        b"test configuration",
        [version as u8; 12],
    )
    .expect("authenticated envelope");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at: time,
        principal: if fenced {
            serde_json::json!({"principal": principal, "recovery_required": true}).to_string()
        } else {
            principal.to_owned()
        },
        source: CommitSource::LocalOperator,
        schema_digest: schema,
        plaintext_digest: Sha256::digest(b"test configuration").to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    AttestedConfigCommit::try_new(record, Vec::new(), envelope.claim().expect("claim"))
        .expect("attested commit")
}

// SDK #802: force a second connection's mutation exactly between authentication
// and metadata use. The first read must return its authenticated snapshot; the
// next read must refuse the changed fence. A mutex without a SQLite transaction
// returns the unresolved second record in the first read.
#[tokio::test]
async fn authenticated_history_read_keeps_one_sqlite_snapshot() {
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("history.sqlite");
    let backend = SqliteBackend::open_with_audit_key(
        &path,
        true,
        0,
        AuditKey::new([0x64; 32]).expect("audit key"),
    )
    .await
    .expect("backend");
    let node = ConfigConsensusNodeId::new(1).expect("node");
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("read-snapshot-test").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x64; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology = ConfigConsensusTopology::try_new(identity, node, [node].into_iter().collect())
        .expect("topology");
    let store = ConsensusConfigStore::open(
        topology,
        backend.clone(),
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("consensus");
    store.initialize_cluster().await.expect("initialize");
    let ids = [TxId::new(), TxId::new()];
    store
        .append_attested_commit(commit(ids[0], None, 1, false))
        .await
        .expect("first record");
    store
        .append_attested_commit(commit(ids[1], Some(ids[0]), 2, true))
        .await
        .expect("fenced record");
    let first = backend.read_config_history(move |conn, key| {
        let writer = rusqlite::Connection::open(path).expect("independent writer");
        assert_eq!(writer.execute(
            "UPDATE config_history SET principal = replace(principal, '\"recovery_required\":true', '\"recovery_required\":false') WHERE version = 2", [],
        ).expect("concurrent metadata mutation"), 1);
        SqliteBackend::load_committed_latest_impl(conn, key)
    }).await.expect("one authenticated read snapshot").expect("published head");
    let subsequent_refused = backend.load_committed_latest().await.is_err();
    store.shutdown().await.expect("shutdown");
    assert_eq!(
        first.record.tx_id, ids[0],
        "the concurrent write cannot publish the fenced head"
    );
    assert!(
        subsequent_refused,
        "the next snapshot must authenticate and refuse the changed metadata"
    );
}

#[tokio::test]
async fn consensus_history_refuses_temporary_schema_shadowing() {
    let dir = tempfile::tempdir().expect("directory");
    let backend = SqliteBackend::open_with_audit_key(
        dir.path().join("history.sqlite"),
        true,
        0,
        AuditKey::new([0x66; 32]).expect("audit key"),
    )
    .await
    .expect("backend");
    let node = ConfigConsensusNodeId::new(1).expect("node");
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("read-schema-test").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x66; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology = ConfigConsensusTopology::try_new(identity, node, [node].into_iter().collect())
        .expect("topology");
    let store = ConsensusConfigStore::open(
        topology,
        backend.clone(),
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("consensus");
    store.initialize_cluster().await.expect("initialize");
    store
        .append_attested_commit(commit(TxId::new(), None, 1, false))
        .await
        .expect("record");
    {
        let connection = backend.conn.lock().await;
        // Even an identical copy must not replace the admitted main table.
        // Its rows authenticate, but its schema lacks the owned constraints.
        connection
            .execute_batch("CREATE TEMP TABLE config_history AS SELECT * FROM main.config_history")
            .expect("isolated temporary schema fault");
    }
    let refused = backend.load_latest().await.is_err();
    store.shutdown().await.expect("shutdown");
    assert!(
        refused,
        "temporary schema cannot shadow authenticated history"
    );
}

#[tokio::test]
async fn genuine_standalone_history_keeps_its_read_and_write_contract() {
    let dir = tempfile::tempdir().expect("directory");
    let backend = SqliteBackend::open_with_audit_key(
        dir.path().join("standalone.sqlite"),
        true,
        0,
        AuditKey::new([0x65; 32]).expect("audit key"),
    )
    .await
    .expect("standalone");
    assert!(backend
        .load_latest()
        .await
        .expect("empty history")
        .is_none());
    assert!(backend
        .retained_history_floor()
        .await
        .expect("no consensus policy")
        .is_none());
    let tx_id = TxId::new();
    let (record, audit, _) = commit(tx_id, None, 1, false).into_parts();
    backend
        .append_commit(record, audit)
        .await
        .expect("standalone write");
    assert_eq!(
        backend
            .load_committed_latest()
            .await
            .expect("standalone read")
            .expect("head")
            .record
            .tx_id,
        tx_id
    );
    assert_eq!(
        backend
            .load_since(ConfigVersion::new(0), 1)
            .await
            .expect("standalone tail")
            .len(),
        1
    );
}

async fn assert_consensus_history_identity(reopen: bool) {
    let dir = tempfile::tempdir().expect("directory");
    let mut backends = Vec::new();
    for ordinal in [1_u8, 2] {
        let backend = SqliteBackend::open_with_audit_key(
            dir.path().join(format!("history-{ordinal}.sqlite")),
            true,
            0,
            AuditKey::new([0x67; 32]).expect("shared synthetic audit key"),
        )
        .await
        .expect("backend");
        // Hold a clone made before the consensus claim; its identity must also
        // tighten when initialization succeeds on the shared connection.
        let reader = backend.clone();
        let node = ConfigConsensusNodeId::new(1).expect("node");
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([ordinal; 32]),
            ConfigConsensusConfigurationId::from_bytes([ordinal; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, [node].into_iter().collect())
                .expect("topology");
        let store = ConsensusConfigStore::open(
            topology.clone(),
            backend,
            dir.path().join(format!("snapshots-{ordinal}")),
            BTreeMap::new(),
        )
        .await
        .expect("consensus authority");
        store
            .shutdown()
            .await
            .expect("quiescent initialized authority");
        drop(store);
        assert!(reader
            .load_latest()
            .await
            .expect("genuine empty authority")
            .is_none());
        if reopen {
            let readmission = SqliteBackend::open_with_audit_key(
                dir.path().join(format!("history-{ordinal}.sqlite")),
                true,
                0,
                AuditKey::new([0x67; 32]).expect("same synthetic audit key"),
            )
            .await
            .expect("generic reopen of claimed authority");
            assert!(
                matches!(readmission.load_latest().await, Err(error)
                if matches!(error.kind(), crate::PersistErrorKind::CorruptBlob)),
                "consensus metadata cannot supply its own trusted identity"
            );
            let store = ConsensusConfigStore::open(
                topology,
                readmission.clone(),
                dir.path().join(format!("snapshots-{ordinal}")),
                BTreeMap::new(),
            )
            .await
            .expect("independent topology admits the legitimate reopened authority");
            assert!(readmission
                .load_latest()
                .await
                .expect("read after independent admission")
                .is_none());
            store
                .shutdown()
                .await
                .expect("readmitted authority shutdown");
            drop(store);
            // Keep a distinct generic reopen unadmitted during the replay.
            // Another backend's successful claim cannot authorize this one.
            backends.push(
                SqliteBackend::open_with_audit_key(
                    dir.path().join(format!("history-{ordinal}.sqlite")),
                    true,
                    0,
                    AuditKey::new([0x67; 32]).expect("same synthetic audit key"),
                )
                .await
                .expect("independently unadmitted reopen"),
            );
        } else {
            backends.push(reader);
        }
    }
    let foreign_state: (Vec<u8>, Vec<u8>) = backends[1]
        .conn
        .lock()
        .await
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_history_retention",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("genuine foreign state and tag");
    {
        let conn = backends[0].conn.lock().await;
        let tx = conn.unchecked_transaction().expect("atomic replay");
        tx.execute(
            "UPDATE config_raft_identity SET cluster_id = ?1, configuration_id = ?1",
            [[2_u8; 32].as_slice()],
        )
        .expect("replay foreign identity fields");
        tx.execute(
            "UPDATE config_raft_history_retention SET state_json = ?1, state_hmac = ?2",
            rusqlite::params![foreign_state.0, foreign_state.1],
        )
        .expect("replay authentic foreign state without resealing");
        tx.commit().expect("commit replay");
    }
    for reader in [&backends[0], &backends[0].clone()] {
        assert!(
            matches!(reader.load_latest().await, Err(error)
            if matches!(error.kind(), crate::PersistErrorKind::CorruptBlob)),
            "a clone must retain the independently admitted identity"
        );
        assert!(
            matches!(reader.retained_history_floor().await, Err(error)
            if matches!(error.kind(), crate::PersistErrorKind::CorruptBlob)),
            "negative metadata reads must retain the independently admitted identity"
        );
    }
}

#[tokio::test]
async fn consensus_history_keeps_admitted_identity_after_live_sql_replacement() {
    assert_consensus_history_identity(false).await;
}

#[tokio::test]
async fn reopened_consensus_history_requires_independent_identity_before_reads() {
    assert_consensus_history_identity(true).await;
}
