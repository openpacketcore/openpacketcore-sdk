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

// Refuse one actual SQLite read without modifying stored bytes. The source
// boundary must retain the failed-read class, including inside write APIs.
fn deny_column_read(
    conn: &rusqlite::Connection,
    table: &'static str,
    column: &'static str,
    occurrence: usize,
) -> Arc<std::sync::atomic::AtomicUsize> {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let reads = Arc::new(AtomicUsize::new(0));
    let hook_reads = reads.clone();
    conn.authorizer(Some(move |context: AuthContext<'_>| {
        if matches!(context.action, AuthAction::Read { table_name, column_name }
            if table_name == table && column_name == column)
            && hook_reads.fetch_add(1, Ordering::SeqCst) + 1 == occurrence
        {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    }))
    .unwrap();
    reads
}

#[tokio::test]
async fn rollback_point_read_outage_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollback.sqlite");
    let backend =
        SqliteBackend::open_with_audit_key(&path, true, 0, AuditKey::new([0x64; 32]).unwrap())
            .await
            .unwrap();
    let tx_id = TxId::new();
    let (record, audit, _) = commit(tx_id, None, 1, false).into_parts();
    backend.append_commit(record, audit).await.unwrap();
    let before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(path.with_extension("sqlite-wal")).unwrap();
    let reads = deny_column_read(
        &*backend.conn.lock().await,
        "config_history",
        "principal",
        1,
    );
    let error = backend
        .create_rollback_point(tx_id, None)
        .await
        .unwrap_err();
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read(path.with_extension("sqlite-wal")).unwrap(),
        wal_before
    );
    assert!(
        matches!(error.kind(), crate::PersistErrorKind::Unavailable),
        "{error:?}"
    );
}

#[tokio::test]
async fn append_replay_digest_read_outage_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.sqlite");
    let backend =
        SqliteBackend::open_with_audit_key(&path, true, 0, AuditKey::new([0x64; 32]).unwrap())
            .await
            .unwrap();
    let tx_id = TxId::new();
    let (mut record, audit, _) = commit(tx_id, None, 1, false).into_parts();
    record.principal =
        serde_json::json!({"principal": record.principal, "replay_lookup_digest": "a".repeat(64), "recovery_required": false})
            .to_string();
    let before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(path.with_extension("sqlite-wal")).unwrap();
    // The latest-head query reads principal first; the replay-index query is second.
    let reads = deny_column_read(
        &*backend.conn.lock().await,
        "config_history",
        "principal",
        2,
    );
    let error = backend.append_commit(record, audit).await.unwrap_err();
    assert!(reads.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read(path.with_extension("sqlite-wal")).unwrap(),
        wal_before
    );
    assert!(
        matches!(error.kind(), crate::PersistErrorKind::Unavailable),
        "{error:?}"
    );
}

async fn audit_read_outage_is_unavailable(table: &'static str, column: &'static str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let key = AuditKey::new([0x64; 32]).unwrap();
    let backend = SqliteBackend::open_with_audit_key(&path, true, 0, key.clone())
        .await
        .unwrap();
    let node = ConfigConsensusNodeId::new(1).unwrap();
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("audit-read-test").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([0x64; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, [node].into_iter().collect()).unwrap();
    let store = ConsensusConfigStore::open(
        topology,
        backend.clone(),
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    store.shutdown().await.unwrap();
    let conn = backend.conn.lock().await;
    assert!(crate::consensus::read_sync(&conn, &key, identity)
        .unwrap()
        .is_none());
    let before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(path.with_extension("sqlite-wal")).unwrap();
    let reads = deny_column_read(&conn, table, column, 1);
    let error = crate::error::history_read_error(
        crate::consensus::read_sync(&conn, &key, identity)
            .err()
            .unwrap(),
    );
    assert!(reads.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read(path.with_extension("sqlite-wal")).unwrap(),
        wal_before
    );
    assert!(
        matches!(error.kind(), crate::PersistErrorKind::Unavailable),
        "{error:?}"
    );
}

#[tokio::test]
async fn audit_ledger_read_outage_is_unavailable() {
    audit_read_outage_is_unavailable("config_raft_management_audit", "state_json").await;
}

#[tokio::test]
async fn audit_identity_read_outage_is_unavailable() {
    audit_read_outage_is_unavailable("config_raft_identity", "cluster_id").await;
}
