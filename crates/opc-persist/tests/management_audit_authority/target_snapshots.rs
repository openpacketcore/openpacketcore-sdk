//! Inactive target-profile snapshot compatibility, not device/effect activation.
use super::*;
use crate::audit_authority::{AuditLedgerLimits, AuditToken};
use crate::consensus::audit::AuditCommand;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusTopology, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};

struct Fixture {
    directory: tempfile::TempDir,
    backend: SqliteBackend,
    identity: ConsensusIdentity,
    members: BTreeSet<ConsensusNodeId>,
    key: AuditKey,
}

impl Fixture {
    async fn new(profile: RetainedConfigProfile, authority: u8) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let identity = ConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([authority; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let node = ConsensusNodeId::new(1).unwrap();
        let members = BTreeSet::from([node]);
        let topology = ConfigConsensusTopology::try_new(identity, node, members.clone()).unwrap();
        let key = AuditKey::new([0x61; 32]).unwrap();
        let options = RetainedConfigOptions::new(
            directory.path().join("authority.sqlite"),
            RetainedConfigBinding::new(topology, [0x62; 32], [0x63; 32])
                .unwrap()
                .with_profile(profile),
            RetainedConfigDurability::Ephemeral,
            16 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap();
        let backend = SqliteBackend::provision_config_authority(options, key.clone())
            .await
            .unwrap();
        // Seed only fixed membership/frontier, using the same SQLite primitives
        // as membership apply. No target effect or active owner is fabricated.
        let shared = backend.conn();
        let conn = shared.lock().await;
        let tx = conn.unchecked_transaction().unwrap();
        let first = LogId::new(CommittedLeaderId::new(1, node), 0);
        let membership = StoredMembership::new(
            Some(first),
            Membership::new(vec![members.clone()], members.clone()),
        );
        store_membership_sync(&tx, identity, &members, &membership).unwrap();
        save_log_pointer(&tx, "config_raft_applied", identity, &first).unwrap();
        tx.commit().unwrap();
        drop(conn);
        Self {
            directory,
            backend,
            identity,
            members,
            key,
        }
    }

    async fn snapshot(
        &self,
        profile: RetainedConfigProfile,
    ) -> (PathBuf, SnapshotMeta<ConsensusNodeId, EmptyNode>) {
        let path = self.directory.path().join("snapshot.sqlite");
        let shared = self.backend.conn();
        let conn = shared.lock().await;
        // A real authenticated ledger row must travel with the target bodies.
        super::super::audit::apply_sync(
            &conn,
            &self.key,
            self.identity,
            &AuditCommand::Initialize {
                projection: AuditToken::from_keyed_projection([0x64; 32]).unwrap(),
                limits: AuditLedgerLimits::new(6, 2).unwrap(),
            },
            1,
            None,
        )
        .unwrap()
        .unwrap();
        let (last_log_id, last_membership) = build_snapshot_database_for_profile_sync(
            &conn,
            self.identity,
            &self.members,
            &self.key,
            &path,
            &Arc::new(SqliteWorkCancellation::new()),
            profile,
        )
        .expect("explicitly selected snapshot profile");
        (
            path,
            SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id: "synthetic-snapshot".into(),
            },
        )
    }

    async fn install(
        &self,
        path: &Path,
        meta: &SnapshotMeta<ConsensusNodeId, EmptyNode>,
        profile: RetainedConfigProfile,
    ) -> io::Result<()> {
        let shared = self.backend.conn();
        let conn = shared.lock().await;
        install_snapshot_database_for_profile_sync(
            &conn,
            self.identity,
            &self.members,
            &self.key,
            path,
            meta,
            "snapshot.opc",
            [0x65; 32],
            4096,
            &Arc::new(SqliteWorkCancellation::new()),
            profile,
        )
    }
}

// Read every logical authority table independently. Failed imports must leave
// even the metadata/ledger tables unchanged; do not print their bodies on error.
fn logical_rows(conn: &Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let mut tables = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name").unwrap();
    let tables = tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut select = conn
                .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
                .unwrap();
            let width = select.column_count();
            let rows = select
                .query_map([], |row| {
                    (0..width)
                        .map(|n| row.get(n))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

#[tokio::test]
async fn target_snapshot_round_trip_preserves_all_authenticated_rows() {
    let profile = RetainedConfigProfile::NetconfTargetsV1;
    let source = Fixture::new(profile, 0x31).await;
    let destination = Fixture::new(profile, 0x31).await;
    let (path, meta) = source.snapshot(profile).await;
    // Repair from authenticated snapshot must actually replace all four rows;
    // fresh zero-generation rows alone would fail to detect a skipped copy.
    {
        let shared = destination.backend.conn();
        let conn = shared.lock().await;
        for table in [
            "config_netconf_profile",
            "config_netconf_targets",
            "config_netconf_lifecycle",
        ] {
            conn.execute(&format!("UPDATE {table} SET state_hmac=zeroblob(32)"), [])
                .unwrap();
        }
    }
    destination
        .install(&path, &meta, profile)
        .await
        .expect("complete target snapshot repair");
    let snapshot = Connection::open(&path).unwrap();
    let shared = destination.backend.conn();
    let conn = shared.lock().await;
    for table in [
        "config_netconf_profile",
        "config_netconf_targets",
        "config_netconf_lifecycle",
        "config_raft_management_audit",
    ] {
        let rows = |c: &Connection| {
            let mut query = c
                .prepare(&format!(
                    "SELECT state_json,state_hmac FROM {table} ORDER BY rowid"
                ))
                .unwrap();
            query
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert!(!rows(&snapshot).is_empty());
        assert!(
            rows(&snapshot) == rows(&conn),
            "authenticated snapshot rows changed"
        );
    }
    assert_eq!(
        read_applied_sync(&conn, destination.identity).unwrap(),
        meta.last_log_id
    );
    validate_existing_schema_for_profile(
        &conn,
        destination.identity,
        &destination.members,
        &destination.key,
        false,
        &SqliteWorkCancellation::new(),
        profile,
    )
    .unwrap();
}

#[tokio::test]
async fn target_snapshot_rejects_omitted_altered_and_substituted_state_without_import() {
    let profile = RetainedConfigProfile::NetconfTargetsV1;
    for attack in [
        "DELETE FROM config_netconf_profile",
        "DELETE FROM config_netconf_targets WHERE target=0",
        "DELETE FROM config_netconf_targets WHERE target=1",
        "DELETE FROM config_netconf_lifecycle",
        "UPDATE config_netconf_profile SET state_hmac=zeroblob(32)",
        "UPDATE config_netconf_targets SET state_hmac=zeroblob(32) WHERE target=0",
        "UPDATE config_netconf_targets SET state_hmac=zeroblob(32) WHERE target=1",
        "UPDATE config_netconf_lifecycle SET state_hmac=zeroblob(32)",
        "UPDATE config_netconf_targets SET state_json=(SELECT state_json FROM config_netconf_targets WHERE target=0),state_hmac=(SELECT state_hmac FROM config_netconf_targets WHERE target=0) WHERE target=1",
        "DROP TABLE config_netconf_lifecycle",
        "CREATE INDEX extra_target_index ON config_netconf_targets(state_json)",
        "UPDATE config_raft_identity SET schema_version=5",
        "UPDATE config_raft_identity SET schema_manifest_digest=zeroblob(32)",
    ] {
        let source = Fixture::new(profile, 0x31).await;
        let destination = Fixture::new(profile, 0x31).await;
        let (path, meta) = source.snapshot(profile).await;
        Connection::open(&path).unwrap().execute_batch(attack).unwrap();
        let shared = destination.backend.conn();
        let before = logical_rows(&**shared.lock().await);
        assert!(destination.install(&path, &meta, profile).await.is_err(), "altered snapshot admitted");
        assert!(logical_rows(&**shared.lock().await) == before, "rejected import changed authority");
    }
}

#[tokio::test]
async fn snapshot_selection_never_infers_profile_from_source_or_destination() {
    for (source_profile, destination_profile, selected) in [
        (
            RetainedConfigProfile::Legacy,
            RetainedConfigProfile::NetconfTargetsV1,
            RetainedConfigProfile::NetconfTargetsV1,
        ),
        (
            RetainedConfigProfile::NetconfTargetsV1,
            RetainedConfigProfile::Legacy,
            RetainedConfigProfile::Legacy,
        ),
        (
            RetainedConfigProfile::NetconfTargetsV1,
            RetainedConfigProfile::Legacy,
            RetainedConfigProfile::NetconfTargetsV1,
        ),
        (
            RetainedConfigProfile::Legacy,
            RetainedConfigProfile::NetconfTargetsV1,
            RetainedConfigProfile::Legacy,
        ),
    ] {
        let source = Fixture::new(source_profile, 0x31).await;
        let destination = Fixture::new(destination_profile, 0x31).await;
        let (path, meta) = source.snapshot(source_profile).await;
        let shared = destination.backend.conn();
        let before = logical_rows(&**shared.lock().await);
        assert!(destination.install(&path, &meta, selected).await.is_err());
        assert!(
            logical_rows(&**shared.lock().await) == before,
            "profile rejection changed authority"
        );
    }
    let profile = RetainedConfigProfile::NetconfTargetsV1;
    let foreign = Fixture::new(profile, 0x71).await;
    let destination = Fixture::new(profile, 0x31).await;
    let (path, meta) = foreign.snapshot(profile).await;
    let shared = destination.backend.conn();
    let before = logical_rows(&**shared.lock().await);
    assert!(destination.install(&path, &meta, profile).await.is_err());
    assert!(logical_rows(&**shared.lock().await) == before);
}

#[tokio::test]
async fn target_snapshot_build_rejects_invalid_source_before_creating_output() {
    let profile = RetainedConfigProfile::NetconfTargetsV1;
    let source = Fixture::new(profile, 0x31).await;
    let path = source.directory.path().join("rejected.sqlite");
    let shared = source.backend.conn();
    let conn = shared.lock().await;
    conn.execute("DELETE FROM config_netconf_targets WHERE target=0", [])
        .unwrap();
    let before = logical_rows(&conn);
    assert!(build_snapshot_database_for_profile_sync(
        &conn,
        source.identity,
        &source.members,
        &source.key,
        &path,
        &Arc::new(SqliteWorkCancellation::new()),
        profile
    )
    .is_err());
    assert!(!path.exists());
    assert!(logical_rows(&conn) == before);
    assert!(
        conn.is_autocommit(),
        "failed build retained its read transaction"
    );
}

// Exercise the actual effect transaction from the target lifecycle fixtures.
// This test-only adapter deliberately supplies no consensus or provider mock.
pub(in crate::consensus) fn apply_ordinary_running(
    conn: &Connection,
    key: &AuditKey,
    identity: ConsensusIdentity,
    prepared: &crate::consensus::PreparedAuditedMutation,
    keys: &crate::audit_authority::continuity::AuditKeyRing,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let tx = conn.unchecked_transaction().unwrap();
    let result = apply_audited_mutation_for_profile_sync(
        &tx,
        key,
        identity,
        prepared,
        Some(keys),
        Timestamp::from_offset_datetime(time::OffsetDateTime::from_unix_timestamp(100).unwrap()),
        opc_consensus::ConsensusRequestId::from_bytes([0x73; 16]),
        &SqliteWorkCancellation::new(),
        RetainedConfigProfile::NetconfTargetsV1,
    )?;
    tx.commit().unwrap();
    Ok(result)
}
