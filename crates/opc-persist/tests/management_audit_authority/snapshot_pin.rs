// RFC019 snapshot construction must pin validation, frontier and contents.
// An independent connection commits an authenticated audit transition exactly
// after the builder captured its frontier; no timing loop or sleeps are used.
use super::*;
use crate::audit_authority::{AuditLedgerLimits, AuditToken};
use crate::consensus::audit::AuditCommand;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusRequestId, ConfigConsensusTopology,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions,
    CONFIG_CONSENSUS_COMMAND_VERSION,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};

#[tokio::test]
async fn snapshot_keeps_captured_frontier_and_audit_state_from_one_source_view() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let node = ConsensusNodeId::new(1).unwrap();
    let members = BTreeSet::from([node]);
    let topology = ConfigConsensusTopology::try_new(identity, node, members.clone()).unwrap();
    let key = AuditKey::new([0x61; 32]).unwrap();
    let options = RetainedConfigOptions::new(
        &path,
        RetainedConfigBinding::new(topology, [0x62; 32], [0x63; 32]).unwrap(),
        RetainedConfigDurability::Ephemeral,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    let backend = SqliteBackend::provision_config_authority(options, key.clone())
        .await
        .unwrap();
    let shared = backend.conn();
    let source = shared.lock().await;
    let first = LogId::new(CommittedLeaderId::new(1, node), 0);
    let second = LogId::new(CommittedLeaderId::new(1, node), 1);
    apply_entries_sync(
        &source,
        &key,
        identity,
        &members,
        vec![Entry {
            log_id: first,
            payload: EntryPayload::Membership(Membership::new(
                vec![members.clone()],
                members.clone(),
            )),
        }],
    )
    .unwrap();
    let other = Connection::open(&path).unwrap();
    let mode: String = other
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let competing_members = members.clone();
    let competing_key = key.clone();
    SNAPSHOT_AFTER_FRONTIER.with(|hook| {
        assert!(hook.borrow().is_none());
        *hook.borrow_mut() = Some(Box::new(move || {
            let response = apply_entries_sync(
                &other,
                &competing_key,
                identity,
                &competing_members,
                vec![Entry {
                    log_id: second,
                    payload: EntryPayload::Normal(ConfigConsensusCommand {
                        schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                        identity,
                        request_id: ConfigConsensusRequestId::from_bytes([0x64; 16]),
                        logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
                        intent: ConfigMutationIntent::ManagementAudit(AuditCommand::Initialize {
                            projection: AuditToken::from_keyed_projection([0x65; 32]).unwrap(),
                            limits: AuditLedgerLimits::new(6, 2).unwrap(),
                        }),
                    }),
                }],
            )
            .expect("independent WAL apply at deterministic barrier");
            assert!(response[0].result.is_ok());
            assert_eq!(read_applied_sync(&other, identity).unwrap(), Some(second));
            assert!(
                super::super::audit::read_sync(&other, &competing_key, identity)
                    .unwrap()
                    .is_some()
            );
        }));
    });
    let snapshot_path = directory.path().join("snapshot.sqlite");
    let (captured, membership) =
        build_snapshot_database_sync(&source, identity, &members, &key, &snapshot_path)
            .expect("coherent snapshot");
    SNAPSHOT_AFTER_FRONTIER.with(|hook| assert!(hook.borrow().is_none()));
    assert_eq!(captured, Some(first));
    let snapshot = Connection::open(&snapshot_path).unwrap();
    assert_eq!(
        read_applied_sync(&snapshot, identity).unwrap(),
        captured,
        "snapshot copied a frontier newer than its captured metadata"
    );
    assert_eq!(
        read_membership_sync(&snapshot, identity, &members).unwrap(),
        membership
    );
    assert!(
        super::super::audit::read_sync(&snapshot, &key, identity)
            .unwrap()
            .is_none(),
        "snapshot mixed later audit state into its captured frontier"
    );
    // The concurrent transition happened; the retained source sees it after
    // the builder releases its read view, while the snapshot remains pinned.
    assert_eq!(read_applied_sync(&source, identity).unwrap(), Some(second));
    assert!(super::super::audit::read_sync(&source, &key, identity)
        .unwrap()
        .is_some());
}
