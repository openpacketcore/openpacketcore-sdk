//! Real native Durable storage and snapshot-format controls. Direct file
//! transfer here does not qualify authenticated multi-node transport.

use std::collections::BTreeSet;
use std::time::Duration;

use opc_consensus::engine::{CommittedLeaderId, EntryPayload, Membership};
use rusqlite::types::ValueRef;

use super::*;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusTopology, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};

fn identity(marker: u8) -> ConsensusIdentity {
    ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x91; 32]),
        ConfigConsensusConfigurationId::from_bytes([marker; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    )
}

fn members() -> BTreeSet<ConsensusNodeId> {
    BTreeSet::from([ConsensusNodeId::new(1).expect("synthetic node")])
}

fn key() -> AuditKey {
    AuditKey::new([0x93; 32]).expect("synthetic key")
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
        .prefix("config-capacity-snapshot-")
        .tempdir_in(scratch)
        .expect("private snapshot fixture")
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

fn options(path: &Path, profile: ConfigCapacityProfile, backing: u8) -> RetainedConfigOptions {
    let topology = ConfigConsensusTopology::try_new(
        identity(0x92),
        ConsensusNodeId::new(1).expect("node"),
        members(),
    )
    .expect("topology");
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology, [backing; 32], [0x94; 32])
            .expect("binding")
            .with_capacity_profile(profile),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained options")
}

async fn binding(backend: &SqliteBackend) -> Vec<u8> {
    backend
        .conn()
        .lock()
        .await
        .query_row(
            "SELECT record FROM consensus_retained_binding WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("local binding")
}

async fn authority_digest(backend: &SqliteBackend) -> [u8; 32] {
    let connection = backend.conn();
    let connection = connection.lock().await;
    let mut hash = Sha256::new();
    for table in [
        "config_history",
        "audit_trail",
        "config_lifecycle_audit",
        "config_raft_identity",
        "config_raft_vote",
        "config_raft_log",
        "config_raft_applied",
        "config_raft_committed",
        "config_raft_machine",
        "config_raft_membership",
        "config_raft_request_outcomes",
        "config_raft_snapshot",
        "config_raft_management_audit",
        "config_raft_history_retention",
        "consensus_retained_binding",
    ] {
        hash.update(table.as_bytes());
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("authority query");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("authority rows");
        while let Some(row) = rows.next().expect("authority row") {
            hash.update([0xFF]);
            for column in 0..columns {
                match row.get_ref(column).expect("authority value") {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(value) => {
                        hash.update([1]);
                        hash.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        hash.update([2]);
                        hash.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) | ValueRef::Blob(value) => {
                        hash.update([3]);
                        hash.update((value.len() as u64).to_be_bytes());
                        hash.update(value);
                    }
                }
            }
        }
    }
    hash.finalize().into()
}

#[tokio::test]
async fn config_capacity_957_snapshot_footer_preserves_legacy_and_authenticates_profile() {
    let root = disk_fixture();
    let raw = root.join("synthetic-body");
    let body = b"synthetic format control; not a SQLite snapshot";
    tokio::fs::write(&raw, body).await.expect("body");
    for (profile, other, revision) in [
        (
            ConfigCapacityProfile::Legacy,
            ConfigCapacityProfile::BoundedV1,
            5_u16,
        ),
        (
            ConfigCapacityProfile::BoundedV1,
            ConfigCapacityProfile::Legacy,
            6_u16,
        ),
    ] {
        let path = root.join(format!("format-{revision}"));
        let (digest, length, _guard) =
            envelope_snapshot_database(&raw, &path, profile, identity(0x92), &key())
                .await
                .expect("seal synthetic format control");
        assert_eq!(length, body.len() as u64 + 50);
        assert_eq!(
            verify_snapshot_envelope(&path, profile, identity(0x92), &key())
                .await
                .expect("matching format"),
            (body.len() as u64, digest, length)
        );
        assert!(
            verify_snapshot_envelope(&path, other, identity(0x92), &key())
                .await
                .is_err()
        );
        let actual = tokio::fs::read(&path).await.expect("encoded snapshot");
        assert_eq!(
            &actual[body.len() + 8..body.len() + 10],
            revision.to_be_bytes()
        );
        if profile == ConfigCapacityProfile::Legacy {
            let mut expected = body.to_vec();
            expected.extend_from_slice(b"OPCCFG01");
            expected.extend_from_slice(&5_u16.to_be_bytes());
            expected.extend_from_slice(&(body.len() as u64).to_be_bytes());
            expected.extend_from_slice(&Sha256::digest(body));
            assert!(
                actual == expected,
                "legacy snapshot bytes must remain exact"
            );
        } else {
            for (scope, selected_key) in [
                (identity(0x95), key()),
                (
                    identity(0x92),
                    AuditKey::new([0x96; 32]).expect("other key"),
                ),
                (
                    identity(0x92),
                    AuditKey::new_with_epoch([0x93; 32], 2).expect("other epoch"),
                ),
            ] {
                assert!(
                    verify_snapshot_envelope(&path, profile, scope, &selected_key)
                        .await
                        .is_err()
                );
            }
            // Replacing a valid MAC with the public body checksum must fail.
            let mut forged = actual;
            let offset = forged.len() - 32;
            forged[offset..].copy_from_slice(&Sha256::digest(body));
            tokio::fs::write(&path, forged)
                .await
                .expect("checksum substitution");
            assert!(
                verify_snapshot_envelope(&path, profile, identity(0x92), &key())
                    .await
                    .is_err()
            );
        }
    }
}

async fn source_snapshot(
    root: &Path,
    profile: ConfigCapacityProfile,
) -> (
    SqliteBackend,
    OpenedConfigStorage,
    Snapshot<ConfigRaftTypeConfig>,
) {
    let backend = SqliteBackend::provision_config_authority(
        options(&root.join("source.sqlite"), profile, 0xA1),
        key(),
    )
    .await
    .expect("native Durable source");
    let mut opened = open(
        &backend,
        root.join("source-snapshots"),
        identity(0x92),
        members(),
    )
    .await
    .expect("source storage");
    let membership = Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(1, ConsensusNodeId::new(1).expect("node")),
            1,
        ),
        payload: EntryPayload::Membership(Membership::new(vec![members()], None)),
    };
    opened
        .1
        .apply([membership])
        .await
        .expect("applied membership");
    let snapshot = opened
        .1
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("source snapshot");
    (backend, opened, snapshot)
}

async fn transfer(
    source: &Path,
    target: &mut SqliteConfigStateMachine,
    meta: &SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> Result<(), StorageError<ConsensusNodeId>> {
    let mut incoming = target
        .begin_receiving_snapshot()
        .await
        .expect("private incoming file");
    let mut file = tokio::fs::File::open(source).await.expect("source file");
    tokio::io::copy(&mut file, incoming.as_mut())
        .await
        .expect("finite file transfer");
    target.install_snapshot(meta, incoming).await
}

#[tokio::test]
async fn config_capacity_957_native_snapshot_profile_rejects_before_authority_changes() {
    for (profile, other) in [
        (
            ConfigCapacityProfile::Legacy,
            ConfigCapacityProfile::BoundedV1,
        ),
        (
            ConfigCapacityProfile::BoundedV1,
            ConfigCapacityProfile::Legacy,
        ),
    ] {
        let root = disk_fixture();
        let (_source, _source_storage, snapshot) = source_snapshot(&root, profile).await;
        let target = SqliteBackend::provision_config_member_repair(
            options(&root.join("target.sqlite"), other, 0xA2),
            key(),
        )
        .await
        .expect("native Durable target");
        let mut target_storage = open(
            &target,
            root.join("target-snapshots"),
            identity(0x92),
            members(),
        )
        .await
        .expect("target storage");
        let before = authority_digest(&target).await;
        assert!(transfer(
            snapshot.snapshot.path(),
            &mut target_storage.1,
            &snapshot.meta
        )
        .await
        .is_err());
        assert!(
            before == authority_digest(&target).await,
            "wrong profile changed authority"
        );

        // Authenticate under the receiver's profile, but retain the sender's
        // incompatible SQLite body. This independently exercises body validation.
        let raw = root.join("wrong-profile.sqlite");
        let body_length = std::fs::metadata(snapshot.snapshot.path())
            .expect("snapshot length")
            .len()
            - SNAPSHOT_FOOTER_BYTES;
        let _raw_guard = extract_snapshot_database(snapshot.snapshot.path(), &raw, body_length)
            .await
            .expect("extract body");
        let forged = root.join("resealed-wrong-profile.opc");
        let (_, _, _forged_guard) =
            envelope_snapshot_database(&raw, &forged, other, identity(0x92), &key())
                .await
                .expect("adversarial reseal");
        assert!(transfer(&forged, &mut target_storage.1, &snapshot.meta)
            .await
            .is_err());
        assert!(
            before == authority_digest(&target).await,
            "wrong body changed authority"
        );
    }
}

#[tokio::test]
async fn config_capacity_957_native_snapshot_preserves_receiver_binding_and_reopens() {
    let root = disk_fixture();
    let profile = ConfigCapacityProfile::BoundedV1;
    let (source, _source_storage, snapshot) = source_snapshot(&root, profile).await;
    let target_options = options(&root.join("target.sqlite"), profile, 0xA3);
    let target = SqliteBackend::provision_config_member_repair(target_options.clone(), key())
        .await
        .expect("native Durable target");
    let receiver_binding = binding(&target).await;
    assert!(
        receiver_binding != binding(&source).await,
        "independent local bindings"
    );
    let mut target_storage = open(
        &target,
        root.join("target-snapshots"),
        identity(0x92),
        members(),
    )
    .await
    .expect("target storage");
    transfer(
        snapshot.snapshot.path(),
        &mut target_storage.1,
        &snapshot.meta,
    )
    .await
    .expect("matching profile restore");
    assert!(
        receiver_binding == binding(&target).await,
        "receiver local authority preserved"
    );
    assert_eq!(
        target_storage
            .1
            .applied_state()
            .await
            .expect("restored state")
            .0,
        snapshot.meta.last_log_id
    );
    drop(target_storage);
    drop(target);
    let reopened = SqliteBackend::reopen_config_authority(target_options, key())
        .await
        .expect("retained profile reopen");
    let mut reopened_storage = open(
        &reopened,
        root.join("target-snapshots"),
        identity(0x92),
        members(),
    )
    .await
    .expect("verify retained snapshot before cleanup");
    let restored = reopened_storage
        .1
        .get_current_snapshot()
        .await
        .expect("read retained snapshot")
        .expect("snapshot present");
    assert_eq!(restored.meta, snapshot.meta);
    assert!(
        receiver_binding == binding(&reopened).await,
        "reopen keeps exact local binding"
    );
}
