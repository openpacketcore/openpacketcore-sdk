//! Baseline-compatible gate and native fixture. These tests do not admit a
//! joint target authority, construct an Intent, or exercise target reduction.

use super::*;
use crate::consensus::audit_mutation::joint_running::tests::prepared_for_store;
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusTopology,
};
use crate::{
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile,
};
use opc_crypto::ConfigPreparationPool;

pub(super) struct Fixture {
    pub(super) backend: SqliteBackend,
    pub(super) options: RetainedConfigOptions,
    pub(super) identity: ConsensusIdentity,
    pub(super) key: AuditKey,
    pub(super) root: tempfile::TempDir,
}

pub(super) async fn fixture() -> Fixture {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("joint-native-running-")
        .tempdir_in(scratch)
        .expect("private disk fixture");
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(root.path())
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xC1; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xC2; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    );
    let node = ConsensusNodeId::new(1).expect("synthetic voter");
    let topology = ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
        .expect("singleton topology");
    let binding = RetainedConfigBinding::new(topology, [0xC3; 32], [0xC4; 32])
        .expect("native binding")
        .with_capacity_profile(ConfigCapacityProfile::BoundedV1);
    let options = RetainedConfigOptions::new(
        root.path().join("config.sqlite"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("unchanged retained limits");
    let key = AuditKey::new([0xC5; 32]).expect("synthetic audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("genuine capacity8 native substrate");
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert!(crate::schema::verify_wal_mode(&conn).expect("native WAL"));
        assert!(crate::schema::verify_synchronous_extra(&conn).expect("native Durable"));
        super::super::history::validate_access_for_profile_sync(
            &conn,
            &key,
            true,
            Some(identity),
            RetainedConfigMode::BoundedV1,
            &SqliteWorkCancellation::new(),
        )
        .expect("independently selected authenticated empty history");
    }
    Fixture {
        backend,
        options,
        identity,
        key,
        root,
    }
}

pub(super) fn context(
    cancellation: &SqliteWorkCancellation,
) -> super::super::audit::ApplyContext<'_> {
    super::super::audit::ApplyContext {
        logical_time: Timestamp::from_str("1970-01-01T00:01:41Z").expect("within original lease"),
        request_id: opc_consensus::ConsensusRequestId::from_bytes([0xC6; 16]),
        cancellation,
    }
}

// Whole rows, including authenticated ledgers, native frontiers and binding.
// The test observes an actual SQLite transaction; no effect callback is mocked.
pub(super) fn authority_digest(conn: &Connection) -> [u8; 32] {
    use rusqlite::types::ValueRef;
    let mut digest = Sha256::new();
    for table in [
        "config_history",
        "audit_trail",
        "config_lifecycle_audit",
        "rollback_labels",
        "config_raft_identity",
        "config_raft_vote",
        "config_raft_log",
        "config_raft_applied",
        "config_raft_committed",
        "config_raft_purged",
        "config_raft_machine",
        "config_raft_membership",
        "config_raft_request_outcomes",
        "config_raft_snapshot",
        "config_raft_management_audit",
        "config_raft_history_retention",
        "config_raft_capacity_records",
        "config_raft_legacy_recovery",
        "consensus_retained_binding",
    ] {
        digest.update(table.as_bytes());
        if !table_exists(conn, table).expect("authority table") {
            digest.update([0]);
            continue;
        }
        digest.update([1]);
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("whole authority query");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("whole authority rows");
        while let Some(row) = rows.next().expect("whole authority row") {
            digest.update([0xFF]);
            for column in 0..columns {
                match row.get_ref(column).expect("authority value") {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(value) => {
                        digest.update([1]);
                        digest.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        digest.update([2]);
                        digest.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) => {
                        digest.update([3]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value);
                    }
                    ValueRef::Blob(value) => {
                        digest.update([4]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value);
                    }
                }
            }
        }
    }
    digest.finalize().into()
}

#[tokio::test]
async fn joint_native_running_dispatch_refuses_without_independent_authority() {
    let fixture = fixture().await;
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&pool, fixture.identity, &fixture.key).await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let before = authority_digest(&conn);
    conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
        .expect("authority savepoint");
    let cancellation = SqliteWorkCancellation::new();
    let result = apply_target_running_sync(
        &conn,
        &fixture.key,
        prepared.command(),
        None,
        &context(&cancellation),
    )
    .expect("typed refusal");
    conn.execute_batch("ROLLBACK").expect("native rollback");
    assert_eq!(
        authority_digest(&conn),
        before,
        "closed dispatch has no effect"
    );
    assert!(
        matches!(result, Err(ConfigMutationFailure::InvalidInput)),
        "JOINT_NATIVE_RUNNING_DISPATCH_CLOSED: no successful silent fallthrough"
    );
}

#[tokio::test]
async fn joint_native_running_joint_open_still_refuses_before_files() {
    let fixture = fixture().await;
    let path = fixture.root.path().join("joint-must-not-exist.sqlite");
    let node = ConsensusNodeId::new(1).expect("synthetic voter");
    let topology = ConfigConsensusTopology::try_new(fixture.identity, node, BTreeSet::from([node]))
        .expect("singleton topology");
    let binding = RetainedConfigBinding::new(topology, [0xC3; 32], [0xC4; 32])
        .expect("native binding")
        .with_profile(RetainedConfigProfile::NetconfTargetsV1)
        .with_capacity_profile(ConfigCapacityProfile::BoundedV1);
    let options = RetainedConfigOptions::new(
        path.clone(),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    );
    let refusal = match options {
        Err(error) => error,
        Ok(options) => {
            match SqliteBackend::provision_config_authority(options, fixture.key.clone()).await {
                Err(error) => error,
                Ok(_) => panic!("joint target/capacity opening unexpectedly succeeded"),
            }
        }
    };
    assert!(
        matches!(refusal, crate::RetainedConfigError::Unsupported),
        "JOINT_NATIVE_RUNNING_JOINT_OPEN_CLOSED"
    );
    assert!(!path.exists(), "no joint authority file");
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        assert!(!PathBuf::from(sidecar).exists(), "no joint sidecar");
    }
    // The separate supported capacity authority still opens with the same
    // immutable options, establishing a positive gate control.
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key)
        .await
        .expect("supported capacity8 reopening is unaffected");
    drop(reopened);
}
