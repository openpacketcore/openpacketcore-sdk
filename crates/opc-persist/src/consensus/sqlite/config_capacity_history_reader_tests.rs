//! Disk-backed native WAL controls for history-authentication Rust copies.
//! These do not qualify the complete memory envelope or a multi-node profile.

use super::*;
use crate::consensus::history::config_capacity_read_buffers::{Observation, Sample};
use crate::consensus::history::{ConfigHistoryLimits, ConfigHistoryRetention};
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusTopology,
};
use crate::{RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use sha2::{Digest, Sha256};

const LOGICAL_BYTES: usize = 96 * 1024;

struct Fixture {
    backend: SqliteBackend,
    options: RetainedConfigOptions,
    topology: ConfigConsensusTopology,
    key: AuditKey,
}

fn tx_id(version: u64) -> TxId {
    TxId::from_uuid(uuid::Uuid::from_u128(0xD500 + u128::from(version)))
}

fn append_entry(
    topology: &ConfigConsensusTopology,
    key: &AuditKey,
    version: u64,
) -> Entry<ConfigRaftTypeConfig> {
    let committed_at = Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time");
    let parent = (version > 1).then(|| tx_id(version - 1));
    let principal = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config";
    let schema_digest = SchemaDigest::from_bytes([0xD6; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        opc_key::ConfigAad::new(
            tx_id(version),
            parent,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("history-reader-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xD7; 32]),
    );
    let mut plaintext = vec![b'q'; LOGICAL_BYTES];
    plaintext[0] = b'"';
    plaintext[LOGICAL_BYTES - 1] = b'"';
    let nonce = [u8::try_from(version).expect("fixture nonce"); 12];
    let envelope = opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
        &handle, &aad, &plaintext, nonce,
    )
    .expect("real synthetic encryption");
    let record = crate::types::CommitRecord {
        tx_id: tx_id(version),
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let prepared = super::super::types::PreparedConfigCommit::prepare(record, Vec::new(), key)
        .expect("sealed fixture record");
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, topology.local_node_id()), version),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: topology.identity(),
            request_id: super::super::ConfigConsensusRequestId::from_bytes(
                [u8::try_from(version).expect("fixture ordinal"); 16],
            ),
            logical_time: committed_at,
            intent: ConfigMutationIntent::AppendCommit(Box::new(prepared)),
        }),
    }
}

async fn fixture() -> Fixture {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-history-reader-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let node = ConsensusNodeId::new(1).expect("node");
    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xD8; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xD9; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology = ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
        .expect("singleton storage topology");
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0xDA; 32], [0xDB; 32]).expect("binding"),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("native retained limits");
    let key = AuditKey::new([0xDC; 32]).expect("synthetic audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained backend");
    let shared = backend.conn();
    let conn = shared.lock().await;
    assert!(crate::schema::verify_wal_mode(&conn).expect("native WAL"));
    assert!(crate::schema::verify_synchronous_extra(&conn).expect("native durability"));
    let mut entries = vec![Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, node), 0),
        payload: EntryPayload::Membership(Membership::new(
            vec![topology.members().clone()],
            topology.members().clone(),
        )),
    }];
    entries.extend((1..=3).map(|version| append_entry(&topology, &key, version)));
    append_logs_sync(&conn, identity, topology.members(), &entries).expect("native WAL append");
    save_committed_sync(&conn, identity, entries.last().map(|entry| entry.log_id))
        .expect("committed native prefix");
    let responses = apply_entries_sync(&conn, &key, identity, topology.members(), entries)
        .expect("atomic retained records");
    assert!(responses.iter().all(|response| response.result.is_ok()));
    super::super::history::validate_access_sync(&conn, &key, true, &SqliteWorkCancellation::new())
        .expect("authenticated fixture");
    drop(conn);
    drop(shared);
    Fixture {
        backend,
        options,
        topology,
        key,
    }
}

fn assert_borrowed(sample: Sample, required_sites: &[usize]) {
    for &site in required_sites {
        assert!(
            sample.calls[site] > 0,
            "required history projection was reached"
        );
    }
    assert_eq!(
        sample.peak_owned_ciphertext, 0,
        "history authentication must not own a ciphertext copy"
    );
}

#[tokio::test]
async fn config_capacity_957_history_authentication_borrows_ciphertext() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tx = conn
        .unchecked_transaction()
        .expect("pinned read transaction");
    let observation = Observation::start();
    super::super::history::validate_access_sync(
        &tx,
        &fixture.key,
        true,
        &SqliteWorkCancellation::new(),
    )
    .expect("authenticate retained rows");
    let sample = observation.finish();
    tx.commit().expect("finish read transaction");
    assert_borrowed(sample, &[0, 1]);
}

#[tokio::test]
async fn config_capacity_957_history_rejection_borrows_ciphertext() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    conn.execute(
        "UPDATE config_history SET encrypted_blob = zeroblob(length(encrypted_blob)) WHERE version = 2",
        [],
    )
    .expect("synthetic retained corruption");
    let tx = conn
        .unchecked_transaction()
        .expect("pinned read transaction");
    let observation = Observation::start();
    let rejected = super::super::history::validate_access_sync(
        &tx,
        &fixture.key,
        true,
        &SqliteWorkCancellation::new(),
    );
    let sample = observation.finish();
    assert!(
        rejected.is_err(),
        "changed ciphertext must fail authentication"
    );
    tx.commit().expect("finish rejected read transaction");
    assert_borrowed(sample, &[0, 1]);
}

#[tokio::test]
async fn config_capacity_957_history_retention_boundary_borrows_ciphertext() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let decision = ConfigHistoryRetention::new(
        tx_id(3),
        ConfigVersion::new(3),
        ConfigVersion::new(1),
        ConfigVersion::new(2),
        ConfigHistoryLimits::new(2, 1024 * 1024).expect("unchanged retention limits"),
    )
    .expect("acknowledged prefix");
    let tx = conn
        .unchecked_transaction()
        .expect("atomic retention transaction");
    let observation = Observation::start();
    super::super::history::retain_sync(
        &tx,
        &fixture.key,
        &decision,
        &SqliteWorkCancellation::new(),
    )
    .expect("retention storage")
    .expect("admitted retention");
    super::super::history::validate_access_sync(
        &tx,
        &fixture.key,
        true,
        &SqliteWorkCancellation::new(),
    )
    .expect("authenticated retained boundary");
    let parent = super::super::history::original_parent_sync(
        &tx,
        &fixture.key,
        tx_id(2).as_uuid().as_bytes(),
        2,
        None,
    )
    .expect("original AEAD parent");
    assert!(parent.as_deref() == Some(tx_id(1).as_uuid().as_bytes().as_slice()));
    let sample = observation.finish();
    tx.commit().expect("durable retention");
    assert_borrowed(sample, &[0, 1, 2, 3]);
    drop(conn);
    drop(shared);
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key.clone())
        .await
        .expect("retained native reopen");
    let shared = reopened.conn();
    let conn = shared.lock().await;
    let observation = Observation::start();
    validate_retained_schema(
        &conn,
        &fixture.topology,
        &fixture.key,
        ConfigCapacityProfile::Legacy,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .expect("retained schema and original parent");
    assert_borrowed(observation.finish(), &[0, 1, 2]);
}
