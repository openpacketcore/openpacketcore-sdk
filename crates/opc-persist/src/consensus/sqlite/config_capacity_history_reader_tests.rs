//! Disk-backed native WAL controls for history-authentication Rust copies.
//! These do not qualify the complete memory envelope or a multi-node profile.
//! Scalar probes measure owned projection buffers, not total allocator traffic.

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
    append_logs_sync(
        &conn,
        identity,
        topology.members(),
        &entries,
        crate::consensus::RetainedConfigMode::try_from(ConfigCapacityProfile::Legacy)
            .expect("supported fixture mode"),
    )
    .expect("native WAL append");
    save_committed_sync(
        &conn,
        identity,
        entries.last().map(|entry| entry.log_id),
        crate::consensus::RetainedConfigMode::try_from(ConfigCapacityProfile::Legacy)
            .expect("supported fixture mode"),
    )
    .expect("committed native prefix");
    let responses = apply_entries_sync(&conn, &key, identity, topology.members(), entries)
        .expect("atomic retained records");
    assert!(responses.iter().all(|response| response.result.is_ok()));
    super::super::history::validate_access_sync(
        &conn,
        &key,
        true,
        identity,
        &SqliteWorkCancellation::new(),
    )
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

fn assert_fixed_width(sample: Sample, required_sites: &[usize]) {
    for &site in required_sites {
        assert!(
            sample.fixed_width_calls[site] > 0,
            "required fixed-width projection was reached"
        );
    }
    assert_eq!(
        sample.peak_owned_fixed_width, [0; 9],
        "fixed-width history projections must not own heap buffers"
    );
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
        fixture.topology.identity(),
        &SqliteWorkCancellation::new(),
    )
    .expect("authenticate retained rows");
    let sample = observation.finish();
    tx.commit().expect("finish read transaction");
    assert_borrowed(sample, &[0, 1]);
    assert_fixed_width(sample, &[0, 1, 2]);
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
        fixture.topology.identity(),
        &SqliteWorkCancellation::new(),
    );
    let sample = observation.finish();
    assert!(
        rejected.is_err(),
        "changed ciphertext must fail authentication"
    );
    tx.commit().expect("finish rejected read transaction");
    assert_borrowed(sample, &[0, 1]);
    assert_fixed_width(sample, &[0, 1, 2]);
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
        fixture.topology.identity(),
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
    assert_fixed_width(sample, &[0, 1, 2, 3, 4, 6, 7, 8]);
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
        crate::consensus::RetainedConfigMode::try_from(ConfigCapacityProfile::Legacy)
            .expect("supported fixture mode"),
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .expect("retained schema and original parent");
    let sample = observation.finish();
    assert_borrowed(sample, &[0, 1, 2]);
    assert_fixed_width(sample, &[0, 1, 2, 3, 4]);
}

fn assert_sealed_borrowed(sample: super::config_capacity_sealed_buffers::Sample, rows: usize) {
    assert_eq!(
        sample.calls, rows,
        "every expected sealed record was reached"
    );
    assert_eq!(
        sample.peak_owned_ciphertext, 0,
        "sealed validation must not own a ciphertext copy"
    );
}

#[tokio::test]
async fn config_capacity_957_sealed_validation_borrows_ciphertext() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tx = conn.unchecked_transaction().expect("pinned validation");
    let observation = super::config_capacity_sealed_buffers::Observation::start();
    validate_sealed_state_sync(
        &tx,
        fixture.topology.identity(),
        &fixture.key,
        &SqliteWorkCancellation::new(),
    )
    .expect("sealed native records");
    assert_sealed_borrowed(observation.finish(), 3);
    let decision = ConfigHistoryRetention::new(
        tx_id(3),
        ConfigVersion::new(3),
        ConfigVersion::new(1),
        ConfigVersion::new(2),
        ConfigHistoryLimits::new(2, 1024 * 1024).expect("unchanged retention limits"),
    )
    .expect("acknowledged prefix");
    super::super::history::retain_sync(
        &tx,
        &fixture.key,
        &decision,
        &SqliteWorkCancellation::new(),
    )
    .expect("retention storage")
    .expect("admitted retention");
    let observation = super::config_capacity_sealed_buffers::Observation::start();
    validate_sealed_state_sync(
        &tx,
        fixture.topology.identity(),
        &fixture.key,
        &SqliteWorkCancellation::new(),
    )
    .expect("sealed boundary restores original AEAD parent");
    assert_sealed_borrowed(observation.finish(), 2);
    tx.commit().expect("durable retained prefix");
    drop(conn);
    drop(shared);
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key.clone())
        .await
        .expect("native retained reopen");
    let shared = reopened.conn();
    let conn = shared.lock().await;
    let tx = conn
        .unchecked_transaction()
        .expect("pinned retained reopen");
    let observation = super::config_capacity_sealed_buffers::Observation::start();
    validate_retained_schema(
        &tx,
        &fixture.topology,
        &fixture.key,
        crate::consensus::RetainedConfigMode::try_from(ConfigCapacityProfile::Legacy)
            .expect("supported fixture mode"),
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .expect("retained schema and original parent");
    assert_sealed_borrowed(observation.finish(), 2);
    tx.commit().expect("finish reopened read");
}

#[tokio::test]
async fn config_capacity_957_sealed_rejection_borrows_ciphertext() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tx = conn
        .unchecked_transaction()
        .expect("pinned negative fixture");
    tx.execute(
        "UPDATE config_history SET encrypted_blob = zeroblob(length(encrypted_blob)) WHERE version = 2",
        [],
    )
    .expect("synthetic malformed middle envelope");
    // This test owns the synthetic signing key. Deliberately reauthenticate
    // the changed history so the negative reaches sealed-envelope validation.
    // It does not claim that ordinary on-disk corruption can reauthenticate.
    super::super::history::refresh_sync(&tx, &fixture.key, true, &SqliteWorkCancellation::new())
        .expect("synthetic history authentication")
        .expect("within original history bounds");
    super::super::history::validate_access_sync(
        &tx,
        &fixture.key,
        true,
        fixture.topology.identity(),
        &SqliteWorkCancellation::new(),
    )
    .expect("negative reaches envelope validation after authenticated history");
    let observation = super::config_capacity_sealed_buffers::Observation::start();
    let error = validate_sealed_state_sync(
        &tx,
        fixture.topology.identity(),
        &fixture.key,
        &SqliteWorkCancellation::new(),
    )
    .expect_err("malformed envelope must be rejected");
    let sample = observation.finish();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_sealed_borrowed(sample, 2);
    // Roll back fixture tampering; no negative-path mutation is committed.
    tx.rollback().expect("restore original fixture");
    validate_sealed_state_sync(
        &conn,
        fixture.topology.identity(),
        &fixture.key,
        &SqliteWorkCancellation::new(),
    )
    .expect("original retained records remain valid");
}

// These cases preserve the original schema, ciphertext and authenticated state.
// Deferred foreign keys permit a deliberately corrupt UUID/parent in a transaction
// that is always rolled back; the malformed data is never admitted or resigned.
fn assert_fixed_width_rejection(
    conn: &Connection,
    fixture: &Fixture,
    update: &str,
    width: usize,
    site: usize,
    accepted_before_rejection: usize,
) {
    // The large value is an adversarial field size, not a mutation-memory budget.
    for length in [128 * 1024, 0, width - 1, width + 1] {
        let tx = conn
            .unchecked_transaction()
            .expect("pinned corrupt fixture");
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")
            .expect("defer only the negative fixture's foreign keys");
        assert_eq!(
            tx.execute(update, [i64::try_from(length).expect("fixture length")])
                .expect("replace exactly one retained field"),
            1
        );
        let observation = Observation::start();
        let error = super::super::history::validate_access_sync(
            &tx,
            &fixture.key,
            true,
            fixture.topology.identity(),
            &SqliteWorkCancellation::new(),
        )
        .expect_err("malformed fixed-width history field must be rejected");
        let sample = observation.finish();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            sample.peak_owned_fixed_width[site], 0,
            "field site {site}, length {length}: rejection must precede an owned copy"
        );
        assert_eq!(
            sample.fixed_width_calls[site], accepted_before_rejection,
            "field site {site}, length {length}: malformed field must not be projected"
        );
        assert_eq!(sample.peak_owned_ciphertext, 0);
        tx.rollback().expect("restore valid retained bytes");
        super::super::history::validate_access_sync(
            conn,
            &fixture.key,
            true,
            fixture.topology.identity(),
            &SqliteWorkCancellation::new(),
        )
        .expect("the original full authenticated history remains valid");
    }
}

#[tokio::test]
async fn config_capacity_957_retained_fixed_width_head_uuid_rejects_before_copy() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_fixed_width_rejection(
        &conn,
        &fixture,
        "UPDATE config_history SET tx_id = zeroblob(?1) WHERE version = 3",
        16,
        0,
        0,
    );
}

#[tokio::test]
async fn config_capacity_957_retained_fixed_width_chain_uuid_rejects_before_copy() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_fixed_width_rejection(
        &conn,
        &fixture,
        "UPDATE config_history SET tx_id = zeroblob(?1) WHERE version = 2",
        16,
        1,
        1,
    );
}

#[tokio::test]
async fn config_capacity_957_retained_fixed_width_terminal_hash_rejects_before_copy() {
    let fixture = fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_fixed_width_rejection(
        &conn,
        &fixture,
        "UPDATE config_history SET audit_terminal_hash = zeroblob(?1) WHERE version = 2",
        32,
        2,
        1,
    );
}

async fn fixed_width_retained_fixture() -> Fixture {
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
        .expect("atomic retained prefix");
    super::super::history::retain_sync(
        &tx,
        &fixture.key,
        &decision,
        &SqliteWorkCancellation::new(),
    )
    .expect("retention storage")
    .expect("admitted retention");
    tx.commit().expect("durable retained prefix");
    drop(conn);
    drop(shared);
    fixture
}

#[tokio::test]
async fn config_capacity_957_retained_fixed_width_boundary_uuid_rejects_before_copy() {
    let fixture = fixed_width_retained_fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_fixed_width_rejection(
        &conn,
        &fixture,
        "UPDATE config_history SET tx_id = zeroblob(?1) WHERE version = 2",
        16,
        3,
        0,
    );
}

#[tokio::test]
async fn config_capacity_957_retained_fixed_width_boundary_parent_rejects_before_copy() {
    let fixture = fixed_width_retained_fixture().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_fixed_width_rejection(
        &conn,
        &fixture,
        "UPDATE config_history SET parent_tx_id = zeroblob(?1) WHERE version = 2",
        16,
        4,
        0,
    );
    // Correct width still cannot change the authenticated NULL boundary link.
    let tx = conn
        .unchecked_transaction()
        .expect("pinned boundary tamper");
    tx.execute(
        "UPDATE config_history SET parent_tx_id = ?1 WHERE version = 2",
        [tx_id(3).as_uuid().as_bytes().as_slice()],
    )
    .expect("existing fixed-width foreign key");
    assert!(super::super::history::validate_access_sync(
        &tx,
        &fixture.key,
        true,
        fixture.topology.identity(),
        &SqliteWorkCancellation::new(),
    )
    .is_err());
    tx.rollback().expect("restore NULL boundary link");
    drop(conn);
    drop(shared);
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key)
        .await
        .expect("valid history reopens after every malformed scalar is rolled back");
    drop(reopened);
}

// These controls use real reserved bounded encryption and the public native
// writer. Their synchronous probe measures SHA input, not total memory or time.
const DIGEST_PRINCIPAL: &str = "spiffe://qualification.invalid/tenant/test/ns/test/sa/history";

struct DigestExpectedRecord {
    version: u64,
    logical_bytes: usize,
    ciphertext_bytes: usize,
    ciphertext_digest: [u8; 32],
}

struct DigestFixture {
    root: tempfile::TempDir,
    backend: SqliteBackend,
    options: RetainedConfigOptions,
    topology: ConfigConsensusTopology,
    key: AuditKey,
    expected: Vec<DigestExpectedRecord>,
    handles: Vec<crate::consensus::ConfigCommitRecoveryHandle>,
    has_boundary: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct DigestInput {
    rows: usize,
    bytes: usize,
    head_bytes: usize,
    boundary_bytes: usize,
}

fn digest_provider() -> opc_key::MemoryKeyProvider {
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("history-digest-fixture").expect("synthetic key ID"),
            opc_key::KeyPurpose::Config,
            TenantId::from_static("test"),
            opc_key::Zeroizing::new([0xE7; 32]),
        )
        .expect("synthetic provider");
    provider
}

fn digest_aad(version: u64) -> opc_key::EnvelopeAad {
    opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        opc_key::ConfigAad::new(
            tx_id(version),
            (version > 1).then(|| tx_id(version - 1)),
            Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time"),
            DIGEST_PRINCIPAL,
            SchemaDigest::from_bytes([0xE6; 32]),
            "running",
        )
        .expect("synthetic AAD"),
    )
}

async fn verify_digest_native(
    store: &crate::consensus::ConsensusConfigStore,
    expected: &[DigestExpectedRecord],
    handles: &[crate::consensus::ConfigCommitRecoveryHandle],
) {
    use crate::ConfigStore;
    let actual = store
        .load_latest()
        .await
        .expect("linearizable retained read");
    if let Some(last) = expected.last() {
        let actual = actual.expect("actual committed head");
        assert_eq!(actual.record.version.get(), last.version);
        assert_eq!(actual.record.tx_id, tx_id(last.version));
        assert_eq!(actual.record.encrypted_blob.len(), last.ciphertext_bytes);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&actual.record.encrypted_blob)),
            last.ciphertext_digest
        );
        let plaintext = opc_crypto::decrypt_envelope(
            &digest_provider(),
            &digest_aad(last.version),
            &actual.record.encrypted_blob,
        )
        .await
        .expect("decrypt original exact record");
        assert_eq!(plaintext.len(), last.logical_bytes);
        assert_eq!(plaintext.first(), Some(&b'"'));
        assert_eq!(plaintext.last(), Some(&b'"'));
        assert!(plaintext[1..plaintext.len() - 1]
            .iter()
            .all(|byte| *byte == b'q'));
    } else {
        assert!(actual.is_none(), "empty bounded history remains empty");
    }
    for handle in handles {
        assert!(matches!(
            store
                .lookup_commit_operation(handle, DIGEST_PRINCIPAL)
                .await
                .expect("original authenticated recovery handle"),
            crate::consensus::ConfigCommitRecoveryOutcome::Committed
        ));
    }
}

async fn digest_fixture(rows: usize, retain: bool) -> DigestFixture {
    use crate::consensus::ConsensusConfigStore;
    use crate::ConfigStore;
    assert!(rows == 0 || rows == 3);
    assert!(!retain || rows == 3);
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-history-digest-")
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
    let node = ConsensusNodeId::new(1).expect("node");
    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xE8; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xE9; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology = ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
        .expect("singleton");
    let options = RetainedConfigOptions::new(
        root.path().join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0xEA; 32], [0xEB; 32])
            .expect("binding")
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("unchanged retained limits");
    let key = AuditKey::new_with_epoch([0xEC; 32], 7).expect("synthetic history key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("explicit bounded authority");
    let store = ConsensusConfigStore::open(
        topology.clone(),
        backend.clone(),
        root.path().join("snapshots"),
        std::collections::BTreeMap::new(),
    )
    .await
    .expect("native bounded store");
    store
        .initialize_cluster()
        .await
        .expect("natural singleton initialization");
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    assert!(store
        .load_latest()
        .await
        .expect("original public read deadline")
        .is_none());
    let provider = digest_provider();
    let mut expected = Vec::new();
    let mut handles = Vec::new();
    for (index, logical_bytes) in [65_537, 98_306, 131_075].into_iter().take(rows).enumerate() {
        let version = u64::try_from(index + 1).expect("fixture version");
        let reservation = store
            .try_reserve_config_preparation()
            .expect("destination admission")
            .expect("real bounded preparation reservation");
        let mut plaintext = vec![b'q'; logical_bytes];
        plaintext[0] = b'"';
        plaintext[logical_bytes - 1] = b'"';
        let encrypted = opc_crypto::encrypt_reserved_bounded_config_envelope(
            reservation,
            &provider,
            &digest_aad(version),
            &plaintext,
        )
        .await
        .expect("genuine reserved bounded encryption");
        expected.push(DigestExpectedRecord {
            version,
            logical_bytes,
            ciphertext_bytes: encrypted.encoded().len(),
            ciphertext_digest: Sha256::digest(encrypted.encoded()).into(),
        });
        let record = crate::CommitRecord {
            tx_id: tx_id(version),
            parent_tx_id: (version > 1).then(|| tx_id(version - 1)),
            version: ConfigVersion::new(version),
            committed_at: Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time"),
            principal: DIGEST_PRINCIPAL.to_owned(),
            source: CommitSource::Gnmi,
            schema_digest: SchemaDigest::from_bytes([0xE6; 32]),
            plaintext_digest: Sha256::digest(&plaintext).to_vec(),
            encrypted_blob: encrypted.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        };
        let commit = crate::AttestedConfigCommit::try_new(
            record,
            Vec::new(),
            encrypted.claim().expect("one-shot claim"),
        )
        .expect("paired bounded record");
        drop(encrypted);
        let operation = store
            .prepare_recoverable_commit(
                opc_consensus::ConsensusRequestId::new(),
                commit,
                DIGEST_PRINCIPAL,
            )
            .expect("prepare once");
        handles.push(operation.recovery_handle().clone());
        store
            .append_prepared_commit(operation)
            .await
            .expect("native durable append");
    }
    verify_digest_native(&store, &expected, &handles).await;
    if retain {
        let retention = ConfigHistoryRetention::new(
            tx_id(3),
            ConfigVersion::new(3),
            ConfigVersion::new(1),
            ConfigVersion::new(2),
            ConfigHistoryLimits::new(2, 2 * 1024 * 1024).expect("bounded retained pair"),
        )
        .expect("acknowledged retention");
        store
            .retain_history_idempotent(opc_consensus::ConsensusRequestId::new(), retention)
            .await
            .expect("real native retention command");
        verify_digest_native(&store, &expected, &handles).await;
    }
    store.shutdown().await.expect("join original native owners");
    drop(store);
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert!(crate::schema::verify_wal_mode(&conn).expect("actual WAL"));
        assert!(crate::schema::verify_synchronous_extra(&conn).expect("actual durable mode"));
    }
    DigestFixture {
        root,
        backend,
        options,
        topology,
        key,
        expected,
        handles,
        has_boundary: retain,
    }
}

fn digest_access(conn: &Connection, fixture: &DigestFixture) -> io::Result<()> {
    assert!(
        !conn.is_autocommit(),
        "observation consumes the pinned SQL transaction"
    );
    super::super::history::validate_access_for_profile_sync(
        conn,
        &fixture.key,
        true,
        Some(fixture.topology.identity()),
        RetainedConfigMode::try_from(ConfigCapacityProfile::BoundedV1).expect("bounded mode"),
        &SqliteWorkCancellation::new(),
    )
}

fn digest_input(conn: &Connection, fixture: &DigestFixture) -> DigestInput {
    // Expected work comes from actual row borrows, independently compared with
    // the ciphertext encrypted before submission. No observer total is reused.
    let mut result = DigestInput::default();
    let mut statement = conn
        .prepare("SELECT version, encrypted_blob FROM config_history ORDER BY version ASC")
        .expect("independent retained input");
    let mut rows = statement.query([]).expect("actual retained rows");
    while let Some(row) = rows.next().expect("actual row") {
        let version: u64 = row.get(0).expect("positive version");
        let ciphertext = row
            .get_ref(1)
            .expect("borrowed ciphertext")
            .as_blob()
            .expect("actual blob");
        let expected = fixture
            .expected
            .iter()
            .find(|record| record.version == version)
            .expect("original encrypted record");
        assert_eq!(ciphertext.len(), expected.ciphertext_bytes);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(ciphertext)),
            expected.ciphertext_digest
        );
        if result.rows == 0 && fixture.has_boundary {
            result.boundary_bytes = ciphertext.len();
        }
        result.rows += 1;
        result.bytes += ciphertext.len();
        result.head_bytes = ciphertext.len();
    }
    assert_eq!(
        result.rows,
        fixture.expected.len() - usize::from(fixture.has_boundary)
    );
    result
}

fn sample_digest_access(conn: &Connection, fixture: &DigestFixture) -> (Sample, DigestInput) {
    let input = digest_input(conn, fixture);
    let observation = Observation::start();
    digest_access(conn, fixture).expect("all original history checks");
    (observation.finish(), input)
}

fn assert_digest_work(sample: Sample, input: DigestInput) {
    use crate::consensus::history::config_capacity_read_buffers::CiphertextHashSite;
    let head = CiphertextHashSite::Head as usize;
    let chain = CiphertextHashSite::Chain as usize;
    let capacity = CiphertextHashSite::Capacity as usize;
    let boundary = CiphertextHashSite::Boundary as usize;
    assert_eq!(
        sample.completed_checks,
        [input.rows, input.rows, input.rows, input.rows, 1],
        "every capacity MAC, anchor, metadata, chain extension and final comparison must complete"
    );
    assert_eq!(
        sample.ciphertext_hash_calls[head],
        usize::from(input.rows != 0)
    );
    assert_eq!(sample.ciphertext_hash_bytes[head], input.head_bytes);
    assert_eq!(
        sample.ciphertext_hash_calls[boundary],
        usize::from(input.boundary_bytes != 0)
    );
    assert_eq!(sample.ciphertext_hash_bytes[boundary], input.boundary_bytes);
    assert_eq!(
        sample.peak_owned_ciphertext, 0,
        "no ciphertext clone in authentication"
    );
    let actual_calls = sample.ciphertext_hash_calls[chain] + sample.ciphertext_hash_calls[capacity];
    let actual_bytes = sample.ciphertext_hash_bytes[chain] + sample.ciphertext_hash_bytes[capacity];
    println!("HISTORY_CIPHERTEXT_DIGEST_WORK rows={} bytes={} actual_calls={actual_calls} actual_bytes={actual_bytes} completed={:?}", input.rows, input.bytes, sample.completed_checks);
    assert_eq!((actual_calls, actual_bytes), (input.rows, input.bytes),
        "HISTORY_CIPHERTEXT_DIGEST_REUSE: one real raw SHA per retained row after all checks and native reopen");
}

async fn reopen_digest_fixture(mut fixture: DigestFixture) -> (Sample, DigestInput) {
    use crate::consensus::ConsensusConfigStore;
    drop(fixture.backend);
    fixture.backend =
        SqliteBackend::reopen_config_authority(fixture.options.clone(), fixture.key.clone())
            .await
            .expect("fresh retained reopen");
    let store = ConsensusConfigStore::open(
        fixture.topology.clone(),
        fixture.backend.clone(),
        fixture.root.path().join("snapshots"),
        std::collections::BTreeMap::new(),
    )
    .await
    .expect("fresh native engine");
    store
        .initialize_cluster()
        .await
        .expect("natural reopened membership");
    verify_digest_native(&store, &fixture.expected, &fixture.handles).await;
    store.shutdown().await.expect("join reopened native owners");
    drop(store);
    let sample = {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tx = conn
            .unchecked_transaction()
            .expect("pinned reopened validation");
        let sample = sample_digest_access(&tx, &fixture);
        tx.commit().expect("finish reopened validation");
        sample
    };
    // Close SQLite before the private temporary directory removes its files.
    drop(fixture.backend);
    drop(fixture.root);
    sample
}

fn assert_digest_restored(conn: &Connection, fixture: &DigestFixture) {
    let tx = conn
        .unchecked_transaction()
        .expect("fresh transaction after rollback");
    digest_access(&tx, fixture).expect("exact original authenticated history restored");
    let _ = digest_input(&tx, fixture);
    tx.commit().expect("finish restoration control");
}

fn resign_digest_test_state(
    conn: &Connection,
    key: &AuditKey,
    change: impl FnOnce(&mut serde_json::Value),
) {
    use hmac::{KeyInit, Mac};
    // Deliberately signed corrupt state, using only this fixture's synthetic
    // key. Production callers cannot use this helper to bless row corruption.
    let encoded: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_history_retention WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("original authenticated state");
    let mut state: serde_json::Value = serde_json::from_slice(&encoded).expect("history JSON");
    change(&mut state);
    let encoded = serde_json::to_vec(&state).expect("changed synthetic state");
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("synthetic history key");
    mac.update(b"openpacketcore/config-consensus/history-retention/v1\0");
    mac.update(&encoded);
    let tag = mac.finalize().into_bytes();
    assert_eq!(conn.execute(
        "UPDATE config_raft_history_retention SET state_json = ?1, state_hmac = ?2 WHERE singleton = 1",
        params![encoded, tag.as_slice()],
    ).expect("signed negative fixture"), 1);
}

fn flip_digest_json_byte(value: &mut serde_json::Value) {
    let bytes = value.as_array_mut().expect("fixed digest array");
    assert_eq!(bytes.len(), 32);
    bytes[0] = serde_json::Value::from(bytes[0].as_u64().expect("byte") ^ 1);
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_reuses_raw_hash_after_reopen() {
    let fixture = digest_fixture(3, false).await;
    let first = {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tx = conn
            .unchecked_transaction()
            .expect("pinned original validation");
        let result = sample_digest_access(&tx, &fixture);
        tx.commit().expect("finish original validation");
        result
    };
    let reopened = reopen_digest_fixture(fixture).await;
    // The red/control cost assertion follows readback, recovery and both joins.
    assert_digest_work(first.0, first.1);
    assert_digest_work(reopened.0, reopened.1);
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_empty_history_checks_orphans() {
    let fixture = digest_fixture(0, false).await;
    let first = {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tx = conn.unchecked_transaction().expect("pinned empty access");
        let first = sample_digest_access(&tx, &fixture);
        tx.rollback().expect("finish empty access");
        let tx = conn.unchecked_transaction().expect("isolated orphan");
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")
            .expect("test-only deferred foreign key");
        tx.execute(
            "INSERT INTO config_raft_capacity_records (tx_id, binding) VALUES (?1, ?2)",
            params![
                tx_id(99).as_uuid().as_bytes().as_slice(),
                [0_u8; 44].as_slice()
            ],
        )
        .expect("actual orphan fixture");
        assert!(
            digest_access(&tx, &fixture).is_err(),
            "empty history must still reject orphan proofs"
        );
        tx.rollback().expect("remove orphan");
        assert_digest_restored(&conn, &fixture);
        first
    };
    let reopened = reopen_digest_fixture(fixture).await;
    assert_digest_work(first.0, first.1);
    assert_digest_work(reopened.0, reopened.1);
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_rejects_authenticated_head_and_chain_changes(
) {
    let fixture = digest_fixture(3, false).await;
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        for head in [true, false] {
            let tx = conn.unchecked_transaction().expect("isolated signed state");
            resign_digest_test_state(&tx, &fixture.key, |state| {
                if head {
                    flip_digest_json_byte(&mut state["head"]["encrypted_digest"]);
                } else {
                    flip_digest_json_byte(&mut state["record_chain"]);
                }
            });
            assert!(
                digest_access(&tx, &fixture).is_err(),
                "valid state MAC never excuses a wrong head or chain digest"
            );
            tx.rollback().expect("restore exact state");
            assert_digest_restored(&conn, &fixture);
        }
    }
    let _ = reopen_digest_fixture(fixture).await;
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_checks_inner_proof_after_outer_rebind() {
    let fixture = digest_fixture(3, false).await;
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tx = conn
            .unchecked_transaction()
            .expect("isolated inner proof corruption");
        let mut binding: Vec<u8> = tx
            .query_row(
                "SELECT binding FROM config_raft_capacity_records WHERE tx_id = ?1",
                [tx_id(2).as_uuid().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("fixed original proof");
        assert_eq!(binding.len(), 44);
        binding[43] ^= 1;
        tx.execute(
            "UPDATE config_raft_capacity_records SET binding = ?1 WHERE tx_id = ?2",
            params![binding, tx_id(2).as_uuid().as_bytes().as_slice()],
        )
        .expect("invalid inner tag");
        // Rebind only the OUTER chain with the test key. Chain validation alone
        // must pass, so it cannot mask a removed per-row capacity-MAC check.
        super::super::history::refresh_sync(
            &tx,
            &fixture.key,
            true,
            &SqliteWorkCancellation::new(),
        )
        .expect("test-only outer rebind")
        .expect("unchanged retained bounds");
        super::super::history::validate_record_chain_sync(
            &tx,
            &fixture.key,
            &SqliteWorkCancellation::new(),
        )
        .expect("outer chain independently authenticates this negative fixture");
        let observation = Observation::start();
        assert!(
            digest_access(&tx, &fixture).is_err(),
            "capacity MAC remains independently required"
        );
        let sample = observation.finish();
        assert_eq!(
            sample.completed_checks[0], 1,
            "the first row verified, the corrupt middle proof did not"
        );
        tx.rollback()
            .expect("restore original proof and outer state");
        assert_digest_restored(&conn, &fixture);
    }
    let _ = reopen_digest_fixture(fixture).await;
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_rechecks_ciphertext_and_metadata() {
    let fixture = digest_fixture(3, false).await;
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        // All controls follow successful validation of these exact rows. A
        // saved digest or a head-only check must not authorize a later change.
        assert_digest_restored(&conn, &fixture);
        let tx = conn
            .unchecked_transaction()
            .expect("later ciphertext mutation");
        let last: u8 = tx
            .query_row(
                "SELECT encrypted_blob FROM config_history WHERE version = 2",
                [],
                |row| {
                    let value = row.get_ref(0)?;
                    let bytes = value.as_blob().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok(*bytes.last().expect("nonempty real ciphertext"))
                },
            )
            .expect("actual tag byte");
        tx.execute("UPDATE config_history SET encrypted_blob = CAST(substr(encrypted_blob, 1, length(encrypted_blob) - 1) || ?1 AS BLOB) WHERE version = 2", [[last ^ 1].as_slice()])
            .expect("one actual changed ciphertext byte");
        assert!(
            digest_access(&tx, &fixture).is_err(),
            "previous validation is not a cache authority"
        );
        tx.rollback().expect("restore ciphertext");
        assert_digest_restored(&conn, &fixture);
        for sql in [
            "UPDATE config_history SET rollback_point = 1 WHERE version = 2",
            "UPDATE config_history SET audit_count = 1 WHERE version = 2",
            "INSERT INTO rollback_labels (label, tx_id, created_at) SELECT 'synthetic-label', tx_id, committed_at FROM config_history WHERE version = 2",
            "INSERT INTO config_lifecycle_audit (tx_id, action, principal, occurred_at, details) SELECT tx_id, 'confirm', principal, committed_at, '{}' FROM config_history WHERE version = 2",
        ] {
            let tx = conn.unchecked_transaction().expect("later reference mutation");
            assert_eq!(tx.execute(sql, []).expect("actual metadata mutation"), 1);
            assert!(digest_access(&tx, &fixture).is_err(), "old metadata and audit anchors remain chained");
            tx.rollback().expect("restore metadata");
            assert_digest_restored(&conn, &fixture);
        }
    }
    let _ = reopen_digest_fixture(fixture).await;
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_preserves_retention_boundary() {
    let fixture = digest_fixture(3, true).await;
    let first = {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tx = conn
            .unchecked_transaction()
            .expect("pinned retained boundary");
        let first = sample_digest_access(&tx, &fixture);
        let parent = super::super::history::original_parent_sync(
            &tx,
            &fixture.key,
            tx_id(2).as_uuid().as_bytes(),
            2,
            None,
        )
        .expect("original AEAD parent");
        assert_eq!(
            parent.as_deref(),
            Some(tx_id(1).as_uuid().as_bytes().as_slice())
        );
        tx.commit().expect("finish boundary check");
        for digest in [true, false] {
            let tx = conn.unchecked_transaction().expect("signed wrong boundary");
            resign_digest_test_state(&tx, &fixture.key, |state| {
                if digest {
                    flip_digest_json_byte(&mut state["boundary"]["first"]["encrypted_digest"]);
                } else {
                    state["boundary"]["original_parent"] =
                        serde_json::to_value(tx_id(99)).expect("wrong original parent");
                }
            });
            assert!(
                digest_access(&tx, &fixture).is_err(),
                "boundary remains independently bound to actual ciphertext and AAD"
            );
            tx.rollback().expect("restore boundary state");
            assert_digest_restored(&conn, &fixture);
        }
        for length in [0_usize, 15, 16, 17] {
            let tx = conn
                .unchecked_transaction()
                .expect("invalid detached SQL parent");
            tx.execute_batch("PRAGMA defer_foreign_keys = ON")
                .expect("test-only deferred parent");
            tx.execute(
                "UPDATE config_history SET parent_tx_id = zeroblob(?1) WHERE version = 2",
                [i64::try_from(length).expect("length")],
            )
            .expect("replace actual SQL parent");
            assert!(
                digest_access(&tx, &fixture).is_err(),
                "the pruned SQL parent must remain null with exact scalar shape"
            );
            tx.rollback().expect("restore null parent");
            assert_digest_restored(&conn, &fixture);
        }
        first
    };
    let reopened = reopen_digest_fixture(fixture).await;
    assert_digest_work(first.0, first.1);
    assert_digest_work(reopened.0, reopened.1);
}

#[tokio::test]
async fn config_capacity_957_history_ciphertext_digest_preserves_scope_missing_proof_and_cancellation(
) {
    let fixture = digest_fixture(3, false).await;
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tx = conn
            .unchecked_transaction()
            .expect("scope controls share actual immutable bytes");
        let mode =
            RetainedConfigMode::try_from(ConfigCapacityProfile::BoundedV1).expect("bounded mode");
        for key in [
            AuditKey::new_with_epoch([0xED; 32], 7).expect("wrong material"),
            AuditKey::new_with_epoch([0xEC; 32], 8).expect("wrong key epoch"),
        ] {
            assert!(super::super::history::validate_access_for_profile_sync(
                &tx,
                &key,
                true,
                Some(fixture.topology.identity()),
                mode,
                &SqliteWorkCancellation::new(),
            )
            .is_err());
        }
        let other = ConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xE8; 32]),
            ConfigConsensusConfigurationId::from_bytes([0xE9; 32]),
            ConfigConsensusConfigurationEpoch::new(2).expect("other admitted epoch"),
        );
        assert!(super::super::history::validate_access_for_profile_sync(
            &tx,
            &fixture.key,
            true,
            Some(other),
            mode,
            &SqliteWorkCancellation::new(),
        )
        .is_err());
        assert!(super::super::history::validate_access_for_profile_sync(
            &tx,
            &fixture.key,
            true,
            Some(fixture.topology.identity()),
            RetainedConfigMode::Legacy,
            &SqliteWorkCancellation::new(),
        )
        .is_err());
        let cancellation = SqliteWorkCancellation::new();
        assert!(
            cancellation.cancel_before_commit(),
            "cancel before history use"
        );
        assert!(
            super::super::history::validate_access_for_profile_sync(
                &tx,
                &fixture.key,
                true,
                Some(fixture.topology.identity()),
                mode,
                &cancellation,
            )
            .is_err(),
            "digest reuse cannot authorize cancelled work"
        );
        tx.rollback().expect("finish unchanged scope controls");
        for sql in [
            "DELETE FROM config_raft_capacity_records WHERE tx_id = (SELECT tx_id FROM config_history WHERE version = 2)",
            "INSERT INTO config_raft_capacity_records (tx_id, binding) SELECT zeroblob(16), binding FROM config_raft_capacity_records LIMIT 1",
        ] {
            let tx = conn.unchecked_transaction().expect("proof set corruption");
            tx.execute_batch("PRAGMA defer_foreign_keys = ON").expect("test-only deferred orphan");
            assert_eq!(tx.execute(sql, []).expect("actual proof set mutation"), 1);
            assert!(digest_access(&tx, &fixture).is_err(), "missing and orphan proofs remain rejected");
            tx.rollback().expect("restore proof set");
            assert_digest_restored(&conn, &fixture);
        }
    }
    let _ = reopen_digest_fixture(fixture).await;
}
