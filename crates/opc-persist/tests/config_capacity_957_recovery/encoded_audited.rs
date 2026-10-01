//! Real BoundedV1 audited recovery from protected encoded bytes after native
//! Durable reopen. Original prepared values, envelope aliases and receipts do
//! not cross the shutdown boundary. Plain record/plaintext witnesses below are
//! test-owned comparisons, not admission owners or a complete memory proof.
//!
//! The checkpoint port stores only SDK-issued authenticated checkpoints with
//! exact compare-and-advance semantics. It is independent of the native store,
//! but is a single-process fixture, not external-service crash qualification.

use super::{counts, disk_fixture, topology, CALLER};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_crypto::{ConfigCapacityProfile, ConfigPreparationReservation};
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort, AuditContinuityPolicy,
    AuditKeyRing, AuditSigningKey,
};
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationReceipt,
    AuditOperationState, AuditPrivacyKey, PreparedAuditedMutation,
};
use opc_persist::{
    AttestedConfigCommit, AuditKey, CommitRecord, CommitSource, ConfigConsensusIdentity,
    ConfigStore, ConsensusConfigStore, ManagementAuditEventRecord, ManagementAuditInstant,
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode,
    ManagementAuditTransportCode, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LOGICAL_BYTES: usize = 1_572_864;
const PREPARATION_SLOTS: usize = 8;

#[derive(Default)]
struct Checkpoints(Mutex<Option<AuditCheckpoint>>);

impl Checkpoints {
    fn sequence(&self) -> u64 {
        self.0
            .lock()
            .expect("checkpoint fixture")
            .as_ref()
            .expect("provisioned independent checkpoint")
            .sequence()
    }
}

#[async_trait]
impl AuditCheckpointPort for Checkpoints {
    async fn load(
        &self,
        identity: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        assert_eq!(identity, topology().identity());
        Ok(self.0.lock().expect("checkpoint fixture").clone())
    }

    async fn compare_advance(
        &self,
        identity: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        assert_eq!(identity, topology().identity());
        let mut current = self.0.lock().expect("checkpoint fixture");
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(AuditCheckpointAdvance::Applied)
    }
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0xC1; 32]).expect("synthetic privacy key")
}

fn caller() -> AuditCaller {
    AuditCaller::project(&privacy(), "test", CALLER).expect("trusted fixture caller")
}

fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected actual native admission, got {other:?}"),
    }
}

async fn open(root: &Path, checkpoints: Arc<Checkpoints>, reopen: bool) -> ConsensusConfigStore {
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology(), [0xC2; 32], [0xC3; 32])
            .expect("retained identity")
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("unchanged native limits and deadline");
    let key = AuditKey::new([0xC4; 32]).expect("synthetic retained key");
    let backend = if reopen {
        SqliteBackend::reopen_config_authority(options, key).await
    } else {
        SqliteBackend::provision_config_authority(options, key).await
    }
    .expect("same retained native authority");
    let keys = AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [0xC5; 32]).expect("independent signing key")
    ])
    .expect("key ring");
    let store = ConsensusConfigStore::open_with_audit_continuity(
        topology(),
        backend,
        root.join("snapshots"),
        BTreeMap::new(),
        AuditContinuityPolicy::new(keys, checkpoints, 1, 1).expect("required continuity"),
    )
    .await
    .expect("native reopen verifies retained audit/checkpoint continuity");
    store.initialize_cluster().await.expect("singleton");
    if !reopen {
        // Required continuity readiness needs its provisioned ledger/checkpoint.
        // Reopen never reinitializes either authority.
        store
            .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).expect("limits"))
            .await
            .expect("actual native ledger and initial independent checkpoint");
    }
    store
        .probe_durable_readiness()
        .await
        .expect("real leader and initial local apply");
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    store
}

fn reserve(store: &ConsensusConfigStore, count: usize) -> Vec<ConfigPreparationReservation> {
    (0..count)
        .map(|_| {
            store
                .try_reserve_config_preparation()
                .expect("available destination slot")
                .expect("BoundedV1 requires a reservation")
        })
        .collect()
}

fn all_owners_released(store: &ConsensusConfigStore) {
    let held = reserve(store, PREPARATION_SLOTS);
    assert!(store.try_reserve_config_preparation().is_err());
    drop(held);
}

async fn input(
    store: &ConsensusConfigStore,
    provider: &MemoryKeyProvider,
) -> (AttestedConfigCommit, CommitRecord, EnvelopeAad, Vec<u8>) {
    let reservation = store
        .try_reserve_config_preparation()
        .expect("public admission")
        .expect("bounded destination slot");
    let plaintext = serde_json::to_vec(&"x".repeat(LOGICAL_BYTES - 2)).expect("logical JSON");
    assert_eq!(plaintext.len(), LOGICAL_BYTES);
    assert!(plaintext.len() > 1024 * 1024);
    let tx_id = TxId::new();
    let committed_at = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed time"),
    );
    let schema_digest = SchemaDigest::from_bytes([0xC6; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        1,
        ConfigAad::new(tx_id, None, committed_at, CALLER, schema_digest, "running").expect("AAD"),
    );
    let encrypted = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        provider,
        &aad,
        &plaintext,
    )
    .await
    .expect("real reserved encryption at the logical limit");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at,
        principal: CALLER.into(),
        source: CommitSource::LocalOperator,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: encrypted.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let expected = record.clone();
    let commit = AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        encrypted.claim().expect("one-shot authenticated claim"),
    )
    .expect("exact record attestation");
    drop(encrypted);
    (commit, expected, aad, plaintext)
}

fn event(tx_id: TxId) -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [0xC7; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .expect("event time"),
        "test",
        CALLER,
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config/fixture:value"],
        Some(tx_id.to_string()),
    )
    .expect("valid public Intent")
}

fn save(root: &Path, encoded: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("original-recovery.json"))
        .expect("private protected recovery file");
    file.write_all(encoded)
        .expect("retain actual original bytes");
    file.sync_all().expect("persist original recovery bytes");
}

fn audit_bytes(root: &Path) -> (Vec<u8>, Vec<u8>) {
    let conn = rusqlite::Connection::open_with_flags(
        root.join("config.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("independent read-only ledger observation");
    conn.query_row(
        "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("actual native ledger")
}

async fn readback(
    store: &ConsensusConfigStore,
    expected: &CommitRecord,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    provider: &MemoryKeyProvider,
) {
    let latest = store
        .load_latest()
        .await
        .expect("linearizable head")
        .expect("committed head");
    assert!(&latest.record == expected, "exact native encrypted record");
    assert!(latest.audit.is_empty());
    let decrypted = opc_crypto::decrypt_envelope(provider, aad, &latest.record.encrypted_blob)
        .await
        .expect("original historical key and exact authenticated AAD");
    assert!(
        decrypted.as_slice() == plaintext,
        "exact decrypted logical bytes"
    );
    assert_eq!(decrypted.len(), LOGICAL_BYTES);
    drop(decrypted);
    drop(latest);
    let history = store
        .load_since(ConfigVersion::new(0), 2)
        .await
        .expect("retained history");
    assert_eq!(
        history.len(),
        1,
        "recovery never manufactures a second revision"
    );
    assert!(
        &history[0].record == expected,
        "exact retained historical record"
    );
    assert!(history[0].audit.is_empty());
    drop(history);
    assert!(store
        .load_since(ConfigVersion::new(1), 2)
        .await
        .expect("history tail")
        .is_empty());
}

// Borrow the large effect unchanged while corrupting only the small handle.
// The adversarial fixture does not decode a million-element JSON Value array.
#[derive(Deserialize, Serialize)]
struct EncodedFields<'a> {
    handle: serde_json::Value,
    #[serde(borrow)]
    effect: &'a serde_json::value::RawValue,
}

fn changed_handle_mac(encoded: &[u8]) -> Vec<u8> {
    let mut fields: EncodedFields<'_> = serde_json::from_slice(encoded).expect("original framing");
    let mac = fields.handle["mac"]
        .as_array_mut()
        .expect("issued handle MAC");
    let byte = mac[0].as_u64().expect("MAC byte");
    mac[0] = serde_json::Value::from(byte ^ 1);
    serde_json::to_vec(&fields).expect("syntactically valid unauthenticated handle")
}

fn changed_ciphertext(encoded: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(encoded).expect("original encoded JSON");
    let field = "\"encrypted_blob\":[";
    let start = text.find(field).expect("actual encrypted record") + field.len();
    let end = start + text[start..].find(']').expect("ciphertext array end");
    let last = start
        + text[start..end]
            .rfind(',')
            .expect("nonempty ciphertext and tag")
        + 1;
    let byte: u8 = text[last..end]
        .parse()
        .expect("last authenticated ciphertext byte");
    let mut changed = text.to_owned();
    changed.replace_range(last..end, &(byte ^ 1).to_string());
    changed.into_bytes()
}

fn rejected_decode_releases_reservation(store: &ConsensusConfigStore, encoded: &[u8]) {
    let held = reserve(store, PREPARATION_SLOTS - 1);
    assert!(
        matches!(
            store.decode_prepared_audited_mutation(encoded),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "ENCODED_RECOVERY_DECODE_AUTHENTICATION: tampered original must fail authenticated decode"
    );
    let last = reserve(store, 1);
    assert!(store.try_reserve_config_preparation().is_err());
    drop(last);
    drop(held);
}

async fn recover_after_reopen(committed_before_reopen: bool) {
    let root = disk_fixture();
    let checkpoints = Arc::new(Checkpoints::default());
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("synthetic-encoded-recovery-key").expect("key ID"),
            KeyPurpose::Config,
            TenantId::from_static("test"),
            Zeroizing::new([0xC8; 32]),
        )
        .expect("synthetic key provider");

    // No prepared mutation, alias, receipt or in-memory handle leaves this scope.
    let (expected, aad, plaintext, original_handle, encoded_digest) = {
        let store = open(&root, Arc::clone(&checkpoints), false).await;
        assert_eq!(checkpoints.sequence(), 0);
        let (commit, expected, aad, plaintext) = input(&store, &provider).await;
        let prepared = store
            .prepare_audited_commit(
                &privacy(),
                &event(expected.tx_id),
                commit,
                Duration::from_secs(60),
            )
            .expect("usable exact at-limit prepared operation");
        let encoded = prepared
            .encode()
            .expect("original recovery bytes before Intent");
        assert!(encoded.len() > LOGICAL_BYTES && encoded.len() <= 16 * 1024 * 1024);
        let encoded_digest: [u8; 32] = Sha256::digest(&encoded).into();
        save(&root, &encoded);
        drop(encoded);
        let original_handle = prepared
            .handle()
            .encode()
            .expect("original handle byte witness");
        let intent = applied(
            store
                .admit_audit_operation_local(prepared.handle(), caller())
                .await,
        );
        assert_eq!(intent.state(), AuditOperationState::Intent);
        assert!(!intent.terminal_recorded());
        assert_eq!(checkpoints.sequence(), 0);
        if committed_before_reopen {
            let outcome = applied(
                store
                    .submit_audited_mutation_local(&prepared, &intent, caller())
                    .await,
            );
            assert_eq!(
                outcome.state(),
                AuditOperationState::Committed { version: 1 }
            );
            assert!(!outcome.terminal_recorded());
            assert_eq!(
                checkpoints.sequence(),
                1,
                "Intent is checkpointed before the native effect"
            );
            store
                .complete_required_audit_outcome(&outcome, caller())
                .await
                .expect("mandatory terminal and checkpoint");
            let terminal = store
                .lookup_audit_operation(prepared.handle(), caller())
                .await
                .expect("settled lookup")
                .expect("retained result");
            assert_eq!(
                terminal.state(),
                AuditOperationState::Committed { version: 1 }
            );
            assert!(terminal.terminal_recorded());
            assert_eq!(checkpoints.sequence(), 3);
            readback(&store, &expected, &aad, &plaintext, &provider).await;
        } else {
            // An unsubmitted Intent is not externally checkpointed. A checkpointed
            // unresolved mutation would correctly require authoritative recovery
            // before startup; this fixture must not bypass that production guard.
            assert!(store
                .load_latest()
                .await
                .expect("no submitted effect")
                .is_none());
            assert_eq!(checkpoints.sequence(), 0);
        }
        drop(prepared);
        store
            .shutdown()
            .await
            .expect("joined original native shutdown");
        all_owners_released(&store);
        drop(store);
        (expected, aad, plaintext, original_handle, encoded_digest)
    };

    let store = open(&root, Arc::clone(&checkpoints), true).await;
    let encoded = std::fs::read(root.join("original-recovery.json"))
        .expect("reload actual retained recovery bytes");
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&encoded)), encoded_digest);
    let before = counts(&root);
    let ledger_before = audit_bytes(&root);
    type EncodedTamper = fn(&[u8]) -> Vec<u8>;
    let tamper: [EncodedTamper; 2] = [changed_handle_mac, changed_ciphertext];
    for change in tamper {
        let changed = change(&encoded);
        assert!(
            changed != encoded,
            "tamper fixture changes authentic original bytes"
        );
        // Negative controls reach authentication, not malformed framing.
        drop(PreparedAuditedMutation::decode(&changed).expect("valid altered recovery DTO"));
        rejected_decode_releases_reservation(&store, &changed);
        assert_eq!(counts(&root), before);
        assert_eq!(audit_bytes(&root), ledger_before);
    }
    let held = reserve(&store, PREPARATION_SLOTS);
    assert!(matches!(
        store.decode_prepared_audited_mutation(&encoded),
        Err(AuditAuthorityError::Unavailable)
    ));
    drop(held);

    // Generic framing decode cannot manufacture the destination's reservation.
    let generic =
        PreparedAuditedMutation::decode(&encoded).expect("legacy generic framing decoder");
    let receipt = store
        .lookup_audit_operation(generic.handle(), caller())
        .await
        .expect("real exact-operation lookup")
        .expect("retained original Intent/result");
    assert!(matches!(
        store
            .submit_audited_mutation_local(&generic, &receipt, caller())
            .await,
        AuditAdmission::Rejected(AuditAuthorityError::InvalidInput)
    ));
    drop(generic);
    assert_eq!(counts(&root), before);
    assert_eq!(audit_bytes(&root), ledger_before);

    let held = reserve(&store, PREPARATION_SLOTS - 1);
    let recovered = store
        .decode_prepared_audited_mutation(&encoded)
        .expect("destination-owned authenticated recovery");
    assert!(
        store.try_reserve_config_preparation().is_err(),
        "recovered payload owns the eighth destination slot"
    );
    assert!(
        recovered.encode().expect("exact canonical recovery bytes") == encoded,
        "exact original recovery bytes"
    );
    assert_eq!(
        recovered.handle().encode().expect("same original handle"),
        original_handle
    );
    drop(held);
    let receipt = store
        .lookup_audit_operation(recovered.handle(), caller())
        .await
        .expect("fresh lookup using only decoded original handle")
        .expect("actual retained receipt");
    let wrong = AuditCaller::project(&privacy(), "other-tenant", CALLER)
        .expect("different authenticated caller");
    assert!(matches!(
        store
            .lookup_audit_operation(recovered.handle(), wrong)
            .await,
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(matches!(
        store
            .submit_audited_mutation_local(&recovered, &receipt, wrong)
            .await,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(counts(&root), before);
    assert_eq!(audit_bytes(&root), ledger_before);
    if committed_before_reopen {
        assert_eq!(
            receipt.state(),
            AuditOperationState::Committed { version: 1 }
        );
        assert!(receipt.terminal_recorded());
        assert_eq!(checkpoints.sequence(), 3);
    } else {
        assert_eq!(receipt.state(), AuditOperationState::Intent);
        assert!(!receipt.terminal_recorded());
        assert_eq!(checkpoints.sequence(), 0);
    }
    let outcome = applied(
        store
            .submit_audited_mutation_local(&recovered, &receipt, caller())
            .await,
    );
    assert_eq!(
        outcome.state(),
        AuditOperationState::Committed { version: 1 }
    );
    if committed_before_reopen {
        assert_eq!(
            outcome, receipt,
            "exact settled replay preserves its original receipt"
        );
        assert_eq!(
            counts(&root),
            before,
            "known replay never appends another proposal or history row"
        );
        assert_eq!(audit_bytes(&root), ledger_before);
    } else {
        assert!(!outcome.terminal_recorded());
        assert_eq!(checkpoints.sequence(), 1);
        store
            .complete_required_audit_outcome(&outcome, caller())
            .await
            .expect("recovered native effect's mandatory terminal/checkpoint");
    }
    let terminal = store
        .lookup_audit_operation(recovered.handle(), caller())
        .await
        .expect("terminal lookup")
        .expect("retained original result");
    assert_eq!(
        terminal.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(terminal.terminal_recorded());
    assert_eq!(
        terminal
            .handle()
            .encode()
            .expect("original terminal identity"),
        original_handle
    );
    assert_eq!(checkpoints.sequence(), 3);
    readback(&store, &expected, &aad, &plaintext, &provider).await;
    drop(recovered);
    drop(encoded);
    store
        .shutdown()
        .await
        .expect("joined recovered native shutdown");
    all_owners_released(&store);
    drop(store);

    // A further real reopen authenticates the completed terminal checkpoint and
    // resulting native state, including the effect first submitted after reopen.
    let store = open(&root, Arc::clone(&checkpoints), true).await;
    let encoded = std::fs::read(root.join("original-recovery.json")).expect("same recovery file");
    let recovered = store
        .decode_prepared_audited_mutation(&encoded)
        .expect("same original decoder after terminal reopen");
    let terminal = store
        .lookup_audit_operation(recovered.handle(), caller())
        .await
        .expect("reopened terminal lookup")
        .expect("retained result");
    assert_eq!(
        terminal.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(terminal.terminal_recorded());
    assert_eq!(
        terminal.handle().encode().expect("unchanged handle"),
        original_handle
    );
    assert_eq!(checkpoints.sequence(), 3);
    readback(&store, &expected, &aad, &plaintext, &provider).await;
    drop(recovered);
    store.shutdown().await.expect("final native shutdown");
    all_owners_released(&store);
}

#[tokio::test]
async fn config_capacity_957_encoded_audited_commit_replays_after_native_reopen() {
    recover_after_reopen(true).await;
}

#[tokio::test]
async fn config_capacity_957_encoded_audited_intent_commits_after_native_reopen() {
    recover_after_reopen(false).await;
}
