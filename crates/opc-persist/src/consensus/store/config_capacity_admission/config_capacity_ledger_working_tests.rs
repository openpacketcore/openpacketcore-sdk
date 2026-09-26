//! Necessary simultaneous-owner evidence from a real accepted SQL apply.
//!
//! The fixture uses genuine encryption, preparation, command admission, ledger
//! transitions, canonical retained encoding, and the production apply function.
//! In-memory SQL is intentional: this measures SDK owners, not native WAL,
//! transport, allocator/RSS, parser scratch, or the complete operation peak.

use std::collections::BTreeSet;
use std::io::Write;
use std::mem::size_of;
use std::time::{Duration, Instant};

use super::*;
use crate::audit_authority::ledger::{HandleBody, LedgerState};
use crate::audit_authority::{
    AuditLedgerLimits, AuditOperationBinding, AuditOperationHandle, AuditOperationState,
    AuditPrivacyKey, AuditPrivacyProjection, AuditPrivacyPurpose, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{
    AuditedConfigCommand, AuditedConfigEffect, AuditedMutationFields,
};
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::config_capacity_simultaneous_working_tests::ledger::{
    ObservationGuard, Sample,
};
use crate::consensus::preparation::PreparationOwnership;
use crate::consensus::sqlite::{self, SqliteWorkCancellation};
use crate::consensus::{
    ConfigConsensusCommand, ConfigConsensusResponse, ConfigConsensusTopology, ConfigRaftTypeConfig,
    PreparedAuditedMutation, PreparedConfigCommit,
};
use crate::{
    AttestedConfigCommit, AuditKey, AuditRecord, CommitRecord, CommitSource, SqliteBackend,
};
use opc_consensus::engine::{Entry, EntryPayload, Membership};
use opc_consensus::{ConsensusIdentity, ConsensusRequestId};
use opc_crypto::{AuthenticatedEnvelope, ConfigPreparationPool};
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const OPERATION_BYTES: usize = 33_554_432;
const METADATA_BYTES: usize = 196_608;
const ENVELOPE_BYTES: usize = 1_704_492;

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0x91; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x92; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    )
}

fn key() -> AuditKey {
    AuditKey::new([0x93; 32]).expect("synthetic audit key")
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x94; 32]).expect("synthetic privacy key")
}

fn logical_time() -> Timestamp {
    "1970-01-01T00:01:40Z"
        .parse()
        .expect("synthetic apply time")
}

fn handle(number: u64, mutation: Option<[u8; 32]>) -> AuditOperationHandle {
    let mut request = [0x95; 16];
    request[..8].copy_from_slice(&number.to_be_bytes());
    let event = crate::ManagementAuditEventRecord::try_new(
        request,
        crate::ManagementAuditInstant::try_new(
            100,
            999_999_999,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic event time"),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:configuration"],
        Some("synthetic-allocation-control"),
    )
    .expect("bounded synthetic event");
    let event =
        ProjectedAuditEvent::project(&privacy(), &event).expect("actual privacy projection");
    let digest = mutation.unwrap_or([0x96; 32]);
    let binding = AuditOperationBinding::project(&privacy(), &event, 0, &digest)
        .expect("actual operation binding");
    AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: request,
            key_epoch: key().epoch(),
            mutation,
        },
        &key(),
    )
    .expect("authenticated original operation")
}

fn mutation(
    commit: PreparedConfigCommit,
    binding: CapacityRecordBinding,
    pool: &ConfigPreparationPool,
) -> PreparedAuditedMutation {
    let evidence = binding
        .recover(&commit.record, identity(), &key(), PROFILE)
        .expect("genuine retained plaintext evidence");
    let effect = AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    };
    let digest = effect
        .digest(&key())
        .expect("canonical effect authentication");
    let prepared = PreparedAuditedMutation::new(
        handle(1023, Some(digest)),
        effect,
        Some(PreparationOwnership::recovered(
            pool.try_reserve().expect("real preparation reservation"),
            evidence,
        )),
    );
    prepared
        .command()
        .verify_effect(&key())
        .expect("original effect authentication");
    prepared
}

fn command(prepared: &PreparedAuditedMutation) -> ConfigConsensusCommand {
    ConfigConsensusCommand {
        schema_version: 8,
        identity: identity(),
        request_id: ConsensusRequestId::from_bytes([0x97; 16]),
        logical_time: logical_time(),
        intent: ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
    }
}

fn probe(value: &ConfigConsensusCommand) -> ConfigConsensusCommandSizeProbe<'_> {
    ConfigConsensusCommandSizeProbe {
        schema_version: value.schema_version,
        identity: value.identity,
        request_id: value.request_id,
        // Use the same conservative time as real store preflight.
        logical_time: super::super::maximum_encoded_config_timestamp()
            .expect("maximum encoded timestamp"),
        intent: &value.intent,
    }
}

fn maximum_parts() -> (
    PreparedConfigCommit,
    CapacityRecordBinding,
    AuthenticatedEnvelope,
) {
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0x9800));
    let principal_prefix =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/";
    let principal = format!(
        "{principal_prefix}{}",
        "p".repeat(16_384 - principal_prefix.len())
    );
    let schema_digest = SchemaDigest::from_bytes([0x99; 32]);
    let encryption_key = KeyHandle::new(
        KeyId::new("k".repeat(512)).expect("maximum key identifier"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0x9A; 32]),
    );
    let make_aad = |store: &str| {
        EnvelopeAad::config(
            TenantId::from_static("test"),
            1,
            ConfigAad::new(
                tx_id,
                None,
                logical_time(),
                &principal,
                schema_digest,
                store,
            )
            .expect("real configuration metadata"),
        )
    };
    let mut store = String::from("synthetic-\"\\é-");
    let aad_bytes = opc_key::serialize_bound_aad(&make_aad(&store), encryption_key.key_id())
        .expect("canonical base AAD")
        .len();
    store.extend(std::iter::repeat_n('s', 65_536 - aad_bytes));
    let aad = make_aad(&store);
    assert_eq!(
        opc_key::serialize_bound_aad(&aad, encryption_key.key_id())
            .expect("maximum AAD")
            .len(),
        65_536
    );
    let mut plaintext = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    plaintext.extend(std::iter::repeat_n(b'x', 1_572_864 - 2));
    plaintext.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    plaintext.resize(1_572_864 + 65_536 - 2, b'r');
    plaintext.extend_from_slice(b"\"}");
    assert_eq!(plaintext.len(), 1_638_400);
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &encryption_key,
        &aad,
        &plaintext,
        [0x9B; 12],
    )
    .expect("genuine at-limit bounded encryption");
    assert_eq!(envelope.encoded().len(), ENVELOPE_BYTES);
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&encryption_key, &aad, envelope.encoded())
            .expect("authenticated at-limit plaintext")
            .as_slice(),
        plaintext
    );
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: logical_time(),
        principal,
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let audit = (0..22)
        .map(|sequence| AuditRecord {
            tx_id,
            sequence,
            yang_path: format!(
                "/fixture:{}",
                "x".repeat(if sequence == 21 { 128 } else { 8192 } - 9)
            ),
            op_type: crate::types::AuditOpType::Update,
            previous_value: Some("synthetic-before".to_owned()),
            new_value: Some("synthetic-after".to_owned()),
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        })
        .collect();
    let attested = AttestedConfigCommit::try_new(
        record,
        audit,
        envelope
            .claim()
            .expect("original one-shot encryption claim"),
    )
    .expect("genuine plaintext attestation");
    let evidence = attested.capacity_evidence().expect("bounded evidence");
    assert_eq!(evidence.logical_bytes(), 1_572_864);
    assert_eq!(evidence.replay_bytes(), 65_536);
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE)
        .expect("exact retained record proof");
    let (record, audit, _) = attested.into_parts();
    let commit = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE)
        .expect("real synchronous bounded preparation");
    (commit, binding, envelope)
}

fn maximize_metadata(
    commit: PreparedConfigCommit,
    binding: CapacityRecordBinding,
    pool: &ConfigPreparationPool,
) -> PreparedConfigCommit {
    let baseline = mutation(commit, binding, pool);
    let value = command(&baseline);
    let bytes = config_command_encoded_size(&probe(&value)).expect("actual command codec");
    let additional = METADATA_BYTES
        .checked_sub(bytes - ENVELOPE_BYTES)
        .expect("metadata room with maximum envelope");
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &baseline.command().effect else {
        panic!("bounded append fixture");
    };
    let mut commit = (**commit).clone();
    drop(value);
    drop(baseline);
    let path = &mut commit.audit.last_mut().expect("last path").yang_path;
    let length = path.len() + additional;
    assert!((128..=8192).contains(&length));
    *path = format!("/fixture:{}", "x".repeat(length - 9));
    PreparedConfigCommit::prepare_for_profile(commit.record, commit.audit, &key(), PROFILE)
        .expect("final audit after exact metadata adjustment")
}

fn ledger(prepared: &PreparedAuditedMutation) -> LedgerState {
    let mut ledger = LedgerState::new(
        identity(),
        privacy()
            .project(AuditPrivacyPurpose::KeyIdentity, &[])
            .expect("projection identity"),
        AuditLedgerLimits::new(4096, 1024).expect("existing admitted limits"),
    );
    // Reach the operation ceiling through authenticated transitions. The final
    // slot is the actual submitted effect. No forged JSON, padding, or direct
    // history-vector growth is used to approach the byte ceiling.
    for number in 0..1023 {
        let handle = handle(number, None);
        ledger.admit(&key(), &handle, 100).expect("real Intent");
        ledger
            .resolve(&key(), &handle, AuditOperationState::Rejected)
            .expect("real rejection");
        ledger
            .acknowledge_terminal(&key(), &handle)
            .expect("real terminal");
    }
    ledger
        .admit(&key(), prepared.handle(), 100)
        .expect("original mutation Intent");
    ledger
        .validate(&key(), identity())
        .expect("authenticated reachable ledger");
    assert_eq!(ledger.entries.len(), 3070);
    assert_eq!(ledger.operations.len(), 1024);
    ledger
}

fn initialize() -> (Connection, ConfigConsensusTopology) {
    let mut conn = Connection::open_in_memory().expect("component SQL fixture");
    let transaction = conn.transaction().expect("schema transaction");
    crate::schema::initialize_schema(&transaction).expect("real base schema");
    transaction.commit().expect("base schema commit");
    let node = ConsensusNodeId::new(1).expect("synthetic node");
    let topology = ConfigConsensusTopology::try_new(identity(), node, BTreeSet::from([node]))
        .expect("component topology");
    sqlite::provision_retained_schema(
        &conn,
        &topology,
        &key(),
        PROFILE,
        Instant::now() + Duration::from_secs(10),
    )
    .expect("real profile schema and authenticated empty state");
    let membership = Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, node), 0),
        payload: EntryPayload::Membership(Membership::new(
            vec![topology.members().clone()],
            topology.members().clone(),
        )),
    };
    append_committed(&conn, &topology, &membership);
    assert!(apply(&conn, &topology, vec![membership]).result.is_ok());
    (conn, topology)
}

fn append_committed(
    conn: &Connection,
    topology: &ConfigConsensusTopology,
    entry: &Entry<ConfigRaftTypeConfig>,
) {
    sqlite::append_logs_sync(
        conn,
        identity(),
        topology.members(),
        std::slice::from_ref(entry),
        PROFILE,
    )
    .expect("actual log encoder and SQL append");
    sqlite::save_committed_sync(conn, identity(), Some(entry.log_id), PROFILE)
        .expect("real committed prefix");
}

fn apply(
    conn: &Connection,
    topology: &ConfigConsensusTopology,
    entries: Vec<Entry<ConfigRaftTypeConfig>>,
) -> ConfigConsensusResponse {
    let mut responses = sqlite::apply_entries_cancellable_sync(
        conn,
        identity(),
        topology.members(),
        entries,
        &SqliteWorkCancellation::new_for_capacity_observation(),
        &key(),
        None,
        PROFILE,
    )
    .expect("real atomic accepted apply");
    assert_eq!(responses.len(), 1);
    responses.pop().expect("one response")
}

fn command_heap(command: &AuditedConfigCommand) -> usize {
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &command.effect else {
        panic!("bounded fixture");
    };
    // Count each distinct real Arc payload once. The effect's execution copy
    // does not exist at the measured nested validation checkpoint. Arc headers
    // and allocator rounding are omitted.
    size_of::<AuditedMutationFields>()
        + size_of::<PreparedConfigCommit>()
        + commit.record.encrypted_blob.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.record.principal.capacity()
        + commit.audit.capacity() * size_of::<AuditRecord>()
        + commit
            .audit
            .iter()
            .map(|entry| {
                entry.yang_path.capacity()
                    + entry.previous_value.as_ref().map_or(0, String::capacity)
                    + entry.new_value.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}

fn simultaneous_apply(expanded: bool) {
    let pool = ConfigPreparationPool::bounded_v1();
    let (commit, binding, envelope) = maximum_parts();
    let mut commit = maximize_metadata(commit, binding, &pool);
    if expanded {
        // Keep every authenticated byte unchanged; spare Vec capacity is a
        // real admitted input owner and must not be replaced by its length.
        commit
            .record
            .encrypted_blob
            .reserve_exact(14 * 1024 * 1024 - commit.record.encrypted_blob.len());
        commit =
            PreparedConfigCommit::prepare_for_profile(commit.record, commit.audit, &key(), PROFILE)
                .expect("expanded owner passes actual early preparation admission");
    }
    let prepared = mutation(commit, binding, &pool);
    if expanded {
        let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.command().effect else {
            panic!("bounded fixture");
        };
        assert!(commit.record.encrypted_blob.capacity() >= 14 * 1024 * 1024);
        assert_eq!(commit.record.encrypted_blob.len(), ENVELOPE_BYTES);
    }
    let value = command(&prepared);
    let sizes =
        preflight(&probe(&value), PROFILE).expect("actual command working and encoding admission");
    assert_eq!(sizes.command - ENVELOPE_BYTES, METADATA_BYTES);
    let applied_metadata =
        config_command_encoded_size(&value).expect("actual applied command size") - ENVELOPE_BYTES;
    assert!(applied_metadata <= METADATA_BYTES);
    super::super::preflight_config_command_replication_budget(
        identity(),
        value.request_id,
        &value.intent,
        PROFILE,
    )
    .expect("same public store preflight");
    value
        .validate_for_profile(identity(), &key(), PROFILE)
        .expect("real received command admission");
    let submission = prepared
        .begin_submission(&pool, PROFILE)
        .expect("real submission ownership");
    assert!(submission.is_some());
    let recovery = prepared
        .encode()
        .expect("actual reserved SDK recovery encoder");
    assert_eq!(recovery.len(), sizes.recovery_json);
    let decoded: PreparedAuditedMutation =
        serde_json::from_slice(&recovery).expect("actual recovery decode");
    assert!(
        decoded == prepared,
        "recovery bytes retain the exact authenticated effect"
    );
    drop(decoded);
    let (conn, topology) = initialize();
    crate::consensus::audit::write_sync(&conn, &key(), identity(), Some(ledger(&prepared)), false)
        .expect("actual canonical authenticated retained state");
    let entry = Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, topology.local_node_id()), 1),
        payload: EntryPayload::Normal(value),
    };
    append_committed(&conn, &topology, &entry);
    drop(entry);
    let entries = sqlite::read_log_range_sync(
        &conn,
        identity(),
        topology.members(),
        1,
        Some(2),
        Some(1),
        PROFILE,
    )
    .expect("actual retained-log page decoding");
    assert_eq!(entries.len(), 1);
    let EntryPayload::Normal(logged_command) = &entries[0].payload else {
        panic!("logged mutation fixture");
    };
    let ConfigMutationIntent::AuditedMutation(page) = &logged_command.intent else {
        panic!("logged audited fixture");
    };
    assert!(
        page == prepared.command(),
        "the decoded page retains the exact original effect"
    );
    assert!(
        !std::ptr::eq(&**prepared.command(), &**page),
        "APPLY_PAGE_OWNER: log decoding must own a distinct command, not share the original Arc"
    );
    let base = Sample {
        command: command_heap(prepared.command())
            + size_of::<PreparationOwnership>()
            + std::mem::size_of_val(submission.as_deref().expect("submission allocation")),
        apply_page: entries.capacity() * size_of::<Entry<ConfigRaftTypeConfig>>()
            + command_heap(page),
        // AuthenticatedEnvelope owns an exact Arc<[u8]>, not a Vec capacity.
        encryption_alias: envelope.encoded().len(),
        recovery: recovery.capacity(),
        ..Sample::default()
    };
    let observation = ObservationGuard::start(base);
    let response = apply(&conn, &topology, entries);
    let observation = observation.finish();
    assert!(
        response.result.is_ok(),
        "measured operation must actually commit"
    );
    let receipt = response
        .audit_receipt
        .as_ref()
        .expect("atomic audit receipt")
        .read_back(
            &key(),
            identity(),
            prepared.handle(),
            prepared.handle().body.binding.caller,
        )
        .expect("authenticate exact applied receipt");
    assert!(matches!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    ));
    let retained = crate::consensus::audit::read_sync(&conn, &key(), identity())
        .expect("authenticated retained readback")
        .expect("active ledger");
    assert!(matches!(
        retained
            .lookup(
                &key(),
                prepared.handle(),
                prepared.handle().body.binding.caller
            )
            .expect("original-handle lookup")
            .expect("retained original")
            .state(),
        AuditOperationState::Committed { version: 1 }
    ));
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.command().effect else {
        panic!("bounded fixture");
    };
    let stored =
        SqliteBackend::load_by_tx_id_bytes(&conn, commit.record.tx_id.as_uuid().as_bytes(), &key())
            .expect("actual SDK configuration readback")
            .expect("applied exact record");
    assert_eq!(stored.record, commit.record);
    assert_eq!(stored.audit, commit.audit);
    assert_eq!(
        observation.nested_reads, 1,
        "LEDGER_OVERLAP: real apply must reread while its original ledger is live"
    );
    assert!(
        observation.reads >= 3,
        "real admission, nested validation and receipt reads"
    );
    assert_eq!(
        observation.derived_len, 1024,
        "DERIVED_OWNER: actual validation reconstructs all admitted operations"
    );
    assert!(observation.derived_capacity >= observation.derived_len);
    let sample = observation.nested_peak;
    assert!(
        sample.held_ledger > 0
            && sample.apply_page > 0
            && sample.row_json > 0
            && sample.decoded_ledger > 0
            && sample.derived > 0
            && sample.authentication > 0,
        "SIMULTANEOUS_OWNERS: all required real owners overlap"
    );
    writeln!(std::io::stdout().lock(),
        "CONFIG_CAPACITY_LEDGER_APPLY expanded={expanded} preflight_metadata={} applied_metadata={applied_metadata} reads={} nested_reads={} derived_capacity={} nested={sample:?} observed_peak={:?}",
        sizes.command - ENVELOPE_BYTES, observation.reads, observation.nested_reads, observation.derived_capacity, observation.peak)
        .expect("value-free simultaneous allocation evidence");
    assert!(
        observation.peak.total <= OPERATION_BYTES,
        "LEDGER_WORKING_BOUND: actual simultaneous allocated payloads exceed 32 MiB: {:?}",
        observation.peak
    );
    // Keep these exact owners alive through the measured call; no imaginary
    // recovery/native-encoder phase sum and no duplicate shared Arc charges.
    assert_eq!(recovery.len(), sizes.recovery_json);
    assert_eq!(envelope.encoded(), commit.record.encrypted_blob);
    drop(submission);
}

#[test]
fn config_capacity_957_ledger_apply_simultaneous_maxima() {
    simultaneous_apply(false);
}

#[test]
fn config_capacity_957_ledger_apply_simultaneous_spare_capacity() {
    simultaneous_apply(true);
}
