//! Actual disk-backed WAL append owners, including the encoder-local error
//! lifetime. This is component evidence, not whole-node/RSS qualification.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{
    AuditedConfigEffect, AuditedMutationFields, PreparedAuditedMutation,
};
use crate::consensus::capacity_observation::{
    AppendOwnerSample, NativeOwnerObserver, NativeOwnerSample, NativeRegistration,
    PreparationCensus,
};
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::preparation::PreparationOwnership;
use crate::consensus::{ConfigConsensusCommand, PreparedConfigCommit};
use crate::{AttestedConfigCommit, CommitRecord};
use opc_consensus::engine::CommittedLeaderId;
use opc_consensus::ConsensusRequestId;
use opc_crypto::ConfigPreparationPool;
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use std::mem::size_of;
use std::sync::{Mutex, Weak};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const MODE: RetainedConfigMode = RetainedConfigMode::BoundedV1;
const RECEIPTS: usize = 128;

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0x61; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x62; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn node() -> ConsensusNodeId {
    ConsensusNodeId::new(1).unwrap()
}

fn request() -> ConsensusRequestId {
    ConsensusRequestId::from_bytes([0x63; 16])
}

fn prepared(
    size: usize,
    pool: &ConfigPreparationPool,
) -> (PreparedAuditedMutation, Weak<PreparationOwnership>, usize) {
    let key = AuditKey::new([0x64; 32]).unwrap();
    let tx_id = TxId::new();
    let committed_at = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
    );
    let principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
    let schema_digest = SchemaDigest::from_bytes([0x65; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        1,
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .unwrap(),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("append-buffer-fixture").unwrap(),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0x66; 32]),
    );
    let mut plaintext = vec![b'x'; size];
    plaintext[0] = b'"';
    plaintext[size - 1] = b'"';
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle, &aad, &plaintext, [0x67; 12],
    )
    .unwrap();
    let attested = AttestedConfigCommit::try_new(
        CommitRecord {
            tx_id,
            parent_tx_id: None,
            version: ConfigVersion::new(1),
            committed_at,
            principal: principal.to_owned(),
            source: CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: Sha256::digest(&plaintext).to_vec(),
            encrypted_blob: envelope.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        },
        Vec::new(),
        envelope.claim().unwrap(),
    )
    .unwrap();
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key, PROFILE).unwrap();
    let (record, audit, _) = attested.into_parts();
    let mut commit = PreparedConfigCommit::prepare(record, audit, &key).unwrap();
    // Unused capacity has no serialized representation and must still count.
    commit.record.encrypted_blob.reserve_exact(4096);
    commit.record.principal.reserve_exact(2048);
    commit.audit.reserve_exact(3);
    let expected_payload = size_of::<AuditedMutationFields>()
        + size_of::<PreparedConfigCommit>()
        + commit.record.encrypted_blob.capacity()
        + commit.record.principal.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.audit.capacity() * size_of::<crate::AuditRecord>();
    let recovered = binding
        .recover(&commit.record, identity(), &key, PROFILE)
        .unwrap();
    let effect = AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    };
    let privacy = AuditPrivacyKey::new([0x68; 32]).unwrap();
    let event = crate::ManagementAuditEventRecord::try_new(
        [0x69; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        "test",
        principal,
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-append-buffers"),
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &event).unwrap();
    let digest = effect.digest(&key).unwrap();
    let binding = AuditOperationBinding::project(&privacy, &event, 6, &digest).unwrap();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0x6A; 16],
            key_epoch: key.epoch(),
            mutation: Some(digest),
        },
        &key,
    )
    .unwrap();
    let owner = PreparationOwnership::recovered(pool.try_reserve().unwrap(), recovered);
    let weak = Arc::downgrade(&owner);
    (
        PreparedAuditedMutation::new(handle, effect, Some(owner)),
        weak,
        expected_payload,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Success,
    CancelAllocated,
    CancelPartial,
    RejectAggregate,
    Unwind,
}

struct Observation {
    samples: Vec<AppendOwnerSample>,
    lost: usize,
    counter_mismatches: usize,
}

struct Observer {
    observations: Mutex<Observation>,
    census: Arc<PreparationCensus>,
    cancellation: Arc<SqliteWorkCancellation>,
    case: Case,
}

impl NativeOwnerObserver for Observer {
    fn observe(&self, _: NativeOwnerSample) {}

    fn observe_append(&self, sample: AppendOwnerSample) {
        {
            let mut receipts = self.observations.lock().unwrap();
            receipts.counter_mismatches +=
                usize::from(self.census.snapshot() != sample.preparations);
            if receipts.samples.len() < RECEIPTS {
                receipts.samples.push(sample);
            } else {
                receipts.lost += 1;
            }
        }
        if sample.completed_outputs == 1 {
            let cancel = match self.case {
                Case::CancelAllocated => sample.stage == AppendStage::JsonAllocated,
                Case::CancelPartial => sample.stage == AppendStage::JsonWriting,
                _ => false,
            };
            if cancel {
                assert!(self.cancellation.cancel_before_commit());
            }
            if self.case == Case::Unwind && sample.stage == AppendStage::JsonWriting {
                panic!("synthetic observer unwind");
            }
        }
    }
}

struct Outcome {
    receipts: Vec<AppendOwnerSample>,
    expected_payload: usize,
    json_lengths: Vec<usize>,
    result: Option<io::Result<()>>,
    rows: usize,
}

fn run(case: Case) -> Outcome {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("append.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=EXTRA;")
        .unwrap();
    assert!(crate::schema::verify_wal_mode(&conn).unwrap());
    assert!(crate::schema::verify_synchronous_extra(&conn).unwrap());
    conn.execute_batch(CONFIG_RAFT_SCHEMA).unwrap();
    let pool = ConfigPreparationPool::bounded_v1();
    let other_reservations: Vec<_> = (0..7).map(|_| pool.try_reserve().unwrap()).collect();
    let (prepared, weak, expected_payload) = prepared(
        if case == Case::RejectAggregate {
            1_572_864
        } else {
            65_536
        },
        &pool,
    );
    let alias = prepared.clone();
    assert!(pool.try_reserve().is_err());
    let command = ConfigConsensusCommand {
        schema_version: 8,
        identity: identity(),
        request_id: request(),
        logical_time: Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        ),
        intent: ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
    };
    let count = if case == Case::RejectAggregate { 13 } else { 2 };
    let entries: Vec<_> = (0..count)
        .map(|index| Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, node()), index),
            payload: EntryPayload::Normal(command.clone()),
        })
        .collect();
    drop(command);
    // Independent serialization owners are dropped before the actual append.
    let json_lengths = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().len())
        .collect::<Vec<_>>();
    let census = Arc::new(PreparationCensus::default());
    let original_owner = census.observe_audited(node(), &prepared).unwrap();
    let alias_owner = census.observe_audited(node(), &alias).unwrap();
    let cancellation = Arc::new(SqliteWorkCancellation::new());
    let observer = Arc::new(Observer {
        observations: Mutex::new(Observation {
            samples: Vec::with_capacity(RECEIPTS),
            lost: 0,
            counter_mismatches: 0,
        }),
        census: census.clone(),
        cancellation: cancellation.clone(),
        case,
    });
    let registration = NativeRegistration::new(
        &conn,
        identity(),
        node(),
        request(),
        &prepared,
        census.clone(),
        observer.clone(),
    )
    .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        append_logs_cancellable_sync(
            &conn,
            identity(),
            &BTreeSet::from([node()]),
            &entries,
            &cancellation,
            MODE,
        )
    }))
    .ok();
    let drained = registration.snapshot();
    assert_eq!(
        drained.append_scopes, 0,
        "append counter drains after original output locals"
    );
    assert_eq!(drained.native_scopes, 0);
    assert_eq!(drained.transport_scopes, 0);
    // The observer cannot release genuine original owners or preparation slots.
    assert!(weak.upgrade().is_some());
    assert!(pool.try_reserve().is_err());
    drop(entries);
    drop(original_owner);
    drop(alias_owner);
    drop(prepared);
    drop(alias);
    assert!(
        weak.upgrade().is_none(),
        "observer must own no preparation/command"
    );
    assert_eq!(census.snapshot().registrations, 0);
    assert_eq!(census.snapshot().commands, 0);
    let recovered_slot = pool.try_reserve().unwrap();
    assert!(pool.try_reserve().is_err());
    drop(recovered_slot);
    drop(other_reservations);
    registration.detach();
    assert!(!registration.snapshot().registered);
    drop(registration);
    conn.close().unwrap();
    // Reopen durable bytes after cleanup; cancellation/rejection must write none.
    let reopened = Connection::open(&path).unwrap();
    let rows = reopened
        .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| {
            row.get::<_, usize>(0)
        })
        .unwrap();
    if case == Case::Success {
        let mut statement = reopened
            .prepare("SELECT entry_json FROM config_raft_log ORDER BY log_index")
            .unwrap();
        let persisted = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap();
        for (index, encoded) in persisted.enumerate() {
            let decoded: Entry<ConfigRaftTypeConfig> =
                serde_json::from_slice(&encoded.unwrap()).unwrap();
            assert_eq!(decoded.log_id.index, index as u64);
            let EntryPayload::Normal(command) = decoded.payload else {
                panic!("original command")
            };
            assert_eq!(command.request_id, request());
            command
                .validate_for_profile(identity(), &AuditKey::new([0x64; 32]).unwrap(), PROFILE)
                .unwrap();
        }
    }
    reopened.close().unwrap();
    drop(directory);
    let observation = observer.observations.lock().unwrap();
    assert_eq!(
        observation.lost, 0,
        "bounded receipt buffer must not truncate"
    );
    assert_eq!(
        observation.counter_mismatches, 0,
        "counter reads reenter safely"
    );
    assert_eq!(drained.append_callbacks, observation.samples.len());
    println!(
        "CAPACITY_APPEND_CLEANUP rows={rows} callbacks={} scopes=0 registrations=0 owners=0",
        observation.samples.len()
    );
    Outcome {
        receipts: observation.samples.clone(),
        expected_payload,
        json_lengths,
        result,
        rows,
    }
}

fn assert_census(outcome: &Outcome) {
    assert!(
        !outcome.receipts.is_empty(),
        "CAPACITY_APPEND_OBSERVER_OMISSION_RED"
    );
    for sample in &outcome.receipts {
        assert_eq!(sample.source, node());
        assert_eq!(sample.request, request());
        assert_eq!(sample.batch, 1);
        assert_eq!(sample.preparations.registrations, 2);
        assert_eq!(sample.preparations.commands, 1);
        assert_eq!(sample.entries, outcome.json_lengths.len());
        assert_eq!(sample.selected_entries, sample.entries);
        assert_eq!(sample.unmeasured_entries, 0);
        assert_eq!(
            sample.entry_payload_bytes, outcome.expected_payload,
            "aliased original payload counted once, including unused capacity"
        );
        assert_eq!(sample.selected_entry_bytes, outcome.expected_payload);
        assert_eq!(sample.selected_prepared_bytes, outcome.expected_payload);
        assert_eq!(sample.node_prepared_bytes, outcome.expected_payload);
        assert_eq!(
            sample.descriptor_bytes,
            sample.entries * size_of::<Vec<u8>>(),
            "CAPACITY_APPEND_DESCRIPTOR_OMISSION_RED"
        );
        let completed: usize = outcome.json_lengths[..sample.completed_outputs]
            .iter()
            .sum();
        assert_eq!(
            sample.json_bytes,
            completed + sample.current_output_bytes,
            "CAPACITY_APPEND_JSON_OMISSION_RED"
        );
        assert_eq!(sample.selected_json_bytes, sample.json_bytes);
        assert_eq!(
            sample.selected_mutation_bytes,
            outcome.expected_payload + sample.json_bytes,
            "preparation and original command alias deduplicated"
        );
        assert_eq!(
            sample.node_mutation_bytes,
            sample.selected_mutation_bytes + sample.descriptor_bytes
        );
        if sample.current_output_bytes != 0 {
            assert_eq!(
                sample.current_output_bytes,
                outcome.json_lengths[sample.completed_outputs]
            );
            assert!(sample.current_output_len <= sample.current_output_bytes);
        }
    }
}

#[test]
fn capacity_append_buffers_success_counts_original_aliases_and_outputs() {
    let outcome = run(Case::Success);
    assert!(outcome.result.as_ref().unwrap().is_ok());
    assert_eq!(outcome.rows, 2);
    assert_census(&outcome);
    let ready = outcome
        .receipts
        .iter()
        .find(|sample| sample.stage == AppendStage::OutputsReady)
        .unwrap();
    assert_eq!(ready.completed_outputs, 2);
    assert_eq!(ready.current_output_bytes, 0);
    assert_eq!(ready.json_bytes, outcome.json_lengths.iter().sum::<usize>());
    assert_eq!(
        outcome
            .receipts
            .iter()
            .filter(|sample| sample.stage == AppendStage::JsonAllocated)
            .count(),
        2,
        "CAPACITY_APPEND_PREMATURE_RELEASE_RED"
    );
    assert!(ready.selected_mutation_bytes + ready.descriptor_bytes <= 32 * 1024 * 1024);
}

#[test]
fn capacity_append_buffers_cancellation_observes_allocated_and_partial_output() {
    for case in [Case::CancelAllocated, Case::CancelPartial] {
        let outcome = run(case);
        assert_eq!(
            outcome
                .result
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(outcome.rows, 0);
        assert_census(&outcome);
        let rejected = outcome
            .receipts
            .iter()
            .find(|sample| sample.stage == AppendStage::JsonRejected)
            .expect("CAPACITY_APPEND_REJECTED_OUTPUT_OMISSION_RED");
        assert_eq!(rejected.completed_outputs, 1);
        assert!(rejected.current_output_bytes > 0);
        if case == Case::CancelPartial {
            assert!(rejected.current_output_len > 0);
            assert!(rejected.current_output_len < rejected.current_output_bytes);
        } else {
            assert_eq!(rejected.current_output_len, 0);
        }
        let unwound = outcome.receipts.last().unwrap();
        assert_eq!(unwound.stage, AppendStage::EncodingRejected);
        assert_eq!(
            unwound.current_output_bytes, 0,
            "failed local output already dropped"
        );
        assert_eq!(unwound.completed_outputs, 1);
    }
}

#[test]
fn capacity_append_buffers_encoding_rejection_preserves_prior_output_owners() {
    let outcome = run(Case::RejectAggregate);
    let error = outcome.result.as_ref().unwrap().as_ref().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "config consensus log append exceeds aggregate byte limit"
    );
    assert_eq!(outcome.rows, 0);
    assert_census(&outcome);
    let rejected = outcome.receipts.last().unwrap();
    assert_eq!(rejected.stage, AppendStage::EncodingRejected);
    assert!(rejected.completed_outputs > 1);
    assert!(rejected.completed_outputs < outcome.json_lengths.len());
    assert_eq!(rejected.current_output_bytes, 0);
    assert!(rejected.json_bytes <= CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES);
    assert!(
        rejected.json_bytes + outcome.json_lengths[rejected.completed_outputs]
            > CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES
    );
    assert_eq!(
        outcome
            .receipts
            .iter()
            .filter(|sample| sample.stage == AppendStage::JsonAllocated)
            .count(),
        rejected.completed_outputs
    );
}

#[test]
fn capacity_append_buffers_unwind_drains_without_retaining_original_owners() {
    let outcome = run(Case::Unwind);
    assert!(outcome.result.is_none());
    assert_eq!(outcome.rows, 0);
    assert_census(&outcome);
    assert_eq!(
        outcome.receipts.last().unwrap().stage,
        AppendStage::JsonWriting
    );
}
