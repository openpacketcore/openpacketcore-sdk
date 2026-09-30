//! Component evidence through the production SQLite decoder and RaftNetwork
//! append path. The peer below is an awaited transport hold, not a Raft runtime.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::PreparedAuditedMutation;
use crate::consensus::capacity_observation::{
    AppendOwnerSample, AppendStage, NativeOwnerObserver, NativeOwnerSample, NativeRegistration,
    PreparationCensus,
};
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::preparation::PreparationOwnership;
use crate::consensus::raft_adapter::ConfigRaftNetworkFactory;
use crate::consensus::types::encode_config_wire_for_profile;
use crate::consensus::{sqlite, ConfigConsensusCommand, ConfigConsensusTopology};
use crate::{AttestedConfigCommit, AuditKey, CommitRecord, CommitSource};
use opc_consensus::engine::error::RaftError;
use opc_consensus::engine::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use opc_consensus::engine::raft::AppendEntriesResponse;
use opc_consensus::engine::{CommittedLeaderId, EmptyNode, Entry, LogId, Membership, Vote};
use opc_consensus::{ConsensusPeer, ConsensusPeerError, ConsensusWireResponse};
use opc_crypto::{ConfigCapacityProfile, ConfigPreparationPool};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const HANG_GUARD: Duration = Duration::from_secs(10);
static NEXT_IDENTITY: AtomicU8 = AtomicU8::new(1);

fn identity() -> ConsensusIdentity {
    let discriminator = NEXT_IDENTITY.fetch_add(1, Ordering::SeqCst);
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([discriminator; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x79; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn node(value: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(value).unwrap()
}
fn request(value: u8) -> ConsensusRequestId {
    ConsensusRequestId::from_bytes([value; 16])
}

// Independent closed-form oracle: no production census helper is used.
fn commit_heap(commit: &PreparedConfigCommit) -> usize {
    size_of::<PreparedConfigCommit>()
        + commit.record.encrypted_blob.capacity()
        + commit.record.principal.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.audit.capacity() * size_of::<crate::AuditRecord>()
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

fn entry_heap(entry: &Entry<ConfigRaftTypeConfig>) -> usize {
    let EntryPayload::Normal(command) = &entry.payload else {
        panic!("normal fixture")
    };
    let ConfigMutationIntent::AuditedMutation(command) = &command.intent else {
        panic!("audited fixture")
    };
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &command.effect else {
        panic!("bounded fixture")
    };
    size_of::<AuditedMutationFields>() + commit_heap(commit)
}

fn entry_weak(entry: &Entry<ConfigRaftTypeConfig>) -> Weak<AuditedMutationFields> {
    let EntryPayload::Normal(command) = &entry.payload else {
        panic!("normal fixture")
    };
    let ConfigMutationIntent::AuditedMutation(command) = &command.intent else {
        panic!("audited fixture")
    };
    command.weak_fields()
}

fn prepared(
    size: usize,
    pool: &ConfigPreparationPool,
    identity: ConsensusIdentity,
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
        vec![crate::AuditRecord {
            tx_id,
            sequence: 0,
            yang_path: "/fixture:config".to_owned(),
            op_type: crate::AuditOpType::Update,
            previous_value: Some("old".to_owned()),
            new_value: Some("new".to_owned()),
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        }],
        envelope.claim().unwrap(),
    )
    .unwrap();
    let binding = CapacityRecordBinding::issue(&attested, identity, &key, PROFILE).unwrap();
    let (record, audit, _) = attested.into_parts();
    let mut commit = PreparedConfigCommit::prepare(record, audit, &key).unwrap();
    // Unused capacity has no serialized representation and must still count.
    commit.record.encrypted_blob.reserve_exact(4096);
    commit.record.principal.reserve_exact(2048);
    commit.audit.reserve_exact(3);
    commit.audit[0].yang_path.reserve_exact(193);
    commit.audit[0]
        .previous_value
        .as_mut()
        .unwrap()
        .reserve_exact(113);
    commit.audit[0]
        .new_value
        .as_mut()
        .unwrap()
        .reserve_exact(71);
    let expected_payload = size_of::<AuditedMutationFields>() + commit_heap(&commit);
    let recovered = binding
        .recover(&commit.record, identity, &key, PROFILE)
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
            identity,
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

fn entries(
    identity: ConsensusIdentity,
    prepared: &PreparedAuditedMutation,
    ids: &[u8],
) -> Vec<Entry<ConfigRaftTypeConfig>> {
    ids.iter()
        .enumerate()
        .map(|(index, id)| Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, node(1)), index as u64),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: 8,
                identity,
                request_id: request(*id),
                logical_time: Timestamp::from_offset_datetime(
                    time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
                ),
                intent: ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
            }),
        })
        .collect()
}

fn rpc(entries: Vec<Entry<ConfigRaftTypeConfig>>) -> AppendEntriesRequest<ConfigRaftTypeConfig> {
    AppendEntriesRequest {
        vote: Vote::new_committed(1, node(1)),
        prev_log_id: None,
        entries,
        leader_commit: None,
    }
}

// Pauses the original typed request and its already-encoded output in the
// production append method, before its physical disposal and first network poll.
// Tests release the same call into HeldPeer to inspect the subsequent wire phase.
pub(super) struct EncodedGate {
    pub(super) arrived: Semaphore,
    pub(super) release: Semaphore,
}

impl EncodedGate {
    fn attach(census: &RaftAppendCensus) -> Arc<Self> {
        let gate = Arc::new(Self {
            arrived: Semaphore::new(0),
            release: Semaphore::new(0),
        });
        assert!(lock(&census.encoded_gate).replace(gate.clone()).is_none());
        gate
    }

    async fn wait(&self, count: u32) {
        tokio::time::timeout(HANG_GUARD, self.arrived.acquire_many(count))
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}

#[derive(Debug)]
struct Gate {
    live: Mutex<BTreeMap<ConsensusNodeId, Option<RaftAppendWitness>>>,
    arrived: Semaphore,
    release: Semaphore,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            live: Mutex::new(BTreeMap::new()),
            arrived: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }

    async fn wait(&self, count: u32) {
        tokio::time::timeout(HANG_GUARD, self.arrived.acquire_many(count))
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}

struct WireBorrow<'a> {
    gate: &'a Gate,
    target: ConsensusNodeId,
    _request: &'a ConsensusWireRequest,
}
impl Drop for WireBorrow<'_> {
    fn drop(&mut self) {
        lock(&self.gate.live).remove(&self.target);
    }
}

#[derive(Debug)]
struct HeldPeer {
    target: ConsensusNodeId,
    gate: Arc<Gate>,
}

#[async_trait::async_trait]
impl ConsensusPeer for HeldPeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let witness = raft_append_witness(&request, self.target);
        lock(&self.gate.live).insert(self.target, witness);
        let _borrow = WireBorrow {
            gate: &self.gate,
            target: self.target,
            _request: &request,
        };
        self.gate.arrived.add_permits(1);
        self.gate.release.acquire().await.unwrap().forget();
        let response: Result<AppendEntriesResponse<ConsensusNodeId>, RaftError<ConsensusNodeId>> =
            Ok(AppendEntriesResponse::Success);
        Ok(ConsensusWireResponse {
            result: Ok(encode_config_wire_for_profile(PROFILE, &response).unwrap()),
        })
    }
}

async fn start(
    identity: ConsensusIdentity,
    target: u64,
    gate: &Arc<Gate>,
    request: AppendEntriesRequest<ConfigRaftTypeConfig>,
) -> tokio::task::JoinHandle<bool> {
    let peer: Arc<dyn ConsensusPeer> = Arc::new(HeldPeer {
        target: node(target),
        gate: gate.clone(),
    });
    let mut factory = ConfigRaftNetworkFactory::try_new(
        identity,
        node(1),
        BTreeMap::from([(node(target), peer)]),
        PROFILE,
    )
    .unwrap();
    let mut network = factory.new_client(node(target), &EmptyNode {}).await;
    tokio::spawn(async move {
        matches!(
            network
                .append_entries(request, RPCOption::new(HANG_GUARD))
                .await,
            Ok(AppendEntriesResponse::Success)
        )
    })
}

struct Outcome {
    sample: RaftAppendSample,
    wire_phase: RaftAppendSample,
    decoded_fields_live: bool,
    decoded_fields_retired: bool,
    union: RaftAppendUnion,
    conflicting: RaftAppendUnion,
    witnesses: Vec<Option<RaftAppendWitness>>,
    expected_descriptors: usize,
    expected_payload: usize,
    expected_shared: usize,
}

fn disk_log(
    identity: ConsensusIdentity,
    members: &BTreeSet<ConsensusNodeId>,
) -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir().unwrap();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(filesystem.status.success());
    assert!(!matches!(
        std::str::from_utf8(&filesystem.stdout).unwrap().trim(),
        "tmpfs" | "ramfs"
    ));
    let connection = Connection::open(directory.path().join("raft.sqlite")).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=EXTRA;")
        .unwrap();
    crate::schema::initialize_schema(&connection).unwrap();
    let topology = ConfigConsensusTopology::try_new(identity, node(1), members.clone()).unwrap();
    sqlite::provision_retained_schema(
        &connection,
        &topology,
        &AuditKey::new([0x64; 32]).unwrap(),
        PROFILE,
        Instant::now() + HANG_GUARD,
    )
    .unwrap();
    (directory, connection)
}

async fn held_sqlite_calls() -> Outcome {
    let identity = identity();
    let pool = ConfigPreparationPool::bounded_v1();
    let (prepared, weak, expected_shared) = prepared(4096, &pool, identity);
    let initial = entries(identity, &prepared, &[1, 2]);
    let members = BTreeSet::from([node(1), node(2), node(3), node(4), node(5)]);
    let (directory, connection) = disk_log(identity, &members);
    sqlite::append_logs_sync(&connection, identity, &members, &initial, PROFILE).unwrap();
    drop(initial);
    // Each follower really decodes distinct original commands from SQLite.
    let mut first =
        sqlite::read_limited_log_range_sync(&connection, identity, &members, 0, 2, 64, PROFILE)
            .unwrap();
    let mut second =
        sqlite::read_limited_log_range_sync(&connection, identity, &members, 0, 2, 64, PROFILE)
            .unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    // Weak witnesses retain only the Arc headers, never the nested allocations.
    // The four separately decoded field payloads have no other strong owner.
    let decoded_fields: Vec<_> = first.iter().chain(&second).map(entry_weak).collect();
    let mut aliases = entries(identity, &prepared, &[1, 1]);
    let mut other_aliases = entries(identity, &prepared, &[1, 1]);
    first.reserve_exact(5);
    second.reserve_exact(9);
    aliases.reserve_exact(13);
    other_aliases.reserve_exact(21);
    let expected_descriptors =
        (first.capacity() + second.capacity() + aliases.capacity() + other_aliases.capacity())
            * size_of::<Entry<ConfigRaftTypeConfig>>();
    let expected_payload = first.iter().map(entry_heap).sum::<usize>()
        + second.iter().map(entry_heap).sum::<usize>()
        + expected_shared;
    let census = Arc::new(RaftAppendCensus::default());
    let registration = census.observe_source(identity, node(1)).unwrap();
    let encoded = EncodedGate::attach(&census);
    let preparations = Arc::new(PreparationCensus::default());
    let preparation = preparations.observe_audited(node(1), &prepared).unwrap();
    let gate = Gate::new();
    let first = start(identity, 2, &gate, rpc(first)).await;
    let second = start(identity, 3, &gate, rpc(second)).await;
    let aliases = start(identity, 4, &gate, rpc(aliases)).await;
    let other_aliases = start(identity, 5, &gate, rpc(other_aliases)).await;
    encoded.wait(4).await;
    let decoded_fields_live = decoded_fields
        .iter()
        .all(|fields| fields.strong_count() == 1);
    let (sample, union, conflicting) = {
        // Exact intended lock order: preparations -> transport -> original DTOs.
        let borrowed_preparations = lock(&preparations.state);
        let native = &borrowed_preparations
            .owners
            .values()
            .next()
            .unwrap()
            .allocations;
        let _transport = lock(&gate.live);
        census.with_current_capture(|capture| {
            let sample = capture.sample();
            let union = capture.join(&AllocationView::new(identity, node(1), native));
            let mut inconsistent = native.clone();
            *inconsistent.values_mut().next().unwrap() += 1;
            let conflicting = capture.join(&AllocationView::new(identity, node(1), &inconsistent));
            (sample, union, conflicting)
        })
    };
    encoded.release.add_permits(4);
    gate.wait(4).await;
    let (wire_phase, witnesses) = {
        let transport = lock(&gate.live);
        census.with_current_capture(|capture| {
            (capture.sample(), transport.values().copied().collect())
        })
    };
    let decoded_fields_retired = decoded_fields
        .iter()
        .all(|fields| fields.strong_count() == 0);
    // All semantic observation assertions happen only after real cancellation,
    // success, owner drainage, connection close and preparation release.
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    gate.release.add_permits(3);
    assert!(second.await.unwrap());
    assert!(aliases.await.unwrap());
    assert!(other_aliases.await.unwrap());
    assert!(lock(&gate.live).is_empty());
    assert!(census.with_current_capture(|capture| capture.sample().calls.is_empty()));
    drop(registration);
    assert_eq!(
        census.with_current_capture(|capture| capture.sample().registrations),
        0
    );
    drop(preparation);
    drop(prepared);
    assert!(
        weak.upgrade().is_none(),
        "observation metadata owns no preparation"
    );
    assert_eq!(preparations.snapshot().registrations, 0);
    assert!(pool.try_reserve().is_ok());
    connection.close().unwrap();
    drop(directory);
    println!(
        "CAPACITY_RAFT_CLEANUP calls=0 transport=0 registrations=0 preparations=0 storage=closed"
    );
    Outcome {
        sample,
        wire_phase,
        decoded_fields_live,
        decoded_fields_retired,
        union,
        conflicting,
        witnesses,
        expected_descriptors,
        expected_payload,
        expected_shared,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capacity_raft_buffers_real_sqlite_calls_count_original_batches_and_aliases() {
    let result = held_sqlite_calls().await;
    assert!(
        result.decoded_fields_live,
        "original SQLite owners are live before disposal"
    );
    assert_eq!(
        result.sample.calls.len(),
        4,
        "CAPACITY_RAFT_EARLY_RELEASE_RED"
    );
    assert!(result.sample.issues.complete(), "complete supported census");
    assert!(
        result
            .sample
            .calls
            .iter()
            .all(|call| call.attribution.len() == 2 && call.entries == 2),
        "CAPACITY_RAFT_BATCH_OMISSION_RED"
    );
    assert_eq!(
        result.sample.descriptor_bytes, result.expected_descriptors,
        "CAPACITY_RAFT_DESCRIPTOR_OMISSION_RED"
    );
    assert_eq!(
        result.sample.payload_bytes, result.expected_payload,
        "CAPACITY_RAFT_PAYLOAD_OMISSION_RED"
    );
    assert_eq!(
        result.sample.original_bytes,
        result.expected_descriptors + result.expected_payload
    );
    assert_eq!(
        result
            .sample
            .calls
            .iter()
            .map(|call| call.entries)
            .sum::<usize>(),
        8
    );

    assert_eq!(
        result
            .sample
            .calls
            .iter()
            .flat_map(|call| call.attribution.iter())
            .filter(|entry| entry.request == Some(request(2)))
            .count(),
        2,
        "CAPACITY_RAFT_BATCH_OMISSION_RED"
    );
    assert_eq!(
        result
            .sample
            .calls
            .iter()
            .map(|call| call.generation)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        result
            .sample
            .calls
            .iter()
            .map(|call| call.target)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([node(2), node(3), node(4), node(5)])
    );
    assert!(
        result.witnesses.iter().all(Option::is_some),
        "CAPACITY_RAFT_WITNESS_LIFETIME_RED"
    );
    assert_eq!(
        result
            .witnesses
            .iter()
            .map(|witness| witness.unwrap().generation)
            .collect::<BTreeSet<_>>(),
        result
            .sample
            .calls
            .iter()
            .map(|call| call.generation)
            .collect()
    );
    assert_eq!(
        result
            .sample
            .calls
            .iter()
            .map(|call| call.payload_bytes)
            .sum::<usize>(),
        result.expected_payload + result.expected_shared,
        "separate live follower calls sharing the same Arc count once globally"
    );
    assert!(result
        .sample
        .calls
        .iter()
        .filter(|call| call.target == node(4) || call.target == node(5))
        .all(|call| call.payload_bytes == result.expected_shared));
    assert!(result.union.issues.complete());
    assert_eq!(result.union.calls, 4);
    assert_eq!(result.union.shared_bytes, result.expected_shared);
    assert_eq!(result.union.native_bytes, result.expected_shared);
    assert_eq!(
        result.union.union_bytes, result.sample.original_bytes,
        "true preparation aliases deduplicate"
    );
    assert!(result.conflicting.issues.inconsistent_extents);
    assert!(!result.conflicting.issues.complete());
    assert!(result.wire_phase.issues.complete());
    assert!(
        result.decoded_fields_retired,
        "CAPACITY_RAFT_PHYSICAL_RETIREMENT_RED"
    );
    assert!(
        result.wire_phase.calls.is_empty(),
        "CAPACITY_RAFT_TYPED_RETIREMENT_RED"
    );
    assert_eq!(result.wire_phase.original_bytes, 0);
    assert_eq!(result.wire_phase.origins.len(), 4);
    assert_eq!(
        result
            .wire_phase
            .origins
            .iter()
            .map(|origin| origin.generation)
            .collect::<BTreeSet<_>>(),
        result
            .sample
            .calls
            .iter()
            .map(|call| call.generation)
            .collect()
    );
}

#[test]
fn capacity_raft_buffers_physical_drop_waits_for_capture() {
    let identity = identity();
    let pool = ConfigPreparationPool::bounded_v1();
    let (prepared, lease, _) = prepared(1024, &pool, identity);
    let entries = entries(identity, &prepared, &[1]);
    let fields = entry_weak(&entries[0]);
    drop(prepared);
    assert!(lease.upgrade().is_none());
    let census = Arc::new(RaftAppendCensus::default());
    let registration = census.observe_source(identity, node(1)).unwrap();
    let original = OriginalAppend::start(identity, node(1), node(2), rpc(entries));
    let (started, start) = std::sync::mpsc::channel();
    let (finished, finish) = std::sync::mpsc::channel();
    let (thread, waited, fields_still_live) = census.with_current_capture(|capture| {
        assert_eq!(capture.sample().calls.len(), 1);
        let thread = std::thread::spawn(move || {
            started.send(()).unwrap();
            drop(original);
            finished.send(()).unwrap();
        });
        start.recv_timeout(HANG_GUARD).unwrap();
        let waited = finish.recv_timeout(Duration::from_millis(50)).is_err();
        (thread, waited, fields.strong_count() == 1)
    });
    thread.join().unwrap();
    finish.recv_timeout(HANG_GUARD).unwrap();
    assert_eq!(fields.strong_count(), 0);
    let drained = census.with_current_capture(|capture| capture.sample());
    drop(registration);
    assert!(drained.calls.is_empty() && drained.origins.is_empty());
    println!(
        "CAPACITY_RAFT_CLEANUP physical_drop calls=0 transport=0 registrations=0 preparations=0"
    );
    assert!(waited);
    assert!(fields_still_live, "CAPACITY_RAFT_PHYSICAL_DROP_BARRIER_RED");
}

async fn single(
    census: &Arc<RaftAppendCensus>,
    identity: ConsensusIdentity,
    request: AppendEntriesRequest<ConfigRaftTypeConfig>,
) -> (RaftAppendSample, Option<RaftAppendWitness>) {
    let encoded = EncodedGate::attach(census);
    let gate = Gate::new();
    let call = start(identity, 2, &gate, request).await;
    encoded.wait(1).await;
    let sample = census.with_current_capture(|capture| capture.sample());
    encoded.release.add_permits(1);
    gate.wait(1).await;
    let (wire_phase, witness) = {
        let transport = lock(&gate.live);
        census.with_current_capture(|capture| (capture.sample(), transport[&node(2)]))
    };
    gate.release.add_permits(1);
    assert!(call.await.unwrap());
    assert!(lock(&gate.live).is_empty());
    let drained = census.with_current_capture(|capture| capture.sample());
    assert!(drained.calls.is_empty() && drained.origins.is_empty());
    lock(&census.encoded_gate).take();
    assert!(
        wire_phase.calls.is_empty(),
        "CAPACITY_RAFT_TYPED_RETIREMENT_RED"
    );
    assert_eq!(wire_phase.original_bytes, 0);
    assert_eq!(wire_phase.origins.len(), usize::from(witness.is_some()));
    (sample, witness)
}

#[tokio::test]
async fn capacity_raft_buffers_heartbeat_spare_capacity_and_retry_generations() {
    let identity = identity();
    let census = Arc::new(RaftAppendCensus::default());
    let registration = census.observe_source(identity, node(1)).unwrap();
    let mut generations = Vec::new();
    for _ in 0..2 {
        let entries = Vec::with_capacity(7);
        let expected = entries.capacity() * size_of::<Entry<ConfigRaftTypeConfig>>();
        let (sample, witness) = single(&census, identity, rpc(entries)).await;
        assert!(sample.issues.complete());
        assert_eq!(sample.calls.len(), 1);
        assert_eq!(sample.calls[0].entries, 0);
        assert!(sample.calls[0].attribution.is_empty());
        assert_eq!(sample.payload_bytes, 0);
        assert_eq!(sample.descriptor_bytes, expected);
        assert_eq!(witness.unwrap().entries, 0);
        generations.push(witness.unwrap().generation);
    }
    assert!(generations[1] > generations[0]);
    drop(registration);
}

#[tokio::test]
async fn capacity_raft_buffers_unsupported_and_wrong_scope_are_incomplete() {
    let identity = identity();
    let census = Arc::new(RaftAppendCensus::default());
    let registration = census.observe_source(identity, node(1)).unwrap();
    let entries = vec![
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, node(1)), 0),
            payload: EntryPayload::Membership(Membership::new(vec![BTreeSet::from([node(1)])], ())),
        },
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, node(1)), 1),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: 8,
                identity: super::tests::identity(),
                request_id: request(8),
                logical_time: Timestamp::now_utc(),
                intent: ConfigMutationIntent::MarkConfirmed { tx_id: TxId::new() },
            }),
        },
    ];
    let (sample, witness) = single(&census, identity, rpc(entries)).await;
    drop(registration);
    assert!(witness.is_some());
    assert_eq!(sample.issues.unsupported_entries, 1);
    assert_eq!(sample.issues.mismatched_identity_entries, 1);
    assert!(!sample.issues.complete());
}

#[tokio::test]
async fn capacity_raft_buffers_metadata_saturation_refuses_completeness() {
    for limits in [
        RaftAppendLimits {
            calls: 1,
            entries_per_call: 0,
            allocations_per_call: 8,
        },
        RaftAppendLimits {
            calls: 1,
            entries_per_call: 8,
            allocations_per_call: 0,
        },
    ] {
        let identity = identity();
        let pool = ConfigPreparationPool::bounded_v1();
        let (prepared, weak, _) = prepared(1024, &pool, identity);
        let census = Arc::new(RaftAppendCensus::new(limits));
        let registration = census.observe_source(identity, node(1)).unwrap();
        let (sample, _) = single(
            &census,
            identity,
            rpc(entries(identity, &prepared, &[1, 2])),
        )
        .await;
        drop(registration);
        drop(prepared);
        assert!(weak.upgrade().is_none());
        assert!(sample.issues.metadata_saturated);
        assert!(sample.calls[0]
            .attribution
            .iter()
            .all(|entry| !entry.supported));
        assert!(!sample.issues.complete());
        assert!(census.with_current_capture(|capture| capture.sample().issues.metadata_saturated));
    }
    let identity = identity();
    let census = Arc::new(RaftAppendCensus::default());
    let registration = census.observe_source(identity, node(1)).unwrap();
    lock(&census.state).next = u64::MAX;
    let (sample, witness) = single(&census, identity, rpc(Vec::new())).await;
    drop(registration);
    assert!(sample.issues.metadata_saturated);
    assert!(witness.is_none());
}

#[tokio::test]
async fn capacity_raft_buffers_ambiguous_source_refuses_attribution() {
    let identity = identity();
    let first = Arc::new(RaftAppendCensus::default());
    let second = Arc::new(RaftAppendCensus::default());
    let a = first.observe_source(identity, node(1)).unwrap();
    let b = second.observe_source(identity, node(1)).unwrap();
    let (sample, witness) = single(&first, identity, rpc(Vec::new())).await;
    drop(a);
    drop(b);
    assert!(sample.issues.ambiguous_source);
    assert!(sample.calls.is_empty());
    assert!(witness.is_none());
    assert!(second.with_current_capture(|capture| capture.sample().issues.ambiguous_source));
}

#[tokio::test]
async fn capacity_raft_buffers_call_saturation_and_detach_keep_originals_borrowed() {
    let identity = identity();
    let census = Arc::new(RaftAppendCensus::new(RaftAppendLimits {
        calls: 1,
        ..RaftAppendLimits::default()
    }));
    let registration = census.observe_source(identity, node(1)).unwrap();
    let encoded = EncodedGate::attach(&census);
    let gate = Gate::new();
    let first = start(identity, 2, &gate, rpc(Vec::new())).await;
    encoded.wait(1).await;
    let second = start(identity, 3, &gate, rpc(Vec::new())).await;
    encoded.wait(1).await;
    let before = census.with_current_capture(|capture| capture.sample());
    drop(registration);
    let detached = census.with_current_capture(|capture| capture.sample());
    encoded.release.add_permits(2);
    gate.wait(2).await;
    let wire_phase = census.with_current_capture(|capture| capture.sample());
    first.abort();
    second.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(second.await.unwrap_err().is_cancelled());
    assert!(lock(&gate.live).is_empty());
    let drained = census.with_current_capture(|capture| capture.sample());
    assert!(drained.calls.is_empty() && drained.origins.is_empty());
    assert_eq!(before.calls.len(), 1);
    assert!(before.issues.metadata_saturated);
    assert_eq!(
        detached.calls.len(),
        1,
        "attachment metadata cannot free original owners"
    );
    assert_eq!(detached.registrations, 0);
    assert!(detached.issues.ambiguous_source);
    assert!(!detached.issues.complete());
    assert!(
        wire_phase.calls.is_empty(),
        "CAPACITY_RAFT_TYPED_RETIREMENT_RED"
    );
    assert_eq!(wire_phase.original_bytes, 0);
    assert_eq!(wire_phase.origins.len(), 1);
}

#[derive(Clone, Copy)]
struct AuthorityReceipt {
    stage: AppendStage,
    source: ConsensusNodeId,
    live_calls: usize,
    live_bytes: usize,
    live_complete: bool,
    joined: RaftAppendUnion,
}

struct AuthorityObserver {
    census: Arc<RaftAppendCensus>,
    transport: Arc<Gate>,
    receipts: Mutex<Vec<AuthorityReceipt>>,
}

impl NativeOwnerObserver for AuthorityObserver {
    fn observe(&self, _: NativeOwnerSample) {}

    fn observe_append_with_allocations(
        &self,
        sample: AppendOwnerSample,
        owners: AllocationView<'_>,
    ) {
        // Called by the actual SQLite append while native/preparation borrows
        // are still held. Join under the actual transport and original barriers.
        let _transport = lock(&self.transport.live);
        let receipt = self.census.with_current_capture(|capture| {
            let live = capture.sample();
            AuthorityReceipt {
                stage: sample.stage,
                source: sample.source,
                live_calls: live.calls.len(),
                live_bytes: live.original_bytes,
                live_complete: live.issues.complete(),
                joined: capture.join(&owners),
            }
        });
        lock(&self.receipts).push(receipt);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capacity_raft_buffers_native_append_callback_refuses_other_authority() {
    let native_identity = identity();
    let remote_identity = identity();
    let members = BTreeSet::from([node(1), node(2), node(3)]);
    let (directory, connection) = disk_log(native_identity, &members);
    let pool = ConfigPreparationPool::bounded_v1();
    let (native, native_weak, _) = prepared(1024, &pool, native_identity);
    let (remote, remote_weak, _) = prepared(2048, &pool, remote_identity);
    let originals = Arc::new(RaftAppendCensus::default());
    let remote_registration = originals.observe_source(remote_identity, node(1)).unwrap();
    let encoded = EncodedGate::attach(&originals);
    let preparations = Arc::new(PreparationCensus::default());
    let preparation = preparations.observe_audited(node(1), &native).unwrap();
    let gate = Gate::new();
    let observer = Arc::new(AuthorityObserver {
        census: originals.clone(),
        transport: gate.clone(),
        receipts: Mutex::new(Vec::new()),
    });
    let native_registration = NativeRegistration::new(
        &connection,
        native_identity,
        node(1),
        request(1),
        &native,
        preparations.clone(),
        observer.clone(),
    )
    .unwrap();
    let call = start(
        remote_identity,
        2,
        &gate,
        rpc(entries(remote_identity, &remote, &[2])),
    )
    .await;
    encoded.wait(1).await;
    let native_entries = entries(native_identity, &native, &[1]);
    let result = sqlite::append_logs_sync(
        &connection,
        native_identity,
        &members,
        &native_entries,
        PROFILE,
    );
    let mismatched_receipts = lock(&observer.receipts).len();
    // A second exact authority registration must permit A's native-only union
    // without attributing B's still-live original request to A's node number.
    let local_registration = originals.observe_source(native_identity, node(1)).unwrap();
    let mut continuation = native_entries.clone();
    continuation[0].log_id = LogId::new(CommittedLeaderId::new(1, node(1)), 1);
    let matched_result = sqlite::append_logs_sync(
        &connection,
        native_identity,
        &members,
        &continuation,
        PROFILE,
    );
    encoded.release.add_permits(1);
    gate.wait(1).await;
    let wire_phase = originals.with_current_capture(|capture| capture.sample());
    gate.release.add_permits(1);
    assert!(call.await.unwrap());
    assert!(lock(&gate.live).is_empty());
    let drained = originals.with_current_capture(|capture| capture.sample());
    assert!(drained.calls.is_empty() && drained.origins.is_empty());
    drop(remote_registration);
    drop(local_registration);
    let drained = native_registration.snapshot();
    assert_eq!(drained.append_scopes, 0);
    assert_eq!(drained.native_scopes, 0);
    assert_eq!(drained.transport_scopes, 0);
    native_registration.detach();
    assert!(!native_registration.snapshot().registered);
    drop(native_registration);
    drop(native_entries);
    drop(continuation);
    drop(preparation);
    drop(native);
    drop(remote);
    assert!(native_weak.upgrade().is_none());
    assert!(remote_weak.upgrade().is_none());
    assert_eq!(preparations.snapshot().registrations, 0);
    connection.close().unwrap();
    drop(directory);
    println!("CAPACITY_RAFT_CLEANUP authority_join calls=0 transport=0 registrations=0 preparations=0 storage=closed");
    assert!(result.is_ok());
    assert!(matched_result.is_ok(), "{matched_result:?}");
    assert!(
        wire_phase.calls.is_empty(),
        "CAPACITY_RAFT_TYPED_RETIREMENT_RED"
    );
    assert_eq!(wire_phase.original_bytes, 0);
    assert_eq!(wire_phase.origins.len(), 1);
    let receipts = lock(&observer.receipts);
    assert!(mismatched_receipts > 0 && receipts.len() > mismatched_receipts);
    assert!(receipts
        .iter()
        .any(|receipt| receipt.stage == AppendStage::OutputsReady));
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.source, node(1));
        assert_eq!(receipt.live_calls, 1);
        assert!(receipt.live_bytes > 0);
        assert!(receipt.live_complete);
        assert_eq!(receipt.joined.identity, native_identity);
        if index < mismatched_receipts {
            assert!(
                receipt.joined.issues.ambiguous_source,
                "CAPACITY_RAFT_AUTHORITY_JOIN_RED"
            );
            assert!(!receipt.joined.issues.complete());
        } else {
            assert!(
                receipt.joined.issues.complete(),
                "exact authorities remain independent despite the same node number"
            );
        }
        assert_eq!(receipt.joined.calls, 0);
        assert_eq!(receipt.joined.original_bytes, 0);
        assert_eq!(receipt.joined.shared_bytes, 0);
        assert!(receipt.joined.native_bytes > 0);
        assert_eq!(receipt.joined.union_bytes, receipt.joined.native_bytes);
    }
}
