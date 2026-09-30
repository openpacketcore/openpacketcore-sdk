//! Concurrent production encoders, each owning a fresh SQLite-decoded request.
//! These are real adapter component calls on OS threads, not a consensus cluster.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{AuditedConfigEffect, AuditedMutationFields};
use crate::consensus::capacity_observation::raft_buffers::RaftAppendCensus;
use crate::consensus::capacity_observation::with_audited_allocations;
use crate::consensus::capacity_observation::working_buffers::{
    WorkingBufferCensus, WorkingBufferKind, WorkingBufferObserver, WorkingBufferOwner,
    WorkingBufferStage,
};
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::preparation::PreparationOwnership;
use crate::consensus::raft_adapter::ConfigRaftNetworkFactory;
use crate::consensus::{
    sqlite, ConfigConsensusTopology, ConfigRaftTypeConfig, PreparedAuditedMutation,
};
use opc_consensus::engine::error::{Infallible, RaftError};
use opc_consensus::engine::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use opc_consensus::engine::raft::{AppendEntriesRequest, AppendEntriesResponse};
use opc_consensus::engine::{CommittedLeaderId, EmptyNode, Entry, EntryPayload, LogId, Vote};
use opc_consensus::{
    ConsensusIdentity, ConsensusNodeId, ConsensusPeer, ConsensusPeerError, ConsensusRequestId,
    ConsensusRpcFamily, ConsensusWireRequest, ConsensusWireResponse,
};
use opc_crypto::{AuthenticatedEnvelope, ConfigCapacityProfile, ConfigPreparationPool};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::{poll_fn, Future};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const FOLLOWERS: usize = 8;
const GUARD: Duration = Duration::from_secs(10);
const OPERATION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Default)]
struct EncoderState {
    waiting_on: Option<usize>,
    guard: Option<usize>,
    pointer: usize,
    capacity: usize,
}

#[derive(Default)]
struct ProbeState {
    encoders: [EncoderState; FOLLOWERS],
    released: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Checkpoint {
    #[default]
    Encoded,
    OriginalReady,
}

#[derive(Default)]
struct Probe {
    checkpoint: Checkpoint,
    state: Mutex<ProbeState>,
    changed: Condvar,
}

thread_local! {
    static PROBE: RefCell<Option<(Arc<Probe>, usize)>> = const { RefCell::new(None) };
}

struct ProbeScope;
impl ProbeScope {
    fn enter(probe: Arc<Probe>, index: usize) -> Self {
        PROBE.with(|slot| assert!(slot.borrow_mut().replace((probe, index)).is_none()));
        Self
    }
}
impl Drop for ProbeScope {
    fn drop(&mut self) {
        PROBE.with(|slot| *slot.borrow_mut() = None);
    }
}

// Witness Poll::Pending from the actual production mutex future. A pending
// request retains its real DTO; this does not substitute a test-only queue.
pub(crate) async fn observe_wait<F: Future>(
    encoding: &tokio::sync::Mutex<()>,
    wait: F,
) -> F::Output {
    let mutex = encoding as *const tokio::sync::Mutex<()> as usize;
    struct Pending;
    impl Drop for Pending {
        fn drop(&mut self) {
            pending(None);
        }
    }
    let _pending = Pending;
    let mut wait = std::pin::pin!(wait);
    poll_fn(|context| {
        let result = wait.as_mut().poll(context);
        pending(result.is_pending().then_some(mutex));
        result
    })
    .await
}

fn pending(waiting_on: Option<usize>) {
    PROBE.with(|slot| {
        if let Some((probe, index)) = slot.borrow().as_ref() {
            probe.state.lock().unwrap().encoders[*index].waiting_on = waiting_on;
            probe.changed.notify_all();
        }
    });
}

// The adapter borrows its actual encoded Vec and guard at each checkpoint.
// Both borrows survive the hold. No payload or guard owner is manufactured.
pub(crate) fn encoded(value: &Vec<u8>, guard: Option<&tokio::sync::MutexGuard<'_, ()>>) {
    checkpoint(Checkpoint::Encoded, value, guard);
}

pub(crate) fn original_ready(value: &Vec<u8>, guard: Option<&tokio::sync::MutexGuard<'_, ()>>) {
    checkpoint(Checkpoint::OriginalReady, value, guard);
}

fn checkpoint(
    checkpoint: Checkpoint,
    value: &Vec<u8>,
    guard: Option<&tokio::sync::MutexGuard<'_, ()>>,
) {
    PROBE.with(|slot| {
        let binding = slot.borrow();
        let Some((probe, index)) = binding.as_ref() else {
            return;
        };
        if probe.checkpoint != checkpoint {
            return;
        }
        let mut state = probe.state.lock().unwrap();
        state.encoders[*index] = EncoderState {
            waiting_on: None,
            guard: guard.map(|guard| {
                tokio::sync::MutexGuard::mutex(guard) as *const tokio::sync::Mutex<()> as usize
            }),
            pointer: value.as_ptr() as usize,
            capacity: value.capacity(),
        };
        probe.changed.notify_all();
        state = probe
            .changed
            .wait_timeout_while(state, GUARD, |state| !state.released)
            .unwrap()
            .0;
        assert!(state.released, "bounded actual encoder release");
        std::hint::black_box((value, guard));
        state.encoders[*index] = EncoderState::default();
    });
}

impl Probe {
    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }

    fn wait_until_all_observed(&self) -> bool {
        let state = self
            .changed
            .wait_timeout_while(self.state.lock().unwrap(), GUARD, |state| {
                !state.all_observed()
            })
            .unwrap()
            .0;
        state.all_observed()
    }
}

impl ProbeState {
    fn blocked_by_borrowed_guard(&self, value: &EncoderState) -> bool {
        value.waiting_on.is_some_and(|mutex| {
            self.encoders
                .iter()
                .any(|holder| holder.capacity != 0 && holder.guard == Some(mutex))
        })
    }

    fn all_observed(&self) -> bool {
        // A last Poll::Pending receipt may be stale after unlock. It counts
        // only while a held output checkpoint still borrows the very mutex
        // guard that blocks that waiter. With early unlock, wait for the real
        // outputs to arrive instead of sampling an unfinished handoff.
        self.encoders
            .iter()
            .all(|value| value.capacity != 0 || self.blocked_by_borrowed_guard(value))
    }
}

struct RecoveryGate {
    arrived: Mutex<Option<std::sync::mpsc::Sender<WorkingBufferOwner>>>,
    released: Mutex<bool>,
    changed: Condvar,
}
impl RecoveryGate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
impl WorkingBufferObserver for RecoveryGate {
    fn observe(&self, stage: WorkingBufferStage, owner: WorkingBufferOwner) {
        if stage != WorkingBufferStage::RecoveryReady {
            return;
        }
        if let Some(sender) = self.arrived.lock().unwrap().take() {
            sender.send(owner).unwrap();
        }
        let released = self
            .changed
            .wait_timeout_while(self.released.lock().unwrap(), GUARD, |value| !*value)
            .unwrap()
            .0;
        assert!(*released, "bounded actual recovery release");
    }
}

struct ReleaseOnDrop {
    probe: Arc<Probe>,
    recovery: Arc<RecoveryGate>,
}
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.probe.release();
        self.recovery.release();
    }
}

#[derive(Debug)]
struct Peer {
    target: ConsensusNodeId,
    response: Vec<u8>,
}
#[async_trait::async_trait]
impl ConsensusPeer for Peer {
    fn node_id(&self) -> ConsensusNodeId {
        self.target
    }
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        request.validate()?;
        if request.family != ConsensusRpcFamily::AppendEntries {
            return Err(ConsensusPeerError::Protocol);
        }
        Ok(ConsensusWireResponse {
            result: Ok(self.response.clone()),
        })
    }
}

fn node(value: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(value).unwrap()
}

fn prepared(
    identity: ConsensusIdentity,
    key: &crate::AuditKey,
    pool: &ConfigPreparationPool,
) -> (PreparedAuditedMutation, AuthenticatedEnvelope) {
    let time: Timestamp = "1970-01-01T00:01:40Z".parse().unwrap();
    let tx_id = TxId::new();
    let prefix = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/";
    let principal = format!("{prefix}{}", "p".repeat(16_384 - prefix.len()));
    let schema = SchemaDigest::from_bytes([0xDA; 32]);
    let reservation = pool.try_reserve().unwrap();
    let encryption = opc_key::MemoryKeyProvider::new();
    let key_id = opc_key::KeyId::new("k".repeat(512)).unwrap();
    encryption
        .insert_active_key(
            key_id.clone(),
            opc_key::KeyPurpose::Config,
            TenantId::from_static("test"),
            opc_key::Zeroizing::new([0xDB; 32]),
        )
        .unwrap();
    let aad = |store: &str| {
        opc_key::EnvelopeAad::config(
            TenantId::from_static("test"),
            1,
            opc_key::ConfigAad::new(tx_id, None, time, &principal, schema, store).unwrap(),
        )
    };
    let mut store = String::from("parallel-encoding-fixture");
    let length = opc_key::serialize_bound_aad(&aad(&store), &key_id)
        .unwrap()
        .len();
    store.extend(std::iter::repeat_n('s', 65_536 - length));
    let aad = aad(&store);
    let mut plaintext = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    plaintext.extend(std::iter::repeat_n(b'x', 1_572_864 - 2));
    plaintext.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    plaintext.resize(1_572_864 + 65_536 - 2, b'r');
    plaintext.extend_from_slice(b"\"}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let envelope = runtime
        .block_on(opc_crypto::encrypt_reserved_bounded_config_envelope(
            reservation,
            &encryption,
            &aad,
            &plaintext,
        ))
        .unwrap();
    assert_eq!(envelope.encoded().len(), 1_704_492);
    let record = crate::CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: time,
        principal,
        source: crate::CommitSource::Gnmi,
        schema_digest: schema,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let audit = (0..22)
        .map(|sequence| crate::AuditRecord {
            tx_id,
            sequence,
            yang_path: format!(
                "/fixture:{}",
                "x".repeat(if sequence == 21 { 128 } else { 8192 } - 9)
            ),
            op_type: crate::types::AuditOpType::Update,
            previous_value: Some("before".to_owned()),
            new_value: Some("after".to_owned()),
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        })
        .collect();
    let attested =
        crate::AttestedConfigCommit::try_new(record, audit, envelope.claim().unwrap()).unwrap();
    let binding = CapacityRecordBinding::issue(&attested, identity, key, PROFILE).unwrap();
    let (record, audit, resolution, evidence, reservation) = attested.into_capacity_parts();
    assert!(resolution.is_none());
    let reservation =
        reservation.expect("the actual encryption reservation transfers with its claim");
    assert!(pool.owns(&reservation));
    assert_eq!(evidence.unwrap().profile(), PROFILE);
    let commit = PreparedConfigCommit::prepare_for_profile(record, audit, key, PROFILE).unwrap();
    let effect = AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    };
    let privacy = AuditPrivacyKey::new([0xDD; 32]).unwrap();
    let event = crate::ManagementAuditEventRecord::try_new(
        [0xDE; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:configuration"],
        Some("parallel-encoding-fixture"),
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &event).unwrap();
    let digest = effect.digest(key).unwrap();
    let binding = AuditOperationBinding::project(&privacy, &event, 0, &digest).unwrap();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity,
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0xDF; 16],
            key_epoch: key.epoch(),
            mutation: Some(digest),
        },
        key,
    )
    .unwrap();
    (
        PreparedAuditedMutation::new(
            handle,
            effect,
            Some(PreparationOwnership::new(reservation, evidence)),
        ),
        envelope,
    )
}

fn weak(entry: &Entry<ConfigRaftTypeConfig>) -> Weak<AuditedMutationFields> {
    let EntryPayload::Normal(command) = &entry.payload else {
        panic!("normal persisted command");
    };
    let ConfigMutationIntent::AuditedMutation(command) = &command.intent else {
        panic!("audited persisted command");
    };
    command.weak_fields()
}

struct Peak {
    total: usize,
    encoders: usize,
    pending: usize,
    typed: usize,
    recovery_capacity: usize,
    cancel_index: Option<usize>,
}

struct Completed {
    peak: Peak,
    reached_all: bool,
    canceled: usize,
    cancellation_retired: bool,
    encoded: Vec<u8>,
}

fn simultaneous(checkpoint: Checkpoint) {
    let root = tempfile::Builder::new()
        .prefix("parallel-")
        .tempdir_in(std::env::var_os("TMPDIR").expect("explicit private disk scratch"))
        .unwrap();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout).unwrap().trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let identity = ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes(
            *uuid::Uuid::new_v4()
                .as_bytes()
                .repeat(2)
                .first_chunk::<32>()
                .unwrap(),
        ),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xE0; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let key = crate::AuditKey::new([0xE1; 32]).unwrap();
    let pool = ConfigPreparationPool::bounded_v1();
    let (prepared, envelope) = prepared(identity, &key, &pool);
    // The preparation and retained encryption alias share the one reservation
    // consumed by encryption, rather than being charged to an unrelated slot.
    let other_slots: Vec<_> = (0..7).map(|_| pool.try_reserve().unwrap()).collect();
    assert!(pool.try_reserve().is_err());
    drop(other_slots);
    let topology = ConfigConsensusTopology::try_new(
        identity,
        node(1),
        (1..=9).map(node).collect::<BTreeSet<_>>(),
    )
    .unwrap();
    let mut conn = Connection::open(root.path().join("encoder.sqlite")).unwrap();
    let transaction = conn.transaction().unwrap();
    crate::schema::initialize_schema(&transaction).unwrap();
    transaction.commit().unwrap();
    sqlite::provision_retained_schema(&conn, &topology, &key, PROFILE, Instant::now() + GUARD)
        .unwrap();
    let log_id = LogId::new(CommittedLeaderId::new(1, node(1)), 0);
    let command = ConfigConsensusCommand {
        schema_version: 8,
        identity,
        request_id: ConsensusRequestId::new(),
        logical_time: "1970-01-01T00:01:40Z".parse().unwrap(),
        intent: ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
    };
    command
        .validate_for_profile(identity, &key, PROFILE)
        .unwrap();
    let original = Entry {
        log_id,
        payload: EntryPayload::Normal(command),
    };
    sqlite::append_logs_sync(
        &conn,
        identity,
        topology.members(),
        std::slice::from_ref(&original),
        PROFILE,
    )
    .unwrap();
    sqlite::save_committed_sync(&conn, identity, Some(log_id), PROFILE).unwrap();
    drop(original);
    let response = encode_config_wire_for_profile(
        PROFILE,
        &Ok::<_, RaftError<ConsensusNodeId, Infallible>>(
            AppendEntriesResponse::<ConsensusNodeId>::Success,
        ),
    )
    .unwrap();
    let peers = (2..=9)
        .map(|target| {
            let target = node(target);
            (
                target,
                Arc::new(Peer {
                    target,
                    response: response.clone(),
                }) as Arc<dyn ConsensusPeer>,
            )
        })
        .collect();
    let factory = ConfigRaftNetworkFactory::try_new(identity, node(1), peers, PROFILE).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut calls = Vec::new();
    let mut weak_fields = Vec::new();
    for target in 2..=9 {
        let entries = sqlite::read_limited_log_range_sync(
            &conn,
            identity,
            topology.members(),
            0,
            1,
            1,
            PROFILE,
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        weak_fields.push(weak(&entries[0]));
        // A fresh factory clone and new client cannot create another gate.
        let mut generation = factory.clone();
        let client = runtime.block_on(generation.new_client(node(target), &EmptyNode::default()));
        calls.push((
            client,
            AppendEntriesRequest {
                vote: Vote::new_committed(1, node(1)),
                prev_log_id: None,
                entries,
                leader_commit: Some(log_id),
            },
        ));
    }
    assert_eq!(
        weak_fields
            .iter()
            .map(Weak::as_ptr)
            .collect::<BTreeSet<_>>()
            .len(),
        FOLLOWERS,
        "each actual SQLite read owns a distinct decoded command"
    );
    let raft = Arc::new(RaftAppendCensus::default());
    let raft_registration = raft.observe_source(identity, node(1)).unwrap();
    let (recovery_tx, recovery_rx) = std::sync::mpsc::channel();
    let recovery = Arc::new(RecoveryGate {
        arrived: Mutex::new(Some(recovery_tx)),
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let working = Arc::new(WorkingBufferCensus::default());
    let working_registration = working
        .observe_source(identity, node(1), Some(recovery.clone()))
        .unwrap();
    let enrollment = working_registration.observe_recovery(&prepared).unwrap();
    let probe = Arc::new(Probe {
        checkpoint,
        ..Probe::default()
    });
    let Completed {
        peak,
        reached_all,
        canceled,
        cancellation_retired,
        encoded,
    } = std::thread::scope(|scope| {
        let _release = ReleaseOnDrop {
            probe: probe.clone(),
            recovery: recovery.clone(),
        };
        let encoder = scope.spawn(|| prepared.encode());
        let recovery_owner = recovery_rx.recv_timeout(GUARD).unwrap();
        assert_eq!(recovery_owner.kind, WorkingBufferKind::RecoveryOutput);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let mut cancellations = Vec::new();
        let threads: Vec<_> = calls
            .into_iter()
            .enumerate()
            .map(|(index, (mut client, request))| {
                let probe = probe.clone();
                let finished_tx = finished_tx.clone();
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                cancellations.push(Some(cancel));
                scope.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    let _scope = ProbeScope::enter(probe, index);
                    let result = runtime.block_on(async {
                        tokio::select! {
                            result = client.append_entries(request, RPCOption::new(GUARD)) => Some(result),
                            _ = cancelled => None,
                        }
                    });
                    finished_tx.send(index).unwrap();
                    result
                })
            })
            .collect();
        let reached_all = probe.wait_until_all_observed();
        let peak = with_audited_allocations(node(1), &prepared, |prepared_allocations| {
            working.with_current_capture(|working_capture| {
                working_capture.with_joined(&prepared_allocations, |working_union, joined| {
                    raft.with_current_capture(|raft_capture| {
                        let raft_union = raft_capture.join(&joined);
                        let state = probe.state.lock().unwrap();
                        let outputs: BTreeMap<_, _> = state
                            .encoders
                            .iter()
                            .filter(|value| value.capacity != 0)
                            .map(|value| (value.pointer, value.capacity))
                            .collect();
                        assert!(working_union.issues.complete() && raft_union.issues.complete());
                        Peak {
                            total: raft_union.union_bytes
                                + outputs.values().sum::<usize>()
                                + envelope.encoded().len(),
                            encoders: outputs.len(),
                            pending: state
                                .encoders
                                .iter()
                                .filter(|value| state.blocked_by_borrowed_guard(value))
                                .count(),
                            typed: raft_union.calls,
                            recovery_capacity: recovery_owner.bytes,
                            cancel_index: state
                                .encoders
                                .iter()
                                .position(|value| state.blocked_by_borrowed_guard(value)),
                        }
                    })
                })
            })
        })
        .unwrap();
        // Cancel an actually pending adapter future while the encoder remains
        // held. Its independently decoded DTO must retire without that release.
        let cancellation_retired = peak.cancel_index.is_some_and(|index| {
            cancellations[index].take().unwrap().send(()).unwrap();
            let finished = finished_rx.recv_timeout(GUARD).ok() == Some(index);
            let remaining = raft.with_current_capture(|capture| capture.sample());
            finished
                && remaining.calls.len() == FOLLOWERS - 1
                && remaining.issues.complete()
                && weak_fields[index].upgrade().is_none()
        });
        probe.release();
        recovery.release();
        let mut canceled = 0;
        for thread in threads {
            match thread.join().unwrap() {
                Some(result) => assert!(result.is_ok(), "actual adapter call completes"),
                None => canceled += 1,
            }
        }
        Completed {
            peak,
            reached_all,
            canceled,
            cancellation_retired,
            encoded: encoder.join().unwrap().unwrap(),
        }
    });
    assert_eq!(encoded.capacity(), peak.recovery_capacity);
    assert!(PreparedAuditedMutation::decode(&encoded).unwrap() == prepared);
    drop(encoded);
    drop(enrollment);
    drop(prepared);
    let alias_slots: Vec<_> = (0..7).map(|_| pool.try_reserve().unwrap()).collect();
    assert!(
        pool.try_reserve().is_err(),
        "the original envelope retains its shared reservation"
    );
    drop(alias_slots);
    drop(envelope);
    drop((factory, runtime, conn));
    let working_clean = working.with_current_capture(|capture| capture.sample());
    let raft_clean = raft.with_current_capture(|capture| capture.sample());
    assert!(working_clean.owners.is_empty() && working_clean.issues.complete());
    assert!(raft_clean.calls.is_empty() && raft_clean.issues.complete());
    assert!(weak_fields.iter().all(|owner| owner.upgrade().is_none()));
    let slots: Vec<_> = (0..8).map(|_| pool.try_reserve().unwrap()).collect();
    assert!(pool.try_reserve().is_err());
    drop(slots);
    drop((working_registration, raft_registration));
    root.close().unwrap();
    assert!(probe
        .state
        .lock()
        .unwrap()
        .encoders
        .iter()
        .all(|value| value.waiting_on.is_none() && value.guard.is_none() && value.capacity == 0));
    eprintln!("CAPACITY_PARALLEL_CLEANUP typed=0 recovery=0 slots=8 total={} active_encoders={} pending={} captured_typed={} recovery_capacity={} canceled={canceled} cancellation_retired={cancellation_retired}", peak.total, peak.encoders, peak.pending, peak.typed, peak.recovery_capacity);
    assert!(
        reached_all,
        "all real encoders or admission waiters were witnessed"
    );
    assert_eq!(
        peak.typed, FOLLOWERS,
        "CAPACITY_PARALLEL_PENDING_RED: all actual decoded DTOs remain visible"
    );
    assert!(
        peak.total <= OPERATION_BYTES,
        "CAPACITY_PARALLEL_BOUND_RED: actual simultaneous allocations {} exceed {OPERATION_BYTES}",
        peak.total
    );
    assert_eq!(
        peak.encoders, 1,
        "CAPACITY_PARALLEL_ENCODER_RED: one factory permits one encoding pair"
    );
    assert_eq!(
        peak.pending,
        FOLLOWERS - 1,
        "actual queued DTO owners were captured"
    );
    assert_eq!(canceled, 1, "exactly one pending future was canceled");
    assert!(
        cancellation_retired,
        "cancellation physically retires the pending DTO before unlock"
    );
}

#[test]
fn capacity_parallel_encoding_actual_originals_and_recovery_stay_within_reservation() {
    simultaneous(Checkpoint::Encoded);
}

#[test]
fn capacity_parallel_encoding_holds_guard_until_original_drop() {
    simultaneous(Checkpoint::OriginalReady);
}
